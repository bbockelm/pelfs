# pelfs v2 format: packed objects, split catalogs, signed superblock

Status: **design complete** — every section is settled, with rejected
alternatives recorded; the only deferred items (end of document) wait on
external partners or production mileage, not on design. Phase 1 (the pack
middleware) is implemented; v1 (JuiceFS-native storage) is what ships
today.

## Why change

Three problems observed with the v1 (JuiceFS blocks + whole-volume SQLite
snapshot) layout, all confirmed in real use:

1. **Small objects.** Every JuiceFS slice becomes its own federation object.
   Small files and fragmented writes produce storms of tiny objects (we
   measured uniform 32KB objects from the NFS backend before the handle
   cache); each costs an HTTP round trip, pollutes the namespace, and
   caches poorly.
2. **Metadata scaling.** The entire SQLite catalog is re-uploaded every
   snapshot interval, forever, no matter how little changed. Cost grows
   with volume size, not churn. A million-file volume pays gigabytes of
   upload per hour while idle.
3. **Cache hostility.** Data blocks are keyed by mutable-looking names and
   the metadata snapshot is overwritten in place, so mutable-object reads
   must bypass federation caches (`?directread`) and the lease machinery
   guards several objects.

The v2 format is, in one sentence: **writable CVMFS with restic-style
packs** — content-addressed immutable packs and split SQLite catalogs, with
a single small signed mutable superblock as the trust and consistency root.

## Object classes

The federation prefix holds exactly four kinds of objects. Everything
under refs/ is mutable and ETag-guarded; everything else is immutable.
(Full layout, naming, and the no-manifest decision: see "Federation
namespace layout" below.)

```
<prefix>/
  refs/<branch>         <- mutable superblocks; small, signed, ETag-CAS
  tags/<name>           <- immutable superblocks (frozen generations)
  leases/<branch>.json  <- advisory liveness beacons
  packs/p-<ts>-<rand>   <- immutable packs: data chunks, small files,
                           catalogs, inode shards, superblock backups
```

### 1. Packs

A pack is a concatenation of **independently compressed (and encrypted)
chunks**, plus an index mapping `chunk-hash -> (offset, length)`. Any chunk
is retrievable with a single HTTP range request — Pelican origins and
caches serve ranges natively, so a pack never has to be fetched whole.

Explicitly rejected: the literal git packfile format. Git packs are zlib
streams with delta chains optimized for whole-object reconstruction; a
filesystem serves range reads, and delta chains force reconstructing an
object to serve any byte of it. The "edits share storage with the previous
version" benefit comes instead from **content-defined chunking** (FastCDC):
an edited large file re-chunks and shares unmodified chunks with its
ancestor via content addressing, at zero read-path cost. True deltas, if
ever wanted, are confined to small objects and are not in this design.

Packs hold everything: data chunks, whole small files, catalogs, inode
shards. Target pack size is 64 MiB (matching the phase-1 middleware's
TargetSize: large enough that a 10 GB write is ~160 uploads, small enough
that repack passes and range-served cold reads stay granular); the
open-pack append strategy is the spool-file design below.

**Write path (the "memtable"):** the accumulating structure is a local
spool file — an append-only file whose byte layout is already the final
pack layout, plus an in-memory key -> (offset, length) table. There is no
merge step: cutting a pack appends the index trailer and uploads the spool
verbatim (zero-copy publish). Reads of not-yet-flushed entries are served
from the spool. The spool is not mmap'd (plain WriteAt/ReadAt; mmap of a
growing file buys remap churn, not speed). Entries are byte-packed with
**no alignment padding**: HTTP range requests are byte-granular and the
local block cache reads whole entries, so alignment would pay only if
packs were mmap'd locally — revisit then, not before.

**Compression is per-entry, never per-pack-stream.** Each entry is
independently compressed, and the compression algorithm is recorded
explicitly (an algo id in the entry's index/catalog record — never sniffed
from magic bytes) so it is per-entry flexible: zstd by default, `none`
under a store-if-smaller policy (compress, keep the smaller of the two —
the git/borg trick that avoids paying for incompressible data), future
algorithms are new ids. Order is compress-then-encrypt — encrypting first
would destroy compressibility. (Noted: compressed sizes leak through
encryption, a CRIME-family side channel we accept for a scratch
filesystem.)

This resolves the classic tension between **sub-pack fetching and
compression ratio** in favor of fetching: per-entry compression makes
every entry independently range-readable, at the cost of losing cross-file
compression context. Two mitigations keep the ratio loss small: tiny files
— where solid compression wins big — mostly live *inline in catalogs*,
so pack entries skew large, where per-entry zstd approaches solid ratios
anyway; and if small-entry corpora ever matter, a per-pack **zstd
dictionary** (trained over the pack's entries, stored in the pack header,
referenced by algo id) recovers most of the solid-compression gap while
preserving per-entry independence. Whole-pack solid compression is
rejected outright: one cold read would fetch and decompress everything
before it.

### 2. Path catalogs

SQLite databases (schema inspired by JuiceFS's node/edge/chunk tables, not
bound to them) covering a subtree of the namespace. Each catalog is a
self-contained blob, packed, content-addressed.

- **Inline data:** files at or below a threshold (default 4KB — one SQLite
  page; SQLite outperforms filesystems for blobs below ~10KB) are stored
  directly in the catalog row. No federation object exists for them, and
  the metadata fetch carries their content.
- **Splitting:** when a catalog exceeds its threshold, it splits at a
  directory boundary chosen by subtree weight; the parent catalog carries a
  transition-point row (the CVMFS nested-catalog scheme). Split at S_max,
  merge back at S_min << S_max — hysteresis prevents thrashing. Policy and
  thresholds below are **measured**, not guessed (simulation over four
  real trees: a miniconda root, a node_modules, glibc, and a 16GB/677K-
  entry Go module cache; proto-catalog SQLite validated the row model).

  **Weight function:** W = 200·entries + inline_bytes (+ xattr bytes).
  Measured structural cost is 176 B/entry, so 200 is mildly conservative.
  Inline bytes MUST be in the weight — they dominate real catalogs (62-91%
  of files inline across the sample trees; 46 of 59 MB of a miniconda's
  catalog weight is inline data). An entry-count threshold alone (CVMFS's
  choice) would produce wildly variable catalog sizes here.

  **Policy: bottom-up, peel largest child first.** Walking post-order, a
  directory whose accumulated weight exceeds S_max detaches its largest
  attached child subtree (which becomes a nested catalog), repeating until
  it fits. The naive alternative — detach the whole directory when it
  exceeds — measurably fails: a directory of many medium children detaches
  as one catalog 10-15x over threshold. Peeling keeps p95 <= S_max on
  every sampled tree.

  **Thresholds: S_max = 8 MiB, S_min = 1 MiB** (merge a nested catalog
  below S_min into its parent only if the parent stays under S_max; 8:1
  hysteresis). At 8 MiB: miniconda = 31 catalogs (nest depth <= 3),
  node_modules = 87, glibc = 10, Go module cache = 527 (depth <= 4, zero
  pathological). 2 MiB explodes catalog counts (1,447 for the module
  cache, depth 6) for no churn benefit; 32 MiB collapses miniconda to two
  catalogs, making a one-file touch republish ~30 MB. Dirty amplification
  at 8 MiB: a leaf write republishes the leaf catalog plus <= 4 ancestors,
  and post-split ancestors hold only residue rows, so the republish unit
  is ~one catalog (<= 8 MiB raw, ~1/3 of that compressed — catalogs
  measure 36% under zlib).

  **Flat-directory exception:** a single directory whose own rows exceed
  S_max cannot split (catalog roots are directories) and remains one
  oversized catalog. Measured worst case: @mui/icons-material at 13.3 MiB
  (thousands of tiny inlined files in one directory) — under 5 MiB
  compressed, tolerable, and rare (one to two per sampled ecosystem tree).

  **Hardlink validation:** the miniconda tree carries 23,598 hardlink
  groups and every one of them spans catalogs at any reasonable S_max —
  confirming both that eager promotion was the right call (lazy promotion
  would have bought nothing) and that its cost is trivial: ~24K shard
  records, roughly 5 MB, for a full conda installation.
- Catalogs contain **only** records with nlink == 1, plus references
  (see hardlinks). This makes every directory boundary a legal split point
  unconditionally — the splitter needs no hardlink awareness.

### 3. Inode shards ("inode catalogs")

Structurally identical to path catalogs — same SQLite-blob-in-pack format —
but keyed by **inode** instead of path. They hold the records of promoted
(nlink > 1) files. Shards are range-partitioned by dynamic boundaries
(B-tree-leaf style, split at the median inode on overflow, merge on
underflow); the routing lives in the superblock. Because they partition by
sort order rather than tree structure, shards can never form unsplittable
atoms.

Monotonic inode allocation gives temporal locality for free: newly promoted
inodes land in the tail shard, publish churn concentrates there, and old
shards go cold and live in federation caches indefinitely.

### 4. Superblock

The single mutable object and the root of both trust and consistency:

| field | purpose |
|---|---|
| format version, generation counter | identify + order snapshots |
| root catalog hash | entry point of the namespace |
| catalog routing (transition points -> pack locations) | find any catalog without fetching parents' bodies |
| inode-shard ranges -> pack locations | find any promoted inode record |
| **pack list** (name, size, trailer hash per pack) | the generation's location layer: which packs constitute this snapshot |
| `next_inode` | allocator high-water mark |
| key table (key-id -> wrapped DEK) | confidentiality keys, wrapped by the user's KEK |
| previous-superblock hash | lineage: snapshot history, fork detection |
| signature | trust root over all of the above |

Format: deliberately boring (CBOR or a tiny SQLite DB, loaded fully into
RAM). A minimal-perfect-hash mmap structure was considered and rejected:
the superblock has one row per *catalog/shard* (thousands at pathological
extremes, since each holds ~100K entries), far below where MPH pays. If a
per-pack chunk index ever holds millions of entries, a sorted-hash-array
with binary search on mmap is the next step there — still not MPH.

Because everything else is immutable and content-addressed, the superblock
is the only object a *reader* ever depends on that mutates, and the only
thing a reader must re-fetch to observe a new generation. Readers get
snapshot-consistent views by pinning a generation. Federation caches work
at full strength for all data and all metadata; `?directread` is needed
only for the superblock (and the advisory lease, which no reader touches —
see the concurrency section).

## Concurrency: CAS is the guard, the lease is a courtesy

The volume has exactly **two** mutable objects, with disjoint roles:

- **Superblock — consistency.** The publish-time superblock flip is an ETag
  compare-and-swap. If two writers race, the loser's flip fails cleanly:
  its packs are uploaded but unreferenced (orphans for GC), nothing
  interleaves, nothing corrupts. This is a categorical improvement over
  v1, where concurrent writers destructively interleave chunk objects and
  the lease is load-bearing for correctness.
- **Lease — liveness (advisory).** The v1 lease survives essentially
  unchanged (heartbeat + TTL + takeover warning), but demoted: its only
  job in v2 is preventing *wasted work* — fail fast at mount instead of at
  the first failed publish, warn mid-session on takeover. It is unsigned,
  not content-addressed, never read by read-only mounts, and its loss or
  corruption affects no data. `--no-lease` and `--ro` semantics carry over.

Rejected: heartbeating through the superblock itself (to keep a
"one mutable object" purity claim). That conflates roles — re-signing
every 30s, lineage polluted or bypassed by heartbeats, and readers unable
to distinguish "new generation" from "still alive" without parsing.

## Identity vs. location: how snapshots record where chunks land

A snapshot must capture *what* every file's chunks are without freezing
*where* they live, or repack would invalidate history. The decomposition:

- **Identity lives in catalogs.** A file's row records its chunk list as
  content hashes — location-free, which is what lets an unchanged
  subtree's catalog stay hash-identical (and therefore shared) across any
  number of generations.
- **Location lives in pack trailers, versioned by the superblock's pack
  list.** Trailers (hash -> offset, length within their pack) are
  immutable and shared; each superblock records the *set of packs* that
  constitutes its generation — a per-pack list (name, size, trailer
  hash), not a per-chunk map, so it stays small (hundreds of entries for
  a million-chunk volume, versus tens of MB for a chunk-level manifest).
  Resolution is: hash -> this generation's pack set -> trailer -> range.

Consequences:

- **Tagged generations never rot.** A generation pins its pack set;
  repack emits a *new* generation whose list routes moved chunks to the
  new pack, while retained older generations keep their old packs alive.
  GC's pack-liveness question is simply "does any retained generation's
  pack list name this pack" (plus the reader grace window).
- **Repack remains metadata-free in v2**: catalogs never change; only the
  next superblock's pack list does.
- **Bootstrap-by-listing dies with phase 1.** Today a session lists
  packs/ and trusts name-ordered shadowing; in v2 the superblock hands a
  fresh session the authoritative, generation-consistent pack set — no
  listing, no race against concurrent repack.
- File versioning in the user-visible sense falls out: mount any tagged
  generation for its point-in-time tree; a file's versions across
  generations are different chunk lists in (mostly shared) catalogs, with
  CDC + content addressing sharing every unchanged chunk between
  versions. Retention policy is ref/tag retention.

(Contrast with v1, which has the same two layers — metadata references
logical block names, trailers map names to locations — but does not
version the pack set and deletes overwritten blocks eagerly: a v1
"snapshot" is a crash-recovery checkpoint whose older siblings rot as
later sessions tombstone their blocks. Only the newest is guaranteed
consistent, by the pre-snapshot flush ordering.)

## Retention and GC (v2)

Retention is expressed entirely in the ref/generation layer, and the pack
list makes the sweep set arithmetic rather than tree traversal:

- **Retained generations** = every ref's current generation, every tag,
  plus each branch's trailing ancestors within `K` generations or
  `T_grace` of age (walked via lineage hashes; defaults K=8,
  T_grace=72h, recorded in the superblock so writers, readers, and GC
  agree; configurable per volume).
- **Retained packs** = the union of retained generations' pack lists.
  No catalog walking is needed for deletion safety — the pack list *is*
  the reachable closure at pack granularity. (Catalog walking exists only
  inside publish, for repack liveness accounting.) Retention deliberately
  overapproximates liveness; repack trims dead bytes *within* retained
  generations.
- **Sweep** = delete packs that are (a) absent from the retained union
  AND (b) older than T_grace by name timestamp. Guard (b) is what makes
  GC safe to run concurrently with writers and forkers, with no locking:
  a writer's new packs are always younger than T_grace, so they are never
  candidates regardless of when GC listed the refs; and the fork rule
  (fork only from ref-reachable generations) means any mid-GC fork's
  closure is already inside the retained set. GC re-lists refs
  immediately before issuing deletes as a cheap window-narrower, not a
  correctness requirement.
- **Granularity:** whole packs, superseded superblock backups, and ref
  debris only — never entries (repack's job). Deleting a branch or tag is
  how space is actually released.
- **Who runs it:** each publish piggybacks trimming of its own branch's
  anonymous ancestors (cheap: lineage walk plus set difference);
  cross-ref sweep after branch/tag deletion is an explicit `pelfs gc`,
  which needs no lease.
- **The reader contract:** a reader pinned to an untagged generation
  older than T_grace may see "snapshot expired — refresh or remount." A
  workflow that needs a longer pin tags first; tags pin exactly and
  indefinitely.

## Signing and key management (v2)

- **Two keys, two jobs.** The volume *signing* keypair (Ed25519,
  generated at volume creation) authenticates superblocks; the user KEK
  wraps DEKs and the identity key for confidentiality. They have
  different lifecycles and different audiences: every reader verifies
  signatures, only key-holders decrypt. An unencrypted volume still has a
  signing key.
- **First-mount trust**, in order of preference: an explicit
  `--volume-pubkey` (or fingerprint embedded in a shared tag reference);
  else trust-on-first-use with the key pinned in local state and loud
  errors on change (the SSH model). Registry-issued attestation was
  considered and is explicitly out: pelfs stays a pure client of dumb
  federation storage, with no registry integration.
- **Rotation:** a superblock may introduce a successor public key, signed
  by the current key; readers follow the custody chain through lineage.
  Compromise recovery is out-of-band re-pinning (custody chains cannot
  distinguish a stolen key's rotation from a legitimate one).
- **Threat model, stated honestly:** the federation origin is dumb
  storage and cannot verify signatures, so a compromised *write token*
  permits clobbering the mutable ref objects — an availability attack.
  Signatures make forgery detectable (readers reject), and lineage plus
  in-pack superblock backups make recovery mechanical (`pelfs rescue`).
  Integrity holds; availability under token compromise does not, and no
  client-side design can change that.

## Federation namespace layout (v2)

```
<prefix>/
  refs/<branch>          mutable superblocks (branch heads); ETag-CAS
  tags/<name>            immutable superblocks (frozen generations)
  leases/<branch>.json   advisory liveness beacon, one per branch
  packs/p-<ts>-<rand>    immutable packs (data, catalogs, shards, backups)
```

Pack names stay time-ordered (`p-<unixnano hex>-<rand>`) rather than
content-derived: the age guard in GC and the creation ordering come free,
and integrity does not need hash *names* — each generation's pack list
records the trailer hash, so a fetched pack verifies against the list.
(Outer hash-naming was considered and rejected as buying nothing.)
Normal operation never lists the namespace: the superblock carries the
pack set, and refs/tags are addressed by name. Listing is needed only by
`pelfs rescue` and cross-ref GC (PROPFIND over refs/, tags/, packs/). No
manifest object exists.

## Catalog schema (v2)

Informed by the proto-catalog measurements (176 B/entry structural, 36%
compression). All tables WITHOUT ROWID where the key is natural.

- `catalog_meta(key, value)` — volume UUID, covered path, generation,
  format version, identity algo — the self-identification rescue needs.
- `node(inode PK, type, mode, uid, gid, mtime_ns, ctime_ns, nlink,
  length, rdev, keyid, flags)` — **no atime** (scratch volumes run
  noatime; persisting atime would dirty catalogs on read, an absurdity).
  Special files (fifo/dev/socket) store as types with rdev; the NFS
  frontend may refuse to expose some — recorded limitation.
- `edge(parent, name BLOB, inode, type)` PK(parent, name).
- `nested(parent, name BLOB, catalog_identity BLOB)` — transition points.
- `chunkref(inode, idx, identity BLOB[32], llen, clen, alg, keyid)` —
  logical offsets are prefix sums of llen at load (rows per file are few;
  saves 8 bytes/row); holes in sparse files are rows with NULL identity
  and llen = hole length.
- `inline(inode PK, data BLOB)` — separate table keeps node rows hot.
- `xattr(inode, name, value)`; `symlink(inode PK, target)`.
- Inode shards reuse node/chunkref/inline/xattr keyed purely by inode.
- Dropped from the JuiceFS lineage: sessions, sustained inodes, flocks,
  plocks, delayed-slices, dir-stats (recomputable), counters (superblock
  owns them), trash, and ACL tables (POSIX ACLs out of scope for v2.0;
  xattrs can carry them opaquely).

## Benchmarks and acceptance criteria (v2)

Fixed suite, run against a local posixv2 federation and one real OSDF
prefix; targets follow from the measurements in this document:

1. Kernel-source untar + publish: publish cost ∝ churn; republish after
   touching one file ≈ one catalog + ancestors (≤ ~4 MB compressed).
2. `conda create` (the hardlink storm): completes; promotion adds ≤ ~10 MB
   of shards; subsequent publish seconds, not minutes.
3. `git clone` + `git status`: correct (the v1 NFS lessons as regression
   tests) and status latency within 2x local disk on warm cache.
4. 10 GB single-file write: ≥ 0.8x the raw pelican upload throughput of
   the same host (chunking+packing overhead budget: 20%).
5. Cold mount of a 1M-entry volume: ≤ 30 s to usable in phase 2
   (full-hydrate ≈ 60-120 MB compressed metadata); ≤ 3 s in phase 3
   (lazy descent).
6. Overwrite-loop soak: federation usage stays ≤ live/L + G + one pack
   (the repack bound), verified over hours.

## Migration: v1 -> v2

Decision: **no in-place migration.** A v1 volume is drained by mounting
it read-only with v1 code and publishing its contents into a fresh v2
prefix (a copy pipeline through the filesystem layer — `pelfs migrate`
can automate exactly this and nothing subtler). In-place conversion is
rejected: it would force every v2 reader to carry v1's slice-name block
layout and unversioned-snapshot semantics forever, for the convenience of
volumes that are, by charter, scratch. Phase-1 packs are already
forward-compatible where it matters (typed trailer entries), and the
phase-1 middleware never writes anything a v1 mount cannot read back.

## Disaster recovery: scavenging a lost superblock

The superblock is the only mutable object, which makes it the natural
worry: what survives if it is lost or corrupted? Answer: everything except
the map — packs contain the catalogs and inode shards as well as the data,
so recovery is a scavenging problem, made tractable by three format
provisions:

1. **Typed pack entries.** Every trailer entry carries a type (data chunk,
   catalog, inode shard, superblock backup; absent = data). One byte of
   JSON per entry; without it, recovery would have to sniff SQLite magic,
   which encryption makes impossible.
2. **Self-identifying catalogs.** Each catalog embeds a metadata table:
   volume UUID, its covered subtree root path, the generation that
   produced it, and — because transition-point rows carry child catalog
   hashes — the tree is *self-assembling*: find all catalog entries,
   descend by embedded child hashes, and a root candidate is any catalog
   covering "/" that no other catalog references. Generation stamps order
   candidates; recovery prefers the newest generation whose reachable
   closure is complete (a crash mid-publish legitimately leaves a newer,
   incomplete set — publish ordering uploads packs before flipping the
   superblock — so fall back a generation when the closure has holes).
3. **Superblock backups ride in packs.** Superblocks are tiny; each pack
   carries the most recent one as an entry (type: superblock-backup,
   including its ref name). Losing the mutable object then costs only the
   generations since the last pack — recovery becomes "restore the newest
   embedded backup, verify its signature, re-point the ref," recovering
   the allocator counter, shard ranges, pack list, and the KEK-wrapped
   key table exactly. (A lost KEK is still fatal for encrypted data, by
   design; the wrapped DEK in a backup is harmless to expose.)

`pelfs rescue` (the human-facing tool; specified here, implemented with
phase 2): enumerate packs,
inventory trailers, assemble the newest complete generation, then report —
subtrees intact, files damaged by missing chunks, catalogs missing (their
siblings remain fine), and a hash-only lost+found for data reachable from
no surviving catalog (promoted inode-shard records can even recover file
bodies whose dirents are gone). Partial pack loss degrades proportionally
and legibly, because the hash tree makes "what is missing" exactly
enumerable rather than a guess.

(Phase-1/v1 note: today the metadata snapshot objects under meta/ are the
only namespace record; packs hold logically-named blocks, so losing every
snapshot leaves lost+found-grade recovery only. keep-sessions retention is
the v1 mitigation. The phase-1 trailer format already reserves the entry
type field so existing packs stay forward-compatible with scavenging.)

## Refs: branches, tags, and forks

A superblock generation is already a commit: immutable once written, signed,
parent-linked via the lineage hash, rooting an immutable object graph. Refs
add the missing distinction between a commit and the *name* pointing at it:

- **Branch** — a mutable ref object (`refs/<name>`), advanced by publish.
  Each ref is independently ETag-CAS'd and guarded by its own advisory
  lease; the entire concurrency section applies per-ref. The v2 design's
  single superblock is simply `refs/main`, which bare-prefix mounts use by
  default.
- **Tag / named snapshot** — an immutable ref: a frozen superblock under a
  name, never CAS'd. Costs one tiny object; everything it references is
  shared. Read-only tag mounts are exactly the pinned-generation mounts
  described above.
- **Fork** — a new ref whose first superblock's parent is the forked
  generation. Copy-on-write over the whole volume: catalogs, shards, and
  chunks are shared until they diverge.

Consequences, deliberate and otherwise:

- **Single-writer becomes single-writer per branch.** Writers on different
  branches never conflict: disjoint superblocks, shared immutable objects,
  and content-addressed pack uploads collide only on identical content
  (idempotent). This enables the fan-out batch pattern — one tagged base
  environment, N jobs each forking a private writable branch and
  publishing results as tags — container-image layering for scratch data.
- **Fork rule (GC soundness):** forking is allowed only from ref-reachable
  generations — a branch's history within the GC grace window, or any tag.
  To fork something older, tag it first. This closes the race between
  forking a generation and GC condemning it.
- **GC is multi-root mark-and-sweep:** the live set is the union of
  reachability from all refs plus the grace window. Refs are enumerated by
  listing (they are few); no refs-manifest object exists. Deleting a
  branch is how space is actually freed.

  Kept scalable by four structural properties. (1) Content addressing
  dedups the mark walk: unchanged subtrees share catalog hashes, so each
  distinct catalog is visited once regardless of how many refs and
  generations reference it — mark cost is proportional to *distinct*
  metadata, not refs × tree. (2) The walk is two-level: each catalog
  carries a summary of the **pack ids** it references, so the mark phase
  unions pack-id sets and computes per-pack liveness ratios without
  touching chunk-level detail; only packs falling below a liveness
  threshold get exact, entry-level accounting — and that happens as part
  of repacking them anyway (copy live entries forward, delete the pack).
  The GC unit is the pack. (3) The generational frontier is free:
  monotonic naming means objects younger than the grace window are never
  candidates, so GC scans only the old tail. (4) The fork rule makes
  concurrent GC sound without coordination: forks come only from
  ref-reachable generations, so an object unreachable from every ref and
  older than the grace window can never become reachable again.
- **Inode uniqueness is per-lineage.** Fork descendants allocate from the
  same counter and may assign equal inode values to different files —
  harmless, since inodes need uniqueness only within a mounted tree and
  branches mount separately. A future cross-branch *merge* would need to
  renumber one side; merge is explicitly out of scope, and this rule is
  why.
- Retention becomes explicit: "retain last K generations" is anonymous
  snapshot retention; tags are the user-controlled form. Keep what you
  name, grace-window the rest.

## Read-only mounts and update propagation

Read-only clients ingest external updates by polling the superblock and
atomically swapping generations. CVMFS's propagation pain — often
misdiagnosed — was never "caches served the wrong object" (their objects
are content-addressed too); it was (a) manifest freshness behind TTL'd
squid hierarchies with no bypass, and (b) live catalog reload renumbering
inodes under the kernel (their inodes are assigned per catalog load),
which broke open files and spawned years of translation machinery. Both
are structurally absent here:

- **Freshness signal:** a conditional GET (`If-None-Match` + ETag,
  `?directread`) of one tiny object against the origin. A stream of 304s;
  no TTL guessing. Poll interval is a mount option.
- **Generation swap:** verify signature; verify **lineage** (the new
  generation must chain, via previous-superblock hashes, to a known
  ancestor — a fork from a stolen lease is detected exactly here); then
  atomically replace the in-memory routing table. Stable inodes mean
  generations agree on file identity: kernel-cached dentries/inodes for
  unchanged files remain valid, changed files keep their inode.
- **Per-handle snapshot isolation:** an open file's chunk list was
  resolved at open against immutable chunks, so open handles keep reading
  their generation's content consistently across a swap — no torn files,
  ever. The GC grace window (retain the last K generations' objects) is
  the contract backing this; a reader older than the window gets an
  explicit "snapshot expired, refresh" rather than a silent mixture.
- **Refresh policy is per-mount, not architectural:** batch jobs
  (HTCondor) default to **pinned** — one generation for the job's
  lifetime, for reproducibility; interactive read-only mounts default to
  polling. No reader registration exists (readers stay invisible, no
  third mutable object); staleness bounds come from the time-based GC
  grace window instead.

Phase caveat: live refresh requires the catalog-native runtime (phase 3),
where a swap is a routing-pointer change over directly-read catalogs. In
phase 2 — read-only mounts hydrating the JuiceFS hot engine from catalogs
— refresh means remount. Acceptable for batch; stated here so nobody
discovers it in production.

## Overwrite churn

The hostile workload is a file — or one hot 32KB byte range — rewritten
and fsynced over and over (notebook autosave, a database WAL, checkpoint
files). Immutable-object designs turn every fsynced version into new
objects; without countermeasures, storage grows with write volume rather
than live data. Four layers absorb it, ordered by how early they act:

1. **Die-young elimination (implemented, phase 1).** Every fsync of a hot
   range creates a new JuiceFS slice; the chunk's slice stack triggers
   compaction at just **5 slices**, which tombstones the stale versions'
   blocks. Blocks tombstoned while still pending in the pack spool are
   dropped at cut time: the pack uploads only live extents (re-based to
   fresh offsets), so versions that die within the pack window — a
   64MiB/snapshot-interval horizon — never reach the federation at all.
   A same-range fsync loop thus costs one live version per pack cut, not
   one per fsync.

   Sealing at snapshot cadence is *optimal* under the durability contract:
   a block that survives until the snapshot is live at publish time and
   must be uploaded regardless, so holding the active pack open longer can
   never reduce garbage — the die-young window is automatically maximal.
   The converse also holds: **there is no seal clock other than the
   snapshot**, deliberately. Sealing more often than snapshotting buys
   zero recoverable durability — the snapshot is the recovery point, and a
   sealed block no snapshot references is an orphan after a crash — while
   every early seal converts would-die-young bytes into sealed garbage
   for repack. Unsealed bytes are bounded in *size* by the pack target
   (the cut runs before an append that would exceed it; a lone
   larger-than-target block seals immediately), and in *time* by the
   snapshot interval. A session running --snapshot-interval 0 has opted
   out of periodic durability entirely; its spool still respects the size
   bound and seals at shutdown.
   Conversely, sealed packs are never reworked on the snapshot path: seal
   compaction is synchronous and cheap (a local sequential copy of live
   bytes, bounded by the 64MiB target — it cannot fall behind the writer,
   which blocks on cut), while sealed-pack cleanup is repack's job on its
   own schedule. Repack is self-limiting in the adversarial case: the more
   a pack's contents have died, the fewer live bytes a repack must move —
   pathological churn makes repack cheaper per pack, not dearer.
2. **Slice compaction (wired since v1).** JuiceFS merges a chunk's slice
   stack into one slice (reading only the union of written ranges, so a
   hot 32KB range compacts by reading 32KB, not the 64MiB chunk). This
   bounds metadata growth and read fan-out between publishes; its
   tombstones feed layer 1.
3. **Repack (implemented).** Versions that survive a pack cut and die
   later become dead entries inside immutable packs.
   Per-pack liveness is exact and free (the bootstrap index knows every
   entry; tombstones and shadowing mark the dead). Repack rewrites the
   live entries of packs below a liveness threshold into the current
   spool and then deletes the old packs whole. Three properties make it
   simple: **cost is proportional to live bytes moved**, not pack size;
   **no tombstones are needed** — the moved entries reappear in a newer
   pack, and name-ordered shadowing already makes the newer copy
   authoritative; and **crash mid-repack is idempotent** — duplicates
   resolve newest-wins, and the old pack is deleted only after the new
   one is durable (plus, in the v2 refs world, the GC grace window).
   Policy: trigger on liveness ratio (default: condemn below 50% live)
   with an age floor (default 10m) so the hot tail is never repacked, and
   a total-garbage floor (default 256MiB) so small volumes are left alone.
   In-session, repack runs opportunistically after each pre-snapshot flush
   with a per-pass move budget (64MiB of live bytes) bounding the added
   snapshot latency; `pelfs repack` drains everything offline under the
   volume lease. **This bounds federation space against overwrite loops:**
   with liveness threshold L and garbage floor G, steady-state usage is at
   most live/L + G + one unsealed pack — a client looping overwrites
   forever caps at roughly 2x its live data plus 256MiB, regardless of
   write volume.
4. **Content addressing (v2).** The endgame: identical content hashes to
   the same chunk — a rewrite that changes nothing costs nothing — and
   CDC re-chunking makes an edit cost proportional to the changed bytes,
   not the file. Layers 1–3 then handle only genuinely novel dead data.

## Identity: inodes and hardlinks

**Inodes are opaque, stable 64-bit values** allocated monotonically from
the superblock's `next_inode` counter (sessions lease a range at mount and
publish their high-water mark; a crash burns numbers, which is fine in a
64-bit space).

Explicitly rejected: inode = (32-bit catalog ID, 32-bit file ID). Encoding
location into identity means catalog splits renumber whole subtrees and a
cross-catalog `mv` changes a file's inode — breaking POSIX rename
semantics, open handles, NFS filehandles, and `tar`/`rsync` same-file
detection. This is CVMFS's deepest scar (years of inode-translation
workarounds), and a *writable* filesystem cannot dodge it the way read-only
CVMFS does. With opaque inodes, a cross-catalog rename is just: row moves
from catalog A to catalog B, both dirty, both republished in one
superblock generation. The tree is the mapping; no registry exists.

**Hardlinks (eager promotion).** The invariant is a single biconditional:

> dirent shared-flag set <=> nlink > 1 <=> record lives in an inode shard

- `link()` taking nlink 1 -> 2 promotes the record from its path-catalog row
  into a shard, leaving `(inode, shared-flag)` references in both dirents.
- `unlink()` decrements in the shard; nlink 0 deletes the record.
- Demotion when nlink returns to 1 is optional; if skipped, the invariant
  relaxes one direction (`nlink > 1 => promoted`; `shared <=> in shard`).
  If done, only opportunistically at publish while the referencing catalog
  is being rewritten anyway.
- Directories never promote (their nlink counts subdirectories); symlinks
  are ordinary rows. Shards hold regular files only.

Lazy promotion (promote only when a boundary would cut a link group) was
considered and rejected for v1: it buys micro-locality for intra-catalog
link groups — which barely exist in scratch workloads — at the price of a
link-aware splitter and a delicate "unpromoted groups are catalog-local"
invariant. The heavy hitters (conda/pnpm/uv package stores, `git clone` of
local paths) span distant directories and promote under either policy.
Eager promotion makes the "hardlink farms create unsplittable catalogs"
problem structurally impossible rather than mitigated.

Cross-catalog `link()` needs no EXDEV restriction: promotion handles it.

## Integrity and encryption

Two independent mechanisms, cleanly layered:

- **Integrity: the hash tree, always on.** Signature over the superblock ->
  root catalog hash -> catalog rows carry chunk/child hashes -> every byte
  verifies up a Merkle path to the signature. This holds with or without
  encryption. (Rejected: integrity via DEK/AEAD tags — with a public DEK,
  anyone can forge valid tags; a signed-but-unencrypted DEK provides no
  integrity at all. AEAD tags under a secret DEK are redundant with the
  hash tree, which is strictly stronger.)
- **Confidentiality: DEKs, optional and per-ref.** The superblock carries
  a **key table**: key-id -> KEK-wrapped DEK. Every object reference
  (catalog row, shard row, routing entry) records the key-id its target
  was encrypted under (id 0 = plaintext). Catalogs and shards are
  encrypted too — filenames leak otherwise. An unencrypted volume simply
  has an empty key table.

  Making the key-id per-reference rather than per-volume buys three things:
  **encryption as a branch property** — a fork of an unencrypted base can
  introduce a fresh DEK in its own superblock, and everything written
  after the fork is protected while inherited plaintext objects are read
  as-is (the confidentiality boundary is copy-on-write: what diverges is
  protected, what stays shared stays at the base's level); **key
  rotation** — new writes under a new key-id, old objects readable under
  old ids, re-encryption deferred to repack; and **honest declassify
  semantics** — an encrypted base can NOT be forked into a public branch
  by pointer games, because the shared objects stay ciphertext; publishing
  them requires an explicit re-encrypting repack, which is exactly the
  operation a user should have to consciously invoke.

**Chunk identity: keyed content addressing (decided).** The tension:
plaintext hashes give dedup but leak content-equality (an adversary with
a candidate file can test for its presence — the confirmation attack that
plagues convergent encryption); ciphertext hashes with random nonces kill
dedup. Resolution — separate the *identity key* from the *data keys*:

- **Unencrypted volume:** identity = BLAKE3(plaintext). Anyone can verify
  the Merkle path; maximal transparency.
- **Encrypted volume:** identity = BLAKE3 in **keyed mode** with a
  per-volume identity key stored in the superblock key table alongside
  the DEKs. Dedup works fully inside the volume and across its forks
  (forks inherit the identity key even when they introduce a fresh DEK,
  so cross-branch dedup survives encryption changes; a declassify-style
  fork rotates both). No party without the identity key can test content
  presence, and cross-tenant dedup — which we never wanted — is
  structurally impossible. Data encryption stays DEK + random nonce,
  fully independent of identity.
- Identities appear only inside encrypted catalogs/shards/indexes;
  federation-visible object names are never content-derived. Readers
  verify integrity by decrypting a chunk and recomputing its keyed
  identity — every reader of an encrypted volume holds the key table by
  definition, so the Merkle chain stays verifiable exactly where it needs
  to be.
- Rejected: convergent encryption (confirmation attacks by construction,
  breaks rotation); plaintext hashes as object names (leaks equality to
  the whole federation); pure ciphertext addressing (no dedup).

**Chunking parameters (decided, recorded per-volume in the superblock):**
FastCDC with min/avg/max = 1/4/16 MiB, inline threshold 4 KiB (well below
the CDC minimum). Rationale: scientific data dedups modestly, so the
per-chunk costs — a catalog row and a range-GET per chunk — argue for
large chunks; 4 MiB average preserves continuity with the v1 block size,
and a 64 MiB pack holds ~16 chunks. Hash digests are 32 bytes (BLAKE3 in
both modes).

## Read path / write path / publish

The architecture splits **hot** (live session, local) from **cold**
(published, federation). Packs and catalogs are publish-oriented; a live
FUSE mount needs random writes at full POSIX semantics, and teaching a
multi-catalog engine to be the live engine would rewrite the hottest code
in JuiceFS while invalidating its battle-testing.

- **Hot:** exactly today's runtime — live JuiceFS SQLite + local block
  cache + FUSE/NFS frontends. Unmodified in phases 1-2.
- **Publish:** the transactional pipeline below (replaces the v1 whole-DB
  snapshot). Cost is proportional to churn, not volume size.
- **Restore/read:** fetch superblock, verify signature; fetch root
  catalog; hydrate (see the hydration decision below); chunk reads are
  range-GETs into packs, served through federation caches.

### Publish: the transactional pipeline

Publish turns a continuously-mutating hot volume into a consistent
generation without pausing writers. The key inversion: **the cut is
defined by a metadata snapshot taken first, and durability is reconciled
against exactly that cut afterward** — not "flush everything, then
snapshot," which races new writes into the snapshot between the flush and
the cut (a hole v1 carries).

State machine, one publish at a time (single writer, single publisher):

1. **CUT.** Take a consistent local snapshot of the hot metadata (SQLite
   makes this cheap and instantaneous relative to I/O). This defines
   generation N+1's contents; writes continuing during publish belong to
   N+2 and are irrelevant.
2. **RECONCILE.** For every chunk the cut references: if already sealed,
   done; if pending in the spool, seal; if still in a JuiceFS writer,
   flush that inode's writer and seal. Reconciliation touches only the
   cut's dirty set, and force-seals at most one partial pack.
3. **TRANSFORM.** From the cut, regenerate every dirty path catalog and
   inode shard (dirty = owns a row changed since the last published cut —
   in phase 2, a local indexed `changed-since` query; in phase 3 the
   engine maintains the dirty set natively). Flatten slices into extent
   lists; CDC-chunk; dedup against the chunk index; append new chunks,
   small files, catalogs, shards, and the superblock backup into packs.
   Ancestor catalogs of dirty catalogs are dirty too (transition hashes
   change), up to the root. Content addressing makes this idempotent: a
   regenerated-but-identical catalog hashes the same and is skipped.
   **Repack folds in here** as one more transform: live entries of
   condemned packs move into the open pack, and the condemned packs are
   simply omitted from the new pack list — repack becomes
   generation-atomic and grace-windowed by ref retention, rather than a
   separate mutation as in phase 1.
4. **UPLOAD.** All new packs, in parallel. Everything uploaded is
   content-addressed and unreferenced until the flip.
5. **FLIP.** Write the new superblock (root hash, routing, pack list,
   allocator high-water, lineage pointer, signature) via ETag
   compare-and-swap on the ref. CAS failure = concurrent writer: abort
   loudly; uploaded objects are orphans, nothing corrupts.

Crash analysis, by phase: before UPLOAD — nothing remote changed; during
UPLOAD — complete or partial packs exist unreferenced (orphans; rescue can
adopt, GC will sweep); after UPLOAD, before FLIP — a complete generation
exists unreferenced (same); FLIP is atomic. Re-publishing after any crash
re-derives the same content hashes, skips what already uploaded, and
completes — publish is idempotent end to end. If a publish overruns the
interval, the next tick is skipped and its churn coalesces into the
following cut; publishes never overlap.

Readers observe generation N or N+1, never a mixture: the superblock is
the sole entry point, and everything beneath it is immutable.

### Hydration (phase-2 decision)

Phase 2 mounts hydrate the hot engine with **full metadata, lazy data**:
download all catalogs/shards for the pinned generation (parallel,
resumable — compressed metadata for a million files is a few hundred MB,
tens of seconds on decent links, and batch jobs pay it once), build the
hot DB, then fetch chunk data on demand through the block cache. True
lazy *metadata* descent — mount instantly, fault catalogs in on first
lookup — requires intercepting lookups inside the metadata engine and is
deliberately deferred to phase 3, where the catalog-native engine reads
catalogs directly and lazy descent is its natural mode, not a retrofit.
This also restates the earlier read-only caveat: phase-2 refresh is
remount; live generation swap arrives with phase 3.

## Migration phases

1. **Pack store as ObjectStorage middleware.** — **IMPLEMENTED**
   (internal/packstore). Writeback staging batches blocks locally;
   drain-time packing plus indexed range-read GETs fixes small-object
   overhead and read RTTs with zero metadata format change. Packs carry a
   JSON index trailer (entries + tombstones); packs sort by name in
   creation order and later tombstones shadow earlier entries, so a fresh
   session bootstraps by listing packs/ and fetching trailers. Write-side
   packing requires --writeback (Put defers durability to the pack flush;
   flushes precede every metadata snapshot and run at shutdown after the
   staging drain); the read side is always active, so any session — 
   including gc/fsck and non-writeback restores — reads packed volumes.
   Space from deleted entries is reclaimed by a future `pelfs repack`
   (tombstoned entries remain in their packs until then); gc --delete of a
   packed entry from a read-only session is non-durable (the entry
   resurfaces at the next bootstrap — space, never correctness).
2. **Cold format.** Publish/restore of catalogs + shards + superblock;
   JuiceFS remains the hot engine; v1 snapshot machinery (lease, ETag,
   stats) collapses onto the superblock.
3. **Catalog-native runtime.** Replace the hot engine and VFS with our own
   FUSE/NFS filesystem whose live format *is* the catalog format (publish
   becomes "seal", not "translate"), and eject JuiceFS — the pin, the fork
   replaces, and the cgo shims all go with it. Tractable because pelfs is
   single-writer scratch: no distributed sessions, no multi-client
   coherence. JuiceFS is ejected last, after the format has production
   mileage; what is battle-tested by then is our format, not their schema.

## Settled decisions (with rejected alternatives)

| decision | rejected alternative | why |
|---|---|---|
| opaque stable 64-bit inodes | (catalog ID, file ID) composition | splits/renames must not change identity; CVMFS scar |
| catalog located by tree descent | inode -> catalog registry | no consumer needs reverse lookup for nlink==1; registry is pure liability |
| eager promotion of nlink>1 to inode shards | intra-catalog-only hardlinks (EXDEV); lazy promotion | hardlink farms (conda!) make catalogs unsplittable; lazy needs link-aware splitter |
| shards live as own object class, routed by superblock | in superblock; in a path catalog | superblock must stay tiny; path-catalog home re-couples location and rebuilds the hotspot |
| range-friendly packs, CDC for edit sharing | literal git packfile with delta chains | filesystems serve range reads; delta chains force full reconstruction |
| integrity from Merkle + signature | integrity from DEK/AEAD tags | public DEK forges tags; hash tree is stronger and encryption-independent |
| boring small superblock (CBOR/SQLite) | mmap'd minimal perfect hash | wrong cardinality: thousands of rows, not millions |
| 4KB inline threshold (configurable) | 512B | SQLite beats the filesystem below ~10KB; kills most dotfiles/configs |
| hot/cold split; JuiceFS stays live engine until phase 3 | multi-catalog live engine | rewriting JuiceFS's hottest paths forfeits exactly the battle-testing we cited |
| GC = set arithmetic on retained generations' pack lists | mark-sweep over catalog trees | pack lists ARE the closure at pack granularity; no walk, no marking state |
| T_grace age guard makes GC lock-free | GC/writer/fork coordination via lease | new packs are always younger than the guard; fork sources are already retained |
| separate Ed25519 signing key per volume | sign with the KEK | verification is public, decryption is not; unencrypted volumes still need authenticity |
| TOFU + pinning for first-mount trust | mandatory pre-shared pubkey; registry attestation | SSH model works; pelfs stays a pure client, no registry integration (owner's call) |
| time-ordered pack names, trailer hash in pack list | content-hash pack names | age guard + ordering come free; the list-recorded hash gives verification anyway |
| no atime in catalogs | persisted atime | reads must never dirty metadata on a publish-what-changed filesystem |
| migration = drain v1 read-only into fresh v2 prefix | in-place format conversion | dual-format readers forever, for volumes that are by charter scratch |

## Open design work

**The open list is empty.** Every item from earlier drafts is now settled
in a section above: publish transactionality (CUT/RECONCILE/TRANSFORM/
UPLOAD/FLIP, repack folded into TRANSFORM); chunk identity (keyed BLAKE3,
FastCDC 1/4/16 MiB); phase-2 hydration; versioned pack lists; catalog
split heuristics (measured: peel-largest-child, W = 200·entries +
inline bytes, S_max 8 MiB / S_min 1 MiB); retention and GC (set
arithmetic on pack lists, T_grace age guard replaces locking); signing
and key management (Ed25519 volume identity separate from KEK, TOFU
pinning, custody-chain rotation); federation namespace layout (refs/,
tags/, leases/, packs/; time-ordered pack names, no manifest object);
catalog schema (atime dropped, prefix-sum chunkrefs, JuiceFS
session/trash/lock tables removed); benchmarks and acceptance criteria;
and the migration decision (drain-and-copy, never in-place).

Deliberately deferred, not open — these need external partners or
production mileage, not more design:

- **POSIX ACLs** (schema section): out of scope for v2.0; xattrs carry
  them opaquely if a frontend ever needs them.
- **`pelfs rescue` implementation.** Fully specified by the
  disaster-recovery section; its format prerequisites (typed entries,
  self-identifying catalogs, in-pack superblock backups) are pinned to
  land with phase 2 because retrofitting leaves early volumes
  unrescuable. What remains is code, not design.
- **Compression dictionaries** for small-chunk cohorts: measure first.

## Relationship to v1 components

Survives unchanged: pelicanobj transports, preflight, token machinery,
Docker/NFS/FUSE frontends, stats, prefetch (walks catalogs instead of
ScanSlices), lease (degenerates to superblock ETag guard). Replaced: the
block-per-object layout, whole-DB snapshots, and — in phase 3 — the JuiceFS
runtime itself.
