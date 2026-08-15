# pelfs v2 format: packed objects, split catalogs, signed superblock

Status: **design draft** — settled at the architecture level, open questions
listed at the end. Nothing here is implemented yet; v1 (JuiceFS-native
storage) is what ships today.

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

The federation prefix holds exactly four kinds of objects. All but the
superblock are content-addressed (named by hash) and immutable.

```
<prefix>/
  superblock            <- the ONLY mutable object; small, signed, ETag-guarded
  packs/<hash>          <- immutable packs: data chunks, small files, catalogs,
                           inode shards, pack indexes
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
shards. Target pack size and the open-pack append strategy are open
questions (see below).

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
  merge back at S_min << S_max — hysteresis prevents thrashing.
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

Open interaction (see open questions): content addressing over plaintext
leaks equality between chunks to anyone who can see object names/indexes;
addressing over ciphertext destroys dedup unless convergent encryption is
used. Current leaning: hash plaintext for dedup, encrypt with DEK + random
nonce, keep hashes only inside encrypted indexes/catalogs, name federation
objects by an outer (ciphertext) hash. Needs a decision.

## Read path / write path / publish

The architecture splits **hot** (live session, local) from **cold**
(published, federation). Packs and catalogs are publish-oriented; a live
FUSE mount needs random writes at full POSIX semantics, and teaching a
multi-catalog engine to be the live engine would rewrite the hottest code
in JuiceFS while invalidating its battle-testing.

- **Hot:** exactly today's runtime — live JuiceFS SQLite + local block
  cache + FUSE/NFS frontends. Unmodified in phases 1-2.
- **Publish** (replaces the v1 whole-DB snapshot): walk dirty subtrees;
  flatten JuiceFS slices into contiguous chunk extents (fragmentation from
  small writes compacts away here, for free); CDC-chunk large files; append
  chunks/small files to an open pack; rewrite dirty catalogs and shards;
  upload packs -> catalogs -> shards -> superblock, in that order, so a
  crash mid-publish leaves only unreferenced garbage, never a broken
  generation; flip the superblock last (ETag-guarded). Publish cost is
  proportional to churn, not volume size.
- **Restore/read:** fetch superblock, verify signature; fetch root catalog;
  hydrate catalogs lazily on directory descent; chunk reads are range-GETs
  into packs, served through federation caches.

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

## Open design work

Roughly ordered by how much they block implementation:

1. **Publish transactionality details.** Dirty-subtree tracking in the hot
   layer; whether publish runs against a frozen view (copy-on-publish) or
   tolerates concurrent writes; crash recovery mid-publish (safe by upload
   ordering, but needs an orphan-sweep story); publish duration targets.
2. **Pack lifecycle and GC.** Target pack size; open-pack append vs
   session-scoped packs; repack policy for sparse packs; multi-root
   mark-sweep from the union of all refs (see the refs section) vs
   refcounts; how long superseded generations' objects must live
   (reader-pinning grace period); ref-listing atomicity vs concurrent
   fork/branch creation; Pelican DELETE granularity (whole packs only — a
   nice property: the GC unit is the pack).
3. **Chunking and hashing parameters.** FastCDC min/avg/max (interacts with
   the 4KB inline threshold and pack size); hash algorithm (BLAKE3 vs
   SHA-256) for content addressing; the dedup-vs-confidentiality decision
   for encrypted volumes (plaintext-hash inside encrypted indexes vs
   convergent encryption vs no cross-file dedup).
4. **Phase-2 lazy hydration mechanics.** How a restored session populates
   the live JuiceFS engine per-catalog on descent (a meta wrapper that
   faults in catalogs? full metadata hydration as an interim?). This is
   the least-designed piece of phase 2.
5. **Catalog split heuristics.** Weight function (entries vs bytes vs
   inline data), S_max/S_min values, split-point search; validate against
   real trees (conda env, linux kernel, home directory).
6. **Superblock signing and key management.** Same key as KEK or a separate
   signing identity; key rotation; what a reader trusts on first mount
   (TOFU vs pinned key vs federation-issued).
7. **Federation namespace layout.** Object naming (outer hash), prefix
   layout, how gc/fsck/`pelfs`-tooling enumerate packs efficiently
   (PROPFIND vs a pack manifest object).
8. **Schema details.** Dirent/record column layout, xattrs, special files,
   sparse files; what of the JuiceFS schema is kept vs dropped (sessions,
   trash, counters all go).
9. **Benchmarks and acceptance criteria.** conda env create, git clone,
   kernel untar, JupyterLab cold-start; targets for publish latency and
   mount-to-first-byte.
10. **v1 -> v2 migration.** Probably "none — scratch volumes drain and
    recreate," but that should be an explicit decision, and phase 1's pack
    middleware must not paint v1 volumes into a corner.

## Relationship to v1 components

Survives unchanged: pelicanobj transports, preflight, token machinery,
Docker/NFS/FUSE frontends, stats, prefetch (walks catalogs instead of
ScanSlices), lease (degenerates to superblock ETag guard). Replaced: the
block-per-object layout, whole-DB snapshots, and — in phase 3 — the JuiceFS
runtime itself.
