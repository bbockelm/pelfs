# The pelfs format: packed objects, split catalogs, signed superblock

Status: **shipped** — this format is what pelfs is. Every section below
describes the system as built, with two exceptions that are marked in
place and listed together under "Designed, not built". Considered-and-
rejected alternatives live in Appendix B; the engine this format replaced
is Appendix A.

In one sentence: **writable CVMFS with restic-style packs** —
content-addressed immutable packs and split catalogs, with a single small
signed mutable superblock as the trust and consistency root.

## What a volume is

The federation prefix holds exactly four kinds of objects. Everything
under `refs/` is mutable and guarded on ETag; everything else is
immutable.

```
<prefix>/
  refs/<branch>         mutable superblocks (branch heads)
  tags/<name>           immutable superblocks (frozen generations)
  meta/lease.json       advisory liveness beacon, one per volume
  packs/p-<ts>-<rand>   immutable packs: data chunks, small files,
                        catalogs, inode shards, superblock backups
```

Pack names stay time-ordered (`p-<unixnano hex>-<rand>`) rather than
content-derived: the age guard in GC and the creation ordering come free,
and integrity does not need hash *names* — each generation's pack list
records the trailer hash, so a fetched pack verifies against the list.
Normal operation never lists the namespace: the superblock carries the
pack set, and refs and tags are addressed by name. Listing is needed only
by GC. No manifest object exists.

## Packs

A pack is a concatenation of **independently compressed (and encrypted)
entries**, plus an index mapping `entry-key -> (offset, length)`. Any
entry is retrievable with a single HTTP range request — Pelican origins
and caches serve ranges natively, so the FORMAT never requires a whole
object to serve one entry. Whether a reader exercises that is its own
policy, and the shipped reader does not: it takes packs whole and relies
on a small cut size instead (see "Whole packs, not ranges").

Packs hold everything: data chunks, whole small files, catalogs, inode
shards, and one superblock backup per publish.

### Byte layout

A pack is entry bytes, then a JSON index trailer, then a fixed 16-byte
footer — nothing else, and nothing at the front. There is no header,
because the local spool file must already be the final layout and a
header would have to be rewritten at seal time.

```
offset 0
+------------------------------------------------------------+
| entry 0 bytes   (independently compressed, then encrypted)  |
| entry 1 bytes                                               |
| ...              byte-packed, no alignment padding          |
| entry N-1 bytes                                             |
+------------------------------------------------------------+  <- trailer_off
| trailer: zstd-compressed JSON, unencrypted                  |
|   (decompressed:)                                           |
|   {                                                         |
|     "v": 1,                                                 |
|     "created_ms": 1755300000000,                            |
|     "entries": [        // sorted by key                    |
|       {"k":"<key>", "o":<offset>, "l":<length>,             |
|        "t":"catalog"},  // "t" omitted for data entries     |
|       ...                                                   |
|     ]                                                       |
|   }                                                         |
+------------------------------------------------------------+
| footer, 16 bytes:                                           |
|   [0:8)   uint64 little-endian = STORED trailer length      |
|   [8:16)  magic "PELFSPK2"                                  |
|           ("PELFSPK1" = uncompressed-JSON trailer,          |
|            still read, never written)                       |
+------------------------------------------------------------+
```

The two footer magics are a real wire distinction and the only versioning
the container has: `PELFSPK1` marks a plain-JSON trailer and is accepted
forever; every pack written today is `PELFSPK2`. The trailer struct also
carries a `"dead"` tombstone list, which nothing writes and nothing reads
— it belonged to a shadowing scheme this format does not use (Appendix A)
and survives only as a field.

Locating what a pack holds takes at most two range requests: a fixed-size
tail probe (128 KiB, `packstore.tailProbe`) — the magic and trailer length
sit at the very end, and the trailer is usually inside the probe — and, if
the trailer is longer than the probe, one exact range read for the rest.
There is no separate index object and no index at the front: the trailer
IS the index, and putting it at the end is what lets the local spool file
upload verbatim.

`"o"`/`"l"` are relative to the pack start and locate the
COMPRESSED+ENCRYPTED entry bytes. How to decode them — compression algo,
key id — is recorded in the record that referenced the entry (catalog
chunkref columns), never sniffed from the bytes.

**Entry types** (`"t"`): absent for data chunks, `"catalog"`, `"shard"`,
`"sb"` for a superblock backup, so rescue can inventory a namespace from
packs alone.

**Trailer hash**: the superblock's pack list records BLAKE3-256 of the
STORED trailer bytes, so a reader verifies the location map right after
the tail read, before even decompressing. Entry data integrity does not
depend on this — chunk identities are end-to-end.

Index cost: ~100 bytes of JSON per entry before compression; zstd takes
the structural repetition out, leaving mostly the incompressible hash keys
(~40–50 B/entry stored). Measured across a Linux 6.6 corpus, trailers are
0.84–0.86% of stored bytes at every cut size from 1 to 64 MiB — the ratio
is set by entry size, not by pack size, so cutting smaller costs objects
and pack-list rows, not container overhead. JSON-inside-zstd is
deliberate: rescue tooling gets human-legible structure for the cost of a
`zstd -d`.

### Compression and encryption are per entry

Each entry is independently compressed, and the algorithm is recorded
explicitly (an algo id in the referencing record — never sniffed from
magic bytes) so it is per-entry flexible: zstd by default, `none` under a
store-if-smaller policy (compress, keep the smaller of the two — the
git/borg trick that avoids paying for incompressible data), future
algorithms are new ids. Order is compress-then-encrypt; encrypting first
would destroy compressibility. Encryption is AES-256-GCM with a random
12-byte nonce prepended. Entries are byte-packed with **no alignment
padding**: HTTP range requests are byte-granular and the local cache reads
whole entries, so alignment would pay only if packs were mmap'd locally.

(Noted: compressed sizes leak through encryption, a CRIME-family side
channel accepted for a scratch filesystem.)

This resolves the classic tension between sub-pack fetching and
compression ratio in favor of fetching: per-entry compression makes every
entry independently range-readable, at the cost of losing cross-file
compression context. Two mitigations keep the ratio loss small: tiny files
mostly live *inline in catalogs*, so pack entries skew large, where
per-entry zstd approaches solid ratios anyway; and if small-entry corpora
ever matter, a per-pack zstd dictionary would recover most of the gap
while preserving per-entry independence.

### Cut size, the ramp, and upload concurrency

Target pack size is **2 MiB** (`publish.DefaultTargetPackSize`). Because a
reader fetches packs whole, the cut size is the granularity of every
transfer it makes — the publisher's answer to "what does one small file
cost", which is not a question a reader can answer for itself. The sweep
behind the number is under "Whole packs, not ranges".

**The first packs of a publish are cut smaller** — 1 MiB, doubling until
the cut size reaches the target — because nothing can be uploaded until a
whole pack exists. Cutting only at the target leaves the uplink idle
through the first packful of walking and then has to drain the remainder
after the walk is over; starting small is the same trade as TCP slow
start. Measured against a modelled link on a 185 MiB seal, the ramp takes
the share of the seal with nothing in flight from 2.0% to 0.5% at 20 Mb/s
and from 18% to 3% at 1 Gb/s, and moves the first byte from 1.6 s into the
seal to 0.3 s. (Those figures were taken at a 64 MiB target with an 8 MiB
ramp; the shape of the argument is unchanged at 2 MiB from 1 MiB, the
magnitude is smaller.) It costs at most three extra packs however large
the volume — and a pack is never free again, because it is a row in every
superblock from now on. In wall time the ramp is worth −1.6% at 20 Mb/s
and −6.5% at 100 Mb/s against +6% on a 1 Gb/80 ms path, where the seal is
limited by how fast the walk produces packs and the extra round trips are
the whole cost. The trade is taken toward the slow link deliberately: that
is where a seal is 80 s rather than 9 s.

**Pack uploads run four at a time.** The number is a property of the link,
not of the format. On a bandwidth-bound uplink the streams only divide the
same pipe — measured seal wall time at 20 Mb/s is flat from one stream to
eight — while on a long-fat path a single stream is window-limited and
cannot fill the pipe alone: at 1 Gb/s and 80 ms RTT the same seal takes
17.1 s with one stream, 11.7 s with two, 9.0 s with four, and nothing more
with eight. Four is where that curve flattens. It stays settable
(`publish.Options.UploadConcurrency`) because a data-centre node and a
laptop sharing its uplink with a mount that is still serving reads do not
want the same answer.

### The spool file

The accumulating structure on the write side is a local spool file — an
append-only file whose byte layout is already the final pack layout, plus
an in-memory key -> (offset, length) table. There is no merge step:
cutting a pack appends the index trailer and uploads the spool verbatim.
Reads of not-yet-flushed entries are served from the spool. The spool is
not mmap'd (plain `WriteAt`/`ReadAt`; mmap of a growing file buys remap
churn, not speed).

## Reading

### Whole packs, not ranges

A pack is immutable and content-addressed, so it is the natural unit for
a reader's cache. It is also the unit of transfer: a mount fetches a pack
whole on the first entry anyone wants from it, and never reads one in
pieces. `genfs.Options.PackCacheBytes` bounds the cache; a **negative**
value turns whole-pack fetching off and leaves reads on coalesced ranges —
the setting for a client with less disk than bandwidth, and the only
configuration in which a pack is read in pieces at all. A pack larger than
256 MiB is never taken whole, and any whole-pack failure degrades to
ranges.

Swept against a Linux 6.6 checkout (81,690 files, 255 MiB stored) at a
modelled 20 ms round trip, with each read measured both ways — packs
whole, and on coalesced ranges, which is the floor on bytes moved:

| cut | packs | pack list | cold mount | walk 2026 files | 100 scattered files |
|-----|-------|-----------|------------|-----------------|---------------------|
| 1 MiB | 256 | 21.7 KiB | 3 GET, 2.4 MiB | 1.3 s, 36.4 MiB (1.0x) | 2.2 s, 81.8 MiB (2.0x) |
| 2 MiB | 131 | 11.1 KiB | 3 GET, 2.4 MiB | 0.9 s, 21.8 MiB (1.1x) | 1.7 s, 95.0 MiB (3.8x) |
| 4 MiB | 65 | 5.5 KiB | 2 GET, 4.1 MiB | 0.8 s, 15.8 MiB (1.3x) | 1.2 s, 138.9 MiB (8.2x) |
| 8 MiB | 33 | 2.8 KiB | 2 GET, 6.0 MiB | 0.8 s, 20.4 MiB (2.5x) | 1.0 s, 197.5 MiB (15x) |
| 16 MiB | 17 | 1.4 KiB | 2 GET, 13.6 MiB | 0.7 s, 36.0 MiB (4.7x) | 1.0 s, 245.6 MiB (19x) |
| 64 MiB | 5 | 433 B | 3 GET, 62.5 MiB | 0.7 s, 66.8 MiB (11x) | 0.6 s, 195.7 MiB (18x) |

Multipliers are against the ranged floor. Read the two workload columns
as the two halves of the trade:

- **The walk wins outright.** Reading everything under one directory took
  29–31 s on ranged reads at every cut size, because a source tree is
  tens of thousands of files each stored as exactly one chunk and there
  is nothing to coalesce across them. Whole packs answer it in 0.7–1.3 s
  — about 40x — and at 1–4 MiB they move roughly the bytes the ranged
  reader moved anyway. This is the workload the policy exists for.
- **Scattered reads lose, and the cut size is the whole dial.** One
  hundred small files picked at random across the tree wanted 368 KiB;
  ranged reads moved 11–41 MiB (most of it locating packs), whole packs
  moved 82–246 MiB. That is 2x the floor at 1 MiB and 17x at 64 MiB.
  Wall time is nevertheless BETTER whole-pack at every size, because
  there are fewer round trips — so the loss is real on a bandwidth-bound
  link and invisible on a latency-bound one.

2 MiB is the balance point and the shipped default: the walk costs 10%
over the floor and the scattered penalty is under 4x. 4 MiB moves the
fewest bytes on a walk and is the better setting for a volume read in
bulk. Below 1 MiB the fixed 128 KiB tail probe starts to dominate what
locating a pack costs at all.

The cost that does not appear in the table: every pack is a row in this
generation's pack list and in every superblock after it, since publish
carries the list forward. The list grows as volume size over the cut size,
so a volume two orders of magnitude larger than this corpus wants a
proportionally larger cut.

### Locations resolve on demand

A catalog names an entry's identity; a trailer says which pack holds it.
A mount needs exactly one of those answers to serve its first question —
where the root catalog lives — so it does not index the generation to
start. Probing runs newest-pack-first, with a budget of four serial
probes, which is a good bet because publish appends this generation's
packs after the ones it carried forward and writes the root catalog last.

Measured at three pack counts, before and after (cold mount to first
readdir, 20 ms modelled round trip):

| packs | eager index | on demand |
|-------|-------------|-----------|
| 12 | 66 ms, 13 GET, 1.3 MiB | 44 ms, 2 GET, 6.3 KiB |
| 102 | 302 ms, 103 GET, 12.5 MiB | 44 ms, 2 GET, 31 KiB |
| 1002 | 2.9 s, 1003 GET, 125 MiB | 44 ms, 2 GET, 268 KiB |

Two rules keep it honest. **Absence is only ever reported from a complete
map**: "present in no listed pack" fails a read, and a seal's
carry-forward check would read it as "this content is gone", so the probe
resolves every listed pack before saying it. And the callers that reason
about content they are not about to read — `fsck`, a seal's carry-forward
check, a prefetch — ask for the whole map explicitly rather than relying
on a mount having built it.

The bet on recency loses for a chunk in an old pack. Past the probe budget
the rest of the map resolves at once: at 1002 packs that first old read
costs 1001 GETs and 125 MiB — precisely what an eager index would charge
every mount — and never again, since verified trailers are kept on disk.
Recording a location in the superblock would remove even that; see "Open
format questions".

## Catalogs

A catalog covers a subtree of the namespace. Each is a self-contained
blob, packed, content-addressed by BLAKE3 over its bytes, and carried
forward by reference into later generations whose subtree did not change.

What a catalog holds, independent of encoding:

- **metadata** — volume UUID, covered path, identity algorithm: the
  self-identification rescue needs.
- **nodes** — `inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink,
  length, rdev, keyid, flags`. **No atime**: persisting it would dirty
  catalogs on read, an absurdity on a publish-what-changed filesystem.
  Special files (fifo, dev, socket) store as types with `rdev`; the NFS
  frontend may refuse to expose some.
- **edges** — `(parent, name) -> inode, type`.
- **nested** — transition points: `(parent, name) -> child catalog
  identity`. A transition directory carries BOTH halves in the parent
  catalog: its edge and node rows, so lookup and stat of the directory
  itself never fetch the child, plus the nested locator; only descending
  into its entries opens the child.
- **chunkrefs** — `(inode, idx) -> identity, llen, clen, alg, keyid`.
  Logical offsets are prefix sums of `llen` at load. Sparse holes are
  *not* preserved: they materialize as zero bytes through the chunker, so
  content stays byte-exact and sparseness does not.
- **inline** — bytes for small files, stored RAW, because the catalog is
  itself zstd-compressed as one pack entry and per-row compression would
  only degrade the catalog-level ratio.
- **xattrs** and **symlink targets**.

Catalogs contain **only** records with `nlink == 1`, plus references to
promoted inodes (see hardlinks). That makes every directory boundary a
legal split point unconditionally — the splitter needs no hardlink
awareness.

Catalog and shard entries are always zstd-compressed and encrypted under
the single key named by the superblock's `catalog_key_id` (0 =
plaintext). Unlike chunks, their references carry no per-entry alg/keyid
columns, so the encoding is stated once, never sniffed.

### Two encodings

Catalogs are written in a **static, mmap-friendly packed format**
(`PELFSCAT`), specified in `design-catalog.md`. A SQLite encoding also
exists and is still read; `publish.Options.SQLiteCatalogs` selects it for
writing. A reader dispatches on the blob's first bytes, so a generation
may reference both, and switching the default converted nothing — a volume
stays mixed until every subtree has been touched. Converting in bulk would
give every catalog a new identity and re-upload the whole namespace.

The static format was worth building: on an 80k-file tree it reseals the
whole tree in 0.61 s against 3.03 s, seals a one-file change in 217 ms
against 535 ms, and lets a mount fetch 1.2 MiB instead of 1.8. The reason
is in `design-catalog.md`, and the sharpest part of it is that the SQLite
encoding stamps the generation into its metadata, so an unchanged subtree
hashed differently every seal and silently defeated reuse.

### Inline data

Files at or below `publish.DefaultInlineMax` — **2048 bytes** — are stored
directly in the catalog. No federation object exists for them, and the
metadata fetch carries their content.

The threshold is a two-sided trade, swept over a real kernel tree in
`TestInlineMaxSweep` and written up in `design-writepath.md`. The
counter-intuitive half: inlining is what makes catalogs *numerous* rather
than large, and catalog count is what makes an incremental seal cheap. At
4096 one changed file rebuilds 23% of the namespace; at 1024 it rebuilds
63%. 2048 is the deliberate middle — it halves the catalog bytes a seal
must move at exit against 4096 (11.2 MiB against 19.9 on that tree) while
a one-file change still rebuilds only 41%.

### Splitting

When a catalog exceeds its threshold it splits at a directory boundary
chosen by subtree weight; the parent carries a transition-point row (the
CVMFS nested-catalog scheme). Split at `S_max`, merge back at
`S_min << S_max` — hysteresis prevents thrashing. Policy and thresholds
are **measured**, not guessed: simulation over four real trees (a
miniconda root, a node_modules, glibc, and a 16 GB/677K-entry Go module
cache).

**Weight function:** `W = 200·entries + inline_bytes (+ xattr bytes)`.
Measured structural cost is 176 B/entry, so 200 is mildly conservative.
Inline bytes MUST be in the weight — they dominate real catalogs (62–91%
of files inline across the sample trees; 46 of 59 MB of a miniconda's
catalog weight is inline data). An entry-count threshold alone (CVMFS's
choice) would produce wildly variable catalog sizes here.

**Policy: bottom-up, peel largest child first.** Walking post-order, a
directory whose accumulated weight exceeds `S_max` detaches its largest
attached child subtree (which becomes a nested catalog), repeating until
it fits. The naive alternative — detach the whole directory when it
exceeds — measurably fails: a directory of many medium children detaches
as one catalog 10–15x over threshold. Peeling keeps p95 <= `S_max` on
every sampled tree.

**Thresholds: `S_max` = 8 MiB, `S_min` = 1 MiB** (merge a nested catalog
below `S_min` into its parent only if the parent stays under `S_max`; 8:1
hysteresis). At 8 MiB: miniconda = 31 catalogs (nest depth <= 3),
node_modules = 87, glibc = 10, Go module cache = 527 (depth <= 4, zero
pathological). 2 MiB explodes catalog counts (1,447 for the module cache,
depth 6) for no churn benefit; 32 MiB collapses miniconda to two catalogs,
making a one-file touch republish ~30 MB.

**Flat-directory exception:** a single directory whose own rows exceed
`S_max` cannot split (catalog roots are directories) and remains one
oversized catalog. It is not a special case in the code so much as where
the peeling loop runs out of children. Measured worst case:
`@mui/icons-material` at 13.3 MiB (thousands of tiny inlined files in one
directory) — under 5 MiB compressed, tolerable, and rare.

### Carry-forward

An unchanged subtree's catalog is referenced, not rewritten. Publish arms
this before the walk (`internal/publish/catalogreuse.go`) and refuses it
wholesale unless the previous generation exists, the seal builds directly
on it, and `S_max`, `InlineMax` and the catalog key id all match — any of
those changes what the bytes would be. Per subtree it additionally
requires that nothing below is dirty, that the previous generation rooted
a catalog at exactly that path, and that the span holds no promoted
inodes. A pruned subtree is one the seal never reads at all, which is the
difference between "did not rewrite the tree" and "did not look at it".

## Inode shards

Structurally identical to catalogs — same blob-in-pack shape — but keyed
by **inode** instead of path. They hold the content records (chunkrefs,
inline, xattrs) of promoted (`nlink > 1`) files. Promoted inodes keep
their node row in every referencing path catalog as well, so a stat from a
path catalog needs no shard fetch, and the shard stays authoritative for
content.

Shards are contiguous inode ranges, split when a range grows past a
target weight; the routing lives in the superblock as
`(first_inode, last_inode, identity)`. Because they partition by sort
order rather than tree structure, shards can never form unsplittable
atoms. Monotonic inode allocation gives temporal locality for free: newly
promoted inodes land in the tail shard, publish churn concentrates there,
and old shards go cold and live in federation caches indefinitely.

## The superblock

The single mutable object and the root of both trust and consistency. It
is CBOR, encoded deterministically, loaded fully into RAM, and signed with
the signature field zeroed.

| field | purpose |
|---|---|
| `FormatVersion`, `Generation` | identify and order snapshots |
| `VolumeID`, `CreatedUnixNano` | volume identity, timestamp |
| `RootCatalog` | entry point of the namespace |
| `Shards` | inode-shard ranges -> catalog identity |
| `PackList` | name, size, trailer hash per pack: the generation's pack set |
| `NextInode` | allocator high-water mark |
| `KeyTable` | key-id -> KEK-wrapped DEK or identity key |
| `CatalogKeyID` | the one key catalogs and shards are encrypted under |
| `Params` | `SMaxBytes`, `SMinBytes`, `InlineMax`, `TGraceSeconds`, `RetainK` |
| `Catalogs` | a seal-planning hint, not routing — see below |
| `Condemned` | repack's ledger of dropped packs (no writer yet) |
| `PrevHash` | lineage: snapshot history, fork detection |
| `SigningPub`, `NextPub`, `Signature` | trust root and rotation |

**Nothing in the superblock says where any identity lives.** `Catalogs`
carries `(inode, identity, path, weight, promoted)` for each catalog in
the generation, and exists so the next seal can plan reuse; a reader needs
nothing from it. There is no identity-to-pack map anywhere except a pack
trailer, which is why a cold mount probes trailers newest-first. The
options for changing that are under "Open format questions".

A minimal-perfect-hash mmap structure was considered and rejected: the
superblock has one row per catalog or shard, far below where MPH pays.

Because everything else is immutable and content-addressed, the superblock
is the only object a *reader* ever depends on that mutates, and the only
thing a reader must re-fetch to observe a new generation. Federation
caches work at full strength for all data and all metadata; `?directread`
is needed only for the superblock and for the advisory lease.

That "only" is a trap, and we fell into it. Because the direct-read
requirement applies to just two objects, it was originally satisfied at
each call site — and an audit found three of four `refs.New` callers
passing a cache-served store, including the mount itself. The symptom on a
real federation was not a stale read but an md5 mismatch on `refs/main`: a
cache that mis-reports object length returns a truncated body, so a
caching bug arrives disguised as corruption. The invariant now lives
inside `refs.New` and `lease.Acquire`, which switch any store they are
handed to its direct variant. Rule of thumb: an invariant that holds for
exactly the objects one package owns belongs inside that package, not in
its callers' heads.

## Identity versus location

A snapshot must capture *what* every file's chunks are without freezing
*where* they live, or repack would invalidate history. The decomposition:

- **Identity lives in catalogs.** A file's row records its chunk list as
  content hashes — location-free, which is what lets an unchanged
  subtree's catalog stay hash-identical (and therefore shared) across any
  number of generations.
- **Location lives in pack trailers, versioned by the superblock's pack
  list.** Trailers are immutable and shared; each superblock records the
  *set of packs* that constitutes its generation — a per-pack list, not a
  per-chunk map, so it stays small (hundreds of entries for a
  million-chunk volume, versus tens of MB for a chunk-level manifest).
  Resolution is: identity -> this generation's pack set -> trailer ->
  range.

Consequences:

- **Tagged generations never rot.** A generation pins its pack set; a
  repack would emit a *new* generation whose list routes moved chunks to
  the new pack, while retained older generations keep their old packs
  alive. GC's pack-liveness question is simply "does any retained
  generation's pack list name this pack", plus the reader grace window.
- **Repack would be metadata-free**: catalogs never change; only the next
  superblock's pack list does.
- File versioning in the user-visible sense falls out: mount any tagged
  generation for its point-in-time tree; a file's versions across
  generations are different chunk lists in mostly-shared catalogs, with
  content-defined chunking and content addressing sharing every unchanged
  chunk between versions. Retention policy is ref and tag retention.

## Refs: branches, tags, and forks

A superblock generation is already a commit: immutable once written,
signed, parent-linked via the lineage hash, rooting an immutable object
graph. Refs add the missing distinction between a commit and the *name*
pointing at it:

- **Branch** — a mutable ref object (`refs/<name>`), advanced by publish.
  Each is independently guarded and covered by the advisory lease. A bare
  prefix mounts `refs/main`.
- **Tag** — an immutable ref: a frozen superblock under a name, never
  overwritten. Costs one tiny object; everything it references is shared.
  Read-only tag mounts are the pinned-generation mounts. *Reading* a tag
  is wired up (`--tag`); `refs.Store.Tag` exists but no command calls it,
  so tags cannot currently be created through the CLI.
- **Fork** — a new ref whose first superblock's parent is the forked
  generation, giving copy-on-write over the whole volume. **Not
  implemented.** The rules below are the design it would have to obey.

Consequences, deliberate and otherwise:

- **Single-writer becomes single-writer per branch.** Writers on different
  branches never conflict: disjoint superblocks, shared immutable objects,
  and content-addressed pack uploads collide only on identical content.
  This enables the fan-out batch pattern — one tagged base environment, N
  jobs each forking a private writable branch and publishing results as
  tags.
- **Fork rule (GC soundness):** forking is allowed only from ref-reachable
  generations — a branch's history within the GC grace window, or any tag.
  To fork something older, tag it first. This closes the race between
  forking a generation and GC condemning it.
- **Inode uniqueness is per-lineage.** Fork descendants allocate from the
  same counter and may assign equal inode values to different files —
  harmless, since inodes need uniqueness only within a mounted tree and
  branches mount separately. A future cross-branch *merge* would need to
  renumber one side; merge is explicitly out of scope, and this rule is
  why.
- Retention becomes explicit: tags are the user-controlled form of keeping
  a generation; anonymous generations get the `T_grace` window. Keep what
  you name, grace-window the rest.

## Concurrency: the ref guard, and the lease as a courtesy

The volume has exactly **two** mutable objects, with disjoint roles:

- **Superblock — consistency.** The publish-time flip re-stats the ref and
  refuses if its ETag moved since the fetch (`refs.ErrStaleFlip`). If two
  writers race, the loser's flip fails: its packs are uploaded but
  unreferenced (orphans for GC), nothing interleaves, nothing corrupts.
  This is **check-then-put, not a true compare-and-swap** — the transport
  has no `If-Match` — so the window is narrow rather than zero. A separate
  monotonicity guard (`refs.ErrRollback`) refuses a branch head older than
  the newest generation this client has already accepted.
- **Lease — liveness (advisory).** Heartbeat plus TTL plus takeover
  warning, at `meta/lease.json`. Its only job is preventing *wasted work*:
  fail fast at mount instead of at the first failed publish, warn
  mid-session on takeover. It is unsigned, not content-addressed, never
  read by read-only mounts, and its loss or corruption affects no data.
  `--no-lease` skips it; `--steal-lease` overrides a live one.

Given that the flip is not atomic, the lease is doing more work than
"courtesy" implies. It is the only thing standing between two writers and
a lost generation, and it is advisory.

## Signing, keys, and trust

- **Two keys, two jobs.** The volume *signing* keypair (Ed25519, generated
  at volume creation) authenticates superblocks; the user KEK — an RSA
  private key, `--encrypt-key`, unlocked by `$PELFS_KEY_PASSPHRASE` —
  wraps DEKs and the identity key for confidentiality. They have different
  lifecycles and different audiences: every reader verifies signatures,
  only key-holders decrypt. An unencrypted volume still has a signing key.
- **First-mount trust**: an explicit `--volume-pubkey`, else
  trust-on-first-use with the key pinned under the state directory
  (`refs/volume.pub`) and loud errors on change — the SSH model.
  Registry-issued attestation is explicitly out: pelfs stays a pure client
  of dumb federation storage.
- **Rotation:** a superblock may introduce a successor public key
  (`NextPub`), signed by the current key; readers follow the custody chain
  through lineage in `VerifyChain`. Verification is implemented; **nothing
  in the CLI sets `NextPub`**, so rotation cannot be initiated today.
  Compromise recovery is out-of-band re-pinning — custody chains cannot
  distinguish a stolen key's rotation from a legitimate one.
- **Threat model, stated honestly:** the federation origin is dumb storage
  and cannot verify signatures, so a compromised *write token* permits
  clobbering the mutable ref objects — an availability attack. Signatures
  make forgery detectable (readers reject), and lineage plus in-pack
  superblock backups make recovery mechanical. Integrity holds;
  availability under token compromise does not, and no client-side design
  can change that.

## Integrity and encryption

Two independent mechanisms, cleanly layered:

- **Integrity: the hash tree, always on.** Signature over the superblock
  -> root catalog identity -> catalog rows carry chunk and child
  identities -> every byte verifies up a Merkle path to the signature.
  This holds with or without encryption.
- **Confidentiality: DEKs, optional and per-ref.** The superblock carries
  a key table: key-id -> KEK-wrapped key. Every object reference records
  the key-id its target was encrypted under (id 0 = plaintext). Catalogs
  and shards are encrypted too — filenames leak otherwise. An unencrypted
  volume simply has an empty key table.

  Making the key-id per-reference rather than per-volume buys three
  things: **encryption as a branch property** — a fork of an unencrypted
  base can introduce a fresh DEK in its own superblock, and everything
  written after the fork is protected while inherited plaintext objects
  are read as-is; **key rotation** — new writes under a new key-id, old
  objects readable under old ids, re-encryption deferred to repack; and
  **honest declassify semantics** — an encrypted base can NOT be forked
  into a public branch by pointer games, because the shared objects stay
  ciphertext.

**Chunk identity: keyed content addressing.** The tension: plaintext
hashes give dedup but leak content-equality (the confirmation attack that
plagues convergent encryption); ciphertext hashes with random nonces kill
dedup. Resolution — separate the *identity key* from the *data keys*:

- **Unencrypted volume:** identity = BLAKE3(plaintext). Anyone can verify
  the Merkle path; maximal transparency.
- **Encrypted volume:** identity = BLAKE3 in **keyed mode** with a
  per-volume identity key stored in the key table alongside the DEKs.
  Dedup works fully inside the volume and across its forks, since forks
  inherit the identity key even when they introduce a fresh DEK. No party
  without the identity key can test content presence, and cross-tenant
  dedup — which we never wanted — is structurally impossible. Data
  encryption stays DEK plus random nonce, fully independent of identity.
- Identities appear only inside encrypted catalogs, shards and indexes;
  federation-visible object names are never content-derived. Readers
  verify integrity by decrypting a chunk and recomputing its keyed
  identity — every reader of an encrypted volume holds the key table by
  definition.

**Chunking parameters:** FastCDC with min/avg/max = 1/4/16 MiB and
normalization 2 (`internal/chunkid`). Rationale: scientific data dedups
modestly, so the per-chunk costs — a catalog row and a pack fetch per
chunk — argue for large chunks. Digests are 32 bytes. Note the
interaction with the 2 MiB cut size: a chunk larger than the target seals
into a pack of its own, so a large file is roughly one pack per chunk and
a whole-pack fetch of it costs what the chunk costs.

These parameters are compiled in. They are **not** recorded per volume in
the superblock — `Params` carries the catalog thresholds and the retention
window, and nothing else — so changing them changes chunk boundaries for
every volume a build touches.

## Inodes and hardlinks

**Inodes are opaque, stable 64-bit values** allocated monotonically from
the superblock's `NextInode` counter (sessions lease a range at mount and
publish their high-water mark; a crash burns numbers, which is fine in a
64-bit space).

Explicitly rejected: inode = (32-bit catalog ID, 32-bit file ID). Encoding
location into identity means catalog splits renumber whole subtrees and a
cross-catalog `mv` changes a file's inode — breaking POSIX rename
semantics, open handles, NFS filehandles, and `tar`/`rsync` same-file
detection. This is CVMFS's deepest scar (years of inode-translation
workarounds), and a *writable* filesystem cannot dodge it the way
read-only CVMFS does. With opaque inodes, a cross-catalog rename is just:
row moves from catalog A to catalog B, both dirty, both republished in one
superblock generation. The tree is the mapping; no registry exists.

**Hardlinks: eager promotion.** The invariant is a single biconditional:

> dirent shared-flag set <=> nlink > 1 <=> content record lives in an
> inode shard

- `link()` taking nlink 1 -> 2 promotes the record from its catalog into a
  shard, leaving `(inode, shared-flag)` references in both dirents.
- `unlink()` decrements in the shard; nlink 0 deletes the record.
- Demotion when nlink returns to 1 is optional; if skipped, the invariant
  relaxes one direction. If done, only opportunistically at publish while
  the referencing catalog is being rewritten anyway.
- Directories never promote (their nlink counts subdirectories); symlinks
  are ordinary rows. Shards hold regular files only.
- Cross-catalog `link()` needs no EXDEV restriction: promotion handles it.

**Validated against a real hardlink farm:** the miniconda tree carries
23,598 hardlink groups and every one of them spans catalogs at any
reasonable `S_max` — confirming both that eager promotion was the right
call and that its cost is trivial: ~24K shard records, roughly 5 MB, for a
full conda installation.

## Publish

Publish turns a continuously-mutating volume into a consistent generation
without pausing writers. The key inversion: **the cut is defined by a
metadata snapshot taken first, and durability is reconciled against
exactly that cut afterward** — not "flush everything, then snapshot",
which races new writes into the snapshot between the flush and the cut.

One publish at a time, five phases. The session owns the first two;
`internal/publish` owns the last three.

1. **CUT.** Take a consistent local view of the overlay. This defines
   generation N+1's contents; writes continuing during publish belong to
   N+2 and are irrelevant. A mid-session **checkpoint** freezes the
   overlay to get that instant, because it publishes while writers keep
   working; the **seal at unmount** does not, because the mountpoint is
   already gone and the live overlay *is* an instant. That distinction is
   worth ~32 s of hardlinking plus ~6 s of unlinking on an 85k-file
   session, all of it in front of a waiting user.
2. **RECONCILE.** Everything the cut references must exist locally before
   it can be packed.
3. **TRANSFORM.** From the cut, regenerate every dirty catalog and inode
   shard. Chunk with CDC; dedup against the chunk index and against the
   previous generation; append new chunks, small files, catalogs, shards,
   and the superblock backup into packs. Ancestor catalogs of dirty
   catalogs are dirty too, up to the root. Content addressing makes this
   idempotent: a regenerated-but-identical catalog hashes the same and is
   skipped, and an unchanged subtree is carried forward without being
   read.
4. **UPLOAD.** New packs, four at a time. Everything uploaded is
   content-addressed and unreferenced until the flip.
5. **FLIP.** Write the new superblock via the ref guard. A stale ref means
   a concurrent writer: abort loudly; uploaded objects are orphans,
   nothing corrupts.

The pack list is carried forward from the previous generation
unconditionally, and content reuse depends on that: a carried-forward
chunkref names bytes living in one of the previous generation's packs, and
retention deletes any pack no live superblock lists. If that ever grows a
filter, reuse must be gated on the surviving set in the same change.

Crash analysis: before UPLOAD — nothing remote changed; during UPLOAD —
complete or partial packs exist unreferenced (orphans; GC will sweep);
after UPLOAD, before FLIP — a complete generation exists unreferenced
(same); FLIP is a single small write. Re-publishing after any crash
re-derives the same content hashes, skips what already uploaded, and
completes — publish is idempotent end to end. If a publish overruns the
interval, the next tick is skipped and its churn coalesces into the
following cut; publishes never overlap.

Readers observe generation N or N+1, never a mixture: the superblock is
the sole entry point, and everything beneath it is immutable.

A **superblock backup** rides in the last pack of each publish, stored
raw, so a lost ref object can be recovered. It is built before the final
seal, so its own pack list lacks the very pack that carries it.

## The mount

A full POSIX implementation — including kernel dentry caching done right —
requires the RAW FUSE protocol layer, not a convenience wrapper: pelfs
implements `fuse.RawFileSystem` on upstream `hanwen/go-fuse`, whose raw
surface carries everything the binding needs — per-reply entry and attr
validity, entry and inode notification, readdirplus, `Attr.Blksize`. The
high-level layers hide exactly the knobs this design exists to exploit.

The FUSE-agnostic core — generation resolver: catalog descent, residency,
shard routing, chunk reads — is `internal/genfs`. The raw binding is
`internal/rawfuse`, and the crash-safe write overlay is
`internal/overlay`.

### The immutability dividend

Within a generation, clean inodes never change — so Lookup and GetAttr
replies for them carry effectively infinite entry and attr timeouts (ten
years), and the kernel becomes the dentry and attr cache. Metadata storms
(`git status`, build scans) hit userspace once per mount, not once per
call. This single decision is why the custom VFS outperforms a generic
engine.

Measured through a real Linux kernel (2000 files, stat walk):

| stat walk, 2000 files | A: writable, all dirty | B: read-only, clean | C: writable over clean |
|---|---|---|---|
| cold | 0.87 s | 0.39 s | 0.42 s |
| repeat | 1.03 s (no gain) | **0.14 s** | **0.25 s** |
| read all | 0.37 s | 0.12 s | 0.18 s |

C is the case that matters in practice — a writable mount over a large
tree whose content is almost entirely untouched — and it performs close to
the read-only mount, because clean inodes keep their infinite TTLs even
when the mount is writable. Writability costs almost nothing on the parts
you did not write. That only holds because the "is this inode dirty?"
question, asked on every lookup, is answered from memory in ~15 ns; as a
SQL query it cost 24 µs, more than a whole Lookup.

Dirty inodes reply with a **short** TTL — one second
(`rawfuse.dirtyValidity`) — not zero. The TTL was originally zero, on the
reasoning that an inode the overlay owns can change at any moment.
Measurement showed what that cost: with no attribute cache the kernel
re-asks about every change it just made itself, and an untar traced at
14.1 FUSE operations per created file, six of them existing only because
of the zero TTL. Raising it to one second cut the untar 1.57x (878 -> 1379
files/s) and a walk over the dirty tree 1.87x.

The safety argument is exclusive ownership, not optimism: the overlay is
opened `locking_mode EXCLUSIVE`, so the only mutations are ones the kernel
itself issued, and the reply to each refreshes the very entry in question.
The kernel can hold its own most recent view, never another writer's stale
one. It stays short rather than infinite because one transition does move
state out from under the kernel — a mid-session checkpoint returning
inodes to clean — and a bounded TTL converges on its own if an
invalidation is ever missed.

The repeat walk over dirty inodes gains far less than over clean ones,
where the kernel answers from its own caches and the same walk is 5.5x
faster. That gap is the design's central claim, confirmed end to end
rather than argued.

Resolver latency, measured on a 512-entry catalog against a loopback
origin, before and after the prepared-statement, pooling and
readdirplus-join work:

| op | before | after |
|---|---|---|
| Lookup, 1 thread | 19.1 µs | 15.3 µs |
| Lookup, 64 threads | 48.6 µs | 15.7 µs |
| GetAttr, 64 threads | 34.1 µs | 5.7 µs |
| Readdir (512 entries) | 12.6 ms | 0.78 ms |
| warm 1 MiB read | 24.5 GB/s | 33.9 GB/s |
| inline read | 32 ns, 0 allocs | unchanged |

Metadata latency is FLAT under concurrency instead of degrading 2.5x, and
a cold 1M-entry walk falls from ~25 s to ~1.5 s.

The next bottleneck it names: in writable mounts every operation pays a
userspace round trip into an overlay that serializes on one mutex and
commits a SQLite transaction per op (~0.4 ms/stat). Finer overlay locking
is the tuning lever.

### Inode residency

The catalog is a locator by descent: the kernel always Lookups parent
before child, so the VFS builds `inode -> (catalog, shard)` residency on
the way down and holds it exactly for kernel-live inodes; FORGET and
BatchForget (nlookup accounting) retire entries. Residency is a cache of
the descent, never an authority — the CVMFS translation-machinery scar
stays closed.

### Read path

ReaddirPlus fills entries and attributes in one pass from a catalog page.
File reads resolve chunkrefs to the identity-keyed decoded-chunk cache,
then to the pack holding the chunk, fetched whole. `FOPEN_KEEP_CACHE`
holds the page cache across open and close of clean files on a read-only
mount; kernel writeback-cache mode batches dirty pages for the overlay.
Zero-copy `splice` from the cache file (`ReadResultFd`) is *not*
implemented — reads copy through `ReadResultData`.

Open is stateless (`Fh 0`) and there is no per-handle snapshot isolation.
Chunk lists live in a per-inode cache which a generation swap clears
wholesale, so an open file re-resolves its chunks after a swap rather than
keeping the generation it opened. What the resolver does guarantee is that
no read is torn: catalog handles are refcounted and the swap takes a lock
against readers.

### Generation swap

Read-only clients ingest external updates by polling the superblock
(`--poll`) and atomically swapping generations. Freshness comes from a
conditional GET (`If-None-Match` plus ETag, direct-read) of one tiny
object against the origin — a stream of 304s, no TTL guessing.

The swap verifies the signature, verifies **lineage** (the new generation
must chain, via previous-superblock hashes, to a known ancestor — a fork
from a stolen lease is detected exactly here), then atomically replaces
the in-memory routing table and issues `EntryNotify` for changed or
removed dirents and `InodeNotify` for changed content. Stable inodes mean
the difference between two generations is exactly the catalog diff: no TTL
guessing, no cache flush. Verified on a real kernel with two independent
processes — a reader following the branch picks up another writer's sealed
generation with no remount, invalidating only what it holds.

Refresh policy is per-mount, not architectural: batch jobs default to
**pinned** — one generation for the job's lifetime, for reproducibility;
`--poll` opts into following. No reader registration exists (readers stay
invisible, no third mutable object); staleness bounds come from the
time-based GC grace window instead.

CVMFS's propagation pain — often misdiagnosed — was never "caches served
the wrong object"; their objects are content-addressed too. It was
manifest freshness behind TTL'd squid hierarchies with no bypass, and live
catalog reload renumbering inodes under the kernel, which broke open files
and spawned years of translation machinery. Both are structurally absent
here.

### Write path

Writes never mutate a generation: a local overlay — dirty tree plus staged
chunks, SQLite-backed — shadows the immutable base, and each modified file
gets a staging file keyed by inode. A **checkpoint** on a cadence
(`--snapshot-interval`, default 5 minutes) or on write pressure (128 MiB
of dirty bytes) seals a frozen view into a generation and rebases
provably-unmodified inodes back to clean; the seal at unmount does the
same without freezing. `--no-seal` keeps the overlay for a later remount
instead.

`design-writepath.md` proposes replacing the staging directory with an
LSM-shaped memtable so content leaves during the session. It is **not
built**.

### Frontends

Two, both real. Native **FUSE** is the default wherever `/dev/fuse` or
macFUSE is present. On macOS without either, a **loopback NFSv3 server**
(`internal/nfsmount` over `internal/vfsbilly`) is mounted by the OS NFS
client, unprivileged, with no kernel extension. `--backend auto|fuse|nfs`
picks. The low-level caching wins are FUSE-only: NFS keeps client-driven
caching with no invalidation push, and stays the degraded path. Hard links
work over it, on a small go-nfs fork documented in `go-nfs-patches.md`.

## Retention and GC

Retention is expressed entirely in the ref and generation layer, and the
pack list makes the sweep set arithmetic rather than tree traversal:

- **Pack lists carry forward.** Publish appends new packs to the previous
  generation's list; the only thing that would ever REMOVE a pack from the
  list is repack. So a branch head's list covers every ancestor's packs.
- **The condemned ledger covers the exception.** When repack drops a pack
  from the list, the new superblock is to record it in a small `condemned`
  ledger as (name, condemned-at); publish carries ledger entries forward
  until they age past `T_grace`. GC honours the ledger today. **Nothing
  writes it**, because there is no repack.
- **Retained packs** = the union over every ref head and every tag of
  (pack list + condemned entries younger than `T_grace`). No catalog
  walking is needed for deletion safety — the pack list *is* the reachable
  closure at pack granularity. `T_grace` defaults to 72h, is recorded in
  the superblock `Params` so writers, readers and GC agree, and is
  configurable per volume.
- **Sweep** = delete packs that are (a) absent from the retained union AND
  (b) older than `T_grace` by the timestamp in the pack name. Guard (b) is
  what makes GC safe to run concurrently with writers, with no locking: a
  writer's new packs are always younger than `T_grace`, so they are never
  candidates regardless of when GC listed the refs. GC re-lists refs
  immediately before issuing deletes as a cheap window-narrower, not a
  correctness requirement. It **fails closed**: any unverifiable ref or
  tag aborts the sweep, as does finding no refs and no tags at all.
- **Granularity:** whole packs and ref debris only — never entries, which
  would be repack's job. Deleting a branch or tag is how space is actually
  released.
- **Who runs it:** `pelfs gc`, which needs no lease and reports without
  `--delete`.
- **The reader contract:** a reader pinned to an untagged generation older
  than `T_grace` may see "snapshot expired — refresh or remount". A
  workflow that needs a longer pin tags first; tags pin exactly and
  indefinitely. Nothing raises that error today; the grace window is
  enforced only from the sweep side.

## Codec marking

The CVMFS scar to avoid: bytes whose compression algorithm is implied by
convention rather than recorded. Every place the format transforms bytes,
and where its algorithm lives:

| bytes | compression | encryption | recorded where |
|---|---|---|---|
| chunk pack entries | zstd or none (store-if-smaller) | AES-256-GCM or none | `chunkref.alg` + `chunkref.keyid`, per entry |
| catalog / shard pack entries | always zstd | one volume key or none | fixed by rule + `superblock.CatalogKeyID` (their references have no per-entry columns) |
| superblock backup entries | none | none | stored raw; the superblock is signed and public |
| pack trailer | zstd (`PELFSPK2`) or none (`PELFSPK1`) | never | footer magic versions the codec |
| superblock | none | never (signed, public) | `FormatVersion` |
| static catalog | n/a (self-describing header) | n/a | `format_major`/`format_minor` in the header; identity algo in the header and the meta section |
| inline bytes | raw | ride inside the catalog entry | n/a |

New algorithms are new ids, or a new footer magic; nothing is ever sniffed
from magic bytes inside an entry.

## Local caching

One cache, under the volume's state directory (`gencache/`), with four
kinds of thing in it:

- `chunks/` — **decoded** chunk bytes (post-zstd, post-AES), keyed by
  chunk identity. This is the only local data store.
- `packs/` — whole packs, the unit of transfer.
- `catalogs/` — catalog blobs by identity.
- `trailers/` — verified pack trailers, so a resolved location map
  survives a remount.

`--prefetch all` fills the chunk cache for a whole generation before the
mount starts and refuses to run if anything is unavailable; `--prefetch
background` starts the same warmup without blocking. Prefetch walks
catalogs rather than the pack list on purpose: the pack list includes
catalogs, shards and backups, and can name packs holding chunks no live
file references.

## Overwrite churn

The hostile workload is a file — or one hot byte range — rewritten and
fsynced over and over (notebook autosave, a database WAL, checkpoint
files). Immutable-object designs turn every fsynced version into new
objects; without countermeasures, storage grows with write volume rather
than live data. Three things absorb it, and the third does not exist yet:

1. **Local overwrite in place.** A staging file is overwritten, not
   appended to, so intermediate versions never become chunks and never
   reach the federation. Only what survives to a checkpoint or a seal is
   chunked at all. This is the largest effect and it is free.
2. **Content addressing.** Identical content hashes to the same chunk — a
   rewrite that changes nothing costs nothing — and CDC re-chunking makes
   an edit cost proportional to the changed bytes, not to the file. A
   chunk that a later generation stops referencing stays in its pack.
3. **Repack — NOT IMPLEMENTED.** Versions that survive a seal and die
   later are dead entries inside immutable packs, and nothing reclaims
   them. `pelfs gc` deletes whole packs no retained generation lists; it
   never rewrites one. So federation usage on a long-lived volume under an
   overwrite loop grows without bound, and the `live/L + G + one pack`
   bound this document once claimed is a property of a design, not of the
   code.

   What a repack would do: rewrite the live entries of packs below a
   liveness threshold into the current spool, then delete the old packs
   whole. Three properties make it simple: cost is proportional to live
   bytes moved, not pack size; no tombstones are needed, since the moved
   entries reappear in a newer pack and the pack list decides what is
   live; and crash mid-repack is idempotent, because the old pack is
   deleted only after the new one is durable and the grace window covers
   the gap. It folds into TRANSFORM as one more transform — condemned
   packs are simply omitted from the new pack list — which makes it
   generation-atomic rather than a separate mutation. Repack is
   self-limiting in the adversarial case: the more a pack's contents have
   died, the fewer live bytes a repack must move. `design-writepath.md`
   carries the policy work.

## Disaster recovery

The superblock is the only mutable object, which makes it the natural
worry: what survives if it is lost or corrupted? Answer: everything except
the map — packs contain the catalogs and inode shards as well as the data,
so recovery is a scavenging problem, made tractable by three format
provisions that are all in place:

1. **Typed pack entries.** Every trailer entry carries a type (data chunk,
   catalog, inode shard, superblock backup; absent = data). One byte of
   JSON per entry; without it, recovery would have to sniff container
   magic, which encryption makes impossible.
2. **Self-identifying catalogs.** Each catalog embeds volume UUID, its
   covered subtree root path, and its identity algorithm; because
   transition-point rows carry child catalog identities, the tree is
   *self-assembling* — find all catalog entries, descend by embedded child
   identities, and a root candidate is any catalog covering "/" that no
   other catalog references. A crash mid-publish legitimately leaves a
   newer, incomplete set (packs upload before the flip), so recovery falls
   back a generation when a closure has holes.
3. **Superblock backups ride in packs.** Superblocks are tiny; each
   publish writes the current one into its last pack as a typed entry.
   Losing the mutable object then costs only the generations since the
   last publish — recovery becomes "restore the newest embedded backup,
   verify its signature, re-point the ref", recovering the allocator
   counter, shard ranges, pack list, and the wrapped key table exactly. (A
   lost KEK is still fatal for encrypted data, by design; the wrapped DEK
   in a backup is harmless to expose.)

`pelfs rescue` — enumerate packs, inventory trailers, assemble the newest
complete generation, then report subtrees intact, files damaged by missing
chunks, catalogs missing, and a hash-only lost+found for data reachable
from no surviving catalog — is **specified here and not implemented**. The
format prerequisites above all shipped, which was the point: retrofitting
them would have left early volumes unrescuable.

`pelfs fsck` does exist and verifies a published generation: it builds the
full location map from the signed pack list, walks catalogs and shards,
checks record order, and with `--deep` verifies chunk bytes against their
identities.

## Session control socket

The primary interface is `pelfs shell` / `mount` / `umount`; publishing is
a session activity, not a separate workflow. Each session listens on a
Unix-domain socket in its state directory (`control.sock`, mode 0600)
speaking plain HTTP — curl-able, no custom framing:

- `GET  /v1/status` — mount point, prefix, generation, uptime
- `GET  /v1/stats` — the live session-statistics JSON
- `POST /v1/publish` — checkpoint now, keep serving (writable mounts only;
  a read-only mount 404s it)
- `GET  /v1/bugreport` — tar.gz: status, stats, goroutine dump, runtime
  info, volume public key
- `/debug/pprof/*` — the standard profiling surface

`pelfs ctl <prefix-or-mountpoint> <verb>` is the CLI client. Possession of
the state dir is already possession of the volume's local keys, so no
further auth.

## Fuzzing

1. **Parser fuzzing — unrestricted.** Everything that parses untrusted
   federation bytes has a native Go fuzz target: pack trailers
   (`FuzzDecodeTrailer`, `FuzzParseTail`), superblock decode and verify
   (`FuzzDecodeVerify` — mutations must never verify, `VerifyChain` must
   never panic), the entry codec (`FuzzDecode`, GCM fails closed), the
   chunker (`FuzzChunker` — termination, bounds, exact reassembly,
   determinism), and the static catalog parser (`FuzzStaticCatalog`).
   Pure functions on byte slices; run anywhere, run in CI. The first run
   already forced a hardening fix (negative trailer extents reaching the
   range-read path).
2. **Op-sequence fuzzing — CONTAINED, ALWAYS.** `FuzzOps` drives random
   filesystem operation sequences (the fsx/syzkaller shape) against the
   overlay, checked against an in-memory reference model, plus a
   concurrent stress mode under the race detector. This tier mutates real
   files, so a bug under fuzz pressure could write ANYWHERE the process
   can — containment is mandatory, never optional: the harness only builds
   under the `opfuzz` tag, refuses to run unless the containment
   launcher's environment is present, does its own path work through
   `os.Root`, and the ONLY sanctioned entrypoint is
   `scripts/opfuzz-docker.sh` — a network-less, cap-dropped, unprivileged,
   read-only-rootfs container whose only writable space is a tmpfs.
3. **Mounted-FS fuzzing — future, same containment.** Driving real
   syscalls through the kernel against a mount, with the mountpoint as the
   fuzzer's `os.Root`, so neither a VFS bug nor a fuzzer bug can traverse
   out.

## Benchmarks and acceptance criteria

A fixed suite, run against a local federation and one real OSDF prefix;
targets follow from the measurements above. The container-based gates live
in `scripts/` (`mount-gate-docker.sh`, `bench-untar-docker.sh`,
`bench-untar-nfs-docker.sh`, `e2e-docker.sh`).

1. Kernel-source untar plus publish: publish cost proportional to churn;
   republish after touching one file ≈ one catalog plus ancestors.
2. `conda create` (the hardlink storm): completes; promotion adds ≤ ~10 MB
   of shards; subsequent publish seconds, not minutes.
3. `git clone` plus `git status`: correct, and status latency within 2x
   local disk on a warm cache.
4. 10 GB single-file write: ≥ 0.8x the raw upload throughput of the same
   host (chunking and packing overhead budget: 20%).
5. Cold mount of a 1M-entry volume: ≤ 3 s to usable. Measured at ~1.5 s.
6. Overwrite-loop soak: federation usage bounded over hours. **Cannot
   pass** until repack exists — see "Overwrite churn".

## Settled decisions

| decision | rejected alternative | why |
|---|---|---|
| opaque stable 64-bit inodes | (catalog ID, file ID) composition | splits and renames must not change identity; CVMFS scar |
| catalog located by tree descent | inode -> catalog registry | no consumer needs reverse lookup for nlink==1; registry is pure liability |
| eager promotion of nlink>1 to inode shards | intra-catalog-only hardlinks (EXDEV); lazy promotion | hardlink farms (conda) make catalogs unsplittable; lazy needs a link-aware splitter |
| shards as their own object class, routed by superblock | in the superblock; in a path catalog | superblock must stay tiny; a path-catalog home re-couples location and rebuilds the hotspot |
| range-friendly packs, CDC for edit sharing | literal git packfile with delta chains | filesystems serve range reads; delta chains force full reconstruction |
| integrity from Merkle plus signature | integrity from DEK/AEAD tags | a public DEK forges tags; the hash tree is stronger and encryption-independent |
| boring small CBOR superblock | mmap'd minimal perfect hash | wrong cardinality: thousands of rows, not millions |
| inline threshold 2048, configurable | 512; never inlining | inlining makes catalogs numerous, which is what makes an incremental seal cheap |
| GC = set arithmetic on retained generations' pack lists | mark-sweep over catalog trees | pack lists ARE the closure at pack granularity |
| `T_grace` age guard makes GC lock-free | GC/writer/fork coordination via the lease | new packs are always younger than the guard; fork sources are already retained |
| separate Ed25519 signing key per volume | sign with the KEK | verification is public, decryption is not; unencrypted volumes still need authenticity |
| TOFU plus pinning for first-mount trust | mandatory pre-shared pubkey; registry attestation | the SSH model works; pelfs stays a pure client, no registry integration |
| time-ordered pack names, trailer hash in the pack list | content-hash pack names | the age guard and ordering come free; the list-recorded hash gives verification anyway |
| no atime in catalogs | persisted atime | reads must never dirty metadata on a publish-what-changed filesystem |
| reader fetches whole packs, publisher cuts small (2 MiB) | promote a pack on consumption evidence | four constants tuned against an unnameable workload; the same read cost 10 KiB or 64 MiB depending on history |
| locations resolved on demand, newest pack first | index every trailer at mount | one round trip per pack before serving a byte, scaling with volume rather than with the question |
| static packed catalogs, SQLite still readable | in-place conversion of every catalog | conversion re-identifies and re-uploads the whole namespace for no reader benefit |

## Designed, not built

Everything in this list is specified above and has no implementation.
Nothing else in this document is aspirational.

- **Repack.** No function, no command. `superblock.Condemned` is a field
  nothing writes. This is the one gap with a user-visible consequence:
  dead bytes inside retained packs are never reclaimed.
- **`pelfs rescue`.** Fully specified; the format prerequisites shipped.
- **Forks.** No command creates a ref from another generation.
- **Tag creation.** `refs.Store.Tag` exists with no caller; tags can be
  read (`--tag`) but not written.
- **Key rotation.** `NextPub` is verified but never set.
- **The LSM write path** of `design-writepath.md`, except its
  `internal/memtable` prototype, which nothing imports.
- **`splice`/`ReadResultFd`** on cache hits.
- **The "snapshot expired" reader error.** The grace window is enforced
  from the sweep side only.

## Open format questions

One question is open, it is additive, and it is the owner's to decide.

**Nothing in the signed superblock says where any identity lives.** So a
cold mount cannot find its own root catalog without fetching at least one
trailer. Three candidates, cheapest first, measured on the Linux 6.6
corpus:

1. **Record the root catalog's pack** (a `root_pack` string, omitempty).
   Saves the one trailer probe a cold mount pays today: 1–2 GETs and
   128–256 KiB, ~20–40 ms. Small on average. What it really buys is the
   tail: the probe order is a heuristic — "the root catalog is in the
   newest pack, because publish writes it last" — which held at every pack
   size measured, but if it ever fails (a generation whose root catalog is
   carried forward unchanged while later packs were appended, or a repack
   that reorders the list) the probe budget runs out and the mount
   resolves the whole map instead. At 1002 packs that is 1001 GETs and
   125 MiB, at mount. This converts a 1-GET mount with a rare four-figure
   tail into a 1-GET mount with no tail.
2. **Record each catalog's pack** (a `pack` field on `CatalogEntry`, which
   publish already maintains). Makes the whole namespace descent
   location-free. Measured value is LOW on top of (1), because publish
   already writes catalogs at the end of a seal. It buys determinism
   rather than requests.
3. **A per-generation location index**: one object holding every trailer's
   entries merged, named from the superblock by identity and size. This is
   the one that addresses the real cost. What forces a mount into
   resolving the whole map is a CHUNK in an old pack, and no amount of
   catalog metadata helps with that. On this corpus the merged trailers
   are about 2.2 MiB — one GET — against 251 GETs and 32.1 MiB of tail
   probes at 1 MiB packs, or 63 GETs and 7.9 MiB at 4 MiB. It is also what
   would let the cut size go below 1 MiB, where the fixed 128 KiB probe
   currently dominates. Backward compatible in both directions: a reader
   that finds no such field falls back to trailers, and a reader that does
   not understand the field ignores it.

Deliberately deferred, needing external partners or production mileage
rather than design: **POSIX ACLs** (out of scope; xattrs carry them
opaquely) and **compression dictionaries** for small-chunk cohorts
(measure first).

---

## Appendix A: the engine this replaced

pelfs v1 stored data as JuiceFS blocks and metadata as a whole-volume
SQLite snapshot, with the JuiceFS metadata engine as the live filesystem.
It is deleted — nothing in the tree imports it — and it is recorded here
because the reasons it existed, and the reasons it stopped being enough,
are the argument for everything above.

**Why it existed.** A live FUSE mount needs random writes at full POSIX
semantics, and JuiceFS had a battle-tested engine for exactly that.
Teaching a multi-catalog engine to be the live engine meant rewriting the
hottest code in someone else's filesystem while invalidating its testing.
So the split was hot (live session, local) versus cold (published,
federation), with the borrowed engine on the hot side. It also meant the
default mount path stayed on proven code until this format had run real
workloads — deliberately, so that what is battle-tested now is our format
rather than somebody else's schema.

**Why it stopped being enough**, all three confirmed in real use:

1. **Small objects.** Every JuiceFS slice became its own federation
   object. Small files and fragmented writes produced storms of tiny
   objects — uniform 32 KB objects from the NFS backend before the handle
   cache — each costing an HTTP round trip, polluting the namespace, and
   caching poorly.
2. **Metadata scaling.** The entire SQLite catalog was re-uploaded every
   snapshot interval, forever, no matter how little changed. Cost grew
   with volume size, not churn: a million-file volume paid gigabytes of
   upload per hour while idle.
3. **Cache hostility.** Data blocks were keyed by mutable-looking names
   and the metadata snapshot was overwritten in place, so mutable-object
   reads had to bypass federation caches and the lease machinery guarded
   several objects.

**Two of its mechanisms are worth remembering.** Its packs bootstrapped by
*listing* `packs/` and trusting name-ordered shadowing, with tombstones in
the trailer marking dead entries — which is why the trailer schema still
has a `"dead"` field. A generation's pack list replaced all of it: the
superblock hands a fresh session the authoritative, generation-consistent
pack set, with no listing and no race against a concurrent repack. And its
snapshots were crash-recovery checkpoints rather than versions: older
siblings rotted as later sessions tombstoned their blocks, so only the
newest was guaranteed consistent. Versioning the pack set is what makes a
tagged generation permanent instead.

**Migration is drain, never convert.** A v1 volume is read with the last
release that had the v1 engine and copied into a fresh prefix. In-place
conversion was rejected: it would force every reader to carry v1's
slice-name block layout and unversioned-snapshot semantics forever, for
the convenience of volumes that are by charter scratch. `pelfs publish`,
which promoted a v1 volume in place, is gone — keeping it meant keeping
the v1 metadata engine and block reader, the heaviest part of the
dependency. A prefix holding v1 metadata is still RECOGNIZED
(`classifyVolume` probes for it) and refused with instructions, because
the alternative failure mode is reading it as an empty prefix and
initializing a new volume over somebody's data.

**What ejecting it bought**, beyond the format: one direct dependency and
its whole transitive tree left `go.mod`, the three cgo-free shim modules
that existed to keep that tree buildable are gone, and the build needs no
tags at all. The `object.ObjectStorage` abstraction went with it —
everything here is immutable and content-addressed, so there is nothing
for rename, copy, multipart, or storage classes to abstract over — and so
did the go-fuse fork that had outlived the engine.

**What survived:** the transports, preflight, the token machinery, the NFS
and FUSE frontends, stats, prefetch (which walks catalogs instead of
scanning slices), and the lease.

## Appendix B: considered and not taken

Recorded so they are not re-proposed. Decisions already summarised in the
"Settled decisions" table are not repeated here.

**The literal git packfile format.** Git packs are zlib streams with delta
chains optimized for whole-object reconstruction; a filesystem serves
range reads, and delta chains force reconstructing an object to serve any
byte of it. The "edits share storage with the previous version" benefit
comes instead from content-defined chunking: an edited large file
re-chunks and shares unmodified chunks with its ancestor via content
addressing, at zero read-path cost. True deltas, if ever wanted, are
confined to small objects and are not in this design.

**Whole-pack solid compression.** Rejected outright: one cold read would
fetch and decompress everything before it. Per-entry compression is what
makes an entry independently readable.

**Alignment padding between pack entries.** HTTP ranges are byte-granular
and the local cache reads whole entries, so alignment would pay only if
packs were mmap'd locally. Revisit then, not before.

**A pack promotion heuristic** — fetch a pack whole only after a reader
had demonstrably started consuming it, via a byte ratio, an entry ratio, a
floor on distinct entries, and a bound on how far ahead of the reader it
would speculate. It worked, and it was unpredictable: the same read cost a
kilobyte or sixty-four megabytes depending on what the mount had happened
to read earlier, and tuning it meant tuning four constants against a
workload nobody can name in advance. Bounding the transfer is the
publisher's job instead, through the cut size.

**Indexing every pack trailer at mount.** One round trip per pack before
serving a byte, scaling with volume size rather than with the question
asked. The numbers are in "Locations resolve on demand".

**Walking lineage hashes to ancestors' pack lists** instead of carrying a
condemned ledger forward. Rejected because anonymous ancestors'
superblocks are not reliably fetchable once the ref moves — they live only
as scattered in-pack backups. The head must state everything.

**Content-derived pack names.** Buys nothing: the age guard and creation
ordering come free from time-ordered names, and the pack list already
records each trailer's hash.

**Heartbeating through the superblock** to preserve a "one mutable object"
purity claim. That conflates roles — re-signing every 30 s, lineage
polluted or bypassed by heartbeats, and readers unable to distinguish "new
generation" from "still alive" without parsing.

**Convergent encryption** (confirmation attacks by construction, breaks
rotation); **plaintext hashes as object names** (leaks content equality to
the whole federation); **pure ciphertext addressing** (no dedup). Keyed
BLAKE3 with a per-volume identity key is the resolution.

**Lazy hardlink promotion** — promote only when a catalog boundary would
cut a link group. It buys micro-locality for intra-catalog link groups,
which barely exist in scratch workloads, at the price of a link-aware
splitter and a delicate "unpromoted groups are catalog-local" invariant.
The heavy hitters (conda, pnpm, uv package stores, `git clone` of local
paths) span distant directories and promote under either policy. Eager
promotion makes "hardlink farms create unsplittable catalogs"
structurally impossible rather than mitigated.

**Three writeback dispositions** — synchronous, writeback with a
dirty-bytes cap, and an "accumulate" mode that uploaded nothing until job
end. None was built, and the overlay plus checkpoint covers the ground
they were meant to: content stays local until a checkpoint or the seal,
which is the accumulate shape, and the checkpoint cadence is the dial. The
one idea worth keeping is the cap — a session that fills local disk should
push back on the writer rather than explode — and nothing enforces one
today.

**Full-metadata hydration at mount** — download every catalog and shard
for a generation, rebuild a local database, then fetch data on demand.
This was the bridge design for a runtime that could not read catalogs
directly. The resolver reads them natively and descends lazily, so
hydration was deleted rather than tuned; a cold 1M-entry walk is ~1.5 s
without it.
