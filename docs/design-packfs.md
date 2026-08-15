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
| `next_inode` | allocator high-water mark |
| wrapped DEK | confidentiality key, wrapped by the user's KEK |
| previous-superblock hash | lineage: snapshot history, fork detection |
| signature | trust root over all of the above |

Format: deliberately boring (CBOR or a tiny SQLite DB, loaded fully into
RAM). A minimal-perfect-hash mmap structure was considered and rejected:
the superblock has one row per *catalog/shard* (thousands at pathological
extremes, since each holds ~100K entries), far below where MPH pays. If a
per-pack chunk index ever holds millions of entries, a sorted-hash-array
with binary search on mmap is the next step there — still not MPH.

Because everything else is immutable and content-addressed, the superblock
is the only object that needs `?directread`, the only object the
single-writer lease must guard (ETag compare-and-set on overwrite), and the
only thing a reader must re-fetch to observe a new generation. Readers get
snapshot-consistent views by pinning a generation. This one property —
*exactly one mutable object* — is the strongest Pelican-fit argument for
the whole design: federation caches work at full strength for all data and
all metadata.

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
- **Confidentiality: the DEK, optional.** One volume DEK, wrapped by the
  user's KEK, stored in the superblock. Catalogs and shards are encrypted
  too — filenames leak otherwise. An unencrypted volume simply has no DEK
  and loses nothing else.

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

1. **Pack store as ObjectStorage middleware.** Writeback staging already
   batches blocks locally; drain-time packing plus an indexed range-read
   GET fixes small-object overhead and read RTTs with zero metadata format
   change. Independently valuable even if later phases shift.
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
   session-scoped packs; repack policy for sparse packs; mark-sweep from
   superblock roots vs refcounts; how long superseded generations' objects
   must live (reader-pinning grace period); Pelican DELETE granularity
   (whole packs only — a nice property: the GC unit is the pack).
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
