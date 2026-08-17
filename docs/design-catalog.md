# The catalog format: a static, mmap'd layout

Status: design, being built. Companion to `design-packfs.md`, which
covers packs, superblocks and generations. This document specifies the
on-disk layout of a **catalog** — the immutable, content-addressed
namespace object a generation is made of — and the versioning rules that
let it change later.

It replaces SQLite for catalogs only. The write overlay stays on SQLite,
where transactions, crash recovery and an open-ended query surface are
worth a query engine.

## Why

A catalog is immutable, content-addressed, downloaded, and read through
exactly ten queries. It was implemented as a SQLite database because that
was the fastest way to be correct, and the cost of that choice was
measured on an 80k-file kernel tree (whole-tree reseal, 59 catalogs, no
new content, 3.15s of samples):

| | |
|---|---|
| building catalogs — `sqlite.(*conn).step` | **940 ms**, all of it |
| reading catalogs — `genfs.ContentOf` under `BaseContent` | **880 ms** |
| BLAKE3 over catalog bytes | 30 ms |
| zstd | ~0 |

So roughly 1.8s of 3.15s is SQLite and its consequences, split about
evenly between writing catalogs and reading them, against 30 ms of work
any format must do. The syscall breakdown says where it goes: `pread`
0.34s reading pages back while `WITHOUT ROWID` indexes rebalance, `pwrite`
0.22s writing them out scattered, and `mmap` 0.21s plus `madvise` 0.32s
plus `memclrNoHeapPointers` 0.24s of allocator churn from
`modernc.org/memory` and the Go runtime servicing it.

Three properties motivate the replacement, in order of importance:

**Concurrency.** `modernc.org/libc` puts every SQLite allocation in the
process behind one global mutex. Parallel catalog building measured 6.44s
at one worker against 6.23s at twelve, for 60% more CPU — the ceiling is
the allocator, and it applies to reads under a live mount too. A static
layout allocates nothing on the read path: a lookup is bounds-checked
pointer arithmetic over mapped bytes.

**Determinism.** Catalog identity is a content hash. SQLite fought that:
the `generation` value stamped into `catalog_meta` meant an unchanged
subtree hashed differently every seal, silently defeating catalog reuse
until it was found. Page layout, freelists and insert order are all
things we neither control nor want to depend on. A packed format is
byte-deterministic by construction, which is what content addressing
requires.

**Build cost.** A sorted array is written once, sequentially. There is no
rebalancing, so nothing is read back.

## What it must serve

The entire query surface, from `internal/catalog`:

| query | key |
|---|---|
| lookup a child | `(parent, name)` |
| lookup a nested catalog | `(parent, name)` |
| list a directory | `parent`, ordered by name |
| list nested catalogs | `parent`, ordered by name |
| list a directory with attributes | `parent`, ordered by name |
| stat | `inode` |
| chunk refs | `inode`, ordered by index |
| inline bytes | `inode` |
| xattrs | `inode`, ordered by name |
| symlink target | `inode` |
| "does this catalog hold any xattr at all" | — |
| catalog metadata | — |

Every one is a point lookup or an ordered range scan on a single key.
There are no ad-hoc predicates, no aggregation and no sort order other
than the key's own. One join — list-with-attributes — which the layout
removes by making it an index rather than a search.

## Threat model

Catalog bytes are **verified against their identity before they are
parsed** (`genfs` checks the BLAKE3 hash; trailers pass through
`verifiedTrailer` against the signed pack list). So the parser is not
defending against an adversary who can choose its input: an attacker
would have to break the signature or find a hash collision first.

What it must survive is **corruption** — a truncated download, a bad
cache, a torn local file — without reading out of bounds or panicking.
The rules that follow are written for that, and the `opfuzz` harness is
pointed at the parser from the first commit.

Concretely:

- Structure is validated once at open: magic, version, the section table,
  and that every section lies within the blob and every record array is a
  whole number of records.
- Every reference into a variable-length arena (a name, a blob) is
  bounds-checked at access. It is a compare and a branch against a length
  already in a register; it is not worth trading for the risk.
- **Sortedness is not verified at open.** It is O(n) over the whole
  catalog and would defeat the purpose. A catalog whose records are out
  of order returns wrong answers, never unsafe reads — and `fsck` checks
  order explicitly, which is the right place for an O(n) check.

## Layout

All integers are little-endian. Every section begins at an 8-byte
boundary, and every fixed-size record array is a multiple of its record
size, so a validated section can be aliased as a slice of records.

    ┌──────────────────────────────────────┐
    │ header            64 bytes, fixed    │
    ├──────────────────────────────────────┤
    │ section table     24 bytes × count   │
    ├──────────────────────────────────────┤
    │ sections, 8-byte aligned, any order  │
    │   names, edges, nodes, chunks,       │
    │   inline, xattr, symlink, nested,    │
    │   identities, blobs                  │
    └──────────────────────────────────────┘

### Header (64 bytes)

| offset | size | field |
|---|---|---|
| 0 | 8 | magic, `PELFSCAT` |
| 8 | 2 | `format_major` |
| 10 | 2 | `format_minor` |
| 12 | 2 | `header_len` (64 for major 1) |
| 14 | 2 | `section_count` |
| 16 | 8 | `flags` |
| 24 | 8 | `root_inode` |
| 32 | 8 | `entry_count` (edges) |
| 40 | 8 | `node_count` |
| 48 | 4 | `identity_algo` |
| 52 | 4 | `inline_max` (the threshold this catalog was built with) |
| 56 | 8 | reserved, zero |

`flags` bit 0 is "this catalog holds at least one xattr", which answers
the `HasXattrs` question from the header with no section read at all —
today's fast path, kept.

### Section table

One 24-byte entry per section: `id uint32`, `flags uint32`, `off uint64`,
`len uint64`. Entries are ordered by `id`. An unknown `id` is **skipped**,
which is the forward-compatibility hinge: a future minor version may add
sections that an older reader ignores.

| id | section | record |
|---|---|---|
| 1 | names | arena, no records |
| 2 | edges | 32 bytes, sorted by `(parent, name)` |
| 3 | nodes | 64 bytes, sorted by `inode` |
| 4 | chunkrefs | 64 bytes, sorted by `(inode, idx)` |
| 5 | inline | 16 bytes, sorted by `inode` |
| 6 | xattrs | 24 bytes, sorted by `(inode, name)` |
| 7 | symlinks | 16 bytes, sorted by `inode` |
| 8 | nested | 24 bytes, sorted by `(parent, name)` |
| 9 | identities | 32 bytes, referenced by index |
| 10 | blobs | arena, no records |

### Records

**Edge (32 bytes)** — the directory structure.

| off | size | field |
|---|---|---|
| 0 | 8 | `parent` |
| 8 | 8 | `inode` |
| 16 | 4 | `name_off` into names |
| 20 | 2 | `name_len` |
| 22 | 1 | `type` |
| 23 | 1 | `flags` |
| 24 | 4 | `node_idx` into nodes |
| 28 | 4 | reserved, zero |

`node_idx` is what removes the join. Listing a directory with attributes
is a contiguous scan of edges plus a direct index into nodes — no search
per entry, and no duplication of node records for hardlinked inodes.

**Node (64 bytes)** — `inode`, `mtime_ns`, `ctime_ns`, `length` (8 each),
then `mode`, `uid`, `gid`, `nlink`, `rdev`, `keyid` (4 each), then `type`
and `flags` (1 each), padded to 64 with zeroes.

**Chunkref (64 bytes)** — `inode` (8), `idx` (4), `llen` (4), `clen` (4),
`keyid` (4), `alg` (1), 3 bytes zero padding, `identity` (32).

**Inline (16 bytes)** and **symlink (16 bytes)** — `inode` (8),
`blob_off` (4), `blob_len` (4).

**Xattr (24 bytes)** — `inode` (8), `name_off` (4), `name_len` (2), 2
bytes zero, `blob_off` (4), `blob_len` (4).

**Nested (24 bytes)** — `parent` (8), `name_off` (4), `name_len` (2), 2
bytes zero, `identity_idx` (4) into identities, 4 bytes zero.

### Reads

- **Lookup** — binary search edges comparing `parent`, then the name
  bytes from the arena. O(log n), no allocation.
- **Readdir** — lower-bound on `parent`, then scan while `parent` holds.
  Entries are already name-ordered because the sort key is
  `(parent, name)`, so no sorting at read time.
- **Readdir with attributes** — the same scan, following `node_idx`.
- **Stat, inline, symlink** — binary search by `inode`.
- **Chunkrefs, xattrs** — lower-bound on `inode`, then scan; already in
  `idx` (respectively name) order.

## Determinism

Byte-identical input must produce a byte-identical catalog, or content
addressing silently stops deduplicating — the failure that made every
unchanged subtree rewrite itself under SQLite. The rules:

1. Sort orders are exactly as tabled above, with names compared as raw
   bytes (`bytes.Compare`), not by locale or by any normalized form.
2. Arena contents are appended in the order their referencing records are
   emitted, so the arena is a function of the sorted record order.
3. All padding and reserved fields are zero.
4. Sections are emitted in ascending `id`.
5. **Nothing derived from the environment appears anywhere** — no
   timestamp, no hostname, no generation number, no build counter. The
   `generation` stamp is precisely what broke reuse before, and it does
   not exist in this format. Where a caller needs to know the generation,
   it is in the superblock, which is the mutable object that may carry
   mutable facts.

A test pins this the way `TestChunkIdentityDomainIsStable` pins chunk
boundaries: build the same tree twice, in one process and across
processes, and require identical bytes.

## Versioning

`format_major` is the compatibility gate. A reader **refuses** a major it
does not implement, with an error naming both versions — a wrong guess
about layout is worse than a clean refusal.

`format_minor` is additive only. A minor bump may add sections, add
header fields inside the space `header_len` covers, or set previously
reserved flags. It may never change the meaning or size of an existing
record, reorder fields, or repurpose a section id. Readers ignore unknown
sections and unknown flags, so an older reader reads a newer minor
correctly, just without whatever the new section offered.

Both numbers are in the header of every catalog, so a volume can contain
catalogs of different versions simultaneously — which is what makes
carry-forward safe across an upgrade: an old catalog that nothing touched
stays byte-identical, keeps its identity, and is still readable, while
new catalogs are written at the new version.

Changing `format_major` therefore rewrites every catalog it touches and
loses reuse against prior generations for those subtrees. That is a real
cost and the reason the record layouts above carry reserved space.

## What this does not change

- **The overlay stays SQLite.** It is local, mutable, transactional, and
  its access patterns are still moving.
- **Nothing about packs, superblocks, or generations.** A catalog is
  still an entry in a pack, still identified by BLAKE3 over its bytes,
  still carried forward by reference when unchanged.
- **The `catalog` package's interface.** The format sits behind it, so
  `genfs`, `publish` and `fsck` do not know which implementation they
  are talking to — which is also how the two get A/B measured.

## Open questions

1. **Aliasing versus decoding.** Validated sections can be aliased as
   `[]Edge` with `unsafe.Slice`, or decoded field-by-field with
   `binary.LittleEndian` on each access. Aliasing is faster and imposes
   alignment and layout constraints that Go does not check; decoding
   costs a few nanoseconds per field and is obviously safe. Start with
   decoding, measure, and only alias if it is worth the hazard.
2. **Name prefix compression.** Sibling names in a source tree share long
   prefixes. Compressing them shrinks the arena and the download, at the
   cost of a more complex comparison in the hot lookup path. Deferred
   until the size measurement says what it would buy — and note zstd over
   the whole catalog already captures some of it.
3. **Dense inode indexing.** If a catalog's inodes turn out to be dense,
   the node section could be indexed directly rather than binary
   searched. Worth measuring on a real tree before adding a second path.
4. Whether `inline_max` belongs in the header at all, or whether recording
   the threshold a catalog was built with invites readers to depend on it.
