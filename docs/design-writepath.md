# The write path: pack as you go

Status: design, not yet built. Companion to `design-packfs.md`, which
describes the on-federation format (packs, catalogs, superblocks) and the
read path. This document covers only how bytes written by a user become
bytes in a pack, and it supersedes the staging-directory write path that
exists today.

## What is wrong with the current write path

Every modified or created file gets its own local file in the overlay's
staging directory, keyed by inode (`overlay.stagingPath`). Content stays
there for the whole session. Nothing reaches a pack until the seal, which
then does all of the chunking, hashing, packing and uploading at once.

That is correct and simple, and it costs three things:

**The seal is a burst.** Every byte and every round trip lands at
unmount, when the user is waiting, rather than during the work, when the
process is otherwise blocked on the kernel and the network is idle. A
kernel-tree extraction measured 22.5 MiB of uploads and tens of seconds
of publish, all after the user typed `exit`.

**Freezing costs a link per file.** A seal must read a view that does not
change under it while writes continue, so the snapshot hardlinks every
staging file: 31.6 s for 85k files on APFS, plus 5.9 s to unlink them
again, with the filesystem lock held. That entire mechanism exists only
because content is still local and mutable when the seal starts.

**Dead data is written anyway.** A file created, rewritten, and rewritten
again pays full local I/O for every version. Only the survivor matters,
but nothing notices until seal.

## The shape: an LSM tree whose bottom level is the federation

Writes go to a memory table. Full memory tables are flushed into packs.
The catalog names content by identity throughout, so a chunk's *location*
is resolved late, and the catalog never has to be rewritten just because
data moved from memory into a pack.

    write() ──► memtable (mmap'd buffer file) ──flush──► pack ──► federation
                     │                                    │
                     └──────── identity ──────────────────┘
                                   │
                              catalog rows (written immediately)

The three levels are:

1. **The active memtable.** An mmap'd file in the state directory.
   Chunks are appended to it; an in-memory index maps chunk identity to
   an offset within it. This is the only level that accepts writes.
2. **The flushing memtable.** When the active table fills, it is frozen
   and handed to a background flusher, and a fresh active table takes
   over. Reads consult it after the active table.
3. **Packs.** Immutable, in the federation, exactly as `design-packfs.md`
   describes. The pack index resolves identity to a location.

### The indirection: content rows name a handle, not a place

A file's content row names a list of **extent handles**. One side table
resolves a handle, and only that table changes as data moves:

| stage | a handle resolves to |
|---|---|
| in the active or flushing memtable | buffer id + offset + length |
| after flush | one or more chunk identities |
| reading a chunk | pack + offset, via the pack index |

So neither binding — identity at flush, location within a pack — ever
rewrites a catalog row. That is what keeps a flush proportional to the
data it moves rather than to the size of the tree.

### Why late-bound location falls out of the existing format

A catalog row for a file already stores `[]catalog.ChunkRef`, and a
`ChunkRef` carries the chunk's **identity** (a BLAKE3 hash), not a pack
name and offset. Resolution goes through `genfs.packIndex`, built from
the pack list.

So a chunk can be recorded with its final identity before anyone knows
which pack it will land in. Flushing adds entries to the location map; it
does not touch a catalog row. That is the property that makes the design
cheap.

**But the format does NOT already support it, contrary to what this
document originally claimed.** A prototype proved otherwise. `ChunkRef`
carries `Identity` and `LogicalOffset`, and `genfs` reads a row as "chunk
bytes [0,LLen) are file bytes [LogicalOffset, +LLen)". There is **no
offset-into-the-chunk field**. So a file whose extent was partially
overwritten has live bytes that do not tile onto whole chunks, and no
catalog row can name them. The prototype pins the case as `ErrNotTiled`.

Two ways out, and this is now the first thing to decide:

1. **Grow `ChunkRef` a chunk-offset field.** A format change, though an
   additive one under the evolution rule.
2. **CDC only the live sub-ranges of each extent**, so every emitted
   chunk is wholly live and tiles by construction. No format change; more
   chunk boundaries, and boundaries that depend on overwrite history
   rather than content alone, which weakens dedup.

What must change is the resolver: `genfs` must consult live memtables
before the pack index, and must treat "identity present in the location
map" as the terminal case rather than the only one.

### Overwrites die in memory

A chunk that is superseded before its memtable is flushed is never
uploaded. Its bytes remain in the buffer file — the table is append-only
— but the flusher walks the *live* identity set, not the buffer, so dead
chunks are skipped and their space is reclaimed when the table is
recycled.

This is the generational argument, and it is where the design earns its
keep on real workloads: build outputs, editor save-rewrite cycles,
extract-then-patch sequences. Nothing that dies young is ever sent.

A chunk that is superseded *after* its flush is ordinary garbage in a
pack, reclaimed by whatever repack eventually exists. Creating packs is
nearly free; repacking is deferrable. That is the intended asymmetry.

### Flush, and the backpressure rule

Flushing is asynchronous: the writer swaps in a fresh memtable and
returns, and a background worker chunks nothing (chunks already exist),
assembles a pack, uploads it, and then publishes the new locations into
the location map.

If the active table fills while the previous flush is still in flight,
the flush becomes **synchronous** — the writer waits. That is deliberate
backpressure: a session that produces data faster than the federation
accepts it must slow down rather than accumulate unbounded local state.
The bound is two memtables, one active and one flushing.

A checkpoint or seal forces a flush of the active table and waits for it,
which is the only case where a user-visible operation blocks on the
network by design.

### What a seal becomes

Metadata only: flush, write catalogs for whatever changed, write the
superblock, flip the ref. No chunking, no content upload, no snapshot,
no hardlink storm. The freeze machinery disappears entirely, because
there is no mutable local content to freeze — the memtable is
append-only and its live set is a value that can be captured under a
lock in constant time.

## The parts that are not obvious

### Chunking happens at flush, not at write

CDC decides boundaries from the content itself, over a rolling window, so
it needs a settled byte stream. A file still being randomly rewritten has
no such stream: an early offset can change after a later one was already
chunked.

Chunking therefore runs as a **second pass at flush time**, not as bytes
arrive:

1. Writes append raw extents to the memtable. No hashing, no boundary
   decisions, nothing that a subsequent write can invalidate.
2. At flush, collapse trivially dead extents — anything wholly superseded
   by a later write to the same inode is dropped without being examined.
3. Run CDC over what survives, producing identities.
4. Assemble the pack and upload.

This removes the limitation entirely rather than working around it.
Random rewrites collapse in step 2 exactly like sequential ones, because
by flush time the data has settled by construction: the memtable is
frozen before the pass begins. The deferred-inode hatch below is then an
optimization for pathological churn, not a correctness requirement.

CDC was also going to be a **backpressure release valve** — abandon the
pass under pressure, trade dedup for latency. **Measurement says do not
build it.** With the valve a prototype session ran 10.31 s and abandoned
38 of 39 flushes; with the valve disabled it ran **7.77 s** and abandoned
none. Abandoning still has to hash every extent, because a pack key *is*
the chunk identity — only the cut search is skipped — so it trades a
cheap gear-hash scan for extra pack entries and comes out behind. It also
fired on nearly every flush even at zero modelled latency, so it was
never the exception this document imagined.

Identity is therefore bound at flush, along with location. See the
indirection note above: content rows name a stable extent handle, and one
side table resolves that handle to a memtable offset before the flush and
to chunk identities after it. Neither binding rewrites a catalog row.

### The deferred-inode escape hatch

An inode that produces large volumes of nearly-instantly-dead data, or
that is randomly rewritten, is redirected to a real local file — what the
staging directory does today — and chunked once when it settles (on
close, or at seal). The kernel's page cache collapses the churn, which is
exactly what it is good at, and pelfs never sees the intermediate states.

Detection is a heuristic and should start crude: bytes written to an
inode far exceeding its live length, or any write that is not at the
current end of file. Both are cheap to measure per inode. Promotion is
one-way within a session — an inode that has gone to a real file stays
there — because the alternative is a policy that oscillates.

This is a future optimization, not part of the first implementation, but
the memtable interface should be shaped so it can be added without
restructuring: content for an inode resolves through one indirection that
can point at either level.

### Crash recovery

The buffer file is mmap'd, so writes are not durable at the moment they
land. The recovery contract must be stated in terms of what a POSIX
filesystem promises, which is nothing without `fsync` — but the
*internal* state must be consistent regardless of when the crash occurs.

The rule: a catalog row may reference an identity that recovery cannot
find, and recovery must treat that as the file having lost that content,
not as corruption. Concretely, on reopening a state directory:

1. Scan the buffer file, validating each record against its own length
   and checksum, and stop at the first malformed record — everything
   after it is a torn tail.
2. Rebuild the identity→offset index from the surviving records.
3. Drop overlay content rows whose identities are neither in the rebuilt
   index nor in the location map, and report them.

Step 3 is the part that must be loud: it is data loss from a crash, and
the user is entitled to know which files are affected. A silent partial
recovery would be far worse than a refusal.

Open question: whether to msync at file-close boundaries to narrow the
window, and whether that is worth the cost. Measure before deciding.

### Reads during a session

A read resolves an identity in order: active memtable, flushing
memtable, location map, then the federation. The first two are pointer
arithmetic into an mmap, so the common case of reading back what you just
wrote never touches the network — better than today, where a read of
staged content goes through the staging file.

The ordering must be stable across a flush completing mid-read. The
simplest correct discipline is to resolve identity to a *source* under
the lock, then read outside it, since neither a memtable's bytes nor a
pack's are mutable once written.

### Interaction with the overlay's metadata

None of this changes how names, attributes, and directory structure are
stored: they stay in the overlay's SQLite database. What changes is the
content side — `ocontent` rows stop meaning "there is a staging file for
this inode" and start meaning "this inode's content is this list of
identities". The `materializeContentLocked` path and the staging
directory go away for every inode that is not deferred.

## Repack: cheap liveness, and running it when nobody is waiting

Packing as you go writes more packs and strands more dead bytes, so this
design raises the pressure for a repack that v2 currently does not have
at all. Two questions decide it: how to know a repack is needed without
paying to find out, and when to run it.

### Liveness is nearly free if the seal records it

A pack's exact live fraction requires walking every retained generation's
catalogs — far too expensive to ask casually. But a seal is already
walking the whole changed tree and already resolves identities through
the location map, so it can attribute bytes to packs as it goes at
essentially no marginal cost.

Proposal: record per-pack **live bytes for the generation being
published** in the superblock's pack list, beside the fields already
there. Liveness is then `live / stored`, available to any client that
reads the superblock, with no extra I/O — and shared, so a repack
decision does not depend on which client happens to hold local state.

Two honest caveats:

- It is liveness *for the newest generation*, and older retained
  generations may still reference chunks the newest one dropped. So the
  figure over-estimates garbage, by an amount the retention policy
  bounds. Treat it as a trigger, not as an accounting of reclaimable
  space; the repack itself must confirm against the retention set before
  deleting anything.
- It costs a field per pack per generation. The pack list already grows
  per generation, and this makes each entry slightly larger. Worth
  measuring against a volume with thousands of packs before committing.

### Run it when the mount is quiet

Repack is I/O the user did not ask for, so it should not compete with
work they did.

- **Detect** from the recorded liveness at seal, against a threshold that
  measurement should set — earlier work found 0.50 the most expensive
  useful setting and recommended 0.25–0.30, with a garbage floor that
  scales with volume size rather than a fixed 256 MiB.
- **Wait for quiescence**: no write activity for about a second.
- **Work in small units, re-checking quiet between them**, so the first
  write after a repack starts stalls at most one unit rather than the
  whole job. Bound the unit in round trips, not bytes: measurement showed
  a byte budget means ~16 requests on a big-file volume and ~2,500 on a
  source tree.
- **Never block on it** except when liveness is dire, and even then treat
  a blocking implicit repack as an optimization to be justified rather
  than assumed — a mount that stalls to tidy itself is worse than a
  volume that is temporarily fat.

Coalescing adjacent live entries is the single biggest lever measured on
the old implementation: 9,000 requests down to 132 for 1.7x the bytes.
Any repack built here should start with it.

## What this does not solve

- **The walk and transform still dominate a seal.** Profiling puts them
  at 77% of publish, as ~8 SQLite point queries per inode. That is a
  separate problem in `internal/publish/source.go` and this design
  neither helps nor hurts it.
- **Garbage accumulates faster.** More packs are written, and chunks that
  die after a flush are dead weight until a repack exists. The v2 tree
  currently has no repack at all; this design increases the pressure to
  build one, with the round-trip-budgeted policy that measurement already
  recommended.
- **A pack per flush may be too small.** If a session flushes several
  partly-full memtables, the volume accrues small packs. Coalescing them
  is repack's job, but the memtable size and the pack target should be
  the same number so the common case produces full packs.

## What a prototype measured, and what it falsified

`internal/memtable` is a working vertical slice beside the staging path.
On 85k files (2442 MiB written, 1688 MiB live, 50 ms modelled pack round
trip, APFS):

| | staging | memtable |
|---|---|---|
| write | 31.90 s | 10.08 s |
| freeze | 39.97 s link + 5.40 s unlink | **0** |
| seal | 37.30 s, 1688 MiB | **0.23 s, 59 MiB** |
| total | 114.56 s | **10.31 s** |
| peak local content | 1688 MiB | **128 MiB** |

Flush overlaps writing as intended: 1629 of 1688 MiB left during the
write phase, and the seal moves one memtable's tail — 3.5% of the
session. The freeze disappears. Those are the wins, and they hold.

Corrections this document owes:

- **"The live set is a value captured under a lock in constant time"** is
  wrong. It is proportional to the content refs of the inodes the table
  touched — proportional to the flush rather than to the tree, which is
  the property that matters, but not constant.
- **"Resolve to a source under the lock, then read outside it"** is
  necessary and not sufficient. Immutable bytes still get *unmapped* when
  a table is recycled, so an unpinned read is a segfault, not a stale
  read. Tables need pin/unpin.
- **The location map must be durable, and nothing in the format can
  rebuild it.** Pack trailers know identities; nothing on the federation
  has ever heard of an extent handle. So a flush owes one durable row per
  surviving extent — a real write per extent per flush that "flushing
  does not touch a catalog row" quietly omitted.
- **"Dead data is written anyway"** overstates the case against staging.
  Staging never *uploads* dead versions either; it overwrites in place.
  The 754 MiB never sent is what keeps an append-only buffer from being
  ~45% worse than staging, not a win over it.
- **Memtable size must exceed the pack target, not equal it.** A 64 MiB
  table holding ~31% dead bytes yields ~43 MiB packs against a 64 MiB
  target — 39 packs where staging wrote 27. Either size the table above
  the target or carry a partial pack across flushes.
- **Backpressure binds structurally, not just under burst**: 38 of 39
  rotations blocked. Two tables means session throughput equals flusher
  throughput. That is the intent, but the consequence is that a burst
  staging absorbs at local-disk speed now throttles continuously. A
  product trade to make deliberately.

## Settled

- **Crash recovery** as described above. `fsync` flows through to the
  mmap'd buffer, and torn tails are detected by a **CRC per record**. The
  expected deployment ties a mount to a job, so the common recovery is
  discarding the state along with the failed job — recovery must be
  correct and loud, but it is not the path to optimize.
- **Memtable size**: deferred until there is operating experience. Start
  at the pack target and revisit with numbers.
- **One flushing table**, not a list. Revisit only if bursts prove it too
  coarse.
- **Identity binds at flush**, not at write, which the second-pass
  chunking above requires anyway.
- **`--no-seal` goes away.** It exists so a session can keep an overlay
  and resume it later; with memtables that promise grows to recovering a
  buffer file, and the feature has no remaining user.

## Open questions

1. Does the per-pack live-byte field belong in the superblock's pack list
   at all, given it grows per generation on volumes that may hold
   thousands of packs? A local sidecar is cheaper but unshared, so a
   second client cannot act on it.
2. When CDC is skipped under backpressure, should the extents be emitted
   as one chunk per extent, or split at a fixed size so a later repack
   has boundaries to work with? Fixed splitting costs nothing now and may
   make a future repack cheaper.
3. Should a flush upload one pack or several concurrently? The packer
   already runs four uploads at once, but a flusher that inherits that
   has to order location-map updates against partial failures.
4. Is there a case for flushing on idle — no writes for some interval —
   rather than only on a full table? It would shorten the crash-loss
   window and smooth uploads, at the cost of smaller packs.
