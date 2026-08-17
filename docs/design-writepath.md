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

### Two kinds of flush, and only one of them waits

"Flush" names two operations with different contracts, and conflating
them is a mistake the prototype made — its `Flush` blocks on the network
and is documented as "what a checkpoint or a seal calls".

**Background flush (periodic, while mounted).** Takes a consistent point
— freeze the memtable, capture the catalog state that goes with it — and
**returns immediately**. Packing, uploading and the ref flip proceed in
the background while the mount keeps serving and the user keeps writing.
This is what `--snapshot-interval` drives. It must not block: a mount
that stalls every few minutes to talk to a federation is precisely the
behaviour the snapshot-based checkpoint was removed for.

Consequences to design for:
- The published generation appears *later* than the checkpoint that
  started it. That is fine — the mount serves its own view regardless,
  and the branch head simply advances when the publication lands.
- Publications must not overtake one another: generation N's ref flip
  has to precede N+1's, so a checkpoint whose publication is still in
  flight when the next one fires must either coalesce with it or be
  skipped. Skipping is the simpler rule and loses nothing, since the
  later checkpoint covers a superset.
- A failed background publication must not fail the mount. Retry on the
  next interval; the memtable and the buffer file remain authoritative
  until publication succeeds.

**Synchronous flush (explicit, or at shutdown).** `pelfs ctl publish`,
and the seal at exit. These *must* complete before returning, because the
caller's whole purpose is to know the data has landed — neither the CLI
verb nor a shell exit may finish while bytes are still in flight. This is
the only place a user waits on the network by design, and at shutdown it
is unavoidable: the process is about to stop, so anything unpublished
would be lost or left for a later mount to recover.

The practical effect on a session: writes pace against the flusher (the
backpressure rule below), periodic checkpoints cost nothing observable,
and exit waits only for whatever the last interval did not already cover.

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

## Should small files still be inlined?

Today a file at or below `InlineMax` is stored **inline in the catalog**
— its bytes live in a SQLite row rather than as a chunk in a pack. On a
kernel tree that is 51% of files, and the argument for it is read
latency: the catalog has already been fetched, so a small file costs zero
additional round trips.

The cost is paid at every seal, and it is now the largest one left.
Profiling an 80k-file tree put `catalog.Inline` at ~1.0s, and it is
**byte movement, not query overhead**: roughly 160 MB read out of base
catalogs and written into new ones, because a catalog that must be
rewritten carries its inline bytes with it. Batching queries cannot touch
it; the pages have to move.

That reframes the question as: *inline inside a packfile, or inline
inside SQLite?* Small files no longer cost an inode either way — a pack
entry is just an entry — so the choice is purely about where the bytes
live and when they move.

Packing them instead would:

- move those 160 MB out of the synchronous exit and into the memtable
  flush, where they upload during the session like everything else;
- make catalogs small, which makes rewriting one cheap and makes
  carry-forward more effective, since a catalog would hold references
  rather than content;
- cost a round trip on a **cold** read of a small file, where inline
  costs none. The pack cache mitigates this — it promotes a whole pack
  once enough distinct entries have been demanded — but the first reader
  of a scattered small file pays.

The likely answer is a much lower `InlineMax` rather than none at all:
keep inlining where a chunk's own overhead would dominate the payload
(hundreds of bytes), pack everything above it. That needs measuring, not
guessing, and the measurement is specific: seal cost and catalog size as
a function of `InlineMax`, against cold-read latency for a small file at
each setting.

Worth noting the interaction with generations: inline bytes are rewritten
into a new catalog on *every* generation that touches that catalog, so
the cost recurs for the life of the volume, while a packed chunk is
written once and referenced thereafter.

### Measured: keep 4096

`TestInlineMaxSweep` (`internal/publish`) sweeps the threshold over a real
Linux 6.6 checkout — 81,690 files, 5,316 directories, 1290.8 MiB, 51.4% of
files at or below 4096, which is the corpus the paragraphs above describe.
Every byte and request count below is reproducible to the byte across
runs; wall times are macOS and vary 10–30% run to run, so both runs are
shown where they differ.

| | never | 512 | 1024 | **4096** | 16384 |
|---|---|---|---|---|---|
| files inlined | 0 | 11.5% | 21.0% | **51.4%** | 81.8% |
| catalogs in the generation | 3 | 3 | 5 | **24** | 105 |
| initial seal, wall | 22.3 s | 19.0 s | 20.2–26.1 s | **20.6–21.4 s** | 22.3–23.6 s |
| initial seal, uploaded | 263.3 MiB | 261.8 | 259.8 | **248.8** | 230.2 |
| … catalog (exit-only) | 5.6 MiB | 6.1 | 7.5 | **19.9** | 65.5 |
| … data (session-flushable) | 254.3 MiB | 252.6 | 249.6 | **227.2** | 164.1 |
| one-file seal, wall | 1.61–1.80 s | 1.59–1.63 s | 1.36–1.39 s | **0.85 s** | 0.85–1.34 s |
| one-file seal, namespace rebuilt | 79.4% | 78.0% | 63.4% | **23.0%** | 10.1% |
| whole-tree reseal, wall | 2.03–2.14 s | 1.97–2.10 s | 1.87–2.14 s | **2.24–2.81 s** | 4.18–4.85 s |
| whole-tree reseal, uploaded | 5.6 MiB | 6.1 | 7.5 | **19.9** | 65.5 |
| 100 scattered small reads, cold | 2.29 s, 102 GET, 3.5 MiB | 1.92, 85, 3.8 | 1.62, 70, 5.5 | **1.23–1.29, 48, 16.8** | 1.41–1.48, 39, 70.5 |
| … a neighbour in each directory | 2.20, 99 GET | 1.78, 79 | 1.40, 63 | **0.67–0.72, 30** | 0.006, 0 |
| `grep -r arch/powerpc`, 2026 files | 20.6–21.3 s, 909 GET | 17.9–19.3, 783 | 15.8, 693 | **9.2–9.3, 404** | 2.7, 116 |
| mount (open + root readdir) | 118 ms, 6.7 MiB | 115, 6.4 | 126, 5.9 | **109, 4.4** | 95, 3.8 |

Reads are against a store with a modelled 20 ms round trip; warm re-reads
cost 0 GET at every threshold, so only the cold column discriminates.

**The guess above was wrong in direction.** Lowering `InlineMax` makes
every measured axis worse except one, and the one it improves is smaller
than it looks. Three findings the framing missed:

**Inline bytes are what make catalogs numerous.** Catalog weight is
`200·entries + inline_bytes` and the split bounds it at `SMax` — so a
catalog costs about the same to rewrite whatever the threshold is, and
what the threshold moves is how MANY catalogs the tree has. With nothing
inline the kernel tree weighs 16.6 MiB and splits into **3** catalogs, and
one changed file rebuilds 79% of the namespace. At 4096 it weighs 78.7 MiB
and splits into **24**, and one changed file rebuilds 23% — 15 subtrees
pruned, 21 catalogs carried by reference, and a one-file seal that takes
0.85 s instead of 1.6–1.8 s. Packing does not "make catalogs small"; it
makes them few.

**Inlining uploads fewer bytes, not more.** Total wire falls monotonically
as the threshold rises: 263.3 MiB at never, 248.8 at 4096, 230.2 at 16384.
A chunked small file costs a chunkref row plus a pack trailer entry that an
inline file does not, and a catalog is zstd-encoded as one blob over
thousands of files' source text, which compresses far better than a
separate frame per 1–4 KiB chunk. "Inline in a packfile or inline in
SQLite" is not byte-neutral: SQLite is the cheaper container for small
source files.

**The pack cache does not mitigate the cold small-file read.** With
nothing inline, reading a *different* small file from each sampled
directory still costs one GET per file (99 GET for 99 files) — the
promotion rule's ratio guard refuses for a scattered reader, exactly as
designed, and the scattered reader is the interactive case. The
mitigation only appears once the files are inline, so it is no defence of
packing them.

What packing genuinely buys is the one thing the memtable cares about:
bytes that can leave during the session. At 4096, 19.9 MiB of the initial
seal can only move after the walk, against 5.6 MiB at never — the seal
uploads 14.5 MiB *less* in total but 14.3 MiB more of it lands in the
synchronous exit. That penalty applies only to a generation that rewrites
the whole tree; the steady-state one-file seal moves 5.1 MiB at 4096
against 4.5 MiB at never, and it finishes twice as fast.

Going the other way past 4096 stops paying. 16384 buys a much faster
directory walk (2.7 s against 9.2 s) but converts round trips into
bandwidth: 70.5 MiB transferred to read 100 scattered small files, against
16.8 MiB at 4096 — and it is *slower* in wall time, because the catalog a
scattered reader must pull grows with the threshold. Its whole-tree reseal
also doubles, to 65.5 MiB and 4.2–4.8 s.

The workloads do disagree — batch extraction keeps improving past 16384,
interactive browsing has its latency minimum at 4096 and its byte cost
exploding past it — and there is one default. 4096 is at the interactive
optimum and already 2.3× better than never on the batch walk, so it is the
value that serves both.

**Settled: `DefaultInlineMax` stays 4096.** Nothing in the sweep argues
for lowering it, and the recurring cost the section opens with is real but
small: the whole-tree reseal that carries all 62.1 MiB of inline bytes
forward costs 2.24–2.81 s against 2.03–2.14 s with nothing inline at all.

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
