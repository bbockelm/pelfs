# The write path: pack as you go

> **Status: DESIGN. Not built, and not scheduled.** Nothing in this
> document describes how pelfs writes today. The shipped write path is
> the overlay plus staging directory described in `design-packfs.md`:
> every modified file gets a local file keyed by inode, and the seal at
> unmount does all the chunking, packing and uploading at once.
>
> The only code that exists is `internal/memtable`, a vertical slice
> built to measure the idea. **No non-test file in the tree imports it.**
> It is not wired into a mount, a seal, or a checkpoint, and removing it
> would change no user-visible behaviour. Where this document says "the
> prototype", it means that package; everything else is unimplemented.
>
> Read `design-packfs.md` for the format and the read path. This document
> covers only how bytes written by a user would become bytes in a pack,
> and what measurement has already said about that.

## What is wrong with the current write path

Every modified or created file gets its own local file in the overlay's
staging directory, keyed by inode (`overlay.stagingPath`). Content stays
there for the whole session. Nothing reaches a pack until a checkpoint or
the seal, which then does all of the chunking, hashing, packing and
uploading at once.

That is correct and simple, and it costs two things.

**The seal is a burst.** Every byte and every round trip lands at the
checkpoint or at unmount, when the user is waiting, rather than during the
work, when the process is otherwise blocked on the kernel and the network
is idle. A kernel-tree extraction measured 22.5 MiB of uploads and tens of
seconds of publish, all after the user typed `exit`.

**Dead data is written locally anyway.** A file created, rewritten, and
rewritten again pays full local I/O for every version. Only the survivor
matters, but nothing notices until the content is chunked. (This is a
weaker complaint than it looks; see the correction in "What the prototype
falsified" — staging never *uploads* the dead versions either.)

A third cost — the freeze — has since been paid down without any of this,
twice. A seal needs a view that does not change under it, and freezing one
used to hardlink every staging file: measured at 31.6 s for 85k files on
APFS (362 µs per link) plus 5.9 s to unlink them again. First, the **seal
at unmount no longer freezes at all**: it runs after the mountpoint is
gone and the server has stopped, so the live overlay already is an
instant. Then the remaining path, the mid-session **checkpoint**, stopped
copying anything at freeze time: it records each staged file's length and
reads the live staging files, and the live side hands a file over — one
rename — only when it is about to disturb bytes below the recorded length.
A 28k-file checkpoint went from 8.5 s of overlay lock hold to tens of
milliseconds, which matters because the lock is the mount: at 8.5 s the
NFS client had already declared the server unresponsive and writes were
failing.

So the freeze cost is now bounded to what a checkpoint's writers actually
disturb, and a write path that removed mutable local content would remove
what is left of it rather than all of it.

## The shape: an LSM tree whose bottom level is the federation

Writes go to a memory table. Full memory tables are flushed into packs.
The catalog names content by identity throughout, so a chunk's *location*
is resolved late, and the catalog never has to be rewritten just because
data moved from memory into a pack.

    write() ──► memtable (mmap'd ring file) ──flush──► pack ──► federation
                     │                                   │
                     └──────── identity ─────────────────┘
                                   │
                              catalog rows (written immediately)

The levels are:

1. **The active memtable.** An mmap'd file in the state directory.
   Chunks are appended to it; an in-memory index maps chunk identity to
   an offset within it. This is the only level that accepts writes.
2. **The flushing memtable.** When the active table fills, it is frozen
   and handed to a background flusher, and a fresh active table takes
   over. Reads consult it after the active table. (One flushing table,
   not a list — see "Settled".)
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

### The format does not yet support late-bound identity

This document originally claimed the existing format already supported
this, because a `catalog.ChunkRef` carries a BLAKE3 **identity** rather
than a pack name and offset, resolved through `genfs`'s pack index. The
claim was false and only a prototype found it.

`ChunkRef` carries `Identity`, `LogicalOffset`, `LLen` and `CLen`, and
`genfs` reads a row as "chunk bytes `[0,LLen)` are file bytes
`[LogicalOffset, +LLen)`". There is **no offset-into-the-chunk field**. So
a file whose extent was partially overwritten has live bytes that do not
tile onto whole chunks, and no catalog row can name them. The prototype
pins the case as `ErrNotTiled` (`internal/memtable/catalogrefs.go`).

Two ways out, and this is the first thing to decide:

1. **Grow `ChunkRef` a chunk-offset field.** A format change, though an
   additive one under the evolution rule.
2. **CDC only the live sub-ranges of each extent**, so every emitted
   chunk is wholly live and tiles by construction. No format change; more
   chunk boundaries, and boundaries that depend on overwrite history
   rather than content alone, which weakens dedup.

The resolver must change either way: `genfs` must consult live memtables
before the pack index, and must treat "identity present in the location
map" as the terminal case rather than the only one.

### Overwrites die in memory

A chunk that is superseded before its memtable is flushed is never
uploaded. Its bytes remain in the buffer file — the table is append-only
— but the flusher walks the *live* identity set, not the buffer, so dead
chunks are skipped and their space is reclaimed when the region is
recycled.

This is the generational argument, and it is where the design earns its
keep on real workloads: build outputs, editor save-rewrite cycles,
extract-then-patch sequences. Nothing that dies young is ever sent.

A chunk that is superseded *after* its flush is ordinary garbage in a
pack, reclaimed by whatever repack eventually exists. Creating packs is
nearly free; repacking is deferrable. That is the intended asymmetry —
and the pressure it puts on a repack that does not exist is the largest
cost this design carries.

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
behaviour the checkpoint is meant to avoid.

Consequences to design for:
- The published generation appears *later* than the checkpoint that
  started it. That is fine — the mount serves its own view regardless,
  and the branch head simply advances when the publication lands.
- Publications must not overtake one another: generation N's ref flip
  has to precede N+1's, so a checkpoint whose publication is still in
  flight when the next one fires must either coalesce with it or be
  skipped. Skipping is the simpler rule and loses nothing, since the
  later checkpoint covers a superset. (The shipped checkpoint already
  serializes this way — publishes never overlap.)
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

### Aging, not settling: when content is eligible to leave

Extents are promoted by **age**: elapsed time or, more usefully,
accumulated bytes behind them. An extent superseded before it is promoted
was never sent, and one that survives promotion was stable enough to be
worth sending. Nothing has to predict a file's future, and the rule
tunes itself — a burst pushes data through faster, filling the uplink
exactly when there is something to fill it with. The `tar` case falls
out: each file is written once, nothing supersedes it, and its extents
age straight through. (The rejected alternative — waiting for a file to
look "settled" — is in the appendix.)

### One ring, not a stack of tables

The buffer is a **ring**. Writes append at the head; packing consumes
from the tail; a reclaimed region is immediately reusable. Three
consequences, and the first is the one that answers what discrete levels
would have cost:

- **Duplication is bounded by pack size, not table size.** A tail region
  becomes a pack, the pack is uploaded, the region is reclaimed. What
  exists twice is the few packs in flight rather than a whole table — and
  it improves as the pack target shrinks, which suits a 2 MiB target.
- **Backpressure is gradual instead of a cliff.** A writer blocks only
  when the head catches the tail, and the tail advances continuously. The
  two-table prototype blocked on 38 of 39 rotations, in whole-table
  steps; a ring paces a fast writer smoothly against the uplink.
- **Age becomes a coordinate, not a level.** How old an extent is, is
  simply how far behind the head it sits — `Ring.Promotable` is one
  subtraction. Promotion is one distance rather than a level count plus a
  copy per hop, which dissolves the question of how many levels are worth
  having.

What a ring does not fix: a dead extent in the middle still occupies its
space until the tail passes it. It is skipped at packing and never
uploaded, so the generational win survives intact — but unlike dropping a
whole table, it does not free space early.

### Reclamation, wraparound, recovery

Three obligations the ring adds, all of them well-trodden, and all three
implemented in the prototype:

**A reader watermark.** The tail may not advance past the oldest offset a
reader still holds (`Pin`/`Unpin`/`oldestPin`, enforced inside
`Reclaim`). The underlying lesson came from the two-table prototype:
recycling a table unmaps bytes a reader may be mid-read of, which is a
segfault rather than a stale answer. A ring makes it finer-grained rather
than different in kind.

**Wraparound.** A record never straddles the seam: a writer that cannot
fit one pads to the end and wraps. Usable capacity is therefore slightly
below the buffer size, which is a reason to size the buffer above the
promotion distance rather than at it. It is also why the largest record
is capped at a *fraction* of the ring (`MaxRecord` = ring/16 minus the
header) rather than at whatever happens to fit: a pad plus a record must
always fit in a drained ring, or a writer waiting for a packer with
nothing left to pack waits forever.

**Sequenced records.** An append-only log is recovered by scanning until
a bad CRC. A ring cannot be, because stale bytes beyond the head are
well-formed records from a previous lap. Every record carries a
monotonically increasing sequence number and a crc32c over its header and
payload, and recovery accepts the longest run whose sequences ascend —
the discipline a write-ahead log uses, and the reason recovery is written
in terms of "the surviving run" rather than "everything before the first
bad CRC".

### Queued for upload is the seal boundary

**A pack queued for upload is sealed.** Its bytes and its identity are
fixed from that moment; nothing rewrites it. Everything below that line —
the active table, any frozen level — is still rewritable, and compaction
there is free because no one outside the process has seen it.

This is a better boundary than "settled per file" because it is a
property of the pack rather than a guess about a file, and it gives
compaction one unambiguous line to respect.

It raises a question that turns out to be already answered: a pack
uploaded mid-session is in no generation's pack list until the next ref
flip, so what stops a concurrent GC from deleting it? The age guard.
Pack names embed their creation time (`p-<unixnano hex>-<rand>`), and
retention skips anything younger than `Params.TGraceSeconds`, 72 hours by
default. The window between uploading a pack and referencing it is
minutes. The guard was built for coordination-free safety among writers
and it covers this case by three orders of magnitude — but **no test
pins it**, and until one does it is a coincidence rather than a
guarantee.

### Sizes

Starting points, to be revised with operating experience. The prototype's
constants are named where they exist:

| | design | in `internal/memtable` |
|---|---|---|
| ring buffer | 72 MiB | `DefaultRingSize` = 72 MiB |
| promotion distance (start packing) | 64 MiB | `DefaultPromotionDistance` = 64 MiB |
| headroom before a writer blocks | 8 MiB | no constant; it is the difference of the two |
| largest single record | — | `MaxRecord` = ring/16 ≈ 4.5 MiB |
| queued-for-upload threshold | 64 MiB | **no counterpart in code** |
| pack target | 2 MiB today, plausibly 4–16 MiB | `publish.DefaultTargetPackSize` = 2 MiB |

Note that `memtable.Store` does not default to the ring sizes above: its
`DefaultTableSize` is 64 MiB with a promotion distance of zero, which
packs whatever is present. That is what a one-shot flush wants, and a
session would have to pass the ring defaults explicitly. The two sets of
numbers should be reconciled when this is built.

The buffer is deliberately LARGER than the promotion distance. Packing is
not free — it chunks, hashes and compresses — so a writer that filled the
buffer exactly at the moment packing began would block immediately and
every time. The 8 MiB of slack is the writer's runway: it keeps writing
while the tail is being drained, and blocks only if it outruns the
packer by more than that.

The promotion distance bounds how much a crash can lose and how far a
session may run ahead of its uplink. The pack target is a separate dial
— it sets what a READER fetches, since a reader takes packs whole — and
the sweep put it at 2 MiB on the argument that a scattered reader pays a
factor of two there against seventeen at 64 MiB. It is the number least
settled of the four.

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
superblock, flip the ref. No chunking, no content upload, no freeze. The
freeze machinery would disappear from the checkpoint path too, because
there would be no mutable local content to freeze — the memtable is
append-only and its live set can be captured under a lock. (Not in
constant time; see the corrections below.)

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

Identity is therefore bound at flush, along with location. See the
indirection note above: content rows name a stable extent handle, and one
side table resolves that handle to a memtable offset before the flush and
to chunk identities after it.

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

This is a future optimization, not part of a first implementation, but
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
   and checksum, and take the longest run of ascending sequence numbers
   — everything after it is a torn tail or a previous lap.
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

The ordering must be stable across a flush completing mid-read. Resolving
identity to a *source* under the lock and reading outside it is necessary
and not sufficient: immutable bytes still get unmapped when a region is
recycled, so the source must also be pinned.

### Interaction with the overlay's metadata

None of this changes how names, attributes, and directory structure are
stored: they stay in the overlay's SQLite database. What changes is the
content side — `ocontent` rows stop meaning "there is a staging file for
this inode" and start meaning "this inode's content is this list of
identities". The `materializeContentLocked` path and the staging
directory go away for every inode that is not deferred.

## Repack: cheap liveness, and running it when nobody is waiting

**There is no repack in the tree.** Not a partial one — no function, no
command, no scheduler. `superblock.Condemned` exists as a field and
nothing writes it; `retention.GC` reads it and would honour it. Packing
as you go writes more packs and strands more dead bytes, so this design
raises the pressure for the repack that is already missing. Two questions
decide it: how to know a repack is needed without paying to find out, and
when to run it.

### Liveness is nearly free if the seal records it

A pack's exact live fraction requires walking every retained generation's
catalogs — far too expensive to ask casually. But a seal is already
walking the whole changed tree and already resolves identities through
the location map, so it can attribute bytes to packs as it goes at
essentially no marginal cost.

Proposal: record per-pack **live bytes for the generation being
published** in the superblock's pack list, beside the fields already
there (`superblock.PackEntry` carries name, size and trailer hash, and no
liveness). Liveness is then `live / stored`, available to any client that
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
  die after a flush are dead weight until a repack exists.
- **A pack per flush may be too small.** If a session flushes several
  partly-full memtables, the volume accrues small packs. Coalescing them
  is repack's job.

## What the prototype measured, and what it falsified

`internal/memtable` is a working vertical slice beside the staging path,
exercised only by its own tests. On 85k files (2442 MiB written, 1688 MiB
live, 50 ms modelled pack round trip, APFS):

| | staging | memtable |
|---|---|---|
| write | 31.90 s | 10.08 s |
| freeze | 39.97 s link + 5.40 s unlink | **0** |
| seal | 37.30 s, 1688 MiB | **0.23 s, 59 MiB** |
| total | 114.56 s | **10.31 s** |
| peak local content | 1688 MiB | **128 MiB** |

Flush overlaps writing as intended: 1629 of 1688 MiB left during the
write phase, and the seal moves one memtable's tail — 3.5% of the
session. Those are the wins, and they hold. Note that the freeze row no
longer measures a difference against the shipped seal at unmount, which
does not freeze; it measures the difference against a checkpoint.

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
- **The format does not support late-bound identity**, as recorded above.
  This is the correction that cost the most to find.

## Should small files still be inlined?

A file at or below `InlineMax` is stored **inline in the catalog** — its
bytes live in a catalog record rather than as a chunk in a pack. The
argument for it is read latency: the catalog has already been fetched, so
a small file costs zero additional round trips.

The cost is paid at every seal. Profiling an 80k-file tree put
`catalog.Inline` at ~1.0s, and it is **byte movement, not query
overhead**: roughly 160 MB read out of base catalogs and written into new
ones, because a catalog that must be rewritten carries its inline bytes
with it. Batching queries cannot touch it; the pages have to move.

That reframes the question as: *inline inside a packfile, or inline
inside a catalog?* Small files no longer cost an inode either way — a
pack entry is just an entry — so the choice is purely about where the
bytes live and when they move. It matters to this design specifically,
because inline bytes are the part of a seal that **cannot** move during
the session: a catalog is not identified until the tree is.

### Measured

`TestInlineMaxSweep` (`internal/publish`) sweeps the threshold over a real
Linux 6.6 checkout — 81,690 files, 5,316 directories, 1290.8 MiB, 51.4% of
files at or below 4096. Every byte and request count below is reproducible
to the byte across runs; wall times are macOS and vary 10–30% run to run,
so both runs are shown where they differ.

| | never | 512 | 1024 | 4096 | 16384 |
|---|---|---|---|---|---|
| files inlined | 0 | 11.5% | 21.0% | 51.4% | 81.8% |
| catalogs in the generation | 3 | 3 | 5 | 24 | 105 |
| initial seal, wall | 22.3 s | 19.0 s | 20.2–26.1 s | 20.6–21.4 s | 22.3–23.6 s |
| initial seal, uploaded | 263.3 MiB | 261.8 | 259.8 | 248.8 | 230.2 |
| … catalog (exit-only) | 5.6 MiB | 6.1 | 7.5 | 19.9 | 65.5 |
| … data (session-flushable) | 254.3 MiB | 252.6 | 249.6 | 227.2 | 164.1 |
| one-file seal, wall | 1.61–1.80 s | 1.59–1.63 s | 1.36–1.39 s | 0.85 s | 0.85–1.34 s |
| one-file seal, namespace rebuilt | 79.4% | 78.0% | 63.4% | 23.0% | 10.1% |
| whole-tree reseal, wall | 2.03–2.14 s | 1.97–2.10 s | 1.87–2.14 s | 2.24–2.81 s | 4.18–4.85 s |
| whole-tree reseal, uploaded | 5.6 MiB | 6.1 | 7.5 | 19.9 | 65.5 |
| 100 scattered small reads, cold | 2.29 s, 102 GET, 3.5 MiB | 1.92, 85, 3.8 | 1.62, 70, 5.5 | 1.23–1.29, 48, 16.8 | 1.41–1.48, 39, 70.5 |
| … a neighbour in each directory | 2.20, 99 GET | 1.78, 79 | 1.40, 63 | 0.67–0.72, 30 | 0.006, 0 |
| `grep -r arch/powerpc`, 2026 files | 20.6–21.3 s, 909 GET | 17.9–19.3, 783 | 15.8, 693 | 9.2–9.3, 404 | 2.7, 116 |
| mount (open + root readdir) | 118 ms, 6.7 MiB | 115, 6.4 | 126, 5.9 | 109, 4.4 | 95, 3.8 |

Reads are against a store with a modelled 20 ms round trip; warm re-reads
cost 0 GET at every threshold, so only the cold column discriminates.

**The guess that packing small files would help was wrong in direction.**
Lowering `InlineMax` toward zero makes every measured axis worse except
one, and the one it improves is smaller than it looks. Three findings the
framing missed:

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
separate frame per 1–4 KiB chunk. "Inline in a packfile or inline in a
catalog" is not byte-neutral: the catalog is the cheaper container for
small source files.

**A whole-pack fetch does not rescue the cold small-file read.** With
nothing inline, reading a *different* small file from each sampled
directory still costs one GET per file (99 GET for 99 files) — the
scattered reader is the interactive case, and it is exactly the case a
pack-granular transfer serves worst. The mitigation only appears once the
files are inline, so it is no defence of packing them.

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

### Shipped: 2048

`publish.DefaultInlineMax` is **2048**, taken as the deliberate middle
between the two effects above. Catalog bytes are the part of a seal that
cannot move before exit, and 2048 halves them against 4096 — 11.2 MiB
against 19.9 on this tree — while a one-file change still rebuilds only
41% of the namespace against 23%. Raising it trades exit latency for read
locality; lowering it trades incremental seal cost for it.

Those figures are measured, not interpolated between the columns above:
they come from a separate run of the same harness over the same corpus at
1024/2048/4096. The full 2048 row — 9 catalogs, 41.2 MiB of namespace,
initial seal 255.5 MiB on the wire (11.2 catalog + 242.1 data), one-file
seal 1.15 s rebuilding 40.9% of the namespace with 6 catalogs reused and
5 subtrees pruned, whole-tree reseal 1.94 s (the fastest of the three),
100 scattered cold reads in 1.34 s over 57 GET.

The sweep's default value list now includes 2048, so the shipped default
is re-measured rather than taken on trust.

## Settled

- **Crash recovery** as described above: a CRC and a sequence number per
  record, `fsync` flowing through to the mmap'd buffer, and the longest
  ascending run as the surviving state. The expected deployment ties a
  mount to a job, so the common recovery is discarding the state along
  with the failed job — recovery must be correct and loud, but it is not
  the path to optimize.
- **Memtable size**: deferred until there is operating experience. Start
  at the pack target and revisit with numbers.
- **One flushing table**, not a list. Revisit only if bursts prove it too
  coarse.
- **Identity binds at flush**, not at write, which the second-pass
  chunking above requires anyway.
- **`--no-seal` would go away.** It exists so a session can keep an
  overlay and resume it later; with memtables that promise grows to
  recovering a buffer file, and the feature has no remaining user. It is
  still a flag on `mount` and `mount-gen` today, because none of this is
  built.

## Open questions

1. Does the per-pack live-byte field belong in the superblock's pack list
   at all, given it grows per generation on volumes that may hold
   thousands of packs? A local sidecar is cheaper but unshared, so a
   second client cannot act on it.
2. Should a flush upload one pack or several concurrently? The packer
   already runs four uploads at once, but a flusher that inherits that
   has to order location-map updates against partial failures.
3. Is there a case for flushing on idle — no writes for some interval —
   rather than only on a full table? It would shorten the crash-loss
   window and smooth uploads, at the cost of smaller packs.
4. Which of the two ways out of the tiling problem to take: a chunk-offset
   field on `ChunkRef`, or CDC over live sub-ranges only.

## Appendix: considered and not taken

**Waiting for a file to look "settled"** — `close`, or an idle timer —
before chunking it. That is a guess dressed as a signal: a file can be
reopened, appended to, or written through an mmap, and a long-running
appender never closes at all. Replaced by promotion on age, which needs
to predict nothing.

**Discrete levels: an active table, a frozen table, maybe more, with
content copied between them.** Counting what it costs kills it. Two
tables double the cheap thing — mmap'd file pages the OS can evict —
while a flush duplicates the *expensive* thing, because a table's
contents exist simultaneously as raw extents and as the chunked,
compressed packs built from them, for the whole duration of the flush. A
ring bounds that duplication by pack size instead. The two-table
prototype is also where the pin/unpin lesson and the 38-of-39 blocking
measurement came from.

**CDC as a backpressure release valve** — abandon the chunking pass under
pressure, trading dedup for latency. Built, measured, and **deleted**:
with the valve a prototype session ran 10.31 s and abandoned 38 of 39
flushes; with it disabled it ran **7.77 s** and abandoned none.
Abandoning still has to hash every extent, because a pack key *is* the
chunk identity — only the cut search is skipped — so it trades a cheap
gear-hash scan for extra pack entries and comes out behind. It also fired
on nearly every flush even at zero modelled latency, so it was never the
exception this document imagined. This is the strongest reason not to
re-propose "skip CDC when busy" in any form.

**Lowering `InlineMax` toward zero, or removing inlining entirely.** The
sweep above rejected it on every axis. Recorded because the intuition —
"packing small files makes catalogs cheap" — is a natural one and is
backwards: inlining makes catalogs *numerous*, and numerous catalogs are
what make an incremental seal cheap.
