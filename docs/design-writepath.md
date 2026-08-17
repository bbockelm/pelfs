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

### Why late-bound location falls out of the existing format

A catalog row for a file already stores `[]catalog.ChunkRef`, and a
`ChunkRef` carries the chunk's **identity** (a BLAKE3 hash), not a pack
name and offset. Resolution goes through `genfs.packIndex`, built from
the pack list.

So a chunk written to the memtable can be recorded in the catalog
immediately, with its final identity, before anyone knows which pack it
will land in. Flushing adds entries to the location map; it does not
touch a single catalog row. This is the property that makes the whole
design cheap, and it is already true of the format — no compatibility
break, no new record type in the catalog.

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

### Chunk boundaries need a settled stream

CDC decides boundaries from the content itself, over a rolling window.
That works when bytes arrive in order and stop arriving: an append, a
sequential write, a file copied in. It does **not** work for a file being
randomly rewritten, where an early offset can change after a later one
has been chunked.

So the memtable path applies to sequential and append-mostly writes, and
random rewrites need the escape hatch below. This is the one real
limitation of the design and it should be stated plainly rather than
discovered later.

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

## Open questions

1. Memtable size. The pack target is 64 MiB; matching it makes flushes
   produce full packs, but it also sets the backpressure granularity and
   the crash-loss window. Is one number right for both?
2. Whether the flushing memtable should be a *list* rather than a single
   table, trading memory for smoother backpressure under bursts.
3. Whether identities should be recorded in the catalog at write time or
   at flush time. Write time is simpler and is assumed above; flush time
   would let a rewritten file avoid ever having a catalog row for the
   dead version, at the cost of a second pass.
4. What `--no-seal` means here. Today it keeps the overlay for a later
   session to resume. With memtables, resuming means recovering a buffer
   file, which is a strictly larger promise than resuming a directory of
   staging files.
5. Whether a flush should upload one pack or several concurrently. The
   packer already uploads up to four packs at once; a flusher that
   inherits that gets throughput but complicates the ordering of location
   map updates.
