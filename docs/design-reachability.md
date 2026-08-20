# Reachability: measuring liveness, and the case for persisting it

Status: **shipped**, except the last section. The streaming sweep
(`internal/reach`), the planner and the executor that consumes it
(`internal/repack`, `pelfs repack --apply`) are all built. Persisted
reachability bitmaps — the last section — are **designed, not built**, and
that part exists to record why they fit and what they would cost.

In one sentence: **liveness is a measurement, not a list**, and everything
maintenance wants to do is a question about that measurement.

## The question

Three policies in `design-packfs.md` are written in terms of a number
nothing used to compute:

- retire an index whose packs are under half live,
- repack a pack that is mostly garbage,
- rewrite a manifest segment that is mostly dead.

The second and third are now acted on: a repack rewrites the packs and
replaces the manifest wholesale. The first — retiring an index on its own
account — is still only measured.

A pack list cannot answer any of them. It says which packs a generation
*may* read from, never which bytes inside them anyone still wants. Only a
walk knows. This is git's model — packs are storage, reachability
decides — and the trio is completed by `internal/fsck` ("is this
generation intact") and `internal/retention` ("which whole packs may be
deleted", by set arithmetic over pack lists alone).

## What a sweep walks

Reachability here is much shallower than git's. A generation's superblock
names its catalogs and inode shards **directly** — a flat list, signed —
so the frontier is known before anything is fetched. There is no
commit→tree→blob descent, and nothing has to be discovered by reading a
parent first.

```
superblock ──▶ RootCatalog, Catalogs[], Shards[]     (the frontier)
                    │
                    ├─ catalog ──▶ chunk identities
                    │           └─ nested catalog locators (queued)
                    │           └─ promoted inodes (nlink > 1)
                    │
                    └─ shard  ──▶ chunk identities of promoted inodes
```

Shards are a second pass: the content records of hardlinked inodes live
outside the path catalog that holds their node row, so they can only be
collected once the catalog pass has said which inodes are promoted.
Routing is unioned across generations rather than evaluated per
generation — an over-approximation, in the safe direction, that avoids
re-walking every shared catalog once per generation.

## Conservative, and why that shape is in the API

A pack wrongly reported dead is deleted, and that is data loss. A pack
wrongly reported live costs bytes until the next sweep. The errors are
not comparable, so the sweep is not symmetric about them: **anything it
cannot read, decode, parse or account for makes the affected packs count
as fully live and the whole result incomplete.** There is no partial
credit and no attempt to scope the damage — an undecodable catalog could
reference a chunk in any pack of any live generation, so the only sound
response is to treat the entire live pack set as live.

That is why incompleteness is not a *field*. `Sweep` returns a `*Report`
only when the sweep was clean; otherwise the report is nil and the error
is an `*Incomplete` carrying the conservative numbers. A caller who
ignores the error dereferences nil and crashes on the spot, which is
strictly better than one who forgets to check a boolean and deletes live
data. A flag can be forgotten; a nil pointer cannot.

The planner inherits the same property *structurally*: `repack.Options`
has no field through which a report can be supplied, `Compute` runs the
sweep itself, and every function that can append a candidate takes an
unexported value whose only constructor sits on the branch where the
sweep returned a real report. There is no "plan from this report" entry
point to call with the conservative one.

## The streaming join

The sweep asks one question of two sets — which identities does something
live reference, and where does each identity sit — and both are keyed by
identity. That is a **merge**, not a lookup. It only looked like a lookup
because a map was the easiest thing to reach for, and that map was what
bounded the package to volumes that fit in memory: a hundred million
entries keyed by hex string is tens of gigabytes before the reference set
is counted at all.

So both sides are accumulated as fixed-width records, sorted, spilled as
runs when a buffer fills, and read back through a k-way merge
(`internal/extsort`).

| side | record | width |
|---|---|---|
| placements | identity, pack index, stored length, flags | 45 B |
| references | identity | 32 B |

Four decisions carry most of the benefit:

- **Raw identities, not hex.** Halves every byte sorted, moved and
  compared. The old code hex-encoded every chunkref during the walk —
  one allocation per reference, a hundred million of them.
- **The offset is not spilled.** Only catalog-class entries are ever read
  back, and those are held resident; a chunk's placement is needed to
  attribute bytes, never to fetch them. Eight bytes per entry that
  nothing reads would have been the largest single line item.
- **Batches, not records.** A whole trailer's or a whole catalog's worth
  is handed over in one call, so the lock is taken per object.
- **Fixed width with the key as prefix.** A run sorts by swapping bytes
  in place — no per-record allocation, no pointers to chase.

Duplicate handling is asymmetric, and the asymmetry is the correctness
argument. The reference side is **deduplicated**: a chunk shared by a
thousand files is reached a thousand times and counted once. The
placement side is **not**: the same bytes in two packs keep both alive,
since either may be the copy a reader resolves.

What stays resident is proportional to packs, catalogs and hardlinked
inodes — thousands each, not hundreds of millions: the per-pack counters
(the answer being computed), the locations of catalog-class entries (the
only ones ever read back), the set of catalogs already walked, and the
promoted inodes the shard pass has yet to find.

One consequence worth stating plainly: because only *typed* entries are
held resident, a catalog written as an untyped entry cannot be located.
That is a format violation — typed entries are what let rescue inventory
a namespace from packs alone — and it lands in the safe direction: the
catalog fails to resolve, which is a failure, which makes the sweep
incomplete and every pack fully live.

## fsck: the same wall, a different shape

`internal/fsck` had the same problem and could not take the same
solution. It resolves a chunkref **inline**, as the walk passes it, so
that the problem it reports carries the path the reference came from — a
merge join would have to defer every finding to a second pass and reunite
it with its path afterwards.

What transfers is the sort, not the join. The index becomes a sorted,
**mapped** table (`extsort.Table`): a lookup is a binary search over
pages rather than a probe into a resident hash table, so what is resident
is page cache the kernel can reclaim. At a hundred million entries that
is 27 probes, nearly all landing in the same warm upper levels. A sampled
index (`internal/packidx`) would be the wrong tool here — its samples
exist to bound what a REMOTE reader asks for, and there are no range
requests to bound over a local mapping.

Two smaller structures fell out of having the table:

- **The set of chunks already counted is a bit per index position.**
  Every chunk that gets that far resolved in the index, so the index
  already holds each identity exactly where the lookup found it; a second
  copy of a hundred million keys buys nothing over a hundred million
  bits. This is a small, local instance of the bitmap idea above — over
  positions in a sorted table, computed rather than persisted.
- **Deep mode's work list is gone.** Chunks are verified as the walk
  finds them through a bounded pool, which also starts fetching during
  the walk instead of after it. The work list was hiding the backpressure
  a bounded pool makes explicit.

Keeping every duplicate placement rather than letting the last writer win
also fixed a latent false positive: the same identity in two packs may be
stored at two compressed lengths, and checking a chunkref against an
arbitrary one of them would report an intact file as damaged.

## Designed, not built: persisted reachability

The sweep recomputes everything every time. Git does not: it stores, for
selected commits, a bitmap over pack order marking what is reachable.
The idea maps onto this format unusually well, and is worth writing down
even though it is not built.

**Where pelfs is structurally easier.** Git's expense is the walk, so its
bitmaps exist to avoid traversal — and everything awkward about them
follows from not being able to afford one per commit: a *commit-selection
heuristic*, and *XOR-delta chains* between selected commits. pelfs has no
DAG to walk. A generation is a flat set of immutable, content-addressed
catalogs, so:

- a generation's bitmap is simply the OR of its catalogs' bitmaps — no
  selection heuristic;
- sharing between generations is already expressed by two generations
  naming the same catalog — no delta chains;
- a catalog is immutable and hash-named, so its bitmap is **permanently
  valid** and can be a derived, hash-named object listed exactly the way
  an MPI segment is.

**Where the win lands.** GC's real question is a union over the live
set — head, the retain window, tags — which is the single operation
bitmaps do best. And the writer already computes the answer: publish
holds the (identity → pack) pairing it feeds to the multi-pack index
(`ProvidedEntries`), so a per-catalog bitmap falls out of that same pass.
This is recording a fact already in hand, not adding a walk. Only
carried-forward content — a catalog referencing chunks this generation
did not write — needs an index lookup.

Per-*catalog* granularity beats per-generation even though per-generation
bitmaps would be denser, because an unchanged directory then costs
nothing at each seal. That is the incremental-sweep property.

**The position space is the design question.** The tempting choice is
positions within an MPI segment: dense (a 2 MB segment is ~131,000
entries, a 16 KB bitmap) and cheap to remap, since `mpi.MergeKeys`
already streams every key with its source table. But segments are
consolidated on every seal, so a catalog written a year ago would need
its bitmap rewritten on each merge — exactly the churn MPI tiering exists
to avoid. **Pack trailer order is the only ordering stable for the life
of the data**, and it is already a canonical sorted table (`PELFSPK3`).
Only a repack invalidates it, and a repack rewrites the pack anyway,
which is when git regenerates bitmaps too.

That choice has a cost. At a 2 MiB target pack the manifest's own
estimate is 200–400k packs for 100M objects, so a pack holds a few
hundred entries and a per-(catalog, pack) bitmap is tiny and usually
sparse. Two consequences:

- **Roaring rather than EWAH.** Git chose EWAH for large packs with
  dense, linearly scanned bitmaps. Here most containers hold a handful of
  set bits out of a few hundred — roaring's array-container case, and
  EWAH's worst one.
- Pack references need interning (a per-object name table, or manifest
  ordinals) or the 23-byte names outweigh the bits.

**The objection.** This converts the sweep's best property from *refusal*
into *confident wrongness*. A persisted bitmap is a cached derivation
trusted for a destructive operation; hashing catches corruption, but not
a well-formed bitmap written from buggy logic. Two things make it
survivable, and both are shapes already used here: an absent bitmap must
be *structurally* distinguishable from a bitmap that says nothing — "no
bitmap" falls back to the walk, and a zero bitmap must never be reachable
by absence — and there must be a verify mode that recomputes from
catalogs and compares, run the way fsck is.

**Sequencing.** The blocker at a hundred million objects was memory, and
streaming fixed that without introducing a trusted structure, which is
why it was done first. Bitmaps become worth building when sweep
*frequency* is the complaint — which is really a question about the
planner: if `pelfs repack-plan` should run routinely rather than as a
batch job, this is what makes that possible.

One thing the executor added is worth noting here, because it is the
smallest possible version of the same idea. `reach` can now hand back the
identity set it reached (`Options.CollectReachable`), as a sorted mapped
table, because a repack has to ask it membership questions. That set is
computed and discarded on every run. Persisting it *per catalog* — which
is what the bitmap design is — is the difference between recomputing the
whole namespace and reading back what an unchanged directory contributed
last time.
