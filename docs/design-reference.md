# References and imports: borrowing another pelfs volume

Status: **`import` is BUILT; `reference` is designed and deliberately not
built.** This study's own recommendation was to build import first and
probably only, and that is what happened — see `pelfs import`, whose
approach comes from here: it is `repack`'s shape rather than `merge`'s, and
it walks the source's catalogs for a lineage map because, as measured
below, a superblock does not record the lineage set of its own tree.

What would justify revisiting references: a cooperating volume owner who
will keep a tag alive for you. Absent that, a reference's availability is
the product of two storage systems, one of which has no obligation to you,
and `import` is the same data with none of that exposure.

One deflation this study makes about itself, kept because it changed the
answer: the reference's headline advantage — no index to build or carry —
was PARTLY an argument about an unfinished graft. Once the graft index
became windowed (`graft.Reader`, one ranged request and a ~64 KiB window),
505 MB of resident index became 256 KiB, and that advantage mostly
evaporated. What survives is real but shorter: exact fidelity (symlinks,
hardlinks, xattrs, uid/gid — none of which a graft carries), no digest
computation at setup, one trust chain instead of two, encryption as key
management rather than refusal, and span-granular copy-on-write.

The spike that settled the inode-lineage question (`internal/refspike`) is
NOT in the tree: it was throwaway code for an unbuilt feature, and its two
findings outlived it. That two volumes hand out the same inode numbers is
now proven over a real published volume by `pelfs import`'s own
`TestTheRenumberingIsABijectionOverARealVolume`; that a superblock
undercounts the lineages in its tree is pinned by
`importvol.TestTheSuperblockUndercountsTheLineagesInTheTree`, which builds
a twice-branched volume and reads it back cold — the measurement needs a
real tree, and `internal/inodemap` never sees one. Its half of the story,
the refusal to alias an inode from an undeclared lineage, is pinned by
`inodemap.TestAnUndeclaredLineageIsRefusedRatherThanAliased`. The measurements quoted below came
from that spike and were reproduced by the import work.

This document covers two features because they are one mechanism seen from
two ends. It is written against `docs/design-graft.md` (on the
`graft-design` branch), which established the locator pattern this reuses:
identity in the catalog, location outside it, `chunkref` unchanged.

---

## The answer, in one paragraph

**A reference is cheaper than a graft on every axis that matters and buys a
strictly worse guarantee on the one that matters most.** Cheaper because
the source is already a pelfs volume: its bytes are already
content-addressed, so nothing has to be digested; its catalogs already map
names to identities, so nothing has to be spidered or expanded into our
catalogs; and its multi-pack index already answers "which pack holds this",
through a reader (`internal/mpi/remote.go`) that is *already* lazy and
ranged — which is the graft design's unimplemented work item 4. Measured:
a reference costs a reader **one superblock entry and zero rows in our
catalogs**, against a graft's ~505 MB index fetched whole at mount and
10.5 million chunkref rows for the same 10 TB tree. Worse because the
bytes belong to somebody whose `gc` has never heard of us: pinning a signed
superblock digest makes the tree *immutable and verifiable* but cannot make
it *exist*, and the only pin that keeps it alive is a tag in their volume
that they choose to keep. The one thing that genuinely surprised me is
where it breaks: not in the trust model, which the digest pin makes
*simpler* than a graft's (one chain, not two), and not in the inode space,
which has room for 8.4 million references — but in **inode shards**, where
a referenced hardlink is dropped by the next seal because shards are
rebuilt whole from the inodes the walk visited. Everything else in the
inventory is a stop condition the seal does not yet have.

**If only one of these gets built, build `import`.** It is smaller, it has
no ongoing operational surface, and it is the inode-renumbering tool
`docs/known-issues.md` KL-7 has been missing since merges landed.

---

## The spectrum, and a decision table you can follow

Three points on one axis: **how much of somebody else's storage system your
filesystem's availability depends on.**

| | **graft** | **reference** | **import** |
|---|---|---|---|
| what the source is | any HTTP/Pelican tree | another **pelfs volume** | another pelfs volume |
| bytes stored by us | none | none | all of them |
| bytes streamed at setup | **every byte, once** | none | every byte, once |
| work at setup | spider + digest, O(source bytes) | walk their catalogs, O(catalog bytes) | copy stored pack entries, O(source bytes) |
| rows added to OUR catalogs | 1 node + 1 edge per file, 1 chunkref per **block** | **one transition row** | 1 node + 1 edge per file, chunkrefs carried |
| new index object we must build | yes — 48.2 B/block, **fetched whole at mount today** | **none — we use theirs** | none |
| **10 TB / 100k files, at mount** | ~**505 MB** index + 10.5M chunkref rows in our catalogs | ~**141 KB** fixed, then ~**64 B per file actually stat'd** | nothing; it is ours |
| verification | our per-block digests, computed by streaming the source | **theirs, unchanged** — identity already *is* the digest | ours |
| fidelity | 0444/0555, grafter's uid, **no symlinks, no hardlinks** | exact: mode, uid, gid, mtime, xattrs, symlinks, hardlinks | exact |
| trust chains a reader walks | one (ours) + per-block digests | **one**, if pinned to a digest; **two** if following a head | one |
| immutable under our signature | yes (expanded at graft time) | yes **iff pinned** | yes |
| availability | ours × theirs | ours × theirs | **ours** |
| survives the source owner's `gc` | n/a | **no**, unless they tag and keep the tag | yes |
| `fsck` can be conclusive | only by re-reading the source | yes, if pinned | yes |
| `rescue` from our packs alone | no | no | yes |
| encryption | **refused** (no AEAD tag, no recomputable identity) | same-custody-domain only (a key-management problem, not a mechanism gap) | needs a real repack across keys |
| write to a borrowed file | copy-up: the **whole file** | **copy-on-write: the written span only** | ordinary write |

### The rule

1. **The source is not a pelfs volume** → graft. It is the only option, and
   it is what grafts are for.
2. **The source is a pelfs volume and you need the tree to keep working
   when its owner stops caring** → import. This is most cases.
3. **The source is a pelfs volume, its owner will keep a tag for you, and
   the tree is large relative to the part you read** → reference. This is
   the shared-software-area case, and it is the only one where a reference
   is clearly right.
4. **The tree is small enough to store** → import, always. "Small enough"
   is the same threshold `docs/design-graft.md` wanted documented and never
   named; on the numbers here it is wherever `O(catalog bytes)` and
   `O(data bytes)` stop being different orders — call it single-digit GB.
5. **You want a live view of their tree, not a pinned one** → mount *their*
   volume. That is not a reference. See Decision 1.

### Where the reader-cost numbers come from

`TestWhatAReaderHoldsForABorrowedSubtree`, in the spike this study was
written against (see the note at the top: the spike is not in the tree),
over a real published volume of 400 files in 20 directories split into 21 catalogs,
with whole-pack caching disabled so what is counted is the ranged reads
descent actually needs:

```
their superblock                  2775 B
their manifest (pack set)          440 B  (1 ref)
their multi-pack index            6985 B  (1 ref, 21 catalogs listed)
their root catalog, on wire       1294 B

WHAT A COLD READER PULLS OFF THE WIRE to serve the namespace (no file is read):
  stat one directory of 20:    141034 B  [5 GET(s), manifests=440 mpi=6985 packs=133609]
  stat the whole tree:         165295 B  [24 GET(s), manifests=440 mpi=6985 packs=157870]
  fixed (manifest + index + trailers, paid once): ~141034 B
  marginal per additional file's metadata:        ~64 B
```

The shape is the point: **descent is proportional to what you look at.**
Nineteen more directories cost 24 KB. The fixed part is their manifest,
their index and the pack trailers the first lookup pulls — paid once,
whatever the tree's size.

Against the graft design's own measured 48.2 bytes per 1 MiB block, for
100,000 files and 10 TB:

- **graft** — ~215 B in our superblock, 100,000 node+edge rows and
  ~10,485,760 chunkref rows written into *our* catalogs, and a new index
  object of ~505 MB that a mount fetches **whole** today.
- **reference** — one entry in our superblock, zero rows in our catalogs,
  no index of our own, and their index consulted through `mpi.Reader`,
  which fetches whole only under 4 MiB and otherwise takes one 256 KiB
  prefix plus a ~64 KiB window per lookup.

**Verified against the code, not assumed.** `mpi.Reader` "makes NO REQUESTS
until something asks it a question" and holds only the samples and the
strings blob (`internal/mpi/remote.go:17-75`); `genfs.Open` fetches the
manifest and the root catalog and nothing else, "so mounting costs what the
first question costs, not what the generation is made of"
(`internal/genfs/genfs.go:256-262`); and `packIndex.loadHints` names the
indexes without reading them (`internal/genfs/packindex.go:490-503`). The
referenced volume's `mpi` objects and pack trailers are used **directly, as
published**, with nothing re-derived.

**The honest deflation of this argument** is in "Why this might be a bad
idea", reason 5: the graft's 505 MB is a property of an *unfinished* graft,
and the fix is the ranged reader that already exists.

---

## What the spike measured

The spike was `internal/refspike`, a package nothing outside its own tests
imported. It is **not in the tree** — it was throwaway code for an unbuilt
feature — so the table below is a record of what it established, not an
index of tests you can run. Where a finding still carries weight, the note
says which shipped test now pins it.

| test | what it establishes |
|---|---|
| `TestTwoVolumesHandOutTheSameInodeNumbers` | the collision is a certainty, not a risk |
| `TestALineageMapSeparatesTwoVolumesEntirely` | the proposed fix is a bijection over a real volume's inodes and round-trips |
| `TestAnUndeclaredLineageIsRefusedRatherThanAliased` | the read-time guard, and the message it produces |
| `TestAMapThatIsNotABijectionIsRefusedUpFront` | a two-to-one map, and an out-of-range lineage, are refused before signing |
| `TestTheSuperblockUndercountsTheLineagesInTheTree` | **the map cannot be derived from the source superblock** |
| `TestHowManyReferencesTheLineageSpaceHolds` | capacity arithmetic |
| `TestWhatAReaderHoldsForABorrowedSubtree` | the reader-cost table above |

---

## Decision 1 — Pin a signed superblock digest. Following a head is refused

**Decision: a reference pins `{source prefix, source volume id, the wire
hash of their superblock, the identity of the referenced subtree's catalog,
their generation number, the tag that keeps it alive}`. Following a branch
head is not offered.**

Why the *superblock* hash and not only the catalog identity: the catalog
identity fixes the namespace, but a reader also has to *locate* the bytes,
and the pack set lives in their manifest, which their superblock names. The
catalog identity is carried alongside anyway, because it is what descent
uses and it lets a reader check the subtree without re-deriving it.

This is the same objection that killed lazy grafts, answered rather than
dodged. `docs/design-graft.md` refuses a lazy subtree pointer because "a
generation is an immutable signed statement of a namespace" and a pointer
would make the namespace a function of when you looked. A digest pin
*restores* that property: the pointer is to a content-addressed, immutable
document. Nothing about when you look changes what you see. That is the
whole asymmetry, and it is why a reference may be lazy where a graft may
not.

**Following a head is refused, and there is a positive reason, not just a
conservative one.** The pin is what collapses two trust chains into one
(Decision 5). Following a head reintroduces the second chain as
load-bearing: a reader would need their signing key pinned, a second TOFU
surface, and a second `refs.Store` — and `internal/refs`' own rationale for
a *volume-level* pin ("every branch and tag of a volume is signed by the one
volume identity", `refs.go:111-113`) is an argument against multiplying
those. It would also make `fsck` structurally unable to be conclusive: a
reader could not verify what it was about to see, only what it happened to
get.

**What is offered instead** is `pelfs reference --update`, which resolves
their current head, prints a diff of what moved, and publishes a **new
generation of ours** with a new pin. Git submodules, exactly, and right for
the same reason.

**The counter-argument, engaged.** "I want a live view of the shared
software area." That is a mount of *their* volume — `pelfs mount` their
prefix. A reference exists to make their tree part of *your signed
namespace*, and "part of your signed namespace" and "changes without your
signature" are contradictory. Naming the two things separately is the
answer, not a flag.

---

## Decision 2 — Inode identity: a per-reference lineage map. This is the crux, and it is where the spike lives

### The problem is worse than "may collide"

pelfs splits an inode into a 23-bit lineage and a 40-bit counter
(`superblock.InodeLineageShift`, `MaxLineage`). A **branch** draws an
unused lineage (`cmd/pelfs/branch.go:454 pickLineage`), which is what makes
`pelfs merge` possible at all. Two **independent volumes** draw nothing:
both start in lineage 0 and both begin allocating at `FirstInode(0) == 2`.

Measured, `TestTwoVolumesHandOutTheSameInodeNumbers`:

```
inode 1 is "/"                    in ours and "/"                     in theirs
inode 2 is "/ourdir"              in ours and "/theirdir"             in theirs
inode 3 is "/ourdir/ours-1.txt"   in ours and "/theirdir/theirs-1.txt" in theirs
inode 4 is "/ours-2.txt"          in ours and "/theirs-2.txt"          in theirs
EVIDENCE: 4 of our 4 inodes are also in their 4 — both volumes allocate from lineage 0
```

**Every inode collides, including the roots.** Splicing without translation
hands the kernel two different files with one `st_ino`, which it reads as a
hardlink and which `tar`, `rsync -H`, `find -samefile`, `genfs`'s residency
map (`res map[uint64]*residency`) and the shard router all believe.

### The fix: translate at the boundary, never on disk

**Decision: each reference carries a signed `LineageMap` — one row per
lineage the SOURCE allocates from, naming a lineage THIS volume reserved —
applied as pure arithmetic at the descent boundary.**

```
ours = (map[LineageOf(theirs)] << 40) | (theirs & (1<<40 - 1))
```

Two shifts, a mask and a small map lookup. Their catalogs stay **byte for
byte what they published**, which is what keeps them content-addressed,
shareable, and free to dedup against themselves. The inverse (`Unmap`) is
what a write path needs when the kernel names an inode in our numbering and
the source has to be asked about it.

`TestALineageMapSeparatesTwoVolumesEntirely` runs this over two real
published volumes and asserts injectivity, no collision with ours, exact
round-trip, and that every result fits a signed `int64` — the constraint
`superblock.MaxLineage` exists for, since catalogs and the overlay are
SQLite.

The alternative — rewriting their catalogs so the numbers are ours — is
exactly the renumbering KL-7 says does not exist, is a repack-class
operation, and destroys laziness. That alternative *is* `import`, and it is
the right answer there for the same reasons it is the wrong one here.

**Why a reference can do what `merge` cannot.** KL-7's renumbering is
unavoidable for a merge because a merge produces **one** catalog set that
must name both inode spaces. A reference never does: their catalogs stay
theirs, read-only, and the translation lives at the seam. Same problem,
different topology, and the topology is what makes it solvable.

### Does a reference get its own lineage id? Yes — one per *source* lineage

Not one per reference. A source volume that has been branched and merged
contains inodes from several lineages, and each needs its own row or the
map is not injective (`TestAMapThatIsNotABijectionIsRefusedUpFront`).

**Capacity** (`TestHowManyReferencesTheLineageSpaceHolds`): 8,388,608
lineages of 1,099,511,627,776 inodes each. At one lineage per reference,
8.4 million references. **The lineage space is not the binding constraint.**

Two things that *are*:

- **Branches and references must draw from one allocator.** `pickLineage`
  today scans branches and tags for taken lineages
  (`cmd/pelfs/branch.go:454-495`). It must also scan the superblock's
  reference entries, or a later `pelfs branch` will draw a lineage a
  reference already owns. Small change, and it must land with the feature.
- **The superblock budget.** `superblock.MaxEncodedBytes` is 512 KiB and it
  is a write budget a seal refuses at (`internal/superblock/size.go:19-36`).
  A reference entry plus a one-row map is on the order of 200–250 bytes, so
  a few thousand references would compete with the pack list and the
  ledgers. A `ReferenceBudgetBytes`, in the shape of `CatalogBudgetBytes`
  and the graft design's `GraftBudgetBytes`, belongs in the format.

### The finding that costs something: the map cannot be derived from their superblock

`TestTheSuperblockUndercountsTheLineagesInTheTree` builds the ordinary
shape of a volume with history — files from before a fork, files from a
middle branch, files from the head branch — and measures:

```
the tree actually contains lineages [0 1234 5678]
the superblock alone reveals        [0 5678]

  inode 1                (lineage 0)    /
  inode 2                (lineage 0)    /before-any-fork.txt
  inode 1356797348675586 (lineage 1234) /from-the-middle-branch.txt
  inode 6243027022512130 (lineage 5678) /from-the-head-branch.txt

EVIDENCE: the superblock does NOT name lineage 1234
```

`Fork.Lineage` and `NextInode` name the lineage a generation **allocates
from**; `Catalogs[].Inode` samples the directories that happen to root a
catalog (which always includes the root, hence lineage 0 always appearing);
`Shards` cover only promoted inodes. **Nothing in the format records the set
of lineages a tree contains.**

**Decision: build the map by walking the source's catalogs at
`pelfs reference` time, AND keep a read-time guard that fails closed.**

- The walk is `O(catalog bytes)`, not `O(data bytes)` — the same walk that
  computes the reference's file count and size for the report, and the one
  moment a reference can afford it. Against a graft's obligation to stream
  every byte of the source, this is a rounding error.
- The guard is required anyway, because a `--update` to a newer generation
  of theirs can gain a lineage they merged in after we looked. The message
  it produces (`TestAnUndeclaredLineageIsRefusedRatherThanAliased`):

  ```
  reference: source inode is in a lineage this reference does not declare:
  reference "/refs/theirs", source inode 108851651149833 is in lineage 99
  (declared: [0]); re-scan the reference to pick up the lineages it has gained
  ```

  An error, never a fallback. Passing an unmapped inode through
  untranslated, or folding it into a default lineage, is silent aliasing —
  and a loud refusal on a tree nobody has referenced before is recoverable
  where a quiet alias is not.

**A cheaper scheme, considered and refused.** Reserve a *contiguous slab*
of our lineages and map `their L -> base + L`, needing only their maximum
lineage. Refused: a source whose highest lineage is 5678 would consume
5,679 of ours, and lineages are drawn by hashing (`branch.go:481-495`), so
they are large and sparse by construction. The row table is right.

---

## Decision 3 — Nested catalogs: the right seam for the namespace, a false friend for everything else

**Decision: reuse the nested *transition*. Do not reuse the nested *row*.**

The transition is exactly right. `nested(parent, name, catalog_identity)`
(`internal/catalog/catalog.go:88-93`) means "descend into a different
catalog at this edge", and `genfs` already handles it end to end: `catCache.
acquire(idHex)` fetches, spills, opens and refcounts an arbitrary catalog by
identity, and `residency` records which catalog an inode resolved in so a
generation swap can re-descend it. A reference is that, with one extra fact.

That fact is why the row is a false friend, on four counts, each concrete:

1. **A nested row says identity and nothing else, and there is no room to
   add location.** In a single-volume format that is correct — location is
   "the packs this superblock lists". Across volumes it is not, and the
   obvious repair does not exist: `manifest.Add` refuses a pack name longer
   than 32 bytes (`internal/manifest/manifest.go:88-98`), and `PackEntry`
   has no origin field (`superblock.go:55-59`). **You cannot encode a
   foreign prefix in a pack name.** So a reference needs the superblock
   entry that names which store to resolve it in — the same locator pattern
   the graft design established, except the index at the far end is theirs
   and already exists.
2. **`reach` queues every nested locator it finds** (`walk.go:192-199`) and
   fails the sweep when it cannot resolve one (`reach.go:657`,
   `walk.go:113`). A reference implemented as a plain nested row therefore
   makes `reach.Sweep` return `Incomplete`, which reports every pack fully
   live, which makes **repack and index retirement permanently impossible
   on the host volume**. This is the most expensive single consequence in
   the whole design and it is invisible until someone tries to repack.
3. **`publish.planReuse` and `pruneSubtree` reason about nested catalogs by
   `(root inode, path, promoted count)` out of `sb.Catalogs`**
   (`internal/publish/catalogreuse.go:145-158, 204-219`). A referenced
   catalog must never enter `sb.Catalogs`: it is not ours to carry forward,
   its recorded path is in their namespace, and `TrimCatalogs` would
   silently drop it under budget pressure.
4. **`reach` refuses a live set that mixes `CatalogKeyID`**
   (`reach.go:417-419`), which a foreign volume differs in by
   construction whenever either side is encrypted.

**Implementation:** a `node.Flags` bit on the transition directory (the
flags column is unused, as `docs/design-graft.md` notes) plus a
`Superblock.References` entry keyed by that inode. The catalog format does
not change.

---

## Decision 4 — Copy-on-write, and the one case that genuinely breaks

**Decision: `memtable.Adopt`'s by-reference path applies UNCHANGED, and
adopt-by-reference is the DEFAULT — which is the opposite of the graft
answer, for a reason that is sound rather than convenient.**

`Adopt` (`internal/memtable/base.go:67-143`) declines to adopt by reference
in exactly two shapes: an inline body, and a **hole** — a chunkref with an
empty identity, which is "a shape publish never emits but a foreign
producer may" (`base.go:63-66`). A referenced file's records are ordinary
chunkrefs with real identities, so they take the by-reference path, which
copies `[]catalog.ChunkRef` verbatim and never touches a byte
(`base.go:113-142`). At seal time `baseExtent.pieces` re-emits them with
the base's own `llen/clen/alg/keyid` (`catalogrefs.go:43-48`), and
`stillStored` already returns `true` for an adopted extent without
consulting `chunkLoc` (`seal.go:95-122`). Nothing fights this.

**Why the graft refused this and a reference should not.** The graft design
rejects adopt-by-reference because it "would leave the file half its own
and half somebody else's: the written span in a pack, the untouched spans
still pointing at a URL that may change under it". A **pinned** reference's
untouched spans point at a content-addressed object inside a signed,
immutable generation. They cannot change. So the objection does not reach a
reference, and refusing anyway would mean writing 4 KiB into a 10 GB
borrowed file costs 10 GB — which is not copy-on-write at all.

What it *does* leave is an **availability** dependency: a file you wrote
still depends on them. So: adopt by reference is the default and is
reported; `--materialize` copies up for independence. Say the dependency
out loud rather than hiding it in a mode.

### The four cases asked about

- **Rename of a referenced directory — works, and is cheaper than an
  ordinary rename.** `Rename` of a base entry is a whiteout at the source
  plus an `oedge` at the destination pointing at the same inode; "subtree
  contents follow because children resolve via the moved inode"
  (`internal/overlay/write.go:391-397`), and exactly three inodes are
  marked dirty. For an *ordinary* subtree `planReuse` then refuses to carry
  any catalog whose path moved (`catalogreuse.go:204-219`), so the rename
  costs `O(subtree)` in catalog bytes at the next seal. For a *referenced*
  subtree that never applies, because referenced catalogs are not in
  `sb.Catalogs`. Cost: the reference entry's recorded path becomes a lie
  for reporting — the same cosmetic defect the graft has, with the same fix
  (record the root inode, or re-derive the path at report time).
- **`chmod` on a referenced file — works unchanged.** `materializeAttrsLocked`
  seeds the row from the base with `base: true` (`write.go:490-494`), and
  `BaseContent` reuses the content records because no `ocontent` row exists
  (`accessors.go:364-389`, `ContentReuser` at `publish/source.go:71-83`:
  "attribute changes do not count, a write or truncate does"). The reused
  records name *their* packs, so `ContentOf` must not veto them — the same
  `Content.External` flag the graft spike added is required here.
  `chmod -R` is N attribute rows and no materialization.
- **A referenced symlink — works, and is a fidelity win over a graft**,
  which has no symlinks at all because a spider sees objects, not links.
  The one cost: `pipeline.walk` calls `src.Readlink` for every symlink it
  *visits* (`publish.go:773-780`) and there is no symlink-reuse capability,
  so a seal that descends into a referenced subtree re-reads every target
  from the source. The fix is the same one below.
- **A referenced hardlink — THIS IS THE BREAK, and it is not the one I
  expected.** Promoted (`nlink > 1`) files' content records do not live in
  the path catalog; they live in **inode shards**, which the superblock
  routes by *our* inode ranges (`superblock.ShardEntry`,
  `genfs.shardHexFor`, `genfs.go:975-983`) and which `writeShards` rebuilds
  **whole every generation from `p.promoted`** — the inodes this walk
  visited (`publish.go:1044-1088`). A referenced subtree's promoted inodes
  are not in that set, so the next ordinary seal **drops their shard
  entries entirely** and every referenced hardlink then fails with
  `promoted inode N covered by no shard`. This is also why
  `pruneSubtree` refuses to prune any span with `Promoted != 0`
  (`catalogreuse.go:153`).

  Three ways out. (a) Refuse a reference containing hardlinks — unusable,
  a software area is full of them. (b) Materialize referenced promoted
  inodes into *our* shards at every seal — costs one catalog row per
  hardlinked file, not the bytes, and is what the existing `Promoted` gate
  already implies. (c) **Resolve referenced hardlinks through THEIR shard
  list, after `Unmap`.** Their shard list is in their superblock, which we
  hold anyway; the un-map is one map lookup. (c) is correct and cheap;
  recommend it, with (b) as the `--materialize` path.

### The stop condition that makes most of this go away

**The seal must never descend into a referenced subtree.** Nothing under it
is ours; the whole subtree is one signed pointer. That is one new stop
condition in `pipeline.walk`, on `pruneSubtree`'s existing pattern, and it
is what removes the symlink re-read, the catalog-list pollution, the shard
rebuild and most of the `reach` damage in one move. It is ranked work item
3 for that reason.

---

## Decision 5 — Trust: the pin collapses two chains into one

**Decision: our superblock signs the pin; the pin authenticates their
document by hash; their signature is checked for attribution and is not
load-bearing.**

**Chain A, ours.** `refs.Fetch` reads `refs/<branch>` under our prefix,
refuses a head older than one this client accepted, and verifies against an
explicit `--volume-pubkey`, the volume-level pin at
`stateDir/refs/volume.pub`, or TOFU-with-a-warning, then one
`VerifyChain` step (`internal/refs/refs.go:136-199`;
`superblock.VerifyChain` at `superblock.go:686-722` requires
generation `+1`, `PrevHash == Hash(prevRaw)`, and the same key or an
announced successor). What it guarantees: **exactly what our owner chose is
what a reader will follow** — the mount path, the source prefix, the pinned
hash, the subtree catalog identity, and the lineage map.

**Chain B, theirs.** Fetch the object at their prefix; hash it; compare to
our pin. What it guarantees: **the document is the one we pinned.** Their
Ed25519 signature is then redundant for *integrity* — the hash already
fixed the document — and is worth checking only so an error can say "this
is generation 47 of volume 3f2a…, signed by …". A reader with no way to
verify their key can still read safely.

That is the headline, and it is a real advantage over both alternatives. A
graft has no signed document at the far end at all, which is precisely why
it must compute and carry per-block digests. A head-following reference
would put chain B back in the load-bearing position and require a second
pinned key and a second TOFU surface.

### What a malicious source owner can do

**With a pin:**

- Move their branch head, retag, publish anything at all — **inert**. Our
  generation names a hash.
- Serve wrong bytes for a pinned object — **caught**. Identity is BLAKE3
  of the plaintext and `genfs` recomputes it at cache fill on unencrypted
  volumes; on an encrypted source in one custody domain (Decision 7) the
  AES-GCM tag under their DEK does the same job.
- **Delete the objects — NOT caught.** Availability, and it is Decision 6.
- Learn our readers' access pattern, and be the party our readers' clients
  connect to. This is `docs/design-graft.md` Decision 8's risk verbatim,
  and it needs the same answer: a **reader-side veto**, a
  `genfs.Options.ReferenceOpener` that builds the transport for one source
  prefix, where `nil` refuses every reference. `file://` refused
  absolutely, for the same reason a graft refuses it: a local path resolves
  to a different tree on every machine that mounts it.

**Without a pin**, i.e. following their head: replace the whole subtree,
add a setuid binary, remove files — and our signature says nothing about
any of it. That is the argument, complete.

### Auth, and the failure mode

Reading a reference needs a credential for **their** prefix, which our
reader may not have.

**Decision: do NOT fail the mount.** This is a deliberate asymmetry with
the graft rule, where a missing index fails `Open` because it is the only
record of where the bytes live. A reference costs nothing at mount, so
there is nothing to check at mount, and refusing a whole volume because of
a subtree the user may never enter is the wrong trade.

- At **mount**: one log line per reference, before a byte is served —
  `pelfs graft --list`'s discipline.
- At **first descent** into the reference: `EACCES`, naming the reference,
  the source, the pinned generation, and the fix.
- `--no-reference` mounts with referenced subtrees returning `EACCES`
  rather than being followed at all.

```
pelfs: /soft/atlas is a reference to pelican://osg-htc.org/atlas-sw
       (volume 3f2a…, generation 47, pinned to tag pelfs-2026-08)
       and this client has no credential for that prefix: EACCES.
       Get one, or mount with --no-reference to hide referenced subtrees.
```

---

## Decision 6 — Availability and GC: what a reference cannot promise that an import can

**The pin makes the bytes immutable. It does not make them exist.** This is
the honest downside and it is arithmetic, not engineering.

The mechanism, from the code. Retention's live set is built by listing
`refs/` and `tags/` **under their prefix** and unioning each root's packs,
indexes and manifests (`internal/retention/retention.go:391-586`,
`:502`, `:560`). Their sweep covers exactly three key spaces, all relative
to their own prefix (`retention.go:210-218`). `T_grace` ages objects to
make the sweep safe against *their* concurrent writers
(`retention.go:9-11`); the condemned ledgers pin retired generations of
*their* volume for that window. **Nothing our volume writes can enter that
set**, and there is no cross-volume pin primitive anywhere in the format —
`Superblock` has no field that names another volume, and `refs.Store` holds
one prefix, one state dir and one trusted key.

So, plainly:

- The moment their branch moves past the generation we pinned, our packs
  survive only inside their last-K window or under a tag.
- When the window rolls, their `gc` deletes them. Not "may" — will, on
  schedule, correctly, doing its job.
- **The only pin that works is a tag in their volume that they choose to
  keep.** That is a social contract the format cannot record.

**Consequences for the design:**

1. `pelfs reference` **requires** `--tag` naming a tag in the source
   volume, records it, and says out loud that it is a promise nobody made.
2. `pelfs reference --check` verifies the tag still resolves and still
   hashes to the pin. Cheap, useful, and the honest substitute for a
   guarantee.
3. `--prefetch references` (opt-in) makes availability ours for whatever is
   prefetched.
4. `pelfs reference --materialize` turns a reference into an import in
   place. It is the escape hatch and it should exist from the start.

**Nothing short of import fixes it.** In those words.

### "Availability is the product of two systems", restated for the cooperating case

`docs/design-graft.md`'s first objection is that a grafted volume is
readable only if its prefix *and* every graft source are readable, by every
reader, from wherever they are — "the availability of the whole is the
product of the parts". Cooperation removes **malice**; it does not remove
**arithmetic**. A cooperating owner still has outages, still runs `gc`,
still deletes a tag by accident, still decommissions a prefix, still leaves
the project.

And the failure is **worse** than a graft's, in a way worth stating
precisely:

| | graft, source changed | reference, pinned generation collected |
|---|---|---|
| blast radius | one block of one file | the whole subtree |
| who sees it | whoever reads that byte range | every reader, at once |
| what our superblock says | still correct about everything else | still cheerfully names a tree that is gone |
| recovery | `--refresh` re-spiders | nothing, unless someone still has the bytes |

### What a reference cannot promise, in one list

Against `import`, a reference gives up:

- **existence** — their `gc`, their tag, their prefix, their decisions;
- **`rescue`** — `internal/rescue` reconstructs from superblock backups in
  *our* packs (`rescue.go:288-349, 582-618`); a referenced subtree was
  never in one, and a rescue can "succeed" and produce a mountable head
  whose referenced subtree is unreadable with nothing in `RootStatus`
  saying so;
- **`fsck` from our objects alone** — checking a reference means fetching
  theirs;
- **`--prefetch all`** as a default;
- **encryption** except within one custody domain (Decision 7);
- **`merge` without a new conflict class** (two branches pinning different
  generations of the same source);
- **`repack` being able to shrink anything under the reference**, since
  those packs are not ours.

In exchange it gives up storing the bytes, and setup cost drops from
`O(data)` to `O(catalogs)`. That is the entire trade.

---

## Decision 7 — Encryption: three refusals and one legitimate case

**Decision: refuse three of the four combinations. The fourth is a
key-management problem, not a mechanism gap — which is itself a difference
from grafts, where encryption is refused outright.**

1. **Both plaintext.** Works. Their identities are plain BLAKE3, `genfs`
   recomputes them at cache fill, everything is checkable.
2. **Ours encrypted, theirs plaintext — refuse.** Our superblock would
   carry, in the clear inside a signed document, a foreign prefix naming
   exactly what is inside the volume, plus our readers' byte-range access
   pattern. `docs/design-packfs.md` promises "federation-visible object
   names are never content-derived" and that "an encrypted base can NOT be
   forked into a public branch by pointer games". Both fail — and worse
   than in the graft case, because a referenced volume's **catalogs** are
   plaintext SQLite, so the filenames are in the clear at a third party.
3. **Ours plaintext, theirs encrypted — refuse, and it is mechanism, not
   taste.** Their catalogs are AES-GCM under *their* DEK and their chunk
   identities are keyed BLAKE3 under *their* identity key. We hold neither.
   There is nothing to read, let alone verify.
4. **Both encrypted, one custody domain — possible, and the only encrypted
   case worth building.** Their DEK and identity key are wrapped into *our*
   key table under our KEK; the format already has the shape
   (`KeyEntry{ID, Kind, Alg, Wrapped}`, `KeyKindDEK`, `KeyKindIdentity`).
   What it lacks is a way to say "catalogs *under this reference* use key
   id 7": `CatalogKeyID` is one value per generation, and the field's own
   comment says catalog-class references "carry no per-entry alg/keyid the
   way chunkrefs do, so their encoding is fixed — always zstd, this one
   key". So case 4 needs a `CatalogKeyID` on the **reference entry**: small,
   additive, signed. Build it only if someone asks.

**The contrast worth drawing.** A graft is refused on encrypted volumes
because a grafted block has no AEAD tag and no recomputable identity —
"the only unauthenticated byte in the system, on the volume that asked
hardest for authentication". A reference in case 4 has **both**: their GCM
tag and their keyed identity, under a key we legitimately hold. Encryption
is a hard refusal for grafts and a key-management problem for references.

---

## Decision 8 — The interaction inventory

Severity: 🔴 breaks today · 🟠 wrong-but-quiet · 🟡 works, needs a decision ·
🟢 fine as is.

| Subsystem | What it assumes | What a reference does to it | Verdict |
|---|---|---|---|
| `genfs.ContentOf` (`read.go:152-185`) | every non-hole identity is in a listed pack; a miss fails the **whole inode**, not one ref | aborts the carry-forward of every referenced file. Needs `Content.External` plus a reference resolver — the graft spike's shape exactly | 🔴 |
| `publish.walk` descent | the walk covers everything the generation names | **must stop at the reference boundary.** One new stop condition, on `pruneSubtree`'s pattern, and it is what removes most of this table | 🔴 |
| Inode shards (`publish.writeShards` `publish.go:1044-1088`; `genfs.shardHexFor` `genfs.go:975-983`) | shards are rebuilt **whole** each generation from `p.promoted`, routed by OUR inode ranges | the next seal drops every referenced hardlink → `promoted inode N covered by no shard`. Fix: resolve through **their** shard list after `Unmap` (Decision 4) | 🔴 |
| `reach.Sweep` (`reach.go:401-419`; `walk.go:113, 192-199`) | one volume, one `CatalogKeyID`; every nested locator must resolve in a listed pack | refuses the live set on volume/key-id mismatch, and fails the sweep on the reference's catalog → **repack and index retirement become impossible on the host volume**. The most expensive consequence here, and invisible until someone repacks | 🔴 |
| `fsck` (`walk.go:252-279`; `fsck.go:200`) | a chunk in no listed pack is `KindMissingChunk`; `OK()` is `len(Problems)==0`; **no severity axis exists** (confirmed) | reports every referenced file as damaged and exits 1. Needs reference-awareness *and* the `Severity` axis the graft design already asks for — same prerequisite, one implementation | 🔴 |
| `--prefetch all` (`prefetch.go:107-113, 249-309`) | absence is decidable after `packIndex.all`; a miss is a failure | refuses to mount. Must skip references and count them; `--prefetch references` opt-in | 🔴 |
| Dedup sidecar (`rememberReusedChunks` `publish.go:975-990`; `dedup.go:13-24`) | an identity in it means **a pack this branch lists holds these bytes** | a referenced identity entering it makes the next seal *skip an upload* and write a chunkref no pack of ours holds — silent data loss, surfacing much later as `KindMissingChunk`. Must be excluded. Note: `rememberExcept` does **not** exist on `main`; the graft branch added it | 🟠 |
| `rescue` (`rescue.go:288-349, 582-618`) | reconstructs from superblock backups buried in **our** packs | a rescue "succeeds" and produces a head whose referenced subtree is unreadable, with nothing in `RootStatus` saying so | 🟠 |
| `retention` / `gc` (`retention.go:210-218, 391-586`) | live set = refs+tags **under this prefix**; three key spaces, all local | our GC can neither delete their objects (safe) nor keep them (Decision 6). Nothing to change here — the gap *is* the design | 🟠 by design |
| `repack` (`repackedSuperblock` `execute.go:800`; `Worthwhile` `auto.go:78-107`) | `sb := *prev` carries everything not explicitly rewritten; worth-doing is judged from pack count alone | a `References` field survives by value-copy — luck, not intent, exactly as `Grafts` does; make it explicit. A 99%-reference volume is judged by its 1% | 🟡 |
| `merge` (`sameRef` `merge.go:627-632`; `checkInputs` `merge.go:236-238`) | location is deliberately ignored when comparing refs; the three generations must be one volume | two branches referencing *different* generations of the same source produce identical chunkrefs and a conflicting pin — a new conflict class. Cross-volume merge is already refused | 🟡 |
| Symlinks (`publish.go:773-780`) | a seal re-reads every symlink target it **visits**; there is no symlink-reuse capability | fine once the walk stops at the boundary; a seal that descends re-reads every referenced target | 🟡 |
| `stats` (`stats.go:472`; `mountgen.go:561`) | one wrapped store, one `Summary.Prefix` | a reference's store is a second instance and is silently uncounted. There is already a precedent leak (`acquireLease`, `mountgen.go:995`, wrapped in nothing) | 🟡 |
| Superblock budget (`size.go:19-48`) | 512 KiB write budget shared by pack list, catalogs, key table, ledgers | reference entries plus lineage maps compete with it; needs a `ReferenceBudgetBytes` in `CatalogBudgetBytes`' shape | 🟡 |
| `memtable.Adopt` (`base.go:67-143`) | base records can be carried by reference; declines only inline and holes | **works unchanged, and correctly** — a pinned reference's bytes are immutable, so adopt-by-reference is sound where it is unsound for a graft. This is the feature, not a hazard | 🟢 |
| `overlay` rename / chmod (`write.go:391-397`; `accessors.go:364-389`) | edges move without touching child inodes; `base:true` rows reuse content records | both work unchanged, and a referenced rename is *cheaper* than an ordinary one because `planReuse`'s path check never applies | 🟢 |
| `refs` / branches / tags (`refs.go:111-199`) | one volume, one pinned key, one state dir; `VerifyChain` is +1 generation, same key | a pinned reference needs **no second `refs.Store`** — that is the point of the digest pin. Head-following would need one, plus a second TOFU surface | 🟢 pinned / 🔴 head-following |
| `manifest` (`manifest.go:88-98`) | pack names ≤ 32 bytes, resolved under one prefix | you *cannot* encode a foreign prefix in a pack name. Constraint, not damage: it is why the reference entry lives in the superblock | 🟢 |
| `mpi` (`remote.go:17-100`) | consulted lazily — whole under 4 MiB, else a 256 KiB prefix once plus a ~64 KiB window per lookup | **this is the win.** Their index is used as published, through a reader that already exists. The graft design's ranked item 4 is already done on this path | 🟢 |
| Catalog format | `nested` carries identity only; `node.Flags` is unused | **no change.** The transition is a nested-shaped edge plus a superblock entry | 🟢 |

---

## Import: the smaller half, and probably the more useful one

### Two premises in the brief are wrong, and both matter

**"Pack names are content-derived, so no collisions."** They are not.
`newPackName` is `p-<unixnano hex>-<2 random bytes>`
(`internal/packstore/packstore.go:369`), and `PackNameTime` parses that
timestamp because GC's age guard rests on it (`writer.go:193-207`). Two
volumes can mint the same name. More importantly, copying pack *objects*
**over-copies**: a pack holds entries from all over the tree, so importing
a subtree by copying packs drags in bytes nobody asked for.

**"Identical catalogs dedup for free."** Chunk identities are over *bytes*,
so **content dedup survives an import**. Catalogs contain **inode
numbers**, and an import must renumber them (below) — so **catalog dedup
does not survive**. Importing the same subtree into two volumes produces
two distinct catalog objects.

### Is import a superset of `merge`? No, and it should not reuse that code

`merge.checkInputs` refuses outright when the three generations are not
from one volume (`merge.go:236-238`), and `inodeCut` refuses without a
common fork record. Cross-volume there **is** no base, so the three-way
walk has nothing to do.

What import *does* share with merge is the **handover shape**.
`mergeSource` is a `publish.Source` + `ContentProvider` that never reads a
byte — `Open` is a hard error, "a merge never reads file content; both
sides are already packed" (`internal/merge/apply.go:28-32, 375-377`) — and
hands publish the chunkrefs it already has, naming the other side's whole
pack set in `ProvidedPacks` (`apply.go:399-401`). But that last step is
exactly what cannot work across volumes: those pack names would have to be
resolvable under our prefix, and the format has no way to say otherwise.

**Import is `repack`'s shape, not `merge`'s.** `rewritePacks`
(`internal/repack/execute.go:618-720`) already reads **stored** entries out
of packs and writes them into new packs, keeping identity, `clen`, `alg`
and `keyid` untouched and needing **no DEK at all** — "the bytes are copied
STORED — already compressed, already encrypted — so a repack needs no
data-encryption key and cannot corrupt content it cannot read"
(`execute.go:48-51`). Three changes turn it into an importer:

1. the source packs come from a **foreign prefix**'s store;
2. the identity set comes from the **imported subtree's chunkrefs** instead
   of a `reach.Report`;
3. the catalogs are **rebuilt** for our namespace instead of carried.

### What import has to decide

- **Inode lineage — and this is the good news.** The same `Map`, applied
  **once at import time and baked into our catalogs**. That is precisely
  the renumbering `docs/known-issues.md` KL-7 says does not exist — and it
  is *cheap here*, because an import is rewriting the catalogs anyway.
  `publish.InodeMarker` (`source.go:138-140`) already exists for "a tree
  that contains inodes the SOURCE DID NOT ALLOCATE". **Import is the
  renumbering tool KL-7 has been missing**, arriving from a different
  direction, and that alone may justify building it.
- **Generation numbering.** Ours, `+1`, on our branch. Theirs is discarded.
  Record the provenance (source volume id, generation, hash) in the
  superblock — but *not* as a `Fork`, which would be a lie: `Fork.Base`
  means "a generation of this volume", and `merge` reads it.
- **The dedup sidecar.** Imported identities **may and should** enter it:
  after an import the bytes are genuinely in our packs, so the invariant
  ("a pack this branch lists holds these bytes", `dedup.go:13-24`) holds.
  That is the *opposite* of the reference and graft rule, and it is worth
  stating because the three features are otherwise so similar.
- **Re-signing.** Our key, our superblock. Their signature is checked at
  import time — to confirm we imported what they published — and then has
  nothing left to sign in our document.
- **Encryption.** The one thing import cannot avoid: a source encrypted
  under a different key must be **decrypted and re-encrypted**, which is a
  real repack and needs their DEK. Two corollaries from the code. If you
  instead keep their `keyid` and copy stored bytes, our `KeyTable` must
  contain their key entry — which is Decision 7's case 4 again. And
  `sameRef` compares identity and extent while deliberately ignoring
  `CLen`, `Alg` and `KeyID` (`merge.go:627-632`), so any code path that
  reuses it across a key boundary will call a plaintext ref and an
  encrypted ref equal.

---

## Ranked implementation work

Calendar-days for someone who knows this codebase. Items 1–5 are the
feature; 7 is what keeps maintenance possible; 16 stands alone and is the
one I would build first.

| # | Work | Why it is here | Effort |
|---|---|---|---|
| 1 | `superblock.ReferenceEntry` + `References` + `ReferenceBudgetBytes`; `pickLineage` drawing from **one** allocator across branches, tags and references | without the shared allocator a later `pelfs branch` takes a lineage a reference owns | 2 d |
| 2 | The reference resolver in `genfs`: a store per reference, `Content.External`, the `Map` applied at the descent boundary, `ReferenceOpener` as the reader's veto | this is the read path | 4–5 d |
| 3 | **The seal stops at the reference boundary** (`publish.walk`, `planContent`, `pruneSubtree`) | removes the symlink re-read, the catalog-list pollution and most of the `reach` damage in one move | 2–3 d |
| 4 | Referenced hardlinks resolved through **their** shard list after `Unmap` | the one 🔴 that is not a stop condition | 2 d |
| 5 | `pelfs reference add\|list\|update\|check\|remove`, including the source walk that builds the lineage map | the map cannot be derived; the walk is where it comes from | 4 d |
| 6 | Dedup-sidecar exclusion for referenced identities | silent data loss otherwise, and `rememberExcept` does not exist on `main` | 1 d |
| 7 | `reach`: a reference boundary is a **stop**, not a failure; do not queue their catalogs | until this lands, repack and index retirement are impossible on any volume holding a reference | 2 d |
| 8 | `fsck`: a `Severity` axis (contract change, own commit), then reference awareness | `fsck` exits 1 on a healthy volume otherwise. Shared prerequisite with grafts | 2 d + 2 d |
| 9 | `--prefetch`: skip references, count them, add `--prefetch references` | `--prefetch all` refuses to mount | 1–2 d |
| 10 | `merge`: a `References` rule, and a conflicting pin as a conflict class | two branches can pin different generations of one source | 2 d |
| 11 | `repack`: carry `References` explicitly; teach `Worthwhile` about reference-heavy volumes | value-copy is luck, not intent | 1 d |
| 12 | `stats`: wrap each reference's store; report per-reference traffic | "how much of this mount went to a third party" is a question an aggregate cannot answer | 1 d |
| 13 | `rescue`: say in `RootStatus` that references were not verified | a rescue currently looks clean and is not | 0.5 d |
| 14 | `--no-reference` mount flag and a federation allowlist | the reader's veto is all-or-nothing otherwise | 1 d |
| 15 | `pelfs reference --materialize` (reference → import in place) | the escape hatch Decision 6 requires | 3 d |
| 16 | **`pelfs import`**: `rewritePacks` over a foreign prefix + inode renumbering + catalog rebuild | independently useful, no ongoing surface, **and it is KL-7's missing renumbering tool** | 6–8 d |

Roughly five to seven weeks for the whole of it, and I would not trust that
to better than 50%. Item 16 alone is one to two weeks and delivers most of
the user-visible value.

---

## Why this might be a bad idea

Five reasons, descending by how much they worry me.

**1. The availability arithmetic is unchanged, and the failure is worse
than a graft's.** A graft that goes stale errors one block of one file and
names the fix. A reference whose pinned generation has been collected loses
a whole subtree, for every reader at once, while our signed superblock
still cheerfully names it. And the only pin that prevents it is a tag in
someone else's volume — a promise the format cannot record, cannot check
between runs of `--check`, and cannot enforce. Everything else in this
document is engineering; this is arithmetic plus a handshake.

**2. It adds a second inode-numbering authority to a system that has
exactly one, and the map cannot be derived.** The spike shows the lineage
map has to come from a walk, and that a source volume can gain a lineage
between our reference and our `--update` — at which point a perfectly
healthy tree produces read-time errors until someone re-scans. The
mechanism is sound and provably injective; the *operational* surface is
new, and it is the kind that shows up months later on somebody else's
volume.

**3. The seal has to learn a new stop condition, and stop conditions are
where this codebase's subtle bugs live.** `pruneSubtree`, `planReuse`,
`rebase`'s provenance replay and `writeShards` all reason about "what this
walk visited". Adding a boundary the walk must not cross touches all four,
and the rename-across-a-nested-boundary case `docs/design-graft.md` flagged
as untested is the same case here — harder, because the boundary is a trust
boundary as well as a catalog one.

**4. It is a second way to do something pelfs already does well, and the
good version is the one that isn't built.** Everything a reference buys is
"don't store the bytes". Everything it costs is self-containment, `fsck`
conclusiveness, rescuability, prefetchability, mergeability, encryption,
and other people's GC schedules. `import` buys the opposite trade, has no
ongoing operational surface at all, and hands back the renumbering tool
KL-7 has been asking for. If exactly one of these gets built, it should be
import.

**5. The best argument for references — the reader cost — is partly an
argument about an unfinished graft.** A reference needs no index because
`mpi.Reader`'s ranged-window path already exists. That path *is* the graft
design's ranked item 4, at 2–3 days. Build it, and the graft's 505 MB
at mount becomes a 256 KiB prefix too. What survives that deflation is
still real — fidelity (symlinks, hardlinks, modes, uid/gid, xattrs), no
digest computation at setup, one trust chain instead of digests, encryption
being a key-management problem instead of a refusal, and copy-on-write at
span granularity instead of whole-file copy-up — but it is a shorter list
than it looks before you notice that half the headline number is a bug
somewhere else.

**Recommendation.** Build `import` first, on `repack`'s machinery, and get
the inode renumbering out of it. Build references only once a cooperating
source has actually appeared — someone willing to keep a tag — and only
with a digest pin. Do not build head-following at all.
