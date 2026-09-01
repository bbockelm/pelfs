# Grafts: serving a foreign Pelican tree as part of a pelfs volume

Status: **spiked, built out for scale, then made usable on a volume that
already has content in it.** A grafted tree is spidered
in parallel, block-digested, published into a signed generation, and read
back byte-for-byte through a real Linux kernel mount, with no copy of the
data under the volume's own prefix — and when the source changes
underneath the signed generation the read fails closed, naming the graft,
the object and the fix. Since the first round it has gained the things
that make it usable at the size it is for: a **resumable** parallel walk,
a **per-object block size**, an index read **by window** rather than
fetched whole, and a `--prefetch all` that **fetches the grafted blocks
into a local cache** — proven by killing the graft source and reading the
tree anyway. The end-to-end is
`scripts/graft-spike-docker.sh`, and the transcript is in "The spike"
below.

**The writer's own limit is now gone**, which was ranked item 1 and the one
thing between this and a usable feature: a graft is SPLICED into the
previous generation at one path. The volume's other content keeps its
inodes, its attributes and its published content records; the catalogs
outside the graft path are carried forward rather than rebuilt; there is a
verdict per collision case at the path with every refusal ending in what to
do instead; both nesting cases are refused by name; the advisory lease and
a re-read of the head bracket the flip; and `--remove` fell out of the same
source. Decision 14. A graft-integrity failure is also its own error class
now, so "the source changed" is distinguishable from "the network blinked"
by a caller and by an errno (Decision 15).

**And the volume can now be checked**, which was ranked item 2 and the
last thing that made a grafted volume look broken: `pelfs fsck` reported
every grafted file as `missing-chunk` and exited 1. It resolves grafted
chunkrefs through the graft index the way a read does, reports what can
go wrong with a graft at a severity that says who owns the problem —
this volume's objects are damage, a third party's storage is a warning —
and offers two source depths whose very different costs are stated in
the output rather than both called "checked". Decision 4.

The design content is the decisions, the interaction inventory, and the
ranked work.

---

## The answer, in one paragraph

**Yes, and more cheaply than expected, because the format already had the
seam.** A graft is not a new content model — it is a second **location
layer**, and pelfs already separates the two: a `chunkref` stores
`{identity, llen, clen, alg, keyid}` and no pack name, because location
lives outside the catalog (`internal/genfs/genfs.go:155`). So a grafted
file's rows are ordinary chunkref rows, **no catalog format change at all**,
and the only additions are a signed `Grafts []GraftEntry` on the superblock
and a resolver consulted one branch earlier than the pack index. Identity
stays the same BLAKE3 function, which makes the two location layers
interchangeable and makes verification free of new mechanism. The two
places that fought back were both found by reading the code and both had
one-line answers already sitting in it: a write to a grafted file
un-grafts *that file* by taking the copy-up path the memtable already has
for holes (`internal/memtable/base.go`), and grafted identities must be
kept out of the dedup sidecar or a locally written file silently acquires a
dependency on a third party's URL. The two things that genuinely do not
work are that **encryption is a hard incompatibility** (an encrypted volume
literally cannot verify a grafted block — argued below, and it is a
mechanism problem, not a taste problem) and that **`--prefetch all` refuses
to mount a grafted volume today**, which is measured, not predicted. Both
are fixable; neither is a reason not to do this.

---

## What was built

| | |
|---|---|
| `internal/graft/graft.go` | the index format (v2), the streaming `Writer` (extsort + `packidx.StreamWriter`, no resident table), `Index`, `Publish` |
| `internal/graft/remote.go` | `Reader`: whole under 4 MiB, header-plus-window above it, the `mpi/remote.go` pattern |
| `internal/graft/blocks.go` | `BlockPolicy`: the per-object block-size ladder |
| `internal/graft/spider.go` | the parallel walk (span tasks), progress, the two-listing consistency check |
| `internal/graft/checkpoint.go` | the append-only resume log |
| `internal/superblock` | `GraftEntry` (+`BlockMax`, `BlocksPerObject`, `Files`, `Objects`), `Superblock.Grafts`, `GraftBudgetBytes` |
| `internal/genfs/graft.go` | the resolver (memoized, ctx-carrying), the reader-side veto, unconditional verification, `GraftStats` |
| `internal/genfs/prefetch.go` | grafted blocks fetched into the local cache (`PrefetchOptions.Grafts`), budget refusal with both numbers, `PrefetchReport.FullyLocal` |
| `internal/genfs/graftcache.go` | the local disk tier: self-describing blobs under `packs/`, resident identity→(blob, offset) map, verified on every read |
| `internal/genfs/gencache.go` | two-pass eviction: prefetched graft blobs go last, and the loss is counted |
| `internal/publish/graftsource.go` | `GraftSource`: a `publish.Source` + `ContentProvider` over a spider result |
| `internal/publish/graftsplice.go` | `GraftSpliceSource`: the splice into a POPULATED volume, plus `GraftPreflight` and the collision matrix (Decision 14) |
| `internal/genfs/grafterr.go` | the graft-integrity error class: `ErrGraftIntegrity`, `*GraftIntegrityError` (Decision 15) |
| `internal/graft/enumerate.go` | `Reader.Enumerate`: the sequential pass over an index object — one ranged read, one buffer, the whole-object hash and the sort order checked on the way past |
| `internal/fsck/graft.go` | the graft arm of `fsck`: grafted blocks in the shared identity index, the severity table, the `HEAD` sweep, deep block verification, `GraftDepth` |
| `cmd/pelfs/graft.go` | `pelfs graft`, `--refresh`, `--replace`, `--remove`, `--list`, the block/concurrency knobs, the scheme allowlist, the mount's `GraftOpener` |
| `cmd/pelfs/graftsplice.go` | the command's side of the splice: the preflight, what it reports, and `--remove` |
| `cmd/pelfs/mountgen.go` | `--prefetch all｜packs｜background` and what each promises |
| `internal/genfs/graft_test.go` | the whole read path in the ORDINARY lane: good read, straddling read, fail-closed, no-opener refusal, prefetch arithmetic, a windowed index, and **offline reads after a prefetch** |
| `internal/genfs/graftintegrity_test.go` | the error class: a changed source, a truncated one, and — the half that makes it worth having — an UNREACHABLE source that must not be classified as changed data |
| `internal/publish/graftsplice_test.go` | the splice in the ORDINARY lane: the whole collision matrix, both nesting refusals, two grafts side by side, catalog reuse across a nested boundary, idempotence, `--remove`, and interruption safety against a dying store |
| `internal/fsck/graft_test.go` | the severity assignment, kind by kind, in the ORDINARY lane: a healthy grafted volume clean, a chunk in neither layer still damage, a lost and a corrupt index, an entry that contradicts it, a changed / deleted / unreachable / refused source, both depths on a same-length edit, and the exit codes that follow |
| `internal/graft/enumerate_test.go` | the pass agrees with `Lookup` in both modes, refuses a corrupt or unsorted index, and holds a flat live set at 8x the block count |
| `internal/rawfuse/graftstatus_internal_test.go` | `EBADMSG` for an integrity failure, `EIO` for a transport one, and the separate log budget |
| `internal/genfs/graftcache_internal_test.go` | the storage shape (one file per blob, not per block), reopen, torn blobs, both eviction passes |
| `scripts/graft-spike-{test,docker}.sh` | the mount-backed end-to-end, now including resume and the prefetch modes |

`go build ./...`, `go vet ./...`, `go test ./...` are green, and
`scripts/graft-spike-docker.sh` and `scripts/mount-gate-docker.sh` both
pass.

---

## Decision 1 — Expand at graft time. Confirmed, with a size limit

**Decision: spider now, emit an inode and chunkrefs per file into the
signed catalogs. A lazy subtree pointer is refused.**

The reason is the one you gave and the code agrees with it: a lazy pointer
lets the tree change without a new generation, and "a generation is an
immutable signed statement of a namespace" is the property everything else
rests on — `refs.Fetch` refuses a generation older than one it has
accepted, `VerifyChain` hashes wire bytes, retention reasons about
generations as fixed sets. A pointer would make the namespace a function of
when you looked.

But expansion has a price and it should be stated in numbers rather than
waved at.

**Catalog rows.** A grafted file costs exactly what a packed file costs:
one `node` row, one `edge` row, and `ceil(size / block)` `chunkref` rows.
At the 1 MiB default block a 1 TB graft is ~1M chunkref rows, which is the
same order as a 1 TB packed tree at the 4 MiB average CDC chunk (~256k
rows) — within 4x, not a different regime. `SMax` splitting therefore
behaves exactly as it does for packed content and needs no graft-specific
handling: a grafted directory that grows past the threshold gets a nested
catalog like any other.

**The graft index.** Measured, not estimated:
`TestIndexSizePerBlock` builds 20,000 blocks and gets **48.2 bytes per
block** (32-byte identity + 16-byte record, plus the sampled index and the
object-key string table). So:

| graft size | blocks at 1 MiB | index |
|---|---|---|
| 1 GB | 1,024 | 49 KB |
| 1 TB | 1.05M | 50 MB |
| 100 TB | 105M | 5.0 GB |

**When is a graft too big to expand?** Two different limits bind, and they
bind at very different sizes.

- The **superblock** does not bind at all, and that is by construction: only
  the graft *roots* live there, one entry per graft. A realistic entry
  (long CVMFS-shaped paths) encodes to **215 bytes**, so
  `GraftBudgetBytes = 16 KiB` carries **~76 roots**. The superblock never
  grows with the number of grafted files, which is the same discipline
  `Manifests` imposed on the pack list.
- The **index fetch** bound first, and the spike bound hard on it by
  fetching each index **whole** at mount. That is fixed:
  `internal/graft/remote.go` reads an index whole under 4 MiB and by
  header-plus-window above it, exactly as `internal/mpi/remote.go` does
  for the multi-pack index at the same 100M-object target — a change of
  caller, not of format, because the graft index was built on `packidx`
  for this reason. Decision 9 has the arithmetic and the integrity
  argument that licenses reading without a whole-object hash.

So the honest answer: **a graft scales to the same 100M objects the rest
of the format targets**, and the per-object block ladder (Decision 10)
keeps the index for a realistic 10 TB tree near 123 MB rather than 480.

The other cost is time, and it is unavoidable: the spider **streams every
byte of the source once**. That is O(source) bandwidth at graft time and
O(0) storage forever, against a copy's O(source) in both, forever. It is
also the moment at which the source is known to be self-consistent —
Decision 11 makes that an enforced claim (two listings, and an abort) and
makes the walk parallel, resumable and visible, which is what turns
"O(source) once" from a sentence into something a person can actually
run against 10 TB.

---

## Decision 2 — Fixed blocks with per-block digests. `--verify=digest` is refused

**Decision: fixed-size blocks with a per-block digest, and that is the only
mode. The whole-object-digest alternative is not offered, not even as a
flag.**

I came in expecting to agree with you about `--verify=blocks|digest` and
the code talked me out of it. The argument is already written down in this
repo, from the other direction, in `internal/pelicanobj/fedstore.go:240`:

> GetUnverified reads an object through a RANGED transfer, which the
> Pelican client deliberately does not checksum: **a server-advertised
> digest covers a whole object and cannot be applied to a range**, so
> verification is skipped.

A `--verify=digest` graft would therefore be a mode in which **no read is
ever verified**, because every read of a grafted file is a range. Not
"partial reads are unverified" — *all* of them, since a 4 KiB `read()` of a
2 GB file cannot be checked against that file's digest without downloading
the 2 GB. The only way to make it mean anything is to fetch whole objects
always, which is the copy you are trying to avoid.

And the offer is worth less than it looks even at graft time. The saving a
service digest buys is "don't stream the source once". But you must stream
it once anyway to know the object *lengths* the catalog records agree with
the bytes — and the spike's own failure case is a **one-byte change with
the length unchanged**, which no amount of `HEAD` would catch.

So: blocks, always. Three consequences, stated rather than buried.

**The block digest IS the chunk identity.** BLAKE3-256 of the plaintext
block, `chunkid.Hasher`, the same function as everywhere else. This is the
single best thing about the design and it was free: the two location layers
become interchangeable. If a graft block happens to equal a pack chunk,
either location serves the same bytes and reading from the pack is simply
cheaper. No new verification mechanism exists; `entrycodec.AlgNone` with
`clen == llen` and `keyid == 0` passes through `decodeChunk` untouched.

**A graft never dedups against packed content.** Correct, as you said, and
the reason is boundaries: FastCDC cuts where the content says, a graft cuts
every 1 MiB. Two grafts of the same tree dedup perfectly with each other;
a graft and a pack of the same file share nothing. Accepted.

**Block size is a different trade from chunk size.** A CDC chunk is sized
to maximize dedup across edits. A graft block is sized to trade index size
against read amplification, and nothing about it dedups. That trade turned
out to be the one that could not be settled with a single number —
Decision 10.

### Verification is unconditional, unlike for packed chunks

`genfs` verifies packed chunks only when `fs.verify` is set (unencrypted
volumes, checked once at cache fill). Grafted blocks are verified **always,
with no configuration that disables it**, and the asymmetry is deliberate:

> A packed chunk came from an object this volume wrote, under a prefix its
> own keys authorize, and the Merkle path to the superblock signature
> already covers it. A grafted block came from a party with no obligation
> to this volume and no signature over its content — the identity check is
> the ONLY thing standing between a changed source and a wrong read.

### Small files are inlined, and stop being grafted

This fell out of the spike rather than being designed, and it is right.
Publish stores a file at or under `InlineMax` (2048 bytes) in the catalog
by rule, and `ContentProvider` has no shape for "inline this but here are
chunk records". So the spider keeps the bytes of files under
`graft.InlineKeep` (64 KiB) and publish inlines them.

Those files are **copied into the volume and are not grafted at all**. That
is a feature: they are then covered by the catalog's identity and the
superblock signature, they no longer depend on the source, and serving a
200-byte file from a catalog that was fetched anyway costs nothing where
serving it from a foreign origin costs a request. `pelfs graft` reports the
count and bytes out loud, because a user counting "grafted files" would
otherwise be counting the wrong thing. In the spike, 1 of 4 files
(21 bytes) was inlined.

---

## Decision 3 — Ungraft at FILE granularity. Your framing is stricter than necessary, and here is the proof

**Decision: a write un-grafts the file it touches, and nothing else. A new
file inside a grafted directory is an ordinary local file and its grafted
siblings are untouched. Whole-tree ungrafting is refused.**

You asked for a concrete argument either way. Here it is, and then here is
the test that runs it.

**The mechanism already exists and needed no invention.** `memtable.Adopt`
(`internal/memtable/base.go:67`) gives an inode a writable body starting
from the base generation's version, and it already has two shapes it
declines to adopt *by reference* and falls back to reading for: inline
bodies, and holes. A graft is a third such shape, and the change is
literally the same three lines:

```go
if c.External {
    return s.adoptByReading(ctx, ino, length)
}
```

The bytes come through the base read path — **so they are verified against
the graft's identities on the way**, which means a copy-up cannot launder
changed source bytes into a pack — and are re-chunked and packed like any
other write. Cost: one file download, once.

**Why not adopt by reference (which would be cheaper)?** Because that is
where your instinct is right. Adoption by reference would leave the file
half its own and half somebody else's: the written span in a pack, the
untouched spans still pointing at a URL that may change under it, and an
mtime that no longer matches the graft a freshness check would compare
against. That file is not a graft any more and should not pretend to be
one. So *at file granularity* your invariant holds exactly: the moment you
write to it, the file leaves the graft entirely.

**Why not the whole tree?** Because nothing forces it, and the cost is
enormous. The overlay records a per-inode change; the seal reuses every
inode it did not touch; the graft list carries forward in the superblock.
A `touch` in a grafted tree is one file's work.

**The spike tests exactly this**, and it tests it the only way that can't
be faked — by **deleting the source object** for the file that was written:

```
wrote 5 bytes into a grafted file, and created a new file beside it
packs grew from 2682 to 2102431 bytes
PASS: the written file was materialized into packs (2099749 bytes) -- it is ungrafted
-- now DELETE the source object for the file that was written --
PASS: the written file reads with its source object DELETED -- fully local
PASS: its grafted siblings are untouched and still served from the source
PASS: a file created inside a grafted directory is an ordinary local file
```

### The cases that genuinely force wider materialization — I could not find one

You asked me to name a case that forces it. I went looking at rename,
chmod, and directory ops, and the honest answer is **there isn't one**,
for a structural reason: the graft index is keyed by **identity**, and the
superblock's `GraftEntry.Path` is used for reporting, not for resolution.
Nothing about where a grafted file *sits* in the namespace affects whether
its bytes resolve.

- **Rename a grafted directory.** The overlay writes edges; the chunkrefs
  underneath are untouched and still resolve by identity. The graft's
  recorded `Path` becomes a lie for reporting purposes — `pelfs graft
  --list` would name a path that no longer exists — which is a **cosmetic**
  defect with a real fix (record the graft's root inode alongside its path,
  or re-derive the path at report time). It is not a correctness defect,
  and it must not be allowed to become one by making resolution
  path-dependent.
- **`chmod` one grafted file.** An attribute override in the overlay. The
  seal reuses the content records via `ContentReuser` and the file stays
  grafted with a new mode. Nothing materializes.
- **`chmod -R` a grafted tree.** N attribute overrides, no content
  materialization, one seal. Cheap.
- **Delete a grafted file.** A whiteout edge. The blocks stay in the graft
  index, unreferenced, which is harmless — the index is an immutable
  hash-named object, and an entry nothing references costs bytes in the
  index and nothing else.

The one thing I could not test and would want to before shipping is a
**rename of a grafted directory across a nested-catalog boundary**, because
that is where the overlay's rebase machinery is most intricate. Stated as
unverified rather than claimed.

---

## Decision 4 — Fail closed, and fsck needs a severity axis it does not have

**Decision: never serve an unverified byte; error naming the graft, the
source object, the byte range, and the command that fixes it.**

Implemented, and this is the spike's second half. One byte changed at
offset 1,500,000 of a 2.5 MB source file, length unchanged:

```
dd: error reading '.../mnt/ext/data/multiblock.bin': Input/output error

genfs: graft /ext: http://127.0.0.1:18997/ext/data/multiblock.bin [1048576,+1048576)
hashes to 8a7b79e1…, the generation says 5dfc7171… — the graft source has changed
since it was spidered, so these bytes are NOT what this volume published; run
`pelfs graft --refresh /ext` to republish it
```

Four things a person needs, in one sentence: which graft, which object and
range, that the **source** is what changed rather than the volume, and what
to run. And the failure is **per block**: the same file's unchanged blocks
still read, and the other grafted files are unaffected. Both are asserted
in the spike.

The mount also fails closed at `Open` if a **graft index** cannot be
fetched or does not hash to what the superblock says. That is a deliberate
asymmetry with `PackIndexes`, which are hints with a fallback: a graft is
the *only* record of where its bytes live, so a mount that shrugged would
look healthy and answer an error for every file under it. Same class as
`Manifests`, same treatment.

`--refresh` is named in the error and is **not implemented**. It is
mechanically a re-spider that publishes a new generation with a new index —
the same code path `pelfs graft` already runs — plus a diff report so a
user learns what moved.

### `fsck` on a grafted volume — built, and here is the severity table

Two modes, matching the existing `--deep` precedent, and both are now
built. **Everything below is implemented**; the boundary note this
section used to carry is at the end, kept because it is the argument.

- **Cheap (`--grafts=head`, the DEFAULT): one `HEAD` per source object.**
  Presence, size, and mtime. No source bytes at all: 100,000 requests for
  a 10 TB graft, independent of how many bytes or blocks it holds.
- **Deep (`--grafts=deep`, and implied by `--deep`): re-read and re-hash
  every referenced external block.** The same comparison a read makes,
  run over the whole graft. The only mode that catches a change that kept
  the length — which is the spike's own failure case.
- **`--grafts=none`: touch no third party at all.**

The graft INDEX is read on every run whatever the depth says, because a
grafted chunkref cannot resolve without it, and resolution is not
optional. That has a bonus: streaming the object verifies it against the
hash the superblock signs, which a MOUNT of a large graft cannot do
(`remote.go` reads it by window and argues, correctly, that it does not
need to). `fsck` is the only place that check happens.

**The report states which claim you paid for**, because "checked" would
otherwise cover a factor of ten thousand:

```
grafts:  1 root serving 4 external chunks from 2 source objects
source:  2 source objects stat'd by HEAD — size and mtime, no source bytes
         read; a same-length edit is invisible to this mode
         (--grafts=deep re-hashes every block)
```
```
source:  4 external blocks re-read from the source and re-hashed
         (3021440 bytes), 2 source objects stat'd
```

#### The line: this volume's objects are damage, a third party's are news

**Does a stale graft fail `fsck` or warn?** It warns, and the severity
axis that made that possible landed first (`Severity`, `--strict`,
`Report.Damaged`). What that decision generalizes to is one rule, and
every kind below follows from it rather than from taste:

> **`SeverityError` is for objects THIS VOLUME owns and can repair.
> `SeverityWarning` is for a third party's storage, and for fields no
> reader resolves through.**

| Kind | Severity | Why |
|---|---|---|
| `graft-index` | 🔴 error | The index lives under this volume's prefix, is hash-named, is covered by the signature, and is the ONLY record of where a grafted file's bytes are. Gone or corrupt, no reader serves a single byte under the graft, and nobody but this operator can fix it. |
| `graft-entry` | 🔴 error | The signed entry contradicts the hash-named object it names (block count, object count), or names a configuration no reader will serve — a graft on an encrypted volume, which `genfs.openGrafts` refuses to mount. Decidable without touching any source, and not fixable by a refresh. |
| `graft-block` | 🔴 error | The catalog and the index disagree about a block: a length mismatch, or a chunkref claiming a codec or a key over bytes a graft stores raw. The generation cannot be turned into the file it describes. |
| `graft-source-changed` | 🟡 warning | An upstream republish is the ordinary life of a graft source — it is the event a graft EXISTS to expose. Calling it damage would fail a healthy volume's cron on somebody else's routine maintenance, and the operator who learns `fsck` cries wolf stops running `fsck`. |
| `graft-source-missing` | 🟡 warning | **The one worth arguing about**: the files behind it are unreadable and `--refresh` will not bring them back. Still not this volume's damage — pelfs never held those bytes and never promised to (the graft's bargain is O(0) storage, and its stated price is that availability becomes the product of two systems) — and decisively, `fsck` CANNOT TELL a deletion from an expired token, a maintenance window, or a partition at this reader's position. Classifying an outage as corruption is the mistake `grafterr.go` already refuses to make. |
| `graft-unchecked` | 🟡 warning | The source could not be asked at all: unreachable, or refused by the reader's veto. A kind of its own rather than silence, because "I did not check" is a different claim from "I checked and it was fine", and a report that swallowed the difference would let an operator believe the second. |
| `graft-unreferenced` | 🟡 warning | A graft the namespace never resolves through: a leaked index object and a dependency on a third party that nothing uses. Costs storage and confusion, never a byte. `--remove` drops it. |
| `graft-metadata` | 🟡 warning | `Path` after a rename (ranked item 13 — nothing routes by it, so it can only make `--list` lie), a duplicate path, a recorded block policy that could not have cut this index (it breaks `--refresh`, not reads). |
| `missing-chunk` | 🔴 error | **Unchanged.** An identity in no pack AND no graft is still damage. The fix was "a graft is a location", not "absence is fine". |

`Bytes` and `Files` on the entry are deliberately NOT checked: `Bytes`
counts inlined files and `Files` does not, so a comparison would need to
re-derive the inline split and would misfire. A check that can be wrong
is worse than no check.

#### What it cost to make resolution work, which is the part that could have gone badly

Grafted blocks go into the **same sorted identity index as packed
chunks** — the external sort `fsck` already spills — with a marker in the
record's spare bits. There is no wider record and no second table: the
ordinal field's top bit is free (a generation cannot have two billion
packs) and the length field's top 32 bits are free (a graft block cannot
reach 4 GiB, because `BlockPolicy.Validate` refuses a ceiling over 1 GiB
— "the ceiling is the minimum verified read, and a read that large is a
download"), so the source object's ordinal rides there.

The consequence is that resolution costs one binary search over pages the
kernel can reclaim, `seenChunk`'s bit-per-position dedup covers both
populations without knowing there are two, and **nothing per grafted
block is resident**. The alternative — a set of grafted identities — is
the 336 MB at 10.5 million blocks that this package deleted a helper
rather than ship.

A tie is resolved **in the pack's favour**. Identity is the same BLAKE3
function in both layers, so an identity both hold names the same bytes
and either location is a correct read; the pack is this volume's own
object, needs no third party, and is verifiable without leaving the
prefix. It is also what makes a file written over a grafted one count as
packed, which is what it is.

#### The cheap mode's size check is sound under deduplication

This is the one place the arithmetic could have produced false alarms on
exactly the trees this feature is for. The index **collapses duplicate
identities** (`Writer.Encode` keeps the lower location), so the records
for a source object are a SUBSET of its blocks and `max(off+length)` is a
LOWER BOUND on its size, not its size. A software area full of identical
files would report most of its objects as "the source grew".

So the bound is used only where it stays sound, and equality is claimed
only where the records prove it:

- `size < extent` → **short**, always. The generation names bytes past
  the object's end and those reads fail today, whatever deduplication
  did.
- `size != extent` is claimed only when the surviving records tile
  `[0, extent)` with no gap AND `extent` is not a multiple of the block
  size — meaning the top record is a SHORT block, and only an object's
  final block is short, so `extent` is where the object ended.
- An object with **no** surviving records (every block deduplicated into
  an earlier object) is skipped by the `HEAD` sweep entirely: nothing
  resolves through it, so its absence breaks no read.

#### mtime is the cheap mode's only signal against a same-length edit, and it is free

The `HEAD` was made anyway. An object modified **after the generation was
created** was modified after it was spidered, because the spider ran
first — so the test is one-sided: an older mtime proves nothing and a
newer one is real. There is exactly one false-positive mechanism, a
source clock running ahead, and `graftMtimeSkew` (5 minutes) covers it.

The **advertised digest** (ranked item 15) does NOT fall out cheaply, and
the reason is already written down in this tree, from the other
direction: `pelicanobj.VerifyPut` records that "neither transport
promises a content digest in that field — the test origin derives it from
size and mtime, and an HTTP origin's ETag is opaque by specification". So
an ETag is either a restatement of size+mtime or an opaque token, and in
neither case is there anything recorded at graft time to compare it
against — the index carries no per-object digest. Item 15 needs a format
field, not a call site, and it stays on the ranked list.

#### The enumerator, and the boundary note that asked for it

`fsck` needed a way to walk a graft's blocks, and the shape it wanted was
stated when the previous round declined to build it:

> The spike had a `graftIdentities` helper that nothing called; it was
> removed rather than kept, because at 10.5M blocks the resident set it
> builds is 336 MB and the shape a deep `fsck` wants is a sequential
> stream of the index object — a few ranged reads.

That is `graft.Reader.Enumerate`: **one** ranged request for the whole
object, read through a 256 KiB buffer, hashed as it goes. What stays
resident is the string table (bounded by source objects, 6 MB at 100,000
of them however large the tree) and the buffer. Measured rather than
asserted, at two sizes eight times apart: the live set is 550 KB at
30,000 blocks and 587 KB at 240,000 — flat, while the object grew from
1.4 MB to 11.5 MB.

It also makes two checks nothing else was in a position to make. The
**whole-object hash**, as above. And **sort order**: `packidx`
deliberately does not verify order at open, because that is a pass over
every entry and an out-of-order table answers "not found" rather than
answering wrongly — which for a pack degrades to the caller's fallback,
and for a graft is silently unreadable files, since a graft has no
fallback.

## Decision 5 — The interaction inventory

This is where a design like this dies, so it is a table with a verdict per
row. **Severity** is: 🔴 breaks today, 🟠 wrong-but-quiet, 🟡 works, needs a
decision, 🟢 fine as is.

| Subsystem | What it assumes | What a graft does to it | Verdict |
|---|---|---|---|
| `genfs.ContentOf` (`read.go:152`) | every non-hole identity is in a listed pack, else abort | **would abort every seal over a grafted subtree.** Fixed in the spike: the graft table is consulted first, and `Content.External` is set. | 🔴 → fixed |
| `--prefetch all` (`genfs/prefetch.go`) | everything referenced is in a pack; failures are fatal | **refused to mount**, reporting grafted chunks as `present in no listed pack` — the sentence that means damage. Fixed: grafted blocks are FETCHED into a local cache tier of their own, verified on the way in, and read offline afterwards; the only refusal left is about cache size and carries both numbers. Decision 13. | 🔴 → fixed |
| `fsck` (`walk.go:263`) | ditto | **reported every grafted file as `missing-chunk`, exit 1.** Fixed: grafted blocks go into the same identity index as packed chunks, so a grafted chunkref resolves like any other and an identity in neither layer is still damage. Plus a graft-aware check with two source depths and a severity per finding (Decision 4). | 🔴 → fixed |
| Dedup sidecar (`publish/dedup.go`, `rememberReusedChunks`) | an identity in the set means "a listed pack holds these bytes" | **silent data loss** if graft identities enter it: a locally written file's chunk is elided from upload because a third party holds the same block, and no graft record names it. **Not a coincidence** — a graft block is a whole file whenever the file is under the block size, and CDC cuts such a file into one chunk of the same bytes. Fixed in the spike via `Content.External` → `rememberExcept`. | 🟠 → fixed |
| `memtable.Adopt` (`base.go:67`) | base records can be carried by reference | would leave a written file half-grafted. Fixed: `External` → `adoptByReading` (Decision 3). | 🟠 → fixed |
| Graft index fetch | `graft.Fetch` read every index WHOLE at mount and hashed it | at 10 TB that is a 123 MB fetch before the first byte is served, and at 100 TB it is not a mount. Fixed: `graft.Reader` reads whole under 4 MiB and header-plus-window above, on `mpi/remote.go`'s pattern. Decision 9. | 🔴 → fixed |
| `reach` / `gc` | `Report.Unresolved` counts identities in no pack; it is "damage, fsck's business" | grafted identities inflate `Unresolved` silently, destroying it as a damage signal. **GC itself is safe** — it only deletes under `packs/`, `mpi/`, `manifest/` in this volume's prefix, so it can neither collect a foreign object nor a graft index it doesn't know about. That last part is the actual bug: `grafts/` has **no live-set key space**, so index objects leak forever. Needs a `scanHashNamed` arm. | 🟠 |
| `repack` | drives from the pack side | **never touches external content**, correctly. But `repackedSuperblock` copies field-by-field (`execute.go:800`) — `Grafts` survives by value-copy today, which is luck rather than intent and should be explicit. `Worthwhile` judges from pack count alone, so a 95%-graft volume is judged by its 5%. | 🟡 |
| Decoded-chunk arena | it amortizes **decode**; keyed by identity hex | a graft block has no decode to amortize — it amortizes a **round trip**, worth strictly more. Sharing it is right, and sharing it **by identity** is what makes it safe: the arena's shard function reads chars 0–1 of the key and its ghost filter chars 0–16, so a synthetic key like `graft:<url>:<off>` would collapse every graft block into one of 64 shards. Open question: the arena is a fixed reservation *tuned against decode cost*, and a graft-heavy mount competes for it in a different currency. | 🟡 |
| `merge` (`sameRef`, `apply.go:400`) | location is deliberately ignored when comparing refs; `ProvidedPacks` is the only location statement | `sameRef` would call a packed ref and an external ref with the same identity "equal", and the merged generation could inherit a foreign dependency the other branch never named. There is **no `ProvidedGrafts`**, so a merge that takes a grafted file publishes chunkrefs with no location. Today `merge` passes no `GraftOpener`, so it **fails loudly** rather than silently — the safe direction, and not a solution. | 🔴 |
| `rescue` | reconstructs from **packs alone** | a graft cannot be rescued from packs — by construction, since the bytes were never in one. Worse, a graft-only generation writes no pack, so there is **no carrier for the superblock backup** and it is unrescuable at all. Mitigated in practice by catalogs always being packed; should be stated in `RootStatus` ("and these grafts were not verified"). | 🟠 |
| Encryption | the federation-visible surface carries nothing content- or name-derived | **hard incompatibility.** Decision 6. | 🔴 refuse |
| `stats` | one `WrapStorage` site (`mountgen.go:561`) counts transport ops | a graft's store is a **different store instance** and is silently uncounted. `GraftStats` exists in the spike (resolved/fetches/bytes/failures/mismatch, deliberately separate from chunk counters — "how much of this mount's traffic went to a third party" is a question an aggregate cannot answer) but is not yet published into the JSON summary. | 🟡 |
| `--prefetch` budget | sizes from the signed pack list | a graft has no pack sizes; a budget would need `GraftEntry.Bytes` (which is recorded). | 🟡 |
| `branch` / `fast-forward` | copies the head's bytes | carries `Grafts` correctly, but a fast-forward can import a foreign dependency onto `main` with no reachability check. | 🟡 |
| Catalog format | `chunkref` is fully packed; `node.Flags` is unused | **no change needed.** This is the headline: grafts touch the catalog format not at all. `node.Flags` remains available if a "this inode is grafted" marker is ever wanted for reporting. | 🟢 |
| `retention` / grace window | ages hash-named objects | graft indexes are immutable and hash-named, so they fit the existing model exactly — once `grafts/` is added to the swept key spaces. | 🟢 |

---

## Decision 6 — Encryption is refused, and the reason is mechanism, not taste

**Decision: a graft on an encrypted volume is refused at the writer AND at
the reader. There is no flag.**

I expected to argue this on confidentiality grounds and found a harder
reason first, in `internal/genfs`'s own package comment:

> On encrypted volumes identity is keyed BLAKE3 under the volume identity
> key, **which genfs does NOT hold** (only the unwrapped DEK arrives in
> Options) — there the AES-GCM tag, opened under the DEK, already
> authenticates every entry, so identity recomputation is skipped.

Now put a grafted block into that. It is `AlgNone`, `keyid 0`, so it has
**no GCM tag**. And identity recomputation is skipped because the reader
holds no identity key. The result is that a grafted block on an encrypted
volume would be **the only unauthenticated byte in the system, on the
volume that asked hardest for authentication.** That is not a policy
preference; it is an absence of any available mechanism.

The confidentiality argument is the same shape and worth stating anyway,
because it is sharper than "plaintext at a third party is bad".
`docs/design-packfs.md` promises that catalogs and shards are encrypted
*specifically because filenames leak otherwise*, and that
"federation-visible object names are never content-derived". A graft
publishes, in the clear inside the signed superblock, **a foreign URL
naming exactly what is inside the volume** — plus the byte-range access
pattern of everyone who reads it. Keyed identity exists to make
content-confirmation attacks impossible without the key; a graft hands the
answer over in the superblock. The feature and the promise contradict each
other internally.

There is a third, quieter one. `docs/design-packfs.md` claims "honest
declassify semantics — an encrypted base can NOT be forked into a public
branch by pointer games, because the shared objects stay ciphertext." A
graft **is** the pointer game that property was written to rule out,
arriving from the other direction.

So: refused. The reader-side refusal is the load-bearing one, because it
holds whatever wrote the generation:

```
genfs: this generation names 1 graft(s) and the volume is encrypted; grafted
blocks carry no AEAD tag and their identity is keyed, so nothing here can
verify them
```

I note that this repo's usual pattern for encrypted volumes is
**degrade-and-document** (identity verification silently off, GCM standing
in) rather than refusal. That pattern does not extend here because there is
nothing left to degrade *to* — there is no second check for the graft case
the way the GCM tag is a second check for the packed case.

---

## Decision 7 — Synthesized metadata: 0444/0555, owned by the grafting user

**Decision: grafted files are `0444`, grafted directories `0555`, and both
are owned by the uid/gid of whoever ran `pelfs graft`.**

A spider learns size and mtime. There is no uid, gid or mode at the other
end of a Pelican `GET`. Three sub-decisions:

**Mode is read-only, and that is a statement rather than a default.** A
grafted file cannot be written in place — the first byte written un-grafts
it — so a writable mode would advertise something the tree does not do. It
also sidesteps `fsperm`'s first-match-wins rule, under which a mode like
`0044` denies its own owner (`internal/fsperm/perm.go:244`, and the v0.2.0
permission change in the CHANGELOG). `0555` for directories matches
`initvolume.go`'s `0755` in spirit minus write.

**Ownership is the grafting user's, not the source's and not root's.** This
is the one that would have bitten. `internal/idmap` translates **exactly
one** identity — the volume root's — to the mounting process; every other
uid passes through untouched into the other-class arm of the permission
check. So reporting a plausible upstream `uid 4242, mode 0640` would make
the tree unreadable on every machine whose uid differs, with no mechanism
to rescue it.

**And squashing is defensible here specifically**, which is worth saying
because this codebase argues *against* squashing at length.
`internal/idmap`'s package comment refuses a general squash because it
makes `chown` invisible, so `tar -p`, `cp -a` and installers appear to
succeed having done nothing — "worse than failing". **That objection does
not reach a graft**, because a read-only tree has no `chown` to make
invisible. It is the one place the standing argument does not apply, and
the design leans on that rather than ignoring it.

Verified in the spike: `mode=444 uid=0 gid=0` for files, `mode=555` for
directories (uid 0 because the container runs as root).

One fidelity loss, stated plainly: **a grafted tree has no symlinks.** A
spider sees objects, not links. Where the source was made by publishing a
POSIX tree, its symlinks are gone. `GraftSource.Readlink` says so rather
than inventing something.

---

## Decision 8 — Security: two vetoes, and only one of them protects a reader

**Decision: a writer-side scheme allowlist (`pelican://`, `osdf://`;
`http(s)://` with a warning; `file://` refused absolutely), and — the one
that matters — a reader-side veto at mount, `genfs.Options.GraftOpener`.**

You identified the non-obvious risk exactly: a grafted volume shared with
other people makes **their** clients fetch URLs **you** chose, from their
network position, with their credentials. Packs do not have this property
because a pack lives under the volume's own prefix, and a reader who trusts
the volume already trusts that prefix.

And you are right that the signature does not help: **the URL being inside
a signed catalog makes it tamper-evident, not safe.** The signature says
"the volume's author chose this", which is the whole of what it says. The
author may be careless, or may be someone who obtained the signing key, and
either way the fetch happens from the reader's side.

So the enforcement point has to be the **reader**, and in the spike it is a
function the mount supplies:

```go
// GraftOpener builds a transport for one graft SOURCE prefix. […]
// It is also THE READER'S VETO. […] Returning an error here refuses the
// source and fails the mount, which is the only place that decision can
// be enforced. Nil refuses every graft.
GraftOpener func(ctx context.Context, source string) (pelicanobj.Store, error)
```

`nil` refuses every graft, which is the correct default for a caller that
has not thought about it — and it is why `merge` and `testvol`, which pass
no opener, fail loudly on a grafted volume rather than quietly fetching.

**`file://` is refused absolutely**, and not as a policy preference: a
graft is part of a shared, signed generation, and a local path resolves to
a *different tree on every machine that mounts it*. A volume carrying one
is not a filesystem — it is a filesystem whose contents depend on who is
looking.

**Should a reader be able to see grafts?** Yes, and cheaply — the answer
comes out of the superblock with no index fetch. `pelfs graft --list` is
implemented:

```
/ext <- http://127.0.0.1:18997/ext (6 blocks of 1048576, 3970037 bytes)
```

and every mount of a grafted volume logs one line per source before it
serves a byte:

```
graft source: reads under a grafted path will fetch http://127.0.0.1:18997/ext
```

**What is not implemented** and should be, in order of how much it matters:

1. **A `--no-graft` mount flag**, which mounts the volume with grafted
   paths returning `EACCES` rather than refusing the whole mount. Today the
   only choices are "open every source" and "fail to mount".
2. **A federation allowlist** — `--graft-allow pelican://osg-htc.org/…` —
   so a site can say which third parties its users' clients may be pointed
   at, as configuration rather than per-mount vigilance.
3. **Same-federation-only as a policy option.** I considered making this
   the *default* and decided against it: the CVMFS-shaped use case this
   feature exists for is precisely cross-federation, so a same-federation
   default would refuse the motivating case. It belongs as a site policy
   knob, off by default, rather than as a format rule.
4. **A first-use prompt or pin**, analogous to the volume-key
   trust-on-first-use warning that already exists. A graft source silently
   changing between mounts of the same branch is a real event, and the
   machinery for pinning-and-warning is already in `refs`.


---

## Decision 9 — "100,000 files and 10 TB: does that all go in the superblock?"

**No. The superblock gains ONE entry, 215 bytes, for the graft root — and
it would gain exactly one if the tree were 10 files or 10 million.** The
100,000 files are ordinary catalog rows, in ordinary catalogs, in ordinary
packs. What DOES grow with the tree is the graft index, and that is where
the work went.

Here is the whole of it, in the three places a big graft could have
landed:

| | 100,000 files, 10 TB | grows with |
|---|---|---|
| **superblock** | **one 215-byte `GraftEntry`** | number of graft ROOTS, never files |
| **catalogs** | 100,000 nodes + edges, ~2.7M chunkrefs | the same as any packed tree of that shape; `SMax` splits them like any other |
| **graft index** | **~123 MB** (2.7M blocks × 48 B, with the ladder) | total bytes / block size |

The superblock's discipline is deliberate and is the same one `Manifests`
imposed on the pack list: *only the roots live there*, bounded by
`GraftBudgetBytes = 16 KiB`, and the identity → (object, offset, length)
table is a hash-named object the entry names. A graft root is an
operator-scale thing — a person types the URL — so tens are plausible and
thousands are a misuse of the feature rather than a volume that grew.

### The index was the gating item, and it is now read by window

The spike fetched each index **whole at mount** and hashed it. At 459
bytes that is right; at 123 MB it is a bad mount, and at the 5 GB of a
100 TB graft it is not a mount at all. This was ranked item 4 and it has
been promoted and built, because it is the difference between the feature
and the actual use case.

`internal/graft/remote.go` is the `internal/mpi/remote.go` reader, against
the same `packidx` sampling:

- **under 4 MiB** (about 87,000 blocks) the object still comes down whole
  and its hash is still checked. One round trip either way, the stronger
  check applies, and every lookup afterwards is free.
- **above it**, the reader fetches a PREFIX — header, the source-object
  string table, and the samples — and thereafter one ~48 KB window per
  lookup. The graft stride is 1024 records rather than `packidx`'s 4096,
  because a graft entry is 48 bytes where a multi-pack entry is 16 and the
  default stride would make every lookup a 196 KB window.

What stays resident is two things, and neither scales with blocks:

| resident | 10 TB / 100k objects |
|---|---|
| samples (count/1024 identities) | ~84 KB |
| the source-object string table | ~6 MB (100,000 keys × 60 chars) |

### The integrity argument that licenses it — this is the part worth reading

A windowed reader cannot check the superblock's BLAKE3 over the whole
index. The spike's own comment said that check was "the whole reason a
graft can be trusted at all", and **that was an overstatement**, which is
what unblocks this.

What an index produces is a **location**. The bytes that come back from
that location are hashed and compared against the identity the **signed
catalog** names, unconditionally, with no configuration that disables it
(`genfs.readGraftChunk`). So a substituted, corrupted or truncated index
can send a reader to the wrong object, to the wrong offset, or to nothing
at all — and every one of those ends in a **failed read**. None of them
ends in an accepted byte. The index is exactly as trusted as a multi-pack
index, for exactly the reason `mpi` gives.

What the whole-object hash was *also* doing is bounding the reader's
appetite, and that is replaced the way `mpi` replaced it: every length off
the wire is held against `GraftEntry.Size`, which the signature does
cover, before a byte is allocated. `TestWindowedReaderRefusesAnIndexThat
DoesNotFitItsOwnSize` is that rule.

### What it costs: one extra small round trip per distinct block

A windowed lookup is a request. Two callers ask about the same identity in
quick succession — `fillChunks` probes it to decide whether to coalesce,
then `readChunkAt` resolves it — so `graftTable` memoizes, including
NEGATIVE answers, because "no graft holds this" is what every packed chunk
read asks and re-asking the network for it would make a graft's presence a
tax on the rest of the volume. An error is never memoized.

That still leaves one lookup per distinct block on a large graft. **The
fix is free and is not built:** a file's blocks are contiguous in one
source object, so having resolved block *i* to `(key, off, len)`, block
*i+1* is almost always at `(key, off+len, len)`. A reader can fetch that
speculatively and **the identity check already verifies the guess** — a
wrong speculation costs one wasted fetch and cannot cost correctness. That
is the right shape for the coalescing work (ranked item 5) to take.

---

## Decision 10 — Block size is chosen PER OBJECT, and the format already allowed it

**Decision: a recorded ladder — floor 1 MiB, ceiling 8 MiB, doubling once
an object would exceed 32 blocks. `--block`, `--block-max` and
`--blocks-per-object` are the knobs, and all three are recorded in the
superblock entry.**

You are right that a graft cannot cheat this: verification needs a whole
block, so **the block size IS the minimum verified read**. That makes it
one knob with two opposed costs and no third option — index size
(`bytes/block × 48`) against read amplification (the block itself).

One global value has to be wrong for one of them, because a real tree is
not one size. A CVMFS software area is hundreds of thousands of files of a
few KB next to a handful of multi-GB payloads, and the number that keeps
the index small on the payloads is the number that makes every small-file
read absurd:

| | blocks | index | minimum verified read |
|---|---|---|---|
| one global 1 MiB | 10.5M | 480 MB | 1 MiB, on everything |
| one global 8 MiB | 1.4M | 64 MB | **8 MiB, on a 4 KiB read of a 200 KB file** |
| the ladder | 2.7M | 123 MB | 4 MiB on a 100 MB file, 1 MiB on a 1 MB file, **the file itself** under 1 MiB |

(Those three rows are `TestTheOwnersCase`, run rather than remembered.)

### The format change, stated plainly, and why it is small

**The index needed no change at all.** A record already carries a
per-block LENGTH, because the last block of every object is short; cutting
different objects at different sizes uses a field that was always there,
and `genfs` reads `Loc.Length` bytes whatever it is. The chunkrefs carry
`LogicalOffset` and `LLen`, so the read path maps an offset to a block
without knowing any global block size.

What DID have to change is the **superblock entry**, because the RULE has
nowhere else to live and a refresh that cut differently would move every
identity in the graft:

```go
Block           int64  `cbor:"block"`                        // the floor
BlockMax        int64  `cbor:"block_max,omitempty"`          // the ceiling
BlocksPerObject uint32 `cbor:"blocks_per_object,omitempty"`  // the trigger
```

Both new fields are `omitempty` and a generation written without them
reads as `BlockMax == 0`, which `graft.BlockPolicy` interprets as "one
global size" — exactly what such a generation was cut with. This is the
right moment to make the change and it is made.

### The rule

```
block = Block
while size/block > BlocksPerObject and block < BlockMax: block *= 2
```

The invariant it buys is that the index is bounded by the OBJECT COUNT
(at most `BlocksPerObject` records each) as well as by the byte count. So
a tree of a few enormous files cannot produce an index that must be
windowed at all, and a tree of many small files — where each file is one
short block anyway — is untouched by the ladder.

The honest justification for "large objects get large blocks" is not that
big files are less important. It is that **a random 4 KiB read of a 10 GB
file is rare and a random 4 KiB read of a 200 KB file is common**, and in
the second case the block is the file. Where that assumption is wrong —
a multi-TB columnar file read by scattered small ranges — `--block-max` is
one flag, and setting it equal to `--block` turns the ladder off.

---

## Decision 11 — The walk: parallel, resumable, and it says what it is doing

The spider is the only expensive thing a graft ever does, and you are
right that it dominates: verifiable ranged reads need a digest per block,
so grafting **reads every byte of the source once**.

### Parallelism, and where the default came from

Fixed blocks are independent, so the work is embarrassingly parallel in
two dimensions — across objects, and within one large object. **The same
mechanism serves both**, which is why there is no second code path for the
big-file case: the unit of work is a **span**, a contiguous run of blocks
inside one object, fetched by one ranged GET and hashed block by block. A
tree of small objects produces one span each; a 100 GB object produces
hundreds. `DefaultSpanBytes` is 32 MiB, bounded by BYTES rather than block
count so the request size does not move when the ladder changes the block
size.

The default concurrency is **measured, not chosen**.
`TestSpiderThroughputTable` (`PELFS_GRAFT_BENCH=1`) walks a 456 MB tree of
204 objects against `cmd/fakeorigin`'s handler at three simulated
round-trip times, on a 12-core M2 Pro whose BLAKE3 floor is 1.7 GB/s per
core:

| workers | RTT 0 | RTT 5 ms | RTT 20 ms |
|---|---|---|---|
| 1 | 1984 | 280 | 86 |
| 2 | 2521 | 439 | 178 |
| 4 | 3244 | 887 | 353 |
| 8 | 3614 | 1434 | 594 |
| 16 | 3753 | 1643 | 1009 |
| 32 | **3873** | **2023** | 1433 |
| 64 | 3656 | 1693 | **1695** |

(MB/s. The latency term is the point: with none, a loopback origin answers
before a second request can be issued and the table measures BLAKE3 and
nothing else.)

**Two knees, and the default has to sit between them.** With no latency
the walk is CPU-bound and flattens at 8 — everything past it is
contention, and 64 is already *slower* than 32. With latency it is
round-trip-bound and keeps climbing to 32 and beyond, because a worker
spends its time waiting.

**`DefaultConcurrency = 16`**: within 4% of the zero-latency ceiling, 70%
of the 20 ms ceiling, and nowhere near where more workers make an origin
somebody else operates unhappy. It does not invent a third pool — a
`pelicanobj.TransferWorkers` larger than 16 is an operator who has already
said what their client should do, and it wins. `--concurrency` is how you
say a source is further away.

Applied to the case in question: 10 TB at the measured 1.4 GB/s is about
two hours, once, ever.

### Resumability

**The unit of durability is the OBJECT.** An append-only log next to the
volume's state gets one record per source object, written only after every
block of it has been hashed *and* its delivered length has been checked
against its listed length. A half-hashed object leaves no record and is
redone; nothing partial is ever resumed, which keeps the resume logic to a
comparison rather than a reconciliation.

- **What a crash costs.** Each record is flushed with `write(2)` as it is
  made, so process death — Ctrl-C, OOM, a token expiring, an eviction —
  loses **nothing**. `fsync` runs on a 5-second timer instead, because an
  fsync per object would dominate a tree of small files and would only buy
  protection against the one failure this is not about. A torn tail (the
  machine died mid-write) is dropped on load: records are length-prefixed
  and CRC'd, the reader stops at the first that does not check out, and
  the log is append-only so a bad tail can never take good records with
  it.
- **How a resumed run proves it is the same source.** Two gates, neither
  of which costs a request. The header records the source, the mount, the
  block rule and the identity function — a run whose parameters differ is
  not a resume, and the log is discarded *and said to be discarded*. Each
  record carries the size and mtime the listing reported when it was
  hashed; a resumed run re-lists (which it must do anyway to know what to
  walk) and compares. Changed size or mtime → re-hash. Vanished → drop.
  Appeared → hash.
- **What that cannot see** is a rewrite preserving size AND mtime. That is
  the same blind spot `fsck`'s cheap mode has, it is stated rather than
  papered over, and the per-block identity check at READ time catches it,
  fails closed and names the object.
- **The log is KEPT on success**, and that is what makes `--refresh` cost
  what changed rather than what exists. Measured in the end-to-end: a
  refresh of an unchanged 3,970,037-byte tree reads **0 bytes**; after one
  400,000-byte file is rewritten it reads **400,000 bytes**.

### A source that moves mid-walk

The listing taken at the start is the walk's manifest; **the same listing
is taken again at the end**, and anything that appeared, vanished, or
changed size or mtime **aborts the graft**.

This is the failure mode with no later defence: an index describing two
different versions of a tree has every block verifying, every file length
self-consistent, and describes a tree that never existed at any instant.
It has to be caught here or never. Aborting is affordable *precisely
because of the checkpoint* — the re-run re-hashes only what moved.

Per-object, the same rule is enforced twice more: a span must deliver
exactly the bytes it asked for, and nothing may follow the last block of
an object (an object that GREW under the walk would otherwise be indexed
at its old length).

### Progress

On a **timer**, not per object, because a walk of one enormous file has no
per-object event to hang a line on and going quiet for minutes is the
complaint this exists to answer:

```
spidering: 41231515648/10995116277760 bytes (0%), 412/100000 objects,
39328 blocks, 1465341644 bytes/s, about 1h52m30s left
```

and the walk opens by saying what it is: *"every byte is read ONCE to
digest it, which is network you pay now and never again — the volume
stores no copy of it"*.

### What the walk no longer holds

The spike held every record in a `packidx.Builder` and every identity in a
dedup set — about 150 bytes a block, so ~1.5 GB resident for a 10 TB graft
before the object was encoded. Records now go to `internal/extsort` (the
same external sort the seal path uses for this exact problem) and come
back in key order to a `packidx.StreamWriter`, which keeps only the
samples. Memory is the extsort budget plus the string table, both
independent of the block count.

### The encoded index is a function of the source, not of the schedule

An index object is **hash-named** and the superblock entry names it by
hash, so two walks of an unchanged tree under an unchanged policy must
write **byte-identical** objects. That is what makes `--refresh` of a
quiet source cost a listing: the encode reproduces the same object, the
upload is idempotent on a key that already exists, and the entry does not
move. If the bytes varied, a refresh that read zero bytes of source data
would still upload a fresh index and rewrite the entry every time.

Two things had to be pinned for that to hold, because the walk is
concurrent and both of them were taking their order from it:

- **The object-key string table is sorted at encode time**, and the
  records are remapped through the permutation. It used to be built in
  `Writer.Add` order -- which is the order the span workers finished in --
  so every record's object index depended on the schedule. The
  permutation costs one `uint32` per OBJECT, the bound the string table
  already carries.
- **A repeated identity collapses to the lowest location**, not to
  whichever the sort happened to put in front (the sort compares keys
  only, so its order among equal keys is the input order, which is again
  the schedule). Either location serves the same bytes; what matters is
  that the choice be a property of the tree. One record is held, never a
  run, so a tree of identical blocks cannot make the encode allocate.

Pinned by `TestTheSameSourceAlwaysEncodesTheSameIndex`, which walks a tree
holding two identical objects twelve times and compares the bytes.

One resident cost remains and is stated rather than hidden: a spider
result carries 32 bytes per block for the identities (336 MB at 10 TB),
because `publish` pulls one file's records at a time and something must
hold them until it asks. The rows themselves are built ON DEMAND
(`graft.File.Refs`), which is the difference between 336 MB and a
gigabyte. Reading them back from the checkpoint instead would remove even
that, and is the next thing to do if it bites.

---

## Decision 12 — Trust-on-first-use: costed, and refused as the default

You asked for TOFU to be designed and costed rather than dismissed. Here
it is, and the recommendation at the end is **not to ship it yet** — with
a specific thing to build instead.

### What it would be

Record the block layout from the LISTING alone. No byte is read; a 10 TB
graft becomes a few seconds. Then pin each block's digest on first read
and compare on every read after that.

The mechanism problem is immediate: **a chunkref must carry an identity,
and there is no digest to put there.** The only workable shape is a
SYNTHETIC identity — `BLAKE3(graft-nonce ‖ object key ‖ offset ‖ length)`
— which is a stable *name* rather than a digest. That drags four things
with it:

1. `genfs` must know the graft is TOFU and **skip the identity check** on
   any block not yet pinned. The fail-closed guarantee is off for exactly
   the reads that have never happened.
2. The pin store is **local** — under the cache dir, per machine. So a
   volume shared with ten people has ten independent baselines, and a
   source that changed before reader B's first read is invisible to B
   forever. TOFU gives drift detection *per reader, from that reader's
   first read*; it is not a statement the volume can make.
3. **The two location layers stop being interchangeable.** A synthetic
   identity can never equal a pack chunk's, so "if a graft block happens
   to equal a pack chunk, either location serves the same bytes" — the
   best property in Decision 2 — is gone for that graft.
4. **Ungraft-on-write becomes a laundering path.** A copy-up reads through
   the base path and repacks; for a TOFU graft those bytes are unverified,
   so writing one byte into a grafted file can move unverified third-party
   content into a signed pack under the volume's own prefix. That is a
   worse outcome than a failed read and it is not obvious from the flag.

### The comparison

| | eager (what is built) | TOFU |
|---|---|---|
| graft time, 10 TB | ~2 h (measured rate), once, ever | seconds |
| network at graft time | 10 TB | one listing |
| index size | 123 MB | 123 MB — **identical**, the layout is the same |
| source changed BEFORE the graft | caught: the walk *is* the check | not caught — it signs whatever is there, unseen |
| source changed mid-walk | caught (two listings) | not applicable, and no claim of self-consistency is possible |
| source changed AFTER the graft | caught on first read, by every reader | caught only after *this* reader has read *this* block once |
| can a wrong byte be served | never | yes, on any block this reader has not read before |
| guarantee for a SHARED volume | one, signed, the same for everyone | none; each reader has a private baseline |
| `fsck --grafts=head｜deep` | cheap: HEAD per object; deep: rehash | **nothing to verify until it has been read**; a deep run can only *establish* pins, and establishing them means reading every byte — the eager walk, done too late to be authoritative |
| ungraft-on-write | verified bytes enter the pack | unverified bytes can enter a signed pack |
| cost of choosing wrong | hours you did not need to spend | a signed namespace whose contents you never saw |

### Both CAN coexist — the question is whether the weaker one stays weak

Yes, mechanically: `--verify=eager｜tofu`, the mode recorded in
`GraftEntry`, the reader given a second veto axis so a mount can refuse a
TOFU graft the way it can refuse a source, and a mount line saying "*N
blocks under /ext have never been verified*" every time.

But the honest risk is behavioural, and it is the reason for the
recommendation. **A `--verify` flag whose weaker value is one keystroke
away is the value everyone uses the day the walk takes two hours**, and
the failure it enables is silent. Every other weakening in this design is
loud: a missing index fails the mount, a changed byte fails the read, an
encrypted volume is refused outright. This one is quiet by construction.

### The sharper finding: TOFU's real competitor is not "read everything"

The premise — "for the CVMFS-style case the source is trusted at graft
time" — deserves a second look, because **CVMFS's own model is the
opposite of TOFU**: a CVMFS catalog carries a content hash for every file,
computed by the publisher, and the client verifies. The reason such a
source feels trustworthy is precisely that its bytes are *already*
content-addressed upstream.

So the right move for that case is not to stop verifying. It is to **get
the digests from whoever already computed them**. Pelican advertises a
whole-object checksum; that cannot verify a range (Decision 2, and
`pelicanobj/fedstore.go:240` from the other direction), so it cannot
replace block digests on the read path — but it can do two things worth
having:

- make `fsck --grafts=head` cheap and *meaningful* rather than
  size-and-mtime shaped;
- make `--refresh` skip objects whose advertised digest is unchanged,
  which is strictly stronger than the size+mtime gate the checkpoint uses
  today.

And if a source ever offers **per-range or per-block** digests, the eager
walk becomes nearly free without giving up one thing — which is a better
place to spend the effort than making unverified reads possible.

### Recommendation

**Do not add `--verify=tofu` now.** The eager walk costs about two hours
for the 10 TB case, is paid once ever (the checkpoint makes every later
refresh cost only what changed), and is what every other guarantee in this
design is built on. Revisit it only when someone presents a source they
trust, cannot afford to read, and *cannot get digests from* — and if it
ships then, it ships with the mode in the superblock, a reader-side
refusal, an unmissable mount line, and ungraft-on-write refused rather
than quietly laundering.

---

## Decision 13 — `--prefetch all` FETCHES the graft, and reads it offline

**Decision: `--prefetch all` fetches every grafted block into the local
cache, verifies each against the identity the signed catalog names, and
mounts. `--prefetch packs` makes the packed content local and says out
loud that the grafted content is still remote. The only refusal left is
about SIZE, and it carries both numbers.**

An earlier round of this design refused instead, on the argument that
"fully prefetching a graft is the same operation as materializing it." That
argument is **wrong**, and the correction is the whole of this decision:

| | writes to | needs | afterwards |
|---|---|---|---|
| **materialize** | PUBLISHED packs, under the volume's prefix | the write lease, a new generation | the file is not grafted any more, for everyone, forever |
| **prefetch** | the LOCAL CACHE, on this machine | nothing | the file is still grafted, the volume is byte-for-byte unchanged, and this machine happens to have the bytes |

A prefetch is a read-side operation. It is exactly what somebody who typed
`--prefetch all` asked for, and there was never a reason it could not be
done. Refusing was the wrong default.

### What it does

`PrefetchOptions{Grafts: true}` walks the generation, collects the grafted
chunk references it finds, and fetches each block **through
`readGraftChunk` — the same function the read path uses**, with a pin flag
set. That is deliberate rather than convenient: it means a prefetched
block is verified before it is written, by the same unconditional check,
and there is no second path on which an unverified byte could reach the
disk. What ends up cached is exactly what a read would have accepted.

### Storage shape: blobs under `packs/`, and the lesson it must not undo

**Not one file per block.** That is the inode explosion `chunkarena.go`
was built to end — 6,646 files down to 1 on a 166 MiB tree — and a graft
is where it would be worst: 10 TB at the 1 MiB floor is ten and a half
million blocks.

**Not the arena either.** The arena is a bounded *decode* cache: a fixed
mmap'd reservation, 256 MiB by default, capped at `CacheBytes/8`, with a
cursor that overwrites. A prefetch is not a decode cache — it is asked to
hold what it was told to hold.

So: **blobs under `packs/`**, next to the cached packs, cut at 256 MiB —
the same order as `maxWholePackBytes`, for the same two reasons (eviction
should take back a bounded unit, and a process killed mid-prefetch should
lose a bounded unit). Each blob is **one file** and is self-describing:

```
[block bytes ...][n × {32-byte identity, u64 offset, u32 length}][footer]
```

Two choices inside that are worth stating.

**One file, not a blob plus a sidecar index.** Eviction deletes *files*,
and a pair can be split — leaving an index that points at nothing, or data
nothing can find. A blob that carries its own table cannot lose it.

**Under `packs/`, not in a directory of its own.** Everything that already
accounts for the cache — the LRU sweep, the single byte budget, `DirUsage`
reporting, `pelfs cache` — walks `cacheDirNames`, and putting the blobs
there means **all of it keeps working with no change**. A blob is named
`g-<hex>.gcache`, which cannot collide with a pack (`p-<unixnano>-<hex>`),
and the in-flight one is `.gcache.tmp`, which the eviction sweep already
skips and `sweepPackTmp` already cleans up after a crash.

The identity → (blob, offset, length) map is **resident**, which sounds
like the thing `internal/graft`'s windowed reader exists to avoid and is
not: this map describes what is **on this disk**, so it is bounded by the
cache budget over the block size. A 100 GB cache at the 1 MiB floor is
~100,000 entries, about 5 MB. The graft may be 10 TB; the cache is not.

### The cache is a pure HINT, because every read is verified

A block served from the cache is hashed against the identity the signed
catalog names, exactly as one off the wire is. That is not
belt-and-braces — it is what lets this whole tier be a hint. A corrupt
blob, a stale index entry, a file truncated by a killed process: every one
of them produces a hash that does not match, which is treated as a **miss**
and refetched. The cache can make a read slow; it cannot make a read
wrong, and it cannot make a read fail.

One distinction is kept carefully, in `readGraftChunk`: **a mismatch from
the CACHE is a miss; a mismatch from the SOURCE is "the graft source has
changed" and fails closed.** Blurring them would either hide a changed
source behind a refetch loop, or accuse a third party of changing when a
local file rotted. They are counted apart too (`Cached`, `CacheBad`).

The cache also **survives process exit**, exactly as the pack cache does,
and for a stronger reason: re-fetching is somebody else's bandwidth as
well as yours.

### Reads populate it too, not only prefetch

Gated on the same switch as whole-pack caching (`PackCacheBytes` negative
turns both off — a mount with less disk than bandwidth has said what it
wants). Without it, a graft's central hazard would be paid on every
re-read forever, and `--prefetch` would be the only way to avoid it. With
it, a warm cache builds itself and a prefetch is the way to say "all of
it, now".

### The budget: refuse up front, with both numbers

This is where the honest refusal lives. Prefetching 10 TB into a 100 GB
cache cannot work, and that — not "grafts cannot be prefetched" — is the
thing worth refusing.

**Refuse up front, not fetch-what-fits.** The precedent is already in the
file and the argument is identical: `PrefetchBudgetError` refuses a pack
set larger than the budget because "fetching it anyway would evict the
front of the set to make room for the back and leave the mount both slow
and incomplete". A partial graft warm is worse than that, because *which*
part you got depends on walk order — an unpredictable outcome from a flag
that exists to make outcomes predictable. And the user is not stranded:
`--prefetch packs` mounts, and read-driven caching warms what is actually
touched.

The check has two stages. A **cheap one before anything is walked**, off
`GraftEntry.Bytes` in the signed superblock — which is why that field is
recorded — so the 10-TB-into-100-GB case is answered without touching a
catalog. Then the **exact combined check** once the pack set is known.
Grafted bytes count against the budget *only when the pass intends to
fetch them*, so `--prefetch packs` still works on a volume whose graft
dwarfs the disk. (That was a real bug in the first cut: it refused
packs-only mode for bytes nobody had asked for.)

What the user sees:

```
ERROR pelfs: prefetch: refusing to mount: making this generation local needs 3.9 MiB
— 3.9 MiB grafted from /ext <- http://127.0.0.1:18998/ext (3.9 MiB) — and the local
cache budget is 187.5 KiB. Raise --cache-size above 3.9 MiB, or use `--prefetch packs`
to make the packed content local and read the grafted content from its source
```

and with packs in the mix, `… needs 4.1 GiB — 210 MiB in 12 packs and 3.9
GiB grafted from /sw <- pelican://osg-htc.org/sw (3.9 GiB) — and the local
cache budget is 3.6 GiB.` The pack clause is omitted when the cheap check
fired, because "0 B in 0 packs" there would describe a walk that never
happened.

### Eviction, and what `FullyLocal()` can honestly mean

This is the subtle part, and the answer is **preferred, not immortal**.

Two things are both true. A cached graft block is **re-fetchable**, so
evicting one is always safe — the read path falls back to the source —
which means it is never worth failing a write or filling a disk to keep
one. That rules out an unconditional pin. But plain LRU takes prefetched
blobs **first**, because the moment a prefetch finishes they are the
oldest thing in the cache and the next catalog spill is the newest. A
prefetch whose bytes are evicted before anything reads them did nothing.
That rules out no pin at all.

So the sweep is two passes (`gencache.go`, on the shape `pinnedCatalogs`
already established):

1. Everything else first, down to the low-water mark, skipping blobs a
   prefetch filled.
2. Only if the cache is **still over its CAP** — not merely over the
   low-water mark — the prefetched blobs go too.

And when pass 2 fires it is **recorded**: `GraftCacheStats.PinnedEvicted`
counts the bytes taken back. That is the number that says a `--prefetch
all` report stopped being true, and nobody should have to infer it.

`FullyLocal()` is therefore documented as **a statement about the moment
the pass returned**, and it is defined as `Failed == 0 && GraftLocal ==
Grafted` — never `Failed == 0`, so no caller can reach "local" from a zero
failure count. This is not a new weakness introduced by grafts: it was
already true of packs, which are evictable and were the oldest thing in
the cache after a prefetch too. What is new is that it is written down,
that eviction prefers to take something else, and that the loss is
counted.

Machine-readable: `prefetch_complete`, `prefetch_grafted_chunks`,
`prefetch_grafted_bytes`, `prefetch_graft_local_bytes`.

### Keeping the two words apart, in the CLI and everywhere else

The mount says it, every time:

```
prefetched 4 of 4 grafted blocks (2.9 MiB local, 2.9 MiB transferred from the graft
source); the files are still grafted and the volume is unchanged — this is a local
copy, not a materialization
```

and `--prefetch packs` says the other half:

```
WARN prefetch: /ext is GRAFTED from http://…/ext and this mode does not fetch it —
reads under it will go to http://…/ext (2.9 MiB of grafted content in this
generation). `--prefetch all` fetches and verifies it into the local cache
```

`pelfs graft --list` still names the source after a prefetch, because the
volume still depends on it: another reader has none of your cache, and
your own cache is evictable. Prefetch is a local convenience; only
materialize removes the dependency.

### Mode 3, materialize — still designed, still not built

It reuses machinery that exists: `genfs.ContentOf` already reports
`External`, and `memtable.Adopt` already routes an External record to
`adoptByReading`, so the bytes come through the **verified** read path and
a materialization cannot launder changed source bytes into a pack. They
are then re-chunked by FastCDC and packed by `publish`, so the result
dedups against the rest of the volume — which a graft's fixed blocks never
could.

What it still needs: the **write lease**, a resumable driver (importing
10 TB has exactly the interruption problem the spider had, and should
reuse the same checkpoint shape), and a decision about the half-imported
state — which argues for making the unit a subtree. It is `pelfs graft
--materialize`, not a mount flag, because `--prefetch` may not change the
volume.

### Proven offline, which is the only test that counts

`scripts/graft-spike-test.sh` now runs **two fakeorigin processes** over
one directory, so the graft source can be killed without touching the
volume's own storage. Section 7:

```
prefetched 1 packs … fully local: true
prefetched 4 of 4 grafted blocks (2.9 MiB local, 2.9 MiB transferred …)

-- NOW KILL THE GRAFT SOURCE. The volume's own origin stays up. --
the graft source at http://127.0.0.1:18998/ext is unreachable (curl fails);
http://127.0.0.1:18997/vol is still up

PASS: every still-grafted file read back byte-for-byte WITH THE SOURCE OFFLINE
PASS: the locally packed files in the same tree still read too
PASS: an offline read across a 1 MiB block boundary is correct
"prefetch_complete": true
"prefetch_graft_local_bytes": 3021440
PASS: a fresh process served the grafted tree from the cache the last one filled
```

The last line is the remount: a second `mount-gen` over the same cache
directory, still offline, still correct — the cache outlives the process.
In the ordinary lane, `TestPrefetchAllMakesGraftedBlocksLocalAndReadsThem
Offline` asserts the same thing plus that **zero** source fetches were
attempted after the source went away, and
`TestPrefetchedBlobsAreEvictedLastAndTheLossIsRecorded` drives both
eviction passes.

---

## Decision 14 — Grafting into a POPULATED volume: the splice, and what happens at the path

**Decision: a `publish.Source` that splices the spidered tree over the
previous generation at exactly one path, on `mergeSource`'s pattern; and a
verdict per collision case, with every refusal ending in what to do
instead.**

This was ranked item 1 and it was the thing between the feature and being
usable: everything before it was `pelfs init` then `pelfs graft`, which
nobody wants. `internal/publish/graftsplice.go`.

### The shape, and why it is cheap

`mergeSource` was the right model and the analogy is exact in one respect
and narrower in another: like a merge, the tree publish walks is assembled
from two sides that already have their content records; unlike a merge, the
two sides meet at **one path** rather than everywhere, so what has to be
held is proportional to the depth of the graft path and not to the
divergence.

Three optional `Source` capabilities carry the whole design, and each
answers for one half of the tree:

| capability | answers for | what it buys |
|---|---|---|
| `ContentReuser` | BASE files | their chunkrefs are the ones the previous generation published, in packs `buildSuperblock` carries forward verbatim. **No byte of the volume is re-read or re-chunked.** |
| `ContentProvider` | GRAFTED files | external chunkrefs located by the `GraftEntry`, exactly as `GraftSource` does on a fresh volume |
| `CatalogReuser` | the whole tree | `DirtyInodes`/`DirtyScope` are **the spine and nothing else**, so the walk stops at every catalog root outside the graft path |

The third is the one that makes size irrelevant. A graft into a 10M-inode
volume rewrites the catalogs from the graft to the root and does not *look
at* the rest — the git property. `TestGraftAcrossANestedCatalogBoundary`
measures it: a volume with a real catalog tree, a graft inside one of the
nested catalogs, and assertions that `CatalogsReused > 0` **and**
`SubtreesPruned > 0`. A graft path crossing a nested-catalog boundary
therefore needs no special handling at all and is not refused: catalog
boundaries are recomputed from weights every publish, and a pruned subtree
stands in for itself with its recorded weight (`buildDirNode`, `Pinned`).

The completeness argument for that tiny dirty set is worth writing down,
because `CatalogReuser`'s contract says a missing inode is a lost change.
Grafted inodes are numbered **above the base generation's allocator mark**,
so no entry in the previous generation's catalog list can be keyed by one
of them, and the carry-forward test needs a matching inode *and* a matching
path. A grafted inode cannot be mistaken for an unchanged one. Everything
the base published is either on the spine (dirty, rebuilt) or untouched.

A spine directory the volume already has **keeps its inode and its
attributes** — mode, owner, times, xattrs, and its other entries. That is
the whole of why an existing volume survives a graft, and
`TestGraftKeepsAnExistingDirectorysIdentity` pins it.

### The collision matrix

What is at the graft path decides what happens to it. Silently replacing a
populated directory is the worst outcome this feature had available, so it
is a refusal; and because a refusal that leaves somebody guessing is worse
than the operation it prevented, each one ends in a way forward.

| at the graft path | what happens | why |
|---|---|---|
| nothing | **graft** | the ordinary case |
| nothing, and intermediate directories missing | **graft**, synthesizing them (0555, the grafting user) | and it says which ones it will create, so a mistyped path is visible now rather than as empty directories somebody finds later |
| an intermediate component is a file/symlink/device | **REFUSE** (`ErrGraftPathNotDir`), naming the component | there is nowhere to put the tree. `--replace` does NOT force this: replacing a file with a directory tree the user did not describe is a different operation |
| an EMPTY directory | **graft into it** | nothing is lost, so nothing is asked. This is the shape a user who prepared a mount point leaves behind, and refusing it would be pedantry |
| a POPULATED directory | **REFUSE** (`ErrGraftPathNotEmpty`) — with the entry count and two of the names — unless `--replace` | a graft REPLACES the directory it lands on rather than merging into it. Merging was considered and rejected: the hybrid tree it produces has no defensible answer for what the next `--refresh` does to the local half |
| a file, symlink, or device | **REFUSE** (`ErrGraftPathOccupied`), naming what it is and its size, unless `--replace` | same reason, smaller blast radius |
| a graft from the SAME source | **REFUSE** (`ErrGraftSameSource`) and say it is a refresh | re-grafting the same source IS `--refresh`, which re-reads only what changed AND keeps the block rule the graft was cut with. A different rule moves every identity in it, so this is not a stylistic preference |
| a graft from a DIFFERENT source | **REPLACE**, loudly | a graft's bytes were never in this volume, so nothing local is lost — but it changes who every reader of this volume fetches from, so the report names both sources at `WARN` |
| a whiteout from an earlier deletion | **there is no such case** | whiteouts are an overlay concept (`internal/overlay`); a published generation records a deleted path as simple absence, so this is the "nothing" row. A live writable mount's whiteout over the same path is a concurrent-writer question, answered by the lease and the CAS flip below |

`--replace` covers only the two rows that name it. It is not a
force-everything flag, and in particular it does not override the nesting
refusals or the same-source refusal, both of which have specific and
better answers.

### Nesting: both directions refused, by name

- **A graft INSIDE an existing graft** (`ErrGraftNested`). The directory
  that would hold it is synthesized from the outer graft's spider result,
  so the outer graft's next `--refresh` rebuilds that subtree from its
  source and the inner graft simply stops being in the namespace — a
  signed generation quietly missing a tree somebody grafted. There is no
  mechanism here that could keep it, so it is refused rather than
  half-supported. The message names the outer graft and its source, and
  offers `--remove`.
- **A graft CONTAINING an existing graft** (`ErrGraftSwallows`). The new
  tree covers the inner graft's mount point, so the inner graft's files
  leave the namespace while its `GraftEntry` stays in the superblock: a
  volume that names a third party it no longer reads. `--remove` the inner
  one first and the outer is an ordinary graft.
- **Two grafts side by side** is the case that must NOT be refused, and
  `TestTwoGraftsSideBySide` exists to make sure the checks are about
  nesting rather than about there being a graft at all.

### The generation is a write, so it is a write

`pelfs graft` now does everything a publish does, and the order is the
interesting part:

1. **Everything that can fail cheaply fails first.** The signing key is
   loaded and checked against the head, and `publish.GraftPreflight` runs
   the whole collision matrix — one directory listing per component of the
   path — *before* a byte of the source is read. A graft streams the whole
   source once, which at TB scale is hours; "there is a populated
   directory at that path" is news that has to arrive in the first second.
2. **The walk.** No lease. It reads a third party's storage and touches
   nothing of this volume, and holding the branch for the hours it takes
   would stop a mount from checkpointing for no reason.
3. **The lease**, taken between the walk and the flip, which is the window
   that actually needs protecting (`maintenanceLease`, the same one
   `repack` and `merge` take, on the same per-branch key).
4. **The head is RE-READ**, and the preflight runs again against it.
   Splicing against the generation the command started from would publish
   a tree that never existed: every write a mount checkpointed while the
   spider ran would be silently reverted. If the branch moved, it says so
   and splices into what is there now.
5. **The publish**, whose flip is CAS-guarded against `PrevRaw` and then
   read back (`publish.flip`).

**Interruption safety** is therefore the pipeline's own, not something
added: nothing mutable changes until the flip, so a killed `pelfs graft`
leaves the branch exactly where it was and its uploaded packs as
unreferenced orphans for GC.
`TestAFailedGraftLeavesThePreviousGeneration` proves it with a store that
stops accepting writes partway through — the shape a `kill -9`, a full
disk or an expired token has from in here — and then asserts the branch
still holds the old generation, that it still reads through a **cold
cache**, and that `/ext` is not in its namespace.
`TestAGraftAgainstAMovedBranchIsRefused` drives the other half: a
concurrent writer advances the branch mid-walk, the loser's publish is
refused naming the skew, and the winner's generation is intact.

### `--remove` came along, and it was cheap

Ranked item 5's other half. With the splice in place a removal is the same
source with the spliced entry **dropped and not re-stated**: the previous
generation's tree minus one subtree, and the superblock's graft list stated
without that entry (a non-nil empty slice, since nil carries the parent's
list forward). It reads nothing, so there is no walk to interrupt and no
checkpoint to keep — which is what makes it the answer the nesting
refusals are able to offer.

Two things it deliberately does not do. It does not remove the
directories the original graft had to CREATE on its way to the mount path
— removing them would mean guessing which of them the volume's owner also
wanted, and a graft does not record that — and it is not an undo: the
generation that served the graft stays readable until it ages out of the
retention window, so the way back is to re-graft, and the report says so.

### What this leaves for later, stated rather than discovered

- **A refresh RENUMBERS the grafted subtree.** Inodes are numbered from
  the base generation's allocator mark upward, which makes routing an
  inode to its side arithmetic rather than a lookup — and means the mark
  has moved on by the next refresh. Correct but not free: every catalog
  under the graft rebuilds even where nothing changed, and the allocator
  advances by the size of the graft each time. Preserving the numbers
  means walking the old subtree for its path→inode map. Ranked below.
- **An out-of-band publish strands a leftover write overlay**, and this
  is where people will meet it. An overlay records the generation it
  shadows, so a head that moves underneath it makes it unsealable and
  `pelfs mount --rw` refuses with `overlay.ErrGeneration`. Not new and not
  graft-specific — `pelfs repack`, `pelfs merge` and a second writer have
  always done it — but grafting into a *populated* volume means the state
  directory has usually just had a writable mount in it. `pelfs graft`
  now WARNS about it up front, where it costs nothing to act on. The real
  fix is for `overlay.Open` to retire a mismatched overlay that has
  nothing unsealed in it, and that is a change to the write path's
  contract rather than to this feature. Ranked below.
- **A source truncated below a block's START** comes back as a transport
  error (HTTP 416) and is classified as one rather than as a
  graft-integrity failure. Distinguishing "the object shrank" from any
  other range refusal would mean parsing the transport's status here or
  spending a HEAD on every failure. The read fails closed either way; only
  the label is less precise. `TestATruncatedSourceIsAlsoAnIntegrityError`
  truncates *inside* the block being read, which is the case the
  classification does catch.

---

## Decision 15 — Graft-integrity failure is its own error class

**Decision: `genfs.ErrGraftIntegrity`, a `*genfs.GraftIntegrityError`
carrying the evidence, and `EBADMSG` at the FUSE boundary. The message is
unchanged.**

Ranked item 12, and the log line that named it —
`Read: returning EIO for an unrecognized error` — was the whole
complaint: the one failure in this system that is neither damage nor a bug
was arriving as the sentence we print when we do not understand our own
failure.

The distinction that makes the class worth having is **operational, not
aesthetic**. A grafted read fails in two ways that mean opposite things:

| what happened | retry? | class | errno |
|---|---|---|---|
| the source was unreachable — a GET failed, a token expired, a federation was down | **yes**, probably in a second | ordinary I/O error | `EIO` |
| the source ANSWERED and the bytes were not the published bytes | **never** — the next read of the same range returns the same wrong bytes, because the source really has changed | `ErrGraftIntegrity` | `EBADMSG` |

A job that retries on `EIO` spins forever on the second, and from one
errno it cannot tell them apart. `EBADMSG` ("Bad message") is also the
honest sentence for it — the message that arrived is not the message that
was asked for — and it is what a user sees out of `cp`, `tar` or `dd`,
distinctive enough to search for where "Input/output error" is the generic
muddle.

Three consequences:

- **Go callers ask once.** `errors.Is(err, genfs.ErrGraftIntegrity)`
  covers both kinds; `errors.As` into `*GraftIntegrityError` gets the
  graft, the source, the object key, the range, and both hashes, so an
  fsck finding or a report never has to parse the message.
- **The log line is its own**, on its own suppression budget rather than
  the EIO explainer's, so a mount drowning in unrelated EIOs cannot
  silence the one message that names a changed source. It keeps the whole
  original sentence, which already named the graft, the object, the range,
  both hashes, what changed, and the fix.
- **`GraftStats.Mismatch` now counts both kinds** — a hash mismatch and a
  short object are both "the source changed" — so `Failures` with
  `Mismatch` at zero means a network, and a non-zero `Mismatch` is never
  zero for a benign reason.

---

## The spike

`scripts/graft-spike-docker.sh` → `scripts/graft-spike-test.sh`. Docker,
because macOS denies the shell access to its own FUSE mounts; a real Linux
kernel, real FUSE, `--network none`, a `fakeorigin` serving **two prefixes**
— `/vol` is the pelfs volume, `/ext` is the foreign tree. Exit 0.

### The tree, and the claim that nothing was copied

```
source tree: 4 files, 3970037 bytes
grafted 3 files (3970016 bytes) at /ext from http://127.0.0.1:18997/ext
1 files under 65536 bytes were stored inline in the catalog (21 bytes) and are not grafted
5 blocks across 3 source objects; index is 396 bytes, read whole

grafted tree:      3970037 bytes at http://127.0.0.1:18997/ext
volume pack bytes: 2689 bytes under http://127.0.0.1:18997/vol/packs
the data was NOT repacked locally: packs are 0% of the tree
```

**2,689 bytes of volume storage for a 3,970,037-byte tree** — 0.07%, and
those bytes are the catalogs, not the data. This is checked, not printed:
the script fails if the packs are as large as the source.

### The good read

```
-r--r--r-- 1 root root 1048576 Aug 23 19:53 exactblock.bin
-r--r--r-- 1 root root 2621440 Aug 23 19:53 multiblock.bin
-r--r--r-- 1 root root      21 Aug 23 19:53 small.txt

diff -r --no-dereference $WORK/ref $WORK/mnt/ext
PASS: every grafted byte read back correctly through the mount
PASS: a 2000-byte read across the 1 MiB block boundary is correct
PASS: grafted files are read-only (0444), directories 0555
```

The tree is diffed against a **reference copy**, not against the origin
directory, so the test that mutates the origin next cannot also mutate what
it compares to. The ranged read straddling a block boundary is the property
a whole-object digest could not have verified (Decision 2).

### The failure

One byte at offset 1,500,000; the file's **length unchanged**, so nothing
about the namespace looks wrong.

```
-- the UNTOUCHED files must still read fine --
PASS: the other grafted files are unaffected

-- the mutated block must FAIL, not return wrong bytes --
dd: error reading '…/mnt/ext/data/multiblock.bin': Bad message
0 bytes copied

ERROR pelfs: graft integrity failure, returning EBADMSG ("Bad message"): genfs: graft /ext:
http://127.0.0.1:18997/ext/data/multiblock.bin [1048576,+1048576) hashes to
8a7b79e18a96b98ac30a6287c32eb8ec9405514f03e11b3f82d4c76d20a52a78, the generation
says 5dfc71717d9f562de745c6870a9af3ce870a2614ca366c0814f3591939f7ed63 — the graft
source has changed since it was spidered, so these bytes are NOT what this volume
published; run `pelfs graft --refresh /ext` to republish it

PASS: failed closed, naming the graft, the source, the object and the fix
PASS: the unchanged blocks of the SAME file still read (per-block granularity)
```

That log line used to read `Read: returning EIO for an unrecognized
error` — the raw-FUSE binding saying it had no errno for this — and it was
**a finding, not noise**. It is fixed: Decision 15 gave the failure its own
error class, its own errno, and its own log budget, and `dd` now says `Bad
message` instead of `Input/output error`, which is both more accurate and
distinguishable from the transport failure that IS worth retrying.

### Ungraft on write

Section 5, quoted in full under Decision 3. The load-bearing move is
deleting the source object for the written file: it reads anyway.

### Resume, and a refresh that costs what changed

```
-- a re-run of an unchanged source --
resuming: 3970037 bytes of this source were already digested
digested 0 bytes in 0s; 3970037 bytes were already checkpointed and were not read again
PASS: the refresh read ZERO bytes of source data -- the checkpoint carried it
PASS: the refreshed generation serves the same bytes

-- and a source that CHANGED costs only the file that changed --
digested 400000 bytes in 0s; 3670037 bytes were already checkpointed
the refresh read 400000 bytes for a 400000-byte change in a 3970037-byte tree
PASS: only the changed file was re-read
PASS: the refreshed graft serves the NEW bytes of the changed file
```

### `--prefetch`, which used to be the section that failed

Two fakeorigin processes over one directory, so the graft SOURCE can be
killed without touching the volume's own storage. That separation is the
whole test: a graft makes a volume's availability the intersection of two
storage systems, and the only honest proof that the bytes are local is to
remove the one you do not own.

```
-- --prefetch all must MOUNT and report the volume fully local --
INFO pelfs: prefetched 1 packs (1 already cached) across 5 files, 1.0 MiB local; fully local: true
INFO pelfs: prefetched 4 of 4 grafted blocks (2.9 MiB local, 2.9 MiB transferred from the
graft source); the files are still grafted and the volume is unchanged — this is a local
copy, not a materialization
PASS: --prefetch all fetched the graft into the local cache and said so

-- NOW KILL THE GRAFT SOURCE. The volume's own origin stays up. --
the graft source at http://127.0.0.1:18998/ext is unreachable (curl fails);
http://127.0.0.1:18997/vol is still up

PASS: every still-grafted file read back byte-for-byte WITH THE SOURCE OFFLINE
PASS: the locally packed files in the same tree still read too
PASS: an offline read across a 1 MiB block boundary is correct
"prefetch_complete": true
"prefetch_grafted_bytes": 3021440
"prefetch_graft_local_bytes": 3021440
PASS: a fresh process served the grafted tree from the cache the last one filled
```

The tree at that point is deliberately MIXED — section 6 ungrafted one
file into local packs and added a local one — so the offline reads are
checked per file rather than with `diff -r`, and the packed files are
checked too. That is what says the grafted reads came from the graft cache
and not from a pack.

The other two modes, and the refusal:

```
-- --prefetch packs must MOUNT, WARN, and not claim the volume is local --
WARN pelfs: prefetch: /ext is GRAFTED from http://…/ext and this mode does not fetch it
— reads under it will go there (2.9 MiB of grafted content in this generation).
`--prefetch all` fetches and verifies it into the local cache
INFO pelfs: … fully local: false
PASS: --prefetch packs mounts, warns by name, and reports not-fully-local

-- and a cache too small must refuse with BOTH NUMBERS, not a categorical no --
ERROR pelfs: prefetch: refusing to mount: making this generation local needs 3.9 MiB —
3.9 MiB grafted from /ext <- http://127.0.0.1:18998/ext (3.9 MiB) — and the local cache
budget is 187.5 KiB. Raise --cache-size above 3.9 MiB, or use `--prefetch packs` to make
the packed content local and read the grafted content from its source
PASS: the refusal is about SIZE, carries both numbers, names the graft, and offers a way on
```

The test also asserts that no message anywhere contains "no listed pack",
because that sentence means damage everywhere else in this system and a
graft is not damage.

### What is still NOT proven

Said plainly:

- ~~It grafts over an empty root.~~ **Done, Decision 14** — and the
  transcript above is section 9 of the spike: a volume written through a
  real writable mount and sealed, then grafted into, with every
  pre-existing file compared byte for byte afterwards, a seal over the
  grafted volume, and a cold remount that agrees with all of it. Nothing
  in the read path or the format changed, as predicted.
- ~~`fsck` still reports every grafted file as damaged.~~ **Done,
  Decision 4** — and the spike's section 10 is the transcript: clean at
  exit 0 on a healthy grafted volume, a truncated source object a warning
  at exit 0 and an error under `--strict`, a one-byte same-length edit
  invisible to `--grafts=head` (which says so) and caught by
  `--grafts=deep`, and a missing index object damage at exit 1.
- **Grafted reads are not coalesced.** `fillChunks` skips them, so a
  multi-block read is one request per block, plus one index lookup per
  block on a windowed index. The speculation trick in Decision 9 makes
  both nearly free and is not built.
- No `merge` support, no `grafts/` retention key space, no `GraftStats` in
  the stats JSON (the PREFETCH graft counters are there; the read-path ones
  are not yet). **`--remove` is built** (Decision 14).
- **No `pelfs cache` awareness of graft blobs as a category.** They are
  counted — they live under `packs/`, which is the point — but a user
  reading the breakdown sees them as pack bytes. A `graft` line in
  `DirUsage` would need the blobs in a directory of their own, which
  would cost the free accounting; the honest fix is to split the `packs`
  row by filename prefix at report time.
- **A prefetched graft is not durable against eviction**, by design
  (Decision 13). Pass 2 of the sweep can take it back if the cache goes
  over its cap, and `PinnedEvicted` records that. Nothing yet SURFACES
  that number to the user mid-session.
- **No test of concurrent readers of one graft block**, or of a source that
  fails mid-read. A graft across a nested-catalog boundary IS tested now
  (`TestGraftAcrossANestedCatalogBoundary`).
- **The resume is tested against process exit, not against a kill in the
  middle of a span.** The unit of durability is the object, so a killed
  span costs that object; that is argued, and it is not yet asserted by a
  test that actually kills something mid-walk.

---

## Ranked implementation work

Effort is calendar-days for someone who knows this codebase. **Struck
items are done** in this round.

| # | Work | Why it is here | Effort |
|---|---|---|---|
| 1 | ~~**Graft into a populated volume**~~ | **done** — Decision 14; `publish.GraftSpliceSource`, the collision matrix, both nesting refusals, the lease and the re-read, and interruption safety proven against a dying store | — |
| 2 | ~~**`fsck`: a `Severity` axis, then graft awareness**~~ | **done** — Decision 4; the severity axis landed first, then grafted blocks joined the identity index, the severity table, `--grafts=none｜head｜deep`, and `graft.Reader.Enumerate`. `pelfs fsck` is clean at exit 0 on a healthy grafted volume | — |
| 3 | ~~`--prefetch`: FETCH grafted blocks into a local cache tier~~ | **done** — Decision 13; blobs under `packs/`, verified on the way in, offline reads proven, two-pass eviction, budget refusal with both numbers | — |
| 4 | ~~Ranged-window index lookup~~ | **done** — Decision 9; `graft.Reader`, whole under 4 MiB, windowed above | — |
| 5 | ~~`pelfs graft --refresh`~~ / ~~**`--remove`**~~ | **done** — refresh costs only what changed (Decision 11); `--remove` fell out of the splice (Decision 14) and is what the nesting refusals now offer | — |
| 6 | **`grafts/` in the retention key space** | index objects leak forever today, and they are now large | 0.5 d |
| 7 | **Coalesce adjacent graft blocks, and SPECULATE the next block's location** | one request per block, plus one index lookup per block on a windowed index. The identity check makes a wrong guess free (Decision 9) | 1–2 d |
| 8 | **`merge`: `ProvidedGrafts`, and make `sameRef` location-aware** | merge on a grafted volume fails loudly now; making it work needs both | 2–3 d |
| 9 | **Publish `GraftStats` into the stats JSON; wrap the graft store in `stats.WrapStorage`** | third-party traffic is invisible in the summary | 1 d |
| 10 | ~~Spider: parallelism, and `extsort` instead of an in-memory identity set~~ | **done** — Decision 11; plus the checkpoint, the progress ticker, and the two-listing consistency check, none of which were on this list and all of which the size demanded | — |
| 11 | **`--no-graft` and `--graft-allow` mount flags** | the reader's veto is all-or-nothing today | 1 d |
| 12 | ~~**A distinct errno/error class for graft-integrity failure**~~ | **done** — Decision 15; `genfs.ErrGraftIntegrity`, `*GraftIntegrityError`, `EBADMSG`, its own log budget | — |
| 13 | **Re-derive `GraftEntry.Path` at report time, or record the root inode** | renaming a grafted directory makes `--list` lie | 0.5 d |
| 14 | **`pelfs graft --materialize`** | permanently ungraft a subtree (Decision 13) — distinct from prefetch, which is now built; reuses `adoptByReading` and `publish`, needs the lease and a resumable driver | 3–4 d |
| 17 | **Report graft blobs as their own line in `pelfs cache`, and surface `PinnedEvicted`** | a prefetched graft that got evicted is invisible to the user today | 0.5 d |
| 15 | **Record a per-object digest at graft time**, then use it in `fsck --grafts=head` and to gate `--refresh` | still the thing to build instead of TOFU (Decision 12), but it is a FORMAT change and not a call site: an ETag is either a restatement of size+mtime or opaque (`pelicanobj.VerifyPut` says so), and the index records nothing to compare one against. Decision 4 has the finding | 2–3 d |
| 16 | **Arena sizing for graft-heavy mounts** | the arena is tuned against decode cost, and a graft trades in round trips | investigation |
| 18 | **Preserve grafted inode numbers across a `--refresh`** | a refresh renumbers the whole grafted subtree, so every catalog under it rebuilds even where nothing changed, and the allocator advances by the size of the graft each time. Needs a walk of the old subtree for its path→inode map (Decision 14) | 1–2 d |
| 19 | **`overlay.Open` should retire a mismatched overlay that has nothing unsealed** | an out-of-band publish — graft, repack, merge, a second writer — strands a clean leftover overlay and `mount --rw` refuses it. `pelfs graft` warns now; the fix belongs to the write path (Decision 14) | 1 d |

Items 1 and 2 are done, so the feature is usable on a volume that already
has content in it AND the volume can be checked: `pelfs fsck` is clean at
exit 0 on a healthy grafted volume, a moved source is a warning that
exits 0 (and 1 under `--strict`), and a lost index object is damage that
exits 1. Section 10 of the graft spike asserts all three end to end.

What is left on this list is no longer load-bearing for using the
feature. The largest remaining red is **`merge`** (item 8), which fails
loudly rather than silently; the cheapest real win is **`grafts/` in the
retention key space** (item 6), which `fsck` has just made more visible
by reporting a graft nothing references.

---

## Why this might be a bad idea

Five reasons, in descending order of how much they worry me.

**1. It makes a pelfs volume's availability the intersection of two
storage systems.** Today, a volume is readable if its own prefix is
readable. A grafted volume is readable if its prefix **and** every graft
source are readable, by every reader, from wherever they are. The
availability of the whole is the product of the parts, and one of the parts
belongs to someone with no obligation to you. Everything else here is
engineering; this one is arithmetic.

**2. "Fail closed" is correct and will still feel like a bug.** The
spike's error message is as good as I know how to make one — it names the
graft, the object, the range, both hashes, what changed, and the fix. It
will still arrive as `Input/output error` in the middle of somebody's job,
hours after an upstream maintainer republished a file for a perfectly good
reason. A graft turns an ordinary upstream event into a read failure in a
filesystem, and no amount of error-message quality changes that. It is
worth asking whether the real use case wants a graft or wants
`pelfs` to *ingest* the tree once and be done.

**3. The security property is genuinely new and users will not model
it.** Every other object a pelfs mount fetches lives under a prefix the
reader already decided to trust. A graft is the first time reading a file
sends your client somewhere the volume's author picked. The mitigations
here are real but they are all *opt-in vigilance* — a log line, a
`--list`, a veto function nobody will supply a policy for. The safe
default would be to refuse grafts unless the mount explicitly allows them,
and I did not choose that default because it would make the feature
unusable out of the box. That is a trade I would want you to make
deliberately rather than inherit from this spike.

**4. The interaction surface is large and still not done.** The inventory
table had four 🔴 rows and five 🟠. Three of the reds are now closed
(`ContentOf`, `--prefetch`, the whole-index fetch) and the two 🟠 that
would have caused silent wrongness were closed in the first round — but
`fsck` and `merge` are still red, and a feature that requires touching
`fsck`, `merge`, `retention`, `stats` and `rescue` before it is coherent
is a feature with a long tail. What remains in the ranked table sums to
roughly two to three weeks, and I would not trust it to better than 50%.

**5. It is a second way to do something pelfs already does well.** The
chunker plus cross-generation dedup means ingesting a tree you don't own is
not that expensive, and the result has none of the properties above: it is
self-contained, verifiable from packs alone, rescuable, mergeable,
prefetchable, and encryptable. A graft buys you "don't store the bytes" and
pays for it with every one of those. The case where that trade is clearly
right is a *large* tree you would never store and *mostly do not read* — a
CVMFS software area, which is presumably why CVMFS has the feature. The
case where it is clearly wrong is a tree small enough to ingest. I would
want a size threshold in the documentation, and I would want `pelfs graft`
to say something when you graft a tree that is under it.

None of these is a reason to stop. The first three are reasons to be
careful about defaults, and the last two are reasons to be honest in the
documentation about when *not* to use it.
