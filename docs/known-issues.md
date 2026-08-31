# Known issues

Open defects that have been **found and not fixed**, and limitations that
were **accepted on purpose**. This file is TRACKED, which is the whole
point of it: a bug that lives only in one working copy has not been filed.

Where the other three homes are, so nothing is duplicated into this one:

| document | scope | tracked? |
|---|---|---|
| `docs/known-issues.md` (this file) | open defects + accepted limitations, as of **main** | yes |
| `docs/TODO.md` | the working punchlist — burn-down, agent notes, post-mortems | **no**, `.gitignore:4` |
| `CHANGELOG.md` → *Known limitations* | what a given RELEASE shipped with, frozen | yes |
| `README.md` → *Caveats (prototype)* | what a USER has to know before mounting | yes |
| `internal/hostile/testdata/corpus/*.plan` | findings pinned as executable plans | yes |

Rules for an entry here:

1. **Every entry says whether an executable test pins it**, in those words.
   A tracked bug and a tracked hope look identical in a document and
   nothing alike in a repository, and the difference is worth one line.
2. An entry is deleted when the defect is fixed, not annotated — the fix's
   own test is the record from then on, and `git log` is the history.
3. Verified against a commit, and the commit is named. A claim carried
   forward on faith is how `docs/TODO.md` came to assert that the v0.1.0
   tag was unpushed three weeks after the release went out.

**Audited at `25100f3` (main, 2026-08-22)** by triage-agent, against every
open item in `docs/TODO.md`, and **re-verified at `0c2baf0`** by
release-agent for the v0.2.0 release. What was audited and found already
fixed is listed at the bottom, so nobody re-files it.

**Re-audited at `b037b03`** by docsync-agent, for the `pelfs browse`
surfaces only: KI-11 and KL-11 through KL-14 were filed from that work,
two rows were added to the table at the bottom, and the KI/KL entries that
predate it were not re-checked (they were current at `0c2baf0` and nothing
in `pelfs browse` touches them).

**KL-17 was closed** by durableprofile-agent, one commit after it was
filed. It said the next thing to fix on that path was "a client id derived
from a per-volume key in the state directory so that a regenerated profile
is byte-identical to the one the user already installed", and that is what
landed: `internal/localoauth/identity.go`. Its row is in the table at the
bottom, including the one thing the entry did NOT predict — that a pure
function of the identity tuple lets a revoked profile be re-armed by
re-adding the same label, which is why the derivation carries a per-entry
epoch. **KL-18 stays open and is still true**: the port is derivable by any
local process and can be squatted, and nothing in that work changes it.

**KI-11 was closed at `b16784d`** by mount-app-agent, the pass that put the
file manager on the route table — the same pass that made the defect
reachable by a user at all, since until then nothing served the app. Its row
is in the table at the bottom, with what the entry got wrong about its own
mechanism.

**Re-verified at `b16784d`** by release2-agent for the v0.2.1 release,
this time over every entry rather than one surface. The file now holds
**7 KI (4-9, 11) and 15 KL (1-9, 11-16)** — KL-15 and KL-16 are new here,
for the two limitations this release ships with that nothing else tracks:
no resumable upload on any surface, and what an NFS mount's honest `fsync`
costs on real storage. Three things were wrong and are fixed:

- **KI-10 was still here as an open entry while the table at the bottom
  said it was fixed.** It is fixed — `f49cb8f` in this repo and `d92cb75`
  in the go-nfs fork — so by rule 2 the entry is deleted and the table row
  is the record. The preamble above already claimed this had happened; it
  had not.
- The closing prose carried a **duplicated half-sentence** from a merge,
  which listed KI-10 as open in the same breath as the paragraph explaining
  how it was closed.
- **Every KI entry except KI-9 had stale citations.** `cmd/pelfs/mountgen.go`
  moved ~130 lines this cycle, `internal/genfs/packindex.go` ~110, and
  `internal/vfsbilly/vfsbilly.go` ~97. KI-9's ten line numbers are all
  still exact. KL-6's SCOPE was also wrong rather than merely its
  citations, and KL-9 named the wrong harness script.

Every entry was previously checked against the code at `0c2baf0`, where all
of the then-open KI and KL entries were still true. (KL-8 was filed after
that audit, with the `--fusemount` work; KL-10 was filed and then closed
after it, and is in the table at the bottom.) What had rotted then was the
citations — `internal/repack/execute.go` had moved ~83 lines under KI-9 —
and one paragraph that had itself gone stale (removed).

---

## Open defects

### KI-4. No checkpoint-health signal: no last-checkpoint time, no failure count

**Severity: medium, operators.** A periodic checkpoint that fails forever
is invisible to every reporting surface except a WARN in `daemon.log`. This
is the early warning for the whole class of "the mount looks fine and has
published nothing for a day".

**Mechanism.** The maintenance half of this shape landed with auto-collect
— `Summary.Maintenance` carries `last_repack_at`, `last_gc_at`,
`collections`, `reclaimed_objects`, `reclaimed_bytes`, `condemned_bytes`,
the grace window applied, `collection_failures` and `last_collection_error`
(`internal/stats/stats.go:232-250`, reported by
`pelfs ctl <mount> status`). The **checkpoint** half did not. The seal
block of `Summary` is counters and ids only — `Seals`, `SealedGeneration`,
`SealedChunks`, `SealedCatalogs`, `SealedPacks`, `SealOK`
(`stats.go:187-204`) — with no timestamp anywhere:
`grep -rn 'LastCheckpoint\|last_seal' --include=*.go` is empty repo-wide.
And the failure count is not merely unreported, it is never computed:
`checkpointPeriodically` (`cmd/pelfs/mountgen.go:2014-2135`) keeps a local
`backoff` duration, resets it on success (`:2083`), warns
(`:2079-2081` and `:2120-2122`), and never touches `g.stats`. `SealOK`
(`mountgen.go:2167`, `:2172`) is a boolean about the seal at EXIT.

**Field shape to copy:** `MaintenanceStats`.

**Pinned by an executable test: NO** — and it cannot be, since the fields
do not exist. This is a gap, not a regression risk.

### KI-5. No standing size signal for a volume nobody mounts writably

**Severity: low-medium.** "Do I need a repack?" is answerable only by
paying for a full sweep.

**Mechanism.** No volume pack count and no volume byte total in the stats
file. The nearest fields, `PrefetchPacks` / `PrefetchBytes`
(`internal/stats/stats.go:155-156`), are the right number written from
exactly one place — `runPrefetch`'s recorder,
`cmd/pelfs/mountgen.go:1172-1173` — so a mount without `--prefetch` leaves
both zero. `pelfs ctl <mount> status` (`mountgen.go:2356-2422`) reports
neither. Offline it IS answered
twice, both by commands that do real work: `pelfs repack-plan` prints
`packs: <n>, <bytes> (<pct> live)` (`cmd/pelfs/repackplan.go:190`) and
`pelfs fsck` prints a pack count (`cmd/pelfs/fsck.go:173`). Auto-repack
narrowed this for volumes that ARE mounted writably; the volume this item
was written for is the one nobody mounts.

**Pinned by an executable test: NO** (nothing to pin).

### KI-6. Terminal federation errors are neither classed nor logged

**Severity: low-medium, diagnosis.** When a transfer fails permanently, the
class the retry loop just computed is thrown away.

**Mechanism.** `internal/packstore/retry.go:189-193` returns a
non-retryable error with no counter and no log line, on the stated grounds
that logging FAILED there would cry wolf on every legitimate 404 probe —
a good reason not to log, not a reason to discard the class. `retryable`
(`retry.go:219-228`) distinguishes context-end from `isNotExist` from a
`"404"`/`"not found"` substring and returns a bare bool.
`internal/packstore` imports no `stats` at all. The op IS counted
downstream, because the stats wrapper sits inside the retry loop
(`cmd/pelfs/mountgen.go:574`), into per-verb `Errors` plus 20 error samples
(`internal/stats/stats.go:88-105`, sampled at `:420-430`) — which is precisely the
"one scalar + verb-split" that is not enough to tell a misconfigured token
from a flaky link.

**Pinned by an executable test: NO.**

### KI-7. SETATTR is one SQLite transaction per attribute

**Severity: performance; bites every archive restore.** `tar`'s
chown/chmod/utimes triple is three transactions per file, and `SetAttr`
alone was measured at 22% of untar CPU. The cheapest remaining write-path
win.

**Mechanism.** `overlay.FS.SetAttr` takes `fs.mu` then one `withTx`
(`internal/overlay/write.go:606-613`), and `withTx` is
`Begin`…`Commit`, one commit per call
(`internal/overlay/overlay.go:552-569`). No group commit, no deferred
writeback. `internal/rawfuse/rw.go:380-415` does merge mode/uid/gid/size/
mtime WITHIN one kernel request, but tar's three syscalls arrive as three
requests; `internal/vfsbilly/vfsbilly.go:1005-1084` calls `SetAttr` once per
operation from `Chmod`/`Chown`/`Lchown`/utimes.

**Reproduce.** `make big-tree`, or `scripts/e2e-docker.sh`'s untar leg,
with a CPU profile from `pelfs ctl <mount> pprof cpu`.

**Pinned by an executable test: NO.** `BenchmarkOverlayCreateWrite`
(`internal/overlay/bench_test.go:69`) exercises a `SetAttr` but asserts no
cost, and nothing fails if the per-attribute transaction count grows.

### KI-8. The location cap is lifted wholesale for the whole-map callers

**Severity: high at the design target, invisible below it.** The C2
burn-down capped the read path's resident location map at 131,072 entries
(~21 MB, measured); several callers still opt out and hold every location —
measured at 169-174 bytes each, so 15.8-16.2 GiB at 100M objects.

**Mechanism.** `packIndex.holdEverything`
(`internal/genfs/packindex.go:278-287`) sets `unbounded` one-way and is
called from `packIndex.all` (`:657`). Callers of `all` at HEAD:

- `FS.ContentOf` — **NO LONGER, on a volume with an index** (renameseal-agent,
  2026-08-24). It called `all` to protect the "present in no listed pack"
  verdict, which made the verdict cost one trailer fetch per pack in the
  volume — the headline defect behind a 40.8 s publish of a one-file rename.
  It now asks `packIndex.holds` (`internal/genfs/packindex.go`), which
  answers presence from the hot map, from local trailers, and from the
  generation's own multi-pack index held against the signed pack list, and
  falls through to `all` only when none of those can confirm an identity.
  So the cap is lifted for a volume whose index does not cover an
  identity — an old generation written before indexes existed, or one whose
  index upload failed — and not otherwise. Every caller of `ContentOf`
  inherits that: the seal walk
  (`internal/overlay/accessors.go:381` → `internal/publish/source.go:305`),
  an ordinary write's copy-up (`internal/memtable/base.go:71` ←
  `internal/overlay/write.go:528`), `internal/merge/merge.go:595` and
  `:599`, `internal/merge/apply.go:381`, and
  `internal/memtable/recover.go:557`. `pelfs merge` over two INDEXED
  generations no longer holds every location of both.
- `FS.Prefetch` — `internal/genfs/prefetch.go:110`.
- `FS.LoadPackIndex` (`packindex.go:627`) has no non-test callers.

**The blocker named in the TODO is gone**: the "spill the merged trailers
into a sorted, mmap'd, binary-searchable table" step was built — as
`internal/extsort`, for `internal/fsck` and `internal/reach`
(`internal/fsck/fsck.go:242`). It was simply never wired into
`packIndex`. Note also that **fsck is no longer a `holdEverything` caller**
— `internal/fsck` does not reference `packIndex` at all — so both
`docs/TODO.md`'s list and the code comment at `packindex.go:640-644` name
it wrongly.

**Pinned by an executable test: PARTLY.** `TestLocationHeap`
(`internal/genfs/packindex_test.go`, gated on `PELFS_LOCATION_HEAP=1`)
measures per-location heap and pins the CAP; nothing fails because
`Prefetch` still bypasses it. What IS pinned, ungated, is that `ContentOf`
no longer does: `TestContentOfDoesNotIndexTheGeneration`
(`internal/genfs/contentofcost_test.go`) confirms every file in a 32-pack
generation in one request, and `TestMetadataOnlySealDoesNotFetchTheVolume`
(`internal/publish/renameseal_test.go`) bounds the objects a rename's seal
may fetch in a 98-pack volume. The remaining work is the same as it was —
spill the merged trailers into a `packidx` table under `CacheDir` and
binary-search it — but it is now the answer for `Prefetch` and for the
index-less fallback, not for every seal.

### KI-9. A repack stamps its condemned-ledger rows from the wall clock

**Severity: low in production, real for testability.** It makes a class of
test impossible to write, which is why it is here rather than in the
punchlist.

**Mechanism.** `repackedSuperblock` (`internal/repack/execute.go:796`)
takes `now := time.Now()` at `:799` and stamps `CreatedUnixNano` (`:802`),
the condemned-manifest rows (`:865`), retired indexes (`:870`, `:902`),
`RepackUnixNano` (`:919`) and condemned packs (`:925`) from it — while the
same call path has an injected clock, `Options.Now`
(`internal/repack/repack.go:134`, defaulted at `:345`), and uses it for the
ledger-room check six hundred lines earlier (`execute.go:221`). There is a
second wall-clock read at `execute.go:347`. Harmless in production, where
the wall clock IS the right clock.

**Consequence.** A test cannot drive the ledger's clock through a repack.
That is why the mount-level auto-collect test asserts only the windows and
the reporting, and why the end-to-end "condemned, then collected" property
had to be written in the lifecycle interleaving where the world drives its
own clock.

**Pinned by an executable test: NO, and cannot be.** Fixing it means
deciding whether a repack's ledger stamp is inside the injectable clock —
a repack-semantics call.

---

---

## Accepted limitations

Deliberate, current on main, and each one either pinned or documented where
a user will meet it. Listed here so a triage pass does not re-file them as
defects.

### KL-1. Rotating a key makes a pending merge base permanently unreadable

A branch pins its merge base with a `fork-<branch>` tag, every tag stops
verifying across a rotation, and `pelfs tag` can only freeze a branch HEAD
— so there is no repair. The only correct advice is ordering: **merge
first, then rotate.** `pendingForkTags` (`cmd/pelfs/rotate.go:250`) fetches
each head and the command WARNS, naming each branch and its pinning tag,
before writing anything (`rotate.go:295-301`); `--break-siblings` gates it.
Not fixed on purpose: making rotation re-pin fork bases would have it mint
new tags under the new key, which is a scope and blast-radius change.

**Pinned by an executable test: YES.**
`TestRotationMakesAPendingMergeBaseUnreadable`
(`cmd/pelfs/rotaterescue_test.go:440`) drives `pelfs branch` for real,
asserts the base is readable before, that the warning names the tag, and
that the base is unreadable after — and so **fails loudly if the
interaction is ever fixed elsewhere**, telling whoever fixed it to delete
the warning.

### KL-2. The exit drain is unbounded and cannot be interrupted

A mount that is asked to exit while a checkpoint is in flight WAITS for it,
with no deadline: a federation that never answers leaves the drain waiting
for the transport's own timeouts or a SIGKILL, and under a batch system
SIGTERM spends the grace period finishing the seal. That is the trade the
owner asked for — a deadline here would be inventing policy.

**Pinned by an executable test: YES.**
`TestExitDrainsAnInFlightCheckpoint` (`cmd/pelfs/mountgen_test.go`) parks a
checkpoint inside `sealLocked` behind a gated upload, asserts the drain
does NOT return, then asserts the generation landed and the ref advanced.

### KL-3. A branch NAME is not a lineage

`(branch, generation)` is now an identity for retention attribution, but
delete a branch, recreate it from an older generation and seal the same
numbers again, and the two incarnations collide exactly as two branches
used to. The newest-first scan favours the live one, and a repack that
copied an old backup into a new pack can defeat that. Tag a generation to
pin it exactly. Documented in `CHANGELOG.md` (*What is still not fixed*).

**Pinned by an executable test: NO.** The attribution rule it qualifies is
tested; this residue is not.

### KL-4. A long grace window buys less than it looks like it buys

The two derived-ref ledgers gain ~a row per checkpoint per key space
against a 48 KiB cap (~517 hash-named rows), so past
`517 x checkpoint-interval` the byte cap binds before the window does: the
volume behaves as though its window were that long, and repack paces to the
room left. At the 5-minute default that is ~43h — the 72h default is
already past it and `--grace 30d` is past it forty-fold. Safe (pacing only;
nothing a head or tag names is affected), so it is computed
(`superblock.LedgerWindow`, `internal/superblock/condemn.go:150`) and
printed by `pelfs init` when the numbers collide rather than being
prevented. One gap: `gracePacingNotice` is called under `if window > 0`
(`cmd/pelfs/volume.go:184`), so the notice appears only when `--grace` was
passed explicitly — the 72h DEFAULT collides too (864 rows against 517) and
says nothing.

**Pinned by an executable test: YES.**
`TestTheLedgerCarriesAsManyRowsAsLedgerWindowClaims`
(`internal/superblock/ledgerwindow_test.go:26`) holds the arithmetic to
what the ledger rule actually does, so the sentence `pelfs init` prints
cannot drift from the behaviour.

### KL-5. Mixing a pelfs v0.1.0 client onto a v0.2 volume is asymmetric

A v0.2 writer refuses while a live `meta/lease.json` exists (it cannot tell
which branch that client is on) and never writes that object, so **a
v0.1.0 client sees a v0.2 writer as unleased and mounts straight past it**
— its only guard is then the seal's refusal to publish over a moved ref.
Separately, `Branch` in the superblock is a one-way door: a v0.1.0 binary
cannot read a generation a v0.2 writer sealed (`ErrBadSignature`, chosen
over a quiet mis-read that would collect live packs).

**Pinned by an executable test: YES.**
`internal/lease/lease_test.go`'s `TestLiveVolumeLeaseExcludesEveryBranch`
(`:591`), `TestAnExpiredVolumeLeaseIsNoObstacle` (`:653`),
`TestStealLeaseDoesNotTouchTheVolumeLease` (`:617`). For the superblock
door, the wire compatibility against CAPTURED v0.1.0 bytes:
`TestAV010SuperblockStillVerifies` and
`TestABranchStampedSuperblockIsRefusedByAReaderThatDropsTheField`
(`internal/superblock/branchfield_test.go:55`, `:119`) over the committed
fixture `internal/superblock/testdata/v010-superblock.hex`, plus
`TestAV010AnnouncementIsStillTheSameAnnouncement`
(`internal/superblock/nextpubcompat_test.go:39`) for the announcement.
Documented in `README.md` *Caveats* and in `CHANGELOG.md` *Upgrading from
v0.1.0*.

### KL-6. No frontend on the shared layer consults a per-request credential

Every request is evaluated as the server process's own identity. For NFS
that means the AUTH_UNIX credential is deliberately ignored: the export is
loopback and single-user, and any local process can dial 127.0.0.1 and
claim any uid, so honoring the credential would make the check look like a
security boundary, which it is not. This is FIDELITY — the same answer
through every frontend — and not access control. Written down in those
words in `docs/go-nfs-patches.md`.

**The scope is wider than this entry's old title said.** The identity is a
property of the shared layer (`internal/vfsbilly/perm.go`), so it now
governs the **WebDAV** surface too (`internal/vfsdav`, served by
`pelfs browse`), and a `--fusemount` mount, which checks permissions in
`internal/rawfuse` over the same `internal/fsperm` model. A per-client
WebDAV credential decides *whether you may reach the surface at all* and
whether the surface is read-only; it does not change *whose* uid the
filesystem answers as. Do not treat any of the three as a multi-user
boundary. `bd7b89c` narrowed the separate NFS *owner override* to the NFS
constructors, which is a different exception and is not this one.

**Pinned by an executable test: YES** for the model it implements
(`internal/vfsbilly/perm_test.go`, plus the `permission_gate` in
`scripts/mount-gate-test.sh` which compares every permission answer over a
real kernel NFS client against the same probe on a local tree), and for the
owner override's confinement to the NFS frontend
(`internal/vfsbilly/owneroverride_test.go:98`, `:170`, a call-site
allowlist that fails naming the constructor to use instead). The
credential decision itself is a policy, not a behaviour to assert.

### KL-7. Two branches cut before inode lineages existed cannot be merged

`pelfs merge` needs the two sides to allocate inodes out of disjoint
spaces, which is what the lineage partition gives a branch cut by this
release (23 bits of lineage above a 40-bit allocation space,
`superblock.InodeLineageShift`). Branches cut before that all sit in lineage
0 and allocated the same numbers for different files.

The merge does not guess: `findCollisions` (`internal/merge/merge.go`)
reports every colliding inode and `Plan.FirstFreeInode` names the number one
side must be shifted above, and `Apply` refuses any plan with collisions
(`cmd/pelfs/merge.go:309-337` prints it). **Nothing in the tool performs the
shift.**

**Partly addressed by `pelfs import`, and it is worth being exact about
which part.** `internal/inodemap` is now the renumbering this issue has
been missing, and it arrived from the other direction — an import has to
renumber a foreign volume's inodes into lineages this one owns, which is
the same operation. What it gives KL-7:

- **The map, including the form this case specifically needs.**
  `inodemap.NewAbove(pairs, cut)` renumbers only inodes at or above a cut
  and leaves the rest alone, which is the whole difficulty here: the
  numbers allocated BEFORE the fork mean the same file on both sides, and
  a three-way merge pairs them up by exactly that equality, so a
  wholesale remap would make every pre-fork file look new on one side.
  `TestAWholesaleRemapWouldMoveTheInodesTwoBranchesSHARE` shows both
  halves.
- **A lineage nobody else holds.** `inodemap.Draw` through
  `cmd/pelfs/branch.go takenLineages`, which now unions every branch,
  every tag and every recorded import (`superblock.TakenLineages`).
- **A permanent record of the claim**, so the renumbered lineage can
  never be drawn again (`superblock.ImportEntry`).
- **Proof it survives a real tree**: `pelfs import` renumbers a whole
  published volume into another, hardlinks, inode shards, symlinks and
  xattrs included, verified through a mount in `make mount-gate`.

**What is still missing, and it is the reason this issue stays open:** a
verb. There is no `pelfs renumber`, and for a v0.1.0 branch — the only
kind this issue is about — there is also nowhere for the cut to come
from, because such a branch records no `Fork.BaseNextInode`. Both are
specified in `docs/TODO.md` under "import-agent", including why pointing
`pelfs import` at the other branch is NOT the fix (it copies every byte
again and renumbers the shared pre-fork inodes as well).

**Pinned by an executable test: YES**, for the refusal and its inverse:
`TestInodesAllocatedOnBothSidesCollide`,
`TestAForkedLineageHasNoInodeCollisions` and
`TestInheritedInodesFromAThirdLineageAreNotCollisions` in
`internal/merge/`; and now for the renumbering itself, in
`internal/inodemap/` and `internal/importvol/`. The VERB that would join
them is, of course, pinned by nothing.

### KL-8. On a passed /dev/fuse descriptor, pelfs checks permissions and reaches two places the kernel would have

A `--fusemount` mount (`docs/design-apptainer.md`) is created by whoever
opened the descriptor, so `default_permissions` is not applied — measured,
from the container's own `/proc/self/mountinfo`; apptainer does not ask for
it and pelfs cannot, the mount predates the driver. `internal/rawfuse`
therefore applies the mode bits itself there, over `internal/fsperm`, and
two things a kernel check would cover it cannot:

- **Path traversal is enforced only on a dentry-cache MISS.** The kernel
  resolves a cached name without asking us, and this mount hands out
  effectively infinite entry TTLs (`entryValidity`), so a directory whose
  mode denies search still admits a name that some permitted caller looked
  up earlier. OPEN, OPENDIR, ACCESS and the namespace operations are never
  served from cache, so those are exact; the walk is not.
- **A caller's supplementary groups are not on the wire.** The FUSE header
  carries uid and gid only, and `/proc/<pid>` is not usable for the rest
  (the pid is in the caller's namespace). For the mount owner pelfs
  substitutes its own group set and CapEff, which is exact; for any other
  uid the group class is evaluated on the primary gid alone, which can deny
  what the kernel would have allowed.

Not fixed because neither is fixable from a FUSE server: closing the first
is precisely what `default_permissions` exists for. A `--fusemount` driver
serves one job's uid, where both reduce to nothing. An ordinary pelfs mount
is unaffected — the kernel still does the checking there, and `ACCESS` still
answers ENOSYS.

**Pinned by an executable test: YES** for what it does enforce
(`internal/rawfuse/perm_test.go` for the ops and the statuses,
`scripts/apptainer-test.sh` section 7e for the same answers through a real
`--fusemount` mount against a real kernel, with an ordinary FUSE mount as
the control). The two gaps are pinned by nothing, which is the honest state
of them: they are properties of the caching contract, not behaviours to
assert.

### KL-9. Cross-generation dedup is per generation, not per session: a session larger than the ring cuts some chunks where the ring flushed

The default write path recognises content the generation it is building on
already holds (`genfs.Placed`), and for the workload that matters — one
image per generation — it realises the chunker's full potential: measured
149,224,395 bytes for four related container images against
`--no-memtable`'s 149,221,054, where before it was 272,755,301
(`docs/design-apptainer.md`, and `scripts/apptainer-test.sh` section 8b
is the harness).

What it does **not** fix is where the boundaries come from. The flush
chunks one batch of the ring at a time (`chunkInode`,
`internal/memtable/flush.go`), so the first chunk of a batch begins where
the batch begins and the last one ends where it ends, and neither is a
content boundary. A chunk with a boundary the ring chose is a chunk no
other generation will ever produce, so it can neither be recognised nor be
recognisable.

**How much it costs, measured.** The damage is two chunks per batch, so it
scales as the chunk size over the BATCH size, and the shipped defaults are
the bad end of that ratio: a batch is `promoteAt`, which is
`DefaultPackTarget` = 2 MiB, against a 4 MiB average chunk.

| session shape | chunks cut on content | bytes |
|---|---|---|
| one 68 MB file (fits the 72 MiB ring; no batch fires) | 14 of 14 | 100% |
| four 68 MB files, one session | 17 of 87 | 28% |

So: **publish one image per generation.** Several large files in one
`mount-gen --rw` session dedup against a later generation only partially,
and two ~93%-identical files in the SAME session dedup against each other
hardly at all (measured before this work: 273,007,591 of 273,846,272
logical).

Not fixed because the fix is not local. A batch would have to defer its
trailing partial chunk to the next batch so the next one resumes at a
content boundary, which means the batch no longer consumes a fixed prefix
of the ring, which puts it in the middle of the backpressure rule
(`appendLocked`, `promoteAt`, and the ring-full path that must always make
progress). It is W2b in `docs/design-apptainer.md`.

**Pinned by an executable test: YES**, for the invariant and the direction
rather than for the numbers —
`memtable.TestFlushBatchBoundariesLimitWhatCanBeDeduped` asserts that a
session inside the ring cuts EVERY chunk on content, which is what the
whole cross-generation claim rests on, and that a session overflowing it
has not collapsed to zero. The two rows above need production chunker
parameters and a quarter of a gigabyte, so they are recorded here rather
than asserted; the apptainer harness reproduces the first one on every run.

### KL-11. A background `pelfs mount` registers machine-globally even under `--state-dir`

`--state-dir` now covers everything a **foreground** session creates —
`pelfs shell`, `pelfs mount-gen`, `pelfs browse` create nothing outside the
root their own flags select, including the mount record that used to be
derived from `$XDG_STATE_HOME/pelfs` regardless of the flag. **`pelfs
mount` is the deliberate exception**, because it detaches: its whole
contract is that a shell finds it afterwards by prefix — `pelfs status`,
`pelfs umount <prefix>`, `pelfs ctl <prefix> publish`, the sequence
`scripts/mount-gate-test.sh` runs — and a reader cannot be told about a
`--state-dir` it never saw. A live background mount that cannot be stopped
by name is a worse bug than the one being fixed, so that one record stays
in the machine-wide registry, like a pid file.

What was fixed for it instead: **the registry no longer accumulates.** The
retraction at exit removes the `vol-<id>` directory as well as the record
when nothing else is in it, so a session that comes and goes leaves the
state root exactly as it found it. Directories that already hold a volume's
state are untouched — the removal only succeeds on an empty one.

**Pinned by an executable test: YES.**
`TestABackgroundMountRegistersMachineGlobally`
(`cmd/pelfs/statedir_test.go`) asserts the exception itself — the record IS
found by prefix in the default root, with no flag — so **changing it is a
decision rather than an accident**, and the foreground half is pinned by a
walk of two directory trees that fails on any path created outside
`--state-dir`.

### KL-12. The WebDAV adapter hides symlinked DIRECTORIES

A symlink to a regular file is followed over `/dav/`, so `lib.so ->
lib.so.1` is the file it names. A symlink to a **directory** is hidden from
listings and counted, which is narrower than `docs/design-windows.md`'s
"follow within the volume".

**Mechanism, and why hiding is the honest answer.** Path resolution in
`internal/vfsbilly` is component-by-component and does not traverse a
symlinked directory component — `resolveDir` requires every component to
BE a directory. So a followed directory link would appear in a listing as a
collection whose own PROPFIND then failed: a folder a client can see,
cannot open, and gets an error from. Hiding it is a smaller lie than that,
and it is counted rather than swallowed (`vfsdav.Counts.DirectorySymlinks`),
so a caller can say how many. Dangling links, FIFOs, sockets and device
nodes are hidden and counted for the same reason: no client could render
them.

Not fixed because the fix is component-wise link resolution in
`internal/vfsbilly`, which is a change to the layer every frontend shares
rather than to this adapter. Neither can escape the volume in the meantime:
an absolute link target is resolved against the VOLUME root
(`vfsbilly.resolveFollow`), so there is no host path to reach.

**Pinned by an executable test: YES**, for the policy and the counting
(`internal/vfsdav/vfsdav_test.go`), which means the test **fails loudly if
directory links are ever followed** — telling whoever implemented the
resolution to delete this entry.

### KL-13. A property set over WebDAV does not outlive the process

PROPPATCH works — it has to, or `litmus`'s `props` suite collapses and
every client that writes a scratch property gets a 403 — but the dead-
property store is **in memory** (`internal/vfsdav/props.go`), so anything a
client sets is gone when `pelfs browse` exits.

Deliberate, for two reasons. A client's scratch properties (Cyberduck's,
Finder's, litmus's) are worth exactly as long as the connection, and
writing each one into the overlay would put them in a published generation
forever. And the properties that *should* be durable are not dead
properties at all: `Win32LastModifiedTime` and the `Win32FileAttributes`
read-only bit are translations onto `vfsbilly.Chtimes` and `.Chmod`, which
is `docs/design-windows.md` D6's surviving half and a separate work item.
The consequence of that item still being open is that **mtime is not
preserved across a WebDAV upload** (no `X-OC-Mtime` either).

Keys are paths, so the store follows a rename and is dropped on a delete —
an entry left behind under an old name would reappear on a file created
there later, which is the one way an in-memory store can lie about the
volume rather than merely forget.

**Pinned by an executable test: YES** for the rename-follows and
delete-drops behaviour (`internal/vfsdav`); the non-durability is a
property of where the map lives and has nothing to assert.

### KL-14. Under `--test-hooks`, the synthetic download source shadows the real one

A `pelfs browse --test-hooks` session cannot mint a working download ticket
for a real file in the volume: the synthetic source is registered **ahead
of** the volume's (`browseServer.downloadSource`).

This is the fix, not the bug, and it is recorded here so that nobody
"corrects" it by reordering. A browser-driver run passes `--test-hooks`
precisely to reach states the volume is not in, and a driver that had to
create a file before it could exercise the ticket round trip would be
testing the **upload** path instead of the ticket. Reordering reintroduces
exactly that coupling.

The blast radius is zero for users: the flag's own help text is
`NEVER on a real volume: it lets the page be driven into states the volume
is not in`, it is off in every real session, and the end-to-end gate
(`make browse-gate`) runs **without** it, against the shipped binary, so
the real source is what is actually proven.

**Pinned by an executable test: YES** — the browser harness depends on the
ordering, so a reorder fails it. What is NOT pinned is the reason, which is
why it is written down here.

### KL-15. An upload that dies is discarded rather than resumable, on every surface

Filed at `b16784d` with the v0.2.1 release pass.

There is no resumable upload anywhere: not in the JSON data plane, and not
over WebDAV. `internal/webapi` takes one whole-file `POST`, so a dropped
connection at 90% of a 68 MB file starts over, and nothing can render a
progress bar until the request finishes.

What IS designed, and is the half worth having, is that a dead upload does
not leave a lie behind. Bytes land under `<name>.pelfs-part`
(`webapi.PartSuffix`, `internal/webapi/webapi.go:119`) and the final name
appears only on a completed rename, with the temp file unlinked on failure
(`internal/webapi/upload.go:265`, `:298`). Since bytes are in the overlay
the moment they are written, a truncated upload under its FINAL name is
what the next checkpoint would publish — so the part-then-rename discipline
is durability rather than tidiness.

Not fixed because a resume needs a range-addressable server-side handle
that outlives an HTTP request, which the single-writer overlay does not
offer today. **Note that the CHANGELOG's claim that the WebDAV surface
shares the `.pelfs-part` convention is aspirational** —
`internal/vfsdav` implements no temp-then-rename at all, and a WebDAV
client's own partial-file convention is what plays that role there.

**Pinned by an executable test: PARTLY.** The part-then-rename discipline
and the shared durability vocabulary are pinned
(`internal/webapi/upload_test.go`, `internal/webui/durability_test.go`).
The absence of resume is pinned by nothing, being an absence.

**Updated at `7bcce06` (uitext-agent):** the browse UI used to state this in
its status line on every screen and no longer does — see KL-19 for the
instruction and for the two sibling limits that left the chrome with it.

### KL-16. An NFS mount commits once per small file created, whether or not anything called `fsync`

Filed at `b16784d` with the v0.2.1 release pass.

`fsync` over NFS now reaches the filesystem (the fork's `nfs.Committer`,
implemented by `internal/vfsbilly` over `overlay.FS.Sync`), and the cost
came with the capability. A Linux client sends a small file's whole body as
a FILE_SYNC write to save itself a COMMIT round trip, and RFC 1813 makes
that a durability requirement, so the server commits inline once per file
created — in a workload that never calls `fsync` at all. That is what an
NFS server costs, and the kernel's own server does the same.

**The number, and its provenance, because this is the figure that decides
whether someone should pick the NFS backend:** copying 500 small files,
392 ms before against 1239 ms after with the state directory on a real
disk, and 332 ms against 246 ms on tmpfs. Those are **single hand-run
measurements on the owner's machine, and no harness in this tree reproduces
them** — every containerized gate keeps its scratch on tmpfs, where
`fsync` is nearly free, which is exactly why CI shows the change as a wash.
Trust the direction, which is structural, over the digits.

Not "fixed" because the alternative is replying UNSTABLE and lying about
durability, which is the defect this replaced.

**Pinned by an executable test: NO** for the cost — it is a measurement on
real storage that a tmpfs runner cannot see, and building a gate for it
would mean asserting a wall-clock ratio. The BEHAVIOUR is pinned:
`internal/vfsbilly/commit_test.go`,
`internal/nfsmount/diag_internal_test.go`, the fork's own
`nfs_oncommit_test.go`, and `commit_gate` in
`scripts/mount-gate-test.sh`, which asserts against a real kernel NFS
client that a COMMIT is SENT.

### KL-18. A predictable browse port can be squatted before pelfs starts

Filed at `c01d35c` by oauthfix-agent, with the stable-port change, and
recorded because the change is what makes it stateable rather than because
it is new.

The port is now PUBLISHED — `pelfs browse` takes the first free port at or
above 8443 — so any local process can bind it first without computing
anything. A user's saved bookmark would then reach the squatter instead of
pelfs.

**Updated at the probe (browseback-agent):** this used to say "derived from
the volume, so any local process can compute it". The change from
*computable* to *published* is a change in degree and not in kind, and the
paragraph below was written for the computable case and applies unaltered.

**Why this is accepted rather than fixed.** It is not a new capability: a
process running as the user can already read the volume, the state
directory and the federation tokens, so it does not need to impersonate a
listener to do anything the listener could do. And pelfs does not
cooperate quietly — the bind fails, `browseListen` reports it, and the
session says on the terminal that it is on a different port and that a
saved bookmark will not match. The whole of `docs/design-webui.md`'s
threat model already refuses to rely on the port being unguessable ("a
random port is not a secret … nothing in this design may rely on it"), and
that claim was audited control by control — first for a derived port and
again for a well-known one; see the "A WELL-KNOWN port is not a weaker
port" note there.

**Pinned by an executable test: PARTLY.** That a taken port is stepped over
rather than silently bound, and that an exhausted window falls back and
says so, are pinned (`cmd/pelfs/browseport_test.go`'s `stepsOverWhatIsTaken`
and `fallsBackToTheKernelWhenTheWholeWindowIsGone`). The squat itself is
not a behaviour to assert.

### KL-20. A `pelfs browse` port no longer identifies a volume, so a profile is only good while its volume keeps its port

Filed with the 8443 probe (browseback-agent).

`pelfs browse` takes the first free port at or above 8443, so two volumes
land on 8443 and 8444 **in whatever order they happened to start**. The
port a bookmark names is therefore not a promise about which volume answers
it, and it used to be: the port before this was a hash of the volume's
prefix URL, so one volume meant one port for as long as the salt held.

**What does NOT happen** is the outcome that would matter — a bookmark
quietly opening another volume's files. The profile's `Vendor` is keyed on
the volume (`davprofile.VolumeTag`), not on the port, so volume A's
bookmark keeps resolving to volume A's profile and keeps presenting volume
A's `client_id`. That names no client in a session serving volume B, so
`/oauth/authorize` refuses — and the refusal page NAMES THE VOLUME THAT
LISTENER IS SERVING, because "you have reached the wrong session" and "your
profile is corrupt" are otherwise the same page.

**What does happen, and is the accepted cost:** a profile whose volume did
not get its usual port has to be downloaded again, because the profile
carries `Default Port` and both OAuth URLs. The user is told: the session
says on the terminal which port it got and, when it is not 8443, that a
profile from an earlier session will not reach it.

**Why accepted.** The alternative is the hash this replaced, and the owner
asked for the probe by name: "I asked you to preferentially bind to a known
port, such as 8443 … try probing starting at 8443 and going up." A port a
human can predict and type is worth more than a port that never moves, and
the cost of the move is one download rather than a wrong answer.

**Pinned by an executable test: YES.** That the `Vendor` is keyed on the
volume and not the port (`internal/davprofile/davprofile_test.go`, "the
Vendor is the volume, not the port") and that another volume's client is
refused by a page naming this session's volume
(`internal/localoauth/localoauth_test.go`,
`TestABookmarkFromAnotherVolumeIsRefusedByName`).

### KL-19. `pelfs browse`'s search covers loaded rows only, and the page no longer says so

Filed at `7bcce06` by uitext-agent, and filed HERE because it was deleted
from the screen.

The file manager's search box is client-side: typing in it fires no request
at all (measured, `internal/webui/testdata/svar-contract/recording.json`,
step `search`) and the store filters the rows that tab has already loaded.
A listing is also capped, because the component does not virtualize
(100,000 entries produced 703 MB of heap). So **"no results" in that box
means "not in what this tab has loaded", not "not in your volume"** — for a
whole-volume search, use `pelfs mount`, a WebDAV client, or a narrower
path.

Two other limits of the same shape belong with it, since they were all in
ambient chrome and are all now off it: **an upload is whole-file** (KL-15
has the detail — a dropped connection restarts it and nothing can draw a
progress bar until the request finishes), and **a capped folder shows the
first N entries**. The pane still prints the count when it differs
(`showing 5,000 of 6,000`), because that is a fact about the user's data
rather than a caveat about ours.

**Why the UI does not state them.** The owner asked twice, in writing, for
both standing caveats off the page: *"'whole-file upload only: a dropped
connection restarts it, and there is no progress bar…' which is the exact
over-explaining crap I asked you to remove. NOTHING is valuable there for
an inexperienced user"*, and *"SAME PROBLEM WITH SEARCH ('search covers
loaded rows'). I ASKED YOU TO DO THAT LAST ROUND."* The earlier passes had
each answered the complaint by making the sentence smaller and hiding it
behind a disclosure, which is relocation rather than deletion. This entry
is where the facts live instead. `webapi.PartialSearchNotice` still carries
the search one on the wire (`GET /api/v1/info/{id}`), so a different client
may render it; nothing in this repository has to.

Where a limit actually bites, the user is still told AT THAT MOMENT — a
failed upload reports its failure, and the app's own `UploadNotice` says
what a *finished* upload does and does not mean. That is the distinction
being drawn: an event, not ambient chrome.

**Pinned by an executable test: PARTLY.** That the search is client-side is
pinned by the recording (`internal/webui/contract_test.go` replays it, and
a search step that grew a request would fail it). That the caveats stay OFF
the screen is pinned by `webui/frontend/tests/chrome.spec.ts` ("no legend,
no search caveat, no upload caveat -- the chrome states nothing"), which
counts them at zero. The partial-search behaviour itself is an absence and
is pinned by nothing.

### KL-21. The seal's carry-forward check trusts the index's 12-byte key

Filed at `a212428` by renameseal-agent, as the stated cost of removing the
whole-generation trailer sweep from `genfs.ContentOf` (see KI-8).

An `mpi` entry keys on 12 bytes of identity, not 32, on the reasoning
written at `internal/mpi/mpi.go:15`: *"a truncated key can only produce a
FALSE POSITIVE: the caller holds the full identity and checks what it
finds"*. Every other consumer does check — `probeHints` fetches the named
pack's trailer and confirms the full 32 bytes before it returns a location.
`packIndex.hintsName`, which answers the PRESENCE question for the seal's
carry-forward check, does not: it stops at the pack's name, because
fetching the trailer is exactly the per-pack cost being removed.

**Consequence.** A 96-bit prefix collision reads as "present in a listed
pack" for a chunk that is not there, and the seal carries the record
forward into a signed generation. It is only reachable when the real chunk
is genuinely missing — if the identity is stored, the answer was right by
whatever route — so it needs a damaged volume AND a ~10^-13 event. The
damage surfaces on read, where the chunk is verified against its identity,
which is where a missing chunk surfaces in any case.

**What is NOT affected: a swept pack.** That is settled by the SIGNED pack
list rather than by the key — `hintsName` ignores any name the generation
no longer lists, and an identity with no listed name falls through to the
whole-generation sweep, which is still the only thing entitled to say
"present in no listed pack".

**The exact alternative was measured and refused.** Confirming through the
trailer costs one request per pack the reused content touches, which for a
volume of a few large files under one catalog is every pack in the volume —
the defect this replaced, on every seal. A check whose price is the volume
does not stay switched on. Making it both exact and cheap means a wider
key, which is a format change to `mpi` (16 bytes/entry is 1.6 GB at 100M
objects; 20 would be 2.0), or spilling confirmed trailers to a local
`packidx` table — the same step KI-8 wants for `Prefetch`.

**Pinned by an executable test: the half that matters, yes.**
`TestContentOfStillReportsASweptPackAsAbsent`
(`internal/genfs/contentofcost_test.go`) drops a pack from the list while
leaving the index naming it and requires "present in no listed pack"; it
fails if the pack-list guard is removed. The collision itself is not
pinned and cannot practically be — constructing a 96-bit BLAKE3 prefix
collision is the test.

### KL-22. One SQLite connection serves both halves of the content journal, so a slow `Located` transaction stalls every writer

Filed at `e0fad28` by flakehunt-agent, alongside the promotion-trigger fix
in `internal/memtable/store.go` (which shrank the exposure by two orders of
magnitude but did not remove it). **Re-verified against `63d0f4c`**, which
changes nothing here: `internal/overlay/journal.go` is untouched by it.

`overlay.contentJournal` opens its database with `db.SetMaxOpenConns(1)`
(`internal/overlay/journal.go:96`), which is what makes its statements safe
to share. `Append` and `Adopted` are called by the writer WITH the store's
mutex held; `Located` is called by a flusher WITHOUT it, and — since the
ring began holding a batch until its location record was durable — two
flushers can be inside `Located` at once. All of them queue on the one
connection.

**Consequence.** A `Located` transaction that is slow for any reason — a
cold WAL, a contended disk, a busy timeout — is a transaction the next
`Write` waits behind while HOLDING `Store.mu`, so the stall is not confined
to the flusher: every reader and writer of the store is behind it. It is a
latency spike and never a wrong answer.

**Why it is smaller than it was.** The promotion trigger used to start a
pack run on nearly every write whenever the tail lagged, so a slow uplink
produced hundreds of `Located` transactions where it should produce a
handful (measured: 271 against 2 over 6 MiB). With the trigger measuring
aged-and-unclaimed bytes instead of ring occupancy, the number of these
transactions is a function of bytes written, which is what the design
always claimed.

**Not attempted here.** The fix is either a second connection for the
flusher's writes (SQLite serialises writers anyway, so this moves the wait
off `Store.mu` rather than removing it) or making `Located` asynchronous
with respect to the writer entirely. Both are write-path design decisions
rather than defect repairs.

**Pinned by an executable test: no.** The contract it violates is now
written down — `memtable.Journal.Located` says out loud that it is called
off the store's lock and may be called concurrently — but nothing exercises
a slow journal against a writer.

### KL-23. Go's fuzzing engine can report its own fuzztime expiry as the test failure `context deadline exceeded`

Filed at `47668cc` by opfuzzdl-agent, from the red `opfuzz` job on PR #7
(run 33276653875). It is a bug in the Go toolchain, not in pelfs, and it is
open upstream: **golang/go#72104** and **#72088**, both `NeedsInvestigation`,
both watchflakes reports of Go's own `cmd/go` fuzz tests failing this way on
Go's builders. Reproduced here against `go1.26.0`.

**What it looks like.** The whole failure, with no crasher, no
`Failing input written to`, no minimisation, and a steady exec rate right up
to the boundary:

```
fuzz: elapsed: 2m0s, execs: 102621 (867/sec)
--- FAIL: FuzzOps (120.12s)
    context deadline exceeded
FAIL
```

**The mechanism, end to end.** `-test.fuzztime <duration>` becomes
`CoordinateFuzzingOpts.Timeout`, and `internal/fuzz/fuzz.go:105-109` turns
it into `ctx, cancel = context.WithTimeout(ctx, opts.Timeout)`. The workers
are cancelled through a CHILD of that context, `fuzzCtx` (`fuzz.go:112`).
When the budget expires the coordinator's main loop takes
`case <-doneC: stop(ctx.Err())` (`fuzz.go:228`), and `stop` is supposed to
recognise that error as its own normal termination and drop it
(`fuzz.go:129`):

```go
if err == fuzzCtx.Err() || isInterruptError(err) { err = nil }
```

That test races. `context.cancelCtx.cancel` publishes the PARENT's error and
closes the parent's done channel (`context.go:561-568`) **before** it walks
`c.children` to cancel `fuzzCtx` (`context.go:569-572`). A coordinator
goroutine woken by that close and scheduled before the children loop runs
observes `fuzzCtx.Err() == nil`, the suppression misses, `fuzzErr` is set to
`context.DeadlineExceeded`, and it is what `CoordinateFuzzing` returns at
`fuzz.go:235`. `testdeps` has a second suppression
(`deps.go:172: if err == ctx.Err()`) but it tests the PARENT context, whose
error is `Canceled` on ^C and never `DeadlineExceeded`, so a deadline is the
one termination with a single racy guard. `testing/fuzz.go:368-371` then
calls `f.Fail()` and prints the error verbatim.

**Why CI and not the laptop.** The window is real but narrow, and it widens
with CPU contention — the coordinator plus one worker process per core, on
four vCPUs. Measured as the rate at which `ctx.Err() == fuzzCtx.Err()` is
false at the instant the parent's done channel closes:

| where | per deadline |
|---|---|
| host, idle, GOMAXPROCS=12 | 0.010% - 0.020% |
| container, `--cpus 4`, GOMAXPROCS=4, idle | 0.040% |
| container, `--cpus 4`, GOMAXPROCS=4, 5 competing processes (the CI shape) | **0.275%** |

**What it is NOT.** Not KL-22, and not a slow machine: the failing run's
exec rate (867/sec) is indistinguishable from the passing runs either side
of it (860, 969, 989/sec), so nothing stalled — it lost a coin flip that
this runner tosses on every fuzz job. Not PR #7 either; nothing in that
branch is reachable from the overlay ops, and the mechanism is entirely in
the toolchain.

**What was done about it.** The `opfuzz` job budgets EXECUTIONS
(`120000x`), not seconds. `Nx` sets `CoordinateFuzzingOpts.Limit` and leaves
`Timeout` at 0, so `fuzz.go:105-109` never creates the deadline context and
the racy suppression is never reached; the limit path exits through
`stop(nil)`. This is not a smaller gate — 120000 is above every measured CI
run (102621, 103913, 116178, 118047 execs in the 120s the job used to ask
for) and lands in the same 2-2.5 minutes. The engine's wall clock was also
the only bound on a HUNG fuzz target, so the launcher now passes
`-test.timeout 15m` (`PELFS_OPFUZZ_HARDTIMEOUT`), which dumps every
goroutine instead of letting the job's 20-minute cap kill it blind.

**Reproduced on demand, on nothing but a squeezed container.** The overlay
below is only a magnifier; the failure comes out of the unmodified
toolchain and the unmodified launcher once the container is made to look
like the runner — `PELFS_OPFUZZ_CPUS=2 PELFS_OPFUZZ_GOMAXPROCS=4
scripts/opfuzz-docker.sh 1s FuzzOps`, three such loops at once so they
contend. **2 failures in ~386 runs (0.5%)**, each printing the job's text
verbatim at the job's exec rate:

```
fuzz: elapsed: 1s, execs: 953 (889/sec)
--- FAIL: FuzzOps (1.09s)
    context deadline exceeded
FAIL
```

The budget's LENGTH is irrelevant — the race is one coin toss per run, at
the boundary — so a 1s budget buys the same event as the job's 120s one,
hundreds of times an hour instead of once. That is also why "run it again"
is not a diagnosis: nothing about the run before the boundary differs.

**Pinned by an executable test: no, and it cannot be from here** — the
racing code is the toolchain's. What is pinned is the shape of the
reproduction, which is exact: build the fuzz binary against a stdlib overlay
that sleeps 2ms between `close(d)` and the children loop in
`cancelCtx.cancel`, and a duration budget fails with the CI text every time
(2/2) while a count budget passes under the identical build (3/3). Revisit
if Go closes #72104: a duration budget is the more natural knob.

**Second-order, noticed while reading the launcher and left alone.** The
container has no repo mount, so a crasher is written to
`/scratch/testdata/fuzz/FuzzOps` on a tmpfs that dies with the container.
When this gate does find something, the message survives in the job log and
the reproducing INPUT does not.

---

## `CHANGELOG.md` v0.1.0 *Known limitations*: status on main

Those entries are RELEASE-scoped and stay where they are — the *Known
limitations* block under `## v0.1.0 — first release` in `CHANGELOG.md`
describes what v0.1.0 shipped and must not be rewritten. (Cited by heading
rather than by line: this table has already once pointed at the wrong
range.) But a reader who arrives from the release notes should not be
misled about **main**, so:

| v0.1.0 limitation | on main (`b16784d`) |
|---|---|
| Reclamation is manual; a repack then a sweep frees nothing | **fixed** — a writable mount repacks AND collects itself (`--no-auto-gc`); `Summary.Maintenance` reports both halves. A volume nobody mounts writably is still never maintained (see KI-5). |
| Grace window 72h, not configurable | **fixed** — `pelfs init --grace`, carried forward by every seal, read by the sweep, the planner and all three ledgers, with a one-hour floor at CREATION (`superblock.MinTGrace`, enforced in `cmd/pelfs/volume.go:215`; `pelfs gc --grace` has no floor because it can only widen). See KL-4 for what a large window really buys. |
| Retain window only as good as the superblock backups | **unchanged and still true**; reported and warned about, never silently assumed. |
| A repack cannot retire index or manifest objects | **fixed** — under 50% live pack coverage a repack drops the segment, re-emits the entries it still answers for, and condemns the old object through the existing ledger. |
| Single writer per VOLUME rather than per branch | **fixed** — the key is `meta/lease-<branch>.json` (`internal/lease/lease.go:119`); `TestBranchesDoNotShareAWriteLease` (`cmd/pelfs/branch_test.go:698`) asserts the inverse of what v0.1.0 pinned. The legacy object is still READ, never written: see KL-5. |
| Two diverged branches stay diverged; no merge | **fixed for branches cut with a lineage** — `pelfs merge`, report-first, three-way over the catalogs, reads no file content. A pair of v0.1.0 branches has no fork record and no inode lineage, and those still cannot be merged: see KL-7. |
| The retain window over-retains on a multi-branch volume (no branch attribution) | **fixed** — a superblock records the ref it was sealed onto, so `(branch, generation)` is an identity; generations below a fork point and anything sealed by v0.1.0 keep the old conservative rule and the sweep says which it used. Residue: KL-3. |
| No key rotation; `pelfs rescue` specified and not built | **both fixed** — `pelfs rotate` (two generations per branch, announce-then-apply, resumable) and `pelfs rescue` (rebuilds refs from the packs, verifies every scavenged backup, never deletes). New consequence: KL-1. |
| The origin must permit GET/PUT/DELETE and listing | unchanged, checked up front. |

(This section previously carried a note about a stale `access(2)` /
`tar -p` claim in the CHANGELOG's *Unreleased* block. That block became
`## v0.2.0` and the claim was rewritten to what the code does; there is
nothing left to flag. `docs/go-nfs-patches.md` has the fork-side detail.)

---

## Audited and deliberately NOT carried here

Checked against `25100f3` and found already fixed or stale, and re-checked
at `0c2baf0`, and again at `b16784d` — three of the rows below were fixed by commits that did not
exist at `25100f3`, and the commit is named in each. Recorded so the next
pass does not re-file them.

| item (`docs/TODO.md`) | verdict |
|---|---|
| **E5.** "local v0.1.0 is annotated at a64a15e, unpushed, already stale" | **STALE.** The retag happened: `v0.1.0` is annotated `b409546` over commit `e68a538` both locally and at `origin`, and the GitHub release published 2026-08-21. |
| **G7**, first half: "README reclamation section stale (repack now exists)" | **FIXED.** `README.md:372-389` documents auto-repack, auto-gc, both windows, and the reporting. The second half — `pelfs ctl pprof` undocumented in the README, though it exists at `cmd/pelfs/ctl.go:42` — is a doc punchlist item and stays in `docs/TODO.md`. |
| **"VOLUME-WIDE WRITE LEASE — NOT FIXED, DOCUMENTED"** | **FIXED** by the lease key-space change; see the table above and KL-5. `TestBranchesShareOneWriteLease` no longer exists; its inverse does. |
| **"the half that is still open"** (go.mod fork pin, honest ACCESS) | **FIXED** by access-agent. `13c0560` is a commit in the **go-nfs fork**, not in this repo, and it is now HISTORICAL: the pin has since advanced past it for the `fsync` work, so at `b16784d` `go.mod:144` pins `github.com/bbockelm/go-nfs v0.0.5-0.20260823220622-d92cb75455ad`. It still exports `nfs.PermissionChecker` (asserted at `internal/vfsbilly/vfsbilly.go:100`) and now also `nfs.Committer`. |
| **readopt: "A SECOND WRITABLE SESSION REFUSES TO START"** | **FIXED** by readopt-agent (two bugs in one sentence); the corpus entry `second-session-refuses-after-adopt.plan` is now a passing regression with its marker removed. |
| **"SHAKEN LOOSE BY THE RAISED-OP RUNS"** — hostile phase E dies with `memtable: re-adopt inode N: genfs: stale inode (no residency)` | **FIXED** by the same readopt work: it is the same refusal, and phase E now starts on an adopted plan. |
| **NFS frontend enforces no permission checks** (hostile finding) | **FIXED** by modebits-agent + access-agent. `nfs-ignores-mode-bits.plan` carries no marker and now FAILS if the write is ever accepted again. |
| **nlink not decremented for a clean hardlinked file** | **FIXED** by nlink-agent (a third option, neither of the two the report proposed). |
| **rename ghost across a checkpoint** | **FIXED** by renameghost-agent, with the whole sibling family (unlink, one of two hardlinks, rmdir, rename onto a name, cross-parent rename, recreate-over-whiteout). |
| **`link(2)` of a clean inode after a checkpoint** (was KI-1) | **FIXED** by prov-agent (`e614330`; doc follow-up `9e2273d`): `genfs.FS.Edge` (`internal/genfs/genfs.go:569`) plus a fallback in `persistChainLocked` (`internal/overlay/overlay.go:645`), pinned by `internal/overlay/linkprov_test.go` (five cases). The reachable shape is NOT "a file sitting still" as first reported — `rawfuse`'s dirty mark is sticky for a mount's lifetime, so within one session the sweep's victims carry a 1s TTL and the dentry expires. It is a SECOND session over an inherited file: mount, look up a file that was already there, edit it, keep working, then link it. Two corpus entries were built for it and NEITHER reproduced, so none was kept — this entry's own prediction that a plan would be `flaky-open` at best was right, and stronger than it knew. |
| **Crash-stranded scratch is never swept** (was KI-2) | **FIXED** by spool-agent (`a7d336a`): `internal/scratch` names every scratch directory for the process that made it (`publish-<pid>-*`, `snapshot-<pid>-*`, `repack-<pid>-*`) and `sweepStateScratch` (`cmd/pelfs/mountgen.go`) collects, at every mount, the ones whose owner is no longer running — reporting the bytes and the names it took. A repack's spool is now a per-run subdirectory removed on **every** exit from `Execute`, so the happy path no longer strands one either. Pinned by `internal/scratch/scratch_test.go` (ten cases, including a live sibling's spool being left alone), `cmd/pelfs/scratchsweep_test.go`, `internal/repack/spool_test.go`, and phase 4b of `scripts/crash-recovery-docker.sh`. The discipline is pid liveness with a 24h guard for unowned names and a 7d backstop against pid reuse; why liveness rather than the lease is argued at the top of `internal/scratch/scratch.go`. |
| **The dedup sidecar after a repack** (was KI-3) | **FIXED** by spool-agent (`a7d336a`), both halves in one operation: `publish.RestampDedupIndex`, called from `repack.execute` after the flip, rewrites the sidecar with exactly the rows the sweep's reachable set still reaches and stamps it with the generation the repack published. Filtering without restamping would be a file nobody reads; restamping without filtering would promise chunks the repack has just dropped — which is why they are one function and not two. Pinned by `TestASealAfterARepackStillDeduplicates` (`internal/repack/dedup_test.go:67`), which measures the bytes the post-repack seal puts on the wire for a 3 MiB file the generation already stores. Its ASSERTION is a ceiling (`dedup_test.go:174`, under half the file); the observed 4 KiB with the fix against 3.15 MiB without it is a logged number, not a pinned one. |
| **A crash between a flush's publish and its location record loses that batch** (was KL-10) | **FIXED** by durability-agent: `publish` no longer reclaims the ring region a batch came from. It queues the region (`Store.locating`) and `journalLocated` releases it, so until the `Located` record binding handles to packs is durable the ring is still where recovery finds those extents — and a crash in the window loses nothing rather than one flush batch (2 MiB at the shipped pack target). Only a PREFIX is released, because that is all a ring can release: four upload workers finish out of order, so a batch is marked done and the tail advances over however many done batches sit at the front. `Flush` waits for the queue to drain, which is what makes "a flush means recorded" true as well as "a flush means uploaded". Pinned by `memtable.TestACrashBeforeTheLocatedRecordLosesNothing` and `memtable.TestTheRingIsNotReclaimedUntilTheLocatedRecordIsDurable` (`internal/memtable/losswindow_test.go`) — one through `Store.Durable`/`Recover`, one at the ring itself, neither killing anything. The cost was the reason it was deferred and it was MEASURED rather than argued (`memtable.TestMeasureRingHoldBackpressure`, `PELFS_RINGHOLD_MEASURE=1`): holding the ring moves the uplink's cost from the seal into the write phase and leaves end-to-end throughput alone. |
| **`fsync` over NFS makes nothing durable** (was KI-10) | **FIXED** by commit-agent, and NOT where this file said the fix was. The COMMIT no-op was real but unreachable: `onWrite` wrote the constant FILE_SYNC into the stability field of every WRITE reply, and a Linux client queues a page for commit only when the reply said UNSTABLE — so it never sent a COMMIT. Measured before the fix on this repo's own mount-gate container: `dd conv=fsync` produced 2 WRITEs and **0** COMMITs; after, 1 COMMIT. The fork (`d92cb75`, pinned in `go.mod`) now exports `nfs.Committer`, which both `onWrite` and `onCommit` consult; `internal/vfsbilly` implements it with `overlay.FS.Sync`, the same body the FUSE frontend's `Fsync` calls. Pinned by `internal/vfsbilly/commit_test.go` (a commit syncs, a repeat commit is free), `internal/nfsmount/diag_internal_test.go` (the wrapper must not over-claim the interface), the fork's own `nfs_oncommit_test.go`, and `commit_gate` in `scripts/mount-gate-test.sh`, which asserts against a real kernel NFS client that a COMMIT is SENT. |
| **A refused mutation in the file manager resolved to `undefined`, so a failed rename looked successful** (was KI-11) | **FIXED** by mount-app-agent, and the mechanism was not the one this file named. The entry said `PelfsDataProvider` "calls `super.send()`", so upstream's swallowed rejection reached the app: it does not — `send()` is a full override that does its own fetch and REJECTS on `!res.ok`, which was true when the entry was written. What actually kept the lie on the screen is a step further on: the STORE applies every mutation optimistically (`@svar-ui/filemanager-store`'s `rename-file` renames the node and re-parents its children before the provider is reached), and a rejection rolls none of that back — so the banner said "that did not happen" beside a row showing that it had. Of the three options this file offered, the second was taken: `PelfsDataProvider.getHandlers` (`webui/frontend/src/api/provider.ts`) wraps each of the five mutating handlers, and on a rejection RE-LISTS the directories the event touched and hands the answer to the store as `provide-data`, which replaces that directory outright. Deliberately not an inverse operation: undoing a rename in the store means keeping a second model of the volume, and the first case that model gets wrong is a batch whose fourth id failed. No copy of upstream's promise chain, so no re-read on every component upgrade. **Pinned by two executable tests**, which the entry said were the missing thing: `A REFUSED RENAME DOES NOT STAY ON THE SCREEN` and `a refused delete leaves the file where it was` (`webui/frontend/tests/filemanager.spec.ts`), driving a real 403 from a read-only path in the mock volume (`mockEntry.ro`, `internal/webui/mockapi_test.go`) and asserting BOTH halves — that the user is told, with the server's reason, and that the row is back under its original name. |
| **KL-17.** A stable browse port made the BOOKMARK survive a restart; the CREDENTIAL in the generated profile did not, so the profile had to be reinstalled every session | **FIXED** by durableprofile-agent, with the shape KL-17 itself named: the `.cyberduckprofile`'s `OAuth Client ID` is now `HMAC-SHA256(key, label ‖ redirect ‖ write ‖ epoch)` under a 32-byte key in the state directory (`internal/localoauth/identity.go`; `browse-identity.key`, mode 0600, created lazily on the first download), so the generated profile is byte-identical across restarts and the one the user installed keeps working. What the entry did not foresee: a derivation over the tuple ALONE lets a revoked profile come back the moment the user re-adds the same label, so every entry carries a random epoch and `Revoke` destroys it — which is also what makes `Revoke` durable, and why it now returns an error (a revocation that did not reach the disk must not be reported as one). Unchanged on purpose, and said in the code, the docs and the page: no token and no Basic password is persisted, and **consent is still required on every `/authorize`** — the bookmark stops being one-time-use, the click per session does not. **Pinned by executable tests**, which is what the entry said was missing: `internal/localoauth/identity_test.go` (including that the first session's token and password are dead in the second, that a read-only session adopts a writable identity and refuses the SCOPE rather than disowning the client, and that a re-added label is a different client), `cmd/pelfs/browseidentity_test.go` (the page's own JSON across a restart on one port), and `scripts/browse-gate.sh` step 8 — two `pelfs browse` processes in sequence, REAL duck, the profile from the first session neither regenerated nor reinstalled, and its stale refresh token left in place on purpose. |
| **C2**, the "fsck lifts the cap" claim | **STALE** in that detail — `internal/fsck` does not touch `packIndex`. The rest of C2 survives as KI-8. |
| **F11** dead/unwired inventory; **G4**, **G6** doc-staleness sweeps | Real work, but hygiene and prose rather than defects or limitations. They stay in `docs/TODO.md`, which is what a punchlist is for. |
| **`golang.org/x/net` is in `go.mod` as `// indirect`** while `internal/vfsdav` imports `webdav` directly (reported by the WebDAV pass, and predicted to be "promoted by the next `go mod tidy`") | **STALE — the promotion already happened.** `go.mod`'s direct `require` block carries `golang.org/x/net v0.56.0` with **no** `// indirect` marker, at the same version it was pinned at as an indirect. `docs/design-windows.md`'s "The Go half is already compliant" was updated to say so. Nothing to file. |
| **`internal/pelicanobj/fedstore.go`'s doc comment claimed the device flow "refuses to start when stdout is not a TTY"** (found while verifying the SSO hook; filed in `docs/TODO.md` under `webui-agent`) | **FIXED** by `d4c3767`. There is no `IsTerminal` check in pelican's `client/acquire_token.go`; the only gate is `opts.NonInteractive`, which pelfs does not set. The comment now states the correct behaviour **and why the distinction matters** — it is what lets a GUI surface the flow instead of a terminal — rather than merely deleting the wrong sentence. The same commit added `go.work`/`go.work.sum` to `.gitignore`, which `docs/design-webui.md`'s `go.mod` section asked for. |

At `0c2baf0` the hostile corpus holds **no open finding**: all six entries
in `internal/hostile/testdata/corpus/` are marker-free, i.e. each is a
regression that must PASS. That is a good state and worth checking against
whenever this file gains an entry — a bug the corpus can express belongs
there rather than here, because there it fails on its own.

KL-10 was the one entry whose halves came apart like that: the HONESTY
half was expressible in ordinary Go tests (`holerecovery_test.go`) and the
LOSS half was not, because a loss the contract permits has nothing to
assert. It is gone from this file because durability-agent closed the
window rather than documenting it, and closing it made the loss half
expressible too — the assertion is byte-exact recovery, which only exists
once there is something to recover.

Nothing left in this file is expressible as a plan, which is why they
are here:
a memory ceiling reached only at a hundred million objects (KI-8), a
missing stats field (KI-4, KI-5), an error class thrown away (KI-6), a
transaction count (KI-7), and a wall clock in the wrong place (KI-9).

KI-11 was the one entry the corpus could not express for a different
reason — it needed a BROWSER, not a filesystem — and that turned out to be
a statement about the corpus rather than about the bug: the assertion was
perfectly ordinary once it was made in Playwright, where a suite already
existed. The lesson worth keeping is the one in its row below: the entry
named the wrong mechanism (`super.send()`, which the code does not call)
and the right symptom, and a reader who had fixed only what it named would
have changed nothing.

KI-10 was the second entry whose halves came apart the way KL-10's did,
and it is worth one paragraph because the resolution was not the one this
file predicted. It was filed as untestable on the grounds that the
observable difference is what survives a MACHINE crash — true, and still
true. But that was the wrong question to look for a test for. The
falsifiable claim underneath it is on the WIRE: whether the client sends a
COMMIT at all, which `/proc/self/mountstats` answers for free. It did not
(zero, against a real kernel client), because the server was claiming
FILE_SYNC for buffered writes. That is an ordinary assertion, and it is
now `commit_gate` in `scripts/mount-gate-test.sh`.

Both entries that needed a crash or a repack plus a look at the disk
(KI-2, KI-3, now fixed) turned out to be expressible after all, in
ordinary Go tests, once the question was asked in the right units: not
"is the directory gone" but "whose process made it", and not "does the
sidecar exist" but "how many bytes did the next seal upload". The one
entry that looked plan-shaped (KI-1, now fixed) turned out not to be: two
corpus entries were written for it and neither reproduced, because
whether a LOOKUP precedes a LINK is the kernel dcache's call.
