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
open item in `docs/TODO.md`. What was audited and found already fixed is
listed at the bottom, so nobody re-files it.

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
(`internal/stats/stats.go:225-246`, reported by
`pelfs ctl <mount> status`). The **checkpoint** half did not. The seal
block of `Summary` is counters and ids only — `Seals`, `SealedGeneration`,
`SealedChunks`, `SealedCatalogs`, `SealedPacks`, `SealOK`
(`stats.go:186-197`) — with no timestamp anywhere:
`grep -rn 'LastCheckpoint\|last_seal' --include=*.go` is empty repo-wide.
And the failure count is not merely unreported, it is never computed:
`checkpointPeriodically` (`cmd/pelfs/mountgen.go:1877-1993`) keeps a local
`backoff` duration, resets it on success (`:1971`), warns
(`:1976-1979`), and never touches `g.stats`. `SealOK`
(`mountgen.go:2030`) is a boolean about the seal at EXIT.

**Field shape to copy:** `MaintenanceStats`.

**Pinned by an executable test: NO** — and it cannot be, since the fields
do not exist. This is a gap, not a regression risk.

### KI-5. No standing size signal for a volume nobody mounts writably

**Severity: low-medium.** "Do I need a repack?" is answerable only by
paying for a full sweep.

**Mechanism.** No volume pack count and no volume byte total in the stats
file. The nearest fields, `PrefetchPacks` / `PrefetchBytes`
(`internal/stats/stats.go:155-156`), are the right number written from
exactly one place — `runPrefetch`'s recorder, `cmd/pelfs/mountgen.go:1025`
— so a mount without `--prefetch` leaves both zero. `pelfs ctl <mount>
status` (`mountgen.go:2183-2245`) reports neither. Offline it IS answered
twice, both by commands that do real work: `pelfs repack-plan` prints
`packs: <n>, <bytes> (<pct> live)` (`cmd/pelfs/repackplan.go:190`) and
`pelfs fsck` prints a pack count (`cmd/pelfs/fsck.go:94`). Auto-repack
narrowed this for volumes that ARE mounted writably; the volume this item
was written for is the one nobody mounts.

**Pinned by an executable test: NO** (nothing to pin).

### KI-6. Terminal federation errors are neither classed nor logged

**Severity: low-medium, diagnosis.** When a transfer fails permanently, the
class the retry loop just computed is thrown away.

**Mechanism.** `internal/packstore/retry.go:189-194` returns a
non-retryable error with no counter and no log line, on the stated grounds
that logging FAILED there would cry wolf on every legitimate 404 probe —
a good reason not to log, not a reason to discard the class. `retryable`
(`retry.go:216-227`) distinguishes context-end from `isNotExist` from a
`"404"`/`"not found"` substring and returns a bare bool.
`internal/packstore` imports no `stats` at all. The op IS counted
downstream, because the stats wrapper sits inside the retry loop
(`cmd/pelfs/mountgen.go:487`), into per-verb `Errors` plus 20 error samples
(`internal/stats/stats.go:88-104`, `:460-505`) — which is precisely the
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
(`internal/overlay/overlay.go:502-519`). No group commit, no deferred
writeback. `internal/rawfuse/rw.go:301-330` does merge mode/uid/gid/size/
mtime WITHIN one kernel request, but tar's three syscalls arrive as three
requests; `internal/vfsbilly/vfsbilly.go:908-953` calls `SetAttr` once per
operation from `Chmod`/`Chown`/`Lchown`/utimes.

**Reproduce.** `make big-tree`, or `scripts/e2e-docker.sh`'s untar leg,
with a CPU profile from `pelfs ctl <mount> pprof cpu`.

**Pinned by an executable test: NO.** `BenchmarkOverlayCreateWrite`
(`internal/overlay/bench_test.go:69`) exercises a `SetAttr` but asserts no
cost, and nothing fails if the per-attribute transaction count grows.

### KI-8. The location cap is lifted wholesale for two whole-map callers

**Severity: high at the design target, invisible below it.** The C2
burn-down capped the read path's resident location map at 131,072 entries
(~21 MB, measured); two callers still opt out and hold every location —
measured at 169-174 bytes each, so 15.8-16.2 GB at 100M objects.

**Mechanism.** `packIndex.holdEverything`
(`internal/genfs/packindex.go:282-286`) sets `unbounded` one-way and is
called from `packIndex.all` (`:547`). Callers of `all` at HEAD:

- `FS.ContentOf` — `internal/genfs/read.go:155`, protecting the "present in
  no listed pack" verdict at `read.go:177-179`. Reached from the seal walk
  (`internal/overlay/accessors.go:381` → `internal/publish/source.go:305`)
  **and from an ordinary write's copy-up** (`internal/memtable/base.go:71`
  ← `internal/overlay/write.go:528`), so this is reachable without sealing.
- `FS.Prefetch` — `internal/genfs/prefetch.go:110`.
- `FS.LoadPackIndex` (`packindex.go:517`) has no non-test callers.

**The blocker named in the TODO is gone**: the "spill the merged trailers
into a sorted, mmap'd, binary-searchable table" step was built — as
`internal/extsort`, for `internal/fsck` and `internal/reach`
(`internal/fsck/fsck.go:202-224`). It was simply never wired into
`packIndex`. Note also that **fsck is no longer a `holdEverything` caller**
— `internal/fsck` does not reference `packIndex` at all — so both
`docs/TODO.md`'s list and the code comment at `packindex.go:531-534` name
it wrongly.

**Pinned by an executable test: PARTLY.** `TestLocationHeap`
(gated, `PELFS_LOCATION_HEAP=1`) measures per-location heap and pins the
CAP; nothing fails because `ContentOf` and `Prefetch` bypass it.

### KI-9. A repack stamps its condemned-ledger rows from the wall clock

**Severity: low in production, real for testability.** It makes a class of
test impossible to write, which is why it is here rather than in the
punchlist.

**Mechanism.** `internal/repack/execute.go:716` takes `now := time.Now()`
and stamps `CreatedUnixNano` (`:719`), the condemned-ref rows (`:783`),
retired indexes (`:789`, `:824`), `RepackUnixNano` (`:836`) and condemned
packs (`:842`) from it — while the same call path has an injected clock,
`Options.Now` (`internal/repack/repack.go:134`), and uses it for the
ledger-room check two hundred lines earlier (`execute.go:196`). Harmless in
production, where the wall clock IS the right clock.

**Consequence.** A test cannot drive the ledger's clock through a repack.
That is why the mount-level auto-collect test asserts only the windows and
the reporting, and why the end-to-end "condemned, then collected" property
had to be written in the lifecycle interleaving where the world drives its
own clock.

**Pinned by an executable test: NO, and cannot be.** Fixing it means
deciding whether a repack's ledger stamp is inside the injectable clock —
a repack-semantics call.

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
before writing anything (`rotate.go:294-299`); `--break-siblings` gates it.
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
(`superblock.LedgerWindow`) and printed by `pelfs init` when the numbers
collide rather than being prevented.

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
`internal/lease/lease_test.go`'s `TestLiveVolumeLeaseExcludesEveryBranch`,
`TestAnExpiredVolumeLeaseIsNoObstacle`,
`TestStealLeaseDoesNotTouchTheVolumeLease`; the wire compatibility against
CAPTURED v0.1.0 bytes in `internal/superblock/nextpubcompat_test.go`.
Documented in `README.md` *Caveats*.

### KL-6. The NFS frontend does not consult the AUTH_UNIX credential

Every request is evaluated as the server process's own identity. The export
is loopback and single-user, and any local process can dial 127.0.0.1 and
claim any uid, so honoring the credential would make the check look like a
security boundary, which it is not. This is FIDELITY — the same answer
through both frontends — and not access control. Written down in those
words in `docs/go-nfs-patches.md`.

**Pinned by an executable test: YES** for the model it implements
(`internal/vfsbilly/perm_test.go`, plus the `permission_gate` in
`scripts/mount-gate-test.sh` which compares every permission answer over a
real kernel NFS client against the same probe on a local tree). The
credential decision itself is a policy, not a behaviour to assert.

---

## `CHANGELOG.md` v0.1.0 *Known limitations*: status on main

Those entries are RELEASE-scoped and stay where they are —
`CHANGELOG.md:551-610` describes what v0.1.0 shipped and must not be
rewritten. But a reader who arrives from the release notes should not be
misled about **main**, so:

| v0.1.0 limitation | on main (`25100f3`) |
|---|---|
| Reclamation is manual; a repack then a sweep frees nothing | **fixed** — a writable mount repacks AND collects itself (`--no-auto-gc`); `Summary.Maintenance` reports both halves. A volume nobody mounts writably is still never maintained (see KI-5). |
| Grace window 72h, not configurable | **fixed** — `pelfs init --grace`, carried forward by every seal, read by the sweep, the planner and all three ledgers, one-hour floor. See KL-4 for what a large window really buys. |
| Retain window only as good as the superblock backups | **unchanged and still true**; reported and warned about, never silently assumed. |
| A repack cannot retire index or manifest objects | **fixed** — under 50% live pack coverage a repack drops the segment, re-emits the entries it still answers for, and condemns the old object through the existing ledger. |
| Single writer per VOLUME rather than per branch | **fixed** — the key is `meta/lease-<branch>.json` (`internal/lease/lease.go:119`); `TestBranchesDoNotShareAWriteLease` (`cmd/pelfs/branch_test.go:698`) asserts the inverse of what v0.1.0 pinned. The legacy object is still READ, never written: see KL-5. |
| Two diverged branches stay diverged; no merge | **fixed** — `pelfs merge`, report-first, three-way over the catalogs, reads no file content. A v0.1.0 branch has no fork record or inode lineage, so merging one needs its inodes renumbered first, which `pelfs merge` reports. |
| The retain window over-retains on a multi-branch volume (no branch attribution) | **fixed** — a superblock records the ref it was sealed onto, so `(branch, generation)` is an identity; generations below a fork point and anything sealed by v0.1.0 keep the old conservative rule and the sweep says which it used. Residue: KL-3. |
| No key rotation; `pelfs rescue` specified and not built | **both fixed** — `pelfs rotate` (two generations per branch, announce-then-apply, resumable) and `pelfs rescue` (rebuilds refs from the packs, verifies every scavenged backup, never deletes). New consequence: KL-1. |
| The origin must permit GET/PUT/DELETE and listing | unchanged, checked up front. |

The *Unreleased* section carries one **stale** claim of the same kind,
noted here because it is exactly the failure mode this file exists to
prevent: the NFS-permissions entry's "What can still surprise you"
paragraph (`CHANGELOG.md:206-219`) says `access(2)` / `test -w` answer from
an ACCESS RPC that ignores the mode, and that `tar -p` of a read-only file
fails on the write. Both were fixed by the access-agent fork bump
(`13c0560`) — honest ACCESS via `nfs.PermissionChecker` plus the
knfsd-scoped owner override on the data path, gated by `permission_gate` in
`scripts/mount-gate-test.sh`. See `docs/go-nfs-patches.md`.

---

## Audited and deliberately NOT carried here

Checked against `25100f3` and found already fixed or stale. Recorded so the
next pass does not re-file them.

| item (`docs/TODO.md`) | verdict |
|---|---|
| **E5.** "local v0.1.0 is annotated at a64a15e, unpushed, already stale" | **STALE.** The retag happened: `v0.1.0` is annotated `b409546` over commit `e68a538` both locally and at `origin`, and the GitHub release published 2026-08-21. |
| **G7**, first half: "README reclamation section stale (repack now exists)" | **FIXED.** `README.md:367-395` documents auto-repack, auto-gc, both windows, and the reporting. The second half — `pelfs ctl pprof` undocumented in the README, though it exists at `cmd/pelfs/ctl.go:42` — is a doc punchlist item and stays in `docs/TODO.md`. |
| **"VOLUME-WIDE WRITE LEASE — NOT FIXED, DOCUMENTED"** | **FIXED** by the lease key-space change; see the table above and KL-5. `TestBranchesShareOneWriteLease` no longer exists; its inverse does. |
| **"the half that is still open"** (go.mod fork pin, honest ACCESS) | **FIXED** by access-agent (fork `13c0560`, pin moved). |
| **readopt: "A SECOND WRITABLE SESSION REFUSES TO START"** | **FIXED** by readopt-agent (two bugs in one sentence); the corpus entry `second-session-refuses-after-adopt.plan` is now a passing regression with its marker removed. |
| **"SHAKEN LOOSE BY THE RAISED-OP RUNS"** — hostile phase E dies with `memtable: re-adopt inode N: genfs: stale inode (no residency)` | **FIXED** by the same readopt work: it is the same refusal, and phase E now starts on an adopted plan. |
| **NFS frontend enforces no permission checks** (hostile finding) | **FIXED** by modebits-agent + access-agent. `nfs-ignores-mode-bits.plan` carries no marker and now FAILS if the write is ever accepted again. |
| **nlink not decremented for a clean hardlinked file** | **FIXED** by nlink-agent (a third option, neither of the two the report proposed). |
| **rename ghost across a checkpoint** | **FIXED** by renameghost-agent, with the whole sibling family (unlink, one of two hardlinks, rmdir, rename onto a name, cross-parent rename, recreate-over-whiteout). |
| **`link(2)` of a clean inode after a checkpoint** (was KI-1) | **FIXED** by prov-agent (`e614330`): `genfs.FS.Edge` plus a fallback in `persistChainLocked`, pinned by `internal/overlay/linkprov_test.go` (five cases). The reachable shape is NOT "a file sitting still" as first reported — `rawfuse`'s dirty mark is sticky for a mount's lifetime, so within one session the sweep's victims carry a 1s TTL and the dentry expires. It is a SECOND session over an inherited file: mount, look up a file that was already there, edit it, keep working, then link it. Two corpus entries were built for it and NEITHER reproduced, so none was kept — this entry's own prediction that a plan would be `flaky-open` at best was right, and stronger than it knew. |
| **Crash-stranded scratch is never swept** (was KI-2) | **FIXED** by spool-agent: `internal/scratch` names every scratch directory for the process that made it (`publish-<pid>-*`, `snapshot-<pid>-*`, `repack-<pid>-*`) and `sweepStateScratch` (`cmd/pelfs/mountgen.go`) collects, at every mount, the ones whose owner is no longer running — reporting the bytes and the names it took. A repack's spool is now a per-run subdirectory removed on **every** exit from `Execute`, so the happy path no longer strands one either. Pinned by `internal/scratch/scratch_test.go` (nine cases, including a live sibling's spool being left alone), `cmd/pelfs/scratchsweep_test.go`, `internal/repack/spool_test.go`, and phase 4b of `scripts/crash-recovery-docker.sh`. The discipline is pid liveness with a 24h guard for unowned names and a 7d backstop against pid reuse; why liveness rather than the lease is argued at the top of `internal/scratch/scratch.go`. |
| **The dedup sidecar after a repack** (was KI-3) | **FIXED** by spool-agent, both halves in one operation: `publish.RestampDedupIndex`, called from `repack.execute` after the flip, rewrites the sidecar with exactly the rows the sweep's reachable set still reaches and stamps it with the generation the repack published. Filtering without restamping would be a file nobody reads; restamping without filtering would promise chunks the repack has just dropped — which is why they are one function and not two. Pinned by `internal/repack/dedup_test.go`, which measures the bytes the post-repack seal puts on the wire: 4 KiB with the fix, 3.15 MiB without it. |
| **C2**, the "fsck lifts the cap" claim | **STALE** in that detail — `internal/fsck` does not touch `packIndex`. The rest of C2 survives as KI-8. |
| **F11** dead/unwired inventory; **G4**, **G6** doc-staleness sweeps | Real work, but hygiene and prose rather than defects or limitations. They stay in `docs/TODO.md`, which is what a punchlist is for. |

At `25100f3` the hostile corpus holds **no open finding**: all six entries
in `internal/hostile/testdata/corpus/` are marker-free, i.e. each is a
regression that must PASS. That is a good state and worth checking against
whenever this file gains an entry — a bug the corpus can express belongs
there rather than here, because there it fails on its own.

Nothing left in this file is expressible as a plan, which is why they are
here:
a memory ceiling reached only at a hundred million objects (KI-8), a
missing stats field (KI-4, KI-5), an error class thrown away (KI-6), a
transaction count (KI-7), and a wall clock in the wrong place (KI-9).
Both entries that needed a crash or a repack plus a look at the disk
(KI-2, KI-3, now fixed) turned out to be expressible after all, in
ordinary Go tests, once the question was asked in the right units: not
"is the directory gone" but "whose process made it", and not "does the
sidecar exist" but "how many bytes did the next seal upload". The one
entry that looked plan-shaped (KI-1, now fixed) turned out not to be: two
corpus entries were written for it and neither reproduced, because
whether a LOOKUP precedes a LINK is the kernel dcache's call.
