# Changelog

## v0.1.0 — first release

`pelfs` mounts a POSIX filesystem whose data lives in a
[Pelican](https://pelicanplatform.org) federation. Content-addressed packs
and signed, split catalogs are the on-disk format; a generation of the tree
is one immutable, verifiable object graph, and publishing a change is one
atomic ref flip. Everything runs unprivileged and builds with
`CGO_ENABLED=0`.

This is a **first release of a prototype**. It is used against real
federations and it does not lose data on the paths that are tested, but the
maintenance story is incomplete in one way that matters — see *Known
limitations*.

### What it does

- **Mount**, read-only or read-write, over FUSE or over a loopback NFS
  server. The NFS backend is what a macOS box without macFUSE gets, and it
  is the path the project is developed on.
- **`pelfs shell`** for a subshell on a temporary mountpoint that seals on
  exit; **`pelfs mount`** for a background daemon with per-prefix local
  state; **`pelfs status`**, **`pelfs umount`**, **`pelfs ctl`**.
- **Pack as you go.** A writable mount chunks, packs, encrypts and uploads
  during the session rather than at the seal, from an mmap'd ring buffer
  with promotion by age (`internal/memtable`, `docs/design-writepath.md`).
  Periodic checkpoints publish a generation without unmounting.
- **Encryption at rest.** Pack entries are zstd-compressed (unless that
  grows them) and AES-256-GCM sealed under a volume key wrapped by a PEM
  private key you supply.
- **Maintenance.** `pelfs fsck [--deep]` verifies a generation end to end;
  `pelfs gc [--delete]` sweeps packs, multi-pack indexes and manifests no
  retained generation references; `pelfs repack-plan` reports what a repack
  would rewrite and what it would cost, and `pelfs repack --apply` carries
  it out — rewriting the packs that are mostly garbage into new ones and
  publishing a generation that condemns the old ones, after which `gc
  --delete` can reclaim them.
- **Retention that keeps the last K generations.** The sweep's root set is
  every branch head, the last `Params.RetainK` generations behind each head
  (8 by default, stated in the superblock), and every tag — so a reader
  still holding a recently retired generation keeps everything it names,
  not just whatever the grace window happens to cover. A retired generation
  has no address, so the sweep reads the disaster-recovery superblock a
  seal buries in its last pack; a generation it cannot establish is
  reported and warned about, and a read it cannot complete fails the sweep
  closed rather than guessing.
- **`pelfs tag`, and `pelfs tag --rm`.** Freeze a branch head under a name,
  list what is pinned, and release a pin. Tags are immutable, so a name in
  use never silently moves; deleting one takes its generation out of the
  root set and the next sweep reclaims what it was holding.
- **`pelfs branch` — more than one line of history per volume.** Create a
  branch at the current head of `--from` (default `main`) or at a pinned
  generation with `--from-tag`, list them, and delete one. A branch is a
  NAME over a generation: creating one copies the VERIFIED head's bytes
  under a second name, after which the two advance independently, each seal
  reading and flipping its own ref. Creation is create-if-absent — this verb
  never moves a branch, because repointing one out from under a writer would
  strand its next publish and reparent its work. Deleting the last branch is
  refused: every object in a volume is reachable from a ref, so a volume
  with none has no head to mount and no way back from the CLI.
  Every `--branch` flag in the tool finally means something, and every
  "every branch head" in the retention design is now a claim with more than
  one branch behind it. The single-branch assumptions that had gone
  untested are named under *Known limitations* and in the design doc.
- **`pelfs version`**, and `pelfs ctl <prefix> bugreport` for a tarball with
  the build, the stats and every goroutine.
- **Unprivileged by construction.** One static binary, no root, no setup;
  state under `$HOME`. The only thing it needs from the host is the ability
  to open `/dev/fuse`.
- **Automatic repacking.** A writable mount repacks itself once it has been
  idle for a while and the branch has drifted since the last one — `git gc
  --auto`'s shape, where a counter read from the head decides whether to
  pay for a reachability sweep. `--no-auto-repack` turns it off.

### Scale

The format and the maintenance tools are built for volumes of order a
hundred million objects: the pack list moved out of the superblock into a
hash-named manifest, lookups go through a tiered multi-pack index with
16-byte entries, and both `fsck` and the reachability sweep stream over
sorted spill files rather than holding an identity map. Memory for those
passes is a buffer the caller sizes rather than a function of object count.

That is a design target with unit-level evidence, not a claim about a
production volume of that size.

What is checked end to end, on every push, is smaller and exact. CI untars
**62,500 files** — 50,000 distinct plus 12,500 hard links to them,
small-file shaped at ~900 bytes each, ~45 MB of content — through *both*
frontends, real FUSE and a real kernel NFS client, and then: diffs the
whole tree against the source through the live mount, seals it, mounts the
published generation with a state directory that never existed before and
diffs it again, runs `fsck --deep` and `gc`, and publishes a **second
generation** carrying an add, a modify and a delete which is cold-mounted
and diffed once more. The untar's per-chunk rate and the NFS client's RPCs
per created file are bounded rather than merely reported. Separately, a
mount is `kill -9`'d mid-flush after writing 384 MB, remounted, and held
to the recovery contract.

Past that it is manual, and the numbers are nobody's guarantee: the same
gate takes a file count on the command line (`make big-tree` is the 50,000
CI runs), and `PELFS_BIGSEAL=1 PELFS_BIGSEAL_FILES=…` runs the seal-cost
rig over bigger trees. Between the 62,500 files CI proves and the hundred
million the format is built for there is design and unit-level evidence,
and no end-to-end run.

### Known limitations

- **Deleting the reclaimed packs is still manual, and now waits for two
  windows.** A mount repacks on its own, but nothing collects: `pelfs gc
  --delete` is a separate command, it only takes objects older than the
  grace window (72h, not configurable), and — new in this release — it
  keeps whatever the last `Params.RetainK` generations of the branch still
  name. A repack followed straight away by a sweep therefore frees nothing:
  the generations the repack retired are inside the retain window and they
  name the condemned packs. Reclamation happens once the branch has sealed
  K more times, or under `pelfs gc --retain-k 1`, which is the sweep as it
  behaved before the window was enforced. A volume nobody mounts is never
  maintained at all.
- **The retain window is only as good as the superblock backups.** A
  retired generation has no address, so the sweep reconstructs it from the
  disaster-recovery superblock every seal buries in its last pack. Repack
  carries those backups forward, so ordinary maintenance keeps them; a pack
  collected by a sweep from BEFORE this release took its backup with it, so
  the first sweeps on an existing volume may report a short window
  (`retain window: branch main keeps N of 8 generations`). That is reported
  and warned about, never silently assumed — and those generations age out
  of the window within K seals.
- **A repack cannot yet retire index or manifest objects on their own
  account.** Replacing the manifest already drops superseded segments, so
  what is missing is the narrower case of an index whose packs are mostly
  gone: it costs fetch time, never correctness.
- **Single writer, per VOLUME rather than per branch.** The advisory lease
  is detection, not mutual exclusion — the transport has no
  compare-and-swap. A seal that would overwrite another writer's generation
  is refused, so the failure mode is a rejected seal rather than silent
  corruption. `meta/lease.json` is one object for the whole prefix, so two
  writable mounts on DIFFERENT branches of one volume exclude each other
  even though they would never touch the same ref. The refusal names the
  holder; branches share one write lease in v0.1.0, and a per-branch lease
  is a v0.2 change.
- **Two branches that have diverged stay diverged.** There is no merge, and
  none is planned for this release. What exists is branching, tagging and
  deleting.
- **The retain window over-retains on a multi-branch volume, deliberately.**
  A retired generation is described only by the superblock backup its seal
  buried in a pack, and a backup carries a generation NUMBER — which counts
  steps along one lineage, so both children of generation N seal N+1 and
  their backups are indistinguishable. Nothing in the store can attribute
  one to a branch (the lineage chain authenticates a single step). The sweep
  therefore keeps EVERY candidate for a wanted generation number, which
  retains more than one branch strictly needs rather than dropping a
  generation out of the root set. The scan runs to the end of the pack space
  or to its budget on such volumes, instead of stopping at the first
  complete answer; single-branch volumes are unaffected in both respects.
- **No key rotation.** It is a format feature (custody-chain verification)
  with no writer behind it. When one lands, note that the volume key pin is
  volume-wide by design, so rotating on one branch will retire the pin and
  siblings still signed by the old key will fail until republished.
  `pelfs rescue` is specified and not built.
- The origin must permit GET/PUT/DELETE and listing on the prefix; `pelfs`
  checks this up front and names the missing scope.

### What a failure looks like

A seal that cannot reach the federation loses nothing: the overlay is left
intact, the branch does not move, and the next mount of the same prefix
resumes it and seals again. This is tested, including the reopen-from-disk
half.

Anything `fsck` or the reachability sweep cannot read, decode or account for
makes the result *incomplete* rather than partial — every affected pack is
reported fully live, and `repack-plan` refuses to plan at all. A pack
wrongly called dead is data loss; a pack wrongly called live costs bytes
until the next sweep. The tools are not symmetric about those two.

### Verified by

`make test` (unit and CLI, including a model-based random test of the write
path, and under `-race` in CI), `make e2e` (a full mount loop in a
container against a fake origin), `make mount-gate` (the kernel mount
gate: real FUSE and a real NFS client, both required), `make big-tree`
(the 62,500-file scale gate described under *Scale*), `make crash`
(`kill -9` of a mount mid-flush, then recovery and `fsck --deep`),
`make opfuzz` (the overlay op-sequence fuzzer, in a sealed container), and
`make integration` (transport and publish/resolve against a
federation-in-a-box). Every one of them runs on every push, and on tags.

The parser fuzz targets carry a committed corpus under each package's
`testdata/fuzz/`, which an ordinary `go test` replays. Cost-attribution
benchmarks — the tmpfs floor, the overlay without a kernel, the FUSE op
mix — live in `scripts/bench-*` and are stopwatches, not gates.
