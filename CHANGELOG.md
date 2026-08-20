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

- **Deleting the reclaimed packs is still manual.** A mount repacks on its
  own, but nothing collects: `pelfs gc --delete` is a separate command, and
  it only takes packs older than the grace window (72h, not configurable).
  A volume nobody mounts is never maintained at all.
- **A repack cannot yet retire index or manifest objects on their own
  account.** Replacing the manifest already drops superseded segments, so
  what is missing is the narrower case of an index whose packs are mostly
  gone: it costs fetch time, never correctness.
- **Single writer.** The advisory lease is detection, not mutual exclusion —
  the transport has no compare-and-swap. A seal that would overwrite another
  writer's generation is refused, so the failure mode is a rejected seal
  rather than silent corruption.
- **No ref deletion, no forks, no key rotation.** `pelfs tag` freezes a
  branch head under a name and `--tag` mounts it, but nothing deletes a tag
  or a branch — and deleting a ref is what finally releases its space, so a
  tag pins its generation for good. `pelfs rescue` is specified and not
  built.
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
