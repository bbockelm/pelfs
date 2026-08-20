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
  would rewrite and what it would cost.
- **`pelfs version`**, and `pelfs ctl <prefix> bugreport` for a tarball with
  the build, the stats and every goroutine.

### Scale

The format and the maintenance tools are built for volumes of order a
hundred million objects: the pack list moved out of the superblock into a
hash-named manifest, lookups go through a tiered multi-pack index with
16-byte entries, and both `fsck` and the reachability sweep stream over
sorted spill files rather than holding an identity map. Memory for those
passes is a buffer the caller sizes rather than a function of object count.

That is a design target with unit-level evidence, not a claim about a
production volume of that size. The largest trees exercised end to end are
kernel-source-sized: ~90,000 files, ~1.5 GB.

### Known limitations

- **Space from rewritten or deleted content is not reclaimed.** `gc
  --delete` removes packs no retained generation references, which covers
  aborted publishes and superseded indexes. But a generation's pack list is
  carried forward wholesale, so a pack whose contents are *entirely* dead
  stays listed and stays on disk. `repack-plan` measures this exactly; the
  repack that would act on it is **not built**. Plan for storage that grows
  with rewrites.
- **Single writer.** The advisory lease is detection, not mutual exclusion —
  the transport has no compare-and-swap. A seal that would overwrite another
  writer's generation is refused, so the failure mode is a rejected seal
  rather than silent corruption.
- **No tag creation, no forks, no key rotation.** Tags can be read
  (`--tag`) but not written. `pelfs rescue` is specified and not built.
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
path), `make e2e` (a full mount loop in a container against a fake origin),
`make mount-gate` (the kernel mount gate: real FUSE and real NFS clients),
`make opfuzz` (the overlay op-sequence fuzzer, in a sealed container), and
`make integration` (transport and publish/resolve against a
federation-in-a-box). Benchmarks for metadata throughput and untar rate live
in `scripts/bench-*`.
