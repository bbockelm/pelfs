# Unprivileged apptainer against pelfs: what it would take

Status: **measured, not designed.** Everything below the "What works
today" heading was run, and the numbers are from a run you can repeat
with `scripts/apptainer-docker.sh`. The design content is the ranked list
at the end, and it is short, because the answer to "what would that take?"
turned out to be **almost nothing for the workflow the owner actually
runs**.

In one sentence: **an unprivileged `apptainer exec` of a SIF stored on a
pelfs mount works today, unmodified, and the two things worth changing are
one `os.MkdirAll` and the write path's dedup.**

---

## What works today

Every line below ran as **uid 1001, no capabilities, no setuid apptainer,
no root anywhere**, against a real Linux kernel. The mount is an ordinary
read-only pelfs FUSE mount:

```
pelfs mount --ro pelican://<federation>/<prefix> ~/images
```

Then, all of these:

```
# 1. THE headline. A SIF that lives in a pelfs volume, run unprivileged.
apptainer exec  ~/images/el9.sif /bin/true
apptainer exec  ~/images/el9.sif cat /etc/redhat-release   # -> AlmaLinux release 9.8
apptainer run   ~/images/el9.sif
apptainer exec  ~/images/el9.sif /bin/sh -c 'ls /usr/bin | wc -l'   # -> 389

# 2. An extracted sandbox tree on pelfs (9,390 entries, 219 MB).
apptainer exec  ~/images/el9-sandbox /bin/true
apptainer exec  ~/images/el9-sandbox /bin/sh -c 'ls -laR /usr | wc -l'
apptainer exec --fakeroot ~/images/el9-sandbox /bin/true

# 3. A pelfs mount visible INSIDE the container, by bind.
apptainer exec --bind ~/images:/data IMAGE ls /data
apptainer exec --bind ~/images:/data IMAGE /bin/sh -c 'wc -c < /data/el9.sif'
apptainer exec --bind ~/images:/data IMAGE /data/busybox-static echo hi

# 4. Plain exec off the mount, which is what all of the above rests on.
~/images/busybox-static echo hello      # static
~/images/echo-dynamic  hello            # dynamic: the loader mmaps it too
```

Three things are worth pulling out of that list.

**`mmap(PROT_EXEC)` on `internal/rawfuse` is fine.** This was the
foundational unknown — the mount asks for `default_permissions` and
nothing else, no `direct_io`, so the page cache backs the mapping and the
kernel's ELF loader gets what it needs. Both a static binary and a
dynamically linked one exec off the mount, and a binary on the mount can
exec another binary on the mount.

**Apptainer reaches the SIF through a passed file descriptor, not a loop
device.** From its own debug log:

```
DEBUG  Mounting block [squashfs] image: /work/mnt/el9.sif
DEBUG  findOnPath()  Found "squashfuse_ll" at "/usr/bin/squashfuse_ll"
DEBUG  Mount()  Executing /usr/bin/squashfuse_ll -f \
         -o allow_other,ro,uid=1001,gid=1001,offset=36864 \
         /proc/self/fd/3 /usr/local/var/apptainer/mnt/session/rootfs
```

So the only thing pelfs has to satisfy is **a seekable regular file that
answers `pread`** — apptainer opens the SIF, hands the fd to
`squashfuse_ll`, and `squashfuse_ll` never sees a path. pelfs satisfies it.
No loop device is created, so nothing about this needs privilege.

**A second `apptainer exec` in the same mount session is free.** Not
"cheap" — *free*: the second run issued **zero** FUSE reads, because the
kernel page cache still held everything the first one touched. A job that
starts the same container repeatedly pays once.

### The version that was tested

| | |
|---|---|
| apptainer | 1.5.3, built from source, `mconfig --without-suid` (`APPTAINER_SUID_INSTALL=0`) |
| squashfuse | Debian `squashfuse` 0.5.2, `/usr/bin/squashfuse_ll` |
| kernel | 6.12.54-linuxkit aarch64 (Docker Desktop's VM) |
| identity | uid 1001, empty supplementary group set, no file capabilities |
| origin | `cmd/fakeorigin` on loopback over a tmpfs, `--network none` |

`scripts/apptainer-docker.sh` builds that image and runs
`scripts/apptainer-test.sh` inside it. The launcher's header documents
every deviation from a stock container and why each one is not a privilege.

---

## What does not work: `--fusemount`

This is the interesting failure, because `--fusemount` is the mechanism
that would let a job mount a pelfs volume **inside its own container with
no host-side setup at all** — no `pelfs mount` on the worker node, no bind,
nothing for a site to install.

It fails, for one reason, and the reason is three lines of pelfs.

### What apptainer hands the driver

The harness ran an argv probe as the FUSE driver. For
`--fusemount "container:/work/argvprobe.sh /mnt/probe"` and for the `host:`
form alike, apptainer runs:

```
/work/argvprobe.sh /dev/fd/3 -f
        with fd 3 -> /dev/fuse   (already opened; the kernel-side mount is done)
```

That is the libfuse "magic mountpoint" convention. The mountpoint written
in the spec (`/mnt/probe`) is **not** passed to the driver; apptainer
substitutes `/dev/fd/N`. Two more facts the probe established:

- the driver's **environment is scrubbed** — a `$PREFIX` exported by the
  caller is not there, so a wrapper must spell out the prefix, the state
  directory and `HOME`;
- with the `container:` form the driver is resolved **inside the container's
  filesystem**, so a host path fails with
  `could not start program ...: no such file or directory`. pelfs would
  have to be in the image, or bound in.

### What pelfs does with it

`pelfs mount-gen` is otherwise exactly the right shape: foreground, one
generation, no daemonizing, no re-exec, serves until SIGTERM. And go-fuse
v2.11.0 **already implements** the magic mountpoint —
`fuse/server.go:854 parseFuseFd` recognises `/dev/fd/N` and skips
`fusermount` entirely; its own package doc names Singularity as the
expected "privileged parent".

pelfs never gets that far:

```
$ pelfs mount-gen --ro <prefix> /dev/fd/3
ERROR pelfs: mkdir /dev/fd/3: not a directory
```

`cmd/pelfs/mountgen.go:616` does `os.MkdirAll(mountpoint, 0755)` before
mounting. On `/dev/fd/3` — a symlink to the fuse device — that is
`ENOTDIR`, and the session exits before `rawfuse.Mount` is reached.
Through apptainer the same failure surfaces as
`ls: cannot access '/mnt/pelfs': Transport endpoint is not connected`.

**The control proves nothing else is in the way.** A stock libfuse driver
in the same container, through the same mechanism, works:

```
$ cat /work/sq-fusemount.sh
#!/bin/sh
exec /usr/bin/squashfuse_ll -o offset=36864 /images/el9.sif "$1"

$ apptainer exec --fusemount "host:/work/sq-fusemount.sh /mnt/probe" IMAGE ls /mnt/probe
afs bin dev environment etc home ...
```

So: apptainer's plumbing works, go-fuse's half works, and one `MkdirAll`
is the blocker. See work item **W1**; it is not implemented here, and
there is more to decide than the `mkdir` (below).

---

## Read amplification, measured

The worry was specific: squashfuse issues small random reads; pelfs
decodes a whole chunk to serve any part of one; a cold miss fetches a
whole pack. Here is what actually happens.

### The reads really are small

Read sizes the kernel asked pelfs for during **one cold
`apptainer exec el9.sif /bin/true`** — 58 requests, 2,564,096 bytes total:

```
   4096 x13     20480 x2     32768 x4     53248 x1     65536 x4     77824 x1    126976 x1
   8192 x4      24576 x2     40960 x1     57344 x2     69632 x1     81920 x2    131072 x6
  16384 x7      28672 x1     45056 x1     61440 x2     73728 x2    102400 x1
```

Mean 43 KiB, floor 4 KiB, ceiling 128 KiB (`MaxWrite` is unset in
`internal/rawfuse`, so 128 KiB is the kernel's cap). The SIF is 68,497,408
bytes and the chunker averages 4 MiB, so it is roughly 17 chunks: a single
4 KiB read that misses costs a ~4 MiB decode, about **1000x on that
read**.

### But the arena and the whole-pack policy absorb it

Deltas across each run. `kernel asked` is summed FUSE `READ` sizes from the
`--debug` protocol trace; `origin GET` is `get.bytes` from
`pelfs ctl <mnt> stats`; hits/misses are the decoded-chunk arena's.

| scenario | kernel asked pelfs for | origin GET | ratio | arena hit/miss | wall |
|---|---|---|---|---|---|
| **cold** `exec /bin/true` (cache cleared, fresh mount) | 2,564,096 | 22,184,569 | **8.7x** | 51 / 7 | 0.13 s |
| **warm** `exec /bin/true`, same session | 0 | 0 | — | 0 / 0 | 0.09 s |
| warm, workload touching many files in the image | 8,355,840 | 25,135,990 | 3.0x | 107 / 7 | 1.11 s |
| **warm packs, cold arena** (a second job, new mount) `exec /bin/true` | 2,564,096 | 0 | **0x** | 51 / 7 | 0.11 s |
| warm packs, cold arena, workload | 1,024,000 | 0 | 0x | 16 / 2 | 0.97 s |
| `--prefetch all`, then `exec /bin/true` | 2,564,096 | 0 | 0x | 51 / 7 | 0.11 s |
| **cold whole-file read** of the SIF (`cp` off the mount) | 68,497,408 | 71,537,741 | **1.04x** | 505 / 24 | 0.13 s |
| **cold** sandbox-on-pelfs `exec /bin/true` | 3,358,720 | 11,336,146 | 3.4x | 31 / 13 | 0.07 s |
| cold sandbox, `ls -laR /usr` workload | 1,953,792 | 928,777 | 0.5x | 21 / 3 | 1.31 s |
| **local disk baseline** `exec /bin/true` | — | — | — | — | 0.09 s |
| local disk baseline, workload | — | — | — | — | 0.99 s |

One run is tabulated; three were taken. The `kernel asked` column is
byte-for-byte identical across runs, and the `origin GET` column moves
±10% — 22.2, 24.2 and 26.5 MB for the cold exec — because which chunks
share a pack depends on how the write session cut them, and a whole-pack
fetch inherits that. Read **8.7x as "between 8 and 11"**.

`pelfs fsck` on the volume: 180 packs, 3,082 chunks, 486,725,482 logical
bytes. Largest pack ~4.46 MB (124 packs over 1 MiB).

**Decoded bytes are an estimate, not a measurement.** There is no
"bytes decoded" counter to read; the arena reports hits and misses only.
Taking the SIF's chunks at the 4 MiB average, the 7 misses in a cold exec
decode roughly **28 MiB to deliver 2.44 MiB — about 11x**. The 51 hits
against 7 misses is the arena doing exactly its job: once a chunk is
decoded, the neighbouring small reads are memcpys.

### The conclusion, which is not the one the worry predicted

Amplification is real — **8.7x on origin bytes, ~11x on decode** — and it
does not matter, because of the absolute numbers:

- a cold `apptainer exec` of a 68 MB SIF moves **22 MiB**;
- **staging that same SIF locally moves 68 MiB**.

Reading the image lazily through pelfs therefore moves **a third of the
bytes** that copying it first would, even at 8.7x amplification. The 8.7x
is a ratio against a very small numerator. And at the other end, a job
that does read the whole image converges to **1.04x** — the whole-pack
policy is nearly free when the whole file is wanted, because a pack is
almost entirely the file you asked for.

The pathological case the worry describes — scattered small reads across
an image, cold — is the "warm, workload" row at 3.0x, and even there the
absolute traffic (25 MiB) is under half the image.

Two more results matter more than the ratios:

- **`--prefetch all` and a warm pack cache are indistinguishable from local
  disk**: both give 0 origin bytes. The second job on a node pays nothing.
- **Nested FUSE costs about 12%.** squashfuse-over-pelfs is two userspace
  round trips per read, and the same in-container workload ran 1.11 s
  through pelfs against 0.99 s off local disk — with the packs already
  local in both cases, so that 12% is the nesting and the FUSE protocol,
  not the federation. Container startup itself is indistinguishable
  (0.11 s vs 0.09 s). Every wall-clock number here is over a **loopback
  origin on tmpfs**, so it is an ordering, not a rate; a real federation
  adds to the origin-GET column and to nothing else.

### Which configuration is acceptable

Plainly:

- **Short jobs, cold cache: read straight off the mount.** Cheaper in bytes
  than staging. No flags.
- **Many jobs on one node: nothing to do.** The pack cache makes the second
  job cost zero origin bytes, whether or not you prefetch.
- **A job that reads most of a large image, over a slow link: prefetch or
  stage.** `--prefetch all` is the blunt instrument — it fetches the
  **whole generation** (334 MB here for four images and a sandbox), because
  `genfs.Prefetch` takes no path (work item **W3**). If the volume holds
  one image, use it; if it holds twenty, `cp` the one you want off the
  mount at 1.04x and run from that.

The honest answer to "is it unusable without prefetch and a warm arena" is
**no** — it is usable cold, and the reason is that 8.7x of a small number
is still a small number.

---

## The distribution-channel question

Content-defined chunking should let the squashfs blocks of related images
dedup, making a pelfs volume an image *distribution* channel and not just a
filesystem. It holds — with a caveat that is currently fatal by default.

### The chunker's potential is large and real

`internal/dedupbench`'s `TestIncrementalTree`, run over real SIFs
(gen1 = base image, gen2 = the derived one):

| gen1 → gen2 | CDC (1/4/16 MiB) | fixed 4 MiB | whole-file |
|---|---|---|---|
| el9 → el9 **+ one small file** | **4.70 MiB new** of 65.32 | 65.32 MiB | 65.32 MiB |
| el9 → el9 **+ a 3 MB payload + a script** | **10.50 MiB new** of 68.18 | 68.18 MiB | 68.18 MiB |
| el9 → **el10** (base moved a major version) | 62.33 MiB | 62.33 MiB | 62.33 MiB |

And all three SIFs in one volume: 25.77% of chunked bytes deduped, of which
**100% is sub-file matching** — whole-file hashing finds nothing at all,
because no two SIFs are byte-identical.

So: a derived image costs **7%** of its size, content-defined chunking is
the *only* scheme that finds it, and a rebuilt base costs full price. Note
also the floor: adding **one small file** to a squashfs still costs 4.7 MiB,
because mksquashfs re-lays out what follows. "Costs nothing" is not on the
table; "costs 7% instead of 100%" is.

### The write path throws all of it away — unless you pass `--no-memtable`

Measured end to end against a real volume, one generation per
`mount-gen --rw` session (section 8b of the harness; `uploaded` is
`put.bytes` from the stats file, `origin` is the fakeorigin's directory
size after that generation):

| generation | default: uploaded | `--no-memtable`: uploaded |
|---|---|---|
| gen1 `el9.sif` (68,497,408 bytes) | 68,200,190 | 68,199,809 |
| gen2 `+` **one small file** added | 68,202,172 | **4,894,763** |
| gen3 `+` a 3 MB payload (derived) | 71,204,714 | **10,980,738** |
| gen4 `+` `el10.sif` (base moved) | 65,150,940 | 65,148,468 |
| **the volume at the end** | **272,755,301** | **149,221,054** |

Four related images cost **149 MB with `--no-memtable` and 273 MB
without** — the same four images, the same volume, one flag. gen2's
4,894,763 bytes against the chunker's predicted 4.70 MiB is the same
number: the seal path realises the full potential, and gen4 confirms the
mechanism is content and not luck (a rebuilt base dedups against nothing,
in both modes).

Three more hand-run data points, from the same shape:

| what | uploaded | verdict |
|---|---|---|
| **default**, the SAME 68 MB file twice in one session | 136,453,288 | **no dedup at all** |
| **default**, four SIFs (two ~93% identical) in one session | 273,007,591 of 273,846,272 logical | **no dedup at all** |
| `--no-memtable`, a byte-identical copy of el9 in a later generation | **7,101** | essentially free |

The cause is structural, not a bug. The default path packs and uploads
**during** the session through `internal/memtable`, whose only dedup is
`Store.chunkLoc` — an in-memory map, per session — and whose chunker runs
over **one flush batch's** extents (`internal/memtable/flush.go:175`), so
boundaries depend on where the ring flushed, not only on content. The
`--no-memtable` path stages writes and chunks everything at the seal
through `internal/publish`, which loads the SQLite **dedup sidecar**
(`internal/publish/dedup.go`) keyed by chunk identity across generations.
One path has cross-generation dedup; the other has none.

Two smaller things fall out of this:

- `write.deduped_chunks` in the stats file reported **0 for every one of the
  rows above**, including the row that deduped 92.8%. The counter is
  incremented only on the memtable path (`internal/memtable/seal.go:225`),
  so the path that actually dedups is invisible in the statistics.
- `--no-memtable` is not free: it stages the whole write locally before
  chunking it, so pushing a 68 MB image needs 68 MB of local scratch and
  the upload does not overlap the write.

**So the distribution claim holds, and today it is spelled
`--no-memtable`.** For anyone publishing images into a pelfs volume that is
the flag, and nothing in the documentation says so.

---

## Environment constraints that are site policy, not engineering

No amount of work on pelfs moves any of these.

1. **Unprivileged user namespaces must be enabled.** Everything above needs
   them; many HPC sites disable them. Measured present here
   (`max_user_namespaces=43744`, `unshare -U -r` succeeds), and no container
   can decide it for a real worker node.
2. **The setuid-apptainer alternative changes the analysis, and was NOT
   tested here.** A setuid install mounts the SIF's squashfs with a **loop
   device** rather than squashfuse. Whether the loop driver will accept a
   FUSE-backed file as its backing store is the whole question for a
   SIF-on-pelfs, and this harness cannot answer it: it deliberately builds
   apptainer `--without-suid`, and there is no `starter-suid` to exercise.
   **COULD-NOT-TEST-HERE**, and it is the single most valuable thing to test
   on a real OSPool worker node. If the answer is no, the SIF must be staged
   at setuid sites — which the 1.04x whole-file number says is cheap.
3. **`/dev/fuse` must exist and be usable by the job's uid** (0666 here).
   Already the README's caveat; apptainer needs it too.
4. **`fusermount3` matters only for pelfs's own mount.** Inside its user
   namespace apptainer performs the FUSE mount itself with the namespace's
   `CAP_SYS_ADMIN`, so `squashfuse_ll` needs no setuid helper. The setuid
   `fusermount3` is what `pelfs mount` needs on the way in.
5. **Nested FUSE doubles the round trips** and, measured, costs about 12%
   on an in-container workload with the packs already local (1.11 s against
   0.99 s off local disk) and nothing measurable on container startup.
   Worth re-measuring at a site with a real federation.

### Three failures that were the test rig, not the system

Recorded because each one cost time and each one looks exactly like a pelfs
bug:

- **amd64 emulation breaks apptainer entirely.** Under Docker Desktop's
  x86 emulation on Apple Silicon, every `apptainer exec` dies at the final
  `execve` with `EINVAL` — including images on local disk. The harness now
  builds apptainer from source for the native arch instead.
- **This kernel cannot exec off overlayfs-whose-lower-layer-is-FUSE.**
  Apptainer's default container root is a kernel overlay over the
  squashfuse mount; a binary on it can be `read` and not `execve`'d
  (`EINVAL`, because `load_elf_binary` turns a failed `mmap` into `EINVAL`).
  Identical for a SIF on local disk, which is what proves it is the kernel.
  The image therefore sets `enable overlay = no`, moving apptainer to its
  underlay/bind path. Real sites plainly do not have this, since they run
  SIFs all day.
- **Docker's `/proc` masking blocks `--fusemount`.** Apptainer mounts a
  fresh procfs to run a FUSE driver, and the kernel's
  `mount_too_revealing()` check refuses that inside a user namespace while
  the existing `/proc` has masked entries. Hence
  `--security-opt systempaths=unconfined` in the launcher.

---

## Ranked work items

| | change | buys | effort | unblocks |
|---|---|---|---|---|
| **W1** | Skip `os.MkdirAll` for a `/dev/fd/N` mountpoint (`cmd/pelfs/mountgen.go:616`), and skip `srv.Unmount()` for it at teardown (go-fuse refuses a magic mountpoint by design). Tolerate a trailing `-f`. | `--fusemount`: a job mounts a pelfs volume **inside its own container**, no host-side pelfs, nothing for a site to install | ~1 hour for the plumbing; see the caveat below | the only FAILS row in the matrix |
| **W2** | Cross-generation dedup on the **default** write path — or, far cheaper, document `--no-memtable` as the flag for publishing images and count the seal path's dedup in `write.deduped_chunks` | 149 MB instead of 273 MB for four related images; 92.8% off a derived image, ~100% off a re-push | documenting + the counter: hours. Making the memtable path dedup: real work — its chunker cuts per flush batch and its index is per session | pelfs as an image distribution channel |
| **W3** | A path argument to `genfs.Prefetch` / `--prefetch <path>` | prefetch one image out of a volume of twenty, instead of the whole generation | moderate | "prefetch or stage" on a slow link |
| **W4** | Set `MaxWrite`/`MaxReadAhead` in `rawfuse.mount`'s `MountOptions` (both unset today, so reads cap at 128 KiB against a 4 MiB chunk) | fewer FUSE round trips per decoded chunk on the nested-FUSE path | two fields | nothing blocked; a constant-factor win |
| **W5** | A `pelfs get <prefix> <path> <dest>` verb | staging one file at the measured 1.04x without standing up a mount — the fallback for setuid-apptainer sites (constraint 2) | small | the setuid-site path, if constraint 2 turns out badly |
| **W6** | Persist the decoded-chunk arena's index across mounts | a fresh mount with warm packs still re-decodes (`warm packs, cold arena` shows the same 7 misses as cold) | real; the index is deliberately memory-only | CPU only, no bandwidth |
| **W7** | A decoded-bytes counter in the stats file | decode amplification is currently only estimable, never measurable | small | this document's one estimate |

**The caveat inside W1**, which is design and not plumbing: on a passed
`/dev/fuse` fd, go-fuse never calls `mount(2)`, so
`rawfuse.mount`'s `options = ["ro", "default_permissions"]` are **never
applied** — apptainer chose the mount options. pelfs leaves `Access` at
`ENOSYS` precisely because `default_permissions` makes the kernel do the
checking, so a `--fusemount` session silently loses its permission model.
Either implement `Access`, or refuse the magic mountpoint with a message
saying why. Do not merely delete the `MkdirAll`.

---

## Recommended minimal path

**For the primary workflow — an unprivileged HTCondor job running apptainer
on a SIF in a pelfs volume backed by an OSDF origin — the recommended
change set is empty. It works today.** In a job:

```
pelfs mount --ro pelican://<federation>/<prefix>/images "$_CONDOR_SCRATCH_DIR/images"
apptainer exec "$_CONDOR_SCRATCH_DIR/images/mypipeline.sif" ./payload
pelfs umount "$_CONDOR_SCRATCH_DIR/images"
```

No flags, no staging, no prefetch. It moves a third of the bytes that
staging the image would, and on a node that has run the image before it
moves none. The two conditions are site policy and stated above:
unprivileged user namespaces, and a usable `/dev/fuse`.

**For publishing images into the volume, add one flag** — this is the only
thing worth changing about how the owner would use it today:

```
pelfs mount-gen --rw --no-memtable <prefix> ~/publish -- cp mypipeline.sif ~/publish/
```

Without it a derived image costs 68 MB; with it, 4.9 MB.

**The smallest change set that unblocks a workflow that does not work
today** is **W1 alone**, and the workflow it buys is worth naming, because
it removes the last thing a site has to agree to:

```
apptainer exec \
  --fusemount "host:$_CONDOR_SCRATCH_DIR/mount-my-volume.sh /data" \
  mypipeline.sif ./payload
```

where the wrapper is, in full:

```
#!/bin/bash
# apptainer runs us as: <this> /dev/fd/N -f, with a SCRUBBED environment,
# so everything it needs is written out rather than inherited.
export HOME=/scratch/home
exec /scratch/pelfs-bin/pelfs mount-gen --ro --state-dir /scratch/pelfs \
     pelican://<federation>/<prefix> "$1"
```

That is a pelfs volume mounted at `/data` inside the job's own container,
by the job, with **no `pelfs mount` on the host** and nothing for the site
to install beyond apptainer itself — condor ships the binary and the
wrapper into the scratch directory and that is the whole deployment. The
`host:` form is the right one here because the driver is a host path; the
`container:` form works identically but resolves the driver inside the
image, so it needs pelfs baked into the image or bound in. Everything in
that command line works now except the `os.MkdirAll`, and the control run
proves it.

---

## Re-running this

```
scripts/apptainer-docker.sh          # builds the image (network) then runs with --network none
```

The dedup numbers come from `internal/dedupbench` against real SIFs:

```
PELFS_CORPUS_A=<dir with el9.sif> PELFS_CORPUS_B=<dir with el9-tiny-change.sif> \
  go test -tags nogspt,notikv ./internal/dedupbench/ -run TestIncrementalTree -v
```

The write-path dedup table is section 8b of the same harness (`DEDUP|`
lines in its machine-readable summary). The three extra hand-run rows
under it were taken the same way — one `mount-gen --rw [--no-memtable]`
session per generation against a fakeorigin, reading `put.bytes` out of
`--stats-file`.
