# Unprivileged apptainer against pelfs: what it would take

Status: **measured, not designed.** Everything below the "What works
today" heading was run, and the numbers are from a run you can repeat
with `scripts/apptainer-docker.sh` (`-- --only-fusemount` for sections 0-2
and 7 alone). The design content is the ranked list at the end, and it is
short, because the answer to "what would that take?" turned out to be
**almost nothing for the workflow the owner actually runs**.

In one sentence: **an unprivileged `apptainer exec` of a SIF stored on a
pelfs mount works today, unmodified, and the one thing still worth
changing is the write path's dedup.**

**W1 is implemented** (2026-08-23, the `--fusemount` section below is
rewritten from the failure it recorded): `pelfs mount-gen` is an apptainer
`--fusemount` driver, so a job can mount a pelfs volume inside its own
container with no host-side pelfs. What that took, and the permission
question it forced, is the "`--fusemount`" section.

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

## `--fusemount`: a volume mounted inside the job's own container

This is the mechanism that lets a job mount a pelfs volume **inside its own
container with no host-side setup at all** — no `pelfs mount` on the worker
node, no bind, nothing for a site to install. It works as of 2026-08-23
(work item **W1**), and getting there answered a permission question that
was not optional.

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
substitutes `/dev/fd/N` and appends `-f`. Anything the spec itself carries
before the mountpoint IS passed through, which is how the wrapper below
receives the prefix and the work directory. Three more facts the probe
established:

- the driver's **environment is scrubbed**, and this is all of it:

  ```
  APPTAINER_MESSAGELEVEL=95  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  PWD=/  SHLVL=1  _=/usr/bin/env
  ```

  No `HOME`, no `TMPDIR`, no `BEARER_TOKEN_FILE`, and a `$PREFIX` exported
  by the caller is not there. So a wrapper must spell out the prefix, the
  state directory, `HOME`, the token and (for `--rw`) the signing key —
  which is why `scripts/pelfs-fusemount.sh` takes them as arguments and not
  from the environment;
- with the `container:` form the driver is resolved **inside the
  container's filesystem**, so a host path fails with
  `could not start program ...: no such file or directory`. pelfs has to
  be in the image, or bound in. `host:` is the right form when condor just
  delivered the binary;
- go-fuse v2.11.0 already implements the magic mountpoint
  (`fuse/server.go:854 parseFuseFd`), and its own package doc names
  Singularity as the expected "privileged parent".

### What pelfs had to change

`pelfs mount-gen` was otherwise exactly the right shape — foreground, one
generation, no daemonizing, no re-exec, serves until the mount goes away —
and it died before reaching `rawfuse.Mount`:

```
$ pelfs mount-gen --ro <prefix> /dev/fd/3
ERROR pelfs: mkdir /dev/fd/3: not a directory
```

`os.MkdirAll(mountpoint, 0755)` on `/dev/fd/3` is `ENOTDIR`. Five things
now key off `rawfuse.PassedFD(mountpoint)` instead:

1. **no mkdir** — there is no directory to create;
2. **no unmount at teardown** — the mount belongs to whoever opened the
   descriptor, this process does not even know its path, and
   `fuse.Server.Unmount` refuses a magic mountpoint by design;
3. **no `/dev/fuse` usability probe** — the mount already exists, and on a
   host that permits FUSE only through that parent the probe would refuse a
   mount that works;
4. **`--backend nfs` and `--subshell` are refused with a reason** — the NFS
   backend attaches by calling `mount(2)` on a directory, and a subshell
   needs a path to run in;
5. **pelfs applies the mode bits itself** — the next section, which is the
   part that was not plumbing.

A trailing `-f` is accepted too (hoisted before flag parsing, since Go's
flag package stops at the first positional). `mount-gen` has always run in
the foreground; the flag is documented as the no-op it is.

### The permission question, and its measured answer

On a passed descriptor go-fuse never calls `mount(2)`, so
`rawfuse.mount`'s `options = ["ro", "default_permissions"]` are **never
delivered to anything**. pelfs left `Access` at ENOSYS precisely because
`default_permissions` makes the kernel do the checking, so the risk was a
`--fusemount` session that silently enforces no permissions at all — six
weeks after v0.2.0 shipped POSIX enforcement as a headline change.

**Measured, not assumed.** Two pelfs mounts of the same volume by the same
binary, as `/proc/self/mountinfo` records them — the first an ordinary
`pelfs mount` on the host, the second a `--fusemount` mount as the
container sees it:

```
/work/mnt  ... - fuse.pelfs pelfs ro,user_id=1001,group_id=1001,default_permissions,max_read=131072
/data      ... - fuse       fuse  rw,user_id=1001,group_id=1001
```

The first asked for `ro,default_permissions` through `fusermount` and got
them. The second has neither, and not even the `fuse.pelfs` subtype,
because none of it was ours to set: apptainer called `mount(2)` before the
driver existed. (A stock libfuse driver through the same mechanism gets the
identical line — the harness's argv probe shows `/mnt/probe` with exactly
those options, so this is apptainer's choice and not something about pelfs.)

So on that mount **nothing was applying the mode bits**, and the answer is
not a documented exception:

- `internal/rawfuse/perm.go` implements the check, over
  **`internal/fsperm`** — the model `internal/vfsbilly/perm.go` already
  encoded for the NFS frontend, moved into a package both frontends import.
  There is one permission model in pelfs, not two;
- it is active **only** when pelfs did not choose the mount options, i.e.
  on a passed descriptor. An ordinary mount still leaves the check to the
  kernel, which is cheaper and more faithful, and `Access` still answers
  ENOSYS there so the kernel stops asking;
- the identity evaluated is the **caller's**, from the FUSE request header
  (uid and gid, authenticated by the kernel) — not the server's, which is
  what the NFS frontend has to use for the reasons in `vfsbilly/perm.go`.
  The mount owner is evaluated with this process's real groups and CapEff;
  uid 0 is credited with the four DAC capabilities, which is correct for a
  mount owned by a user namespace whose root it is.

Where it is applied, and the two holes that leaves, are in
`internal/rawfuse/perm.go` and worth reading before trusting it: with
`default_permissions` off the kernel checks nothing but "an exec needs SOME
execute bit", so the checks go on the requests that are always sent — OPEN,
OPENDIR, ACCESS, and the namespace operations. **Path traversal is enforced
only on a dentry-cache miss** (this mount hands out effectively infinite
entry TTLs, so a permitted caller's lookup can be reused by one who is not
permitted), and **a caller's supplementary groups are not on the wire**, so
for any uid but the mount owner the group class is evaluated on the primary
gid alone. Closing the first is exactly what `default_permissions` is for.
A `--fusemount` driver serves one job's uid, where none of this bites.

Verified in the container, not just in unit tests. Same volume, same modes,
both frontends:

```
CONTROL, an ordinary pelfs FUSE mount (the kernel checks):
    $ cat /work/mnt/secret.txt
    cat: /work/mnt/secret.txt: Permission denied

INSIDE a --fusemount mount (pelfs checks), as uid 1001:
    $ stat -c '%n uid=%u gid=%g mode=%a' /data /data/public.txt /data/owneronly.txt
      /data uid=1001 gid=1001 mode=755
      /data/public.txt uid=1001 gid=1001 mode=644
      /data/owneronly.txt uid=1001 gid=1001 mode=600
    $ cat /data/secret.txt        -> Permission denied     (mode 000)
    $ test -r /data/secret.txt    -> no                    (the ACCESS request)
    $ cat /data/owneronly.txt     -> read                  (mode 600, we are the owner)
    $ cat /data/public.txt        -> read
```

Reverting only the permission half — `Mount`/`MountRW` binding unchecked
even for a passed fd — makes the same container print `SECRET_READ` and
`TEST_R_YES`: the 0000 file reads, and `test -r` says yes. That is the
mutation this section is claiming to prevent.

### The command line that works today

```
apptainer exec \
  --fusemount "host:$_CONDOR_SCRATCH_DIR/pelfs-fusemount.sh \
               pelican://<federation>/<prefix> \
               $_CONDOR_SCRATCH_DIR/pelfs-work /data" \
  mypipeline.sif ./payload
```

`scripts/pelfs-fusemount.sh` is in the repo, is what the harness runs (not
a copy of it), and documents each thing it has to spell out because the
environment is scrubbed. Condor ships the binary and the wrapper into the
scratch directory and that is the whole deployment. For a writable mount
add `--rw` and `--signing-key <file>` — see the constraints below.

### Teardown: a killed container still seals

There is nothing to unmount, so exactly two things end the session, and
both were exercised:

- **the connection going away**, which is the ordinary case: apptainer
  closes its copy of the fd, or the container's mount namespace dies with
  it. The device answers `ENODEV`, go-fuse's serve loop exits, and the seal
  runs with no server left to race it;
- **a signal**, which is why the wait is a `select` and not a `Wait`. A
  blocked `read(2)` on `/dev/fuse` cannot be interrupted from userspace —
  neither `close` nor `dup2` wakes it, which is why libfuse unmounts or
  writes the kernel's abort file instead — so a signalled driver cannot
  stop its own serve loop. It stops waiting, seals, releases the lease and
  exits; the process exiting drops the connection.

SIGKILL to apptainer alone, mid-write, in the harness (section 7f):

```
    the job wrote 32 MiB into the mount; killing apptainer (pid 1014) now
    apptainer is gone (rc=137)
    INFO pelfs: sealing the overlay into the next generation...
    INFO pelfs: seal took 114ms (259ms CPU, 22.1 MiB downloaded, 919.6 KiB uploaded)
    INFO pelfs: sealed generation 4 (0 chunks, 1 catalogs written, 1 packs)
    INFO pelfs: torn down in 116ms (... seal 115ms, ... lease release 0s, ...)
  [WORKS] the killed container's generation WAS sealed (seal_ok=true)
    branch head: generation 3 -> 4
  [WORKS] the lease was released: a new writable session takes it without --steal-lease
  [WORKS] the 32 MiB the job wrote before the SIGKILL reads back from a NEW mount
```

The distinction that matters: this is SIGKILL to **apptainer**, not to the
driver. A SIGKILL of the driver itself (which is what a cgroup kill of the
whole job does) cannot seal anything — no process can — and leaves exactly
what any `kill -9` of any pelfs mount leaves: the overlay intact in the
state directory for a remount to seal, and a write lease that expires on
its own 2-minute TTL. `--snapshot-interval` bounds what such a kill can
cost; the default is 5 minutes.

### Two things a writable `--fusemount` job must do

Both were found by running it, and both fail at the worst possible moment
if missed.

**1. Ship the volume's signing key.** A writable session in a fresh work
directory has nothing to sign a new generation with, and the seal fails
*after* the job has finished:

```
ERROR pelfs: seal: no signing key at /work/fmrw/state/v2-signing.key but the branch
  already has generations signed by e344ad58 — import the volume signing key
  (the overlay is intact at /work/fmrw/state/overlay; remount to retry)
```

The wrapper takes `--signing-key <file>` for this, and warns at mount time
rather than at the seal when `--rw` has no key. Reading needs no key.

**2. Something must stat the mountpoint before the first write — and this
one is the kernel's, not pelfs's.** With no prior stat, the first write
into a `--fusemount` mount is refused:

```
    rx 4: LOOKUP n1 "nostat.bin"  p18
    tx 4:     2=no such file or directory
    dd: failed to open '/data/nostat.bin': Permission denied     <- no CREATE was ever sent
    rx 6: GETATTR n1              p20                            <- one stat of /data
    tx 6:     OK, {M040755 ... 1001:1001 ...}
    rx 8: LOOKUP n1 "afterstat.bin"
    rx 10: CREATE n1 {0100644 [WRONLY,CREAT,TRUNC]} "afterstat.bin"
    tx 10:    OK                                                 <- the same write, now fine
```

`dd as the FIRST op: rc=1   the same dd after one stat of the mountpoint: rc=0`.

**No CREATE reaches pelfs at all**, which is what pins the blame: the
kernel refuses it in `inode_permission`, before `->permission` and before
any request. The root inode it created at `mount(2)` carries placeholder
attributes with uid 0; apptainer mounted inside a user namespace that does
not map uid 0, so `i_uid` is `INVALID_UID` and `HAS_UNMAPPED_ID` fails any
`MAY_WRITE` with EACCES. Reads are unaffected — the check is write-only —
which is why a read-only `--fusemount` mount never sees this. One `stat` of
the mountpoint replaces those attributes with the ones pelfs reports and
everything after it works. It reproduces with the permission half of pelfs
removed entirely, and an ordinary `pelfs mount-gen --rw` on a directory
takes the same first write with no stat at all (both are controls in the
harness).

Nothing pelfs can do about it from inside: a FUSE server cannot push
attributes, and the driver does not know the mountpoint's path. So a
writable job's payload should begin with a `ls -ld "$MOUNT"` or `test -d
"$MOUNT"`, which most scripts do by accident.

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

### The write path realizes it — since W2, on the default path too

Measured end to end against a real volume, one generation per
`mount-gen --rw` session (section 8b of the harness; `uploaded` is
`put.bytes` from the stats file, `origin` is the fakeorigin's directory
size after that generation):

| generation | default BEFORE W2 | default AFTER W2 | `--no-memtable` |
|---|---|---|---|
| gen1 `el9.sif` (68,497,408 bytes) | 68,200,190 | 68,200,190 | 68,199,809 |
| gen2 `+` **one small file** added | 68,202,172 | **4,895,856** | **4,894,763** |
| gen3 `+` a 3 MB payload (derived) | 71,204,714 | **10,982,211** | **10,980,738** |
| gen4 `+` `el10.sif` (base moved) | 65,150,940 | 65,148,852 | 65,148,468 |
| **the volume at the end** | **272,755,301** | **149,224,395** | **149,221,054** |

Four related images cost **149 MB either way now, and 273 MB before W2**.
The default path is within **3,341 bytes** of the seal path over the whole
volume — 0.002%, which is a few catalog rows and not a mechanism. gen2's
4,895,856 bytes against the chunker's predicted 4.70 MiB is the same
number: both paths realise the full potential, and gen4 confirms the
mechanism is content and not luck (a rebuilt base dedups against nothing,
in every mode).

**What changed.** The default path now asks the generation it is building
ON whether it already stores a chunk, through the same windowed pack index
the read path uses (`genfs.Placed` over `internal/packidx` /
`internal/mpi`) — so there is no new structure, no sidecar to load, and no
search: a hit is a pack the base generation's SIGNED pack list names, with
the identity confirmed against that pack's own trailer. It is asked only
about chunks at least as large as the 64 KiB window one lookup transfers,
which at the shipped 1 MiB chunker minimum is every chunk of a file, and
the answers cost nothing measurable here — the whole index of a
four-generation volume is one object, fetched once.

The two mechanisms that were there before are unchanged and still first in
line, because both are free: this session's own location map, then the open
pack's entries. The base generation is asked last, because it is the only
one of the three that can cost a request.

Three more hand-run data points, from the same shape. All three are
BEFORE W2, and the first two are the ones W2 did **not** fix — they are
one session, not one generation, which is the batch limitation below:

| what | uploaded | verdict |
|---|---|---|
| **default**, the SAME 68 MB file twice in one session | 136,453,288 | **no dedup at all** |
| **default**, four SIFs (two ~93% identical) in one session | 273,007,591 of 273,846,272 logical | **no dedup at all** |
| `--no-memtable`, a byte-identical copy of el9 in a later generation | **7,101** | essentially free |

The cause had been structural, not a bug. The default path packs and
uploads **during** the session through `internal/memtable`, whose only
dedup was `Store.chunkLoc` — an in-memory map, per session. The
`--no-memtable` path stages writes and chunks everything at the seal
through `internal/publish`, which loads the SQLite **dedup sidecar**
(`internal/publish/dedup.go`) keyed by chunk identity across generations.
One path had cross-generation dedup; the other had none.

Three things fall out, two of them fixed with it:

- `write.deduped_chunks` reported **0 for every one of the BEFORE rows**,
  including the one that deduped 92.8%, because it is incremented only on
  the memtable path. There are now three counters and each says something
  different: `write.base_deduped_chunks` / `base_deduped_bytes` are the
  cross-generation case, `write.deduped_chunks` is that plus the
  within-session repeats, and `sealed_deduped_chunks` is publish's own —
  which is the one `--no-memtable` moves, and which had no field anywhere
  (the `write` section is not even emitted when there is no memtable).
- **The residual gap is the flush BATCH, not the index.** The chunker runs
  over one batch of the ring at a time (`internal/memtable/flush.go`), so
  a session whose writes exceed the ring is cut partly where the ring
  flushed rather than where the content says. One file per generation —
  which is what publishing an image is, and what the table above measures
  — fits and is unaffected. Several large files in ONE session do not:
  measured, 17 of 87 chunks and 28% of bytes content-determined over a
  four-file 274 MB session. See `docs/known-issues.md` KL-9.
- `--no-memtable` is not free: it stages the whole write locally before
  chunking it, so pushing a 68 MB image needs 68 MB of local scratch and
  the upload does not overlap the write. Which is now a reason not to use
  it, since the default path gets the same bytes.

**So the distribution claim holds, and it no longer needs a flag.**

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
   `fusermount3` is what `pelfs mount` needs on the way in — and what a
   `--fusemount` driver does **not**: apptainer has already mounted, so
   that path needs no setuid helper on the host either. On a node with no
   `fusermount3` at all, `--fusemount` is the only way in.
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
| ~~**W1**~~ | **DONE (2026-08-23).** `rawfuse.PassedFD` gates the mkdir, the unmount, the `/dev/fuse` probe, the backend choice and the permission check; `internal/fsperm` + `internal/rawfuse/perm.go` apply the mode bits where the kernel does not; `scripts/pelfs-fusemount.sh` is the driver wrapper. | `--fusemount`: a job mounts a pelfs volume **inside its own container**, no host-side pelfs, nothing for a site to install | took an afternoon: the plumbing was an hour and the permission model was the rest | was the only FAILS row in the matrix |
| ~~**W2**~~ | **DONE (2026-08-23).** The default write path asks the base generation's own windowed pack index (`genfs.Placed` over `internal/packidx` / `internal/mpi`) before storing a chunk, above the 64 KiB a lookup transfers; the seal rechecks what it borrowed if a repack moved the base under it. Three counters replace the one that read 0. **Measured 149,224,395 against `--no-memtable`'s 149,221,054.** | 149 MB instead of 273 MB for four related images, on the DEFAULT path; 93% off a derived image, ~100% off a re-push | an afternoon, and the reachability half was most of it | pelfs as an image distribution channel |
| **W2b** | Chunk an inode's stream across flush BATCHES rather than within one, so a session larger than the ring still cuts on content | the remaining gap: 28% of bytes content-determined over a four-file 274 MB session, against 100% for one file per generation | real — a batch would have to defer its trailing partial chunk, which touches backpressure | several large files published in ONE session |
| **W3** | A path argument to `genfs.Prefetch` / `--prefetch <path>` | prefetch one image out of a volume of twenty, instead of the whole generation | moderate | "prefetch or stage" on a slow link |
| **W4** | Set `MaxWrite`/`MaxReadAhead` in `rawfuse.mount`'s `MountOptions` (both unset today, so reads cap at 128 KiB against a 4 MiB chunk) | fewer FUSE round trips per decoded chunk on the nested-FUSE path | two fields | nothing blocked; a constant-factor win |
| **W5** | A `pelfs get <prefix> <path> <dest>` verb | staging one file at the measured 1.04x without standing up a mount — the fallback for setuid-apptainer sites (constraint 2) | small | the setuid-site path, if constraint 2 turns out badly |
| **W6** | Persist the decoded-chunk arena's index across mounts | a fresh mount with warm packs still re-decodes (`warm packs, cold arena` shows the same 7 misses as cold) | real; the index is deliberately memory-only | CPU only, no bandwidth |
| **W7** | A decoded-bytes counter in the stats file | decode amplification is currently only estimable, never measurable | small | this document's one estimate |

**The caveat inside W1 was the real work, and it was answered rather than
documented as an exception**: on a passed `/dev/fuse` fd, go-fuse never
calls `mount(2)`, so `rawfuse.mount`'s
`options = ["ro", "default_permissions"]` are never applied — apptainer
chose the mount options, and it does not ask for `default_permissions`
(measured, above). `Access` and the rest of the check are therefore
implemented in `internal/rawfuse`, over the model in `internal/fsperm` that
the NFS frontend uses, and active only where the kernel is not doing it.
`ro` is enforced the same way it always was on a read-only binding: every
mutating op answers EROFS.

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

**For publishing images into the volume, no flag either** — this is what
W2 changed, and it is the only thing that has changed about how the owner
would use it:

```
pelfs mount-gen --rw <prefix> ~/publish -- cp mypipeline.sif ~/publish/
```

A derived image costs 4.9 MB rather than 68 MB, on the default path.
`--no-memtable` reaches the same number and stages the whole file locally
to get there, so there is no longer a reason to pass it. One caveat, and
it is the batch limitation above: publish **one image per generation**. Two
large files in one `mount-gen` session are cut partly at the ring's flush
points rather than on content, and dedup against a later generation
degrades accordingly (`docs/known-issues.md` KL-9).

**And for a job that would rather not mount anything on the host at all**,
W1 is now in, so this works:

```
apptainer exec \
  --fusemount "host:$_CONDOR_SCRATCH_DIR/pelfs-fusemount.sh \
               pelican://<federation>/<prefix> \
               $_CONDOR_SCRATCH_DIR/pelfs-work /data" \
  mypipeline.sif ./payload
```

That is a pelfs volume mounted at `/data` inside the job's own container,
by the job, with **no `pelfs mount` on the host** and nothing for the site
to install beyond apptainer itself — condor ships the binary and
`scripts/pelfs-fusemount.sh` into the scratch directory and that is the
whole deployment. The `host:` form is the right one here because the driver
is a host path; the `container:` form works identically but resolves the
driver inside the image, so it needs pelfs baked in or bound in. Add `--rw`
and `--signing-key` to write, and read the two constraints in the
`--fusemount` section first.

---

## Re-running this

```
scripts/apptainer-docker.sh                        # builds the image (network) then runs with --network none
scripts/apptainer-docker.sh -- --only-fusemount    # sections 0-2 and 7 only, ~40s of container time
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
