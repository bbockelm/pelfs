# Changelog

## Unreleased

### `pelfs mount-gen` is an apptainer `--fusemount` driver

A job can now mount a pelfs volume **inside its own container**, with no
pelfs on the host and nothing for a site to install beyond apptainer:

```
apptainer exec \
  --fusemount "host:$_CONDOR_SCRATCH_DIR/pelfs-fusemount.sh \
               pelican://<federation>/<prefix> \
               $_CONDOR_SCRATCH_DIR/pelfs-work /data" \
  mypipeline.sif ./payload
```

`scripts/pelfs-fusemount.sh` is that wrapper, ready to ship with a job;
`docs/design-apptainer.md` has the measurements and the constraints.

What changed to make it work:

- **A `/dev/fd/N` mountpoint is understood.** Apptainer opens `/dev/fuse`,
  performs the kernel mount itself, and runs the driver as
  `<driver> /dev/fd/N -f` — the libfuse magic-mountpoint convention, which
  go-fuse already implements. `mount-gen` used to `os.MkdirAll` its
  mountpoint first and die with `mkdir /dev/fd/3: not a directory`. It now
  recognises the form (`rawfuse.PassedFD`) and skips the mkdir, skips the
  unmount at teardown (there is nothing of ours to unmount, and go-fuse
  refuses a magic mountpoint by design), skips the `/dev/fuse` usability
  probe (the mount already exists), refuses `--backend nfs` and
  `--subshell` for it with a reason, and tolerates the trailing `-f`.
- **Permissions are enforced by pelfs on such a mount.** On a passed
  descriptor go-fuse never calls `mount(2)`, so the `ro` and
  `default_permissions` this process asks for are never delivered —
  measured: the mount options are the parent's, and apptainer does not ask
  for `default_permissions`. A `--fusemount` mount would therefore have
  applied no mode bits at all, which is the inconsistency v0.2.0 closed for
  the NFS frontend. So `internal/rawfuse` now answers `ACCESS` and checks
  OPEN, OPENDIR, LOOKUP and every namespace operation itself **when and
  only when** the kernel is not doing it, over the same model the NFS
  frontend uses. That model moved to `internal/fsperm`, imported by both
  frontends; `internal/vfsbilly/perm.go` keeps the NFS-specific half. An
  ordinary mount is unchanged and still leaves the check to the kernel.
- **Teardown seals.** A `--rw` driver whose container is killed still
  publishes: the connection dies with the container's namespace, the device
  answers `ENODEV`, and the seal and the lease release run then. Verified
  by SIGKILL'ing apptainer mid-write in the container harness — 32 MiB
  written, generation sealed, lease released, bytes read back from a fresh
  mount.
- `-f`/`--foreground` is accepted (and documented as a no-op: `mount-gen`
  has always run in the foreground, which is what a `--fusemount` driver
  must do).

Two constraints a writable `--fusemount` job has to know, both recorded in
`docs/design-apptainer.md`:

- the driver's environment is **scrubbed**, so the prefix, the work
  directory, the token and the signing key are command-line arguments of
  the wrapper, not inherited;
- with `--rw`, ship the volume's **signing key** (`--signing-key`): a fresh
  work directory has none, and without it the seal fails after the job has
  already finished.

## v0.2.0

v0.1.0 could mount, write, seal, branch and tag. It could not merge a
branch back, rebuild a lost ref, replace a signing key, or free the bytes
its own repacks had condemned — and it let any process write any file
through the NFS frontend regardless of that file's mode bits. All five are
fixed here.

The on-disk format is still `FormatVersion 2` and no volume needs
converting. Two things change for a v0.1.0 user anyway: an NFS mount now
refuses writes it used to accept, and a generation this release seals
**cannot be read by a v0.1.0 binary**. Read *Upgrading from v0.1.0* before
you upgrade a volume anyone else is using.

Still a prototype, still used against real federations, and still
unprivileged and `CGO_ENABLED=0`.

### Upgrading from v0.1.0

Seven changes a v0.1.0 user will notice, and what to do about each.

#### 1. An NFS mount enforces POSIX permissions. It enforced none.

This is the one most likely to break a working script. On a v0.1.0
NFS-backed mount a write to a mode-0444 file **succeeded**, and the bytes
survived the seal; `access(2)` and `test -w` answered "writable" for
everything, because go-nfs replied to an ACCESS RPC with whatever the
client had asked for. The same write through FUSE was refused with
`EACCES` — that mount asks the kernel to check
(`default_permissions`), and NFSv3 puts the check on the server, where
nothing performed it. Which backend you happened to mount with decided
whether your own mode bits meant anything.

The model now lives in `internal/vfsbilly/perm.go`, and the go-nfs fork pin
moved to `13c0560` to carry the half that cannot be done from outside the
package:

- Mode bits by class — owner, else group, else other, **first match
  deciding** — so a mode of `0004` denies its owner, exactly as the kernel
  does.
- Write and search on the parent directory for anything that creates or
  removes a name; search permission on every path component; the sticky-bit
  rule on `rm` and `rename`; ownership for `chmod` and `utimes`;
  `CAP_CHOWN` for a `chown`, and `CAP_FOWNER`, `CAP_DAC_OVERRIDE`,
  `CAP_DAC_READ_SEARCH` honoured where the kernel would honour them.
- `EPERM` where the kernel says `EPERM` (you are not the owner) and
  `EACCES` where it says `EACCES` (the mode bits say no).
- **`access(2)` and `test -w` answer honestly.** The fork exports
  `nfs.PermissionChecker`, so the ACCESS reply is a projection of the model
  above rather than an echo of the request.
- **`tar -p` works.** A read-only file created and then written through one
  file descriptor is allowed for the file's owner, scoped exactly as knfsd
  scopes it: existing regular files, on `open`, and nowhere else — not
  ACCESS, not the namespace operations, not the path walk, not the
  ownership questions.

**Whose permissions: the mount's own.** Every request is evaluated as the
identity that started the server — its uid, gid, supplementary groups and
effective capabilities, read from the process and translated through the
same id map that decides whose name the mount puts on a file. The AUTH_UNIX
credential NFSv3 puts in each request is deliberately **not** consulted:
the export is loopback and single-user, any local process can dial
127.0.0.1 and claim any uid, so honouring it would make the check look like
a security boundary. It is not one. What this buys is fidelity — the same
answer through both frontends — and nothing else. The reasoning is written
out in `docs/go-nfs-patches.md`.

**There is no escape hatch.** No flag, no environment variable and no
config field restores v0.1.0 behaviour; the only way to get it is to
recompile against a different credential. If a script of yours writes
through a mode that denies it, fix the mode, or run the mount as a uid the
mode permits.

Two deliberate non-implementations, so they are not discovered as bugs:
`S_ISUID` and `S_ISGID` are not cleared on a `chown`, nor on a `chmod` by a
non-member of the file's group.

**FUSE mounts are unaffected** — there is no permission logic on the FUSE
side, before or after this work. The kernel does it, and always did.

#### 2. A writable mount now collects as well as repacks.

Auto-repack shipped in v0.1.0 and nothing ever COLLECTED: a repack
condemns packs, the retention sweep is what deletes them, and the only
thing that ran the sweep was a person typing `pelfs gc --delete`. A volume
that repacked itself faithfully every six hours still grew forever, and
both halves of the v0.1.0 limitation stayed true for the half that frees
bytes.

The sweep now runs in the same idle machinery, under the same quiescence
and back-off rules: after a repack that published — that repack is what
created the work — and otherwise on a six-hour floor while the mount is
quiet. Default ON, `--no-auto-gc` to turn it off, separately from
`--no-auto-repack` because the two fail differently: a repack that does
not run costs storage, and **a sweep deletes.**

What that costs, and how to watch it:

- **It is the existing sweep, not a new one.** `retention.GC` with
  `Delete`, every window intact — the grace window the volume records, the
  retain-K generations, the three condemned ledgers — and the same
  fail-closed rule: a ref or tag that will not verify aborts the run and
  deletes NOTHING. There is deliberately no second deletion path in the
  mount to keep in agreement with the first.
- **The first sweep of a session does not wait six hours.** A mount that
  has just started is the best evidence available that nobody has swept
  this volume lately, so the floor counts as passed. In practice a writable
  mount deletes something within about seven minutes of going idle — a
  two-minute check tick against a five-minute quiescence window. If that is
  not what you want on a volume you were about to inspect, mount it
  read-only or pass `--no-auto-gc`.
- **It rides the write lease**, so it happens on writable mounts with a
  non-zero `--snapshot-interval` and nowhere else. Read-only mounts never
  maintain, and — unchanged, and still the honest limit — **a volume nobody
  mounts writably is never maintained.**
- Where to look, because it has to be readable months later and not only in
  a log: `pelfs ctl <mount> status` gains `last_gc_at`, `last_repack_at`,
  `reclaimed_bytes`, `reclaimed_objects` and `last_gc_error`. The
  statistics file gains a `maintenance` section carrying `repacks`,
  `last_repack_at`, `condemned_bytes`, `collections`, `last_gc_at`,
  `reclaimed_objects`, `reclaimed_bytes`, `grace_seconds` (the window the
  last sweep applied), `collection_failures` and `last_collection_error`.
  The failure counter is the one to alert on: a sweep that fails closed
  every time looks exactly like a volume with nothing to collect.

#### 3. State-directory and statistics changes

Nothing here needs a migration step, but a script or supervisor that reads
either will notice.

- **The decoded-chunk tier is one file.** `gencache/chunks/` — a plaintext
  file per chunk the mount had ever read — is now `gencache/chunks.arena`,
  one preallocated, mmap'd file. **The first mount with this build sweeps
  the old directory** and logs what it reclaimed. Nothing is lost:
  everything under `gencache/` is re-derivable from the federation, and a
  v0.1.0 binary pointed back at the same state directory simply refills the
  old shape.
- **Scratch directories are pid-named and swept.** Spool directories are
  now `publish-<pid>-*`, `snapshot-<pid>-*` and `repack-<pid>-*`, and every
  mount — read-only ones too — collects the ones whose owner process is no
  longer running, reporting the bytes and the names it took. A directory an
  older release wrote carries no pid and waits out a 24-hour idle guard
  instead; a week untouched collects even a live-owned one, because pids are
  reused.
- **The dedup sidecar is restamped by a repack**, so the first seal after a
  repack deduplicates again instead of re-uploading everything. Nothing to
  do; the file is rewritten in place by the repack that publishes.
- **Statistics keys changed, and `pelfs_stats_version` is now `3`.** Two
  keys were REMOVED, which is exactly what that number exists to
  announce: a reader keyed to a removed name gets nothing rather than a
  zero, so it has to be able to tell. Version 2 only ever added fields.
  Three things to fix in a supervisor:
  - `prefetch_chunks` is **gone**, replaced by `prefetch_packs`.
    `prefetch_fetched_bytes` is new — what this session actually
    transferred, as against `prefetch_bytes`, the size of the set now
    local. `prefetch_complete` and `prefetch_failed` are unchanged.
  - `cache.dirs.chunks` is **gone**, replaced by `cache.dirs.arena`.
    `cache.chunk_hits` and `cache.chunk_misses` are new and are how you
    tell whether the arena is the right size for the workload.
  - Everything else in the window is additive: `lease_key`,
    `lease_interrupted`, `lease_revalidated_at`, and the `maintenance`
    section above.

#### 4. Interop with a v0.1.0 client: one direction is safe, the other is not

**A v0.2 client can read and write a v0.1.0 volume. A v0.1.0 client must
not be pointed at a volume this release has written.** Two independent
reasons.

**The write lease is per branch now.** It was `meta/lease.json`, one object
for the whole prefix, so two writable mounts on DIFFERENT branches of one
volume refused each other though they could never touch the same ref. The
key is now `meta/lease-<branch>.json`: writable mounts of `main` and `dev`
run concurrently and both seal, and only a second writer on the SAME branch
is refused, still naming the holder. Nothing about the guarantee changed —
the lease was always advisory DETECTION and not mutual exclusion, and what
actually prevents two writers corrupting each other is the seal's refusal
to publish over a ref that moved. A per-branch key removes a FALSE
exclusion; it adds no safety.

Mixed with a v0.1.0 client the rule is asymmetric on purpose:

| writer | excluded by | excludes |
|---|---|---|
| v0.2 on branch B | a live `meta/lease.json` (any v0.1.0 writer), and a live `meta/lease-B.json` | v0.2 writers on B only |
| v0.1.0 (any branch) | a live `meta/lease.json` | every v0.1.0 writer on the volume — and nothing else |

A v0.2 writer READS `meta/lease.json` and refuses while one is live, naming
the holder, because a v0.1.0 record does not say which branch it is on. It
never WRITES that object: doing so would put two v0.2 writers on different
branches back to excluding each other through the legacy key. The
consequence, stated rather than hidden: **a v0.1.0 client sees a v0.2
writer as unleased and will mount straight past it**, and its only guard is
then the seal refusal. New flag `--ignore-volume-lease` proceeds past a
live legacy object, leaving it exactly where it was to expire on its own
TTL; `--steal-lease` deliberately does not apply to it, because that flag
takes one branch's lease and the legacy object belongs to a client whose
branch you cannot see.

**The superblock's new `Branch` field is a one-way door.** Every superblock
written before the field still verifies unchanged — pinned against
**captured v0.1.0 wire bytes** rather than a round trip through the current
encoder (`TestAV010SuperblockStillVerifies` in
`internal/superblock/branchfield_test.go`, over the committed fixture
`internal/superblock/testdata/v010-superblock.hex`). The other direction is
a hard refusal: `Verify` re-encodes the decoded struct, so a v0.1.0 binary
— which drops a field it does not know — gets **`ErrBadSignature`**,
"superblock signature verification failed", on any generation a v0.2 writer
sealed. `FormatVersion` did not change, so the old binary has no polite way
to say "newer format": expect the signature error, and read it as version
skew rather than as tampering.

That was chosen deliberately. Stamping only the disaster-recovery backup
would have kept old mounts working, and an old `pelfs gc` would then have
mounted the volume, failed to verify the new backups, read them as absent,
reported a short retain window and collected what those generations alone
named. A loud refusal beats a quiet deletion.

#### 5. Ordering constraint: merge before rotate

A branch pins its merge base with a `fork-<branch>` tag, because the base
stops being any branch's head the moment the source branch seals again.
Every tag stops verifying across a key rotation, permanently, and
`pelfs tag` can only freeze a branch HEAD — so a fork point cannot be
re-pinned once it is unreadable. **A rotation therefore makes a pending
merge impossible, with no repair afterwards.** `pelfs rotate` names the
affected branches and their pinning tags before it writes anything, and
`--break-siblings` is what lets you past the refusal. If you have branches
to merge, merge them first.

#### 6. `--prefetch` moves packs, not decoded chunks

"I want the data local" now means the generation's *packs* are local, which
is what a read is served out of anyway. It used to pull every chunk through
the read path — decompressing, decrypting and writing one plaintext file
per chunk — so a prefetch cost a full decode of the volume up front plus a
second copy of it on disk, for a decode the mount then repeated later
anyway whenever a chunk file had been evicted. Strict mode's contract is
unchanged: it still refuses to start unless everything is local, and the
check is now that every referenced pack is cached and length-verified.

Two refusals are new, and both happen before any payload moves: a
generation whose pack set exceeds the local cache budget is declined with
both numbers rather than fetched and evicted piece by piece, and a mount
with whole-pack caching turned off (a negative `PackCacheBytes`) reports
that a prefetch is impossible rather than warming nothing.

#### 7. One v0.1.0 state directory this release will refuse to write

If a v0.1.0 writable session was **interrupted** — `kill -9`, `--no-seal`,
a failed seal — after it had partially overwritten a file the base
generation already held, and before the checkpoint that would have
published that write, then `pelfs mount-gen --rw` on that state directory
refuses to start here.

The reason is the fix described under *Fixed* below: a partial write to a
published file ADOPTS it by reference, and v0.1.0 journalled the adoption
as "handle H came from inode N" on the reasoning that an immutable
generation can always be asked for N's records again. It cannot — a mount
that has just started has descended nothing, so nothing is resident. This
release writes the chunk identities down at adoption time, and it refuses
rather than guess for a state directory that has none: those extents' bytes
are published and immutable, and dropping them would write zeros over live
content at the next seal.

The refusal names every affected inode at once and says what it costs. What
is still readable is everything the volume ever published, including the
last checkpoint's generation — mount without `--rw`, or `pelfs fsck` it. To
start writing again, move `<state-dir>/content` and the overlay directory
aside, or use a fresh `--state-dir`; that discards what was written after
the last checkpoint and nothing else.

A v0.1.0 state directory whose adoption WAS published is unaffected: the
handle is one no surviving row names, and it is now silently dropped.

### What's new

- **`pelfs merge` — bring one branch into another.** Report-first like
  `repack` and `rescue`: the default says what would come from each side
  and names every path it cannot resolve; `--apply` carries it out. A
  fast-forward publishes the other side's tree directly. A diverged merge
  builds one, three-way over the catalogs, and **reads no file content** —
  both sides are already chunked, so the merged tree is handed to publish
  as a `ContentProvider`, the chunkrefs point into the packs that already
  hold the bytes, and the merged generation names both sides' packs with an
  index that covers what came from the other branch.

  It finds its own base. `pelfs branch` now records the generation a branch
  was cut from and pins it with a tag (`fork-<branch>`), because naming a
  base is not enough to make one readable: the moment the source branch
  seals again, the fork point stops being any ref's head. A base named by
  hand is verified against that record, so a wrong one is refused rather
  than silently mis-attributing every change.

  Conflicts refuse by default and are listed with the reason.
  `--keep-both` is the other choice: ours keeps its name, theirs is written
  as `name (from <branch>).ext` — the suffix goes before the extension so
  the file still opens. Nothing is lost and nothing cleans the copies up,
  which is why it is opt-in. It refuses what it cannot duplicate: a
  modify/delete has one version, so "both" would mean resurrecting a
  deleted file under a name nobody chose.

- **The inode space is partitioned by branch**, which is what makes merging
  possible at all. A branch takes its own slice — 23 bits of lineage above
  a 40-bit allocation space, 63 bits in all so that every inode still fits
  a signed 64-bit integer — so two branches can never assign one number to
  two files. Lineage 0 is every volume that predates this.

  A pair of branches cut before lineages existed cannot be merged as they
  stand. `pelfs merge` reports the colliding inodes and the number one side
  must be shifted above, and refuses to apply; **there is no renumbering
  tool in this release**, so that is a report and not yet a path.

- **`pelfs rescue` — rebuild a volume's refs from its packs.** The
  operation the format was built for and never had: `refs/<branch>` is the
  only mutable object, so it is the only one that can be lost, and
  everything needed to replace it is already in the packs — typed entries,
  self-identifying catalogs, and a signed superblock backup from every
  seal. Report-first; `--apply` re-points the refs; **it never deletes
  anything.**

  Safety, since this is trust-boundary code run in a panic. Every scavenged
  backup is VERIFIED against the pinned key or an explicit
  `--volume-pubkey` — a pack is appendable by anyone with write access, so
  a rescue that trusted a planted backup would be the attack.
  Non-verifying documents are reported, never used, and trust-on-first-use
  is not available: with no key the answer is an error, not a new pin.
  Ambiguity is presented, never auto-picked — two verifiable candidates for
  one head is both a legitimate state and what a rollback looks like, and
  `--pick <id>` is how you decide. A candidate whose pack set will not
  resolve is skipped WITH A REASON and the walk falls back a generation,
  rather than offering a head that names fewer packs than it needs.
  `--apply` needs the signing key; the report does not.

- **`pelfs rotate` — replace the volume signing key.**
  `superblock.NextPub` has been verified since v0.1.0 and set by nothing,
  so the format could describe a rotation and no tool could start one.

  A rotation is two generations per branch — one announcing the successor,
  signed by the current key, and one signed by the successor — published by
  a single command, because nothing carries an announcement forward and
  leaving the second half to "whatever seals next" is a silent race. Both
  generations are content-neutral: no pack, no catalog, no change to what
  the volume holds.

  Report-first, and read the report. Three consequences, each stated before
  anything is written:

  - **A reader only follows a rotation if it observed the announcement.** A
    pin advances by exactly one lineage step, so a client whose recorded
    generation predates the announcement refuses the new head. Hence
    `--announce-only`: publish the announcement, wait past your readers'
    poll interval, then finish with `--apply`. A client that misses the
    window needs `--volume-pubkey` or a cleared state directory.
  - **The pin is per VOLUME**, so the default rotates EVERY branch to one
    successor key; narrowing with `--branch` requires `--break-siblings`.
  - **Every existing tag stops verifying, permanently** — a tag is
    immutable and takes no chain step. `--break-siblings` covers this too,
    and the retired key is archived read-only as
    `v2-signing.key.retired-<pub8>` precisely so `--volume-pubkey` can
    still read old tags.

  See *Upgrading* for the fourth consequence, which is an ordering rule:
  merge before you rotate.

  Crash safety: a rotation interrupted anywhere is resumable or abortable
  and never leaves a volume whose next seal cannot be signed. Re-running
  adopts the successor already minted instead of generating a second one;
  `--abort` retracts an announcement that has not been used; and an
  interrupt between the final flip and the local key promotion is repaired
  by the next seal, through the one key resolver every writer shares.

- **`T_grace` is a per-volume parameter, and now it really is one.** It was
  recorded in `Params.TGraceSeconds`, written from a compiled-in 72 hours,
  and the sweep FLOORED its own window at the same constant — so a volume
  that recorded twelve hours was swept at seventy-two, and the
  documentation calling it configurable was describing a field nothing
  read. `pelfs init --grace 12h` sets it, with a one-hour floor; every
  later seal carries the RECORDED value forward; and the sweep, the repack
  planner and all three condemned ledgers age against it. `pelfs gc
  --grace` is unchanged and may still only WIDEN — an option that could
  narrow the window is an option to delete a concurrent writer's packs.
  `pelfs gc` prints the window it applied.

  **A large window buys less than it looks like it buys**, and
  `pelfs init --grace` says so when the value you pass collides. The two
  derived-ref ledgers gain about a row per checkpoint per key space against
  a 48 KiB cap, which is 517 hash-named rows, so past
  `517 x checkpoint-interval` the byte cap binds before the window does:
  the volume behaves as though its window were that long and repacks pace
  to the room left. At the 5-minute `--snapshot-interval` default that is
  ~43 hours — the 72-hour default is already past it, and `--grace 30d` is
  past it forty-fold. Nothing a branch head or tag names is affected; what
  is shortened is the window for objects only a RETIRED generation names,
  and a workflow that needs a real pin should tag.

- **The retain window no longer over-retains on a multi-branch volume.** A
  superblock now records the ref it was sealed onto (`Branch`), which is
  what a scavenged disaster-recovery backup was missing: a generation
  NUMBER counts steps along one lineage, so both children of generation N
  seal N+1 and their backups were indistinguishable. v0.1.0 answered by
  keeping EVERY candidate for a wanted number — safe, but it meant one
  branch's window carried the other's manifests, indexes and packs, and the
  scan could never stop at the first complete answer.

  With `(branch, generation)` an identity, a generation resolved from a
  backup this branch sealed drops the siblings, and the scan stops as soon
  as every generation in the window has one. On the two-branch fixture in
  `internal/retention/branches_test.go` — main nine generations deep, dev
  five, at `--retain-k 3` — the retained set falls from 29 objects to 25;
  on an equal-depth fork of the same shape the window scan reads 3–4 pack
  trailers of 15 where it previously read all of them.

  **Attribution cannot cover everything, so the old rule survives per
  generation.** A branch's window reaches back past its own fork point, and
  those generations were sealed by the parent branch and say so — they are
  the branch's history all the same — as are any backups written before the
  field existed. Both keep every distinct candidate, and only those
  generations do, so an upgraded volume gets the tight rule for its new
  history and the conservative one across the legacy span until it has
  sealed K more times. `pelfs gc` says which rule each window used:
  `retain window:    branch dev keeps 6 of 8 generations (attributed, 3
  legacy candidates kept for 3 generation(s))`.

  A repack now also stamps the branch it publishes onto rather than
  inheriting the parent's — `pelfs branch dev` copies main's head verbatim,
  so a repack can be the first writer a branch ever has. It writes no
  backup either way; the generation a repack grew from is covered by the
  condemned-ledger floor, as before.

  **What is still not fixed:** a branch NAME is not a lineage. Delete
  `dev`, recreate it from an older generation and seal the same numbers
  again, and the two incarnations collide exactly as two branches used to.
  The newest-first scan favours the live one, and a repack that copied an
  old backup into a new pack can defeat that. Tag a generation to pin it
  exactly.

- **A repack retires index segments whose packs are mostly gone.** The
  planner has measured this since indexes were tiered and the executor
  ignored it, so a segment written for packs a later repack condemned went
  on being listed, fetched and windowed through forever — spending its
  bytes on entries that resolve to nothing. Under 50% live pack coverage a
  repack now drops the segment, **re-emits the entries it still answers
  for** into the segment it was writing anyway, and condemns the old object
  through the existing condemned-index ledger, which `pelfs gc` already
  honours — so it survives the grace window for readers pinned to the
  generation before the repack.

  Re-emitting is the half that matters: an index is derived, so dropping
  one costs only fetch time, but dropping one whose surviving packs nothing
  else indexes sends every lookup of those identities down the pack-trailer
  fallback — a cleanup that makes cold reads slower. Coverage is preserved
  and only the dead share is discarded. Retirement is **paced by the
  ledger**, exactly as pack condemnation is: what has no room for a row is
  left listed for a later run rather than dropped with nothing to speak for
  it. Manifest segments are unchanged, since a repack rewrites the manifest
  whole and condemns its segments together.

- **The decoded-chunk cache is one file, not one file per chunk.**
  `gencache/chunks/` held a plaintext file per chunk the mount had ever
  read — an inode and a flat directory entry each, with no upper bound on a
  real volume. It is now `gencache/chunks.arena`: one preallocated, mmap'd
  file with an in-memory index that is never written down, and a default
  size of 256 MiB capped at an eighth of the cache budget (previously the
  tier was unbounded except by the shared budget). Space is allocated by
  bump cursors that WRAP, so allocation is O(1) and there is no
  fragmentation to manage; wrapping over live chunks is the eviction. There
  are two cursors rather than one — a probation region of a sixteenth and a
  protected region for the rest, with a ghost table promoting a chunk that
  is read again — because plain FIFO thrashes as soon as the volume does not
  fit in the mapping.

  It is faster as well as smaller. With the tier off entirely, a cold scan
  of a 166 MiB source-shaped tree costs 0.89 s, a hot re-read 0.89 s and
  twenty thousand scattered 4 KiB reads 1.43 s; the arena serves the same
  three in 0.55 s, 13 ms and 32 ms — 1.6x on the cold scan and 68x on the
  re-read. (Reproducible: `PELFS_CHUNKCACHE_BENCH=1 go test
  ./internal/genfs/ -run TestChunkCacheWorkloads`. The absolute numbers are
  the owner's laptop, macOS/arm64; the ratios are the point.) It also beats
  the flat directory it replaces, which won on re-reads and lost on fills,
  because an arena fill is a memcpy into a mapping.

  `ChunkArenaBytes` negative turns the tier off, which is also what a
  volume whose plaintext must not touch local disk wants — as with the
  chunks directory before it, the arena holds DECODED bytes. The arena's
  size is reported by `pelfs cache` and in the statistics file under
  `cache.dirs.arena`, and `cache.chunk_hits` / `cache.chunk_misses` say
  whether it is the right size for the workload.

- Two cache-reporting bugs found on the way. `CacheUsage` returned zero
  eviction counters whenever it had to rescan, so "has this cache been
  evicting" was answerable only by luck; and a mount opened with a smaller
  budget than the last one inherited the previous arena reservation without
  agreeing to it.

- **`pelfs branch --rm` says what the fork pin is still holding.** Deleting
  a branch left its `fork-<branch>` tag behind in silence, so the space did
  not come back and nothing said why. The pin outliving the branch is
  correct — a merge may still need that generation — so the deletion now
  names the tag, the generation it pins, and the command that releases it.

### Fixed

- **A file could be visible under two names after a mid-session
  checkpoint.** Create a file and rename it inside one session, with a
  checkpoint sealing between the two, and both names resolved. Whether a
  name has been removed is decided by asking whether the base has it — and
  a checkpoint changes what the base is. The order is freeze, seal, swap,
  rebase, and the seal is seconds of network work with the mount still
  serving; for that whole window a name created before the freeze is in the
  instant being published but not yet in the mounted base, so it was in
  neither place the overlay looks. Nothing repaired it afterwards. A name a
  frozen-but-not-yet-rebased snapshot is publishing now counts as a base
  name from the moment it is frozen. **The window reached every removal,
  not just rename** — unlink, unlink of one of two hardlinks, rmdir, rename
  onto an existing name and rename between two parents were all reproduced
  and are all fixed together. It had a scale symptom too: a ghosted
  directory is reachable under two names, the seal descends it under both,
  and its entry list doubles per checkpoint.

- **Removing one name of a hardlinked file decrements its link count.** It
  did not, when the file was one the base generation already held: the
  write overlay had no row for a clean inode, so it wrote the whiteout for
  the removed name and left the count alone. The wrong count was
  **published**, not merely served — a cold mount of the sealed generation
  saw `nlink 2` for a file with one name — and it never converged, because a
  later write seeded its row from the same stale value. Nothing downstream
  corrected it: the seal recomputes a link count from surviving edges for
  DIRECTORIES, whose count is a function of the namespace, while a file's is
  a stored attribute, and the stored attribute was the stale one.

  The count is now decremented where the name is removed, and only when
  names survive — the last name still costs exactly one whiteout, so
  removing a published tree is unchanged (`BenchmarkOverlayUnlinkCleanFile`
  on the owner's laptop: allocations identical at 5,430 B/op and 142
  allocs/op, time within run-to-run noise).

  Beyond the wrong number, a file that is falsely hardlinked keeps its
  content records in an inode SHARD and marks its catalog as holding a
  promoted inode, which stops that whole subtree from ever being skipped by
  a later seal. Stale counts therefore made incremental seals monotonically
  more expensive. Found by the hostile exerciser's random lane, and proven
  to have reached published bytes by the phase that compares the sealed
  generation cold.

- **`ln` works on a file an earlier session published.** Hard-linking such
  a file on a writable FUSE mount failed with `overlay: no base provenance
  for inode N` — EIO at the `ln` — once the current session had edited it
  and a checkpoint had published the edit. Mount a state directory, open a
  file that was already there, change it, keep working, then hard-link it:
  that was enough. Nothing was lost or corrupted; the operation refused.

  The cause was a memory fix reaching further than intended. `link(2)` is
  the only namespace operation that names its source by **bare inode** and
  resolves no name, so the write path only hears about the file if
  something else looked it up first. That was always true and never
  mattered, because the cache of descent steps it consults was emptied by
  nothing — until checkpoints began sweeping it for everything they
  published, to bound a map that otherwise grows for the life of a session.
  A cache miss that had been declared impossible became ordinary, and the
  kernel's directory-entry cache is what decides whether a lookup refills
  it: the entry a mount stamps for a file it has not touched is valid for
  ten years, so an edit does not un-cache it and no lookup precedes the
  link.

  The miss now asks the base generation, which holds the same step for
  every inode a descent has reached — so the sweep keeps its bound and the
  link succeeds. An inode nothing ever looked up still gets `ESTALE`, which
  is the honest answer and is not reachable from a mount. The path
  frontends were never affected: NFS resolves `link` by path.

- **A state directory can be mounted for writing more than once.** Four
  ordinary operations left one that no writable mount would ever open
  again: write a file, let a checkpoint publish it, overwrite part of it,
  let a second checkpoint publish that. The next `pelfs mount-gen --rw`
  exited 1 before mounting, and it was not one file — the volume could not
  be written from that state directory again.

  A partial write to a published file **adopts** it from the base
  generation by reference rather than copying it, and the adoption was
  journalled as "handle H came from inode N", on the reasoning that an
  immutable generation can always be asked for N's records again. It
  cannot. The base a later mount serves is a LATER generation, and a
  generation answers for an inode only after a descent has made it
  resident — a mount that has just started has descended nothing. So the
  adoption's records are written down now, at adoption time, and recovery
  reads them instead of asking anything outside the state directory. They
  are chunk IDENTITIES, which are content-addressed and survive a repack; a
  pack location would not have.

  The four-op sequence had a second cause, and it is why the second
  checkpoint was needed: publishing an adopted file rebases the inode
  clean, which forgets its content, so the handle recovery refused over was
  one no surviving row named — and one recovery itself would have discarded
  moments later. Nothing that no row names is resolved at all now.

  The same refusal also met **every remount of an interrupted session** that
  had adopted a file — `kill -9`, `--no-seal`, a failed seal — which no
  test saw, because the existing crash test reopens the content store
  against the same live generation handle and inherits residency a real
  remount does not have. Both are pinned by ordinary-lane tests now, and
  the exerciser's corpus entry for the sequence is a passing regression.
  What is left is one honest refusal, for a state directory written by a
  build that recorded no adoption records — see *Upgrading*, item 7.

- **A lost flip is no longer silent.** The ref flip is check-then-put,
  because the transports have no `If-Match`. That was documented; how a
  lost race LOOKED from inside was not — both writers' puts succeeded, both
  flips returned nil, and one generation simply ceased to exist. No branch
  named it, so its packs became garbage nobody had asked to collect, and
  the writer that lost went on to report a generation that was not on the
  branch. Both flip paths now read the object back and compare bytes. It
  prevents nothing; it turns a silent loss into `pelicanobj.ErrClobbered`,
  surfaced as `refs.ErrFlipClobbered` and naming the generation that won.

- **A seal asks whether the branch is still ours.** Lease detection was
  partial and enforcement was absent, and a laptop that sleeps for hours
  manufactures exactly the concurrent-flip window the lease exists to
  prevent. The come-and-gone case left no witness at all: another writer
  takes the expired lease, seals, and releases — and a release DELETES the
  object — which the renewal loop read as "someone deleted our lease,
  reclaim it". A seal is now fenced against the lease, a session that
  wakes up revalidates, and a usurper that has been and gone is detected.
  The statistics file records `lease_interrupted` and
  `lease_revalidated_at`. `--no-lease` is unchanged in effect and its help
  text now says what it costs: concurrent writers are not detected and
  seals are not fenced, so publishing rests entirely on the flip's
  compare-and-swap against the branch head.

- **The lease holder is whoever the record says.** A transient federation
  error on a renewal could make a mount decide it had lost the lease,
  latch `conflicted` for the rest of the session, refuse every seal — and
  name ITSELF as the thief in the message. Ownership is now decided by the
  session the record names, not by an ETag that failed to match.

- **A state directory cleans up after a session that was killed.** Every
  operation that spools to local disk before it uploads — a seal building
  packs, a checkpoint's frozen overlay, a repack rewriting packs — left its
  scratch behind when the process died, and nothing ever collected it: the
  one sweeper a mount ran emptied `trash`, and all three scratch families
  live in the state directory's root. So a `kill -9` mid-seal cost a seal's
  worth of packs, permanently, per crash. A repack leaked its spool with no
  crash at all — the cleanup fired only when `repack.Execute` had made the
  directory itself, and both callers supply one — which, with a writable
  mount now repacking by itself, turned from a manual-command footgun into
  something every writable volume did on its own.

  Scratch directories now carry the pid of the process that made them, and
  every mount collects the ones whose owner is no longer running.
  **Ownership is asked of the OS, not of the lease:** a lease says who
  should be writing and stands until it expires, so a killed holder's
  scratch is exactly what must go, while a read-only mount or a
  `pelfs repack` on another branch is a live process with no writable lease
  whose spool must not. See *Upgrading*, item 3, for the naming and the age
  guards. A repack's spool is now a per-run subdirectory removed on every
  exit from `Execute`, success or failure.

- **A seal after a repack still deduplicates.** The local dedup index that
  lets a seal skip re-uploading content the volume already stores is valid
  only for the generation it was written against — and a repack published a
  new generation without restamping it, so the whole file was silently
  ignored and the first seal after any repack re-uploaded everything it
  would have deduplicated. On the fixture in
  `internal/repack/dedup_test.go`, a 3 MiB file already sitting in a pack
  the generation lists cost 3.15 MiB back on the wire before the fix and
  4 KiB after.

  The same rewrite fixes the second half — the index never dropped an
  entry, so it also grew without bound over a volume's life, carrying rows
  for chunks nothing references any more. A repack already computes exactly
  which chunks are live, so it now writes the index with that set and
  stamps it with the generation it published. Both halves are one operation
  on purpose: restamping without filtering would promise the next seal that
  chunks the repack has just dropped are still stored.

### Scale

Unchanged as a design target — volumes of order a hundred million objects —
and unchanged in what is actually proven end to end. CI still untars
**62,500 files** (50,000 distinct plus 12,500 hard links to them,
small-file shaped at ~900 bytes each, ~45 MB of content) through *both*
frontends, real FUSE and a real kernel NFS client, then diffs the whole
tree through the live mount, seals it, cold-mounts the published generation
into a state directory that never existed before and diffs it again, runs
`fsck --deep` and `gc`, and publishes a **second generation** carrying an
add, a modify and a delete which is cold-mounted and diffed once more. The
untar's per-chunk rate and the NFS client's RPCs per created file are
bounded rather than merely reported. Separately, a mount is `kill -9`'d
mid-flush after writing 384 MB, remounted, and held to the recovery
contract.

Two memory structures changed for the better and one is honestly still
open. The decoded-chunk tier is now bounded by construction rather than by
a shared budget (above). The read path's resident pack-location map is
capped at 131,072 entries; **two callers still opt out and hold every
location** — `FS.ContentOf`, which protects the "present in no listed
pack" verdict and is reachable from an ordinary write's copy-up rather than
only from a seal, and `FS.Prefetch`. At the design target that is the
largest resident structure in the tree. It is tracked as KI-8 in
`docs/known-issues.md`; the sorted, mmap'd spill table it needs exists
(`internal/extsort`, built for `fsck` and the reachability sweep) and is
simply not wired in.

Between the 62,500 files CI proves and the hundred million the format is
built for there is design and unit-level evidence, and no end-to-end run.
`make big-tree` takes a file count on the command line, and
`PELFS_BIGSEAL=1 PELFS_BIGSEAL_FILES=…` runs the seal-cost rig over bigger
trees; those numbers are nobody's guarantee.

### Known limitations

- **A volume nobody mounts writably is never maintained.** Maintenance
  rides the mount, because that is what holds the branch's write lease and
  knows when the volume is idle. `pelfs gc --delete` and `pelfs repack
  --apply` remain the answer for a volume that is only ever read.
- **The retain window is only as good as the superblock backups.** A
  retired generation has no address, so the sweep reconstructs it from the
  disaster-recovery superblock every seal buries in its last pack. Repack
  carries those backups forward, so ordinary maintenance keeps them; a pack
  collected by a sweep from before v0.1.0's retention work took its backup
  with it, so early sweeps on an old volume may report a short window.
  That is reported and warned about, never silently assumed.
- **A branch NAME is not a lineage** (above, and KL-3 in
  `docs/known-issues.md`). Tag a generation to pin it exactly.
- **Two branches cut before inode lineages existed cannot be merged.** The
  merge names the collisions and the number to shift above; no tool
  performs the shift (KL-7).
- **A key rotation makes a pending merge base permanently unreadable.**
  Merge first. There is no repair, by design — see *Upgrading*, item 5, and
  KL-1.
- **A large grace window is paced by the condemned ledgers**, not by the
  window (above).
- **Permission enforcement is fidelity, not access control.** The NFS
  export is loopback and single-user and every request is evaluated as the
  server process's own identity; the AUTH_UNIX credential is not
  consulted. Do not treat a pelfs NFS export as a multi-user boundary.
- **The exit drain is unbounded and cannot be interrupted.** A mount asked
  to exit while a checkpoint is in flight waits for it, with no deadline
  (KL-2).
- The origin must permit GET/PUT/DELETE and listing on the prefix; `pelfs`
  checks this up front and names the missing scope.

Open defects that are found and not fixed are tracked in
`docs/known-issues.md`, and every entry there says whether an executable
test pins it.

### What a failure looks like

A seal that cannot reach the federation loses nothing: the overlay is left
intact, the branch does not move, and the next mount of the same prefix
resumes it and seals again. This is tested, including the reopen-from-disk
half.

A seal that has LOST its branch — because another writer moved the ref, or
took the lease while this session was asleep — now refuses rather than
publishing into a fork nobody names. That refusal is
`refs.ErrFlipClobbered` or a lease fence, and it names what won.

Anything `fsck` or the reachability sweep cannot read, decode or account
for makes the result *incomplete* rather than partial — every affected pack
is reported fully live, and `repack-plan` refuses to plan at all. A pack
wrongly called dead is data loss; a pack wrongly called live costs bytes
until the next sweep. The tools are not symmetric about those two. The
automatic sweep inherits all of this unchanged: any ref or tag it cannot
verify aborts the run and deletes nothing.

### Verified by

`make test` (unit and CLI, including a model-based random test of the write
path), `make e2e` (a full mount loop in a container against a fake origin),
`make mount-gate` (the kernel mount gate: real FUSE and a real NFS client,
both required, and now including a permission gate that extracts a
read-only tree with `tar -p` over a real kernel NFS client and requires
every permission answer to match the same probe on a local tree, on both
backends), `make big-tree` (the 62,500-file scale gate described under
*Scale*), `make crash` (`kill -9` of a mount mid-flush, then recovery,
`fsck --deep`, and a check that the killed session's scratch was
reclaimed), `make opfuzz` (the overlay op-sequence fuzzer, in a sealed
container), and `make integration` (transport and publish/resolve against
a federation-in-a-box).

New in this release, and the reason several of the fixes above exist:

- **`make hostile` — the impolite user, continuously.** Adversarial op
  sequences against a REAL mount on BOTH frontends, with a reference tree
  on tmpfs mutated identically and compared byte-and-metadata-exact at 1 s
  checkpoints; then the whole lifecycle (seal, cold remount, full compare,
  `fsck --deep`, `gc`), a second WRITABLE session over the generation the
  first one published, and a `kill -9` with remount and recovery. Contained
  the way `opfuzz` is and then some: a build tag, an env gate, an image
  sentinel, `os.Root` confinement proven before the first op, and a
  container whose only host-visible path is a read-only directory of two
  binaries. Every correctness bug in the v0.1.0 release week was found by
  the owner's ordinary shell usage and none by a gate, because every other
  gate writes polite tar-shaped data. Six findings are pinned as executable
  plans under `internal/hostile/testdata/corpus/`, all of them now
  regressions that must pass. CI runs the corpus and a fixed-seed campaign,
  plus the corpus again against ENCRYPTED volumes — where a chunk is
  compressed and THEN sealed, so no entry in any pack is the length of its
  plaintext.
- **The whole suite under `-race`, over the whole tree.** Only the
  op-sequence stress was raced before, which left the memtable's promotion
  against its writers, genfs's caches, the overlay's checkpoint against
  reads, and both frontends serving in parallel checked by nothing. It has
  already caught one data race in shipped code.
- **CI runs on tags**, which it did not before — so the one commit anyone
  will ever look up, the one a release was cut from, is no longer the one
  commit nothing checked. The release job waits on every gate above.
- **`make e2e` is a CI job.** v0.1.0's notes said it ran on every push; it
  did not.

The parser fuzz targets carry a committed corpus under each package's
`testdata/fuzz/`, which an ordinary `go test` replays. Cost-attribution
benchmarks — the tmpfs floor, the overlay without a kernel, the FUSE op
mix, the decoded-chunk cache workloads — live in `scripts/bench-*` and
behind `PELFS_*` env gates, and are stopwatches, not gates.

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
  is a v0.2 change. *(Done — see v0.2.0. The record of what v0.1.0
  shipped stands; a v0.1.0 client still locks the whole volume, and how the
  two versions interact is described there.)*
- **Two branches that have diverged stay diverged.** There is no merge, and
  none is planned for this release. What exists is branching, tagging and
  deleting. *(Done — see v0.2.0. The record of what v0.1.0 shipped
  stands: a v0.1.0 branch has no fork record and no inode lineage of its
  own, so merging one needs its inodes renumbered first.)*
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
