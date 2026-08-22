# Changelog

## Unreleased

### Added

- **`pelfs merge` — bring one branch into another.** Branches could diverge
  and never come back; the reason given was the inode space, and that is
  fixed at the fork rather than at the merge (below).

  Report-first, like `repack` and `rescue`: the default says what would come
  from each side and names every path it cannot resolve. `--apply` carries it
  out. A fast-forward publishes the other side's tree directly; a diverged
  merge builds one, three-way over the catalogs, and **reads no file
  content** — both sides are already chunked, so the merged tree is handed to
  publish as a `ContentProvider` and the chunkrefs point into the packs that
  already hold the bytes. The merged generation names both sides' packs and
  its index covers what came from the other branch.

  It finds its own base. `pelfs branch` now records the generation a branch
  was cut from and pins it with a tag (`fork-<branch>`), because naming a
  base is not enough to make one readable: the moment the source branch
  seals again, the fork point stops being any ref's head. A base named by
  hand is verified against that record, so a wrong one is refused rather
  than silently mis-attributing every change.

  Conflicts refuse by default and are listed with the reason. `--keep-both`
  is the other choice: ours keeps its name, theirs is written as `name (from
  <branch>).ext`, with the suffix before the extension so the file still
  opens. Nothing is lost and nothing cleans the copies up, which is why it
  is opt-in. It refuses what it cannot duplicate — a modify/delete has one
  version, so "both" would mean resurrecting a deleted file under a name
  nobody chose.

- **The inode space is partitioned by branch**, which is what makes merging
  possible at all. A branch takes its own slice — the top 23 bits of an
  inode name the lineage, the low 40 the allocation — so two branches can
  never assign one number to two files. Lineage 0 is every volume that
  predates this. A branch cut before this existed can still be merged, but
  its inodes have to be renumbered first, and `pelfs merge` reports the
  collisions and the number to shift above.

- **`pelfs rescue` — rebuild a volume's refs from its packs.** The operation
  the format was built for and never had: `refs/<branch>` is the only mutable
  object, so it is the only one that can be lost, and everything needed to
  replace it is already in the packs (typed entries, self-identifying
  catalogs, and a signed superblock backup from every seal).

  Report-first, like `repack`: the default lists, per branch, what the ref
  holds now, which generation is recoverable and out of which pack, and
  whether that generation's root catalog can actually be found. `--apply`
  re-points the refs. **It never deletes anything.**

  Safety, since this is trust-boundary code run in a panic:
  - Every scavenged backup is VERIFIED against the pinned key or an explicit
    `--volume-pubkey`. A pack is appendable by anyone with write access, so a
    rescue that trusted a planted backup would be the attack. Non-verifying
    documents are reported, never used, and trust-on-first-use is not
    available — with no key, the answer is an error, not a new pin.
  - **Ambiguity is presented, never auto-picked.** Two verifiable candidates
    for one head is both a legitimate state and what a rollback looks like;
    `--pick <id>` is how you decide.
  - A candidate whose pack set will not resolve is skipped WITH A REASON and
    the rescue falls back a generation, rather than offering a head that
    names fewer packs than it needs.
  - `--apply` needs the signing key; the report does not.

  Three things had moved since the design specified this, all recorded in
  `docs/design-packfs.md`: a backup cannot name the pack that CARRIES it
  (which is where the root catalog usually is, so the rescuer supplies it —
  and a rescue therefore recovers the full newest generation rather than
  "minus its tail"); a rescue must RE-SIGN rather than flip the backup's
  bytes; and the per-file damage report is deliberately left to
  `pelfs fsck --deep` instead of being reimplemented.

- **`pelfs rotate` — replace the volume signing key.** `superblock.NextPub`
  has been verified since v0.1.0 and set by nothing, so the format could
  describe a key rotation and no tool could start one. Now one can.

  A rotation is two generations per branch — one announcing the successor
  (signed by the current key), one signed by the successor — published by a
  single command, because nothing carries an announcement forward and
  leaving the second half to "whatever seals next" is a silent race. Both
  generations are content-neutral: no pack, no catalog, no change to what the
  volume holds.

  **Report-first, and read the report.** Three consequences, each of which
  the command states before acting and refuses to skip past:
  - **A reader only follows a rotation if it observed the announcement.** A
    pin advances by exactly one lineage step, so a client whose recorded
    generation predates the announcement refuses the new head. Hence
    `--announce-only`: publish the announcement, wait past your readers'
    poll interval, then finish with `--apply`. A client that misses the
    window needs `--volume-pubkey` or a cleared state directory.
  - **The pin is per VOLUME**, so the default rotates EVERY branch with one
    successor key; narrowing with `--branch` requires `--break-siblings`.
  - **Every existing tag stops verifying, permanently** — a tag is immutable
    and takes no chain step. `--break-siblings` covers this too, and the
    retired key is archived read-only (`v2-signing.key.retired-<pub8>`)
    precisely so `--volume-pubkey` can still read old tags.
  - **MERGE FIRST, THEN ROTATE.** A branch pins its merge base with a tag,
    because the base stops being any branch's head as soon as the source
    seals again; `pelfs merge` reads it through that tag. A rotation
    therefore makes a pending merge impossible, with no repair afterwards —
    `pelfs tag` can only freeze a branch HEAD, so a fork point cannot be
    re-pinned once unreadable. `pelfs rotate` names the affected branches
    before acting.

  Crash safety: a rotation interrupted anywhere is resumable or abortable and
  never leaves a volume whose next seal cannot be signed. Re-running adopts
  the successor already minted instead of generating a second one;
  `--abort` retracts an announcement that has not been used; and an interrupt
  between the final flip and the local key promotion is repaired by the next
  seal, through the one key resolver every writer shares.

### Changed

- **The NFS frontend enforces file permissions.** It enforced none. A file
  chmod'd 0444 accepted a write through an NFS-backed mount and the bytes
  survived the seal; through FUSE the same write was refused with EACCES,
  because that mount asks the kernel to check (`default_permissions`) and
  NFSv3 puts the check on the server, where nothing performed it. Two
  frontends over one filesystem answered the same question differently, and
  which mount flag you used decided whether your own mode bits meant
  anything. Found by the hostile exerciser; pinned by a regression entry in
  its corpus.

  The model is now applied in `internal/vfsbilly`: mode bits by class
  (owner, else group, else other, first match deciding), write and search on
  the parent directory for anything that creates or removes a name, the
  sticky-bit rule, search permission on every path component, and ownership
  for `chmod`/`utimes` — with `CAP_CHOWN` for a `chown` and `CAP_FOWNER`,
  `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` where the kernel would honor
  them. It is EPERM where the kernel says EPERM and EACCES where it says
  EACCES.

  **Whose permissions**: the mount's own. The export is loopback and
  single-user, so every request is evaluated as the identity that started
  the server — uid, gid, groups and capabilities, translated through the
  same id map that decides whose name the mount puts on a file. The
  AUTH_UNIX credential in each NFS request is deliberately not consulted:
  any local process can claim any uid over loopback, so honoring it would
  make the check look like a security boundary, which it is not. This is
  fidelity — the same answer through both frontends — and not access
  control.

  **What can still surprise you**, and it is written down rather than left
  to be discovered: `access(2)` and `test -w` are answered by an ACCESS RPC
  that go-nfs replies to without consulting the mode, so they still say
  "writable" for a file the write path will refuse, and a read-only file
  created and then written through one file descriptor — `tar -p` extracting
  a 0444 file — fails on the write over NFS where FUSE allows it. Both need
  a change in the go-nfs fork; see `docs/go-nfs-patches.md`.

- **The write lease is per branch.** It was `meta/lease.json`, one object
  for the whole prefix, so two writable mounts on DIFFERENT branches of one
  volume refused each other though they could never touch the same ref —
  the v0.1.0 limitation that shipped with `pelfs branch` and a warning
  attached to it. The key is now `meta/lease-<branch>.json`: writable
  mounts of `main` and `dev` run concurrently and both seal, and only a
  second writer on the SAME branch is refused, still naming the holder.

  Nothing about the guarantee changed, and that is worth being clear about.
  The lease was always advisory DETECTION and not mutual exclusion — the
  transport has no compare-and-swap, and what actually prevents two writers
  corrupting each other is the seal's refusal to publish over a ref that
  moved. A per-branch key removes a FALSE exclusion; it adds no safety.

  `pelfs status` now prints which lease object a session holds, the
  statistics file records it as `lease_key`, and `pelfs ctl <mount> status`
  reports `lease_key`.

  **Mixed with a pelfs v0.1.0 client**, the rule is asymmetric on purpose:

  | writer | excluded by | excludes |
  |---|---|---|
  | v0.2 on branch B | a live `meta/lease.json` (any v0.1.0 writer), and a live `meta/lease-B.json` | v0.2 writers on B only |
  | v0.1.0 (any branch) | a live `meta/lease.json` | every v0.1.0 writer on the volume — and nothing else |

  A v0.2 writer reads `meta/lease.json` and refuses while one is live,
  naming the holder, because a v0.1.0 record does not say which branch it
  is on. It never WRITES that object: doing so would make two v0.2 writers
  on different branches exclude each other through the legacy key again.
  The consequence, stated rather than hidden: **a v0.1.0 client sees a v0.2
  writer as unleased and will mount past it**, and its only guard is then
  the seal refusal. Do not point a v0.1.0 client at a volume a v0.2 client
  is writing.

  New flag `--ignore-volume-lease` proceeds past a live `meta/lease.json`.
  `--steal-lease` deliberately does not: it takes one branch's lease, and
  the legacy object belongs to a client whose branch you cannot see. The
  new flag ignores rather than steals — the object is left exactly where it
  was, to expire on its own TTL.

- **The decoded-chunk cache is one file, not one file per chunk.**
  `gencache/chunks/` held a plaintext file per chunk the mount had ever
  read — an inode and a flat directory entry each, 6,646 of them for a
  166 MiB source tree, with no upper bound on a real volume. It is now
  `gencache/chunks.arena`: one preallocated, mmap'd file with an in-memory
  index, a bump cursor that wraps for eviction, and a default size of
  256 MiB capped at an eighth of the cache budget (it was previously
  unbounded except by the shared budget).

  It is faster as well as smaller — measured on that tree with the packs
  already local: a cold read 2.03 s → 0.55 s, a hot re-read 131 ms →
  13 ms, scattered 4 KiB reads 318 ms → 32 ms. Filling the old directory
  cost more than the decoding it saved.

  The arena's size is reported by `pelfs cache` and in the statistics file
  under `cache.dirs.arena`, and `cache.chunk_hits` / `cache.chunk_misses`
  say whether it is the right size for the workload. `ChunkArenaBytes`
  negative turns the tier off entirely, which on that tree costs 61% on a
  cold scan (a 500 KiB chunk is decoded four times to serve four 128 KiB
  kernel reads) and 68x on a re-read.

  **On-disk change:** the first mount with this build sweeps a v0.1.0
  `gencache/chunks/` directory and logs what it reclaimed. Everything
  under `gencache/` is re-derivable from the federation, so nothing is
  lost; a v0.1.0 binary pointed back at the same state directory simply
  refills it.

- Two cache-reporting bugs found on the way. `CacheUsage` returned zero
  eviction counters whenever it had to rescan, so "has this cache been
  evicting" was answerable only by luck; and a mount opened with a smaller
  budget than the last one inherited the previous arena reservation
  without agreeing to it.

- **`--prefetch` moves packs, not decoded chunks.** "I want the data
  local" now means the generation's *packs* are local, which is what a
  read is served out of anyway. It used to pull every chunk through the
  read path — decompressing, decrypting, and writing one plaintext file
  per chunk — so a prefetch cost a full decode of the volume up front plus
  a second copy of it on disk, for a decode the mount then repeated later
  anyway whenever a chunk file had been evicted. Strict mode's contract is
  unchanged: it still refuses to start unless everything is local, and the
  check is now that every referenced pack is cached and length-verified.

  Two refusals are new, and both happen before any payload moves: a
  generation whose pack set exceeds the local cache budget is declined
  with both numbers rather than fetched and evicted piece by piece, and a
  mount with whole-pack caching turned off (a negative `PackCacheBytes`)
  reports that a prefetch is impossible rather than warming nothing.

  **Statistics change:** `prefetch_chunks` is replaced by
  `prefetch_packs`, and `prefetch_fetched_bytes` is added — what this
  session actually transferred, as against `prefetch_bytes`, the size of
  the set now local. A supervisor keying on `prefetch_chunks` needs
  updating; `prefetch_complete` and `prefetch_failed` are unchanged.

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
  as every generation in the window has one. Measured on a two-branch
  fixture (main nine generations deep, dev five, at `--retain-k 3`) the
  retained set falls from 29 objects to 25; a forked volume's window scan
  reads 3–4 pack trailers of 15 where it previously read all of them.

  **The generations attribution cannot cover keep the old rule, per
  generation.** A branch's window reaches back past its own fork point, and
  those generations were sealed by the parent branch and say so — they are
  the branch's history all the same — as are any backups written before the
  field existed. Both keep every distinct candidate, and only those
  generations do, so an upgraded volume gets the tight rule for its new
  history and the conservative one across the legacy span until it has
  sealed K more times. The sweep says which it used: `retain window: branch
  dev keeps 6 of 8 generations (attributed, 3 legacy candidates kept for 3
  generation(s))`.

  A repack now also stamps the branch it publishes onto rather than
  inheriting the parent's — `pelfs branch dev` copies main's head verbatim,
  so a repack can be the first writer a branch ever has. It writes no
  backup either way; the generation a repack grew from is covered by the
  condemned-ledger floor, as before.

  **On-disk change, and it is a one-way door.** `Branch` is `omitempty`, so
  every superblock written before it still verifies unchanged (pinned
  against captured v0.1.0 wire bytes, not against a round trip through the
  current encoder). The other direction is a hard refusal: `Verify`
  re-encodes the decoded struct, so a **v0.1.0 binary cannot read a
  generation a v0.2 writer sealed** — `ErrBadSignature` at the trust
  boundary, the same door `Manifests` went through. Stamping only the
  backup would have kept old mounts working and was rejected for it: an old
  `pelfs gc` would then mount the volume, fail to verify the new backups,
  read them as absent, report a short window and collect what those
  generations alone named. A loud refusal beats a quiet deletion.

  **What is still not fixed:** a branch NAME is not a lineage. Delete
  `dev`, recreate it from an older generation and seal the same numbers
  again, and the two incarnations collide exactly as two branches used to.
  The newest-first scan favours the live one, and a repack that copied an
  old backup into a new pack can defeat that. Tag a generation to pin it
  exactly.

- **`T_grace` is a per-volume parameter, and now it really is one.** It was
  recorded in `Params.TGraceSeconds` and written from a compiled-in 72
  hours, and the sweep FLOORED its own window at the same constant — so a
  volume that recorded twelve hours was swept at seventy-two, and the
  documentation calling it configurable was describing a field nothing
  read. `pelfs init --grace 12h` sets it; every later seal carries the
  RECORDED value forward; the sweep, the repack planner and the three
  condemned ledgers all age against it. `pelfs gc --grace` is unchanged and
  may still only WIDEN — an option that could narrow the window is an
  option to delete a concurrent writer's packs — and there is a **one-hour
  floor** for the same reason. `pelfs gc` prints the window it applied.

  **A large window buys less than it looks like it buys**, and `pelfs init`
  says so when the numbers collide. The two derived-ref ledgers gain about
  a row per checkpoint per key space against a 48 KiB cap (~517 hash-named
  rows), so past `517 x checkpoint-interval` the byte cap binds before the
  window does: the volume behaves as though its window were that long and
  repacks pace to the room left. At the 5-minute default that is ~43 hours
  — the 72-hour default is already past it, `--grace 30d` is past it
  forty-fold. Nothing a branch head or tag names is affected; what is
  shortened is the window for objects only a RETIRED generation names, and
  a workflow needing a real pin should tag.

- **A repack retires index segments whose packs are mostly gone.** The
  planner has measured this since indexes were tiered and the executor
  ignored it, so a segment written for packs a later repack condemned went
  on being listed, fetched and windowed through forever — spending its
  bytes on entries that resolve to nothing. Under 50% live pack coverage, a
  repack now drops the segment, **re-emits the entries it still answers
  for** into the segment it was writing anyway, and condemns the old object
  through the existing condemned-index ledger (which `pelfs gc` already
  honours, so it survives the grace window for readers pinned to the
  generation before the repack).

  Re-emitting is the half that matters: an index is derived, so dropping
  one costs only fetch time, but dropping one whose surviving packs nothing
  else indexes sends every lookup of those identities down the pack-trailer
  fallback — a cleanup that makes cold reads slower. Coverage is preserved
  and only the dead share is discarded.

  Retirement is **paced by the ledger**, exactly as pack condemnation is:
  what has no room for a row is left listed for a later run rather than
  dropped with nothing to speak for it. Manifest segments are unchanged —
  a repack rewrites the manifest whole, so its segments are already
  condemned together.

- **A writable mount collects, not just condemns.** Auto-repack shipped in
  v0.1.0 and nothing ever COLLECTED: a repack condemns packs, retention's
  sweep is what deletes them, and the only thing that ran the sweep was a
  person typing `pelfs gc --delete`. So the volume that repacked itself
  faithfully every six hours still grew forever, and both halves of the
  v0.1.0 limitation ("a volume nobody runs gc on grows without bound", "a
  volume nobody mounts is never maintained") stayed true for the half that
  frees bytes.

  The sweep now runs in the same idle machinery, under the same quiescence
  and back-off rules: after a repack that published — that repack is what
  created the work — and otherwise every six hours while the mount is
  quiet. Default ON, `--no-auto-gc` to turn it off, separately from
  `--no-auto-repack` because the two fail differently (a repack that does
  not run costs storage; a sweep deletes).

  **It is the existing sweep, not a new one.** `retention.GC` with
  `Delete`, every window intact — the grace window the volume records, the
  retain-K generations, the three condemned ledgers — and the same
  fail-closed rule: a ref or tag that will not verify aborts the run and
  deletes NOTHING. There is deliberately no second deletion path in the
  mount to keep in agreement with the first.

  What it freed is visible where it can still be read months later, not
  only in a log: `pelfs ctl <mount> status` gains `last_gc_at`,
  `last_repack_at`, `reclaimed_bytes` and `reclaimed_objects`, and the
  statistics file gains a `maintenance` section carrying those plus the
  grace window the last sweep applied and the count of sweeps that FAILED
  closed — because a sweep that fails every time looks exactly like a
  volume with nothing to collect.

  Unchanged, and still the honest limit: **a volume nobody mounts writably
  is never maintained.** Maintenance rides the mount because that is what
  holds the branch's write lease and knows when the volume is idle.

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
  is a v0.2 change. *(Done — see Unreleased. The record of what v0.1.0
  shipped stands; a v0.1.0 client still locks the whole volume, and how the
  two versions interact is described there.)*
- **Two branches that have diverged stay diverged.** There is no merge, and
  none is planned for this release. What exists is branching, tagging and
  deleting. *(Done — see Unreleased. The record of what v0.1.0 shipped
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
