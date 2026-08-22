# pelfs — a mountable filesystem backed by a Pelican federation

`pelfs` gives you a POSIX filesystem, mounted locally, whose data lives in a
[Pelican](https://pelicanplatform.org) federation under a namespace prefix
you control. Content-addressed packs and signed, split catalogs are the
on-disk format; a generation of the tree is one immutable, verifiable
object graph, and publishing a change is one atomic ref flip.

```
pelfs init   pelican://osg-htc.org/my/namespace/scratch    # create a volume
pelfs shell  pelican://.../scratch                         # mount + subshell
pelfs mount  [--rw] pelican://.../scratch [mountpoint]     # background mount
pelfs umount pelican://.../scratch                         # stop it cleanly
pelfs status                                               # list background mounts
pelfs gc     [--delete] pelican://.../scratch              # sweep unreferenced packs
pelfs tag    pelican://.../scratch v1.0                    # freeze the head under a name
pelfs tag    --list pelican://.../scratch                  # what is pinned here
pelfs tag    --rm pelican://.../scratch v1.0               # release the pin (gc reclaims)
pelfs branch pelican://.../scratch dev                     # a second line of history
pelfs branch --from-tag v1.0 pelican://.../scratch v1-fix  # ...starting at a pinned generation
pelfs branch --list pelican://.../scratch                  # what branches exist
pelfs branch --rm pelican://.../scratch dev                # delete one (never the last)
pelfs fsck   [--deep] pelican://.../scratch                # verify a generation
pelfs repack-plan pelican://.../scratch                    # what a repack would rewrite
pelfs repack [--apply] pelican://.../scratch               # rewrite it, publish a generation
pelfs version                                              # which build this is
```

`shell` mounts the filesystem on a temporary mountpoint and drops you into a
subshell there; exiting unmounts and seals everything you changed into the
next generation. If that seal cannot reach the federation — a dropped
connection, a closed laptop — nothing is lost: the overlay is left intact,
the branch does not move, and the next mount of the same prefix resumes it
and seals again. A trailing `-- command [args...]` runs that instead of a
shell and exits with its status. `mount` does the same as a background
daemon with persistent per-prefix local state (`~/.local/state/pelfs/`).
Everything runs unprivileged. Before mounting, a preflight probe checks the
credential's read/write/delete access to the prefix and reports missing
scopes up front.

## How it works

- **Data path**: files are split by content-defined chunking, and chunks are
  written into immutable **pack** objects under `<prefix>/packs/`. Readers
  locate a chunk from the generation's pack list and fetch the pack that
  holds it whole — packs are cut small (2 MiB) precisely so that this is
  cheap, and a source-tree walk is about 40x faster than the same reads
  issued as ranges. The transport
  ([internal/pelicanobj](internal/pelicanobj/)) is built for `pelican://` /
  `osdf://` on the Pelican client library (`client.PelicanFS`, plus
  `DoStat`/`DoList`/`DoDelete`), inheriting director handling, endpoint
  failover, retries, ETag plumbing, and token discovery/acquisition. A small
  direct-HTTP transport handles plain `http(s)://` prefixes for tests and
  development against a bare server.
- **Metadata**: **catalogs**, split by subtree, stored as ordinary pack
  entries and addressed by content hash. A signed **superblock** names
  the root catalog, the inode shards, and the pack list; `refs/<branch>` is
  the one mutable object in the volume. Inodes are stable across
  generations, which is what lets a mount swap to a newer generation by
  invalidating exactly what changed.
- **Writing**: a writable mount (`--rw`, or `pelfs shell`) shadows the
  immutable generation with a crash-safe local **overlay**. Unmount seals
  it into the next generation, and a writable mount also checkpoints on a
  cadence (`--snapshot-interval`, default 5 min) so the work is durable
  long before you type `exit`. Nothing mutates the base, so an interrupted
  session loses at most the unsealed overlay — which survives on disk for a
  remount.
- **Trust**: every superblock is Ed25519-signed by a per-volume key. The
  first mount pins the key (TOFU) under the state directory and reports its
  fingerprint; later mounts verify against the pin, or against an explicit
  `--volume-pubkey`.
- **Auth**: `--token <file>`, or the Pelican client's own token machinery
  (WLCG discovery plus, unless `--no-acquire-token`, interactive
  acquisition).
- **Concurrent-writer detection**: every writable session holds an advisory
  lease at `<prefix>/meta/lease-<branch>.json`, renewed every 30s (2 min
  TTL). A second `pelfs` writing the SAME branch refuses to mount while the
  lease is live, naming the holder; a writable mount of a DIFFERENT branch
  of the same volume runs alongside it, since the two can never touch the
  same ref. `--steal-lease` overrides it, read-only mounts skip it, and a
  crashed client's lease simply expires. If another client takes the lease
  over mid-session, pelfs warns loudly and the seal at unmount is refused
  if that client advanced the branch. The ref and the
  lease are always read bypassing federation caches (`?directread`) —
  mutable objects must never be served stale, while immutable packs keep
  enjoying cache-served reads.

## Unprivileged, on a host you do not own

Build for the target, copy one binary, run it as yourself:

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pelfs ./cmd/pelfs
scp pelfs worker:~/ && ssh worker './pelfs shell pelican://.../scratch'
```

No root, no sudo, no package to install, no setup step. State, caches and
the volume signing key go under `$HOME/.local/state/pelfs`.

**Reading** a volume from a second machine needs nothing: the public half
of the volume key travels inside every superblock and is pinned on first
use. **Writing** needs the private key, because only its holder can sign a
new generation — copy `v2-signing.key` across and point at it:

```
scp ~/.local/state/pelfs/vol-<id>/v2-signing.key worker:~/
ssh worker './pelfs shell --signing-key ~/v2-signing.key pelican://.../scratch'
```

Without it the mount works, reads work, writes work, and the seal at
unmount is refused — so it is worth doing before the session, not after. `make
unprivileged` gates exactly this: a linux/amd64 binary run in a container
as uid 1001 with an empty supplementary group set and nothing writable
outside its scratch, mounting, writing, sealing, re-reading, and then
running `fsck --deep`, `gc` and `repack`.

The one thing pelfs cannot supply is FUSE itself. It needs to open
`/dev/fuse`, which is a property of the host — usually mode 0666 and
usable by anyone, but not on a locked-down machine. When it cannot, the
error says which of the possible reasons applies and does not send you
looking for a fallback: on Linux there is none, because the NFS backend
mounts with `mount(2)` and that needs root.

## Pure Go, no cgo

Everything builds with `CGO_ENABLED=0` and no build tags. SQLite is
`modernc.org/sqlite`; compression is `klauspost/compress`.

## Building and testing

```
make             # bin/pelfs
make test        # unit tests
make e2e         # full mount loop in a container against a fake origin
make integration # transport + publish/resolve against a real federation-in-a-box
                 # (pelican serve --module director,registry,origin; needs a
                 #  pelican binary via $PELICAN_BIN/$PELICAN_SRC)
make mount-gate  # the kernel mount gate, in a container (see scripts/mount-gate-docker.sh)
make opfuzz      # the overlay op-sequence fuzzer, in its sealed container
make unprivileged # a linux/amd64 binary, run as a non-root user with no setup
```

`cmd/fakeorigin` is a tiny origin-like HTTP server over a local directory,
handy for kicking the tires without a federation:

```
bin/fakeorigin --root /tmp/origin --listen 127.0.0.1:8081 &
bin/pelfs shell http://127.0.0.1:8081/ns     # https?/http = direct mode, no discovery
```

## macOS without macFUSE: the NFS backend

On a Mac with neither macFUSE nor FUSE-T installed, pelfs attaches the
filesystem through a **loopback NFS mount**: it runs a pure-Go NFSv3 server
on 127.0.0.1 and mounts it with macOS's built-in `mount_nfs`, which works
unprivileged. No kernel extension, no third-party installs, no closed-source
components — this is the same mechanism FUSE-T uses internally, minus the
middleman (FUSE-T's libfuse ABI can't host our go-fuse stack anyway, which
speaks /dev/fuse directly).

Backend selection is automatic (`--backend auto`): native FUSE where it is
available, else NFS on macOS. Force one with `--backend fuse|nfs`.

One macOS quirk: the first time an application touches the mounted volume,
macOS shows its one-time "would like to access files on a network volume"
permission prompt (TCC) for that app — click Allow once per app
(Terminal, Finder, ...).

## Batch / JupyterLab usage (e.g. inside an HTCondor job)

For a user working interactively inside a job sandbox, the intended pattern
is:

```
pelfs shell --prefetch background --stats-file $_CONDOR_SCRATCH_DIR/pelfs-stats.json \
    pelican://osg-htc.org/.../scratch
```

- `--prefetch all` downloads the whole generation into the local cache at
  startup and **refuses to start** if anything is unavailable; `--prefetch
  background` starts the same warmup without blocking, recording the
  outcome in the statistics. What it downloads is the generation's *packs*
  — the unit of transfer, and the unit every read is served out of — so it
  costs no decompression, no decryption and no disk beyond the packs
  themselves. A generation that does not fit in the cache budget
  (`--cache-size`) is refused with both numbers, rather than fetched and
  then evicted piece by piece: raise the budget or drop the flag.
- `--snapshot-interval` sets how often a writable mount checkpoints its
  overlay into a new generation. Everything up to the last checkpoint is
  durable in the federation; `0` seals only at unmount.
- `--stats-file` writes a JSON session summary (updated every 30 s and
  finalized at exit) that a supervisor like HTCondor can inspect:
  object-store operation/error counts with error samples, bytes moved, seal
  results, prefetch completeness, lease conflicts, and an overall
  `clean_shutdown` verdict plus exit code. Error counts include attempts a
  lower layer retried successfully, so nonzero errors with
  `clean_shutdown: true` means "transient trouble, but all data made it".

## Controlling a running mount

```
pelfs ctl <prefix-or-mountpoint> status     # generation, backend, lease
pelfs ctl <prefix-or-mountpoint> stats      # the live statistics document
pelfs ctl <prefix-or-mountpoint> publish    # checkpoint now, keep serving
pelfs ctl <prefix-or-mountpoint> bugreport  # tarball for a bug report
```

## Flags

See `pelfs -h`. Highlights: `--ro` (read-only, no overlay and no seal),
`--branch` / `--tag`, `--encrypt-key key.pem` (the RSA key wrapping the
volume's data keys — the same key must be supplied on every later mount;
`$PELFS_KEY_PASSPHRASE` unlocks a passphrase-protected PEM), `--state-dir`
(where the overlay, caches, trust pin, and signing key live), `--poll`
(read-only mounts follow the branch head live), `--no-seal`, and
`--volume-pubkey`.

## Messages

Everything pelfs says goes to stderr, prefixed `pelfs:` so it stays
distinguishable from the Pelican client's own logging (configured
separately by `$PELICAN_LOGGING_LEVEL`) and from whatever your program
prints inside `pelfs shell`.

On a terminal those lines are plain prose. When stderr is not a terminal
— a background `pelfs mount` writing to its log file, or CI — each line
gets a timestamp and a level in front of the same prose, because whoever
opens that file later was not there when it happened.

Set `$PELFS_LOG_FORMAT` to `plain`, `text`, or `json` to choose
explicitly. `json` is the format for a log collector, and the only one you
have to ask for: one object per line, with the message TEMPLATE as a
constant `msg` you can group by and the values as typed fields (a size is
a count of bytes, a duration a count of nanoseconds).

## Caveats (prototype)

- **Single writer per BRANCH.** The advisory lease is detection, not mutual
  exclusion: the transport has no compare-and-swap. A seal that would
  overwrite another writer's generation is refused, so the failure mode is
  a rejected seal rather than silent corruption — and that refusal, not the
  lease, is the guarantee. The lease is what makes you find out at mount
  time instead of after an hour of work. It is one object per branch,
  `meta/lease-<branch>.json`, so two writable mounts on different branches
  of one volume run concurrently and only a second writer on the same
  branch is refused, naming the holder. `pelfs status` prints which lease
  object a session holds, and the statistics file records it as
  `lease_key`.
- **A pelfs v0.1.0 client on the same volume weakens that, in one
  direction, and it is worth knowing which.** v0.1.0 held one lease for the
  whole prefix, `meta/lease.json`, whatever branch it was writing. So:
  - This release READS that object and refuses to write ANY branch while a
    v0.1.0 lease is live — it cannot tell which branch that client is on,
    so it assumes the worst. `--steal-lease` will not clear it (that flag
    is about one branch); `--ignore-volume-lease` proceeds past it, leaving
    the object untouched to expire on its own TTL.
  - This release never WRITES that object, because writing both would put
    two v0.2 writers on different branches back to excluding each other
    through the legacy key — the exact problem per-branch leases fix.
    The honest consequence: **a v0.1.0 client sees a v0.2 writer as
    unleased and will mount straight past it.** Its only protection is then
    the seal's refusal to publish over a moved ref, which is the real
    protection in every case. Do not run a v0.1.0 client against a volume a
    v0.2 client is writing.
- The origin must permit GET/PUT/DELETE and listing on the prefix (i.e. a
  token with read/modify scopes for the namespace); `pelfs` checks this up
  front and says which scope is missing.
- **Reclaiming space still needs `gc` to be run.** A writable mount
  repacks by itself when it has been idle for a while and the branch has
  drifted since the last one (`--no-auto-repack` turns that off), which
  condemns the mostly-dead packs. Removing them is still a separate,
  manual `pelfs gc --delete`, and only once the grace window (72h, not
  configurable) has passed AND the retain window has moved past the
  generations that named them — so a repack immediately followed by a
  sweep frees nothing until the branch has sealed `RetainK` more times.
  `pelfs repack` with no flags reports what the volume is currently
  carrying.
- **A retired generation gets the grace window, and the last K
  generations of its branch.** The sweep's root set is every branch head,
  the last `Params.RetainK` generations behind each head (8 by default),
  and every tag. The window is real but bounded: a retired generation
  leaves no addressable record, so the sweep reconstructs it from the
  disaster-recovery superblock a seal buries in its last pack, and a
  generation whose backup has itself been collected is reported as not
  retained rather than guessed at. `pelfs gc` prints how many generations
  of the window it could establish; `--retain-k` states a different number
  (it is the one retention knob that may narrow as well as widen, because
  it is a claim about your own readers rather than a race against a live
  writer).

  On a volume with more than one branch the window is resolved per branch:
  a seal records which ref it published onto, so a branch's window holds
  the generations that branch sealed rather than every document carrying
  the same generation number. `pelfs gc` says which rule each window used
  — `(attributed)`, or `(… N legacy candidates kept …)` for the
  generations below a branch's fork point and for anything sealed by pelfs
  v0.1.0, which are kept conservatively until the branch has sealed
  `RetainK` more times.
- **`pelfs tag <prefix> <name>` is the escape from both windows.** A
  tagged generation is in the live set outright, so nothing it references
  is swept while the tag is there. Tags are immutable (creating one over a
  name in use is refused, not overwritten) and are mounted with
  `pelfs mount --tag`. `pelfs tag --rm <prefix> <name>` releases the pin:
  it names the generation it is retiring, and the space comes back on the
  next `pelfs gc` after the grace window — deletion takes a root out of
  the set, it does not itself free a byte. A name freed this way can be
  tagged again; immutability is a property of the object, not the name.
- **`pelfs branch` gives a volume more than one line of history.** A branch
  is a NAME over a generation — nothing in the format records one — so
  `pelfs branch <prefix> <name>` copies the verified head of `--from`
  (default `main`), or of `--from-tag <tag>`, under a second name, and from
  that instant the two advance independently: each seal reads the head of
  the branch it publishes onto and flips that one ref. Creation is
  create-if-absent and a branch is never moved by this verb, because
  repointing one out from under a writer would strand its next publish and
  reparent its work; moving a branch is what publishing does, through the
  CAS guard. `--list` shows what exists. `--rm` deletes one, names the
  generation it is letting go, and — exactly as for a tag — frees nothing
  until the next `pelfs gc` past the grace window. Deleting the LAST branch
  is refused: every object in a volume is reachable from a ref, so a volume
  with none has no head to mount, nothing for a new branch to start from,
  and no way back from the CLI.
- There is no **merge**, and no **key rotation**. Two branches that have
  diverged stay diverged; what exists is branching, tagging and deleting,
  not reconciling. Key rotation is a format feature (custody-chain
  verification) with no writer behind it — and note that when one does
  land, rotating on one branch retires the volume-wide pin and siblings
  still signed by the old key fail until they are republished.
