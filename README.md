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
  lease at `<prefix>/meta/lease.json`, renewed every 30s (2 min TTL). A
  second `pelfs` pointed at the same prefix refuses to mount while the
  lease is live, naming the holder; `--steal-lease` overrides it, read-only
  mounts skip it, and a crashed client's lease simply expires. If another
  client takes the lease over mid-session, pelfs warns loudly and the seal
  at unmount is refused if that client advanced the branch. The ref and the
  lease are always read bypassing federation caches (`?directread`) —
  mutable objects must never be served stale, while immutable packs keep
  enjoying cache-served reads.

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
  outcome in the statistics.
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

- **Single writer.** The advisory lease is detection, not mutual exclusion:
  the transport has no compare-and-swap. A seal that would overwrite
  another writer's generation is refused, so the failure mode is a rejected
  seal rather than silent corruption.
- The origin must permit GET/PUT/DELETE and listing on the prefix (i.e. a
  token with read/modify scopes for the namespace); `pelfs` checks this up
  front and says which scope is missing.
- **Reclaiming space takes two steps, and both are manual.** `pelfs
  repack --apply` rewrites the packs that are mostly garbage and stops
  naming the old ones; `pelfs gc --delete` removes them once the grace
  window (72h) has passed. Neither runs on its own. Until you run them, a
  pack whose contents are entirely dead stays on disk — `pelfs repack`
  with no flags reports exactly what that is costing.
- Volume **tags cannot be created** yet (they can be read with `--tag`),
  there is no **fork** command, and there is no **key rotation**.
