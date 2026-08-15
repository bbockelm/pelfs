# pelfs — a mountable filesystem backed by a Pelican federation

`pelfs` combines [JuiceFS](https://juicefs.com) (as a Go library) with the
[Pelican Platform](https://pelicanplatform.org) to give you a POSIX
filesystem, mounted locally via FUSE, whose data lives in a Pelican
federation under a namespace prefix you control.

```
pelfs shell  pelican://osg-htc.org/my/namespace/scratch    # mount + subshell
pelfs mount  pelican://.../scratch [mountpoint]            # background mount
pelfs umount pelican://.../scratch                         # stop it cleanly
pelfs status                                               # list background mounts
pelfs gc     [--delete] pelican://.../scratch              # collect leaked blocks
pelfs fsck   pelican://.../scratch                         # verify referenced blocks
```

`shell` mounts the filesystem on a temporary mountpoint and drops you into a
subshell there; exiting unmounts, flushes all data blocks to the federation,
and uploads a final metadata snapshot. `mount` does the same as a background
daemon with persistent per-prefix local state (`~/.local/state/pelfs/`).
Everything runs unprivileged. Before mounting, a preflight probe checks the
credential's read/write/delete access to the prefix and reports missing
scopes up front.

## How it works

- **Data path**: JuiceFS splits files into 4 MiB blocks. A custom JuiceFS
  object-storage backend ([internal/pelicanobj](internal/pelicanobj/))
  stores each block under `<prefix>/chunks/...`. For `pelican://` / `osdf://`
  prefixes it is built on the Pelican client library's filesystem interface
  (`client.PelicanFS`, plus `DoStat`/`DoList`/`DoDelete`), inheriting the
  client's director handling, endpoint failover, retries, ETag plumbing, and
  token discovery/acquisition. A small direct-HTTP transport handles plain
  `http(s)://` prefixes for tests and development against a bare server.
- **Metadata**: JuiceFS's SQLite metadata engine, kept in a local temp
  directory alongside a block cache. Every `--snapshot-interval` (default
  5 min) a consistent copy is taken with `VACUUM INTO` and uploaded to
  `<prefix>/meta/<session-id>/current.db`, overwriting the previous copy in
  place; a separate `final.db` is written at shutdown after the filesystem
  quiesces. Overwrites lean on the origin's ETag support: the ETag observed
  after each upload is compared before the next one, so a concurrent writer
  on the same session is detected rather than silently clobbered. On
  startup, the newest snapshot under `<prefix>/meta/` is restored, so a
  later session picks up where the last one left off.
- **Auth**: `--token <file>`, or the Pelican client's own token machinery
  (WLCG discovery plus, unless `--no-acquire-token`, interactive
  acquisition).
- **No FUSE? Docker.** On macOS without macFUSE (or Linux without
  `/dev/fuse`), pelfs re-launches itself inside a small container
  (`alpine` + the bind-mounted `pelfs-linux-<arch>` binary, `--device
  /dev/fuse`), and your subshell runs inside the container with the
  filesystem mounted there. Build the Linux binary with `make linux`.

## Pure Go, no cgo

Everything builds with `CGO_ENABLED=0`. JuiceFS normally needs cgo in three
places; each is swapped out with a `go.mod` replace directive pointing at a
pure-Go shim in [shims/](shims/):

| cgo dependency | shim backend |
|---|---|
| `mattn/go-sqlite3` | `modernc.org/sqlite` (with mattn-style DSN + error translation) |
| `DataDog/zstd` | `klauspost/compress/zstd` |
| `hungys/go-lz4` | `pierrec/lz4/v4` |

Additionally the build uses `-tags nogspt,notikv` to drop JuiceFS's two other
cgo-tainted optional paths (proc-title setting and the TiKV meta engine).

## Building and testing

```
make             # bin/pelfs (host) + bin/pelfs-linux-<arch> (for Docker fallback)
make test        # unit tests (object backend, snapshots, shims, meta engine smoke)
make e2e         # full mount loop in Docker against a fake origin: write → snapshot → restore → read
make integration # object + snapshot layers against a real federation-in-a-box
                 # (pelican serve --module director,registry,origin; needs xrootd
                 #  on PATH and a pelican binary via $PELICAN_BIN/$PELICAN_SRC)
```

`cmd/fakeorigin` is a tiny origin-like HTTP server over a local directory,
handy for kicking the tires without a federation:

```
bin/fakeorigin --root /tmp/origin --listen 127.0.0.1:8081 &
bin/pelfs shell http://127.0.0.1:8081/ns     # https?/http = direct mode, no discovery
```

## Example: running on a Mac without macFUSE (Docker fallback)

`pelfs shell` detects that macFUSE is absent and re-launches itself inside a
small Linux container with `/dev/fuse`; your subshell then runs *inside* the
container with the filesystem mounted there. Only two things are needed: the
Docker CLI, and a Linux build of pelfs next to the host binary.

```console
$ make                    # builds bin/pelfs AND bin/pelfs-linux-arm64 (the container payload)
$ bin/pelfs shell pelican://osg-htc.org/my/namespace/scratch
pelfs: FUSE unavailable on host; launching container (alpine:3.21)
pelfs: restored metadata from meta/20260815T011225Z-pelfs-cbab14f5/final.db
pelfs: mounting pelican://osg-htc.org/my/namespace/scratch on /var/tmp/pelfs/mnt
pelfs: starting /bin/sh in /var/tmp/pelfs/mnt (exit the shell to unmount)
/var/tmp/pelfs/mnt # echo hello > greeting.txt
/var/tmp/pelfs/mnt # ls -l
-rw-r--r--    1 root     root             6 Aug 15 01:21 greeting.txt
/var/tmp/pelfs/mnt # exit
pelfs: unmounting and flushing data to the federation...
pelfs: final metadata snapshot uploaded (session 20260815T012201Z-pelfs-8c1f22a0)
```

Details worth knowing:

- The container is plain `alpine` (override with `--docker-image`); no image
  build happens — the `bin/pelfs-linux-<arch>` binary is bind-mounted in.
  If the binary lives elsewhere, point at it with `$PELFS_LINUX_BINARY`.
- Your bearer token is found on the host (`--token`, `$BEARER_TOKEN_FILE`,
  or WLCG discovery) and bind-mounted read-only into the container; an
  `--encrypt-key` file is forwarded the same way. The host's `~/.pelican`
  credential store is also shared into the container, and the access
  preflight — including any interactive token acquisition (device flow,
  wallet password) — runs on the **host, before** the container starts, so
  existing credentials are reused and prompts happen where your browser is.
- The subshell is `/bin/sh` inside the container, not your host shell, and
  the mount is only visible inside the container. Local state (block cache,
  metadata db) lives in the container and vanishes with it — durability
  comes from the flushed blocks and the final metadata snapshot, exactly as
  in the native case.
- `--docker` forces the container path even where FUSE exists;
  `--no-docker` forbids it.
- Piping commands works too, for scripted use (the container then runs
  without a TTY). Note the commands execute inside the container, so they
  can only see the mounted filesystem, not host paths:

  ```console
  $ echo 'sha256sum big-dataset.bin' | bin/pelfs shell --docker pelican://.../scratch
  ```

## Flags

See `pelfs -h`. Highlights: `--ro` (read-only: restore + mount, upload
nothing), `--compress zstd`, `--encrypt-key key.pem` (client-side encryption
of data blocks **and** metadata snapshots — the same key must be supplied on
every later mount), `--state-dir` (persist local state between sessions),
`--writeback` (async block upload), `--cache-size`, `--keep-sessions`
(snapshot pruning depth), `--no-restore`, `--docker` / `--no-docker`,
`--volume`.

## Caveats (prototype)

- **Single writer.** Nothing yet prevents two concurrent mounts of the same
  prefix. Snapshot uploads detect interference via ETags (a foreign write to
  the session's `current.db` stops further snapshots loudly), but block-level
  writes are not fenced; a proper lease object is future work.
- The origin must permit GET/PUT/DELETE and listing on the prefix (i.e. a
  token with read/modify scopes for the namespace); `pelfs` checks this up
  front and says which scope is missing.
- Trash is disabled (`TrashDays=0`); deleted blocks are removed eagerly.
  Blocks orphaned by crashed sessions are reclaimed with `pelfs gc --delete`.
- JuiceFS is Apache-2.0; this project links it as a library.
