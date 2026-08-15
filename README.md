# pelfs — a mountable filesystem backed by a Pelican federation

`pelfs` combines [JuiceFS](https://juicefs.com) (as a Go library) with the
[Pelican Platform](https://pelicanplatform.org) to give you a POSIX
filesystem, mounted locally via FUSE, whose data lives in a Pelican
federation under a namespace prefix you control.

```
pelfs shell pelican://osg-htc.org/my/namespace/scratch
```

mounts the filesystem on a temporary mountpoint and drops you into a subshell
there. Exiting the shell unmounts, flushes all data blocks to the federation,
and uploads a final metadata snapshot. Everything runs unprivileged.

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

## Flags

See `pelfs shell -h`. Highlights: `--state-dir` (persist local state between
sessions instead of a fresh temp dir), `--keep-state`, `--writeback` (async
block upload), `--cache-size`, `--no-restore`, `--docker` / `--no-docker`,
`--volume`.

## Caveats (prototype)

- **Single writer.** Nothing yet prevents two concurrent mounts of the same
  prefix. Snapshot uploads detect interference via ETags (a foreign write to
  the session's `current.db` stops further snapshots loudly), but block-level
  writes are not fenced; a proper lease object is future work.
- The origin must permit GET/PUT/DELETE and PROPFIND on the prefix (i.e. a
  token with read/modify scopes for the namespace).
- Trash is disabled (`TrashDays=0`); deleted blocks are removed eagerly.
- `pelfs mount` (async mount, no subshell) is a planned future mode.
- JuiceFS is Apache-2.0; this project links it as a library.
