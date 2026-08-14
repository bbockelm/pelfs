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
  streams each block to/from the federation with plain HTTP
  (GET/PUT/DELETE/HEAD + WebDAV PROPFIND for listings), storing them under
  `<prefix>/chunks/...`. `pelican://` prefixes are resolved to the
  federation's director via `.well-known/pelican-configuration`; requests
  follow director redirects, re-attaching the bearer token.
- **Metadata**: JuiceFS's SQLite metadata engine, kept in a local temp
  directory alongside a block cache. Every `--snapshot-interval` (default
  5 min) — and once more at shutdown — a consistent copy is taken with
  `VACUUM INTO` and uploaded to `<prefix>/meta/<session-id>/NNNN-<label>.db`,
  a subdirectory unique to each mount session. On startup, the newest
  snapshot found under `<prefix>/meta/` is restored, so a later session picks
  up where the last one left off.
- **Auth**: a bearer token from `--token`, or WLCG bearer-token discovery
  (`$BEARER_TOKEN`, `$BEARER_TOKEN_FILE`, `$XDG_RUNTIME_DIR/bt_u$UID`,
  `/tmp/bt_u$UID`). The token file is re-read as it is refreshed externally.
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
make            # bin/pelfs (host) + bin/pelfs-linux-<arch> (for Docker fallback)
make test       # unit tests (object backend, sqlite/zstd/lz4 shims, meta engine smoke)
make e2e        # full loop in Docker against a fake origin: write → snapshot → restore → read
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

- **Single writer.** Nothing prevents two concurrent mounts of the same
  prefix; they would corrupt each other's view. Last snapshot wins.
- The origin must permit GET/PUT/DELETE and PROPFIND on the prefix (i.e. a
  token with read/modify scopes for the namespace).
- Trash is disabled (`TrashDays=0`); deleted blocks are removed eagerly.
- `pelfs mount` (async mount, no subshell) is a planned future mode.
- JuiceFS is Apache-2.0; this project links it as a library.
