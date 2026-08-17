# go-nfs: two gaps, and why we don't fork (yet)

The loopback-NFS backend runs on [willscott/go-nfs](https://github.com/willscott/go-nfs).
Two of its behaviors are wrong for us. Neither is patchable from outside the
package, and neither currently justifies a fork — this note records the
analysis so the decision can be revisited quickly.

## Why interception is impossible

Every avenue is closed by design:

- **The dispatch table is write-once.** Handlers live in a package-global
  `registeredHandlers` map, populated by the package's own `init()`.
  `RegisterMessageHandler` returns `"already registered"` for any procedure
  that already has a handler, so a later registration cannot replace one.
- **An outside package cannot even express a handler.** `HandleFunc` is
  `func(context.Context, *response, Handler) error`, and `response` is
  unexported. You cannot name the type, so you cannot write a conforming
  function (short of `reflect.MakeFunc` plus `unsafe` to reach the
  connection's unexported fields — not a maintainable foundation).
- **`Server` has no per-instance handlers.** It carries only an embedded
  `Handler`, an ID, and a context; dispatch still consults the global map.
- **The `Handler` interface is below the decision point.** For CREATE, the
  EXCLUSIVE rejection happens while parsing the request, before the
  filesystem is ever consulted.

Rewriting RPCs in a wrapping `net.Listener` would technically work and is
far worse than a fork: it means re-implementing record marking and XDR, and
the substitution changes message sizes.

So the only real options are: fork, vendor, or upstream.

## Gap 1: EXCLUSIVE create is rejected

`onCreate` fails any NFSv3 EXCLUSIVE create with `NFS3ERR_NOTSUPP` and logs
`failing create to indicate lack of support for 'exclusive' mode` (upstream
marks it `// TODO`). That is what *every* `O_CREAT|O_EXCL` open becomes, and
git uses it for each lockfile and every `mkstemp`, so the message repeats
constantly.

**Why we tolerate it:** the macOS client falls back to GUARDED, which keeps
the property that matters — the create still fails if the name already
exists, so `O_EXCL`'s mutual exclusion is preserved. What's lost is
retransmission idempotency: a retried CREATE for a request that already
succeeded answers `EXIST` instead of OK. A loopback TCP mount does not
retransmit. Evidence: a full `git clone` (61k objects) creates thousands of
files this way and completes.

The log noise is filtered in `internal/nfsmount` (`quietLogger`).

## Gap 2: COMMIT is a no-op

`onCommit` replies OK without flushing, documented as "we always push writes
to the backing store". That was true before our write-handle cache and is
not true now, which makes an `fsync()` through the mount a lie.

**Why we tolerate it:** durability comes from other paths — the idle janitor,
`Rename`/`Remove` (git's write-then-rename is the case that matters), and
the flush at unmount, which is the one that actually bit us (see
`internal/nfsmount/handlecache.go`). A crash mid-session loses the local
cache regardless, and pelfs's durability promise is the final upload at exit.

## Gap 3: LINK is broken at both ends of the wire

`ln`, and every hardlink entry in a tarball, comes back as **EIO**. This is
not our error translation; the RPC never reaches our filesystem intact.

RFC 1813 defines `LINK3args` as `nfs_fh3 file` followed by
`diropargs3 link`. `onLink` reads a `diropargs3` first — so it takes the
source file's handle as `link.dir` and the target *directory's handle* as
`link.name` — then reads a `sattr3` that is not in the message at all,
which usually runs off the end of the body and yields `NFS3ERR_INVAL`. Even
if it did not, the failure reply is 4 bytes short: `LINK3resfail` is
`post_op_attr` + `wcc_data` (12 bytes), and the wcc error formatter writes 8.
The client cannot decode the reply and reports EIO.

Implementing `nfs.UnixChange` on the binding does NOT help: `onLink` would
then hand `Link` a raw file handle where it expects a path.

There is also no way to warn the client off. A client only issues LINK if
FSINFO advertises `FSF3_LINK`, and `onFSInfo` sets that bit for any
filesystem satisfying `billy.Symlink` — which every `billy.Filesystem` does
by definition, since `Symlink` is one of its embedded interfaces. The bit is
unconditionally on.

**Why we tolerate it:** hard links are rare in the workloads a scratch
volume sees, and the failure is loud rather than silent — nothing is
written. `internal/nfsmount` says so once at mount time so that an EIO from
`ln` has a findable explanation.

Reproduced (Linux client, the `scripts/bench-untar-nfs-docker.sh` image):

    tar: .../changes.rst: Cannot hard link to '.../changes-link.rst': Input/output error

## Gap 4: an unrecognized error becomes NFS3ERR_IO

`onCreate`, `onMkdir`, `onSymlink`, `onRemove`, `onRmdir`, `onRename` and
`onRead` answer `NFSStatusIO` for any billy error they cannot place, and
they place only three: `os.IsNotExist`, `os.IsExist`, `os.IsPermission`.
`rmdir` of a non-empty directory is the case that shows up in practice —
ENOTEMPTY has an NFS status (`NFS3ERR_NOTEMPTY`) that no handler ever
returns.

Worse, `onSetAttr` returns `SetFileAttributes.Apply`'s error verbatim,
commented "Already an nfsstatuserror" — which it is not, for the Chmod,
Lchown, Chtimes and Truncate branches, all of which return the backend's
error raw. The response formatter then falls through to
`ResponseCodeSystemError`: an RPC-level rejection rather than an NFS status,
which is how a perfectly ordinary ENOENT reached a client as EIO.

**What we do about it:** `internal/nfsmount/diag.go` wraps the served
filesystem. Errors from the attribute setters come back as
`*nfs.NFSStatusError` carrying the status that describes them, which fixes
SETATTR outright and leaves Apply's own `os.ErrPermission` test working
through the wrap. Everything else that is about to become NFS3ERR_IO is
logged with its operation, path and cause, rate-limited, so a bare
"Input/output error" on a client is always explained on the server.

## The patches, if we ever want them

A branch implementing both is at `~/projects/go-nfs`, branch
`pelfs-exclusive-create` (commit `67d9b3e`), with upstream's tests passing:

- EXCLUSIVE create with an in-memory verifier cache (TTL, dropped on remove
  and rename) so retransmits are idempotent and never re-run `fs.Create`,
  which truncates and would discard the original request's data.
  Watch out: `SetFileAttributes.Apply` dereferences its receiver's fields,
  and EXCLUSIVE carries a verifier rather than attributes — pass
  `&SetFileAttributes{}`, never `nil`.
- COMMIT honoring an optional `Sync() error` on the backend's `billy.File`.
  `billyFile.Sync` already implements it.

Both are upstreamable; a PR is the right home. If they are needed before
that lands, wire them in with a replace pointing at a **pushed** fork
(`github.com/<user>/go-nfs@<sha>`), not a local path — CI cannot resolve a
local path.
