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
