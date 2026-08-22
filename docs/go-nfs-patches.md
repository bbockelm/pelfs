# go-nfs: the fork we carry, and what is left in it

The loopback-NFS backend runs on [willscott/go-nfs](https://github.com/willscott/go-nfs).
Eight of its behaviors were wrong for us: four are fixed on a fork, one was
fixed upstream, two are handled inside pelfs (an error translation, and the
whole POSIX permission check), and one is tolerated as it stands. This note
records what the fork holds and why it exists rather than a set of local
wrappers.

The pin lives in `go.mod`:

    replace github.com/willscott/go-nfs => github.com/bbockelm/go-nfs <pseudo-version>

The branch is `pelfs-nfs-fixes` on `github.com/bbockelm/go-nfs`, based on
upstream `master` (not the v0.0.4 tag: master carries the RMDIR fix below).
Every commit on it is minimal and self-contained, written to be offered
upstream unchanged. Offering them is the owner's call.

## Why the fixes cannot live in pelfs

Every avenue for intercepting a handler is closed by design:

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
  EXCLUSIVE rejection happened while parsing the request, before the
  filesystem was ever consulted.

## Fixed on the fork: LINK

`ln`, and every hardlink entry in a tarball, used to come back as **EIO**.
That was not our error translation; the RPC never reached our filesystem
intact.

RFC 1813 defines `LINK3args` as `nfs_fh3 file` followed by
`diropargs3 link`. `onLink` read a `diropargs3` first — taking the source
file's handle as `link.dir` and the target directory's handle as
`link.name` — then a `sattr3` that is not in the message at all, which
usually ran off the end of the body. The reply was wrong at both ends too:
`LINK3resok` carries no file handle, and the failure body was 8 bytes where
`LINK3resfail` is `post_op_attr` + `wcc_data`, i.e. 12. A client cannot
decode a reply four bytes short, so it reported EIO rather than whatever
status the server had chosen.

The fork parses the message as defined and sizes both replies correctly.
It also stops requiring the operation to arrive through `nfs.UnixChange`,
whose `Link` takes two paths that the old parse had no way to produce: a
filesystem can now implement `nfs.HardLinker` — the same two-path shape,
on the filesystem itself — and `internal/vfsbilly` does
(`vfsbilly.go:74`, `vfsbilly.go:473`). `internal/nfsmount` forwards it
through the diagnostic wrapper only when the wrapped filesystem really has
it (`diag.go:197-250`), the same conditional-wrapping rule that governs
`billy.Change`.

`onFSInfo` used to set `FSF3_LINK` for any filesystem satisfying
`billy.Symlink` — which every `billy.Filesystem` does by definition, since
`Symlink` is one of its embedded interfaces — so the bit was
unconditionally on and a client had no way to know the operation would
fail. It now tracks what `onLink` can actually do.

Gated by `scripts/bench-untar-nfs-docker.sh`, whose corpus contains a hard
link for every fourth file: the extraction must report zero tar failures,
and a sample pair must share one inode with nlink 2.

## Fixed on the fork: EXCLUSIVE create

`onCreate` failed any NFSv3 EXCLUSIVE create with `NFS3ERR_NOTSUPP` and
logged `failing create to indicate lack of support for 'exclusive' mode`
(upstream marked it `// TODO`). That is what *every* `O_CREAT|O_EXCL` open
becomes, and git uses it for each lockfile and every `mkstemp`.

The fork implements the mode: create when the name is free, succeed without
touching the file when the same verifier comes back (a retransmission), and
`NFS3ERR_EXIST` when a different one does. `fs.Create` truncates, so it is
skipped on a retransmission — re-running it would discard the data the
original request's writes already put there. Verifiers are held in memory
with a TTL; see the appendix for why they are not persisted in the file's
timestamps as RFC 1813 suggests.

**This is not a throughput win, and the measurement should be believed over
the intuition.** Removing the wasted round trip drops CREATE from 2.00 to
1.00 per created file and raises SETATTR by exactly as much: EXCLUSIVE
carries a verifier where GUARDED carries the attributes, so the client
follows with a SETATTR to apply them. 5.43 RPCs per file either way, and no
measurable difference in wall time. What it buys is retransmission
idempotency, a mode that answers what the protocol says it should, and the
removal of the log filter `internal/nfsmount` used to need.

The same commit fixes the reply's `post_op_attr`, which stat'ed
`billy.File.Name()` — a basename, resolved against the export root rather
than the directory the file was created in.

## Fixed on the fork: REMOVE resolved through a terminal symlink

A directory would not delete. Three `rm -rf` passes, the same 23 files
surviving every one:

    $ rm -rf htcondor/
    rm: htcondor/src/condor_tests: Directory not empty

Every survivor was a **symlink**, and all 23 named the same target — which
sorts ahead of them. `rm -rf` walks a directory in sorted order, so the
target was unlinked before the walk reached any link, and every link was
**dangling** by the time its own turn came.

`onRemoveObj` stat'ed its operands with `fs.Stat`, which follows a terminal
symlink. On a dangling one that is ENOENT, so the handler answered
`NFS3ERR_NOENT` and returned **without ever calling `fs.Remove`**. `rm`
reads ENOENT on an unlink as "someone else got there first" and moves on
without reporting anything, so the link stayed, and the `rmdir` behind it
refused. Nothing about that converges: the retry deletes nothing new and
the same links survive, which is why repeating the command was no help.

RFC 1813 makes both operands of REMOVE and RMDIR *names in a directory* —
"the file to be removed", not the file the name resolves to — and an NFSv3
client walks symlinks itself, one LOOKUP at a time. A server that follows
one has acted on an object the client never named. Two more cases came
with it: a symlink to a **directory** got `NFS3ERR_ISDIR` from REMOVE and
was accepted by RMDIR, and a symlink to a **file** was removed correctly
only because backends do not follow in their own `Remove` — the handler
and the backend disagreed about which object was named and agreed on the
outcome by luck.

The fork uses `fs.Lstat`, which is what every other handler that names its
object by file handle already does (`onGetAttr`, `onSetAttr`, `onLookup`,
`onLink`'s source, `tryStat`). `onReadLink` carried the same confusion in
its error path — it asked `fs.Stat` whether the object was a symlink, a
question `Stat` can only answer about the object at the far end of one —
and is fixed in the same commit.

This is the REMOVE half of the audit that produced `efc3a30`
("vfsbilly, nfsmount: stop setting a symlink's attributes on its target").
That one found the same defect in the SETATTR path and fixed it in pelfs,
because billy names its methods after the `os` functions and those follow;
`Remove` was never given the same look. `internal/vfsbilly` turns out to
have been right all along — its `Remove` resolves the parent and then does
a raw `Lookup`, following nothing — so this one is purely go-nfs's, and
pins that with `internal/vfsbilly/symlinkremove_test.go`.

Gated three ways: `nfs_onremove_test.go` on the fork (dangling, live,
symlink-to-directory, and RMDIR of a symlink), the vfsbilly tests above,
and `deletion_gate` in `scripts/mount-gate-test.sh`, which reproduces the
reported shape on a real kernel NFS client and asserts one `rm -rf` pass
empties it. That gate runs on the FUSE backend too — raw FUSE unlinks by
`(parent inode, name)` and never resolves a path, so it is immune by
construction, and the second leg is what says so rather than assuming it.

## Fixed upstream: RMDIR on a non-empty directory

`onRmDir` delegated to `onRemove`, so an ENOTEMPTY from the backend became
`NFS3ERR_IO`; `NFS3ERR_NOTEMPTY` existed and no handler returned it.
Upstream `master` fixes this (`onRemoveObj` lists the directory and answers
`NFSStatusNotEmpty` before removing anything), which is one reason the fork
is based on master rather than on the v0.0.4 tag we used to pin. Gated in
`scripts/bench-untar-nfs-docker.sh`.

## Worked around in pelfs: an unrecognized error becomes NFS3ERR_IO

`onCreate`, `onMkdir`, `onSymlink`, `onRemove`, `onRename` and `onRead`
answer `NFSStatusIO` for any billy error they cannot place, and they place
only three: `os.IsNotExist`, `os.IsExist`, `os.IsPermission`.

Worse, `onSetAttr` returns `SetFileAttributes.Apply`'s error verbatim,
commented "Already an nfsstatuserror" — which it is not, for the Chmod,
Lchown, Chtimes and Truncate branches, all of which return the backend's
error raw. The response formatter then falls through to
`ResponseCodeSystemError`: an RPC-level rejection rather than an NFS status,
which is how a perfectly ordinary ENOENT reached a client as EIO.

This one *is* fixable from outside, so it is fixed there rather than on the
fork. `internal/nfsmount/diag.go` wraps the served filesystem. Errors from
the attribute setters come back as `*nfs.NFSStatusError` carrying the status
that describes them, which fixes SETATTR outright and leaves Apply's own
`os.ErrPermission` test working through the wrap. Everything else that is
about to become NFS3ERR_IO is logged with its operation, path and cause,
rate-limited, so a bare "Input/output error" on a client is always
explained on the server.

## Enforced in pelfs: the POSIX permission model

`internal/vfsbilly` now applies the mode check itself (`perm.go`). It has to,
and the shape of the reason is the same as everything else on this page: the
check NFSv3 puts on the server is a check go-nfs's handlers do not make.

The FUSE frontend mounts with `default_permissions`, which asks the kernel to
apply the ordinary mode check from the attributes we report before anything
reaches us. The NFS frontend had no equivalent, so the two frontends over one
filesystem answered the same question differently: a file chmod'd 0444
accepted a write through the mount and the bytes survived the seal, while the
same write through FUSE was refused with EACCES. Found by the hostile
exerciser and pinned by
`internal/hostile/testdata/corpus/nfs-ignores-mode-bits.plan`.

**Whose permissions.** The export is loopback, single-mount and single-user,
and every request is evaluated as the SERVER PROCESS's identity — uid, gid,
supplementary groups and capabilities — translated through `internal/idmap`
exactly as reported ownership is. The AUTH_UNIX credential NFSv3 puts in
every request is deliberately not consulted: it is unauthenticated (any local
process can dial the port and claim any uid, and the mount already advertises
AUTH_NULL), and it does not reach a `billy.Filesystem` in any case, since
go-nfs parses it into an unexported request struct and billy carries no
per-request context. Using it would need a commit here on the fork whose only
justification would be a credential we have decided not to trust. What the
check buys is FIDELITY, not access control — the same answer through both
frontends for a program that probes permissions by attempting an operation.

**Capabilities, not uid 0.** The kernel's rule for "root may write a 0444
file" is CAP_DAC_OVERRIDE, and the two come apart exactly where this bug was
found: the hostile container runs as root with that capability dropped, and
its tmpfs reference tree refused the write our mount accepted. So the four
capabilities that change a permission answer are modelled (DAC_OVERRIDE,
DAC_READ_SEARCH, FOWNER, CHOWN) and the credential carries the ones this
process actually holds, read from `CapEff` in `/proc/self/status`.

**The owner override on the data path** is knfsd's, and it arrived with the
ACCESS commit below because neither half is safe alone. See the next section.

## Fixed on the fork: ACCESS answered whatever it was asked

`onAccess` read the client's requested access mask and wrote it straight
back, minus the three write bits when the filesystem does not advertise
`billy.WriteCapability`. It never looked at the object's mode or ownership —
`tryStat` was called only to fill in `post_op_attr`.

That is the client-side half of `default_permissions`, and it is where an
NFSv3 client's `open(2)` is decided: the protocol has no OPEN, so a Linux or
macOS client answers `open`, `access(2)` and `test -w` from the ACCESS reply
(`nfs_permission` → `nfs_do_access`). Echoing the mask made the mount report
"writable" for a file the write path would then refuse, and moved the refusal
from `open` — where the kernel and the FUSE frontend both put it — to the
first WRITE.

The fork adds `nfs.PermissionChecker`, an interface a `billy.Filesystem` may
implement (`Permitted(path) (nfs.Permission, error)`, the read/write/execute
triple for one object), and maps that triple onto the ACCESS3 bits with
knfsd's three access maps (`fs/nfsd/nfs3proc.c`: `nfs3_regaccess`,
`nfs3_diraccess`, `nfs3_anyaccess`). Those maps carry the parts that do not
follow from the triple alone: changing a directory costs SEARCH as well as
write, DELETE is a property of the directory an entry lives in and is never
granted on a file, LOOKUP is never granted on a file. A permission error from
`Permitted` is an answer rather than a failure — knfsd's ACCESS loop steps
past EACCES/EPERM/EROFS and reports the bit as not granted — while
`ErrNotExist` becomes NFS3ERR_STALE, which is what RFC 1813 lists for ACCESS
(NFS3ERR_NOENT is not among its errors). A filesystem that does not implement
the interface keeps the old reply.

`internal/vfsbilly` implements it on the model that was already there
(`perm.go`): `Permitted` is `mayNode` asked three times, so there is one
permission model and ACCESS is a projection of it.

**And the owner override, which is the other half.** knfsd gives a file's
OWNER a bypass on the data path (`NFSD_MAY_OWNER_OVERRIDE`, added by
`nfsd_open` for READ and WRITE and by `nfsd_setattr` for a size change), and
`internal/vfsbilly` now does the same in `mayOpen`. The case it exists for is
`tar -p` extracting a read-only file: `open(O_CREAT|O_WRONLY, 0444)` followed
by writes, where the descriptor legitimately outlives the mode. A stateless
server sees only a WRITE to a file that is by then 0444; refusing it
second-guesses an open the client already made, and the file arrives empty.

The two halves are one design, and the scope of each is what makes it safe:

- ACCESS never takes the override (knfsd's `nfsd_access` never passes the
  flag), so `test -w` on a 0444 file still answers no — to its owner
  included — and the client refuses the open. That is what keeps
  `nfs-ignores-mode-bits.plan` green: the write in it is refused at `open`
  now rather than at the WRITE, and the bytes still do not land.
- The override reaches the data path ONLY. Not the namespace operations
  (creating, removing and renaming a name cost write and search on the
  DIRECTORY — `NFSD_MAY_CREATE`, `NFSD_MAY_REMOVE`, neither of which carries
  the flag), not search permission on the path, not the ownership questions
  chmod/chown/utimes and the sticky bit ask, and not directories, which the
  data path never opens.
- It is uid equality and nothing else, as `nfsd_permission` tests it. Not
  CAP_FOWNER, which stands in for ownership where ownership is what an
  operation *requires*.

Gated by `internal/vfsbilly/perm_test.go` — the ACCESS matrix, stated as the
answers the kernel gives for the same tree, plus the `tar -p` shape and the
owner-override cases — and by `permission_gate` in
`scripts/mount-gate-test.sh`, which extracts a tarball containing a read-only
file over a real kernel NFS client and requires every permission answer to
match the same probe run against a local tree. That gate runs on the FUSE
backend too, where the answers come from the kernel's own `default_permissions`
check: the two legs together are the statement that the frontends agree.

## Tolerated: COMMIT is a no-op

`onCommit` replies OK without flushing, documented as "we always push writes
to the backing store". That is true for the filesystem we serve:
`internal/vfsbilly` has no write-handle cache — the overlay commits each
Write to its staging file before returning — so there is nothing buffered
for a COMMIT to flush. Durability beyond that is the seal at exit and the
periodic checkpoint, which is pelfs's actual promise.

## Appendix: considered and not taken

Recorded so they are not re-proposed.

- **Rewriting RPCs in a wrapping `net.Listener`.** Technically possible and
  far worse than a fork: it means re-implementing record marking and XDR,
  and the substitution changes message sizes. This is the last avenue left
  once the four interception points above are closed, and it is why the
  fork exists at all.
- **A patch honoring an optional `Sync() error` on the backend's
  `billy.File`.** Easy, and written once. Not carried, because nothing here
  needs it — see "COMMIT is a no-op" — and a fork should hold only what is
  load-bearing. Revisit if a backend ever buffers writes.
- **Persisting EXCLUSIVE verifiers in the file's timestamps**, as RFC 1813
  suggests. Rejected in favour of an in-memory table with a TTL: the
  property that matters — never truncating a file whose name someone else
  won — holds either way, and a verifier lost to a restart or the TTL
  merely turns a retransmission back into the EXIST error it was before.
