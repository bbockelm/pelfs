# A pelfs volume in the Finder

`pelfs mount --finder` makes a mount look and behave like a Mac volume:
it shows up in the Finder sidebar under **Locations**, under a name you
choose, with an eject button that ends the session cleanly.

```
pelfs mount --rw --finder pelican://<federation>/<prefix>
```

That is the whole command. What it does, in one line each:

- resolves a **volume name** — the last component of the prefix, or
  `--volume-name "Survey Data"`;
- mounts on `/Volumes/<name>` if that directory exists and is yours, else
  on `~/Volumes/<name>`, which it creates;
- drops the `nobrowse` mount option, which is what has been keeping pelfs
  volumes out of the macOS GUI;
- **refuses the Finder's bookkeeping files** so they are never sealed into
  the volume's history;
- **watches the mount table**, so ejecting in the Finder seals the session
  and exits, exactly as `pelfs umount` does.

Undo is `pelfs umount <prefix>` — or eject in the Finder, which now means
the same thing. Nothing about the default mount changed: without
`--finder`, pelfs mounts exactly as it always has, invisible to the GUI,
which is what scripts, CI and every Linux user rely on.

## What you should see

- **Finder sidebar → Locations**, an entry named after your volume, with an
  eject symbol beside it. On the Desktop too, if Finder Settings → General
  → "Connected servers" is checked.
- **A network-volume icon**, because that is what it is: an NFS volume
  served from 127.0.0.1 by the pelfs process itself.
- **A very large amount of free space.** go-nfs answers FSSTAT with 2^62
  bytes free, so the Finder's window footer says something like "4.61 EB
  available". Cosmetic; a read-only mount correctly reports zero available
  and the Finder treats it as read-only.
- **One permission prompt, once per application.** The first time an app
  touches the volume, macOS asks whether it may "access files on a network
  volume" (TCC). The Finder is one such app.

## The volume's name

Two things can name an NFS volume on macOS, and which one the system uses
is not something a mount option settles: `mount_nfs` has **no** `volname`
option (its manual page lists every option it accepts), so there is no way
to state the name outright. The two candidates are the last component of
the **mount point** and the **exported path** in `host:/export`. pelfs sets
both to the name you chose, so the answer is the same either way.

That is also why the mount point matters: a `--finder` mount never lands on
`<state-dir>/mnt`, because a volume called "mnt" is exactly the experience
this flag exists to avoid.

## Getting it into /Volumes

`/Volumes` is `drwxr-xr-x root:wheel` with no ACL, so no unprivileged
process can create a directory there — and the kernel will not let you
mount on a directory you do not own. One command, once per volume name,
fixes both:

```
sudo mkdir -p "/Volumes/Survey Data" && sudo chown $(id -u) "/Volumes/Survey Data"
```

Both halves are required. `sudo mkdir` alone leaves a root-owned directory,
and an unprivileged `mount(2)` on it is refused by the kernel — so pelfs
checks the owner before it tries, and falls back with a sentence rather
than failing with a mount error.

From then on `pelfs mount --finder --volume-name "Survey Data" <prefix>`
uses it automatically; it says so in its output, and says the two commands
above when it falls back to `~/Volumes`. To undo:
`sudo rmdir "/Volumes/Survey Data"` when nothing is mounted on it.

Being in `~/Volumes` costs you the path shown in Get Info and nothing else:
the name in the sidebar, the eject button and the teardown are the same,
because all three come from the mount's options and not from its location.

### Why not go through NetFS, like "Connect to Server" does

The Finder's own network mounts land in `/Volumes` without sudo, so the
question is a fair one. The machinery is NetFS: `open nfs://…`,
AppleScript's `mount volume`, and `/usr/libexec/mount_url`, all of which
reach `/System/Library/Filesystems/NetFSPlugins/nfs.bundle`.

It **can** express what this backend needs. The plugin reads the URL's
query parameter `options=`, splits it on commas and hands it to
`mount_nfs` as `-o…` with `:` rewritten to `=`. So

```
nfs://127.0.0.1/Survey%20Data?options=vers:3,tcp,port:54321,mountport:54321,nolocks,noresvport,soft,retrans:3,actimeo:1
```

is the URL form of the exact option list pelfs passes today — the port
included, which is the part that looks impossible. That was verified
against the plugin's own code and then against the system: pointing
`/usr/libexec/mount_url` at a dead port produced `mount_nfs: can't mount
/PelfsProbe from 127.0.0.1: Connection refused`, which is only reachable if
the port and export path from the URL arrived.

pelfs does not use it, for three reasons:

1. **It creates no mount point.** `mount_url` passes NetFS's
   `MountAtMountDir` and still mounted onto the directory it was handed,
   not a subdirectory of it. The `/Volumes` problem is untouched: somebody
   still has to create the directory, and doing it needs root.
2. **The route that does pick a mount point gives up naming and knowing.**
   Only a caller that passes *no* path — the Finder, or `mount volume` —
   gets a `/Volumes/<name>` chosen for it, and then the name is derived by
   the system, the location has to be recovered by reading the mount table
   back, and the whole thing wants a GUI login session, which a background
   `pelfs mount` daemon is not.
3. **It needs cgo or AppleScript.** `NetFSMountURLSync` is a C API, and
   pelfs builds `CGO_ENABLED=0` on purpose.

If you want to try the Finder's own route by hand, this mounts a *second*
client on the same running server (it does not replace the pelfs mount, and
ejecting it does not end the session):

```
osascript -e 'mount volume "nfs://127.0.0.1/name?options=vers:3,tcp,port:PORT,mountport:PORT,nolocks,soft"'
```

with `PORT` from the mount's log line. Untested here; the reason it is
written down is that it is the only route to `/Volumes` that needs no sudo.

## Eject, and what happens to your data

Ejecting in the Finder unmounts the volume. The pelfs process is not
signalled and does not find out — it is the *server*, and a client that
unmounts simply stops sending requests. Before this flag existed, such a
session sat waiting for a signal it would never get, holding an **unsealed
overlay**: the user believed they were finished, and the work was not
published.

So a `--finder` session polls the mount table every two seconds
(`getfsstat(2)` with `MNT_NOWAIT`, one syscall, no RPC), and the first time
its mount point is not in it, it treats that as the end of the session:
stop serving, drain checkpoints, seal, exit. Ejecting is `pelfs umount`.

`getfsstat(2)` and not `statfs(2)` on the mount point, deliberately: that
call goes *to the filesystem*, so on our own NFS mount it is an FSSTAT RPC
into the process doing the polling. `MNT_NOWAIT` reads the kernel's cached
rows and asks nobody anything.

Two details worth knowing:

- **Nothing is lost by ejecting**, sealed or not. Writes reach the local
  overlay before the client is told they are done, and the overlay survives
  on disk; what an unsealed overlay costs is publication, not data, and
  remounting resumes it.
- **An eject the Finder refuses** ("the volume is in use") leaves the mount
  attached and the session running, because nothing was unmounted.

A mount table that cannot be read is not treated as an unmount: the session
seals on evidence, never on a failed probe.

## Eject and idle sealing: two triggers, one teardown

pelfs has another thing that acts on a live session without being asked.
**Idle sealing** (`cmd/pelfs/idleseal.go`, `docs/design-webui.md` U10)
publishes a `pelfs browse` session once the last browser tab has been gone
for a quiet window, because a tab — unlike a mount — has no unmount. From a
distance that is the same idea as watching for an eject, and it is worth
saying plainly why they are two mechanisms and not one.

They answer different questions and produce different outcomes:

| | idle sealing | the eject watch |
|---|---|---|
| asks | should this session **publish now**? | is this session **over**? |
| evidence | the browse server's open SSE streams, plus overlay write pressure | the kernel's mount table |
| outcome | a **checkpoint** — the session keeps serving | a **teardown** — seal once at exit, then exit |
| repeats | yes, with the pressure path's backoff | no; it fires at most once |
| surface | `pelfs browse` (no mount exists) | `pelfs mount --finder` (no browse server exists) |

Merging them would produce a function whose two halves share a ticker and
nothing else, and whose only common parameter is the semantic difference
itself. So they stay separate. What was **not** done is the thing that
would have been wrong: the eject watch is not a second thing that can seal.
It contributes exactly one edge to `awaitMountEnd`, the single select that
already ends a mount session, and everything after that edge — draw the
teardown boundary, unmount, stop the session, drain checkpoints, seal at
exit — is the sequence a signal has always run, in the same order. There is
one sealer at exit and one place that decides the session is over.

What the two triggers **do** share is one fact: `genSession.ending`, set by
`beginTeardown`. Before it existed, "the session is ending" was a
`sync.Once` with no reader, so an automatic publish could start on the far
side of the boundary — after the eject, after the signal, at the moment the
exit path was about to seal the same overlay. Nothing is corrupted when
that happens (`genSession.mu` serializes the seals), but the exit blocks on
a publish nobody is waiting for and the phase breakdown charges a
checkpoint to a teardown. Now every automatic-publish trigger reads the
same bool, however the session came to be ending.

Both directions of the interaction are asserted in
`cmd/pelfs/ejectseal_test.go`:

- **idle during an eject** — an armed idle sealer stops being due the
  instant a teardown begins, and claims no publish slot;
- **eject during a seal** — an eject that lands with a checkpoint parked
  mid-upload joins it through the same `drainCheckpoints` a signal uses,
  and the generation lands.

`pelfs browse` and `--finder` do not meet. A browse session mounts nothing
— its backend is literally `"browse"`, and it serves the volume over HTTP
and WebDAV on 127.0.0.1 — so it has no mount point whose disappearance
could mean anything, and `--finder` is not one of its flags. A future verb
that both mounted and served the page would put both triggers in one
process; the shared `ending` fact is what makes that safe, and the test
above is written so that it keeps being asserted.

## Finder bookkeeping files

Once the Finder can see a volume it writes to it. Every window a user opens
leaves a `.DS_Store`; the metadata daemons drop `.Spotlight-V100`,
`.fseventsd` and `.DocumentRevisions-V100` at the volume root. On a `--rw`
pelfs mount those are not scratch files: they are chunked, packed,
uploaded, sealed into the next generation and published to every other
client — and rewritten again the next time a window moves.

A `--finder` mount therefore answers as though those names did not exist:
`ENOENT` to a lookup, `EACCES` to a create. This is the same answer a
read-only network volume gives, which is why browsing an SMB share you
cannot write to produces neither a `.DS_Store` nor a complaint. The full
list is `internal/nfsmount/finderfiles.go`, and the filter rides inside the
existing diagnosis wrapper because that wrapper's shape — one type per
combination of the optional interfaces go-nfs type-asserts for — is the
expensive part, and a second wrapper answering those assertions differently
would silently change which RPCs the mount supports.

Two neighbours are deliberately **left alone**, because refusing them would
break something the user asked for rather than housekeeping they did not:

- `._name`, the AppleDouble sidecar the Finder writes when copying a file
  whose extended attributes the destination cannot hold. Refusing it fails
  the copy.
- `.Trashes`, where "Move to Trash" puts things on a network volume.
  Refusing it turns an undoable delete into an error.

Both are sealed and published like any other file today. The right place to
stop them reaching the federation is a **never-publish rule in
`internal/publish`**, which would drop them at the seal without breaking
the copy or the delete that created them — a filter at the mount cannot,
because at that layer a Finder copy and a user's own file are the same
write. That is a follow-up, tracked in `docs/TODO.md`, and deliberately not
built here.

If you would rather no Mac ever wrote `.DS_Store` to a network volume,
macOS has its own switch, and it is global rather than per-volume:

```
defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
```

Spotlight, for its part, does not index network volumes by default, so the
volume is not silently read end to end after mounting.

## Things this does not do yet

- **Unicode normalization.** The Finder types names in NFD; a file created
  on Linux is usually NFC. `mount_nfs` has an `nfc` option that converts
  names on the way to the server, which would make cross-platform names
  match — and would change how names already in a volume are addressed.
  Not enabled; it needs a decision about the volume's on-disk form, not a
  mount option.
- **A volume icon.** `.VolumeIcon.icns` is refused along with the rest of
  the Finder's bookkeeping, so a pelfs volume shows the generic network
  icon.
- **`pelfs shell --finder`.** `shell` mounts on a temporary directory it
  deletes at exit; a volume named `pelfs-mnt-1234567` that vanishes when a
  subshell exits is not what this flag is for. Use `pelfs mount --finder`.
- **The eject watch on an ordinary NFS mount.** A mount without `--finder`
  has no eject button, so the watch is not attached — but an outside
  `umount` of one has the same unsealed-overlay trap, and `pelfs umount`
  avoids it only because it sends a signal. Widening the watch to every NFS
  mount is a behaviour change for every existing scripted mount, so it is
  written down rather than done: see `docs/TODO.md`.
