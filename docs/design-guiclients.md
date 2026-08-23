# Which protocol pelfs should export so an existing GUI client can drive it

Status: **measured; the SFTP recommendation is still NOT built, and
something else shipped in its place.** `docs/design-webui.md` was written
after this document, took its analysis as input, and built a browser UI
plus a WebDAV export on one loopback listener. So **G6, G8, G9 and G11 are
DONE, G4 shipped under this document's own name but as HTTP rather than
SFTP, and G1/G2/G3/G5/G10 — the SFTP frontend itself — remain open**. Every
ranked item now carries a verdict; read that column before chasing
anything here. The verdict below still stands as the argument for SFTP, and
nothing in it was overturned: what happened is that a second document found
a cheaper route to the *same two user questions*, and SFTP was not built
rather than being ruled out.

The rest of this document is unchanged. The one thing that *is* measured is the Go side:
`scripts/sftp-clients-docker.sh` drives `github.com/pkg/sftp`'s own
reference handler with two real, independent clients (OpenSSH `sftp(1)` and
`rclone`) and its numbers are in "What was measured". Every client-side
claim is cited to a vendor page or to the client's own source, or marked
UNVERIFIED with the experiment that would settle it. There is no Windows
machine in this loop and no paid client, and the document says so where
that matters.

This document **replaces the frontend recommendation** in
`docs/design-windows.md` and does not re-argue any of its findings. Read
that document for the WebDAV redirector's limits, the deprecation, the
`MAX_PATH`/reserved-name hazard table, the loopback-SMB dead end and the
WinFsp cgo correction; all of it stands. What changed is the *goal*: not a
drive letter, but "upload, download, and double-click to open." The section
"What survives of D1–D10" says exactly which of that document's ranked work
items live and which are now dead.

---

## Verdict

**Export SFTP first**, because it is the only protocol that every free
Windows GUI client already speaks, the only one whose semantics match
pelfs's POSIX model without a translation table, and the one that hands the
drive-letter problem to somebody else's WinFsp code.

Unpacked, in order of how much each fact decides:

1. **The caps that killed the drive letter belong to the Windows
   redirector, not to WebDAV, and not to any protocol.**
   `FileSizeLimitInBytes` (50,000,000) and `FileAttributesLimitInBytes`
   (1,000,000) are values under
   `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters` and
   Microsoft documents them as limits *"that the WebClient service
   allows"* [S1]. An ordinary HTTP or SSH client has no WebClient service
   in its path: Cyberduck's WebDAV is Sardine over Apache HttpClient [S12],
   WinSCP's is neon [S13], rclone's is its own `rest.Client` [S14]. So the
   47.68 MiB refusal and the ~1,000-entry listing are properties of the
   *mount mechanism* the last document chose, and they vanish the moment
   the client is an application instead of a filesystem. **This is the
   pivot's load-bearing claim, and it is confirmed** — with the honesty
   note that no vendor writes the sentence "we do not use the Windows
   redirector"; the argument is from Microsoft's own scoping of the
   registry values (they are values *of the WebClient service*) plus a
   source-level reading of each client's HTTP stack. State it at that
   strength and no higher.
2. **Only one protocol is free in every client.** FileZilla's **free**
   client is FTP/FTPS/SFTP; WebDAV and S3 are **FileZilla Pro** features
   [S8]. So a recommendation of WebDAV or S3 is a recommendation that a
   physicist either buy FileZilla Pro or use a different program. SFTP is
   the intersection of WinSCP (free, GPL) [S5], FileZilla free [S8],
   Cyberduck (free, GPL) [S9], rclone (MIT) [S10] and Windows' own
   in-box `sftp.exe` [S16].
3. **SFTP's semantics are pelfs's semantics.** Modes, mtime, symlinks,
   hard links, random-access reads **and writes**, resume, and free-space
   reporting all have a wire representation, and `internal/vfsbilly`
   already implements every one of them. WebDAV has no symlink concept and
   no standard mtime; S3 has no rename, no mode, no mtime and no partial
   write at all (see "S3, assessed honestly").
4. **The drive letter comes for free, from somebody else.** `rclone mount`
   is free, MIT, pure Go, and mounts an SFTP remote as a Windows drive
   letter through WinFsp [S11]; Mountain Duck (USD 49) does the same from
   the Cyberduck authors and, since v5, without a driver at all [S15]. If
   pelfs speaks SFTP, the drive-letter question is answered by the
   ecosystem and **pelfs writes no Windows filesystem code, ever** — which
   deletes work item D10 and most of D3.
5. **It costs one new module.** `github.com/pkg/sftp` v1.13.11 is
   BSD-2-Clause, pure Go with no `import "C"` anywhere, and its only
   non-test dependencies are `github.com/kr/fs`, `golang.org/x/crypto` and
   `golang.org/x/sys` [S2]. Two of those three are already in the graph
   (`go.mod:115`, `go.mod:13`); the transport plumbing is 80 lines by
   upstream's own example count.

**And build WebDAV second, not instead.** It is genuinely cheap (D1 is
measured at litmus 16/16 · 13/13 · 30/30 · 32/34 against x/net's example
server; **29/30 on `props` is the honest ceiling for a real one** — see
`docs/design-windows.md`),
it is the only protocol Explorer speaks with no install at all, and it is
the second independent client for the same `internal/vfsbilly` code via
macOS `mount_webdav`. What it is *not* is the answer to the question asked,
because it is worse than SFTP at every one of the five points above.

**Do not build S3.** It is the broadest tooling of all and it is the worst
fit: a flat keyspace, no rename on general-purpose buckets [S18], no way to
set an object's mtime [S19], whole-object PUT only [S20], SigV4 to verify,
and `aws-chunked` framing that current AWS SDKs turn on by default [S21].
Every one of those is a lie pelfs would have to tell about a POSIX tree.
The honest assessment is in its own section, and the conclusion is that S3
is the right answer to a *different* question — bulk data movement by
`rclone`/`aws-cli` in a HEP workflow — which `pelfs get` and the pelican
federation already serve better.

**A zero-install browser UI is worth exactly one small thing**, and it is
not the protocol answer: see "The browser UI". Ship it, if at all, as the
*landing page of the SFTP server* — the page that shows the connection
URL, the host-key fingerprint and a "publish now" button — not as the file
transfer mechanism.

---

## The client matrix

Windows specifically. "free" means usable with no payment and no trial
expiry. Every row is cited; the two blanks are marked.

| Client | SFTP | WebDAV | S3 | Free? | Source |
|---|---|---|---|---|---|
| **WinSCP** | **yes** | yes (**5.6+**, 2014-07) | yes (5.13+, plain HTTP needs **6.1+**) | yes, GPLv3+ | [S5], [S6] |
| **FileZilla (free)** | **yes** | **no** | **no** | yes | [S8] |
| FileZilla **Pro** | yes | yes | yes | **paid** | [S8] |
| **Cyberduck** | **yes** | yes | yes (plain HTTP needs a downloaded profile) | yes, GPL | [S9], [S17] |
| **rclone** | **yes** | yes | yes | yes, MIT | [S10] |
| Windows Explorer, *Map network drive* / *Add a network location* | **no** | yes — **via the WebClient redirector, with its caps** | no | in-box | [S1], [S7] |
| Windows in-box `sftp.exe` (OpenSSH client) | **yes** | no | no | in-box | [S16] |
| `duck` (Cyberduck CLI) | yes | yes | yes | yes | [S22] |
| `rclone mount` → drive letter (needs WinFsp) | **yes** | yes | yes | yes, MIT | [S11] |
| Mountain Duck → drive letter | yes | yes | yes | **USD 49** | [S15] |

Four things to read out of that table.

**SFTP is the only column with no "no" and no "paid".** That is the whole
recommendation in one line.

**Explorer's WebDAV is the redirector.** Both Explorer entry points go
through the `WebClient` service, so both inherit `FileSizeLimitInBytes` and
`FileAttributesLimitInBytes`. **Partly UNVERIFIED:** Microsoft documents
those values against the *service* [S1] and documents `NET USE` / *Map
Network Drive* as the way in, but no Microsoft page enumerates what the
*Add a network location* wizard accepts or states that it shares the
redirector. Treat "Explorer WebDAV = redirector limits" as strongly
established for Map-network-drive and inferred for the wizard; the
one-command experiment is `net stop webclient` and then trying the wizard
against an `http://` URL.

**Explorer cannot speak SFTP.** No Microsoft page enumerates the wizard's
accepted schemes, so this is an absence-of-evidence claim rather than a
vendor denial — but it is uncontested, and it is the one thing WebDAV can
do that SFTP cannot. Note what it buys: a drive letter capped at 47.68 MiB
per file and ~1,000 entries per directory, on a service Microsoft
deprecated in November 2023 (`docs/design-windows.md`).

**A Windows box can drive SFTP with nothing installed.** `sftp.exe` ships
in the OpenSSH Client feature, and Microsoft's OEM documentation lists
`OpenSSH.Client` under *"Preinstalled FODs"* — *"the following Features on
Demand come preinstalled in a Windows image"* [S16b]. **Two Microsoft pages
disagree**: the admin-facing OpenSSH overview's table says *"Not installed,
install and enable using optional features"* for Windows 10 1809+ [S16].
The most likely reading is that the overview's column tracks the `sshd`
*service* (its Server-2025 row says "Installed but not enabled", which only
makes sense for a service) while the OEM page is authoritative about the
*client*. Either way the CI answer is the same: probe with `where sftp` and
keep `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0` as the
documented fallback. The GitHub-hosted runner images' own inventories do
not mention OpenSSH at all, so **whether `windows-latest` has `sftp.exe` is
UNVERIFIED** and must be probed rather than assumed.

---

## What was measured

`scripts/sftp-clients-docker.sh`, in the same spirit and the same shape as
`scripts/webdav-litmus-docker.sh`: pkg/sftp's **own** reference handler
(`sftp.InMemHandler()`, the exact analogue of `webdav.NewMemFS()`) behind
`golang.org/x/crypto/ssh`, driven by two independent real clients. **No
pelfs code, no `go.mod` change** — the module is fetched into a throwaway
module inside the image, and the run is `--network none`.

Measured 2026-08-23, **0 failing checks**. `pkg/sftp v1.13.11`,
`x/crypto v0.55.0`, `OpenSSH_10.0p2`, `rclone v1.60.1`, on
`golang:1.26-trixie`.

| check | result |
|---|---|
| `version` | **SFTP protocol 3**; `hardlink@openssh.com`, `posix-rename@openssh.com`, `statvfs@openssh.com` advertised |
| `mkdir-put-get` | **ok** — 1,000,000 bytes, byte-for-byte |
| **`size-68497408`** | **ok** — the owner's own SIF size (`docs/design-apptainer.md`) transfers in **both** directions, byte-for-byte |
| **`dir-5000`** | **ok** — a 5,000-entry directory listed 5000 of 5000 |
| `preserve-mtime` | **baseline gap** — `put -p` sends SETSTAT; `InMemHandler` honours only the size attribute and drops it |
| `chmod` | **baseline gap** — same reason |
| `symlink` | **ok** — created, and listed as a symlink |
| `hardlink` | **ok** — `hardlink@openssh.com` |
| `rename` | **ok** |
| `posix-rename` | **ok** — rename **onto an existing name** succeeds, which plain `SSH_FXP_RENAME` must refuse |
| `df` | **ok** — `statvfs@openssh.com` answered |
| `resume` | **ok** — `reput` completed a truncated upload, i.e. a random-access write at a non-zero offset |
| `rm`/`rmdir` | **ok** |
| `rclone lsl` | **ok** — second, independent client; 5000 of 5000 with mtimes |
| `rclone copy` + `rclone check` | **ok** — clean, 68 MB file included |

**The two rows that decide the pivot are `size-68497408` and `dir-5000`.**
They are precisely the WebDAV redirector's two hard caps, and an ordinary
SFTP client has neither. Nothing was configured to make that true; no
registry value was touched, because there is none.

**The two "baseline gap" rows are the useful failures**, and they are this
suite's equivalent of litmus's two known `locks` failures. They are not
protocol limits: `InMemHandler`'s `Filecmd` does
`if r.AttrFlags().Size { ... Truncate }; return nil` for `Method ==
"Setstat"` [S3], so mtime and mode are accepted on the wire and dropped by
the reference handler. **A pelfs adapter must fill exactly those two
holes, and it already has the code to** —
`internal/vfsbilly.(*billyFS).Chtimes` and `.Chmod` exist and are the NFS
frontend's own implementations. So the table above is the floor a pelfs
adapter must not fall below *and* names the two rows it is expected to
raise.

**One bug the probe found in its own server, worth carrying into the
design.** The first version served each SSH channel synchronously inside
the `for nc := range chans` loop, which deadlocks the second channel on a
connection until the first closes. rclone reported it as
`Discarding closed SSH connection: ... i/o timeout`. A GUI client opens
several channels and several connections — Cyberduck defaults to 2
connections, rclone's `--sftp-concurrency` defaults to 64 — so **each
channel must be served in its own goroutine.** This is the kind of defect
that looks like a pelfs bug from the client side and is not.

---

## Click-to-open, which is half of what was asked

"Double-click a file and it opens" is the same mechanism in both GUI
clients: download to a temp file, launch the associated application, watch
the file, re-upload on save.

- **Cyberduck**: *"The file will be downloaded to a temporary directory and
  opened with the preferred editor. The file will be uploaded to the server
  every time you choose File → Save."* and — usefully — *"The file is not
  changed on the server if you just close the document without saving it or
  if the content has not changed"* [S23]. On Windows the editor is chosen
  by the Explorer file-type association, not by Cyberduck.
- **WinSCP**: *"it needs to download the remote file to temporary directory
  first. Then it opens the file in your preferred editor or associated
  application"* … *"Once you change the file, WinSCP uploads it back"* …
  *"WinSCP watches for changes to them all"* [S24].

What the server must get right, in order of how likely it is to be wrong.

### 1. Rename onto an existing name — the single most important one

Both clients' *default* upload path renames.

- **WinSCP, by default, for every SFTP transfer over 100 KB**: *"Transfer
  to temporary file name is enabled by default for files larger than a
  given threshold"* … *"The threshold is initially 100 KB"*, and *"Transfer
  to temporary filename is supported with SFTP protocol only and only for
  binary transfers"* [S25]. It writes `foo.filepart` and renames onto
  `foo`. If `foo` already exists — which it does on every editor save —
  **that rename must overwrite**, which plain `SSH_FXP_RENAME` is required
  to refuse (SFTP-v2: *"It is an error if there already exists a file with
  the name specified by newpath"*). So `posix-rename@openssh.com` is not
  an optional nicety: **without `PosixRenameFileCmder`, every WinSCP upload
  over 100 KB appears to succeed and then fails at the very last step.**
  The probe's `posix-rename` row is the check for this.
- **Cyberduck**, for the editor path specifically, does the same:
  `editor.upload.temporary` writes a UUID-suffixed name and renames on
  completion [S23]. (Its general queue does not — `queue.upload.file
  .temporary=false` [S17] — so the two paths differ. The default of
  `editor.upload.temporary` is **UNVERIFIED**: the docs frame the hidden
  option as *"Disable* Upload of Temporary File on Save → `= false`", which
  implies `true`, but no page states it.)

This is also *good news*, and it is the write path's best lever: a
rename-on-completion upload is **atomic**, so a checkpoint that fires
mid-drag can never publish a half-written file under its final name. See
"The write path".

### 2. mtime, and only if the client asks

- **WinSCP** has a *"Preserve timestamp"* option [S26], forced on for
  synchronization. Over SFTP the only expression of it is
  `SSH_FXP_SETSTAT` with `SSH_FILEXFER_ATTR_ACMODTIME`, which in protocol 3
  is **atime and mtime together, never mtime alone** — so the adapter's
  `Filecmd` must accept a `Setstat` whose only flag is `Acmodtime` and map
  it to `vfsbilly.Chtimes`. (That SETSTAT is *mechanically* required;
  WinSCP does not document the opcode, so the inference is ours.)
- **Cyberduck** does **not** by default: `queue.upload.timestamp.change
  =false` and `queue.upload.permissions.change=false` [S17]. So a
  Cyberduck upload arrives with the server's clock, and that is the
  client's choice, not our defect.

The rule that follows: **a `Setstat` the adapter cannot honour must
succeed-or-benignly-ignore, never error.** An error there fails the whole
upload after the bytes are already on the server.

### 3. Truncate on open, and the permission check that must not be skipped

An editor save re-opens the file with `O_WRONLY|O_TRUNC`. Both are already
handled: `vfsbilly.OpenFile` implements `O_TRUNC` through
`overlay.SetAttr{Size:&0}` and handles `O_CREATE`/`O_EXCL`/`O_APPEND`.

**But there is a real fidelity defect waiting here, and it is specific to
SFTP.** `vfsbilly.mayOpen` gives the file's owner knfsd's
`NFSD_MAY_OWNER_OVERRIDE` bypass, and its own comment says why: *"NFSv3 has
no OPEN operation at all, so none of these is the client's open(2) — that
was answered on the client, from our ACCESS reply (Permitted below)"*.
**SFTP does have an OPEN.** `SSH_FXP_OPEN` arrives with `pflags`, and the
server is the only thing that can refuse it. An SFTP frontend that calls
`billy.OpenFile` directly therefore inherits the owner override and will
happily truncate a `0444` file — which the kernel refuses locally, which
`default_permissions` refuses on FUSE, and which the NFS frontend refuses
through its ACCESS reply. The fix is one call and the interface already
exists: **ask `billyFS.Permitted(name)` before `OpenFile`, exactly as the
NFS client asks ACCESS before its open.** `Permitted` is documented as *"the
ordinary mode check and NOTHING else: no owner override"* — that is the
check SFTP needs.

### 4. What SFTP does *not* need: a lock

Cyberduck does not lock on WebDAV either — *"Locking is not supported
editing with Cyberduck"*, and only Mountain Duck sends `LOCK`/`UNLOCK`
[S12]. And it sends **no conditional PUT**: its `DAVWriteFeature` sets only
`Content-Range`, `Expect: 100-continue` and (when a lock is held) `If`, and
never `If-Match`/`If-None-Match` [S12]. So the lost-update protection a
WebDAV frontend would build for the editor round trip is protection nobody
asks for. On SFTP the question does not arise: the export is single-user by
construction, and a truncating open is the whole protocol.

**The consequence worth stating on its own: WebDAV class-2 LOCK support is
NOT required for click-to-edit.** That requirement came from the OS
redirector, which takes an exclusive lock before writing
(`docs/design-windows.md` row 16), and the redirector is no longer the
client. So the two `locks` failures in the measured litmus baseline
(`memLS` has no shared locks) stop being "off the path this design needs"
and become "off the path entirely" — a WebDAV frontend for third-party
clients can ship `webdav.NewMemLS()` or, arguably, nothing.

For completeness, the WebDAV editor round trip Cyberduck performs, read
from its source: a `HEAD` (and/or `PROPFIND Depth: 0`) to capture the
current state, then a **plain unconditional `PUT`** with
`Expect: 100-continue` — no `If-Match`, no `If-None-Match`, no `LOCK`
[S12]. **Two readings of this exist and they differ on one point**: whether
the PUT goes to the final name or to a UUID-suffixed name followed by a
`MOVE`. Both are true, and the switch is `editor.upload.temporary` [S23] —
so a WebDAV frontend must implement `MOVE` to be safe, and a design that
skips it works only for users who turned that option off. mtime is not
written at all by default (`queue.upload.timestamp.change=false` [S17]);
when enabled it is a PROPPATCH of `lastmodified` in Sardine's **`SAR:`
custom namespace** — not `DAV:getlastmodified`, not the
`Win32LastModifiedTime` the redirector sends, and not rclone's
`X-OC-Mtime` header [S14]. **Three incompatible mtime conventions and none
of them standard is a WebDAV-specific tax**; the cheapest single win is
`X-OC-Mtime` plus replying `X-OC-Mtime: accepted`, which covers rclone
completely and nothing else. SFTP has one convention, and it is in the
protocol.

---

## The write path: when does an upload become durable?

This is the part most likely to be wrong in a first implementation, so
here is the mechanism as it exists today and exactly where it is
insufficient.

### What already happens, with the numbers

A writable pelfs mount writes into a crash-safe local overlay and
publishes generations on a cadence. From `cmd/pelfs/mountgen.go`:

| trigger | value | source |
|---|---|---|
| periodic checkpoint | **5 minutes**, `--snapshot-interval` (0 disables) | `cmd/pelfs/main.go:172` |
| write-pressure, bytes | **1 GiB** of staged content | `checkpointBytes`, `mountgen.go:1837` |
| write-pressure, inodes | **200,000** dirty inodes | `checkpointInodes`, `mountgen.go:1861` |
| pressure sampling | interval/10, clamped to [1 s, 15 s] | `pressureSampleInterval` |
| skip a pressure checkpoint while uploading | backlog > **64 MiB** | `checkpointBacklogHold` |
| seal at exit | always, unless `--no-seal` | `sealAtExit` |

So there are **three** levels of durability, and a GUI user needs to be
told which one they are at:

1. **Locally durable, immediately.** The overlay commits each write before
   returning (`internal/vfsbilly`: *"The overlay commits each Write to its
   staging file before returning"*), and the write path's own guarantee is
   that a crash **cuts a file back rather than serving it as zeros**. A
   killed `pelfs` loses nothing that was written; a remount resumes the
   same overlay.
2. **In the federation, at the next checkpoint.** Packs are uploaded
   continuously, but a *generation* — the published namespace that names
   them — appears only at a checkpoint or the seal.
3. **Named by the branch**, which is the same event: the checkpoint's
   compare-and-swap on `refs/<branch>`.

For someone dragging 200 files in, the arithmetic is worth doing:

| what they drag | staged bytes | which trigger fires |
|---|---|---|
| 200 documents, ~2 MB each (400 MB) | 400 MB | **neither pressure trigger**; the 5-minute clock |
| 200 SIF images, 68,497,408 B each (13.7 GB) | 13.7 GB | the **1 GiB** trigger, ~13 times |
| 200,000 small files | small | the **200,000-inode** trigger |

The middle row is the good case and the top row is the trap: **a modest
drag-and-drop finishes, the user closes the client, and nothing has been
published for up to five minutes.** If the process is killed in that window
the data is safe locally and invisible to the federation — correct, and
indistinguishable from lost, from the user's side.

### The four things that must be added

**(a) The session needs an end, because a GUI client does not provide
one.** `pelfs mount` seals at unmount; a served port has no unmount. Three
answers, and all three should exist:

- `pelfs browse` runs in the **foreground** and seals on exit, exactly as
  `pelfs mount` does. Ctrl-C is the unmount. This is the default and it is
  the one a physicist will use.
- **Publish on demand needs no new mechanism**: `internal/control` already
  exposes a `Publish` hook over the session's Unix socket (*"seals the
  write overlay into the next generation and returns a summary"*), so
  `pelfs ctl publish` is already the "publish now" button. Print that
  command in the startup banner.
- **Seal on idle.** A checkpoint after the last client disconnects and N
  seconds of quiet is the one genuinely new trigger, and SFTP is the
  protocol that can express it: an SSH connection close is an event.
  WebDAV cannot — HTTP is stateless and "the client went away" is
  indistinguishable from "the user is reading". Recommended: seal when
  connection count returns to zero and stays there for `min(30 s,
  snapshot-interval)`, and say so in the banner. **A pressure-style
  backoff is required** — the existing pressure path doubles its wait to
  the interval on failure, and an idle seal that retried every 30 s
  against a broken federation would reproduce the "same warning forever"
  failure that backoff exists to prevent.

  **This item is DONE, over HTTP, and the "WebDAV cannot" sentence is
  half wrong.** It is true of WebDAV. It is not true of a single-page app
  that holds an SSE stream open for the life of the tab: an SSE stream is
  one long-lived response, so the tab closing cancels the request context,
  which is an event on the same footing as an SSH channel close — and it
  arrives sooner, because there is exactly one stream per tab and the page
  opens it on load. `cmd/pelfs/idleseal.go` is the implementation and the
  backoff requirement above is honoured verbatim. Two corrections to the
  recipe: `min(30 s, snapshot-interval)` is **undefined at interval 0**,
  which a user types on purpose to mean "seal only at unmount", so idle
  sealing is **off** there; and a `sendBeacon` hint on `pagehide` arrives
  *before* the stream teardown, so it needs a lead tolerance or it is
  discarded every single time.

**(b) A partial upload must not be published under its final name.** If a
client disconnects mid-`PUT`, the bytes already written are in the overlay
and the next checkpoint publishes a truncated file. Three mitigations, in
order of strength:

- **Rely on the client's temp-name-and-rename, and make it work.**
  WinSCP does this by default above 100 KB [S25]; Cyberduck's editor does
  it [S23]. Then the final name never exists until the upload completed,
  and a checkpoint mid-drag publishes `foo.filepart` — visible, obviously
  incomplete, and cleanable. **This is the strongest argument for
  implementing `PosixRenameFileCmder`, and it is a durability argument, not
  a compatibility one.**
- **Use `TransferError`.** pkg/sftp offers an opt-in interface:
  *"an optional interface that readerAt and writerAt can implement to be
  notified about the error causing Serve() to exit with the request still
  open"* [S2]. A `WriterAt` that implements it learns, precisely, that this
  upload died. What to do with that is a policy question the design should
  settle deliberately: **unlink a file this session created and never
  finished**, and leave a file that already existed alone (it has been
  partially overwritten, which is what the client asked for). Do not
  silently unlink somebody's pre-existing file.
- **Report it.** Count interrupted uploads and name them in the banner and
  in `pelfs ctl stats`. Every omission in this project is counted; this one
  should be too.

**(c) `--rw` needs a different default posture than it has for a mount.**
A mount's writer holds an advisory lease on the branch for the whole
session (`internal/lease`), and the seal's compare-and-swap is the real
guard. A `pelfs browse --rw` session is *longer and idler* than a mount
session — somebody leaves Cyberduck open all afternoon — which is exactly
the shape the lease documentation warns about: *"A suspended process runs
no ticks: a laptop that closes its lid for three hours wakes with a lease
that expired long ago."* `Fence` already handles this on every
flip-bearing operation. What the design must add is not a mechanism but a
**message**: an idle browse session that has lost its branch should say so
in the banner rather than at the seal, and `pelfs browse` should probably
default to **read-only**, with `--rw` explicit. Downloading is what most
people want, and a read-only export cannot lose anything.

**(d) On Windows specifically, `--rw` is blocked on work that is not this
document's.** The `winport-agent` audit in `docs/TODO.md` is explicit:
Go opens files without `FILE_SHARE_DELETE`, so `internal/overlay`'s
`handOver` — whose *design* is a rename under an open reader — fails on
Windows, and *"every write below a frozen length during a live checkpoint
fails."* Add `os.Getuid() == -1` making `fsperm.ProcessCred()` a uid of
`0xFFFFFFFF` with no groups and no capabilities, and the AF_UNIX control
socket's missing unlink-on-close. **So the read-only download-and-browse
milestone is close on Windows and the upload milestone is not.** The
honest sequencing is: read-only SFTP export runs on Windows first; writes
from a Windows-hosted pelfs wait for that hazard list; and a Windows user
who needs to *upload today* points their client at a pelfs running on
Linux or macOS — where the write path is shipped — at the cost of leaving
the loopback threat model, which is a decision the owner should make
explicitly and not by accident.

---

## Auth, per protocol

The bar to clear is low and worth stating: **the loopback NFS export pelfs
ships today has no authentication at all.** It advertises `AUTH_NULL`, and
`internal/vfsbilly/perm.go` says why that is acceptable and what it costs:
*"The export is loopback (127.0.0.1, a port nobody is told), single-mount,
and single-user"*, and *"Any local process can dial the loopback port and
claim any uid it likes."* Every option below is strictly stronger than
that.

**SFTP — recommended.** A host key plus a per-session credential.

- **Host key: persist it in the volume state directory.** An ephemeral
  key means an "unknown host key" dialog on every launch, which trains the
  user to click through warnings. One key per state dir means one dialog,
  ever. `x/crypto/ssh` refuses to start without one
  (*"ssh: server has no host keys"*), so generation is not optional;
  ed25519 via `crypto/ed25519` + `ssh.NewSignerFromSigner` costs nothing.
- **Credential: a random per-session password over `PasswordCallback`, or
  a per-session keypair over `PublicKeyCallback`.** The password is
  simpler and is what lets a one-click URL work (below). Compare in
  constant time. Note the x/crypto caveat that *"A call to
  [`PublicKeyCallback`] does not guarantee that the key offered is in fact
  used to authenticate"* — use `VerifiedPublicKeyCallback` if any decision
  hangs on it.
- **Two pitfalls in `x/crypto/ssh` server-side**: there is **no handshake
  timeout** (`Timeout` exists only on `ClientConfig`), so the listener must
  `SetDeadline` around `NewServerConn` itself or a stalled connection pins
  a goroutine forever; and the global `reqs` channel and the `chans`
  channel must both be drained or *"the connection will hang"*.
- **Identity: do not change the model.** Evaluate every request as the
  server process's own `fsperm.ProcessCred()`, mapped through
  `internal/idmap`, exactly as the NFS frontend does. The per-session
  credential authenticates *the owner*, so the authenticated identity and
  the evaluated identity coincide — which is the same argument
  `vfsbilly/perm.go` already makes, now with the credential actually
  verified.

**WebDAV — Basic over loopback is enough, and simpler than the digest the
last document chose.** `docs/design-windows.md` picked Digest because the
redirector's `BasicAuthLevel` defaults to 1, i.e. *"Basic authentication is
enabled for SSL web sites only"* [S1]. **That is a redirector constraint,
and the redirector is the odd one out.** Every third-party client accepts
Basic over plain HTTP:

- **Cyberduck** ships a distinct plain `WebDAV (HTTP)` protocol
  (`DAVProtocol.java`), supports *"both HTTP Basic Authentication and
  Digest Authentication"* [S12], and sends Basic **preemptively** by
  default (`webdav.basic.preemptive=true` [S17]) — so there is not even a
  401 round trip. It shows a dismissible plaintext-credentials warning;
  `duck --assumeyes` clears it for CI.
- **WinSCP** treats the *"basic **unsecured** variant"* as first-class
  [S13].
- **rclone** gates on nothing; its only guard is on HTTPS→HTTP
  *redirects*, and WinSCP has the same one (*"Not allowing WebDAV
  redirects to an unencrypted URL by default"* [S6]) — which matters only
  for a design that redirects, and this one does not.

**So if WebDAV is built for third-party clients rather than for Explorer,
Basic over 127.0.0.1 is the whole auth story**, and D2's digest handshake
becomes optional. What that gives up, stated plainly: the credential
crosses the loopback socket in base64, readable by anything that can
capture loopback traffic on that machine — which, on Linux and macOS, means
root or the owner's own uid. That is a *weaker* posture than Digest and a
much *stronger* one than the NFS export shipping today, which needs no
credential at all. The one thing it forecloses is Explorer, which refuses
Basic over HTTP by default; if Explorer ever becomes a target, digest
comes back and D2 grows again.

**S3 — SigV4, and there is exactly one reusable Go verifier.**
`github.com/rclone/gofakes3/signature` exports
`V4SignVerify(r *http.Request) ErrorCode`, MIT, lifted from MinIO's
algorithm. `aws-sdk-go-v2/aws/signer/v4` **cannot** be used to verify by
re-signing: `SignHTTP` computes its own `SignedHeaders` set and offers no
way to supply the client's, so re-sign-and-compare matches only by
coincidence. One embedding caveat if gofakes3 is ever used: its credential
store is a package-level `var credStore sync.Map`, so it is one credential
set per process.

---

## Connect-by-click

A `pelfs browse` verb that starts the server and opens the user's client is
a small thing that changes the experience, and all three mechanisms exist.

**A `sftp://` URL handed to `start` (Windows) / `open` (macOS) /
`xdg-open`.** WinSCP's documented session URL is
`<protocol>://[<username>[:<password>][;<advanced>]@]<host>[:<port>]/` and
**accepts a password inline** [S27]. It also supports pinning the host key
in the URL: *"There's a special syntax to include an expected SSH host key
fingerprint in SFTP / SCP URL among advanced site settings:
`fingerprint=<fingerprint>`"*, e.g.
`sftp://martin;fingerprint=ssh-rsa-2EP3...@example.com/` [S27]. **Two
gotchas that must be in the implementation, not discovered later:** the URL
fingerprint *"does not override any fingerprint already cached on the
machine"* (the `-hostkey` switch does), and the URL fingerprint format
differs from every other WinSCP fingerprint format — spaces become dashes,
and the key size is dropped. Whether WinSCP is registered as the `sftp://`
handler is install-dependent; the docs phrase it conditionally, so **do not
design around it being automatic.**

**A `.duck` bookmark for Cyberduck.** *"You can double-click the document
in the file browser to open a new connection to the server specified in the
bookmark"* and *"You can share bookmarks between Mac & Windows as the file
format is the same on both platforms"* [S28]. The key set — read from
`HostDictionary.java`, because **the format is not documented** — includes
`Protocol`, `Hostname`, `Port`, `Username`, `Path`, `Nickname`, `Labels`,
`Readonly` and a free-form `Custom` map. **There is no host-key or
fingerprint key**; Cyberduck pins through OpenSSH's own file
(`ssh.knownhosts=~/.ssh/known_hosts` in its `default.properties`), so the
pre-seed path for Cyberduck is **appending a `known_hosts` line**, not the
bookmark. (Whether `ssh.knownhosts` can be overridden per-bookmark via the
hidden-properties mechanism is **UNVERIFIED**.) That `.duck` is a plist is
strongly implied by the sibling `.cyberduckprofile` format but not stated
in any doc.

**A WinSCP scripting invocation for CI and for power users.** `winscp.com`
with `/script=` or `/command=`, and `open ... -hostkey="..."` which
*"makes WinSCP automatically accept host key with the fingerprint"* [S29].
Note *"When running commands specified using `/script` or `/command`, batch
mode is used implicitly and overwrite confirmations are turned off"* — good
for CI, and the reason CI and interactive behaviour can differ.

**rclone pins with `--sftp-known-hosts-file`** (*"Set this value to enable
server host key validation"*) or `--sftp-host-keys` (*"Pinned host keys for
this remote... the same format as the second and third fields of an
OpenSSH known_hosts line"*) [S10]. Note the option is `host_keys`, plural.

**Recommendation.** `pelfs browse` should: bind `127.0.0.1:0`; load or
generate a persistent ed25519 host key in the state dir; mint a random
session password; print the URL, the port and the SHA-256 fingerprint in
all three formats a client wants; write a `.duck` bookmark and a
`known_hosts` line next to it; and `--open` (opt-in, not default) hand the
URL to the platform opener. **Do not write into the user's
`~/.ssh/known_hosts` without asking** — that file is theirs, the standing
rule in this repo is nothing under `$HOME` that was not asked for, and an
appended line for a port that will change is litter.

---

## Testing without a GUI

Four layers, cheapest first. Three need no Windows and none needs a GUI.

1. **`pkg/sftp` + OpenSSH + rclone in Docker, as a gate.**
   `scripts/sftp-clients-docker.sh` exists and is measured. Point it at the
   pelfs adapter instead of `InMemHandler` and the table above becomes a
   regression test: a new failure in a row that was `ok` is the adapter's,
   and the two `preserve-mtime`/`chmod` rows must **flip to `ok`**, because
   `vfsbilly` implements what `InMemHandler` does not. Cheap enough for
   every PR. This is the exact pattern
   `scripts/webdav-litmus-docker.sh` established, and the reason to keep
   both scripts is that they test different frontends over the same
   `internal/vfsbilly`.
2. **`httptest`-shaped Go units, no client.** The `Handlers` methods are
   ordinary functions of a `*sftp.Request`; drive them directly and assert
   the `Pflags()`/`AttrFlags()` mapping, that a `Setstat` with only
   `Acmodtime` succeeds, that `Permitted` is consulted before `OpenFile`
   (the owner-override defect above), and that a `TransferError` unlinks a
   file this session created and does not unlink one it did not.
3. **`duck`, the Cyberduck CLI, as a third client — and the cheapest way
   to exercise a real client's stack in CI.** Packaged for Windows
   (`choco install duck`), macOS (`brew install duck`) and Linux (apt/yum
   repos), with `--upload`/`--download` and the SFTP, WebDAV and S3
   protocols [S22], and — better for CI — an official container image
   `ghcr.io/iterate-ch/cyberduck` and a GitHub Action
   `iterate-ch/cyberduck-cli-action@v1`. Use `--assumeyes` to clear the
   plaintext-credentials prompt. It shares the Cyberduck codebase, so it
   exercises Sardine and the Cyberduck SSH core rather than our reading of
   the spec. Two notes: the shipped version was reported as **6** by one
   source and **9.5.3** by another, so pin it in the job and log what it
   used; and it documents **no** host-key or fingerprint CLI option, so a
   CI job must arrange `known_hosts` itself (**UNVERIFIED** that it reads
   one).
4. **A `windows-latest` job driving `sftp.exe` and `WinSCP.com`.** The only
   layer that needs Windows, and it is far cheaper than the WebDAV one the
   last document proposed: no registry writes, no service restart, no
   elevation, and therefore no need to run twice at two configurations.
   The job must (a) `where sftp` and log the answer — the runner image
   inventory does not document OpenSSH, so a green run that silently
   installed it proves less; (b) drive `WinSCP.com /script=` with
   `open ... -hostkey=` to prove the no-dialog path; and (c) transfer a
   68,497,408-byte file both ways, byte-for-byte, which is the whole point
   of the pivot.

For a WebDAV frontend, `rclone` has `--webdav-unix-socket`, which makes a
hermetic run possible with no TCP port at all — worth using, because it
removes the whole class of "a green run reached something else". `litmus`
and `cadaver` remain the right tools and
both are alive under the neon author: litmus **0.18** (2026-06-28) and
cadaver **0.28** (2025-09-18) [S30]. Note cadaver 0.28's changelog entry
*"'edit' uses a conditional PUT (where possible) to avoid conflicts"* —
which makes cadaver a *better* conditional-PUT exerciser than Cyberduck,
whose editor sends none.

---

## The browser UI, assessed

**This section's conclusion — "build the landing page, not a file manager"
— was overturned, and `docs/design-webui.md` is where the argument is.**
Two things this assessment did not have: the licence answer for the
component that removes most of the UI cost (`@svar-ui/*` is MIT, not
GPLv3 — that belief describes the retired `wx-*` generation), and the
observation that a single-page app holding an SSE stream open makes "the
client went away" a real event, which is the mechanism this section says
HTTP cannot express. The *cost* reasoning below is still correct and is
worth reading before anyone adds to the UI; the verdict it reached is not.
The `iofs`/`io.Seeker` concern is retired outright: going through
`webdav.File`, or calling `http.ServeContent` with the `billy.File`
directly, avoids `iofs` and the problem does not arise.

A page served on `127.0.0.1` with drag-and-drop upload and click-to-
download needs no client software at all, which for "most folks just want
upload and download" is the lowest-friction thing imaginable. It deserves a
fair hearing and it does not win.

**What it costs.** The read half is nearly free — `internal/vfsbilly` is a
`billy.Filesystem`, and `go-billy`'s `helper/iofs` adapts that to `fs.FS`
— *except* that `iofs`'s file type implements `fs.File` and **not
`io.Seeker`**, so `http.FS` + `http.FileServer` cannot serve a `Range`
request and every download would be a whole-file stream from byte zero.
The fix is small (call `http.ServeContent` with the `billy.File`, which
does have `Seek`) but it is the first sign of the real cost: **a browser UI
is a UI**. Directory listing, sort, breadcrumbs, a progress bar, multi-file
upload, resumable upload, error surfaces, and every one of those is a
thing to maintain forever in a project whose entire frontend surface today
is three protocol adapters over one interface. The GUI clients already have
all of it, written by people who do that for a living.

**Where it is worse.**

- **No resume, no random access, no partial write.** A browser upload is
  one `POST`/`PUT` per file; a dropped connection at 90% of a 68 MB file
  starts over. SFTP's `reput` is measured working above.
- **No mtime, no mode, no symlinks.** The same losses S3 has.
- **No drive letter, ever**, and no click-to-open-and-save: the browser
  downloads to `Downloads` and the round trip back is manual.
- **Directory upload is a Chrome-family extension** (`webkitdirectory`),
  not a standard, and drag-and-drop of a folder is inconsistent across
  browsers.
- **It is a new authenticated HTTP surface** with a CSRF story, whereas
  SFTP's auth is the SSH handshake.

**Where it wins, and this is worth keeping.** As the *landing page of the
SFTP server*, a single static page is genuinely valuable: it shows the
`sftp://` URL, the port, the host-key fingerprint in the three formats
different clients want, a copy button, a "publish now" button wired to the
`control.Publish` hook that already exists, and the count of files uploaded
and not yet sealed. That is one page with no file transfer in it, and it
turns `pelfs browse`'s startup banner into something a person can act on.
**Recommendation: build that page, not a file manager.**

---

## S3, assessed honestly

S3 has the broadest tooling of the three — Cyberduck, WinSCP, FileZilla
Pro, rclone, `aws-cli`, and every data mover in HEP — and pelfs is already
a content-addressed object store underneath. The case is real. It still
loses, and not narrowly.

**What it would cost.** `github.com/rclone/gofakes3` (MIT, pure Go) is the
right library if it is ever built: `gofakes3.New(backend).Server()` returns
an `http.Handler` and the required `Backend` interface is 11 methods, with
`MultipartBackend` (4 more) and `VersionedBackend` optional by type
assertion. Note MinIO is **not** an option: the repository is archived
(*"THIS REPOSITORY IS NO LONGER MAINTAINED"*), community binaries are gone,
and it is AGPL.

**What it cannot express, each of which is a lie about a POSIX tree.**

| pelfs has | S3 has | consequence |
|---|---|---|
| directories | a flat keyspace with `Delimiter`/`CommonPrefixes` [S18] | an empty directory does not exist unless a 0-byte `dir/` marker is invented |
| rename | nothing on general-purpose buckets — *"Folders can be created, deleted, and made public, but they can't be renamed"* [S18] | every rename is copy+delete; a directory rename is O(entries) |
| mtime | `Last-Modified`, and AWS's own metadata table says the user **cannot** modify it [S19] | mtime must be smuggled in `x-amz-meta-mtime` (see below) |
| POSIX modes, symlinks, hard links | nothing | dropped |
| random-access writes, `reput` | *"Amazon S3 never adds partial objects"*; whole-object PUT only [S20] | no resume of a partial object, no editor save of a large file without re-uploading it whole |
| a 68 MB file in one operation | 5 GB single-PUT ceiling, and **multipart is not optional** | Cyberduck's own known-issues page: *"The S3 interoperable service must support multipart uploads"* [S17] — so `CreateMultipartUpload`/`UploadPart`/`Complete`/`Abort` are day-one work, with a 5 MiB minimum part and 10,000-part maximum [S31] |

**And one modern complication that is easy to miss.** Current AWS SDKs
default to `request_checksum_calculation = WHEN_SUPPORTED`, so an ordinary
`aws s3 cp` sends `Content-Encoding: aws-chunked`,
`x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`,
`x-amz-decoded-content-length` and a trailing checksum — **a body that is
not the object bytes** [S21]. This broke a wave of S3 clones in early 2025.
A server must strip the framing regardless; the client-side opt-out
(`AWS_REQUEST_CHECKSUM_CALCULATION=when_required`) cannot be forced from
our side.

**The one genuinely attractive S3 finding**, recorded so it is not lost:
`x-amz-meta-mtime` (float seconds since the epoch) is **interoperable
between rclone and Cyberduck** — Cyberduck's own docs say so, behind its
`S3 (Timestamps)` profile, and rclone's `X-Amz-Meta-Mtime` is the same
convention [S19]. If S3 is ever built, that one header buys mtime
preservation from both major clients.

**Verdict: no.** The work is a multipart implementation plus SigV4 plus
`aws-chunked` plus a lie about the namespace, and it delivers strictly less
than SFTP to the person who asked. Where S3 would genuinely help — moving
bulk data with `rclone`/`aws-cli` in a HEP pipeline — the answer is
`pelfs get` and the federation's own object interface, not an S3 shim in
front of a POSIX view.

---

## What survives of D1–D10

`docs/design-windows.md`'s ranked list was written for a drive letter over
the redirector. Under the pivot:

| item | fate | why |
|---|---|---|
| **D1** — `internal/vfsdav`: `webdav.FileSystem` over `internal/vfsbilly` | **BUILT — and it went FIRST, not second** | shipped as `internal/vfsdav` on `pelfs browse`'s listener, read-write, gated by `scripts/webdav-adapter-litmus-docker.sh` at `16/16 · 13/13 · 29/30 · 32/34` (the `props` ceiling for a real server is 29/30; the 30/30 baseline hard-codes a 400 for `propfind_invalid2`). It was not as cheap as "nearly the same interface" promised: `DeadPropsHolder` is mandatory, `Mkdir` and `RemoveAll` need their own bodies, and a symlink must be followed on OPEN. It is also the macOS second client, as predicted. |
| **D2** — `--backend webdav`, ephemeral port, per-session digest | **SURVIVES, simplified** | the digest half is now optional: third-party clients accept Basic over loopback [S12][S13]. Digest is needed only if Explorer is a target. |
| **D3** — `WNetAddConnection2W`/`WNetCancelConnection2W` via `mpr.dll` | **DEAD** | the drive letter comes from `rclone mount` (free, WinFsp) or Mountain Duck [S11][S15]. pelfs writes no Windows attach code. |
| **D4** — the name-mapping layer (reserved chars, device names, trailing dot/space, case shadowing) | **DEAD as a requirement** | it existed because a drive letter makes volume names into *Windows filesystem* names. An SFTP or WebDAV client shows names in a listing; only a download to a Windows path can fail, and the client reports which file and why. Keep the *counting* (how many names Windows cannot hold) as a banner line; drop the remapping. |
| **D5** — litmus in CI against the pelfs adapter | **SURVIVES, only if D1 is built** | and it is joined by `scripts/sftp-clients-docker.sh`, which is the same idea for the recommended protocol. Its two known `locks` failures now matter even less: the redirector was the only client that locked, and Cyberduck does not [S12]. |
| **D6** — `DeadPropsHolder` + `Win32*` properties, `O_RDWR` on directories | **DEAD as specified** | `Win32LastModifiedTime` is the redirector's convention. Third-party WebDAV clients use `X-OC-Mtime` (rclone) or a `SAR:` PROPPATCH (Cyberduck) [S12][S14], and SFTP has mtime in the protocol. If D1 is built, implement `X-OC-Mtime` instead; golang/go#43929 stops being on the path. |
| **D7** — `pelfs windows-setup` (raise `FileSizeLimitInBytes`, restart `WebClient`) | **DEAD, and this is the point of the pivot** | measured: a 68,497,408-byte file transfers both ways over SFTP with nothing configured. No registry write, no service restart, no UAC prompt. |
| **D8** — the `windows-latest` CI job at both registry configurations | **SURVIVES, halved** | one configuration, because there is no registry value. It becomes the `where sftp` + `WinSCP.com /script=` job described above. |
| **D9** — WebDAV write path (PUT/MKCOL/DELETE/MOVE/LOCK) | **SUBSUMED** | the write path is now the *first-class* concern (see "The write path"), and SFTP is where it is built. If D1 ships, `MOVE` is required — Cyberduck's editor renames [S23]. `LOCK` is not: Cyberduck does not lock [S12]. |
| **D10** — a WinFsp frontend in pelfs | **DEAD** | `rclone mount` already is one, for any backend pelfs exports. This is the single largest saving in the pivot: a third frontend implementation, deleted. |

Net: **two items dead outright (D3, D10), two dead as specified (D4, D6),
one dead as a goal (D7), one halved (D8), and four survive in reduced or
deferred form.** Everything deleted was Windows-specific pelfs code.

---

## Ranked work items

**Read the verdict column first.** `docs/design-webui.md` came after this
document and built a browser UI plus WebDAV on one loopback listener, which
delivered four of these items and took `pelfs browse`'s name for a
different transport. The SFTP frontend — G1, G2, G3, G5, G10 — is still
unbuilt and still the recommendation for a Windows user with no browser in
the loop; nothing here was retracted.

| | change | verdict | buys | effort | unblocks |
|---|---|---|---|---|---|
| **G1** | `internal/vfssftp`: `sftp.Handlers` (`FileReader`, `FileWriter`, `OpenFileWriter`, `FileCmder`, `FileLister`, `LstatFileLister`, `ReadlinkFileLister`, `PosixRenameFileCmder`, `StatVFSFileCmder`) over `internal/vfsbilly`, **read-only first** | **OPEN.** There is no `internal/vfssftp`. The reasoning stands; the work was not done because `internal/vfsdav` answered the same two user questions on a listener that had to exist anyway | the whole idea | small — the mapping is nearly 1:1: `billy.File` already is `ReaderAt`/`WriterAt`/`Truncate`, and `Stat`/`Lstat`/`ReadDir`/`Rename`/`Remove`/`MkdirAll`/`Symlink`/`Readlink`/`Link`/`Chmod`/`Chtimes` all exist | everything below |
| **G2** | `Permitted()` before every `OpenFile`, so the SFTP OPEN is checked as an OPEN and not as NFS's data path | **OPEN for SFTP, DONE for the surfaces that shipped.** `internal/vfsdav` and `internal/webapi` both open through `vfsbilly.OpenAnsweredHere`, and a call-site test in `internal/vfsbilly` fails any HTTP-side caller that reaches for the NFS variants. The correctness point was right and it generalised | the third frontend answers `test -w`-shaped questions like the other two | trivial, and it is a **correctness** item, not a nicety | trust in the export |
| **G3** | `internal/sftpmount.Serve(bfs)`: `127.0.0.1:0`, persisted ed25519 host key, per-session credential, `SetDeadline` around the handshake, one goroutine per channel | **OPEN** | a server a real client can reach | small; `internal/nfsmount.Serve` is the template, ~80 lines of transport by upstream's own example | G4, G5, the whole CI story |
| **G4** | `pelfs browse [--rw]`: start the server, print URL + port + fingerprint in the three formats clients want, seal at exit, name `pelfs ctl publish` in the banner | **DONE, under this name, with a different transport.** `pelfs browse [--rw] [--open]` serves an HTTP page on `127.0.0.1:0` (tcp4), prints the URL, seals at exit, and names publish on the page rather than in a banner. There is no host-key fingerprint to print because there is no SSH | a person can use it | small; `runMountGen` already has the backend switch and the teardown discipline, and `control.Publish` already exists | the deliverable |
| **G5** | `scripts/sftp-clients-docker.sh` pointed at the pelfs adapter, as a gate | **OPEN** (needs G1). Its WebDAV analogue shipped: `scripts/webdav-adapter-litmus-docker.sh`, `scripts/webdav-clients-docker.sh` and `scripts/oauth-cyberduck-docker.sh` | the measured table becomes a regression test, with `preserve-mtime` and `chmod` expected to flip to `ok` | hours — the script exists | catching adapter regressions before a client does |
| **G6** | Seal on idle: last-client-disconnect + quiet window, with the pressure path's backoff | **DONE**, and this document said it could not be done over HTTP. It can: the SPA holds an SSE stream open, so "the last client went away" is a real event. Two things the design did not foresee — `min(30 s, --snapshot-interval)` is undefined at interval 0 (it ships OFF), and `pagehide` fires *before* the teardown, so a naive beacon comparison discards every beacon that worked | an uploaded file becomes durable without the user knowing what a checkpoint is | moderate; the trigger is new, the sealing is not | the write path being honest |
| **G7** | `TransferError` policy: unlink an unfinished file **this session created**, leave a pre-existing one, count both | **DONE in a different shape.** No client `TransferError` hook exists over HTTP, so the JSON API implements the convention itself: bytes land in `<name>.pelfs-part`, the final `Rename` happens only on completion, and an abandoned upload is unlinked. A leftover `*.pelfs-part` is visible as exactly what it is on both surfaces | a killed upload does not get published as a truncated file under its final name | small | the write path being correct |
| **G8** | The landing page: URL, fingerprint, "publish now", unsealed-file count. **No file manager.** | **DONE, and then overtaken.** It was promoted from a nicety to the foundation of `docs/design-webui.md`'s M1 — with the auth story it did not have here — and M3/M4 then added the file manager this item said not to build. The discipline survived: the page still says out loud what it is not showing you | connect-by-click without a bookmark file | small, and bounded on purpose | the friction |
| **G9** | `.duck` bookmark + `known_hosts` line written **next to the volume, not into `$HOME`**, and `--open` to hand the URL to the platform opener | **DONE for WebDAV, not SFTP.** `internal/davprofile` writes a `.cyberduckprofile`, a `.duck` bookmark and a Basic-path bookmark, handed out by the page rather than written next to the volume — nothing lands in `$HOME`. `--open` exists. There is no `known_hosts` question because there is no SSH; the equivalent problem, a credential the user must not have to type, is solved by OAuth instead | one double-click to a browsable volume | small; the `.duck` key set is known (from source, not docs) | the experience |
| **G10** | The `windows-latest` job: `where sftp`, `sftp.exe` round trip of a 68,497,408-byte file, `WinSCP.com /script=` with `-hostkey=` | **OPEN.** No Windows job exists for either transport. It is now the single largest gap in both this document and `docs/design-windows.md` | every Windows row below | moderate; it is the only place the answers exist | calling this supported |
| **G11** | D1/D2/D5 — the WebDAV frontend, with **Basic** over loopback, `X-OC-Mtime`, `MOVE`, and **no LOCK requirement** | **DONE, and it went first rather than eleventh.** With Basic over loopback *and* OAuth Bearer; `MOVE` implemented, `LOCK` present as `webdav.NewMemLS()` and not required. `X-OC-Mtime` is **not** implemented — mtime preservation over WebDAV is still open, and is `docs/design-windows.md` D6's surviving half | Explorer with no install (at 47.68 MiB), macOS `mount_webdav` as a second independent client, `litmus` as a second gate | small–moderate, and already measured | a second opinion on the same adapter |
| **G12** | The write path on Windows: the `FILE_SHARE_DELETE` hazard list in `docs/TODO.md` | **OPEN**, and still not this document's work | `--rw` from a Windows-hosted pelfs | real, and **not this document's work** | uploads on Windows |

---

## Recommended minimal first milestone

**STILL THE RECOMMENDATION, AND STILL NOT BUILT.** What shipped instead is
`docs/design-webui.md`'s M1: `pelfs browse` serving an HTTP page, then
WebDAV on the same listener. That covers the same two user questions for
anyone with a browser, and it does not cover this milestone's own case — a
Windows user pointing WinSCP at a volume with no browser in the loop. G1,
G2, G3, G5 and G10 remain open, and the banner mock below is the spec for
them. Note that **`pelfs browse` is now taken** by the HTTP verb, so an
SFTP export needs either a flag on it or a name of its own.

**A read-only SFTP export a physicist can point WinSCP at — G1, G2, G3,
G4, G5.** Concretely:

```
pelfs browse pelican://<federation>/<prefix>
  sftp://pelfs@127.0.0.1:49731/          (read-only)
  password:    <32 random characters>
  host key:    SHA256:xxxxxxxx…          (persisted; you will see this prompt once)
  WinSCP URL:  sftp://pelfs;fingerprint=ssh-ed25519-xxxx…@127.0.0.1:49731/
  publish now: pelfs ctl publish         (read-only session: nothing to publish)
  Ctrl-C to stop.
```

and the user drags files **out** of a Cyberduck or WinSCP window. That is
browse, download, and double-click-to-open — three of the four things
asked for — with no admin, no FUSE, no drive letter, no registry, no
WebClient service, no size cap and no directory-size cap. It runs on
Windows, macOS and Linux from the same code, and on Windows it is the
**first** thing in pelfs that shows a user their files at all
(`cmd/pelfs/main.go`'s Windows branch today says only that publish, fsck,
gc, repack, cache and status work).

Then **G6, G7 and `--rw`** as the second milestone, on Linux and macOS,
where the write path is shipped; and G10 before either is called
supported.

What the first milestone deliberately does **not** do: write, mount a
drive letter, remap illegal names (it counts them), or serve more than one
user. The banner must say the first two in one sentence, because a person
who wanted a drive letter and got a bookmark needs to be told that
`rclone mount` is the drive letter and that it is free.

---

## What cannot be verified without a Windows machine or a paid client

In the order they would change the plan. Every one is answered by G10 or by
one purchase; none is answered by more reading.

1. **Whether `sftp.exe` is present on a stock Windows 11 and on
   `windows-latest`.** Two Microsoft pages disagree [S16][S16b] and the
   runner-image inventories do not mention OpenSSH at all. Settled by
   `where sftp` in CI and on one real machine.
2. **Whether WinSCP's `;fingerprint=` in a URL actually suppresses the
   host-key dialog on a machine with no cached key**, and whether the
   dash-separated format is accepted for ed25519 (the vendor's example is
   `ssh-rsa`).
3. **Whether Windows registers `sftp://` to WinSCP on a default install.**
   The docs phrase it conditionally [S27]; if it does not, `pelfs browse
   --open` falls back to printing the URL.
4. **Cyberduck's `editor.upload.temporary` default** — inferred `true`
   from the docs' phrasing, never stated [S23]. It decides whether an
   editor save needs rename-over-existing.
5. **Whether Cyberduck's `ssh.knownhosts` can be set per-`.duck`
   bookmark.** If it can, G9 writes one file and touches nothing of the
   user's. If not, G9 prints a fingerprint and the user clicks once.
6. **The free FileZilla client's own protocol list.**
   `filezilla-project.org` refused automated fetches from this session
   (HTTP 403), so the citation here is the official Pro site, which states
   the free client's set [S8]. A second reviewer reported reaching the free
   client's own feature page and reading the same answer (FTP/FTPS/SFTP
   only), so this is corroborated but not first-hand here. One browser
   visit closes it.
7. **Whether the free FileZilla client offers a temp-name-and-rename
   upload.** No citation either way, for the same reason.
8. **Whether Explorer's *Add a network location* wizard shares the
   WebClient redirector's limits** (as opposed to *Map network drive*,
   which does). Settled by `net stop webclient` plus one wizard attempt.
9. **Mountain Duck's v5 "Integrated" mode without WinFsp**, and whether it
   is usable against a loopback SFTP server. Needs the USD 49 licence
   [S15].
10. **`duck`'s host-key handling** — no CLI option is documented [S22], so
    a CI job using it must arrange `known_hosts` itself and confirm that
    works.

---

## Sources

- **[S1]** Microsoft, *Using the WebDAV Redirector* — the registry table
  scoped to the WebClient service (`FileSizeLimitInBytes` 50,000,000;
  `FileAttributesLimitInBytes` 1,000,000; `BasicAuthLevel` 1 =
  *"enabled for SSL web sites only"*; `SendReceiveTimeoutInSec` 60), and
  *"You are using Basic Authentication and connecting to your web site
  using HTTP instead of HTTPS"* as a documented cause of System error 67.
  <https://learn.microsoft.com/en-us/iis/publish/using-webdav/using-the-webdav-redirector>
  See `docs/design-windows.md` for the full treatment; not repeated here.
- **[S2]** `github.com/pkg/sftp` — `NewRequestServer`, the four required
  `Handlers` interfaces and the optional `OpenFileWriter`,
  `PosixRenameFileCmder`, `StatVFSFileCmder`, `LstatFileLister`,
  `ReadlinkFileLister`, `RealPathFileLister`, `TransferError`; protocol 3
  (`sftpProtocolVersion = 3`, draft-ietf-secsh-filexfer-02); the three
  advertised OpenSSH extensions; BSD-2-Clause; v1.13.11, 2026-07-12.
  <https://github.com/pkg/sftp> ·
  <https://github.com/pkg/sftp/blob/master/request-interfaces.go> ·
  <https://github.com/pkg/sftp/blob/master/request-readme.md>
- **[S3]** `pkg/sftp`, `request-example.go` — `InMemHandler()`, and the
  `Setstat` case that honours only `AttrFlags().Size`. This is the
  measured baseline's gap.
  <https://github.com/pkg/sftp/blob/master/request-example.go>
- **[S4]** `pkg/sftp`, `examples/request-server/main.go` — the SSH+SFTP
  transport in 130 lines including flags and logging; the `"subsystem"` /
  `"sftp"` payload handling. The shape `internal/sftpmount` would take.
  <https://github.com/pkg/sftp/blob/master/examples/request-server/main.go>
- **[S5]** WinSCP, *Supported protocols* — *"SFTP, SCP, S3 and FTP
  client"*, WebDAV and S3 in the list; and *License* — *"WinSCP is free
  software... under the terms of the GNU General Public License"*.
  <https://winscp.net/eng/docs/protocols> ·
  <https://winscp.net/eng/docs/license>
- **[S6]** WinSCP version history — S3 in **5.13** (2018-02-19),
  non-default endpoints in 5.15, non-standard ports in 5.17,
  *"Support for S3 servers without TLS encryption"* in **6.1** (2023-05-23);
  and *"Not allowing WebDAV redirects to an unencrypted URL by default"*.
  <https://winscp.net/eng/docs/history_old> ·
  <https://winscp.net/eng/docs/history>
- **[S7]** Microsoft, *File sharing over a network in Windows* — the
  Map-network-drive path. Cited for what it does **not** say: no
  enumeration of the *Add a network location* wizard's schemes.
  <https://support.microsoft.com/en-us/windows/experience/connectivity-networking/file-sharing-over-a-network-in-windows>
- **[S8]** FileZilla Pro, *Supported protocols* — *"FileZilla Pro supports
  the same core FTP, FTPS, and SFTP protocols as the free FileZilla
  client"* and *"FileZilla Pro additionally connects to cloud storage
  services — Amazon S3, ... and WebDAV — which the free client does not
  support."* **The free client's own page returns HTTP 403 to automated
  fetches**, so this is the vendor citation available.
  <https://filezillapro.com/docs/v3/basic-usage-instructions/filezilla-pro-supported-protocols/>
- **[S9]** Cyberduck — *"FTP, SFTP, WebDAV, Amazon S3, ..."*, *"libre
  server and cloud storage browser"*, *"Licensed under the GPL"*, Mac and
  Windows. <https://cyberduck.io/>
- **[S10]** rclone — the `sftp`, `webdav` and `s3` backends; MIT;
  `--sftp-known-hosts-file` (*"Set this value to enable server host key
  validation"*), `--sftp-host-keys` (*"Pinned host keys for this
  remote"*). <https://rclone.org/sftp/> · <https://rclone.org/webdav/> ·
  <https://rclone.org/s3/>
- **[S11]** rclone, *rclone mount* — *"To run rclone mount on Windows, you
  will need to download and install WinFsp"*; drive-letter and
  nonexistent-subdirectory mount targets.
  <https://rclone.org/commands/rclone_mount/> · <https://winfsp.dev>
- **[S12]** Cyberduck, *WebDAV* docs and source — *"You can connect to any
  WebDAV compliant server using both HTTP and HTTP/SSL"*, *"Both HTTP
  Basic Authentication and Digest Authentication are supported"*; a
  distinct plain-HTTP protocol (`DAVProtocol.java`);
  *"Locking is not supported editing with Cyberduck"* (Mountain Duck does
  `LOCK`/`UNLOCK`); `DAVWriteFeature` sends `Content-Range`,
  `Expect: 100-continue` and `If` only — **no `If-Match`**, and the save
  path is `HEAD`/`PROPFIND Depth: 0` then an unconditional `PUT`;
  `DAVTimestampFeature` PROPPATCHes `lastmodified` and
  `lastmodified_server` in Sardine's `SAR:` custom namespace
  (`SardineUtil`: `CUSTOM_NAMESPACE_URI = "SAR:"`). Also the evidence that
  Cyberduck's WebDAV is not the OS redirector: Sardine over Apache
  HttpClient, in the imports.
  <https://docs.cyberduck.io/protocols/webdav/> ·
  <https://github.com/iterate-ch/cyberduck/blob/master/webdav/src/main/java/ch/cyberduck/core/dav/DAVWriteFeature.java>
- **[S13]** WinSCP, *Login dialog* — *"When WebDAV or S3 protocol is
  selected, you can choose between basic **unsecured** variant and secure
  one"*; and the changelog's repeated *"WebDAV/HTTP core upgraded to
  neon"*, which is the evidence that WinSCP's WebDAV is not the OS
  redirector. <https://winscp.net/eng/docs/ui_login_session>
- **[S14]** rclone, WebDAV backend — *"Plain WebDAV does not support
  modified times"*; the `X-OC-Mtime` request header and the
  `X-OC-Mtime: accepted` reply; the `rclone` vendor sets exactly that.
  <https://rclone.org/webdav/>
- **[S15]** Mountain Duck — *"Based on the solid open source foundation of
  Cyberduck"*, iterate GmbH; SFTP/WebDAV/S3 and more; **USD 49.00** for one
  seat (read from the vendor's own pricing endpoint,
  `reg.mountainduck.io/calculate?volume=1&currency=USD`); v5's *"Integrated
  connect mode ... No device driver installation or network mount
  required."* <https://mountainduck.io/> · <https://mountainduck.io/buy/>
- **[S16]** Microsoft, *OpenSSH for Windows overview* — *"`sftp` is the
  service that provides the Secure File Transfer Protocol"*; and the
  install-state table's *"Not installed, install and enable using optional
  features"* for Windows 10 1809+.
  <https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview>
- **[S16b]** Microsoft, *Available Features on Demand* — `OpenSSH.Client`
  listed under *"Preinstalled FODs"*: *"The following Features on Demand
  come preinstalled in a Windows image."* This **contradicts [S16]'s
  table**; see the client matrix.
  <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11>
- **[S17]** Cyberduck, S3 docs and `default.properties` — the
  `S3 (HTTP)` and `S3 (Timestamps)` connection profiles;
  `s3.bucket.virtualhost.disable`; *"The S3 interoperable service must
  support multipart uploads"*; *"The timestamp metadata is interoperable
  with rclone"*; and the upload knobs
  `queue.upload.file.temporary=false`, `queue.upload.timestamp.change
  =false`, `queue.upload.permissions.change=false`; the WebDAV auth knob
  `webdav.basic.preemptive=true`; and `ssh.knownhosts=~/.ssh/known_hosts`.
  <https://docs.cyberduck.io/protocols/s3/> ·
  <https://github.com/iterate-ch/cyberduck/blob/master/defaults/src/main/resources/default.properties>
- **[S18]** AWS, *Organizing objects using folders* — *"general purpose
  buckets have a flat structure"*, *"Folders can be created, deleted, and
  made public, but they can't be renamed"*; and *ListObjectsV2* on
  `Delimiter`/`CommonPrefixes`. (A `RenameObject` API exists but *"is only
  supported for objects stored in the S3 Express One Zone storage
  class"*.)
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-folders.html> ·
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html>
- **[S19]** AWS, *Working with object metadata* — the system-metadata
  table's *"Can user modify the value?"* column is **No** for
  `Last-Modified`, and *"only Amazon S3 can modify the date value"*. The
  `x-amz-meta-mtime` workaround is [S10] and [S17].
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html>
- **[S20]** AWS, *PutObject* — *"Amazon S3 never adds partial objects"*,
  *"You must put the entire object with updated metadata if you want to
  update some values."*
  <https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html>
- **[S21]** AWS, *Checking object integrity on upload* and the SDK
  data-integrity setting — `STREAMING-UNSIGNED-PAYLOAD-TRAILER` /
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`, `aws-chunked`,
  `x-amz-decoded-content-length`, 8 KiB minimum chunk; and
  *"**Default value:** `WHEN_SUPPORTED`"*.
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html> ·
  <https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html>
- **[S22]** `duck`, the Cyberduck CLI — version 6, Windows
  (`choco install duck`), macOS (`brew install duck`), Linux apt/yum;
  `--upload` and `--download`; SFTP, WebDAV and S3 among its protocols.
  No host-key CLI option documented.
  <https://duck.sh/> · <https://docs.duck.sh/cli/>
- **[S23]** Cyberduck, *Edit* — *"The file will be downloaded to a
  temporary directory and opened with the preferred editor. The file will
  be uploaded to the server every time you choose File → Save."*, *"The
  file is not changed on the server if you just close the document without
  saving it"*, and the hidden option *"Disable Upload of Temporary File on
  Save — `editor.upload.temporary = false`"*.
  <https://docs.cyberduck.io/cyberduck/edit/>
- **[S24]** WinSCP, *Editing files* — *"it needs to download the remote
  file to temporary directory first. Then it opens the file in your
  preferred editor or associated application"*, *"Once you change the
  file, WinSCP uploads it back"*, *"WinSCP watches for changes to them
  all"*. <https://winscp.net/eng/docs/task_edit>
- **[S25]** WinSCP, *Resuming file transfers* — *"Transfer to temporary
  file name is enabled by default for files larger than a given
  threshold"*, *"The threshold is initially 100 KB"*, *"Transfer to
  temporary filename is supported with SFTP protocol only and only for
  binary transfers"*, and the `.filepart` remnant.
  <https://winscp.net/eng/docs/resume>
- **[S26]** WinSCP, *Transfer settings* — *"The Preserve timestamp
  checkbox makes WinSCP preserve the last modification timestamp of the
  transferred file"*; *"Including directories"* is SFTP-only.
  <https://winscp.net/eng/docs/ui_transfer_custom>
- **[S27]** WinSCP, *Session URL* — the
  `<protocol>://[<username>[:<password>][;<advanced>]@]<host>[:<port>]/`
  grammar; *"There's a special syntax to include an expected SSH host key
  fingerprint in SFTP / SCP URL among advanced site settings:
  `fingerprint=<fingerprint>`"*; *"For security reasons, fingerprint
  provided in session URL does not override any fingerprint already cached
  on the machine"*; *"Format of the fingerprint for URL somewhat differs
  from format used in other WinSCP features"*; and that URL handling in
  Explorer applies *"if WinSCP is registered to handle file transfer
  protocol URL addresses"*. <https://winscp.net/eng/docs/session_url>
- **[S28]** Cyberduck, *Bookmarks* — *"You can double-click the document in
  the file browser to open a new connection to the server specified in the
  bookmark"*, *"You can share bookmarks between Mac & Windows as the file
  format is the same on both platforms"*. The `.duck` key set is read from
  `HostDictionary.java`, because the format is not documented; the
  `ssh.knownhosts=~/.ssh/known_hosts` default is in
  `default.properties` ([S17]).
  <https://docs.cyberduck.io/cyberduck/bookmarks/> ·
  <https://github.com/iterate-ch/cyberduck/blob/master/core/src/main/java/ch/cyberduck/core/serializer/HostDictionary.java>
- **[S29]** WinSCP, *Scripting* and the `open` command — *"Enter the
  console/scripting mode by using `winscp.com`"*, *"When running commands
  specified using `/script` or `/command`, batch mode is used implicitly
  and overwrite confirmations are turned off"*, and `-hostkey=`
  *"Specifies fingerprint of expected SSH host key... It makes WinSCP
  automatically accept host key with the fingerprint."*
  <https://winscp.net/eng/docs/scripting> ·
  <https://winscp.net/eng/docs/scriptcommand_open>
- **[S30]** `litmus` 0.18 (2026-06-28) and `cadaver` 0.28 (2025-09-18),
  both GPL-2.0 under the neon author; cadaver 0.28's *"'edit' uses a
  conditional PUT (where possible) to avoid conflicts"*; litmus's own
  caveat *"a server which passes all these tests will not necessarily work
  with any real DAV clients"*.
  <https://notroj.github.io/litmus/> · <https://notroj.github.io/cadaver/>
- **[S31]** AWS, *Amazon S3 multipart upload limits* — 10,000 parts
  maximum, part size **5 MiB to 5 GiB** with no minimum on the last part,
  5 GB single-PUT ceiling.
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html> ·
  <https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html>
- **[S32]** `golang.org/x/crypto/ssh` — `NewServerConn` (*"The Request and
  NewChannel channels must be serviced, or the connection will hang"*),
  `PublicKeyCallback` (*"A call to this function does not guarantee that
  the key offered is in fact used to authenticate"*),
  `VerifiedPublicKeyCallback`, `AddHostKey`, and *"ssh: server has no host
  keys"*. `Timeout` exists only on `ClientConfig`, so the server side has
  no handshake timeout. Already in the graph at `go.mod:115`.
  <https://pkg.go.dev/golang.org/x/crypto/ssh>
- **[S33]** `github.com/rclone/gofakes3` — MIT; `gofakes3.New(backend)
  .Server() → http.Handler`; the 11-method `Backend` interface with
  `MultipartBackend`/`VersionedBackend` optional;
  `signature.V4SignVerify(*http.Request) ErrorCode`; `chunkedReader`
  strips `aws-chunked` framing without verifying chunk signatures; the
  package-level `var credStore sync.Map`. MinIO by contrast is **archived**
  (*"THIS REPOSITORY IS NO LONGER MAINTAINED"*) and AGPL-3.0.
  <https://github.com/rclone/gofakes3> · <https://github.com/minio/minio>
- **litmus baseline for a WebDAV frontend**: `basic` 16/16, `copymove`
  13/13, `props` 30/30, `locks` 32/34 — measured in
  `docs/design-windows.md` by `scripts/webdav-litmus-docker.sh`, not
  re-measured here. **The `props` number is the example server's, and it
  is not reachable by a real one:** that server hard-codes a 400 for
  `propfind_invalid2` (golang/go#8068). `29/30` is the honest ceiling and
  what the pelfs adapter is held to.
