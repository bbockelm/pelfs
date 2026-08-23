# Changelog

## Unreleased

**`pelfs browse` opens the file manager.** `GET /` is now the React file
manager — `internal/webui`'s committed bundle, on the route table — and the
hand-written connection page moved to **`GET /connect`**, where the credential
desk, the generated Cyberduck profile and the federation-login cards live.
Until this change the bundle was built, licence-checked, size-capped and
gated by two CI jobs while nothing served it: `pelfs browse` answered `/` with
the connection page, and the ~450 KB of embedded bundle was not linked into
the binary at all. **This supersedes the *Not in this release* note under
v0.2.1**, which described that state accurately when it was written.

The file manager took `/` because that is what the verb promises. A user
whose front door is a credential desk has been handed the plumbing rather
than the tool. Each page carries exactly one anchor to the other, and the
round trip is driven in both directions by the browser suite — because a link
from a single-page app to another page on its own origin is the one navigation
that could silently cost a user their session.

**Both pages keep the durability panel**, in the same words, from the same
`/events` snapshot. Deleting the second rendering and linking to the first
would have been less code and the wrong trade: the sentence about what is and
is not published is what this whole surface exists to put in front of
somebody, and a user who has to navigate to read it does not read it. There is
one answer with two renderings — the server's snapshot, which both pages are
clients of — and a test reads both sources and fails if the words drift apart.

**Two things the file manager owed the session, and only owed once it was the
page a user lands on:**

- The **idle-seal hint**. Closing the tab now shortens the wait before the
  session seals from thirty seconds to about five, the same
  `navigator.sendBeacon` the connection page always sent. The seal itself never
  depended on it — the trigger is the event stream closing — so the effect was
  25 seconds of delay on the one surface that can actually stage files.
- **Waiting for the volume.** `pelfs browse` binds and prints its URL before it
  opens the volume, deliberately, so that a federation login prompt has a page
  to appear on. The file manager asked the data plane for a listing once, at
  load, and treated a refusal as final — so opening the printed URL promptly,
  which `--open` does for you, showed "the JSON data plane did not answer" until
  a manual reload. The page now takes its readiness from the same event stream
  the durability panel reads, and shows the panel and the connection banner
  while it waits.

### Fixed

- **A rename the server refused no longer looks like one that worked.** The
  file grid applies a change the moment you ask for it, and a refusal — a 403
  on a path this session may not write, a 409 during a publish — left the new
  name on the screen with an error message beside it. Of the two, a user
  believes the screen. A refused rename, move, copy, delete or folder-create
  now re-reads the affected directories from the volume, so the row is the
  volume's row again and the message says only what did not happen. Two browser
  assertions pin it.
- The federation-login prompt (the device-code card) is now visible from the
  file manager, as a banner naming what is waiting and linking to the card.
  Before, a user whose institution was asking them to log in sat at `/`
  watching a listing that was never going to arrive.

### Changed

- The page footer is gone, along with the line saying pelfs is not an official
  Pelican Platform product. That attribution stays where it belongs — in
  `NOTICE`, and in `brand/NOTICE.txt` beside the mark it is about, which the
  binary serves. The third-party licence notices are still linked from the
  page, in the status line.

## v0.2.1

v0.2.0 made an NFS mount enforce the mode bits and a writable mount collect
its own garbage. v0.2.1 is two things. `fsync(2)` did nothing and returned
success; it does the work now, on both frontends, and two crash windows
that could lose or fabricate bytes are closed. And a volume can now be
reached without FUSE at all: a page on `127.0.0.1` that says whether your
data is in the federation and publishes it, a WebDAV endpoint for the
clients people already have, a credential desk that connects Cyberduck with
one double-click, an apptainer `--fusemount` driver so a job mounts its own
volume, and Windows binaries.

The on-disk format is still `FormatVersion 2`, no volume needs converting,
and nothing here changes what a v0.2.0 binary can read or write. Three
things change for a v0.2.0 user anyway: **an NFS-backed mount on real
storage pays about 3x on a create-heavy workload**, a write now pays the
uplink while it writes rather than at the seal, and **both forked
dependencies moved** — anyone vendoring needs the new pins. Read
*Upgrading from v0.2.0*.

Still a prototype, still used against real federations, and still
unprivileged and `CGO_ENABLED=0`.

### Upgrading from v0.2.0

Six changes a v0.2.0 user will notice, and what to do about each.

#### 1. `fsync` does work now, and on a real disk an NFS mount pays for it

This is the one most likely to change a number you were watching.

`fsync(2)` and `fsyncdir(2)` returned success unconditionally, without
making anything durable. They now do the work and return success only once
it holds. On the default memtable path that is the write buffer's mapping
msync'd, the journal recording which file those bytes belong to fsync'd,
and the metadata database holding the name, mode and length fsync'd — in
that order, so no layer is ever durable ahead of the one it names. (A
`--no-memtable` mount has no ring and no journal; there it is the staged
body files and the staging directory.) Kill the process, cut the power,
reboot, remount the same state directory: the writes are there.

**What it means is "recoverable by remounting THIS state directory", and
that is not federation durability.** On ephemeral job scratch — an HTCondor
slot wiped on eviction — the state directory dies with the slot, and every
byte `fsync` covered goes with it whether or not `fsync` returned success.
What survives an eviction is a CHECKPOINT: `--snapshot-interval` to have
one happen on a cadence, or `pelfs ctl <mount> publish` at the points a job
knows are worth keeping. A laptop or a long-lived host, where the state
directory outlives the process, gets exactly the guarantee it asks for.
Making `fsync` a federation round trip was the alternative and it was
rejected: for the sqlite-in-a-container workload that makes an application
call `fsync` at all, it would be minutes per call.

A directory `fsync` is the same call, deliberately. It asks for namespace
durability, which is a real question here because the namespace is a
database — but it cannot be answered alone: the content journal may hold
entries for inodes the metadata never committed, and the metadata may never
name content the journal lacks, so a durable namespace over an unsynced
journal is precisely the state that rule forbids.

**An NFS-backed mount gets this too, and that is where the cost is.** A
FUSE mount syncs when the application asks. An NFS mount syncs when the
CLIENT asks, and a Linux client asks far more often than an application
does: a small file written in one go is sent as a FILE_SYNC write rather
than an unstable one, because that saves the client a COMMIT round trip.
RFC 1813 makes FILE_SYNC a requirement — the server must have the data on
stable storage before it replies — so the server commits inline, **once per
file, for an application that never called `fsync` at all.** That is what
an NFS server costs; the kernel's own server behaves the same way.

Copying 500 small files onto an NFS mount, no `fsync` anywhere in the
workload:

| state directory on | before | after |
|---|---|---|
| tmpfs | 332 ms | 246 ms |
| a real disk | 392 ms | **1239 ms** |

Both rows are **single hand-run measurements on the owner's machine, and
no harness in this tree reproduces them.** Trust the direction rather than
the digits: the server now performs a commit per stable write that it
previously skipped, which is a structural change, and about 3.2x is what
one run of it looked like.

**Every containerized gate keeps its scratch on tmpfs, where `fsync` is
nearly free, so CI cannot see this at all.** `make big-tree` shows the
change as a wash for exactly that reason, and its RPCs-per-created-file
figure (5.41, bounded by the gate at 12) does not move — which is the
honest statement of what happened: the RPC count is the same, the cost of a
stable write is not.

Two smaller notes. A file large enough to go out unstable costs **one
commit at `close` rather than one per write** — not zero, which is what it
cost before. And a chatty application pays once: repeat calls with nothing
written between them are coalesced against the overlay's own mutation
counter and cost a lock and a comparison, no syscall. The first call of a
session is never coalesced away, because that counter belongs to this
process and a resumed state directory may hold another session's unsynced
work.

The alternative was answering `fsync` with a lie. This is the trade, not a
regression to be tuned away — but it is a real number, and the NFS frontend
is the one macOS uses, so it is written here rather than left to be
discovered.

#### 2. Both forked dependencies moved, and one of them tracks an open PR

Anyone who vendors, mirrors, or builds from source needs both pins.

- **`go-nfs` moved from `13c0560` to `d92cb754`.** This is the pin that
  carries the COMMIT change above, and building v0.2.1 against v0.2.0's pin
  silently gets the old no-op back. NFSv3 COMMIT was answered inside the
  fork by a hard-coded no-op whose own comment said writes are always
  pushed to the backing store — which for pelfs they are not. Adding a hook
  to COMMIT would have fixed nothing, because the handler was unreachable:
  the fork wrote the constant FILE_SYNC into the stability field of every
  WRITE reply, whatever the client asked for. That field is a promise about
  what the server ACHIEVED, and a Linux client believes it — it queues a
  page for commit only when the reply said UNSTABLE — so it never sent a
  COMMIT at all. The lie was in the WRITE reply first. The fork now carries
  one optional interface, `nfs.Committer`, that both procedures consult: a
  filesystem that implements it is taken to be holding data a crash could
  take, so an unstable write is answered UNSTABLE and left for a later
  COMMIT, a synchronous write is committed before the reply, and COMMIT
  calls the filesystem and reports what it says. `internal/vfsbilly`
  implements it with the same `overlay.Sync` the FUSE frontend calls, so
  both frontends make one promise. A filesystem that does not implement it
  — every other go-nfs user — behaves exactly as before.
- **The `pelican` pin is the head of an unmerged pull request.** It moved
  off a pelfs fork branch onto upstream during this cycle, and then onto
  `oauth-verification-hook` (pelican PR 3672) for the device-flow hook the
  browser page installs. A fork branch of an open PR is rebasable and will
  most likely be deleted when the PR merges, which strands the pin. That is
  a build-reproducibility exposure rather than a runtime one, and it is
  worth knowing before it bites: `scripts/build-pelican-server.sh` detects
  a stranded pin and dies with a named diagnosis rather than a confusing
  build error.

#### 3. A write now pays the uplink while it writes, not at the seal

Closing the flush/location-record crash window (under *Fixed*) means the
write ring holds a region until the record that replaces it is durable.
That is backpressure, and it moves the uplink's cost out of the seal and
into the write phase: a copy paces against the link instead of finishing
fast and then waiting. End-to-end throughput is where it was.

Measured against a **modelled** per-upload round trip
(`PELFS_RINGHOLD_MEASURE=1 go test ./internal/memtable -run RingHold`; the
round trip is a sleep in an in-memory object store, not a network):
192 MiB at a 250 ms round trip now costs **5.17 s writing + 1.56 s sealing,
6.73 s in total.** A script that watched the seal phase for progress will
see a shorter seal and a longer copy for the same work.

The pre-change pair is deliberately not quoted: the harness was added by
the fix itself and there is no knob to turn the hold off, so nothing in the
tree can produce a "before" number. On a genuinely bad link the cost is
real and bounded rather than proportional — 96 MiB at 25 s per 2 MiB pack
takes **350 s against a 300 s bandwidth floor**, and that is pipeline
bubbles rather than bandwidth: the ring's runway is four packs at the
shipped sizes (8 MiB of promotion distance over a 2 MiB pack target), so a
straggler's record can leave upload workers idle. Widening the runway
recovers it.

#### 4. `pelfs browse` is a new surface, and it is worth knowing what it opens

`pelfs browse` is new (see *What's new*). Nothing else exposes a listener,
and it exposes one only while it runs, but three properties are worth
stating before somebody runs it on a shared login node.

- **It binds `127.0.0.1` on a random port and mints its own credentials.**
  There are no cookies anywhere, nothing persists, every secret is
  `crypto/rand` into memory, and exiting revokes everything the process
  ever minted — including any WebDAV credential or OAuth token it handed
  out. A token from a previous session does not validate against a new one
  on the same port.
- **A `--rw` session seals on its own when the last tab closes.** That is
  new behaviour for a writable session: after the last `/events` stream has
  been gone for `min(30s, --snapshot-interval)` with nothing written on any
  surface, it publishes, and labels the generation as one nobody clicked
  for. `--snapshot-interval 0` still means seal only at exit, idle sealing
  included.
- **Permission enforcement is still fidelity, not access control**, and now
  that applies to one more surface. Every request through the shared layer
  is evaluated as the identity that started the server, and the WebDAV
  endpoint is subject to the same rule as the NFS one. Do not treat either
  as a multi-user boundary. (This widens KL-6 in `docs/known-issues.md`,
  which named only the NFS frontend.)

`pelfs browse` also carries a `--test-hooks` flag, which the browser gate
uses to drive the page into states a volume is not in. It is in the shipped
binary and in `--help`, and its own help text says never to point it at a
real volume. It is listed here so that is a decision rather than a
discovery.

#### 5. Statistics: three new fields, and the version does not move

`write.deduped_chunks` reported **0 on every path that was actually
deduplicating**, because it was incremented only on the memtable path,
which had nothing to count. Three fields now, each answering a different
question:

- `write.base_deduped_chunks` / `write.base_deduped_bytes` — content the
  BASE GENERATION already held. This is the cross-generation claim.
- `write.deduped_chunks` — that, plus repeats within the session.
- `sealed_deduped_chunks` — `internal/publish`'s own, which is what
  `--no-memtable` moves. It had no field anywhere, because the `write`
  section is not written at all when there is no memtable.

All three are additive, so **`pelfs_stats_version` stays `3`**. That number
exists to announce REMOVED keys; nothing was removed here, and a reader
keyed to the old names still gets them.

#### 6. A foreground session no longer writes outside `--state-dir`

`--state-dir` covered a session's overlay, caches, control socket and
signing key, but the mount-record registry was derived from
`$XDG_STATE_HOME/pelfs` (or `~/.local/state/pelfs`) independently of the
flag. A run pointed entirely at a temp directory still created a
`vol-<id>` directory in the user's home, wrote `mount.json` into it, and
left the directory behind, empty, at exit — measured, not theorised: the
count went up by one per run of the browser harness.

A **foreground** session — `pelfs shell`, `pelfs mount-gen`, `pelfs browse`
— now creates nothing outside the root its own flags select, and `pelfs
status` and `pelfs umount` grew a `--state-dir` flag so they can look
there. (`pelfs shell` still makes its temporary mountpoint outside the
state directory, which is the one remaining leak and is a mountpoint rather
than state.)

**`pelfs mount` is the deliberate exception**, because it detaches: its
whole contract is that a shell finds it afterwards by prefix, and a reader
cannot be told about a `--state-dir` it never saw. A live background mount
that cannot be stopped by name would be a worse bug than the one being
fixed, so that one record stays in the machine-wide registry (KL-11). What is fixed
for it instead is that **the registry no longer accumulates**: the
retraction at exit removes the `vol-<id>` directory as well as the record
when nothing else is in it. Directories that already hold a volume's state
are untouched — the removal only succeeds on an empty one.

### What's new

- **`pelfs browse [--rw] [--open] <prefix>` — a page on `127.0.0.1` that
  answers the two questions a file manager cannot**: is this staged on my
  laptop or is it in the federation, and publish it now. It opens a volume,
  serves one page on a random loopback port, and prints the URL whether or
  not `--open` launches a browser, because a login node has no opener.
  Read-only unless `--rw`; foreground, so Ctrl-C is the unmount and the
  session seals on the way out exactly as a mount does.

  The durability line never merges the two facts into one checkmark: a
  filled amber dot for "on this machine only", with the file count, the
  bytes and how long until the next automatic publish, and a green check
  for "in the federation (generation N)". A lease that has gone `stale`,
  `interrupted` or `lost` — a laptop that slept, another writer that took
  the branch — is a banner the moment it is known rather than a surprise at
  the seal. `Publish now` answers **202 with a job id** and reports
  progress on a Server-Sent-Events stream, because the seal holds the
  overlay's lock for as long as it takes and a synchronous request would be
  a spinner with no information in it; a second click while one is running
  gets **409** naming the job that holds the lock, not a queue.

  **A `--rw` session also seals on its own once the last tab closes.** A
  browser tab has no unmount, and a drag-and-drop of a couple of hundred
  documents fires neither write-pressure trigger — those are 1 GiB staged
  and 200,000 dirty inodes — so before this the work sat in the overlay
  until the five-minute checkpoint came round, while the user closed the
  laptop and told a collaborator the data was there. The trigger is a quiet
  WINDOW after the `/events` stream set becomes empty, which is what makes
  it safe rather than annoying: a reconnecting browser does not fire it and
  any stream that appears clears it, two tabs open means one closing is not
  idle, a closed lid seals when it wakes because the window is compared
  against the clock rather than counted in samples, `navigator.sendBeacon`
  only shortens a wait that is already running and is never itself a
  trigger, a failed idle seal backs off on the write-pressure path's own
  formula, and it cannot re-enter a seal in flight because it takes the
  same publish slot the button takes.

  **There are no cookies, anywhere.** A cookie set for `127.0.0.1` has no
  port isolation at all (RFC 6265bis §8.5), so it is sent to every other
  local service the browser is made to contact. The launch URL carries a
  single-use 120-second bootstrap token in its **fragment**, the page
  exchanges it once for a session token it keeps in `sessionStorage` (which
  *is* port-scoped) and sends as a request header, and nothing this process
  mints outlives it. `internal/httpguard` puts the rest in one place and
  one order: an exact `Host` allowlist that answers **421** to anything else
  (this is the DNS-rebinding defence, and it is the only thing that works —
  CVE-2018-5702 is the case where a custom header *was* the CSRF defence
  and rebinding walked through it), `net/http.CrossOriginProtection` with
  both of its documented gaps closed, an exact `Origin` match,
  `application/json` on anything that mutates, a strict
  `Content-Security-Policy` with a per-response nonce, and no
  `Access-Control-Allow-*` header on any surface ever. `/debug/pprof` —
  which the control socket exposes on the strength of being a 0600 unix
  socket — is not routable from a browser at all.

  **Downloads carry no credential in the URL.** An `<a href>` cannot set a
  request header, and exempting GET from the credential rule is precisely
  the hole rebinding exploits, so the page asks an authenticated route for a
  single-use 30-second ticket and navigates to `/d/<ticket>`. The URL in the
  browser's download history is already spent by the time it is written
  there. Bytes come from the volume with `Range` support, a symlink to a
  file serves the file it names, and a path this session may not read is a
  403 rather than a 404, because "you cannot" and "there is nothing" are
  different answers.

- **A WebDAV endpoint, at `/dav/` on the same listener.** `internal/vfsdav`
  is a `webdav.FileSystem` over the same layer the NFS frontend mounts, so
  a person on Windows or macOS can browse, download and upload with a client
  they already have and no FUSE, no kext and no administrator — Cyberduck,
  Mountain Duck, rclone, WinSCP, `mount_webdav`, the Windows redirector. It
  is also the answer for a large file on a flaky link, where a real client's
  own resume works.

  What it is held to is measured. `litmus`, the WebDAV compliance suite,
  scores the adapter **basic 16/16, copymove 13/13, props 29/30, locks
  32/34**. The one props failure is the honest part: the same suite scores
  30/30 against `x/net/webdav`'s own in-memory example server, and the
  example server reaches that only by hard-coding a 400 on litmus's own
  probe header. Three real clients also drive it in a container with no
  network — Cyberduck's CLI (the same protocol stack as Cyberduck and
  Mountain Duck), rclone over both a TCP port and a unix socket, and curl —
  and a 68,497,408-byte file, the size the Windows WebDAV *redirector*
  refuses outright, transfers through Cyberduck's stack at the right length,
  with `Range` requests served exactly so a client can resume a download.

  Two things a pelfs volume has that WebDAV has no way to say, handled
  rather than ignored: a symlink to a file is **followed**, so
  `lib.so -> lib.so.1` is the file it names instead of an empty one; and
  the entries no client could render — a link to a directory, a dangling
  link, a fifo, a socket, a device node — are hidden and **counted**, so a
  tree that looks smaller than it is can say so. The surface emits no
  `Access-Control-Allow-*` header on any response, ever, which is not an
  omission: without one a web page on another origin cannot get a preflight
  for PROPFIND, PUT, MKCOL, MOVE, COPY, DELETE, PROPPATCH or LOCK, so the
  entire WebDAV write surface is unreachable from a browser by
  construction. A test asserts it on every one of those verbs, in every
  authentication state.

- **A credential desk: connect Cyberduck by opening a file, and click once
  to say so.** `internal/localoauth` is an authorization server —
  `GET/POST /oauth/authorize`, `POST /oauth/token`, authorization-code with
  PKCE `S256` — and `internal/davprofile` generates the
  `.cyberduckprofile`, the `.duck` bookmark and the per-client HTTP Basic
  credential a client that is not Cyberduck needs. "Connect another
  program" on the page adds a program, saves the profile or the bookmark,
  hands over the username and password for everything else, and lists and
  revokes every credential this session has issued.

  **The consent click is structural, not a convention.** An `/authorize`
  endpoint that mints a token from an existing session with no user
  interaction is a token-exfiltration primitive for anything that can
  navigate the user's browser to it, and being on loopback does not help: a
  top-level navigation needs no preflight. So `GET /oauth/authorize` has no
  code path that emits a `Location` header at all. It renders a screen
  naming the program, the volume, the access being asked for and the address
  the authorization would be sent to; that screen carries a 32-byte consent
  ticket that exists nowhere else, cannot be framed, and — because the
  page's own CSP is `script-src 'none'` — cannot be submitted by script. The
  only thing that can complete an authorization is a person pressing a
  button. That is a deliberate divergence from "remember consent per client
  for the life of the process": the no-re-prompt property lives on the
  refresh token instead, which is where a reconnecting client actually
  needs it.

  **A token from here is strictly weaker than the browser session.** It
  reaches `/dav/*` and nothing else, can never publish, can never mint
  another credential, and can never be wider than the session that issued
  it — a read-only `pelfs browse` cannot mint a writable DAV token, and that
  is checked when the client is registered, when the scope is parsed, when
  the grant is issued, and again on every request. The tables hold HMACs
  under a per-process key rather than the secrets themselves, so a heap
  profile of the process carries no usable credential. Authorization codes
  are single-use with a 60-second life, bound to the client, the exact
  `redirect_uri` and the PKCE challenge; a replayed code is a hard failure,
  is counted, and revokes the grant the first exchange bought. A
  `redirect_uri` that differs by one character is refused **on pelfs's own
  page**, with no redirect anywhere and nothing from the request echoed
  back.

  It was verified against real Cyberduck rather than a golden file:
  `scripts/oauth-cyberduck-docker.sh` runs `duck` — the same protocol stack
  as Cyberduck and Mountain Duck — against a live pelfs authorization server
  in a container with **no network**, and completes the whole flow across 22
  checks with no failures. Three things that were inference from reading
  Cyberduck's source are now observations: a non-blank `OAuth Client ID`
  really is the switch, so the session goes straight to an OAuth flow with
  no password prompt; Cyberduck sends `code_challenge_method=S256`
  unprompted, so REQUIRING PKCE costs the primary client nothing; and the
  `redirect_uri` it sends back for a loopback callback is that string
  verbatim, which is what makes an exact-string allowlist workable rather
  than aspirational.

  **One correction to what the design pencilled in**, because it would have
  broken every Cyberduck connection: `POST /oauth/token` is on the guard's
  new token surface, not on its exchange surface. Cyberduck's back-channel
  POST is a Java HTTP client that carries no `Origin` and no
  `Sec-Fetch-Site` (the exchange surface answers 403) and sends
  `application/x-www-form-urlencoded`, which RFC 6749 mandates (the exchange
  surface answers 415). `SurfaceToken` keeps the Host allowlist, the
  `Sec-Fetch-Site` check, the exact-`Origin` match, the cookie strip and the
  headers, and drops the rules a non-browser cannot satisfy — the positive
  provenance requirement, the no-`Authorization` rule and the surface-level
  body cap, which the token handler re-imposes itself. Tests pin the
  placement. And `internal/vfsdav` learned to narrow a 401's challenge to
  the scheme the client tried, so a client whose Bearer token was refused is
  not offered `Basic`, which would drop Cyberduck into a password prompt for
  a profile that has no password field.

- **A JSON data plane at `/api/v1`.** `internal/webapi` answers a file
  manager's REST contract over the same volume, the same namespace and the
  same permission model every other frontend sees: list, create folder,
  rename, move, copy, delete and whole-file upload, with download on the
  ticket route. It is what a browser file manager will be built on, and it
  is reachable and tested today (see *Not in this release* for what is not).

  The contract is not invented. Every request the real
  `@svar-ui/react-filemanager` component makes, in the order it makes them,
  is recorded in `internal/webui/testdata/svar-contract/recording.json`, and
  Go tests **replay that recording against these handlers**, so the day a
  component upgrade changes the wire shape a Go test fails instead of a
  browser.

  Three properties are the design rather than fallbacks. **A directory
  listing is capped at 5,000 entries**, because the component does not
  virtualize: a probe drove the real component in a real browser and
  measured a 100,000-entry directory as 1,000,067 DOM nodes, 703 MB of heap
  and 17.7 s to open, against 320 ms for 5,000. What makes a cap acceptable
  is being told about it, and there is a second reason the telling is not
  optional: the component's search box filters loaded data only and issues
  no request, so in a capped folder a user who searches, finds nothing, and
  concludes the file is not there has been misled. Every listing therefore
  carries the true count, the cap and the hidden count in its headers,
  `GET /api/v1/info/{id}` returns them as JSON, and the sentence to display
  is generated by the API rather than re-worded per surface. **A batch of
  five moves returns five results**, and the request is still a 200 —
  there is no atomic N-way rename in the overlay, in WebDAV or in POSIX, so
  a batch is N sequential operations and each id gets its own outcome; a
  4xx would tell the client nothing happened when in fact most of it did.
  **Uploads stream**: the body is read with `r.MultipartReader()` and copied
  through a 32 KiB buffer, never `r.ParseMultipartForm`, which buffers and
  then spools the rest to a temp file — writing a 68 MB container image to
  disk twice. The test drives a generated 68,497,408-byte payload and holds
  the whole handler under a 16 MiB peak-footprint ceiling, and an AST check
  fails the build if `ParseMultipartForm` reappears anywhere. Bytes land
  under `<name>.pelfs-part` and are renamed only once the whole body has
  arrived, so a truncated upload never shows a name that the next checkpoint
  would publish.

  Listings do not lie about symlinks: the policy is the WebDAV adapter's
  exactly — a link to a regular file is followed and shown under its own
  name, a link to a directory is hidden because the layer below cannot
  traverse one, a dangling link is hidden, and fifos, sockets and device
  nodes are hidden — and everything hidden is counted and reported, so a
  tree never quietly looks smaller than it is.

  One finding worth recording for whoever writes the next route:
  `net/http`'s `{id}` wildcard does not match a path segment that is exactly
  `%2F` — the volume root as an id — because unescaped it reads as a
  trailing empty segment. Every id route therefore has an `{id...}` sibling,
  without which "add a folder in the root" would be a 404.

- **The federation SSO prompt shows up in the browser instead of the
  terminal.** `pelfs browse` installs pelican's
  `oauth2.SetVerificationURLHandler`, so "authorize with your institution"
  arrives as a card on the page — the URL, the code to type, and what pelfs
  is waiting for — rather than as a URL in a terminal the user was told they
  would not need. The hook is **process-wide**, so `pelfs browse` is the
  only verb that installs it and it removes it on the way out; `pelfs mount`
  and `pelfs get` keep the terminal behaviour they always had, and pelican
  still writes the URL to stderr in every case. Prompts are a **set with a
  TTL**, not a slot, so two namespaces can each open a flow and both get a
  card, and identical prompts fold together. A prompt raised **before the
  browser has connected** — the likely case, since credential priming runs
  as the volume opens — is not lost, because the cards are state and
  `/events` carries snapshots. The card **never says "authorization
  complete"**, because the hook is one-way and cannot know: it greys out on
  a ten-minute TTL, is dismissible by hand, and carries no token of any
  kind.

- **Windows builds.** `CGO_ENABLED=0 GOOS=windows go build ./...` succeeds
  for `amd64` and `arm64`, a CI job holds it there (build, vet, and two test
  lanes), and release tags now carry both. This is groundwork for a Windows
  frontend and **is not one**: `pelfs mount` and `pelfs shell` do not work
  there and say so during argument handling, naming the missing dependency
  rather than the platform, while everything that does not attach a
  filesystem does work. The platform-specific code is now split behind build
  tags rather than assumed. `internal/mmapfile` is new and is the only place
  in the tree that maps memory — four call sites, two of which (the
  memtable's ring and buffer) were not in the original survey — and because
  Windows mappings are stricter in three ways that all four callers depend
  on (a zero-length file cannot be mapped, a mapping cannot survive a resize
  of its file, and a live mapping PINS the file against deletion), each call
  site states which of the three it relies on, and `Table.Close`,
  `Buffer.Remove` and `Ring.Remove` unmap before they unlink. `Ring.Remove`
  did not close its file at all before. Process liveness, which the scratch
  sweeper uses to decide whether to DELETE a directory, has a real Windows
  implementation — `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` plus
  `GetExitCodeProcess`, both needed because a Windows process object
  outlives the process while any handle to it is held, and deliberately
  lopsided: only a positive "no such process" reports dead, while
  access-denied or any unrecognised failure reports alive. The FUSE frontend
  is excluded from the build rather than stubbed, since go-fuse is the Unix
  kernel protocol expressed in Go types. The NFS frontend cross-compiles
  unchanged and is kept, with `nfsmount.Mount` and `Unmount` refusing there
  instead of falling through to the macOS branch and reporting
  `mount_nfs: executable file not found in %PATH%` and then reaching for
  `diskutil`. `pelfs umount` refuses rather than pretending: the Unix path
  sends `SIGTERM` because the exit path seals the overlay into the next
  generation, and Windows offers a detached process only
  `TerminateProcess`, which would strand the session unsealed while telling
  the user it had been published. `internal/rotate`'s `syncDir`, the `errno`
  comparisons in `internal/nfsmount/diag.go`, and everything that unlinks a
  file another handle still holds open remain Unix-shaped, and are listed
  rather than fixed (`docs/TODO.md`, winport-agent).

- **`pelfs mount-gen` is an apptainer `--fusemount` driver**, so a job
  mounts a pelfs volume **inside its own container**, with no pelfs on the
  host and nothing for a site to install beyond apptainer:

  ```
  apptainer exec \
    --fusemount "host:$_CONDOR_SCRATCH_DIR/pelfs-fusemount.sh \
                 pelican://<federation>/<prefix> \
                 $_CONDOR_SCRATCH_DIR/pelfs-work /data" \
    mypipeline.sif ./payload
  ```

  `scripts/pelfs-fusemount.sh` is that wrapper, ready to ship with a job;
  `docs/design-apptainer.md` has the measurements and the constraints.

  A `/dev/fd/N` mountpoint is understood. Apptainer opens `/dev/fuse`,
  performs the kernel mount itself, and runs the driver as
  `<driver> /dev/fd/N -f` — the libfuse magic-mountpoint convention, which
  go-fuse already implements — where `mount-gen` used to `os.MkdirAll` its
  mountpoint first and die with `mkdir /dev/fd/3: not a directory`. It now
  recognises the form and, on such a mount only, skips the mkdir, skips the
  teardown unmount (there is nothing of ours to unmount, and go-fuse refuses
  a magic mountpoint by design), skips the `/dev/fuse` usability probe,
  refuses `--backend nfs` and `--subshell` with a reason, and tolerates the
  trailing `-f`. `-f`/`--foreground` is accepted and documented as a no-op,
  since `mount-gen` has always run in the foreground, which is what a
  `--fusemount` driver must do.

  **Permissions are enforced by pelfs on a passed descriptor.** go-fuse
  never calls `mount(2)` there, so the `ro` and `default_permissions` this
  process asks for are never delivered — measured, and recorded in the
  design doc with the `mountinfo` diff: the mount options are the parent's,
  and apptainer does not ask for `default_permissions`. Such a mount would
  therefore have applied no mode bits at all, which is the inconsistency
  v0.2.0 closed for the NFS frontend. So `internal/rawfuse` answers
  `ACCESS` and checks OPEN, OPENDIR, LOOKUP and every namespace operation
  itself when the mountpoint is a passed descriptor, over the same model the
  NFS frontend uses; that model moved to `internal/fsperm`, imported by both
  frontends, and `internal/vfsbilly/perm.go` keeps the NFS-specific half. An
  ordinary mount is unchanged and still leaves the check to the kernel.

  **Teardown seals.** A `--rw` driver whose container is killed still
  publishes: the connection dies with the container's namespace, the serve
  loop returns, and the seal and the lease release run then. Verified by
  SIGKILL'ing apptainer mid-write in the container harness — 32 MiB written,
  generation sealed, branch advanced, lease released, and the bytes read
  back from a fresh mount.

  Three things a writable `--fusemount` job has to know, all recorded in
  `docs/design-apptainer.md`: the driver's environment is **scrubbed**, so
  the prefix, the work directory, the token and the signing key are
  command-line arguments of the wrapper rather than inherited; with `--rw`
  you must ship the volume's **signing key** (`--signing-key`), because a
  fresh work directory has none and without it the seal fails after the job
  has already finished; and **stat the mountpoint before writing to it** —
  with no prior stat the first write is refused `EACCES` and no CREATE ever
  reaches pelfs, because of an unmapped uid 0 in apptainer's user namespace.
  That last one is nothing pelfs can fix from inside; the harness works
  around it with a bare `ls -ld`.

### Fixed

- **`fsync` and `fsyncdir` made nothing durable and returned success**, on
  both frontends. An application that called `fsync`, checked the result,
  and believed its data was safe — which is the only reason to call it —
  was believing nothing. See *Upgrading*, item 1, for what it now
  guarantees and what it costs.

- **A crash between a flush and its location record no longer loses that
  flush.** A write's LENGTH became durable immediately, while the record of
  WHERE its bytes went was written much later, once the flush's packs had
  landed. In between, publishing a flush reclaimed the ring region its
  records sat in, which moves the tail hint a remount walks from, so a
  crash in that window left bytes referenced by neither place: at least one
  flush batch — 2 MiB at the shipped pack target, and more when packing
  serialises behind a slow link — usually already on the federation, with
  nothing left behind to say which pack it was in.

  The ring region is now released only once the record that replaces it is
  durable. Until then the ring is still where a recovery finds those
  extents, so a crash in the window recovers the file **byte-exact**
  instead of cutting it back. A flush therefore also means "recorded" as
  well as "uploaded": a flush waits for the location records of everything
  it published, so a failure to write one **reaches the caller** rather
  than hanging the writer or being discovered by the next mount. That
  failure is deliberately terminal for the session rather than retryable:
  once a location record cannot be written, every subsequent write and
  flush on that mount fails with the same error instead of proceeding over
  a ring whose records nobody can trust. What the hold costs is
  backpressure — *Upgrading*, item 3.

- **A crash no longer leaves a file that reads at full length with zeros in
  it.** A crash could leave a file that came back at exactly the size it
  was written, full of bytes nobody wrote. Nothing a user could run
  revealed it: `stat` said the file was whole, `cmp` was the only thing
  that disagreed, and the recovered session then sealed those zeros into a
  signed generation that `pelfs fsck --deep` called consistent — a gap in
  an extent map reads as zeros, which is right for a sparse file and a lie
  here.

  Recovery now **cuts the file back to the first byte it cannot serve**, in
  both places a length lives: the extent map and the overlay's node row,
  which is the one `stat` answers and a read clamps to. What comes back is
  a genuine prefix of what was written, or nothing, and the recovery report
  names the cut as well as the loss. A short file after a crash is a
  failure a user can see; a full-length file of zeros is not. Genuine holes
  are untouched. The loss that made this reachable is itself gone now — see
  the entry above, which closes the window rather than reporting it — so
  what is left of this change is the guarantee for every OTHER way an
  extent can go missing: a torn ring record, a truncated buffer file, a
  state directory that lost its location map.

- **Cross-generation dedup on the default write path.** Writing a file
  whose content the volume already holds now costs the metadata and nothing
  else. Before this, only `--no-memtable` deduplicated across generations;
  the default path packed and uploaded during the session against an
  in-memory, per-session map and re-sent every byte.

  Measured on four related container images, one per generation, against a
  real origin (`scripts/apptainer-test.sh` section 8b). The figure is the
  size of the origin at the end of the run, which is the number that
  matters to whoever pays for it:

  | | default | `--no-memtable` |
  |---|---|---|
  | before | 272,755,301 | 149,221,054 |
  | after | **149,224,395** | 149,221,054 |

  The two paths now land within about 3 KB of each other on a 149 MB
  volume, which is catalog-row noise rather than re-sent content. So
  **`--no-memtable` is no longer worth passing to publish images**: it
  reaches the same number and stages the whole file to local disk to get
  there. Adding one small file to a 68,497,408-byte image costs 4.9 MB, and
  a re-push of an unchanged one costs essentially nothing.

  There is no new index, no sidecar, and no new resident structure. The
  write path asks the generation it is building on, through the same
  windowed pack index the read path already uses — one 64 KiB range read
  per lookup at worst, usually nothing at all because a small index is one
  object — and it only asks about chunks at least as large as that window,
  which at the shipped 1 MiB chunker minimum is every chunk except a final
  remainder under 64 KiB.

  **One caveat, and it is a real one: publish one image per generation.**
  The flush chunks one batch of the write ring at a time, so a session
  whose writes exceed the ring cuts some chunks where the ring flushed
  rather than where the content says, and those chunks cannot dedup against
  anything. One large file per generation is unaffected — 100% of bytes cut
  on content — while four in one session measured 28%.
  `docs/known-issues.md` KL-9 has the numbers and why the fix is not local.

- **`write.deduped_chunks` reported 0 on every path that was actually
  deduplicating.** Three fields now — *Upgrading*, item 5.

- **The NFS owner override no longer reaches a frontend that did not ask
  for it.** The layer both mounts share granted one deliberate exception to
  the mode bits: the owner of a file may write it through the NFS frontend
  whatever the mode says. That is knfsd's own rule, and it is why `tar -p`
  can extract a read-only file over NFS — NFSv3 has no open operation, so by
  the time a write arrives the open it belongs to was already decided,
  correctly, on the client from our own ACCESS reply. WebDAV has a real
  open, and for it that check is the ONLY one there will ever be, but a
  frontend built on the shared layer inherited the exception anyway — so a
  WebDAV `PUT` would have emptied a `0444` file that the kernel, a FUSE
  mount and this server's own ACCESS reply all refuse. Two frontends
  disagreeing about the same file is the defect the permission work in
  v0.2.0 existed to end. The exception is now something a frontend must ask
  for **by name**, and the name says who is entitled to it; the zero value
  is the safe one. The NFS mount is unchanged and `tar -p` over a real
  kernel NFS mount still extracts a read-only tree intact.

- **A foreground session no longer creates a `vol-<id>` directory in the
  user's home**, and the mount registry no longer accumulates empty ones —
  *Upgrading*, item 6.

### Not in this release

*(Superseded before this release was tagged: `pelfs browse` now serves the
file manager at `/` and the connection page at `/connect`. See
**Unreleased**, above. The rest of this section — the build machinery, the
provider defects, the no-network property — is unchanged and still true.)*

**The React file manager is built, committed and tested — and no shipped
verb serves it.** `internal/webui` carries a bundle built from the MIT SVAR
component by `go generate` and embedded with `//go:embed`, a licence gate,
a reproducibility gate and a browser suite. But nothing in `cmd/pelfs`
imports the package, so it is not linked into the `pelfs` binary at all,
and `pelfs browse` serves its own hand-written page. What ships and is
reachable is the JSON data plane, the WebDAV endpoint, the credential desk
and that page. Treat the file manager as landed infrastructure whose wiring
is the next milestone, and read any claim about "a file manager in the
browser" as describing what the data plane is for rather than what a user
can open today.

The build machinery around it is real and is worth having regardless. The
bundle is **committed**, so `go build ./...`, `go vet ./...` and
`go test ./...` need no Node, no pnpm and no npm, and the job that needs
Node is a separate workflow with its own path filter, so a Go-only pull
request never waits for it. Because a committed build artefact rots
silently, `.github/workflows/webui.yml` runs the build **twice** — proving
the output is byte-reproducible, which is what makes the gate trustworthy
instead of flaky — and fails if `internal/webui/dist` or
`internal/webui/third_party.txt` differs from what its sources produce. It
also fails if any GPLv3 `wx-*` package appears in the lockfile: the
component is MIT under its `@svar-ui/*` names and was GPLv3 under the
retired `wx-*` ones, pelfs is Apache-2.0, and the bundle would ship *inside*
the binary, so that swap would be a relicensing event disguised as a
version bump. `third_party.txt` lists all 30 bundled packages with their
licences and the full licence text each one requires be carried with a
distribution.

The component was measured before it was adopted, which is where the API's
5,000-entry cap comes from, and **three** defects in its shipped data
provider were found the same way — two on the wire and one by reading the
method afterwards. `setHeaders()` never reaches the wire, so the session
credential would have been silently absent; every mutating request goes out
as `Content-Type: text/plain`, which is the one content type an HTML form can
send and which the threat model answers with 415; and its error handling
catches its own throw, so every failure resolved to success. All three are
fixed in an override inside a subclass, and all three are pinned by tests
that will say so if a future release makes the subclass unnecessary. (The
third had a second half that the override could not reach — see *Fixed*
under **Unreleased**.) The UI also loads nothing off the network — the component's
default theme injects a CDN stylesheet link and its default icons are CDN
URLs per file extension, and three separate checks (one in the build, one
in Go, one in a real browser) keep them off, because a localhost tool that
phones home is both a privacy leak and broken on an air-gapped machine.

**Resumable upload is not built either**, on any surface. The JSON API
takes one whole-file `POST`, so a dropped connection at 90% of a 68 MB file
starts over, and nothing can show a progress bar until the request
finishes. The WebDAV endpoint is the answer for a large file on a flaky
link. Tracked as KL-15 in `docs/known-issues.md`.

### Scale

Unchanged as a design target — volumes of order a hundred million objects
— and unchanged in what is proven end to end: CI still untars 62,500 files
through both frontends, diffs the tree through the live mount, seals it,
cold-mounts the published generation into a state directory that never
existed before and diffs it again, runs `fsck --deep` and `gc`, and
publishes a second generation carrying an add, a modify and a delete which
is cold-mounted and diffed once more. A mount is still `kill -9`'d
mid-flush after writing 384 MB, remounted, and held to the recovery
contract — and that contract is stronger now, because the flush window
above is closed and a recovered file is a genuine prefix rather than a
full-length fabrication.

The resident-memory picture is unchanged by this release and still has one
open item: the read path's pack-location map is capped at 131,072 entries,
and four call-site families still opt out and hold every location. It is
tracked as KI-8 in `docs/known-issues.md`, and the sorted, mmap'd spill
table it needs exists and is simply not wired in.

One new bound worth knowing: **a browser directory listing is capped at
5,000 entries** and the API says so in its headers and in a sentence,
because the component that will consume it does not virtualize. That is a
frontend cap, not a volume limit; WebDAV and both mount frontends list a
directory in full.

### Known limitations

Everything in v0.2.0's list still holds. Four things this release changes
or adds:

- **`fsync` is state-directory durability, not federation durability**, and
  on an NFS mount over real storage it costs a commit per small file
  created whether or not anything called `fsync` (KL-16). A tmpfs CI runner
  cannot see that cost.
- **Permission enforcement is fidelity, not access control — now on three
  surfaces.** The NFS export, the WebDAV endpoint and a `--fusemount` mount
  all evaluate every request as the identity that started the server. Do
  not treat any of them as a multi-user boundary (KL-6, whose scope this
  release widens).
- **The checks pelfs applies on a passed descriptor are weaker than the
  kernel's, in two known ways** (KL-8). Path traversal is enforced only on
  a dentry-cache miss, so a search-denied directory still admits a name the
  kernel already looked up; and supplementary groups are unavailable for
  any uid but the mount owner, so the group class is judged on the primary
  gid alone and can deny what the kernel would allow. Neither is pinned by
  a test. An apptainer job that relies on mode bits for isolation between
  uids inside its own container is getting a weaker check than an ordinary
  mount gives.
- **A session that writes more than the write ring holds cannot fully
  deduplicate.** Publish one image per generation (KL-9).
- **No resumable upload on any surface** (KL-15).
- **`pelfs mount` and `pelfs shell` do not work on Windows.** The Windows
  binary is for everything that does not attach a filesystem; a Windows
  user reaches a volume's files over WebDAV.

### What a failure looks like

Unchanged, with two additions. A `fsync` that cannot make its layers
durable returns the error rather than success, and a flush whose location
record cannot be written fails the writer that asked for it rather than
hanging or deferring the discovery to the next mount. A crash still loses
at most what was not yet durable, and what comes back is a genuine prefix
of what was written, never a full-length file of bytes nobody wrote.

A `pelfs browse` session that cannot reach the federation behaves like any
other seal that cannot: the overlay is left intact, the branch does not
move, and the page says so on its banner rather than at exit. A failed
idle seal backs off rather than retrying every 30 seconds against a broken
federation.

### Verified by

Everything v0.2.0 listed, plus:

- **`make browse-gate`** — the shipped binary against a fakeorigin, curl
  playing the browser against every route, **real Cyberduck** (`duck`)
  playing the WebDAV client including an upload, and then a second, fresh
  `pelfs` that mounts the published generation from an empty state
  directory and reads the payloads back out of the federation, including
  the file Cyberduck uploaded. It is a CI gate and a release gate.
- **The WebDAV compliance and client harnesses** — `litmus` against the
  adapter and against `x/net/webdav`'s example server for comparison, and
  Cyberduck's CLI, rclone (TCP and unix socket) and curl driving the
  adapter in a container with no network.
- **`scripts/oauth-cyberduck-docker.sh`** — the whole authorization-code
  flow against real `duck` in a container with no network.
- **`scripts/webui-playwright.sh`** — a real Chromium against the real
  binary, asserting the browser half of the threat model, which is the one
  half a Go test cannot: no `Set-Cookie` and an empty `document.cookie`
  after a full session; the session token in `sessionStorage` and nothing
  in `localStorage`; a single-use bootstrap token whose second use fails
  visibly and which never survives in the address bar; a ticketed download
  that works with no credential and 404s on replay; a rebound `Host`
  answered 421 (Chromium's `--host-resolver-rules` maps an attacker
  hostname to loopback, which makes DNS rebinding directly testable); a
  cross-site page that cannot read a response, submit a form, load an
  `<img>`, frame the app, or preflight a `PROPFIND`; an SSE reconnect that
  leaves no stale view; the `<noscript>` message; and not one request
  leaving 127.0.0.1 for the whole session. `retries: 0`, no fixed sleeps,
  expect-polling only — a browser gate that needs a rerun to go green
  teaches people to rerun the next real failure too.
- **A Windows CI job** — build, vet, and two test lanes on
  `windows-latest`, so the cross-build is held by something other than a
  release tag.
- **The apptainer container harness**, including the SIGKILL-mid-write case
  above.

Cost-attribution measurements that are stopwatches rather than gates now
include the fsync-coalescing benchmarks
(`internal/overlay`) and the ring-hold model
(`PELFS_RINGHOLD_MEASURE=1`). The NFS `fsync` cost on real storage is
neither — it is a hand measurement, and it is labelled as one above.

## v0.2.0

v0.1.0 could mount, write, seal, branch and tag. It could not merge a
branch back, rebuild a lost ref, replace a signing key, or free the bytes
its own repacks had condemned — and it let any process write any file
through the NFS frontend regardless of that file's mode bits. All five are
fixed here.

The on-disk format is still `FormatVersion 2` and no volume needs
converting. Two things change for a v0.1.0 user anyway: an NFS mount now
refuses writes it used to accept, and a generation this release seals
**cannot be read by a v0.1.0 binary**. Read *Upgrading from v0.1.0* before
you upgrade a volume anyone else is using.

Still a prototype, still used against real federations, and still
unprivileged and `CGO_ENABLED=0`.

### Upgrading from v0.1.0

Seven changes a v0.1.0 user will notice, and what to do about each.

#### 1. An NFS mount enforces POSIX permissions. It enforced none.

This is the one most likely to break a working script. On a v0.1.0
NFS-backed mount a write to a mode-0444 file **succeeded**, and the bytes
survived the seal; `access(2)` and `test -w` answered "writable" for
everything, because go-nfs replied to an ACCESS RPC with whatever the
client had asked for. The same write through FUSE was refused with
`EACCES` — that mount asks the kernel to check
(`default_permissions`), and NFSv3 puts the check on the server, where
nothing performed it. Which backend you happened to mount with decided
whether your own mode bits meant anything.

The model now lives in `internal/vfsbilly/perm.go`, and the go-nfs fork pin
moved to `13c0560` to carry the half that cannot be done from outside the
package:

- Mode bits by class — owner, else group, else other, **first match
  deciding** — so a mode of `0004` denies its owner, exactly as the kernel
  does.
- Write and search on the parent directory for anything that creates or
  removes a name; search permission on every path component; the sticky-bit
  rule on `rm` and `rename`; ownership for `chmod` and `utimes`;
  `CAP_CHOWN` for a `chown`, and `CAP_FOWNER`, `CAP_DAC_OVERRIDE`,
  `CAP_DAC_READ_SEARCH` honoured where the kernel would honour them.
- `EPERM` where the kernel says `EPERM` (you are not the owner) and
  `EACCES` where it says `EACCES` (the mode bits say no).
- **`access(2)` and `test -w` answer honestly.** The fork exports
  `nfs.PermissionChecker`, so the ACCESS reply is a projection of the model
  above rather than an echo of the request.
- **`tar -p` works.** A read-only file created and then written through one
  file descriptor is allowed for the file's owner, scoped exactly as knfsd
  scopes it: existing regular files, on `open`, and nowhere else — not
  ACCESS, not the namespace operations, not the path walk, not the
  ownership questions.

**Whose permissions: the mount's own.** Every request is evaluated as the
identity that started the server — its uid, gid, supplementary groups and
effective capabilities, read from the process and translated through the
same id map that decides whose name the mount puts on a file. The AUTH_UNIX
credential NFSv3 puts in each request is deliberately **not** consulted:
the export is loopback and single-user, any local process can dial
127.0.0.1 and claim any uid, so honouring it would make the check look like
a security boundary. It is not one. What this buys is fidelity — the same
answer through both frontends — and nothing else. The reasoning is written
out in `docs/go-nfs-patches.md`.

**There is no escape hatch.** No flag, no environment variable and no
config field restores v0.1.0 behaviour; the only way to get it is to
recompile against a different credential. If a script of yours writes
through a mode that denies it, fix the mode, or run the mount as a uid the
mode permits.

Two deliberate non-implementations, so they are not discovered as bugs:
`S_ISUID` and `S_ISGID` are not cleared on a `chown`, nor on a `chmod` by a
non-member of the file's group.

**FUSE mounts are unaffected** — there is no permission logic on the FUSE
side, before or after this work. The kernel does it, and always did.

#### 2. A writable mount now collects as well as repacks.

Auto-repack shipped in v0.1.0 and nothing ever COLLECTED: a repack
condemns packs, the retention sweep is what deletes them, and the only
thing that ran the sweep was a person typing `pelfs gc --delete`. A volume
that repacked itself faithfully every six hours still grew forever, and
both halves of the v0.1.0 limitation stayed true for the half that frees
bytes.

The sweep now runs in the same idle machinery, under the same quiescence
and back-off rules: after a repack that published — that repack is what
created the work — and otherwise on a six-hour floor while the mount is
quiet. Default ON, `--no-auto-gc` to turn it off, separately from
`--no-auto-repack` because the two fail differently: a repack that does
not run costs storage, and **a sweep deletes.**

What that costs, and how to watch it:

- **It is the existing sweep, not a new one.** `retention.GC` with
  `Delete`, every window intact — the grace window the volume records, the
  retain-K generations, the three condemned ledgers — and the same
  fail-closed rule: a ref or tag that will not verify aborts the run and
  deletes NOTHING. There is deliberately no second deletion path in the
  mount to keep in agreement with the first.
- **The first sweep of a session does not wait six hours.** A mount that
  has just started is the best evidence available that nobody has swept
  this volume lately, so the floor counts as passed. In practice a writable
  mount deletes something within about seven minutes of going idle — a
  two-minute check tick against a five-minute quiescence window. If that is
  not what you want on a volume you were about to inspect, mount it
  read-only or pass `--no-auto-gc`.
- **It rides the write lease**, so it happens on writable mounts with a
  non-zero `--snapshot-interval` and nowhere else. Read-only mounts never
  maintain, and — unchanged, and still the honest limit — **a volume nobody
  mounts writably is never maintained.**
- Where to look, because it has to be readable months later and not only in
  a log: `pelfs ctl <mount> status` gains `last_gc_at`, `last_repack_at`,
  `reclaimed_bytes`, `reclaimed_objects` and `last_gc_error`. The
  statistics file gains a `maintenance` section carrying `repacks`,
  `last_repack_at`, `condemned_bytes`, `collections`, `last_gc_at`,
  `reclaimed_objects`, `reclaimed_bytes`, `grace_seconds` (the window the
  last sweep applied), `collection_failures` and `last_collection_error`.
  The failure counter is the one to alert on: a sweep that fails closed
  every time looks exactly like a volume with nothing to collect.

#### 3. State-directory and statistics changes

Nothing here needs a migration step, but a script or supervisor that reads
either will notice.

- **The decoded-chunk tier is one file.** `gencache/chunks/` — a plaintext
  file per chunk the mount had ever read — is now `gencache/chunks.arena`,
  one preallocated, mmap'd file. **The first mount with this build sweeps
  the old directory** and logs what it reclaimed. Nothing is lost:
  everything under `gencache/` is re-derivable from the federation, and a
  v0.1.0 binary pointed back at the same state directory simply refills the
  old shape.
- **Scratch directories are pid-named and swept.** Spool directories are
  now `publish-<pid>-*`, `snapshot-<pid>-*` and `repack-<pid>-*`, and every
  mount — read-only ones too — collects the ones whose owner process is no
  longer running, reporting the bytes and the names it took. A directory an
  older release wrote carries no pid and waits out a 24-hour idle guard
  instead; a week untouched collects even a live-owned one, because pids are
  reused.
- **The dedup sidecar is restamped by a repack**, so the first seal after a
  repack deduplicates again instead of re-uploading everything. Nothing to
  do; the file is rewritten in place by the repack that publishes.
- **Statistics keys changed, and `pelfs_stats_version` is now `3`.** Two
  keys were REMOVED, which is exactly what that number exists to
  announce: a reader keyed to a removed name gets nothing rather than a
  zero, so it has to be able to tell. Version 2 only ever added fields.
  Three things to fix in a supervisor:
  - `prefetch_chunks` is **gone**, replaced by `prefetch_packs`.
    `prefetch_fetched_bytes` is new — what this session actually
    transferred, as against `prefetch_bytes`, the size of the set now
    local. `prefetch_complete` and `prefetch_failed` are unchanged.
  - `cache.dirs.chunks` is **gone**, replaced by `cache.dirs.arena`.
    `cache.chunk_hits` and `cache.chunk_misses` are new and are how you
    tell whether the arena is the right size for the workload.
  - Everything else in the window is additive: `lease_key`,
    `lease_interrupted`, `lease_revalidated_at`, and the `maintenance`
    section above.

#### 4. Interop with a v0.1.0 client: one direction is safe, the other is not

**A v0.2 client can read and write a v0.1.0 volume. A v0.1.0 client must
not be pointed at a volume this release has written.** Two independent
reasons.

**The write lease is per branch now.** It was `meta/lease.json`, one object
for the whole prefix, so two writable mounts on DIFFERENT branches of one
volume refused each other though they could never touch the same ref. The
key is now `meta/lease-<branch>.json`: writable mounts of `main` and `dev`
run concurrently and both seal, and only a second writer on the SAME branch
is refused, still naming the holder. Nothing about the guarantee changed —
the lease was always advisory DETECTION and not mutual exclusion, and what
actually prevents two writers corrupting each other is the seal's refusal
to publish over a ref that moved. A per-branch key removes a FALSE
exclusion; it adds no safety.

Mixed with a v0.1.0 client the rule is asymmetric on purpose:

| writer | excluded by | excludes |
|---|---|---|
| v0.2 on branch B | a live `meta/lease.json` (any v0.1.0 writer), and a live `meta/lease-B.json` | v0.2 writers on B only |
| v0.1.0 (any branch) | a live `meta/lease.json` | every v0.1.0 writer on the volume — and nothing else |

A v0.2 writer READS `meta/lease.json` and refuses while one is live, naming
the holder, because a v0.1.0 record does not say which branch it is on. It
never WRITES that object: doing so would put two v0.2 writers on different
branches back to excluding each other through the legacy key. The
consequence, stated rather than hidden: **a v0.1.0 client sees a v0.2
writer as unleased and will mount straight past it**, and its only guard is
then the seal refusal. New flag `--ignore-volume-lease` proceeds past a
live legacy object, leaving it exactly where it was to expire on its own
TTL; `--steal-lease` deliberately does not apply to it, because that flag
takes one branch's lease and the legacy object belongs to a client whose
branch you cannot see.

**The superblock's new `Branch` field is a one-way door.** Every superblock
written before the field still verifies unchanged — pinned against
**captured v0.1.0 wire bytes** rather than a round trip through the current
encoder (`TestAV010SuperblockStillVerifies` in
`internal/superblock/branchfield_test.go`, over the committed fixture
`internal/superblock/testdata/v010-superblock.hex`). The other direction is
a hard refusal: `Verify` re-encodes the decoded struct, so a v0.1.0 binary
— which drops a field it does not know — gets **`ErrBadSignature`**,
"superblock signature verification failed", on any generation a v0.2 writer
sealed. `FormatVersion` did not change, so the old binary has no polite way
to say "newer format": expect the signature error, and read it as version
skew rather than as tampering.

That was chosen deliberately. Stamping only the disaster-recovery backup
would have kept old mounts working, and an old `pelfs gc` would then have
mounted the volume, failed to verify the new backups, read them as absent,
reported a short retain window and collected what those generations alone
named. A loud refusal beats a quiet deletion.

#### 5. Ordering constraint: merge before rotate

A branch pins its merge base with a `fork-<branch>` tag, because the base
stops being any branch's head the moment the source branch seals again.
Every tag stops verifying across a key rotation, permanently, and
`pelfs tag` can only freeze a branch HEAD — so a fork point cannot be
re-pinned once it is unreadable. **A rotation therefore makes a pending
merge impossible, with no repair afterwards.** `pelfs rotate` names the
affected branches and their pinning tags before it writes anything, and
`--break-siblings` is what lets you past the refusal. If you have branches
to merge, merge them first.

#### 6. `--prefetch` moves packs, not decoded chunks

"I want the data local" now means the generation's *packs* are local, which
is what a read is served out of anyway. It used to pull every chunk through
the read path — decompressing, decrypting and writing one plaintext file
per chunk — so a prefetch cost a full decode of the volume up front plus a
second copy of it on disk, for a decode the mount then repeated later
anyway whenever a chunk file had been evicted. Strict mode's contract is
unchanged: it still refuses to start unless everything is local, and the
check is now that every referenced pack is cached and length-verified.

Two refusals are new, and both happen before any payload moves: a
generation whose pack set exceeds the local cache budget is declined with
both numbers rather than fetched and evicted piece by piece, and a mount
with whole-pack caching turned off (a negative `PackCacheBytes`) reports
that a prefetch is impossible rather than warming nothing.

#### 7. One v0.1.0 state directory this release will refuse to write

If a v0.1.0 writable session was **interrupted** — `kill -9`, `--no-seal`,
a failed seal — after it had partially overwritten a file the base
generation already held, and before the checkpoint that would have
published that write, then `pelfs mount-gen --rw` on that state directory
refuses to start here.

The reason is the fix described under *Fixed* below: a partial write to a
published file ADOPTS it by reference, and v0.1.0 journalled the adoption
as "handle H came from inode N" on the reasoning that an immutable
generation can always be asked for N's records again. It cannot — a mount
that has just started has descended nothing, so nothing is resident. This
release writes the chunk identities down at adoption time, and it refuses
rather than guess for a state directory that has none: those extents' bytes
are published and immutable, and dropping them would write zeros over live
content at the next seal.

The refusal names every affected inode at once and says what it costs. What
is still readable is everything the volume ever published, including the
last checkpoint's generation — mount without `--rw`, or `pelfs fsck` it. To
start writing again, move `<state-dir>/content` and the overlay directory
aside, or use a fresh `--state-dir`; that discards what was written after
the last checkpoint and nothing else.

A v0.1.0 state directory whose adoption WAS published is unaffected: the
handle is one no surviving row names, and it is now silently dropped.

### What's new

- **`pelfs merge` — bring one branch into another.** Report-first like
  `repack` and `rescue`: the default says what would come from each side
  and names every path it cannot resolve; `--apply` carries it out. A
  fast-forward publishes the other side's tree directly. A diverged merge
  builds one, three-way over the catalogs, and **reads no file content** —
  both sides are already chunked, so the merged tree is handed to publish
  as a `ContentProvider`, the chunkrefs point into the packs that already
  hold the bytes, and the merged generation names both sides' packs with an
  index that covers what came from the other branch.

  It finds its own base. `pelfs branch` now records the generation a branch
  was cut from and pins it with a tag (`fork-<branch>`), because naming a
  base is not enough to make one readable: the moment the source branch
  seals again, the fork point stops being any ref's head. A base named by
  hand is verified against that record, so a wrong one is refused rather
  than silently mis-attributing every change.

  Conflicts refuse by default and are listed with the reason.
  `--keep-both` is the other choice: ours keeps its name, theirs is written
  as `name (from <branch>).ext` — the suffix goes before the extension so
  the file still opens. Nothing is lost and nothing cleans the copies up,
  which is why it is opt-in. It refuses what it cannot duplicate: a
  modify/delete has one version, so "both" would mean resurrecting a
  deleted file under a name nobody chose.

- **The inode space is partitioned by branch**, which is what makes merging
  possible at all. A branch takes its own slice — 23 bits of lineage above
  a 40-bit allocation space, 63 bits in all so that every inode still fits
  a signed 64-bit integer — so two branches can never assign one number to
  two files. Lineage 0 is every volume that predates this.

  A pair of branches cut before lineages existed cannot be merged as they
  stand. `pelfs merge` reports the colliding inodes and the number one side
  must be shifted above, and refuses to apply; **there is no renumbering
  tool in this release**, so that is a report and not yet a path.

- **`pelfs rescue` — rebuild a volume's refs from its packs.** The
  operation the format was built for and never had: `refs/<branch>` is the
  only mutable object, so it is the only one that can be lost, and
  everything needed to replace it is already in the packs — typed entries,
  self-identifying catalogs, and a signed superblock backup from every
  seal. Report-first; `--apply` re-points the refs; **it never deletes
  anything.**

  Safety, since this is trust-boundary code run in a panic. Every scavenged
  backup is VERIFIED against the pinned key or an explicit
  `--volume-pubkey` — a pack is appendable by anyone with write access, so
  a rescue that trusted a planted backup would be the attack.
  Non-verifying documents are reported, never used, and trust-on-first-use
  is not available: with no key the answer is an error, not a new pin.
  Ambiguity is presented, never auto-picked — two verifiable candidates for
  one head is both a legitimate state and what a rollback looks like, and
  `--pick <id>` is how you decide. A candidate whose pack set will not
  resolve is skipped WITH A REASON and the walk falls back a generation,
  rather than offering a head that names fewer packs than it needs.
  `--apply` needs the signing key; the report does not.

- **`pelfs rotate` — replace the volume signing key.**
  `superblock.NextPub` has been verified since v0.1.0 and set by nothing,
  so the format could describe a rotation and no tool could start one.

  A rotation is two generations per branch — one announcing the successor,
  signed by the current key, and one signed by the successor — published by
  a single command, because nothing carries an announcement forward and
  leaving the second half to "whatever seals next" is a silent race. Both
  generations are content-neutral: no pack, no catalog, no change to what
  the volume holds.

  Report-first, and read the report. Three consequences, each stated before
  anything is written:

  - **A reader only follows a rotation if it observed the announcement.** A
    pin advances by exactly one lineage step, so a client whose recorded
    generation predates the announcement refuses the new head. Hence
    `--announce-only`: publish the announcement, wait past your readers'
    poll interval, then finish with `--apply`. A client that misses the
    window needs `--volume-pubkey` or a cleared state directory.
  - **The pin is per VOLUME**, so the default rotates EVERY branch to one
    successor key; narrowing with `--branch` requires `--break-siblings`.
  - **Every existing tag stops verifying, permanently** — a tag is
    immutable and takes no chain step. `--break-siblings` covers this too,
    and the retired key is archived read-only as
    `v2-signing.key.retired-<pub8>` precisely so `--volume-pubkey` can
    still read old tags.

  See *Upgrading* for the fourth consequence, which is an ordering rule:
  merge before you rotate.

  Crash safety: a rotation interrupted anywhere is resumable or abortable
  and never leaves a volume whose next seal cannot be signed. Re-running
  adopts the successor already minted instead of generating a second one;
  `--abort` retracts an announcement that has not been used; and an
  interrupt between the final flip and the local key promotion is repaired
  by the next seal, through the one key resolver every writer shares.

- **`T_grace` is a per-volume parameter, and now it really is one.** It was
  recorded in `Params.TGraceSeconds`, written from a compiled-in 72 hours,
  and the sweep FLOORED its own window at the same constant — so a volume
  that recorded twelve hours was swept at seventy-two, and the
  documentation calling it configurable was describing a field nothing
  read. `pelfs init --grace 12h` sets it, with a one-hour floor; every
  later seal carries the RECORDED value forward; and the sweep, the repack
  planner and all three condemned ledgers age against it. `pelfs gc
  --grace` is unchanged and may still only WIDEN — an option that could
  narrow the window is an option to delete a concurrent writer's packs.
  `pelfs gc` prints the window it applied.

  **A large window buys less than it looks like it buys**, and
  `pelfs init --grace` says so when the value you pass collides. The two
  derived-ref ledgers gain about a row per checkpoint per key space against
  a 48 KiB cap, which is 517 hash-named rows, so past
  `517 x checkpoint-interval` the byte cap binds before the window does:
  the volume behaves as though its window were that long and repacks pace
  to the room left. At the 5-minute `--snapshot-interval` default that is
  ~43 hours — the 72-hour default is already past it, and `--grace 30d` is
  past it forty-fold. Nothing a branch head or tag names is affected; what
  is shortened is the window for objects only a RETIRED generation names,
  and a workflow that needs a real pin should tag.

- **The retain window no longer over-retains on a multi-branch volume.** A
  superblock now records the ref it was sealed onto (`Branch`), which is
  what a scavenged disaster-recovery backup was missing: a generation
  NUMBER counts steps along one lineage, so both children of generation N
  seal N+1 and their backups were indistinguishable. v0.1.0 answered by
  keeping EVERY candidate for a wanted number — safe, but it meant one
  branch's window carried the other's manifests, indexes and packs, and the
  scan could never stop at the first complete answer.

  With `(branch, generation)` an identity, a generation resolved from a
  backup this branch sealed drops the siblings, and the scan stops as soon
  as every generation in the window has one. On the two-branch fixture in
  `internal/retention/branches_test.go` — main nine generations deep, dev
  five, at `--retain-k 3` — the retained set falls from 29 objects to 25;
  on an equal-depth fork of the same shape the window scan reads 3–4 pack
  trailers of 15 where it previously read all of them.

  **Attribution cannot cover everything, so the old rule survives per
  generation.** A branch's window reaches back past its own fork point, and
  those generations were sealed by the parent branch and say so — they are
  the branch's history all the same — as are any backups written before the
  field existed. Both keep every distinct candidate, and only those
  generations do, so an upgraded volume gets the tight rule for its new
  history and the conservative one across the legacy span until it has
  sealed K more times. `pelfs gc` says which rule each window used:
  `retain window:    branch dev keeps 6 of 8 generations (attributed, 3
  legacy candidates kept for 3 generation(s))`.

  A repack now also stamps the branch it publishes onto rather than
  inheriting the parent's — `pelfs branch dev` copies main's head verbatim,
  so a repack can be the first writer a branch ever has. It writes no
  backup either way; the generation a repack grew from is covered by the
  condemned-ledger floor, as before.

  **What is still not fixed:** a branch NAME is not a lineage. Delete
  `dev`, recreate it from an older generation and seal the same numbers
  again, and the two incarnations collide exactly as two branches used to.
  The newest-first scan favours the live one, and a repack that copied an
  old backup into a new pack can defeat that. Tag a generation to pin it
  exactly.

- **A repack retires index segments whose packs are mostly gone.** The
  planner has measured this since indexes were tiered and the executor
  ignored it, so a segment written for packs a later repack condemned went
  on being listed, fetched and windowed through forever — spending its
  bytes on entries that resolve to nothing. Under 50% live pack coverage a
  repack now drops the segment, **re-emits the entries it still answers
  for** into the segment it was writing anyway, and condemns the old object
  through the existing condemned-index ledger, which `pelfs gc` already
  honours — so it survives the grace window for readers pinned to the
  generation before the repack.

  Re-emitting is the half that matters: an index is derived, so dropping
  one costs only fetch time, but dropping one whose surviving packs nothing
  else indexes sends every lookup of those identities down the pack-trailer
  fallback — a cleanup that makes cold reads slower. Coverage is preserved
  and only the dead share is discarded. Retirement is **paced by the
  ledger**, exactly as pack condemnation is: what has no room for a row is
  left listed for a later run rather than dropped with nothing to speak for
  it. Manifest segments are unchanged, since a repack rewrites the manifest
  whole and condemns its segments together.

- **The decoded-chunk cache is one file, not one file per chunk.**
  `gencache/chunks/` held a plaintext file per chunk the mount had ever
  read — an inode and a flat directory entry each, with no upper bound on a
  real volume. It is now `gencache/chunks.arena`: one preallocated, mmap'd
  file with an in-memory index that is never written down, and a default
  size of 256 MiB capped at an eighth of the cache budget (previously the
  tier was unbounded except by the shared budget). Space is allocated by
  bump cursors that WRAP, so allocation is O(1) and there is no
  fragmentation to manage; wrapping over live chunks is the eviction. There
  are two cursors rather than one — a probation region of a sixteenth and a
  protected region for the rest, with a ghost table promoting a chunk that
  is read again — because plain FIFO thrashes as soon as the volume does not
  fit in the mapping.

  It is faster as well as smaller. With the tier off entirely, a cold scan
  of a 166 MiB source-shaped tree costs 0.89 s, a hot re-read 0.89 s and
  twenty thousand scattered 4 KiB reads 1.43 s; the arena serves the same
  three in 0.55 s, 13 ms and 32 ms — 1.6x on the cold scan and 68x on the
  re-read. (Reproducible: `PELFS_CHUNKCACHE_BENCH=1 go test
  ./internal/genfs/ -run TestChunkCacheWorkloads`. The absolute numbers are
  the owner's laptop, macOS/arm64; the ratios are the point.) It also beats
  the flat directory it replaces, which won on re-reads and lost on fills,
  because an arena fill is a memcpy into a mapping.

  `ChunkArenaBytes` negative turns the tier off, which is also what a
  volume whose plaintext must not touch local disk wants — as with the
  chunks directory before it, the arena holds DECODED bytes. The arena's
  size is reported by `pelfs cache` and in the statistics file under
  `cache.dirs.arena`, and `cache.chunk_hits` / `cache.chunk_misses` say
  whether it is the right size for the workload.

- Two cache-reporting bugs found on the way. `CacheUsage` returned zero
  eviction counters whenever it had to rescan, so "has this cache been
  evicting" was answerable only by luck; and a mount opened with a smaller
  budget than the last one inherited the previous arena reservation without
  agreeing to it.

- **`pelfs branch --rm` says what the fork pin is still holding.** Deleting
  a branch left its `fork-<branch>` tag behind in silence, so the space did
  not come back and nothing said why. The pin outliving the branch is
  correct — a merge may still need that generation — so the deletion now
  names the tag, the generation it pins, and the command that releases it.

### Fixed

- **A file could be visible under two names after a mid-session
  checkpoint.** Create a file and rename it inside one session, with a
  checkpoint sealing between the two, and both names resolved. Whether a
  name has been removed is decided by asking whether the base has it — and
  a checkpoint changes what the base is. The order is freeze, seal, swap,
  rebase, and the seal is seconds of network work with the mount still
  serving; for that whole window a name created before the freeze is in the
  instant being published but not yet in the mounted base, so it was in
  neither place the overlay looks. Nothing repaired it afterwards. A name a
  frozen-but-not-yet-rebased snapshot is publishing now counts as a base
  name from the moment it is frozen. **The window reached every removal,
  not just rename** — unlink, unlink of one of two hardlinks, rmdir, rename
  onto an existing name and rename between two parents were all reproduced
  and are all fixed together. It had a scale symptom too: a ghosted
  directory is reachable under two names, the seal descends it under both,
  and its entry list doubles per checkpoint.

- **Removing one name of a hardlinked file decrements its link count.** It
  did not, when the file was one the base generation already held: the
  write overlay had no row for a clean inode, so it wrote the whiteout for
  the removed name and left the count alone. The wrong count was
  **published**, not merely served — a cold mount of the sealed generation
  saw `nlink 2` for a file with one name — and it never converged, because a
  later write seeded its row from the same stale value. Nothing downstream
  corrected it: the seal recomputes a link count from surviving edges for
  DIRECTORIES, whose count is a function of the namespace, while a file's is
  a stored attribute, and the stored attribute was the stale one.

  The count is now decremented where the name is removed, and only when
  names survive — the last name still costs exactly one whiteout, so
  removing a published tree is unchanged (`BenchmarkOverlayUnlinkCleanFile`
  on the owner's laptop: allocations identical at 5,430 B/op and 142
  allocs/op, time within run-to-run noise).

  Beyond the wrong number, a file that is falsely hardlinked keeps its
  content records in an inode SHARD and marks its catalog as holding a
  promoted inode, which stops that whole subtree from ever being skipped by
  a later seal. Stale counts therefore made incremental seals monotonically
  more expensive. Found by the hostile exerciser's random lane, and proven
  to have reached published bytes by the phase that compares the sealed
  generation cold.

- **`ln` works on a file an earlier session published.** Hard-linking such
  a file on a writable FUSE mount failed with `overlay: no base provenance
  for inode N` — EIO at the `ln` — once the current session had edited it
  and a checkpoint had published the edit. Mount a state directory, open a
  file that was already there, change it, keep working, then hard-link it:
  that was enough. Nothing was lost or corrupted; the operation refused.

  The cause was a memory fix reaching further than intended. `link(2)` is
  the only namespace operation that names its source by **bare inode** and
  resolves no name, so the write path only hears about the file if
  something else looked it up first. That was always true and never
  mattered, because the cache of descent steps it consults was emptied by
  nothing — until checkpoints began sweeping it for everything they
  published, to bound a map that otherwise grows for the life of a session.
  A cache miss that had been declared impossible became ordinary, and the
  kernel's directory-entry cache is what decides whether a lookup refills
  it: the entry a mount stamps for a file it has not touched is valid for
  ten years, so an edit does not un-cache it and no lookup precedes the
  link.

  The miss now asks the base generation, which holds the same step for
  every inode a descent has reached — so the sweep keeps its bound and the
  link succeeds. An inode nothing ever looked up still gets `ESTALE`, which
  is the honest answer and is not reachable from a mount. The path
  frontends were never affected: NFS resolves `link` by path.

- **A state directory can be mounted for writing more than once.** Four
  ordinary operations left one that no writable mount would ever open
  again: write a file, let a checkpoint publish it, overwrite part of it,
  let a second checkpoint publish that. The next `pelfs mount-gen --rw`
  exited 1 before mounting, and it was not one file — the volume could not
  be written from that state directory again.

  A partial write to a published file **adopts** it from the base
  generation by reference rather than copying it, and the adoption was
  journalled as "handle H came from inode N", on the reasoning that an
  immutable generation can always be asked for N's records again. It
  cannot. The base a later mount serves is a LATER generation, and a
  generation answers for an inode only after a descent has made it
  resident — a mount that has just started has descended nothing. So the
  adoption's records are written down now, at adoption time, and recovery
  reads them instead of asking anything outside the state directory. They
  are chunk IDENTITIES, which are content-addressed and survive a repack; a
  pack location would not have.

  The four-op sequence had a second cause, and it is why the second
  checkpoint was needed: publishing an adopted file rebases the inode
  clean, which forgets its content, so the handle recovery refused over was
  one no surviving row named — and one recovery itself would have discarded
  moments later. Nothing that no row names is resolved at all now.

  The same refusal also met **every remount of an interrupted session** that
  had adopted a file — `kill -9`, `--no-seal`, a failed seal — which no
  test saw, because the existing crash test reopens the content store
  against the same live generation handle and inherits residency a real
  remount does not have. Both are pinned by ordinary-lane tests now, and
  the exerciser's corpus entry for the sequence is a passing regression.
  What is left is one honest refusal, for a state directory written by a
  build that recorded no adoption records — see *Upgrading*, item 7.

- **A lost flip is no longer silent.** The ref flip is check-then-put,
  because the transports have no `If-Match`. That was documented; how a
  lost race LOOKED from inside was not — both writers' puts succeeded, both
  flips returned nil, and one generation simply ceased to exist. No branch
  named it, so its packs became garbage nobody had asked to collect, and
  the writer that lost went on to report a generation that was not on the
  branch. Both flip paths now read the object back and compare bytes. It
  prevents nothing; it turns a silent loss into `pelicanobj.ErrClobbered`,
  surfaced as `refs.ErrFlipClobbered` and naming the generation that won.

- **A seal asks whether the branch is still ours.** Lease detection was
  partial and enforcement was absent, and a laptop that sleeps for hours
  manufactures exactly the concurrent-flip window the lease exists to
  prevent. The come-and-gone case left no witness at all: another writer
  takes the expired lease, seals, and releases — and a release DELETES the
  object — which the renewal loop read as "someone deleted our lease,
  reclaim it". A seal is now fenced against the lease, a session that
  wakes up revalidates, and a usurper that has been and gone is detected.
  The statistics file records `lease_interrupted` and
  `lease_revalidated_at`. `--no-lease` is unchanged in effect and its help
  text now says what it costs: concurrent writers are not detected and
  seals are not fenced, so publishing rests entirely on the flip's
  compare-and-swap against the branch head.

- **The lease holder is whoever the record says.** A transient federation
  error on a renewal could make a mount decide it had lost the lease,
  latch `conflicted` for the rest of the session, refuse every seal — and
  name ITSELF as the thief in the message. Ownership is now decided by the
  session the record names, not by an ETag that failed to match.

- **A state directory cleans up after a session that was killed.** Every
  operation that spools to local disk before it uploads — a seal building
  packs, a checkpoint's frozen overlay, a repack rewriting packs — left its
  scratch behind when the process died, and nothing ever collected it: the
  one sweeper a mount ran emptied `trash`, and all three scratch families
  live in the state directory's root. So a `kill -9` mid-seal cost a seal's
  worth of packs, permanently, per crash. A repack leaked its spool with no
  crash at all — the cleanup fired only when `repack.Execute` had made the
  directory itself, and both callers supply one — which, with a writable
  mount now repacking by itself, turned from a manual-command footgun into
  something every writable volume did on its own.

  Scratch directories now carry the pid of the process that made them, and
  every mount collects the ones whose owner is no longer running.
  **Ownership is asked of the OS, not of the lease:** a lease says who
  should be writing and stands until it expires, so a killed holder's
  scratch is exactly what must go, while a read-only mount or a
  `pelfs repack` on another branch is a live process with no writable lease
  whose spool must not. See *Upgrading*, item 3, for the naming and the age
  guards. A repack's spool is now a per-run subdirectory removed on every
  exit from `Execute`, success or failure.

- **A seal after a repack still deduplicates.** The local dedup index that
  lets a seal skip re-uploading content the volume already stores is valid
  only for the generation it was written against — and a repack published a
  new generation without restamping it, so the whole file was silently
  ignored and the first seal after any repack re-uploaded everything it
  would have deduplicated. On the fixture in
  `internal/repack/dedup_test.go`, a 3 MiB file already sitting in a pack
  the generation lists cost 3.15 MiB back on the wire before the fix and
  4 KiB after.

  The same rewrite fixes the second half — the index never dropped an
  entry, so it also grew without bound over a volume's life, carrying rows
  for chunks nothing references any more. A repack already computes exactly
  which chunks are live, so it now writes the index with that set and
  stamps it with the generation it published. Both halves are one operation
  on purpose: restamping without filtering would promise the next seal that
  chunks the repack has just dropped are still stored.

### Scale

Unchanged as a design target — volumes of order a hundred million objects —
and unchanged in what is actually proven end to end. CI still untars
**62,500 files** (50,000 distinct plus 12,500 hard links to them,
small-file shaped at ~900 bytes each, ~45 MB of content) through *both*
frontends, real FUSE and a real kernel NFS client, then diffs the whole
tree through the live mount, seals it, cold-mounts the published generation
into a state directory that never existed before and diffs it again, runs
`fsck --deep` and `gc`, and publishes a **second generation** carrying an
add, a modify and a delete which is cold-mounted and diffed once more. The
untar's per-chunk rate and the NFS client's RPCs per created file are
bounded rather than merely reported. Separately, a mount is `kill -9`'d
mid-flush after writing 384 MB, remounted, and held to the recovery
contract.

Two memory structures changed for the better and one is honestly still
open. The decoded-chunk tier is now bounded by construction rather than by
a shared budget (above). The read path's resident pack-location map is
capped at 131,072 entries; **two callers still opt out and hold every
location** — `FS.ContentOf`, which protects the "present in no listed
pack" verdict and is reachable from an ordinary write's copy-up rather than
only from a seal, and `FS.Prefetch`. At the design target that is the
largest resident structure in the tree. It is tracked as KI-8 in
`docs/known-issues.md`; the sorted, mmap'd spill table it needs exists
(`internal/extsort`, built for `fsck` and the reachability sweep) and is
simply not wired in.

Between the 62,500 files CI proves and the hundred million the format is
built for there is design and unit-level evidence, and no end-to-end run.
`make big-tree` takes a file count on the command line, and
`PELFS_BIGSEAL=1 PELFS_BIGSEAL_FILES=…` runs the seal-cost rig over bigger
trees; those numbers are nobody's guarantee.

### Known limitations

- **A volume nobody mounts writably is never maintained.** Maintenance
  rides the mount, because that is what holds the branch's write lease and
  knows when the volume is idle. `pelfs gc --delete` and `pelfs repack
  --apply` remain the answer for a volume that is only ever read.
- **The retain window is only as good as the superblock backups.** A
  retired generation has no address, so the sweep reconstructs it from the
  disaster-recovery superblock every seal buries in its last pack. Repack
  carries those backups forward, so ordinary maintenance keeps them; a pack
  collected by a sweep from before v0.1.0's retention work took its backup
  with it, so early sweeps on an old volume may report a short window.
  That is reported and warned about, never silently assumed.
- **A branch NAME is not a lineage** (above, and KL-3 in
  `docs/known-issues.md`). Tag a generation to pin it exactly.
- **Two branches cut before inode lineages existed cannot be merged.** The
  merge names the collisions and the number to shift above; no tool
  performs the shift (KL-7).
- **A key rotation makes a pending merge base permanently unreadable.**
  Merge first. There is no repair, by design — see *Upgrading*, item 5, and
  KL-1.
- **A large grace window is paced by the condemned ledgers**, not by the
  window (above).
- **Permission enforcement is fidelity, not access control.** The NFS
  export is loopback and single-user and every request is evaluated as the
  server process's own identity; the AUTH_UNIX credential is not
  consulted. Do not treat a pelfs NFS export as a multi-user boundary.
- **The exit drain is unbounded and cannot be interrupted.** A mount asked
  to exit while a checkpoint is in flight waits for it, with no deadline
  (KL-2).
- The origin must permit GET/PUT/DELETE and listing on the prefix; `pelfs`
  checks this up front and names the missing scope.

Open defects that are found and not fixed are tracked in
`docs/known-issues.md`, and every entry there says whether an executable
test pins it.

### What a failure looks like

A seal that cannot reach the federation loses nothing: the overlay is left
intact, the branch does not move, and the next mount of the same prefix
resumes it and seals again. This is tested, including the reopen-from-disk
half.

A seal that has LOST its branch — because another writer moved the ref, or
took the lease while this session was asleep — now refuses rather than
publishing into a fork nobody names. That refusal is
`refs.ErrFlipClobbered` or a lease fence, and it names what won.

Anything `fsck` or the reachability sweep cannot read, decode or account
for makes the result *incomplete* rather than partial — every affected pack
is reported fully live, and `repack-plan` refuses to plan at all. A pack
wrongly called dead is data loss; a pack wrongly called live costs bytes
until the next sweep. The tools are not symmetric about those two. The
automatic sweep inherits all of this unchanged: any ref or tag it cannot
verify aborts the run and deletes nothing.

### Verified by

`make test` (unit and CLI, including a model-based random test of the write
path), `make e2e` (a full mount loop in a container against a fake origin),
`make mount-gate` (the kernel mount gate: real FUSE and a real NFS client,
both required, and now including a permission gate that extracts a
read-only tree with `tar -p` over a real kernel NFS client and requires
every permission answer to match the same probe on a local tree, on both
backends), `make big-tree` (the 62,500-file scale gate described under
*Scale*), `make crash` (`kill -9` of a mount mid-flush, then recovery,
`fsck --deep`, and a check that the killed session's scratch was
reclaimed), `make opfuzz` (the overlay op-sequence fuzzer, in a sealed
container), and `make integration` (transport and publish/resolve against
a federation-in-a-box).

New in this release, and the reason several of the fixes above exist:

- **`make hostile` — the impolite user, continuously.** Adversarial op
  sequences against a REAL mount on BOTH frontends, with a reference tree
  on tmpfs mutated identically and compared byte-and-metadata-exact at 1 s
  checkpoints; then the whole lifecycle (seal, cold remount, full compare,
  `fsck --deep`, `gc`), a second WRITABLE session over the generation the
  first one published, and a `kill -9` with remount and recovery. Contained
  the way `opfuzz` is and then some: a build tag, an env gate, an image
  sentinel, `os.Root` confinement proven before the first op, and a
  container whose only host-visible path is a read-only directory of two
  binaries. Every correctness bug in the v0.1.0 release week was found by
  the owner's ordinary shell usage and none by a gate, because every other
  gate writes polite tar-shaped data. Six findings are pinned as executable
  plans under `internal/hostile/testdata/corpus/`, all of them now
  regressions that must pass. CI runs the corpus and a fixed-seed campaign,
  plus the corpus again against ENCRYPTED volumes — where a chunk is
  compressed and THEN sealed, so no entry in any pack is the length of its
  plaintext.
- **The whole suite under `-race`, over the whole tree.** Only the
  op-sequence stress was raced before, which left the memtable's promotion
  against its writers, genfs's caches, the overlay's checkpoint against
  reads, and both frontends serving in parallel checked by nothing. It has
  already caught one data race in shipped code.
- **CI runs on tags**, which it did not before — so the one commit anyone
  will ever look up, the one a release was cut from, is no longer the one
  commit nothing checked. The release job waits on every gate above.
- **`make e2e` is a CI job.** v0.1.0's notes said it ran on every push; it
  did not.

The parser fuzz targets carry a committed corpus under each package's
`testdata/fuzz/`, which an ordinary `go test` replays. Cost-attribution
benchmarks — the tmpfs floor, the overlay without a kernel, the FUSE op
mix, the decoded-chunk cache workloads — live in `scripts/bench-*` and
behind `PELFS_*` env gates, and are stopwatches, not gates.

## v0.1.0 — first release

`pelfs` mounts a POSIX filesystem whose data lives in a
[Pelican](https://pelicanplatform.org) federation. Content-addressed packs
and signed, split catalogs are the on-disk format; a generation of the tree
is one immutable, verifiable object graph, and publishing a change is one
atomic ref flip. Everything runs unprivileged and builds with
`CGO_ENABLED=0`.

This is a **first release of a prototype**. It is used against real
federations and it does not lose data on the paths that are tested, but the
maintenance story is incomplete in one way that matters — see *Known
limitations*.

### What it does

- **Mount**, read-only or read-write, over FUSE or over a loopback NFS
  server. The NFS backend is what a macOS box without macFUSE gets, and it
  is the path the project is developed on.
- **`pelfs shell`** for a subshell on a temporary mountpoint that seals on
  exit; **`pelfs mount`** for a background daemon with per-prefix local
  state; **`pelfs status`**, **`pelfs umount`**, **`pelfs ctl`**.
- **Pack as you go.** A writable mount chunks, packs, encrypts and uploads
  during the session rather than at the seal, from an mmap'd ring buffer
  with promotion by age (`internal/memtable`, `docs/design-writepath.md`).
  Periodic checkpoints publish a generation without unmounting.
- **Encryption at rest.** Pack entries are zstd-compressed (unless that
  grows them) and AES-256-GCM sealed under a volume key wrapped by a PEM
  private key you supply.
- **Maintenance.** `pelfs fsck [--deep]` verifies a generation end to end;
  `pelfs gc [--delete]` sweeps packs, multi-pack indexes and manifests no
  retained generation references; `pelfs repack-plan` reports what a repack
  would rewrite and what it would cost, and `pelfs repack --apply` carries
  it out — rewriting the packs that are mostly garbage into new ones and
  publishing a generation that condemns the old ones, after which `gc
  --delete` can reclaim them.
- **Retention that keeps the last K generations.** The sweep's root set is
  every branch head, the last `Params.RetainK` generations behind each head
  (8 by default, stated in the superblock), and every tag — so a reader
  still holding a recently retired generation keeps everything it names,
  not just whatever the grace window happens to cover. A retired generation
  has no address, so the sweep reads the disaster-recovery superblock a
  seal buries in its last pack; a generation it cannot establish is
  reported and warned about, and a read it cannot complete fails the sweep
  closed rather than guessing.
- **`pelfs tag`, and `pelfs tag --rm`.** Freeze a branch head under a name,
  list what is pinned, and release a pin. Tags are immutable, so a name in
  use never silently moves; deleting one takes its generation out of the
  root set and the next sweep reclaims what it was holding.
- **`pelfs branch` — more than one line of history per volume.** Create a
  branch at the current head of `--from` (default `main`) or at a pinned
  generation with `--from-tag`, list them, and delete one. A branch is a
  NAME over a generation: creating one copies the VERIFIED head's bytes
  under a second name, after which the two advance independently, each seal
  reading and flipping its own ref. Creation is create-if-absent — this verb
  never moves a branch, because repointing one out from under a writer would
  strand its next publish and reparent its work. Deleting the last branch is
  refused: every object in a volume is reachable from a ref, so a volume
  with none has no head to mount and no way back from the CLI.
  Every `--branch` flag in the tool finally means something, and every
  "every branch head" in the retention design is now a claim with more than
  one branch behind it. The single-branch assumptions that had gone
  untested are named under *Known limitations* and in the design doc.
- **`pelfs version`**, and `pelfs ctl <prefix> bugreport` for a tarball with
  the build, the stats and every goroutine.
- **Unprivileged by construction.** One static binary, no root, no setup;
  state under `$HOME`. The only thing it needs from the host is the ability
  to open `/dev/fuse`.
- **Automatic repacking.** A writable mount repacks itself once it has been
  idle for a while and the branch has drifted since the last one — `git gc
  --auto`'s shape, where a counter read from the head decides whether to
  pay for a reachability sweep. `--no-auto-repack` turns it off.

### Scale

The format and the maintenance tools are built for volumes of order a
hundred million objects: the pack list moved out of the superblock into a
hash-named manifest, lookups go through a tiered multi-pack index with
16-byte entries, and both `fsck` and the reachability sweep stream over
sorted spill files rather than holding an identity map. Memory for those
passes is a buffer the caller sizes rather than a function of object count.

That is a design target with unit-level evidence, not a claim about a
production volume of that size.

What is checked end to end, on every push, is smaller and exact. CI untars
**62,500 files** — 50,000 distinct plus 12,500 hard links to them,
small-file shaped at ~900 bytes each, ~45 MB of content — through *both*
frontends, real FUSE and a real kernel NFS client, and then: diffs the
whole tree against the source through the live mount, seals it, mounts the
published generation with a state directory that never existed before and
diffs it again, runs `fsck --deep` and `gc`, and publishes a **second
generation** carrying an add, a modify and a delete which is cold-mounted
and diffed once more. The untar's per-chunk rate and the NFS client's RPCs
per created file are bounded rather than merely reported. Separately, a
mount is `kill -9`'d mid-flush after writing 384 MB, remounted, and held
to the recovery contract.

Past that it is manual, and the numbers are nobody's guarantee: the same
gate takes a file count on the command line (`make big-tree` is the 50,000
CI runs), and `PELFS_BIGSEAL=1 PELFS_BIGSEAL_FILES=…` runs the seal-cost
rig over bigger trees. Between the 62,500 files CI proves and the hundred
million the format is built for there is design and unit-level evidence,
and no end-to-end run.

### Known limitations

- **Deleting the reclaimed packs is still manual, and now waits for two
  windows.** A mount repacks on its own, but nothing collects: `pelfs gc
  --delete` is a separate command, it only takes objects older than the
  grace window (72h, not configurable), and — new in this release — it
  keeps whatever the last `Params.RetainK` generations of the branch still
  name. A repack followed straight away by a sweep therefore frees nothing:
  the generations the repack retired are inside the retain window and they
  name the condemned packs. Reclamation happens once the branch has sealed
  K more times, or under `pelfs gc --retain-k 1`, which is the sweep as it
  behaved before the window was enforced. A volume nobody mounts is never
  maintained at all.
- **The retain window is only as good as the superblock backups.** A
  retired generation has no address, so the sweep reconstructs it from the
  disaster-recovery superblock every seal buries in its last pack. Repack
  carries those backups forward, so ordinary maintenance keeps them; a pack
  collected by a sweep from BEFORE this release took its backup with it, so
  the first sweeps on an existing volume may report a short window
  (`retain window: branch main keeps N of 8 generations`). That is reported
  and warned about, never silently assumed — and those generations age out
  of the window within K seals.
- **A repack cannot yet retire index or manifest objects on their own
  account.** Replacing the manifest already drops superseded segments, so
  what is missing is the narrower case of an index whose packs are mostly
  gone: it costs fetch time, never correctness.
- **Single writer, per VOLUME rather than per branch.** The advisory lease
  is detection, not mutual exclusion — the transport has no
  compare-and-swap. A seal that would overwrite another writer's generation
  is refused, so the failure mode is a rejected seal rather than silent
  corruption. `meta/lease.json` is one object for the whole prefix, so two
  writable mounts on DIFFERENT branches of one volume exclude each other
  even though they would never touch the same ref. The refusal names the
  holder; branches share one write lease in v0.1.0, and a per-branch lease
  is a v0.2 change. *(Done — see v0.2.0. The record of what v0.1.0
  shipped stands; a v0.1.0 client still locks the whole volume, and how the
  two versions interact is described there.)*
- **Two branches that have diverged stay diverged.** There is no merge, and
  none is planned for this release. What exists is branching, tagging and
  deleting. *(Done — see v0.2.0. The record of what v0.1.0 shipped
  stands: a v0.1.0 branch has no fork record and no inode lineage of its
  own, so merging one needs its inodes renumbered first.)*
- **The retain window over-retains on a multi-branch volume, deliberately.**
  A retired generation is described only by the superblock backup its seal
  buried in a pack, and a backup carries a generation NUMBER — which counts
  steps along one lineage, so both children of generation N seal N+1 and
  their backups are indistinguishable. Nothing in the store can attribute
  one to a branch (the lineage chain authenticates a single step). The sweep
  therefore keeps EVERY candidate for a wanted generation number, which
  retains more than one branch strictly needs rather than dropping a
  generation out of the root set. The scan runs to the end of the pack space
  or to its budget on such volumes, instead of stopping at the first
  complete answer; single-branch volumes are unaffected in both respects.
- **No key rotation.** It is a format feature (custody-chain verification)
  with no writer behind it. When one lands, note that the volume key pin is
  volume-wide by design, so rotating on one branch will retire the pin and
  siblings still signed by the old key will fail until republished.
  `pelfs rescue` is specified and not built.
- The origin must permit GET/PUT/DELETE and listing on the prefix; `pelfs`
  checks this up front and names the missing scope.

### What a failure looks like

A seal that cannot reach the federation loses nothing: the overlay is left
intact, the branch does not move, and the next mount of the same prefix
resumes it and seals again. This is tested, including the reopen-from-disk
half.

Anything `fsck` or the reachability sweep cannot read, decode or account for
makes the result *incomplete* rather than partial — every affected pack is
reported fully live, and `repack-plan` refuses to plan at all. A pack
wrongly called dead is data loss; a pack wrongly called live costs bytes
until the next sweep. The tools are not symmetric about those two.

### Verified by

`make test` (unit and CLI, including a model-based random test of the write
path, and under `-race` in CI), `make e2e` (a full mount loop in a
container against a fake origin), `make mount-gate` (the kernel mount
gate: real FUSE and a real NFS client, both required), `make big-tree`
(the 62,500-file scale gate described under *Scale*), `make crash`
(`kill -9` of a mount mid-flush, then recovery and `fsck --deep`),
`make opfuzz` (the overlay op-sequence fuzzer, in a sealed container), and
`make integration` (transport and publish/resolve against a
federation-in-a-box). Every one of them runs on every push, and on tags.

The parser fuzz targets carry a committed corpus under each package's
`testdata/fuzz/`, which an ordinary `go test` replays. Cost-attribution
benchmarks — the tmpfs floor, the overlay without a kernel, the FUSE op
mix — live in `scripts/bench-*` and are stopwatches, not gates.
