# A Windows drive letter for pelfs: what a WebDAV export can and cannot buy

Status: **researched, not built.** No pelfs code exists for this and none is
proposed here as done. Every Windows-side claim below is either cited to
Microsoft's own documentation or marked as unverified with the experiment
that would settle it — there is no Windows machine in this loop, and the
document says so in the places where that matters. The one thing that *is*
measured is the Go side: `scripts/webdav-litmus-docker.sh` runs the `litmus`
compliance suite against `golang.org/x/net/webdav`'s own example server, and
its numbers are in "The Go half is already compliant".

---

## Verdict

**A no-admin Windows drive letter is achievable, and it will not open the
files this was wanted for.**

Three sentences, in order of how much they hurt:

1. **The mechanism needs no administrator.** The WebDAV redirector
   (`WebClient` service) is installed on every workstation edition of
   Windows, its start type is `Manual (Trigger Start)`, and **a standard
   user can trigger it** by touching a `\\host@port\DavWWWRoot\` path. A
   loopback HTTP server plus `WNetAddConnection2` gets a drive letter with
   no elevation, no driver, and no reboot.
2. **The payload does need administrator.** The redirector refuses any file
   transfer over **`FileSizeLimitInBytes`, default 50,000,000 bytes
   (47.68 MiB)** [S1][S2]. The owner's SIF images are **68,497,408 bytes**
   (`docs/design-apptainer.md`). That value lives in
   `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters` and taking
   effect needs the service restarted — **both are administrator
   operations, and no per-user equivalent is documented anywhere.** So the
   "unprivileged Windows user" premise survives for the mount and dies for
   the 68 MB image. It is a one-time, per-machine elevation (a `.reg` write
   plus `net stop/start webclient`), not a per-session one, but it is
   elevation.
3. **And the redirector reads whole files.** Any open of a remote file
   downloads the entire file into the redirector's local cache before any
   byte of it can be read [S9][S10]. That means the 50 MB check fires on a
   *read*, not just on a copy — there is no "only touch the first 4 KB of
   the SIF" escape — and it means a drive letter is not a lazy filesystem
   no matter what pelfs does underneath.

Two more findings change the shape of the plan:

4. **Microsoft deprecated this component.** *"The Webclient (WebDAV) service
   is deprecated. The Webclient service isn't started by default in
   Windows."* — announced **November 2023** [S6]. Deprecated is not removed,
   and it still ships in Windows 11 24H2 and Server 2025, but a Windows
   story built on it is built on a component with no future feature work.
5. **The premise that WinFsp costs cgo is wrong.** `winfsp/cgofuse` has a
   **`//go:build !cgo && windows`** implementation that loads
   `winfsp-x64.dll` with `syscall.LoadDLL` after reading
   `HKLM\Software\WinFsp\InstallDir` [S16]. `CGO_ENABLED=0` is *not* the
   argument against WinFsp; a one-time MSI driver install is. See
   "The alternatives".

**Recommendation.** Build it, read-only, as a **second-class frontend with a
stated limit** — a drive letter for browsing and for files under 47 MiB — and
be explicit in the mount summary about which files in the volume the
redirector will refuse. Ship `pelfs windows-setup` (one UAC prompt, raises
`FileSizeLimitInBytes` to 4 GB, restarts `WebClient`) as the documented way
to make large files work, and keep WinFsp on the shelf as the escape hatch if
the redirector's other limits (below) turn out to bite as hard as this one.
The macOS answer stays NFS: `mount_webdav` is worth having as a *second test
client*, not as a second mount path.

---

## The evidence

Every row is either from Microsoft or marked. `[S#]` keys the source list at
the end.

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | File-size cap | `FileSizeLimitInBytes`, DWORD, **default 50,000,000 decimal (50 MB)**, "the maximum size in bytes that the WebClient service allows for **file transfers**" — so both directions. Max settable 0xFFFFFFFF (4 GB). Requires WebClient restart. | [S1] (MS, IIS docs, updated 2025-12-20), [S2] (archived MSDN) |
| 2 | Where it lives, who may change it | `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Parameters`; changes take effect only after `net stop webclient && net start webclient` or a reboot. HKLM writes and service control are **administrator**. No documented HKCU or per-user override. | [S1][S3] |
| 3 | Does it apply to reads | Yes. Microsoft's own KB for the read direction is titled *"Folder copy error message when **downloading** a file that is larger than 50000000 bytes from a Web folder"* (KB 900900), and the `Can't access WebDAV Web folder` article links to it by that title. | [S3] (links KB 900900) |
| 4 | What the user sees | `0x800700DF` — *"The file size exceeds the limit allowed and cannot be saved"*. Reported on Windows 10 and 11 to this day. Community sources only; Microsoft names the registry value, not the modern error string. | [S4] |
| 5 | The **other** cap, nearly as bad | `FileAttributesLimitInBytes`, DWORD, **default 1,000,000 (1 MB)** — "the maximum collective size of all file attributes in one folder … covers all the PROPFIND and PROPPATCH responses". Microsoft: with the default, *"Windows will enumerate a maximum of approximately 1,000 files in one folder"*. Symptoms: `error 31 = ERROR_GEN_FAILURE`, *"Disk is not formatted"*, `File Not Found`, plus ~20 MB of svchost growth per 20,000 files, not released until reboot. Also HKLM. | [S3] |
| 5b | The lever on row 5 | Microsoft: *"By default, the WebClient service does not ask for specific WebDAV properties. Therefore, the server returns all file attributes."* A lean `allprop` response is the server-side mitigation — see "Performance". | [S3] |
| 6 | Basic auth over plain HTTP | Refused by default: `BasicAuthLevel` default **1** = "Basic authentication is enabled for **SSL web sites only**". `2` enables non-SSL — HKLM again, and Microsoft calls it *"strongly discouraged"*. Using Basic over HTTP is listed as a cause of `System error 67 — The network name cannot be found`. | [S1] |
| 7 | Digest over plain HTTP | Supported. WinHTTP's scheme table lists Basic, **Digest**, NTLM, Passport, Negotiate; nothing restricts Digest to TLS (the restriction exists for Basic because Basic sends the password). Practitioner corroboration: *"HTTP Digest is support across the board"*. **The owner's instinct is right: Digest is the baseline.** | [S7] (MS WinHTTP), [S8] (sabre/dav) |
| 8 | Which digest algorithms | **UNVERIFIED.** Microsoft documents the *scheme*, never the algorithm. Assume MD5 and MD5-sess; assume RFC 7616 SHA-256 is **not** implemented (curl needed explicit work for SHA-256 on Windows, and no Microsoft document mentions it). Settled in one CI run: offer both `SHA-256` and `MD5` challenges and log which one the redirector answers. | [S7], gap |
| 9 | A stronger scheme than MD5 | Not viable on loopback. NTLM and Negotiate would require pelfs to *be* an NTLM/Kerberos acceptor holding a machine or domain credential; Negotiate to `127.0.0.1` would try Kerberos against the local machine SPN; and **NTLM itself is deprecated** (announced June 2024, NTLMv1 removed in 24H2 / Server 2025). Loopback Digest with a random per-session credential is the right trade; over `127.0.0.1` the MD5 weakness is not the threat model. | [S6] (NTLM row), [S7] |
| 10 | WebClient presence and start type | Installed by default on **workstation** editions; **not** installed on Windows Server, which needs the *Desktop Experience* feature and a reboot. Start type `Manual (Trigger Start)`, and per Microsoft's deprecation note it *"isn't started by default"*. | [S1] (Server), [S6], [S11] |
| 11 | Can a standard user start it | **Yes** — *"This service is installed by default on workstation versions of Windows and can be triggered to start from a local standard user context."* The whole WebDAV-coercion attack class depends on this, which is unusually good evidence that it works on stock machines. | [S11], [S12] |
| 12 | Mount syntax | `NET USE * http://www.example.com` is Microsoft's own example. The UNC form is `\\server@port\DavWWWRoot\path\`, with `@SSL@port` for TLS; `DavWWWRoot` names the server root. **Non-standard ports work** via `@port`. | [S1], [S8b] |
| 13 | Password not on a command line | `WNetAddConnection2W(lpNetResource, lpPassword, lpUserName, dwFlags)` takes the password as a parameter — no argv, no environment, callable from Go with `syscall.NewLazyDLL("mpr.dll")` and no new dependency. `CONNECT_TEMPORARY` (0x4) keeps the mapping out of the logon profile; `WNetCancelConnection2` removes it. | [S13] |
| 14 | Does the drive survive the launching process exiting | Yes — drive letters are **per logon session**, not per process: "the WNet functions create and delete network drive letters in the MS-DOS device namespace associated with a **logon session**". Corollary worth designing for: a mapping made under one logon is **invisible** to another logon of the same user. | [S13] |
| 15 | Unmounting reliably | `WNetCancelConnection2(name, 0, TRUE)` (or `net use X: /delete /y`). The mapping outlives the server process, so teardown must be explicit and must also run on the crash path — the same problem `pelfs umount` already solves for FUSE. | [S13] |
| 16 | `DAV: 1,2` and `MS-Author-Via` | `x/net/webdav` already sends both: `handleOptions` sets `DAV: 1, 2` and `MS-Author-Via: DAV` (module cache, `webdav/webdav.go`). `SupportLocking` defaults to **1**, so the redirector will LOCK before writing; `webdav.NewMemLS()` satisfies it. | [S1], x/net source |
| 17 | Range reads | `handleGetHeadPost` serves through `http.ServeContent`, so `Range`/`If-Range`/206 are handled. Whether the redirector ever *uses* them is row 18. | x/net source |
| 18 | Whole-file caching | The redirector downloads the whole file to a local cache on open, and uploads the whole file on close; even a preview or a property read pulls the file through that cache. **Community-sourced, not Microsoft-documented** — and load-bearing, so it is first on the CI list. | [S9], [S10] |
| 19 | `Expect: 100-continue` | Free. Go's `net/http` server writes `HTTP/1.1 100 Continue` on first body read (`net/http/server.go`, `expectContinueReader`). | Go source |
| 20 | Timestamps: the `Win32*` properties | The redirector PROPPATCHes `Win32CreationTime`, `Win32LastAccessTime`, `Win32LastModifiedTime`, `Win32FileAttributes` in the `urn:schemas-microsoft-com:` namespace. `x/net/webdav` stores dead properties only if the `File` implements `DeadPropsHolder`, and `prop.go`'s `patch()` calls `fs.OpenFile(ctx, name, os.O_RDWR, 0)` — **which is exactly golang/go#43929, still open**: the redirector PROPPATCHes *directories* and the open fails. An adapter must accept `O_RDWR` on a directory. | [S14], [S15], x/net source |
| 21 | Case collisions | Microsoft warns about precisely pelfs's situation: *"The windows file system is case insensitive, Linux is case sensitive. … it's possible to have multiple versions of a file with the same name but differing by case. This can lead to **overwritten data** and errors like 'File Not Found'"*, and advises *"Use unique file names, never differ file names by case."* Separately, the redirector has been observed **capitalizing the first path segment** of its own requests. | [S1], [S17] |
| 22 | Names Windows cannot hold | Reserved: `< > : " / \ | ? *`, bytes 1–31, NUL. Reserved device names `CON PRN AUX NUL COM1-9 LPT1-9` (and the ISO-8859-1 superscript variants `COM¹`), *including* with an extension — `NUL.tar.gz` is `NUL`. *"Do not end a file or directory name with a space or a period."* | [S18] |
| 23 | Path length | `MAX_PATH` = 260 before Windows 10 1607; after, removing it needs a registry key **or** Group Policy **plus** a per-app manifest opt-in. `WNetAddConnection2`'s own `lpRemoteName` is capped at `MAX_PATH`. Practitioner report: when a path exceeds the limit *"Windows does not display any files or folders within that path"*. | [S18], [S13], [S19] |
| 24 | A loopback SMB server instead | **Dead end, and decisively.** Windows' kernel-mode server owns port 445: *"Windows automatically captures port 445 — you cannot even bind port 445 on 127.0.0.X or create another adapter and bind that port."* Freeing it means disabling `LanmanServer` and rebooting (administrator), and the SMB **client** does not support an alternate port at all. This is the strongest argument for WebDAV: it is the only mount protocol on Windows that a userspace program can serve without touching the kernel's turf. | [S20], [S21] |
| 25 | Timeouts | `LocalServerTimeoutInSec` **15** (connect, local server), `SendReceiveTimeoutInSec` **60** (after issuing a request, e.g. `GET /file.ext`). Both HKLM. The second is a hard ceiling on a single whole-file GET — see "Performance". | [S1] |
| 26 | GitHub Actions can test this | `windows-latest` runners *"are configured to run as administrators with UAC disabled"*. Good news for exercising the raised-registry path; **bad news for proving the no-admin path**, which CI cannot faithfully reproduce and must instead *assert* by reading the registry value back before the test. | [S22] |

### The Go half is already compliant

`golang.org/x/net v0.56.0` is **already in the module graph** (`go.mod:116`,
as `// indirect`), the `webdav` package is pure Go, and it is present in the
module cache with `FileSystem`, `File`, `Dir`, `NewMemFS`, `NewMemLS`,
`DeadPropsHolder` and `Handler`. Using it promotes an existing indirect
requirement to direct — **no new module, no new licence, no cgo.** (`go.mod`
is owned by another session; the change is one line and the version does not
move.)

Measured, `scripts/webdav-litmus-docker.sh`, 2026-08-23, litmus 0.13 against
`x/net/webdav`'s own `litmus_test_server.go` (memFS + memLS), no pelfs code:

| suite | result |
|---|---|
| `basic` | 16/16 — **100.0%** |
| `copymove` | 13/13 — **100.0%** |
| `props` | 30/30 — **100.0%** |
| `locks` | 32/34 — 94.1% (`lock_shared`: LOCK → 501; `fail_complex_cond_put`) |

Both `locks` failures are upstream and neither is on the path this design
needs: `memLS` implements exclusive locks only, and the redirector takes an
exclusive lock to write. **That table is the ceiling for a pelfs WebDAV
frontend and the floor a pelfs adapter must not fall below** — a new failure
in `basic`, `copymove` or `props` after substituting the pelfs filesystem is
the adapter's fault, and finding it costs one script run.

---

## Where the volume meets the namespace: a policy per hazard

pelfs volumes are written on Linux. The table is the recommendation, not a
menu; the reasoning is under it where it is not obvious.

| hazard | recommended policy | why not the alternative |
|---|---|---|
| reserved characters `< > : " \| ? *`, bytes 1–31 | **Reversibly remap to the private-use plane: byte `C` → `U+F000+C`**, the Samba/Cygwin convention. Applies on the way out; decode on the way in. | Hiding them loses data with no signal. Percent-encoding does not survive: the wire is already URL-encoded, so `%3A` decodes back to `:` and Windows rejects the *name*, not the URL. |
| `%` in a name | Same remap, **pending verification** — one practitioner source says the mini-redirector cannot handle `%` at all [S8b]. If confirmed, `%` joins the table; if not, leave it alone. | Remapping `%` unconditionally makes a legal, common filename unrecognisable for no proven reason. |
| reserved device names (`CON`, `NUL`, `COM1`, `NUL.tar.gz`, `COM¹`) | Remap the **last character** of the stem the same way (`NUL` → `NU` + `U+F04C`). Log a count. | Prefixing or suffixing (`NUL_`) collides with a real file called `NUL_`; the private-use range cannot collide with a POSIX name. |
| trailing `.` or ` ` | Remap the trailing character (`U+F02E`, `U+F020`). This is what Samba does. | Trimming creates collisions (`a.` and `a` become one name). |
| **case-insensitive collisions** | **Shadow, do not rename.** In each directory, if two entries fold to the same name, expose the lexicographically first and hide the rest; count them in `pelfs ctl stats` and name the first few in the mount summary. | Windows would otherwise *silently overwrite one with the other* — Microsoft's own warning, row 21. Disambiguating suffixes (`file~2.txt`) invent names that do not exist in the volume and break any write-back. |
| `MAX_PATH` | **Do not truncate or hide.** Serve the tree; report, at mount, how many paths exceed `260 - len("X:\\")`. Suggest mounting a subtree instead. | Hiding deep files makes a volume look corrupt. The long-path opt-in is HKLM *and* a per-app manifest — not something a mount can arrange. |
| **symlinks** (23 in one directory of the owner's own tree) | **Follow within the volume; hide when the target is missing or escapes the volume; count both.** WebDAV has no symlink concept, and the read-only milestone has no write-back ambiguity to worry about. | Exposing them as 0-byte files makes an image tree unusable — every `lib -> lib64` becomes an empty file. Hiding all of them loses the working majority. |
| **hard links** (`nlink > 1`) | **Expose every name; change nothing; report the count.** Each name is an independent file to the client. Copying the tree off the drive duplicates the bytes; a write through one name is visible through the other, because they are one inode — correct, and surprising. Document it. | Synthesizing a Windows hardlink is impossible over WebDAV, and picking one name to expose silently drops files that exist. |
| POSIX mode bits | **Evaluate exactly as the NFS frontend does** — `internal/fsperm` against `fsperm.ProcessCred()`, the reasoning in `docs/go-nfs-patches.md` transferring verbatim: the export is loopback and single-user, the client presents no credential worth trusting, and the check buys **fidelity across frontends**, not access control. Then **project** the result: `Win32FileAttributes` with `FILE_ATTRIBUTE_READONLY` (0x1) when the process would be denied write, `FILE_ATTRIBUTE_DIRECTORY` (0x10), and `FILE_ATTRIBUTE_HIDDEN` (0x2) for dotfiles. | Skipping the check makes a third frontend answer `test -w` differently from the other two — the exact defect `internal/fsperm` exists to prevent. Skipping the projection leaves Explorer showing a read-only volume as writable and then failing at PUT. |
| mtime preservation | **Implement `DeadPropsHolder`** and translate `Win32LastModifiedTime` → `vfsbilly.Chtimes` (it already exists), `Win32FileAttributes` read-only bit → chmod, and **accept `OpenFile(O_RDWR)` on a directory** so PROPPATCH on a folder does not 500 (golang/go#43929). | Without this a `tar`- or `robocopy`-shaped workflow loses every timestamp, which is the failure mode the owner named. `x/net/webdav` emits only its 10 `DAV:` live props, so `Win32FileAttributes` must come from `DeadProps()` too. |
| xattrs, sockets, devices, fifos | Omit from listings; count them. | Nothing in the Windows namespace corresponds, and a client that stats them gets a type it cannot render. |

One cross-cutting rule: **every mapping is reversible and every omission is
counted.** A read-only milestone can afford a lossy view; a write path cannot,
and the mapping is the part that would have to be right before writes turn on.

---

## Performance: the redirector inverts pelfs's amplification story

Reusing the measurements in `docs/design-apptainer.md` — no new
measurement, and the numbers there are for the same 68,497,408-byte SIF:

| workload shape | pelfs behaviour (measured, apptainer doc) | what the redirector does to it |
|---|---|---|
| scattered 4–128 KiB reads, cold | **8.7x** on origin bytes, ~11x on decode; 22 MiB moved to run a container | **cannot happen through a drive letter.** The redirector reads whole files [S9][S10], so the small-read pattern never reaches the server |
| whole-file read, cold | **1.04x** — 71,537,741 origin bytes for a 68 MB file | **this is the only shape the drive letter has.** Every open of the SIF is this row |
| whole-file read, warm packs | **0 origin bytes** | same, and the redirector then caches locally too — a second open is free twice over |

So the amplification worry is the wrong worry here, and it is replaced by a
worse one: **the redirector makes every open cost the whole file.** A 4 KB
`head` of a 68 MB image moves 68 MB of local cache and ~71.5 MB from the
origin. On pelfs's side that is nearly optimal (1.04x); on the user's side it
is a 68 MB stall at open. Together with `FileSizeLimitInBytes` this is the
verdict: for files over ~47 MiB the drive letter does not merely go slow, it
**refuses**, and prefetching a file the client will not accept is beside the
point.

What that implies for configuration:

- **`SendReceiveTimeoutInSec` = 60 is a hard deadline on one file.** The
  whole-file GET must complete inside it. 68 MB in 60 s is ~1.1 MB/s — fine
  on a warm pack cache, marginal on a cold fetch over a slow federation
  link. **On a slow link, `--prefetch` before mapping the drive stops being
  an optimisation and becomes a correctness requirement.** `--prefetch all`
  fetches the whole generation (work item **W3** in the apptainer doc — a
  path argument — is worth more here than it was there).
- **Arena sizing barely matters.** Whole-file reads converge on 1.04x with
  505 arena hits against 24 misses; the arena is already doing its job for
  this access pattern.
- **Keep PROPFIND responses lean** (row 5/5b). `x/net/webdav`'s `allprop` is
  10 `DAV:` properties, which is already far leaner than the verbose servers
  Microsoft's ~1,000-file estimate assumed — the per-entry cost should be
  measured off the probe server and reported here rather than guessed. Adding
  `Win32*` dead properties to every entry spends part of that 1 MB budget, so
  emit them on PROPPATCH round-trips, not gratuitously in listings.
- **Expect a 401 per connection.** WinHTTP cannot pre-authenticate Digest
  (*"Digest — never possible"* [S7]), so the first request on each connection
  pays a challenge. Keep-alive and a stable nonce keep that from being
  per-request; whether it *is* per-request is a CI measurement.

---

## The alternatives, stated fairly

**WinFsp (or Dokany): real filesystem semantics, one admin install.** This is
the option that actually fixes the problems above — no 50 MB cap, no 1 MB
directory cap, real sparse/partial reads, real timestamps, no deprecated
service. The stated objection was cgo, and **that objection is wrong**:
`winfsp/cgofuse` ships `host_nocgo_windows.go` under
`//go:build !cgo && windows`, loading `winfsp-x64.dll` through
`syscall.LoadDLL` after reading `HKLM\Software\WinFsp\InstallDir` [S16], so
`CGO_ENABLED=0` — the project's whole build story (`Makefile:8`,
`.github/workflows/ci.yml:410`) — is preserved. The real costs are: a signed
kernel driver the user must install once with administrator rights; a new
direct dependency; and a **third frontend implementation**, because
`internal/rawfuse` is written against go-fuse's raw protocol and would not
port — the work would resemble `internal/vfsbilly`'s in size, not a shim's.
Given that the WebDAV path *also* needs an administrator for the file-size
cap, the honest comparison is "one admin step for a limited mount" versus
"one admin step for a real one", and it is closer than it looks. The reason
to do WebDAV first is that it is a few hundred lines over an interface pelfs
already satisfies, and it doubles as the macOS test client.

**Loopback SMB: not possible.** Row 24. The kernel owns 445 on every
interface including loopback, freeing it needs a service disable plus reboot,
and the SMB client cannot be pointed at another port. If it *were* possible
it would be the better answer; it is not, and that is the cleanest argument
for WebDAV in this document.

**Plain HTTP and no mount at all.** A `pelfs get` verb (work item **W5** in
the apptainer doc) plus the existing loopback HTTP surface gives a Windows
user the bytes with no redirector, no cap and no service — for the workflow
"fetch this image, then run it" that is strictly better than a drive letter.
Worth saying out loud before writing any of the above: **the 68 MB SIF case
is better served by `pelfs get` than by any mount.**

---

## Testing strategy

Four layers, cheapest first. Three of them need no Windows at all.

1. **`httptest`, no client.** The adapter and the digest handshake are
   ordinary Go units: construct the `webdav.Handler`, drive it with
   `httptest.NewServer` and a hand-built `Authorization` header, assert the
   nonce/qop/`nc` handling and a canned MS-shaped PROPPATCH body
   (`Win32LastModifiedTime` on a **directory**, which is the golang#43929
   shape). This is where the name-mapping table gets its test matrix — one
   case per row, both directions.
2. **`litmus` in Docker as a gate.** `scripts/webdav-litmus-docker.sh` exists
   and is measured. Point it at the pelfs adapter instead of `memFS` and the
   baseline table above becomes a regression test. Cheap enough for every PR;
   the two known `locks` failures are the documented baseline.
3. **macOS `mount_webdav` as a second, independent client.** Worth as much as
   litmus and for a different reason: it exercises paths the Windows client
   hides, and vice versa. **Mount under `/Volumes` or a scratch directory —
   nothing under `$HOME`, ever.** That is a standing rule from the owner and
   not a preference: no test tree, mountpoint or artifact goes in his home
   directory, and a harness that defaults to `~/mnt` is wrong even if it
   passes. Expect macOS to write
   `.DS_Store` and `._*` files, so the read-only milestone must refuse them
   with 403 and not 500.
4. **A `windows-latest` CI job driving `net use` end to end.** This is the
   only layer that needs Windows, and it must run **twice**: once with
   `FileSizeLimitInBytes` at its default (asserting that a 60 MB file
   *fails*, and that the failure is reported by pelfs as a diagnosable
   condition rather than a hang) and once with it raised (asserting the same
   file reads byte-for-byte). The runner is administrator with UAC disabled
   [S22], so the job must **read the registry value back and log it** — a
   green run whose default-configuration half silently ran against a raised
   limit proves nothing. The same job answers most of the unverified list
   below at once by capturing the request log: which auth scheme and digest
   algorithm the redirector picks, how many requests one open costs, whether
   a partial read pulls the whole file, and whether the drive survives the
   server process exiting.

---

## Ranked work items

| | change | buys | effort | unblocks |
|---|---|---|---|---|
| **D1** | `internal/vfsdav`: a `webdav.FileSystem` + `File` over `internal/vfsbilly` (read-only), with `fsperm` applied as the NFS frontend applies it | the whole idea; a `webdav.Handler` that serves a pelfs volume | small — `billy.Filesystem` and `webdav.FileSystem` are nearly the same interface; `Stat`/`OpenFile`/`Readdir`/`Rename`/`RemoveAll` all exist already | everything below |
| **D2** | `--backend webdav` in `cmd/pelfs`: bind `127.0.0.1:0`, generate a per-session digest credential, serve, and tear down with the mount | a mount that works on macOS today and can be driven by litmus | moderate; `runMountGen` already has the backend switch (`cmd/pelfs/mountgen.go:739`) and the teardown discipline | D3, D5, and the macOS second client |
| **D3** | Windows attach/detach: `WNetAddConnection2W` / `WNetCancelConnection2W` via `mpr.dll` (`CONNECT_TEMPORARY`), password never on argv | the drive letter itself, with no admin | small, but Windows-only code with no local way to test it | the deliverable |
| **D4** | The name-mapping layer (reserved chars, device names, trailing dot/space, case shadowing) with counters in the mount summary and `pelfs ctl stats` | a Linux-written volume that does not silently lose or overwrite files on Windows | moderate; the policy table above is the spec, and it is unit-testable with no client | trust in the view; a future write path |
| **D5** | litmus wired into CI against the pelfs adapter (script exists) | the baseline table becomes a gate | hours | catching adapter regressions before a client does |
| **D6** | `DeadPropsHolder` + `Win32*` properties, incl. `O_RDWR` on directories | timestamps survive; `tar`-shaped workflows work; Explorer shows truthful read-only/hidden bits | moderate | write path; anything that cares about mtime |
| **D7** | `pelfs windows-setup` — one elevated step that raises `FileSizeLimitInBytes` and restarts `WebClient`, plus a **startup check that reads the value and names the files in the volume that exceed it** | the 68 MB SIF; and, more valuable, an honest error instead of `0x800700DF` | small | the owner's actual payload |
| **D8** | The `windows-latest` CI job, both registry configurations | every unverified row below | moderate; it is the only place the answers exist | the confidence to call this supported |
| **D9** | Write path: PUT/MKCOL/DELETE/MOVE/LOCK, and the mapping made lossless | a writable drive letter | real — and it wants D4 and D6 finished first | not on the critical path for the stated use case |
| **D10** | WinFsp frontend (no cgo needed — [S16]) | real filesystem semantics: no 50 MB cap, no 1 MB directory cap, real partial reads | large: a third frontend, plus a driver install | the escape hatch if D7's admin step is unacceptable anyway |

## Recommended minimal first milestone

**A read-only WebDAV export, mounted as a drive letter, for files under
47 MiB — D1, D2, D3, D5.** Concretely, what a person could use:

```
pelfs mount --ro --backend webdav pelican://<federation>/<prefix> W:
... browse W:, read files, copy small ones off ...
pelfs umount W:
```

and on macOS, the same server behind `mount_webdav` into a scratch
mountpoint, purely so the server gets a second client's opinion before a
Windows user ever sees it.

What it deliberately does **not** do: write, preserve timestamps, remap
illegal names (it hides them and says how many), or open a 68 MB SIF. The
mount summary must say all four in one sentence, and must name the count of
files the redirector will refuse — a user who learns about
`FileSizeLimitInBytes` from `0x800700DF` will conclude pelfs is broken.

---

## What cannot be verified without a Windows machine

Listed in the order they would break the plan. Every one is answered by the
CI job in D8; none is answered by more reading.

1. **Whether the redirector accepts Digest over plain HTTP to `127.0.0.1`
   at all.** Everything rests on this. Microsoft documents that *Basic* is
   TLS-gated and documents Digest as a supported scheme, but no Microsoft
   document says "Digest over HTTP to a loopback address is accepted".
2. **Which digest algorithm** it will answer (MD5 / MD5-sess / SHA-256), and
   whether it requires `qop=auth`.
3. **Whether a partial read of a large file really pulls the whole file** —
   and therefore whether the 50 MB refusal fires on a 4 KB read of a 68 MB
   file. Row 18 is the only load-bearing claim in this document with no
   Microsoft source.
4. **Whether `System error 224`** (the *"add the web site to your trusted
   sites list"* path, [S1]) fires for loopback HTTP with Digest. If it does,
   the zone list is per-user in Internet Options — probably fixable without
   admin, but that is a guess.
5. **Whether the trigger start actually fires** for
   `\\127.0.0.1@PORT\DavWWWRoot\` as a standard user on a freshly booted
   stock machine, and what the failure looks like if `WebClient` is disabled
   by policy (many enterprises disable it precisely because of [S12]).
6. **How many entries a directory can hold** with `x/net/webdav`'s lean
   `allprop` before the 1 MB attribute cap bites. Microsoft's ~1,000 assumed
   a chattier server; the real number needs measuring on both sides.
7. **How many HTTP requests one file open costs**, and whether the 401
   challenge is per connection or per request.
8. **Whether the mapping survives the server process exiting** in practice
   (the API says logon-session scope; the redirector's own behaviour when the
   server disappears is untested), and whether `WNetCancelConnection2`
   reliably tears down a drive whose server is already gone.
9. **Whether Explorer sends `Win32LastModifiedTime`** on an ordinary copy-in,
   or only Office does.
10. **`%`, non-ASCII names, and deep paths** — the practitioner claims in
    rows 22/23 and the `%` note need one directory of adversarial names and
    one listing to settle.

---

## Sources

- **[S1]** Microsoft, *Using the WebDAV Redirector* (IIS docs; page updated
  2025-12-20) — the registry table (`FileSizeLimitInBytes`,
  `FileAttributesLimitInBytes`, `BasicAuthLevel`, timeouts, `SupportLocking`),
  the Server *Desktop Experience* requirement, `NET USE`, the `System error`
  list, and the case-sensitivity warning.
  <https://learn.microsoft.com/en-us/iis/publish/using-webdav/using-the-webdav-redirector>
- **[S2]** Microsoft (archived MSDN blog), *WebDAV Redirector Registry
  Settings* — the same table, earliest published form.
  <https://learn.microsoft.com/en-us/archive/blogs/robert_mcmurray/webdav-redirector-registry-settings>
- **[S3]** Microsoft, *Can't access WebDAV Web folder* (KB 912152) —
  `FileAttributesLimitInBytes`, the ~1,000-file consequence, the error
  strings, the svchost leak, and the link to KB 900900 by title.
  <https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/cannot-access-webdav-web-folder>
- **[S4]** Community reports of `0x800700DF` on Windows 10/11 (wintips.org,
  appuals, MyWorkDrive) — the modern error string and that the default is
  still 50 MB. Not primary.
- **[S6]** Microsoft, *Deprecated features in the Windows client* — the
  *"Webclient (WebDAV) Service"* row (November 2023) and the NTLM row
  (June 2024).
  <https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features>
- **[S7]** Microsoft, *Authentication in WinHTTP* — the scheme table
  (Basic/Digest/NTLM/Passport/Negotiate) and *"Digest — never possible"* for
  pre-authentication.
  <https://learn.microsoft.com/en-us/windows/win32/winhttp/authentication-in-winhttp>
- **[S8]** sabre/dav, *Windows client notes* — *"HTTP Digest is support
  across the board"*, `MS-Author-Via`, the malformed `Lock-Token` in UNLOCK,
  the `Win32*` properties. Practitioner, not primary.
  <https://sabre.io/dav/clients/windows/>
- **[S8b]** IT Hit, *Connecting to WebDAV server on Microsoft Windows* — the
  `\\server@SSL@port\DavWWWRoot\` syntax and the `%`-in-filename claim.
  <https://www.webdavsystem.com/server/access/windows/>
- **[S9]** Files.com, *WebDAV issues on Windows-based systems* — 50 MB
  download limit, `MAX_PATH`, credential-persistence notes.
  <https://www.files.com/docs/services/webdav/troubleshooting-webdav/issues-on-windows-based-systems>
- **[S10]** C. Andrews, *Performance testing WebDAV clients* — the request
  shape (PROPFIND+GET per download; PROPFIND/PROPPATCH/PUT plus LOCK/UNLOCK
  per upload) and the redirector being the slowest client tested.
  <https://candrews.integralblue.com/2019/03/performance-testing-webdav-clients/>
- **[S11]** Misconfiguration-Manager, PREVENT-11 — *"installed by default on
  workstation versions of Windows and can be triggered to start from a local
  standard user context"*; Server editions do not have it.
  <https://github.com/subat0mik/Misconfiguration-Manager/blob/main/defense-techniques/PREVENT/PREVENT-11/prevent-11_description.md>
- **[S12]** The Hacker Recipes, *WebClient abuse (WebDAV)* — the
  `\\SERVER@PORT\PATH` trigger form and that starting the service needs no
  elevation on Windows 10/11.
  <https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient>
- **[S13]** Microsoft, *WNetAddConnection2W* — parameters, `CONNECT_*` flags,
  and the logon-session scope of drive letters.
  <https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w>
- **[S14]** golang/go issue 43929, *x/net/webdav: microsoft miniredirector
  fails setting properties of directories* — open, `NeedsDecision`.
  <https://github.com/golang/go/issues/43929>
- **[S15]** rclone issue 5171, *optional support for Win32LastModifiedTime* —
  the property names and namespace as clients send them.
  <https://github.com/rclone/rclone/issues/5171>
- **[S16]** `winfsp/cgofuse`, `fuse/host_nocgo_windows.go` —
  `//go:build !cgo && windows`, `syscall.LoadDLL("winfsp-x64.dll")`,
  `HKLM\Software\WinFsp\InstallDir`.
  <https://github.com/winfsp/cgofuse/blob/master/fuse/host_nocgo_windows.go>
- **[S17]** Microsoft Q&A, *WebDAV redirector makes strange requests in
  Windows 10* — path capitalization, and requests issued under machine
  credentials alongside the user's.
  <https://learn.microsoft.com/en-us/answers/questions/1275064/webdav-redirector-makes-strange-requests-in-window>
- **[S18]** Microsoft, *Naming Files, Paths, and Namespaces* — reserved
  characters, device names (incl. `COM¹`), trailing dot/space, `MAX_PATH`,
  *"Do not assume case sensitivity"*.
  <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>
- **[S19]** Microsoft, *Maximum Path Length Limitation* — the 1607 change and
  the registry + manifest opt-in.
  <https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation>
- **[S20]** `jjkeijser/cifs-over-ssh`, Windows 10 loopback notes — *"Windows
  automatically captures port 445 — you cannot even bind port 445 on
  127.0.0.X"*; freeing it needs `LanmanServer` disabled and a reboot.
  <https://github.com/jjkeijser/cifs-over-ssh/blob/main/Win10/Singlehost.md>
- **[S21]** Microsoft Q&A, *How to access SMB share from Windows on a
  different port number* — the SMB client does not support alternate ports.
  <https://learn.microsoft.com/en-us/answers/questions/908346/how-to-access-smb-share-from-windows-on-a-differen>
- **[S22]** `actions/runner-images` discussion 6557 — hosted Windows runners
  *"are configured to run as administrators with UAC disabled"*.
  <https://github.com/actions/runner-images/discussions/6557>
- **litmus** — WebDAV protocol compliance suite; default suites
  `basic copymove props locks`, `X-Litmus` header per request.
  <http://www.webdav.org/neon/litmus/>
