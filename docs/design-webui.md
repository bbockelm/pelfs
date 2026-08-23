# A browser UI for pelfs: what it takes, and what it exposes

Status: **BUILT.** This began as a design written before any pelfs code
existed. It is now a description of what shipped, reconciled against the
tree at `b037b03` by docsync-agent and re-checked at `b16784d` by
mount-app-agent, the pass that put the file manager on the route table and
gave the two surfaces their addresses (`/` and `/connect`). `pelfs browse` is
a verb a person can run: `cmd/pelfs/browse.go` plus `internal/httpguard`,
`internal/browsesession`, `internal/webapi`, `internal/vfsdav`,
`internal/localoauth`, `internal/davprofile`, `internal/webui` and
`webui/frontend`.

**Where the implementation contradicted the design, the code won and this
document changed.** Every such place is named once in "Where this document
was wrong", immediately after the verdict, and then corrected in its own
section in the document's own voice — so a reader who lands mid-document
is never reading a plan that was overtaken. Nothing below is a proposal
unless it says so.

The four verifications that preceded the code stand, and **three of the
four came back different from the assumption** — the licence, the data
protocol, and the Cyberduck OAuth question, which turned out to be a yes.
Every browser-platform claim in the threat model is still cited to a spec,
a browser's own release note, or the source of the library that implements
it. What "could not be verified" has shrunk a great deal: the U0 component
probe and a container running **real Cyberduck (duck 9.5.3)** closed most
of it. What survives is at the end, each with the experiment that closes
it.

This document is a **companion** to `docs/design-guiclients.md`, not a
replacement. That document's verdict — export SFTP first, because it is
the only protocol every free Windows GUI client already speaks — is not
re-argued and is not overturned here. What changes is the cost of its
second-place item: a browser UI needs an HTTP listener, an auth story and
a durability panel anyway, and once those exist, WebDAV on the same
listener is nearly free. Its client matrix, its SFTP measurements, its
`x-amz-meta-mtime` finding and its S3 rejection all stand unmodified.

It also **supersedes one paragraph of its own predecessor**: the section
"The browser UI, assessed" in `docs/design-guiclients.md` concluded "build
the landing page, not a file manager", on the grounds that a browser UI is
a UI and the GUI clients already have one. That reasoning is still
correct about *cost*. What it did not have was the licence answer for the
component that removes most of that cost, and it got one mechanism wrong:
it says seal-on-idle "cannot" be expressed over HTTP because "the client
went away" is indistinguishable from "the user is reading". A single-page
app holding an SSE stream open makes that distinguishable, and better than
SFTP does. Both corrections are below, in their sections.

---

## Verdict

**Build it, in the order M1 → M2 → M3, and make M1 need no JavaScript
toolchain at all.** The proposal survives verification largely intact.
Four corrections, in descending order of how much each changes the plan:

1. **SVAR File Manager for React is MIT, not GPLv3.** The GPL belief is
   real but stale: it describes the retired `wx-*` package generation.
   The current `@svar-ui/*` generation is MIT throughout — verified
   package by package across all eleven packages, the component plus its
   complete `dependencies` list [W1]. There is no licence conflict with
   pelfs's Apache-2.0, and no alternative component needs to be found. The one hard rule this
   produces: **pin `@svar-ui/*` and never `wx-*`**, because the `wx-*`
   packages *are* GPLv3 and one of them is still on npm [W2].
2. **The component does not speak WebDAV.** It is REST-driven over a
   supplied data provider whose wire protocol is a fixed set of eleven
   route patterns [W3][W4]. So the honest architecture is **two HTTP
   surfaces over one filesystem layer**, and the document says which owes what to which
   rather than pretending one protocol serves both. This is the largest
   structural change to the proposal, and it is an improvement: the JSON
   surface is where resumable upload, upload progress and a per-directory
   listing come from, none of which a browser gets from PROPFIND without
   parsing XML by hand.
3. **The browser is not the only thing that must be defended against, and
   `SameSite=Strict` does not defend against the nearest attacker.** Ports
   are not part of a "site", so *another local server on another 127.0.0.1
   port is same-site*, and cookies have **no port isolation at all** —
   RFC 6265bis says so in as many words. So the design **drops the session
   cookie entirely**: the API's credential is a token the app holds in
   `sessionStorage` (which *is* port-scoped) and sends as a request header,
   which makes CSRF structurally impossible rather than merely checked.
   Strict `Host` validation stands behind it — and the check that catches
   a page on another loopback port is **in the Go standard library**:
   `net/http.CrossOriginProtection` (Go 1.25; this repo is `go 1.26.0`)
   rejects `Sec-Fetch-Site: same-site`, which is exactly what that page
   looks like [B22]. The attack-by-attack table is the "Threat model"
   section, and it is the longest section here on purpose.
4. **Vite under `go generate`, with the bundle committed.** SSR buys
   nothing for a localhost SPA served by a Go binary, and this repo has
   already paid once for a Next.js build sitting in a Go build path
   (`24c393c`, `scripts/build-pelican-server.sh`'s header). The frontend
   build runs under `//go:generate`, its output is committed, and
   `//go:embed` serves it — so `go build ./...` needs no Node at all and
   `go install …@latest` still yields a working UI. Both halves of that
   pattern already exist next door: pelican commits
   `web_ui/frontend/out/placeholder` purely to satisfy a non-optional
   `go:embed`, and uses `//go:generate` for its command docs
   (`cmd/main.go:41-42`). CI verifies the committed bundle by regenerating
   it and diffing. Measured, so the tree cost is arguable rather than
   guessed: SVAR and its ten dependencies are **166,892 bytes minified,
   50,143 gzipped** [W5].

Two further answers, stated up front because they are what the owner asked
and because the first of them reshapes M2:

- **Cyberduck *can* do OAuth2 against a plain `dav` endpoint driven purely
  by a downloaded profile**, and it is what the external-client story is
  built on. It shipped in **9.1.3**, the maintainers added it in answer to
  a question identical to this one [W9][W10], and the switch is a non-blank
  `OAuth Client ID` in a `dav` profile — no compiled protocol class, no
  vendor borrowing. The Bearer header reaches the WebDAV backend through
  `OAuth2RequestInterceptor` [W12][W18], and a loopback `OAuth Redirect Url`
  selects the provider that needs nothing installed and no typing [W14].
  What pelfs owes in return is a minimal OAuth2 **authorization server** on
  the same loopback origin — `/oauth/authorize`, `/oauth/token`,
  authorization-code with PKCE `S256`, Bearer acceptance on `/dav/*` — all
  pure Go with no new module. "Verification 2" is the mechanism, read out
  of Cyberduck's source because its documentation does not cover this path;
  "A7" is the threat model that endpoint creates, and it is the reason the
  design requires **one consent click** rather than treating the existing
  browser session as consent.
- **Pelican branding is approved by the project's PI**, so the design uses
  the mark and the palette (`#0885ff` / `#CFE4FF` / `#FFFFFA`,
  `web_ui/frontend/components/ThemeProvider.tsx:34-39`). One correction to
  the brief: the mark **is** in the pelican checkout, at
  `web_ui/frontend/public/static/images/PelicanPlatformLogo_Icon.png` — it
  is a **PNG, and there is no SVG anywhere**, so an SVG has to be drawn or
  obtained. See "Branding".

**And one thing this design refuses to do**, stated in the verdict because
it is the single easiest way to turn a CSRF bug into a catastrophe:
**the web surface is not a proxy for the control socket.** `internal/control`
exposes the *entire* `net/http/pprof` surface — index, cmdline, profile,
symbol, trace — and its package comment says exactly why that is safe:
*"The socket is the auth boundary, so the full pprof surface is safe to
expose"* (`internal/control/control.go:147-150`). A browser session on
127.0.0.1 is a materially weaker boundary than a 0600 unix socket in a
directory that already holds the volume's signing key. So the web surface gets a
hand-written allowlist of three things — publish, session status, dirty
counts — reaching the same in-process functions the socket's hooks reach,
and `/debug/pprof` is never routable from a browser.

---

## Where this document was wrong

Seven implementation passes were run against this design, and each one
reported back the places where the plan did not survive contact. This is
the whole list in one table, so a reader who remembers the original can
find what moved; every row is also corrected in its own section, and the
section is where the argument lives. Nothing here is an apology for the
design — most of it held — but a document that quietly absorbs its own
corrections teaches the next reader to distrust all of it.

| what this document said | what shipped, and why | corrected in |
|---|---|---|
| the threat-model table is **"fifteen assertions"** | it lists **sixteen** rows. `TestThreatModelTable` is those sixteen; `internal/httpguard` ships **39 assertions** in all | Testing, layer 1 |
| **`Origin` absent on `/api/v1` → 403** | **wrong as written, and it would have refused every read the page makes**: a browser sends NO `Origin` on a same-origin GET. Implemented as *provenance* — a matching `Origin` **or** `Sec-Fetch-Site: same-origin` — with 403 for the request carrying neither | A1, control 3 |
| the M1 terminal mock prints `http://127.0.0.1:49731/` | that URL has **no `#bt=` fragment**, so the page it opens has nothing to exchange and the mock's own next line ("paste that URL") is false. The full URL, fragment and all, is printed | Recommended minimal first milestone |
| **`--no-open` is the middle ground** (A3) / **`--open`** is the flag (U3) | those contradict. Shipped: **`--open`, default off**, and the URL is printed either way | A3; U3 |
| `phaseClock` is "what the progress stream should carry" | **it cannot.** `phaseClock` reports at the END of a seal and has no subscription. The stream carries job state and elapsed time instead | "Publish now" must be asynchronous |
| a CSP **nonce** | must be base64**url**. `html/template` escapes `+` in an attribute to `&#43;`, so a standard-alphabet nonce works only by way of entity decoding | A5 |
| `POST /oauth/token` on the API-minus-session surface | **cannot live there.** Cyberduck's back-channel POST sends no `Origin`/`Sec-Fetch-Site` (403 on provenance) and `application/x-www-form-urlencoded` (415 on the JSON rule). `httpguard.SurfaceToken` exists for it | The split; U7 |
| A7 control 2: "an authenticated browser session is required", per request | **cannot be per-request.** A navigation cannot carry `X-Pelfs-Session` and the consent page runs no script. It is a per-process "is anyone signed in" gate; the weight is carried by the per-download `client_id` | A7, control 2 |
| 2e: remember consent **per `client_id`** for the life of the process | **that reinstates the attack control 6 removes** — after one click a navigation could mint codes again. Consent is required on **every** `/authorize`; the no-re-prompt property lives on the **refresh token** | Verification 2e |
| `Vendor` = `org.pelicanplatform.pelfs.local` | two concurrent sessions would collide on one profile identity. The `Vendor` **carries the listener port** | Verification 2f |
| four Cyberduck behaviours "need a live Cyberduck to confirm" | **confirmed on the wire**, duck 9.5.3 (45464), 2026-08-23 | Verification 2g |
| eleven SVAR routes, `{id}` per route | `net/http`'s `{id}` wildcard **does not match a bare `%2F`**, so `POST /api/v1/files/%2F` — create a folder at the root — 404s or falls through to the SPA. **Every id route needs an `{id...}` sibling.** Found independently by two passes | The routes, concretely |
| the cap's numbers ride on the listing response | **they cannot.** The provider requires a bare array and drops response headers, so the numbers travel as `X-Pelfs-Listing-*` headers and as `GET /api/v1/info/{id}` | The routes, concretely |
| `GET /files` (un-pathed) returns the whole tree, so drop it | **not droppable** — the component fetches it at boot. It means the **ROOT directory**, never the tree | Verification 3 |
| — | opening a symlink **by its own path answers `ESTALE`**; resolve first. It bit the copy path and the download source as well as WebDAV | Verification 3; the WebDAV adapter |
| two defects in the shipped SVAR provider | **three, and then a fourth thing that is not the provider's.** `setHeaders()` never reaches the wire; mutations ship as `text/plain` (415); and `send()`'s `.catch` sits AFTER the `!res.ok` throw, so every failure resolves to `undefined`. Overriding `send()` fixes all three and is **not enough**: the STORE applies every mutation optimistically and rolls nothing back, so a refused rename still kept its new name on the screen with the error banner beside it. Closed by re-listing from the server, in `PelfsDataProvider.getHandlers` | Verification 3 |
| "does the component virtualize" is unknown | **it does not.** 100,000 entries measured 1,000,067 DOM nodes and **703 MB** of heap. Search is client-side over loaded data, so a capped listing is a **partial search** — and the user has to be told, in `webapi.PartialSearchNotice`'s exact words | Verification 3 |
| seal on idle after `min(30 s, --snapshot-interval)` | **undefined at interval 0**, which a user types on purpose. Implemented as **off** | The correction: a browser CAN express seal-on-idle |
| `sendBeacon` on `pagehide` shortens the wait | `pagehide` fires **before** the connection tears down, so comparing the two instants naively discards every beacon that worked. `idleHintLead` is the tolerance | same |
| the reordered startup solves the prompt-before-the-page case | **it does not, on its own.** A prompt raised in the second between the browser launching and its stream attaching is caught by **SSE snapshots**, not by the ordering | The ordering problem |
| litmus ceiling `props 30/30` | **29/30.** x/net's example server passes `propfind_invalid2` by hard-coding a 400 (citing golang/go#8068); the unmodified handler answers 207. The adapter holds the honest ceiling | Testing, layer 2 |
| `DeadPropsHolder` is optional | **it is not** — without it every PROPPATCH is 403 | The WebDAV adapter |
| a symlink is followed on `Stat` | it must be followed on **OPEN**. x/net sniffs 512 bytes of unknown-extension files, so a followed link vanished from its own listing | The WebDAV adapter |
| `Mkdir` and `RemoveAll` come free from billy | **they do not.** `MkdirAll` answers 201 where MKCOL requires 409/405, and billy's `Remove` refuses a non-empty directory | The WebDAV adapter |
| the WebDAV handler is a route in the table | **`vfsdav.New` reads write capability at CONSTRUCTION**, and the route table is built before the volume opens. The handler is built at `setReady`, behind a 503 delegator | Wiring |
| — | `--test-hooks`'s synthetic download source sits **ahead of** the real one, so a `--test-hooks` session cannot ticket a real file. Recorded WITH the fix so nobody "fixes" it by reordering | Wiring |
| **no `replace` in `go.mod`** | one shipped, deliberately, pinning PR 3672's head for `SetVerificationURLHandler`, with the drop condition written next to it | The `go.mod` question |

---

## Architecture

```
                          the user's browser
                                   |
   launch:  http://127.0.0.1:PORT/#bt=<32-byte single-use bootstrap token>
                                   |
      +----------------------------v--------------------------------+
      |  pelfs browse            one net/http.Server, 127.0.0.1:0   |
      |                          (tcp4, random port, foreground)    |
      |                                                            |
      |  guard: Host allowlist -> net/http.CrossOriginProtection    |
      |         -> Origin exact-match -> PROVENANCE -> principal     |
      |         (internal/httpguard: nine named surfaces, THREE      |
      |          principals, never interchangeable)                  |
      |                                                            |
      |  A  /               go:embed'd Vite bundle    (no secret)   |
      |     /assets/*                                              |
      |  B  /api/v1/*       first-party JSON API      X-Pelfs-      |
      |                     (SVAR provider contract)  Session: tok  |
      |                     + /api/v1/session, /beacon: body-borne  |
      |  D  /events         SSE: SSO prompts, seal    Session: tok  |
      |                     state, publish job        (in ?s=)      |
      |  E  /d/<ticket>     ticketed download GET     ticket only   |
      |                     (no session token accepted)            |
      |                                                            |
      |  C  /dav/*          x/net/webdav.Handler      Basic OR      |
      |                     via internal/vfsdav       Bearer,       |
      |                     (external clients only)   per-client    |
      |  F  /oauth/authorize  consent page, no script  navigation   |
      |                       (mints nothing on GET)   + a click    |
      |  G  /oauth/token      RFC 6749 back channel    code+PKCE    |
      |                       (NOT the B surface's      or refresh  |
      |                        rules -- see The split)  token      |
      +----------------------------+-------------------------------+
                                   |
                    internal/vfsbilly  (billy.Filesystem)
                    ONE permission model: internal/fsperm
                                   |
              +--------------------+--------------------+
              | overlay.FS  (--rw) |  genfs.FS  (read)  |
              +--------------------+--------------------+
                                   |
                      internal/pelicanobj -> federation
                                   |
                 oauth2.SetVerificationURLHandler  ---> D
```

**F and G are one authorization server split across two surfaces**, and
the split is not cosmetic: F is reached by a browser navigation and can
therefore require no header of ours, while G is reached by a Java HTTP
client that sends no browser signal at all. Putting G on B's rules — which
this document originally did — answers 403 and 415 to every exchange
Cyberduck attempts. See "The split".

Three properties of that picture are load-bearing and worth naming.

**One filesystem layer, two protocol surfaces.** Both B and C go through
`internal/vfsbilly`, which is where `internal/fsperm`'s mode check lives
and where the overlay's crash-safety guarantee is made. Neither surface
may reach around it into `overlay.FS` or `genfs.FS` directly. This is the
same discipline that already lets FUSE and loopback-NFS answer `test -w`
identically (`internal/fsperm`'s package comment: *"One model, three
callers, so that a mode bit means the same thing on all of them"*), and it
is the reason a WebDAV surface costs almost nothing once the listener
exists: `webdav.FileSystem` is five methods
(`Mkdir`/`OpenFile`/`RemoveAll`/`Rename`/`Stat`,
`x/net@v0.56.0/webdav/file.go:40`) and `billyFS` already implements every
one of them under a different name.

**Two principals, never interchangeable — three, once downloads exist.**
The browser session (A, B, D), the external-client credential (C, minted
by F/G) and the download ticket (E) are separate secrets with separate
lifetimes and separate scopes. A session token presented at `/dav/*` is
rejected; a Basic credential presented at `/api/v1/*` is rejected. Two
middlewares, no shared code path, and a test for each of the four
combinations. The reason is not tidiness: the browser surface is
*reachable* by every page the user visits (F2 — being HTTPS is no obstacle),
while the WebDAV credential lives in a client's own keychain and is never
in a browser at all. Merging them would give the exposed surface the
unexposed one's reach.

**The download path is its own surface with its own credential.** E exists
because a `<a href>` download cannot carry a custom header, and a custom
header is the control that stops a cross-origin `<img>`/`<script>`/form
from reaching B. Rather than punch an ambient-credential hole in B for GET,
downloads use a short-TTL single-use ticket minted by an authenticated
call on B. This is the one piece of the design that exists purely because
of the threat model, and it is explained in full there.

---

## The four verifications

### Verification 1 — SVAR's licence: MIT, and the GPL belief has a real source

**Result: MIT throughout. No conflict. Use the component.**

The whole dependency closure was checked against the npm registry's own
metadata rather than a vendor marketing page, because the `license` field
in the published package is what a compliance audit reads:

| package | version | `license` |
|---|---|---|
| `@svar-ui/react-filemanager` | 2.6.0 | **MIT** [W1] |
| `@svar-ui/react-core` | 2.6.0 | MIT |
| `@svar-ui/react-grid` | 2.7.0 | MIT |
| `@svar-ui/react-menu` | 2.6.0 | MIT |
| `@svar-ui/react-uploader` | 2.6.0 | MIT |
| `@svar-ui/filemanager-store` | 2.6.0 | MIT |
| `@svar-ui/filemanager-data-provider` | 2.6.0 | MIT |
| `@svar-ui/filemanager-locales` | 2.6.0 | MIT |
| `@svar-ui/lib-dom` | 0.13.1 | MIT |
| `@svar-ui/lib-react` | 1.3.0 | MIT |
| `@svar-ui/lib-state` | 1.9.7 | MIT |

That is the complete `dependencies` list of `@svar-ui/react-filemanager@2.6.0`
plus the package itself; the peer dependencies are `react >= 18` and
`react-dom >= 18`. The repository's own licence file is the standard MIT
text with the copyright held by **XB Software Sp. z o.o.** [W7].

**Where the GPLv3 belief comes from, because it is not imaginary.** The
previous package generation, published under bare `wx-*` names, was
GPLv3. `wx-react-gantt@1.3.1` still carries `"license": "GPLv3"` on the
registry today, with a deprecation notice that names the change:
*"This package is no longer actively maintained. Use @svar-ui/react-gantt
instead: a fully React-based architecture (no wrappers), TypeScript
support, and an MIT license."* [W2]. Anyone who evaluated SVAR before that
migration formed exactly the belief in the proposal, and was right at the
time.

**Two obligations, and they are small.**

- **Pin the scope, not the name.** `@svar-ui/react-filemanager` is MIT;
  a `wx-react-*` package is GPLv3. A dependency named without its scope,
  or resolved through an alias, is a licence change disguised as a version
  bump. The build must fail on any `wx-*` package in the lockfile — one
  grep in the regenerate-and-diff job, and it belongs there rather than in
  a comment.
- **Carry the notices.** MIT requires the copyright notice and permission
  notice to travel with the distribution, and the distribution here is a
  Go binary with the bundle inside it. So `go:embed` a generated
  `internal/webui/third_party.txt` (from `pnpm licenses list --json`, a
  second `//go:generate` line, **committed** alongside `dist/` so a
  Node-less build still has it) and give the UI an About screen that shows
  it. This is the one compliance artifact the
  design owes, and it is also the artifact that makes a future licence
  regression visible in a diff.

**Not verified, and it does not matter here:** SVAR's *commercial* terms.
Gantt, Calendar and Kanban have paid PRO tiers; File Manager, Core,
DataGrid, Editor and Filter are listed as MIT with no PRO tier at all, so
no commercial licence is in the path of this design. No full EULA text was
reachable, which is only relevant if pelfs ever wants a PRO component.

**One capability gap that is not a licence question but was found while
answering it**, recorded here because it lands squarely on the two-surface
design: the bundled `RestDataProvider` uploads with **a single multipart
`POST` via `fetch`** — no `XMLHttpRequest`, no `upload.onprogress`, no
chunking, no resume [W4]. So the component gives the UI its file list, its
selection, its context menus and its drag-and-drop, and gives it **nothing
for a 68 MB SIF on a flaky link**. **Resumable upload is deferred** — the
first milestones use ordinary whole-file uploads, and the ceiling that
implies is stated in the two-surface section. When it is picked up, the
named investigation is **`tus` plus `uppy`**, and the component's
documented extension point (`api.intercept()` / `api.setNext()`) is where
that plugs in.

### Verification 2 — Cyberduck + OAuth2 over WebDAV: the mechanism

**Result: it works, driven entirely by the profile, with no compiled Java
protocol class — and this is the first thing to build for external
clients.** What follows is the mechanism read out of Cyberduck's own
source, because its documentation does not cover this path at all.

The belief that WebDAV in Cyberduck is Basic/Digest/NTLM/Kerberos only was
true until January 2025. It changed in answer to precisely this question:
discussion [#16780][W9], *"OAuth possible with generic WebDAV
configuration?"*, where the maintainer replied *"Not out of the box but
theoretically possible as we already support this for ownCloud Infinite
Scale (oCIS)"*, then opened [#16791][W10] and shipped [#16792][W10].
`CHANGELOG.md`'s **9.1.3** section, read first-hand, is one line:

```
* [Bugfix] Allow OAuth configuration in connection profiles (WebDAV) (#16792)
```

with the top of that changelog at 9.5.4 [W11].

#### 2a. The Bearer path reaches the WebDAV backend

`#16792` moved the OAuth wiring **out of** the ownCloud-specific session
and **into** the generic `DAVSession`. `DAVSession.getConfiguration`, at
master [W12]:

```java
if(host.getProtocol().isOAuthConfigurable()) {
    authorizationService = new OAuth2RequestInterceptor(configuration.build(), host, prompt)
            .setRedirectUri(host.getProtocol().getOAuthRedirectUrl());
    if(host.getProtocol().getAuthorization() != null) {
        authorizationService.setFlowType(OAuth2AuthorizationService.FlowType.valueOf(host.getProtocol().getAuthorization()));
    }
    configuration.addInterceptorLast(authorizationService);
    configuration.setServiceUnavailableRetryStrategy(new CustomServiceUnavailableRetryStrategy(host,
            new OAuth2ErrorResponseInterceptor(host, authorizationService)));
}
```

and `DAVSession.login` carries the matching half — `credentials.setOauth(authorizationService.validate(credentials.getOauth()))`
under the same predicate, with the Basic/Digest/NTLM/SPNEGO branch behind
`isPasswordConfigurable()` [W12]. The interceptor is an ordinary Apache
HttpClient request interceptor, and the header it adds is exactly what a
Go server needs to see [W18]:

```java
request.addHeader(new BasicHeader(HttpHeaders.AUTHORIZATION,
    String.format("Bearer %s", tokens.getAccessToken())));
```

It also refreshes on its own, before the request goes out [W18]:

```java
OAuthTokens tokens = host.getCredentials().getOauth();
if(tokens.isExpired()) {
    try { tokens = this.save(this.authorizeWithRefreshToken(tokens)); }
    catch(BackgroundException e) { log.warn("Failure {} refreshing OAuth tokens {}", e, tokens); }
}
```

**`DAVProtocol.java` has no OAuth code at all.** The switch is entirely
credential-driven, and `AbstractProtocol`'s defaults are what make it so
[W13]:

```java
public boolean isOAuthConfigurable()    { return StringUtils.isNotBlank(this.getOAuthClientId()); }
public boolean isPasswordConfigurable() { return StringUtils.isBlank(this.getOAuthClientId()); }
public boolean isOAuthPKCE()            { return true; }
public String  getAuthorization()       { return null; }
```

So **a non-blank `OAuth Client ID` in a `dav` profile turns OAuth on, and
turns password auth off in the same move.** No vendor protocol, no
compiled class, no `owncloud` protocol borrowing.

#### 2b. The profile keys, and how `Profile.java` consumes them

Every key below was read from `Profile.java`'s `public static final String
…_KEY` declarations, and every getter from the same file [W13].

| key | type | read by | notes |
|---|---|---|---|
| `Protocol` | string | `PROTOCOL_KEY` | **`dav`** for plain HTTP (`DAVProtocol`'s scheme is `http`), `davs` for TLS |
| `Vendor` | string | `VENDOR_KEY` | the profile's identity; must be unique |
| `Description` | string | `DESCRIPTION_KEY` | what the user sees in the bookmark list |
| `Default Hostname` | string | `DEFAULT_HOSTNAME_KEY` | `127.0.0.1` |
| `Default Port` | integer | `DEFAULT_PORT_KEY` | the listener's actual port |
| `Default Path` | string | `DEFAULT_PATH_KEY` | `/dav/` |
| **`OAuth Configurable`** | bool | `OAUTH_CONFIGURABLE_KEY` | optional; **absent means "infer from a non-blank client id"** |
| **`OAuth Client ID`** | string | `OAUTH_CLIENT_ID_KEY` | **the switch.** Must be non-blank |
| `OAuth Client Secret` | string | `OAUTH_CLIENT_SECRET_KEY` | blank ⇒ public client (`ClientParametersAuthentication`); non-blank ⇒ HTTP Basic client auth |
| **`OAuth Authorization Url`** | string | `OAUTH_AUTHORIZATION_URL_KEY` | pelfs's `/oauth/authorize` |
| **`OAuth Token Url`** | string | `OAUTH_TOKEN_URL_KEY` | pelfs's `/oauth/token` |
| **`OAuth Redirect Url`** | string | `OAUTH_REDIRECT_URL_KEY` | see 2c — **this one is load-bearing** |
| `OAuth PKCE` | bool | `OAUTH_PKCE_KEY` | absent ⇒ parent's default ⇒ **`true`** |
| `Scopes` | **array** of string | `SCOPES_KEY`, via `getOAuthScopes()` | a plist `<array>`, not a space-delimited string |
| `Authorization` | string | `AUTHORIZATION_KEY` | for `dav` this is the **OAuth flow type**, not the S3 signature version — see the warning below |
| `Password Configurable` | bool | `PASSWORD_CONFIGURABLE_KEY` | set `false` so no password field is offered |
| `Username Configurable` | bool | `USERNAME_CONFIGURABLE_KEY` | set `false` for the same reason |

Three consumption details that decide whether a profile works:

- **Every string value passes through a `StringSubstitutor` against
  Cyberduck's own preferences.** `private String value(final String key) {
  return substitutor.replace(dict.stringForKey(key)); }` [W13]. That is how
  `${oauth.handler.scheme}` resolves in published profiles — and it means a
  literal `$` or `${` in a pelfs-generated value would be substituted.
  **Generate URLs with no `$` in them.**
- **Every getter falls back to `parent`** (the built-in `DAVProtocol`) when
  the key is blank or absent, so an omitted key is not an empty value, it
  is the built-in default. `isOAuthPKCE()` returning `parent.isOAuthPKCE()`
  is how PKCE ends up on.
- **`Scopes` is a list**, read by `list(SCOPES_KEY)` which substitutes each
  element [W13]. A single string where an array is expected does not
  produce a one-element list.

**The `Authorization` trap, stated plainly because it will bite.** For S3
profiles this key names the signature version (`AWS4HMACSHA256`), and that
is the only meaning Cyberduck's documentation gives it. For a `dav`
profile, `DAVSession` feeds it straight into
`OAuth2AuthorizationService.FlowType.valueOf(...)` [W12], whose only
constants are `AuthorizationCode` and `PasswordGrant`. So the key must be
**omitted** (yielding the default authorization-code flow) or be exactly
one of those two strings. Anything else is an `IllegalArgumentException`
inside a session setup, which will surface as an unexplained connection
failure. **Omit it.**

#### 2c. The redirect target: loopback, with an explicit port

`BrowserOAuth2AuthorizationCodeProvider` dispatches on the redirect URI's
shape [W14], in this order:

1. `StringUtils.endsWith(URIEncoder.decode(redirectUri), ":oauth")` or
   `StringUtils.contains(redirectUri, "://oauth")` →
   **`CustomSchemeHandlerOAuth2AuthorizationCodeProvider`**. Opens the
   browser and waits on `OAuth2TokenListenerRegistry`; needs an
   OS-registered URL-scheme handler (`x-cyberduck-action:oauth`, or
   `x-mountainduck-action:oauth` for Mountain Duck — hence the
   `${oauth.handler.scheme}` indirection in published profiles).
2. `InetAddress.getByName(new URI(redirectUri).getHost()).isLoopbackAddress()`
   → **`LoopbackOAuth2AuthorizationCodeProvider`**, which starts its own
   `HttpServer`, registers a context at the redirect URI's **path**, reads
   `state` and `code` from the query, and hands them to
   `OAuth2TokenListenerRegistry`.
3. otherwise → **`PromptOAuth2AuthorizationCodeProvider`**, the
   out-of-band flow: open the browser, then *paste the code back*.

**Choose (2).** It is the only one of the three that requires nothing
installed, nothing registered, and no typing — and it is the only one that
lets pelfs's own authorization endpoint redirect somewhere real. So:

```
OAuth Redirect Url = http://127.0.0.1:<cbPort>/pelfs/oauth/callback
```

**With an explicit port, always.** The provider takes the port from the URI
and substitutes `0` (OS-chosen) when none is given, which would make the
`redirect_uri` Cyberduck *sends* disagree with the port it is *listening*
on — a mismatch that fails the flow with nothing useful in the UI. This is
an inference from quoted code rather than a tested behaviour, and it is in
"What could not be verified"; the safe move costs nothing.

**A consequence worth designing around:** the port in the profile is
Cyberduck's, not pelfs's, and pelfs must know it in advance to allowlist it
as a `redirect_uri`. So pelfs **picks** it when it generates the profile —
a fixed high port written into both the profile and the allowlist. If it is
in use on the user's machine the flow fails, so the config screen should
offer a "regenerate with a different port" button rather than making the
user edit a plist.

#### 2d. What pelfs must implement

Four pieces, all pure Go, **no new module** — `crypto/rand`,
`crypto/sha256`, `crypto/subtle`, `encoding/base64`, `encoding/json`,
`net/http`.

**(i) `GET /oauth/authorize`** — accepts `response_type=code`, `client_id`,
`redirect_uri`, `scope`, `state`, `code_challenge`,
`code_challenge_method=S256`. Validates, then redirects to
`redirect_uri?code=…&state=…`. Because the user is already logged into the
web app on this same origin, **there is no second login**: the endpoint
recognizes the session and issues the code.

**(ii) `POST /oauth/token`** — `grant_type=authorization_code` with
`code`, `redirect_uri`, `client_id`, `code_verifier`; and
`grant_type=refresh_token`. Returns the standard JSON:
`access_token`, `token_type: "Bearer"`, `expires_in`, `refresh_token`.
Client authentication follows what the profile says: a blank
`OAuth Client Secret` makes Cyberduck a public client sending `client_id`
as a parameter; a non-blank one makes it send HTTP Basic. **Ship blank and
rely on PKCE**, which is the current best practice for a client that is
itself a downloadable file.

**`expires_in` is not optional.** If it is omitted, Cyberduck's token
handling treats the credential as never expiring and will never refresh —
so a token that pelfs *does* expire produces 401s the client will not
recover from. Emit it, and emit a `refresh_token`.

**(iii) Bearer acceptance on `/dav/*`.** The DAV middleware accepts
*either* HTTP Basic (a per-client credential, the contingency below) *or*
`Authorization: Bearer <token>`. One caution from the source: `login()`
probes the home path with a `HEAD`/`PROPFIND` before anything else, so the
challenge behaviour on `/dav/` matters — **do not** answer an unauthorized
`/dav/` request with `WWW-Authenticate: Basic` when a Bearer token was
offered and rejected, or Cyberduck may fall back into a password prompt for
a profile that has no password field.

**(iv) An authorization-code store.** Single-use, 60-second TTL, bound to
the `client_id`, the exact `redirect_uri`, and the PKCE challenge.

#### 2e. Consent: one gesture, on every authorization

**Same-session does *not* imply consent — require exactly one click, on
every `/authorize`.** This section originally said "and remember it per
`client_id` for the life of the process". **That was wrong, and it was
wrong in the direction that matters:** remembering consent at `/authorize`
reinstates precisely the primitive control 6 exists to remove. After one
legitimate click, a navigation the user did not make could mint codes
again — which is the whole attack, with one extra step. So the gesture is
required every time, and the property the "remember it" clause was
reaching for is delivered where the client actually needs it: **the
refresh token.** Cyberduck's `OAuth2RequestInterceptor` refreshes before
each request goes out and never revisits `/authorize` while a refresh
works, so a reconnect within the session does not re-prompt anyway. The
user-visible friction is identical and the endpoint keeps its property.

The argument for "no consent screen" is real: the user just downloaded this
profile from this page, double-clicked it, and is watching. Asking again is
friction with no information in it.

The argument against is A7 in the threat model, and it wins: an
`/authorize` endpoint that mints a token from an existing session **with no
user interaction** is a token-exfiltration primitive for anything that can
navigate the user's browser to it. A single click is the difference between
"an attacker needs a bug" and "an attacker needs a bug *and* the user to
click Authorize on a screen that says what is being authorized". So:

- a consent screen naming the client (`Cyberduck`), the scope
  (`read` / `read+write`), the volume, and the redirect target;
- one click, requiring a real user gesture on the page;
- **required on every authorization**, never remembered at `/authorize`;
- and, as shipped, the gesture is **structural rather than advisory**:
  `GET /oauth/authorize` has no code path that writes a `Location` header
  at all, the `POST` requires a 32-byte consent ticket that exists only in
  the HTML of the consent page, and that page's CSP is `script-src 'none'`
  — so there is no `form.submit()` available on that document to anybody,
  including us. The claim is not "we did not write an auto-submit"; it is
  "an auto-submit cannot execute here". `internal/localoauth`'s package
  comment is the specification and the tests are beside it.

#### 2f. The profile, concretely

```xml
<key>Protocol</key>              <string>dav</string>
<key>Vendor</key>                <string>org.pelicanplatform.pelfs.local.49731</string>
<key>Description</key>           <string>pelfs — pelican://…/… (this session)</string>
<key>Default Hostname</key>      <string>127.0.0.1</string>
<key>Default Port</key>          <integer>49731</integer>
<key>Default Path</key>          <string>/dav/</string>
<key>OAuth Configurable</key>    <true/>
<key>OAuth Client ID</key>       <string>&lt;32 random bytes, base64url&gt;</string>
<key>OAuth Client Secret</key>   <string></string>
<key>OAuth Authorization Url</key><string>http://127.0.0.1:49731/oauth/authorize</string>
<key>OAuth Token Url</key>       <string>http://127.0.0.1:49731/oauth/token</string>
<key>OAuth Redirect Url</key>    <string>http://127.0.0.1:52001/pelfs/oauth/callback</string>
<key>Scopes</key>                <array><string>pelfs.read</string><string>pelfs.write</string></array>
<key>Password Configurable</key> <false/>
<key>Username Configurable</key> <false/>
```

**The `Vendor` carries the port, and that is a correction to what this
section first said.** A bare `org.pelicanplatform.pelfs.local` is a single
profile identity, and Cyberduck registers profiles by vendor — so two
`pelfs browse` sessions on the same machine would collide, the second
profile silently taking over the first's bookmarks and its OAuth
endpoints, which point at a port the second session does not own.
`davprofile.VendorPrefix` is the stem and the listener's port is appended
(`internal/davprofile/davprofile.go`, `Params.vendor`); the generated
`.duck` bookmark's `Provider` names the same string, which is what makes
the bookmark resolve to the OAuth-configured profile rather than the
built-in `dav`.

Note what is **not** there: `Authorization` (omitted deliberately, 2b),
`OAuth PKCE` (omitted so the parent's `true` applies), and any secret other
than the `client_id` — which is itself minted per download, so possessing
the profile is the only thing that identifies the client.

Installation is by double-click, or *Preferences → Profiles*; the same
mechanism and the same core serve **Mountain Duck**, whose only difference
is its handler scheme — which the loopback redirect sidesteps entirely.

#### 2g. What a live Cyberduck confirmed, and the contingency

**This subsection used to be a list of four things that needed a live
Cyberduck. They were run.** `scripts/oauth-cyberduck-docker.sh` drives
**real Cyberduck** — `duck` is the same protocol stack as the desktop app
and Mountain Duck: the same `DAVSession`, the same
`OAuth2RequestInterceptor`, the same
`BrowserOAuth2AuthorizationCodeProvider` — against a live pelfs
authorization server, with `curl` playing the human at the consent screen.
Measured 2026-08-23, **duck 9.5.3 (45464)**, curl 8.14.1,
`debian:stable-slim`, aarch64: **22 checks, 0 failing**, the run itself
`--network none`. So the following move from *read out of the source* to
**observed on the wire**:

| claim, formerly unverified | what was observed |
|---|---|
| a **non-blank `OAuth Client ID` is the switch** | the session went straight to "Start new OAuth flow" with credentials `user='anonymous', password=''` — no password prompt, no password field, nothing typed. `Password Configurable = false` plus OAuth keys does suppress the prompt (item 5a, closed) |
| **PKCE `S256` is sent unprompted** | the URL Cyberduck built carries `code_challenge_method=S256`, so *requiring* it costs the primary client nothing |
| the **loopback provider is selected** for this redirect shape | `Evaluate redirect URI http://127.0.0.1:52001/pelfs/oauth/callback`, then `Started OAuth callback server … Await callback` |
| the **`redirect_uri` is echoed verbatim** | byte for byte the profile's string, which is what makes an exact-string allowlist workable rather than aspirational |
| a **read-only token answers 403, not 401** | which matters: a 401 sends a client with no password field back looking for a password |
| `duck --profile <file>` registers a generated profile | `Register profile Profile{parent=dav, vendor=org.pelicanplatform.pelfs.local.9997}` — and note the port in the vendor (2f) |
| `Scopes` as a plist `<array>` | arrives as a space-delimited `scope` parameter |
| **`duck` can complete the flow headlessly** | it does not need a browser at all: it prints the authorization URL and waits on its own loopback listener. The custom-scheme flow that is documented broken on headless Linux [W15] is not this path |

Two of the design's refusals were exercised in the same run and are also
observations rather than intentions: a callback URL off by one port answers
**400**, an unknown `client_id` answers **400**, an authorization with no
`S256` challenge answers **400**, a `GET` of `/authorize` emits **no
`Location`**, and a refused Bearer is **not** offered `WWW-Authenticate:
Basic` (item 5b, closed — the challenge does have to be narrowed).

The one public report of somebody trying WebDAV+OAuth says the dialog never
appeared [W9], on a profile with a **blank** `OAuth Client ID` — which by
`isOAuthConfigurable()` means OAuth was never enabled at all. That remains
a hypothesis about somebody else's configuration, and it is consistent with
everything above.

**Contingency, one paragraph.** If the flow cannot be made to work, the
`/dav/*` endpoint keeps its HTTP Basic path — a per-client credential
minted in the UI, 32 random characters, presented preemptively (Cyberduck's
`webdav.basic.preemptive=true`, per `docs/design-guiclients.md`). A profile
**cannot** carry the password and neither can a `.duck` bookmark:
`HostDictionary.java`'s key set has `Protocol`, `Hostname`, `Port`, `Path`,
`Username`, `Nickname` and friends and **no `Password`** [W16], so the
contingency costs the user one paste. It is also the path every *other*
WebDAV client needs — WinSCP, rclone, macOS `mount_webdav` — so it gets
built either way; the OAuth flow is what makes Cyberduck and Mountain Duck
one double-click instead of one double-click plus one paste.

One note for the record: **Cyberduck is GPLv3** (`LICENSE.txt`). Irrelevant
here — nothing of Cyberduck is linked or distributed by pelfs, only its
profile format is targeted, and a file format is not a derivative work.

### Verification 3 — what the component actually speaks: a fixed REST contract

**Result: not WebDAV. A fixed REST contract of eleven route patterns, and
there is an official Go reference server that spells it out.**

The component takes a flat array of path-keyed entries and emits actions;
`RestDataProvider` turns those actions into HTTP. The data shape is a
**flat list of full paths**, not a nested tree [W3]:

```js
{ id: "/Code/Datepicker/Year.jsx", size: 1595,
  date: new Date(2023, 11, 7, 15, 23), type: "file" }
```

`id` is the full path and `type` is `"folder"` or `"file"`. The wire
protocol was read from two independent sources that agree: the provider's
published `dist` bundle [W4], and SVAR's own Go reference backend, whose
`server.go` registers precisely these routes [W8]:

```
GET    /files            GET  /files/{path}
POST   /files/{id}       PUT  /files/{id}       PUT /files
DELETE /files
GET    /info             GET  /info/{id}
POST   /upload           GET  /direct
GET    /preview          GET  /icons/{size}/{name}
```

with request bodies `FileUpdate{Operation, Name, Target, Ids []string}`
and `NewFile{Name, Type}`, and an upload handler that reads multipart
field `file`, an optional `name` override, and an `id` query parameter
naming the parent directory [W8].

**Do not copy that server's code.** Its repository has no `LICENSE`,
`LICENSE.md`, `license.txt` or `COPYING` at the root — verified against
the GitHub contents API, which lists nine files and two directories and no
licence among them [W8]. Unlicensed source is all-rights-reserved by
default. The *route contract* is a protocol, and reimplementing a protocol
from its observable behaviour is exactly what pelfs already does for NFSv3
and would do for WebDAV. Read it, cite it, write our own.

**The two questions this verification could not answer decided whether
the component was usable on a pelfs volume at all.** They were the
highest-risk unknowns in the design and they were closed by the U0 probe —
the real component, in a real browser, against a logging stub
(`webui/frontend/probe`, measurements in
`internal/webui/testdata/svar-contract/u0-measurements.json`). Both
answers changed the code.

**1. It IS lazy — but only because the app makes it so.** Entries the
server marks `lazy: true` make the store emit `request-data` when the
folder is *navigated into*; the answer goes back as `provide-data`. The
shipped `RestDataProvider` **registers no handler for `request-data` at
all**, so without the wiring in `webui/frontend/src/api/provider.ts`
(`wireLazyLoading`) nothing loads. Three further facts from the recording,
each of which is a shape in the server:

- expanding a folder in the **sidebar tree** does not load it; only
  navigation does (`set-path` is the only action that emits `request-data`);
- the store emits `request-data` **twice** for one navigation, which on a
  100k-entry directory is two full listings — so `internal/webapi`
  single-flights listings by path rather than trusting the far side's own
  in-flight guard;
- a folder already loaded is **never re-listed** except by the breadcrumb
  refresh button.

**And `GET /files` — the un-pathed form — is not droppable.** This section
first read it as "returns the whole tree, so replace it". It does not: the
component fetches it **at boot**, and it means the **ROOT directory**,
never the tree. Dropping it would have meant a page that never renders.

**2. It does NOT virtualize.** Every entry becomes DOM, in both card and
table mode, and scrolling to the bottom of a 100,000-entry directory
changes nothing because everything was already rendered. Measured:

| entries | cards mode | table mode | DOM nodes | JS heap |
|---|---|---|---|---|
| 1,000 | 0.1 s | 0.07 s | 10,067 | 13 MB |
| 5,000 | 0.3 s | 0.4 s | 50,067 | 40 MB |
| 20,000 | 1.4 s | 2.3 s | 200,067 | 148 MB |
| 50,000 | 6.3 s | 9.4 s | 500,067 | 364 MB |
| 100,000 | 18.1 s | 37.5 s | 1,000,067 | **703 MB** |

**So the response cap is the design, not a fallback**, and 5,000 is a
defensible number rather than a round one: it renders in under half a
second, and it is also the number `scripts/sftp-clients-docker.sh` already
proves a real client handles (`dir-5000: ok`). `webapi.DefaultCap` is
5,000.

**The cap has a consequence this document did not state, and it is the one
a user meets: search is CLIENT-SIDE over what is already loaded.** So a
capped listing is also a **partial search** — a user who searches a capped
folder and finds nothing will conclude the file is not there. Two facts
have to be in the same sentence or one of them misleads, so there is
exactly one wording of it, `webapi.PartialSearchNotice`, and every surface
takes the sentence from there:

> Showing 5,000 of 412,006 entries in this folder. Search matches only
> what is loaded, so it is searching these 5,000 rows and not the whole
> folder — narrow the path, or use the WebDAV endpoint to see all of it.

**The numbers cannot ride on the listing body.** The provider hands
`loadFiles` the parsed body and nothing else, so the array must BE the
array — a `{entries: [...], total: N}` envelope is not something the
component can consume, and it drops response headers on that path too. So
the truth travels three ways: the array itself, `X-Pelfs-Listing-Returned`
/ `-Total` / `-Cap` / `-Truncated` / `-Hidden` on the response, and
`GET /api/v1/info/{id}` as JSON for the callers (the app shell, `curl`)
that can read a body.

#### Three defects in the shipped provider, not two

Two were found by the U0 probe and are documented in
`webui/frontend/probe/README.md`; the third was found later, by the pass
that wired the component to the real API, and it is the worst of them.

1. **`RestDataProvider.send()` never reads `this._customHeaders`.** It
   overrides the base `Rest.send()` and spreads only its `customHeaders`
   argument, so `provider.setHeaders({...})` — the documented way to
   attach a credential — is **silently dropped**. The session token is
   header-borne by design (there is no cookie), so this is not a nicety:
   it is the credential.
2. **Every mutating request goes out as `Content-Type:
   text/plain;charset=UTF-8`**, because the provider sets no content type
   and that is `fetch`'s default for a string body. `text/plain` is one of
   the three types an HTML form can send, so the threat model's
   "mutating route with `text/plain` → 415" row would reject every write
   the file manager makes.
3. **`send()`'s `.catch` sits after the `!res.ok` throw**, so **every
   failure resolves to `undefined`** — and a failed rename is
   indistinguishable, in the UI, from a successful one. This is the one
   that costs a user data rather than a request: they see the new name,
   the volume has the old one. It is **not** fixed by the two-line
   override that fixes (1) and (2), because it is in the base class's
   promise chain; it is recorded in `docs/known-issues.md` rather than
   claimed as handled.

`PelfsDataProvider` (`webui/frontend/src/api/provider.ts`) overrides
`send()` and fixes the first two in three lines, which is why the probe ran
before the app was written. The recording shows the difference on the wire.

**And the component phones home unless told not to.** The default theme
renders `<link rel=stylesheet
href=https://cdn.svar.dev/fonts/wxi/wx-icons.css>` plus a preconnect, and
the default icon callback builds `https://cdn.svar.dev/icons/…` URLs per
file extension. Both were caught on the wire by the probe. `<Willow
fonts={false}>` and `icons="simple"` turn them off; with both off the page
makes **zero** requests off loopback, which `vite.config.ts`'s
no-remote-assets plugin then keeps true. A localhost tool that fetches from
a CDN is a localhost tool that does not work on a login node, and it is
also a CSP the app would have had to widen.

#### One more thing the volume does that the contract does not anticipate

**Opening a symlink by its own path answers `ESTALE`.** The link inode is
not a file to read; it has to be resolved first. This bit three places
before it was understood as one thing — the WebDAV adapter's `OpenFile`,
the JSON API's copy path, and the download source — and the fix is the
same in all three: resolve the terminal link, take the handle on the
resolved path, and answer `Stat` about the name the caller asked for.

### Verification 4 — the toolchain: Vite under `go generate`, bundle committed

**Result: Next.js is the wrong tool, Vite is the right one, and the
Node-toolchain problem is solved by `go generate` plus a committed bundle —
so `go build ./...` needs no Node, ever, and `go install` still produces a
working UI.**

**Next.js buys nothing here.** Server-side rendering, incremental static
regeneration, route handlers, middleware and image optimization are all
answers to problems a localhost SPA served by a Go binary does not have:
no cold-start latency to hide, no SEO, no CDN, no origin server other than
this one Go process. `next build` with `output: 'export'` produces a static
bundle *after* pulling the whole Next runtime into the dependency graph.
`vite build` produces `dist/` with hashed asset names and nothing else.

Pelican's own frontend is the counterexample that proves it: it is Next.js
(`web_ui/frontend/package.json`: `"build": "next build"`), and this repo's
CI died on it. `24c393c` — *"ci: the integration job stops building a web
UI nobody looks at"* — records the failure mode: upstream switched npm to
pnpm, the runner had pnpm nowhere, and the job *"died with `/bin/sh: 1:
pnpm: not found` forty lines into someone else's Makefile — which reads
like a test failure and is not one"* (`scripts/build-pelican-server.sh`
header).

#### The shape: `//go:generate`, a committed `dist/`, and `//go:embed`

```
webui/                          # sources: package.json, vite.config.ts, src/
internal/webui/
    webui.go                    #   //go:generate  (runs the Vite build)
                                #   //go:embed dist
    dist/                       #   COMMITTED build output
        index.html
        assets/index-<hash>.js
        assets/index-<hash>.css
    third_party.txt             #   generated notices, also committed
```

`internal/webui/webui.go` carries both directives:

```go
//go:generate sh -c "cd ../../webui && pnpm install --frozen-lockfile && pnpm build"
//go:generate sh -c "cd ../../webui && pnpm licenses list --json > ../internal/webui/third_party.txt"

//go:embed dist
var assets embed.FS
```

so that:

- **`go build ./...` and `go test ./...` need no Node**, because `dist/` is
  in the tree. This is the property `24c393c` was protecting and it is
  preserved exactly.
- **`go install github.com/bbockelm/pelfs/cmd/pelfs@latest` produces a
  working UI**, which the alternative (a placeholder plus a release-time
  build) does not. This is the decisive advantage and it is why the bundle
  is committed.
- **`go generate ./...` is the only thing that needs pnpm**, and only a
  contributor changing the frontend runs it.
- **`CGO_ENABLED=0` and the four cross-builds are unaffected** — `go:embed`
  is pure Go.

#### Both halves of the precedent are in the neighbourhood already

**Pelican commits build output to satisfy a non-optional `go:embed`**, and
this repo already depends on it. `scripts/build-pelican-server.sh`'s
header: *"pelican's `//go:embed frontend/out/*` (web_ui/ui.go) matches at
least one file, and pelican commits an empty
`web_ui/frontend/out/placeholder` for precisely that purpose — the frontend
.gitignore ignores `/out/*` and then re-includes `!/out/placeholder`. So a
pristine checkout builds a server binary with `go build` and nothing
else."* pelfs commits the *real* bundle rather than a placeholder, which is
the same trick aimed at a stronger outcome: pelican's placeholder yields a
server with no UI, ours yields a binary with one.

**Pelican already uses `//go:generate` for generated artifacts**, so the
pattern is not novel to this ecosystem either — `cmd/main.go:41-42`:

```go
//go:generate go run -tags client . generate-docs docs/app/commands-reference/pelican
//go:generate go run -tags server . generate-docs docs/app/commands-reference/pelican-server
```

#### The gate: regenerate and diff

A committed artifact rots silently unless something checks it, and the only
honest check is to rebuild it and compare. One CI job, **not** on the Go
PR path:

```
- run: go generate ./internal/webui
- run: git diff --exit-code -- internal/webui/dist internal/webui/third_party.txt
```

A non-empty diff means the committed bundle does not match its sources, and
the job says so by failing. Four things make that gate trustworthy rather
than flaky:

- **Pin the toolchain exactly.** Node and pnpm versions pinned in the
  workflow and in `webui/package.json`'s `engines`, `pnpm-lock.yaml`
  committed, `pnpm install --frozen-lockfile`. An unpinned minor version of
  a bundler is a spurious diff, which is the failure mode that teaches
  people to ignore a red job.
- **Make the build deterministic.** Vite's default output is
  content-hash-named and reproducible given the same inputs; forbid
  anything that embeds a timestamp, a build id, or a path from the build
  machine. Verify by running it twice in the job and diffing — cheaper than
  discovering non-determinism from a contributor's PR.
- **Trigger it on the paths that matter**: `webui/**`,
  `internal/webui/**`, and on a schedule. A Go-only PR must not wait for
  Node.
- **Fail the job on any `wx-*` package in `pnpm-lock.yaml`** —
  Verification 1's licence rule, enforced where it can actually run.

#### What this costs, and it is not nothing

- **Minified vendor JavaScript in the tree**, which nobody can review in a
  diff. Measured, so the size is arguable rather than guessed: SVAR and its
  ten dependencies are **166,892 bytes minified / 50,143 gzipped** [W5];
  React's runtime is the other large piece and was not measured cleanly
  (see "What could not be verified"). A bundle in the low hundreds of KB is
  a file a repo can carry.
- **Diff noise on every UI change** — a hashed-asset rename plus a
  wholesale content change, per build. Mitigate by reviewing `webui/src`
  and treating `internal/webui/dist` as generated: `.gitattributes` marking
  it `linguist-generated=true` and `-diff` keeps it out of review diffs
  while keeping it in the tree.
- **A `.gitignore` question to get right.** Unlike pelican, pelfs must
  **not** ignore `dist/` — the whole point is that it is committed. But
  `webui/node_modules/` and `webui/dist/` (Vite's own intermediate output,
  if the build writes there before copying) must be ignored, and
  `go.work`/`go.work.sum` should be added at the same time (see the
  `go.mod` section).

---

## Threat model

### What sets the bar

**An attacker who defeats this gets write access to the user's federation
data.** Not a local file, not a cache: the namespace prefix the session
holds, under the user's own OIDC credential, with `storage.read`,
`storage.create` and `storage.modify` — because `primeCredential` acquires
exactly those three up front, deliberately, so the user approves once
(`internal/pelicanobj/fedstore.go:110-133`). Reads exfiltrate whatever the
prefix contains; writes are published to the branch at the next checkpoint
and are then what every other reader of that federation sees.

Two things bound it, and they are worth stating because they are the only
good news in this section:

- **The bearer token never reaches the browser.** It lives in the pelfs
  process and the credential wallet. Nothing in this design puts a
  federation token in a cookie, a URL, `localStorage`, or an SSE frame. An
  attacker who steals the session token can *use* the user's federation
  access through pelfs; they cannot walk away with a token that outlives
  the process.
- **`pelfs browse` defaults to read-only.** `--rw` is explicit. On the
  default the entire write half of this section is unreachable, and the
  worst outcome is disclosure of data the user can already read.

And one thing makes it worse than a normal localhost app: the process is
holding a *lease on a branch* and a *signing key* (`g.signingKeyFile()`),
so a write is not merely a write — it is a write that will be signed and
published under the user's identity.

### The structural decision that removes the largest risk

**The web surface is not a proxy for the control socket.** Stated in the
verdict and repeated here because it is the one architectural choice that
deletes a whole class of attack. `internal/control` exposes the full
`net/http/pprof` surface — `Index`, `Cmdline`, `Profile`, `Symbol`,
`Trace` (`control.go:147-155`) — and its own comment explains the licence
for that: *"the socket is the auth boundary (0600 in the state dir), so
the full pprof surface is safe to expose"*. A browser session on
127.0.0.1 is not that boundary. A heap profile of a pelfs process
contains file paths, catalog contents and, plausibly, credential material; `Cmdline` contains
the prefix and every flag. So the web listener routes **three** things to
session state — publish, status, dirty counts — by calling the same
in-process functions the hooks call, and `/debug/pprof` is unreachable from
it by construction, asserted by a test.

### What the browser platform actually guarantees, measured against the spec

Eight facts, each cited, because the design is only as good as these and
three of them are the opposite of the common assumption.

**F1. `http://127.0.0.1:<any port>` is a secure context, unconditionally.**
W3C Secure Contexts, "Is origin potentially trustworthy?": *"If origin's
host matches one of the CIDR notations `127.0.0.0/8` or `::1/128`
[RFC4632], return 'Potentially Trustworthy'"*, and *"Note: Neither origin's
domain nor port has any effect on whether or not it is considered to be a
secure context"* [B1]. So `crypto.subtle` is available
(`[SecureContext] readonly attribute SubtleCrypto subtle` [B2]), service
workers are available, and the random port costs nothing. The *name*
`localhost` is the weaker case — the spec makes it conditional on the UA
following RFC 6761's name-resolution rules, because *"resolvers often
ignore these suggestions, and will send localhost to the network for
resolution in a number of circumstances"* [B1]. **Launch at the literal
`127.0.0.1`.**

**F2. An HTTPS page embedding `http://127.0.0.1:PORT` is NOT mixed
content.** W3C Mixed Content defines mixed content as a URL that is *"not
a potentially trustworthy URL"* [B3], and F1 says loopback is. The PNA
explainer states the consequence outright: public sites may embed
non-public resources *"with the exception of `http://localhost` which is
embeddable"* [B4]. **So "an HTTPS site cannot talk to my plain-HTTP
localhost server" is false**, and any design resting on it is resting on
nothing.

**F3. Ports are not part of a "site", so another loopback port is
same-site.** HTML Standard: *"If origin's host's registrable domain is
null, then return (origin's scheme, origin's host)"*, and *"Unlike the same
origin and same origin-domain concepts, for schemelessly same site and same
site, the port and domain components are ignored"* [B5]. An IP literal's
registrable domain is null [B6]. Chromium's `schemeful_site.cc` implements
exactly that, with `ObtainASite` documented as producing *"a port of 0"*
[B7]. **So `http://127.0.0.1:1234` and `http://127.0.0.1:56789` are
same-site**, and `Sec-Fetch-Site` reads `same-site`, not `cross-site`.

**F4. Cookies have no port isolation at all, and this is the fact that
decides the credential design.** RFC 6265bis-22 §8.5, "Weak
Confidentiality": *"Cookies do not provide isolation by port. If a cookie
is readable by a service running on one port, the cookie is also readable
by a service running on another port of the same server. If a cookie is
writable by a service on one port, the cookie is also writable by a
service running on another port of the same server."* [B8] And the
`__Host-` prefix does not fix it: *"Ports are the only piece of the origin
model that `__Host-` cookies continue to ignore."* [B8]

Concretely: if the user ever navigates their browser to *any other*
service on `127.0.0.1` — a Jupyter notebook, a dev server, a Grafana, a
malicious local process — that service receives pelfs's session cookie.
A top-level navigation from the address bar carries `Sec-Fetch-Site: none`
and a `SameSite=Strict` cookie *is* sent on it [B9]. `HttpOnly` stops
`document.cookie` but not the browser attaching the cookie to a request.
**A cookie on 127.0.0.1 is shared with every other local service the
browser talks to.** That is not a bug to mitigate; it is what cookies are.

**F5. `SameSite=Strict` does what it says, and what it says is less than
hoped.** It excludes the cookie on every cross-site retrieval, subresource
and navigation alike — RFC 6265bis-22's retrieval algorithm excludes
unless *"the same-site-flag is 'Lax' or 'Default'"* among other conditions
[B9] — and cross-site top-level navigations get nothing: *"Same-site
cookies in 'Strict' enforcement mode will not be sent along with top-level
navigations which are triggered from a cross-site document context"* [B9].
Useful. But by F3 it does **nothing** about another loopback port, and by
F4 it does nothing about the user visiting one.

**F6. Cross-origin GET reaches the server; CORS only governs reading the
response.** The best citation is Google's own Local Network Access spec:
*"Note that status quo CORS protections don't protect against the kinds of
attacks discussed here as they rely only on CORS-safelisted methods and
CORS-safelisted request-headers. No CORS preflight is triggered, and the
attacker doesn't care about reading the response, as the request itself is
the CSRF attack."* [B10] And the corollary that makes non-GET verbs easy:
*"A CORS-safelisted method is a method that is GET, HEAD, or POST"*, so
every other method forces a preflight; and a single non-safelisted request
header forces one too — the safelist is exactly
`accept`/`accept-language`/`content-language`/`content-type`/`range`, with
`content-type` restricted to `application/x-www-form-urlencoded`,
`multipart/form-data` and `text/plain` [B11]. **`application/json` is not
safelisted**, which is a second, free preflight trigger on every mutating
JSON endpoint — and Fetch's own text warns about the inverse: *"If extract
a MIME type were used the following request would not result in a CORS
preflight and a naïve parser on the server might treat the request body as
JSON"* [B11].

**F7. Private Network Access is dead; Local Network Access shipped, and it
is a permission prompt.** PNA's preflight
(`Access-Control-Request-Private-Network`) never enforced — Chrome's own
post: *"This rollout is currently on hold due to a number of compatibility
problems. … PNA preflights are not currently enforced."* [B12] Only the
warning-only mode ever shipped, in Chrome 104, where *"the subsequent
request is sent as if the preflight had succeeded"* [B13]. **Do not build
against PNA.** What shipped is LNA, gating *"access on a permission rather
than via preflight requests"* [B14]:

| | status |
|---|---|
| Chrome **142** | shipped and enforced, desktop + Android: *"a local network request is any request from a public website to a local IP address or loopback, or from a local website … to loopback"* [B15] |
| Chrome 145 | permission split into `local-network` and `loopback-network` [B15] |
| Chrome 147 | extended to WebSocket and WebTransport [B15] |
| Firefox **153** (2026-07-21) | *"Local Network Access restrictions are now enabled by default for all users"* [B16] |
| Safari | **no shipping implementation, no formal position**; WebKit standards-position #520 open, labelled `concerns: venue` [B17] |

**What LNA does and does not cover, because this decides how much is
free.** It applies to subresources, `fetch()`, subframe navigation, service
workers, WebSockets, WebTransport and WebRTC — and **not** to top-level
navigation: the spec's own note says *"Chromium only applies LNA
restrictions to iframe navigations currently. It may be worth expanding
this to include main-frame navigations (especially popup windows which can
be controlled by their opener)"* [B14]. It is gated on the caller being a
secure context, so *"on non-secure contexts, all requests will fail"*
[B18]. And **loopback → loopback is explicitly not gated**: *"Requests
originating from the loopback address should not be considered local
network requests"*, plus *"Chromium only implements Local Network Access
restrictions for public to local or loopback requests, and does not enforce
the permission for cross-origin local requests"* [B14].

The spec itself forbids leaning on it, and the sentence is worth carrying
verbatim into any review of this design: *"a router's web-based
administration interface must be designed and implemented to defend against
CSRF on its own, and should not rely on a UA that behaves as specified in
this document. … vendors should not consider themselves absolved of
responsibility, even if all UAs implement this mitigation."* [B14]

**F8. `Sec-Fetch-Site` is a real, unforgeable signal, and Go 1.25 shipped
the middleware.** The header carries `same-origin`, `same-site`,
`cross-site` or `none`; the algorithm asserts the target is a potentially
trustworthy URL, so a loopback server does receive it [B19], as Chromium's
`sec_header_helpers.cc` confirms [B20]. It cannot be forged from a page
because Fetch makes any `Sec-`-prefixed name a forbidden request header
[B11][B19]. Support: Chrome 76, Firefox 90, Safari 16.4 — Baseline
*"widely available … since March 2023"* [B21].

And **`net/http.CrossOriginProtection` is in the standard library** as of
Go 1.25, which this repo is past (`go.mod:3` is `go 1.26.0`). Its own doc
comment describes the mechanism and, usefully, its two gaps [B22]:

> *"Cross-origin requests are currently detected with the `Sec-Fetch-Site`
> header, available in all browsers since 2023, or by comparing the
> hostname of the `Origin` header with the Host header."*
> *"The GET, HEAD, and OPTIONS methods are safe methods and are always
> allowed. It's important that applications do not perform any state
> changing actions due to requests with safe methods."*
> *"Requests without `Sec-Fetch-Site` or `Origin` headers are currently
> assumed to be either same-origin or non-browser requests, and are
> allowed."*

It accepts only `same-origin` and `none` — so it rejects `same-site`, which
by F3 is what another loopback port looks like. **Use it, and close both
gaps explicitly**: never mutate on a safe method, and never rely on its
fail-open behaviour for an authenticated route.

### The credential design that follows from F3 and F4: no session cookie

The proposal says "a credential in the launch URL, then a cookie". **Drop
the cookie.** F4 is not a weakness of a particular cookie configuration; it
is the cookie model. Any cookie set for host `127.0.0.1` is sent to every
other service on `127.0.0.1` the browser is made to contact, including on a
user-initiated top-level navigation, and no attribute available —
`SameSite=Strict`, `HttpOnly`, `Secure`, `__Host-` — changes that.

**Instead: a session token the app holds in memory and sends as a request
header.**

| | how |
|---|---|
| **bootstrap** | `#bt=<32 random bytes>` in the launch URL's **fragment** |
| **exchange** | the page reads `location.hash`, `POST`s it to `/api/v1/session`, `history.replaceState`s it away |
| **session token** | returned in the JSON body; held in `sessionStorage`, which **is** origin-scoped including port, unlike a cookie |
| **presented as** | `X-Pelfs-Session: <token>` on every `/api/v1/*` request |
| **SSE** | `/events?s=<token>` — `EventSource` cannot set headers, and a same-origin query string is acceptable here because it never becomes a navigation, never enters history, and the only access log is ours |
| **downloads** | not this token at all; a single-use ticket (below) |
| **app shell** | `/` and `/assets/*` are served **unauthenticated** — a static bundle with no secrets in it, so there is nothing to protect |

What that buys, in order of weight:

1. **There is no ambient credential, so CSRF is structurally impossible for
   the API.** A cross-origin or cross-site page can issue whatever request
   it likes at `/api/v1/*`; the browser attaches nothing, because there is
   nothing to attach. This is a stronger statement than "we check
   `Origin`", and it does not depend on getting a header check right.
2. **No credential leaks to other local services.** F4's whole problem
   disappears: a header is sent only by the code that sets it, only to the
   URL it names.
3. **A custom header is required by construction**, so F6's preflight
   trigger applies to every route including GET — no exemption to carve.
4. **The `Secure`-cookie-on-localhost question becomes moot**, which is
   convenient, because the answer is browser-dependent: Chrome accepts
   (`ProvisionalAccessScheme` returns `kTrustworthy` for a localhost URL
   [B23]) and Firefox accepts [B24], but Safari historically rejects and
   WebKit bug 232088 is still open [B25]. MDN's flat claim that *"the
   `https:` requirements are ignored when the `Secure` attribute is set by
   localhost"* [B26] is true of two engines out of three.

**What it costs, stated honestly.** A token in `sessionStorage` is readable
by script running in the app's origin, where an `HttpOnly` cookie would
not be. That trades an unavoidable exposure (F4) for one this design
already has to defend against anyway — see A5, where the answer is that
user content is never served inline and the app carries a restrictive CSP.
The secondary cost is per-tab scope: a new tab has no token and must be
re-launched. For a single-user local tool that is a feature, not a defect.

### Attack by attack

#### A1. CSRF from any page the user visits

**The attack.** The user has the pelfs tab open, then visits an unrelated
site. That site issues requests at `http://127.0.0.1:PORT`. By F2 it can:
being HTTPS is no obstacle, because loopback is not mixed content. By F6 a
GET or a form POST arrives without any preflight at all. Anything the
browser attaches credentials to is an action taken as the user.

**The primary control is that there are no credentials to attach.** Per the
section above, the API's credential is a header the SPA sets from
`sessionStorage`. A cross-origin page cannot read that storage (it is
origin-scoped, port included) and cannot make the browser attach anything
in its place. That is the answer, and everything below is defence in depth
against the case where it is wrong.

**The middleware, in the order it runs**, one function so the order is a
property of the code rather than of a router:

1. **`Host` allowlist** (A2) — first, because everything after it assumes
   the request was addressed to this server.
2. **`net/http.CrossOriginProtection`** [B22] — standard library, no new
   module, and it rejects `Sec-Fetch-Site: same-site`, which by F3 is what
   a page on another loopback port looks like. Its two documented gaps are
   closed by the two items that follow.
3. **`Origin`, when present, must string-equal the one origin this listener
   serves** — computed once at startup from the port the listener actually
   got. Not a prefix match, not a parsed-host comparison. Note the
   interaction with `Referrer-Policy: no-referrer`: that policy makes the
   browser send `Origin: null` on form submissions and `no-cors` fetches
   [B27], so `null` must be treated as *absent-and-therefore-rejected* on
   authenticated routes, never as a pass.

   **3b. PROVENANCE, which is what this rule actually is.** An earlier
   draft of this document, and the test table below, said "`Origin` absent
   on an `/api/v1` request → 403". **That is wrong as written and it would
   have refused every read the real page makes:** current browsers send NO
   `Origin` header on a same-origin GET, by the Fetch spec. What is
   required is *positive evidence that the request came from our own page*,
   and there are two acceptable forms of it — a matching `Origin`, **or**
   `Sec-Fetch-Site: same-origin`. It is the request carrying **neither**
   that gets the 403. That is `CrossOriginProtection`'s documented
   fail-open gap closed, and it is set on every surface that carries a
   credential of ours (`internal/httpguard`, `policy.provenance`).

   **The consequence for anyone driving this with `curl`, because it will
   look like a bug:** a non-browser client sends neither header, so
   `curl http://127.0.0.1:PORT/api/v1/files` answers 403 no matter how
   correct the session token is. It needs
   `-H 'Sec-Fetch-Site: same-origin'` (or an exact `Origin`). This is
   working as intended — a header a browser refuses to let a page forge is
   exactly the signal being asked for — and it is why the surfaces that a
   non-browser legitimately reaches (`SurfaceToken`, `SurfaceExternal`,
   `SurfaceTicket`, `SurfaceNavigation`, `SurfaceApp`) do not carry the
   requirement at all.
4. **`X-Pelfs-Session: <token>` required on every `/api/v1/*` route,
   including GET.** This is the credential *and* the preflight trigger:
   by F6 a non-safelisted request header forces an `OPTIONS` preflight
   cross-origin, and this server emits no `Access-Control-Allow-*` header
   on any surface, so the preflight fails and the real request is never
   sent.
5. **`Content-Type: application/json` required on every mutating route**,
   because it is not CORS-safelisted [B11] and is therefore a second, free
   preflight trigger — and because Fetch's own text warns about servers
   that accept `text/plain` bodies as JSON [B11]. OWASP makes the same
   recommendation.
6. **No `Access-Control-Allow-Origin` on any surface, ever.** There is no
   legitimate cross-origin consumer of any route here. A test asserts the
   absence, because the way this protection gets deleted is somebody
   "fixing CORS".
7. **Never mutate state on GET, HEAD or OPTIONS** — the standard library's
   own instruction [B22], and the reason the publish route is a POST and
   the download route carries no authority.

**LNA is a bonus, not a control.** By F7, on Chrome ≥142 and Firefox ≥153
a public page's `fetch`/`img`/`iframe` at `http://127.0.0.1:PORT` now needs
a user permission grant, and a public *plain-HTTP* page's fails outright.
That removes the drive-by case for most users on most browsers. It does not
cover top-level navigation or `window.open` in Chromium, does not cover
Safari at all, and can be turned off by enterprise policy — and the spec
says in as many words that a service *"must be designed and implemented to
defend against CSRF on its own, and should not rely on a UA"* [B14]. So it
changes nothing in the list above.

**Where the WebDAV surface sits, and why the right action is to do
nothing.** Every WebDAV method except `GET`/`HEAD`/`POST` is
non-CORS-safelisted [B11], so a cross-origin attempt forces a preflight;
and `x/net/webdav`'s `handleOptions` emits only `Allow`, `DAV: 1, 2` and
`MS-Author-Via` — **no CORS headers at all** (`webdav.go:191-211`, read in
the module cache). The preflight therefore fails and `PROPFIND`, `PUT`,
`MKCOL`, `MOVE`, `COPY`, `DELETE`, `PROPPATCH`, `LOCK` and `UNLOCK` are
unreachable from a cross-origin page **by construction**. `POST` lands in
`handleGetHeadPost`, which is read-only and 405s a directory
(`webdav.go:213-240`). Keep it that way, and assert it.

**GET is the residual hole, and it is why downloads are ticketed.** By F6 a
cross-origin page can *cause* a GET — `<img>`, `<script>`, `<iframe>`,
`<link>`, `<form method=GET>`, a top-level navigation, `window.open` — even
though it cannot read the response. A plain `<a href>` download from the
app's own page cannot carry `X-Pelfs-Session`, so authorizing downloads by
ambient credential would mean exempting GET from control 4: exactly the
exemption an attacker needs, and exactly the shape of the Transmission bug
in A2.

**So: `POST /api/v1/download` (fully authenticated) returns an opaque
single-use ticket with a short TTL; the page navigates to `/d/<ticket>`;
that route accepts no session token and no cookie, validates and burns the
ticket, and serves the bytes.** Three good consequences: a cross-origin
`<img src>` at `/d/…` has 256 bits to guess; the byte-serving path has no
ambient authority whatsoever; and the URL that lands in the download
history is already spent by the time it is written.

#### A2. DNS rebinding

**The attack.** The attacker controls `evil.example.com`, which resolves —
on a second lookup, after their page has loaded — to `127.0.0.1`. Their
page is then, to the browser, **same-origin** with the service on
`127.0.0.1`, and every same-origin protection evaporates at once:
`Sec-Fetch-Site` reads `same-origin`, `Origin` reads
`http://evil.example.com`, and the page can read responses.

**This is the attack that has actually happened to services shaped like
this one.** CVE-2018-5702, Transmission ≤ 2.92: *"relies on
X-Transmission-Session-Id (which is not a forbidden header for Fetch) for
access control, which allows remote attackers to execute arbitrary RPC
commands, and consequently write to arbitrary files, via POST requests to
/transmission/rpc in conjunction with a DNS rebinding attack"* [B28]. Read
that twice: **the custom header *was* the CSRF defence, and rebinding
defeated it** by making the request same-origin. The same technique took
Deluge's WebUI, and the 2025 "Local Mess" incident — web pages bridging to
native Android apps over localhost ports — is what motivated LNA [B29].

**The defence is server-side `Host` validation and nothing else will do.**
NCC Group's guidance is explicit on both halves: *"the service should check
that all HTTP request 'Host' header values strictly contain
'127.0.0.1:3000' and/or 'localhost:3000'. If the host header contains
anything else, then the request should be denied"*, and *"Filtering DNS
responses containing private, link-local or loopback addresses … should not
be relied upon as a primary defense mechanism"* [B30].

```
allowed = { "127.0.0.1:<port>" }        // plus "localhost:<port>" only if
                                        // the listener answers on ::1 too
if r.Host not in allowed:  421 Misdirected Request, empty body
```

Exact strings, computed once at startup. **Not** `strings.HasPrefix`,
**not** `net.SplitHostPort` plus "is this a loopback IP" — a rebinding
attack's `Host` is a *name*, and the entire point is that the name resolves
to a loopback address. Only a literal allowlist rejects it.

**Browser DNS pinning is not a defence.** GitHub Security Lab: *"Browsers
try to resist DNS rebinding like this by caching DNS responses, but the
defense is far from perfect. … the DNS rebinding behavior is very browser
and operating system (OS) dependent"* — and it names the tooling that
automates it [B29].

**LNA helps here, partly and by design**, because it classifies on the
address actually connected to: *"This check MUST be performed for each new
connection made, as DNS rebinding attacks may otherwise trick the user
agent into revealing information it shouldn't"* [B14]. A rebound
`evil.com → 127.0.0.1` is still a public→loopback request and meets the
permission gate. It does not remove the `Host` check: not on Safari, not on
top-level navigations, not with the policy disabled.

**Two implementation notes that will bite.** First,
`internal/nfsmount.Serve` binds `tcp4` with the comment *"IPv4 explicitly:
mount_nfs is pointed at 127.0.0.1, and a hostname like 'localhost' can
resolve to ::1 where nothing listens."* The same holds here: allowlisting
`localhost:<port>` while listening only on `tcp4` produces a dead link
rather than a rejection, which is worse. **Launch at the literal
`127.0.0.1`** — which F1 also prefers, since the literal is
unconditionally a secure context while the name is not. Second, `421
Misdirected Request` is the correct status, and the response must carry no
body echoing the `Host` value.

#### A3. The bootstrap credential in the launch URL

**Where it leaks.** A token in a URL handed to `open`/`xdg-open`/`start`
lands in the browser's history and session-restore data; in the shell
history if the user pastes it; and in the **opener process's argv**, which
on Linux is `/proc/<pid>/cmdline` and readable by other local users unless
`hidepid` is set.

**The design: a single-use bootstrap token, not a session credential.**

- 32 bytes from `crypto/rand`, base64url, compared with
  `crypto/subtle.ConstantTimeCompare`;
- **TTL 120 seconds** — long enough for a cold browser start on a loaded
  laptop, short enough that a leaked argv is stale before anybody reads it;
- **exchanged exactly once** for the session token and then invalidated, so
  the value sitting in history is dead by the time the page has rendered;
- **in the fragment**, `#bt=…`, not the query. A fragment is never sent in
  a request line, so it is in no access log; and it is never in a `Referer`
  under any policy;
- `Referrer-Policy: no-referrer` on every response as well [B31] — though
  it is worth recording that the *default* policy already suffices for the
  query-string case: `strict-origin-when-cross-origin` sends *"only the
  ASCII serialization of the origin"* cross-origin, and from a
  potentially-trustworthy page to a non-trustworthy one *"a `Referer` HTTP
  header will not be sent"* at all [B31][B32];
- and the terminal prints the URL too, because the platform opener may not
  exist (a login node, a container) and because a user whose browser did
  not open needs the fallback every other pelfs verb already gives.

**One thing the no-cookie design gets for free**, worth naming because it
would otherwise be a trap: RFC 6265bis notes that `SameSite` cookies *"can
be set along with any top-level navigation, cross-site or otherwise"*
[B9] — so a cookie-based exchange *would* have worked on the launch
navigation. There is simply no reason to take the F4 exposure to get it.

**The paranoid variant, offered and not the default:** write the URL to a
`0600` file in the state directory and print the path, so the token never
enters any process's argv. That defeats one-click launch.

**The flag is `--open`, and it is OFF by default.** This document
originally proposed `--no-open` in this paragraph and `--open` in work item
U3, which contradict each other; the shipped verb resolves it in the safer
direction. **The URL is printed unconditionally**, first, before any
opener runs, and `--open` additionally hands it to the platform's opener.
So the default behaviour is exactly the "middle ground" above — the token
is in the terminal and the user's clipboard, never in a browser-launcher's
argv — and one-click launch is one word of typing away. It also means the
fallback for the one thing still unverified here (whether `#bt=` survives
Windows's opener) is a line the user has already been given rather than a
recovery step.

`openInBrowser` takes an argv rather than a shell, so the `#` is not a
comment character on macOS or Linux; Windows goes through
`rundll32 url.dll,FileProtocolHandler` rather than `cmd /c start`, which
eats `&` and treats a bare URL with a fragment inconsistently.

#### A4. Port scanning and drive-by discovery

**The attack.** A page enumerates `127.0.0.1:1..65535` looking for
something to talk to. Timing differences and error types leak which ports
are open even when responses cannot be read.

**What helps:** bind `127.0.0.1` only (never `0.0.0.0`, which would put the
UI on the machine's LAN address — a mistake that turns a local threat model
into a network one), and take a random port from the OS (`:0`), as
`nfsmount.Serve` already does.

**What must be said plainly: a random port is not a secret.** The ephemeral
range is tens of thousands of ports and a page can probe all of them in
seconds. So the random port is *friction*, not a control, and nothing in
this design may rely on it — which is exactly why A1's and A2's controls
have to hold on their own. The `Host` allowlist and the `Origin` check are
what make a found port useless.

#### A5. The stored-XSS problem: serving the user's own files

**The attack.** The volume contains `report.html`, which the user did not
write. Served from `http://127.0.0.1:PORT` with `Content-Type: text/html`,
its script runs **in the app's origin**, which holds the session token and
can call every `/api/v1` route with the right custom header. A file in the
federation becomes code in the UI.

**The controls, all of them, on every byte-serving route:**

- `Content-Disposition: attachment; filename="..."` — always, with no
  inline mode and no query parameter that switches it;
- `X-Content-Type-Options: nosniff`;
- `Content-Type: application/octet-stream` for everything, rather than a
  sniffed or extension-derived type — losing "the browser opens the PDF for
  me" is a real cost and it is the right trade for M1-M3;
- a restrictive `Content-Security-Policy` on the *app*, so that even a
  successful injection has nowhere to send anything:
  `default-src 'self'; script-src 'self'; connect-src 'self'; img-src
  'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none';
  base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
  (`'unsafe-inline'` for styles only, and only if the bundler needs it —
  check, and drop it if not.)

**Two things the implementation had to get right that this list does not
say.** First, M1's page is one hand-written HTML file with its script
inline, which `script-src 'self'` forbids and `'unsafe-inline'` would make
pointless, so the page carries a **per-response nonce** instead
(`default-src 'none'; script-src 'nonce-…'; style-src 'nonce-…'; …`) —
one file, and an injected `<script>` still cannot run.

Second, **the nonce must be base64url, not standard base64.** CSP's nonce
grammar accepts both alphabets, but the page is rendered through
`html/template`, which escapes a `+` in an attribute value to `&#43;`. A
standard-alphabet nonce therefore reaches the browser as a different
string than the header names, and works only by way of the parser's entity
decoding — which is one browser's behaviour away from a page whose script
silently stops running. `base64.RawURLEncoding` has no `+` and no `/`, so
the question does not arise (`cmd/pelfs/browse.go`, `servePage`).

**And the one structural answer, if inline preview is ever wanted:** serve
previews from a **second listener on a second random port**, which is a
different origin and therefore cannot touch the app's session token. Same
process, same filesystem layer, ~20 lines. That is the only way to render user
content inline without putting it in the app's origin, and it is the reason
`GET /preview` and `GET /icons/...` are dropped from the SVAR contract in
M3 rather than implemented.

#### A6. The WebDAV surface's own auth, and two principals

The external-client credential is a **different principal** from the
browser session, and the design keeps them apart everywhere:

| | browser session | WebDAV client |
|---|---|---|
| **minted** | by exchanging the single-use bootstrap token | by an authenticated `POST /api/v1/dav-credentials` from the UI, one per client |
| **carried as** | `X-Pelfs-Session` request header, from `sessionStorage` | `Authorization: Bearer` after the OAuth flow, or HTTP Basic preemptively (Cyberduck's `webdav.basic.preemptive=true`, per `docs/design-guiclients.md`) |
| **scope** | the whole app: browse, upload, publish, mint DAV credentials, read status | the filesystem only, at a fixed mode (`ro`/`rw`), and optionally a subtree |
| **may it publish?** | yes | **no** — a WebDAV client cannot trigger a checkpoint, which keeps the publish decision with the person, not with a background sync |
| **revoked** | by exiting; by a "sign out" that rotates the session secret | individually, from the UI, immediately; and collectively at process exit |
| **listed** | n/a | in the UI with a label, creation time and last-used time, because a credential you cannot see is a credential you cannot revoke |
| **accepted at** | `/`, `/assets/*`, `/api/v1/*`, `/events` | `/dav/*` only |

Two rules make that table enforceable rather than aspirational: a session
token at `/dav/*` is a **401**, and a Basic credential at `/api/v1/*` is a
**401**. Both are rows in U1's test table.

**What Basic over loopback gives up**, stated as plainly as
`docs/design-guiclients.md` states it: the credential crosses the loopback
socket in base64, readable by anything that can capture loopback traffic on
that machine — root, or the owner's own uid. That is weaker than Digest and
enormously stronger than the loopback NFS export shipping today, which
advertises `AUTH_NULL` and, in `internal/vfsbilly/perm.go`'s own words,
means *"Any local process can dial the loopback port and claim any uid it
likes."*

#### A7. The OAuth authorization endpoint, which is the juiciest target here

Verification 2 puts an authorization server on the same loopback origin as
the browser session. That is the most attackable thing in this design, and
it is worth being explicit about why: **`/oauth/authorize` turns an
authenticated browser session into a bearer token and hands it to a
URL supplied in the request.** Every other route in this design gives an
attacker one action; this one gives them a credential.

**The attack.** A page the user visits navigates their browser to
`http://127.0.0.1:PORT/oauth/authorize?client_id=…&redirect_uri=http://attacker/…&…`.
If the endpoint mints a code from the existing session and redirects, the
attacker's server receives the code, exchanges it, and holds a token for
the user's federation prefix for as long as pelfs runs. Note what does
*not* save us: by F6 a top-level navigation needs no preflight and by F7
top-level navigation is the one thing LNA does **not** gate in Chromium.

**Seven controls, and none is optional.**

1. **`Host` allowlist and the standard CSRF guard first**, as everywhere
   else (A1, A2). A rebound `Host` must never reach this handler — recall
   from A2 that rebinding is precisely what defeated Transmission's custom
   header [B28].
2. **A live browser session is required — and it is a PER-PROCESS fact,
   not a per-request one.** `/oauth/authorize` with no session at all
   renders a page saying "open pelfs from your terminal first", never a
   login form and never a redirect.

   **Why it cannot be per-request**, stated because the weaker check is
   easy to mistake for the stronger one and because a later reader will
   want to "tighten" it: this route is reached by a **navigation**
   Cyberduck opens, so the request cannot carry `X-Pelfs-Session` (control
   7). The session token lives in `sessionStorage`, which is scoped to the
   tab that minted it — so the *new tab* Cyberduck opens could not read it
   even if script were available, and the consent page runs none by
   design. There is no request-level session binding available on this
   route on a loopback origin. Any design that claims one is claiming it
   from a cookie, and a cookie on `127.0.0.1` is shared with every other
   local service the browser talks to (F4). So control 2 answers "is
   anybody signed in to this process", which is a real gate — it means a
   `pelfs browse` nobody has opened cannot be driven to mint anything —
   and **the weight is carried by control 4**, the per-download
   `client_id`, together with control 6. This is a limitation and it is
   named as one at `localoauth.SessionPresence` rather than papered over.
3. **`redirect_uri` is matched against an exact-string allowlist** — the
   one URL pelfs itself wrote into the profile it generated, including
   scheme, host, **port** and path. Not a prefix match, not a host match,
   not "is it loopback". An unmatched `redirect_uri` renders an error
   **on pelfs's own page** and does not redirect anywhere, because
   redirecting to an unvalidated URI is the vulnerability.
4. **`client_id` is a secret, minted per profile download**, 32 bytes from
   `crypto/rand`, compared in constant time. Possessing the profile is what
   identifies the client, so an attacker who has not been handed a profile
   cannot even name a valid client.
5. **PKCE `S256` is required**, not merely accepted. Cyberduck sends it by
   default (`isOAuthPKCE()` → `true` [W13]), so requiring it costs nothing
   and means a stolen code is useless without the verifier.
6. **One real user gesture, on a consent screen, on EVERY authorization**
   (Verification 2e). This is the control that specifically defeats the
   silent-drive attack: an `/authorize` that cannot complete without a
   click cannot be completed by a navigation the user did not make. The
   screen names the client, the scope, the volume and the redirect target —
   so a user who *is* driven there sees an authorization request they did
   not ask for, which is the only signal a human can act on.

   **This document originally said "remembered per `client_id` for the
   life of the process". Do not reinstate that.** Remembering consent at
   `/authorize` gives the attack back everything this control takes away:
   after one legitimate click, a later navigation mints codes silently. The
   convenience it was buying — no re-prompt on a reconnect — is delivered
   by the **refresh token** instead, which is where the client actually
   asks for it (Verification 2e).
7. **`X-Pelfs-Session`-style header rules do not apply here and cannot.**
   `/oauth/authorize` is reached by a *navigation* Cyberduck triggers, so
   it cannot require a custom header — which is exactly why controls 3, 4
   and 6 have to carry the weight. Say so in the code comment, because the
   natural instinct of a later maintainer is to "make it consistent" with
   the API routes, and the consistent version does not work.

**Scoping.** A token issued here is strictly weaker than the browser
session:

| | browser session | OAuth token for a DAV client |
|---|---|---|
| reaches | app, API, events, publish, credential minting | `/dav/*` only |
| may publish | yes | **no** — a checkpoint stays a human decision |
| may mint credentials | yes | no |
| may reach `/oauth/*` | yes | no |
| filesystem scope | the volume, at the session's mode | the volume, at the **scope in the grant** (`pelfs.read` or `pelfs.read`+`pelfs.write`), never wider than the session's own mode |
| lifetime | the process | `expires_in` (recommend 1 hour), refreshable while the process lives |

A `--rw` session may grant a read-only DAV token; a read-only session may
never grant a writable one. That check is at grant time *and* at request
time, because the session's mode cannot change mid-life but a future
version might let it.

**Revocation, which is the part that is easy to get wrong.** Everything the
authorization server issues lives **only in memory** and dies with the
process:

- **no persistence at all** — no tokens in the state directory, no refresh
  tokens on disk, nothing in the volume. `pelfs browse` exiting is a
  complete revocation of every credential it ever minted, and that property
  is worth more than the convenience of surviving a restart;
- the signing/lookup material is a per-process random key, so a token from
  a previous session does not validate against a new one even if the port
  is reused;
- **individual revocation from the UI**: the credential list shows each
  issued grant with its client label, scope, issue time and last-used time,
  with a Revoke button, exactly as the Basic credentials do (A6). A
  credential the user cannot see is a credential the user cannot revoke.
- **authorization codes are single-use with a 60-second TTL**, bound to
  `client_id`, exact `redirect_uri` and the PKCE challenge; a replayed code
  is a hard failure and is counted, because a replay is either a bug or an
  attack and both deserve a number.

**And one thing to keep off this surface entirely:** the federation bearer
token. pelfs's OAuth server issues *its own* tokens for *its own* WebDAV
endpoint. It never re-issues, wraps, or exposes the pelican credential — as
"What sets the bar" says, the federation token never reaches the browser or
any client, and adding an authorization server must not quietly change
that.

#### A8. What is deliberately not defended against

Named so nobody mistakes silence for coverage:

- **A malicious process running as the user.** It can read the state
  directory, which holds the signing key and the volume keys; the control
  socket's `0600` is a boundary against *other* users, not against the
  user's own processes. Nothing a loopback HTTP server does changes this,
  and it is the same posture the rest of pelfs has.
- **Loopback traffic capture** by root or by the same uid. See above.
- **A compromised browser or a malicious extension.** An extension with
  host permissions for `127.0.0.1` is inside the session by definition.
- **The user pasting the launch URL somewhere public** within the 120-second
  window.

---

## The two-surface design, and what each surface owes the other

Verification 3 forces this and the design should be honest that it is two
protocols, not one. What it must not be is two *filesystems*.

### The split

| surface | routes | principal | what it is for | what it must never do |
|---|---|---|---|---|
| **App** | `/`, `/assets/*` | none — a static bundle with no secrets | serve the embedded bundle | be served with a permissive CSP, or from any Host but the allowlist |
| **JSON** | `/api/v1/*` | `X-Pelfs-Session: <token>` | everything the SPA does: list, mkdir, rename, move, copy, delete, upload, publish, status | invent an operation `internal/vfsbilly` cannot express |
| **Events** | `/events?s=<token>` | the same token, in the query because `EventSource` cannot set headers | SSE: SSO prompts, durability state, upload and publish progress | carry file content, or a federation token |
| **Download** | `/d/<ticket>` | single-use ticket only; **session token rejected** | serve bytes to a plain navigation | ever return `Content-Type: text/html` for user content |
| **WebDAV** | `/dav/*` | `Authorization: Bearer` (Cyberduck, via the OAuth flow) **or** HTTP Basic, per-client (everything else) | external clients: Cyberduck, Mountain Duck, WinSCP, rclone, macOS `mount_webdav`, `duck` | accept the session token, or emit any `Access-Control-Allow-*` header |
| **OAuth (navigation)** | `/oauth/authorize` | a live browser session **plus one consent gesture, every time**; then PKCE + a per-download `client_id` | issuing DAV credentials to Cyberduck with no typing | redirect anywhere not on the exact-string allowlist, or complete without a user gesture |
| **OAuth (back channel)** | `/oauth/token` | the authorization code + PKCE verifier, or a refresh token, **in the body** | the exchange Cyberduck's HTTP client makes with no browser involved | require a browser-only signal — see below |

**`POST /oauth/token` is its own surface, and the reason is worth the
extra row.** This document originally put it on "the API surface minus the
session requirement". That cannot work, and it fails at 100% rather than
at the margin: the caller is not a browser and is not our page — it is
Cyberduck's Apache HttpClient (or rclone's, or `curl`) making a
back-channel POST. It sends no `Origin` and no `Sec-Fetch-Site`, so the
provenance rule answers **403**; and its body is
`application/x-www-form-urlencoded`, which RFC 6749 §4.1.3 mandates, so the
JSON rule answers **415**. A profile pointed at such an endpoint fails
*every* exchange. `httpguard.SurfaceToken` keeps everything that still
applies to a non-browser POST — the `Host` allowlist, `CrossOriginProtection`
(an unsafe method with `Sec-Fetch-Site: same-site` is still rejected, and
by F3 another loopback port is same-site), the exact-`Origin` match
whenever an `Origin` is present at all, no cookie in, no `Set-Cookie` out,
no `Access-Control-Allow-*`, and the full security-header set — and drops
exactly the two rules a non-browser cannot satisfy.
`localoauth.TestTokenEndpointCannotLiveOnSurfaceExchange` pins it, so
nobody moves the route back for consistency's sake.

### What the JSON surface owes WebDAV

**Semantic restraint.** Every JSON operation maps 1:1 onto a
`billy.Filesystem` call, which means it also maps onto something WebDAV can
express. The temptation the SVAR contract creates is `PUT /files` with
`{"operation":"move","ids":[...],"target":...}` — a *batch* move of N paths
in one request. There is no atomic N-way rename in `internal/overlay`, in
WebDAV, or in POSIX. So the JSON handler performs it as N sequential
`Rename` calls and returns a per-id result array (which the contract's
`ResponseMulti` shape already anticipates [W8]), reporting partial success
honestly. A surface that reported "moved" for a batch where the fourth
rename hit `EACCES` would be lying in the one place a user cannot check.

**The temp-name-and-rename convention.** `docs/design-guiclients.md`
establishes this as a *durability* requirement, not a compatibility one: if
a transfer dies mid-upload, the bytes already written are in the overlay
and the next checkpoint publishes a truncated file under its final name.
The mitigation there is to rely on the client's own
temp-name-and-rename (WinSCP above 100 KB; Cyberduck's editor). A browser
has no such convention, so **the JSON surface must implement it itself**:
upload to `<name>.pelfs-part`, `Rename` on completion, and unlink on
abandonment. The same convention makes the two surfaces legible to each
other — a `*.pelfs-part` file visible over WebDAV is obviously an upload in
flight, and the reverse is true of a `.filepart` from WinSCP.

### What WebDAV owes the JSON surface

**Nothing structural — and this is the useful finding.** `x/net/webdav`'s
handler is a bare method dispatch over five filesystem calls
(`webdav.go:61-101`), and three properties of it fall out that the threat
model depends on:

- **It emits no CORS headers at all.** `handleOptions` sets exactly
  `Allow`, `DAV: 1, 2` and `MS-Author-Via: DAV`
  (`x/net@v0.56.0/webdav/webdav.go:191-211`). No
  `Access-Control-Allow-Origin`, no
  `Access-Control-Allow-Methods`. So a cross-origin browser preflight for
  `PROPFIND`, `PUT`, `MKCOL`, `MOVE`, `COPY`, `DELETE`, `PROPPATCH`,
  `LOCK` or `UNLOCK` gets no permission and the browser drops the real
  request. **The entire WebDAV write surface is unreachable from a
  cross-origin page by construction, and the correct action is to change
  nothing.**
- **`GET`/`HEAD`/`POST` all land in `handleGetHeadPost`, which is
  read-only**, and it returns `405` for a directory
  (`webdav.go:213-240`). So the only browser-reachable cross-origin WebDAV
  verbs are reads of single files — which still need the Basic credential,
  and which are covered by the same `Host`/`Origin` guard as everything
  else.
- **`Range` works, for free.** `handleGetHeadPost` calls
  `http.ServeContent` (`webdav.go:238`), and `webdav.File` is
  `http.File` + `io.Writer` (`file.go:53-56`), so `Seek` is mandatory and
  `billy.File` already has it (`internal/vfsbilly/file.go:132`). This
  **retires a concern from `docs/design-guiclients.md`**, which noted that
  `go-billy`'s `helper/iofs` file does not implement `io.Seeker`, so
  `http.FS` + `http.FileServer` could not serve a `Range`. Going through
  `webdav.File` — or calling `http.ServeContent` with the `billy.File`
  directly on the download surface — avoids `iofs` entirely and the
  problem does not arise.

### The adapter, and the four places "five methods, all present" was too cheap

This document said the adapter was "five methods, all present" and
therefore nearly free. The *shape* was right — `internal/vfsdav` wraps
`billyFS` as a `webdav.FileSystem` and `billy.File` as a `webdav.File`
(which needs `Readdir(count int)`, the one method billy puts on the
*filesystem* rather than the file, so the wrapper holds a path and calls
`billyFS.ReadDir`); locks are `webdav.NewMemLS()`, and
`docs/design-guiclients.md` already establishes that Cyberduck does not
lock, so the two known litmus `locks` failures are off the path.

**But four of the five methods could not be a pass-through, and each one
was a wrong status code or a lost file rather than a style question.**

- **`DeadPropsHolder` is not optional.** x/net handles the ten live `DAV:`
  properties itself and hands everything else to a `File` that implements
  `webdav.DeadPropsHolder`. Without one, **every PROPPATCH is answered
  403** and the `props` suite drops well below the ceiling the adapter has
  to hold. `internal/vfsdav/props.go` is an in-memory store, deliberately:
  a client's scratch properties (Cyberduck's, Finder's, litmus's) are
  worth exactly as long as the connection, and writing each into the
  overlay would put them in a published generation forever. The
  properties that *should* be durable — `Win32LastModifiedTime`, the
  `Win32FileAttributes` read-only bit — are not dead properties at all;
  they are translations onto `Chtimes` and `Chmod`, which is
  `docs/design-windows.md`'s own work item. The consequence is stated
  where a user meets it rather than discovered: **a property set over
  WebDAV is gone when the process exits.**
- **A symlink must be followed on OPEN, not only on `Stat`.** An open of
  the link inode answers `ESTALE` on the first read — and x/net reads
  **512 bytes of every file whose extension has no MIME type**
  (`findContentType`), so a followed link **vanished from its own
  listing**. `OpenFile` takes the handle on the resolved path and answers
  `Stat` about the requested one: the bytes come from the target, the name
  the client sees is the name it asked for.
- **`Mkdir` cannot be `MkdirAll`.** MKCOL distinguishes two failures and
  billy collapses both: a missing or non-directory parent must be
  `os.ErrNotExist`, which x/net turns into **409 Conflict**, and an
  existing name must be `os.ErrExist`, which becomes **405**. `MkdirAll`
  would create the parents and answer **201** in the first case, which is
  a protocol violation that looks like success.
- **`RemoveAll` cannot be `Remove`.** WebDAV defines DELETE as
  `Depth: infinity` on a collection; billy's `Remove` unlinks one name and
  refuses a non-empty directory. The recursion is the adapter's,
  depth-first, never on the root itself — and **a symlink is removed as
  itself**, because following one there would delete the *target* and
  leave the link, which is the one mistake a recursive delete cannot take
  back.

**What the adapter deliberately does not show.** A symlink to a regular
file is followed. A symlink to a **directory** is hidden and counted,
which is narrower than `docs/design-windows.md`'s "follow within the
volume" — path resolution in `internal/vfsbilly` is component-by-component
and does not traverse a symlinked directory component, so a followed
directory link would list as a collection whose PROPFIND then failed.
Hiding it is the honest answer until component-wise link resolution
exists; it is in `docs/known-issues.md` as an open limitation rather than
buried here. Dangling links, FIFOs, sockets and device nodes are hidden
and counted for the same reason: no client could render them. Hidden
entries are **counted, not swallowed**, so a caller can say so.

### The routes, concretely

The SVAR contract is the starting point and two of its routes are replaced,
for reasons the contract itself creates:

| SVAR route | pelfs | why |
|---|---|---|
| `GET /files` | **kept, and it is not optional** | it means the **ROOT directory**, not the tree, and the component fetches it at boot. Dropping it is a page that never renders |
| `GET /files/{path}` | kept, one directory, capped | see Verification 3 |
| `GET /info`, `GET /info/{id}` | kept, and it grew a job | the un-`id`'d form is the drive/capacity panel and the **durability counters**; the `{id}` form is where the listing's true counts and `PartialSearchNotice` are served, because the array cannot carry them |
| `POST /files/{id}` (`NewFile`) | kept | mkdir and touch |
| `PUT /files/{id}` (rename) | kept | one `billyFS.Rename` |
| `PUT /files` (move/copy, batch) | kept, per-id results | see "semantic restraint" above |
| `DELETE /files` | kept, per-id results | ditto |
| `POST /upload` | **kept as-is for now** | it is a single multipart POST with no progress and no resume [W4]; resumable upload is deferred — see below. Streamed with `r.MultipartReader()`, never `ParseMultipartForm`, and through `.pelfs-part` |
| `GET /direct` | **replaced** by `/d/<ticket>` | a download must not be an ambient-credential GET; see the threat model |
| `GET /preview`, `GET /icons/...` | dropped | previews render user content; see "the stored-XSS problem". The component's own CDN icon callback is turned off with `icons="simple"` (Verification 3) |

**Eight routes, eleven patterns, and every id route is registered TWICE.**
That is not tidiness; it is a hole in `net/http`'s router that two
implementation passes hit independently.

The component sends an id as a full path percent-encoded into **one**
segment — `/api/v1/files/%2Fdir-0%2Fdir-1`. `ServeMux` matches that as a
single segment and `PathValue` returns it decoded exactly once, which is
what makes both the ordinary case and a filename containing the literal
characters `%2F` work; `r.URL.Path` has already collapsed the `%2F` into a
real slash and is unusable. So `{id}` is the contract.

Its hole, found by probing `net/http` rather than by reading it: **a
segment that is exactly `%2F` does not match a `{id}` wildcard at all.**
Unescaped it is a trailing empty segment and the matcher answers 404 — or,
worse, falls through to the SPA and returns HTML to a caller expecting
JSON. The component reaches the root listing through the un-pathed form so
it never notices, but **"create a folder in the root" is
`POST /api/v1/files/%2F`** and would 404 for exactly this reason.

The `{id...}` sibling closes it. It is strictly less specific, so it takes
nothing away from `{id}`; it catches the bare `%2F` (`PathValue` gives
`/`) and, as a bonus, the unescaped form a person types at a terminal
(`/api/v1/files/dir/sub`). `webapi.Routes` registers both for every id
route and `routing_test.go` fails a table that forgets one.

**And the cap's numbers travel beside the array, never inside it.** The
provider requires a bare JSON array from `loadFiles` and drops response
headers on that path, so:

| carrier | who reads it |
|---|---|
| the array | the component |
| `X-Pelfs-Listing-Returned` / `-Total` / `-Cap` / `-Truncated` / `-Hidden` | anything that can read a response header — the app shell, `curl`, a gate script |
| `GET /api/v1/info/{id}` | the app shell, for the numbers **and** for `PartialSearchNotice`'s exact sentence, so no surface re-words it |

### Upload: whole-file for now, and the ceiling that implies

**Resumable upload is deferred.** The component's provider does a single
multipart `POST` via `fetch` [W4] and the first milestones use it as it is.
That is a defensible starting point — but the ceiling has to be written
down, because it is the thing a physicist will hit first and the failure is
silent-ish.

**What a whole-file browser upload actually costs, in order of what bites
first:**

- **No resume.** A dropped connection at 90% of a 68,497,408-byte SIF —
  this repo's own reference file size, from `docs/design-apptainer.md` —
  starts over. `docs/design-guiclients.md` measured SFTP's `reput`
  succeeding on exactly this and listed the browser's lack of it as a
  weakness; that assessment stands, it is just not being fixed yet.
- **No progress.** The provider uses `fetch`, which still gives no upload
  progress events without a duplex-stream dance, so the UI cannot show a
  bar for the upload leg. It *can* show the durability state afterwards,
  which is the part that matters more (see the durability section) — but
  "did my 68 MB file get anywhere" has no answer until the request
  finishes.
- **Memory.** A `FormData` upload of a `File` is streamed by every current
  browser rather than buffered whole, so the browser side is not the
  binding constraint. **The server side is ours to get right:**
  `r.ParseMultipartForm(n)` buffers `n` bytes in memory and spills the rest
  to a temp file, which for a large upload means writing the payload to
  disk *twice* — once to the temp file, once into the overlay. Use
  `r.MultipartReader()` and stream each part straight into
  `billyFS.OpenFile`, never `ParseMultipartForm`. This is a one-line choice
  with a whole-file-sized consequence, and it is the single most important
  implementation note in this section.
- **Timeouts.** A minutes-long single request must survive
  `http.Server.WriteTimeout`/`ReadTimeout`, so the upload route needs its
  own generous per-request deadline rather than the server default; and any
  intermediary is out of the picture, because loopback has none.
- **A partial upload must not be published under its final name.** This is
  a durability requirement, not a niceness: upload to
  `<name>.pelfs-part`, `Rename` on completion, unlink on abandonment.
  Whole-file upload makes this *more* important, not less, because a
  dropped connection is guaranteed to leave a partial file rather than a
  resumable one.

**The practical ceiling, stated so it can be tested:** whole-file upload is
fine for the documents-and-plots case and workable for a single SIF on a
good link. It is not the mechanism for a 200-file, 13.7 GB drag — for that,
today, the answer is a WebDAV client or `pelfs mount`, and the UI should
say so rather than let someone discover it at 80%.

**When resume is picked up, the named investigation is `tus` plus `uppy`.**
Worth recording why that is the right shape rather than a hand-rolled
ranged `PUT`: `tus` is an open resumable-upload protocol with an existing
Go server implementation and `uppy` is a client that speaks it, so the work
becomes wiring rather than protocol design; and it plugs into the
component at `api.intercept("upload-file")` without touching the rest of
the contract. The pelfs side it needs already exists —
`billy.File.WriteAt` (`internal/vfsbilly/file.go:118`) is the same
random-access write that makes SFTP's `reput` work in
`scripts/sftp-clients-docker.sh`'s measured `resume: ok` row — so the
capability is there and only the protocol is missing.

---

## Wiring: the two things that only appeared when the pieces were connected

Every surface above was built and tested on its own before anything was
mounted on one listener, which was the right order — and it left exactly
two facts that no single-package test could have found. Both are recorded
here **with their fixes**, because in each case the shape that looks wrong
is the correct one and a later reader's instinct will be to "clean it up".

**1. The WebDAV handler cannot be a line in the route table.**
`vfsdav.New` reads the filesystem's **write capability at
construction** — `billy.CapabilityCheck(bfs, …)` — so it cannot be built
before there is a filesystem. But the route table is built **before the
volume opens**, deliberately, and that ordering is not negotiable: it is
what guarantees a device-flow prompt has a page to appear on (see "The
ordering problem"). So `/dav/` is registered to a **delegator** that
answers **503 with `Retry-After: 2`** until `setReady` installs the real
handler.

Two details are load-bearing. It is **503 and not 401**: the credential is
not the problem, and a WebDAV client told 401 goes looking for a password
it was never meant to have. And the alternative — a lazy
`billy.Filesystem` that answered the capability question from
`browseArgs.rw` — was rejected on purpose, because it would put a *second
opinion* about writability next to billy's, and billy's is the one every
other surface asks. One model, one answerer (`internal/fsperm`'s own
discipline).

**2. `--test-hooks`'s synthetic download source sits AHEAD of the real
one, and that is the fix, not the bug.** The consequence has to be stated
plainly because it looks like an oversight: **a `--test-hooks` session
cannot mint a working ticket for a real file in the volume.** The
synthetic source shadows the volume's.

That is deliberate. A browser-driver run passes `--test-hooks` precisely
to reach states the volume is not in, and a driver that had to create a
file before it could exercise the ticket round trip would be testing the
*upload* path instead of the ticket. The flag is off in every real session
— its help text says `NEVER on a real volume` — so the real source is what
a user ever meets. **Do not "fix" this by reordering:** the reorder makes
the ticket test depend on the upload path, which is the coupling the flag
exists to avoid.

---

## Durability, and the one ambiguity that must never reach the screen

`docs/design-guiclients.md` did this analysis and it is not redone here.
Its numbers, from `cmd/pelfs/mountgen.go`, are the input:

| trigger | value | source |
|---|---|---|
| periodic checkpoint | **5 minutes**, `--snapshot-interval` | `cmd/pelfs/main.go:172` |
| write-pressure, bytes | **1 GiB** staged | `checkpointBytes`, `mountgen.go:1836` |
| write-pressure, inodes | **200,000** dirty | `checkpointInodes`, `mountgen.go:1861` |
| seal at exit | always, unless `--no-seal` | `sealAtExit`, `mountgen.go:2125` |

and its three levels of durability are the model the UI must render:
locally durable immediately (the overlay commits each write before
returning; a crash *"cuts a file back rather than serving it as zeros"*);
in the federation at the next checkpoint; named by the branch at the same
event. Its identified trap is the one this UI makes worse: **200 documents
at ~2 MB fires neither pressure trigger**, so a finished drag-and-drop can
sit unpublished for up to five minutes — and a browser tab, unlike a
mount, has no unmount.

### The correction: a browser CAN express seal-on-idle, better than SFTP

`docs/design-guiclients.md` states that seal-on-idle is expressible only
over SFTP, because *"WebDAV cannot — HTTP is stateless and 'the client
went away' is indistinguishable from 'the user is reading'"*. That is true
of WebDAV. It is **not** true of this design, and the difference is
surface D.

The SPA holds an SSE stream open for the whole session. An SSE stream is a
single long-lived HTTP response; when the tab closes, navigates away, or
the browser is killed, the TCP connection closes and the server's
`Request.Context()` is cancelled. That is a real event, on the same
footing as an SSH channel close, and it arrives *sooner* than a
connection-count heuristic because there is exactly one stream per tab and
the SPA opens it on load. So:

- **seal on idle** = the last `/events` stream closed, **and** no write on
  any surface, for `min(30 s, --snapshot-interval)` — **and that formula
  is undefined at interval 0, which this document did not notice.**
  `--snapshot-interval 0` means "seal only at unmount", and it is a thing a
  user types on purpose: a session that must publish exactly once, at a
  moment of its own choosing. `min(30 s, 0)` is 0, which as a quiet window
  means "seal immediately" — the opposite of what was asked for. **Idle
  sealing is automatic publishing, so at interval 0 it is OFF**
  (`idleQuietWindow` returns 0 and the sealer does not run). A session that
  wants idle sealing and no periodic checkpoints makes the interval long
  rather than zero;
- with the **pressure path's backoff**, which is not optional: the
  existing pressure path doubles its wait to the interval on failure, and
  an idle seal retrying every 30 s against a broken federation would
  reproduce the "same warning forever" failure that backoff exists to
  prevent (`docs/design-guiclients.md`, item (a));
- and `navigator.sendBeacon` on `visibilitychange`/`pagehide` as a *hint*
  that shortens the wait to 5 s, never as the trigger — a beacon is
  best-effort by specification and a durability decision must not rest on
  one.

**The beacon needed a tolerance, and without it the hint never fired
once.** `pagehide` fires **before** the connection tears down, so the
beacon's arrival almost always *precedes* the unsubscribe that starts the
quiet window, by a few milliseconds. The obvious comparison — "is the
beacon newer than `idleSince`?" — therefore discards **every beacon that
did its job**, silently, and the feature reads as implemented and does
nothing. `idleHintLead` (5 s) is how far *before* the stream closed a
beacon still counts. Two further properties fall out of the same
ordering and are worth naming: a beacon cannot *start* a window (the
window only runs while the stream set is empty), and a beacon from a tab
that is merely hidden — `visibilitychange` on a minimise or a tab switch —
arrives while its stream is still open and therefore changes nothing.

And the beacon cannot carry `X-Pelfs-Session`, because `sendBeacon` sets
no request headers; the token is in the body, checked in constant time by
the same verifier the guard uses, on `SurfaceExchange`.

The WebDAV surface still cannot express it, exactly as the earlier
document says. The difference is that the browser surface can, and the two
share a process, so `browse` gets idle-sealing for both.

### What the UI must show, and the shape of the lie to avoid

**One badge per object, three states, two icons — never one checkmark.**

| state | what is true | what the UI says |
|---|---|---|
| **staged** | in the overlay, committed, survives `kill -9`, **invisible to the federation** | a filled dot, "on this machine" |
| **uploading** | packs in flight; `WriteStats.UploadBacklog` bytes behind | a moving arc, "sending" |
| **published** | named by generation G on branch B | a check, "in the federation (gen G)" |

The failure mode this table exists to prevent is a green check for the
first row. A file that looks uploaded and is not in the federation is the
worst possible ambiguity for this audience, because the user's next action
is to close the laptop and tell a collaborator the data is there. Two
distinct glyphs, a legend that is always visible, and a global line that
is unambiguous:

```
  14 files (412 MB) on this machine only — next automatic publish in 3m41s
  [ Publish now ]                                 branch: main   gen 87
```

**Where the numbers come from.** `overlay.FS.Stats()` already returns
`StagedBytes`, `DirtyNodes` and `DirtyEdges` — `checkpoint` reads exactly
those and uses `DirtyNodes == 0 && DirtyEdges == 0` as its "nothing
changed" fast path (`mountgen.go:1778-1781`). `stats.WriteStats` already
carries `UploadBacklog`, `RingUsed`/`RingFree`, `Packs` and
`UploadedBytes` (`internal/stats/stats.go:257-285`). Nothing new has to be
counted; it has to be *served*, on `GET /api/v1/info` and pushed on
`/events`.

### "Publish now" must be asynchronous, and that is not a detail

`control.Hooks.Publish` is wired to `genSession.checkpoint`
(`mountgen.go:2430`), and `checkpoint` takes `g.mu` and holds it across
the entire seal — fence, freeze, walk, upload, flip
(`mountgen.go:1772-1774`, `sealLocked` at `:1533`). On the 13.7 GB
drag-and-drop case that is minutes. Three consequences the UI has to
respect:

- **`POST /api/v1/publish` returns `202` with a job id**, and progress
  arrives on `/events`. A handler that blocked on `checkpoint` would hold
  an HTTP request open for minutes, hit every intermediary timeout there
  is, and give the user a spinner with no information. The job runs on the
  **session** context, not the request's — a request context is cancelled
  the moment the 202 is written, which would abort the seal it just
  accepted.

  **`phaseClock` cannot carry the progress, and this document said it
  should.** `phaseClock` reports at the *end* of a seal and has no
  subscription: there is nothing to read from it while the seal is
  running, so a stream fed from it would be silent for the whole minutes
  and then complete. What the stream carries instead is the **job**:
  `{id, state, reason, started, ended, summary, error}` where `state` is
  `running`/`done`/`failed`, plus elapsed time — enough for "publishing,
  1m12s" and for saying afterwards *which* generation the user is looking
  at and whether they asked for it (`reason` is `user` for the button and
  `idle` for the seal that runs when the last tab closes; a generation the
  user did not ask for is otherwise indistinguishable from one they forgot
  asking for). Per-phase progress during a seal is a change to
  `phaseClock`, not to this surface, and it is not made here.
- **A second concurrent request gets `409`**, not a queue. `g.mu` already
  serializes it; the API should say so rather than let two requests
  silently become one.
- **Writes may block during a publish**, because the seal freezes the
  overlay. The UI must disable upload and say "publishing — uploads resume
  in a moment" rather than let a drop fail with an opaque error.

And the fast path is worth surfacing verbatim: `checkpoint` returns
*"nothing changed; still at generation N"* when the overlay is clean, so a
user who mashes the button gets a truthful, cheap answer.

### The rest of the session-end story

- **`pelfs browse` runs in the foreground and seals at exit**, exactly as
  `pelfs mount` does. Ctrl-C is the unmount. Not a daemon by default; a
  background browse session that seals on a signal nobody sends is how
  data gets left staged for a week.
- **If the tab is closed with dirty state**, the SSE close starts the idle
  timer and the seal happens without the user. If the *process* is
  interrupted with dirty state, `sealAtExit` runs. If the machine dies,
  the overlay survives and a remount resumes it — which the UI should say
  on first load if it finds a non-empty overlay from a previous session,
  because "there is unpublished work here from before" is otherwise
  invisible.
- **`beforeunload` with dirty state** gets the browser's generic "leave
  site?" dialog. Use it, but do not rely on it: browsers suppress it
  without prior interaction and the wording is not ours.
- **Lease state belongs on the screen, not at the seal.**
  `docs/design-guiclients.md` item (c) makes this point for a long idle
  session: *"A suspended process runs no ticks: a laptop that closes its
  lid for three hours wakes with a lease that expired long ago."* The
  control socket's status already exposes `lease_state` with four
  meaningful values — `held`, `stale`, `interrupted`, `lost`
  (`mountgen.go:2398`) — and a browse session that has lost its branch
  must show that as a banner the moment it is known, because everything
  the user does afterwards is going to fail at the seal.
- **`pelfs browse` should default to read-only**, `--rw` explicit, for the
  reason the earlier document gives and one more: a read-only browse
  session cannot lose anything, cannot publish anything, and its entire
  threat model collapses to information disclosure. That is a much better
  default for the first thing a physicist runs.

---

## Federation SSO, end to end over the hook

The hook is `oauth2.SetVerificationURLHandler`, pelican commit
**`e55347e5a`**, *"oauth2: let an embedder handle the device-flow
verification URL"* — 68 lines added to `oauth2/oauth2.go` and 97 to its
test, and nothing else. Read at that commit, five properties of it shape
the design and three of them are constraints:

```go
type VerificationURLHandler func(verificationURL, userCode string)
var verificationURLHandler atomic.Pointer[VerificationURLHandler]
func SetVerificationURLHandler(handler VerificationURLHandler)
```

1. **It is process-wide**, an `atomic.Pointer`, one handler per process,
   and the commit says why: *"the TokenGenerationOpts that AcquireToken
   receives is built inside client and cmd, so an embedder calling
   client.DoGet has nothing to put a per-call field on."* So there is
   exactly one place in pelfs allowed to install it.
2. **It fires after the unconditional stderr write, never instead of it.**
   `announceVerification` prints, then calls the handler
   (`oauth2/oauth2.go` at `e55347e5a`). A headless `pelfs browse` on a
   login node still tells the user in the terminal, and a handler that
   fails silently costs nothing.
3. **It runs on the goroutine driving the flow and blocks it.** The doc
   comment is explicit: *"It runs on the goroutine driving the flow, after
   the URL has been written to stderr and before polling begins, so a
   handler that blocks delays the user's own approval."*
4. **It is one-way.** The handler learns that a flow *started*. Nothing
   tells it the flow finished, failed, or expired.
5. **It normalizes the two RFC 8628 shapes**: `verificationURL` is
   `verification_uri_complete` with `userCode` empty when the issuer
   supplied one, otherwise `verification_uri` plus the code to type. The
   caller does not have to know which.

### Who installs it, and when

`cmd/pelfs`'s `browse` path, once, at startup, and
`SetVerificationURLHandler(nil)` on exit. **Not** in a library `init()` and **not** in
`internal/pelicanobj`: a `pelfs mount` or `pelfs get` in the same binary
must keep the terminal behaviour, and a process-wide handler installed by
a package that both verbs import would change it for both.

### The transport to the browser: SSE

**SSE, not websockets, not polling.** The traffic is one-way
(server → client), a `text/event-stream` is a plain
`http.ResponseWriter` with `Flush()` and needs no new module, the browser
reconnects on its own with `Last-Event-ID`, and surface D exists anyway for
durability state and upload progress. `gorilla/websocket` is already in
the module graph as an indirect dependency (`go.mod:55`) so it would cost
nothing to add, but it buys a return channel this design does not need,
and it is a second framing to get wrong. Polling is the wrong answer for
the specific reason that the user is *sitting there waiting* — a 2-second
poll interval is 2 seconds of a person staring at nothing during the one
interaction that most needs to feel immediate.

### The handler itself: a registry, not a channel to a connection

Because of constraints 3 and 4, the handler must do the least possible
work and must not assume a browser is attached:

```
handler(url, code):
    prompts.Add(Prompt{ID: hash(url), URL: url, Code: code, At: now})
    return                       # immediately; no I/O, no lock held long
```

`prompts` is a small in-memory set with a TTL. Then a separate goroutine
fans out to whatever `/events` streams exist. Three reasons this
indirection is not over-engineering:

- **The handler must never write to a network connection.** It blocks the
  device flow, so a slow or half-closed SSE client would delay the user's
  own approval — the exact thing the commit's doc comment warns about.
- **There may be no browser attached yet.** The most likely moment for the
  first flow is *before* the page has loaded (see the ordering problem
  below), so the prompt has to survive until someone asks for it.
- **There may be more than one prompt.** `client.AcquireToken` has no
  global serialization around the device flow — no mutex, no singleflight,
  verified by reading `client/acquire_token.go` at `e55347e5a` (the only
  lock in the file is `authFailureMu`, around failure bookkeeping) — so two
  goroutines needing tokens for two namespaces can each open a flow. The
  registry is therefore a *set*, keyed by a hash of the URL so identical
  prompts dedupe, and the UI shows a list of cards rather than a modal.

**Because the hook is one-way, the UI must not block on it.** A prompt card
is dismissible, expires on a TTL (RFC 8628 device codes typically expire in
minutes, and the issuer's `expires_in` is *not* exposed to the handler —
so the TTL is ours to pick; 10 minutes, with the card greying out rather
than vanishing), and the real completion signal is that the operation which
was waiting succeeded. The UI says "waiting for you to approve at your
institution" and then, when the volume opens, "connected". It never says
"authorization complete", because the hook cannot tell it that.

### The ordering problem, which is easy to get backwards

Today, `pelicanobj.New` calls `primeCredential` *before* any frontend is
stood up (`internal/pelicanobj/fedstore.go:88`, called from `New`), and
`runMountGen` opens the volume before it mounts anything
(`cmd/pelfs/mountgen.go`). `primeCredential` is exactly where the device
flow will fire for `browse`, and deliberately so — it acquires **one**
credential covering read, create and modify up front, so the user approves
once at a moment they are watching rather than three times mid-I/O
(`fedstore.go:110-133`).

For a terminal that ordering is right. **For a browser it is exactly
backwards:** if the volume opens before the listener is up, the first
device-flow prompt is generated with no page to show it on, and the user
sees a hung browser tab while the URL sits in a terminal they were told
they would not need. So `runBrowse` must invert it:

```
1. bind 127.0.0.1:0 (tcp4), install the guard middleware
2. mint the bootstrap token; start serving; open the browser
3. install SetVerificationURLHandler
4. NOW open the volume (pelicanobj.New -> primeCredential -> maybe a flow)
5. stream prompts to the page that is already loaded
6. when the volume is open, the page transitions from "connecting" to the
   file view
```

Steps 1-3 touch no network and cannot fail on the federation, so the page
is guaranteed to be loadable before anything can prompt. This is a real
ordering requirement on new code, not an observation, and it is the reason
the SSO milestone is not simply "add a card".

**But the ordering does not, on its own, solve the case it was written
for — SSE snapshots do, and the registry section above is where to say
so.** "Loadable" is not "loaded". A prompt raised in the second between
the browser being launched and the page's `/events` stream attaching has
no stream to be pushed to, and the ordering cannot shrink that window to
zero: it is the browser's cold start, not ours. What closes it is that
**the registry is the state and `/events` carries snapshots, not deltas**:
the first frame a stream ever receives contains every live prompt, and so
does `GET /api/v1/info`. Nothing is delivered only on the edge, so a
prompt cannot be missed by arriving early — and, for the same reason, a
stream that drops and reconnects (a suspended laptop, a network blip)
cannot show a stale or half-updated view, and needs no `Last-Event-ID`
replay. The cost is bytes on the wire: a few hundred, at 500 ms, for one
tab on loopback.

### One doc-comment defect found while verifying this

`internal/pelicanobj/fedstore.go:130` says the priming is best-effort
because *"it may just mean nobody is at a terminal to approve anything
(the device flow refuses to start when stdout is not a TTY)"*. **The
parenthetical is wrong.** There is no `term.IsTerminal` check anywhere in
`client/acquire_token.go` at `e55347e5a`; the only gate on the interactive
path is `opts.NonInteractive`, which pelfs does not set:

```go
// The only remaining option requires the interactive OAuth2 device-code
// flow. Callers without a controlling terminal (e.g. the client agent)
// set NonInteractive so we fail with an actionable error instead of
// blocking on a prompt the user will never see.
if opts.NonInteractive { ... }
```

So the flow *does* start without a TTY, and the URL goes to stderr
regardless. This is good news for the web UI — nothing has to be tricked
into running.

**FIXED** (`d4c3767`). `fedstore.go`'s comment now says what the code does,
and says why the distinction matters rather than merely deleting the wrong
sentence: *"It does NOT mean a terminal is required … That distinction is
what lets a GUI surface the flow instead of a terminal."* The same commit
added `go.work` and `go.work.sum` to `.gitignore`, which this document's
`go.mod` section asked for and which was one `git add` away from putting a
developer's local pelican checkout in CI.

---

## The `go.mod` question: land it upstream, carry no `replace`

**What actually shipped: the PR was opened, it has not merged, and
`go.mod` carries a `replace` after all** — pinned to the PR's own head on
the fork it is proposed from (`bbockelm/pelican
v0.0.0-20260823165605-e55347e5a951`), with the drop condition written in a
comment beside it. The reasoning below is why that is a *cost* rather than
a free choice, and it is unchanged; what changed is the trade. The three
costs are paid, and two of the three mitigations from this section are the
reason it is survivable:

- it pins **the PR's head commit on a fork**, not a local path, so CI can
  fetch it and the integration job can still build a whole pelican server
  from whatever it resolves to;
- it sits **two commits past** what `go.mod` required before it
  (`d01f207b7f71`), and the change is purely additive;
- and the comment says **DROP THIS the moment 3672 merges**, naming the
  reason: a rebasable fork branch has stranded a pin here once already
  (`f4e6111`).

The sequencing argument below still did its job — M1 through M3 were built
before the hook was needed, so nothing waited on it, and only U13 depends
on the pin. Read the rest of this section as the standing case for
deleting the `replace`, not as a description of the tree.

---

**Original recommendation: no `replace` in `go.mod`. Offer `e55347e5a`
upstream, and sequence the milestones so nothing waits on it.**

**The conflict is real and immediate.** `aebd30e` — *"deps: track upstream
pelican; the fork is no longer needed"*, landed 2026-08-22 by another
session — deliberately deleted the pelican `replace` and its 18-line
justification comment. Re-adding one reverses that commit within a day of
it landing, and `go.mod` is currently owned by a concurrent session.

**What a `replace` would cost, specifically.** Three costs, and the third
one has already happened once:

1. **CI fetches the pin.** Every job in `.github/workflows/ci.yml` runs
   `go build`/`go test` and would resolve the fork over the network.
2. **The integration job builds a whole pelican server from it.**
   `scripts/build-pelican-server.sh` builds `pelican-server` *"from the
   exact pelican revision go.mod pins"*, so the fork branch must be a
   complete, buildable pelican — not a client library with one extra
   function — and must keep the `web_ui/frontend/out/placeholder` property
   the script depends on. A fork branch that drifts breaks the integration
   gate, not just the build.
3. **A rebasable branch has stranded a pin already.** `f4e6111`,
   *"pelicanobj: follow the pelican branch after its rebase onto main"*, is
   the commit that existed only to chase a fork branch that moved. A
   `replace` pointing at a branch the owner rebases is a pin that expires
   on someone else's schedule.

**Why upstream is the right call, and likely to work.** The patch is about
as mergeable as a patch gets: **+68/-5 in one file** plus a test file, and
verified against the tree at `e55347e5a`:

- it is **purely additive** — no existing signature changes, no behaviour
  changes for any current caller, because the stderr write happens
  *unconditionally and first*;
- it follows an **established pattern in the same codebase** —
  `config.SetEmptyPassword` is the same process-wide-handler shape for the
  same kind of question, and the commit message says so;
- it is **tested** (97 lines of `oauth2_test.go`, including the
  no-handler, replaced-handler and no-URL cases);
- and its **rationale is upstream's own problem**, not pelfs's: any
  embedder — a GUI, a FUSE daemon, pelican's own web UI — hits the same
  wall, and the commit message enumerates the five unexported internals an
  embedder would otherwise have to copy.

**The stranding risk is also unusually low.** `e55347e5a` sits **two
commits after `d01f207b7`**, and `d01f207b7f71` is precisely the
pseudo-version `go.mod:10` already pins. So the branch is a two-commit
delta on the current dependency — `4636c1e27` (*"print the verification
URI when the issuer omits the complete one"*) plus the hook — which is the
cheapest possible thing to offer as a PR and the easiest to rebase.

**If a local checkout is genuinely needed "for a bit", use `go.work`, not
`go.mod`.** That is the mechanism designed for exactly this: it is not
committed, CI never resolves it, and it cannot strand a pin.

```
go work init .
go work use /Users/bbockelm/projects/pelican   # local, uncommitted
```

`go.work` and `go.work.sum` are **not** in this repo's `.gitignore` today,
so that entry has to be added first — otherwise the mechanism whose whole
value is that it never reaches CI is one `git add` away from doing so.

**And the sequencing removes the pressure entirely.** Milestones M1, M2 and
M3 need no hook: the credential flow works exactly as it does today
(stderr), and the UI simply does not have an SSO card. Only M4 does. So the
honest plan is to open the PR now, build M1-M3 against upstream, and add
the card when the hook lands — with the `go.work` escape hatch for local
development in the meantime.

---

## Testing a browser UI without making CI a browser farm

Six layers. Five need no browser, and the one that does needs exactly one
test.

### 1. The threat model as a Go test table (highest value in this design)

Both HTTP surfaces are `http.Handler`s, so `net/http/httptest` drives them
with no browser, no port and no network. The threat model's table becomes a
table test, and this is the single most valuable test here because it pins
the security properties that a browser cannot be trusted to enforce:

| request | expected |
|---|---|
| `Host: 127.0.0.1:PORT`, correct `Origin`, valid `X-Pelfs-Session` | 200 |
| `Host: evil.example.com:PORT` (DNS rebinding), everything else correct | **421** |
| `Host: 127.0.0.1:PORT`, `Origin: http://127.0.0.1:OTHER` (same-site, wrong origin) | **403** |
| `Origin: null` (a `no-referrer` form post) on an authenticated route | **403** |
| `Origin` absent **and no fetch metadata either** on a `/api/v1` request | **403** |
| `Origin` absent but `Sec-Fetch-Site: same-origin` — a real same-origin GET | **200** |
| `Sec-Fetch-Site: same-site` (a page on another loopback port) | **403** |
| `X-Pelfs-Session` absent, or wrong, or from a previous session | **401** |
| bootstrap token reused | **401**, and the first use still valid |
| bootstrap token past TTL | **401** |
| session token presented at `/dav/*` | **401** |
| DAV Basic credential presented at `/api/v1/*` | **401** |
| download ticket reused | **404** |
| download ticket for a path the credential may not read | **403** |
| `/debug/pprof/heap` on the web listener | **404** (never routed) |
| any response on any surface carrying `Access-Control-Allow-*` | **fail the test** |
| a mutating `/api/v1` route reached with `Content-Type: text/plain` | **415** |

**Sixteen rows, not the "fifteen" this document used to claim** — it said
fifteen and then listed sixteen, and the count was wrong in the direction
that lets a row go missing unnoticed. `TestThreatModelTable` in
`internal/httpguard/httpguard_test.go` is those sixteen, in this order,
with each row named for the attack rather than the mechanism.

**One row had to be split, because as written it was wrong.** "`Origin`
absent → 403" cannot mean absent alone: current browsers send no `Origin`
on a same-origin GET, so that rule would refuse every read the real page
makes. The requirement is *provenance* — a matching `Origin` **or**
`Sec-Fetch-Site: same-origin` — so both halves are rows: the request
carrying neither is a 403, and the same-origin GET carrying only fetch
metadata is a 200. A table that asserted only the refusal would have
passed while the product did not work.

Beside those sixteen, `internal/httpguard` ships assertions the design did
not ask for and the implementation could not do without — a `Host` with no
port, an incoming `Cookie` never reaching a handler, an outgoing
`Set-Cookie` being stripped, a safe method being unable to publish, the
stream taking its token from the query, the ticket surface ignoring a
session header, the navigation surface needing no custom header, the
external surface keeping its own credential, the API body being capped, and
five for `SurfaceToken`. **39 assertions in the package**, no browser,
milliseconds. Every one is a regression somebody could introduce by adding
a middleware in the wrong order, and none of them is visible in a manual
test.

### 2. litmus, against the pelfs adapter

`scripts/webdav-litmus-docker.sh` exists and its baseline is measured:
`basic 16/16 · copymove 13/13 · props 30/30 · locks 32/34`, x/net v0.56.0,
litmus 0.13, 2026-08-23. Its header already names the intended second use:
*"Re-run this when x/net moves, and again with the pelfs adapter
substituted for memFS — a NEW failure in `basic`, `copymove` or `props` is
the adapter's, and is the signal this script exists to give."*
`scripts/webdav-adapter-litmus-docker.sh` is that second use, against
`internal/vfsdav`. The two known `locks` failures stay known: memLS
implements exclusive locks only, and `docs/design-guiclients.md`
establishes that Cyberduck does not lock.

**But the `props` ceiling for a real server is 29/30, not 30/30, and this
document quoted the wrong number as a target.** The 30/30 baseline is
x/net's *example* server, which passes `propfind_invalid2` **by
hard-coding a 400** — its own comment says the test is obsolete and cites
golang/go#8068:

```go
// Thus, we assume that the propfind_invalid2 test is obsolete, and
if r.Header.Get("X-Litmus") == "props: 3 (propfind_invalid2)" { … }
```

The test sends a body with an empty namespace declaration
(`xmlns:bar=""`); Go's `encoding/xml` accepts one, so the **unmodified**
handler answers 207 and litmus scores it a failure. So `props 29/30` is
the honest ceiling for anything that is not special-casing a litmus
header, and the pelfs adapter holds it rather than copying the
special case. Expected, and asserted by the script: **`basic 16/16 ·
copymove 13/13 · props 29/30 · locks 32/34`.** A 30/30 here would mean
somebody added the hard-coded 400, not that the adapter improved.

### 3. `duck` and `rclone` as real external clients

`docs/design-guiclients.md` already did this sourcing: `duck` ships an
official container image `ghcr.io/iterate-ch/cyberduck` and a GitHub Action
`iterate-ch/cyberduck-cli-action@v1`, and `--assumeyes` clears the
plaintext-credential prompt. rclone's `--webdav-unix-socket` makes a
hermetic run possible with no TCP port at all.

**One trap, specific to this design:** a run over a unix socket has no
meaningful `Host` header and therefore **does not exercise the Host
allowlist** — the control this design leans on hardest. So the WebDAV
client gate must run *both* ways: over the unix socket for hermeticity, and
over `127.0.0.1:0` so the guard middleware is in the path. A green
socket-only run would prove the adapter and silently skip the security
layer.

### 4. The OAuth server, tested with no Cyberduck at all

The authorization server is ordinary HTTP and its whole contract is
testable in Go. This matters more than usual because the *client* half —
whether Cyberduck's loopback provider behaves as read — is the plan's
biggest unknown, so the server half must not also be unproven:

- **The happy path, end to end in `httptest`**: `/oauth/authorize` with a
  valid session and consent → code → `/oauth/token` with the verifier →
  token → a `PROPFIND` at `/dav/` with `Authorization: Bearer` → 207.
- **The A7 table as assertions**: an unallowlisted `redirect_uri` renders an
  error and issues **no** `Location`; a wrong `client_id` fails; a missing
  or wrong `code_verifier` fails; a replayed code fails and is counted; a
  code past its 60-second TTL fails; `/oauth/authorize` with no session
  renders the "open pelfs from your terminal" page; `/oauth/authorize`
  without the consent gesture issues nothing.
- **Scope enforcement**: a `pelfs.read` token gets 403 on `PUT /dav/…`; a
  read-only `browse` session cannot issue a `pelfs.write` grant at all.
- **Revocation**: a revoked grant's token fails at `/dav/`; and a token
  minted by one process does not validate in a second process started on
  the same port (the per-process key).
- **The challenge behaviour** unknown from item 5b: assert whatever is
  decided, so that a later change to the `WWW-Authenticate` header is a
  test failure rather than a Cyberduck bug report.

Then one **manual** spike against real Cyberduck ≥ 9.1.3, recorded in the
doc with the version it was run against — because that is the only thing
that answers the client half, and it is not a CI job.

### 5. The SVAR contract, tested without JavaScript in CI

The component's request sequence is a protocol, and a protocol can be
recorded once and replayed forever. Run the real component against a
logging stub server **once**, by hand, on a machine with Node; commit the
recording as a fixture; and make the Go test replay it against the real
handlers and assert the responses. That converts a permanent Node
dependency into a one-time cost plus a committed artifact — which is the
same trick `internal/hostile/testdata/corpus/` already uses to make bug
reports that cannot rot.

This also happens to be how Verification 3's two open questions get
answered (does it lazy-load; does it virtualize), so the recording session
is the M0 probe, not extra work.

### 6. Playwright: exactly one spec, and it is not a UI test

**Recommendation: one Playwright spec, in a job that is not on the PR
path.** Not because UI tests are worthless, but because the only thing a
real browser proves that Go cannot is *the browser half of the threat
model* — `SameSite`, CORS preflight behaviour, Local Network Access, and
DNS rebinding are all enforced by the browser, and a Go test asserting
"we return 403" does not prove "the browser never sent it".

The spec worth writing loads an **attacker page on a genuinely cross-site
origin** and asserts that every one of the following fails to mutate
anything: a `fetch` at `/api/v1/files`, a `<form method=POST>` submission,
an `<img src>` at a download path, an `<iframe>` of `/`, and a `PROPFIND`
via `fetch` at `/dav/`. Chromium's `--host-resolver-rules` gives the
cross-site origin without touching `/etc/hosts`
(`--host-resolver-rules="MAP attacker.test 127.0.0.1"`), which also makes
the **DNS-rebinding case directly testable**: the page's own requests carry
`Host: attacker.test:PORT`, which is exactly the header the allowlist must
reject.

Everything else Playwright could test here — does the grid render, does
drag-and-drop work — is not worth a browser farm, and the honest reason is
that those failures are loud and immediate in manual use while the CSRF
ones are silent.

Precedent and cost: pelican already uses Playwright
(`web_ui/frontend/playwright.config.ts`), so the pattern is not novel to
this ecosystem. But it needs Node, so it belongs in the same optional job
as `go generate ./internal/webui` — never on the path of a Go-only PR.

---

## Branding

**Approved by the Pelican Project's PI**, so the trademark question is
closed at the source rather than reasoned about — Apache-2.0 §6 does not
grant trademark rights (*"This License does not grant permission to use the
trade names, trademarks, service marks, or product names of the
Licensor…"*, pelican `LICENSE:139-142`), and permission from the project is
exactly the thing that section leaves to be obtained. Record the grant in
the repo next to the asset so the question stays closed.

**The palette**, from `web_ui/frontend/components/ThemeProvider.tsx:34-39`,
which is the authoritative in-repo source rather than a colour picked off a
screenshot:

| token | value | use here |
|---|---|---|
| primary | **`#0885ff`** | accent, links, the Publish button |
| primary light | **`#CFE4FF`** | panel fills, the "staged" badge |
| secondary | **`#FFFFFA`** | page ground |

The public branding page agrees on the first two, `#0885FF` and `#CFE4FF`
[W6]. Add one colour of pelfs's own for the durability states, because they
must *not* read as brand chrome: a distinct amber for "on this machine
only" and a green for "in the federation" — the whole point of the
durability panel is that those two are unmistakably different, and doing it
in shades of the brand blue would fail.

**Where the mark comes from — and one correction.** The mark **is** in the
pelican checkout, and it is a **PNG**: 51,041 bytes at
`web_ui/frontend/public/static/images/PelicanPlatformLogo_Icon.png`,
imported from `components/layout/Header.tsx:25` and three navigation
components. (The brief's note is about `web_ui/frontend/public/`, which
indeed holds only `next.svg` and `vercel.svg`; the mark lives one level
down under `public/static/images/`.) The public branding page offers the
same icon plus `PelicanPlatformLogo_Full_Text.png` [W6].

**There is no SVG, anywhere.** A search of the whole pelican tree outside
`node_modules` finds no Pelican SVG at all. So the "SVG logo with FS mixed
in" starts with a vector that does not exist: either trace/redraw from the
PNG, or ask the project for the original vector art, which whoever drew it
will have. **Ask first** — a redraw of someone's mark is worse than their
own file, and one email is cheaper than the redraw.

**The "FS", subtly.** Two options, in preference order, and both keep the
bird untouched so the mark stays recognizable:

1. **A wordmark, not a logo edit**: the Pelican icon beside `pelfs` set in
   the app's type, with `fs` in the primary blue and `pel` in the text
   colour. Nothing is drawn on top of the mark, so nothing can be got
   wrong, and the association reads immediately.
2. **A small monogram in the corner of the favicon** — the icon at 32px
   with `fs` tucked into the lower-right in `#0885ff`. Favicons are the one
   place a compound mark earns its keep, because there is no room for a
   wordmark.

Whichever is chosen, this document argued that **the page must say what
pelfs is not** — one line in the footer, "an independent tool for Pelican
federations; not an official Pelican Platform product". **It does not, and
that was decided by the person whose call it is:** the Pelican Project's PI,
who granted the permission, asked for the footer off the page. The
attribution is not gone, only off the screen, where nobody was reading it;
see below for where it lives.

**What shipped: option 1, and no redraw.** `webui/frontend/public/brand/`
holds the mark copied **byte for byte** from the pelican tree, with a
`NOTICE.txt` recording its size, its sha256, its provenance, the PI's
permission, and the fact that it has not been traced, redrawn or altered.
The favicon is **type only** — a rounded square in `#0885ff` carrying the
`fs` — so no derivative of the bird exists anywhere in this repository.
Option 2, the compound favicon, is where a real vector mark would go if one
is ever supplied; the file says so.

**And there is no footer.** `NOTICE.txt` is what carries the attribution and
the permission, it ships beside the asset it is about, and the binary serves
it at `/brand/NOTICE.txt` — asserted by `internal/webui/webui_test.go`, so it
cannot quietly stop travelling with the mark. The repository's own `NOTICE`
says the same thing. What the deleted footer was carrying that IS an
obligation rather than a statement — the MIT notices for the 30 bundled
packages — moved to the app's status line, because a person who has nothing
but the binary has to be able to reach them from what it serves.

---

## Ranked work items

**U0 through U14 are DONE.** U15 is deferred by decision. The `status`
column is the reconciliation; the `change` column is left as it was
written, so that what was asked for and what arrived are both readable —
except where the description itself was wrong, which is marked.

| | change | status | buys | effort | needs Node? |
|---|---|---|---|---|---|
| **U0** | The M0 probe: run the real SVAR component against a logging stub, record the request sequence, answer "does it lazy-load" and "does it virtualize", and measure `vite build`'s real gzipped output | **DONE** — `webui/frontend/probe`, recording + measurements in `internal/webui/testdata/svar-contract/`. Both answers changed the code: lazy YES (with wiring), virtualize NO (703 MB at 100k) | the two unknowns that could invalidate M4, and the fixture layer 5 replays | hours, once | yes, once |
| **U1** | `internal/httpguard`: `Host` allowlist, `net/http.CrossOriginProtection`, exact-`Origin` match, `X-Pelfs-Session` requirement, `application/json` requirement, security headers, the 15-row test table | **DONE** — and the table is **16 rows, not 15**; the package ships 39 assertions. The `Origin`-absent row was wrong and became a provenance pair | the entire threat model, before anything is exposed | small, and it is the load-bearing code | no |
| **U2** | `internal/browsesession`: bootstrap token (single-use, fragment-delivered, TTL, constant-time), header-borne session token, download tickets | **DONE** | one principal with a real lifecycle | small | no |
| **U3** | `pelfs browse [--rw]`: bind `127.0.0.1:0` tcp4, serve, `--open`, foreground, seal at exit, print the URL | **DONE** — `--open` defaults OFF and the URL is printed either way, resolving this document's own `--open`/`--no-open` contradiction | a verb a person can run | small; `runMountGen` has the teardown discipline and `nfsmount.Serve` is the listener template | no |
| **U4** | The connection page: **one hand-written HTML file**, no React, no build. Volume, mode, durability panel over SSE, "Publish now" | **DONE** — `cmd/pelfs/browse.html`, one file, with a per-response **base64url** CSP nonce rather than `'unsafe-inline'` | M1 in full, with no toolchain | small, and bounded on purpose | **no** |
| **U5** | `POST /api/v1/publish` as 202 + SSE progress, `409` on concurrent, dirty counts on `GET /api/v1/info`, lease-state banner | **DONE** — but **not** via `phaseClock`, which cannot carry it: the stream carries job state and elapsed | the durability UX, honestly | small; `checkpoint` and `phaseClock` exist | no |
| **U6** | `internal/vfsdav`: `webdav.FileSystem`/`webdav.File` over `billyFS`, `webdav.NewMemLS()`, mounted at `/dav/` | **DONE** — "five methods, all present" was too cheap: `DeadPropsHolder` is mandatory, `Mkdir`/`RemoveAll` needed their own bodies, and a symlink must be followed on OPEN. Ceiling `props 29/30`, not 30/30 | external clients on the same listener | small; five methods, all present. This is `docs/design-windows.md` D1 | no |
| **U7** | `internal/localoauth`: `/oauth/authorize` + `/oauth/token`, authorization-code + PKCE `S256`, per-download `client_id`, exact-`redirect_uri` allowlist, consent screen with a real gesture, in-memory-only grants; **Bearer acceptance on `/dav/*`** | **DONE** — with two corrections: `POST /oauth/token` needs `httpguard.SurfaceToken`, and consent is required on **every** `/authorize` (2e's per-`client_id` memory reinstated the attack) | the Cyberduck/Mountain Duck double-click, and it is the *primary* external-client path | **real, and security-critical**; pure Go, no new module | no |
| **U8** | The generated `.cyberduckprofile` download (Verification 2f), plus a `.duck` bookmark, plus HTTP Basic per-client credentials as the contingency and as every other client's path | **DONE** — the `Vendor` carries the listener port, or two sessions collide | connect-by-click for Cyberduck; connect-at-all for WinSCP, rclone, `mount_webdav` | small | no |
| **U9** | litmus gate against the adapter; `duck` + rclone gate over **both** unix socket and TCP; a Bearer-path integration test | **DONE** — plus `scripts/oauth-cyberduck-docker.sh`, which is **real Cyberduck** (duck 9.5.3) completing the flow headlessly, and `make browse-gate` driving the shipped binary end to end | the WebDAV half proven by three independent clients | hours; both scripts exist | no |
| **U10** | Seal on idle: last `/events` stream closed + quiet window, with the pressure path's backoff; `sendBeacon` as a hint only | **DONE** — `min(30 s, --snapshot-interval)` is undefined at 0 and ships as OFF; the beacon needed `idleHintLead` because `pagehide` precedes the teardown | an upload becomes durable without the user knowing what a checkpoint is | moderate; the trigger is new, the sealing is not | no |
| **U11** | The JSON API: the SVAR route contract under `/api/v1`, per-directory listing with a cap, per-id batch results, `.pelfs-part` convention, whole-file upload via `r.MultipartReader()` (**never** `ParseMultipartForm`) | **DONE** — every id route needs an `{id...}` sibling (`{id}` does not match a bare `%2F`), the cap's numbers ride on headers and `/info/{id}`, and `GET /files` is the ROOT and not droppable | the app's data plane | moderate | no |
| **U12** | The Vite + React + SVAR app; `internal/webui` with `//go:generate` + committed `dist/` + `//go:embed`; `third_party.txt`; the regenerate-and-diff CI job; the `wx-*` lockfile check | **DONE** — `.github/workflows/webui.yml` regenerates twice and diffs, and fails on any `wx-*` in the lockfile | the file manager | moderate | **only under `go generate`** |
| **U13** | The SSO card: `SetVerificationURLHandler` installed in `runBrowse`, the prompt registry, the reordered startup, prompts on `/events` | **DONE** — and the reordered startup is not what closes the early-prompt case; SSE **snapshots** are | "authorize with your institution" in a page instead of a URL in a terminal | small **once the hook is upstream** | no |
| **U14** | The one Playwright cross-origin spec, with `--host-resolver-rules` | **DONE** — `webui/frontend/tests/cross-origin.spec.ts`, in the `browser (threat model)` job, off the Go PR path | the browser half of the threat model | small, off the PR path | yes |
| **U15** | Resumable upload: `tus` server + `uppy` client at `api.intercept("upload-file")` | **DEFERRED**, by decision. Unchanged | a 68 MB SIF that survives a dropped link | moderate — and **deferred**, by decision | yes |

---

## Recommended minimal first milestone

**M1 = U1 + U2 + U3 + U4 + U5. No React, no Node, no file manager.**

`pelfs browse` starts a loopback HTTP server, opens the browser, and serves
**one hand-written HTML page**:

```
pelfs browse pelican://<federation>/<prefix>
  open http://127.0.0.1:49731/#bt=IjRVMk5FN0hLZE5NLTBnN0k in your browser
  (if it did not open, paste that URL — the link is single-use, 2-minute expiry)
  Ctrl-C to stop; read-only, so there is nothing to seal.
```

**Three corrections to that mock, all of them in the printed line.** This
document first showed `opening http://127.0.0.1:49731/` with **no
fragment**, which is a URL the page cannot use: the bootstrap token lives
in `#bt=…` and without it there is nothing to exchange for a session — so
the mock's own next line, "paste that URL", was false. The full URL is
printed, fragment and all. `open` rather than `opening` because `--open`
is **off by default** (A3), and the line says what the user should do
rather than what the program is doing. And the last line varies with the
mode, because "the session seals on exit" is not true of the default:
read-only has nothing to seal.

and the page shows:

```
  pelfs — pelican://<federation>/<prefix>            read-only
  branch main, generation 87                         lease: held

  nothing staged. everything here is in the federation.

  [ Publish now ]   (nothing to publish)

  Connect another program
    (not yet built: WebDAV — M2; SFTP — docs/design-guiclients.md)
```

**That last line is now stale, and pleasantly so:** "Connect another
program" is real. The page adds a program, hands back a
`.cyberduckprofile` or a `.duck` bookmark or a username and password, and
lists and revokes every credential the session has handed out — and says
that all of it dies when the process does. M2 landed. The other line that
is still true, and deliberately so, is that **this page does not browse
files**: it says so, and names what does.

**Why this is the right minimum, and not a consolation prize.** It delivers
the two things a file manager cannot: **a publish button** and **an honest
answer to "is my data in the federation yet"**. Those are the two questions
`docs/design-guiclients.md` identified as the trap — *"a modest
drag-and-drop finishes, the user closes the client, and nothing has been
published for up to five minutes"* — and neither is a file-manager feature.
It is also that document's work item **G8**, promoted from a nicety to the
foundation, with the auth story it did not have.

It costs **no JavaScript toolchain whatsoever**: one HTML file with a few
dozen lines of inline vanilla JS for the SSE subscription, `go:embed`ed as a
single file. And it exercises **every** control in the threat model, each of
which U1's table tests.

**All six milestones landed, and the order held.** M1 = U1+U2+U3+U4+U5,
M2 = U6+U7+U8+U9, M3 = U10+U11, M4 = U12, M5 = U13, M6's Playwright half
= U14; only U15 (resumable upload) is outstanding, by decision.

**And the two surfaces have two addresses.** `GET /` is the file manager —
`internal/webui`'s committed bundle, on the route table — and `GET /connect`
is M1's hand-written page: the credential desk, the SSO cards, and its own
copy of the durability panel. The file manager took `/` because it is what
the verb promises; a user whose front door is a credential desk has been
handed the plumbing. Each page carries exactly one anchor to the other
(`webui/frontend/src/ui/Durability.tsx`, `cmd/pelfs/browse.html`'s nav), and
`webui/frontend/tests/connect.spec.ts` drives the round trip in both
directions — because the one navigation that could silently cost a user
their session is a link from a single-page app to another page on its own
origin.

BOTH pages keep the durability panel, and that was the decision worth
arguing. Deleting the second rendering and linking to the first would have
been less code; it would also have made the sentence this whole design
exists to put in front of somebody into something they had to navigate to
read. So there is one ANSWER — the server's `/events` snapshot, which both
pages are clients of — with two renderings, and
`internal/webui/durability_test.go` reads both sources and fails if the
words drift apart.

**M4's gate was the right gate and it very nearly fired:** the component does
not virtualize, so the answer was not "reconsider the component" but "the
cap is the design" — which is a smaller change only because U0 ran before
the app was written rather than after.

**Then, in order (as planned):**

- **M2 = U6 + U7 + U8 + U9.** WebDAV on the same listener, **the OAuth
  authorization server**, the generated Cyberduck profile, and three
  independent clients gating it. This is the milestone with the most
  security-critical new code in the whole plan (U7), and it is why A7 exists
  as its own section. Sequencing note: build U6 and the Basic path first so
  there is a working WebDAV endpoint to point a Bearer token at, then U7,
  then U8 — a profile that cannot connect is not debuggable until the thing
  it connects to works.
- **M3 = U10 + U11.** Idle sealing and the JSON API. Still no React: the
  API is testable and useful on its own, and `curl` is a better first
  consumer than a bundle.
- **M4 = U12.** The SVAR app, under `go generate` with the bundle
  committed. **Gated on U0's two answers** — if the component cannot load a
  directory lazily, stop here and reconsider the component rather than
  shipping a UI that dies on a real volume.
- **M5 = U13.** The SSO card, when the hook is upstream. *(It is not
  upstream: PR 3672 is open, and `go.mod` carries a `replace` on the PR's
  head. See "The `go.mod` question".)*
- **M6 = U14 + U15.** The Playwright spec, and resumable upload. *(The
  spec shipped; resumable upload did not.)*

**What M1 deliberately did not do:** browse files, upload, download, or
show a directory listing. The page said so, and named what did those
(`pelfs mount`, and a WebDAV client once M2 landed). A person who expected
a file manager and got a publish button needed to be told that in one
sentence, on the page — not in a release note. **M3 and M4 did those
things**, and the discipline survived the promotion: the file manager still
says out loud what it is *not* showing you, which is the capped-listing
sentence (`webapi.PartialSearchNotice`), and the durability panel is still
the part of the page that cannot be replaced by a file manager.

---

## What could not be verified

**Most of this list is closed.** It is kept, rather than deleted, because
a document that silently drops its own unknowns leaves no record of which
ones were answered by an experiment and which by an assumption. Closed
items name what closed them; the four that are still open are marked
**OPEN** and are the only ones worth acting on.

1. **Whether the SVAR file manager loads directories lazily.**
   **CLOSED — yes, but only with wiring of ours.** The U0 probe drove the
   real component against a logging stub: entries marked `lazy: true` make
   the store emit `request-data` on *navigation* (not on a sidebar
   expand), and the shipped `RestDataProvider` registers no handler for it
   at all. See Verification 3.
2. **Whether `@svar-ui/react-grid` virtualizes its rows.**
   **CLOSED — it does not.** 100,000 entries measured 1,000,067 DOM nodes
   and 703 MB of heap, 18.1 s in cards mode and 37.5 s in table mode. So
   the response cap is the design and not a fallback, and 5,000 renders in
   under half a second. The consequence this document had not foreseen is
   that search is client-side, so a capped listing is a partial search —
   which is why `webapi.PartialSearchNotice` exists and why there is
   exactly one wording of it.
3. **The real bundle size, and whether `vite build` is byte-reproducible.**
   **CLOSED by construction rather than by measurement**: the
   regenerate-and-diff job (`.github/workflows/webui.yml`) runs the build
   **twice** and diffs, so non-determinism is a red job rather than a
   surprise in somebody's PR. The pinned toolchain and
   `pnpm install --frozen-lockfile` are what make that gate trustworthy.
4. **Whether Cyberduck's WebDAV OAuth path actually completes against a
   loopback redirect.** **CLOSED — it does.** duck 9.5.3 (45464),
   2026-08-23, 22 checks, 0 failing, `--network none`; see Verification
   2g for the line-by-line. And with it:
   - **5a.** `Password Configurable = false` plus OAuth keys **does**
     suppress the password prompt: `user='anonymous', password=''`, no
     field, nothing typed. **CLOSED.**
   - **5b.** An unauthorized `/dav/` response **must** avoid
     `WWW-Authenticate: Basic` when a Bearer token was offered.
     **CLOSED, and the answer was yes** — the challenge is narrowed, and
     the read-only case answers **403 rather than 401** for the same
     reason: a 401 sends a client with no password field back looking for
     a password.
5. **Whether `LoopbackOAuth2AuthorizationCodeProvider` needs an explicit
   port in the profile's redirect URI.** **CLOSED.** Cyberduck echoed the
   profile's `redirect_uri` **verbatim**, port and all, and a callback off
   by one port answers 400. The safe move was free and it is what shipped.
6. **Whether `duck` (the CLI) can complete an OAuth flow headlessly via a
   loopback redirect.** **CLOSED — yes, and it needs no browser at all.**
   It prints the authorization URL and waits on its own loopback listener,
   so `curl` can play the human's click. That removes the worst outcome
   this item was written against — a CI gate exercising the Basic path
   while users exercise the Bearer path.
7. **The remaining `@svar-ui` transitive licences beyond the eleven
   verified.** **CLOSED.** `internal/webui/third_party.txt` is generated
   from a real install and committed, the CI job fails on any `wx-*`
   package in the lockfile, and `internal/webui/webui_test.go` fails if a
   copyleft licence name appears in the notices.
8. **Whether Cyberduck prompts for a client ID when the profile omits
   one.** **OPEN, and it does not matter.** The documentation claims it
   does; `isOAuthConfigurable()` says a blank client id means OAuth is
   off. No pelfs-generated profile omits one, so this only decides how to
   read somebody else's bug report.
9. **Whether `#bt=` in the fragment survives every platform opener.**
   **PARTLY CLOSED.** Nothing goes through a shell — `exec.Command` takes
   an argv — so the fragment survives on macOS (`open`) and Linux
   (`xdg-open`). **Windows is OPEN:** it goes through
   `rundll32 url.dll,FileProtocolHandler` rather than `cmd /c start`,
   which was chosen because `start` eats `&` and handles a bare URL with a
   fragment inconsistently, but no Windows machine has run it. The
   fallback is the printed URL, which is why it is printed first and
   unconditionally.
10. **Whether Safari has shipped any Local Network Access behaviour.**
    **OPEN, and the design does not rely on LNA either way** (F7's own
    spec text forbids relying on it). Closed by reading a Safari release
    note, or by testing.
11. **Whether the `/events?s=<token>` query-string form is acceptable in
    practice.** **A decision, taken and shipped.** `EventSource` cannot
    set request headers, so the stream carries the session token in a
    same-origin query string; it never becomes a navigation, never enters
    history, and the only access log is ours. The alternative — `fetch()`
    with a `ReadableStream` reader — remains available at a cost of a few
    dozen lines of client code. Recorded because it is the one place a
    credential appears in a URL.
12. **Two questions this design made moot rather than answered**, recorded
    so a future reader does not re-open them: whether `Secure` cookies work
    on `http://127.0.0.1` (Chrome yes [B23], Firefox yes [B24], Safari
    historically no and WebKit bug 232088 still open [B25]) and what
    `SameSite` value to use. Dropping the session cookie removes both.
    `Sec-Fetch-Site`'s own availability is *not* an unknown: Chrome 76,
    Firefox 90, Safari 16.4, Baseline "widely available since March 2023"
    [B21] — it is nonetheless treated as reject-when-wrong rather than
    require-always, so that a client without it is not locked out of a
    surface whose real credential is a header.

**Four things went the other way — unknowns this document did not have.**
They are listed so the next design's "what could not be verified" section
knows to look for this shape:

- **`net/http`'s `{id}` wildcard does not match a bare `%2F`.** Not in the
  documentation; found by probing the router. Two implementation passes
  hit it independently, which is the signal that it was the design's
  omission rather than one author's mistake.
- **`html/template` escapes `+` in an attribute**, which makes a
  standard-base64 CSP nonce work only by way of entity decoding.
- **`pagehide` fires before the connection tears down**, so the obvious
  beacon comparison discards every beacon that worked.
- **x/net's WebDAV handler sniffs 512 bytes of any file whose extension
  has no MIME type**, which is how a followed symlink disappeared from its
  own listing.

---

## Sources

Web sources are `[W*]`; browser-platform sources are `[B*]` and live in
their own list. Everything cited as a file path or a commit was read in a
local checkout: pelfs at `4308088`, pelican at `e55347e5a`,
`golang.org/x/net` at `v0.56.0` from the module cache.

- **[W1]** `@svar-ui/react-filemanager@2.6.0` registry metadata:
  `"license": "MIT"`, `"repository": "git+https://github.com/svar-widgets/react-filemanager.git"`,
  peer deps `react >=18` / `react-dom >=18`, and the complete
  `dependencies` list quoted in Verification 1. The other ten packages were
  fetched the same way.
  <https://registry.npmjs.org/@svar-ui/react-filemanager/latest>
- **[W2]** `wx-react-gantt@1.3.1`: `"license": "GPLv3"`, with the
  deprecation notice *"This package is no longer actively maintained. Use
  @svar-ui/react-gantt instead: a fully React-based architecture (no
  wrappers), TypeScript support, and an MIT license."* This is the source
  of the GPLv3 belief, and it is about the retired generation.
  <https://registry.npmjs.org/wx-react-gantt/latest>
- **[W3]** SVAR File Manager data shape and wiring: the flat path-keyed
  entry `{ id: "/Code/Datepicker/Year.jsx", size: 1595, date: …, type:
  "file" }`, the `data`/`drive` props, and the
  `RestDataProvider` + `api.setNext(provider)` pattern.
  <https://docs.svar.dev/react/filemanager/getting_started/> ·
  <https://docs.svar.dev/react/filemanager/guides/working_with_server/>
- **[W4]** `@svar-ui/filemanager-data-provider@2.6.0`'s published `dist`:
  the action list (*'create-file', 'rename-file', 'delete-files',
  'copy-files', 'move-files', 'upload-file'*), the method/path/body table
  in Verification 3, and the finding that upload is a single multipart
  `POST` via `fetch` with no `XMLHttpRequest`, no `upload.onprogress`, no
  chunking and no resume. Read from minified `dist`, so the endpoint table
  should be re-confirmed against a local `node_modules` copy before
  handlers are written.
  <https://unpkg.com/@svar-ui/filemanager-data-provider@2.6.0/dist/index.js>
- **[W5]** Measured bundle weight: `@svar-ui/react-filemanager@2.6.0`,
  **166,892 bytes minified / 50,143 bytes gzipped**, 10 dependencies.
  React's runtime is **not** included in that figure and was not measured
  cleanly (see "What could not be verified" #3).
  <https://bundlephobia.com/api/size?package=@svar-ui/react-filemanager@2.6.0>
- **[W6]** Pelican Platform branding: three PNG assets
  (`PelicanPlatformLogo_Icon.png`, `PelicanPlatformLogo_Full_Text.png`, a
  concept map), colours `#0885FF` and `#CFE4FF`, and **no usage terms,
  licence, trademark notice or modification policy stated anywhere on the
  page**. No SVG is offered. <https://pelicanplatform.org/branding>
- **[W7]** `svar-widgets/react-filemanager` `license.txt`: standard MIT
  text, copyright **XB Software Sp. z o.o.**
  <https://raw.githubusercontent.com/svar-widgets/react-filemanager/main/license.txt>
- **[W8]** SVAR's own Go reference backend: the eleven registered routes
  quoted in Verification 3, the `FileUpdate{Operation, Name, Target, Ids}`
  and `NewFile{Name, Type}` request bodies, the multipart field names
  (`file`, `name`, and the `id` query parameter), and the
  `Response`/`ResponseMulti` reply shapes. **The repository root contains
  no `LICENSE`, `LICENSE.md`, `license.txt` or `COPYING`** — verified
  against the contents API — so the code is all-rights-reserved and only
  the route contract is usable.
  <https://raw.githubusercontent.com/svar-widgets/filemanager-backend-go/main/server.go> ·
  <https://api.github.com/repos/svar-widgets/filemanager-backend-go/contents/>
- **[W9]** Cyberduck discussion #16780, *"OAuth possible with generic
  WebDAV configuration?"* — the maintainer's *"Not out of the box but
  theoretically possible as we already support this for ownCloud Infinite
  Scale (oCIS)"*, the `Protocol` = `dav` profile template posted in the
  thread, and the reporter's unresolved report that no dialog appeared on
  9.1.3 with a blank `OAuth Client ID`.
  <https://github.com/iterate-ch/cyberduck/discussions/16780>
- **[W10]** Cyberduck issue #16791 *"Add OAuth as authentication option for
  WebDAV"*, milestone 9.1.3, and PR #16792, which moved the OAuth wiring
  out of `OwncloudSession` and into the generic `DAVSession` and added the
  `ch.cyberduck:oauth` dependency to `webdav/pom.xml`.
  <https://github.com/iterate-ch/cyberduck/issues/16791> ·
  <https://github.com/iterate-ch/cyberduck/pull/16792>
- **[W11]** Cyberduck `CHANGELOG.md`, section **9.1.3**: *"[Bugfix] Allow
  OAuth configuration in connection profiles (WebDAV) (#16792)"*. Topmost
  version in the file at the time of reading: **9.5.4**.
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/CHANGELOG.md>
- **[W12]** `webdav/src/main/java/ch/cyberduck/core/dav/DAVSession.java` —
  the `isOAuthConfigurable()` guard, the `OAuth2RequestInterceptor` +
  `.setRedirectUri(getOAuthRedirectUrl())` construction,
  `FlowType.valueOf(getAuthorization())`, and in `login()` both
  `credentials.setOauth(authorizationService.validate(...))` and the
  `isPasswordConfigurable()` branch it replaces. `DAVProtocol.java` has no
  OAuth code: the switch is entirely profile-driven.
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/webdav/src/main/java/ch/cyberduck/core/dav/DAVSession.java>
- **[W13]** `core/src/main/java/ch/cyberduck/core/AbstractProtocol.java` —
  `isOAuthConfigurable() { return StringUtils.isNotBlank(this.getOAuthClientId()); }`,
  `isPasswordConfigurable() { return StringUtils.isBlank(this.getOAuthClientId()); }`,
  `isOAuthPKCE() { return true; }`, `getAuthorization() { return null; }`.
  And `core/src/main/java/ch/cyberduck/core/Profile.java` — the complete
  `…_KEY` literal set quoted in Verification 2b; the consumption helpers
  `value()` (which runs every string through a `StringSubstitutor` against
  Cyberduck's preferences), `list()` (which substitutes each element, so
  `Scopes` must be a plist `<array>`), `map()` and `bool()`; and the getters
  `isOAuthConfigurable`, `getOAuthClientId`, `getOAuthAuthorizationUrl`,
  `getOAuthTokenUrl`, `getOAuthRedirectUrl`, `getOAuthScopes`,
  `isOAuthPKCE`, `getAuthorization`, `isPasswordConfigurable` and
  `getDefaultPath`, each of which falls back to `parent` on a blank or
  absent key.
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/core/src/main/java/ch/cyberduck/core/AbstractProtocol.java> ·
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/core/src/main/java/ch/cyberduck/core/Profile.java>
- **[W14]** `oauth/.../BrowserOAuth2AuthorizationCodeProvider.java` — the
  three-way dispatch: custom scheme when the redirect URI ends `":oauth"`
  or contains `"://oauth"`; **loopback** when
  `InetAddress.getByName(new URI(redirectUri).getHost()).isLoopbackAddress()`;
  otherwise the out-of-band paste-the-code prompt. And
  `LoopbackOAuth2AuthorizationCodeProvider`, which runs its own
  `HttpServer` and takes the port from the URI (`0` when unspecified).
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/oauth/src/main/java/ch/cyberduck/core/oauth/BrowserOAuth2AuthorizationCodeProvider.java> ·
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/oauth/src/main/java/ch/cyberduck/core/oauth/LoopbackOAuth2AuthorizationCodeProvider.java>
- **[W15]** `duck` CLI OAuth on headless Linux: #15587 (*"Failed to launch
  'x-cyberduck-action://oauth/?code=…' because the scheme does not have a
  registered handler"*) and #13587 (*"CLI OAuth workflow never finishes
  with custom URI in redirect_url"*), still open.
  <https://github.com/iterate-ch/cyberduck/issues/15587> ·
  <https://github.com/iterate-ch/cyberduck/issues/13587>
- **[W16]** `core/.../serializer/HostDictionary.java` — the `.duck`
  bookmark key set (`Protocol`, `Provider`, `Hostname`, `UUID`,
  `Username`, `Port`, `Path`, `Nickname`, `CDN Credentials`,
  `Private Key File`, `Client Certificate`, …) with **no `Password` key and
  no OAuth token**; secrets live in the keychain. Corroborates and extends
  `docs/design-guiclients.md` [S28].
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/core/src/main/java/ch/cyberduck/core/serializer/HostDictionary.java>
- **[W17]** SVAR licence overview: File Manager, Core, DataGrid, Editor and
  Filter listed as MIT with no PRO tier; Gantt, Calendar and Kanban dual
  MIT/commercial. No full EULA text was reachable, which is only relevant
  if pelfs ever wants a PRO component. <https://svar.dev/licenses/>

- **[W18]** `oauth/src/main/java/ch/cyberduck/core/oauth/OAuth2RequestInterceptor.java`
  — the header it adds (`request.addHeader(new BasicHeader(HttpHeaders.AUTHORIZATION,
  String.format("Bearer %s", tokens.getAccessToken())))`), both constructor
  signatures, and the pre-request refresh (`if(tokens.isExpired()) { tokens =
  this.save(this.authorizeWithRefreshToken(tokens)); }`). This is the file
  that makes a Bearer token reach a WebDAV request.
  <https://raw.githubusercontent.com/iterate-ch/cyberduck/master/oauth/src/main/java/ch/cyberduck/core/oauth/OAuth2RequestInterceptor.java>

### Browser-platform sources

- **[B1]** W3C Secure Contexts — *"If origin's host matches one of the CIDR
  notations `127.0.0.0/8` or `::1/128` [RFC4632], return 'Potentially
  Trustworthy'"* (unconditional); the *conditional* rule for the name
  `localhost`, and §5.2's reason (*"resolvers often ignore these
  suggestions, and will send localhost to the network for resolution in a
  number of circumstances"*); and *"Note: Neither origin's domain nor port
  has any effect on whether or not it is considered to be a secure
  context."* <https://w3c.github.io/webappsec-secure-contexts/> ·
  <https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts>
- **[B2]** Web Cryptography Level 2 — `[SecureContext] readonly attribute
  SubtleCrypto subtle`. <https://w3c.github.io/webcrypto/> ·
  <https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle>
- **[B3]** W3C Mixed Content — *"A request is mixed content if its URL is
  **not** a potentially trustworthy URL"*.
  <https://w3c.github.io/webappsec-mixed-content/>
- **[B4]** PNA/LNA explainer — *"with the exception of
  `http://localhost` which is embeddable"*.
  <https://github.com/WICG/local-network-access/blob/main/explainer.md>
- **[B5]** HTML Standard §7.1.1.1 "Sites" — *"If origin's host's
  registrable domain is null, then return (origin's scheme, origin's
  host)"*; *"If hostA equals hostB and hostA's registrable domain is null,
  then return true"*; *"Unlike the same origin and same origin-domain
  concepts, for schemelessly same site and same site, the port and domain
  components are ignored."*
  <https://html.spec.whatwg.org/multipage/browsers.html#site>
- **[B6]** URL Standard — *"To obtain the public suffix of a host host …
  If host is not a domain, then return null"*, so an IP literal's
  registrable domain is null. <https://url.spec.whatwg.org/>
- **[B7]** Chromium `net/base/schemeful_site.cc` — scheme equality plus
  host equality, and `ObtainASite`'s *"a port of 0"*. Also
  `net/base/url_util.cc`'s `HostStringIsLocalhost`, which covers the IP
  literal and not only the name.
  <https://chromium.googlesource.com/chromium/src/+/main/net/base/schemeful_site.cc>
- **[B8]** RFC 6265bis-22 §8.5 "Weak Confidentiality" — *"Cookies do not
  provide isolation by port. If a cookie is readable by a service running
  on one port, the cookie is also readable by a service running on another
  port of the same server. If a cookie is writable by a service on one
  port, the cookie is also writable by a service running on another port of
  the same server."* And §4.1.3.2 — *"Ports are the only piece of the
  origin model that `__Host-` cookies continue to ignore."*
  <https://www.ietf.org/archive/id/draft-ietf-httpbis-rfc6265bis-22.txt>
- **[B9]** RFC 6265bis-22 §5.6.7.1 and §5.8.3 — *"Same-site cookies in
  'Strict' enforcement mode will not be sent along with top-level
  navigations which are triggered from a cross-site document context"*; the
  retrieval algorithm's exclusion *"unless … the same-site-flag is 'Lax' or
  'Default'"*; and §4.1.2.7's *"They can be set along with any top-level
  navigation, cross-site or otherwise."* Same URL as [B8].
- **[B10]** WICG Local Network Access §1.1 Goals — *"status quo CORS
  protections don't protect against the kinds of attacks discussed here as
  they rely only on CORS-safelisted methods and CORS-safelisted
  request-headers. No CORS preflight is triggered, and the attacker doesn't
  care about reading the response, as the request itself is the CSRF
  attack."* <https://wicg.github.io/local-network-access/>
- **[B11]** Fetch Standard — *"A CORS-safelisted method is a method that is
  `GET`, `HEAD`, or `POST`"*; the CORS-safelisted request-header list
  (`accept`, `accept-language`, `content-language`, `content-type`
  restricted to three MIME essences, `range`, *"Otherwise: Return false"*);
  the preflight trigger in HTTP fetch; the forbidden request-header rule
  for `Sec-`-prefixed names; and the `Content-Type` warning (*"a naïve
  parser on the server might treat the request body as JSON"*).
  <https://fetch.spec.whatwg.org/> · OWASP concurs on rejecting
  `text/plain` bodies:
  <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- **[B12]** Chrome, *"Private Network Access is on hold"* (2024-10-09) —
  *"This rollout is currently on hold due to a number of compatibility
  problems. … PNA preflights are not currently enforced."*
  <https://developer.chrome.com/blog/pna-on-hold>
- **[B13]** Chrome Platform Status, PNA warning-only preflights, Chrome
  104 — *"the subsequent request is sent as if the preflight had
  succeeded."* <https://chromestatus.com/feature/5737414355058688>
- **[B14]** WICG Local Network Access spec — *"gating access on a
  permission rather than via preflight requests"*; the
  loopback-is-not-a-local-network-request rule; *"Chromium only applies LNA
  restrictions to iframe navigations currently"*; *"does not enforce the
  permission for cross-origin local requests"*; the per-connection
  rebinding rule (*"This check MUST be performed for each new connection
  made, as DNS rebinding attacks may otherwise trick the user agent into
  revealing information it shouldn't"*); and §5.3's *"must be designed and
  implemented to defend against CSRF on its own, and should not rely on a
  UA that behaves as specified in this document."*
  <https://wicg.github.io/local-network-access/>
- **[B15]** Chrome Platform Status, "Local network access restrictions" —
  Chrome **142** shipped and enforced (*"any request from a public website
  to a local IP address or loopback, or from a local website … to
  loopback"*), 145's `local-network`/`loopback-network` permission split,
  147's WebSocket/WebTransport extension, and the enterprise policies.
  <https://chromestatus.com/feature/5152728072060928> ·
  <https://developer.chrome.com/blog/local-network-access>
- **[B16]** Firefox release notes — 151 (*"rolling out to all users"*),
  **153** (*"Local Network Access restrictions are now enabled by default
  for all users"*), 154 (WebSockets).
  <https://www.mozilla.org/en-US/firefox/153.0/releasenotes/> ·
  <https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access>
- **[B17]** WebKit standards-positions #520 — open, labelled
  `concerns: venue`, no position given. Safari is recorded as "No signal"
  on the Chrome Platform Status entry.
  <https://github.com/WebKit/standards-positions/issues/520>
- **[B18]** MDN, Local network access — *"The permissions are restricted to
  secure contexts. On non-secure contexts, all requests will fail."*
  <https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Local_network_access>
- **[B19]** W3C Fetch Metadata — the four `Sec-Fetch-Site` values; *"servers
  SHOULD ignore this header if it contains an invalid value"*; the
  potentially-trustworthy assertion, so a loopback server does receive it;
  and §4.2's unforgeability argument.
  <https://w3c.github.io/webappsec-fetch-metadata/>
- **[B20]** Chromium `services/network/sec_header_helpers.cc` — *"Only
  append the header to potentially trustworthy URLs."*
  <https://chromium.googlesource.com/chromium/src/+/main/services/network/sec_header_helpers.cc>
- **[B21]** MDN BCD / Baseline for `Sec-Fetch-Site`: Chrome 76, Firefox 90,
  Safari 16.4; *"widely available … since March 2023."*
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site>
- **[B22]** Go standard library, `net/http.CrossOriginProtection` (Go 1.25;
  this repo is `go 1.26.0`) — *"Cross-origin requests are currently
  detected with the `Sec-Fetch-Site` header … or by comparing the hostname
  of the `Origin` header with the Host header"*; *"The GET, HEAD, and
  OPTIONS methods are safe methods and are always allowed. It's important
  that applications do not perform any state changing actions due to
  requests with safe methods"*; *"Requests without `Sec-Fetch-Site` or
  `Origin` headers are currently assumed to be either same-origin or
  non-browser requests, and are allowed."* `Check` accepts only
  `same-origin` and `none`, so `same-site` is rejected.
  <https://github.com/golang/go/blob/master/src/net/http/csrf.go>
- **[B23]** Chromium `net/cookies/cookie_util.cc` —
  `ProvisionalAccessScheme` returns `kTrustworthy` for a localhost URL, so
  `Secure` and the `__Secure-`/`__Host-` prefixes are accepted from
  `http://127.0.0.1`.
  <https://chromium.googlesource.com/chromium/src/+/main/net/cookies/cookie_util.cc>
- **[B24]** httpwg/http-extensions#2605 — *"Firefox allows `Secure` cookies
  to be set/sent on `http://localhost`, as well as `__Host-` and
  `__Secure-` prefixed cookies"*, because *"Firefox moved from a 'secure
  protocol' check … to using the definition of potentially trustworthy
  origin defined in the Secure Contexts specification."*
  <https://github.com/httpwg/http-extensions/issues/2605>
- **[B25]** WebKit bug 232088, *"Unable to set Secure cookie for
  localhost"* — still open. WebKit `main`'s `CookieJar.cpp` now gates
  `shouldIncludeSecureCookies` on `HAVE(LOCALHOST_TIED_TO_LOOPBACK)`, which
  `PlatformHave.h` restricts to macOS 26+/iOS; which shipping Safari
  version that reaches, and whether the *setting* path changed, is
  UNVERIFIED. <https://bugs.webkit.org/show_bug.cgi?id=232088>
- **[B26]** MDN `Set-Cookie` — *"The `https:` requirements are ignored when
  the `Secure` attribute is set by localhost."* True of Chrome and Firefox;
  see [B25] for Safari.
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie>
- **[B27]** MDN `Origin` / `Referrer-Policy` interaction — the user agent
  sets `Origin` to `null` when the referrer policy is `no-referrer`;
  `fetch()` defaults to `mode: "cors"` and so always sends its real
  `Origin`.
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy>
- **[B28]** CVE-2018-5702 (Transmission ≤ 2.92) — *"relies on
  X-Transmission-Session-Id (which is not a forbidden header for Fetch) for
  access control, which allows remote attackers to execute arbitrary RPC
  commands, and consequently write to arbitrary files, via POST requests to
  /transmission/rpc in conjunction with a DNS rebinding attack."* The
  custom header *was* the defence. Project Zero issue 1447.
  <https://nvd.nist.gov/vuln/detail/CVE-2018-5702>
- **[B29]** GitHub Security Lab, *"DNS rebinding attacks explained"* — the
  Deluge WebUI case, and *"Browsers try to resist DNS rebinding like this
  by caching DNS responses, but the defense is far from perfect. … the DNS
  rebinding behavior is very browser and operating system (OS)
  dependent."* Plus the 2025 "Local Mess" incident that motivated LNA.
  <https://github.blog/security/application-security/dns-rebinding-attacks-explained-the-lookup-is-coming-from-inside-the-house/> ·
  <https://localmess.github.io/>
- **[B30]** NCC Group, *Singularity of Origin* — *"the service should check
  that all HTTP request 'Host' header values strictly contain
  '127.0.0.1:3000' and/or 'localhost:3000'. If the host header contains
  anything else, then the request should be denied"*, and *"Filtering DNS
  responses … should not be relied upon as a primary defense mechanism."*
  <https://github.com/nccgroup/singularity/wiki/Preventing-DNS-Rebinding-Attacks>
- **[B31]** W3C Referrer Policy — *"The header `Referer` will be omitted
  entirely"* for `no-referrer`; and §3.7's
  `strict-origin-when-cross-origin` behaviour, including *"A `Referer` HTTP
  header will not be sent"* on a trustworthy→non-trustworthy request.
  <https://w3c.github.io/webappsec-referrer-policy/>
- **[B32]** MDN `Referrer-Policy` — *"`strict-origin-when-cross-origin`
  (default) … This is the default policy if no policy is specified, or if
  the provided value is invalid (see spec revision November 2020)."*
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy>
