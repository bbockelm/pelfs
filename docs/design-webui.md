# A browser UI for pelfs: what it takes, and what it exposes

Status: **verified where it could be, designed where it could not.** No
pelfs code exists for this and none is proposed here as done. Four claims
in the proposal were checked before anything was designed around them
(section "The four verifications"), and **three of the four came back
different from the assumption** — the licence, the data protocol, and the
Cyberduck OAuth question, which turned out to be a yes. Every browser-platform claim in the threat
model is cited to a spec, a browser's own release note, or the source of
the library that implements it; the handful that could not be settled from
here are collected at the end under "What could not be verified", each with
the experiment that closes it.

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
      |         -> Origin exact-match -> principal                  |
      |         (two principals, never interchangeable)             |
      |                                                            |
      |  A  /               go:embed'd Vite bundle    (no secret)   |
      |     /assets/*                                              |
      |  B  /api/v1/*       first-party JSON API      X-Pelfs-      |
      |                     (SVAR provider contract)  Session: tok  |
      |  D  /events         SSE: SSO prompts, seal    Session: tok  |
      |                     state, upload progress                 |
      |  E  /d/<ticket>     ticketed download GET     ticket only   |
      |                     (no session token accepted)            |
      |                                                            |
      |  C  /dav/*          x/net/webdav.Handler      HTTP Basic    |
      |                     (external clients only)   per-client    |
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

**Two principals, never interchangeable.** The browser session (A, B, D)
and the external-client credential (C) are separate secrets with separate
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

#### 2e. Consent: require one gesture, once per profile

**Recommendation: same-session does *not* imply consent — require exactly
one click, and remember it per `client_id`.**

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
- remembered per `client_id` **for the life of the process only**, so a
  refresh or a re-connect during the same `pelfs browse` session does not
  re-prompt, and the next session does.

#### 2f. The profile, concretely

```xml
<key>Protocol</key>              <string>dav</string>
<key>Vendor</key>                <string>org.pelicanplatform.pelfs.local</string>
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

Note what is **not** there: `Authorization` (omitted deliberately, 2b),
`OAuth PKCE` (omitted so the parent's `true` applies), and any secret other
than the `client_id` — which is itself minted per download, so possessing
the profile is the only thing that identifies the client.

Installation is by double-click, or *Preferences → Profiles*; the same
mechanism and the same core serve **Mountain Duck**, whose only difference
is its handler scheme — which the loopback redirect sidesteps entirely.

#### 2g. What needs a live Cyberduck, and the contingency

**Needs a live Cyberduck ≥ 9.1.3 to confirm** (all four are in "What could
not be verified"): that the loopback provider is selected for this redirect
URI shape; that an explicit port is required; that a `dav` profile with
`Password Configurable = false` and OAuth keys presents no password prompt;
and that `duck`, the CLI, can complete the loopback flow headlessly — its
custom-scheme flow is documented broken on headless Linux and the tracking
issue is open [W15]. The one public report of somebody trying WebDAV+OAuth
says the dialog never appeared [W9], on a profile with a **blank**
`OAuth Client ID` — which by `isOAuthConfigurable()` means OAuth was never
enabled at all, so it is more likely a misconfiguration than a defect. That
is a hypothesis, not a finding.

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

**The two questions this verification did NOT answer, and they decide
whether the component is usable on a pelfs volume at all.** Both are
listed in "What could not be verified" with the experiment; they are named
here because they are the highest-risk unknowns in the whole design:

1. **Does the component load directories lazily?** `GET /files` with no
   id returns the entire tree. A pelfs volume's scale is stated in this
   repo's own CI as 62,500 files proven end-to-end (`CHANGELOG`, work item
   E7) with the format's binding constraint at millions
   (`docs/TODO.md` A2: *"cap hit at ~6-14M files"*). A component that
   wants the whole array up front is unusable at that scale, full stop.
   `GET /files/{path}` exists in the contract, which is strong evidence
   that per-directory loading is supported — but *whether the component
   requests subdirectories on expand*, rather than expecting the caller to
   supply everything, was not established from the docs.
2. **Does its grid virtualize?** A directory with 100,000 entries is
   ordinary on a pelfs volume and fatal to a non-virtualized DOM list.
   `@svar-ui/react-grid` is the underlying table; whether it windows rows
   is unverified.

Until both are answered, the design's fallback is stated and cheap: the
JSON API **caps a directory response** at a configured N (start at 5,000 —
the number `scripts/sftp-clients-docker.sh` already proves a real client
handles, `dir-5000: ok`), returns a truncation marker, and the UI shows
"showing 5,000 of 412,006 — narrow the path or use the WebDAV endpoint".
A cap the user is told about is a limitation; an unbounded response that
hangs the tab is a defect.

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
enters any process's argv. That defeats one-click launch, which is the
point of the feature. `--no-open` is the middle ground: print the URL, let
the user paste it. The token is then in their clipboard and shell but never
in argv.

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
2. **An authenticated browser session is required.** `/oauth/authorize`
   without a valid session renders a page saying "open pelfs from your
   terminal first", never a login form and never a redirect.
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
6. **One real user gesture, on a consent screen** (Verification 2e). This
   is the control that specifically defeats the silent-drive attack: an
   `/authorize` that cannot complete without a click cannot be completed by
   a navigation the user did not make. The screen names the client, the
   scope, the volume and the redirect target — so a user who *is* driven
   there sees an authorization request they did not ask for, which is the
   only signal a human can act on. Remembered per `client_id` for the life
   of the process, so a reconnect within the session does not re-prompt.
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
| **OAuth** | `/oauth/authorize`, `/oauth/token` | a browser session **plus one consent gesture**; then PKCE + a per-download `client_id` | issuing DAV credentials to Cyberduck with no typing | redirect anywhere not on the exact-string allowlist, or complete without a user gesture |

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

The adapter work is therefore small and known: `internal/vfsdav` wraps
`billyFS` as a `webdav.FileSystem` (five methods, all present), and wraps
`billy.File` as a `webdav.File` (which needs `Readdir(count int)` — the
one method billy puts on the *filesystem* rather than the file, so the
wrapper holds a path and calls `billyFS.ReadDir`). Locks: `webdav.NewMemLS()`,
and `docs/design-guiclients.md` already establishes that Cyberduck does not
lock and that the two known litmus `locks` failures are therefore off the
path.

### The routes, concretely

The SVAR contract is the starting point and two of its routes are replaced,
for reasons the contract itself creates:

| SVAR route | pelfs | why |
|---|---|---|
| `GET /files`, `GET /files/{path}` | **kept**, `{path}` form only, with a response cap | the un-pathed form returns the whole tree; see Verification 3 |
| `GET /info`, `GET /info/{id}` | kept | this is where the drive/capacity panel comes from — and it is the natural home for the **durability counters** |
| `POST /files/{id}` (`NewFile`) | kept | mkdir and touch |
| `PUT /files/{id}` (rename) | kept | one `billyFS.Rename` |
| `PUT /files` (move/copy, batch) | kept, per-id results | see "semantic restraint" above |
| `DELETE /files` | kept, per-id results | ditto |
| `POST /upload` | **kept as-is for now** | it is a single multipart POST with no progress and no resume [W4]; resumable upload is deferred — see below |
| `GET /direct` | **replaced** by `/d/<ticket>` | a download must not be an ambient-credential GET; see the threat model |
| `GET /preview`, `GET /icons/...` | dropped in M3 | previews render user content; see "the stored-XSS problem" |

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
  any surface, for `min(30 s, --snapshot-interval)`;
- with the **pressure path's backoff**, which is not optional: the
  existing pressure path doubles its wait to the interval on failure, and
  an idle seal retrying every 30 s against a broken federation would
  reproduce the "same warning forever" failure that backoff exists to
  prevent (`docs/design-guiclients.md`, item (a));
- and `navigator.sendBeacon` on `visibilitychange`/`pagehide` as a *hint*
  that shortens the wait, never as the trigger — a beacon is best-effort
  by specification and a durability decision must not rest on one.

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
  is, and give the user a spinner with no information. The seal already
  emits phase timings through `phaseClock` (`mountgen.go:1422-1495`) —
  that is what the progress stream should carry.
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
into running — but the comment should be corrected, because it currently
tells a reader the opposite of what the code does. (Not this document's
change to make; filed in `docs/TODO.md` under `webui-agent`.)

---

## The `go.mod` question: land it upstream, carry no `replace`

**Recommendation: no `replace` in `go.mod`. Offer `e55347e5a` upstream,
and sequence the milestones so nothing waits on it.**

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
| `Origin` absent on a `/api/v1` request | **403** |
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

Fifteen assertions, no browser, milliseconds. Every one of them is a
regression somebody could introduce by adding a middleware in the wrong
order, and none of them is visible in a manual test.

### 2. litmus, against the pelfs adapter

`scripts/webdav-litmus-docker.sh` exists and its baseline is measured:
`basic 16/16 · copymove 13/13 · props 30/30 · locks 32/34`, x/net v0.56.0,
litmus 0.13, 2026-08-23. Its header already names the intended second use:
*"Re-run this when x/net moves, and again with the pelfs adapter
substituted for memFS — a NEW failure in `basic`, `copymove` or `props` is
the adapter's, and is the signal this script exists to give."* Point it at
`internal/vfsdav` and the ceiling becomes a gate. The two known `locks`
failures stay known: memLS implements exclusive locks only, and
`docs/design-guiclients.md` establishes that Cyberduck does not lock.

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

Whichever is chosen: **the page must say what pelfs is not.** One line in
the footer — "an independent tool for Pelican federations; not an official
Pelican Platform product" — costs nothing and prevents the one
misunderstanding a borrowed mark can cause. The permission covers using the
mark; it does not make pelfs the product.

---

## Ranked work items

| | change | buys | effort | needs Node? |
|---|---|---|---|---|
| **U0** | The M0 probe: run the real SVAR component against a logging stub, record the request sequence, answer "does it lazy-load" and "does it virtualize", and measure `vite build`'s real gzipped output | the two unknowns that could invalidate M4, and the fixture layer 5 replays | hours, once | yes, once |
| **U1** | `internal/httpguard`: `Host` allowlist, `net/http.CrossOriginProtection`, exact-`Origin` match, `X-Pelfs-Session` requirement, `application/json` requirement, security headers, the 15-row test table | the entire threat model, before anything is exposed | small, and it is the load-bearing code | no |
| **U2** | `internal/browsesession`: bootstrap token (single-use, fragment-delivered, TTL, constant-time), header-borne session token, download tickets | one principal with a real lifecycle | small | no |
| **U3** | `pelfs browse [--rw]`: bind `127.0.0.1:0` tcp4, serve, `--open`, foreground, seal at exit, print the URL | a verb a person can run | small; `runMountGen` has the teardown discipline and `nfsmount.Serve` is the listener template | no |
| **U4** | The connection page: **one hand-written HTML file**, no React, no build. Volume, mode, durability panel over SSE, "Publish now" | M1 in full, with no toolchain | small, and bounded on purpose | **no** |
| **U5** | `POST /api/v1/publish` as 202 + SSE progress, `409` on concurrent, dirty counts on `GET /api/v1/info`, lease-state banner | the durability UX, honestly | small; `checkpoint` and `phaseClock` exist | no |
| **U6** | `internal/vfsdav`: `webdav.FileSystem`/`webdav.File` over `billyFS`, `webdav.NewMemLS()`, mounted at `/dav/` | external clients on the same listener | small; five methods, all present. This is `docs/design-windows.md` D1 | no |
| **U7** | `internal/localoauth`: `/oauth/authorize` + `/oauth/token`, authorization-code + PKCE `S256`, per-download `client_id`, exact-`redirect_uri` allowlist, consent screen with a real gesture, in-memory-only grants; **Bearer acceptance on `/dav/*`** | the Cyberduck/Mountain Duck double-click, and it is the *primary* external-client path | **real, and security-critical**; pure Go, no new module | no |
| **U8** | The generated `.cyberduckprofile` download (Verification 2f), plus a `.duck` bookmark, plus HTTP Basic per-client credentials as the contingency and as every other client's path | connect-by-click for Cyberduck; connect-at-all for WinSCP, rclone, `mount_webdav` | small | no |
| **U9** | litmus gate against the adapter; `duck` + rclone gate over **both** unix socket and TCP; a Bearer-path integration test | the WebDAV half proven by three independent clients | hours; both scripts exist | no |
| **U10** | Seal on idle: last `/events` stream closed + quiet window, with the pressure path's backoff; `sendBeacon` as a hint only | an upload becomes durable without the user knowing what a checkpoint is | moderate; the trigger is new, the sealing is not | no |
| **U11** | The JSON API: the SVAR route contract under `/api/v1`, per-directory listing with a cap, per-id batch results, `.pelfs-part` convention, whole-file upload via `r.MultipartReader()` (**never** `ParseMultipartForm`) | the app's data plane | moderate | no |
| **U12** | The Vite + React + SVAR app; `internal/webui` with `//go:generate` + committed `dist/` + `//go:embed`; `third_party.txt`; the regenerate-and-diff CI job; the `wx-*` lockfile check | the file manager | moderate | **only under `go generate`** |
| **U13** | The SSO card: `SetVerificationURLHandler` installed in `runBrowse`, the prompt registry, the reordered startup, prompts on `/events` | "authorize with your institution" in a page instead of a URL in a terminal | small **once the hook is upstream** | no |
| **U14** | The one Playwright cross-origin spec, with `--host-resolver-rules` | the browser half of the threat model | small, off the PR path | yes |
| **U15** | Resumable upload: `tus` server + `uppy` client at `api.intercept("upload-file")` | a 68 MB SIF that survives a dropped link | moderate — and **deferred**, by decision | yes |

---

## Recommended minimal first milestone

**M1 = U1 + U2 + U3 + U4 + U5. No React, no Node, no file manager.**

`pelfs browse` starts a loopback HTTP server, opens the browser, and serves
**one hand-written HTML page**:

```
pelfs browse pelican://<federation>/<prefix>
  opening http://127.0.0.1:49731/  in your browser
  (if it did not open, paste that URL — the link is single-use, 2-minute expiry)
  Ctrl-C to stop; the session seals on exit.
```

and the page shows:

```
  pelfs — pelican://<federation>/<prefix>            read-only
  branch main, generation 87                         lease: held

  nothing staged. everything here is in the federation.

  [ Publish now ]   (nothing to publish)

  Connect another program
    (not yet built: WebDAV — M2; SFTP — docs/design-guiclients.md)
```

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

**Then, in order:**

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
- **M5 = U13.** The SSO card, when the hook is upstream.
- **M6 = U14 + U15.** The Playwright spec, and resumable upload.

**What M1 deliberately does not do:** browse files, upload, download, or
show a directory listing. The page says so, and names what does those today
(`pelfs mount`, and a WebDAV client once M2 lands). A person who expected a
file manager and got a publish button needs to be told that in one
sentence, on the page — not in a release note.

---

## What could not be verified

In the order they would change the plan. Each names the experiment that
closes it; none is closed by more reading.

1. **Whether the SVAR file manager loads directories lazily.** The route
   contract has `GET /files/{path}`, which is strong evidence, but nothing
   in the documentation states that the component *requests* a subdirectory
   on expand rather than expecting the whole array up front. **This can
   invalidate M4 by itself**, because `GET /files` with no id returns the
   entire tree and a pelfs volume's scale is millions of entries
   (`docs/TODO.md` A2: *"cap hit at ~6-14M files"*). Closed by U0: run the
   real component against a stub that logs every request and expand a
   nested folder.
2. **Whether `@svar-ui/react-grid` virtualizes its rows.** A
   100,000-entry directory is ordinary here. Same probe, same session:
   render a directory of 100,000 stub entries and watch. If it does not
   virtualize, the response cap is not a fallback, it is the design.
3. **The real bundle size, and whether `vite build` is byte-reproducible.**
   Measured: the SVAR component and its ten dependencies at **166,892 bytes
   minified / 50,143 gzipped** [W5]. *Not* measured: React's runtime,
   because bundlephobia reports only `react-dom@19`'s re-export stub at
   3,681 bytes, which is not the real number. And **not established at
   all**: whether two runs of the pinned toolchain produce identical bytes.
   The bundle is committed by decision, so reproducibility is no longer a
   question of *whether* to commit — it is what makes the
   regenerate-and-diff gate trustworthy instead of flaky. Closed by running
   `go generate ./internal/webui` twice in the CI job and diffing, which is
   cheaper than learning it from a contributor's PR.
4. **Whether Cyberduck's WebDAV OAuth path actually completes against a
   loopback redirect.** This is now the **highest-stakes** unknown in the
   plan, because M2 is built on it. The code path is read and quoted
   [W12][W13][W14][W18], the feature is in the 9.1.3 changelog [W11], and
   the one public report of somebody trying it says the dialog never
   appeared [W9] — plausibly because that profile left `OAuth Client ID`
   blank, which by `isOAuthConfigurable()` means OAuth was never enabled at
   all. That is a hypothesis, not a finding. **Closed by a spike against a
   real Cyberduck ≥ 9.1.3 desktop before U7 is written**, not after: a
   throwaway Go server with hard-coded `/authorize` and `/token` and a
   generated profile answers it in an afternoon, and it answers items 5,
   5a and 5b below at the same time.
   - **5a. Whether `Password Configurable = false` plus OAuth keys really
     suppresses the password prompt** on a `dav` profile, or whether
     something in the `login()` probe still challenges.
   - **5b. Whether an unauthorized `/dav/` response must avoid
     `WWW-Authenticate: Basic` when a Bearer token was offered.** Inferred
     from the `login()` HEAD/PROPFIND probe, not observed; it decides
     whether the DAV middleware needs to vary its challenge by what the
     client presented.
5. **Whether `LoopbackOAuth2AuthorizationCodeProvider` needs an explicit
   port in the profile's redirect URI.** The provider takes the port from
   the URI and uses `0` (OS-chosen) when none is given, which would make
   the `redirect_uri` sent to the authorization server disagree with the
   port the listener is on. This is an inference from quoted code, not a
   tested behaviour. Closed by the same prototype; the safe move meanwhile
   is to always write an explicit port.
6. **Whether `duck` (the CLI) can complete an OAuth flow headlessly via a
   loopback redirect.** With a custom-scheme redirect it is documented
   broken on headless Linux and the tracking issue is open [W15]; with a
   loopback redirect it *should* work — the provider runs its own
   `HttpServer` and needs no OS scheme handler — and nobody has reported
   doing it. It matters because `duck` is the cheapest real-client CI gate
   (`docs/design-guiclients.md`), and because a headless-hostile OAuth flow
   would mean the CI gate exercises the Basic path while users exercise the
   Bearer path — the worst split there is. Closed by trying it in
   `ghcr.io/iterate-ch/cyberduck`; until then U9 must gate **both** paths,
   the Bearer one with a Go-level integration test rather than a client.
7. **The remaining `@svar-ui` transitive licences beyond the eleven
   verified.** The eleven checked are the package plus its complete direct
   `dependencies` list, all MIT. A `pnpm licenses list --json` over a real
   install is what proves the *transitive* closure, and it is also the
   command that generates `internal/webui/third_party.txt`, so it is not extra work.
8. **Whether Cyberduck prompts for a client ID when the profile omits
   one.** The documentation claims it does; the OAuth code path's behaviour
   with a blank client ID appears from `isOAuthConfigurable()` to be "OAuth
   is off", which contradicts it. Only matters if a profile ever ships
   without one, and the recommendation is that none does.
9. **Whether `#bt=` in the fragment survives every platform opener.**
   `open`, `xdg-open` and `start` are three programs with three parsers, and
   a `#` is a shell comment character. The URL must be quoted, and the
   round trip must be tested on all three platforms — a fragment silently
   dropped by an opener is a launch that fails with no diagnostic. Closed
   by trying it; the fallback (print the URL) already exists.
10. **Whether Safari has shipped any Local Network Access behaviour.**
    WebKit standards-position #520 is open with no position, labelled
    `concerns: venue`, and Chrome Platform Status records Safari as "No
    signal" [B17]. It matters only for how much of A1 the browser handles;
    the design does not rely on LNA either way. Closed by reading a Safari
    release note, or by testing.
11. **Whether the `/events?s=<token>` query-string form is acceptable in
    practice.** `EventSource` cannot set request headers, so the SSE stream
    carries the session token in a same-origin query string. It never
    becomes a navigation and never enters history, and the only access log
    is ours — but if that is judged wrong, the alternative is `fetch()` with
    a `ReadableStream` body reader, which can set headers and costs perhaps
    forty more lines of client code. A decision, not an unknown, recorded
    here because it is the one place a credential appears in a URL.
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
