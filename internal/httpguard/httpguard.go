// Package httpguard is the transport-level defence for pelfs's loopback
// HTTP listener: the Host allowlist, net/http's CrossOriginProtection, the
// exact-Origin match, the per-surface principal rules, and the security
// headers every response carries.
//
// It exists as its own package because it is the load-bearing code of
// `pelfs browse` and because it must be testable without a browser, a
// port, or a volume: everything here is an http.Handler decision made from
// request headers, so the whole threat model becomes a table test
// (httpguard_test.go, sixteen rows, milliseconds).
//
// # Why a loopback HTTP server needs any of this
//
// The short version, with the four facts that decide the design; the long
// version is docs/design-webui.md's "Threat model".
//
//   - An HTTPS page CAN talk to http://127.0.0.1:PORT. Loopback is a
//     potentially-trustworthy origin, so it is not mixed content. "Nobody
//     can reach my localhost server" is false.
//   - PORTS ARE NOT PART OF A SITE. http://127.0.0.1:1234 and
//     http://127.0.0.1:56789 are same-SITE, so a page served by any other
//     local service reads as `Sec-Fetch-Site: same-site` here, and
//     SameSite=Strict does nothing about it.
//   - COOKIES HAVE NO PORT ISOLATION AT ALL (RFC 6265bis §8.5). A cookie
//     set for 127.0.0.1 is sent to every other service on 127.0.0.1 the
//     browser is made to contact. That is not a cookie configuration to
//     get right; it is what cookies are. So this design has NO cookies:
//     the credential is a header the page sets from sessionStorage, which
//     IS port-scoped. This package never emits a Set-Cookie (it strips
//     one, loudly, if a handler ever tries) and never reads a Cookie
//     header (it deletes it before any handler sees the request).
//   - A CROSS-ORIGIN GET REACHES THE SERVER. CORS governs reading the
//     response, not sending the request, so anything authorized by an
//     ambient credential is reachable from any page the user visits. The
//     credential here is not ambient, which is what makes CSRF
//     structurally impossible rather than merely checked.
//
// # The order of the checks is a property of the code, not of a router
//
// Host allowlist, then CrossOriginProtection, then the exact-Origin match,
// then the principal. The order matters and is therefore one function
// (check) rather than a chain a future edit can reorder: every step after
// the Host check assumes the request was addressed to this server, and
// every step after the origin checks assumes the request came from our own
// page.
//
// # The two gaps in CrossOriginProtection, and how they are closed
//
// net/http.CrossOriginProtection is the standard library's Sec-Fetch-Site
// check and it is exactly right for the same-site case above — it accepts
// only `same-origin` and `none`, so a page on another loopback port is
// rejected. Its own doc comment names two limits:
//
//  1. "The GET, HEAD, and OPTIONS methods are safe methods and are always
//     allowed." Closed by never routing a state change to a safe method
//     (the publish route is POST-only and 405s a GET) and by requiring the
//     session credential on every API request INCLUDING GET.
//  2. "Requests without Sec-Fetch-Site or Origin headers are currently
//     assumed to be either same-origin or non-browser requests, and are
//     allowed." Closed by requireProvenance: on a credentialed surface a
//     request must carry EITHER an exactly-matching Origin OR
//     `Sec-Fetch-Site: same-origin`. A request with neither is refused,
//     which fails closed where the standard library fails open.
//
// # Why Host validation is the DNS-rebinding defence and nothing else is
//
// A rebinding attacker's page is same-ORIGIN with us as far as the browser
// is concerned: evil.example.com resolves to 127.0.0.1 on a second lookup,
// so Sec-Fetch-Site reads same-origin, the Origin header reads
// http://evil.example.com, and every same-origin protection evaporates at
// once. CVE-2018-5702 is the cautionary case: Transmission's custom header
// WAS its CSRF defence, and rebinding defeated it by making the request
// same-origin. What a rebound request cannot forge is the Host header,
// which still names the attacker's own hostname. Hence hostOK: an exact
// string allowlist of the two names this listener answers to, compared
// with no parsing and no prefix matching — a rebinding Host is a NAME that
// resolves to loopback, so "is this a loopback IP" would pass it.
package httpguard

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// Surface names one class of route on the listener and, with it, the
// principal that reaches it. Surfaces are not interchangeable: the whole
// point of the split is that a credential minted for one is refused at the
// others, so that the browser-reachable surface cannot borrow the reach of
// the surface a browser never touches.
//
// This is the seam later milestones mount onto. U6 (WebDAV) takes
// SurfaceExternal, U7 (the OAuth authorization server) takes
// SurfaceNavigation for /oauth/authorize and SurfaceToken for
// /oauth/token, U11 (the JSON API) takes SurfaceAPI and
// SurfaceUpload. Adding a route means naming its surface, which means
// naming its principal — and that is deliberately the one decision a
// contributor cannot skip.
type Surface int

const (
	// SurfaceApp is the app shell: the page itself and any static asset.
	// No credential, because there is no secret in a static bundle — and a
	// top-level navigation from the address bar (`Sec-Fetch-Site: none`)
	// has to work or the URL the terminal printed is useless.
	SurfaceApp Surface = iota

	// SurfaceAPI is the first-party JSON API. X-Pelfs-Session is required
	// on EVERY request including GET: it is the credential and it is also
	// the CORS preflight trigger, since a non-safelisted request header
	// forces an OPTIONS a server emitting no Access-Control-Allow-* can
	// never satisfy. Mutating methods additionally require
	// `Content-Type: application/json`, which is a second, free preflight
	// trigger (that type is not CORS-safelisted) and which stops a
	// form-encoded or text/plain body from being parsed as JSON.
	SurfaceAPI

	// SurfaceExchange is the one route that cannot require a session
	// token, because it is the route that mints one: POST /api/v1/session,
	// which trades the single-use bootstrap token from the launch URL's
	// fragment for the session token the page keeps in sessionStorage.
	//
	// It gets every OTHER rule the API surface gets — the provenance
	// requirement, the JSON content type, the refusal of an Authorization
	// header, the body cap — so the only thing it relaxes is the one thing
	// it has to. The credential it checks is in its body, and the
	// bootstrap token's own single-use 120-second lifetime is what bounds
	// the exposure (see internal/browsesession).
	SurfaceExchange

	// SurfaceUpload is SurfaceAPI for a route that receives a file: the
	// same session credential and the same provenance rules, but
	// multipart/form-data instead of JSON and no body-size cap, because
	// the cap is the point of failure on a 68 MB upload.
	//
	// Note for whoever writes U11: multipart/form-data IS CORS-safelisted,
	// so on this surface the preflight trigger is the session header
	// alone. That is sufficient, and it is the reason the header is
	// required on every surface that mutates rather than only on the JSON
	// ones.
	SurfaceUpload

	// SurfaceStream is the SSE endpoint. Its credential is the same
	// session token in the query string, because EventSource cannot set a
	// request header. A same-origin query string is acceptable here and
	// only here: it never becomes a navigation, never enters history, and
	// the only access log is ours.
	SurfaceStream

	// SurfaceTicket is the byte-serving download route. It accepts NO
	// session credential — the guard strips one if it is offered — because
	// an <a href> cannot carry a custom header, and authorizing downloads
	// by ambient credential would mean exempting GET from the credential
	// rule: exactly the hole DNS rebinding exploits. Authority comes from
	// a single-use ticket in the path, minted by an authenticated call on
	// SurfaceAPI.
	SurfaceTicket

	// SurfaceExternal is for clients that are not this page: WebDAV at
	// /dav/* (U6), driven by HTTP Basic or an OAuth Bearer token. The
	// browser session token is REFUSED here, which is half of the
	// two-principals rule; the other half is that SurfaceAPI refuses an
	// Authorization header.
	SurfaceExternal

	// SurfaceNavigation is for a route a browser reaches by NAVIGATION
	// rather than by fetch — /oauth/authorize (U7), which Cyberduck opens
	// in the user's browser. It therefore CANNOT require a custom header,
	// and no amount of consistency with SurfaceAPI will change that. Its
	// controls have to be elsewhere: an exact-string redirect_uri
	// allowlist, a per-download client_id, PKCE, and one real user gesture
	// on a consent screen. Say so at the handler, because the natural
	// instinct of a later maintainer is to make it look like the API
	// routes, and the consistent version does not work.
	SurfaceNavigation

	// SurfaceToken is the OAuth token endpoint — POST /oauth/token (U7) —
	// and it exists because NO OTHER SURFACE CAN SERVE IT.
	//
	// docs/design-webui.md and cmd/pelfs/browse.go's route comment both
	// pencil that route in on SurfaceExchange, "the API surface minus the
	// session requirement". The caller, though, is not a browser and is not
	// our page: it is Cyberduck's Apache HttpClient (or rclone, or curl)
	// making a back-channel POST. It sends no Origin and no
	// Sec-Fetch-Site, so SurfaceExchange's provenance requirement — which
	// is a browser-only signal — answers 403; and its body is
	// `application/x-www-form-urlencoded`, which RFC 6749 §4.1.3 mandates
	// and SurfaceExchange's JSON rule answers 415. A profile pointed at a
	// SurfaceExchange token endpoint fails every exchange.
	//
	// What this surface KEEPS is everything that still applies to a
	// non-browser POST, and it is most of the list: the Host allowlist, so
	// a rebound Host never reaches the handler; CrossOriginProtection, so a
	// form POST from a page on another loopback port is refused (an unsafe
	// method with `Sec-Fetch-Site: same-site` is rejected, and by F3
	// another loopback port IS same-site); the exact-Origin match whenever
	// an Origin is present at all; no cookie in, no Set-Cookie out; no
	// Access-Control-Allow-*; and a security-header set that makes the
	// response inert. What it drops is the provenance signal a non-browser
	// cannot send and the content type the protocol forbids.
	//
	// The credential it checks is in its body — an authorization code plus
	// a PKCE verifier, or a refresh token — and internal/localoauth is
	// where that is checked.
	SurfaceToken
)

func (s Surface) String() string {
	switch s {
	case SurfaceApp:
		return "app"
	case SurfaceAPI:
		return "api"
	case SurfaceExchange:
		return "exchange"
	case SurfaceUpload:
		return "upload"
	case SurfaceStream:
		return "stream"
	case SurfaceTicket:
		return "ticket"
	case SurfaceExternal:
		return "external"
	case SurfaceNavigation:
		return "navigation"
	case SurfaceToken:
		return "token"
	}
	return "surface(" + strconv.Itoa(int(s)) + ")"
}

// policy is the rule set a surface gets. It is a value derived from the
// surface rather than a set of ifs inside check, so that "what does this
// surface require" is answerable by reading one function and so that
// adding a surface is a matter of stating its policy rather than editing a
// chain of conditions.
type policy struct {
	// provenance requires positive evidence that the request came from our
	// own page: a matching Origin, or Sec-Fetch-Site: same-origin. This is
	// CrossOriginProtection's fail-open gap closed, so it is set for every
	// surface that carries a credential of ours.
	provenance bool
	// session requires a valid X-Pelfs-Session (or, on the stream, the
	// same token in the query).
	session bool
	// noAuthorization refuses an Authorization header outright: it is the
	// external principal's credential and must never be accepted where the
	// browser session's is.
	noAuthorization bool
	// contentType, when set, is required on a mutating method.
	contentType string
	// bodyLimit, when non-zero, caps the request body.
	bodyLimit int64
}

func (s Surface) policy() policy {
	switch s {
	case SurfaceAPI:
		return policy{provenance: true, session: true, noAuthorization: true,
			contentType: "application/json", bodyLimit: APIBodyLimit}
	case SurfaceExchange:
		return policy{provenance: true, noAuthorization: true,
			contentType: "application/json", bodyLimit: APIBodyLimit}
	case SurfaceUpload:
		// No body limit, deliberately: the cap is the point of failure on
		// a 68 MB upload. And multipart/form-data rather than JSON, which
		// IS CORS-safelisted — so on this surface the preflight trigger is
		// the session header alone, which is sufficient.
		return policy{provenance: true, session: true, noAuthorization: true,
			contentType: "multipart/form-data"}
	case SurfaceStream:
		// No content-type rule: an SSE subscription is a GET with no body.
		return policy{provenance: true, session: true, noAuthorization: true}
	}
	// App, Ticket, External, Navigation, Token: no credential of ours, so
	// no provenance requirement either — each has to answer a request made
	// with no page of ours involved (a pasted URL, an <a href> download, a
	// Cyberduck navigation, a back-channel POST from a Java HTTP client).
	// Every one of them still gets the Host allowlist, the Sec-Fetch-Site
	// check, the exact-Origin match, the cookie strip and the headers.
	return policy{}
}

// SessionHeader carries the browser session token on every API request.
//
// It is a custom header on purpose, and the name matters less than the
// fact that it is not CORS-safelisted: that is what forces a preflight for
// any cross-origin attempt, and this server answers no preflight.
const SessionHeader = "X-Pelfs-Session"

// StreamTokenParam carries the session token on the SSE stream, where a
// header cannot be set. See SurfaceStream.
const StreamTokenParam = "s"

// APIBodyLimit bounds a JSON request body. Every JSON route here takes a
// small document; an unbounded reader on a localhost listener is a way for
// a page the user visited to spend our memory even when it cannot read a
// single response byte. SurfaceUpload is exempt, deliberately.
const APIBodyLimit = 1 << 20

// SessionVerifier authenticates the browser-session principal.
//
// An interface rather than a concrete type so that this package knows
// nothing about how a token is minted, stored or expired — that is
// internal/browsesession's business, and the split is what lets the guard's
// table test run against a two-line stub.
type SessionVerifier interface {
	// ValidSession reports whether token is a live session token for this
	// process. Implementations MUST compare in constant time and MUST
	// refuse the empty string.
	ValidSession(token string) bool
}

// Config is what a Guard needs to know about the listener it protects.
type Config struct {
	// Port is the port the listener ACTUALLY got, after binding
	// 127.0.0.1:0. The allowlist and the origin are computed from it once,
	// at startup, so no request-time parsing can disagree with them.
	Port int
	// Sessions authenticates the browser session. A nil verifier refuses
	// every credentialed request, which is the right failure for a
	// misconfigured server.
	Sessions SessionVerifier
}

// Guard applies the transport-level checks and the per-surface principal
// rules. It is immutable after New and safe for concurrent use.
type Guard struct {
	// hosts is the exact-string allowlist. Two entries, both computed from
	// the real port: the literal address the terminal prints, and the name
	// a user may type instead.
	//
	// `localhost:<port>` is here even though the listener binds tcp4 only.
	// The risk it is checked against is a NAME that resolves to loopback
	// under the attacker's control, and `localhost` is not that name: RFC
	// 6761 reserves it and browsers resolve it to a loopback address
	// themselves. What it can cost is a dead link rather than a rejection
	// — a browser that resolves localhost to ::1 finds nothing listening —
	// which is why the URL the terminal prints is the literal 127.0.0.1.
	hosts []string
	// origins is the same two hosts as origins, for the exact-match check.
	origins  []string
	sessions SessionVerifier
	cop      *http.CrossOriginProtection
}

// New builds the guard for a listener on cfg.Port.
func New(cfg Config) *Guard {
	port := strconv.Itoa(cfg.Port)
	g := &Guard{
		hosts:    []string{"127.0.0.1:" + port, "localhost:" + port},
		sessions: cfg.Sessions,
		// NO trusted origins and NO bypass patterns, ever. A trusted
		// origin here would be a cross-origin consumer of a surface that
		// has none, and a bypass pattern is a hole in the one check that
		// catches a page on another loopback port.
		cop: http.NewCrossOriginProtection(),
	}
	for _, h := range g.hosts {
		g.origins = append(g.origins, "http://"+h)
	}
	g.cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		denyCrossOrigin(w, r)
	}))
	return g
}

// Origin is the origin this listener serves, in the form the launch URL
// uses. Callers print it; the guard compares against it.
func (g *Guard) Origin() string { return g.origins[0] }

// Hosts is the exact-string Host allowlist, for a caller that wants to
// report it (a bug report, a log line).
func (g *Guard) Hosts() []string { return append([]string(nil), g.hosts...) }

// hostOK is the DNS-rebinding defence. Exact strings, no parsing: see the
// package comment for why net.SplitHostPort plus "is this loopback" is the
// wrong shape of check.
func (g *Guard) hostOK(host string) bool {
	for _, h := range g.hosts {
		if host == h {
			return true
		}
	}
	return false
}

// originOK requires the Origin header, when present, to name exactly the
// origin this request was addressed to.
//
// It is "http://" + r.Host rather than a fixed string so that a request to
// 127.0.0.1 and a request to localhost each require their OWN origin: the
// two are different origins to a browser, and letting a page from one call
// the other would be a cross-origin call this server has no reason to
// allow. r.Host is already known to be on the allowlist by the time this
// runs.
//
// `Origin: null` fails this, which is correct and worth naming: a
// no-referrer form post and a sandboxed frame both send `null`, and
// treating it as "absent, therefore fine" would turn the header into an
// opt-out.
func originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return o == "http://"+r.Host
}

// nullOriginOK is the one place `Origin: null` is not a refusal, and it
// exists because the alternative was a feature that could not work in any
// browser.
//
// THE BUG IT FIXES, with the bytes. `Referrer-Policy: no-referrer` is set
// on every response by securityHeaders. The Fetch standard's "append a
// request `Origin` header" step says that for a request whose mode is not
// "cors" and whose method is neither GET nor HEAD — which is exactly a form
// submission, mode "navigate" — a referrer policy of `no-referrer` makes
// the serialized origin `null`. So EVERY consent-form POST from a real
// browser arrived as:
//
//	POST /oauth/authorize
//	host: 127.0.0.1:64592
//	origin: null
//	sec-fetch-site: same-origin
//	sec-fetch-mode: navigate
//	sec-fetch-user: ?1
//
// and step 4 answered `403 origin refused`. Every Cyberduck connection
// failed at the click, and no test caught it because the gates hand-set an
// `Origin` header with curl (scripts/oauth-cyberduck-docker.sh's consent(),
// scripts/browse-gate.sh's) — a browser's ROLE played by a client that
// satisfies the check by construction. The real fix is at the source:
// SurfaceNavigation now serves `Referrer-Policy: same-origin`, so the
// browser sends its real origin. This is the belt to that brace, for the
// user whose browser or extension forces `no-referrer` globally
// (Firefox's network.http.referer.defaultPolicy=0 does exactly that) and
// for whom the source fix is overridden.
//
// WHY IT IS SAFE, and it is not a smaller check than the one it replaces:
//
//   - It is SurfaceNavigation only. That surface carries no credential of
//     ours (policy.provenance and policy.session are both false on it), so
//     there is no ambient authority for a forged POST to borrow. Its real
//     controls are elsewhere and unaffected: a per-download client_id, an
//     exact-string redirect_uri, PKCE S256, and a single-use consent
//     ticket that existed only in the body of a page this origin rendered.
//   - `Sec-Fetch-Site: same-origin` is required, and a page cannot set it.
//     It is a browser-attached header, on the forbidden-header list, so it
//     is stronger evidence of provenance than an `Origin` a fetch could
//     choose — the reason requireProvenance already accepts it alone.
//   - A cross-site or same-site page's form POST reads `cross-site` or
//     `same-site` and never reaches here: step 3 (CrossOriginProtection)
//     rejects both on an unsafe method.
//   - DNS rebinding is unaffected. A rebound request IS same-origin to the
//     browser, which is the whole point of A2 — and step 1 has already
//     refused it on the Host, before this line runs.
//
// A sandboxed frame also sends `Origin: null`, and would now be accepted
// here — with `Sec-Fetch-Site: same-origin`, which a sandboxed frame of
// OUR OWN document is, and which frame-ancestors 'none' plus
// X-Frame-Options: DENY stop anybody else from creating.
//
// # WHY SurfaceApp IS IN THE SET, WHICH IS NOT AN ACCIDENT
//
// Because otherwise this function is DEAD CODE and the exception it grants
// is unreachable. Router.top wraps the whole mux as `g.Handler(SurfaceApp,
// r.mux)`, so EVERY request runs check with SurfaceApp BEFORE the mux
// dispatches it to the route that names its real surface (see Router.top on
// why the checks run twice). A per-surface relaxation that names only the
// inner surface is refused by the outer pass and never reaches the inner
// one. Measured: the first version of this named SurfaceNavigation alone and
// answered 403 through the router while passing when the handler was wrapped
// directly.
//
// Naming SurfaceApp costs nothing, and it is worth being precise about why.
// It is the top wrapper's surface and the static bundle's, and neither
// carries a credential of ours: policy() gives both the empty policy. What
// the outer pass lets through, the route's OWN wrapper then checks again
// with its real surface — so a credentialed surface still refuses
// `Origin: null` (TestNullOriginIsStillRefusedOnCredentialedSurfaces), and
// the widening on SurfaceApp itself reaches only GET-only routes and
// net/http's 404, both of which have nothing to authorize.
//
// Anyone adding a surface: if you relax something per-surface in check, ask
// whether Router.top's SurfaceApp pass will refuse it first.
func nullOriginOK(r *http.Request, s Surface) bool {
	switch s {
	case SurfaceNavigation, SurfaceApp:
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	return false
}

// check runs the whole chain for one request and reports whether the
// handler should run. Everything it refuses, it has already answered.
func (g *Guard) check(w http.ResponseWriter, r *http.Request, s Surface) bool {
	// 1. Host, first, because every check after this assumes the request
	// was addressed to this server. 421 Misdirected Request is the correct
	// status, and the body must not echo the Host value back.
	if !g.hostOK(r.Host) {
		w.WriteHeader(http.StatusMisdirectedRequest)
		return false
	}
	// 2. No cookie ever reaches a handler. Not because we set one — this
	// design has none — but because ANOTHER local service's cookie for
	// 127.0.0.1 arrives here whether we like it or not (RFC 6265bis §8.5),
	// and a future handler that authenticated on one would be trusting a
	// value any other process on this machine can set.
	r.Header.Del("Cookie")
	// 3. The standard library's Sec-Fetch-Site check, which is what
	// rejects a page on another loopback port (`same-site`).
	if err := g.cop.Check(r); err != nil {
		denyCrossOrigin(w, r)
		return false
	}
	// 4. Exact Origin, when present.
	//
	// `Origin: null` IS A REFUSAL EVERYWHERE EXCEPT ON A NAVIGATION, and
	// that exception is a BUG FIX, not a relaxation. See nullOriginOK.
	if o := r.Header.Get("Origin"); o != "" && !originOK(r) &&
		!(o == "null" && nullOriginOK(r, s)) {
		denyNav(w, r, http.StatusForbidden, "origin refused",
			"The browser said this request came from a page pelfs did not serve.",
			"If you reached this from a WebDAV client, ask it to connect again. "+
				"If it keeps happening, `pelfs browse` is printing the only URL "+
				"this listener answers to — use that one.")
		return false
	}
	p := s.policy()
	// 5. Provenance, which is CrossOriginProtection's fail-open gap closed.
	// One of the two positive signals must be present: an Origin that
	// matched in step 4, or Sec-Fetch-Site naming our own origin. A
	// request with neither is a non-browser request, and a non-browser
	// request has no business on a surface whose credential the browser
	// holds. (A consequence worth knowing before it surprises somebody:
	// curl at /api/v1/* needs -H 'Sec-Fetch-Site: same-origin' or a
	// matching -H 'Origin: …'. That is the fail-CLOSED direction.)
	if p.provenance && !requireProvenance(r) {
		deny(w, http.StatusForbidden,
			"this surface needs a same-origin request: send Origin or Sec-Fetch-Site")
		return false
	}
	// 6. The principal. Two rules, and the first is the half of "two
	// principals, never interchangeable" that lives on this side: an
	// Authorization header is the WebDAV/OAuth principal's credential and
	// is never accepted here, even alongside a valid session token, so
	// that no handler can be written that accepts either.
	if p.noAuthorization && r.Header.Get("Authorization") != "" {
		deny(w, http.StatusUnauthorized,
			"the JSON API takes the browser session header, never Authorization")
		return false
	}
	if p.session && !g.validSession(sessionToken(r, s)) {
		deny(w, http.StatusUnauthorized, "no valid session")
		return false
	}
	// 7. Content type on anything that mutates. Not CORS-safelisted, so it
	// is a free second preflight trigger; and it stops a text/plain body
	// from reaching a naive JSON parser.
	if p.contentType != "" && mutating(r.Method) && !hasContentType(r, p.contentType) {
		deny(w, http.StatusUnsupportedMediaType, "expected Content-Type: "+p.contentType)
		return false
	}
	if p.bodyLimit > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, p.bodyLimit)
	}
	return true
}

// requireProvenance is check step 5; see there.
func requireProvenance(r *http.Request) bool {
	if originOK(r) {
		return true
	}
	// Same-origin GET/HEAD requests carry no Origin header at all in
	// current browsers, which is why this second signal is not a
	// belt-and-braces extra but the load-bearing one for every read the
	// page does.
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

// sessionToken pulls the credential from wherever this surface carries it.
func sessionToken(r *http.Request, s Surface) string {
	if s == SurfaceStream {
		return r.URL.Query().Get(StreamTokenParam)
	}
	return r.Header.Get(SessionHeader)
}

func (g *Guard) validSession(tok string) bool {
	return tok != "" && g.sessions != nil && g.sessions.ValidSession(tok)
}

// mutating reports whether a method may change state. GET, HEAD and
// OPTIONS are the safe methods CrossOriginProtection always allows, so
// nothing routed here may mutate on one.
func mutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// hasContentType compares only the media type, so a charset parameter is
// not a rejection.
func hasContentType(r *http.Request, want string) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), want)
}

// Handler wraps h with the checks for surface s.
//
// Router is the usual way to reach this; a caller that owns its own mux
// can wrap a handler directly.
func (g *Guard) Handler(s Surface, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w = noCookies(w)
		securityHeaders(w.Header(), s)
		switch s {
		case SurfaceExternal:
			// The browser session is refused here rather than ignored. An
			// external client presenting it is either a bug or an attempt
			// to reach the filesystem with the app's authority, and both
			// deserve an answer rather than a fallthrough into the DAV
			// handler's own challenge.
			if r.Header.Get(SessionHeader) != "" {
				if !g.hostOK(r.Host) {
					w.WriteHeader(http.StatusMisdirectedRequest)
					return
				}
				deny(w, http.StatusUnauthorized,
					"the browser session does not reach this endpoint; use this client's own credential")
				return
			}
		case SurfaceTicket:
			// Stripped, not refused: an <a href> cannot send it anyway, so
			// a request that carries one came from script, and the point
			// is that the byte-serving path has no ambient authority to
			// find. Deleting it here makes that structural rather than a
			// rule the download handler has to remember.
			r.Header.Del(SessionHeader)
			r.Header.Del("Authorization")
		}
		if !g.check(w, r, s) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Router is the mount table for the listener: a route, a surface, a
// handler. It is the seam the later milestones land on —
//
//	r.Handle(httpguard.SurfaceExternal,   "/dav/",             davHandler)      // U6
//	r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", authorize)    // U7
//	r.Handle(httpguard.SurfaceAPI,        "GET /api/v1/files/{path...}", list)  // U11
//
// — and it has two properties worth stating, because both are things a
// plain http.ServeMux would not give:
//
//   - EVERY response goes through the transport guard, including a 404 for
//     a path nobody registered. That is what keeps `/debug/pprof/heap` off
//     this listener: net/http/pprof's init registers on
//     http.DefaultServeMux, and internal/control imports it, so this
//     binary HAS those routes — they are simply not on this mux, and the
//     404 they get here is Host-validated like everything else.
//   - The surface is named at the mount site, so the principal is a
//     property of the route table rather than of a handler's memory.
type Router struct {
	g   *Guard
	mux *http.ServeMux
	// top is the mux behind the transport guard. Dispatch goes through it
	// so that a path NOBODY registered is still Host-validated and still
	// carries the security headers, and so that net/http's own 404 and its
	// trailing-slash redirect are guarded like any other response.
	//
	// A matched route therefore runs the transport checks twice: once here
	// and once in its own per-surface wrapper. Every one of them is
	// idempotent (a header set, a Cookie deleted, two comparisons), and
	// paying for it is how the guard stays a property of the LISTENER
	// rather than of the route table's completeness.
	top http.Handler
}

// NewRouter returns an empty router guarded by g.
func (g *Guard) NewRouter() *Router {
	r := &Router{g: g, mux: http.NewServeMux()}
	r.top = g.Handler(SurfaceApp, r.mux)
	return r
}

// Handle mounts h at pattern (net/http.ServeMux syntax, so "POST /x" and
// "/dav/" both work) on surface s.
func (r *Router) Handle(s Surface, pattern string, h http.Handler) {
	r.mux.Handle(pattern, r.g.Handler(s, h))
}

// HandleFunc is Handle for a function.
func (r *Router) HandleFunc(s Surface, pattern string, h func(http.ResponseWriter, *http.Request)) {
	r.Handle(s, pattern, http.HandlerFunc(h))
}

// ServeHTTP dispatches through the transport guard; see Router.top.
//
// Dispatch is the mux's own ServeHTTP rather than a lookup through
// mux.Handler, because Handler does not populate the request's path values
// — a route mounted as "GET /d/{ticket}" would find PathValue("ticket")
// empty, which is the kind of bug that turns a single-use ticket into an
// unauthenticated route.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.top.ServeHTTP(w, req)
}

// securityHeaders are on every response from every surface.
//
// The CSP here is the restrictive default for a non-HTML response: nothing
// may load, nothing may frame us, no form may post anywhere. The page
// handler replaces it with the app's own policy, which is the same shape
// plus a nonce for its one inline script and its one inline style — see
// cmd/pelfs/browse.go.
func securityHeaders(h http.Header, s Surface) {
	h.Set("Content-Security-Policy",
		"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	// no-referrer everywhere, because the bootstrap token is in a URL
	// fragment and a fragment must never travel. The default policy would
	// already cover the cross-origin case; this covers the same-origin one
	// too, at no cost.
	//
	// EXCEPT ON A NAVIGATION, where "at no cost" was false and the cost was
	// the whole feature. `no-referrer` makes a browser send `Origin: null`
	// on a form submission (Fetch, "append a request `Origin` header"), and
	// `Origin: null` is a refusal at check step 4 — so the consent form on
	// /oauth/authorize could not be submitted by any browser. See
	// nullOriginOK for the bytes.
	//
	// `same-origin` is the narrowest policy that does not null the origin:
	// a full-URL Referer to THIS origin (our own handler, no access log)
	// and NO Referer at all to anywhere else. The 303 that ends the flow
	// goes to the client's own loopback port, which is a different origin,
	// so it still travels with no Referer — the property no-referrer was
	// chosen for. And no page on this surface has a fragment token: the
	// bootstrap token lives on SurfaceApp, which keeps no-referrer.
	rp := "no-referrer"
	if s == SurfaceNavigation {
		rp = "same-origin"
	}
	h.Set("Referrer-Policy", rp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	// Nothing here is cacheable and some of it is a credential exchange.
	h.Set("Cache-Control", "no-store")
	// NO Access-Control-Allow-* header, on any surface, ever. There is no
	// legitimate cross-origin consumer of any route on this listener, and
	// the way this whole protection gets deleted is somebody "fixing
	// CORS". A test asserts the absence.
}

// deny answers a refused request in as few bytes as possible. The body
// never echoes anything from the request.
func deny(w http.ResponseWriter, code int, why string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, why)
}

// denyNav is deny for a refusal a PERSON may be looking at.
//
// A refusal on the navigation surface lands in a browser window, and three
// words of text/plain is what the user who reported this bug was left with:
// "origin refused", no status, no next step, and a WebDAV client still
// spinning on its callback listener behind it. So a request that a browser
// made as a top-level document gets a page instead — same words, plus what
// it means and what to do — and everything else keeps the terse text/plain
// body a script or a CLI wants.
//
// EVERY STRING IT RENDERS IS A CONSTANT FROM THIS PACKAGE OR ITS CALLER.
// Nothing from the request reaches the page: not the Host, not the Origin,
// not the path. That is the same rule internal/localoauth's pages follow,
// and for the same reason — a page that repeats an attacker's string back
// to the user is a page that can be made to say anything.
func denyNav(w http.ResponseWriter, r *http.Request, code int, why, detail, hint string) {
	if !wantsHTML(r) {
		deny(w, code, why)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_ = denyTmpl.Execute(w, struct{ Why, Detail, Hint string }{why, detail, hint})
}

// wantsHTML reports whether this request is a browser fetching a document.
// `Sec-Fetch-Dest: document` is the precise signal and a page cannot forge
// it; the Accept sniff is the fallback for a browser that does not send
// Fetch metadata (Safari, at the time of writing), and it is deliberately
// narrow — `Accept: */*`, which is what curl and every Java HTTP client
// send, is not a document request.
func wantsHTML(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Dest") == "document" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// denyTmpl is the refusal page. No script, no image, no external anything,
// so it renders identically under the CSP securityHeaders already set
// (`default-src 'none'`) — which is also why the style is an attribute
// rather than a <style> block: this response has no nonce.
var denyTmpl = template.Must(template.New("deny").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Why}} — pelfs</title></head>
<body style="font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, sans-serif;
 max-width: 40rem; margin: 3rem auto; padding: 0 1.25rem; color: #1a1a1a">
<h1 style="font-size: 1.35rem; margin: 0 0 .75rem">pelfs refused this request</h1>
<p><strong>{{.Why}}</strong></p>
<p>{{.Detail}}</p>
{{if .Hint}}<p style="color: #555; font-size: .92rem; border-top: 1px solid #e3e3e3;
 margin-top: 1.75rem; padding-top: .9rem">{{.Hint}}</p>{{end}}
</body></html>
`))

// noCookies is the belt to the braces: a ResponseWriter that drops any
// Set-Cookie a handler sets.
//
// No handler in pelfs sets one, and the test table asserts that no
// response from any surface carries one. This makes that a property of the
// server rather than of everyone who ever adds a route, because a cookie
// on 127.0.0.1 is readable and writable by every other service on
// 127.0.0.1 (RFC 6265bis §8.5) — so a Set-Cookie here is not a small bug,
// it is handing this session's credential to whatever else the user's
// browser talks to locally.
func noCookies(w http.ResponseWriter) http.ResponseWriter {
	return &cookieless{ResponseWriter: w}
}

type cookieless struct {
	http.ResponseWriter
	wrote bool
}

func (c *cookieless) WriteHeader(code int) {
	c.Header().Del("Set-Cookie")
	c.wrote = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *cookieless) Write(b []byte) (int, error) {
	if !c.wrote {
		// An implicit 200: the header map is about to be frozen, so this
		// is the last moment the strip can happen.
		c.Header().Del("Set-Cookie")
		c.wrote = true
	}
	return c.ResponseWriter.Write(b)
}

// Flush keeps SSE working through the wrapper. http.NewResponseController
// finds it through Unwrap as well; both are provided because a handler may
// use either.
func (c *cookieless) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.NewResponseController.
func (c *cookieless) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// ConstantTimeEqual compares two secrets without leaking their contents
// through timing. It is here rather than in the session package because
// both packages need it and neither should be tempted to use ==.
func ConstantTimeEqual(a, b string) bool {
	// Length is not secret (every token this program mints is the same
	// length), and ConstantTimeCompare already returns 0 for a mismatch.
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// denyCrossOrigin answers a request CrossOriginProtection refused. Same text
// as before on the wire for a script; a page for a person, because this is
// the refusal a mis-typed launch URL and a mixed-up second `pelfs browse`
// session both land on.
func denyCrossOrigin(w http.ResponseWriter, r *http.Request) {
	denyNav(w, r, http.StatusForbidden, "cross-origin request refused",
		"This request came from a page on a different origin. pelfs's loopback "+
			"listener answers requests from its own page only.",
		"Two `pelfs browse` sessions on two ports are two different origins to a "+
			"browser. Use the URL the terminal printed for the session you mean.")
}
