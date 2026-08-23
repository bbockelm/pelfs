package localoauth_test

// THE WHOLE PATH, WITH NOTHING MOCKED BETWEEN THE PIECES: a real net/http
// listener, internal/httpguard's router in front, internal/localoauth's
// authorization server, and internal/vfsdav's WebDAV handler behind — and
// one token that starts life as a click on a consent screen and ends it as
// an Authorization header on a PROPFIND.
//
// The filesystem here is a billy memfs rather than a real pelfs volume,
// deliberately: what these tests are about is the CREDENTIAL reaching the
// filesystem surface with the right scope, and internal/vfsdav's own suite
// (plus scripts/webdav-clients-docker.sh) is where volume fidelity is
// proven. A volume here would make the test slow and would prove the same
// thing twice.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5/memfs"

	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
	"github.com/bbockelm/pelfs/internal/vfsdav"
)

const sessionToken = "a-browser-session-token-for-the-guard"

// sessions is both halves of what the two packages need from
// internal/browsesession: httpguard.SessionVerifier for the guard and
// localoauth.SessionPresence for A7 control 2. *browsesession.Manager
// satisfies both as it stands; this is the two-line stand-in.
type sessions struct{ live int }

func (s *sessions) ValidSession(tok string) bool { return s.live > 0 && tok == sessionToken }
func (s *sessions) Sessions() int                { return s.live }

type stack struct {
	t       *testing.T
	srv     *httptest.Server
	oauth   *localoauth.Server
	client  *localoauth.Client
	sess    *sessions
	origin  string
	browser *http.Client
}

// newStack is cmd/pelfs's wiring pass, in a test: the exact registration
// lines the browse server will carry.
func newStack(t *testing.T, writable bool) *stack {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	sess := &sessions{live: 1}
	oauth, err := localoauth.New(localoauth.Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: sess,
	})
	if err != nil {
		t.Fatalf("localoauth.New: %v", err)
	}
	fs := memfs.New()
	f, err := fs.Create("hello.txt")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := io.WriteString(f, "hello from a pelfs volume\n"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = f.Close()
	dav, err := vfsdav.New(vfsdav.Config{
		FS: fs, Prefix: "/dav", Auth: oauth.DAVAuth("pelfs"),
	})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}

	guard := httpguard.New(httpguard.Config{Port: port, Sessions: sess})
	r := guard.NewRouter()
	// ---- the wiring pass, verbatim ----
	r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceNavigation, "POST /oauth/authorize", oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceToken, "POST /oauth/token", oauth.TokenHandler())
	r.Handle(httpguard.SurfaceExternal, "/dav/", dav)
	// -----------------------------------
	// A stand-in for the JSON API, so the "a DAV token is not a session
	// token" half of the two-principals rule can be asserted end to end.
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/info", func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	// And the same token handler on the surface the design pencilled in, so
	// TestTokenEndpointCannotLiveOnSurfaceExchange can show why it moved.
	r.Handle(httpguard.SurfaceExchange, "POST /oauth/token-on-exchange", oauth.TokenHandler())

	srv := httptest.NewUnstartedServer(r)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	c, err := oauth.NewClient(localoauth.ClientRequest{
		Label:       "Cyberduck",
		RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
		Write:       writable,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &stack{
		t: t, srv: srv, oauth: oauth, client: c, sess: sess,
		origin: guard.Origin(),
		browser: &http.Client{
			// The browser is driven one hop at a time: the 303 to
			// Cyberduck's loopback listener must NOT be followed, because
			// there is no Cyberduck here and the code is what the test
			// wants.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

const verifier = "pelfs-integration-verifier-0123456789-abcdef"

var ticketRE = regexp.MustCompile(`name="consent_ticket" value="([^"]+)"`)

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func basic(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// navigate is what Cyberduck's browser launcher does: a top-level
// navigation, with no header of ours and no credential of any kind.
func (s *stack) navigate(u string) *http.Response {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	resp, err := s.browser.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

// submit is the click: a same-origin form POST, with exactly the headers a
// browser sends for one.
func (s *stack) submit(form url.Values) *http.Response {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.origin+"/oauth/authorize",
		strings.NewReader(form.Encode()))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", s.origin)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	resp, err := s.browser.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

func (s *stack) authorizeURL(scope string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.client.ID)
	q.Set("redirect_uri", s.client.Redirect)
	q.Set("scope", scope)
	q.Set("state", "state-from-the-client")
	q.Set("code_challenge", challenge(verifier))
	q.Set("code_challenge_method", "S256")
	return s.origin + "/oauth/authorize?" + q.Encode()
}

// token is the back-channel POST, shaped like the one google-oauth-client
// sends from inside Cyberduck: form-encoded, no Origin, no Sec-Fetch-Site,
// and no credential but the ones in the body.
func (s *stack) token(form url.Values, path string) (*http.Response, map[string]any) {
	s.t.Helper()
	if path == "" {
		path = "/oauth/token"
	}
	req, err := http.NewRequest(http.MethodPost, s.origin+path, strings.NewReader(form.Encode()))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.browser.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := map[string]any{}
	_ = json.Unmarshal(body, &out)
	return resp, out
}

// connect drives the entire flow and returns the access token, exactly as
// Cyberduck would hold it.
func (s *stack) connect(scope string) string {
	s.t.Helper()
	resp := s.navigate(s.authorizeURL(scope))
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("authorize: %d\n%s", resp.StatusCode, body)
	}
	m := ticketRE.FindSubmatch(body)
	if m == nil {
		s.t.Fatalf("no consent ticket:\n%s", body)
	}
	resp = s.submit(url.Values{"consent_ticket": {string(m[1])}, "decision": {"allow"}})
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		s.t.Fatalf("consent: %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		s.t.Fatal(err)
	}
	if !strings.HasPrefix(loc.String(), s.client.Redirect+"?") {
		s.t.Fatalf("redirected to %q, want the registered callback", loc)
	}
	if loc.Query().Get("state") != "state-from-the-client" {
		s.t.Fatalf("state %q", loc.Query().Get("state"))
	}
	// Cyberduck's loopback HttpServer has the code now; the exchange is the
	// back channel.
	tokResp, tok := s.token(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {s.client.Redirect},
		"client_id":     {s.client.ID},
	}, "")
	if tokResp.StatusCode != http.StatusOK {
		s.t.Fatalf("token: %d %v", tokResp.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		s.t.Fatalf("no access token in %v", tok)
	}
	if exp, _ := tok["expires_in"].(float64); exp <= 0 {
		s.t.Fatalf("expires_in is %v: Cyberduck never refreshes without it", tok["expires_in"])
	}
	return access
}

// dav sends one WebDAV request with whatever credential the caller names.
func (s *stack) dav(method, path, auth, body string) *http.Response {
	s.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.origin+path, r)
	if err != nil {
		s.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if method == "PROPFIND" {
		req.Header.Set("Depth", "1")
	}
	resp, err := s.browser.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	return resp
}

func TestEndToEndBearerTokenReachesTheWebDAVSurface(t *testing.T) {
	s := newStack(t, false)
	access := s.connect(localoauth.ScopeRead)

	t.Run("PROPFIND", func(t *testing.T) {
		resp := s.dav("PROPFIND", "/dav/", "Bearer "+access, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMultiStatus {
			t.Fatalf("status %d, want 207", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "hello.txt") {
			t.Errorf("the listing has no hello.txt:\n%s", body)
		}
	})

	t.Run("GET", func(t *testing.T) {
		resp := s.dav(http.MethodGet, "/dav/hello.txt", "Bearer "+access, "")
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "hello from a pelfs volume\n" {
			t.Errorf("status %d body %q", resp.StatusCode, body)
		}
	})

	t.Run("a read-only token answers 403 on PUT, not 401", func(t *testing.T) {
		// 403 and not 401 is the whole point of the Grant seam: a 401 would
		// send the client back to ask for a password, which is the wrong
		// instruction and, for an OAuth profile, the wrong dialog.
		resp := s.dav(http.MethodPut, "/dav/new.txt", "Bearer "+access, "nope")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})

	t.Run("a revoked token stops working mid-connection", func(t *testing.T) {
		s.oauth.RevokeGrant(s.oauth.Grants()[0].Ref)
		resp := s.dav("PROPFIND", "/dav/", "Bearer "+access, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
	})
}

func TestEndToEndWritableSessionCanUpload(t *testing.T) {
	s := newStack(t, true)
	access := s.connect(localoauth.ScopeRead + " " + localoauth.ScopeWrite)
	resp := s.dav(http.MethodPut, "/dav/new.txt", "Bearer "+access, "written over WebDAV")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT: status %d, want 201", resp.StatusCode)
	}
	got := s.dav(http.MethodGet, "/dav/new.txt", "Bearer "+access, "")
	defer got.Body.Close()
	body, _ := io.ReadAll(got.Body)
	if string(body) != "written over WebDAV" {
		t.Errorf("read back %q", body)
	}
}

func TestEndToEndBasicCredentialIsTheOtherClientsPath(t *testing.T) {
	s := newStack(t, false)
	resp := s.dav("PROPFIND", "/dav/", "Basic "+basic(s.client.BasicUser, s.client.BasicPassword), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		t.Fatalf("status %d, want 207", resp.StatusCode)
	}
	// And the same credential is read-only on a read-only session.
	put := s.dav(http.MethodPut, "/dav/x.txt",
		"Basic "+basic(s.client.BasicUser, s.client.BasicPassword), "x")
	defer put.Body.Close()
	if put.StatusCode != http.StatusForbidden {
		t.Errorf("PUT with a read-only Basic credential: %d, want 403", put.StatusCode)
	}
}

// TestTheTwoPrincipalsNeverMeet is A6's table, end to end: the browser
// session does not reach /dav/*, and a DAV token does not reach the JSON
// API.
func TestTheTwoPrincipalsNeverMeet(t *testing.T) {
	s := newStack(t, false)
	access := s.connect(localoauth.ScopeRead)

	t.Run("the session token is not a DAV credential", func(t *testing.T) {
		req, _ := http.NewRequest("PROPFIND", s.origin+"/dav/", nil)
		req.Header.Set(httpguard.SessionHeader, sessionToken)
		resp, err := s.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("a DAV token does not reach the JSON API", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, s.origin+"/api/v1/info", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Origin", s.origin)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := s.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
	})

	t.Run("a DAV token reaches no route but /dav/*", func(t *testing.T) {
		// The negative that matters most in A7's scope table — a DAV client
		// cannot publish — asserted as a property of the ROUTE TABLE rather
		// than of a handler: every route but /dav/* either requires the
		// session header or refuses an Authorization header outright.
		for _, path := range []string{"/api/v1/info", "/oauth/token-on-exchange"} {
			req, _ := http.NewRequest(http.MethodPost, s.origin+path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+access)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", s.origin)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			resp, err := s.browser.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Errorf("%s accepted a DAV token", path)
			}
		}
	})
}

// TestChallengeNarrowing is verification 2d(iii): a client that offered a
// Bearer token and was refused must not be told about Basic, or Cyberduck
// may drop into a password prompt for a profile that has no password field.
func TestChallengeNarrowing(t *testing.T) {
	s := newStack(t, false)

	resp := s.dav("PROPFIND", "/dav/", "Bearer not-a-real-token", "")
	_ = resp.Body.Close()
	got := resp.Header.Values("WWW-Authenticate")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Bearer ") {
		t.Errorf("a refused Bearer was challenged with %q; want Bearer only", got)
	}

	resp = s.dav("PROPFIND", "/dav/", "Basic "+basic("nobody", "wrong"), "")
	_ = resp.Body.Close()
	got = resp.Header.Values("WWW-Authenticate")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Basic ") {
		t.Errorf("a refused Basic was challenged with %q; want Basic only", got)
	}

	// A client that offered nothing discovers both paths.
	resp = s.dav("PROPFIND", "/dav/", "", "")
	_ = resp.Body.Close()
	got = resp.Header.Values("WWW-Authenticate")
	if len(got) != 2 {
		t.Errorf("an anonymous request was challenged with %q; want both schemes", got)
	}
}

// TestTokenEndpointCannotLiveOnSurfaceExchange is the design correction,
// pinned as a test so nobody moves the route back. docs/design-webui.md and
// cmd/pelfs/browse.go's route comment both pencil POST /oauth/token in on
// SurfaceExchange; a Cyberduck-shaped request cannot pass that surface.
func TestTokenEndpointCannotLiveOnSurfaceExchange(t *testing.T) {
	s := newStack(t, true)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"},
		"client_id": {s.client.ID}}

	resp, _ := s.token(form, "/oauth/token-on-exchange")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d; expected 403 — a non-browser client sends no "+
			"provenance signal, which is what SurfaceExchange requires",
			resp.StatusCode)
	}
	// The same request on the surface it belongs to gets as far as the
	// protocol: an invalid_grant, which is a refusal BY THE HANDLER rather
	// than by the transport.
	resp, body := s.token(form, "/oauth/token")
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("SurfaceToken answered %d %v", resp.StatusCode, body)
	}
}

// TestGuardIsInFront is A7 control 1: the Host allowlist and the standard
// CSRF guard come first, on every one of these routes.
func TestGuardIsInFront(t *testing.T) {
	s := newStack(t, false)
	for _, path := range []string{"/oauth/authorize", "/oauth/token", "/dav/"} {
		req, err := http.NewRequest(http.MethodGet, s.origin+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		// A rebound Host: the browser thinks it is same-origin with us, and
		// the one thing it cannot forge is the name in this header.
		req.Host = "evil.example.com"
		resp, err := s.browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("%s with a rebound Host: %d, want 421", path, resp.StatusCode)
		}
	}
	// A cross-site form POST at the consent endpoint — which is what a page
	// on another loopback port would send, since by F3 it is same-SITE.
	req, _ := http.NewRequest(http.MethodPost, s.origin+"/oauth/authorize",
		strings.NewReader("decision=allow"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Origin", "http://127.0.0.1:1")
	resp, err := s.browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-site consent POST: %d, want 403", resp.StatusCode)
	}
	// And no response anywhere on this listener carries a CORS header or a
	// cookie.
	resp = s.navigate(s.authorizeURL(localoauth.ScopeRead))
	_ = resp.Body.Close()
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-allow") {
			t.Errorf("the consent page carries %s", k)
		}
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Error("the consent page sets a cookie")
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", resp.Header.Get("Cache-Control"))
	}
}

// TestNoSessionNoAuthorization is A7 control 2 through the real stack: sign
// out of the browser and the authorization endpoint stops minting.
func TestNoSessionNoAuthorization(t *testing.T) {
	s := newStack(t, false)
	s.sess.live = 0
	resp := s.navigate(s.authorizeURL(localoauth.ScopeRead))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if ticketRE.Match(body) {
		t.Error("a session-less authorization still rendered a consent ticket")
	}
}
