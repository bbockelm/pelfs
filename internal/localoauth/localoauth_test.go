package localoauth

// The authorization server's own tests. WHITE BOX, in the package, for one
// reason that is worth the trade: A7's request-time scope check ("that check
// is at grant time AND at request time, because the session's mode cannot
// change mid-life but a future version might let it") is untestable from
// outside — there is no exported way to produce a writable grant on a
// read-only session, which is the whole point. TestRequestTimeScopeClamp
// reaches into cfg to build exactly the state a future bug would produce.
// The end-to-end tests, where the guard and the WebDAV handler are real,
// are in dav_integration_test.go in the external test package.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/davprofile"
)

// A verifier of the shortest legal length (RFC 7636: 43..128 of the
// unreserved set), and its S256 challenge.
const testVerifier = "pelfs-test-verifier-0123456789-abcdefghijklm"

type fakeSessions int

func (f fakeSessions) Sessions() int { return int(f) }

type harness struct {
	t      *testing.T
	s      *Server
	clock  time.Time
	client *Client
}

func newHarness(t *testing.T, writable bool) *harness {
	t.Helper()
	h := &harness{t: t, clock: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
	s, err := New(Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: fakeSessions(1),
		Now:      func() time.Time { return h.clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.s = s
	c, err := s.NewClient(ClientRequest{
		Label:       "Cyberduck",
		RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
		Write:       writable,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	h.client = c
	return h
}

func (h *harness) query() url.Values {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", h.client.ID)
	q.Set("redirect_uri", h.client.Redirect)
	q.Set("code_challenge", s256(testVerifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", "cyberduck-state-value")
	if h.client.Write {
		q.Set("scope", ScopeRead+" "+ScopeWrite)
	} else {
		q.Set("scope", ScopeRead)
	}
	return q
}

// get drives GET /oauth/authorize and asserts the invariant that holds on
// EVERY response from it, valid or not: NO LOCATION HEADER. The GET half of
// this endpoint cannot redirect, which is the structural half of "one real
// user gesture" — see the package comment.
func (h *harness) get(q url.Values) *httptest.ResponseRecorder {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	h.s.AuthorizeHandler().ServeHTTP(w, r)
	if loc := w.Header().Get("Location"); loc != "" {
		h.t.Fatalf("GET /oauth/authorize emitted a redirect to %q: this endpoint "+
			"must never redirect without a consent POST", loc)
	}
	return w
}

var ticketRE = regexp.MustCompile(`name="` + ConsentTicketField + `" value="([^"]+)"`)

// ticket pulls the consent ticket out of the rendered page, which is the
// only place it exists.
func (h *harness) ticket(w *httptest.ResponseRecorder) string {
	h.t.Helper()
	m := ticketRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		h.t.Fatalf("no consent ticket in the page (status %d):\n%s", w.Code, w.Body.String())
	}
	return m[1]
}

func (h *harness) consent(ticket, decision string) *httptest.ResponseRecorder {
	h.t.Helper()
	form := url.Values{}
	if ticket != "" {
		form.Set(ConsentTicketField, ticket)
	}
	if decision != "" {
		form.Set(ConsentDecisionField, decision)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.s.AuthorizeHandler().ServeHTTP(w, r)
	return w
}

// code drives the whole front channel and returns the authorization code.
func (h *harness) code() string {
	h.t.Helper()
	page := h.get(h.query())
	if page.Code != http.StatusOK {
		h.t.Fatalf("consent page: status %d\n%s", page.Code, page.Body.String())
	}
	w := h.consent(h.ticket(page), "allow")
	if w.Code != http.StatusSeeOther {
		h.t.Fatalf("consent POST: status %d, want 303\n%s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		h.t.Fatalf("Location: %v", err)
	}
	if got, want := loc.Scheme+"://"+loc.Host+loc.Path, h.client.Redirect; got != want {
		h.t.Fatalf("redirected to %q, want %q", got, want)
	}
	if got := loc.Query().Get("state"); got != "cyberduck-state-value" {
		h.t.Fatalf("state came back as %q", got)
	}
	c := loc.Query().Get("code")
	if c == "" {
		h.t.Fatalf("no code in %q", loc)
	}
	return c
}

func (h *harness) postToken(form url.Values) (*httptest.ResponseRecorder, tokenResponse) {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.s.TokenHandler().ServeHTTP(w, r)
	var resp tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

func (h *harness) exchange(code, verifier string) (*httptest.ResponseRecorder, tokenResponse) {
	h.t.Helper()
	return h.postToken(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {h.client.Redirect},
		"client_id":     {h.client.ID},
	})
}

// ------------------------------------------------------------- happy path

func TestAuthorizationCodePKCEHappyPath(t *testing.T) {
	h := newHarness(t, false)
	w, tok := h.exchange(h.code(), testVerifier)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: status %d\n%s", w.Code, w.Body.String())
	}
	if tok.AccessToken == "" {
		t.Fatal("no access_token")
	}
	if tok.TokenType != "Bearer" {
		t.Errorf("token_type %q, want Bearer", tok.TokenType)
	}
	// EXPIRES_IN IS NOT OPTIONAL: Cyberduck treats a token with no expiry
	// as one that never expires and never refreshes it, so pelfs's own
	// AccessTTL would turn into 401s the client cannot recover from
	// (docs/design-webui.md, verification 2d).
	if tok.ExpiresIn != int(AccessTTL.Seconds()) {
		t.Errorf("expires_in %d, want %d", tok.ExpiresIn, int(AccessTTL.Seconds()))
	}
	if tok.RefreshToken == "" {
		t.Error("no refresh_token: Cyberduck needs one to reconnect without a new consent screen")
	}
	if tok.Scope != ScopeRead {
		t.Errorf("scope %q, want %q", tok.Scope, ScopeRead)
	}
	g, ok := h.s.Verify(tok.AccessToken)
	if !ok {
		t.Fatal("the token this server just minted does not verify")
	}
	if g.Write {
		t.Error("a read-only session produced a writable grant")
	}
	if got := h.s.Grants(); len(got) != 1 || got[0].Label != "Cyberduck" {
		t.Errorf("Grants() = %+v", got)
	}
	if got := h.s.Clients(); len(got) != 1 || !got[0].Consented || got[0].Grants != 1 {
		t.Errorf("Clients() = %+v", got)
	}
}

func TestRefreshKeepsTheTokenAliveAndRetiresTheOldAccessToken(t *testing.T) {
	h := newHarness(t, false)
	_, first := h.exchange(h.code(), testVerifier)

	// Past the access token's life: Cyberduck's interceptor notices
	// isExpired() and refreshes BEFORE the request goes out.
	h.clock = h.clock.Add(AccessTTL + time.Second)
	if _, ok := h.s.Verify(first.AccessToken); ok {
		t.Fatal("an expired access token still verifies")
	}
	w, second := h.postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {h.client.ID},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: status %d\n%s", w.Code, w.Body.String())
	}
	if second.AccessToken == first.AccessToken {
		t.Error("refresh returned the same access token")
	}
	if second.RefreshToken != first.RefreshToken {
		t.Error("the refresh token was rotated; see localoauth.refresh for why it is not")
	}
	if second.ExpiresIn == 0 {
		t.Error("refresh answered without expires_in")
	}
	if _, ok := h.s.Verify(second.AccessToken); !ok {
		t.Error("the refreshed access token does not verify")
	}
	if _, ok := h.s.Verify(first.AccessToken); ok {
		t.Error("the old access token still verifies after a refresh")
	}
	// And the refresh token is bound to its client.
	if w, _ := h.postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"client_id":     {"not-the-client"},
	}); w.Code != http.StatusBadRequest {
		t.Errorf("refresh with a foreign client_id: status %d, want 400", w.Code)
	}
}

// -------------------------------------------------------------- the traps

func TestTamperedCodeVerifierIsRefusedAndBurnsTheCode(t *testing.T) {
	h := newHarness(t, false)
	code := h.code()
	// One character different, and the same length, so nothing but the
	// SHA-256 comparison can be what rejects it.
	bad := "Xelfs-test-verifier-0123456789-abcdefghijklm"
	w, tok := h.exchange(code, bad)
	if w.Code != http.StatusBadRequest || tok.AccessToken != "" {
		t.Fatalf("tampered verifier: status %d body %s", w.Code, w.Body.String())
	}
	if got := h.s.Counts().VerifierMismatches; got != 1 {
		t.Errorf("VerifierMismatches = %d, want 1", got)
	}
	// The code died with the failure: there is no legitimate retry with a
	// different verifier.
	if w, _ := h.exchange(code, testVerifier); w.Code != http.StatusBadRequest {
		t.Errorf("the right verifier still redeemed a code a wrong one had touched: %d", w.Code)
	}
	if n := len(h.s.Grants()); n != 0 {
		t.Errorf("%d grants exist after a failed exchange", n)
	}
}

func TestReplayedCodeIsCountedAndRevokesWhatTheFirstOneBought(t *testing.T) {
	h := newHarness(t, false)
	code := h.code()
	_, first := h.exchange(code, testVerifier)
	if _, ok := h.s.Verify(first.AccessToken); !ok {
		t.Fatal("the first exchange did not produce a working token")
	}
	w, second := h.exchange(code, testVerifier)
	if w.Code != http.StatusBadRequest || second.AccessToken != "" {
		t.Fatalf("replay: status %d body %s", w.Code, w.Body.String())
	}
	if got := h.s.Counts().CodeReplays; got != 1 {
		t.Errorf("CodeReplays = %d, want 1", got)
	}
	// A replay means the code leaked, so the token it bought is what is at
	// risk (RFC 6819 §5.2.1.1).
	if _, ok := h.s.Verify(first.AccessToken); ok {
		t.Error("a replayed code did not revoke the grant the first exchange created")
	}
	if n := len(h.s.Grants()); n != 0 {
		t.Errorf("%d grants survive a replay", n)
	}
}

func TestRedirectURIOffByOneCharacterIsRefusedAndNothingIsRedirected(t *testing.T) {
	h := newHarness(t, false)
	q := h.query()
	// The last character of the path, and nothing else.
	q.Set("redirect_uri", strings.TrimSuffix(h.client.Redirect, "k")+"K")
	w := h.get(q) // h.get asserts there is no Location header
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	if got := h.s.Counts().RedirectMismatches; got != 1 {
		t.Errorf("RedirectMismatches = %d, want 1", got)
	}
	if strings.Contains(w.Body.String(), q.Get("redirect_uri")) {
		t.Error("the error page echoes the request's redirect_uri back to the user")
	}
	if ticketRE.MatchString(w.Body.String()) {
		t.Error("a refused request still rendered a consent ticket")
	}
	// And the same string at exchange time, against a code that is valid.
	code := h.code()
	w2, _ := h.postToken(url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {testVerifier},
		"redirect_uri":  {h.client.Redirect + "/"},
		"client_id":     {h.client.ID},
	})
	if w2.Code != http.StatusBadRequest {
		t.Errorf("exchange with a different redirect_uri: status %d, want 400", w2.Code)
	}
}

func TestPKCEIsRequiredNotAccepted(t *testing.T) {
	for _, tc := range []struct {
		name              string
		challenge, method string
	}{
		{"absent", "", ""},
		{"challenge but no method", s256(testVerifier), ""},
		{"plain is not accepted", testVerifier, "plain"},
		{"method S256 but no challenge", "", "S256"},
		{"challenge is not a SHA-256 digest", "too-short", "S256"},
		{"lowercase method", s256(testVerifier), "s256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			q := h.query()
			q.Set("code_challenge", tc.challenge)
			q.Set("code_challenge_method", tc.method)
			if tc.challenge == "" {
				q.Del("code_challenge")
			}
			if tc.method == "" {
				q.Del("code_challenge_method")
			}
			w := h.get(q)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400\n%s", w.Code, w.Body.String())
			}
			if got := h.s.Counts().MissingPKCE; got != 1 {
				t.Errorf("MissingPKCE = %d, want 1", got)
			}
		})
	}
}

// ------------------------------------------------------- consent, at length

// TestConsentIsStructural is A7 control 6: a code cannot be minted without
// a human acting on a screen. Every row here is a way the click could be
// skipped if the mechanism were a convention rather than a mechanism.
func TestConsentIsStructural(t *testing.T) {
	t.Run("the GET alone mints nothing", func(t *testing.T) {
		h := newHarness(t, false)
		w := h.get(h.query()) // asserts no Location
		if w.Code != http.StatusOK {
			t.Fatalf("status %d", w.Code)
		}
		if n := len(h.s.codes); n != 0 {
			t.Errorf("%d codes minted by a GET", n)
		}
	})

	t.Run("the page runs no script and says so in its CSP", func(t *testing.T) {
		h := newHarness(t, false)
		w := h.get(h.query())
		csp := w.Header().Get("Content-Security-Policy")
		for _, want := range []string{"script-src 'none'", "form-action 'self'",
			"frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("CSP %q lacks %q", csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") {
			t.Errorf("CSP %q allows unsafe-inline", csp)
		}
		// The header is what makes an auto-submit impossible; the absence
		// of a script in the body is what makes it obvious.
		body := strings.ToLower(w.Body.String())
		for _, forbidden := range []string{"<script", "javascript:", "onload=", "onclick=", ".submit("} {
			if strings.Contains(body, forbidden) {
				t.Errorf("the consent page contains %q", forbidden)
			}
		}
	})

	t.Run("the page names what is being authorized", func(t *testing.T) {
		h := newHarness(t, false)
		body := h.get(h.query()).Body.String()
		for _, want := range []string{"Cyberduck", "pelican://osg-htc.org/user/bbockelman",
			h.client.Redirect, "read only"} {
			if !strings.Contains(body, want) {
				t.Errorf("the consent page does not name %q", want)
			}
		}
		if strings.Contains(body, h.client.ID) {
			t.Error("the consent page renders the client_id, which is a secret")
		}
	})

	t.Run("a POST with no ticket mints nothing", func(t *testing.T) {
		h := newHarness(t, false)
		_ = h.get(h.query()) // a live pending record exists
		w := h.consent("", "allow")
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Fatalf("status %d, Location %q", w.Code, w.Header().Get("Location"))
		}
		if got := h.s.Counts().ConsentTicketsRefused; got != 1 {
			t.Errorf("ConsentTicketsRefused = %d, want 1", got)
		}
	})

	t.Run("a forged ticket mints nothing", func(t *testing.T) {
		h := newHarness(t, false)
		_ = h.get(h.query())
		w := h.consent("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5", "allow")
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Fatalf("status %d, Location %q", w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("a ticket is single use", func(t *testing.T) {
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		if w := h.consent(ticket, "allow"); w.Code != http.StatusSeeOther {
			t.Fatalf("first submit: status %d", w.Code)
		}
		w := h.consent(ticket, "allow")
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("a resubmitted consent page minted a second code: %d %q",
				w.Code, w.Header().Get("Location"))
		}
	})

	t.Run("Deny mints nothing and is counted", func(t *testing.T) {
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		w := h.consent(ticket, "deny")
		if w.Header().Get("Location") != "" {
			t.Fatalf("Deny redirected to %q", w.Header().Get("Location"))
		}
		if n := len(h.s.codes); n != 0 {
			t.Errorf("%d codes after Deny", n)
		}
		if got := h.s.Counts().ConsentDenied; got != 1 {
			t.Errorf("ConsentDenied = %d, want 1", got)
		}
		// And the ticket is spent, so Deny cannot be followed by Allow.
		if w := h.consent(ticket, "allow"); w.Code != http.StatusBadRequest {
			t.Errorf("a denied screen was re-answered: %d", w.Code)
		}
	})

	t.Run("a missing decision is a refusal", func(t *testing.T) {
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		if w := h.consent(ticket, ""); w.Header().Get("Location") != "" {
			t.Errorf("a form with no decision authorized something: %q",
				w.Header().Get("Location"))
		}
	})

	t.Run("a consent page expires", func(t *testing.T) {
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		h.clock = h.clock.Add(ConsentTTL + time.Second)
		if w := h.consent(ticket, "allow"); w.Code != http.StatusBadRequest {
			t.Errorf("a stale consent page still authorized: %d", w.Code)
		}
	})

	t.Run("a non-form body is refused", func(t *testing.T) {
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
			strings.NewReader(`{"`+ConsentDecisionField+`":"allow","`+ConsentTicketField+`":"`+ticket+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.s.AuthorizeHandler().ServeHTTP(w, r)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status %d, want 415", w.Code)
		}
	})

	t.Run("consent pages are capped", func(t *testing.T) {
		h := newHarness(t, false)
		for i := 0; i < maxPending*3; i++ {
			_ = h.get(h.query())
		}
		h.s.mu.Lock()
		n := len(h.s.pending)
		h.s.mu.Unlock()
		if n > maxPending {
			t.Errorf("%d pending consent pages, cap is %d", n, maxPending)
		}
	})

	t.Run("a code still needs its consent even after one succeeded", func(t *testing.T) {
		// The divergence from verification 2e, pinned: consent is NOT
		// remembered per client_id at /authorize, because remembering it
		// there is the silent-drive primitive control 6 removes.
		h := newHarness(t, false)
		_ = h.code()
		w := h.get(h.query())
		if w.Code != http.StatusOK || w.Header().Get("Location") != "" {
			t.Fatalf("a second authorization skipped the screen: %d %q",
				w.Code, w.Header().Get("Location"))
		}
		if !ticketRE.MatchString(w.Body.String()) {
			t.Error("the second authorization did not render a consent screen")
		}
	})
}

// -------------------------------------------------------------- the scope

func TestReadOnlySessionCannotMintAWritableGrant(t *testing.T) {
	h := newHarness(t, false)
	// 1. The registration is refused outright.
	if _, err := h.s.NewClient(ClientRequest{
		Label: "Mountain Duck", Write: true,
		RedirectURI: davprofile.RedirectURI(52002),
	}); err == nil {
		t.Fatal("a read-only session registered a writable client")
	}
	// 2. And a read-only client that ASKS for write is refused at
	//    /authorize rather than silently downgraded.
	q := h.query()
	q.Set("scope", ScopeRead+" "+ScopeWrite)
	w := h.get(q)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("scope escalation: status %d\n%s", w.Code, w.Body.String())
	}
	if ticketRE.MatchString(w.Body.String()) {
		t.Error("a scope escalation still rendered a consent screen")
	}
	// 3. An unknown scope is a refusal, not something to ignore.
	q.Set("scope", ScopeRead+" pelfs.publish")
	if w := h.get(q); w.Code != http.StatusBadRequest {
		t.Errorf("an unknown scope was accepted: %d", w.Code)
	}
}

func TestWritableSessionMintsBothKinds(t *testing.T) {
	h := newHarness(t, true)
	_, tok := h.exchange(h.code(), testVerifier)
	g, ok := h.s.Verify(tok.AccessToken)
	if !ok || !g.Write {
		t.Fatalf("--rw session did not produce a writable grant: %+v ok=%v", g, ok)
	}
	if tok.Scope != ScopeRead+" "+ScopeWrite {
		t.Errorf("scope %q", tok.Scope)
	}
	// A --rw session MAY hand out a read-only credential, which is the
	// asymmetry A7 states: the session's mode is a ceiling, not a floor.
	ro, err := h.s.NewClient(ClientRequest{Label: "rclone", Write: false,
		RedirectURI: davprofile.RedirectURI(52003)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	h.client = ro
	q := h.query()
	q.Set("scope", ScopeRead)
	page := h.get(q)
	w := h.consent(h.ticket(page), "allow")
	loc, _ := url.Parse(w.Header().Get("Location"))
	_, tok2 := h.exchange(loc.Query().Get("code"), testVerifier)
	if g, ok := h.s.Verify(tok2.AccessToken); !ok || g.Write {
		t.Errorf("a read-only client on a --rw session got Write=%v", g.Write)
	}
}

// TestRequestTimeScopeClamp is the third of A7's three enforcement points:
// "that check is at grant time AND at request time, because the session's
// mode cannot change mid-life but a future version might let it." This
// builds the state such a future version could produce and asserts the
// clamp catches it.
func TestRequestTimeScopeClamp(t *testing.T) {
	h := newHarness(t, true)
	_, tok := h.exchange(h.code(), testVerifier)
	if g, _ := h.s.Verify(tok.AccessToken); !g.Write {
		t.Fatal("setup: the grant is not writable")
	}
	h.s.cfg.Writable = false // what a mid-life mode change would look like
	g, ok := h.s.Verify(tok.AccessToken)
	if !ok {
		t.Fatal("the token stopped verifying entirely")
	}
	if g.Write {
		t.Error("a writable grant survived the session going read-only")
	}
	if got := h.s.Counts().ScopeClamped; got == 0 {
		t.Error("the clamp was not counted")
	}
}

// ---------------------------------------------------------- revocation etc

func TestRevocation(t *testing.T) {
	t.Run("a revoked grant's token is dead", func(t *testing.T) {
		h := newHarness(t, false)
		_, tok := h.exchange(h.code(), testVerifier)
		ref := h.s.Grants()[0].Ref
		if !h.s.RevokeGrant(ref) {
			t.Fatal("RevokeGrant reported nothing to revoke")
		}
		if _, ok := h.s.Verify(tok.AccessToken); ok {
			t.Error("a revoked token still verifies")
		}
		if w, _ := h.postToken(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
			"client_id": {h.client.ID},
		}); w.Code != http.StatusBadRequest {
			t.Errorf("a revoked grant's refresh token still worked: %d", w.Code)
		}
		// The client survives and can authorize again — which is what makes
		// this INDIVIDUAL revocation rather than removing the profile.
		if len(h.s.Clients()) != 1 {
			t.Error("revoking a grant removed the client")
		}
	})

	t.Run("a revoked client takes everything with it", func(t *testing.T) {
		h := newHarness(t, false)
		_, tok := h.exchange(h.code(), testVerifier)
		page := h.get(h.query()) // a live consent page, too
		ticket := h.ticket(page)
		if !h.s.Revoke(h.client.Ref) {
			t.Fatal("Revoke reported nothing to revoke")
		}
		if _, ok := h.s.Verify(tok.AccessToken); ok {
			t.Error("a revoked client's OAuth token still verifies")
		}
		if _, ok := h.s.verifyBasic(h.client.BasicUser, h.client.BasicPassword); ok {
			t.Error("a revoked client's Basic credential still verifies")
		}
		if w := h.consent(ticket, "allow"); w.Code != http.StatusBadRequest {
			t.Errorf("a revoked client's outstanding consent page still authorized: %d", w.Code)
		}
		if w := h.get(h.query()); w.Code != http.StatusBadRequest {
			t.Errorf("a revoked client_id is still known: %d", w.Code)
		}
		if h.s.Revoke(h.client.Ref) {
			t.Error("Revoke succeeded twice")
		}
	})

	t.Run("an expired token is dead without anything sweeping", func(t *testing.T) {
		h := newHarness(t, false)
		_, tok := h.exchange(h.code(), testVerifier)
		h.clock = h.clock.Add(AccessTTL + time.Nanosecond)
		if _, ok := h.s.Verify(tok.AccessToken); ok {
			t.Error("an expired token verifies")
		}
	})

	t.Run("an expired code cannot be exchanged", func(t *testing.T) {
		h := newHarness(t, false)
		code := h.code()
		h.clock = h.clock.Add(CodeTTL + time.Second)
		if w, _ := h.exchange(code, testVerifier); w.Code != http.StatusBadRequest {
			t.Errorf("an expired code was exchanged: %d", w.Code)
		}
	})

	t.Run("a token does not survive the process", func(t *testing.T) {
		// The per-process key, asserted: the same token against a second
		// server (a restarted `pelfs browse` on the same port) is nothing.
		h := newHarness(t, false)
		_, tok := h.exchange(h.code(), testVerifier)
		next := newHarness(t, false)
		if _, ok := next.s.Verify(tok.AccessToken); ok {
			t.Error("a token from a previous process verified against a new one")
		}
	})
}

func TestBasicCredentialIsPerClientAndRevocable(t *testing.T) {
	h := newHarness(t, false)
	if !strings.HasPrefix(h.client.BasicUser, "pelfs-") || h.client.BasicPassword == "" {
		t.Fatalf("client credentials look wrong: %q %q", h.client.BasicUser, h.client.BasicPassword)
	}
	if _, ok := h.s.verifyBasic(h.client.BasicUser, h.client.BasicPassword); !ok {
		t.Fatal("the Basic credential does not verify")
	}
	if _, ok := h.s.verifyBasic(h.client.BasicUser, "wrong"); ok {
		t.Error("a wrong password verified")
	}
	if _, ok := h.s.verifyBasic("pelfs-nobody", h.client.BasicPassword); ok {
		t.Error("a wrong username verified")
	}
	if _, ok := h.s.verifyBasic("", ""); ok {
		t.Error("an empty credential verified")
	}
	second, err := h.s.NewClient(ClientRequest{Label: "WinSCP",
		RedirectURI: davprofile.RedirectURI(52004)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if second.BasicUser == h.client.BasicUser || second.BasicPassword == h.client.BasicPassword {
		t.Error("two clients share a credential")
	}
	h.s.Revoke(h.client.Ref)
	if _, ok := h.s.verifyBasic(second.BasicUser, second.BasicPassword); !ok {
		t.Error("revoking one client's credential killed another's")
	}
}

// ------------------------------------------------------- the A7 row-by-row

// TestA7Controls is one row per control in docs/design-webui.md's A7, so
// that a change which deletes one of them fails a test that names it.
func TestA7Controls(t *testing.T) {
	t.Run("1 the transport guard is in front, not here", func(t *testing.T) {
		// The Host allowlist and the Sec-Fetch-Site check belong to
		// internal/httpguard and this package must NOT grow its own: two
		// implementations of one rule is one implementation and one
		// decoration. What is asserted here is that no handler in this
		// package reads Host or Origin to decide anything — the end-to-end
		// proof that the guard is actually in front is
		// TestGuardedRoutesRefuseARebindingHost in the integration file.
		h := newHarness(t, false)
		r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+h.query().Encode(), nil)
		r.Host = "evil.example.com"
		r.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		h.s.AuthorizeHandler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("this package answered %d to a bad Host; that decision is "+
				"internal/httpguard's and duplicating it here would let the two drift", w.Code)
		}
	})

	t.Run("2 a live browser session is required", func(t *testing.T) {
		h := newHarness(t, false)
		s, err := New(Config{Volume: "v", Sessions: fakeSessions(0),
			Now: func() time.Time { return h.clock }})
		if err != nil {
			t.Fatal(err)
		}
		c, err := s.NewClient(ClientRequest{Label: "Cyberduck",
			RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort)})
		if err != nil {
			t.Fatal(err)
		}
		h2 := &harness{t: t, s: s, clock: h.clock, client: c}
		w := h2.get(h2.query())
		if w.Code != http.StatusForbidden {
			t.Errorf("status %d, want 403", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Open pelfs from your terminal first") {
			t.Errorf("body does not say what to do:\n%s", w.Body.String())
		}
		if got := s.Counts().NoSession; got != 1 {
			t.Errorf("NoSession = %d", got)
		}
		// And a nil SessionPresence refuses too, which is the right failure
		// for a misconfigured server.
		s2, _ := New(Config{})
		if s2.hasSession() {
			t.Error("a nil SessionPresence reported a live session")
		}
	})

	t.Run("3 redirect_uri is an exact-string allowlist", func(t *testing.T) {
		h := newHarness(t, false)
		for _, bad := range []string{
			"", "http://127.0.0.1:52001/pelfs/oauth/callback/",
			"http://127.0.0.1:52002/pelfs/oauth/callback",
			"http://127.0.0.1:52001/pelfs/oauth/callbac",
			"http://localhost:52001/pelfs/oauth/callback",
			"http://127.0.0.1:52001/pelfs/oauth/callback?x=1",
			"http://evil.example/pelfs/oauth/callback",
			"HTTP://127.0.0.1:52001/pelfs/oauth/callback",
		} {
			q := h.query()
			q.Set("redirect_uri", bad)
			if w := h.get(q); w.Code != http.StatusBadRequest {
				t.Errorf("redirect_uri %q was accepted (%d)", bad, w.Code)
			}
		}
	})

	t.Run("4 client_id is a per-download secret", func(t *testing.T) {
		h := newHarness(t, false)
		if len(h.client.ID) < 40 {
			t.Errorf("client_id is %d characters; it should be 32 random bytes", len(h.client.ID))
		}
		second, err := h.s.NewClient(ClientRequest{Label: "another",
			RedirectURI: davprofile.RedirectURI(52005)})
		if err != nil {
			t.Fatal(err)
		}
		if second.ID == h.client.ID {
			t.Error("two downloads share a client_id")
		}
		for _, bad := range []string{"", "not-a-client", h.client.ID + "x", h.client.ID[:10]} {
			q := h.query()
			q.Set("client_id", bad)
			if w := h.get(q); w.Code != http.StatusBadRequest {
				t.Errorf("client_id %q was accepted (%d)", bad, w.Code)
			}
		}
		if got := h.s.Counts().UnknownClients; got != 4 {
			t.Errorf("UnknownClients = %d, want 4", got)
		}
	})

	t.Run("5 PKCE S256 required", func(t *testing.T) {
		// Covered exhaustively by TestPKCEIsRequiredNotAccepted; this row
		// exists so the control has a name in this table.
		h := newHarness(t, false)
		q := h.query()
		q.Del("code_challenge")
		if w := h.get(q); w.Code != http.StatusBadRequest {
			t.Errorf("status %d, want 400", w.Code)
		}
	})

	t.Run("6 one real user gesture", func(t *testing.T) {
		// Covered exhaustively by TestConsentIsStructural; the row here is
		// the single fact that matters: a GET mints nothing and a POST
		// needs a ticket that only the page has.
		h := newHarness(t, false)
		_ = h.get(h.query())
		if n := len(h.s.codes); n != 0 {
			t.Fatalf("%d codes without a click", n)
		}
		if w := h.consent("", "allow"); w.Header().Get("Location") != "" {
			t.Error("a POST with no ticket authorized something")
		}
	})

	t.Run("7 no custom-header rule, and none is smuggled in", func(t *testing.T) {
		// The control is that /authorize works WITHOUT any pelfs header,
		// because Cyberduck reaches it by navigation. A later "make it
		// consistent with the API" edit would break the primary client, so
		// the happy path is asserted with a bare navigation: no
		// X-Pelfs-Session, no Origin, no Sec-Fetch-Site.
		h := newHarness(t, false)
		page := h.get(h.query())
		if page.Code != http.StatusOK {
			t.Fatalf("a bare navigation was refused: %d", page.Code)
		}
		if w := h.consent(h.ticket(page), "allow"); w.Code != http.StatusSeeOther {
			t.Fatalf("a bare consent submit was refused: %d", w.Code)
		}
	})
}

// ---------------------------------------------------------- the token edges

func TestTokenEndpointRefusals(t *testing.T) {
	h := newHarness(t, false)
	code := h.code()
	base := func() url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"code_verifier": {testVerifier}, "redirect_uri": {h.client.Redirect},
			"client_id": {h.client.ID},
		}
	}
	for _, tc := range []struct {
		name string
		mut  func(url.Values)
		want int
	}{
		{"no grant_type", func(v url.Values) { v.Del("grant_type") }, http.StatusBadRequest},
		{"password grant", func(v url.Values) { v.Set("grant_type", "password") }, http.StatusBadRequest},
		{"no code", func(v url.Values) { v.Del("code") }, http.StatusBadRequest},
		{"unknown code", func(v url.Values) { v.Set("code", "nope") }, http.StatusBadRequest},
		{"no verifier", func(v url.Values) { v.Del("code_verifier") }, http.StatusBadRequest},
		{"short verifier", func(v url.Values) { v.Set("code_verifier", "too-short") }, http.StatusBadRequest},
		{"verifier outside the unreserved set", func(v url.Values) {
			v.Set("code_verifier", strings.Repeat("a", 42)+"$")
		}, http.StatusBadRequest},
		{"no client_id", func(v url.Values) { v.Del("client_id") }, http.StatusBadRequest},
		{"foreign client_id", func(v url.Values) { v.Set("client_id", "other") }, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base()
			tc.mut(v)
			w, resp := h.postToken(v)
			if w.Code != tc.want {
				t.Errorf("status %d, want %d (%s)", w.Code, tc.want, w.Body.String())
			}
			if resp.AccessToken != "" {
				t.Error("a refusal returned a token")
			}
			// Every refusal reads the same from outside.
			var body map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			switch body["error"] {
			case "invalid_grant", "invalid_request", "unsupported_grant_type":
			default:
				t.Errorf("error %q is not one of the three", body["error"])
			}
		})
	}

	t.Run("a JSON body is refused", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader(`{"grant_type":"authorization_code"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.s.TokenHandler().ServeHTTP(w, r)
		if w.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status %d, want 415", w.Code)
		}
	})

	t.Run("GET is refused", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
		w := httptest.NewRecorder()
		h.s.TokenHandler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d, want 405", w.Code)
		}
	})
}

func TestAuthorizeRefusesOddMethodsAndResponseTypes(t *testing.T) {
	h := newHarness(t, false)
	q := h.query()
	q.Set("response_type", "token") // the implicit flow
	if w := h.get(q); w.Code != http.StatusBadRequest {
		t.Errorf("response_type=token: %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodDelete, "/oauth/authorize", nil)
	w := httptest.NewRecorder()
	h.s.AuthorizeHandler().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: %d", w.Code)
	}
}

func TestStateIsOptionalAndEchoedVerbatim(t *testing.T) {
	h := newHarness(t, false)
	q := h.query()
	q.Del("state")
	page := h.get(q)
	w := h.consent(h.ticket(page), "allow")
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Has("state") {
		t.Error("a request with no state came back with one")
	}
	// A state a client chose, with characters that must survive a round
	// trip through a query string.
	q.Set("state", "a b&c=d/e?f")
	page = h.get(q)
	w = h.consent(h.ticket(page), "allow")
	loc, _ = url.Parse(w.Header().Get("Location"))
	if got := loc.Query().Get("state"); got != "a b&c=d/e?f" {
		t.Errorf("state came back as %q", got)
	}
}

func TestCheckRedirectURI(t *testing.T) {
	good := []string{
		"http://127.0.0.1:52001/pelfs/oauth/callback",
		"http://127.0.0.1:1/x",
		"http://[::1]:52001/pelfs/oauth/callback",
	}
	bad := []string{
		"", "not a url", "://x",
		"https://127.0.0.1:52001/cb",              // no TLS on this listener
		"http://127.0.0.1/pelfs/oauth/callback",   // NO PORT — the trap
		"http://127.0.0.1:0/pelfs/oauth/callback", // port 0, ditto
		"http://localhost:52001/cb",               // a name, not a literal
		"http://example.com:52001/cb",
		"http://127.0.0.1:52001",                     // no path
		"http://127.0.0.1:52001/cb?x=1",              // a query
		"http://127.0.0.1:52001/cb#f",                // a fragment
		"http://u:p@127.0.0.1:52001/cb",              // userinfo
		"http://127.0.0.1:52001/${oauth.handler}/cb", // a substitution
		"x-cyberduck-action:oauth",                   // the custom-scheme provider
	}
	for _, u := range good {
		if err := CheckRedirectURI(u); err != nil {
			t.Errorf("CheckRedirectURI(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := CheckRedirectURI(u); err == nil {
			t.Errorf("CheckRedirectURI(%q) = nil, want an error", u)
		}
	}
}

func TestNewClientRefusesBadRegistrations(t *testing.T) {
	h := newHarness(t, false)
	if _, err := h.s.NewClient(ClientRequest{Label: "x", RedirectURI: "http://127.0.0.1/cb"}); err == nil {
		t.Error("a redirect URI with no port was registered")
	}
	c, err := h.s.NewClient(ClientRequest{RedirectURI: davprofile.RedirectURI(52099)})
	if err != nil {
		t.Fatal(err)
	}
	if c.Label == "" {
		t.Error("a client with no label got no fallback label")
	}
	long := strings.Repeat("l", 500)
	c2, err := h.s.NewClient(ClientRequest{Label: long, RedirectURI: davprofile.RedirectURI(52098)})
	if err != nil {
		t.Fatal(err)
	}
	if len(c2.Label) > 64 {
		t.Errorf("label is %d characters", len(c2.Label))
	}
}

func TestS256MatchesRFC7636AppendixB(t *testing.T) {
	// RFC 7636 Appendix B's worked example, so the transform is pinned
	// against the specification rather than against itself.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := s256(verifier); got != want {
		t.Errorf("s256 = %q, want %q", got, want)
	}
	if !validVerifier(verifier) {
		t.Error("the RFC's own verifier is rejected")
	}
	if !validChallenge(want) {
		t.Error("the RFC's own challenge is rejected")
	}
}
