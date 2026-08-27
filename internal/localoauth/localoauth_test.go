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
	"html"
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

// deliverRE finds the success page's one hidden frame, which is where the
// authorization now reaches the client. It replaced a 303: see
// connectedPage.
var deliverRE = regexp.MustCompile(`<iframe class="deliver" src="([^"]*)"`)

// deliver is the URL the success page hands the authorization to — byte for
// byte the URL the consent POST used to answer 303 with. It asserts on the
// way that the POST answered a PAGE and not a redirect, which is the fix for
// "when I click Authorize, nothing happens in the browser".
//
// html/template escapes the `&` between code and state in an attribute, so it
// is unescaped here rather than in every caller.
func (h *harness) deliver(w *httptest.ResponseRecorder) *url.URL {
	h.t.Helper()
	if w.Code != http.StatusOK {
		h.t.Fatalf("consent POST: status %d, want 200\n%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "" {
		h.t.Fatalf("the consent POST redirected to %q; a success is a page now", loc)
	}
	m := deliverRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		h.t.Fatalf("no delivery frame on the page the consent POST answered:\n%s", w.Body.String())
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		h.t.Fatalf("delivery URL: %v", err)
	}
	return u
}

// code drives the whole front channel and returns the authorization code.
func (h *harness) code() string {
	h.t.Helper()
	page := h.get(h.query())
	if page.Code != http.StatusOK {
		h.t.Fatalf("consent page: status %d\n%s", page.Code, page.Body.String())
	}
	loc := h.deliver(h.consent(h.ticket(page), "allow"))
	if got, want := loc.Scheme+"://"+loc.Host+loc.Path, h.client.Redirect; got != want {
		h.t.Fatalf("the authorization is delivered to %q, want %q", got, want)
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

// TestReplayedCodeWithoutTheVerifierIsCountedAndRevokes is RFC 6819
// §5.2.1.1's case and the hostile half of the used-code branch: a caller who
// has the CODE and not the PKCE verifier. Nothing but the code can have
// leaked to them — the verifier never leaves the client — so the token the
// first exchange bought is what is at risk, and it goes.
func TestReplayedCodeWithoutTheVerifierIsCountedAndRevokes(t *testing.T) {
	h := newHarness(t, false)
	code := h.code()
	_, first := h.exchange(code, testVerifier)
	if _, ok := h.s.Verify(first.AccessToken); !ok {
		t.Fatal("the first exchange did not produce a working token")
	}
	// A verifier of legal SHAPE (or the request never reaches the code at
	// all) that is not the one the challenge was built from: exactly what an
	// attacker who scraped the code out of a callback URL can produce.
	stolen := "Xelfs-test-verifier-0123456789-abcdefghijklm"
	w, second := h.exchange(code, stolen)
	if w.Code != http.StatusBadRequest || second.AccessToken != "" {
		t.Fatalf("replay: status %d body %s", w.Code, w.Body.String())
	}
	if got := h.s.Counts().CodeReplays; got != 1 {
		t.Errorf("CodeReplays = %d, want 1", got)
	}
	if got := h.s.Counts().CodeRetries; got != 0 {
		t.Errorf("CodeRetries = %d on a replay, want 0", got)
	}
	if _, ok := h.s.Verify(first.AccessToken); ok {
		t.Error("a replayed code did not revoke the grant the first exchange created")
	}
	if n := len(h.s.Grants()); n != 0 {
		t.Errorf("%d grants survive a replay", n)
	}
}

// TestTheClientRetryingItsOwnExchangeIsNotAReplay is the benign half, and the
// distinction is the whole point: a client whose token response was lost
// retries the same POST, with the same code AND the same verifier. That is
// the client the code was issued to, proving it with a secret that never left
// it, so destroying the grant would be punishing the user for a dropped
// packet.
//
// What must NOT change: the code is still single use. The retry gets
// invalid_grant like everything else on this endpoint; it just does not cost
// the user their connection.
func TestTheClientRetryingItsOwnExchangeIsNotAReplay(t *testing.T) {
	h := newHarness(t, false)
	code := h.code()
	_, first := h.exchange(code, testVerifier)
	if _, ok := h.s.Verify(first.AccessToken); !ok {
		t.Fatal("the first exchange did not produce a working token")
	}
	w, second := h.exchange(code, testVerifier)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a retried exchange was answered %d; the code is single use", w.Code)
	}
	if second.AccessToken != "" {
		t.Error("a retried exchange minted a SECOND token from one code")
	}
	if got := h.s.Counts().CodeRetries; got != 1 {
		t.Errorf("CodeRetries = %d, want 1", got)
	}
	if got := h.s.Counts().CodeReplays; got != 0 {
		t.Errorf("CodeReplays = %d, want 0: the client proved it holds the verifier", got)
	}
	if _, ok := h.s.Verify(first.AccessToken); !ok {
		t.Error("the client's own retry destroyed the connection it already had")
	}
	// And a caller who follows the retry WITHOUT the verifier is still a
	// replay: the row is not made permanently safe by one honest retry.
	h.exchange(code, "Xelfs-test-verifier-0123456789-abcdefghijklm")
	if got := h.s.Counts().CodeReplays; got != 1 {
		t.Errorf("a verifier-less presentation after a retry: CodeReplays = %d, want 1", got)
	}
	if _, ok := h.s.Verify(first.AccessToken); ok {
		t.Error("the replay after the retry did not revoke the grant")
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

	t.Run("the page names what is being authorized, and nothing else", func(t *testing.T) {
		// THE THREE FACTS THAT MAKE THE CLICK MEANINGFUL, and they are the
		// whole page now: which program, which volume, what access.
		h := newHarness(t, false)
		body := h.get(h.query()).Body.String()
		for _, want := range []string{"Cyberduck", "pelican://osg-htc.org/user/bbockelman",
			"read only"} {
			if !strings.Contains(body, want) {
				t.Errorf("the consent page does not name %q", want)
			}
		}
		if strings.Contains(body, h.client.ID) {
			t.Error("the consent page renders the client_id, which is a secret")
		}
		// AND THE TWO THINGS THAT WERE DELETED, pinned so they do not come
		// back the next time somebody feels a screen looks bare.
		//
		// The callback row ("sends the authorization to
		// http://127.0.0.1:52001/…"): a loopback URL with a port in it is
		// not something a person can act on, and the control it looked like
		// it was doing is done unconditionally in the handler, byte for
		// byte, whatever the screen says.
		if strings.Contains(body, h.client.Redirect) {
			t.Error("the consent page is back to naming the callback URL, " +
				"which the owner called useless and which no user can act on")
		}
		// The essay under the buttons. The page is facts and a decision.
		for _, gone := range []string{"one thing standing", "it can never publish",
			"a page you happened to visit"} {
			if strings.Contains(body, gone) {
				t.Errorf("the consent page grew prose back: %q", gone)
			}
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

	t.Run("a ticket is single use, and a second press is not an error", func(t *testing.T) {
		// THE REPORT: "if I click it twice, I get an error." It was a bare
		// refusal page, because a spent ticket was indistinguishable from a
		// forged one. It is distinguishable now, on evidence: the ticket is
		// 32 bytes that existed in one HTML body, so a caller who can
		// produce it was SHOWN that page.
		//
		// What must not move is the single-use rule, and this asserts it
		// where it counts: after the second press there is still exactly ONE
		// code, and the page carries no second delivery.
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		first := h.consent(ticket, "allow")
		if first.Code != http.StatusOK {
			t.Fatalf("first submit: status %d", first.Code)
		}
		w := h.consent(ticket, "allow")
		if w.Code != http.StatusOK {
			t.Errorf("a second press answered %d; a user who just connected must not "+
				"be shown an error", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Already connected") {
			t.Errorf("a second press does not say the program is already connected:\n%s",
				w.Body.String())
		}
		if deliverRE.MatchString(w.Body.String()) {
			t.Error("a second press re-delivered the authorization, which is a code " +
				"presented twice and would revoke the grant")
		}
		h.s.mu.Lock()
		n := len(h.s.codes)
		h.s.mu.Unlock()
		if n != 1 {
			t.Errorf("%d codes after two presses of one screen, want 1", n)
		}
		if got := h.s.Counts().ConsentRepeats; got != 1 {
			t.Errorf("ConsentRepeats = %d, want 1", got)
		}
		if got := h.s.Counts().ConsentTicketsRefused; got != 0 {
			t.Errorf("ConsentTicketsRefused = %d: a re-press is not a forgery", got)
		}
	})

	t.Run("a second press after the grant is gone says so", func(t *testing.T) {
		// The other half of "already connected": if there is nothing there
		// any more — the user revoked it between presses — saying "already
		// connected" would be a lie, so the page says what is true instead.
		h := newHarness(t, false)
		ticket := h.ticket(h.get(h.query()))
		loc := h.deliver(h.consent(ticket, "allow"))
		h.exchange(loc.Query().Get("code"), testVerifier)
		if ok, err := h.s.RevokeGrant(h.s.Grants()[0].Ref); !ok || err != nil {
			t.Fatalf("RevokeGrant: %v %v", ok, err)
		}
		w := h.consent(ticket, "allow")
		if w.Code != http.StatusOK {
			t.Errorf("status %d", w.Code)
		}
		if strings.Contains(w.Body.String(), "Already connected") {
			t.Error("the page claims a revoked connection is live")
		}
		if !strings.Contains(w.Body.String(), "already been used") {
			t.Errorf("the page does not say the authorization is spent:\n%s", w.Body.String())
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
		// And the ticket is spent, so Deny cannot be followed by Allow. The
		// page says the same thing it said the first time — pressing a
		// button twice is not an error condition — and the assertion that
		// matters is that nothing was minted.
		if w := h.consent(ticket, "allow"); !strings.Contains(w.Body.String(), "Not authorized") {
			t.Errorf("a denied screen was re-answered with %d:\n%s", w.Code, w.Body.String())
		}
		if n := len(h.s.codes); n != 0 {
			t.Errorf("%d codes after Deny then Allow", n)
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
	loc := h.deliver(h.consent(h.ticket(page), "allow"))
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
		if ok, err := h.s.RevokeGrant(ref); !ok || err != nil {
			t.Fatalf("RevokeGrant reported nothing to revoke: %v %v", ok, err)
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
		if ok, err := h.s.Revoke(h.client.Ref); !ok || err != nil {
			t.Fatalf("Revoke reported nothing to revoke: %v %v", ok, err)
		}
		if _, ok := h.s.Verify(tok.AccessToken); ok {
			t.Error("a revoked client's OAuth token still verifies")
		}
		if w := h.consent(ticket, "allow"); w.Code != http.StatusBadRequest ||
			deliverRE.MatchString(w.Body.String()) {
			t.Errorf("a revoked client's outstanding consent page still authorized: %d\n%s",
				w.Code, w.Body.String())
		}
		if w := h.get(h.query()); w.Code != http.StatusBadRequest {
			t.Errorf("a revoked client_id is still known: %d", w.Code)
		}
		if ok, err := h.s.Revoke(h.client.Ref); ok || err != nil {
			t.Errorf("Revoke succeeded twice: %v %v", ok, err)
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

	t.Run("4 client_id is a secret only a profile download carries", func(t *testing.T) {
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
		if w := h.consent(h.ticket(page), "allow"); w.Code != http.StatusOK {
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
	loc := h.deliver(h.consent(h.ticket(page), "allow"))
	if loc.Query().Has("state") {
		t.Error("a request with no state came back with one")
	}
	// A state a client chose, with characters that must survive a round
	// trip through a query string AND through an HTML attribute, which is
	// where the delivery URL now lives.
	q.Set("state", "a b&c=d/e?f")
	page = h.get(q)
	loc = h.deliver(h.consent(h.ticket(page), "allow"))
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
		"http://127.0.0.1:52001/c b",              // a space would truncate the CSP header
		"http://127.0.0.1:52001/c;b",              // a `;` would end the form-action directive
		"http://127.0.0.1:52001/c,b",              // a `,` would split the header
		"http://127.0.0.1:52001/c'b",              // a quote in a CSP source expression
		"http://127.0.0.1:52001/c\"b",             // ditto
		"http://127.0.0.1:52001/c\tb",             // a control character
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

// --------------------------------------- the policies on the three pages,
//                                          one of which was load-bearing and wrong

// TestTheCallbackIsNamedByExactlyOneDirective is the regression test for the
// second of the two bugs that made every real-browser Cyberduck connection
// fail, carried forward to where the mechanism moved.
//
// THE BUG: `form-action` is enforced by Chromium on the REDIRECTS of a form
// submission, not only on its first hop, and a successful authorization used
// to 303 the consent POST to the client's own loopback listener — a different
// origin. `form-action 'self'` blocked the last step of the flow with
//
//	Sending form data to 'http://127.0.0.1:PORT/oauth/authorize' violates
//	the following Content Security Policy directive: "form-action 'self'".
//	The request has been blocked.
//
// and NOTHING ELSE: no status code, no failed response the server can see. A
// CSP violation is reported to the browser console and nowhere else, which is
// why every server-side test passed and why a curl-driven gate could never
// have caught it.
//
// WHAT CHANGED: the consent POST does not redirect at all any more
// (connectedPage). It answers a success page, and the authorization is
// delivered from that page's one hidden frame. So the client's callback must
// now be named by `frame-src` on the SUCCESS page, and must NOT be named on
// the consent page — a cross-origin form target nothing uses is a thing that
// rots. Both halves are asserted, because getting either one wrong is the
// same silent failure as before.
//
// scripts/oauth-browser-docker.sh is the gate that watches the console. This
// is the cheap Go pin under it.
func TestTheCallbackIsNamedByExactlyOneDirective(t *testing.T) {
	h := newHarness(t, false)
	page := h.get(h.query())
	if page.Code != http.StatusOK {
		t.Fatalf("consent page: %d", page.Code)
	}
	csp := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("the consent page's form cannot post to its own origin: %s", csp)
	}
	if strings.Contains(csp, h.client.Redirect) {
		t.Errorf("the consent page's CSP still names the client's callback; nothing on "+
			"that page goes there any more:\n  %s", csp)
	}
	// The clauses that are the structural half of "one real user gesture"
	// and of "the ticket cannot be exfiltrated".
	for _, want := range []string{
		"script-src 'none'", "default-src 'none'", "frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("the consent CSP lost %q: %s", want, csp)
		}
	}

	// THE SUCCESS PAGE, which is where the callback URL lives now.
	w := h.consent(h.ticket(page), "allow")
	scsp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(scsp, "frame-src "+h.client.Redirect) {
		t.Errorf("the success page's CSP does not name the client's callback in\n"+
			"frame-src, so the delivery that ends the flow is blocked by our own\n"+
			"policy:\n  %s", scsp)
	}
	for _, want := range []string{"script-src 'none'", "form-action 'none'",
		"frame-ancestors 'none'"} {
		if !strings.Contains(scsp, want) {
			t.Errorf("the success page's CSP lost %q: %s", want, scsp)
		}
	}
	// And the page itself is a page: something a person can read, saying
	// which program reached which volume. That is the whole of the first
	// report ("nothing happens in the browser").
	body := w.Body.String()
	for _, want := range []string{"Connected", "Cyberduck",
		"pelican://osg-htc.org/user/bbockelman", "close this tab"} {
		if !strings.Contains(body, want) {
			t.Errorf("the success page does not say %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script") {
		t.Error("the success page grew a script")
	}

	// A page with NO form and NO frame gets `form-action 'none'` and names
	// no callback: a refusal page must not carry a URL from the request
	// into a header.
	q := h.query()
	q.Set("client_id", "not-a-client")
	refusal := h.get(q)
	rcsp := refusal.Header().Get("Content-Security-Policy")
	if !strings.Contains(rcsp, "form-action 'none'") {
		t.Errorf("a refusal page's CSP allows a form action: %s", rcsp)
	}
	if strings.Contains(rcsp, "127.0.0.1:") {
		t.Errorf("a refusal page's CSP names a callback: %s", rcsp)
	}
	if strings.Contains(rcsp, "frame-src") {
		t.Errorf("a refusal page's CSP allows a frame: %s", rcsp)
	}
}

// TestRedirectMismatchPageNamesBothPorts is the third thing the bug report
// asked for and the reason loopbackPort exists: "a refusal at
// /oauth/authorize must explain itself on the page in terms a user can act on
// ('this profile expects a callback on port X; Cyberduck asked for port Y')
// without echoing attacker-controlled strings".
//
// The two numbers are safe where the two strings are not: each has been
// through strconv.Atoi and back, so what reaches the page can only be an
// integer in 1..65535.
func TestRedirectMismatchPageNamesBothPorts(t *testing.T) {
	h := newHarness(t, false)
	q := h.query()
	q.Set("redirect_uri", "http://127.0.0.1:61033/pelfs/oauth/callback")
	w := h.get(q)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"52001", "61033"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal page does not name port %s:\n%s", want, body)
		}
	}
	// And still no echo. The sent URL, the client id and the path are all
	// strings a caller chose.
	for _, forbidden := range []string{q.Get("redirect_uri"), h.client.ID} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the refusal page echoes %q back to the user", forbidden)
		}
	}

	// A redirect_uri whose port cannot be read as an integer falls back to
	// saying less rather than to guessing — and to echoing nothing.
	q.Set("redirect_uri", "http://127.0.0.1:notaport/cb")
	w2 := h.get(q)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w2.Code)
	}
	if strings.Contains(w2.Body.String(), "notaport") {
		t.Error("the refusal page echoes an unparseable port back to the user")
	}
}

// TestABookmarkFromAnotherVolumeIsRefusedByName is the case a shared port
// range creates, and the reason the refusal page names the volume.
//
// `pelfs browse` probes upward from 8443, so port 8443 is whichever volume
// started first. A Cyberduck bookmark names a PORT — so tomorrow it can
// reach a session serving somebody else's volume. What must NOT happen is
// that it works: the bookmark carries its own profile's client_id (the
// profile's Vendor is keyed on the volume, davprofile.VolumeTag, so it
// resolves to its own profile whatever the port), that client_id names
// nothing here, and the request is refused.
//
// What must ALSO not happen is that the refusal is illegible. "The client
// identifier does not name a client this pelfs session knows" is, on its
// own, indistinguishable from a corrupt profile — and sends the user off to
// re-download the one file that was never wrong.
func TestABookmarkFromAnotherVolumeIsRefusedByName(t *testing.T) {
	h := newHarness(t, false)

	// The other volume's session, and the client id its profile carries.
	other, err := New(Config{
		Writable: false,
		Volume:   "pelican://osg-htc.org/user/someone-else",
		Sessions: fakeSessions(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := other.NewClient(ClientRequest{
		Label:       "Cyberduck",
		RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
	})
	if err != nil {
		t.Fatal(err)
	}

	q := h.query()
	q.Set("client_id", theirs.ID)
	w := h.get(q)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("another volume's client was accepted: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pelican://osg-htc.org/user/bbockelman") {
		t.Error("the refusal does not name the volume this listener is serving, so a user " +
			"cannot tell a wrong-volume bookmark from a corrupt profile")
	}
	// And it still says nothing about the request: the volume is this
	// process's own configuration, and the client id is the caller's.
	if strings.Contains(body, theirs.ID) {
		t.Error("the refusal echoes the client_id it was sent")
	}
	if strings.Contains(body, "someone-else") {
		t.Error("the refusal names the OTHER volume, which this session cannot know")
	}
}
