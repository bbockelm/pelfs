package browsesession

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clock drives time in these tests. Nothing here sleeps: a TTL test that
// waits on the wall clock is a test that flakes on a loaded machine, and
// this repo has paid for that lesson once already (internal/lease).
type clock struct{ at time.Time }

func (c *clock) now() time.Time       { return c.at }
func (c *clock) step(d time.Duration) { c.at = c.at.Add(d) }

func newManager(t *testing.T) (*Manager, *clock) {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
	m, err := NewAt(c.now)
	if err != nil {
		t.Fatal(err)
	}
	return m, c
}

// TestBootstrapIsSingleUse: the value that ends up in the browser's
// history, in session-restore data, and in the opener's argv must be dead
// by the time anybody could read it out of any of them.
func TestBootstrapIsSingleUse(t *testing.T) {
	m, _ := newManager(t)
	bt := m.Bootstrap()
	if bt == "" {
		t.Fatal("no bootstrap token")
	}
	tok, err := m.Exchange(bt)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if !m.ValidSession(tok) {
		t.Fatal("the session token the exchange returned is not valid")
	}
	if _, err := m.Exchange(bt); err == nil {
		t.Fatal("a second exchange of the same token succeeded")
	}
	// The replay must not have cost the real user their session.
	if !m.ValidSession(tok) {
		t.Fatal("the replay invalidated the first session")
	}
	if m.Bootstrap() != "" {
		t.Fatal("the spent bootstrap token is still readable")
	}
}

// TestBootstrapExpires past its TTL.
func TestBootstrapExpires(t *testing.T) {
	m, c := newManager(t)
	bt := m.Bootstrap()
	c.step(BootstrapTTL - time.Millisecond)
	if _, err := m.Exchange(bt); err != nil {
		t.Fatalf("inside the TTL: %v", err)
	}

	m2, c2 := newManager(t)
	bt2 := m2.Bootstrap()
	c2.step(BootstrapTTL + time.Millisecond)
	if _, err := m2.Exchange(bt2); err == nil {
		t.Fatal("an expired bootstrap token was accepted")
	}
	// And the expiry cleared it, so a late guess has nothing to hit.
	if m2.Bootstrap() != "" {
		t.Fatal("an expired bootstrap token is still held")
	}
}

// TestWrongGuessDoesNotInvalidateTheLaunchURL. If a wrong guess burned the
// token, anything that could reach the exchange route could deny the
// session by racing the browser to it.
func TestWrongGuessDoesNotInvalidateTheLaunchURL(t *testing.T) {
	m, _ := newManager(t)
	bt := m.Bootstrap()
	wrong := strings.Repeat("A", len(bt))
	if _, err := m.Exchange(wrong); err == nil {
		t.Fatal("a wrong token was accepted")
	}
	// Same length, one byte different: the case a constant-time compare is
	// for, and the case a prefix compare would get wrong.
	//
	// The replacement character is chosen against the token rather than
	// hardcoded. "B"+bt[1:] is the REAL token whenever the token happens to
	// start with 'B', which a base64url alphabet makes a 1-in-64 event: it
	// passed locally forever and failed two CI jobs on one commit, reporting
	// "a near-miss token was accepted" -- which reads like an authentication
	// bypass and is really a test asserting that a token is not itself.
	swap := byte('B')
	if bt[0] == swap {
		swap = 'C'
	}
	near := string(swap) + bt[1:]
	if _, err := m.Exchange(near); err == nil {
		t.Fatal("a near-miss token was accepted")
	}
	if _, err := m.Exchange(bt); err != nil {
		t.Fatalf("the real token stopped working after two guesses: %v", err)
	}
}

// TestSessionTokensAreDistinctAndOpaque.
func TestSessionTokensAreDistinctAndOpaque(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		m, _ := newManager(t)
		bt := m.Bootstrap()
		tok, err := m.Exchange(bt)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{bt, tok} {
			if len(s) != 43 { // 32 bytes, base64url, unpadded
				t.Fatalf("token %q is %d chars, want 43", s, len(s))
			}
			if strings.ContainsAny(s, "=+/#?&") {
				t.Fatalf("token %q carries a character that has to be escaped in a URL", s)
			}
			if seen[s] {
				t.Fatalf("token %q repeated", s)
			}
			seen[s] = true
		}
	}
}

func TestValidSessionRefusesTheEmptyString(t *testing.T) {
	m, _ := newManager(t)
	if m.ValidSession("") {
		t.Fatal("the empty string authenticated")
	}
	if _, err := m.Exchange(""); err == nil {
		t.Fatal("an empty bootstrap token was accepted")
	}
}

func TestRevoke(t *testing.T) {
	m, _ := newManager(t)
	tok, err := m.Exchange(m.Bootstrap())
	if err != nil {
		t.Fatal(err)
	}
	m.Revoke(tok)
	if m.ValidSession(tok) {
		t.Fatal("a revoked token still authenticates")
	}
	if m.Sessions() != 0 {
		t.Fatalf("Sessions() = %d after revoking the only one", m.Sessions())
	}
}

// TestLaunchURLPutsTheTokenInTheFragment. A fragment is never sent in a
// request line, so it is in no access log and in no Referer under any
// policy. A query string would be in both.
func TestLaunchURLPutsTheTokenInTheFragment(t *testing.T) {
	m, _ := newManager(t)
	u := m.LaunchURL("http://127.0.0.1:49731")
	if !strings.HasPrefix(u, "http://127.0.0.1:49731/#bt=") {
		t.Fatalf("launch URL = %q", u)
	}
	if strings.Contains(u, "?") {
		t.Fatalf("launch URL carries a query string: %q", u)
	}
	if !strings.Contains(u, m.Bootstrap()) {
		t.Fatalf("launch URL %q does not carry the token", u)
	}
}

// TestTicketsAreSingleUseAndExpire.
func TestTicketsAreSingleUseAndExpire(t *testing.T) {
	m, c := newManager(t)
	tk, err := m.MintTicket("/a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m.Tickets() != 1 {
		t.Fatalf("Tickets() = %d", m.Tickets())
	}
	got, err := m.RedeemTicket(tk)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/a/b.txt" {
		t.Fatalf("ticket path = %q", got.Path)
	}
	if _, err := m.RedeemTicket(tk); err == nil {
		t.Fatal("a spent ticket was redeemed twice")
	}
	if m.Tickets() != 0 {
		t.Fatalf("Tickets() = %d after redemption", m.Tickets())
	}

	tk2, err := m.MintTicket("/a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	c.step(TicketTTL + time.Second)
	if _, err := m.RedeemTicket(tk2); err == nil {
		t.Fatal("an expired ticket was redeemed")
	}
	if m.Tickets() != 0 {
		t.Fatalf("Tickets() = %d after expiry", m.Tickets())
	}
}

// TestTicketsDoNotCollide: two tickets for the same path are two
// authorizations, and redeeming one must not spend the other.
func TestTicketsDoNotCollide(t *testing.T) {
	m, _ := newManager(t)
	a, err := m.MintTicket("/x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.MintTicket("/x")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two tickets are the same string")
	}
	if _, err := m.RedeemTicket(a); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RedeemTicket(b); err != nil {
		t.Fatalf("redeeming one ticket spent the other: %v", err)
	}
}

// nilSource is M1's registered source: none.
func TestDownloadHandlerWithNoSource404s(t *testing.T) {
	m, _ := newManager(t)
	tk, err := m.MintTicket("/whatever")
	if err != nil {
		t.Fatal(err)
	}
	rec := serveTicket(t, DownloadHandler(m, nil), tk)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	// The ticket is spent either way: a redemption is a redemption, and a
	// ticket that survived a 404 would be a replayable one.
	if m.Tickets() != 0 {
		t.Fatalf("Tickets() = %d after a 404 redemption", m.Tickets())
	}
}

type seekSource struct{ body string }

func (s seekSource) Open(context.Context, string) (*Content, error) {
	return &Content{Name: "x/../report.html", Size: int64(len(s.body)),
		ModTime: time.Unix(0, 0), Body: nopSeekCloser{strings.NewReader(s.body)}}, nil
}

type nopSeekCloser struct{ *strings.Reader }

func (nopSeekCloser) Close() error { return nil }

// TestDownloadNeverServesUserContentInline is the stored-XSS control (A5).
// The volume holds files the user did not write; one served as text/html
// from this origin would run its script where the session token is.
func TestDownloadNeverServesUserContentInline(t *testing.T) {
	m, _ := newManager(t)
	tk, err := m.MintTicket("/report.html")
	if err != nil {
		t.Fatal(err)
	}
	rec := serveTicket(t, DownloadHandler(m, seekSource{"<script>alert(1)</script>"}), tk)
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="report.html"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

// TestFilenameCannotBreakTheHeader: a volume path is user-controlled data.
func TestFilenameCannotBreakTheHeader(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`plain.txt`, `"plain.txt"`},
		{`/a/b/deep.bin`, `"deep.bin"`},
		{`he said "hi".txt`, `"he said _hi_.txt"`},
		{"line\r\nX-Evil: 1", `"line__X-Evil: 1"`},
		{`back\slash`, `"slash"`},
		{`/`, `"download"`},
		{``, `"download"`},
	} {
		if got := quoteFilename(tc.in); got != tc.want {
			t.Errorf("quoteFilename(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// TestDownloadForbiddenIsNot404: "you cannot" and "there is nothing" are
// different answers and a user acts differently on each.
func TestDownloadForbiddenIsNot404(t *testing.T) {
	m, _ := newManager(t)
	tk, err := m.MintTicket("/secret")
	if err != nil {
		t.Fatal(err)
	}
	rec := serveTicket(t, DownloadHandler(m, forbidSource{}), tk)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

type forbidSource struct{}

func (forbidSource) Open(context.Context, string) (*Content, error) { return nil, ErrForbidden }

func serveTicket(t *testing.T, h http.Handler, ticket string) *httptest.ResponseRecorder {
	t.Helper()
	// The route is mounted as "GET /d/{ticket}" in production, so the path
	// value has to come from a mux for PathValue to see it.
	mux := http.NewServeMux()
	mux.Handle("GET /d/{"+TicketPathValue+"}", h)
	r := httptest.NewRequest("GET", "/d/"+ticket, nil)
	r.Host = "127.0.0.1:49731"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

// TestExchangeHandlerSaysNothingAboutWhy: three refusals, one answer.
func TestExchangeHandlerSaysNothingAboutWhy(t *testing.T) {
	m, c := newManager(t)
	h := ExchangeHandler(m)
	bodies := map[string]string{}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/v1/session", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	// wrong
	rec := post(`{"bootstrap":"` + strings.Repeat("A", 43) + `"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	bodies["wrong"] = rec.Body.String()
	// spent
	good := m.Bootstrap()
	if rec := post(`{"bootstrap":"` + good + `"}`); rec.Code != 200 {
		t.Fatalf("good token: %d (%s)", rec.Code, rec.Body.String())
	}
	rec = post(`{"bootstrap":"` + good + `"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("spent token: %d", rec.Code)
	}
	bodies["spent"] = rec.Body.String()
	// expired, on a fresh manager
	m2, c2 := newManager(t)
	h2 := ExchangeHandler(m2)
	bt := m2.Bootstrap()
	c2.step(BootstrapTTL + time.Second)
	r := httptest.NewRequest("POST", "/api/v1/session", strings.NewReader(`{"bootstrap":"`+bt+`"}`))
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", rec.Code)
	}
	bodies["expired"] = rec.Body.String()
	if bodies["wrong"] != bodies["spent"] || bodies["spent"] != bodies["expired"] {
		t.Fatalf("the three refusals are distinguishable: %q", bodies)
	}
	_ = c
}

func TestExchangeHandlerRejectsGarbage(t *testing.T) {
	m, _ := newManager(t)
	r := httptest.NewRequest("POST", "/api/v1/session", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	ExchangeHandler(m).ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if m.Bootstrap() == "" {
		t.Fatal("a malformed body spent the bootstrap token")
	}
	_ = io.Discard
}
