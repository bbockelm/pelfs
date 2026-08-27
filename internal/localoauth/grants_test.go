package localoauth

// THE ONE THE OWNER ASKED FOR TWICE: "I feel like we shouldn't need to redo
// the OAuth2 connection each time we start a browse session. Why not
// persist?"
//
// So the assertion that matters here is not "a JSON file round-trips". It is:
//
//	a SECOND process, over the SAME state directory, honours the refresh
//	token the FIRST one issued — with NO CALL TO /oauth/authorize AT ALL —
//	and a grant the user revoked is dead in a THIRD.
//
// Everything else in this file is the fence around that: what must still be
// refused (consent, always, on every /authorize), what the file must not
// contain (the token itself), and what revocation now has to reach (the
// disk).
//
// White box, in the package, for the reason localoauth_test.go gives: the
// store's own shape and the adopted grant's internals have no exported
// surface, by design.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/davprofile"
)

// connected is one `pelfs browse` process over a state directory, with BOTH
// persistent files — which is exactly what cmd/pelfs's browse verb builds. A
// test that wants a restart builds two of these over the same dir.
//
// It differs from identity_test.go's `session` in one field, and that field
// is the whole subject of this file.
func connected(t *testing.T, dir string, writable bool) *harness {
	t.Helper()
	id, err := OpenIdentity(dir)
	if err != nil {
		t.Fatalf("OpenIdentity: %v", err)
	}
	gs, err := OpenGrants(dir)
	if err != nil {
		t.Fatalf("OpenGrants: %v", err)
	}
	h := &harness{t: t, clock: identityTestClock}
	s, err := New(Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: fakeSessions(1),
		Now:      func() time.Time { return h.clock },
		Identity: id,
		Grants:   gs,
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

// reconnect is what Cyberduck's OAuth2RequestInterceptor does before every
// request: present the refresh token and the client id, and expect an access
// token back. NOTHING in it touches /oauth/authorize, which is the property
// under test.
func (h *harness) reconnect(refresh string) (*httptest.ResponseRecorder, tokenResponse) {
	h.t.Helper()
	return h.postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {h.client.ID},
	})
}

// grantRefOf finds the grant a saved refresh token names, which is what the
// page revokes by. A token does not carry its ref — that is the point of a
// ref — so the test looks it up the way the server does.
func (h *harness) grantRefOf(refresh string) string {
	h.t.Helper()
	mac := h.s.refreshMac(refresh)
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	for _, g := range h.s.grants {
		if g.macRefresh == mac {
			return g.ref
		}
	}
	return ""
}

// TestASavedBookmarkReconnectsAcrossARestartWithNoClick is the feature.
func TestASavedBookmarkReconnectsAcrossARestartWithNoClick(t *testing.T) {
	dir := t.TempDir()

	// ---- session 1: the user connects a program, once, with a click.
	first := connected(t, dir, true)
	_, tok := first.exchange(first.code(), testVerifier)
	if tok.RefreshToken == "" {
		t.Fatal("the first session issued no refresh token")
	}
	if _, ok := first.s.Verify(tok.AccessToken); !ok {
		t.Fatal("the first session's own access token does not verify")
	}

	// ---- the restart. Nothing of `first` is reachable from here except the
	// state directory and the two secrets Cyberduck saved: the profile's
	// client id and this refresh token.
	second := connected(t, dir, true)
	second.client = first.client

	t.Run("the refresh token is honoured by a process that never issued it", func(t *testing.T) {
		w, got := second.reconnect(tok.RefreshToken)
		if w.Code != http.StatusOK {
			t.Fatalf("the saved refresh token was refused by the new session: %d\n%s",
				w.Code, w.Body.String())
		}
		if got.AccessToken == "" {
			t.Fatal("no access token came back")
		}
		if g, ok := second.s.Verify(got.AccessToken); !ok || !g.Write {
			t.Errorf("the reconnected token does not reach /dav/*: ok=%v %+v", ok, g)
		}
	})

	t.Run("and NOTHING asked for an authorization", func(t *testing.T) {
		// The claim is "no browser interaction at all", so the thing to
		// assert is that the endpoint a browser would have to visit was
		// never reached: no consent page was rendered and no code was
		// minted in this process.
		second.s.mu.Lock()
		pending, codes := len(second.s.pending), len(second.s.codes)
		second.s.mu.Unlock()
		if pending != 0 || codes != 0 {
			t.Errorf("the reconnect went through /authorize after all: %d consent pages, %d codes",
				pending, codes)
		}
		if c := second.s.Counts(); c.ConsentDenied+c.ConsentTicketsRefused+c.NoSession != 0 {
			t.Errorf("the reconnect touched the consent path: %+v", c)
		}
	})

	t.Run("the ACCESS token still dies with the process", func(t *testing.T) {
		// Only the refresh token persists. An access token is looked up
		// under Server.key, which is crypto/rand at New, so an adopted grant
		// authenticates nothing at /dav/* until the client refreshes it.
		if _, ok := second.s.Verify(tok.AccessToken); ok {
			t.Error("an access token survived the process")
		}
	})

	t.Run("the page can see the standing credential", func(t *testing.T) {
		gs := second.s.Grants()
		if len(gs) != 1 {
			t.Fatalf("%d grants after a restart, want 1", len(gs))
		}
		if !gs[0].Persistent {
			t.Error("a persisted grant is not reported as persistent, so the page " +
				"cannot tell the user what will still be connected tomorrow")
		}
		if gs[0].RefreshExpires.IsZero() {
			t.Error("a persisted grant has no expiry; a standing credential must be bounded")
		}
		if gs[0].Label != "Cyberduck" {
			t.Errorf("the grant is listed as %q", gs[0].Label)
		}
	})

	t.Run("consent is STILL required to create a new grant", func(t *testing.T) {
		// The line that must never move. Persisting the grant is not
		// persisting consent: a client that does NOT hold a refresh token
		// still meets the screen, in the session that already honours one.
		w := second.get(second.query())
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), ConsentTicketField) {
			t.Fatalf("/authorize did not render a consent screen: %d", w.Code)
		}
		if got := second.consent("", "allow"); got.Code != http.StatusBadRequest {
			t.Errorf("a consent POST with no ticket answered %d", got.Code)
		}
	})
}

// TestRevokingAGrantSurvivesARestart is the property that makes persisting a
// credential defensible at all: the revoke button on the page has to mean
// "gone", not "gone until the next restart".
func TestRevokingAGrantSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first := connected(t, dir, true)
	_, tok := first.exchange(first.code(), testVerifier)

	// A SECOND grant for the same client, so the revocation below is shown
	// to be individual rather than a reset.
	_, other := first.exchange(first.code(), testVerifier)
	if other.RefreshToken == "" || other.RefreshToken == tok.RefreshToken {
		t.Fatal("setup: the second connection did not get its own refresh token")
	}

	second := connected(t, dir, true)
	second.client = first.client
	if n := len(second.s.Grants()); n != 2 {
		t.Fatalf("%d grants adopted, want 2", n)
	}
	revoke := second.grantRefOf(tok.RefreshToken)
	if revoke == "" {
		t.Fatal("the saved refresh token names no grant in the restarted session")
	}
	if ok, err := second.s.RevokeGrant(revoke); !ok || err != nil {
		t.Fatalf("RevokeGrant: %v %v", ok, err)
	}
	if w, _ := second.reconnect(tok.RefreshToken); w.Code != http.StatusBadRequest {
		t.Errorf("a revoked refresh token still worked in the session that revoked it: %d", w.Code)
	}

	// ---- the third process, which is where a memory-only revocation would
	// have been exposed.
	third := connected(t, dir, true)
	third.client = first.client
	if w, _ := third.reconnect(tok.RefreshToken); w.Code != http.StatusBadRequest {
		t.Errorf("a revoked grant came back after a restart: %d", w.Code)
	}
	if w, _ := third.reconnect(other.RefreshToken); w.Code != http.StatusOK {
		t.Errorf("revoking one connection killed another: %d", w.Code)
	}
	if n := len(third.s.Grants()); n != 1 {
		t.Errorf("%d grants after revoking one of two", n)
	}
}

// TestRevokingTheCLIENTTakesItsSavedConnectionsWithIt. A profile the user
// killed must not leave a standing credential behind — that would be the
// worst possible half-revocation, because the page would show neither the
// client nor a reason.
func TestRevokingTheClientTakesItsSavedConnectionsWithIt(t *testing.T) {
	dir := t.TempDir()
	first := connected(t, dir, true)
	_, tok := first.exchange(first.code(), testVerifier)
	if ok, err := first.s.Revoke(first.client.Ref); !ok || err != nil {
		t.Fatalf("Revoke: %v %v", ok, err)
	}

	second := connected(t, dir, true)
	// A fresh registration of the same label is a DIFFERENT client (the
	// identity epoch, identity.go), so the old refresh token has neither a
	// client nor a row.
	if w, _ := second.reconnect(tok.RefreshToken); w.Code != http.StatusBadRequest {
		t.Errorf("a revoked client's saved connection still reconnects: %d", w.Code)
	}
	if n := len(second.s.Grants()); n != 0 {
		t.Errorf("%d grants survived revoking the client", n)
	}
}

// TestAPersistedGrantIsBounded: RefreshTTL is a hard ceiling, and it is
// enforced when the file is read as well as when a token is presented, so it
// does not depend on anything sweeping.
func TestAPersistedGrantIsBounded(t *testing.T) {
	dir := t.TempDir()
	first := connected(t, dir, true)
	_, tok := first.exchange(first.code(), testVerifier)

	t.Run("refused at refresh time in a long-lived process", func(t *testing.T) {
		first.clock = first.clock.Add(RefreshTTL + time.Minute)
		if w, _ := first.reconnect(tok.RefreshToken); w.Code != http.StatusBadRequest {
			t.Errorf("an aged-out refresh token still worked: %d", w.Code)
		}
	})

	t.Run("not adopted at all by a later process", func(t *testing.T) {
		// The belt to the refusal's braces: a row that has aged out never
		// becomes a live grant, so nothing depends on the check above being
		// reached.
		reloaded := connectedAt(t, dir, true, identityTestClock.Add(RefreshTTL+time.Minute))
		if n := len(reloaded.s.Grants()); n != 0 {
			t.Errorf("%d expired grants were adopted", n)
		}
	})
}

// connectedAt is `connected` with the clock set before New runs, which is
// what adoption reads.
func connectedAt(t *testing.T, dir string, writable bool, now time.Time) *harness {
	t.Helper()
	id, err := OpenIdentity(dir)
	if err != nil {
		t.Fatalf("OpenIdentity: %v", err)
	}
	gs, err := OpenGrants(dir)
	if err != nil {
		t.Fatalf("OpenGrants: %v", err)
	}
	h := &harness{t: t, clock: now}
	s, err := New(Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: fakeSessions(1),
		Now:      func() time.Time { return h.clock },
		Identity: id,
		Grants:   gs,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.s = s
	return h
}

// TestTheGrantFileIsLazyPrivateAndHoldsNoToken is the threat model, asserted.
func TestTheGrantFileIsLazyPrivateAndHoldsNoToken(t *testing.T) {
	dir := t.TempDir()
	h := connected(t, dir, true)
	path := filepath.Join(dir, GrantFileName)

	// LAZY: registering a client writes the identity, but a session nobody
	// has connected a program to leaves no grant file at all.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a session with no grant wrote %s (err %v)", path, err)
	}

	_, tok := h.exchange(h.code(), testVerifier)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the grant was not written: %v", err)
	}

	// PRIVATE. Advisory on Windows, like every other secret pelfs writes.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s is mode %04o, want 0600", GrantFileName, mode)
		}
	}

	// AND IT HOLDS NO CREDENTIAL. This is the difference between a verifier
	// and a credential, and it is the whole reason persisting this is a
	// different proposition from persisting the password we removed.
	for what, secret := range map[string]string{
		"the refresh token": tok.RefreshToken,
		"the access token":  tok.AccessToken,
		"the client id":     h.client.ID,
	} {
		if strings.Contains(string(body), secret) {
			t.Errorf("%s is written into %s", what, GrantFileName)
		}
	}

	var f grantFile
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("the grant file is not JSON: %v", err)
	}
	if f.Version != grantVersion || f.Key == "" || len(f.Grants) != 1 {
		t.Fatalf("the file does not say what it is: %+v", f)
	}
	if f.Note == "" || !strings.Contains(f.Note, "NEVER the token") {
		t.Errorf("the file does not tell a person who finds it what it is: %q", f.Note)
	}
	g := f.Grants[0]
	if g.Label != "Cyberduck" || g.Redirect != h.client.Redirect || !g.Write {
		t.Errorf("the row does not name its client: %+v", g)
	}
	if g.Expires.IsZero() || !g.Expires.After(g.Issued) {
		t.Errorf("the row is not bounded: issued %v expires %v", g.Issued, g.Expires)
	}
}

// TestAGrantStoreWithoutAnIdentityIsRefused. A grant row names its client by
// the identity tuple, so a store with no identity is a configuration that
// could only adopt grants onto nobody. It fails at construction rather than
// silently doing nothing.
func TestAGrantStoreWithoutAnIdentityIsRefused(t *testing.T) {
	gs, err := OpenGrants(t.TempDir())
	if err != nil {
		t.Fatalf("OpenGrants: %v", err)
	}
	_, err = New(Config{Writable: true, Sessions: fakeSessions(1), Grants: gs})
	if err == nil {
		t.Fatal("a grant store with no identity was accepted")
	}
	if !strings.Contains(err.Error(), "Identity") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// TestAReadOnlySessionClampsAnAdoptedWriteGrant. The session's mode is the
// ceiling, and adoption is where a restart could have quietly raised it: a
// grant written by a `pelfs browse --rw` must come back read-only in a
// session started without --rw.
func TestAReadOnlySessionClampsAnAdoptedWriteGrant(t *testing.T) {
	dir := t.TempDir()
	first := connected(t, dir, true)
	_, tok := first.exchange(first.code(), testVerifier)

	second := connectedAt(t, dir, false, identityTestClock)
	second.client = first.client
	// The client id derives from the tuple including the write flag, so the
	// read-only session has to name the same writable client the profile
	// carries — which is what adoptPersistentClients keeps.
	w, got := second.postToken(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
		"client_id": {first.client.ID},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("the saved connection was refused by a read-only session: %d", w.Code)
	}
	if strings.Contains(got.Scope, ScopeWrite) {
		t.Errorf("a read-only session handed back %q", got.Scope)
	}
	if g, ok := second.s.Verify(got.AccessToken); !ok || g.Write {
		t.Errorf("an adopted write grant reaches /dav/* writable on a read-only session: %+v", g)
	}
	// And the clamp happened at adoption, ONCE, rather than on every
	// request — the counter is the "this should never happen" one and must
	// stay meaningful.
	if n := second.s.Counts().ScopeClamped; n != 0 {
		t.Errorf("ScopeClamped = %d; adoption should have clamped the scope, not Verify", n)
	}
}
