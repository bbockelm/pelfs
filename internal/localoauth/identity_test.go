package localoauth

// THE PERSISTENT CLIENT IDENTITY, ASSERTED AS THE USER MEETS IT.
//
// The report behind this file is one sentence — "can we try to have a stable
// port so the CyberDuck bookmark is not one-time-use?" — and the stable port
// answered only half of it: the bookmark resolved and then the profile's
// client id named nothing, because it was minted per download and held in
// memory. So the assertion that matters is not "a key round-trips through a
// file". It is:
//
//	a SECOND process, over the SAME state directory, recognises the profile
//	the FIRST one generated, and regenerating that profile produces the same
//	bytes.
//
// Everything else here is the fence around that: what must NOT survive on
// an IDENTITY ALONE, what a read-only session must still refuse, and what
// revoking one of these now means.
//
// READ THAT FENCE CAREFULLY, because half of it moved. `session` below builds
// a server with an Identity and NO GrantStore, which is the configuration
// this file is about, and under it nothing but the identity survives: no
// access token, no grant, no consent. A `pelfs browse` also passes a
// GrantStore, and then the ISSUED GRANT survives too, on purpose — grants.go
// says why that is a different thing from persisting consent, and
// grants_test.go asserts it. What is true in BOTH configurations, and is the
// line that must never move, is the last subtest here: consent is never
// remembered at /oauth/authorize.
//
// White box, in the package, for the reason localoauth_test.go gives: the
// read-only-session checks and the derivation's own domain separation have
// no exported surface, by design.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/davprofile"
)

// identityTestClock is the same fixed clock newHarness uses, so a Created
// timestamp is comparable across two "processes".
var identityTestClock = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

// session is one `pelfs browse` process over a state directory: exactly what
// newBrowseServer builds, minus the volume. A test that wants a restart
// builds two of these over the same dir.
func session(t *testing.T, dir string, writable bool) *harness {
	t.Helper()
	id, err := OpenIdentity(dir)
	if err != nil {
		t.Fatalf("OpenIdentity: %v", err)
	}
	h := &harness{t: t, clock: identityTestClock}
	s, err := New(Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: fakeSessions(1),
		Now:      func() time.Time { return h.clock },
		Identity: id,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.s = s
	return h
}

// install is what the connection page's POST /api/v1/credentials does: one
// client, and the .cyberduckprofile the user installs. Returns the client
// and the profile bytes, which are the thing this whole file is about.
func install(t *testing.T, h *harness, label string, write bool) (*Client, []byte) {
	t.Helper()
	c, err := h.s.NewClient(ClientRequest{
		Label:       label,
		RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
		Write:       write,
	})
	if err != nil {
		t.Fatalf("NewClient(%q): %v", label, err)
	}
	h.client = c
	body, err := davprofile.Profile(davprofile.Params{
		// A FIXED PORT, because that is what a volume's stable port is
		// (cmd/pelfs/browseport.go). The two halves of "the bookmark is not
		// one-time-use" are the port and the client id, and this file owns
		// the second one.
		Port: 61234, Volume: "pelican://osg-htc.org/user/bbockelman",
		ClientID: c.ID, RedirectURI: c.Redirect, Write: c.Write,
		Label: label,
	})
	if err != nil {
		t.Fatalf("davprofile.Profile: %v", err)
	}
	return c, body
}

// TestAnInstalledProfileSurvivesARestart is KL-17, inverted.
func TestAnInstalledProfileSurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	first := session(t, dir, true)
	c1, profile1 := install(t, first, "Cyberduck", true)
	// A real connection in the first session, so the second one is not
	// merely inspecting a registry: there is a live grant to be sure dies.
	_, tok := first.exchange(first.code(), testVerifier)
	if _, ok := first.s.Verify(tok.AccessToken); !ok {
		t.Fatal("the first session's own token does not verify")
	}

	// ---- the restart. Nothing of `first` is reachable from here except
	// the state directory and the bytes the user installed.
	second := session(t, dir, true)

	t.Run("the profile is byte-identical, so reinstalling is unnecessary", func(t *testing.T) {
		_, profile2 := install(t, second, "Cyberduck", true)
		if string(profile1) != string(profile2) {
			t.Errorf("the regenerated profile differs from the installed one:\n--- first\n%s\n--- second\n%s",
				profile1, profile2)
		}
	})

	t.Run("the client id in the INSTALLED profile still names a client", func(t *testing.T) {
		if !strings.Contains(string(profile1), "<string>"+c1.ID+"</string>") {
			t.Fatalf("the client id is not in the profile at all:\n%s", profile1)
		}
		// The saved bookmark's authorization, byte for byte what Cyberduck
		// sends: the id out of the file on disk, not one this process minted.
		second.client = c1
		w := second.get(second.query())
		if w.Code != 200 {
			t.Fatalf("the installed profile's client_id was refused: %d\n%s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), ConsentTicketField) {
			t.Error("the response is not a consent page")
		}
	})

	t.Run("and it can be authorized to a working token", func(t *testing.T) {
		second.client = c1
		_, tok2 := second.exchange(second.code(), testVerifier)
		g, ok := second.s.Verify(tok2.AccessToken)
		if !ok {
			t.Fatal("the token the restarted session issued does not verify")
		}
		if !g.Write {
			t.Error("a --rw session issued a read-only grant")
		}
	})

	t.Run("the CREDENTIALS from the first session are dead", func(t *testing.T) {
		// An ACCESS token never survives a process, in any configuration:
		// Server.key is crypto/rand at New, so the table it would be looked
		// up in is keyed under a key this process invented. That is true
		// even with a grant store, where the REFRESH token does survive —
		// which is why an adopted grant serves nothing at /dav/* until the
		// client refreshes it (grants_test.go).
		if _, ok := second.s.Verify(tok.AccessToken); ok {
			t.Error("an access token survived the process", tok.AccessToken[:8])
		}
		// And with no grant store, neither does the refresh token.
		if w, _ := second.postToken(url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken},
			"client_id": {c1.ID},
		}); w.Code != http.StatusBadRequest {
			t.Errorf("a refresh token survived a process with no grant store: %d", w.Code)
		}
	})

	t.Run("consent is still required, so the user still clicks once a session", func(t *testing.T) {
		// The client was consented in the first session and the identity is
		// on disk, and NEITHER of those may shortcut the gesture: harness.get
		// fails the test on any Location header, and what comes back is a
		// page with a ticket in it.
		second.client = c1
		w := second.get(second.query())
		if w.Code != 200 || !strings.Contains(w.Body.String(), ConsentTicketField) {
			t.Fatalf("a known, previously consented client did not get a consent page: %d", w.Code)
		}
		// And the ticket is the only way through: the POST without one is
		// refused, which is what makes "a click per session" a property
		// rather than a habit.
		if got := second.consent("", "allow"); got.Code != 400 {
			t.Errorf("a consent POST with no ticket answered %d", got.Code)
		}
	})
}

// TestTheIdentityIsPerStateDirectory is the "a different volume gets a
// different identity" half. In every default configuration the state
// directory IS the volume (cmd/pelfs/daemon.go's volDirIn hashes the prefix
// URL), so this is the assertion that a key never leaks across volumes.
func TestTheIdentityIsPerStateDirectory(t *testing.T) {
	one, two := t.TempDir(), t.TempDir()
	a, profA := install(t, session(t, one, true), "Cyberduck", true)
	b, profB := install(t, session(t, two, true), "Cyberduck", true)
	if a.ID == b.ID {
		t.Error("two volumes derived the same client id from the same label")
	}
	if string(profA) == string(profB) {
		t.Error("two volumes generated the same profile")
	}
	// And the profile from one volume is not an authorization the other will
	// entertain.
	h := session(t, two, true)
	h.client = a
	if w := h.get(h.query()); w.Code == 200 {
		t.Error("volume two accepted volume one's client id")
	}
}

// TestTheSameProgramIsOneClient pins the idempotence the derivation forces:
// (label, redirect, write) is the identity, so asking twice is one client
// with one revoke button and one profile — and now that there is no password
// to roll, asking twice re-issues NOTHING at all.
func TestTheSameProgramIsOneClient(t *testing.T) {
	dir := t.TempDir()
	h := session(t, dir, true)
	first, _ := install(t, h, "Cyberduck", true)
	second, _ := install(t, h, "Cyberduck", true)
	if first.ID != second.ID {
		t.Error("the same program got two client ids")
	}
	if first.Ref != second.Ref {
		t.Error("the same program got two rows in the credential list")
	}
	if len(h.s.Clients()) != 1 {
		t.Errorf("the credential list has %d rows for one program", len(h.s.Clients()))
	}
	// A different label, or a different write flag, is a different program
	// and therefore a different identity.
	other, _ := install(t, h, "rclone", true)
	if other.ID == first.ID {
		t.Error("two labels derived one client id")
	}
	ro, _ := install(t, h, "Cyberduck", false)
	if ro.ID == first.ID {
		t.Error("the write flag is not part of the identity")
	}
}

// TestRevokingAPersistentClientIsDurable is the promise the page's Revoke
// button now makes: the installed profile stops working, and stays stopped.
func TestRevokingAPersistentClientIsDurable(t *testing.T) {
	dir := t.TempDir()
	first := session(t, dir, true)
	c, _ := install(t, first, "Cyberduck", true)
	if ok, err := first.s.Revoke(c.Ref); !ok || err != nil {
		t.Fatalf("Revoke: %v %v", ok, err)
	}
	if len(first.s.Clients()) != 0 {
		t.Error("the revoked client is still in the list")
	}

	second := session(t, dir, true)
	if len(second.s.Clients()) != 0 {
		t.Error("a revoked client came back after a restart")
	}
	second.client = c
	if w := second.get(second.query()); w.Code == 200 {
		t.Error("the revoked profile still authorizes after a restart")
	}
	// AND ADDING THE SAME PROGRAM AGAIN DOES NOT RE-ARM THE REVOKED PROFILE.
	// This is the epoch's whole job: a user who revoked because a laptop
	// walked off and then set Cyberduck up again on a new one must not hand
	// the old laptop a working credential.
	third := session(t, dir, true)
	again, _ := install(t, third, "Cyberduck", true)
	if again.ID == c.ID {
		t.Error("re-adding a revoked program resurrected its client id")
	}
	third.client = c
	if w := third.get(third.query()); w.Code == 200 {
		t.Error("the revoked profile authorizes again once the label is re-added")
	}
	// The one that was NOT revoked is untouched: revoking a row must not
	// rotate the key out from under every other installed profile.
	keep, _ := install(t, third, "rclone", true)
	if _, err := third.s.Revoke(again.Ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	fourth := session(t, dir, true)
	kept, _ := install(t, fourth, "rclone", true)
	if kept.ID != keep.ID {
		t.Error("revoking one client changed another's identity")
	}
}

// TestRevokeSaysSoWhenItCouldNotReachTheDisk. A revocation that only
// happened in memory is a revocation that comes back next session, and the
// page must not print "revoked" about it.
func TestRevokeSaysSoWhenItCouldNotReachTheDisk(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h := session(t, dir, true)
	c, _ := install(t, h, "Cyberduck", true)
	// The state directory goes away under us. Chosen over a chmod because a
	// chmod does not stop root, and half of this project's gates run as
	// root in a container.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	ok, err := h.s.Revoke(c.Ref)
	if !ok {
		t.Error("the in-memory half of the revocation did not happen")
	}
	if err == nil {
		t.Fatal("Revoke reported a durable revocation it could not write")
	}
	if !strings.Contains(err.Error(), "still on disk") {
		t.Errorf("the error does not say what is still true: %v", err)
	}
	// The in-memory half is done regardless, which is what the error claims:
	// the client id names nothing here any more, so its /authorize is
	// refused even though the file still holds the identity.
	h.client = c
	if w := h.get(h.query()); w.Code != http.StatusBadRequest {
		t.Errorf("the revoked client is still known in this session: %d", w.Code)
	}
}

// TestTheIdentityFileIsLazyAndPrivate: a browse session that hands out no
// profile leaves no new secret on disk, and the one it does leave is 0600
// in the state directory and nowhere else.
func TestTheIdentityFileIsLazyAndPrivate(t *testing.T) {
	dir := t.TempDir()
	h := session(t, dir, false)
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Fatalf("a session that generated nothing wrote %v (err %v)", ents, err)
	}
	c, err := h.s.NewClient(ClientRequest{
		Label: "Cyberduck", RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	path := filepath.Join(dir, IdentityFileName)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the identity file is not at %s: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		if got := st.Mode().Perm(); got != 0o600 {
			t.Errorf("the identity file is mode %o, want 600", got)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != IdentityFileName {
		// A leftover temp file from the atomic write would show up here,
		// and a temp file with a key in it is the same secret with a worse
		// name.
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("the state directory holds %v, want only %s", names, IdentityFileName)
	}
	// NO CREDENTIAL IN THE FILE. The key derives ids; it is not a token and
	// not a password, and the test says so by reading the bytes.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f identityFile
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("the file is not the documented format: %v", err)
	}
	if f.Version != identityVersion || f.Key == "" || len(f.Clients) != 1 {
		t.Errorf("unexpected file contents: %+v", f)
	}
	for _, c := range h.s.Clients() {
		if !c.Persistent {
			t.Error("a client registered with an identity is not reported as persistent")
		}
	}
	// THE THINGS A READER OF THIS FILE MUST NOT FIND. The client id is
	// derived rather than stored, and no credential the session issued is
	// here at all — which is what makes this file weaker than the signing
	// key sitting beside it.
	for what, secret := range map[string]string{
		"the client id": c.ID,
	} {
		if strings.Contains(string(body), secret) {
			t.Errorf("%s is written into the identity file", what)
		}
	}
}

// TestAReadOnlySessionAndAWritableIdentity. The profile a --rw session
// generated asks for pelfs.write; a later read-only session must recognise
// the client (so the user gets a true answer) and refuse the scope.
func TestAReadOnlySessionAndAWritableIdentity(t *testing.T) {
	dir := t.TempDir()
	c, _ := install(t, session(t, dir, true), "Cyberduck", true)

	ro := session(t, dir, false)
	if len(ro.s.Clients()) != 1 {
		t.Fatalf("the read-only session adopted %d clients", len(ro.s.Clients()))
	}
	ro.client = c
	w := ro.get(ro.query()) // the profile asks for read+write
	if w.Code != 400 {
		t.Fatalf("a writable authorization on a read-only session answered %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "wider than this profile") {
		t.Errorf("the page does not say what is wrong:\n%s", w.Body.String())
	}
	// Not "this is not an authorization request pelfs issued", which is the
	// answer that would send the user to reinstall a profile that is fine.
	if strings.Contains(w.Body.String(), "not an authorization request") {
		t.Error("the read-only session disowned a client it has")
	}
	// And it cannot CREATE one either — adoption is not creation.
	if _, err := ro.s.NewClient(ClientRequest{
		Label: "rclone", RedirectURI: davprofile.RedirectURI(davprofile.DefaultCallbackPort),
		Write: true,
	}); err == nil {
		t.Error("a read-only session registered a writable client")
	}
	// The same profile, asked for at read scope, works: the identity is
	// good, only the scope was too wide.
	roq := ro.query()
	roq.Set("scope", ScopeRead)
	if w := ro.get(roq); w.Code != 200 {
		t.Errorf("the same client at read scope answered %d", w.Code)
	}
}

// TestOpenIdentityRefusesWhatItCannotUnderstand. Deriving client ids from a
// key we invented would tell the user their installed profile is not one
// pelfs issued, which is a lie with a bad remedy attached.
func TestOpenIdentityRefusesWhatItCannotUnderstand(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"not json", "this is not a json document"},
		{"a future version", `{"version":99,"key":"AAAA","clients":[]}`},
		{"no key", `{"version":1,"key":"","clients":[]}`},
		{"a short key", `{"version":1,"key":"AAAA","clients":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, IdentityFileName), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenIdentity(dir); err == nil {
				t.Error("OpenIdentity accepted a file it cannot have understood")
			}
		})
	}
	if _, err := OpenIdentity(""); err == nil {
		t.Error("OpenIdentity accepted an empty directory name")
	}
	// A MISSING file is the ordinary case — the first browse of a volume —
	// and is not an error.
	if id, err := OpenIdentity(t.TempDir()); err != nil || id == nil {
		t.Errorf("a fresh state directory was refused: %v", err)
	}
}

// TestTheDerivationSeparatesItsFields. The label is a string the user typed
// on the connection page, so any byte used as a separator is a byte that
// lets two programs share one credential. The fields are length-prefixed;
// this is the assertion that says so in the units of the bug.
func TestTheDerivationSeparatesItsFields(t *testing.T) {
	id, err := OpenIdentity(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	red := davprofile.RedirectURI(davprofile.DefaultCallbackPort)
	seen := map[string]string{}
	derive := func(e identityEntry) string {
		t.Helper()
		got, err := id.derive(e)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, e := range []identityEntry{
		{Label: "a", Redirect: red, Epoch: "e"},
		{Label: "a" + red, Epoch: "e"},
		{Redirect: "a" + red, Epoch: "e"},
		{Label: "a\x00" + red, Epoch: "e"},
		{Label: "ab", Redirect: red, Epoch: "e"},
		{Label: "a", Redirect: red + "b", Epoch: "e"},
		// The epoch is a field of its own, which is what makes a re-added
		// label a different client from the one that was revoked.
		{Label: "a", Redirect: red, Epoch: "f"},
		{Label: "a", Redirect: red, Epoch: "ee"},
		{Label: "a", Redirect: red, Epoch: "e", Write: true},
	} {
		got := derive(e)
		if prev, dup := seen[got]; dup {
			t.Errorf("%+v collides with %s", e, prev)
		}
		seen[got] = fmt.Sprintf("%+v", e)
		// Every id is the same width as a minted secret, so a length never
		// says which kind it is.
		if len(got) != len(mustMint(t)) {
			t.Errorf("a derived id is %d characters, a minted one is %d", len(got), len(mustMint(t)))
		}
	}
}

func mustMint(t *testing.T) string {
	t.Helper()
	s, err := mint()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestTheRosterIsBounded: the file is written by a route a user can call
// with a new label every time, and an unbounded credential file is a slow
// leak with a secret in it. The oldest goes.
func TestTheRosterIsBounded(t *testing.T) {
	dir := t.TempDir()
	h := session(t, dir, false)
	first := ""
	for i := 0; i < maxIdentityClients+3; i++ {
		h.clock = identityTestClock.Add(time.Duration(i) * time.Minute)
		c, _ := install(t, h, fmt.Sprintf("client-%02d", i), false)
		if i == 0 {
			first = c.ID
		}
	}
	id, err := OpenIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(id.clients()); got != maxIdentityClients {
		t.Errorf("the roster holds %d entries, want %d", got, maxIdentityClients)
	}
	next := session(t, dir, false)
	for _, c := range next.s.Clients() {
		if c.Ref == "" {
			t.Error("an adopted client has no handle to revoke it by")
		}
	}
	// The oldest is the one that went, and its profile is dead: that is the
	// cost of the bound and it is stated rather than silent.
	next.client = &Client{ID: first, Redirect: davprofile.RedirectURI(davprofile.DefaultCallbackPort)}
	if w := next.get(next.query()); w.Code == 200 {
		t.Error("the dropped identity still authorizes")
	}
}
