package main

// THE CREDENTIAL DESK ACROSS A RESTART, at the layer where the page meets it.
//
// Two things now survive a process, and this file is about both: the
// IDENTITY, which is who a profile says it is (internal/localoauth's
// identity.go), and the GRANT, which is what a human already authorized it
// to do (grants.go). Together they are the feature — a saved Cyberduck
// bookmark connects to the next `pelfs browse` with no reinstall AND no
// consent screen — and separately they are two different promises, so the
// tests below keep them apart.
//
// internal/localoauth's own suites prove the derivation, the HMAC roster and
// what each file does and does not hold. scripts/browse-gate.sh proves it
// with the shipped binary and real Cyberduck. This file is the middle: the
// JSON contract the connection page selects on, over a real listener on ONE
// PORT, with `pelfs browse` servers in sequence over one state directory.
//
// The port is why the fixture is built the way it is. Every URL in a
// generated profile names the listener's port, so "byte-identical across a
// restart" is only a statement about the client id if the port is held
// still — which is exactly what cmd/pelfs/browseport.go makes true for a
// real session and what re-serving one httptest listener makes true here.
//
// No volume is opened. The authorization server never touches one (see
// newBrowseServer), and a fakeorigin-backed session per restart would be
// three volumes to say one thing about a credential.

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
)

// identityFixture is one loopback listener whose handler is replaced by each
// simulated `pelfs browse` process in turn.
type identityFixture struct {
	t    *testing.T
	srv  *httptest.Server
	port int
	bs   *browseServer
	tok  string
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	return &identityFixture{t: t, srv: srv, port: srv.Listener.Addr().(*net.TCPAddr).Port}
}

// restart is one `pelfs browse` process: a fresh session manager, a fresh
// authorization server, the same port, and BOTH state-directory files in
// dir — the identity, which is who a profile says it is, and the grants,
// which are what a human already authorized it to do. Pass an empty dir for
// the ephemeral server this verb used to be, where neither survives.
func (f *identityFixture) restart(dir string) {
	f.t.Helper()
	var (
		id     *localoauth.Identity
		grants *localoauth.GrantStore
	)
	if dir != "" {
		var err error
		if id, err = localoauth.OpenIdentity(dir); err != nil {
			f.t.Fatalf("OpenIdentity: %v", err)
		}
		if grants, err = localoauth.OpenGrants(dir); err != nil {
			f.t.Fatalf("OpenGrants: %v", err)
		}
	}
	m, err := browsesession.New()
	if err != nil {
		f.t.Fatal(err)
	}
	bs, err := newBrowseServer("pelican://osg-htc.org/user/bbockelman",
		browseArgs{branch: "main", rw: true}, 5*time.Minute, m, f.port, id, grants)
	if err != nil {
		f.t.Fatal(err)
	}
	f.srv.Config.Handler = bs.routes(httpguard.New(httpguard.Config{Port: f.port, Sessions: m}))
	f.bs = bs
	f.tok = ""
	body := `{"bootstrap":"` + m.Bootstrap() + `"}`
	var out browsesession.ExchangeResponse
	f.call("POST", "/api/v1/session", body, 200, &out)
	f.tok = out.Session
}

// call issues one request shaped as the page's fetch and decodes the body.
func (f *identityFixture) call(method, path, body string, want int, into any) {
	f.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rdr)
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Origin", f.srv.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if f.tok != "" {
		req.Header.Set(httpguard.SessionHeader, f.tok)
	}
	res, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		f.t.Fatalf("%s %s: %d, want %d: %s", method, path, res.StatusCode, want, raw)
	}
	if into != nil {
		if err := json.Unmarshal(raw, into); err != nil {
			f.t.Fatalf("%s %s: %v in %s", method, path, err, raw)
		}
	}
}

// profileOf asks for one program's download and returns the
// .cyberduckprofile verbatim — the bytes a user installs — plus the row.
func (f *identityFixture) profileOf(label string, write bool) (credentialResponse, string) {
	f.t.Helper()
	var out credentialResponse
	body := `{"label":"` + label + `","write":` + map[bool]string{true: "true", false: "false"}[write] + `}`
	f.call("POST", "/api/v1/credentials", body, 200, &out)
	for _, file := range out.Files {
		if strings.HasSuffix(file.Name, ".cyberduckprofile") {
			return out, file.Content
		}
	}
	f.t.Fatalf("no .cyberduckprofile in the response: %+v", out)
	return out, ""
}

var clientIDRE = regexp.MustCompile(`<key>OAuth Client ID</key>\s*<string>([^<]*)</string>`)

func clientIDIn(t *testing.T, profile string) string {
	t.Helper()
	m := clientIDRE.FindStringSubmatch(profile)
	if m == nil || m[1] == "" {
		t.Fatalf("no OAuth Client ID in the profile:\n%s", profile)
	}
	return m[1]
}

// refresh is the whole of the no-click reconnect: POST /oauth/token with a
// saved refresh token and the client_id out of the installed profile, and
// NOTHING ELSE — no session header, no consent ticket, no authorization
// request. It is the only request Cyberduck makes when it already holds a
// grant, and the status is returned rather than asserted because a revoked
// grant being refused is as much a property as a live one being renewed.
func (f *identityFixture) refresh(token, clientID string) (int, map[string]any) {
	f.t.Helper()
	return oauthToken(f.t, f.srv.Client(), f.srv.URL, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token},
		"client_id":     {clientID},
	})
}

func (f *identityFixture) list() credentialList {
	f.t.Helper()
	var out credentialList
	f.call("GET", "/api/v1/credentials", "", 200, &out)
	return out
}

// TestTheProfileTheUserInstalledSurvivesARestart is the whole feature, said
// in the page's own JSON.
func TestTheProfileTheUserInstalledSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	f := newIdentityFixture(t)

	f.restart(dir)
	first, installed := f.profileOf("Cyberduck", true)
	// The notice is the only sentence the page shows about what this
	// download costs the user, so it has to be true about both halves of
	// the restart: the file is reusable, AND the connection it makes is.
	if !strings.Contains(first.Notice, "install this profile once") {
		t.Errorf("the notice does not tell the user the profile is reusable: %q", first.Notice)
	}
	if !strings.Contains(first.Notice, "survives a restart") {
		t.Errorf("the notice does not say the connection outlives the session: %q", first.Notice)
	}
	// And it must not go on promising the click that was removed. A page
	// that still says "once per pelfs browse session" would be telling the
	// user to expect a consent screen they will never see, which is how a
	// working feature gets reported as a bug.
	if strings.Contains(first.Notice, "once per") {
		t.Errorf("the notice still promises a click every session: %q", first.Notice)
	}

	f.restart(dir)

	t.Run("the restarted session lists it before anything asks again", func(t *testing.T) {
		got := f.list()
		if len(got.Clients) != 1 {
			t.Fatalf("the credential list has %d rows after a restart, want 1: %+v", len(got.Clients), got)
		}
		row := got.Clients[0]
		if row.Label != "Cyberduck" {
			t.Errorf("label came back as %q", row.Label)
		}
		if !row.Persistent {
			t.Error("an adopted client is not reported as persistent")
		}
		// Nobody ever connected this profile — it was downloaded and never
		// used — so there is nothing for the restart to carry. Adoption is
		// not authorization: a client is re-registered from the identity
		// file, and that on its own gives it no grant and records no
		// consent. (What a client that WAS connected keeps across a restart
		// is TestASavedConnectionSurvivesARestartWithNoConsentScreen's
		// subject, and it is a grant row rather than a consent.)
		if row.Grants != 0 || row.Consented {
			t.Error("a profile nobody has connected came back holding a grant or a consent")
		}
		if !row.Created.Equal(first.Created) {
			t.Errorf("created came back as %s, want the original %s", row.Created, first.Created)
		}
	})

	t.Run("and regenerating it produces the same file", func(t *testing.T) {
		second, again := f.profileOf("Cyberduck", true)
		if again != installed {
			t.Errorf("the regenerated profile is not the installed one:\n--- installed\n%s\n--- again\n%s",
				installed, again)
		}
		if clientIDIn(t, again) != clientIDIn(t, installed) {
			t.Error("the client id changed across the restart")
		}
		if second.Ref != f.list().Clients[0].Ref {
			t.Error("regenerating made a second row for one program")
		}
	})
}

// TestASavedConnectionSurvivesARestartWithNoConsentScreen is the OTHER half
// of the restart story, and the one the user asked for twice: the profile
// surviving is worth nothing if connecting it still costs a click every
// session.
//
// The claim, said exactly: a program that has been authorized ONCE gets a
// working access token out of the next `pelfs browse` process WITHOUT
// /oauth/authorize being reached at all. That distinction is the whole
// argument of internal/localoauth/grants.go — consent is required to CREATE
// a grant and not to keep one — so this test proves it the only way that
// means anything, by never sending the second session an authorization
// request.
//
// And then the price: a standing credential is only defensible if revoking
// it is durable, so the last third revokes the grant and restarts again to
// watch the same refresh token be refused.
func TestASavedConnectionSurvivesARestartWithNoConsentScreen(t *testing.T) {
	dir := t.TempDir()
	f := newIdentityFixture(t)

	// SESSION 1 — the click. The whole authorization-code + PKCE flow: a
	// navigation to the consent screen, a press of Authorize, and the code
	// exchanged on the back channel. This is the only session in the test
	// that touches /oauth/authorize.
	f.restart(dir)
	c, profile := f.profileOf("Cyberduck", true)
	id := clientIDIn(t, profile)
	saved := oauthConnect(t, f.srv.Client(), f.srv.URL, id, c.RedirectURI,
		localoauth.ScopeRead+" "+localoauth.ScopeWrite)
	if saved.refresh == "" {
		t.Fatal("the code exchange handed back no refresh token, so there is nothing to save")
	}
	live := f.list().Grants
	if len(live) != 1 {
		t.Fatalf("one authorization made %d grants: %+v", len(live), live)
	}
	// The page has to SAY that this connection outlives the process — a
	// credential the user cannot see is a credential the user cannot revoke
	// (A6), and this is the only credential pelfs issues that survives an
	// exit.
	if !live[0].Persistent {
		t.Error("the grant is not reported as persistent, so the page cannot tell the " +
			"user that this connection outlives the session")
	}
	if live[0].RefreshExpires.IsZero() {
		t.Error("a standing credential with no refresh_expires: the page has no bound to show")
	}
	grantRef := live[0].Ref

	// SESSION 2 — no click. A brand-new server over the same state
	// directory, and nothing but the token the client saved.
	f.restart(dir)
	status, tok := f.refresh(saved.refresh, id)
	if status != http.StatusOK {
		t.Fatalf("the saved refresh token was refused after a restart: %d %v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("the refresh handed back no access token: %v", tok)
	}
	// "Working" means the restarted session's own authorization server
	// accepts it for the scope the human approved. (No volume is open here,
	// so /dav/* answers 503 whatever it is handed; the credential itself is
	// what this file is about, and cmd/pelfs/browsewiring_test.go is where a
	// token of exactly this shape opens a real WebDAV surface.)
	g, ok := f.bs.oauth.Verify(access)
	if !ok {
		t.Fatal("the access token from the refresh authenticates nothing")
	}
	if !g.Write {
		t.Errorf("the adopted grant came back read-only: %+v", g)
	}
	if g.Ref != grantRef {
		t.Errorf("the adopted grant is %s, want the one the human authorized (%s)", g.Ref, grantRef)
	}
	// The adopted row is on the page too, so the user can find and kill it.
	if got := f.list().Grants; len(got) != 1 || got[0].Ref != grantRef || !got[0].Persistent {
		t.Errorf("the restarted session lists %+v, want the one persistent grant", got)
	}

	// SESSION 2, still — the revoke. The button has to reach the disk, or
	// the standing access it claims to have taken away comes back at the
	// next start.
	var out map[string]any
	f.call("POST", "/api/v1/credentials/revoke", `{"grant":"`+grantRef+`"}`, 200, &out)
	if out["revoked"] != true {
		t.Fatalf("revoking the grant answered %v", out)
	}
	if status, tok := f.refresh(saved.refresh, id); status != http.StatusBadRequest {
		t.Fatalf("the revoked token still refreshes in the session that revoked it: %d %v",
			status, tok)
	}

	// SESSION 3 — and it is still dead. This is what makes persisting a
	// grant defensible at all: the revocation survives the process the same
	// way the grant did.
	f.restart(dir)
	status, tok = f.refresh(saved.refresh, id)
	if status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Fatalf("a revoked grant came back after a restart: %d %v", status, tok)
	}
	if got := f.list().Grants; len(got) != 0 {
		t.Errorf("the revoked grant is still listed after a restart: %+v", got)
	}
}

// TestWithoutAStateDirectoryTheProfileIsStillOneTimeUse pins the contrast,
// so the feature cannot quietly become the default for a caller that has
// nowhere to put a key: a nil identity is the ephemeral server, and that is
// exactly the KL-17 behaviour.
func TestWithoutAStateDirectoryTheProfileIsStillOneTimeUse(t *testing.T) {
	f := newIdentityFixture(t)
	f.restart("")
	_, one := f.profileOf("Cyberduck", true)
	f.restart("")
	if got := f.list(); len(got.Clients) != 0 {
		t.Errorf("an ephemeral server adopted %d clients", len(got.Clients))
	}
	_, two := f.profileOf("Cyberduck", true)
	if clientIDIn(t, one) == clientIDIn(t, two) {
		t.Error("two ephemeral sessions minted the same client id")
	}
	for _, c := range f.list().Clients {
		if c.Persistent {
			t.Error("an ephemeral client is reported as persistent")
		}
	}
}

// TestRevokingFromThePageKillsTheInstalledProfile: what the button means now.
func TestRevokingFromThePageKillsTheInstalledProfile(t *testing.T) {
	dir := t.TempDir()
	f := newIdentityFixture(t)
	f.restart(dir)
	_, installed := f.profileOf("Cyberduck", true)
	ref := f.list().Clients[0].Ref

	var out map[string]any
	f.call("POST", "/api/v1/credentials/revoke", `{"client":"`+ref+`"}`, 200, &out)
	if out["revoked"] != true {
		t.Fatalf("revoke answered %v", out)
	}
	f.restart(dir)
	if got := f.list(); len(got.Clients) != 0 {
		t.Errorf("a revoked profile came back after a restart: %+v", got.Clients)
	}
	// And the identity is gone from the file rather than merely from the
	// list: asking for the same program again derives a DIFFERENT id, which
	// is what "the installed profile is dead" means to Cyberduck.
	_, fresh := f.profileOf("Cyberduck", true)
	if clientIDIn(t, fresh) == clientIDIn(t, installed) {
		t.Error("the revoked identity was re-derived")
	}
}

// TestRevokeReportsAnUndurableRevocation. The page must not print "revoked"
// about a revocation that comes back next session.
func TestRevokeReportsAnUndurableRevocation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newIdentityFixture(t)
	f.restart(dir)
	f.profileOf("Cyberduck", true)
	ref := f.list().Clients[0].Ref
	// The state directory goes away under the session. A chmod would not do
	// it: half of this project's gates run as root.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	f.call("POST", "/api/v1/credentials/revoke", `{"client":"`+ref+`"}`, 500, &out)
	if out["error"] == nil || !strings.Contains(out["error"].(string), "still on disk") {
		t.Errorf("the 500 does not say what is still true: %v", out)
	}
	if out["revoked"] != true {
		t.Errorf("the response hides that the session-local half happened: %v", out)
	}
}

// TestTheSecretsStayInTheStateDirectory. --state-dir must cover BOTH files
// this feature writes, the way cmd/pelfs/statedir_test.go insists everything
// else is covered — and each must be created LAZILY, by the act that needs
// it, so a session that hands out nothing leaves no new secret behind.
func TestTheSecretsStayInTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	f := newIdentityFixture(t)
	names := func() []string {
		t.Helper()
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(ents))
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return out
	}

	f.restart(dir)
	if got := names(); len(got) != 0 {
		t.Fatalf("a session that generated nothing wrote %v", got)
	}
	// A download writes the identity and nothing else: a profile that has
	// never been connected has no grant to record.
	c, profile := f.profileOf("Cyberduck", true)
	if got := names(); len(got) != 1 || got[0] != localoauth.IdentityFileName {
		t.Errorf("after a download the state directory holds %v, want only %s",
			got, localoauth.IdentityFileName)
	}
	// Connecting it writes the second file, which is what makes the
	// connection outlive the process. Both are in --state-dir and nowhere
	// else.
	oauthConnect(t, f.srv.Client(), f.srv.URL, clientIDIn(t, profile), c.RedirectURI,
		localoauth.ScopeRead)
	got := names()
	slices.Sort(got)
	want := []string{localoauth.GrantFileName, localoauth.IdentityFileName}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("after a connection the state directory holds %v, want %v", got, want)
	}
}
