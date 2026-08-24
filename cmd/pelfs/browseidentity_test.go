package main

// THE CREDENTIAL DESK ACROSS A RESTART, at the layer where the page meets it.
//
// internal/localoauth's identity_test.go proves the derivation and what does
// and does not survive a process. scripts/browse-gate.sh proves it with the
// shipped binary and real Cyberduck. This file is the middle: the JSON
// contract the connection page selects on, over a real listener on ONE PORT,
// with two `pelfs browse` servers in sequence over one state directory.
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
	"os"
	"path/filepath"
	"regexp"
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
// authorization server, the same port, and the identity in dir. Pass an
// empty dir for the ephemeral server this verb used to be.
func (f *identityFixture) restart(dir string) {
	f.t.Helper()
	var id *localoauth.Identity
	if dir != "" {
		var err error
		if id, err = localoauth.OpenIdentity(dir); err != nil {
			f.t.Fatalf("OpenIdentity: %v", err)
		}
	}
	m, err := browsesession.New()
	if err != nil {
		f.t.Fatal(err)
	}
	bs, err := newBrowseServer("pelican://osg-htc.org/user/bbockelman",
		browseArgs{branch: "main", rw: true}, 5*time.Minute, m, f.port, id)
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
	if !strings.Contains(first.Notice, "install it once") {
		t.Errorf("the notice does not tell the user the profile is reusable: %q", first.Notice)
	}
	if !strings.Contains(first.Notice, "once per") {
		t.Errorf("the notice does not say a click per session remains: %q", first.Notice)
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
		if row.Grants != 0 || row.Consented {
			t.Error("a restart carried a grant or a consent across the process, which it must not")
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
		if second.BasicPassword == first.BasicPassword {
			t.Error("the Basic password survived the process; only the identity may")
		}
	})
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

// TestTheIdentityStaysInTheStateDirectory. --state-dir must cover it, the
// way cmd/pelfs/statedir_test.go insists everything else is covered.
func TestTheIdentityStaysInTheStateDirectory(t *testing.T) {
	dir := t.TempDir()
	f := newIdentityFixture(t)
	f.restart(dir)
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Fatalf("a session that generated nothing wrote %v (err %v)", ents, err)
	}
	f.profileOf("Cyberduck", true)
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != localoauth.IdentityFileName {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("the state directory holds %v, want only %s", names, localoauth.IdentityFileName)
	}
}
