package main

// THE WIRING PASS, ASSERTED THROUGH THE VERB'S OWN ROUTE TABLE.
//
// internal/webapi, internal/localoauth, internal/vfsdav and internal/httpguard
// each have a suite that proves what they do; internal/localoauth's
// dav_integration_test.go even runs the same four registration lines against a
// memfs. What none of them can prove is that `pelfs browse` mounted them —
// that the JSON API reaches THIS session's overlay, that a credential minted
// here opens THAT WebDAV surface, and that the two principals stay apart on
// the route table this binary actually serves.
//
// So everything here goes over a real listener, against a real volume built
// on a fakeorigin, through browseServer.routes.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// mintCredential runs the page's own registration call and returns the
// response, secrets and all.
func (f *browseFixture) mintCredential(t *testing.T, label string, write bool) credentialResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"label": label, "write": write})
	res := f.do("POST", "/api/v1/credentials", string(body), f.tok)
	raw, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register a client: %d %s", res.StatusCode, raw)
	}
	var out credentialResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// raw sends a request with no session credential and no browser fetch
// metadata: the shape a WebDAV client's request has.
func (f *browseFixture) raw(t *testing.T, method, path, auth, body string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if method == "PROPFIND" {
		req.Header.Set("Depth", "1")
	}
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func basicAuth(user, pass string) string {
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

// TestTheJSONAPIReachesThisSessionsOverlay is U11 mounted: an upload through
// the API is a file the same session's WebDAV surface can read, and a
// directory listing is the volume's own.
func TestTheJSONAPIReachesThisSessionsOverlay(t *testing.T) {
	f := newBrowseFixture(t, true, false)

	// Before the volume opens the surface answers 503 rather than
	// pretending the volume is empty — webapi.ErrNotReady through
	// browseServer.volume, which is the only thing standing between a
	// route table built at second zero and a filesystem that does not
	// exist yet.
	early := f.do("GET", "/api/v1/files", "", f.tok)
	early.Body.Close() //nolint:errcheck
	if early.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/v1/files before the volume: %d, want 503", early.StatusCode)
	}

	f.bs.setReady(f.g, t.Context())
	f.upload(t, "/", "wired.txt", "through the JSON API\n")

	res := f.do("GET", "/api/v1/files", "", f.tok)
	var ents []webapi.Entry
	if err := json.NewDecoder(res.Body).Decode(&ents); err != nil {
		t.Fatal(err)
	}
	res.Body.Close() //nolint:errcheck
	var found *webapi.Entry
	for i := range ents {
		if ents[i].ID == "/wired.txt" {
			found = &ents[i]
		}
	}
	if found == nil {
		t.Fatalf("the root listing does not hold what was uploaded: %+v", ents)
	}
	if found.Type != webapi.TypeFile || found.Size == 0 {
		t.Errorf("entry = %+v", *found)
	}
	// The listing's own truthfulness headers, which the page needs to say
	// "showing 5,000 of N".
	if res.Header.Get(webapi.HeaderTotal) == "" || res.Header.Get(webapi.HeaderCap) == "" {
		t.Errorf("a listing with no count headers: %v", res.Header)
	}

	// And the SAME file over WebDAV, through a credential the page minted.
	// This is the whole wiring pass in one assertion: one overlay, two
	// surfaces, one permission model.
	c := f.mintCredential(t, "rclone in a test", true)
	dav := f.raw(t, http.MethodGet, davprofile.DAVPath+"wired.txt",
		basicAuth(c.BasicUser, c.BasicPassword), "")
	got, _ := io.ReadAll(dav.Body)
	dav.Body.Close() //nolint:errcheck
	if dav.StatusCode != http.StatusOK || string(got) != "through the JSON API\n" {
		t.Fatalf("GET over WebDAV: %d %q", dav.StatusCode, got)
	}

	// A write over WebDAV lands in the same overlay and the JSON API sees
	// it, which is the direction that would break if the two surfaces held
	// separate bindings.
	put := f.raw(t, http.MethodPut, davprofile.DAVPath+"fromdav.txt",
		basicAuth(c.BasicUser, c.BasicPassword), "written over WebDAV")
	put.Body.Close() //nolint:errcheck
	if put.StatusCode != http.StatusCreated {
		t.Fatalf("PUT over WebDAV: %d, want 201", put.StatusCode)
	}
	info := f.do("GET", "/api/v1/files/"+url.PathEscape("/fromdav.txt"), "", f.tok)
	info.Body.Close() //nolint:errcheck
	// A file is not a directory, so listing it is a 400/404 rather than a
	// listing; what matters is that a ticket for it serves the bytes.
	tk := f.do("POST", "/api/v1/download", `{"path":"/fromdav.txt"}`, f.tok)
	var mint struct{ URL string }
	_ = json.NewDecoder(tk.Body).Decode(&mint)
	tk.Body.Close() //nolint:errcheck
	if tk.StatusCode != http.StatusOK {
		t.Fatalf("mint a ticket for the WebDAV-written file: %d", tk.StatusCode)
	}
	down, err := f.srv.Client().Get(f.srv.URL + mint.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(down.Body)
	down.Body.Close() //nolint:errcheck
	if string(body) != "written over WebDAV" {
		t.Errorf("the JSON surface read back %q from the file WebDAV wrote", body)
	}
}

// TestTheTwoPrincipalsNeverMeetOnTheVerbsRouteTable is A6's table again,
// this time on the route table `pelfs browse` actually serves.
// internal/localoauth asserts it over a stand-in mux; the risk this closes is
// that the verb mounted something on the wrong surface.
func TestTheTwoPrincipalsNeverMeetOnTheVerbsRouteTable(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	f.bs.setReady(f.g, t.Context())
	c := f.mintCredential(t, "Cyberduck", true)
	auth := basicAuth(c.BasicUser, c.BasicPassword)

	t.Run("the session token is not a DAV credential", func(t *testing.T) {
		req, err := http.NewRequest("PROPFIND", f.srv.URL+davprofile.DAVPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(httpguard.SessionHeader, f.tok)
		res, err := f.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("PROPFIND with the session token: %d, want 401", res.StatusCode)
		}
	})

	t.Run("a DAV credential reaches no API route", func(t *testing.T) {
		// Including the ones the wiring pass added. A WebDAV client that
		// could publish, or could mint itself a second credential, would
		// be a client with more reach than the page that created it.
		for _, r := range []struct{ method, path string }{
			{"GET", "/api/v1/info"},
			{"GET", "/api/v1/files"},
			{"GET", "/api/v1/credentials"},
			{"POST", "/api/v1/credentials"},
			{"POST", "/api/v1/credentials/revoke"},
			{"POST", "/api/v1/publish"},
			{"POST", "/api/v1/download"},
		} {
			req, err := http.NewRequest(r.method, f.srv.URL+r.path, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", auth)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", f.srv.URL)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			res, err := f.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close() //nolint:errcheck
			if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusAccepted {
				t.Errorf("%s %s accepted a WebDAV credential (%d)", r.method, r.path, res.StatusCode)
			}
		}
	})

	t.Run("the upload route refuses one too", func(t *testing.T) {
		// SurfaceUpload takes multipart rather than JSON, so it is the one
		// API route the loop above cannot shape a request for.
		req, err := http.NewRequest("POST", f.srv.URL+"/api/v1/upload?id=%2F",
			strings.NewReader("--x--\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		req.Header.Set("Origin", f.srv.URL)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := f.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("upload with a WebDAV credential: %d, want 401", res.StatusCode)
		}
	})
}

// TestTokenEndpointIsOnSurfaceTokenInTheVerb pins the correction this wiring
// pass carried: browseServer.routes' doc comment said POST /oauth/token went
// on SurfaceExchange, and a Cyberduck-shaped request cannot pass that
// surface. internal/localoauth proves the property on its own mux; this
// proves the VERB got it right, because the comment is what a later
// maintainer will copy from.
func TestTokenEndpointIsOnSurfaceTokenInTheVerb(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"not-a-real-token"},
		"client_id":     {"not-a-real-client"},
	}
	// The exact shape google-oauth-client sends from inside Cyberduck: no
	// Origin, no Sec-Fetch-Site, and application/x-www-form-urlencoded.
	req, err := http.NewRequest("POST", f.srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	switch res.StatusCode {
	case http.StatusForbidden:
		t.Fatal("the token endpoint answered 403: it is on a surface that requires a " +
			"browser provenance signal, which a back-channel POST cannot send. " +
			"It belongs on httpguard.SurfaceToken")
	case http.StatusUnsupportedMediaType:
		t.Fatal("the token endpoint answered 415: it is on a surface that requires " +
			"application/json, and RFC 6749 §4.1.3 mandates form encoding. " +
			"It belongs on httpguard.SurfaceToken")
	case http.StatusBadRequest:
		// The handler refused it, which is what a bad refresh token gets.
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		if out["error"] != "invalid_grant" {
			t.Errorf("the handler answered %v, want invalid_grant", out)
		}
	default:
		t.Fatalf("POST /oauth/token: %d %s", res.StatusCode, body)
	}
}

// TestCredentialSurfaceListsAndRevokes is A6's "a credential the user cannot
// see is a credential the user cannot revoke", through the routes the page
// drives.
func TestCredentialSurfaceListsAndRevokes(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	f.bs.setReady(f.g, t.Context())

	list := func() credentialList {
		t.Helper()
		res := f.do("GET", "/api/v1/credentials", "", f.tok)
		var out credentialList
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusOK {
			t.Fatalf("list: %d", res.StatusCode)
		}
		return out
	}

	if got := list(); len(got.Clients) != 0 || !got.Writable {
		t.Fatalf("a fresh session already has credentials, or is not writable: %+v", got)
	}

	c := f.mintCredential(t, "Cyberduck", true)
	// Everything a WebDAV client needs, and the two secrets that are handed
	// back exactly once.
	if c.BasicUser == "" || c.BasicPassword == "" {
		t.Fatal("no Basic credential in the registration")
	}
	if c.RedirectURI != davprofile.RedirectURI(davprofile.DefaultCallbackPort) {
		t.Errorf("redirect_uri = %q; it must be the loopback callback pelfs writes "+
			"into the profile, because that string is the whole allowlist", c.RedirectURI)
	}
	if len(c.Files) != 3 {
		t.Fatalf("%d generated files, want 3", len(c.Files))
	}
	var profile string
	for _, file := range c.Files {
		if !strings.HasSuffix(file.Name, ".cyberduckprofile") {
			continue
		}
		profile = file.Content
	}
	if profile == "" {
		t.Fatal("no .cyberduckprofile among the generated files")
	}
	// Trap 1 of internal/davprofile: a non-blank OAuth Client ID is the
	// switch that turns OAuth on and password auth off. A profile without
	// one connects with a password dialog that has no password to give it.
	if !strings.Contains(profile, "<key>OAuth Client ID</key>") {
		t.Error("the generated profile carries no OAuth Client ID")
	}
	// Trap 2: `Authorization` for a dav profile is fed to
	// FlowType.valueOf() and throws inside session setup.
	if strings.Contains(profile, "<key>Authorization</key>") {
		t.Error("the generated profile carries an Authorization key")
	}
	if !strings.Contains(profile, davprofile.RedirectURI(davprofile.DefaultCallbackPort)) {
		t.Error("the profile's redirect does not match the one that was registered")
	}

	got := list()
	if len(got.Clients) != 1 || got.Clients[0].Ref != c.Ref {
		t.Fatalf("the registered client is not in the list: %+v", got.Clients)
	}
	if got.Clients[0].Label != "Cyberduck" || !got.Clients[0].Write {
		t.Errorf("the listed client = %+v", got.Clients[0])
	}
	// No secret in the inventory. The list is what a page keeps on screen,
	// re-fetches on a timer and would render into the DOM; the secrets are
	// handed back exactly once, by the POST that minted them.
	rawList := f.do("GET", "/api/v1/credentials", "", f.tok)
	rawBody, _ := io.ReadAll(rawList.Body)
	rawList.Body.Close() //nolint:errcheck
	for what, secret := range map[string]string{
		"the Basic password": c.BasicPassword,
		"the client id":      clientIDOf(t, profile),
	} {
		if strings.Contains(string(rawBody), secret) {
			t.Errorf("the credential list carries %s", what)
		}
	}

	// The credential works before the revoke and does not after it. This is
	// the property the button is for.
	auth := basicAuth(c.BasicUser, c.BasicPassword)
	before := f.raw(t, "PROPFIND", davprofile.DAVPath, auth, "")
	before.Body.Close() //nolint:errcheck
	if before.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND before revoke: %d, want 207", before.StatusCode)
	}
	rev := f.do("POST", "/api/v1/credentials/revoke", `{"client":"`+c.Ref+`"}`, f.tok)
	var revBody map[string]bool
	_ = json.NewDecoder(rev.Body).Decode(&revBody)
	rev.Body.Close() //nolint:errcheck
	if rev.StatusCode != http.StatusOK || !revBody["revoked"] {
		t.Fatalf("revoke: %d %v", rev.StatusCode, revBody)
	}
	after := f.raw(t, "PROPFIND", davprofile.DAVPath, auth, "")
	after.Body.Close() //nolint:errcheck
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("PROPFIND after revoke: %d, want 401", after.StatusCode)
	}
	if got := list(); len(got.Clients) != 0 {
		t.Errorf("the revoked client is still listed: %+v", got.Clients)
	}

	// Naming both, or neither, is a 400 rather than a guess about which was
	// meant.
	for _, body := range []string{`{}`, `{"client":"a","grant":"b"}`} {
		res := f.do("POST", "/api/v1/credentials/revoke", body, f.tok)
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("revoke %s: %d, want 400", body, res.StatusCode)
		}
	}
}

// TestReadOnlyBrowseCannotMintAWritableCredentialOrPublish is the whole
// read-only story on the wired surface. A read-only `pelfs browse` is the
// DEFAULT, so every one of these is what an ordinary first run gets.
func TestReadOnlyBrowseCannotMintAWritableCredentialOrPublish(t *testing.T) {
	f := newBrowseFixture(t, false, false)
	f.bs.setReady(f.g, t.Context())

	// 1. No writable client, refused at registration — the earliest of
	// internal/localoauth's three ceiling checks.
	res := f.do("POST", "/api/v1/credentials", `{"label":"rclone","write":true}`, f.tok)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a writable client on a read-only session: %d, want 403 (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), localoauth.ScopeWrite) {
		t.Errorf("the refusal does not name the scope it refused: %s", body)
	}

	// 2. A read-only credential is still minted, because a WebDAV client
	// that can only read is a perfectly good thing to want.
	c := f.mintCredential(t, "rclone", false)
	auth := basicAuth(c.BasicUser, c.BasicPassword)
	propfind := f.raw(t, "PROPFIND", davprofile.DAVPath, auth, "")
	propfind.Body.Close() //nolint:errcheck
	if propfind.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND with a read-only credential: %d, want 207", propfind.StatusCode)
	}

	// 3. And it cannot write. 403 and not 401: a 401 sends the client back
	// to ask for a password, which is the wrong instruction and, for an
	// OAuth profile, a dialog with no field in it.
	put := f.raw(t, http.MethodPut, davprofile.DAVPath+"refused.txt", auth, "nope")
	put.Body.Close() //nolint:errcheck
	if put.StatusCode != http.StatusForbidden {
		t.Errorf("PUT with a read-only credential: %d, want 403", put.StatusCode)
	}

	// 4. Nor can the JSON API, which asks billy the same question.
	mk := f.do("POST", "/api/v1/files/"+url.PathEscape("/"), `{"name":"nope.txt","type":"file"}`, f.tok)
	mk.Body.Close() //nolint:errcheck
	if mk.StatusCode != http.StatusForbidden {
		t.Errorf("POST /api/v1/files on a read-only session: %d, want 403", mk.StatusCode)
	}

	// 5. And the publish button is refused, which is where a read-only
	// session would otherwise take a lease it never had.
	pub := f.do("POST", "/api/v1/publish", "{}", f.tok)
	pub.Body.Close() //nolint:errcheck
	if pub.StatusCode != http.StatusForbidden {
		t.Errorf("publish on a read-only session: %d, want 403", pub.StatusCode)
	}

	// 6. The list says so too, so the page can disable the checkbox rather
	// than offering a control that always fails.
	lres := f.do("GET", "/api/v1/credentials", "", f.tok)
	var list credentialList
	_ = json.NewDecoder(lres.Body).Decode(&list)
	lres.Body.Close() //nolint:errcheck
	if list.Writable {
		t.Error("a read-only session reports itself writable")
	}
}

// clientIDOf digs the client_id out of a generated profile. The id is a
// secret only a profile download carries, and this is the only place a test
// in this file may look at one: it is here so that the "no secret in the
// inventory" check above can name the value it is looking for rather than
// trusting a field name. (cmd/pelfs/browseidentity_test.go has its own,
// because it asserts something different: that the id is the SAME one after
// a restart.)
func clientIDOf(t *testing.T, profile string) string {
	t.Helper()
	const key = "<key>OAuth Client ID</key>"
	i := strings.Index(profile, key)
	if i < 0 {
		t.Fatal("no OAuth Client ID in the profile")
	}
	rest := profile[i+len(key):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < start {
		t.Fatalf("the OAuth Client ID has no value: %.120s", rest)
	}
	return rest[start+len("<string>") : end]
}
