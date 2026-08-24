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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// mintCredential runs the page's own registration call and returns the
// response. There is no secret in it any more — the client id is inside the
// generated profile, and there is no password at all.
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

// consentTicketRE scrapes the ticket out of the form on the consent page.
// The ticket exists in exactly one place — the body of a page rendered in
// the user's own browser — which is the whole of A7 control 6, so a test
// that wants a token presses the button like everybody else.
var consentTicketRE = regexp.MustCompile(`name="consent_ticket" value="([^"]+)"`)

// deliverRE pulls the authorization out of the SUCCESS PAGE. Pressing
// Authorize answers 200 with a page rather than a 303: the code reaches the
// client from a hidden frame whose src is the URL the redirect used to name
// (internal/localoauth's connectedPage says why). So this regexp is where a
// test stands in for Cyberduck's loopback listener.
var deliverRE = regexp.MustCompile(`<iframe class="deliver" src="([^"]+)"`)

// oauthTokens is what a client holds when the flow is done: the access token
// it sends to /dav/*, and the refresh token it saves to reconnect later.
type oauthTokens struct{ access, refresh string }

// oauthConnect runs the genuine authorization-code + PKCE flow in-process
// and returns the tokens, exactly as Cyberduck would end up holding them.
//
// THIS IS THE ONLY WAY ONTO /dav/* NOW. HTTP Basic is gone from this
// listener — vfsdav.Bearer is the whole of the DAV auth — so every test
// below that touches WebDAV has to navigate the consent screen, press
// Authorize and exchange the code. That is a feature rather than a tax: the
// credential a test carries is the one a real client would be holding.
//
// A live browse session is required for /oauth/authorize to answer at all
// (A7 control 2), so the caller must have exchanged a bootstrap first; every
// fixture in this package does that when it is built.
func oauthConnect(t *testing.T, hc *http.Client, origin, clientID, redirect, scope string) oauthTokens {
	t.Helper()
	// PKCE: the verifier never leaves this function, only its SHA-256 does.
	const verifier = "pelfs-wiring-verifier-0123456789-abcdefghijklmnopqrst"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {scope},
		"state":                 {"state-from-the-client"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	// The navigation Cyberduck's browser launcher makes: top level, no
	// credential of ours, and cross-site by definition.
	req, err := http.NewRequest(http.MethodGet, origin+"/oauth/authorize?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /oauth/authorize: %d\n%s", res.StatusCode, page)
	}
	m := consentTicketRE.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no consent ticket on the authorization page:\n%s", page)
	}

	// The click: a same-origin form POST with the headers a browser sends
	// for one.
	form := url.Values{"consent_ticket": {string(m[1])}, "decision": {"allow"}}
	req, err = http.NewRequest(http.MethodPost, origin+"/oauth/authorize",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ = io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /oauth/authorize: %d, want the 200 success page\n%s", res.StatusCode, page)
	}
	d := deliverRE.FindSubmatch(page)
	if d == nil {
		t.Fatalf("the success page carries no delivery frame:\n%s", page)
	}
	// html/template escaped the URL into the attribute, so `&` arrived as
	// `&amp;`. A browser unescapes before it fetches the frame, and so does
	// this.
	deliver, err := url.Parse(html.UnescapeString(string(d[1])))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(deliver.String(), redirect+"?") {
		t.Fatalf("the frame delivers to %q, want the registered callback %q", deliver, redirect)
	}
	if got := deliver.Query().Get("state"); got != "state-from-the-client" {
		t.Fatalf("the delivered state is %q", got)
	}

	// The back channel.
	status, tok := oauthToken(t, hc, origin, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {deliver.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
		"client_id":     {clientID},
	})
	if status != http.StatusOK {
		t.Fatalf("POST /oauth/token: %d %v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token came out of the code exchange: %v", tok)
	}
	refresh, _ := tok["refresh_token"].(string)
	return oauthTokens{access: access, refresh: refresh}
}

// oauthToken is one POST /oauth/token, whatever the grant type, shaped like
// the request google-oauth-client sends from inside Cyberduck: form-encoded,
// no Origin, no fetch metadata, and no credential but the ones in the body.
//
// It hands back the status rather than insisting on success. The refusal of
// a revoked or expired grant is as much a property as the acceptance of a
// live one, and cmd/pelfs/browseidentity_test.go asserts both through this.
func oauthToken(t *testing.T, hc *http.Client, origin string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, origin+"/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("POST /oauth/token: %v in %s", err, body)
	}
	return res.StatusCode, out
}

// bearer connects a minted credential for real and returns the
// Authorization header a WebDAV client would then send. `scope` is what the
// client asks for; the session's own mode is still the ceiling on it.
func (f *browseFixture) bearer(t *testing.T, c credentialResponse, scope string) string {
	t.Helper()
	var profile string
	for _, file := range c.Files {
		if strings.HasSuffix(file.Name, ".cyberduckprofile") {
			profile = file.Content
		}
	}
	if profile == "" {
		t.Fatalf("no .cyberduckprofile in the credential response: %+v", c)
	}
	tok := oauthConnect(t, f.srv.Client(), f.srv.URL,
		clientIDOf(t, profile), c.RedirectURI, scope)
	return "Bearer " + tok.access
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

	// And the SAME file over WebDAV, through a credential the page minted
	// and then a token the OAuth flow actually issued for it. This is the
	// whole wiring pass in one assertion: one overlay, two surfaces, one
	// permission model.
	c := f.mintCredential(t, "rclone in a test", true)
	auth := f.bearer(t, c, localoauth.ScopeRead+" "+localoauth.ScopeWrite)
	dav := f.raw(t, http.MethodGet, davprofile.DAVPath+"wired.txt", auth, "")
	got, _ := io.ReadAll(dav.Body)
	dav.Body.Close() //nolint:errcheck
	if dav.StatusCode != http.StatusOK || string(got) != "through the JSON API\n" {
		t.Fatalf("GET over WebDAV: %d %q", dav.StatusCode, got)
	}

	// A write over WebDAV lands in the same overlay and the JSON API sees
	// it, which is the direction that would break if the two surfaces held
	// separate bindings.
	put := f.raw(t, http.MethodPut, davprofile.DAVPath+"fromdav.txt",
		auth, "written over WebDAV")
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
	auth := f.bearer(t, c, localoauth.ScopeRead+" "+localoauth.ScopeWrite)

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
	// Everything a WebDAV client needs. The redirect is the whole allowlist,
	// so it has to be the one pelfs itself wrote into the profile.
	if c.RedirectURI != davprofile.RedirectURI(davprofile.DefaultCallbackPort) {
		t.Errorf("redirect_uri = %q; it must be the loopback callback pelfs writes "+
			"into the profile, because that string is the whole allowlist", c.RedirectURI)
	}
	// Two generated files, not three: the profile and the bookmark that
	// drives it. The third was the bookmark for the password path, and there
	// is no password path.
	if len(c.Files) != 2 {
		t.Fatalf("%d generated files, want 2", len(c.Files))
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
	// re-fetches on a timer and would render into the DOM; the one secret
	// this listener still issues — the client id — travels inside the
	// generated profile and must never appear as a field beside it.
	rawList := f.do("GET", "/api/v1/credentials", "", f.tok)
	rawBody, _ := io.ReadAll(rawList.Body)
	rawList.Body.Close() //nolint:errcheck
	for what, secret := range map[string]string{
		"the client id": clientIDOf(t, profile),
	} {
		if strings.Contains(string(rawBody), secret) {
			t.Errorf("the credential list carries %s", what)
		}
	}

	// The credential works before the revoke and does not after it. This is
	// the property the button is for.
	auth := f.bearer(t, c, localoauth.ScopeRead+" "+localoauth.ScopeWrite)
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
	auth := f.bearer(t, c, localoauth.ScopeRead)
	propfind := f.raw(t, "PROPFIND", davprofile.DAVPath, auth, "")
	propfind.Body.Close() //nolint:errcheck
	if propfind.StatusCode != http.StatusMultiStatus {
		t.Fatalf("PROPFIND with a read-only credential: %d, want 207", propfind.StatusCode)
	}

	// 3. And it cannot write. 403 and not 401: this listener's only
	// challenge is `Bearer`, so a 401 tells the client its token is no good
	// and sends it back through the consent screen for a fresh one — which
	// would issue exactly the same read-only token and fail again. 403 says
	// the true thing instead: the token is fine and the scope is not.
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
// secret the profile download is the ONLY carrier of — there is no field for
// it beside the files, and never was — so every test that has to name a
// client reads it out of the bytes a user would install, exactly as
// Cyberduck does. That is what makes the "no secret in the inventory" check
// above worth anything: it names the real value rather than trusting a field
// name, and it is the same value oauthConnect authorizes with.
// (cmd/pelfs/browseidentity_test.go has its own, because it asserts
// something different: that the id is the SAME one after a restart.)
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
