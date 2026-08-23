package main

// `pelfs browse` end to end, against a real volume.
//
// newGenSession (mountgen_test.go) builds a fakeorigin-backed volume with
// a real genfs and a real write overlay — everything but the kernel
// binding — which is exactly the session `browse` serves. So these tests
// drive the actual route table, the actual publish path and the actual
// page, and the only thing they stub is the browser.
//
// internal/httpguard's table owns the threat model; what is asserted here
// is the verb: the route table this milestone hands to U6/U7/U11, the
// 202/409 publish contract, the SSE snapshot stream, and the page's own
// test hooks (which a Playwright suite selects on, so they are part of the
// contract rather than an implementation detail).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// browseFixture is a browseServer wired to a real session and served over
// a real loopback listener, so Host and Origin are the genuine ones.
type browseFixture struct {
	t   *testing.T
	bs  *browseServer
	g   *genSession
	srv *httptest.Server
	tok string
}

func newBrowseFixture(t *testing.T, rw bool, hooks bool) *browseFixture {
	t.Helper()
	g := newGenSession(t, rw)
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	a := browseArgs{branch: g.branch, rw: rw, testHooks: hooks}
	srv := httptest.NewServer(nil)
	// httptest binds 127.0.0.1 with a random port, which is what the guard
	// wants to hear about: the allowlist and the origin are computed from
	// the port the listener actually got — and so is every URL in a
	// generated WebDAV profile, which is why the server is built after the
	// listener rather than before it.
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	bs, err := newBrowseServer(g.prefix, a, 5*time.Minute, m, port)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = bs.routes(httpguard.New(httpguard.Config{Port: port, Sessions: m}))
	t.Cleanup(srv.Close)
	f := &browseFixture{t: t, bs: bs, g: g, srv: srv}
	f.tok = f.exchange()
	return f
}

// exchange runs the real bootstrap-for-session exchange over HTTP.
func (f *browseFixture) exchange() string {
	f.t.Helper()
	body := `{"bootstrap":"` + f.bs.sessions.Bootstrap() + `"}`
	res := f.do("POST", "/api/v1/session", body, "")
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		f.t.Fatalf("exchange: %d %s", res.StatusCode, b)
	}
	var out browsesession.ExchangeResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		f.t.Fatal(err)
	}
	return out.Session
}

// do issues a request shaped as the page's fetch: our Origin, the fetch
// metadata a browser adds, and the session header when tok is set.
func (f *browseFixture) do(method, path, body, tok string) *http.Response {
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
	if tok != "" {
		req.Header.Set(httpguard.SessionHeader, tok)
	}
	res, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	// Asserted on every response this file makes, for the same reason the
	// guard's table asserts it on every row: a cookie on 127.0.0.1 is
	// readable by every other local service.
	if v := res.Header.Values("Set-Cookie"); len(v) > 0 {
		f.t.Errorf("%s %s set a cookie: %q", method, path, v)
	}
	for k := range res.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			f.t.Errorf("%s %s emitted %s", method, path, k)
		}
	}
	return res
}

func (f *browseFixture) state() browseState {
	f.t.Helper()
	res := f.do("GET", "/api/v1/info", "", f.tok)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		f.t.Fatalf("info: %d %s", res.StatusCode, b)
	}
	var st browseState
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		f.t.Fatal(err)
	}
	return st
}

// TestBrowseStateBeforeAndAfterTheVolumeOpens is the ordering requirement
// from docs/design-webui.md: the page must be loadable and answerable
// BEFORE the volume is open, because that is when a device-flow prompt
// fires and there would otherwise be no page to show it on.
func TestBrowseStateBeforeAndAfterTheVolumeOpens(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	st := f.state()
	if st.Phase != "connecting" {
		t.Fatalf("phase = %q before the volume opens, want connecting", st.Phase)
	}
	if st.Volume != f.g.prefix {
		t.Errorf("volume = %q", st.Volume)
	}
	if st.Mode != "read-write" {
		t.Errorf("mode = %q", st.Mode)
	}
	// Publish must refuse rather than panic on a nil session.
	res := f.do("POST", "/api/v1/publish", "{}", f.tok)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("publish before the volume is open: %d, want 503", res.StatusCode)
	}

	f.bs.setReady(f.g, context.Background())
	st = f.state()
	if st.Phase != "ready" {
		t.Fatalf("phase = %q after setReady", st.Phase)
	}
	if st.Generation != f.g.gfs.Generation() {
		t.Errorf("generation = %d, want %d", st.Generation, f.g.gfs.Generation())
	}
	if st.Lease != "none" {
		// newGenSession takes no lease; "none" is not a fifth lease state
		// and must not read as one.
		t.Errorf("lease = %q, want none", st.Lease)
	}
}

// TestPublishIs202AndProgressArrivesOnTheStream. checkpoint holds g.mu
// across the whole seal, so a synchronous 200 would hang for minutes on a
// large drag. The contract is 202 plus a job id.
func TestPublishIs202AndProgressArrivesOnTheStream(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	f.bs.setReady(f.g, context.Background())
	writeFile(t, f.g.ov, "note.txt", "staged bytes")

	st := f.state()
	if st.StagedFiles == 0 && st.DirtyNodes == 0 {
		t.Fatal("the overlay reports nothing staged after a write")
	}

	res := f.do("POST", "/api/v1/publish", "{}", f.tok)
	var accepted struct {
		Job   string `json:"job"`
		Watch string `json:"watch"`
	}
	if err := json.NewDecoder(res.Body).Decode(&accepted); err != nil {
		t.Fatal(err)
	}
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("publish: %d, want 202", res.StatusCode)
	}
	if accepted.Job == "" || accepted.Watch != "/events" {
		t.Fatalf("202 body = %+v", accepted)
	}
	f.bs.waitForPublish()

	st = f.state()
	if st.Publish == nil || st.Publish.ID != accepted.Job {
		t.Fatalf("state does not carry the job: %+v", st.Publish)
	}
	if st.Publish.State != "done" {
		t.Fatalf("job state = %q, error %q", st.Publish.State, st.Publish.Error)
	}
	if st.Publish.Summary == "" {
		t.Error("a finished publish carries no summary")
	}
	if st.Generation == 0 {
		t.Error("generation is still 0 after a publish")
	}
	// The fast path is worth surfacing verbatim: a second publish with a
	// clean overlay is cheap and says so.
	res = f.do("POST", "/api/v1/publish", "{}", f.tok)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("second publish: %d", res.StatusCode)
	}
	f.bs.waitForPublish()
	if st := f.state(); !strings.Contains(st.Publish.Summary, "nothing changed") {
		t.Errorf("clean-overlay publish said %q", st.Publish.Summary)
	}
}

// TestConcurrentPublishIs409, and it is 409 rather than a queue because
// g.mu already serializes the seal: two clicks silently becoming one
// publish and one long wait is the outcome worth refusing.
//
// The first publish is held by taking g.mu in the test — the same lock
// checkpoint takes — so nothing here waits on a timer.
func TestConcurrentPublishIs409(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	f.bs.setReady(f.g, context.Background())
	writeFile(t, f.g.ov, "note.txt", "staged")

	f.g.mu.Lock()
	first := f.do("POST", "/api/v1/publish", "{}", f.tok)
	first.Body.Close() //nolint:errcheck
	if first.StatusCode != http.StatusAccepted {
		f.g.mu.Unlock()
		t.Fatalf("first publish: %d", first.StatusCode)
	}
	second := f.do("POST", "/api/v1/publish", "{}", f.tok)
	var conflict struct {
		Error string `json:"error"`
		Job   string `json:"job"`
	}
	_ = json.NewDecoder(second.Body).Decode(&conflict)
	second.Body.Close() //nolint:errcheck
	if second.StatusCode != http.StatusConflict {
		f.g.mu.Unlock()
		t.Fatalf("second publish: %d, want 409", second.StatusCode)
	}
	if conflict.Job == "" {
		t.Errorf("the 409 does not name the job that holds the overlay: %+v", conflict)
	}
	f.g.mu.Unlock()
	f.bs.waitForPublish()
	if st := f.state(); st.Publish.State != "done" {
		t.Fatalf("the held publish ended as %q (%s)", st.Publish.State, st.Publish.Error)
	}
}

// TestReadOnlySessionCannotPublish: the whole write half of the threat
// model is unreachable on the default, and the API says so rather than
// failing somewhere deeper.
func TestReadOnlySessionCannotPublish(t *testing.T) {
	f := newBrowseFixture(t, false, false)
	f.bs.setReady(f.g, context.Background())
	res := f.do("POST", "/api/v1/publish", "{}", f.tok)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("publish on a read-only session: %d, want 403", res.StatusCode)
	}
	if st := f.state(); st.Mode != "read-only" {
		t.Errorf("mode = %q", st.Mode)
	}
}

// TestEventsCarriesSnapshotsAndSaysGoodbye.
//
// The stream is snapshots, not deltas: every frame is a complete state, so
// a reconnect (which a real browser does on its own, and which a driver
// test forces) cannot leave a stale view. And the last frame before the
// process leaves is `bye`, so the page can say "pelfs exited" instead of
// "connection lost" — which is also what lets Server.Shutdown return
// instead of waiting on a response that is open by design.
func TestEventsCarriesSnapshotsAndSaysGoodbye(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	req, err := http.NewRequest("GET", f.srv.URL+"/events?s="+f.tok, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	br := bufio.NewReader(res.Body)
	// The first frame is a complete snapshot, before anything has changed.
	first := readSSEState(t, br)
	if first.Phase != "connecting" {
		t.Fatalf("first frame phase = %q", first.Phase)
	}
	// A state change nudges the stream rather than waiting for the tick.
	f.bs.setReady(f.g, context.Background())
	next := readSSEState(t, br)
	if next.Phase != "ready" {
		t.Fatalf("second frame phase = %q", next.Phase)
	}
	if next.Streams != 1 {
		t.Errorf("streams = %d, want 1 (U10 seals on this count)", next.Streams)
	}
	f.bs.closeStreams()
	if line := readSSEEvent(t, br, "bye"); line == "" {
		t.Fatal("no bye frame after closeStreams")
	}
}

// readSSEState reads frames until it finds a `state` one and returns it.
func readSSEState(t *testing.T, br *bufio.Reader) browseState {
	t.Helper()
	var event string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the stream: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: ") && event == "state":
			var st browseState
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &st); err != nil {
				t.Fatalf("frame is not a state document: %v", err)
			}
			return st
		}
	}
}

func readSSEEvent(t *testing.T, br *bufio.Reader, want string) string {
	t.Helper()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the stream: %v", err)
		}
		if strings.TrimRight(line, "\r\n") == "event: "+want {
			return line
		}
	}
}

// TestPageIsOneFileWithANonceAndTheTestIDsAPlaywrightSuiteNeeds, at
// /connect, which is where the hand-written page lives now that / is the
// file manager.
//
// The test ids are a contract, not decoration: a driver suite that selects
// on prose breaks the first time somebody rewords a sentence, and these
// sentences are meant to be reworded.
func TestPageIsOneFileWithANonceAndTheTestIDsAPlaywrightSuiteNeeds(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	res := f.do("GET", "/connect", "", "")
	body, err := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("GET /connect: %d", res.StatusCode)
	}
	page := string(body)

	// The CSP's nonce must be the one the page's own script and style
	// carry, and 'unsafe-inline' must not be there: the whole reason for a
	// nonce is that a file in the volume must not be able to become code
	// in this origin.
	csp := res.Header.Get("Content-Security-Policy")
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]+)'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP has no script nonce: %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP relaxes inline script: %q", csp)
	}
	for _, want := range []string{"frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %s: %q", want, csp)
		}
	}
	if !strings.Contains(page, `<script nonce="`+m[1]+`">`) {
		t.Error("the page's script does not carry the response's nonce")
	}
	if !strings.Contains(page, `<style nonce="`+m[1]+`">`) {
		t.Error("the page's style does not carry the response's nonce")
	}
	if res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", res.Header.Get("Referrer-Policy"))
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
	// Two nonces per response, so the page cannot be cached and replayed
	// with a stale nonce.
	second := f.do("GET", "/connect", "", "")
	secondCSP := second.Header.Get("Content-Security-Policy")
	second.Body.Close() //nolint:errcheck
	if secondCSP == csp {
		t.Error("the nonce is the same on two responses")
	}

	// The hooks a browser driver selects on.
	for _, id := range []string{
		"volume", "mode", "branch-generation", "lease", "lease-banner", "phase-banner",
		"durability", "durability-legend", "glyph-staged", "glyph-sending", "glyph-published",
		"publish-button", "publish-hint", "publish-status", "connect-another-program",
		"stream-status", "noscript", "test-hooks-banner", "body",
		// The anchor to the other surface. Each page carries exactly one,
		// so neither is a dead end; without it a user who followed the
		// file manager's link to the credential desk has no way back.
		"app-link",
		// The credential surface (U7/U8). The form and the two tables are
		// in the shipped HTML; the rows, the revoke buttons and the panel
		// that shows a password once are built by the script, so those ids
		// are checked in the script block below.
		"connect-blurb", "dav-url", "add-program-form", "add-program-label",
		"add-program-write", "add-program-write-label", "add-program-button",
		"connect-hint", "connect-empty", "credential-new", "client-list", "grant-list",
		// U13's card. The container is in the shipped HTML; the card,
		// its URL, its code and its dismiss button are built by the
		// script from the state document, so those ids live in the
		// script rather than the markup and the check below covers them.
		"sso-cards",
	} {
		if !strings.Contains(page, `data-testid="`+id+`"`) {
			t.Errorf("the page has no data-testid=%q", id)
		}
	}
	// The two glyphs must not be the same character. This is the one
	// rendering rule docs/design-webui.md states as a requirement: a file
	// that looks uploaded and is not in the federation is the worst
	// ambiguity this page could carry.
	staged := glyphFor(t, page, "glyph-staged")
	published := glyphFor(t, page, "glyph-published")
	if staged == published {
		t.Errorf("staged and published render the same glyph (%q)", staged)
	}
	// This page still has no file manager on it, and the person who
	// expected one has to be told that on the page rather than in a release
	// note — along with what to do instead, which is now a real answer
	// (connect a program) rather than "use pelfs mount".
	if !strings.Contains(page, "does not browse files") {
		t.Error("the page does not say what it cannot do")
	}
	// ...and, since the wiring pass, WHERE the thing it cannot do lives.
	// "This page does not browse files" was the whole answer when there was
	// no file manager; it is half an answer now, and the missing half is one
	// anchor.
	if !strings.Contains(page, `href="/"`) {
		t.Error("the page does not link to the file manager at /")
	}
	// No JavaScript at all is a real state a driver test will produce.
	if !strings.Contains(page, "<noscript>") {
		t.Error("the page has no noscript fallback")
	}
	// The SSO card's ids and the beacon, which the script builds rather
	// than the markup carrying. They are as much a contract as the ones
	// above: a driver suite selects on them, and the beacon is half of
	// U10's hint.
	for _, want := range []string{
		`"sso-card"`, `"sso-url"`, `"sso-code"`, `"sso-dismiss"`, `"sso-note"`,
		`navigator.sendBeacon`, `"/api/v1/beacon"`, `"pagehide"`, `"visibilitychange"`,
		// The credential rows and the one panel that ever holds a secret.
		`"client-row"`, `"client-revoke"`, `"grant-row"`, `"grant-revoke"`,
		`"credential-label"`, `"credential-dav-url"`, `"credential-basic-user"`,
		`"credential-basic-password"`, `"credential-notice"`,
		`"download-profile"`, `"download-bookmark"`, `"download-basic"`,
		`"/api/v1/credentials"`, `"/api/v1/credentials/revoke"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page's script does not carry %s", want)
		}
	}
	// A card is built with createElement and textContent. innerHTML with an
	// issuer-supplied URL in it would be the one place this page could be
	// made to execute somebody else's string.
	if strings.Contains(page, "innerHTML = `<div class=\"sso\"") {
		t.Error("the SSO card is built with innerHTML")
	}
}

// glyphFor extracts the character inside the element with this test id.
func glyphFor(t *testing.T, page, id string) string {
	t.Helper()
	re := regexp.MustCompile(`data-testid="` + id + `">([^<]+)<`)
	m := re.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no glyph for %s", id)
	}
	return m[1]
}

// THE FILE MANAGER IS ON THE ROUTE TABLE, which is the property this whole
// wiring pass exists to establish.
//
// It is worth a Go test and not only a Playwright one, because for four
// commits internal/webui's bundle was built, licence-checked, size-capped,
// notice-generated and gated by two CI jobs while `pelfs browse` served
// something else at `/` — and every one of those gates passed. A gate on the
// bundle's CONTENTS cannot notice that nothing serves it. This is the gate on
// the route table.
//
// The four assertions are the four things that were actually wrong or could
// be, in the order they were found:
//
//  1. `/` answers with the bundle's shell rather than the connection page.
//  2. The shell's own script and stylesheet are FETCHABLE at the paths it
//     names. There is no catch-all on this listener (see routes), so a bundle
//     whose asset names moved would 404 rather than falling back to
//     index.html — which is the failure mode a catch-all hides until a user
//     meets a white page.
//  3. The CSP lets the bundle's own code run and nothing else. The guard's
//     default is `default-src 'none'`, which renders the app as a blank page
//     with two console violations; that is what happened the first time this
//     route existed, and it is why appCSP is not optional.
//  4. A path nobody registered is still a 404.
func TestTheFileManagerIsServedAtRoot(t *testing.T) {
	f := newBrowseFixture(t, true, false)

	res := f.do("GET", "/", "", "")
	body, err := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("GET /: %d", res.StatusCode)
	}
	page := string(body)
	if !strings.Contains(page, `id="root"`) {
		t.Errorf("GET / is not the bundle's shell:\n%.200s", page)
	}
	// The connection page's own markers must NOT be here: that is the
	// regression this test is named for.
	if strings.Contains(page, `data-testid="connect-another-program"`) {
		t.Error("GET / is still serving the connection page")
	}
	// The no-JavaScript notice travels with the shell, because a React app
	// with scripting off is a blank page and this tool is holding somebody's
	// unpublished data.
	if !strings.Contains(page, `data-testid="noscript"`) {
		t.Error("the app shell has no noscript fallback")
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type %q, want text/html", ct)
	}
	// index.html must never be cached: a stale one across a pelfs upgrade is
	// a UI calling an API that has moved.
	if cc := res.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q on the shell, want no-store", cc)
	}

	// (2) every asset the shell names, at the path it names it.
	refs := regexp.MustCompile(`(?:src|href)="\./(assets/[^"]+)"`).FindAllStringSubmatch(page, -1)
	if len(refs) < 2 {
		t.Fatalf("the shell names %d assets; want at least a script and a stylesheet", len(refs))
	}
	for _, m := range refs {
		a := f.do("GET", "/"+m[1], "", "")
		a.Body.Close() //nolint:errcheck
		if a.StatusCode != 200 {
			t.Errorf("GET /%s: %d — the shell names an asset the route table does not serve", m[1], a.StatusCode)
		}
		// Content-hashed, so the name changes when the bytes do.
		if cc := a.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("GET /%s: Cache-Control %q, want an immutable cache", m[1], cc)
		}
	}

	// (3) the policy. 'self' rather than a nonce, because every byte of the
	// bundle's script and style is a file; 'unsafe-inline' would give away
	// exactly the protection A5 needs.
	csp := res.Header.Get("Content-Security-Policy")
	for _, want := range []string{
		"script-src 'self'", "style-src 'self'", "connect-src 'self'",
		"frame-ancestors 'none'", "form-action 'none'", "base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("the app's CSP lacks %s: %q", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("the app's CSP relaxes inline code: %q", csp)
	}
	if strings.Contains(csp, "default-src 'none'; frame-ancestors") {
		t.Error("the app is being served under the guard's default policy, " +
			"which refuses its own script: appHandler must set appCSP")
	}

	// The notices, which the app's status line links and the MIT licences
	// require to travel with the binary.
	tp := f.do("GET", "/third_party.txt", "", "")
	tpBody, _ := io.ReadAll(tp.Body)
	tp.Body.Close() //nolint:errcheck
	if tp.StatusCode != 200 || !strings.Contains(string(tpBody), "@svar-ui/react-filemanager") {
		t.Errorf("GET /third_party.txt: %d", tp.StatusCode)
	}

	// (4) no catch-all: an unregistered path is a 404, not the shell served
	// under a name that suggests it means something.
	for _, path := range []string{"/no-such-page", "/api/v1/fil", "/assets/nope.js"} {
		miss := f.do("GET", path, "", "")
		miss.Body.Close() //nolint:errcheck
		if miss.StatusCode != 404 {
			t.Errorf("GET %s: %d, want 404", path, miss.StatusCode)
		}
	}
}

// TestPprofIsNotOnTheWebListener, on the REAL route table rather than a
// stub of it. internal/control exposes the whole pprof surface on a 0600
// unix socket and says why that is safe; a browser session is not that
// boundary, and net/http/pprof's init has already put those routes on
// http.DefaultServeMux in this binary.
func TestPprofIsNotOnTheWebListener(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	for _, path := range []string{
		"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/cmdline",
		"/debug/pprof/profile?seconds=1", "/v1/status", "/v1/publish", "/v1/bugreport",
	} {
		res := f.do("GET", path, "", f.tok)
		body, _ := io.ReadAll(io.LimitReader(res.Body, 256))
		res.Body.Close() //nolint:errcheck
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404 (%s)", path, res.StatusCode, body)
		}
	}
}

// TestTicketMechanismOverTheVolume is the ticket round trip with the real
// file surface behind it: upload through the JSON API, mint a ticket for
// what was uploaded, and redeem it with NO credential on the request at
// all.
//
// Before the wiring pass this test asserted a 503 — M1 registered no
// Source, so minting refused rather than handing out a ticket that could
// only 404. That refusal is gone, and this is what replaced it.
func TestTicketMechanismOverTheVolume(t *testing.T) {
	f := newBrowseFixture(t, true, false)

	// Minting before the volume opens still refuses: a ticket lives 30
	// seconds, and one minted against a volume that is not there can only
	// expire.
	early := f.do("POST", "/api/v1/download", `{"path":"/x"}`, f.tok)
	earlyBody, _ := io.ReadAll(early.Body)
	early.Body.Close() //nolint:errcheck
	if early.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("mint before the volume opens: %d, want 503 (%s)", early.StatusCode, earlyBody)
	}

	f.bs.setReady(f.g, context.Background())
	const want = "these bytes came out of the overlay\n"
	f.upload(t, "/", "ticketed.txt", want)

	res := f.do("POST", "/api/v1/download", `{"path":"/ticketed.txt"}`, f.tok)
	var mint struct{ URL string }
	_ = json.NewDecoder(res.Body).Decode(&mint)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 || mint.URL == "" {
		t.Fatalf("mint: %d %+v", res.StatusCode, mint)
	}
	bare, err := f.srv.Client().Get(f.srv.URL + mint.URL)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(bare.Body)
	bare.Body.Close() //nolint:errcheck
	if bare.StatusCode != 200 || string(got) != want {
		t.Fatalf("ticketed download: %d %q", bare.StatusCode, got)
	}
	if cd := bare.Header.Get("Content-Disposition"); !strings.Contains(cd, "ticketed.txt") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	// One use. The URL that landed in the download history is already spent
	// by the time it was written there.
	again, err := f.srv.Client().Get(f.srv.URL + mint.URL)
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close() //nolint:errcheck
	if again.StatusCode != http.StatusNotFound {
		t.Errorf("replayed ticket: %d, want 404", again.StatusCode)
	}
}

// upload pushes one file through POST /api/v1/upload, which is a multipart
// request on SurfaceUpload rather than a JSON one — a different surface
// with a different content type, so it cannot go through do().
func (f *browseFixture) upload(t *testing.T, dir, name, body string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(webapi.UploadField, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, body); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST",
		f.srv.URL+"/api/v1/upload?id="+url.QueryEscape(dir), &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", f.srv.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(httpguard.SessionHeader, f.tok)
	res, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("upload %s: %d %s", name, res.StatusCode, out)
	}
}

// TestTestHooksDriveTheStatesABrowserCannotReach. There is no file surface
// in M1, so "staged, not published" and a stale lease are unreachable from
// a browser — which is exactly why the affordance exists. It is a flag
// rather than a build tag so that the suite drives the SAME binary
// everyone ships, and it is on the session-credentialed surface so it adds
// no reach to anything that could not already publish.
func TestTestHooksDriveTheStatesABrowserCannotReach(t *testing.T) {
	off := newBrowseFixture(t, true, false)
	res := off.do("POST", "/api/v1/testhook", `{"lease":"lost"}`, off.tok)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("without --test-hooks the route answers %d, want 404", res.StatusCode)
	}
	if st := off.state(); st.TestHooks {
		t.Error("test_hooks is true without the flag")
	}

	f := newBrowseFixture(t, true, true)
	f.bs.setReady(f.g, context.Background())
	if st := f.state(); !st.TestHooks {
		t.Fatal("test_hooks is false with the flag (the page's banner keys off this)")
	}
	res = f.do("POST", "/api/v1/testhook", `{"lease":"stale","staged_files":14,`+
		`"staged_bytes":412000000,"upload_backlog":9999,"download_body":"hello"}`, f.tok)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		t.Fatalf("testhook: %d", res.StatusCode)
	}
	st := f.state()
	if st.Lease != "stale" || st.StagedFiles != 14 || st.StagedBytes != 412000000 || st.UploadBacklog != 9999 {
		t.Fatalf("overrides did not land: %+v", st)
	}
	// And the synthetic download source, so the ticket round trip is
	// exercisable from a real browser: minted by an authenticated call,
	// redeemed with NO credential at all.
	res = f.do("POST", "/api/v1/download", `{"path":"/hello.txt"}`, f.tok)
	var mint struct{ URL string }
	_ = json.NewDecoder(res.Body).Decode(&mint)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 || mint.URL == "" {
		t.Fatalf("mint: %d %+v", res.StatusCode, mint)
	}
	bare, err := http.NewRequest("GET", f.srv.URL+mint.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.srv.Client().Do(bare)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(got.Body)
	got.Body.Close() //nolint:errcheck
	if got.StatusCode != 200 || string(payload) != "hello" {
		t.Fatalf("ticketed download with no credential: %d %q", got.StatusCode, payload)
	}
	if cd := got.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	// Replay must fail: the URL in the download history is already spent.
	again, err := f.srv.Client().Get(f.srv.URL + mint.URL)
	if err != nil {
		t.Fatal(err)
	}
	again.Body.Close() //nolint:errcheck
	if again.StatusCode != http.StatusNotFound {
		t.Errorf("replayed ticket: %d, want 404", again.StatusCode)
	}
}

// TestLaunchOutputIsTheDocumentedBlock. The terminal output is a contract
// too: it is what a user on a login node, or a user whose browser did not
// open, has to work from.
func TestLaunchOutputIsTheDocumentedBlock(t *testing.T) {
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	launch := m.LaunchURL("http://127.0.0.1:49731")
	out := captureStdout(t, func() {
		printLaunch("pelican://fed/prefix", launch, browseArgs{rw: true, open: true})
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("printLaunch wrote %d lines:\n%s", len(lines), out)
	}
	if lines[0] != "pelfs browse pelican://fed/prefix" {
		t.Errorf("line 1 = %q", lines[0])
	}
	if !strings.Contains(lines[1], "opening http://127.0.0.1:49731/#bt=") {
		t.Errorf("line 2 = %q", lines[1])
	}
	// The fragment is the credential; a URL printed without it would make
	// the third line's promise false.
	if !strings.Contains(lines[1], m.Bootstrap()) {
		t.Errorf("the printed URL does not carry the bootstrap token: %q", lines[1])
	}
	if !strings.Contains(lines[2], "single-use, 2-minute expiry") {
		t.Errorf("line 3 = %q", lines[2])
	}
	if lines[3] != "  Ctrl-C to stop; the session seals on exit." {
		t.Errorf("line 4 = %q", lines[3])
	}
	// Read-only says something true instead: there is nothing to seal.
	ro := captureStdout(t, func() {
		printLaunch("pelican://fed/prefix", launch, browseArgs{})
	})
	if !strings.Contains(ro, "nothing to seal") {
		t.Errorf("the read-only block promises a seal: %q", ro)
	}
	if !strings.Contains(ro, "  open http") {
		t.Errorf("without --open the block still says it is opening: %q", ro)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = saved
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// TestRunBrowseEndToEnd drives the VERB, not just its handlers: bind,
// print the URL, open a real volume over a fakeorigin, take the branch
// lease, answer the page, then stop and seal.
//
// It is the only test that covers runBrowse's own sequence — the ordering
// requirement (listener before volume), the lease, the teardown order —
// and that sequence is where a mistake costs somebody their unsealed work.
func TestRunBrowseEndToEnd(t *testing.T) {
	ctx := context.Background()
	origin := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	defer origin.Close()
	prefix := origin.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatal(err)
	}
	// Short, because the control socket lives in here and a unix socket
	// path is capped near 104 bytes.
	stateDir, err := os.MkdirTemp("", "pb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stateDir) //nolint:errcheck
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "v2-signing.key"),
		[]byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var volID [16]byte
	if _, err := rand.Read(volID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: stateDir, Branch: "main", SigningKey: priv, VolumeID: volID,
	}); err != nil {
		t.Fatal(err)
	}

	// The verb prints its launch block to stdout; that is how the test
	// learns the port, exactly as a user does.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	savedOut := os.Stdout
	os.Stdout = w
	stop := make(chan struct{})
	browseStop = stop
	t.Cleanup(func() { os.Stdout = savedOut; browseStop = nil })

	o := &cmdOpts{stateDir: stateDir, prefetch: "none", snapshotInterval: 0}
	done := make(chan int, 1)
	go func() {
		done <- runBrowse(o, prefix, browseArgs{branch: "main", rw: true})
	}()

	br := bufio.NewReader(r)
	var launch string
	for launch == "" {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the launch block: %v", err)
		}
		// Matched on the fragment, not on the scheme: the prefix in the
		// block's first line is itself a 127.0.0.1 URL when the volume is
		// a fakeorigin.
		if i := strings.Index(line, "http://127.0.0.1:"); i >= 0 && strings.Contains(line, "#bt=") {
			launch = strings.TrimSpace(strings.Fields(line[i:])[0])
		}
	}
	base, frag, ok := strings.Cut(launch, "#bt=")
	if !ok {
		t.Fatalf("the launch URL carries no bootstrap token: %q", launch)
	}
	base = strings.TrimSuffix(base, "/")

	// The page must be answerable BEFORE the volume finishes opening, and
	// the session exchange with it — that is the whole reason the listener
	// comes first.
	client := &http.Client{Timeout: 10 * time.Second}
	get := func(path, tok string) *http.Response {
		req, err := http.NewRequest("GET", base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if tok != "" {
			req.Header.Set(httpguard.SessionHeader, tok)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return res
	}
	// `/` is the file manager: internal/webui's bundle, whose durability
	// panel is in the JavaScript rather than in the markup. The marker that
	// belongs in a Go test is therefore the SHELL — the mount point React
	// renders into and the hashed script that renders it — not a test id
	// that only exists after the bundle has run.
	page := get("/", "")
	pageBody, _ := io.ReadAll(page.Body)
	page.Body.Close() //nolint:errcheck
	if page.StatusCode != 200 || !strings.Contains(string(pageBody), `id="root"`) {
		t.Fatalf("GET / (the file manager): %d, body %.120q", page.StatusCode, pageBody)
	}
	// And `/connect` is the hand-written page, which does carry the panel in
	// its markup. Both must answer before the volume has finished opening:
	// that is the whole reason the listener comes first.
	conn := get("/connect", "")
	connBody, _ := io.ReadAll(conn.Body)
	conn.Body.Close() //nolint:errcheck
	if conn.StatusCode != 200 || !strings.Contains(string(connBody), `data-testid="durability"`) {
		t.Fatalf("GET /connect: %d", conn.StatusCode)
	}

	req, err := http.NewRequest("POST", base+"/api/v1/session",
		strings.NewReader(`{"bootstrap":"`+frag+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ex browsesession.ExchangeResponse
	_ = json.NewDecoder(res.Body).Decode(&ex)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 || ex.Session == "" {
		t.Fatalf("exchange: %d", res.StatusCode)
	}

	// The volume opens on its own goroutine, so the page's own mechanism —
	// the event stream — is what says when it is ready. This waits on that
	// rather than on a timer.
	sreq, err := http.NewRequest("GET", base+"/events?s="+ex.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	sreq.Header.Set("Sec-Fetch-Site", "same-origin")
	// A separate client with NO timeout: the event stream is a response
	// that stays open for the life of the tab, and a Client.Timeout would
	// cut it off mid-session.
	stream, err := (&http.Client{}).Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close() //nolint:errcheck
	sbr := bufio.NewReader(stream.Body)
	var st browseState
	for st.Phase != "ready" {
		st = readSSEState(t, sbr)
		if st.Phase == "failed" {
			t.Fatalf("the volume failed to open: %s", st.Error)
		}
	}
	if st.Lease != "held" {
		t.Errorf("lease = %q, want held (a --rw browse session takes the branch)", st.Lease)
	}
	if st.Mode != "read-write" {
		t.Errorf("mode = %q", st.Mode)
	}
	if st.Volume != prefix {
		t.Errorf("volume = %q", st.Volume)
	}

	// And a publish, so the whole path — 202, the job, the seal, the
	// generation — runs inside the real verb rather than a fixture.
	preq, err := http.NewRequest("POST", base+"/api/v1/publish", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	preq.Header.Set("Content-Type", "application/json")
	preq.Header.Set("Origin", base)
	preq.Header.Set("Sec-Fetch-Site", "same-origin")
	preq.Header.Set(httpguard.SessionHeader, ex.Session)
	pres, err := client.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close() //nolint:errcheck
	if pres.StatusCode != http.StatusAccepted {
		t.Fatalf("publish: %d, want 202", pres.StatusCode)
	}
	for st.Publish == nil || st.Publish.State == "running" {
		st = readSSEState(t, sbr)
	}
	if st.Publish.State != "done" {
		t.Fatalf("publish ended as %q: %s", st.Publish.State, st.Publish.Error)
	}

	// Stop it the way Ctrl-C does, and let the teardown run.
	close(stop)
	if code := <-done; code != 0 {
		t.Fatalf("runBrowse exited %d", code)
	}
	// The session statistics are the record that the teardown ran at all.
	if _, err := os.Stat(filepath.Join(stateDir, "pelfs-stats.json")); err != nil {
		t.Errorf("no statistics file after teardown: %v", err)
	}
	// And the listener is gone: a browse session that left a port open
	// would be a credential-bearing server outliving its terminal.
	if res := tryGet(base + "/"); res == nil {
		// good: connection refused
	} else {
		res.Body.Close() //nolint:errcheck
		t.Error("the listener is still answering after the session ended")
	}
}

func tryGet(url string) *http.Response {
	c := &http.Client{Timeout: 2 * time.Second}
	res, err := c.Get(url)
	if err != nil {
		return nil
	}
	return res
}
