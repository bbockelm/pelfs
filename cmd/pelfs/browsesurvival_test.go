package main

// A PUBLISH IS NOT AN EXIT, AND AN EXIT IS NOT A HANG.
//
// Two reports, and one gap in the tests behind both.
//
// "After the first publish (automatic or something I triggered), the pelfs
// browse server shuts down automatically." Nothing in the verb asks for
// that, and every path that could — servePublish's goroutine, the idle
// sealer's inline seal, the checkpointer's — was written to leave the
// session running. But NOTHING ASSERTED IT. TestRunBrowseEndToEnd publishes
// and then immediately closes browseStop, and scripts/browse-gate.sh
// publishes and then immediately sends SIGTERM: both stop caring one line
// after the 202, so a session that died on its own between those two lines
// would have been green in every gate this repository has.
//
// "Whenever I start read-write, I just get a page that says 'reading the
// overlay…'. Never seems to progress." That one is the opposite shape: the
// session ENDED, correctly and for a stated reason (a killed session's
// branch lease outlives it by a TTL), inside the second it took the browser
// to attach — so the reason went to a terminal nobody was reading and the
// tab was left retrying against a closed port.
//
// So: a publish must leave the session serving, and a failure must leave the
// session serving long enough to say why. Both are asserted here against the
// real verb, because both are properties of runBrowse's own sequence rather
// than of any handler.

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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// liveBrowse is one `pelfs browse` process's worth of session, driven
// through the same three doors a browser uses: the launch URL on stdout,
// the bootstrap exchange, and the event stream.
type liveBrowse struct {
	t        *testing.T
	base     string
	session  string
	stateDir string
	prefix   string
	stop     chan struct{}
	done     chan int
}

// startLiveBrowse runs runBrowse on its own goroutine over a fakeorigin
// volume and waits until the launch URL has been printed — which is the
// same thing a user waits for, and the earliest instant the page is
// answerable.
func startLiveBrowse(t *testing.T, a browseArgs, o *cmdOpts) *liveBrowse {
	t.Helper()
	ctx := context.Background()
	origin := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(origin.Close)
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
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
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

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	l := &liveBrowse{t: t, stateDir: stateDir, prefix: prefix,
		stop: make(chan struct{}), done: make(chan int, 1)}
	browseStop = l.stop
	t.Cleanup(func() { os.Stdout = saved; browseStop = nil })
	if o == nil {
		o = &cmdOpts{prefetch: "none"}
	}
	o.stateDir = stateDir
	if a.branch == "" {
		a.branch = "main"
	}
	go func() { l.done <- runBrowse(o, prefix, a) }()

	br := bufio.NewReader(r)
	var launch string
	for launch == "" {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the launch block: %v", err)
		}
		if i := strings.Index(line, "http://127.0.0.1:"); i >= 0 && strings.Contains(line, "#bt=") {
			launch = strings.TrimSpace(strings.Fields(line[i:])[0])
		}
	}
	base, frag, ok := strings.Cut(launch, "#bt=")
	if !ok {
		t.Fatalf("the launch URL carries no bootstrap token: %q", launch)
	}
	l.base = strings.TrimSuffix(base, "/")
	l.session = l.exchange(frag)
	return l
}

func (l *liveBrowse) exchange(frag string) string {
	l.t.Helper()
	req, err := http.NewRequest("POST", l.base+"/api/v1/session",
		strings.NewReader(`{"bootstrap":"`+frag+`"}`))
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", l.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	var ex browsesession.ExchangeResponse
	_ = json.NewDecoder(res.Body).Decode(&ex)
	if res.StatusCode != 200 || ex.Session == "" {
		l.t.Fatalf("exchange: %d", res.StatusCode)
	}
	return ex.Session
}

// req issues one page-shaped request. It returns the response rather than
// failing on a status, because several callers are asserting the status.
func (l *liveBrowse) req(method, path, body string) *http.Response {
	l.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, l.base+path, rdr)
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Origin", l.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(httpguard.SessionHeader, l.session)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		l.t.Fatalf("%s %s: %v", method, path, err)
	}
	return res
}

func (l *liveBrowse) state() browseState {
	l.t.Helper()
	res := l.req("GET", "/api/v1/info", "")
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		l.t.Fatalf("GET /api/v1/info: %d %s", res.StatusCode, b)
	}
	var st browseState
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		l.t.Fatal(err)
	}
	return st
}

// stream opens a real event stream and hands back its reader. The client
// has NO timeout: this response stays open for the life of the tab.
func (l *liveBrowse) stream() (*bufio.Reader, func()) {
	l.t.Helper()
	req, err := http.NewRequest("GET", l.base+"/events?s="+l.session, nil)
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	return bufio.NewReader(res.Body), func() { res.Body.Close() } //nolint:errcheck
}

// awaitReady blocks until the volume is open, on the page's own mechanism
// rather than on a timer.
func (l *liveBrowse) awaitReady(br *bufio.Reader) browseState {
	l.t.Helper()
	for {
		st := readSSEState(l.t, br)
		switch st.Phase {
		case "ready":
			return st
		case "failed":
			l.t.Fatalf("the volume failed to open: %s", st.Error)
		}
	}
}

// upload puts one file in the volume through the page's own upload route:
// multipart on SurfaceUpload, which is a different surface and a different
// content type from every other call here.
func (l *liveBrowse) upload(name, body string) {
	l.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(webapi.UploadField, name)
	if err != nil {
		l.t.Fatal(err)
	}
	if _, err := io.WriteString(part, body); err != nil {
		l.t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		l.t.Fatal(err)
	}
	req, err := http.NewRequest("POST", l.base+"/api/v1/upload?id="+url.QueryEscape("/"), &buf)
	if err != nil {
		l.t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", l.base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(httpguard.SessionHeader, l.session)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	out, _ := io.ReadAll(res.Body)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		l.t.Fatalf("upload %s: %d %s", name, res.StatusCode, out)
	}
}

// stillServing is the whole point of both tests below: the session is up,
// the data plane answers, and the verb has not returned.
func (l *liveBrowse) stillServing(what string) browseState {
	l.t.Helper()
	select {
	case code := <-l.done:
		l.t.Fatalf("%s: runBrowse RETURNED (%d) — the session ended on its own", what, code)
	default:
	}
	st := l.state()
	if st.Phase != "ready" {
		l.t.Fatalf("%s: phase = %q, want ready", what, st.Phase)
	}
	// A route that reaches the volume, not just the server: a session
	// whose binding was torn down by a publish would answer /api/v1/info
	// from browseServer's own fields and fail here.
	res := l.req("GET", "/api/v1/files", "")
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		l.t.Fatalf("%s: the volume no longer lists: %d %s", what, res.StatusCode, b)
	}
	return st
}

func (l *liveBrowse) shutDown() int {
	l.t.Helper()
	close(l.stop)
	select {
	case code := <-l.done:
		return code
	case <-time.After(60 * time.Second):
		l.t.Fatal("runBrowse did not return after browseStop")
		return -1
	}
}

// TestASessionOutlivesAPublishTheUserAsked is the button, and everything it
// must NOT do.
//
// --snapshot-interval 0, so nothing publishes on its own: the one seal in
// this test is the one the request asked for, and any session that ends
// afterwards ended because of it.
func TestASessionOutlivesAPublishTheUserAsked(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})
	br, closeStream := l.stream()
	defer closeStream()
	before := l.awaitReady(br)

	l.upload("asked.txt", "published on request")
	res := l.req("POST", "/api/v1/publish", "{}")
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusAccepted {
		t.Fatalf("publish: %d, want 202", res.StatusCode)
	}
	// Followed on the stream, which is also the assertion that the stream
	// SURVIVES the publish: every frame here arrives on the connection that
	// was open before it started.
	var st browseState
	for st.Publish == nil || st.Publish.State == "running" {
		st = readSSEState(t, br)
	}
	if st.Publish.State != "done" {
		t.Fatalf("publish ended as %q: %s", st.Publish.State, st.Publish.Error)
	}

	after := l.stillServing("after a publish the user asked for")
	if after.Generation <= before.Generation {
		t.Errorf("generation %d did not advance past %d", after.Generation, before.Generation)
	}
	// The stream is not merely un-closed, it is still DELIVERING: a
	// half-shut session that had stopped sampling would sit here.
	l.upload("second.txt", "and the stream is still live")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if s := readSSEState(t, br); s.StagedFiles > 0 || s.DirtyNodes > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no frame reflecting a post-publish write arrived on the stream")
		}
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestASessionOutlivesAnAutomaticPublish is the other trigger, and the one
// no gate has ever run: scripts/browse-gate.sh passes --snapshot-interval 0
// precisely so that "the ONLY generation this gate publishes" is the
// button's, which means the periodic checkpointer and the idle sealer have
// never published anything in CI.
//
// Nothing in this test asks for a publish. The generation advances on its
// own, and the session has to still be there afterwards.
func TestASessionOutlivesAnAutomaticPublish(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true},
		&cmdOpts{prefetch: "none", snapshotInterval: time.Second})
	br, closeStream := l.stream()
	before := l.awaitReady(br)
	l.upload("automatic.txt", "nobody asked for this one")
	// The tab goes away, which is the idle sealer's trigger; the periodic
	// checkpointer is on the same short interval. Either one publishing is
	// the case under test — what must not happen is the session leaving
	// with it.
	closeStream()

	deadline := time.Now().Add(60 * time.Second)
	var st browseState
	for {
		select {
		case code := <-l.done:
			t.Fatalf("runBrowse RETURNED (%d) while waiting for an automatic publish", code)
		default:
		}
		st = l.state()
		if st.Generation > before.Generation {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no automatic publish in 60s (generation still %d, %d staged)",
				st.Generation, st.StagedFiles)
		}
		time.Sleep(100 * time.Millisecond)
	}

	l.stillServing("after an automatic publish")
	// And a browser that comes back gets a live stream over the new
	// generation, rather than a connection to a server on its way out.
	br2, close2 := l.stream()
	defer close2()
	again := l.awaitReady(br2)
	if again.Generation != st.Generation {
		t.Errorf("a reattached stream reports generation %d, want %d",
			again.Generation, st.Generation)
	}
	if code := l.shutDown(); code != 0 {
		t.Errorf("runBrowse exited %d", code)
	}
}

// TestAFailedOpenIsServedRatherThanRaced is the "reading the overlay…"
// report, from the page's side.
//
// The volume is made to refuse — an explicit --volume-pubkey that does not
// verify, which is the same shape of refusal as the branch lease that
// actually caused the report: a real error, raised after the URL has been
// printed and the page has been loaded. What the user must NOT be left with
// is a tab retrying against a closed port.
func TestAFailedOpenIsServedRatherThanRaced(t *testing.T) {
	l := startLiveBrowse(t, browseArgs{rw: true, pubkeyHex: strings.Repeat("ab", 32)},
		&cmdOpts{prefetch: "none", snapshotInterval: 0})

	// The listener is still there AFTER the open failed — that is the whole
	// fix — so a browser that attaches a moment late still gets an answer.
	br, closeStream := l.stream()
	defer closeStream()
	var st browseState
	deadline := time.Now().Add(30 * time.Second)
	for st.Phase != "failed" {
		st = readSSEState(t, br)
		if time.Now().After(deadline) {
			t.Fatalf("the stream never reported the failure (phase %q)", st.Phase)
		}
	}
	// The two facts a page has to carry, because its reader has a browser
	// and not a shell: what went wrong, and where this session's state is.
	if !strings.Contains(st.Error, "not signed by the trusted key") {
		t.Errorf("the page does not say what went wrong: %q", st.Error)
	}
	if !strings.Contains(st.Error, l.stateDir) {
		t.Errorf("the page does not name the state directory %s: %q", l.stateDir, st.Error)
	}
	// And /api/v1/info agrees with the stream: a page that missed the frame
	// still gets the reason when it asks.
	if got := l.state(); got.Phase != "failed" || got.Error != st.Error {
		t.Errorf("info reports phase %q / %q", got.Phase, got.Error)
	}

	// Ctrl-C ends the wait immediately, and the verb still reports failure.
	if code := l.shutDown(); code != 1 {
		t.Errorf("runBrowse exited %d after a failed open, want 1", code)
	}
}

// TestTheFailedPageDoesNotWaitForever is the other half of that fix, and the
// one that matters more: a `pelfs browse` that will not stop is a worse bug
// than the one being fixed. With no browser attached the wait is
// browseFailGrace and then the session leaves.
//
// The clock is injected rather than slept through: every call moves it an
// hour, so the first sample is already past any window this file defines
// and the test costs one tick instead of fifteen seconds.
func TestTheFailedPageDoesNotWaitForever(t *testing.T) {
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBrowseServer("pelican://example.org/vol", browseArgs{}, time.Minute, m, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	var calls atomic.Int64
	b.now = func() time.Time { return base.Add(time.Duration(calls.Add(1)) * time.Hour) }

	done := make(chan struct{})
	go func() { b.lingerAfterFailedOpen("http://127.0.0.1:1"); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("lingerAfterFailedOpen never returned with no browser attached")
	}
}
