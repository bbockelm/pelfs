package webapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/httpguard"
)

// THE RECORDED CONTRACT, REPLAYED AGAINST THE REAL HANDLERS.
//
// docs/design-webui.md's testing plan, layer 5: run the real component
// against a logging stub once, on a machine with Node; commit the recording;
// and make the Go test replay it forever. internal/webui/contract_test.go
// pins what the recording SAYS (the routes, the headers, the two behaviours
// that decide whether the component is usable at all) and says, in its own
// words, "when U11 lands, replay belongs here, against these same steps".
// This is that replay: the same fixture, driven through this package's
// handlers behind the real guard.
//
// The fixture is read from ../webui/testdata rather than copied, so there is
// exactly one recording in the repo and a re-record updates both tests at
// once.
const recordingPath = "../webui/testdata/svar-contract/recording.json"

type recordedRequest struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Query         string `json:"query"`
	ContentType   string `json:"contentType"`
	SessionHeader string `json:"sessionHeader"`
	BodyBytes     int    `json:"bodyBytes"`
	Body          string `json:"body"`
	Status        int    `json:"status"`
}

type recordedStep struct {
	Step     string            `json:"step"`
	Gesture  string            `json:"gesture"`
	Note     string            `json:"note"`
	Requests []recordedRequest `json:"requests"`
}

type recording struct {
	APIBase   string            `json:"apiBase"`
	Component map[string]string `json:"component"`
	Steps     []recordedStep    `json:"steps"`
}

func loadRecording(t *testing.T) recording {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(recordingPath))
	if err != nil {
		t.Fatalf("reading the U0 recording: %v\n"+
			"It is committed; regenerate with `pnpm probe:record` in webui/frontend.", err)
	}
	var r recording
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("parsing the U0 recording: %v", err)
	}
	if r.APIBase != "/api/v1" {
		t.Fatalf("the recording's apiBase is %q; these handlers are mounted at /api/v1", r.APIBase)
	}
	if len(r.Steps) == 0 {
		t.Fatal("the recording has no steps")
	}
	return r
}

// The volume the recording was made against: the stub served three folders
// and five files per directory, and the steps name /dir-0, /dir-0/dir-1,
// /dir-0/dir-2, /dir-2 and file-0..3.txt. Staging it here is what makes the
// replay a real exercise of the handlers rather than a 404 tour.
func stageRecordedTree(f *fix) {
	d0 := f.dir(rootIno, "dir-0")
	f.dir(d0, "dir-1")
	f.dir(d0, "dir-2")
	f.dir(rootIno, "dir-2")
	for i := 0; i < 5; i++ {
		f.text(d0, fmt.Sprintf("file-%d.txt", i), strings.Repeat("x", 1024*(i+1)))
	}
}

// Every request the component really made, replayed in order, against the
// handlers behind the guard. A component upgrade that changes the wire shape
// shows up here as a failure.
func TestReplayTheRecordedContract(t *testing.T) {
	rec := loadRecording(t)
	g := newGuarded(t)
	stageRecordedTree(g.fix)

	for _, step := range rec.Steps {
		if step.Step == "as-shipped-provider" {
			continue // asserted separately: it is a recorded DEFECT
		}
		for _, q := range step.Requests {
			target := q.Path + q.Query
			t.Run(step.Step+" "+q.Method+" "+q.Path, func(t *testing.T) {
				// GET /api/v1/info (no id) is the durability panel and is
				// served by the browse server, not by this package. It has
				// its own test below, because "who owns this route" is a
				// wiring question and not a protocol one.
				if q.Method == http.MethodGet && q.Path == "/api/v1/info" {
					t.Skip("the browse server serves this one: see " +
						"TestInfoWithNoIDBelongsToTheBrowseServer")
				}
				ct, body := replayBody(t, q)
				r := g.req(t, q.Method, target, ct, body)
				if r.Code < 200 || r.Code > 299 {
					t.Fatalf("the component's own %s %s was answered %d: %s\n"+
						"gesture: %s\nnote: %s", q.Method, target, r.Code, r.Body, step.Gesture, step.Note)
				}
				// The recording's own status, where it has one, is what the
				// stub answered; a mismatch is worth knowing about but is not
				// a contract violation, so it is a log and not a failure.
				if q.Status != 0 && q.Status != r.Code {
					t.Logf("the stub answered %d and these handlers answer %d", q.Status, r.Code)
				}
			})
		}
	}

	// The steps really did what they said, which is the half a status code
	// cannot show.
	for _, tc := range []struct {
		what   string
		path   string
		exists bool
	}{
		{"create-folder made a folder", "/dir-0/new-folder", true},
		{"rename renamed a file", "/dir-0/renamed.txt", true},
		{"rename left nothing under the old name", "/dir-0/file-0.txt", false},
		{"copy copied into the target", "/dir-0/dir-2/file-1.txt", true},
		{"copy left the source alone", "/dir-0/file-1.txt", true},
		{"move moved into the target", "/dir-0/dir-1/file-2.txt", true},
		{"move left nothing behind", "/dir-0/file-2.txt", false},
		{"delete deleted", "/dir-0/file-3.txt", false},
		{"upload landed the file", "/dir-0/uploaded.bin", true},
	} {
		if got := g.fix.exists(tc.path); got != tc.exists {
			t.Errorf("%s: exists(%s) = %v, want %v", tc.what, tc.path, got, tc.exists)
		}
	}
	// And no upload temp file survived any of it.
	if left := g.fix.parts("/dir-0"); len(left) != 0 {
		t.Errorf("the replay left %v behind", left)
	}
}

// GET /api/v1/info WITH NO ID IS NOT THIS PACKAGE'S, and the wiring pass has
// to be able to mount both without a ServeMux panic.
//
// The browse server already answers it with the durability panel (phase,
// lease, staged bytes, dirty nodes), which is what the design calls "the
// natural home for the durability counters". This package adds the PER-ID
// form beside it. The two patterns coexist — the exact one wins for the exact
// path, so the subtree route this package registers never turns that request
// into a redirect — and this test is the proof, because the failure mode
// otherwise is a panic at startup in somebody else's file.
func TestInfoWithNoIDBelongsToTheBrowseServer(t *testing.T) {
	g := newGuarded(t)
	for _, rt := range g.fix.api.Routes() {
		if rt.Pattern == "GET /api/v1/info" {
			t.Fatal("this package registers GET /api/v1/info. The browse server already does, " +
				"and two registrations of one pattern is a ServeMux panic at startup.")
		}
	}
	// The browse server's own route, mounted here as a stand-in, on the same
	// router and after ours — the order the wiring pass will use.
	g.router.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/info",
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"phase":"ready"}`))
		})
	if got := g.req(t, http.MethodGet, "/api/v1/info", "", "").want(http.StatusOK); got != `{"phase":"ready"}` {
		t.Errorf("GET /api/v1/info served %q, want the browse server's own answer", got)
	}
	// And the per-id form still reaches this package.
	g.fix.dir(rootIno, "dir-0")
	g.req(t, http.MethodGet, "/api/v1/info/"+id("/dir-0"), "", "").want(http.StatusOK)
}

// replayBody turns a recorded request into a body this test can send. The
// recording holds JSON bodies verbatim; the multipart one is a placeholder
// ("<multipart, 4397 bytes>"), because the recorder deliberately did not keep
// 4 KB of binary in a fixture — so it is rebuilt with the RECORDED BOUNDARY
// and the recorded size, which is what the handler actually parses.
func replayBody(t *testing.T, q recordedRequest) (contentType, body string) {
	t.Helper()
	if q.Body == "" || q.BodyBytes == 0 {
		return "", ""
	}
	if !strings.HasPrefix(q.ContentType, "multipart/form-data") {
		return q.ContentType, q.Body
	}
	boundary := strings.TrimPrefix(q.ContentType[strings.Index(q.ContentType, "boundary="):], "boundary=")
	if boundary == "" {
		t.Fatalf("the recorded multipart content type has no boundary: %q", q.ContentType)
	}
	payload := strings.Repeat("u", 4096)
	body = "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"uploaded.bin\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		payload + "\r\n--" + boundary + "--\r\n"
	return q.ContentType, body
}

// The route SET the recording implies is the route set this package serves.
// The other direction of the same check: nothing recorded is unserved, and
// nothing served is a route the component never asked for.
func TestTheRecordedRoutesAreTheRoutesWeServe(t *testing.T) {
	rec := loadRecording(t)
	g := newGuarded(t)
	stageRecordedTree(g.fix)

	seen := map[string]bool{}
	for _, step := range rec.Steps {
		for _, q := range step.Requests {
			key := q.Method + " " + q.Path
			if q.Query != "" {
				key += "?" + strings.SplitN(strings.TrimPrefix(q.Query, "?"), "=", 2)[0] + "="
			}
			seen[key] = true
		}
	}
	var got []string
	for k := range seen {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{
		"DELETE /api/v1/files",
		"GET /api/v1/files",
		"GET /api/v1/files/%2Fdir-0",
		"GET /api/v1/files/%2Fdir-0%2Fdir-1",
		"GET /api/v1/files/%2Fdir-2",
		"GET /api/v1/info",
		"POST /api/v1/files/%2Fdir-0",
		"POST /api/v1/files/%2Fdir-2",
		"POST /api/v1/upload?id=",
		"PUT /api/v1/files",
		"PUT /api/v1/files/%2Fdir-0%2Ffile-0.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the recorded request set changed — the component's protocol moved.\ngot:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// THE DEFECT THE RECORDING PINS, from this side.
//
// The component's own RestDataProvider drops setHeaders() and sends every
// mutation as text/plain, which is why webui/frontend/src/api/provider.ts
// subclasses it. Replayed against the real guard, those two requests are a
// 401 and a 415 — so this test is the server-side statement of why that
// subclass exists, and it fails the day SVAR fixes the provider (at which
// point the subclass can go).
func TestTheShippedProviderIsRefused(t *testing.T) {
	rec := loadRecording(t)
	g := newGuarded(t)
	stageRecordedTree(g.fix)

	var shipped []recordedRequest
	for _, s := range rec.Steps {
		if s.Step == "as-shipped-provider" {
			shipped = s.Requests
		}
	}
	if len(shipped) == 0 {
		t.Fatal("the recording no longer has an as-shipped-provider step, so nothing pins the defect")
	}
	for _, q := range shipped {
		if q.SessionHeader != "" {
			t.Errorf("the shipped provider now sends a session header (%q). Good news: check whether "+
				"webui/frontend/src/api/provider.ts still needs to override send().", q.SessionHeader)
			continue
		}
		// As sent: no session header at all.
		r := g.req(t, q.Method, q.Path+q.Query, q.ContentType, q.Body,
			httpguard.SessionHeader, "")
		if r.Code != http.StatusUnauthorized {
			t.Errorf("%s %s as the shipped provider sends it = %d, want 401: the session token is "+
				"header-borne by design and the provider drops it", q.Method, q.Path, r.Code)
		}
		if q.Method == http.MethodGet {
			continue
		}
		// And even WITH the credential, its content type is refused: one of
		// the three types an HTML form can send is not a first-party JSON
		// request.
		r = g.req(t, q.Method, q.Path+q.Query, q.ContentType, q.Body)
		if r.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s %s with Content-Type %q = %d, want 415",
				q.Method, q.Path, q.ContentType, r.Code)
		}
		if q.ContentType != "text/plain;charset=UTF-8" {
			t.Logf("the shipped provider's mutating content type is now %q, not text/plain", q.ContentType)
		}
	}
}
