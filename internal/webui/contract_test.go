package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The SVAR file manager's wire protocol, replayed from a recording.
//
// docs/design-webui.md's testing plan, layer 5: "Run the real component
// against a logging stub server once, by hand, on a machine with Node; commit
// the recording as a fixture; and make the Go test replay it against the real
// handlers and assert the responses. That converts a permanent Node
// dependency into a one-time cost plus a committed artifact -- which is the
// same trick internal/hostile/testdata/corpus/ already uses to make bug
// reports that cannot rot."
//
// The recording is produced by `pnpm probe:record` in webui/frontend (work
// item U0) and lives in testdata/svar-contract/recording.json. Until the JSON
// API exists (work item U11) there are no real handlers to replay it against,
// so what these tests pin is the PROTOCOL: the routes a pelfs implementation
// has to answer, the headers it will actually see, and the three behaviours
// that decide whether the component is usable at all. When U11 lands, replay
// belongs here, against these same steps.

type recording struct {
	RecordedAt       string   `json:"recordedAt"`
	Browser          string   `json:"browser"`
	APIBase          string   `json:"apiBase"`
	ExternalRequests []string `json:"externalRequests"`
	Component        map[string]string
	Steps            []struct {
		Step     string `json:"step"`
		Gesture  string `json:"gesture"`
		Note     string `json:"note"`
		Requests []struct {
			Method        string `json:"method"`
			Path          string `json:"path"`
			Query         string `json:"query"`
			ContentType   string `json:"contentType"`
			SessionHeader string `json:"sessionHeader"`
			BodyBytes     int    `json:"bodyBytes"`
			Body          string `json:"body"`
			Status        int    `json:"status"`
		} `json:"requests"`
	} `json:"steps"`
}

func load(t *testing.T) recording {
	t.Helper()
	b, err := os.ReadFile(path.Join("testdata", "svar-contract", "recording.json"))
	if err != nil {
		t.Fatalf("reading the U0 recording: %v\n"+
			"It is committed; regenerate with `pnpm probe:record` in webui/frontend.", err)
	}
	var r recording
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("parsing the U0 recording: %v", err)
	}
	if len(r.Steps) == 0 {
		t.Fatal("the recording has no steps")
	}
	return r
}

func (r recording) step(t *testing.T, name string) (out []struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Query         string `json:"query"`
	ContentType   string `json:"contentType"`
	SessionHeader string `json:"sessionHeader"`
	BodyBytes     int    `json:"bodyBytes"`
	Body          string `json:"body"`
	Status        int    `json:"status"`
}) {
	t.Helper()
	for _, s := range r.Steps {
		if s.Step == name {
			return s.Requests
		}
	}
	t.Fatalf("the recording has no step %q", name)
	return nil
}

// THE QUESTION THAT GATED M4. `GET /files` with no id returns the entire
// tree, and a pelfs volume's scale is millions of entries, so a component
// that wants the whole array up front is unusable here -- full stop.
//
// The recording says it does not: boot fetches the root listing and the drive
// info and nothing else, and each folder navigated into costs exactly one
// listing of exactly that folder.
func TestTheComponentLoadsOneDirectoryAtATime(t *testing.T) {
	r := load(t)

	boot := r.step(t, "boot")
	if len(boot) != 2 {
		t.Fatalf("boot made %d requests, want 2 (the root listing and the drive info): %v", len(boot), boot)
	}
	want := map[string]bool{"/api/v1/files": false, "/api/v1/info": false}
	for _, q := range boot {
		if q.Method != http.MethodGet {
			t.Errorf("boot request %s %s is not a GET", q.Method, q.Path)
		}
		if _, ok := want[q.Path]; !ok {
			t.Errorf("boot fetched %q, which is not part of the boot contract", q.Path)
		}
		want[q.Path] = true
	}
	for p, seen := range want {
		if !seen {
			t.Errorf("boot did not fetch %q", p)
		}
	}

	for _, tc := range []struct{ step, id string }{
		{"open-folder", "/dir-0"},
		{"open-nested-folder", "/dir-0/dir-1"},
	} {
		reqs := r.step(t, tc.step)
		if len(reqs) != 1 {
			t.Fatalf("%s made %d requests, want exactly 1 (a listing of that one folder): %v",
				tc.step, len(reqs), reqs)
		}
		q := reqs[0]
		// The id is the FULL PATH, percent-encoded into a single path
		// segment: /api/v1/files/%2Fdir-0%2Fdir-1.
		wantPath := "/api/v1/files/" + url.PathEscape(tc.id)
		if q.Method != http.MethodGet || q.Path != wantPath {
			t.Errorf("%s sent %s %s, want GET %s", tc.step, q.Method, q.Path, wantPath)
		}
	}

	// A folder the store already has is never re-listed, so a listing is
	// answered once per page load, not once per visit. That is why the
	// breadcrumb refresh button exists and why it is the only other read.
	if reqs := r.step(t, "revisit-loaded-folder"); len(reqs) != 0 {
		t.Errorf("re-opening a loaded folder made %d requests, want 0: %v", len(reqs), reqs)
	}
	if reqs := r.step(t, "refresh"); len(reqs) != 1 {
		t.Errorf("the refresh button made %d requests, want 1: %v", len(reqs), reqs)
	}

	// Search is client-side over what is already loaded. This is the fact
	// that makes the response cap visible to the user: a capped listing is
	// also a partial search, and the UI has to say so rather than implying
	// the whole volume was searched.
	if reqs := r.step(t, "search"); len(reqs) != 0 {
		t.Errorf("typing in the search box made %d requests, want 0 (it filters "+
			"loaded data only): %v", len(reqs), reqs)
	}
}

// The route set U11 has to implement, derived from the component's own
// behaviour rather than from SVAR's unlicensed reference server. If a
// component upgrade changes the protocol, this test says so.
func TestTheRouteContractIsTheOneWeThinkItIs(t *testing.T) {
	r := load(t)

	// Normalise a recorded request to (method, pattern), collapsing the
	// percent-encoded id into {id} so the set is readable.
	id := regexp.MustCompile(`%2F[^/?]*`)
	seen := map[string]bool{}
	for _, s := range r.Steps {
		if s.Step == "as-shipped-provider" {
			continue // the same routes, a different provider; asserted below
		}
		for _, q := range s.Requests {
			p := id.ReplaceAllString(q.Path, "{id}")
			if q.Query != "" {
				p += "?" + strings.SplitN(strings.TrimPrefix(q.Query, "?"), "=", 2)[0] + "={id}"
			}
			seen[q.Method+" "+p] = true
		}
	}
	want := []string{
		"DELETE /api/v1/files",        // batch delete, ids in the BODY
		"GET /api/v1/files",           // the root listing
		"GET /api/v1/files/{id}",      // one directory
		"GET /api/v1/info",            // drive totals
		"POST /api/v1/files/{id}",     // create a file or folder in {id}
		"POST /api/v1/upload?id={id}", // whole-file multipart upload
		"PUT /api/v1/files",           // batch move/copy
		"PUT /api/v1/files/{id}",      // rename
	}
	var got []string
	for k := range seen {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the recorded route set is not the expected one.\ngot:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// What the credential and content-type rules will actually see on the wire.
//
// Both of these are properties of webui/frontend/src/api/provider.ts, not of
// the component: the shipped RestDataProvider drops setHeaders() and sets no
// content type at all. The last step of the recording pins that defect, so
// that a future SVAR release which fixes it shows up here as a failure saying
// "the subclass may be able to go away" rather than silently making it dead
// code.
func TestEveryRequestCarriesTheSessionCredentialAndAHonestContentType(t *testing.T) {
	r := load(t)

	for _, s := range r.Steps {
		if s.Step == "as-shipped-provider" {
			continue
		}
		for _, q := range s.Requests {
			if q.SessionHeader == "" {
				t.Errorf("%s: %s %s carries no X-Pelfs-Session header. The session token is "+
					"header-borne by design (no cookie), so a request without it is a 401.",
					s.Step, q.Method, q.Path)
			}
			if q.Method == http.MethodGet {
				continue
			}
			switch {
			case strings.HasPrefix(q.ContentType, "multipart/form-data"):
				// Only the upload, and only there, may be multipart: it is
				// the one route that must accept a form content type, which
				// is why it needs its own handling in the guard.
				if q.Path != "/api/v1/upload" {
					t.Errorf("%s: %s %s is multipart, but only /api/v1/upload may be", s.Step, q.Method, q.Path)
				}
			case q.ContentType == "application/json":
			default:
				t.Errorf("%s: %s %s has Content-Type %q. The threat model rejects a mutating "+
					"request that is not application/json (a form can send text/plain), so this "+
					"would be a 415.", s.Step, q.Method, q.Path, q.ContentType)
			}
		}
	}

	shipped := r.step(t, "as-shipped-provider")
	if len(shipped) != 2 {
		t.Fatalf("the as-shipped step recorded %d requests, want 2", len(shipped))
	}
	for _, q := range shipped {
		if q.SessionHeader != "" {
			t.Errorf("the shipped RestDataProvider now DOES send the session header (%q) even "+
				"though setHeaders() was called. Good news: check whether "+
				"webui/frontend/src/api/provider.ts still needs to override send().", q.SessionHeader)
		}
	}
	var mutation bool
	for _, q := range shipped {
		if q.Method == http.MethodPost {
			mutation = true
			if q.ContentType != "text/plain;charset=UTF-8" {
				t.Errorf("the shipped RestDataProvider's mutating content type is now %q, not "+
					"text/plain. Re-check whether the PelfsDataProvider override is still needed.",
					q.ContentType)
			}
		}
	}
	if !mutation {
		t.Error("the as-shipped step recorded no mutating request, so it proves nothing")
	}
}

// Upload is ONE multipart POST via fetch: no XMLHttpRequest, no progress
// events, no chunking, no resume. That is the ceiling the design accepts for
// now (resumable upload is deferred to tus + uppy), and it is the reason the
// server must read the body with r.MultipartReader() rather than
// ParseMultipartForm -- a 68 MB SIF must not be buffered to answer a request.
func TestUploadIsOneWholeFileMultipartPost(t *testing.T) {
	r := load(t)
	reqs := r.step(t, "upload")
	if len(reqs) != 1 {
		t.Fatalf("the upload made %d requests, want 1 (whole-file, no chunking): %v", len(reqs), reqs)
	}
	q := reqs[0]
	if q.Method != http.MethodPost || q.Path != "/api/v1/upload" {
		t.Errorf("upload sent %s %s, want POST /api/v1/upload", q.Method, q.Path)
	}
	if !strings.HasPrefix(q.ContentType, "multipart/form-data") {
		t.Errorf("upload content type %q, want multipart/form-data", q.ContentType)
	}
	// The parent directory is a query parameter, not part of the path.
	if !strings.HasPrefix(q.Query, "?id=") {
		t.Errorf("upload query %q, want ?id=<parent>", q.Query)
	}
	if q.BodyBytes < 4096 {
		t.Errorf("upload body was %d bytes for a 4096-byte file; the whole file goes in one request", q.BodyBytes)
	}
}

// The page must load nothing off loopback. The default SVAR theme injects a
// stylesheet link to cdn.svar.dev and its default icon callback builds CDN
// URLs per file extension; with fonts={false} and icons="simple" the measured
// answer is zero external requests, and this pins it.
func TestTheComponentMakesNoRequestsOffLoopback(t *testing.T) {
	r := load(t)
	if len(r.ExternalRequests) != 0 {
		t.Errorf("the recording captured %d request(s) off loopback: %v\n"+
			"Check <Willow fonts={false}> and icons=\"simple\" in webui/frontend/src.",
			len(r.ExternalRequests), r.ExternalRequests)
	}
}

// The routing hazard the recording implies, settled here rather than
// discovered during U11.
//
// The component sends the id as a full path percent-encoded into ONE segment
// (/api/v1/files/%2Fdir-0%2Fdir-1). Go's ServeMux gets this right -- a {id}
// wildcard matches the whole escaped segment and PathValue returns it decoded
// -- but r.URL.Path has already collapsed the %2F, so a handler that splits
// the path by hand sees "/api/v1/files//dir-0/dir-1" and will either mis-route
// or mis-read the id. Use PathValue.
func TestGoServeMuxHandlesPercentEncodedIDs(t *testing.T) {
	var gotID, gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/files/{id}", func(w http.ResponseWriter, r *http.Request) {
		gotID, gotPath = r.PathValue("id"), r.URL.Path
	})
	mux.HandleFunc("GET /api/v1/files", func(w http.ResponseWriter, r *http.Request) {
		gotID, gotPath = "", r.URL.Path
	})

	target := "/api/v1/files/" + url.PathEscape("/dir-0/dir-1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", target, rec.Code)
	}
	if gotID != "/dir-0/dir-1" {
		t.Errorf("PathValue(\"id\") = %q, want %q", gotID, "/dir-0/dir-1")
	}
	if gotPath != "/api/v1/files//dir-0/dir-1" {
		t.Errorf("URL.Path = %q; the point of this test is that it is NOT usable for the id "+
			"(want the collapsed form %q so the hazard stays documented)",
			gotPath, "/api/v1/files//dir-0/dir-1")
	}
	if fmt.Sprint(gotID) == gotPath {
		t.Error("unreachable: the decoded id cannot equal the collapsed path")
	}
}
