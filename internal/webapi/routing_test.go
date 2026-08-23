package webapi_test

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// The route table, pinned. A route that appears or disappears here is a
// protocol change and has to be a deliberate one; the surface beside it is
// the principal, and getting THAT wrong is how a credentialed route becomes
// an uncredentialed one.
func TestRouteTable(t *testing.T) {
	api, err := webapi.New(webapi.Config{Volume: webapi.Static(nil)})
	if err != nil {
		t.Fatalf("webapi.New: %v", err)
	}
	var got []string
	for _, rt := range api.Routes() {
		got = append(got, rt.Surface.String()+" "+rt.Pattern)
	}
	sort.Strings(got)
	want := []string{
		"api DELETE /api/v1/files",
		"api GET /api/v1/files",
		"api GET /api/v1/files/{id...}",
		"api GET /api/v1/files/{id}",
		"api GET /api/v1/info/{id...}",
		"api GET /api/v1/info/{id}",
		"api POST /api/v1/files/{id...}",
		"api POST /api/v1/files/{id}",
		"api PUT /api/v1/files",
		"api PUT /api/v1/files/{id...}",
		"api PUT /api/v1/files/{id}",
		"upload POST /api/v1/upload",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the route table changed.\ngot:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// Exactly one route may be on the upload surface: it is the one with no
	// body cap, and a second route sharing that property would be a second
	// place a page could spend our memory.
	uploads := 0
	for _, rt := range api.Routes() {
		if rt.Surface == httpguard.SurfaceUpload {
			uploads++
		}
	}
	if uploads != 1 {
		t.Errorf("%d routes are on the upload surface, want exactly 1", uploads)
	}
}

// THE HOLE IN net/http's {id} WILDCARD, and the sibling route that closes it.
//
// This was found by probing net/http rather than by reading it, and it is
// pinned here because both halves can change under us: if a future Go makes
// {id} match a bare "%2F", the first half fails and the {id...} sibling
// becomes redundant; if the sibling is ever removed, the second half fails
// and "create a folder in the root" 404s.
func TestTheRootAsAnIDNeedsTheMultiSegmentSibling(t *testing.T) {
	// Half one: plain net/http, with only the {id} form registered.
	bare := http.NewServeMux()
	bare.HandleFunc("GET /x/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("id=" + r.PathValue("id")))
	})
	for _, tc := range []struct {
		target, want string
		code         int
	}{
		{"/x/%2Fdir-0", "id=/dir-0", http.StatusOK},
		{"/x/%2Fdir-0%2Fdir-1", "id=/dir-0/dir-1", http.StatusOK},
		// PathValue decodes exactly ONE layer, which is what makes a
		// filename containing the literal characters "%2F" survive.
		{"/x/%2Fa%252Fb", "id=/a%2Fb", http.StatusOK},
		// And the hole: the volume root, alone, matches nothing.
		{"/x/%2F", "", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		bare.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.target, nil))
		if rec.Code != tc.code {
			t.Errorf("net/http: GET %s = %d, want %d", tc.target, rec.Code, tc.code)
		}
		if tc.code == http.StatusOK && rec.Body.String() != tc.want {
			t.Errorf("net/http: GET %s gave %q, want %q", tc.target, rec.Body.String(), tc.want)
		}
	}

	// Half two: our table answers all four, because of the {id...} sibling.
	f := newFix(t)
	f.dir(rootIno, "dir-0")
	if got := f.get("/api/v1/files/" + id("/")).want(http.StatusOK); !strings.Contains(got, "/dir-0") {
		t.Errorf("GET /api/v1/files/%%2F (the root as an id) gave %s", got)
	}
	// The gesture that would really hit it: "Add new folder" in the root.
	r := f.do(http.MethodPost, "/api/v1/files/"+id("/"),
		jsonBody(t, map[string]string{"name": "made-at-root", "type": "folder"}))
	if got := r.result().ID; got != "/made-at-root" {
		t.Fatalf("creating a folder in the root gave id %q, want /made-at-root (body %s)", got, r.Body)
	}
	if !f.exists("/made-at-root") {
		t.Error("the folder was reported created and is not there")
	}
}

// r.URL.Path is unusable for an id and the code must never reach for it. The
// collapsed form is asserted rather than merely avoided, so the hazard stays
// documented where somebody would otherwise re-introduce it.
func TestURLPathCollapsesTheEscapedSlash(t *testing.T) {
	var fromPathValue, fromURLPath string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x/{id}", func(w http.ResponseWriter, r *http.Request) {
		fromPathValue, fromURLPath = r.PathValue("id"), r.URL.Path
	})
	mux.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/x/"+id("/dir-0/dir-1"), nil))
	if fromPathValue != "/dir-0/dir-1" {
		t.Errorf("PathValue = %q, want /dir-0/dir-1", fromPathValue)
	}
	if fromURLPath != "/x//dir-0/dir-1" {
		t.Errorf("URL.Path = %q; the point is that it is NOT the id (want the collapsed %q)",
			fromURLPath, "/x//dir-0/dir-1")
	}
}
