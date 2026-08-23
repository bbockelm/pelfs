package webapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// The API mounted where it will really be mounted: behind internal/httpguard,
// on the surfaces Routes names.
//
// The handler tests reach the handlers directly, which is what makes them
// readable; this one exists so that "the JSON surface requires the session
// header on every request including GET" and "the upload surface takes
// multipart and no body cap" are properties of THIS package's route table and
// not only of the guard's own table test.
type guarded struct {
	t       *testing.T
	fix     *fix
	router  *httpguard.Router
	session string
	host    string
}

type stubSessions struct{ token string }

func (s stubSessions) ValidSession(tok string) bool {
	return tok != "" && httpguard.ConstantTimeEqual(tok, s.token)
}

func newGuarded(t *testing.T) *guarded {
	t.Helper()
	f := newFix(t)
	const port = 49731
	const session = "a-session-token-of-the-usual-length-000"
	g := httpguard.New(httpguard.Config{Port: port, Sessions: stubSessions{session}})
	r := g.NewRouter()
	f.api.Register(r)
	return &guarded{t: t, fix: f, router: r, session: session, host: "127.0.0.1:49731"}
}

// req issues one request with whatever headers the row wants. The provenance
// header is what a same-origin browser fetch really sends, so it is the
// default and a row that wants it missing says so.
//
// The Host is a REQUEST FIELD and not a header in net/http, which is exactly
// the confusion a DNS-rebinding test has to get right: setting
// Header["Host"] changes nothing the server reads.
func (g *guarded) req(t *testing.T, method, target, contentType, body string, hdr ...string) *resp {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	req.Host = g.host
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set(httpguard.SessionHeader, g.session)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
			continue
		}
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	g.router.ServeHTTP(rec, req)
	res := rec.Result()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read %s %s: %v", method, target, err)
	}
	_ = res.Body.Close()
	return &resp{t: t, Code: res.StatusCode, Body: string(out), Hdr: res.Header}
}

func TestTheGuardedSurface(t *testing.T) {
	g := newGuarded(t)
	g.fix.dir(rootIno, "dir-0")
	g.fix.text(rootIno, "a.txt", "A")
	body, ct := multipartBody(t, webapi.UploadField, [][2]string{{"up.bin", "x"}})

	for _, tc := range []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		hdr         []string
		status      int
	}{
		{
			name: "a listing with the session header", method: http.MethodGet,
			target: "/api/v1/files", status: http.StatusOK,
		},
		{
			// The credential is required on GET too. CrossOriginProtection
			// always allows the safe methods, so this is the check that
			// closes that gap for reads.
			name: "a listing with no session header", method: http.MethodGet,
			target: "/api/v1/files", hdr: []string{httpguard.SessionHeader, ""},
			status: http.StatusUnauthorized,
		},
		{
			name: "a listing with no provenance at all", method: http.MethodGet,
			target: "/api/v1/files", hdr: []string{"Sec-Fetch-Site", ""},
			status: http.StatusForbidden,
		},
		{
			name: "a listing addressed to somebody else's Host", method: http.MethodGet,
			target: "/api/v1/files", hdr: []string{"Host", "evil.example.com"},
			status: http.StatusMisdirectedRequest,
		},
		{
			name: "a mutation as JSON", method: http.MethodPost,
			target: "/api/v1/files/" + id("/dir-0"), contentType: "application/json",
			body: `{"name":"made","type":"folder"}`, status: http.StatusOK,
		},
		{
			// text/plain is what the SHIPPED RestDataProvider sends, and it
			// is one of the three types a plain HTML form can send: accepting
			// it would give up the content-type half of the CSRF defence.
			name: "a mutation as text/plain", method: http.MethodPost,
			target: "/api/v1/files/" + id("/dir-0"), contentType: "text/plain;charset=UTF-8",
			body: `{"name":"sneaky","type":"folder"}`, status: http.StatusUnsupportedMediaType,
		},
		{
			name: "a mutation carrying the WebDAV principal's credential", method: http.MethodDelete,
			target: "/api/v1/files", contentType: "application/json", body: `{"ids":["/a.txt"]}`,
			hdr: []string{"Authorization", "Basic cGVsZnM6cGVsZnM="}, status: http.StatusUnauthorized,
		},
		{
			name: "an upload, which is multipart and not JSON", method: http.MethodPost,
			target: "/api/v1/upload?id=" + id("/dir-0"), contentType: ct, body: body,
			status: http.StatusOK,
		},
		{
			// multipart/form-data IS CORS-safelisted, so on the upload
			// surface the session header is the ONLY preflight trigger.
			// Weakening it there would open the one route with no body cap.
			name: "an upload with no session header", method: http.MethodPost,
			target: "/api/v1/upload?id=" + id("/dir-0"), contentType: ct, body: body,
			hdr: []string{httpguard.SessionHeader, ""}, status: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := g.req(t, tc.method, tc.target, tc.contentType, tc.body, tc.hdr...)
			r.want(tc.status)
			// No surface here may ever emit a CORS header or a cookie.
			for _, banned := range []string{
				"Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
				"Access-Control-Allow-Headers", "Set-Cookie",
			} {
				if v := r.Hdr.Get(banned); v != "" {
					t.Errorf("the response carries %s: %q", banned, v)
				}
			}
		})
	}
}

// The body cap is the guard's, and it applies to the JSON routes and not to
// the upload: a batch of a million ids is a request this surface should
// refuse, and a 68 MB file is one it must not.
func TestTheJSONRoutesAreCappedAndTheUploadIsNot(t *testing.T) {
	g := newGuarded(t)
	g.fix.dir(rootIno, "dir-0")

	huge := `{"ids":["` + strings.Repeat("/a/very/long/path/that/goes/on", 60_000) + `"]}`
	if len(huge) <= httpguard.APIBodyLimit {
		t.Fatalf("the test body is %d bytes, which is under the %d-byte cap it is meant to exceed",
			len(huge), httpguard.APIBodyLimit)
	}
	r := g.req(t, http.MethodDelete, "/api/v1/files", "application/json", huge)
	if r.Code == http.StatusOK {
		t.Errorf("a %d-byte JSON body was accepted; the guard caps this surface at %d",
			len(huge), httpguard.APIBodyLimit)
	}

	// And the same size as an upload is fine, because the cap is the point of
	// failure on a large file.
	body, ct := multipartBody(t, webapi.UploadField,
		[][2]string{{"big-enough.bin", strings.Repeat("x", httpguard.APIBodyLimit+1)}})
	g.req(t, http.MethodPost, "/api/v1/upload?id="+id("/dir-0"), ct, body).want(http.StatusOK)
	if got := g.fix.read("/dir-0/big-enough.bin"); len(got) != httpguard.APIBodyLimit+1 {
		t.Errorf("the upload landed %d bytes, want %d", len(got), httpguard.APIBodyLimit+1)
	}
}
