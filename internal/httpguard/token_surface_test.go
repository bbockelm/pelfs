package httpguard_test

// SurfaceToken's own rows, in a file of their own so the sixteen-row table
// in httpguard_test.go stays the table the design describes.
//
// The surface exists because the OAuth token endpoint (U7) is a
// back-channel POST from a program that is not a browser and is not our
// page — Cyberduck's Apache HttpClient — and the two surfaces the design
// pencilled it in on (SurfaceExchange) refuse exactly that shape of
// request. Each row below is either "what a non-browser POST must be
// allowed to do" or "what this surface still refuses anyway".

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/httpguard"
)

// tokenGuard is a listener with the token endpoint mounted, plus the same
// handler on SurfaceExchange so the two can be compared in one test.
func tokenGuard(t *testing.T) (*httpguard.Router, string) {
	t.Helper()
	g := httpguard.New(httpguard.Config{Port: 49731, Sessions: nil})
	r := g.NewRouter()
	served := func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("grant_type=" + req.PostFormValue("grant_type")))
	}
	r.HandleFunc(httpguard.SurfaceToken, "POST /oauth/token", served)
	r.HandleFunc(httpguard.SurfaceExchange, "POST /oauth/token-on-exchange", served)
	return r, "127.0.0.1:49731"
}

// cyberduck is the shape of the request google-oauth-client sends from
// inside Cyberduck: form-encoded, no Origin, no Sec-Fetch-Site, no cookie,
// no custom header.
func cyberduck(host, path string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://"+host+path,
		strings.NewReader("grant_type=refresh_token&refresh_token=x&client_id=y"))
	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestSurfaceTokenServesANonBrowserPost(t *testing.T) {
	r, host := tokenGuard(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, cyberduck(host, "/oauth/token"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: a token endpoint that refuses a "+
			"back-channel POST is a token endpoint no client can use\n%s",
			w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "grant_type=refresh_token" {
		t.Errorf("the form body did not reach the handler: %q", got)
	}
}

func TestSurfaceExchangeCannotServeTheTokenEndpoint(t *testing.T) {
	// The design correction, pinned here as well as in
	// internal/localoauth's integration test, because this is the file a
	// maintainer reads when deciding which surface a route belongs on.
	r, host := tokenGuard(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, cyberduck(host, "/oauth/token-on-exchange"))
	if w.Code == http.StatusOK {
		t.Fatal("SurfaceExchange served a non-browser POST; the surfaces have changed")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 (no provenance signal)", w.Code)
	}
}

func TestSurfaceTokenStillRefusesWhatEveryOtherSurfaceRefuses(t *testing.T) {
	r, host := tokenGuard(t)
	for _, tc := range []struct {
		name string
		mut  func(*http.Request)
		want int
	}{
		{"a rebound Host", func(req *http.Request) {
			req.Host = "evil.example.com"
		}, http.StatusMisdirectedRequest},
		{"a cross-site form POST (another loopback port is same-SITE)", func(req *http.Request) {
			req.Header.Set("Sec-Fetch-Site", "same-site")
			req.Header.Set("Origin", "http://127.0.0.1:1")
		}, http.StatusForbidden},
		{"a cross-site POST from a real page", func(req *http.Request) {
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Origin", "https://evil.example")
		}, http.StatusForbidden},
		{"an Origin that is not ours", func(req *http.Request) {
			req.Header.Set("Origin", "http://127.0.0.1:1")
		}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := cyberduck(host, "/oauth/token")
			tc.mut(req)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Errorf("status %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestSurfaceTokenCarriesTheStandardHeadersAndNoCookie(t *testing.T) {
	r, host := tokenGuard(t)
	req := cyberduck(host, "/oauth/token")
	// Another local service's cookie for 127.0.0.1 arrives here whether we
	// like it or not (RFC 6265bis §8.5); it must not reach the handler.
	req.Header.Set("Cookie", "session=from-some-other-local-service")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	// RFC 6749 §5.1 requires no-store on a token response; the guard sets
	// it on every response, so the endpoint gets it for free.
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", got)
	}
	if got := w.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("Set-Cookie %q", got)
	}
	for k := range w.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-allow") {
			t.Errorf("the token endpoint carries %s", k)
		}
	}
}

func TestSurfaceTokenString(t *testing.T) {
	if got := httpguard.SurfaceToken.String(); got != "token" {
		t.Errorf("String() = %q", got)
	}
}
