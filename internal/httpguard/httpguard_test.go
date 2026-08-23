// The threat model as a table.
//
// docs/design-webui.md's testing section asks for exactly this and says
// why it is the highest-value test in the whole design: both HTTP surfaces
// are http.Handlers, so httptest drives them with no browser, no port and
// no network, and every row is a regression somebody could introduce by
// adding a middleware in the wrong order — none of which is visible in a
// manual test.
//
// The rows below are that document's table, in its order, with the row
// name naming the attack rather than the mechanism. Two notes on what
// changed while writing them, both reported back to the doc:
//
//   - The doc calls it "fifteen assertions" and then lists sixteen rows.
//     There are sixteen.
//   - The doc's row "Origin absent on a /api/v1 request → 403" cannot mean
//     "absent" alone: current browsers send NO Origin header on a
//     same-origin GET, so requiring one outright would refuse every read
//     the real page does. What is required is provenance — a matching
//     Origin OR Sec-Fetch-Site: same-origin — and it is the request
//     carrying NEITHER that gets the 403. Both halves are rows here
//     (originAbsentAndNoFetchMetadata, and the same-origin GET that must
//     succeed).
package httpguard_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
	"github.com/bbockelm/pelfs/internal/httpguard"
)

const port = 49731

var (
	goodHost   = "127.0.0.1:49731"
	goodOrigin = "http://127.0.0.1:49731"
	// otherLoopback is a page served by some other local service. By the
	// design's F3 it is same-SITE with us, which is the whole reason
	// CrossOriginProtection is in the chain.
	otherOrigin = "http://127.0.0.1:58080"
)

// fixture is one guarded listener with every surface mounted, plus the
// live session manager behind it.
type fixture struct {
	router   *httpguard.Router
	sessions *browsesession.Manager
	// publishes counts how many times the mutating API route ran, so a row
	// can assert that a refused request did not merely get a bad status
	// but also did nothing.
	publishes int
	davHits   int
}

// source is the M1 stand-in for U11's file surface: one readable path, one
// path the session may not read.
type source struct{}

func (source) Open(_ context.Context, p string) (*browsesession.Content, error) {
	switch p {
	case "/ok.txt":
		return &browsesession.Content{
			Name: "ok.txt", Size: 5, ModTime: time.Unix(0, 0),
			Body: io.NopCloser(strings.NewReader("hello")),
		}, nil
	case "/secret":
		return nil, browsesession.ErrForbidden
	}
	return nil, errors.New("no such thing")
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureAt(t, time.Now)
}

func newFixtureAt(t *testing.T, now func() time.Time) *fixture {
	t.Helper()
	m, err := browsesession.NewAt(now)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{sessions: m}
	g := httpguard.New(httpguard.Config{Port: port, Sessions: m})
	r := g.NewRouter()
	r.HandleFunc(httpguard.SurfaceApp, "GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<!doctype html>the page")
	})
	r.Handle(httpguard.SurfaceExchange, "POST /api/v1/session", browsesession.ExchangeHandler(m))
	r.HandleFunc(httpguard.SurfaceAPI, "GET /api/v1/info", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	r.HandleFunc(httpguard.SurfaceAPI, "POST /api/v1/publish", func(w http.ResponseWriter, _ *http.Request) {
		f.publishes++
		w.WriteHeader(http.StatusAccepted)
	})
	r.HandleFunc(httpguard.SurfaceStream, "GET /events", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: hello\ndata: {}\n\n")
	})
	r.Handle(httpguard.SurfaceTicket, "GET /d/{ticket}", browsesession.DownloadHandler(m, source{}))
	r.HandleFunc(httpguard.SurfaceExternal, "/dav/", func(w http.ResponseWriter, _ *http.Request) {
		f.davHits++
		w.WriteHeader(http.StatusMultiStatus)
	})
	r.HandleFunc(httpguard.SurfaceNavigation, "GET /oauth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "consent screen")
	})
	f.router = r
	return f
}

// session runs the real bootstrap exchange and returns the session token.
func (f *fixture) session(t *testing.T) string {
	t.Helper()
	body := `{"bootstrap":"` + f.sessions.Bootstrap() + `"}`
	rec := f.do(t, f.pageRequest(t, "POST", "/api/v1/session", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var resp browsesession.ExchangeResponse
	decodeJSON(t, rec.Body.Bytes(), &resp)
	if resp.Session == "" {
		t.Fatal("exchange returned no session token")
	}
	if resp.Header != httpguard.SessionHeader {
		t.Fatalf("exchange named header %q, want %q", resp.Header, httpguard.SessionHeader)
	}
	return resp.Session
}

// pageRequest is a request shaped exactly as the real page's fetch makes
// it: our Host, our Origin, and the fetch-metadata headers a browser adds
// and a page cannot forge.
func (f *fixture) pageRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = goodHost
	r.Header.Set("Origin", goodOrigin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// do runs one request and asserts the two properties that must hold on
// EVERY response from EVERY surface, whatever the row is about.
func (f *fixture) do(t *testing.T, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	// Row 15: no CORS, anywhere, ever. The way this protection gets
	// deleted is somebody "fixing CORS", and this is the assertion that
	// makes that a failing test rather than a silent regression.
	for k := range rec.Header() {
		if strings.HasPrefix(strings.ToLower(k), "access-control-") {
			t.Errorf("%s %s: response carries %s: %q — no surface may emit a CORS header",
				r.Method, r.URL.Path, k, rec.Header().Get(k))
		}
	}
	// The no-cookie rule, asserted on every response rather than once:
	// a cookie on 127.0.0.1 is shared with every other local service.
	if v := rec.Header().Values("Set-Cookie"); len(v) > 0 {
		t.Errorf("%s %s: response set a cookie (%q) — this design has no cookies at all",
			r.Method, r.URL.Path, v)
	}
	return rec
}

// TestThreatModelTable is the sixteen-row table.
func TestThreatModelTable(t *testing.T) {
	tests := []struct {
		name string
		// build returns the request, and may use the fixture to mint
		// credentials first.
		build func(t *testing.T, f *fixture) *http.Request
		// advance steps the fixture's clock AFTER the request is built and
		// before it is served, which is how a TTL row expires a credential
		// without sleeping. (internal/lease paid for timing-driven tests
		// once already; nothing here waits on a timer.)
		advance time.Duration
		want    int
		// check is the row's extra assertion, if it has one.
		check func(t *testing.T, f *fixture, rec *httptest.ResponseRecorder)
	}{{
		// 1. The happy path, which has to be a row too: a guard that
		// refuses everything passes every other row in this table.
		name: "1_pageRequestWithSessionSucceeds",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "GET", "/api/v1/info", "")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			return r
		},
		want: 200,
		check: func(t *testing.T, _ *fixture, rec *httptest.ResponseRecorder) {
			// The security headers are part of the happy path, not a
			// separate concern: a 200 that forgot them is a hole.
			for h, want := range map[string]string{
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "no-referrer",
			} {
				if got := rec.Header().Get(h); got != want {
					t.Errorf("%s = %q, want %q", h, got, want)
				}
			}
			if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("CSP %q lacks frame-ancestors 'none'", csp)
			}
		},
	}, {
		// 2. DNS rebinding. The attacker's page is same-origin as far as
		// the browser is concerned; the Host header is the one thing it
		// cannot change, and this is the row that proves we look at it.
		name: "2_dnsRebindingHostIsMisdirected",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "GET", "/api/v1/info", "")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			r.Host = "evil.example.com:49731"
			r.Header.Set("Origin", "http://evil.example.com:49731")
			return r
		},
		want: 421,
		check: func(t *testing.T, _ *fixture, rec *httptest.ResponseRecorder) {
			// The body must not echo the Host back: a rebinding probe
			// should learn nothing, including what we thought it said.
			if b := rec.Body.String(); strings.Contains(b, "evil.example.com") {
				t.Errorf("421 body echoes the Host: %q", b)
			}
		},
	}, {
		// 3. A page on another loopback port, which by F3 is same-SITE.
		name: "3_originFromAnotherLoopbackPort",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "GET", "/api/v1/info", "")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			r.Header.Set("Origin", otherOrigin)
			return r
		},
		want: 403,
	}, {
		// 4. `Origin: null` — a no-referrer form post, a sandboxed frame.
		// Treating null as "absent, therefore fine" would make the header
		// an opt-out.
		name: "4_originNull",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "POST", "/api/v1/publish", "{}")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			r.Header.Set("Origin", "null")
			return r
		},
		want: 403,
		check: func(t *testing.T, f *fixture, _ *httptest.ResponseRecorder) {
			if f.publishes != 0 {
				t.Error("a refused request still published")
			}
		},
	}, {
		// 5. Neither Origin nor Sec-Fetch-Site: the standard library's
		// fail-open case, closed. (This is the doc's "Origin absent" row,
		// read as it has to be read — see the file comment.)
		name: "5_originAbsentAndNoFetchMetadata",
		build: func(t *testing.T, f *fixture) *http.Request {
			tok := f.session(t)
			r := httptest.NewRequest("GET", "/api/v1/info", nil)
			r.Host = goodHost
			r.Header.Set(httpguard.SessionHeader, tok)
			return r
		},
		want: 403,
	}, {
		// 6. Sec-Fetch-Site: same-site, which is exactly what a page on
		// another loopback port looks like even when it sends no Origin.
		name: "6_secFetchSiteSameSite",
		build: func(t *testing.T, f *fixture) *http.Request {
			tok := f.session(t)
			r := httptest.NewRequest("GET", "/api/v1/info", nil)
			r.Host = goodHost
			r.Header.Set("Sec-Fetch-Site", "same-site")
			r.Header.Set(httpguard.SessionHeader, tok)
			return r
		},
		want: 403,
	}, {
		// 7a. No session token at all.
		name: "7a_sessionTokenAbsent",
		build: func(t *testing.T, f *fixture) *http.Request {
			return f.pageRequest(t, "GET", "/api/v1/info", "")
		},
		want: 401,
	}, {
		// 7b. A well-formed token that is not ours: what a token from a
		// PREVIOUS pelfs process looks like. Nothing persists, so a new
		// process shares no secret with an old one even on the same port.
		name: "7b_sessionTokenFromAnotherProcess",
		build: func(t *testing.T, f *fixture) *http.Request {
			other, err := browsesession.New()
			if err != nil {
				t.Fatal(err)
			}
			tok, err := other.Exchange(other.Bootstrap())
			if err != nil {
				t.Fatal(err)
			}
			r := f.pageRequest(t, "GET", "/api/v1/info", "")
			r.Header.Set(httpguard.SessionHeader, tok)
			return r
		},
		want: 401,
	}, {
		// 8. The bootstrap token is single-use, and the first use survives
		// the second attempt (checked below).
		name: "8_bootstrapTokenReused",
		build: func(t *testing.T, f *fixture) *http.Request {
			bt := f.sessions.Bootstrap()
			first := f.session(t) // spends it
			t.Cleanup(func() {
				if !f.sessions.ValidSession(first) {
					t.Error("the first exchange's session died with the replay")
				}
			})
			return f.pageRequest(t, "POST", "/api/v1/session", `{"bootstrap":"`+bt+`"}`)
		},
		want: 401,
	}, {
		// 9. Past the 120-second TTL. The clock is driven, not slept on.
		name: "9_bootstrapTokenPastTTL",
		build: func(t *testing.T, f *fixture) *http.Request {
			return f.pageRequest(t, "POST", "/api/v1/session",
				`{"bootstrap":"`+f.sessions.Bootstrap()+`"}`)
		},
		advance: browsesession.BootstrapTTL + time.Second,
		want:    401,
	}, {
		// 10. The browser session does not reach the external surface.
		name: "10_sessionTokenAtDav",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := httptest.NewRequest("PROPFIND", "/dav/", nil)
			r.Host = goodHost
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			return r
		},
		want: 401,
		check: func(t *testing.T, f *fixture, _ *httptest.ResponseRecorder) {
			if f.davHits != 0 {
				t.Error("the DAV handler ran for a session-token request")
			}
		},
	}, {
		// 11. And the external principal's credential does not reach the
		// API, even when it is well-formed. Refused on the header's
		// PRESENCE, so no handler can be written that accepts either.
		name: "11_basicCredentialAtAPI",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "GET", "/api/v1/info", "")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			r.Header.Set("Authorization", "Basic cGVsZnM6c2VjcmV0")
			return r
		},
		want: 401,
	}, {
		// 12. A download ticket is single-use. The URL that lands in the
		// browser's download history is already spent.
		name: "12_downloadTicketReused",
		build: func(t *testing.T, f *fixture) *http.Request {
			tk, err := f.sessions.MintTicket("/ok.txt")
			if err != nil {
				t.Fatal(err)
			}
			first := f.do(t, plainGet(t, "/d/"+tk))
			if first.Code != 200 || first.Body.String() != "hello" {
				t.Fatalf("first redemption: %d %q", first.Code, first.Body.String())
			}
			if cd := first.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
				t.Errorf("Content-Disposition = %q, want attachment", cd)
			}
			if ct := first.Header().Get("Content-Type"); ct != "application/octet-stream" {
				t.Errorf("Content-Type = %q, want application/octet-stream", ct)
			}
			return plainGet(t, "/d/"+tk)
		},
		want: 404,
	}, {
		// 13. A ticket for a path the session may not read. The check is
		// the Source's, because it is the only thing that knows the
		// permission model — but the STATUS is the guard's contract, and
		// 403 rather than 404 is deliberate: "you cannot" and "there is
		// nothing" are different answers.
		name: "13_downloadTicketForbiddenPath",
		build: func(t *testing.T, f *fixture) *http.Request {
			tk, err := f.sessions.MintTicket("/secret")
			if err != nil {
				t.Fatal(err)
			}
			return plainGet(t, "/d/"+tk)
		},
		want: 403,
	}, {
		// 14. pprof is never routed here. net/http/pprof's init registers
		// on http.DefaultServeMux and internal/control imports it, so this
		// BINARY has those routes — the point is that this listener does
		// not, and that the 404 is Host-validated like everything else.
		name: "14_pprofNotRouted",
		build: func(t *testing.T, f *fixture) *http.Request {
			return plainGet(t, "/debug/pprof/heap")
		},
		want: 404,
	}, {
		// 15 is asserted on every row; see fixture.do.
		//
		// 16. A mutating route reached with a body type that would not
		// have triggered a preflight.
		name: "16_mutatingWithTextPlain",
		build: func(t *testing.T, f *fixture) *http.Request {
			r := f.pageRequest(t, "POST", "/api/v1/publish", "{}")
			r.Header.Set(httpguard.SessionHeader, f.session(t))
			r.Header.Set("Content-Type", "text/plain")
			return r
		},
		want: 415,
		check: func(t *testing.T, f *fixture, _ *httptest.ResponseRecorder) {
			if f.publishes != 0 {
				t.Error("a 415 still published")
			}
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every row runs on a driven clock, so the one row that needs
			// to expire something is not a special case.
			now := time.Now()
			f := newFixtureAt(t, func() time.Time { return now })
			req := tc.build(t, f)
			now = now.Add(tc.advance)
			rec := f.do(t, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.check != nil {
				tc.check(t, f, rec)
			}
		})
	}
}

// plainGet is a request with nothing but a correct Host: what a top-level
// navigation or an <a href> download looks like.
func plainGet(t *testing.T, target string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	r.Host = goodHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// TestSameOriginGetWithoutOriginHeader is the other half of row 5, and it
// is the row that would have caught the doc's mistake: browsers send no
// Origin on a same-origin GET, so if the guard required the header the
// real page could not read anything.
func TestSameOriginGetWithoutOriginHeader(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	r := httptest.NewRequest("GET", "/api/v1/info", nil)
	r.Host = goodHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.Header.Set(httpguard.SessionHeader, tok)
	if rec := f.do(t, r); rec.Code != 200 {
		t.Fatalf("got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

// TestAppShellIsReachableFromAPastedURL: a top-level navigation from the
// address bar carries `Sec-Fetch-Site: none` and no Origin. The terminal
// prints that URL, so if this row fails the whole verb is unusable.
func TestAppShellIsReachableFromAPastedURL(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = goodHost
	r.Header.Set("Sec-Fetch-Site", "none")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	rec := f.do(t, r)
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "the page") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestLocalhostHostIsAllowed: a user who types localhost instead of the
// literal address gets the page, not a 421. The URL pelfs prints is the
// literal, because the listener is tcp4-only and localhost can resolve to
// ::1 — but a name that DOES reach us must not be refused.
func TestLocalhostHostIsAllowed(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "localhost:49731"
	r.Header.Set("Sec-Fetch-Site", "none")
	if rec := f.do(t, r); rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

// TestOriginMustMatchItsOwnHost: 127.0.0.1 and localhost are different
// origins, so a page from one may not call the other even though both
// Hosts are on the allowlist.
func TestOriginMustMatchItsOwnHost(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	r := httptest.NewRequest("GET", "/api/v1/info", nil)
	r.Host = "localhost:49731"
	r.Header.Set("Origin", goodOrigin) // 127.0.0.1, not localhost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set(httpguard.SessionHeader, tok)
	if rec := f.do(t, r); rec.Code != 403 {
		t.Fatalf("got %d, want 403", rec.Code)
	}
}

// TestHostWithoutPortIsRefused: the allowlist is exact strings, so a bare
// hostname (an HTTP/1.0 client, or a proxy that rewrote it) is refused
// rather than parsed.
func TestHostWithoutPortIsRefused(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{"127.0.0.1", "localhost", "", "127.0.0.1:49731.", "127.0.0.1:49732"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		r.Header.Set("Sec-Fetch-Site", "none")
		if rec := f.do(t, r); rec.Code != 421 {
			t.Errorf("Host %q: got %d, want 421", host, rec.Code)
		}
	}
}

// TestIncomingCookieNeverReachesAHandler. We set no cookies, but another
// service on 127.0.0.1 does, and the browser sends those here. A handler
// that could see one could be written to trust one.
func TestIncomingCookieNeverReachesAHandler(t *testing.T) {
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	g := httpguard.New(httpguard.Config{Port: port, Sessions: m})
	var saw string
	h := g.Handler(httpguard.SurfaceApp, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("Cookie")
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = goodHost
	r.Header.Set("Cookie", "jupyter_session=deadbeef")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if saw != "" {
		t.Fatalf("handler saw Cookie: %q", saw)
	}
}

// TestSetCookieIsStripped: the belt to the braces. A handler that sets one
// is a bug, and the wrapper makes it a harmless one.
func TestSetCookieIsStripped(t *testing.T) {
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	g := httpguard.New(httpguard.Config{Port: port, Sessions: m})
	h := g.Handler(httpguard.SurfaceApp, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "pelfs", Value: "nope"})
		_, _ = io.WriteString(w, "ok")
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = goodHost
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
		t.Fatalf("Set-Cookie survived: %q", v)
	}
}

// TestSafeMethodCannotPublish: CrossOriginProtection always allows GET,
// HEAD and OPTIONS, so the only defence against a state change on a safe
// method is not routing one. A cross-origin <img src> at the publish route
// must find nothing to run.
func TestSafeMethodCannotPublish(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		r := httptest.NewRequest(method, "/api/v1/publish", nil)
		r.Host = goodHost
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set(httpguard.SessionHeader, tok)
		rec := f.do(t, r)
		if rec.Code == 200 || rec.Code == 202 {
			t.Errorf("%s /api/v1/publish: got %d, want a refusal", method, rec.Code)
		}
	}
	if f.publishes != 0 {
		t.Errorf("a safe method published %d times", f.publishes)
	}
}

// TestStreamTakesItsTokenFromTheQuery: EventSource cannot set a header, so
// the SSE surface is the one place the token appears in a URL. It is still
// the same credential and the same provenance rules.
func TestStreamTakesItsTokenFromTheQuery(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	ok := httptest.NewRequest("GET", "/events?s="+tok, nil)
	ok.Host = goodHost
	ok.Header.Set("Sec-Fetch-Site", "same-origin")
	if rec := f.do(t, ok); rec.Code != 200 {
		t.Fatalf("with token: got %d, want 200", rec.Code)
	}
	bad := httptest.NewRequest("GET", "/events?s=wrong", nil)
	bad.Host = goodHost
	bad.Header.Set("Sec-Fetch-Site", "same-origin")
	if rec := f.do(t, bad); rec.Code != 401 {
		t.Fatalf("with a wrong token: got %d, want 401", rec.Code)
	}
}

// TestTicketSurfaceIgnoresASessionHeader: the download route must not be
// reachable BY the session token, and must not be broken by one either —
// the guard strips it, so the ticket is the only authority in play.
func TestTicketSurfaceIgnoresASessionHeader(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	tk, err := f.sessions.MintTicket("/ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	r := plainGet(t, "/d/"+tk)
	r.Header.Set(httpguard.SessionHeader, tok)
	rec := f.do(t, r)
	if rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	// And with no credential at all, which is how a real <a href> arrives.
	tk2, err := f.sessions.MintTicket("/ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if rec := f.do(t, plainGet(t, "/d/"+tk2)); rec.Code != 200 {
		t.Fatalf("bare navigation: got %d, want 200", rec.Code)
	}
}

// TestNavigationSurfaceNeedsNoCustomHeader is A7 control 7 as a test:
// /oauth/authorize is reached by a navigation Cyberduck triggers, so it
// cannot require the session header. Its controls are elsewhere, and a
// later maintainer "making it consistent" with the API routes should have
// to change this test to do it.
func TestNavigationSurfaceNeedsNoCustomHeader(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("GET", "/oauth/authorize?client_id=x", nil)
	r.Host = goodHost
	r.Header.Set("Sec-Fetch-Site", "none")
	if rec := f.do(t, r); rec.Code != 200 {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

// TestExternalSurfaceKeepsItsOwnCredential: the DAV surface accepts an
// Authorization header (its own principal) and is not gated on ours.
func TestExternalSurfaceKeepsItsOwnCredential(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("PROPFIND", "/dav/", nil)
	r.Host = goodHost
	r.Header.Set("Authorization", "Basic cGVsZnM6c2VjcmV0")
	if rec := f.do(t, r); rec.Code != http.StatusMultiStatus {
		t.Fatalf("got %d, want 207", rec.Code)
	}
	if f.davHits != 1 {
		t.Errorf("dav handler ran %d times", f.davHits)
	}
}

// TestAPIBodyIsCapped: an unbounded reader on a localhost listener is a
// way to spend our memory from a page that cannot read a single response
// byte.
func TestAPIBodyIsCapped(t *testing.T) {
	f := newFixture(t)
	tok := f.session(t)
	var got int64
	g := httpguard.New(httpguard.Config{Port: port, Sessions: f.sessions})
	h := g.Handler(httpguard.SurfaceAPI, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		got = n
		if err == nil {
			t.Error("an oversized body was accepted whole")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	body := strings.NewReader(strings.Repeat("a", httpguard.APIBodyLimit+4096))
	r := httptest.NewRequest("POST", "/api/v1/publish", body)
	r.Host = goodHost
	r.Header.Set("Origin", goodOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(httpguard.SessionHeader, tok)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if got > httpguard.APIBodyLimit {
		t.Fatalf("read %d bytes, cap is %d", got, httpguard.APIBodyLimit)
	}
}

func decodeJSON(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
}
