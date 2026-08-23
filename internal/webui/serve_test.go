package webui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
)

// A real server for the browser suite to point at, and the reason it is a
// test rather than a command.
//
// scripts/webui-playwright.sh prefers `pelfs browse` -- the real binary, a
// real volume, a real federation stub -- because that is the gate worth
// having, and since the wiring pass it serves this same bundle at `/`. This is
// the OTHER mode, and it is kept rather than retired because it is the only
// one that can drive the file manager against a volume whose contents the test
// chooses: a 6,000-entry directory for the listing cap, a path that refuses a
// rename, a listing with a known name in it. A real fresh volume has none of
// those and arranging them through the UI would be testing the upload path.
//
// WHAT THIS SERVER MUST KEEP IN COMMON WITH `pelfs browse`, or the suite
// proves the app under rules the product does not use:
//
//   - the same four EXACT routes, so an unregistered path is a 404 in both
//     modes rather than an index.html in one of them;
//   - webui.CSP on the app's responses, which is what the real listener sets
//     (cmd/pelfs/browse.go, appHandler) and what caught the app rendering
//     blank the first time it was mounted for real;
//   - the real internal/browsesession, so the credential flow is not stubbed.
//
// What it deliberately does NOT have is internal/httpguard. The guard's own
// table test owns the threat model, and the cross-origin specs skip in this
// mode and say so.
//
// It is skipped unless PELFS_WEBUI_SERVE=1, so `go test ./...` never starts a
// server. It is a test and not a `main` package so that no shipped binary
// grows a debug listener: this code cannot be reached from cmd/pelfs at all.
func TestServeEmbeddedForBrowserSuite(t *testing.T) {
	if os.Getenv("PELFS_WEBUI_SERVE") != "1" {
		t.Skip("set PELFS_WEBUI_SERVE=1 to serve the embedded UI for the browser suite")
	}

	// tcp4 and 127.0.0.1 explicitly: the suite's Host-header assertions are
	// about a v4 loopback address, and a dual-stack listener answering on
	// [::1] would make them ambiguous.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}

	// The credential lifecycle, for real: the same internal/browsesession the
	// binary uses, so the app's bootstrap-for-session exchange, its
	// header-borne session token and its single-use download tickets are
	// exercised here rather than stubbed. The bootstrap token is printed
	// below for the harness to hand to the suite.
	sessions, err := browsesession.New()
	if err != nil {
		t.Fatalf("minting the session manager: %v", err)
	}

	mux := http.NewServeMux()
	// The same four patterns cmd/pelfs's route table uses, and the same
	// policy, so "it worked in embed mode" means something about browse mode.
	bundle := Handler()
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", CSP)
		bundle.ServeHTTP(w, r)
	})
	mux.Handle("GET /{$}", app)
	mux.Handle("GET /assets/{file}", app)
	mux.Handle("GET /brand/{file}", app)
	mux.Handle("GET /third_party.txt", app)
	// The JSON API, mocked (mockapi_test.go). Work item U11 owns the real
	// one; without a stand-in the app in webui/frontend has nothing to talk
	// to, and the browser suite could only assert that a shell renders.
	newMockAPI(sessions).mount(mux)
	// Echoes the Host header back. This is what makes Chromium's
	// --host-resolver-rules provably a DNS-rebinding simulation rather than a
	// flag somebody passed: a page loaded from http://attacker.test:PORT/
	// sends Host: attacker.test:PORT, and the suite asserts exactly that.
	//
	// internal/httpguard (work item U1) is what will answer 421 to it. This
	// route exists only in the test server, so nothing in a shipped binary
	// reflects a request header back to a caller.
	mux.HandleFunc("/__host", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"host":%q,"origin":%q}`, r.Host, r.Header.Get("Origin"))
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("serving: %v", err)
		}
	}()

	// The line the harness greps for. Printed to stdout, not through t.Log,
	// so it is not buffered until the test ends.
	fmt.Printf("PELFS_WEBUI_URL=http://%s/\n", ln.Addr().String())
	// Single-use, 120 seconds, handed over the same way
	// scripts/webui-playwright.sh hands over `pelfs browse`'s: separately,
	// because the suite has to put it back in the URL FRAGMENT itself.
	fmt.Printf("PELFS_WEBUI_BOOTSTRAP=%s\n", sessions.Bootstrap())
	fmt.Println("pelfs webui: serving the embedded bundle and a mock JSON API; SIGTERM or SIGINT to stop")
	os.Stdout.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// A ceiling, so a harness that dies without signalling cannot leave this
	// running on a CI machine forever.
	timeout := 10 * time.Minute
	if v := os.Getenv("PELFS_WEBUI_SERVE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(timeout):
		t.Logf("no signal within %s; shutting down", timeout)
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
