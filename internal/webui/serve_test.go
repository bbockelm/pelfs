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
)

// A real server for the browser suite to point at, and the reason it is a
// test rather than a command.
//
// scripts/webui-playwright.sh prefers `pelfs browse` -- the real binary, a
// real volume, a real federation stub -- because that is the gate worth
// having. But `pelfs browse` is work item U3 and does not exist yet, and a
// harness that cannot run until someone else's milestone lands is a harness
// nobody has proven. So this is the fallback: the embedded bundle, served by
// Go, on an ephemeral loopback port, with the URL printed for the script to
// pick up.
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

	mux := http.NewServeMux()
	mux.Handle("/", Handler())
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
	fmt.Println("pelfs webui: serving the embedded bundle; SIGTERM or SIGINT to stop")
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
