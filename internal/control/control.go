// Package control is the session control socket: plain HTTP over a
// Unix-domain socket in the volume state directory (the Docker pattern —
// curl-able, no custom framing), so a running mount can be told to
// publish or explain itself without signals or restarts.
//
// The socket is 0600 inside the per-volume state dir; possession of that
// directory is already possession of the volume's local keys, so the
// filesystem is the auth boundary.
package control

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// SocketName is the socket's file name inside a session state directory.
const SocketName = "control.sock"

// Hooks connect the server to a live session. Nil hooks 404 their
// endpoint (e.g. a read-only mount has no Publish).
type Hooks struct {
	// Status returns small always-cheap session facts.
	Status func() map[string]any
	// StatsJSON returns the current session-statistics document.
	StatsJSON func() ([]byte, error)
	// Publish seals the write overlay into the next generation and
	// returns a summary.
	Publish func(ctx context.Context) (string, error)
	// BugreportExtra contributes additional named files to bug reports
	// (config dumps, lineage info); may be nil.
	BugreportExtra func() map[string][]byte
}

// Server is a running control listener.
type Server struct {
	path string
	ln   net.Listener
	srv  *http.Server
}

// Start listens on stateDir/control.sock. A stale socket from a dead
// session is replaced; a LIVE listener in the same state dir is a
// configuration error surfaced as "address already in use".
func Start(stateDir string, h Hooks) (*Server, error) {
	path := filepath.Join(stateDir, SocketName)
	if _, err := os.Stat(path); err == nil {
		// Probe liveness: connect-refused means a dead session's leftover.
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close() //nolint:errcheck
			return nil, fmt.Errorf("control socket %s is already served by a live session", path)
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w", err)
	}
	// Own the unlink explicitly. By default a unix listener removes its
	// socket file when it closes, asynchronously enough that on Linux the
	// removal can land AFTER a successor has created its own socket at
	// the same path — the successor then chmods a file that no longer
	// exists (seen on Linux under CI). With unlink-on-close off, create
	// and remove are strictly ordered by us: Start creates, Close
	// removes.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	// The socket is the auth boundary, so restrict it before serving. A
	// concurrent process cannot be racing us here: one would have been
	// caught by the liveness probe above, and Listen would have failed
	// for a second live listener.
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close() //nolint:errcheck
		return nil, err
	}
	mux := http.NewServeMux()
	registerRoutes(mux, h)
	s := &Server{path: path, ln: ln, srv: &http.Server{Handler: mux}}
	go s.srv.Serve(ln) //nolint:errcheck
	return s, nil
}

// Close shuts the listener down and removes the socket.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	// We disabled the listener's own unlink, so removing the socket is
	// ours to do — and doing it here, after Shutdown, means the path is
	// free before this call returns.
	_ = os.Remove(s.path)
	return err
}

func registerRoutes(mux *http.ServeMux, h Hooks) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if h.Status == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, h.Status())
	})
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) {
		if h.StatsJSON == nil {
			http.NotFound(w, r)
			return
		}
		b, err := h.StatsJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("POST /v1/publish", func(w http.ResponseWriter, r *http.Request) {
		if h.Publish == nil {
			http.NotFound(w, r)
			return
		}
		summary, err := h.Publish(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"published": true, "summary": summary})
	})
	mux.HandleFunc("GET /v1/bugreport", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=pelfs-bugreport.tar.gz")
		writeBugreport(w, h)
	})
	// Live profiling of a running session: the socket is the auth
	// boundary (0600 in the state dir), so the full pprof surface is
	// safe to expose. `pelfs ctl <target> pprof cpu` fetches profiles;
	// `go tool pprof` can read the saved files.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeBugreport streams a tar.gz of everything a human debugging a
// misbehaving session wants first: status, stats, a full goroutine dump
// (the hung-transfer kit), runtime facts, and any extras the session
// contributes.
func writeBugreport(w http.ResponseWriter, h Hooks) {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := time.Now()
	add := func(name string, data []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), ModTime: now})
		_, _ = tw.Write(data)
	}
	if h.Status != nil {
		b, _ := json.MarshalIndent(h.Status(), "", "  ")
		add("status.json", b)
	}
	if h.StatsJSON != nil {
		if b, err := h.StatsJSON(); err == nil {
			add("stats.json", b)
		}
	}
	buf := make([]byte, 4<<20)
	buf = buf[:runtime.Stack(buf, true)]
	add("goroutines.txt", buf)
	rt, _ := json.MarshalIndent(map[string]any{
		"go":         runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"time":       now.Format(time.RFC3339),
	}, "", "  ")
	add("runtime.json", rt)
	if h.BugreportExtra != nil {
		for name, data := range h.BugreportExtra() {
			add(name, data)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
}

// Client talks to a session's control socket.
type Client struct {
	http http.Client
}

// NewClient dials stateDir/control.sock.
func NewClient(stateDir string) *Client {
	path := filepath.Join(stateDir, SocketName)
	return &Client{http: http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Do issues one control request; the host in the URL is ignored by the
// unix transport.
func (c *Client) Do(ctx context.Context, method, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://pelfs"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w (is the mount running?)", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %s: %s", method, endpoint, resp.Status, string(body))
	}
	return body, nil
}
