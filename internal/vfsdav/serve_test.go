package vfsdav_test

import (
	"context"
	"crypto/subtle"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	"github.com/bbockelm/pelfs/internal/vfsdav"
)

// THE HARNESS THE REAL-CLIENT GATES DRIVE.
//
// scripts/webdav-adapter-litmus-docker.sh and scripts/webdav-clients-docker.sh
// need a pelfs WebDAV endpoint inside a container, over a REAL volume, with
// no pelfs command to run: `pelfs browse` belongs to a sibling work item
// (U3) and a shipped `cmd/` for a test server would be a permanent
// liability. So the server is this test, cross-compiled with `go test -c`
// and run with -test.run=TestServeForClientGates. It is skipped unless the
// environment names an address, which is what keeps it out of `go test
// ./...`.
//
// Environment:
//
//	PELFS_DAV_TCP    listen address, e.g. 127.0.0.1:9999
//	PELFS_DAV_UNIX   unix socket path (both may be set; both are served)
//	PELFS_DAV_USER   Basic username (default "pelfs")
//	PELFS_DAV_PASS   Basic password (default "probe-secret")
//	PELFS_DAV_RO     if non-empty, the credential is read-only
//	PELFS_DAV_BEARER also accept this Bearer token (the U7 seam)
//	PELFS_DAV_SEED   if non-empty, seed a fixture tree (see below)
//	PELFS_DAV_BIG    seed a file of this many bytes (0 = none)
//	PELFS_DAV_TTL    exit after this duration (default 20m)
//
// It prints one `ready` line per listener and then serves until SIGTERM,
// SIGINT or the TTL — the same shape as the SFTP probe's server
// (scripts/sftp-clients-docker.sh), whose "ready" line the launcher polls
// for rather than sleeping.
//
// BOTH TRANSPORTS ON PURPOSE. A run over a unix socket is hermetic, and
// docs/design-webui.md names the trap that comes with it: a socket request
// has no meaningful Host header, so it does not exercise the Host allowlist
// the browser-facing guard leans on. A socket-only green run would prove the
// adapter and silently skip the security layer, so the gate runs both ways.
func TestServeForClientGates(t *testing.T) {
	tcpAddr, unixPath := os.Getenv("PELFS_DAV_TCP"), os.Getenv("PELFS_DAV_UNIX")
	if tcpAddr == "" && unixPath == "" {
		t.Skip("no PELFS_DAV_TCP or PELFS_DAV_UNIX: this test is the client-gate " +
			"server, driven by scripts/webdav-*-docker.sh")
	}
	user, pass := env("PELFS_DAV_USER", "pelfs"), env("PELFS_DAV_PASS", "probe-secret")
	ttl, err := time.ParseDuration(env("PELFS_DAV_TTL", "20m"))
	if err != nil {
		t.Fatalf("PELFS_DAV_TTL: %v", err)
	}

	ov := newOverlay(t)
	cred := vfsbilly.ProcessCred()
	if os.Getenv("PELFS_DAV_SEED") != "" {
		seed(t, ov, cred)
	}
	grant := vfsdav.Grant{Subject: "probe", Write: os.Getenv("PELFS_DAV_RO") == ""}
	auth := vfsdav.Auth(vfsdav.Basic("pelfs", user, pass, grant))
	// The Bearer seam, exercised by a real client rather than only by a Go
	// test: rclone has --webdav-bearer-token, so the gate can prove that the
	// path U7's authorization server will plug into accepts a token today.
	// The verifier here is a fixed string, which is all a seam needs to be.
	if tok := os.Getenv("PELFS_DAV_BEARER"); tok != "" {
		auth = vfsdav.AnyOf(vfsdav.Bearer("pelfs", func(got string) (vfsdav.Grant, bool) {
			if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
				return vfsdav.Grant{}, false
			}
			return grant, true
		}), auth)
	}
	h, err := vfsdav.New(vfsdav.Config{
		FS:     vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere),
		Prefix: "/dav",
		Auth:   auth,
		Logger: func(r *http.Request, err error) {
			if err != nil {
				fmt.Printf("dav %s %s: %v\n", r.Method, r.URL.Path, err)
			}
		},
	})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/dav/", h)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}
	for _, l := range listeners(t, tcpAddr, unixPath) {
		go func(l net.Listener) { _ = srv.Serve(l) }(l)
		fmt.Printf("ready %s %s\n", l.Addr().Network(), l.Addr())
	}
	fmt.Printf("credential %s %s\n", user, pass)
	_ = os.Stdout.Sync()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		fmt.Printf("stopping on %v\n", s)
	case <-time.After(ttl):
		fmt.Printf("stopping: PELFS_DAV_TTL (%s) elapsed\n", ttl)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	// The counts are the interesting half of a client run: they say what
	// the clients could NOT have seen, and why.
	fmt.Printf("hidden %+v\n", h.Counts())
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func listeners(t *testing.T, tcpAddr, unixPath string) []net.Listener {
	t.Helper()
	var out []net.Listener
	if tcpAddr != "" {
		// tcp4 for the same reason `pelfs mount` binds tcp4: a client that
		// resolves "localhost" to ::1 and finds nothing listening reports a
		// connection refused that looks like a server bug.
		l, err := net.Listen("tcp4", tcpAddr)
		if err != nil {
			t.Fatalf("listen %s: %v", tcpAddr, err)
		}
		out = append(out, l)
	}
	if unixPath != "" {
		_ = os.Remove(unixPath)
		l, err := net.Listen("unix", unixPath)
		if err != nil {
			t.Fatalf("listen %s: %v", unixPath, err)
		}
		// 0600: the socket is the credential's peer, and every other user on
		// the machine is outside this session (docs/design-webui.md, A8).
		if err := os.Chmod(unixPath, 0o600); err != nil {
			t.Fatalf("chmod %s: %v", unixPath, err)
		}
		out = append(out, l)
	}
	return out
}

// seed writes the tree the client gates look at: a small file, a nested
// directory, a wide directory, the entries WebDAV cannot represent (so the
// clients prove they are hidden rather than broken), and optionally one big
// file — PELFS_DAV_BIG=68497408 is the owner's own SIF size, which is the
// one the Windows redirector refuses and every other client must not.
func seed(t *testing.T, ov interface {
	Create(context.Context, uint64, string, uint32, uint32, uint32) (genfs.Node, error)
	Mkdir(context.Context, uint64, string, uint32, uint32, uint32) (genfs.Node, error)
	Symlink(context.Context, uint64, string, string, uint32, uint32) (genfs.Node, error)
	Mknod(context.Context, uint64, string, uint8, uint32, uint32, uint32, uint32) (genfs.Node, error)
	Write(context.Context, uint64, int64, []byte) (int, error)
}, cred vfsbilly.Cred) {
	t.Helper()
	c := context.Background()
	uid, gid := cred.UID, cred.GID
	write := func(ino uint64, body []byte) {
		for off := 0; off < len(body); {
			n, err := ov.Write(c, ino, int64(off), body[off:])
			if err != nil {
				t.Fatalf("seed write: %v", err)
			}
			off += n
		}
	}
	file := func(parent uint64, name string, body []byte) uint64 {
		n, err := ov.Create(c, parent, name, 0o644, uid, gid)
		if err != nil {
			t.Fatalf("seed create %s: %v", name, err)
		}
		if len(body) > 0 {
			write(n.Inode, body)
		}
		return n.Inode
	}

	root := uint64(genfs.RootInode)
	file(root, "hello.txt", []byte("hello from a pelfs volume\n"))
	dir, err := ov.Mkdir(c, root, "sub", 0o755, uid, gid)
	if err != nil {
		t.Fatalf("seed mkdir: %v", err)
	}
	file(dir.Inode, "nested.txt", []byte("nested\n"))
	wide, err := ov.Mkdir(c, root, "wide", 0o755, uid, gid)
	if err != nil {
		t.Fatalf("seed mkdir wide: %v", err)
	}
	n := 500
	if v, err := strconv.Atoi(os.Getenv("PELFS_DAV_WIDE")); err == nil {
		n = v
	}
	for i := range n {
		file(wide.Inode, "f"+strconv.Itoa(i), nil)
	}
	// The three shapes a client must not see, and one it must.
	if _, err := ov.Symlink(c, root, "link-to-hello", "hello.txt", uid, gid); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}
	if _, err := ov.Symlink(c, root, "link-dangling", "nowhere", uid, gid); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}
	if _, err := ov.Symlink(c, root, "link-to-sub", "sub", uid, gid); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}
	if _, err := ov.Mknod(c, root, "a.fifo", catalog.TypeFIFO, 0o600, uid, gid, 0); err != nil {
		t.Fatalf("seed mknod: %v", err)
	}
	if big, err := strconv.Atoi(os.Getenv("PELFS_DAV_BIG")); err == nil && big > 0 {
		body := make([]byte, big)
		rand.New(rand.NewSource(1)).Read(body)
		ino := file(root, "big.bin", nil)
		write(ino, body)
		fmt.Printf("seeded big.bin %d bytes\n", big)
	}
	fmt.Printf("seeded a volume: hello.txt, sub/nested.txt, wide/ (%d entries), "+
		"3 symlinks, 1 fifo\n", n)
}
