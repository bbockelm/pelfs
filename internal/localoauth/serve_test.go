package localoauth_test

// THE SERVER THE REAL-CYBERDUCK GATE DRIVES.
//
// scripts/oauth-cyberduck-docker.sh needs the whole `pelfs browse` HTTP
// surface — the transport guard, the authorization server, the WebDAV
// adapter — inside a container, with a generated profile on disk, and with
// no pelfs command to run: `pelfs browse` belongs to a sibling work item and
// a shipped `cmd/` for a probe server would be a permanent liability. So
// the server is this test, cross-compiled with `go test -c` and run with
// -test.run=TestServeForCyberduckGate. It is skipped unless the environment
// names an address, which is what keeps it out of `go test ./...`.
//
// This is the same shape as internal/vfsdav's TestServeForClientGates, and
// for the same reason.
//
// Environment:
//
//	PELFS_OAUTH_TCP       listen address, e.g. 127.0.0.1:9997 (required)
//	PELFS_OAUTH_CALLBACK  the port to allowlist as Cyberduck's own loopback
//	                      listener (default davprofile.DefaultCallbackPort)
//	PELFS_OAUTH_DIR       where to write the profile, the bookmarks and
//	                      creds.env (default: the working directory)
//	PELFS_OAUTH_RW        if non-empty, the session is writable
//	PELFS_OAUTH_TTL       exit after this duration (default 10m)
//
// It writes the generated files, prints one `ready` line, and serves until
// SIGTERM, SIGINT or the TTL — at which point it prints the refusal
// counters and the credential list, which is what the probe reads to say
// what the client actually did.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"

	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/httpguard"
	"github.com/bbockelm/pelfs/internal/localoauth"
	"github.com/bbockelm/pelfs/internal/vfsdav"
)

func TestServeForCyberduckGate(t *testing.T) {
	addr := os.Getenv("PELFS_OAUTH_TCP")
	if addr == "" {
		t.Skip("no PELFS_OAUTH_TCP: this test is the Cyberduck-gate server, " +
			"driven by scripts/oauth-cyberduck-docker.sh")
	}
	dir := os.Getenv("PELFS_OAUTH_DIR")
	if dir == "" {
		dir = "."
	}
	callback := davprofile.DefaultCallbackPort
	if v := os.Getenv("PELFS_OAUTH_CALLBACK"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("PELFS_OAUTH_CALLBACK: %v", err)
		}
		callback = n
	}
	ttl := 10 * time.Minute
	if v := os.Getenv("PELFS_OAUTH_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("PELFS_OAUTH_TTL: %v", err)
		}
		ttl = d
	}
	writable := os.Getenv("PELFS_OAUTH_RW") != ""

	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	sess := &sessions{live: 1}
	oauth, err := localoauth.New(localoauth.Config{
		Writable: writable,
		Volume:   "pelican://osg-htc.org/user/bbockelman",
		Sessions: sess,
	})
	if err != nil {
		t.Fatalf("localoauth.New: %v", err)
	}
	fs := memfs.New()
	seedGate(t, fs)
	dav, err := vfsdav.New(vfsdav.Config{FS: fs, Prefix: "/dav", Auth: oauth.DAVAuth("pelfs")})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}
	guard := httpguard.New(httpguard.Config{Port: port, Sessions: sess})
	r := guard.NewRouter()
	r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceNavigation, "POST /oauth/authorize", oauth.AuthorizeHandler())
	r.Handle(httpguard.SurfaceToken, "POST /oauth/token", oauth.TokenHandler())
	r.Handle(httpguard.SurfaceExternal, "/dav/", dav)

	client, err := oauth.NewClient(localoauth.ClientRequest{
		Label:       "Cyberduck",
		RedirectURI: davprofile.RedirectURI(callback),
		Write:       writable,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	p := davprofile.Params{
		Port: port, Volume: "pelican://osg-htc.org/user/bbockelman",
		ClientID: client.ID, RedirectURI: client.Redirect, Write: writable,
		BasicUser: client.BasicUser, Label: "Cyberduck",
	}
	for name, gen := range map[string]func(davprofile.Params) ([]byte, error){
		"pelfs.cyberduckprofile": davprofile.Profile,
		"pelfs.duck":             davprofile.Bookmark,
		"pelfs-basic.duck":       davprofile.BasicBookmark,
	} {
		b, err := gen(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// The secrets the probe needs, in a file rather than on the command
	// line: this is a throwaway container, but a credential in argv is a
	// habit worth not having.
	creds := fmt.Sprintf("PELFS_CLIENT_ID=%s\nPELFS_BASIC_USER=%s\nPELFS_BASIC_PASS=%s\n"+
		"PELFS_ORIGIN=%s\nPELFS_REDIRECT=%s\n",
		client.ID, client.BasicUser, client.BasicPassword, guard.Origin(), client.Redirect)
	if err := os.WriteFile(filepath.Join(dir, "creds.env"), []byte(creds), 0o600); err != nil {
		t.Fatalf("write creds.env: %v", err)
	}

	srv := &http.Server{Handler: r, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	fmt.Printf("ready %s\n", guard.Origin())
	fmt.Printf("profile %s\n", filepath.Join(dir, "pelfs.cyberduckprofile"))
	fmt.Printf("mode %s\n", map[bool]string{true: "read-write", false: "read-only"}[writable])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(ttl):
	}
	_ = srv.Close()

	// What the client actually did, which is the whole point of running a
	// real one.
	c := oauth.Counts()
	fmt.Printf("counts replays=%d redirect-mismatch=%d unknown-client=%d "+
		"missing-pkce=%d verifier-mismatch=%d consent-denied=%d ticket-refused=%d "+
		"no-session=%d clamped=%d\n",
		c.CodeReplays, c.RedirectMismatches, c.UnknownClients, c.MissingPKCE,
		c.VerifierMismatches, c.ConsentDenied, c.ConsentTicketsRefused,
		c.NoSession, c.ScopeClamped)
	for _, g := range oauth.Grants() {
		fmt.Printf("grant %s client=%s scopes=%s write=%v last-used=%s\n",
			g.Ref, g.Label, strings.Join(g.Scopes, "+"), g.Write,
			g.LastUsed.Format(time.RFC3339))
	}
	for _, cl := range oauth.Clients() {
		fmt.Printf("client %s label=%s consented=%v grants=%d\n",
			cl.Ref, cl.Label, cl.Consented, cl.Grants)
	}
}

// seedGate is the little fixture tree the probe lists and downloads: one
// file at the root and one in a subdirectory, which is enough to tell a
// working listing from an empty one.
func seedGate(t *testing.T, fs billy.Filesystem) {
	t.Helper()
	for path, content := range map[string]string{
		"hello.txt":      "hello from a pelfs volume\n",
		"sub/nested.txt": "nested\n",
	} {
		if dir := filepath.Dir(path); dir != "." {
			if err := fs.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("seed %s: %v", path, err)
			}
		}
		f, err := fs.Create(path)
		if err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		if _, err := io.WriteString(f, content); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		_ = f.Close()
	}
}
