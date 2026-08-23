package vfsdav_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	"github.com/bbockelm/pelfs/internal/vfsdav"
)

// The fixture is a REAL volume — signed superblock, real packs, a write
// overlay — behind the real billy adapter, because the point of these tests
// is what a WebDAV client sees of a pelfs volume and a memFS would answer
// none of it.
//
// The mount identity is the process's own (vfsbilly.ProcessCred), which is
// what makes the volume root writable: publish.InitVolume stamps the root
// with the uid that created it, and a fixture mounted as anybody else is a
// volume whose root directory it may not write. Entries testvol creates are
// stamped uid 0 / gid 0 instead, so a test that needs a file the MOUNT owns
// creates it through the adapter.

const (
	davUser = "pelfs"
	davPass = "correct-horse-battery-staple"
)

func newInner(t testing.TB) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner
}

// newOverlay is a fresh volume's write overlay.
func newOverlay(t testing.TB) *overlay.FS {
	t.Helper()
	return testvol.New(t, newInner(t), testvol.Options{}).Overlay()
}

// newBilly is the binding a frontend with a real open must use. Passing
// vfsbilly.New here instead would inherit NFS's owner override, and
// TestAPutCannotTruncateAReadOnlyFile is what notices.
func newBilly(t testing.TB) billy.Filesystem {
	t.Helper()
	return vfsbilly.NewFor(newOverlay(t), vfsbilly.ProcessCred(), vfsbilly.OpenAnsweredHere)
}

// newServer puts a handler behind a real HTTP server: these tests go over
// the wire on purpose, because half of what is being asserted (statuses,
// headers, Range) is the server's rendering of what the adapter returned.
func newServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// dav is one WebDAV surface under test: the handler, a server in front of
// it, and the credential.
type dav struct {
	t   *testing.T
	h   *vfsdav.Handler
	srv *httptest.Server
	fs  billy.Filesystem
}

func newDav(t *testing.T) *dav { return newDavWith(t, newBilly(t), vfsdav.Grant{Write: true}) }

func newDavWith(t *testing.T, bfs billy.Filesystem, grant vfsdav.Grant) *dav {
	t.Helper()
	h, err := vfsdav.New(vfsdav.Config{
		FS:     bfs,
		Prefix: "/dav",
		Auth:   vfsdav.Basic("pelfs", davUser, davPass, grant),
	})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/dav/", h)
	return &dav{t: t, h: h, srv: newServer(t, mux), fs: bfs}
}

// do issues one request with the Basic credential, and returns the
// response with its body already read.
func (d *dav) do(method, p, body string, hdr ...string) (*http.Response, string) {
	d.t.Helper()
	return d.raw(method, p, body, append([]string{"auth", "basic"}, hdr...)...)
}

// raw is do without a credential unless one is asked for: "auth","basic"
// adds the Basic header, anything else is a literal header pair.
func (d *dav) raw(method, p, body string, hdr ...string) (*http.Response, string) {
	d.t.Helper()
	req, err := http.NewRequest(method, d.srv.URL+p, strings.NewReader(body))
	if err != nil {
		d.t.Fatalf("%s %s: %v", method, p, err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "auth" && hdr[i+1] == "basic" {
			req.SetBasicAuth(davUser, davPass)
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := d.srv.Client().Do(req)
	if err != nil {
		d.t.Fatalf("%s %s: %v", method, p, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		d.t.Fatalf("read %s %s: %v", method, p, err)
	}
	return resp, string(out)
}

// want asserts one status, printing the body — which for a multistatus is
// the only useful part of a failure.
func (d *dav) want(method, p, body string, status int, hdr ...string) string {
	d.t.Helper()
	resp, got := d.do(method, p, body, hdr...)
	if resp.StatusCode != status {
		d.t.Fatalf("%s %s = %d, want %d\n%s", method, p, resp.StatusCode, status, got)
	}
	return got
}
