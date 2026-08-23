package vfsdav_test

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	"github.com/bbockelm/pelfs/internal/vfsdav"
)

// The round trip everything else rests on.
func TestPutGetHeadDelete(t *testing.T) {
	d := newDav(t)
	body := strings.Repeat("pelfs over webdav. ", 500)

	d.want("PUT", "/dav/file.txt", body, http.StatusCreated)
	resp, got := d.do("GET", "/dav/file.txt", "")
	if resp.StatusCode != http.StatusOK || got != body {
		t.Fatalf("GET = %d, %d bytes; want 200 and %d bytes", resp.StatusCode, len(got), len(body))
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("no ETag on the GET; clients use it to avoid re-downloading a file")
	}
	// The redirector, Finder and rclone all HEAD before they GET.
	resp, _ = d.do("HEAD", "/dav/file.txt", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD = %d, want 200", resp.StatusCode)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("HEAD Content-Length = %d, want %d", resp.ContentLength, len(body))
	}

	// A GET of a collection is 405 upstream, and that is not a bug to fix
	// here: it is the property that keeps the whole browser-reachable part
	// of this surface read-only and file-shaped.
	d.want("GET", "/dav/", "", http.StatusMethodNotAllowed)

	d.want("DELETE", "/dav/file.txt", "", http.StatusNoContent)
	d.want("GET", "/dav/file.txt", "", http.StatusNotFound)
	d.want("DELETE", "/dav/file.txt", "", http.StatusNotFound)
}

// RANGE, VERIFIED RATHER THAN ASSUMED.
//
// docs/design-webui.md claims Range works "for free": handleGetHeadPost
// calls http.ServeContent, webdav.File is http.File + io.Writer so Seek is
// mandatory, and billy's file has Seek. Every step of that is true, and the
// conclusion is still worth measuring, because a wrapper that returned a
// short read at an offset, or a Stat with a stale size, would produce a 206
// with the wrong bytes and nothing would complain.
//
// This is also the row docs/design-windows.md cares about most: the
// redirector reads whole files, but Cyberduck, `rclone`, `mount_webdav` and
// every resumed download issue ranged GETs.
func TestRangeRequestsAreServedByteExact(t *testing.T) {
	d := newDav(t)
	body := make([]byte, 1<<20)
	rand.New(rand.NewSource(11)).Read(body)
	d.want("PUT", "/dav/big.bin", string(body), http.StatusCreated)

	for _, tc := range []struct {
		hdr        string
		from, to   int // inclusive
		wantStatus int
	}{
		{hdr: "bytes=0-0", from: 0, to: 0, wantStatus: http.StatusPartialContent},
		{hdr: "bytes=100-199", from: 100, to: 199, wantStatus: http.StatusPartialContent},
		{hdr: "bytes=1048575-1048575", from: 1<<20 - 1, to: 1<<20 - 1, wantStatus: http.StatusPartialContent},
		{hdr: "bytes=-4096", from: 1<<20 - 4096, to: 1<<20 - 1, wantStatus: http.StatusPartialContent},
		{hdr: "bytes=1048576-", wantStatus: http.StatusRequestedRangeNotSatisfiable},
	} {
		t.Run(tc.hdr, func(t *testing.T) {
			resp, got := d.do("GET", "/dav/big.bin", "", "Range", tc.hdr)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantStatus != http.StatusPartialContent {
				return
			}
			want := body[tc.from : tc.to+1]
			if got != string(want) {
				t.Fatalf("%d bytes, want %d, and the bytes %s",
					len(got), len(want), map[bool]string{true: "match", false: "DIFFER"}[got == string(want)])
			}
			wantCR := fmt.Sprintf("bytes %d-%d/%d", tc.from, tc.to, len(body))
			if cr := resp.Header.Get("Content-Range"); cr != wantCR {
				t.Errorf("Content-Range = %q, want %q", cr, wantCR)
			}
		})
	}
}

// NO CORS HEADER, ON ANY VERB, IN ANY STATE.
//
// This is a structural defence and not a nicety: with no
// Access-Control-Allow-Methods, a cross-origin preflight for PROPFIND, PUT,
// MKCOL, MOVE, COPY, DELETE, PROPPATCH, LOCK or UNLOCK fails and the
// browser never sends the real request — so the entire WebDAV write surface
// is unreachable from a page by construction (docs/design-webui.md, "What
// WebDAV owes the JSON surface"). The correct action was to change nothing;
// this is what makes "nothing" checkable.
//
// The 401 and 403 paths are in the table too, because a middleware that
// added CORS headers to error responses only would be exactly as broken and
// far easier to miss.
func TestNoCORSHeaderOnAnyVerb(t *testing.T) {
	d := newDav(t)
	d.want("PUT", "/dav/f.txt", "body", http.StatusCreated)
	d.want("MKCOL", "/dav/coll", "", http.StatusCreated)

	type req struct {
		method, path, body string
		hdr                []string
	}
	reqs := []req{
		{method: "OPTIONS", path: "/dav/"},
		{method: "OPTIONS", path: "/dav/f.txt"},
		{method: "GET", path: "/dav/f.txt"},
		{method: "HEAD", path: "/dav/f.txt"},
		{method: "POST", path: "/dav/f.txt"},
		{method: "PUT", path: "/dav/f2.txt", body: "x"},
		{method: "PROPFIND", path: "/dav/", hdr: []string{"Depth", "1"}},
		{method: "PROPPATCH", path: "/dav/f.txt", body: propPatchBody},
		{method: "MKCOL", path: "/dav/coll2"},
		{method: "COPY", path: "/dav/f.txt", hdr: []string{"Destination", "/dav/copy.txt"}},
		{method: "MOVE", path: "/dav/copy.txt", hdr: []string{"Destination", "/dav/moved.txt"}},
		{method: "LOCK", path: "/dav/f.txt", body: lockBody},
		{method: "UNLOCK", path: "/dav/f.txt", hdr: []string{"Lock-Token", "<nope>"}},
		{method: "DELETE", path: "/dav/moved.txt"},
		{method: "GET", path: "/dav/nope.txt"},
	}
	// Every request twice: once authenticated, once not (the 401 path), and
	// each with an Origin header, which is what a page would send.
	for _, r := range reqs {
		for _, auth := range []bool{true, false} {
			hdr := append([]string{"Origin", "http://evil.example"}, r.hdr...)
			var resp *http.Response
			if auth {
				resp, _ = d.do(r.method, r.path, r.body, hdr...)
			} else {
				resp, _ = d.raw(r.method, r.path, r.body, hdr...)
			}
			for k := range resp.Header {
				if strings.HasPrefix(strings.ToLower(k), "access-control-allow") {
					t.Errorf("%s %s (auth=%v) returned %s: %q — the WebDAV surface "+
						"must never be reachable cross-origin", r.method, r.path, auth,
						k, resp.Header.Get(k))
				}
			}
			if !auth && resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s with no credential = %d, want 401",
					r.method, r.path, resp.StatusCode)
			}
		}
	}
	// And the read-only grant's 403 path.
	ro := newDavWith(t, newBilly(t), vfsdav.Grant{Write: false})
	resp, _ := ro.do("PUT", "/dav/f.txt", "x")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT with a read-only grant = %d, want 403", resp.StatusCode)
	}
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "access-control-allow") {
			t.Errorf("the 403 carried %s", k)
		}
	}
}

// The credential: what is accepted, what is refused, and what is offered.
func TestBasicCredential(t *testing.T) {
	d := newDav(t)
	d.want("PUT", "/dav/f.txt", "body", http.StatusCreated)

	resp, _ := d.raw("GET", "/dav/f.txt", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no credential = %d, want 401", resp.StatusCode)
	}
	if ch := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(ch, "Basic ") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge — a client with "+
			"no challenge never asks the user for a password", ch)
	}

	for _, tc := range []struct{ name, user, pass string }{
		{"wrong password", davUser, davPass + "x"},
		{"wrong user", davUser + "x", davPass},
		{"empty", "", ""},
	} {
		req, _ := http.NewRequest("GET", d.srv.URL+"/dav/f.txt", nil)
		req.SetBasicAuth(tc.user, tc.pass)
		resp, err := d.srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", tc.name, resp.StatusCode)
		}
	}

	// THE SESSION TOKEN IS NOT A WEBDAV CREDENTIAL. The browser session
	// token lives in sessionStorage and is sent by the SPA on every /api/v1
	// request; a WebDAV surface that accepted it would make every verb here
	// reachable from the page (docs/design-webui.md, A7).
	resp, _ = d.raw("PROPFIND", "/dav/", "", "X-Pelfs-Session", "any-session-token")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("X-Pelfs-Session presented at /dav/ = %d, want 401", resp.StatusCode)
	}
}

// The scope seam, which is also U7's: a credential that may read and not
// write is refused on the mutating verbs with 403, not 401 — a 401 would
// send the client back to ask for the password again, which is the wrong
// instruction.
func TestReadOnlyGrantRefusesWriteVerbs(t *testing.T) {
	d := newDavWith(t, newBilly(t), vfsdav.Grant{Write: false})
	for _, tc := range []struct {
		method, path string
		hdr          []string
	}{
		{method: "PUT", path: "/dav/f.txt"},
		{method: "DELETE", path: "/dav/f.txt"},
		{method: "MKCOL", path: "/dav/coll"},
		{method: "MOVE", path: "/dav/f.txt", hdr: []string{"Destination", "/dav/g.txt"}},
		{method: "COPY", path: "/dav/f.txt", hdr: []string{"Destination", "/dav/g.txt"}},
		{method: "PROPPATCH", path: "/dav/"},
		{method: "LOCK", path: "/dav/f.txt"},
	} {
		resp, _ := d.do(tc.method, tc.path, "", tc.hdr...)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with a read-only grant = %d, want 403", tc.method, resp.StatusCode)
		}
	}
	// And the read verbs still work.
	d.want("PROPFIND", "/dav/", "", http.StatusMultiStatus, "Depth", "0")
	d.want("OPTIONS", "/dav/", "", http.StatusOK)
}

// THE SEAM FOR U7. This package accepts Bearer tokens through a verifier it
// is given; it does not issue them, store them or know what PKCE is. This
// test is the whole contract internal/localoauth has to satisfy, and it
// runs with no authorization server in existence.
func TestBearerSeam(t *testing.T) {
	const writeToken, readToken = "write-token", "read-token"
	verify := func(tok string) (vfsdav.Grant, bool) {
		switch tok {
		case writeToken:
			return vfsdav.Grant{Subject: "cyberduck", Write: true}, true
		case readToken:
			return vfsdav.Grant{Subject: "cyberduck", Write: false}, true
		}
		return vfsdav.Grant{}, false
	}
	h, err := vfsdav.New(vfsdav.Config{
		FS:     newBilly(t),
		Prefix: "/dav",
		Auth: vfsdav.AnyOf(
			vfsdav.Bearer("pelfs", verify),
			vfsdav.Basic("pelfs", davUser, davPass, vfsdav.Grant{Write: true}),
		),
	})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/dav/", h)
	d := &dav{t: t, h: h}
	d.srv = newServer(t, mux)

	// Both challenges are offered, so a client that speaks either knows it
	// may. Cyberduck picks Bearer; WinSCP and rclone pick Basic.
	resp, _ := d.raw("PROPFIND", "/dav/", "")
	ch := resp.Header.Values("WWW-Authenticate")
	if len(ch) != 2 || !strings.HasPrefix(ch[0], "Bearer ") || !strings.HasPrefix(ch[1], "Basic ") {
		t.Fatalf("challenges = %q, want a Bearer line and a Basic line", ch)
	}

	bearer := func(tok string) []string { return []string{"Authorization", "Bearer " + tok} }
	// A write token writes, a read token reads and is refused a write, and
	// an unknown token is 401 — the three cases U7's tests assert against a
	// real /oauth/token.
	if resp, _ := d.raw("PUT", "/dav/f.txt", "body", bearer(writeToken)...); resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT with a write-scope Bearer = %d, want 201", resp.StatusCode)
	}
	if resp, _ := d.raw("GET", "/dav/f.txt", "", bearer(readToken)...); resp.StatusCode != http.StatusOK {
		t.Errorf("GET with a read-scope Bearer = %d, want 200", resp.StatusCode)
	}
	if resp, _ := d.raw("PUT", "/dav/g.txt", "x", bearer(readToken)...); resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT with a read-scope Bearer = %d, want 403", resp.StatusCode)
	}
	if resp, _ := d.raw("GET", "/dav/f.txt", "", bearer("forged")...); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET with an unknown Bearer = %d, want 401", resp.StatusCode)
	}
	// And Basic still works alongside it.
	if resp, _ := d.do("GET", "/dav/f.txt", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET with Basic alongside Bearer = %d, want 200", resp.StatusCode)
	}
}

// MKCOL's four answers, which are four different statuses and the reason
// Mkdir does its own parent and existence checks rather than calling
// billy's MkdirAll.
func TestMkcolStatuses(t *testing.T) {
	d := newDav(t)
	d.want("MKCOL", "/dav/coll", "", http.StatusCreated)
	d.want("MKCOL", "/dav/coll", "", http.StatusMethodNotAllowed)
	d.want("MKCOL", "/dav/missing/coll", "", http.StatusConflict)
	d.want("MKCOL", "/dav/withbody", "not allowed", http.StatusUnsupportedMediaType)
	// MKCOL where the parent is a FILE is also 409: nothing can be created
	// under a non-collection.
	d.want("PUT", "/dav/f.txt", "x", http.StatusCreated)
	d.want("MKCOL", "/dav/f.txt/coll", "", http.StatusConflict)
	// And PUT under a missing parent, which is the same distinction on the
	// data path: 409, never a silent mkdir -p.
	d.want("PUT", "/dav/missing/f.txt", "x", http.StatusConflict)
}

// PROPFIND over a real directory: the listing a client renders, at both
// depths, plus the collection's own resourcetype.
func TestPropfindListsTheVolume(t *testing.T) {
	d := newDav(t)
	d.want("MKCOL", "/dav/dir", "", http.StatusCreated)
	for i := range 3 {
		d.want("PUT", "/dav/dir/f"+strconv.Itoa(i), strings.Repeat("x", i+1), http.StatusCreated)
	}

	got := d.want("PROPFIND", "/dav/dir/", "", http.StatusMultiStatus, "Depth", "1")
	for i := range 3 {
		if !strings.Contains(got, "/dav/dir/f"+strconv.Itoa(i)) {
			t.Errorf("depth-1 PROPFIND of /dav/dir/ is missing f%d:\n%s", i, got)
		}
	}
	if !strings.Contains(got, "<D:collection") {
		t.Errorf("the collection did not report resourcetype collection:\n%s", got)
	}
	if !strings.Contains(got, "<D:getcontentlength>3<") {
		t.Errorf("no 3-byte length for f2 — sizes come from the volume:\n%s", got)
	}

	// Depth 0 is the resource itself and nothing else.
	got = d.want("PROPFIND", "/dav/dir/", "", http.StatusMultiStatus, "Depth", "0")
	if strings.Contains(got, "/dav/dir/f0") {
		t.Errorf("depth-0 PROPFIND listed children:\n%s", got)
	}
}

// PROPPATCH, including on a COLLECTION — which is golang/go#43929: x/net
// reaches DeadPropsHolder through OpenFile(O_RDWR), an honest EISDIR on a
// directory, and the result upstream is a 500 on a folder. The adapter
// serves that one open as a read handle whose Write is refused, which is
// what makes a PROPPATCH on a folder work without letting anything write
// bytes to a directory.
func TestProppatchOnFilesAndCollections(t *testing.T) {
	d := newDav(t)
	d.want("MKCOL", "/dav/dir", "", http.StatusCreated)
	d.want("PUT", "/dav/dir/f.txt", "body", http.StatusCreated)

	for _, target := range []string{"/dav/dir/f.txt", "/dav/dir/"} {
		got := d.want("PROPPATCH", target, propPatchBody, http.StatusMultiStatus)
		if !strings.Contains(got, "200 OK") {
			t.Fatalf("PROPPATCH %s did not report 200 for the property:\n%s", target, got)
		}
		got = d.want("PROPFIND", target, propFindBody, http.StatusMultiStatus, "Depth", "0")
		if !strings.Contains(got, "the-value") {
			t.Fatalf("the dead property did not come back from %s:\n%s", target, got)
		}
	}

	// A property does not follow the file's old name, and is not left
	// behind for whatever is created there next.
	d.want("MOVE", "/dav/dir/f.txt", "", http.StatusCreated, "Destination", "/dav/dir/moved.txt")
	got := d.want("PROPFIND", "/dav/dir/moved.txt", propFindBody, http.StatusMultiStatus, "Depth", "0")
	if !strings.Contains(got, "the-value") {
		t.Errorf("the dead property did not follow the MOVE:\n%s", got)
	}
	d.want("PUT", "/dav/dir/f.txt", "a new file at the old name", http.StatusCreated)
	got = d.want("PROPFIND", "/dav/dir/f.txt", propFindBody, http.StatusMultiStatus, "Depth", "0")
	if strings.Contains(got, "the-value") {
		t.Errorf("a new file inherited the moved file's dead property:\n%s", got)
	}

	// A live property is protected: x/net answers 403 for it, and a server
	// that let a client rewrite getcontentlength would be lying about the
	// volume.
	got = d.want("PROPPATCH", "/dav/dir/f.txt", liveProppatchBody, http.StatusMultiStatus)
	if !strings.Contains(got, "403") {
		t.Errorf("PROPPATCH of a live property was not refused:\n%s", got)
	}
}

// COPY and MOVE, on files and on collections, which is the whole copymove
// suite in miniature: the recursion is x/net's, the Rename, Mkdir and
// RemoveAll under it are the adapter's.
func TestCopyAndMoveCollections(t *testing.T) {
	d := newDav(t)
	d.want("MKCOL", "/dav/src", "", http.StatusCreated)
	d.want("MKCOL", "/dav/src/inner", "", http.StatusCreated)
	d.want("PUT", "/dav/src/a.txt", "a", http.StatusCreated)
	d.want("PUT", "/dav/src/inner/b.txt", "b", http.StatusCreated)

	d.want("COPY", "/dav/src/", "", http.StatusCreated, "Destination", "/dav/copy")
	if got, _ := d.do("GET", "/dav/copy/inner/b.txt", ""); got.StatusCode != http.StatusOK {
		t.Fatalf("the deep COPY did not reach inner/b.txt: %d", got.StatusCode)
	}
	// The source survives a copy.
	d.want("GET", "/dav/src/inner/b.txt", "", http.StatusOK)

	// Overwrite: F onto an existing name is 412; T replaces.
	d.want("COPY", "/dav/src/a.txt", "", http.StatusPreconditionFailed,
		"Destination", "/dav/copy/a.txt", "Overwrite", "F")
	d.want("COPY", "/dav/src/a.txt", "", http.StatusNoContent,
		"Destination", "/dav/copy/a.txt", "Overwrite", "T")

	d.want("MOVE", "/dav/src/", "", http.StatusCreated, "Destination", "/dav/moved")
	d.want("GET", "/dav/moved/inner/b.txt", "", http.StatusOK)
	d.want("PROPFIND", "/dav/src/", "", http.StatusNotFound, "Depth", "0")

	// DELETE of a collection is Depth: infinity, and billy.Remove refuses a
	// non-empty directory — so the recursion in RemoveAll is what makes this
	// 204 instead of a 405 on a directory that is not empty.
	d.want("DELETE", "/dav/moved", "", http.StatusNoContent)
	d.want("PROPFIND", "/dav/moved", "", http.StatusNotFound, "Depth", "0")
}

// A PUT MUST NOT TRUNCATE A FILE THE MODE BITS PROTECT.
//
// This is the latent defect the adapter would have inherited, seen from the
// protocol: internal/vfsbilly's mayOpen used to grant knfsd's owner
// override to every caller, so a WebDAV PUT — O_RDWR|O_CREATE|O_TRUNC —
// would have emptied a 0444 file that the kernel, FUSE's
// `default_permissions` and the NFS ACCESS reply all refuse. The override
// is now the NFS binding's alone (vfsbilly.OpenSemantics), and this is the
// frontend-level proof.
//
// The status is upstream's mapping of a non-ENOENT open error on PUT (404),
// which is a poor status for EACCES and is not this package's to change; the
// bytes are the part that matters.
func TestAPutCannotTruncateAReadOnlyFile(t *testing.T) {
	bfs := newBilly(t)
	d := newDavWith(t, bfs, vfsdav.Grant{Write: true})
	const body = "the body a read-only file keeps"
	d.want("PUT", "/dav/ro.txt", body, http.StatusCreated)
	if err := bfs.(billy.Change).Chmod("/ro.txt", 0o444); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	resp, _ := d.do("PUT", "/dav/ro.txt", "clobbered")
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
		t.Fatalf("PUT over a 0444 file was ACCEPTED (%d) — the adapter inherited "+
			"NFS's owner override; see vfsbilly.OpenSemantics", resp.StatusCode)
	}
	if _, got := d.do("GET", "/dav/ro.txt", ""); got != body {
		t.Fatalf("the file now holds %q, want %q", got, body)
	}
	// Reading it is still fine: 0444 grants read to everybody.
	d.want("GET", "/dav/ro.txt", "", http.StatusOK)
}

// A read-only BINDING — `pelfs browse` without --rw — refuses every write
// with a status a client can act on, and does not accept property changes
// it could not keep either.
func TestReadOnlyVolumeRefusesEveryWrite(t *testing.T) {
	bfs, names := newReadOnlyBilly(t)
	d := newDavWith(t, bfs, vfsdav.Grant{Write: true})

	// Reads work.
	d.want("GET", "/dav/"+names[0], "", http.StatusOK)
	d.want("PROPFIND", "/dav/", "", http.StatusMultiStatus, "Depth", "1")

	// Writes do not. Every one of these is billy answering EPERM, which
	// x/net maps to a status; what matters is that none of them is a
	// success and none of them is a 500.
	for _, tc := range []struct {
		method, path string
		hdr          []string
	}{
		{method: "PUT", path: "/dav/new.txt"},
		{method: "MKCOL", path: "/dav/coll"},
		{method: "DELETE", path: "/dav/" + names[0]},
		{method: "MOVE", path: "/dav/" + names[0], hdr: []string{"Destination", "/dav/moved"}},
	} {
		resp, body := d.do(tc.method, tc.path, "x", tc.hdr...)
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("%s on a read-only volume = %d, want a 4xx refusal\n%s",
				tc.method, resp.StatusCode, body)
		}
	}
	// And PROPPATCH is refused rather than accepted into memory: a property
	// this process remembers and no other reader of the generation can see
	// is a lie about the volume.
	got := d.want("PROPPATCH", "/dav/"+names[0], propPatchBody, http.StatusMultiStatus)
	if !strings.Contains(got, "403") {
		t.Errorf("PROPPATCH on a read-only volume was accepted:\n%s", got)
	}
}

// What a pelfs volume has and WebDAV does not, in one listing: a symlink to
// a file (followed), a dangling symlink (hidden), a symlink to a directory
// (hidden — see the package comment), a fifo (hidden), and a hard link
// (both names, untouched). Every hidden entry is counted.
func TestListingsHandleWhatWebDAVCannotRepresent(t *testing.T) {
	ov := newOverlay(t)
	c := context.Background()
	cred := vfsbilly.ProcessCred()
	uid, gid := cred.UID, cred.GID

	fn, err := ov.Create(c, genfs.RootInode, "target.txt", 0o644, uid, gid)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := ov.Write(c, fn.Inode, 0, []byte("seven!!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	dir, err := ov.Mkdir(c, genfs.RootInode, "realdir", 0o755, uid, gid)
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, l := range []struct{ name, target string }{
		{"good.link", "target.txt"},
		{"dangling.link", "nowhere.txt"},
		{"dir.link", "realdir"},
	} {
		if _, err := ov.Symlink(c, genfs.RootInode, l.name, l.target, uid, gid); err != nil {
			t.Fatalf("symlink %s: %v", l.name, err)
		}
	}
	if _, err := ov.Mknod(c, genfs.RootInode, "a.fifo", catalog.TypeFIFO, 0o600, uid, gid, 0); err != nil {
		t.Fatalf("mknod: %v", err)
	}
	_ = dir
	if _, err := ov.Link(c, fn.Inode, genfs.RootInode, "hard.txt"); err != nil {
		t.Fatalf("link: %v", err)
	}

	bfs := vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere)
	d := newDavWith(t, bfs, vfsdav.Grant{Write: true})
	got := d.want("PROPFIND", "/dav/", "", http.StatusMultiStatus, "Depth", "1")

	for _, want := range []string{"target.txt", "hard.txt", "good.link", "realdir"} {
		if !strings.Contains(got, want) {
			t.Errorf("listing is missing %s:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"dangling.link", "dir.link", "a.fifo"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("listing exposes %s, which no client can render:\n%s", unwanted, got)
		}
	}
	// The followed link is the TARGET's seven bytes, not an empty file: the
	// failure mode this policy exists to prevent is an image tree where
	// every `lib -> lib64` is 0 bytes.
	if _, body := d.do("GET", "/dav/good.link", ""); body != "seven!!" {
		t.Errorf("GET of a symlink returned %q, want the target's bytes", body)
	}
	if c := d.h.Counts(); c.DanglingSymlinks != 1 || c.DirectorySymlinks != 1 || c.SpecialFiles != 1 {
		t.Errorf("Counts() = %+v, want one of each — a hidden entry that is not "+
			"counted is a tree that silently looks smaller than it is", c)
	}
}

// The lock system is memLS, whose two litmus failures are the documented
// upstream baseline. What matters here is that LOCK and UNLOCK are wired at
// all: the Windows redirector takes an exclusive write lock before it
// writes, so a handler with no lock system would refuse every write from
// Explorer.
func TestExclusiveLockRoundTrip(t *testing.T) {
	d := newDav(t)
	d.want("PUT", "/dav/f.txt", "body", http.StatusCreated)
	resp, body := d.do("LOCK", "/dav/f.txt", lockBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LOCK = %d, want 200\n%s", resp.StatusCode, body)
	}
	tok := resp.Header.Get("Lock-Token")
	if tok == "" {
		t.Fatalf("LOCK returned no Lock-Token:\n%s", body)
	}
	// A write with no token is refused while the lock is held.
	if resp, _ := d.do("PUT", "/dav/f.txt", "x"); resp.StatusCode != http.StatusLocked {
		t.Errorf("PUT to a locked file = %d, want 423", resp.StatusCode)
	}
	// And with the token, allowed. (x/net answers 201 for every successful
	// PUT, new file or not.)
	d.want("PUT", "/dav/f.txt", "x", http.StatusCreated, "If", "("+tok+")")
	d.want("UNLOCK", "/dav/f.txt", "", http.StatusNoContent, "Lock-Token", tok)
	d.want("PUT", "/dav/f.txt", "y", http.StatusCreated)
}

// New refuses to build something unsafe rather than defaulting to it.
func TestNewRefusesAnUnauthenticatedSurface(t *testing.T) {
	if _, err := vfsdav.New(vfsdav.Config{FS: newBilly(t)}); err == nil {
		t.Fatal("vfsdav.New with no Auth succeeded — a WebDAV endpoint with no " +
			"credential is writable by every process on the machine")
	}
	if _, err := vfsdav.New(vfsdav.Config{Auth: vfsdav.Basic("r", "u", "p", vfsdav.Grant{})}); err == nil {
		t.Fatal("vfsdav.New with no filesystem succeeded")
	}
	// A trailing slash on the prefix is the obvious thing to write and must
	// not turn every path into a 404.
	h, err := vfsdav.New(vfsdav.Config{
		FS: newBilly(t), Prefix: "/dav/",
		Auth: vfsdav.Basic("pelfs", davUser, davPass, vfsdav.Grant{Write: true}),
	})
	if err != nil {
		t.Fatalf("vfsdav.New: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/dav/", h)
	d := &dav{t: t, h: h, srv: newServer(t, mux)}
	d.want("PUT", "/dav/f.txt", "body", http.StatusCreated)
	d.want("GET", "/dav/f.txt", "", http.StatusOK)
}

// newReadOnlyBilly publishes a small generation and binds it read-only —
// what `pelfs browse` without --rw serves. It returns the names it wrote.
func newReadOnlyBilly(t *testing.T) (billy.Filesystem, []string) {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{})
	names := []string{"sealed.txt", "other.txt"}
	for i, n := range names {
		v.WriteFile(testvol.RootInode, n, []byte(strings.Repeat("s", i+1)))
	}
	res := v.Publish(publish.Options{TargetPackSize: 2 << 20})
	fs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return vfsbilly.NewReadOnlyFor(fs, vfsbilly.ProcessCred(), vfsbilly.OpenAnsweredHere), names
}

// Request bodies, kept out of the tests that use them.
const (
	propPatchBody = `<?xml version="1.0" encoding="utf-8" ?>
<D:propertyupdate xmlns:D="DAV:" xmlns:P="http://pelfs.example/ns">
  <D:set><D:prop><P:marker>the-value</P:marker></D:prop></D:set>
</D:propertyupdate>`

	liveProppatchBody = `<?xml version="1.0" encoding="utf-8" ?>
<D:propertyupdate xmlns:D="DAV:">
  <D:set><D:prop><D:getcontentlength>99</D:getcontentlength></D:prop></D:set>
</D:propertyupdate>`

	propFindBody = `<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:" xmlns:P="http://pelfs.example/ns">
  <D:prop><P:marker/></D:prop>
</D:propfind>`

	lockBody = `<?xml version="1.0" encoding="utf-8" ?>
<D:lockinfo xmlns:D="DAV:">
  <D:lockscope><D:exclusive/></D:lockscope>
  <D:locktype><D:write/></D:locktype>
  <D:owner><D:href>pelfs-test</D:href></D:owner>
</D:lockinfo>`
)
