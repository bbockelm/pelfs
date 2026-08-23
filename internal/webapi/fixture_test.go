package webapi_test

import (
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	"github.com/bbockelm/pelfs/internal/webapi"
)

// The fixture is a REAL volume — signed superblock, real packs, a real write
// overlay — behind the real billy adapter, because what these tests are about
// is what a browser sees of a pelfs volume and a memFS would answer none of
// it. It is internal/vfsdav's fixture with one difference, explained below.
//
// THE MOUNT IDENTITY IS SYNTHETIC, not the process's. internal/idmap
// translates the volume's own identity — the uid publish.InitVolume stamped
// on the root — onto whoever mounts, so a mount as any uid owns the root and
// can write there. Staging an object under a DIFFERENT uid with a restrictive
// mode therefore produces a genuinely forbidden path on every machine,
// including a CI container running as root with all capabilities, where
// ProcessCred would hold CAP_DAC_OVERRIDE and be refused nothing. This is
// internal/vfsbilly/perm_test.go's own trick and it is the only way the
// permission rows in these tables mean anything.

// uids used by the fixture, derived from the process uid for the reason
// perm_test.go gives (a fixed 1000 is the volume identity on one machine and
// a stranger on another).
func fixtureUIDs() (me, grp, they, thgr uint32) {
	base := uint32(os.Getuid())
	return base + 1001, base + 2002, base + 3003, base + 4004
}

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

// fix is one API under test: a volume, the billy binding, the handlers, and a
// plain mux to reach them through.
type fix struct {
	t   *testing.T
	ov  *overlay.FS
	fs  billy.Filesystem
	cnt *countingFS
	api *webapi.API
	mux *http.ServeMux

	me, grp, they, thgr uint32
}

// newFix is the read-write API over a fresh volume.
func newFix(t *testing.T) *fix { return newFixCap(t, 0) }

// newFixCap is newFix with an explicit listing cap.
func newFixCap(t *testing.T, capN int) *fix {
	t.Helper()
	me, grp, they, thgr := fixtureUIDs()
	ov := testvol.New(t, newInner(t), testvol.Options{}).Overlay()
	// NewVolume, not vfsbilly.New: an HTTP handler has a real open, so this
	// binding must not carry NFS's owner override. internal/vfsbilly's
	// owneroverride_test.go fails any call site that forgets.
	inner := webapi.NewVolume(ov, vfsbilly.Cred{UID: me, GID: grp})
	cnt := &countingFS{Filesystem: inner}
	f := &fix{t: t, ov: ov, fs: cnt, cnt: cnt, me: me, grp: grp, they: they, thgr: thgr}
	api, err := webapi.New(webapi.Config{Volume: webapi.Static(cnt), Cap: capN})
	if err != nil {
		t.Fatalf("webapi.New: %v", err)
	}
	f.api = api
	f.mux = http.NewServeMux()
	for _, rt := range api.Routes() {
		f.mux.Handle(rt.Pattern, rt.Handler)
	}
	return f
}

// readOnly is the same volume through a binding that reports no write
// capability, which is what a `pelfs browse` without --rw hands this package.
func (f *fix) readOnly() *fix {
	f.t.Helper()
	ro := &countingFS{Filesystem: f.cnt.Filesystem, noWrite: true}
	api, err := webapi.New(webapi.Config{Volume: webapi.Static(ro)})
	if err != nil {
		f.t.Fatalf("webapi.New: %v", err)
	}
	out := &fix{t: f.t, ov: f.ov, fs: ro, cnt: ro, api: api,
		me: f.me, grp: f.grp, they: f.they, thgr: f.thgr}
	out.mux = http.NewServeMux()
	for _, rt := range api.Routes() {
		out.mux.Handle(rt.Pattern, rt.Handler)
	}
	return out
}

// ---- staging, underneath the frontend ------------------------------------
//
// Setup goes through the overlay rather than through the handlers, so that
// what a handler is asked is only ever the question being tested.

const rootIno = testvol.RootInode

func (f *fix) mkdir(parent uint64, name string, mode, uid, gid uint32) uint64 {
	f.t.Helper()
	n, err := f.ov.Mkdir(context.Background(), parent, name, mode, uid, gid)
	if err != nil {
		f.t.Fatalf("stage mkdir %s: %v", name, err)
	}
	return n.Inode
}

// dir is a directory the mount owns, which is the ordinary case.
func (f *fix) dir(parent uint64, name string) uint64 {
	return f.mkdir(parent, name, 0o755, f.me, f.grp)
}

func (f *fix) file(parent uint64, name string, mode, uid, gid uint32, body []byte) uint64 {
	f.t.Helper()
	n, err := f.ov.Create(context.Background(), parent, name, mode, uid, gid)
	if err != nil {
		f.t.Fatalf("stage create %s: %v", name, err)
	}
	for done := 0; done < len(body); {
		k, werr := f.ov.Write(context.Background(), n.Inode, int64(done), body[done:])
		if werr != nil {
			f.t.Fatalf("stage write %s: %v", name, werr)
		}
		done += k
	}
	return n.Inode
}

// text is a file the mount owns, with a body.
func (f *fix) text(parent uint64, name, body string) uint64 {
	return f.file(parent, name, 0o644, f.me, f.grp, []byte(body))
}

func (f *fix) symlink(parent uint64, name, target string) {
	f.t.Helper()
	if _, err := f.ov.Symlink(context.Background(), parent, name, target, f.me, f.grp); err != nil {
		f.t.Fatalf("stage symlink %s: %v", name, err)
	}
}

func (f *fix) fifo(parent uint64, name string) {
	f.t.Helper()
	if _, err := f.ov.Mknod(context.Background(), parent, name, catalog.TypeFIFO, 0o600, f.me, f.grp, 0); err != nil {
		f.t.Fatalf("stage fifo %s: %v", name, err)
	}
}

// ---- requests ------------------------------------------------------------

// resp is one answer, with the body already read.
type resp struct {
	t    *testing.T
	Code int
	Body string
	Hdr  http.Header
}

// id escapes a volume path the way the component does: percent-encoded into
// ONE path segment.
func id(p string) string { return url.PathEscape(p) }

// do issues one request against the handlers. contentType is set when a body
// is present, because the real surface's guard requires it.
func (f *fix) do(method, target, body string) *resp {
	f.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	res := rec.Result()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		f.t.Fatalf("read %s %s: %v", method, target, err)
	}
	_ = res.Body.Close()
	return &resp{t: f.t, Code: res.StatusCode, Body: string(out), Hdr: res.Header}
}

// get is do for a read.
func (f *fix) get(target string) *resp { return f.do(http.MethodGet, target, "") }

// list is a listing of one directory, by the route the component uses.
func (f *fix) list(dir string) *resp {
	if dir == "/" {
		// Both forms mean the root; the un-pathed one is what boot sends.
		return f.get("/api/v1/files")
	}
	return f.get("/api/v1/files/" + id(dir))
}

// want asserts the status and returns the body.
func (r *resp) want(code int) string {
	r.t.Helper()
	if r.Code != code {
		r.t.Fatalf("status %d, want %d: %s", r.Code, code, r.Body)
	}
	return r.Body
}

// entries decodes a listing.
func (r *resp) entries() []webapi.Entry {
	r.t.Helper()
	r.want(http.StatusOK)
	var out []webapi.Entry
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		r.t.Fatalf("decoding a listing: %v\n%s", err, r.Body)
	}
	if out == nil {
		r.t.Fatalf("a listing decoded to nil; an empty directory must be [] and never null: %s", r.Body)
	}
	return out
}

// ids is the listing's ids, in order.
func (r *resp) ids() []string {
	r.t.Helper()
	var out []string
	for _, e := range r.entries() {
		out = append(out, e.ID)
	}
	return out
}

// batch decodes a per-id batch response.
func (r *resp) batch() webapi.BatchResponse {
	r.t.Helper()
	r.want(http.StatusOK)
	var out webapi.BatchResponse
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		r.t.Fatalf("decoding a batch response: %v\n%s", err, r.Body)
	}
	return out
}

// result decodes a {"result":{...}} response.
func (r *resp) result() webapi.Result {
	r.t.Helper()
	r.want(http.StatusOK)
	var out struct {
		Result webapi.Result `json:"result"`
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		r.t.Fatalf("decoding a result: %v\n%s", err, r.Body)
	}
	return out.Result
}

// info decodes GET /api/v1/info/{id}.
func (r *resp) info() webapi.InfoResponse {
	r.t.Helper()
	r.want(http.StatusOK)
	var out webapi.InfoResponse
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		r.t.Fatalf("decoding an info response: %v\n%s", err, r.Body)
	}
	return out
}

// read is the body of one file, straight from the volume — the check that a
// mutation did what it said.
func (f *fix) read(p string) string {
	f.t.Helper()
	h, err := f.fs.OpenFile(p, os.O_RDONLY, 0)
	if err != nil {
		f.t.Fatalf("open %s: %v", p, err)
	}
	defer h.Close() //nolint:errcheck
	b, err := io.ReadAll(h)
	if err != nil {
		f.t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// exists reports whether a name is there at all, without following a link.
func (f *fix) exists(p string) bool {
	f.t.Helper()
	_, err := f.fs.Lstat(p)
	return err == nil
}

// names is every name in a directory, straight from the volume.
func (f *fix) names(dir string) []string {
	f.t.Helper()
	ents, err := f.fs.ReadDir(dir)
	if err != nil {
		f.t.Fatalf("readdir %s: %v", dir, err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// parts is every *.pelfs-part left in a directory, which must be none once an
// upload has finished or failed.
func (f *fix) parts(dir string) []string {
	f.t.Helper()
	var out []string
	for _, n := range f.names(dir) {
		if strings.HasSuffix(n, webapi.PartSuffix) {
			out = append(out, n)
		}
	}
	return out
}

// ---- the counting filesystem --------------------------------------------

// countingFS is the real binding with three counters over it: how many
// readdirs happened (the in-flight guard's proof), how many bytes were
// written to the volume and in what size chunks (the streaming upload's
// proof).
//
// It also carries the write capability, because billy.CapabilityCheck reads
// it off the filesystem and a wrapper that did not forward it would report
// every volume writable — which would make the read-only rows in these tables
// pass for the wrong reason.
type countingFS struct {
	billy.Filesystem
	noWrite  bool
	readDirs atomic.Int64
	written  atomic.Int64
	maxWrite atomic.Int64
	opens    atomic.Int64
}

func (c *countingFS) ReadDir(p string) ([]os.FileInfo, error) {
	c.readDirs.Add(1)
	return c.Filesystem.ReadDir(p)
}

func (c *countingFS) Capabilities() billy.Capability {
	if c.noWrite {
		return billy.ReadCapability | billy.SeekCapability
	}
	return billy.Capabilities(c.Filesystem)
}

func (c *countingFS) OpenFile(name string, flag int, perm os.FileMode) (billy.File, error) {
	h, err := c.Filesystem.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	c.opens.Add(1)
	return &countingFile{File: h, fs: c}, nil
}

func (c *countingFS) Create(name string) (billy.File, error) {
	return c.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

type countingFile struct {
	billy.File
	fs *countingFS
}

func (f *countingFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	f.fs.written.Add(int64(n))
	for {
		old := f.fs.maxWrite.Load()
		if int64(n) <= old || f.fs.maxWrite.CompareAndSwap(old, int64(n)) {
			break
		}
	}
	return n, err
}

// multipartBody builds one upload body. files are name/content pairs; extra
// are field/value pairs sent as ordinary form fields.
func multipartBody(t testing.TB, field string, files [][2]string, extra ...[2]string) (string, string) {
	t.Helper()
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	for _, kv := range extra {
		if err := mw.WriteField(kv[0], kv[1]); err != nil {
			t.Fatalf("writing field %s: %v", kv[0], err)
		}
	}
	for _, f := range files {
		w, err := mw.CreateFormFile(field, f[0])
		if err != nil {
			t.Fatalf("creating part %s: %v", f[0], err)
		}
		if _, err := io.WriteString(w, f[1]); err != nil {
			t.Fatalf("writing part %s: %v", f[0], err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("closing the multipart body: %v", err)
	}
	return b.String(), mw.FormDataContentType()
}

// upload posts one multipart body to the upload route.
func (f *fix) upload(dir, body, contentType string) *resp {
	f.t.Helper()
	return f.uploadReader(dir, strings.NewReader(body), contentType)
}

// uploadReader is upload for a body that is generated rather than held: the
// streaming test's 68 MB never exists as a string on either side.
func (f *fix) uploadReader(dir string, body io.Reader, contentType string) *resp {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/upload?id="+url.QueryEscape(dir), body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	res := rec.Result()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		f.t.Fatalf("read the upload response: %v", err)
	}
	_ = res.Body.Close()
	return &resp{t: f.t, Code: res.StatusCode, Body: string(out), Hdr: res.Header}
}

// jsonBody renders a request body, so a table row can be a Go value.
func jsonBody(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling a request body: %v", err)
	}
	return string(b)
}

// errorOf pulls the {"error":...} message out of a refusal.
func (r *resp) errorOf() string {
	r.t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		r.t.Fatalf("a refusal must be a JSON object with an error field, got %q", r.Body)
	}
	if out.Error == "" {
		r.t.Fatalf("a refusal carried no message: %q", r.Body)
	}
	return out.Error
}

// decodeInto unmarshals a response body into v, failing the test with the
// body when it cannot.
func decodeInto(t testing.TB, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("decoding %T: %v\n%s", v, err, body)
	}
}

// multipartBodyFieldsLast is multipartBody with the ordinary form fields
// AFTER the files, which is the order a client is free to use and the order
// that breaks a handler which decides the final name too early.
func multipartBodyFieldsLast(t testing.TB, field string, files [][2]string, extra ...[2]string) (string, string) {
	t.Helper()
	var b strings.Builder
	mw := multipart.NewWriter(&b)
	for _, f := range files {
		w, err := mw.CreateFormFile(field, f[0])
		if err != nil {
			t.Fatalf("creating part %s: %v", f[0], err)
		}
		if _, err := io.WriteString(w, f[1]); err != nil {
			t.Fatalf("writing part %s: %v", f[0], err)
		}
	}
	for _, kv := range extra {
		if err := mw.WriteField(kv[0], kv[1]); err != nil {
			t.Fatalf("writing field %s: %v", kv[0], err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("closing the multipart body: %v", err)
	}
	return b.String(), mw.FormDataContentType()
}
