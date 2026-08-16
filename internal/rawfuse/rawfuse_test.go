package rawfuse_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
)

const rootIno = genfs.RootInode

var errStale = fuse.Status(syscall.ESTALE)

// --- fixture: publish a small tree over fakeorigin (the genfs test
// pattern), open genfs, and Bind it ---

func newInner(t *testing.T) pelicanobj.Store {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner
}

type testVolume struct {
	t        *testing.T
	metaPath string
	m        meta.Meta
	blob     object.ObjectStorage
	store    chunk.ChunkStore
	cuts     int
}

func newTestVolume(t *testing.T, uuid string) *testVolume {
	t.Helper()
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format := &meta.Format{
		Name:      "rawfuse-test",
		UUID:      uuid,
		Storage:   "mem",
		BlockSize: 4096, // KiB
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("init meta: %v", err)
	}
	if err := m.NewSession(true); err != nil {
		t.Fatalf("session: %v", err)
	}
	t.Cleanup(func() { _ = m.CloseSession() })

	blob, err := object.CreateStorage("mem", "", "", "", "")
	if err != nil {
		t.Fatalf("mem store: %v", err)
	}
	store := chunk.NewCachedStore(blob, chunk.Config{
		BlockSize:  format.BlockSize * 1024,
		CacheDir:   "memory",
		CacheSize:  64 << 20,
		GetTimeout: 10 * time.Second, PutTimeout: 10 * time.Second,
		MaxUpload: 2, MaxDownload: 2, MaxRetries: 1, BufferSize: 32 << 20,
	}, prometheus.NewRegistry())
	return &testVolume{t: t, metaPath: metaPath, m: m, blob: blob, store: store}
}

func (v *testVolume) ctx() meta.Context { return meta.WrapContext(context.Background()) }

func (v *testVolume) mkdir(parent uint64, name string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Mkdir(v.ctx(), meta.Ino(parent), name, 0755, 0, 0, &ino, &attr); st != 0 {
		v.t.Fatalf("mkdir %s: %s", name, st)
	}
	return uint64(ino)
}

func (v *testVolume) create(parent uint64, name string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Create(v.ctx(), meta.Ino(parent), name, 0644, 0, 0, &ino, &attr); st != 0 {
		v.t.Fatalf("create %s: %s", name, st)
	}
	return uint64(ino)
}

// write stores data as one slice at offset 0 of chunk 0 (data must fit one
// 64 MiB chunk).
func (v *testVolume) write(ino uint64, data []byte) {
	v.t.Helper()
	var sliceID uint64
	if st := v.m.NewSlice(v.ctx(), &sliceID); st != 0 {
		v.t.Fatalf("new slice: %s", st)
	}
	w := v.store.NewWriter(sliceID, 0)
	if _, err := w.WriteAt(data, 0); err != nil {
		v.t.Fatalf("write slice: %v", err)
	}
	if err := w.Finish(len(data)); err != nil {
		v.t.Fatalf("finish slice: %v", err)
	}
	s := meta.Slice{Id: sliceID, Size: uint32(len(data)), Len: uint32(len(data))}
	if st := v.m.Write(v.ctx(), meta.Ino(ino), 0, 0, s, time.Now()); st != 0 {
		v.t.Fatalf("meta write: %s", st)
	}
}

func (v *testVolume) symlink(parent uint64, name, target string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Symlink(v.ctx(), meta.Ino(parent), name, target, &ino, &attr); st != 0 {
		v.t.Fatalf("symlink %s: %s", name, st)
	}
	return uint64(ino)
}

func (v *testVolume) setxattr(ino uint64, name string, value []byte) {
	v.t.Helper()
	if st := v.m.SetXattr(v.ctx(), meta.Ino(ino), name, value, 0); st != 0 {
		v.t.Fatalf("setxattr %s: %s", name, st)
	}
}

// cut takes the publish-time metadata snapshot: VACUUM INTO a fresh file.
func (v *testVolume) cut() string {
	v.t.Helper()
	v.cuts++
	dst := filepath.Join(v.t.TempDir(), fmt.Sprintf("cut-%d.db", v.cuts))
	db, err := sql.Open("sqlite", "file:"+v.metaPath+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		v.t.Fatalf("open meta for cut: %v", err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.Exec(fmt.Sprintf("VACUUM INTO '%s'", dst)); err != nil {
		v.t.Fatalf("vacuum into: %v", err)
	}
	return dst
}

func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// fixture is a published tree served through the binding:
//
//	/big.bin        chunked pseudorandom content
//	/dir/small.txt  inline content, xattr user.color=blue
//	/dir/link       -> small.txt
type fixture struct {
	raw fuse.RawFileSystem

	dirIno, smallIno, linkIno, bigIno uint64
	smallContent, bigContent          []byte
}

func newFixture(t *testing.T, uuid string) *fixture {
	t.Helper()
	inner := newInner(t)
	v := newTestVolume(t, uuid)

	f := &fixture{
		bigContent:   pseudorandom(8<<20, 42),
		smallContent: []byte("hello raw fuse binding"),
	}
	f.dirIno = v.mkdir(rootIno, "dir")
	f.smallIno = v.create(f.dirIno, "small.txt")
	v.write(f.smallIno, f.smallContent)
	v.setxattr(f.smallIno, "user.color", []byte("blue"))
	f.linkIno = v.symlink(f.dirIno, "link", "small.txt")
	f.bigIno = v.create(rootIno, "big.bin")
	v.write(f.bigIno, f.bigContent)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := publish.Publish(context.Background(), publish.Options{
		CutPath:        v.cut(),
		Blob:           v.blob,
		CacheDir:       t.TempDir(),
		Inner:          inner,
		SpoolDir:       t.TempDir(),
		SigningKey:     priv,
		TargetPackSize: 2 << 20,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	gfs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = gfs.Close() })
	f.raw = rawfuse.Bind(gfs)
	return f
}

// --- raw-op helpers (no kernel: fabricate headers, call the binding) ---

func header(ino uint64) *fuse.InHeader { return &fuse.InHeader{NodeId: ino} }

func lookup(t *testing.T, r fuse.RawFileSystem, parent uint64, name string) (*fuse.EntryOut, fuse.Status) {
	t.Helper()
	out := &fuse.EntryOut{}
	st := r.Lookup(nil, header(parent), name, out)
	return out, st
}

func mustLookup(t *testing.T, r fuse.RawFileSystem, parent uint64, name string) *fuse.EntryOut {
	t.Helper()
	out, st := lookup(t, r, parent, name)
	if st != fuse.OK {
		t.Fatalf("Lookup(%d, %q) = %v", parent, name, st)
	}
	return out
}

func getattr(r fuse.RawFileSystem, ino uint64) (*fuse.AttrOut, fuse.Status) {
	out := &fuse.AttrOut{}
	st := r.GetAttr(nil, &fuse.GetAttrIn{InHeader: *header(ino)}, out)
	return out, st
}

func opendir(t *testing.T, r fuse.RawFileSystem, ino uint64) uint64 {
	t.Helper()
	out := &fuse.OpenOut{}
	if st := r.OpenDir(nil, &fuse.OpenIn{InHeader: *header(ino)}, out); st != fuse.OK {
		t.Fatalf("OpenDir(%d) = %v", ino, st)
	}
	return out.Fh
}

// minValiditySec: every clean reply must carry an effectively infinite TTL.
const minValiditySec = uint64(1e8)

func checkValidity(t *testing.T, what string, entrySec, attrSec uint64) {
	t.Helper()
	if entrySec <= minValiditySec || attrSec <= minValiditySec {
		t.Fatalf("%s validity = %d/%d sec, want > %d", what, entrySec, attrSec, minValiditySec)
	}
}

// --- DirEntryList wire parsing (test-only): the list's buffer is private,
// so read it via reflect+unsafe and decode the kernel wire format go-fuse
// serializes (EntryOut? + dirent + name + pad-to-8) ---

// wireDirent mirrors the fuse package's private _Dirent.
type wireDirent struct {
	Ino     uint64
	Off     uint64
	NameLen uint32
	Typ     uint32
}

type parsedEntry struct {
	name  string
	ino   uint64
	off   uint64
	typ   uint32
	entry fuse.EntryOut // readdirplus only; zero value for plain readdir
}

func listBytes(l *fuse.DirEntryList) []byte {
	v := reflect.ValueOf(l).Elem().FieldByName("buf")
	return *(*[]byte)(unsafe.Pointer(v.UnsafeAddr()))
}

func parseList(t *testing.T, l *fuse.DirEntryList, plus bool) []parsedEntry {
	t.Helper()
	buf := listBytes(l)
	direntSize := int(unsafe.Sizeof(wireDirent{}))
	entryOutSize := int(unsafe.Sizeof(fuse.EntryOut{}))
	var out []parsedEntry
	pos := 0
	for pos < len(buf) {
		var pe parsedEntry
		if plus {
			pe.entry = *(*fuse.EntryOut)(unsafe.Pointer(&buf[pos]))
			pos += entryOutSize
		}
		d := *(*wireDirent)(unsafe.Pointer(&buf[pos]))
		pos += direntSize
		pe.name = string(buf[pos : pos+int(d.NameLen)])
		pos += int(d.NameLen)
		pos += (8 - int(d.NameLen)&7) & 7
		pe.ino, pe.off, pe.typ = d.Ino, d.Off, d.Typ
		out = append(out, pe)
	}
	return out
}

func names(es []parsedEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.name)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- tests ---

func TestLookupAttrsAndTimeouts(t *testing.T) {
	f := newFixture(t, "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b")

	dir := mustLookup(t, f.raw, rootIno, "dir")
	if dir.NodeId != f.dirIno || dir.Generation != 0 {
		t.Fatalf("dir NodeId/Generation = %d/%d, want %d/0", dir.NodeId, dir.Generation, f.dirIno)
	}
	if dir.Attr.Mode != syscall.S_IFDIR|0755 {
		t.Fatalf("dir mode = %o, want %o", dir.Attr.Mode, syscall.S_IFDIR|0755)
	}
	checkValidity(t, "dir", dir.EntryValid, dir.AttrValid)

	small := mustLookup(t, f.raw, f.dirIno, "small.txt")
	if small.NodeId != f.smallIno || small.Attr.Size != uint64(len(f.smallContent)) {
		t.Fatalf("small.txt entry = %+v", small)
	}
	if small.Attr.Mode != syscall.S_IFREG|0644 {
		t.Fatalf("small.txt mode = %o", small.Attr.Mode)
	}
	if small.Attr.Ino != f.smallIno || small.Attr.Blksize != 4096 {
		t.Fatalf("small.txt attr = %+v", small.Attr)
	}
	checkValidity(t, "small.txt", small.EntryValid, small.AttrValid)

	link := mustLookup(t, f.raw, f.dirIno, "link")
	if link.NodeId != f.linkIno || link.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Fatalf("link entry = %+v", link)
	}

	if _, st := lookup(t, f.raw, rootIno, "nope"); st != fuse.ENOENT {
		t.Fatalf("Lookup(missing) = %v, want ENOENT", st)
	}

	// GetAttr through the binding matches Lookup, with infinite validity.
	ao, st := getattr(f.raw, f.smallIno)
	if st != fuse.OK || ao.Attr != small.Attr {
		t.Fatalf("GetAttr(small) = %+v (%v), want %+v", ao.Attr, st, small.Attr)
	}
	if ao.AttrValid <= minValiditySec {
		t.Fatalf("GetAttr validity = %d sec", ao.AttrValid)
	}

	// A fabricated NodeId the kernel never looked up is stale.
	if _, st := getattr(f.raw, f.bigIno); st != errStale {
		t.Fatalf("GetAttr(never looked up) = %v, want ESTALE", st)
	}
}

func TestOpenAndRead(t *testing.T) {
	f := newFixture(t, "11112222-3333-4444-5555-666677778888")
	mustLookup(t, f.raw, rootIno, "big.bin")

	oo := &fuse.OpenOut{}
	if st := f.raw.Open(nil, &fuse.OpenIn{InHeader: *header(f.bigIno)}, oo); st != fuse.OK {
		t.Fatalf("Open = %v", st)
	}
	if oo.Fh != 0 {
		t.Fatalf("Open Fh = %d, want stateless 0", oo.Fh)
	}
	if oo.OpenFlags&fuse.FOPEN_KEEP_CACHE == 0 {
		t.Fatal("Open did not set FOPEN_KEEP_CACHE")
	}

	read := func(off int64, size int) []byte {
		t.Helper()
		buf := make([]byte, size)
		rr, st := f.raw.Read(nil, &fuse.ReadIn{
			InHeader: *header(f.bigIno), Offset: uint64(off), Size: uint32(size),
		}, buf)
		if st != fuse.OK {
			t.Fatalf("Read at %d = %v", off, st)
		}
		data, st := rr.Bytes(make([]byte, rr.Size()))
		if st != fuse.OK {
			t.Fatalf("ReadResult.Bytes = %v", st)
		}
		return data
	}

	// Several offsets, including chunk-straddling windows (FastCDC chunks
	// are >= 1 MiB, so 2 MiB reads at odd offsets cross boundaries).
	for _, off := range []int64{0, 1, 4096, 1<<20 - 7, 3 << 20, int64(len(f.bigContent)) - 100} {
		size := 2 << 20
		want := f.bigContent[off:]
		if len(want) > size {
			want = want[:size]
		}
		if got := read(off, size); !bytes.Equal(got, want) {
			t.Fatalf("Read at %d: %d bytes mismatch", off, len(got))
		}
	}
	// At EOF: empty result.
	if got := read(int64(len(f.bigContent)), 4096); len(got) != 0 {
		t.Fatalf("Read at EOF returned %d bytes", len(got))
	}

	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: *header(f.bigIno)})
}

func TestReadDirPlusResidencyAndOffsets(t *testing.T) {
	f := newFixture(t, "aaaa1111-2222-3333-4444-555566667777")

	// One-call listing of root: ".", "..", then the catalog entries.
	fh := opendir(t, f.raw, rootIno)
	l := fuse.NewDirEntryList(make([]byte, 4096), 0)
	if st := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: *header(rootIno), Fh: fh}, l); st != fuse.OK {
		t.Fatalf("ReadDirPlus = %v", st)
	}
	es := parseList(t, l, true)
	if got, want := names(es), []string{".", "..", "big.bin", "dir"}; !equalStrings(got, want) {
		t.Fatalf("readdirplus names = %v, want %v", got, want)
	}
	for _, e := range es {
		switch e.name {
		case ".", "..":
			if e.entry.NodeId != 0 {
				t.Fatalf("%q carries NodeId %d, want 0 (uncached)", e.name, e.entry.NodeId)
			}
		case "big.bin":
			if e.entry.NodeId != f.bigIno || e.entry.Attr.Size != uint64(len(f.bigContent)) {
				t.Fatalf("big.bin entry = %+v", e.entry)
			}
			if e.entry.Attr.Mode != syscall.S_IFREG|0644 || e.typ != syscall.S_IFREG>>12 {
				t.Fatalf("big.bin mode/typ = %o/%d", e.entry.Attr.Mode, e.typ)
			}
			checkValidity(t, "big.bin (readdirplus)", e.entry.EntryValid, e.entry.AttrValid)
		case "dir":
			if e.entry.NodeId != f.dirIno || e.entry.Attr.Mode != syscall.S_IFDIR|0755 {
				t.Fatalf("dir entry = %+v", e.entry)
			}
		}
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: *header(rootIno), Fh: fh})

	// ReadDirPlus counted as a lookup: children have residency, GetAttr
	// succeeds without any explicit Lookup.
	if _, st := getattr(f.raw, f.bigIno); st != fuse.OK {
		t.Fatalf("GetAttr(big.bin) after readdirplus = %v", st)
	}
	if _, st := getattr(f.raw, f.dirIno); st != fuse.OK {
		t.Fatalf("GetAttr(dir) after readdirplus = %v", st)
	}
	// ... and the kernel Forgets what readdirplus emitted.
	f.raw.Forget(f.bigIno, 1)
	if _, st := getattr(f.raw, f.bigIno); st != errStale {
		t.Fatalf("GetAttr(big.bin) after forget = %v, want ESTALE", st)
	}

	// Offset resumption: a buffer sized for ~2 readdirplus rows pages the
	// same listing in multiple calls, resuming by the encoded offset.
	fh = opendir(t, f.raw, rootIno)
	var all []parsedEntry
	off := uint64(0)
	for calls := 0; ; calls++ {
		if calls > 8 {
			t.Fatal("readdirplus did not terminate")
		}
		l := fuse.NewDirEntryList(make([]byte, 2*int(unsafe.Sizeof(fuse.EntryOut{}))+128), off)
		if st := f.raw.ReadDirPlus(nil, &fuse.ReadIn{InHeader: *header(rootIno), Fh: fh, Offset: off}, l); st != fuse.OK {
			t.Fatalf("ReadDirPlus at %d = %v", off, st)
		}
		es := parseList(t, l, true)
		if len(es) == 0 {
			break
		}
		if len(es) >= 4 {
			t.Fatalf("small buffer fit %d entries; resumption untested", len(es))
		}
		all = append(all, es...)
		off = es[len(es)-1].off
	}
	if got, want := names(all), []string{".", "..", "big.bin", "dir"}; !equalStrings(got, want) {
		t.Fatalf("paged readdirplus names = %v, want %v", got, want)
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: *header(rootIno), Fh: fh})
}

func TestReadDirPlainNoResidency(t *testing.T) {
	f := newFixture(t, "bbbb1111-2222-3333-4444-555566667777")
	mustLookup(t, f.raw, rootIno, "dir")

	fh := opendir(t, f.raw, f.dirIno)
	l := fuse.NewDirEntryList(make([]byte, 4096), 0)
	if st := f.raw.ReadDir(nil, &fuse.ReadIn{InHeader: *header(f.dirIno), Fh: fh}, l); st != fuse.OK {
		t.Fatalf("ReadDir = %v", st)
	}
	es := parseList(t, l, false)
	if got, want := names(es), []string{".", "..", "link", "small.txt"}; !equalStrings(got, want) {
		t.Fatalf("readdir names = %v, want %v", got, want)
	}
	for _, e := range es {
		if e.name == "small.txt" && e.ino != f.smallIno {
			t.Fatalf("small.txt ino = %d, want %d", e.ino, f.smallIno)
		}
	}
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: *header(f.dirIno), Fh: fh})

	// Plain ReadDir creates no residency: a child seen only through it is
	// stale until the kernel Lookups it.
	if _, st := getattr(f.raw, f.smallIno); st != errStale {
		t.Fatalf("GetAttr(small.txt) after plain readdir = %v, want ESTALE", st)
	}

	// A released (or never-issued) dir handle is EBADF.
	if st := f.raw.ReadDir(nil, &fuse.ReadIn{InHeader: *header(f.dirIno), Fh: fh}, fuse.NewDirEntryList(make([]byte, 512), 0)); st != fuse.EBADF {
		t.Fatalf("ReadDir on released handle = %v, want EBADF", st)
	}
}

func TestForgetReleases(t *testing.T) {
	f := newFixture(t, "cccc1111-2222-3333-4444-555566667777")

	// Two lookups, one combined forget (BATCH_FORGET dispatches here per
	// node with the summed count).
	mustLookup(t, f.raw, rootIno, "dir")
	mustLookup(t, f.raw, rootIno, "dir")
	f.raw.Forget(f.dirIno, 1)
	if _, st := getattr(f.raw, f.dirIno); st != fuse.OK {
		t.Fatalf("GetAttr with one reference left = %v", st)
	}
	f.raw.Forget(f.dirIno, 1)
	if _, st := getattr(f.raw, f.dirIno); st != errStale {
		t.Fatalf("GetAttr after matching forgets = %v, want ESTALE", st)
	}
}

func TestReadOnly(t *testing.T) {
	f := newFixture(t, "dddd1111-2222-3333-4444-555566667777")
	mustLookup(t, f.raw, rootIno, "big.bin")

	for _, flags := range []uint32{syscall.O_WRONLY, syscall.O_RDWR, syscall.O_RDONLY | syscall.O_TRUNC} {
		oo := &fuse.OpenOut{}
		if st := f.raw.Open(nil, &fuse.OpenIn{InHeader: *header(f.bigIno), Flags: flags}, oo); st != fuse.EROFS {
			t.Fatalf("Open(flags %#o) = %v, want EROFS", flags, st)
		}
	}
	if st := f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: *header(rootIno), Mode: 0755}, "newdir", &fuse.EntryOut{}); st != fuse.EROFS {
		t.Fatalf("Mkdir = %v, want EROFS", st)
	}
	if st := f.raw.Unlink(nil, header(rootIno), "big.bin"); st != fuse.EROFS {
		t.Fatalf("Unlink = %v, want EROFS", st)
	}
	if _, st := f.raw.Write(nil, &fuse.WriteIn{InHeader: *header(f.bigIno)}, []byte("x")); st != fuse.EROFS {
		t.Fatalf("Write = %v, want EROFS", st)
	}
	if st := f.raw.SetAttr(nil, &fuse.SetAttrIn{}, &fuse.AttrOut{}); st != fuse.EROFS {
		t.Fatalf("SetAttr = %v, want EROFS", st)
	}
}

func TestXattrAndReadlink(t *testing.T) {
	f := newFixture(t, "eeee1111-2222-3333-4444-555566667777")
	mustLookup(t, f.raw, rootIno, "dir")
	mustLookup(t, f.raw, f.dirIno, "small.txt")
	mustLookup(t, f.raw, f.dirIno, "link")

	// GetXAttr round-trip, ERANGE sizing probe first (dest too small
	// returns the required size).
	if sz, st := f.raw.GetXAttr(nil, header(f.smallIno), "user.color", make([]byte, 1)); st != fuse.ERANGE || sz != 4 {
		t.Fatalf("GetXAttr(short dest) = %d, %v; want 4, ERANGE", sz, st)
	}
	dest := make([]byte, 64)
	sz, st := f.raw.GetXAttr(nil, header(f.smallIno), "user.color", dest)
	if st != fuse.OK || string(dest[:sz]) != "blue" {
		t.Fatalf("GetXAttr = %q, %v", dest[:sz], st)
	}
	// Missing attr: ENODATA, or ENOATTR (93) on darwin where they differ.
	if _, st := f.raw.GetXAttr(nil, header(f.smallIno), "user.missing", dest); st != fuse.ENODATA && int(st) != 93 {
		t.Fatalf("GetXAttr(missing) = %v, want ENODATA/ENOATTR", st)
	}

	// ListXAttr: NUL-delimited names, same ERANGE protocol.
	want := []byte("user.color\x00")
	if sz, st := f.raw.ListXAttr(nil, header(f.smallIno), make([]byte, 1)); st != fuse.ERANGE || int(sz) != len(want) {
		t.Fatalf("ListXAttr(short dest) = %d, %v", sz, st)
	}
	sz, st = f.raw.ListXAttr(nil, header(f.smallIno), dest)
	if st != fuse.OK || !bytes.Equal(dest[:sz], want) {
		t.Fatalf("ListXAttr = %q, %v", dest[:sz], st)
	}

	// Readlink round-trip.
	target, st := f.raw.Readlink(nil, header(f.linkIno))
	if st != fuse.OK || string(target) != "small.txt" {
		t.Fatalf("Readlink = %q, %v", target, st)
	}

	// StatFs is synthetic but sane.
	sfs := &fuse.StatfsOut{}
	if st := f.raw.StatFs(nil, header(rootIno), sfs); st != fuse.OK || sfs.Bsize != 4096 || sfs.Bfree == 0 {
		t.Fatalf("StatFs = %+v (%v)", sfs, st)
	}
}
