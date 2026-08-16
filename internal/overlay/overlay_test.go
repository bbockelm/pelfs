package overlay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

const rootIno = genfs.RootInode

// The fixture publishes a fixed base tree over fakeorigin exactly as the
// genfs tests do, then the overlay shadows it.

func newInner(t testing.TB) pelicanobj.Store {
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

// testVolume is a live JuiceFS volume the fixture mutates and cuts (the
// publish/genfs test pattern).
type testVolume struct {
	t        testing.TB
	metaPath string
	m        meta.Meta
	blob     object.ObjectStorage
	store    chunk.ChunkStore
	cuts     int
}

func newTestVolume(t testing.TB, uuid string) *testVolume {
	t.Helper()
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format := &meta.Format{
		Name:      "overlay-test",
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

// write stores data as one slice at offset 0 of chunk 0 (data must fit
// one 64 MiB chunk).
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

func publishVolume(t testing.TB, v *testVolume, inner pelicanobj.Store, opts publish.Options) *publish.Result {
	t.Helper()
	opts.CutPath = v.cut()
	opts.Blob = v.blob
	opts.CacheDir = t.TempDir()
	opts.Inner = inner
	opts.SpoolDir = t.TempDir()
	if opts.SigningKey == nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		opts.SigningKey = priv
	}
	res, err := publish.Publish(context.Background(), opts)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return res
}

func openBase(t testing.TB, inner pelicanobj.Store, sb *superblock.Superblock) *genfs.FS {
	t.Helper()
	fs, err := genfs.Open(context.Background(), genfs.Options{Inner: inner, SB: sb, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// fixture is one published base tree:
//
//	/base.txt   small text
//	/big.bin    64 KiB pseudorandom (chunked)
//	/dir/child.txt
//	/dir/inner/leaf.txt
//	/tagged.txt with xattrs user.color=blue, user.keep=yes
type fixture struct {
	inner pelicanobj.Store
	res   *publish.Result
	base  *genfs.FS
	ino   map[string]uint64
	body  map[string][]byte
}

func newFixture(t testing.TB, uuid string) *fixture {
	t.Helper()
	inner := newInner(t)
	v := newTestVolume(t, uuid)
	fx := &fixture{inner: inner, ino: map[string]uint64{}, body: map[string][]byte{}}
	fx.body["base.txt"] = []byte("the base file body, generation zero")
	fx.body["big.bin"] = pseudorandom(64<<10, 42)
	fx.body["dir/child.txt"] = []byte("child body")
	fx.body["dir/inner/leaf.txt"] = []byte("leaf body")
	fx.body["tagged.txt"] = []byte("tagged body")

	fx.ino["base.txt"] = v.create(rootIno, "base.txt")
	fx.ino["big.bin"] = v.create(rootIno, "big.bin")
	fx.ino["dir"] = v.mkdir(rootIno, "dir")
	fx.ino["dir/child.txt"] = v.create(fx.ino["dir"], "child.txt")
	fx.ino["dir/inner"] = v.mkdir(fx.ino["dir"], "inner")
	fx.ino["dir/inner/leaf.txt"] = v.create(fx.ino["dir/inner"], "leaf.txt")
	fx.ino["tagged.txt"] = v.create(rootIno, "tagged.txt")
	for p, b := range fx.body {
		v.write(fx.ino[p], b)
	}
	v.setxattr(fx.ino["tagged.txt"], "user.color", []byte("blue"))
	v.setxattr(fx.ino["tagged.txt"], "user.keep", []byte("yes"))

	fx.res = publishVolume(t, v, inner, publish.Options{TargetPackSize: 1 << 20})
	fx.base = openBase(t, inner, fx.res.Superblock)
	return fx
}

func (fx *fixture) options() overlay.Options {
	return overlay.Options{
		NextInode:      fx.res.Superblock.NextInode,
		BaseRoot:       fx.res.Superblock.RootCatalog,
		BaseGeneration: fx.res.Superblock.Generation,
	}
}

func openOverlay(t testing.TB, fx *fixture, dir string) *overlay.FS {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	ov, err := overlay.Open(dir, fx.base, fx.options())
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = ov.Close() })
	return ov
}

// lookupPath walks path from the root through overlay Lookups (the
// kernel descent pattern every operation relies on).
func lookupPath(t *testing.T, ov *overlay.FS, path string) overlay.Node {
	t.Helper()
	n, err := lookupPathErr(ov, path)
	if err != nil {
		t.Fatalf("lookup %s: %v", path, err)
	}
	return n
}

func lookupPathErr(ov *overlay.FS, path string) (overlay.Node, error) {
	ctx := context.Background()
	ino := uint64(rootIno)
	var n overlay.Node
	var err error
	for _, part := range strings.Split(path, "/") {
		n, err = ov.Lookup(ctx, ino, part)
		if err != nil {
			return overlay.Node{}, err
		}
		ino = n.Inode
	}
	return n, nil
}

type contentReader interface {
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
}

func readAllFS(t *testing.T, r contentReader, ino uint64, length int) []byte {
	t.Helper()
	out := make([]byte, 0, length)
	buf := make([]byte, 1<<16)
	for off := 0; off < length; {
		n, err := r.Read(context.Background(), ino, int64(off), buf)
		if err != nil {
			t.Fatalf("read inode %d at %d: %v", ino, off, err)
		}
		if n == 0 {
			t.Fatalf("read inode %d at %d: unexpected EOF (want %d more bytes)", ino, off, length-off)
		}
		out = append(out, buf[:n]...)
		off += n
	}
	return out
}

func entryNames(es []overlay.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func wantNames(t *testing.T, got []overlay.DirEntry, want []string) {
	t.Helper()
	names := entryNames(got)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("readdir = %v, want %v", names, want)
	}
}

func TestCreateWriteReaddir(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0aaa1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	n, err := ov.Create(ctx, rootIno, "new.txt", 0644, 501, 20)
	if err != nil {
		t.Fatal(err)
	}
	if n.Inode < fx.res.Superblock.NextInode {
		t.Fatalf("new inode %d collides with base space (< %d)", n.Inode, fx.res.Superblock.NextInode)
	}
	body := []byte("hello overlay world")
	if k, err := ov.Write(ctx, n.Inode, 0, body); err != nil || k != len(body) {
		t.Fatalf("write = %d, %v", k, err)
	}
	if got := readAllFS(t, ov, n.Inode, len(body)); !bytes.Equal(got, body) {
		t.Fatalf("read back = %q", got)
	}
	if ga, err := ov.GetAttr(ctx, n.Inode); err != nil || ga.Length != int64(len(body)) || ga.Nlink != 1 {
		t.Fatalf("GetAttr(new) = %+v (%v)", ga, err)
	}

	// A directory tree, a file inside it, and a symlink.
	d1, err := ov.Mkdir(ctx, rootIno, "d1", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ov.Mkdir(ctx, d1.Inode, "d2", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	deep, err := ov.Create(ctx, d2.Inode, "deep.txt", 0600, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	deepBody := []byte("deep body")
	if _, err := ov.Write(ctx, deep.Inode, 0, deepBody); err != nil {
		t.Fatal(err)
	}
	if got := lookupPath(t, ov, "d1/d2/deep.txt"); got.Inode != deep.Inode {
		t.Fatalf("deep lookup = %+v", got)
	}
	if got := readAllFS(t, ov, deep.Inode, len(deepBody)); !bytes.Equal(got, deepBody) {
		t.Fatalf("deep read = %q", got)
	}
	sn, err := ov.Symlink(ctx, rootIno, "sym", "base.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if target, err := ov.Readlink(ctx, sn.Inode); err != nil || target != "base.txt" {
		t.Fatalf("readlink = %q (%v)", target, err)
	}
	if _, err := ov.Mknod(ctx, rootIno, "fifo", catalog.TypeFIFO, 0600, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if fn := lookupPath(t, ov, "fifo"); fn.Type != catalog.TypeFIFO {
		t.Fatalf("fifo node = %+v", fn)
	}

	// Merged root: base + new, sorted, no duplicates.
	es, err := ov.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"base.txt", "big.bin", "d1", "dir", "fifo", "new.txt", "sym", "tagged.txt"})
	for _, e := range es {
		if e.Name == "sym" && e.Node.Type != catalog.TypeSymlink {
			t.Fatalf("sym entry = %+v", e.Node)
		}
	}

	// Existing merged names refuse creates.
	if _, err := ov.Create(ctx, rootIno, "base.txt", 0644, 0, 0); !errors.Is(err, overlay.ErrExist) {
		t.Fatalf("create over base name = %v, want ErrExist", err)
	}
	if _, err := ov.Mkdir(ctx, rootIno, "new.txt", 0755, 0, 0); !errors.Is(err, overlay.ErrExist) {
		t.Fatalf("mkdir over overlay name = %v, want ErrExist", err)
	}
}

func TestCOW(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0bbb1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	big := fx.body["big.bin"]
	bigIno := lookupPath(t, ov, "big.bin").Inode
	tail := []byte("appended tail bytes")
	if _, err := ov.Write(ctx, bigIno, int64(len(big)), tail); err != nil {
		t.Fatalf("append: %v", err)
	}
	want := append(append([]byte{}, big...), tail...)
	if ga, err := ov.GetAttr(ctx, bigIno); err != nil || ga.Length != int64(len(want)) {
		t.Fatalf("appended length = %+v (%v)", ga, err)
	}
	if got := readAllFS(t, ov, bigIno, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("appended content mismatch (%d bytes)", len(want))
	}

	// The base generation is untouched: a second plain genfs handle
	// still serves the original bytes and length.
	base2 := openBase(t, fx.inner, fx.res.Superblock)
	bn, err := base2.Lookup(ctx, rootIno, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if bn.Length != int64(len(big)) {
		t.Fatalf("base length changed: %d", bn.Length)
	}
	if got := readAllFS(t, base2, bigIno, len(big)); !bytes.Equal(got, big) {
		t.Fatal("base content changed")
	}

	// Truncate a base file shorter, then another to zero.
	baseTxt := fx.body["base.txt"]
	btIno := lookupPath(t, ov, "base.txt").Inode
	size := int64(10)
	if n, err := ov.SetAttr(ctx, btIno, overlay.SetAttrIn{Size: &size}); err != nil || n.Length != size {
		t.Fatalf("truncate = %+v (%v)", n, err)
	}
	if got := readAllFS(t, ov, btIno, int(size)); !bytes.Equal(got, baseTxt[:size]) {
		t.Fatalf("truncated content = %q", got)
	}
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	zero := int64(0)
	if n, err := ov.SetAttr(ctx, tagIno, overlay.SetAttrIn{Size: &zero}); err != nil || n.Length != 0 {
		t.Fatalf("truncate to zero = %+v (%v)", n, err)
	}
	if k, err := ov.Read(ctx, tagIno, 0, make([]byte, 8)); err != nil || k != 0 {
		t.Fatalf("read of zero-truncated = %d, %v", k, err)
	}
	// Extension past a truncation zero-fills.
	ext := int64(4)
	if _, err := ov.SetAttr(ctx, tagIno, overlay.SetAttrIn{Size: &ext}); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 4)
	if k, err := ov.Read(ctx, tagIno, 0, dst); err != nil || k != 4 || !bytes.Equal(dst, []byte{0, 0, 0, 0}) {
		t.Fatalf("zero-extended read = %q (%d, %v)", dst[:k], k, err)
	}

	// Base still intact for the truncated files too (the second handle
	// needs its own descent before reading).
	if _, err := base2.Lookup(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	if got := readAllFS(t, base2, btIno, len(baseTxt)); !bytes.Equal(got, baseTxt) {
		t.Fatal("base base.txt changed")
	}
}

func TestUnlinkRmdir(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0ccc1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	oldIno := lookupPath(t, ov, "base.txt").Inode
	if err := ov.Unlink(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupPathErr(ov, "base.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("lookup after unlink = %v, want ErrNotExist", err)
	}
	es, err := ov.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"big.bin", "dir", "tagged.txt"})

	// Recreate the same name: a NEW inode with new content, replacing
	// the whiteout; readdir shows exactly one entry.
	n, err := ov.Create(ctx, rootIno, "base.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n.Inode == oldIno {
		t.Fatalf("recreate reused inode %d", n.Inode)
	}
	body := []byte("recreated body")
	if _, err := ov.Write(ctx, n.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	if got := lookupPath(t, ov, "base.txt"); got.Inode != n.Inode || got.Length != int64(len(body)) {
		t.Fatalf("recreated node = %+v", got)
	}
	if got := readAllFS(t, ov, n.Inode, len(body)); !bytes.Equal(got, body) {
		t.Fatalf("recreated content = %q", got)
	}
	es, err = ov.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"base.txt", "big.bin", "dir", "tagged.txt"})

	// Rmdir refuses while the MERGED view is non-empty: base children
	// and an overlay child both count.
	dirIno := lookupPath(t, ov, "dir").Inode
	if _, err := ov.Create(ctx, dirIno, "extra.txt", 0644, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rmdir(ctx, rootIno, "dir"); !errors.Is(err, overlay.ErrNotEmpty) {
		t.Fatalf("rmdir non-empty = %v, want ErrNotEmpty", err)
	}
	if err := ov.Unlink(ctx, dirIno, "extra.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rmdir(ctx, rootIno, "dir"); !errors.Is(err, overlay.ErrNotEmpty) {
		t.Fatalf("rmdir with base children = %v, want ErrNotEmpty", err)
	}
	if err := ov.Unlink(ctx, dirIno, "child.txt"); err != nil {
		t.Fatal(err)
	}
	innerIno := lookupPath(t, ov, "dir/inner").Inode
	if err := ov.Rmdir(ctx, dirIno, "inner"); !errors.Is(err, overlay.ErrNotEmpty) {
		t.Fatalf("rmdir inner with leaf = %v, want ErrNotEmpty", err)
	}
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rmdir(ctx, dirIno, "inner"); err != nil {
		t.Fatalf("rmdir inner: %v", err)
	}
	if err := ov.Rmdir(ctx, rootIno, "dir"); err != nil {
		t.Fatalf("rmdir dir: %v", err)
	}
	if _, err := lookupPathErr(ov, "dir"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("lookup removed dir = %v, want ErrNotExist", err)
	}
	es, err = ov.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"base.txt", "big.bin", "tagged.txt"})

	// Unlink of a directory and rmdir of a file are refused.
	if err := ov.Unlink(ctx, rootIno, "big.bin"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rmdir(ctx, rootIno, "tagged.txt"); !errors.Is(err, overlay.ErrNotDir) {
		t.Fatalf("rmdir of file = %v, want ErrNotDir", err)
	}
}

func TestRename(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0ddd1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	// Overlay file rename.
	on, err := ov.Create(ctx, rootIno, "o.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	oBody := []byte("overlay body")
	if _, err := ov.Write(ctx, on.Inode, 0, oBody); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rename(ctx, rootIno, "o.txt", rootIno, "o2.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupPathErr(ov, "o.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("old overlay name = %v, want ErrNotExist", err)
	}
	if got := lookupPath(t, ov, "o2.txt"); got.Inode != on.Inode {
		t.Fatalf("renamed overlay inode = %d, want %d", got.Inode, on.Inode)
	}
	if got := readAllFS(t, ov, on.Inode, len(oBody)); !bytes.Equal(got, oBody) {
		t.Fatalf("renamed overlay content = %q", got)
	}

	// Base file rename: same stable inode, content readable at the new
	// path, whiteout at the old.
	btIno := lookupPath(t, ov, "base.txt").Inode
	if err := ov.Rename(ctx, rootIno, "base.txt", rootIno, "moved.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupPathErr(ov, "base.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("old base name = %v, want ErrNotExist", err)
	}
	mn := lookupPath(t, ov, "moved.txt")
	if mn.Inode != btIno {
		t.Fatalf("moved inode = %d, want %d", mn.Inode, btIno)
	}
	if got := readAllFS(t, ov, btIno, len(fx.body["base.txt"])); !bytes.Equal(got, fx.body["base.txt"]) {
		t.Fatalf("moved content = %q", got)
	}

	// Base DIRECTORY rename: children remain reachable through the new
	// path (they resolve via the moved inode), old path is gone.
	dirIno := lookupPath(t, ov, "dir").Inode
	if err := ov.Rename(ctx, rootIno, "dir", rootIno, "pivot"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupPathErr(ov, "dir/child.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("old dir path = %v, want ErrNotExist", err)
	}
	if got := lookupPath(t, ov, "pivot"); got.Inode != dirIno || got.Type != catalog.TypeDir {
		t.Fatalf("pivot node = %+v", got)
	}
	child := lookupPath(t, ov, "pivot/child.txt")
	if got := readAllFS(t, ov, child.Inode, len(fx.body["dir/child.txt"])); !bytes.Equal(got, fx.body["dir/child.txt"]) {
		t.Fatalf("pivot child content = %q", got)
	}
	leaf := lookupPath(t, ov, "pivot/inner/leaf.txt")
	if got := readAllFS(t, ov, leaf.Inode, len(fx.body["dir/inner/leaf.txt"])); !bytes.Equal(got, fx.body["dir/inner/leaf.txt"]) {
		t.Fatalf("pivot leaf content = %q", got)
	}
	es, err := ov.Readdir(ctx, lookupPath(t, ov, "pivot").Inode)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"child.txt", "inner"})

	// Rename onto an existing target replaces it atomically.
	vn, err := ov.Create(ctx, rootIno, "victim.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, vn.Inode, 0, []byte("victim body")); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rename(ctx, rootIno, "moved.txt", rootIno, "victim.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := lookupPathErr(ov, "moved.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("moved.txt after replace = %v, want ErrNotExist", err)
	}
	rv := lookupPath(t, ov, "victim.txt")
	if rv.Inode != btIno {
		t.Fatalf("replaced victim inode = %d, want %d", rv.Inode, btIno)
	}
	if got := readAllFS(t, ov, btIno, len(fx.body["base.txt"])); !bytes.Equal(got, fx.body["base.txt"]) {
		t.Fatal("replaced victim content mismatch")
	}

	// Replacing an existing BASE name: the oedge shadows it.
	bigIno := lookupPath(t, ov, "big.bin").Inode
	if err := ov.Rename(ctx, rootIno, "big.bin", rootIno, "tagged.txt"); err != nil {
		t.Fatal(err)
	}
	if got := lookupPath(t, ov, "tagged.txt"); got.Inode != bigIno {
		t.Fatalf("tagged.txt now = %d, want %d", got.Inode, bigIno)
	}
	es, err = ov.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	wantNames(t, es, []string{"o2.txt", "pivot", "tagged.txt", "victim.txt"})

	// Directory-onto-file and file-onto-directory are refused.
	if err := ov.Rename(ctx, rootIno, "pivot", rootIno, "victim.txt"); !errors.Is(err, overlay.ErrNotDir) {
		t.Fatalf("dir onto file = %v, want ErrNotDir", err)
	}
	if err := ov.Rename(ctx, rootIno, "victim.txt", rootIno, "pivot"); !errors.Is(err, overlay.ErrIsDir) {
		t.Fatalf("file onto dir = %v, want ErrIsDir", err)
	}
	if err := ov.Rename(ctx, rootIno, "victim.txt", lookupPath(t, ov, "pivot").Inode, "child.txt"); err != nil {
		t.Fatalf("file replace across dirs: %v", err)
	}
}

func TestHardlink(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0eee1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	btIno := lookupPath(t, ov, "base.txt").Inode
	ln, err := ov.Link(ctx, btIno, rootIno, "hard2.txt")
	if err != nil {
		t.Fatal(err)
	}
	if ln.Inode != btIno || ln.Nlink != 2 {
		t.Fatalf("link node = %+v", ln)
	}
	if got := lookupPath(t, ov, "base.txt"); got.Nlink != 2 {
		t.Fatalf("original path nlink = %d, want 2", got.Nlink)
	}
	if got := lookupPath(t, ov, "hard2.txt"); got.Inode != btIno || got.Nlink != 2 {
		t.Fatalf("link path node = %+v", got)
	}
	body := fx.body["base.txt"]
	if got := readAllFS(t, ov, btIno, len(body)); !bytes.Equal(got, body) {
		t.Fatal("hardlink content mismatch")
	}

	// Unlinking one path drops nlink; the other still resolves.
	if err := ov.Unlink(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	if got := lookupPath(t, ov, "hard2.txt"); got.Nlink != 1 {
		t.Fatalf("after unlink nlink = %d, want 1", got.Nlink)
	}
	if got := readAllFS(t, ov, btIno, len(body)); !bytes.Equal(got, body) {
		t.Fatal("survivor content mismatch")
	}

	// Directories refuse hardlinks.
	dirIno := lookupPath(t, ov, "dir").Inode
	if _, err := ov.Link(ctx, dirIno, rootIno, "dirlink"); !errors.Is(err, overlay.ErrIsDir) {
		t.Fatalf("link of dir = %v, want ErrIsDir", err)
	}
}

func TestXattr(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "0fff1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	tagIno := lookupPath(t, ov, "tagged.txt").Inode

	// Set new, overwrite base, remove base (tombstone).
	if err := ov.SetXattr(ctx, tagIno, "user.new", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	if err := ov.SetXattr(ctx, tagIno, "user.color", []byte("red")); err != nil {
		t.Fatal(err)
	}
	if err := ov.RemoveXattr(ctx, tagIno, "user.keep"); err != nil {
		t.Fatal(err)
	}
	if v, err := ov.GetXattr(ctx, tagIno, "user.new"); err != nil || string(v) != "fresh" {
		t.Fatalf("user.new = %q (%v)", v, err)
	}
	if v, err := ov.GetXattr(ctx, tagIno, "user.color"); err != nil || string(v) != "red" {
		t.Fatalf("user.color = %q (%v)", v, err)
	}
	if _, err := ov.GetXattr(ctx, tagIno, "user.keep"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("removed base xattr = %v, want ErrNotExist", err)
	}
	names, err := ov.ListXattr(ctx, tagIno)
	if err != nil || !reflect.DeepEqual(names, []string{"user.color", "user.new"}) {
		t.Fatalf("listxattr = %v (%v)", names, err)
	}
	// Removing again reports absence; removing an overlay-only xattr
	// deletes its row outright.
	if err := ov.RemoveXattr(ctx, tagIno, "user.keep"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("re-remove = %v, want ErrNotExist", err)
	}
	if err := ov.RemoveXattr(ctx, tagIno, "user.new"); err != nil {
		t.Fatal(err)
	}
	if names, err := ov.ListXattr(ctx, tagIno); err != nil || !reflect.DeepEqual(names, []string{"user.color"}) {
		t.Fatalf("listxattr after remove = %v (%v)", names, err)
	}

	// Overlay-new files have only overlay xattrs.
	n, err := ov.Create(ctx, rootIno, "n.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.SetXattr(ctx, n.Inode, "user.mine", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if names, err := ov.ListXattr(ctx, n.Inode); err != nil || !reflect.DeepEqual(names, []string{"user.mine"}) {
		t.Fatalf("new file listxattr = %v (%v)", names, err)
	}
}

// mergedView walks the whole overlay and captures identity, shape, and
// content of every entry — the reopen test's equality subject.
func mergedView(t *testing.T, ov *overlay.FS) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(ino uint64, prefix string)
	walk = func(ino uint64, prefix string) {
		es, err := ov.Readdir(context.Background(), ino)
		if err != nil {
			t.Fatalf("readdir %s: %v", prefix, err)
		}
		for _, e := range es {
			p := prefix + "/" + e.Name
			desc := fmt.Sprintf("ino=%d type=%d len=%d mode=%o nlink=%d",
				e.Node.Inode, e.Node.Type, e.Node.Length, e.Node.Mode, e.Node.Nlink)
			switch e.Node.Type {
			case catalog.TypeDir:
				// Lookup keeps the kernel descent contract before
				// touching the child's entries.
				if _, err := ov.Lookup(context.Background(), ino, e.Name); err != nil {
					t.Fatalf("lookup %s: %v", p, err)
				}
				walk(e.Node.Inode, p)
			case catalog.TypeFile:
				if _, err := ov.Lookup(context.Background(), ino, e.Name); err != nil {
					t.Fatalf("lookup %s: %v", p, err)
				}
				body := readAllFS(t, ov, e.Node.Inode, int(e.Node.Length))
				desc += fmt.Sprintf(" body=%x", body)
			}
			out[p] = desc
		}
	}
	walk(rootIno, "")
	return out
}

func TestReopenAndGeneration(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "1aaa1111-2222-3333-4444-555566667777")
	dir := t.TempDir()
	ov := openOverlay(t, fx, dir)

	// A batch of every mutation kind.
	n, err := ov.Create(ctx, rootIno, "n.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte("new body")); err != nil {
		t.Fatal(err)
	}
	bigIno := lookupPath(t, ov, "big.bin").Inode
	if _, err := ov.Write(ctx, bigIno, int64(len(fx.body["big.bin"])), []byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rename(ctx, rootIno, "dir", rootIno, "pivot"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	if err := ov.SetXattr(ctx, tagIno, "user.new", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := ov.RemoveXattr(ctx, tagIno, "user.keep"); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0700)
	if _, err := ov.SetAttr(ctx, tagIno, overlay.SetAttrIn{Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	before := mergedView(t, ov)
	dirtyBefore, err := ov.Dirty()
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}

	// Fresh Open over the same base: the dirty state survived and the
	// merged view is identical (this replays persisted base-edge chains
	// for the renamed directory's descent).
	ov2 := openOverlay(t, fx, dir)
	after := mergedView(t, ov2)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("merged view changed across reopen:\nbefore: %v\nafter:  %v", before, after)
	}
	if v, err := ov2.GetXattr(ctx, tagIno, "user.new"); err != nil || string(v) != "v" {
		t.Fatalf("xattr after reopen = %q (%v)", v, err)
	}
	if _, err := ov2.GetXattr(ctx, tagIno, "user.keep"); !errors.Is(err, overlay.ErrNotExist) {
		t.Fatalf("tombstone after reopen = %v, want ErrNotExist", err)
	}
	dirtyAfter, err := ov2.Dirty()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dirtyBefore, dirtyAfter) {
		t.Fatal("dirty report changed across reopen")
	}
	// New allocations continue past the persisted counter, never reusing.
	n2, err := ov2.Create(ctx, rootIno, "n2.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Inode <= n.Inode {
		t.Fatalf("inode reuse across reopen: %d after %d", n2.Inode, n.Inode)
	}
	if err := ov2.Close(); err != nil {
		t.Fatal(err)
	}

	// A DIFFERENT generation refuses the overlay directory outright.
	fx2 := newFixture(t, "1bbb1111-2222-3333-4444-555566667777")
	if _, err := overlay.Open(dir, fx2.base, fx2.options()); !errors.Is(err, overlay.ErrGeneration) {
		t.Fatalf("open over different generation = %v, want ErrGeneration", err)
	}
}

func TestDirty(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "1ccc1111-2222-3333-4444-555566667777")
	ov := openOverlay(t, fx, "")

	bigIno := lookupPath(t, ov, "big.bin").Inode
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	dirIno := lookupPath(t, ov, "dir").Inode

	n, err := ov.Create(ctx, rootIno, "n.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	nBody := []byte("fresh")
	if _, err := ov.Write(ctx, n.Inode, 0, nBody); err != nil {
		t.Fatal(err)
	}
	tail := []byte("tail")
	if _, err := ov.Write(ctx, bigIno, int64(len(fx.body["big.bin"])), tail); err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rename(ctx, rootIno, "dir", rootIno, "pivot"); err != nil {
		t.Fatal(err)
	}
	if err := ov.SetXattr(ctx, tagIno, "user.new", []byte("v")); err != nil {
		t.Fatal(err)
	}
	sym, err := ov.Symlink(ctx, rootIno, "s", "n.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := ov.Dirty()
	if err != nil {
		t.Fatal(err)
	}

	// Edges: exactly the touched names, ordered by (parent, name).
	wantEdges := []overlay.DirtyEdge{
		{Parent: rootIno, Name: "base.txt", Inode: 0, Type: 0}, // whiteout
		{Parent: rootIno, Name: "dir", Inode: 0, Type: 0},      // whiteout
		{Parent: rootIno, Name: "n.txt", Inode: n.Inode, Type: catalog.TypeFile},
		{Parent: rootIno, Name: "pivot", Inode: dirIno, Type: catalog.TypeDir},
		{Parent: rootIno, Name: "s", Inode: sym.Inode, Type: catalog.TypeSymlink},
	}
	if !reflect.DeepEqual(rep.Edges, wantEdges) {
		t.Fatalf("dirty edges = %+v, want %+v", rep.Edges, wantEdges)
	}

	// Nodes: the COW'd base file, the new file, the new symlink —
	// ascending by inode; base flag distinguishes modified from new.
	if len(rep.Nodes) != 3 {
		t.Fatalf("dirty nodes = %+v", rep.Nodes)
	}
	if rep.Nodes[0].Node.Inode != bigIno || !rep.Nodes[0].Base {
		t.Fatalf("nodes[0] = %+v, want modified base inode %d", rep.Nodes[0], bigIno)
	}
	if rep.Nodes[0].Node.Length != int64(len(fx.body["big.bin"])+len(tail)) {
		t.Fatalf("nodes[0] length = %d", rep.Nodes[0].Node.Length)
	}
	if rep.Nodes[1].Node.Inode != n.Inode || rep.Nodes[1].Base {
		t.Fatalf("nodes[1] = %+v, want new inode %d", rep.Nodes[1], n.Inode)
	}
	if rep.Nodes[2].Node.Inode != sym.Inode || rep.Nodes[2].Base {
		t.Fatalf("nodes[2] = %+v, want new symlink %d", rep.Nodes[2], sym.Inode)
	}

	wantX := []overlay.DirtyXattr{{Inode: tagIno, Name: "user.new", Value: []byte("v")}}
	if !reflect.DeepEqual(rep.Xattrs, wantX) {
		t.Fatalf("dirty xattrs = %+v, want %+v", rep.Xattrs, wantX)
	}
	wantS := []overlay.DirtySymlink{{Inode: sym.Inode, Target: "n.txt"}}
	if !reflect.DeepEqual(rep.Symlinks, wantS) {
		t.Fatalf("dirty symlinks = %+v, want %+v", rep.Symlinks, wantS)
	}
	if !reflect.DeepEqual(rep.Content, []uint64{bigIno, n.Inode}) {
		t.Fatalf("dirty content = %v, want [%d %d]", rep.Content, bigIno, n.Inode)
	}

	// Deterministic: a second enumeration is byte-identical.
	rep2, err := ov.Dirty()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rep, rep2) {
		t.Fatal("Dirty() is not deterministic")
	}

	s, err := ov.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.DirtyNodes != 3 || s.StagedFiles != 2 || s.DirtyEdges != len(wantEdges) {
		t.Fatalf("stats = %+v", s)
	}
	if want := int64(len(fx.body["big.bin"]) + len(tail) + len(nBody)); s.StagedBytes != want {
		t.Fatalf("staged bytes = %d, want %d", s.StagedBytes, want)
	}
}

// The accessors exist to replace consumer workarounds; each is checked
// against the behavior it replaces.
func TestAccessors(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "acce5501-0000-4000-8000-000000000001")
	ov := openOverlay(t, fx, t.TempDir())

	// NextInode advances past created inodes and SURVIVES deletion — the
	// tree-walk reconstruction seal used cannot see burned numbers.
	start, err := ov.NextInode()
	if err != nil {
		t.Fatalf("NextInode: %v", err)
	}
	n, err := ov.Create(ctx, 1, "burned.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, 1, "burned.txt"); err != nil {
		t.Fatal(err)
	}
	after, err := ov.NextInode()
	if err != nil {
		t.Fatal(err)
	}
	if after <= start || after <= n.Inode {
		t.Fatalf("NextInode = %d after burning inode %d (was %d); must never reuse", after, n.Inode, start)
	}

	// IsDirty: a clean base inode is clean, and writing it makes it dirty.
	base := lookupPath(t, ov, "base.txt")
	dirty, err := ov.IsDirty(base.Inode)
	if err != nil {
		t.Fatal(err)
	}
	if dirty {
		t.Fatal("untouched base inode reports dirty")
	}
	if _, err := ov.Write(ctx, base.Inode, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if dirty, err = ov.IsDirty(base.Inode); err != nil || !dirty {
		t.Fatalf("written inode dirty=%v err=%v, want dirty", dirty, err)
	}

	// AllXattrs matches ListXattr+GetXattr, tombstones honored.
	if err := ov.SetXattr(ctx, base.Inode, "user.a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := ov.SetXattr(ctx, base.Inode, "user.b", []byte("2")); err != nil {
		t.Fatal(err)
	}
	if err := ov.RemoveXattr(ctx, base.Inode, "user.a"); err != nil {
		t.Fatal(err)
	}
	all, err := ov.AllXattrs(ctx, base.Inode)
	if err != nil {
		t.Fatalf("AllXattrs: %v", err)
	}
	names, err := ov.ListXattr(ctx, base.Inode)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(names) {
		t.Fatalf("AllXattrs has %d entries, ListXattr %d", len(all), len(names))
	}
	if _, gone := all["user.a"]; gone {
		t.Fatal("AllXattrs returned a tombstoned attribute")
	}
	if string(all["user.b"]) != "2" {
		t.Fatalf("AllXattrs[user.b] = %q, want 2", all["user.b"])
	}

	// OpenFile streams the merged content exactly.
	big, err := ov.Create(ctx, 1, "stream.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("streaming!"), 5000)
	if _, err := ov.Write(ctx, big.Inode, 0, want); err != nil {
		t.Fatal(err)
	}
	rc, err := ov.OpenFile(ctx, big.Inode, int64(len(want)))
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close() //nolint:errcheck
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("streamed %d bytes, want %d", len(got), len(want))
	}
}
