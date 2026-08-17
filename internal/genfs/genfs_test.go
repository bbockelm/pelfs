package genfs_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

const rootIno = genfs.RootInode

// newInner starts a fakeorigin-backed pelicanobj store rooted at /vol (the
// publish test pattern) and also returns the on-disk volume directory so
// tests can delete pack objects to prove cache hits.
func newInner(t testing.TB) (pelicanobj.Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner, filepath.Join(root, "vol")
}

// testVolume is a live JuiceFS volume the tests mutate and cut (the
// publish test pattern).
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
		Name:      "genfs-test",
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

func (v *testVolume) link(ino, parent uint64, name string) {
	v.t.Helper()
	var attr meta.Attr
	if st := v.m.Link(v.ctx(), meta.Ino(ino), meta.Ino(parent), name, &attr); st != 0 {
		v.t.Fatalf("link %s: %s", name, st)
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

// pseudorandom returns deterministic incompressible content.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// publishVolume cuts v and publishes it through inner, filling in the
// boilerplate options.
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

// openFS opens a genfs over the published superblock with a fresh cache dir.
func openFS(t testing.TB, inner pelicanobj.Store, sb *superblock.Superblock, o genfs.Options) *genfs.FS {
	t.Helper()
	o.Inner = inner
	o.SB = sb
	if o.CacheDir == "" {
		o.CacheDir = t.TempDir()
	}
	fs, err := genfs.Open(context.Background(), o)
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

func entryNames(es []genfs.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
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

// readAll reads a file through fs.Read in bufSize pieces.
func readAll(t *testing.T, fs *genfs.FS, ino uint64, length int, bufSize int) []byte {
	t.Helper()
	out := make([]byte, 0, length)
	buf := make([]byte, bufSize)
	for off := 0; off < length; {
		n, err := fs.Read(context.Background(), ino, int64(off), buf)
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

func TestDescentReaddir(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b")

	bigContent := pseudorandom(8<<20, 42)
	smallContent := []byte("hello inline world, generation zero")
	hardContent := pseudorandom(100, 7)

	dirIno := v.mkdir(rootIno, "dir")
	smallIno := v.create(dirIno, "small.txt")
	v.write(smallIno, smallContent)
	v.setxattr(smallIno, "user.color", []byte("blue"))
	v.symlink(dirIno, "link", "small.txt")
	bigIno := v.create(rootIno, "big.bin")
	v.write(bigIno, bigContent)
	hardIno := v.create(rootIno, "hard1")
	v.write(hardIno, hardContent)
	v.link(hardIno, dirIno, "hard2")

	// SMax 1000 forces /dir into a nested catalog: the descent crosses a
	// transition point.
	res := publishVolume(t, v, inner, publish.Options{SMax: 1000, TargetPackSize: 2 << 20})
	if res.Stats.Catalogs < 2 {
		t.Fatalf("fixture did not split: %d catalogs", res.Stats.Catalogs)
	}
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	// Root listing: full merged listing, transition dir present with attrs.
	root, err := fs.Readdir(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entryNames(root), []string{"big.bin", "dir", "hard1"}; !equalStrings(got, want) {
		t.Fatalf("root readdir = %v, want %v", got, want)
	}
	for _, e := range root {
		switch e.Name {
		case "big.bin":
			if e.Node.Inode != bigIno || e.Node.Type != catalog.TypeFile || e.Node.Length != int64(len(bigContent)) {
				t.Fatalf("big.bin entry = %+v", e.Node)
			}
		case "dir":
			if e.Node.Inode != dirIno || e.Node.Type != catalog.TypeDir {
				t.Fatalf("dir entry = %+v", e.Node)
			}
		case "hard1":
			if e.Node.Inode != hardIno || e.Node.Nlink != 2 || e.Node.Length != int64(len(hardContent)) {
				t.Fatalf("hard1 entry = %+v", e.Node)
			}
		}
	}

	// Descent through the transition point.
	dirNode, err := fs.Lookup(ctx, rootIno, "dir")
	if err != nil {
		t.Fatalf("lookup dir: %v", err)
	}
	if dirNode.Inode != dirIno || dirNode.Type != catalog.TypeDir {
		t.Fatalf("dir node = %+v", dirNode)
	}
	if ga, err := fs.GetAttr(ctx, dirIno); err != nil || ga != dirNode {
		t.Fatalf("GetAttr(dir) = %+v (%v), want %+v", ga, err, dirNode)
	}
	smallNode, err := fs.Lookup(ctx, dirIno, "small.txt")
	if err != nil {
		t.Fatalf("lookup small.txt: %v", err)
	}
	if smallNode.Inode != smallIno || smallNode.Length != int64(len(smallContent)) || smallNode.Type != catalog.TypeFile {
		t.Fatalf("small.txt node = %+v", smallNode)
	}
	if ga, err := fs.GetAttr(ctx, smallIno); err != nil || ga != smallNode {
		t.Fatalf("GetAttr(small.txt) = %+v (%v), want %+v", ga, err, smallNode)
	}
	inside, err := fs.Readdir(ctx, dirIno)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entryNames(inside), []string{"hard2", "link", "small.txt"}; !equalStrings(got, want) {
		t.Fatalf("dir readdir = %v, want %v", got, want)
	}
	for _, e := range inside {
		if e.Name == "link" && e.Node.Type != catalog.TypeSymlink {
			t.Fatalf("link entry = %+v", e.Node)
		}
		if e.Name == "hard2" && (e.Node.Inode != hardIno || e.Node.Nlink != 2) {
			t.Fatalf("hard2 entry = %+v", e.Node)
		}
	}

	if _, err := fs.Lookup(ctx, rootIno, "nope"); !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("lookup of a missing name = %v, want ErrNotExist", err)
	}
}

func TestErrStale(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "11112222-3333-4444-5555-666677778888")
	dirIno := v.mkdir(rootIno, "d")
	fIno := v.create(dirIno, "f")
	v.write(fIno, []byte("payload"))

	res := publishVolume(t, v, inner, publish.Options{})
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	// Valid inode, never looked up: stale.
	if _, err := fs.GetAttr(ctx, dirIno); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("GetAttr before lookup = %v, want ErrStale", err)
	}
	if _, err := fs.Lookup(ctx, rootIno, "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.GetAttr(ctx, dirIno); err != nil {
		t.Fatalf("GetAttr after lookup: %v", err)
	}

	// nlookup accounting: two lookups need two forgets.
	if _, err := fs.Lookup(ctx, dirIno, "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, dirIno, "f"); err != nil {
		t.Fatal(err)
	}
	fs.Forget(fIno, 1)
	if _, err := fs.GetAttr(ctx, fIno); err != nil {
		t.Fatalf("GetAttr with one reference left: %v", err)
	}
	fs.Forget(fIno, 1)
	if _, err := fs.GetAttr(ctx, fIno); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("GetAttr after matching forgets = %v, want ErrStale", err)
	}
	if _, err := fs.Read(ctx, fIno, 0, make([]byte, 4)); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("Read after forget = %v, want ErrStale", err)
	}

	// Re-lookup revives.
	if _, err := fs.Lookup(ctx, dirIno, "f"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.GetAttr(ctx, fIno); err != nil {
		t.Fatalf("GetAttr after re-lookup: %v", err)
	}

	// Forgetting the parent stales operations under it too.
	fs.Forget(dirIno, 1)
	if _, err := fs.Readdir(ctx, dirIno); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("Readdir on forgotten dir = %v, want ErrStale", err)
	}
	if _, err := fs.Lookup(ctx, dirIno, "f"); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("Lookup under forgotten dir = %v, want ErrStale", err)
	}

	// Root has implicit permanent residency; Forget is a no-op.
	fs.Forget(rootIno, 99)
	if _, err := fs.GetAttr(ctx, rootIno); err != nil {
		t.Fatalf("GetAttr(root) after forget: %v", err)
	}
}

func TestReadAndChunkCache(t *testing.T) {
	ctx := context.Background()
	inner, volDir := newInner(t)
	v := newTestVolume(t, "aaaa1111-2222-3333-4444-555566667777")

	bigContent := pseudorandom(8<<20, 99)
	smallContent := []byte("tiny inline body")
	bigIno := v.create(rootIno, "big.bin")
	v.write(bigIno, bigContent)
	smallIno := v.create(rootIno, "small.txt")
	v.write(smallIno, smallContent)

	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 2 << 20})
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	if _, err := fs.Lookup(ctx, rootIno, "big.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, rootIno, "small.txt"); err != nil {
		t.Fatal(err)
	}

	// Sequential 1 MiB reads, byte-exact.
	if got := readAll(t, fs, bigIno, len(bigContent), 1<<20); !bytes.Equal(got, bigContent) {
		t.Fatalf("sequential read mismatch (%d bytes)", len(got))
	}

	// Random-offset reads straddling chunk boundaries.
	rng := mrand.New(mrand.NewSource(5))
	for i := 0; i < 50; i++ {
		off := rng.Int63n(int64(len(bigContent)))
		l := 1 + rng.Intn(3<<20)
		dst := make([]byte, l)
		n, err := fs.Read(ctx, bigIno, off, dst)
		if err != nil {
			t.Fatalf("random read %d at %d: %v", i, off, err)
		}
		want := int64(l)
		if off+want > int64(len(bigContent)) {
			want = int64(len(bigContent)) - off
		}
		if int64(n) != want {
			t.Fatalf("random read %d at %d: n = %d, want %d", i, off, n, want)
		}
		if !bytes.Equal(dst[:n], bigContent[off:off+int64(n)]) {
			t.Fatalf("random read %d at %d: content mismatch", i, off)
		}
	}

	// Reads at and past EOF return 0.
	if n, err := fs.Read(ctx, bigIno, int64(len(bigContent)), make([]byte, 16)); err != nil || n != 0 {
		t.Fatalf("read at EOF = %d, %v", n, err)
	}
	if n, err := fs.Read(ctx, bigIno, int64(len(bigContent))+1000, make([]byte, 16)); err != nil || n != 0 {
		t.Fatalf("read past EOF = %d, %v", n, err)
	}

	// Inline file, whole and windowed.
	if got := readAll(t, fs, smallIno, len(smallContent), 64); !bytes.Equal(got, smallContent) {
		t.Fatalf("inline read = %q", got)
	}
	dst := make([]byte, 6)
	if n, err := fs.Read(ctx, smallIno, 5, dst); err != nil || !bytes.Equal(dst[:n], smallContent[5:11]) {
		t.Fatalf("inline window = %q (%v)", dst[:n], err)
	}

	// Second read is served from the decoded-chunk cache: delete every
	// pack object from the fakeorigin directory first — a cache hit must
	// not touch the store.
	if err := os.RemoveAll(filepath.Join(volDir, "packs")); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, bigIno, len(bigContent), 1<<20); !bytes.Equal(got, bigContent) {
		t.Fatalf("cached re-read mismatch (%d bytes)", len(got))
	}
}

func TestHardlinks(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "bbbb1111-2222-3333-4444-555566667777")

	bigContent := pseudorandom(3<<20, 21)
	smallContent := []byte("small hardlinked body")
	dirIno := v.mkdir(rootIno, "d")
	bigIno := v.create(rootIno, "hardbig")
	v.write(bigIno, bigContent)
	v.link(bigIno, dirIno, "hardbig2")
	smallIno := v.create(rootIno, "hardsmall")
	v.write(smallIno, smallContent)
	v.setxattr(smallIno, "user.tag", []byte("shared"))
	v.link(smallIno, dirIno, "hardsmall2")

	res := publishVolume(t, v, inner, publish.Options{})
	if res.Stats.PromotedInodes != 2 {
		t.Fatalf("promoted %d inodes, want 2", res.Stats.PromotedInodes)
	}
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	n1, err := fs.Lookup(ctx, rootIno, "hardbig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, rootIno, "d"); err != nil {
		t.Fatal(err)
	}
	n2, err := fs.Lookup(ctx, dirIno, "hardbig2")
	if err != nil {
		t.Fatal(err)
	}
	if n1.Inode != n2.Inode || n1.Inode != bigIno {
		t.Fatalf("hardlink inodes differ: %d vs %d", n1.Inode, n2.Inode)
	}
	if n1.Nlink != 2 || n2.Nlink != 2 {
		t.Fatalf("nlink = %d/%d, want 2", n1.Nlink, n2.Nlink)
	}

	// Content routes through the inode shard: chunked and inline.
	if got := readAll(t, fs, bigIno, len(bigContent), 1<<20); !bytes.Equal(got, bigContent) {
		t.Fatalf("shard chunked content mismatch (%d bytes)", len(got))
	}
	if _, err := fs.Lookup(ctx, rootIno, "hardsmall"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, smallIno, len(smallContent), 64); !bytes.Equal(got, smallContent) {
		t.Fatalf("shard inline content = %q", got)
	}
	// Promoted files' xattrs live in the shard too.
	if val, err := fs.GetXattr(ctx, smallIno, "user.tag"); err != nil || string(val) != "shared" {
		t.Fatalf("promoted xattr = %q (%v)", val, err)
	}
}

func TestSymlinkXattr(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "cccc1111-2222-3333-4444-555566667777")

	dirIno := v.mkdir(rootIno, "d")
	smallIno := v.create(dirIno, "small.txt")
	v.write(smallIno, []byte("body"))
	v.setxattr(smallIno, "user.color", []byte("blue"))
	linkIno := v.symlink(dirIno, "link", "small.txt")

	res := publishVolume(t, v, inner, publish.Options{})
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	if _, err := fs.Lookup(ctx, rootIno, "d"); err != nil {
		t.Fatal(err)
	}
	ln, err := fs.Lookup(ctx, dirIno, "link")
	if err != nil {
		t.Fatal(err)
	}
	if ln.Inode != linkIno || ln.Type != catalog.TypeSymlink {
		t.Fatalf("link node = %+v", ln)
	}
	if target, err := fs.Readlink(ctx, linkIno); err != nil || target != "small.txt" {
		t.Fatalf("readlink = %q (%v)", target, err)
	}

	if _, err := fs.Lookup(ctx, dirIno, "small.txt"); err != nil {
		t.Fatal(err)
	}
	if val, err := fs.GetXattr(ctx, smallIno, "user.color"); err != nil || string(val) != "blue" {
		t.Fatalf("getxattr = %q (%v)", val, err)
	}
	if _, err := fs.GetXattr(ctx, smallIno, "user.missing"); !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("missing xattr = %v, want ErrNotExist", err)
	}
	if names, err := fs.ListXattr(ctx, smallIno); err != nil || !equalStrings(names, []string{"user.color"}) {
		t.Fatalf("listxattr = %v (%v)", names, err)
	}
	if names, err := fs.ListXattr(ctx, linkIno); err != nil || len(names) != 0 {
		t.Fatalf("listxattr on the symlink = %v (%v)", names, err)
	}
}

func TestEncrypted(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "dddd1111-2222-3333-4444-555566667777")

	secret := []byte("the inline secret")
	blob := pseudorandom(3<<20, 33)
	dirIno := v.mkdir(rootIno, "enc")
	secretIno := v.create(dirIno, "secret.txt")
	v.write(secretIno, secret)
	blobIno := v.create(rootIno, "blob.bin")
	v.write(blobIno, blob)

	dek := pseudorandom(32, 1)
	idKey := pseudorandom(32, 2)
	res := publishVolume(t, v, inner, publish.Options{
		IdentityKey: idKey,
		DEK:         dek,
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})

	// The right DEK decodes the whole tree.
	fs := openFS(t, inner, res.Superblock, genfs.Options{DEK: dek})
	if _, err := fs.Lookup(ctx, rootIno, "enc"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, dirIno, "secret.txt"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, secretIno, len(secret), 64); !bytes.Equal(got, secret) {
		t.Fatalf("secret = %q", got)
	}
	if _, err := fs.Lookup(ctx, rootIno, "blob.bin"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, blobIno, len(blob), 1<<20); !bytes.Equal(got, blob) {
		t.Fatalf("encrypted blob mismatch (%d bytes)", len(got))
	}

	// A wrong DEK fails at Open, on the root catalog's GCM open.
	if _, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: res.Superblock, DEK: pseudorandom(32, 1234), CacheDir: t.TempDir(),
	}); err == nil {
		t.Fatal("Open with the wrong DEK succeeded")
	}
	// No DEK at all is rejected up front.
	if _, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	}); err == nil {
		t.Fatal("Open without a DEK succeeded on an encrypted volume")
	}
}

func TestCatalogLRU(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "eeee1111-2222-3333-4444-555566667777")

	faContent := pseudorandom(2500, 11)
	fbContent := pseudorandom(2500, 12)
	aIno := v.mkdir(rootIno, "a")
	bIno := v.mkdir(rootIno, "b")
	faIno := v.create(aIno, "fa")
	v.write(faIno, faContent)
	fbIno := v.create(bIno, "fb")
	v.write(fbIno, fbContent)

	// SMax 1000 peels both /a and /b: a 3-catalog tree.
	res := publishVolume(t, v, inner, publish.Options{SMax: 1000})
	if res.Stats.Catalogs != 3 {
		t.Fatalf("fixture built %d catalogs, want 3", res.Stats.Catalogs)
	}

	// One open handle (the pinned root is separate) must still walk the
	// whole tree via evict/reopen.
	fs := openFS(t, inner, res.Superblock, genfs.Options{MaxOpenCatalogs: 1})

	if got, err := fs.Readdir(ctx, rootIno); err != nil || !equalStrings(entryNames(got), []string{"a", "b"}) {
		t.Fatalf("root readdir = %v (%v)", entryNames(got), err)
	}
	if _, err := fs.Lookup(ctx, rootIno, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Lookup(ctx, rootIno, "b"); err != nil {
		t.Fatal(err)
	}
	if got, err := fs.Readdir(ctx, aIno); err != nil || !equalStrings(entryNames(got), []string{"fa"}) {
		t.Fatalf("a readdir = %v (%v)", entryNames(got), err)
	}
	if _, err := fs.Lookup(ctx, aIno, "fa"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, faIno, len(faContent), 512); !bytes.Equal(got, faContent) {
		t.Fatalf("fa content mismatch")
	}
	if got, err := fs.Readdir(ctx, bIno); err != nil || !equalStrings(entryNames(got), []string{"fb"}) {
		t.Fatalf("b readdir = %v (%v)", entryNames(got), err)
	}
	if _, err := fs.Lookup(ctx, bIno, "fb"); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, fbIno, len(fbContent), 512); !bytes.Equal(got, fbContent) {
		t.Fatalf("fb content mismatch")
	}
	// Bounce back to a's catalog (evicted by b's) and forward again.
	if _, err := fs.GetAttr(ctx, faIno); err != nil {
		t.Fatalf("GetAttr(fa) after eviction: %v", err)
	}
	if got := readAll(t, fs, faIno, len(faContent), 512); !bytes.Equal(got, faContent) {
		t.Fatalf("fa re-read mismatch")
	}
	if got, err := fs.Readdir(ctx, bIno); err != nil || !equalStrings(entryNames(got), []string{"fb"}) {
		t.Fatalf("b re-readdir = %v (%v)", entryNames(got), err)
	}
}

// Parent answers "..", LookupPath re-attaches by path, and the
// generation accessors expose what a writer layered above needs.
func TestParentLookupPathAndAccessors(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "abcdabcd-0000-4000-8000-0000000000aa")
	dir := v.mkdir(1, "d")
	sub := v.mkdir(dir, "sub")
	fileIno := v.create(sub, "f.txt")
	v.write(fileIno, []byte("hello"))
	res := publishVolume(t, v, inner, publish.Options{})
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	// Root is its own parent; unlooked-up inodes are stale.
	if p, err := fs.Parent(genfs.RootInode); err != nil || p != genfs.RootInode {
		t.Fatalf("Parent(root) = %d, %v; want root, nil", p, err)
	}
	if _, err := fs.Parent(fileIno); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("Parent of never-looked-up inode = %v, want ErrStale", err)
	}

	// LookupPath establishes residency the whole way down.
	node, err := fs.LookupPath(ctx, "/d/sub/f.txt")
	if err != nil {
		t.Fatalf("LookupPath: %v", err)
	}
	if node.Inode != fileIno || node.Length != 5 {
		t.Fatalf("LookupPath node = %+v, want inode %d length 5", node, fileIno)
	}
	// ..-chain walks back to the root.
	p, err := fs.Parent(node.Inode)
	if err != nil || p != sub {
		t.Fatalf("Parent(f.txt) = %d, %v; want %d", p, err, sub)
	}
	if p, err = fs.Parent(p); err != nil || p != dir {
		t.Fatalf("Parent(sub) = %d, %v; want %d", p, err, dir)
	}
	if p, err = fs.Parent(p); err != nil || p != genfs.RootInode {
		t.Fatalf("Parent(d) = %d, %v; want root", p, err)
	}
	if _, err := fs.LookupPath(ctx, "/d/nope"); !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("LookupPath(missing) = %v, want ErrNotExist", err)
	}

	if got := fs.Generation(); got != res.Superblock.Generation {
		t.Fatalf("Generation = %d, want %d", got, res.Superblock.Generation)
	}
	if got := fs.RootCatalog(); got != res.Superblock.RootCatalog {
		t.Fatalf("RootCatalog mismatch")
	}
	if got := fs.NextInode(); got != res.Superblock.NextInode || got <= fileIno {
		t.Fatalf("NextInode = %d, want %d (> %d)", got, res.Superblock.NextInode, fileIno)
	}
	bytes, inodes := fs.Usage()
	if bytes <= 0 || inodes != res.Superblock.NextInode {
		t.Fatalf("Usage = %d bytes, %d inodes; want positive bytes and NextInode", bytes, inodes)
	}
}

// A generation swap must invalidate exactly what changed and nothing
// else: stable inodes are the reason an unchanged file's cached dentry
// and attributes stay valid across a publish.
func TestGenerationSwap(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "5eaf5eaf-0000-4000-8000-000000000055")
	dir := v.mkdir(1, "d")
	stableIno := v.create(dir, "stable.txt")
	v.write(stableIno, []byte("unchanged across generations"))
	changedIno := v.create(dir, "changed.txt")
	v.write(changedIno, []byte("v1"))
	doomedIno := v.create(dir, "doomed.txt")
	v.write(doomedIno, []byte("deleted next generation"))
	gen0 := publishVolume(t, v, inner, publish.Options{})

	fs := openFS(t, inner, gen0.Superblock, genfs.Options{})
	// The kernel walks the tree: everything below is now resident.
	dirNode, err := fs.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stable.txt", "changed.txt", "doomed.txt"} {
		if _, err := fs.Lookup(ctx, dirNode.Inode, name); err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
	}

	// Second generation: change one file, delete another, add a third.
	v.write(changedIno, []byte("v2 is longer than v1"))
	if st := v.m.Unlink(v.ctx(), meta.Ino(dir), "doomed.txt"); st != 0 {
		t.Fatalf("unlink: %s", st)
	}
	addedIno := v.create(dir, "added.txt")
	v.write(addedIno, []byte("new in generation 1"))
	gen1 := publishVolume(t, v, inner, publish.Options{
		Prev: gen0.Superblock, PrevRaw: gen0.Raw,
	})

	rep, err := fs.Swap(ctx, gen1.Superblock)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if rep.From != 0 || rep.To != 1 {
		t.Fatalf("swap %d->%d, want 0->1", rep.From, rep.To)
	}

	changed := map[uint64]genfs.Change{}
	for _, c := range rep.Changes {
		changed[c.Inode] = c
	}
	// The unchanged file must NOT be invalidated — this is the property
	// the whole stable-inode design exists to provide.
	if c, bad := changed[stableIno]; bad {
		t.Fatalf("unchanged file was invalidated: %+v", c)
	}
	if c, ok := changed[changedIno]; !ok || !c.Content {
		t.Fatalf("modified file change = %+v (present=%v), want Content", c, ok)
	}
	if c, ok := changed[doomedIno]; !ok || !c.Gone {
		t.Fatalf("deleted file change = %+v (present=%v), want Gone", c, ok)
	}

	// Entry invalidations cover the addition and the removal.
	var sawAdded, sawRemoved bool
	for _, e := range rep.Entries {
		if e.Parent == dirNode.Inode && e.Name == "added.txt" && !e.Gone {
			sawAdded = true
		}
		if e.Parent == dirNode.Inode && e.Name == "doomed.txt" && e.Gone {
			sawRemoved = true
		}
	}
	if !sawAdded || !sawRemoved {
		t.Fatalf("entry invalidations added=%v removed=%v; got %+v", sawAdded, sawRemoved, rep.Entries)
	}

	// The swapped filesystem serves the NEW generation.
	if fs.Generation() != 1 {
		t.Fatalf("Generation = %d after swap, want 1", fs.Generation())
	}
	got := make([]byte, 20)
	n, err := fs.Read(ctx, changedIno, 0, got)
	if err != nil || string(got[:n]) != "v2 is longer than v1" {
		t.Fatalf("post-swap read = %q (%v), want the new content", got[:n], err)
	}
	if _, err := fs.Lookup(ctx, dirNode.Inode, "added.txt"); err != nil {
		t.Fatalf("post-swap lookup of the added file: %v", err)
	}
	if _, err := fs.Lookup(ctx, dirNode.Inode, "doomed.txt"); !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("post-swap lookup of the deleted file = %v, want ErrNotExist", err)
	}

	// Swapping to the same generation is a no-op, not a rebuild.
	rep2, err := fs.Swap(ctx, gen1.Superblock)
	if err != nil || len(rep2.Changes) != 0 || len(rep2.Entries) != 0 {
		t.Fatalf("idempotent swap reported %+v (%v)", rep2, err)
	}
}

// MaxResident bounds residency for path-based frontends, which
// re-descend on every operation. A FUSE binding must NOT set it: the
// kernel owns those lifetimes.
func TestBoundedResidency(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "b0bdb0bd-0000-4000-8000-000000000042")
	dir := v.mkdir(1, "d")
	var inos []uint64
	for i := 0; i < 20; i++ {
		ino := v.create(dir, fmt.Sprintf("f%02d.txt", i))
		v.write(ino, []byte("x"))
		inos = append(inos, ino)
	}
	res := publishVolume(t, v, inner, publish.Options{})
	fs := openFS(t, inner, res.Superblock, genfs.Options{MaxResident: 8})

	dirNode, err := fs.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatal(err)
	}
	for i := range inos {
		if _, err := fs.Lookup(ctx, dirNode.Inode, fmt.Sprintf("f%02d.txt", i)); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	// The earliest entries were evicted; the most recent survive.
	if _, err := fs.GetAttr(ctx, inos[0]); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("oldest inode still resident under a cap of 8: %v", err)
	}
	if _, err := fs.GetAttr(ctx, inos[len(inos)-1]); err != nil {
		t.Fatalf("newest inode was evicted: %v", err)
	}
	// Eviction is not loss: a path-based frontend re-descends and the
	// inode resolves again, which is exactly why the cap is safe there.
	if _, err := fs.Lookup(ctx, dirNode.Inode, "f00.txt"); err != nil {
		t.Fatalf("re-descent after eviction failed: %v", err)
	}
	if _, err := fs.GetAttr(ctx, inos[0]); err != nil {
		t.Fatalf("re-descended inode not resident: %v", err)
	}

	// Unbounded remains the default: nothing is evicted without the cap.
	fs2 := openFS(t, inner, res.Superblock, genfs.Options{})
	d2, err := fs2.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatal(err)
	}
	for i := range inos {
		if _, err := fs2.Lookup(ctx, d2.Inode, fmt.Sprintf("f%02d.txt", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fs2.GetAttr(ctx, inos[0]); err != nil {
		t.Fatalf("unbounded residency evicted an inode: %v", err)
	}
}

// Prefetch warms the whole generation's chunk cache: the batch mode that
// wants every byte local before a job starts.
func TestPrefetchWarmsCache(t *testing.T) {
	ctx := context.Background()
	inner, originDir := newInner(t)
	v := newTestVolume(t, "9efe7c40-0000-4000-8000-000000000077")
	dir := v.mkdir(1, "d")
	big := v.create(dir, "big.bin")
	bigContent := pseudorandom(6<<20, 99)
	v.write(big, bigContent)
	twin := v.create(dir, "twin.bin") // identical content: one chunk set
	v.write(twin, bigContent)
	small := v.create(dir, "small.txt")
	v.write(small, []byte("inline, nothing to fetch"))
	res := publishVolume(t, v, inner, publish.Options{})

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	rep, err := fs.Prefetch(ctx, 4)
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if rep.Failed != 0 {
		t.Fatalf("prefetch reported %d failures: %v", rep.Failed, rep.Sample)
	}
	if rep.Files != 3 {
		t.Fatalf("walked %d files, want 3", rep.Files)
	}
	if rep.Chunks == 0 {
		t.Fatalf("fetched no chunks: %+v", rep)
	}
	if rep.Bytes < int64(len(bigContent)) {
		t.Fatalf("warmed %d bytes, want at least one copy of the %d-byte file", rep.Bytes, len(bigContent))
	}

	// The twin shares every chunk identity, so dedup means the warm set
	// is one file's worth, not two.
	if rep.Bytes > int64(len(bigContent))*3/2 {
		t.Fatalf("warmed %d bytes for two identical files; dedup did not apply", rep.Bytes)
	}

	// The cache is genuinely warm: delete the packs and reads still work.
	if err := os.RemoveAll(filepath.Join(originDir, "packs")); err != nil {
		t.Fatal(err)
	}
	dirNode, err := fs.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatal(err)
	}
	n, err := fs.Lookup(ctx, dirNode.Inode, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(bigContent))
	if _, err := fs.Read(ctx, n.Inode, 0, got); err != nil {
		t.Fatalf("read after prefetch with packs deleted: %v", err)
	}
	if !bytes.Equal(got, bigContent) {
		t.Fatal("prefetched content mismatch")
	}

	// A second pass finds everything cached and transfers nothing.
	rep2, err := fs.Prefetch(ctx, 4)
	if err != nil {
		t.Fatalf("second Prefetch: %v", err)
	}
	if rep2.Chunks != 0 || rep2.Cached == 0 {
		t.Fatalf("second pass fetched %d chunks (cached %d); want all cached", rep2.Chunks, rep2.Cached)
	}
}

// A generation swap must never be observable half-applied. Swap empties
// the residency table, replaces the catalog cache, and closes the old
// catalogs before it has re-descended anything; a concurrent operation
// caught in that window used to fail. This is not a synthetic concern: a
// writable mount checkpoints on a timer, and every checkpoint made a
// burst of concurrent file creations fail — "Can't create ...:
// Input/output error" from tar, ESTALE underneath — while the base
// generation swapped out from under them.
func TestSwapIsAtomicForConcurrentOps(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, "5eaf5eaf-0000-4000-8000-000000000099")
	dir := v.mkdir(1, "d")
	// Enough residency that the re-descend takes long enough for a
	// concurrent reader to land inside it. Too few and the race is real
	// but unobserved, which is worse than no test at all.
	const files = 600
	inos := make([]uint64, 0, files)
	for i := 0; i < files; i++ {
		ino := v.create(dir, fmt.Sprintf("f%04d.txt", i))
		v.write(ino, []byte(fmt.Sprintf("generation 0 body of file %d", i)))
		inos = append(inos, ino)
	}
	gen0 := publishVolume(t, v, inner, publish.Options{})

	fs := openFS(t, inner, gen0.Superblock, genfs.Options{})
	dirNode, err := fs.Lookup(ctx, genfs.RootInode, "d")
	if err != nil {
		t.Fatal(err)
	}
	for i := range inos {
		if _, err := fs.Lookup(ctx, dirNode.Inode, fmt.Sprintf("f%04d.txt", i)); err != nil {
			t.Fatalf("lookup f%04d.txt: %v", i, err)
		}
	}

	added := v.create(dir, "added.txt")
	v.write(added, []byte("new in generation 1"))
	gen1 := publishVolume(t, v, inner, publish.Options{
		Prev: gen0.Superblock, PrevRaw: gen0.Raw,
	})

	// Hammer the tree from several goroutines for the whole swap. Every
	// inode below is resident and present in BOTH generations, so every
	// one of these calls must succeed no matter when it lands.
	stop := make(chan struct{})
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("f%04d.txt", (i*7+w*131)%files)
				n, err := fs.Lookup(ctx, dirNode.Inode, name)
				if err != nil {
					errs <- fmt.Errorf("lookup %s during swap: %w", name, err)
					return
				}
				if _, err := fs.GetAttr(ctx, n.Inode); err != nil {
					errs <- fmt.Errorf("getattr %s (inode %d) during swap: %w", name, n.Inode, err)
					return
				}
				if _, err := fs.Readdir(ctx, dirNode.Inode); err != nil {
					errs <- fmt.Errorf("readdir during swap: %w", err)
					return
				}
			}
		}(w)
	}
	// Let the workers get going so the swap really does overlap them.
	time.Sleep(20 * time.Millisecond)
	if _, err := fs.Swap(ctx, gen1.Superblock); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	close(stop)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatalf("operation failed across a generation swap: %v", err)
	default:
	}
}
