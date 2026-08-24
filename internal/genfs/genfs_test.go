package genfs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
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

// newTestVolume creates an empty volume the tests fill in and publish.
func newTestVolume(t testing.TB, inner pelicanobj.Store, uuid string) *testvol.Volume {
	t.Helper()
	return testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
}

// pseudorandom returns deterministic incompressible content.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// publishVolume seals everything written into v since the last publish.
// packsOf resolves a generation's pack set the way a mount does: through
// the manifest segments it names, or through the inline list when it
// names none (manifest.Packs).
func packsOf(t testing.TB, inner pelicanobj.Store, sb *superblock.Superblock) []superblock.PackEntry {
	t.Helper()
	packs, err := manifest.Packs(context.Background(), inner, sb)
	if err != nil {
		t.Fatalf("resolve pack set: %v", err)
	}
	return packs
}

func publishVolume(t testing.TB, v *testvol.Volume, _ pelicanobj.Store, opts publish.Options) *publish.Result {
	t.Helper()
	return v.Publish(opts)
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
	v := newTestVolume(t, inner, "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b")

	bigContent := pseudorandom(8<<20, 42)
	smallContent := []byte("hello inline world, generation zero")
	hardContent := pseudorandom(100, 7)

	dirIno := v.Mkdir(rootIno, "dir")
	smallIno := v.Create(dirIno, "small.txt")
	v.Write(smallIno, smallContent)
	v.SetXattr(smallIno, "user.color", []byte("blue"))
	v.Symlink(dirIno, "link", "small.txt")
	bigIno := v.Create(rootIno, "big.bin")
	v.Write(bigIno, bigContent)
	hardIno := v.Create(rootIno, "hard1")
	v.Write(hardIno, hardContent)
	v.Link(hardIno, dirIno, "hard2")

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
	v := newTestVolume(t, inner, "11112222-3333-4444-5555-666677778888")
	dirIno := v.Mkdir(rootIno, "d")
	fIno := v.Create(dirIno, "f")
	v.Write(fIno, []byte("payload"))

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
	v := newTestVolume(t, inner, "aaaa1111-2222-3333-4444-555566667777")

	bigContent := pseudorandom(8<<20, 99)
	smallContent := []byte("tiny inline body")
	bigIno := v.Create(rootIno, "big.bin")
	v.Write(bigIno, bigContent)
	smallIno := v.Create(rootIno, "small.txt")
	v.Write(smallIno, smallContent)

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
	v := newTestVolume(t, inner, "bbbb1111-2222-3333-4444-555566667777")

	bigContent := pseudorandom(3<<20, 21)
	smallContent := []byte("small hardlinked body")
	dirIno := v.Mkdir(rootIno, "d")
	bigIno := v.Create(rootIno, "hardbig")
	v.Write(bigIno, bigContent)
	v.Link(bigIno, dirIno, "hardbig2")
	smallIno := v.Create(rootIno, "hardsmall")
	v.Write(smallIno, smallContent)
	v.SetXattr(smallIno, "user.tag", []byte("shared"))
	v.Link(smallIno, dirIno, "hardsmall2")

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
	// Promoted files' xattrs live in the shard too — and ONLY there, since
	// path catalogs carry a promoted inode's node row without its content
	// records. This volume's only xattr is this one, so the path catalog's
	// xattr table is empty: the whole-catalog "no xattrs here" shortcut has
	// to consult the shard as well, or the attribute disappears.
	if val, err := fs.GetXattr(ctx, smallIno, "user.tag"); err != nil || string(val) != "shared" {
		t.Fatalf("promoted xattr = %q (%v)", val, err)
	}
	if names, err := fs.ListXattr(ctx, smallIno); err != nil || len(names) != 1 || names[0] != "user.tag" {
		t.Fatalf("promoted ListXattr = %v (%v)", names, err)
	}
	// An unpromoted inode in the same volume genuinely has none.
	if names, err := fs.ListXattr(ctx, dirIno); err != nil || len(names) != 0 {
		t.Fatalf("ListXattr of an attribute-free inode = %v (%v)", names, err)
	}
}

func TestSymlinkXattr(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, inner, "cccc1111-2222-3333-4444-555566667777")

	dirIno := v.Mkdir(rootIno, "d")
	smallIno := v.Create(dirIno, "small.txt")
	v.Write(smallIno, []byte("body"))
	v.SetXattr(smallIno, "user.color", []byte("blue"))
	linkIno := v.Symlink(dirIno, "link", "small.txt")

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
	dek := pseudorandom(32, 1)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, "dddd1111-2222-3333-4444-555566667777"),
		DEK:         dek,
		IdentityKey: pseudorandom(32, 2),
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})

	secret := []byte("the inline secret")
	blob := pseudorandom(3<<20, 33)
	dirIno := v.Mkdir(rootIno, "enc")
	secretIno := v.WriteFile(dirIno, "secret.txt", secret)
	blobIno := v.WriteFile(rootIno, "blob.bin", blob)

	res := publishVolume(t, v, inner, publish.Options{})

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
	v := newTestVolume(t, inner, "eeee1111-2222-3333-4444-555566667777")

	faContent := pseudorandom(2500, 11)
	fbContent := pseudorandom(2500, 12)
	aIno := v.Mkdir(rootIno, "a")
	bIno := v.Mkdir(rootIno, "b")
	faIno := v.Create(aIno, "fa")
	v.Write(faIno, faContent)
	fbIno := v.Create(bIno, "fb")
	v.Write(fbIno, fbContent)

	// SMax 1000 peels both /a and /b: a 3-catalog tree. The split weight
	// this relies on is the files' INLINE bytes, so the threshold is stated
	// rather than inherited — the shipped default has since moved below
	// 2500, leaving the fixture one flat catalog and nothing to evict.
	res := publishVolume(t, v, inner, publish.Options{SMax: 1000, InlineMax: 4096})
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
	v := newTestVolume(t, inner, "abcdabcd-0000-4000-8000-0000000000aa")
	dir := v.Mkdir(1, "d")
	sub := v.Mkdir(dir, "sub")
	fileIno := v.Create(sub, "f.txt")
	v.Write(fileIno, []byte("hello"))
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
	v := newTestVolume(t, inner, "5eaf5eaf-0000-4000-8000-000000000055")
	dir := v.Mkdir(1, "d")
	stableIno := v.Create(dir, "stable.txt")
	v.Write(stableIno, []byte("unchanged across generations"))
	changedIno := v.Create(dir, "changed.txt")
	v.Write(changedIno, []byte("v1"))
	doomedIno := v.Create(dir, "doomed.txt")
	v.Write(doomedIno, []byte("deleted next generation"))
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

	// Next generation: change one file, delete another, add a third. The
	// overlay establishes residency by descent, so each inode carried over
	// from the published generation is looked up before it is touched.
	v.Lookup(genfs.RootInode, "d")
	v.Lookup(dir, "changed.txt")
	v.Truncate(changedIno, 0)
	v.Write(changedIno, []byte("v2 is longer than v1"))
	v.Unlink(dir, "doomed.txt")
	addedIno := v.Create(dir, "added.txt")
	v.Write(addedIno, []byte("new in generation 1"))
	gen1 := publishVolume(t, v, inner, publish.Options{})

	rep, err := fs.Swap(ctx, gen1.Superblock)
	if err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if rep.From != gen0.Superblock.Generation || rep.To != gen1.Superblock.Generation {
		t.Fatalf("swap %d->%d, want %d->%d", rep.From, rep.To,
			gen0.Superblock.Generation, gen1.Superblock.Generation)
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
	if fs.Generation() != gen1.Superblock.Generation {
		t.Fatalf("Generation = %d after swap, want %d", fs.Generation(), gen1.Superblock.Generation)
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
	v := newTestVolume(t, inner, "b0bdb0bd-0000-4000-8000-000000000042")
	dir := v.Mkdir(1, "d")
	var inos []uint64
	for i := 0; i < 20; i++ {
		ino := v.Create(dir, fmt.Sprintf("f%02d.txt", i))
		v.Write(ino, []byte("x"))
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

// ReaddirRetain replaces a Lookup per entry, so it has to be
// indistinguishable from one: same entries, same residency, and the same
// eviction order when residency is bounded. The transition point is the
// case worth pinning — a child catalog's entries are unreachable unless
// the retain recorded the CHILD catalog, which only the nested rows say.
func TestReaddirRetainMatchesLookupPerEntry(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, inner, "cafe0001-0000-4000-8000-00000000abcd")
	dirIno := v.Mkdir(rootIno, "dir")
	deepIno := v.Mkdir(dirIno, "deep")
	for _, d := range []uint64{rootIno, dirIno, deepIno} {
		for i := 0; i < 8; i++ {
			ino := v.Create(d, fmt.Sprintf("f%02d.txt", i))
			v.Write(ino, pseudorandom(400, int64(d)+int64(i)))
		}
	}
	v.Symlink(dirIno, "link", "deep")
	// SMax 1000 splits /dir (and /dir/deep) into nested catalogs.
	res := publishVolume(t, v, inner, publish.Options{SMax: 1000, TargetPackSize: 2 << 20})
	if res.Stats.Catalogs < 3 {
		t.Fatalf("fixture did not split: %d catalogs", res.Stats.Catalogs)
	}

	byLookup := openFS(t, inner, res.Superblock, genfs.Options{})
	byRetain := openFS(t, inner, res.Superblock, genfs.Options{})

	// Walk both the whole way down, one through Readdir+Lookup, one
	// through ReaddirRetain alone, and compare listing by listing.
	var walk func(ino uint64)
	walk = func(ino uint64) {
		want, err := byLookup.Readdir(ctx, ino)
		if err != nil {
			t.Fatalf("Readdir %d: %v", ino, err)
		}
		for _, e := range want {
			if _, err := byLookup.Lookup(ctx, ino, e.Name); err != nil {
				t.Fatalf("Lookup %d/%s: %v", ino, e.Name, err)
			}
		}
		got, err := byRetain.ReaddirRetain(ctx, ino)
		if err != nil {
			t.Fatalf("ReaddirRetain %d: %v", ino, err)
		}
		if len(got) != len(want) {
			t.Fatalf("ReaddirRetain %d = %v, want %v", ino, entryNames(got), entryNames(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("entry %d of inode %d = %+v, want %+v", i, ino, got[i], want[i])
			}
		}
		for _, e := range got {
			// Residency, not just naming: every entry must now be operable
			// without any further descent.
			if _, err := byRetain.GetAttr(ctx, e.Node.Inode); err != nil {
				t.Fatalf("entry %q (inode %d) not resident after ReaddirRetain: %v", e.Name, e.Node.Inode, err)
			}
			switch e.Node.Type {
			case catalog.TypeDir:
				walk(e.Node.Inode)
			case catalog.TypeSymlink:
				if _, err := byRetain.Readlink(ctx, e.Node.Inode); err != nil {
					t.Fatalf("readlink %q: %v", e.Name, err)
				}
			default:
				readAll(t, byRetain, e.Node.Inode, int(e.Node.Length), 64<<10)
			}
		}
	}
	walk(rootIno)

	// Bounded residency: retaining a listing must evict exactly as the
	// per-entry loop does, so the same inode falls off the end.
	capped := openFS(t, inner, res.Superblock, genfs.Options{MaxResident: 2})
	ents, err := capped.ReaddirRetain(ctx, rootIno)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 3 {
		t.Fatalf("fixture root has %d entries, need at least 3 to overflow the cap", len(ents))
	}
	if _, err := capped.GetAttr(ctx, ents[0].Node.Inode); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("first entry survived a cap of 2: %v", err)
	}
	if _, err := capped.GetAttr(ctx, ents[len(ents)-1].Node.Inode); err != nil {
		t.Fatalf("last entry was evicted: %v", err)
	}
}

// Prefetch warms the whole generation's chunk cache: the batch mode that
// wants every byte local before a job starts.
func TestPrefetchWarmsCache(t *testing.T) {
	ctx := context.Background()
	inner, originDir := newInner(t)
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-000000000077")
	dir := v.Mkdir(1, "d")
	big := v.Create(dir, "big.bin")
	bigContent := pseudorandom(6<<20, 99)
	v.Write(big, bigContent)
	twin := v.Create(dir, "twin.bin") // identical content: one chunk set
	v.Write(twin, bigContent)
	small := v.Create(dir, "small.txt")
	v.Write(small, []byte("inline, nothing to fetch"))
	res := publishVolume(t, v, inner, publish.Options{})

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	rep, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 4})
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if rep.Failed != 0 {
		t.Fatalf("prefetch reported %d failures: %v", rep.Failed, rep.Sample)
	}
	if rep.Files != 3 {
		t.Fatalf("walked %d files, want 3", rep.Files)
	}
	if rep.Packs == 0 {
		t.Fatalf("fetched no packs: %+v", rep)
	}
	if rep.Bytes < int64(len(bigContent)) {
		t.Fatalf("warmed %d bytes, want at least one copy of the %d-byte file", rep.Bytes, len(bigContent))
	}
	// Nearly all of it was transferred here: the only pack already local is
	// the one Open pulled to read the root catalog out of.
	if rep.Fetched == 0 || rep.Fetched > rep.Bytes {
		t.Fatalf("a cold prefetch made %d bytes local but transferred %d", rep.Bytes, rep.Fetched)
	}

	// The twin shares every chunk identity, so dedup at publish means the
	// pack set is one file's worth, not two.
	if rep.Bytes > int64(len(bigContent))*3/2 {
		t.Fatalf("warmed %d bytes for two identical files; dedup did not apply", rep.Bytes)
	}

	// The whole point: nothing was DECODED. A prefetch makes packs local;
	// unpacking them is a read's business and a read's cost.
	if ents, err := os.ReadDir(filepath.Join(cache, "chunks")); err == nil && len(ents) != 0 {
		t.Fatalf("prefetch decoded %d chunk(s) to disk; it is supposed to move packs and nothing else", len(ents))
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
	rep2, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 4})
	if err != nil {
		t.Fatalf("second Prefetch: %v", err)
	}
	if rep2.Packs != 0 || rep2.Cached == 0 || rep2.Fetched != 0 {
		t.Fatalf("second pass fetched %d packs / %d bytes (cached %d); want all cached",
			rep2.Packs, rep2.Fetched, rep2.Cached)
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
	v := newTestVolume(t, inner, "5eaf5eaf-0000-4000-8000-000000000099")
	dir := v.Mkdir(1, "d")
	// Enough residency that the re-descend takes long enough for a
	// concurrent reader to land inside it. Too few and the race is real
	// but unobserved, which is worse than no test at all.
	const files = 600
	inos := make([]uint64, 0, files)
	for i := 0; i < files; i++ {
		ino := v.Create(dir, fmt.Sprintf("f%04d.txt", i))
		v.Write(ino, []byte(fmt.Sprintf("generation 0 body of file %d", i)))
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

	v.Lookup(genfs.RootInode, "d")
	added := v.Create(dir, "added.txt")
	v.Write(added, []byte("new in generation 1"))
	gen1 := publishVolume(t, v, inner, publish.Options{})

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

// The equivalence a bulk retain claims — same inodes, same catalogs, same
// order as a Lookup per entry — only matters where residency is scarce,
// so it is checked on a tree several times LARGER than the bound. What
// must agree is not that everything survives (most of it cannot) but that
// the SAME things survive: eviction is driven by the order residency was
// established, and a bulk pass that established it in a different order
// would leave a different tail of the tree reachable.
func TestReaddirRetainEvictsLikeLookupPerEntry(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, inner, "cafe0002-0000-4000-8000-00000000abcd")
	for d := 0; d < 3; d++ {
		dir := v.Mkdir(rootIno, fmt.Sprintf("d%d", d))
		for i := 0; i < 40; i++ {
			v.Write(v.Create(dir, fmt.Sprintf("f%02d.txt", i)), pseudorandom(300, int64(d*100+i)))
		}
	}
	res := publishVolume(t, v, inner, publish.Options{SMax: 1000, TargetPackSize: 2 << 20})

	// Below one directory's entry count, so a single listing overflows it
	// and the eviction happens DURING the pass being compared.
	const bound = 36
	byLookup := openFS(t, inner, res.Superblock, genfs.Options{MaxResident: bound})
	byRetain := openFS(t, inner, res.Superblock, genfs.Options{MaxResident: bound})

	var all []uint64
	list := func(parent uint64, at string) []genfs.DirEntry {
		ents, err := byLookup.Readdir(ctx, parent)
		if err != nil {
			t.Fatalf("Readdir %s: %v", at, err)
		}
		for _, e := range ents {
			if _, err := byLookup.Lookup(ctx, parent, e.Name); err != nil {
				t.Fatalf("Lookup %s/%s: %v", at, e.Name, err)
			}
		}
		got, err := byRetain.ReaddirRetain(ctx, parent)
		if err != nil {
			t.Fatalf("ReaddirRetain %s: %v", at, err)
		}
		if !reflect.DeepEqual(got, ents) {
			t.Fatalf("listing of %s differs: %v vs %v", at, entryNames(got), entryNames(ents))
		}
		for _, e := range ents {
			all = append(all, e.Node.Inode)
		}
		// After every pass, not only at the end: a divergence in retain
		// ORDER shows up as a different survivor set one listing later,
		// and the next listing would bury it.
		for _, ino := range all {
			l, r := byLookup.Resident(ino), byRetain.Resident(ino)
			if l != r {
				t.Fatalf("after %s, inode %d: resident=%v by Lookup per entry, %v by ReaddirRetain",
					at, ino, l, r)
			}
		}
		return ents
	}

	for _, e := range list(rootIno, "/") {
		// Re-resolving the directory before descending is what a kernel
		// does and what both walks must do alike: the listings above have
		// already evicted it, and neither filesystem replays anything.
		lk, err := byLookup.Lookup(ctx, rootIno, e.Name)
		if err != nil {
			t.Fatalf("re-lookup %s: %v", e.Name, err)
		}
		if _, err := byRetain.Lookup(ctx, rootIno, e.Name); err != nil {
			t.Fatalf("re-lookup %s: %v", e.Name, err)
		}
		list(lk.Inode, e.Name)
	}

	if len(all) <= bound*2 {
		t.Fatalf("tree has %d inodes against a bound of %d; eviction would barely engage", len(all), bound)
	}
	resident := 0
	for _, ino := range all {
		if byRetain.Resident(ino) {
			resident++
		}
	}
	if resident == 0 || resident > bound {
		t.Fatalf("%d of %d inodes survived a bound of %d", resident, len(all), bound)
	}
}

// Edge hands out the DESCENT STEP behind an inode's residency, which is
// what a layer above needs to refill a cache of the same fact rather than
// fail on a miss. The overlay's write path does exactly that: it caches one
// base descent step per inode, a checkpoint sweeps the cache to bound its
// memory, and link(2) -- the one operation that names its subject by bare
// inode -- then arrives with nothing behind it. See persistChainLocked in
// internal/overlay and internal/overlay/linkprov_test.go.
//
// The contract in four parts: the step is the one the descent used, it is
// still a valid step (re-resolving it returns the same inode), an inode no
// descent reached is ErrStale rather than a scan, and the root is named by
// no edge at all.
func TestEdgeIsTheDescentStepResidencyWasEstablishedBy(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)
	v := newTestVolume(t, inner, "abcdabcd-0000-4000-8000-0000000000ed")
	dir := v.Mkdir(1, "d")
	sub := v.Mkdir(dir, "sub")
	fileIno := v.Create(sub, "f.txt")
	v.Write(fileIno, []byte("hello"))
	res := publishVolume(t, v, inner, publish.Options{})
	fs := openFS(t, inner, res.Superblock, genfs.Options{})

	if _, _, err := fs.Edge(genfs.RootInode); !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("Edge(root) = %v, want ErrNotExist: the root is named by no edge", err)
	}
	if _, _, err := fs.Edge(fileIno); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("Edge of a never-looked-up inode = %v, want ErrStale: there is no "+
			"reverse index from inode to name, and the honest answer is to say so", err)
	}

	if _, err := fs.LookupPath(ctx, "/d/sub/f.txt"); err != nil {
		t.Fatalf("LookupPath: %v", err)
	}
	// Every step of the descent, child to root, with the name it was
	// reached by -- not just the parent Parent() already answered.
	for _, want := range []struct {
		ino    uint64
		parent uint64
		name   string
	}{
		{fileIno, sub, "f.txt"},
		{sub, dir, "sub"},
		{dir, genfs.RootInode, "d"},
	} {
		parent, name, err := fs.Edge(want.ino)
		if err != nil || parent != want.parent || name != want.name {
			t.Fatalf("Edge(%d) = %d/%q, %v; want %d/%q", want.ino, parent, name, err, want.parent, want.name)
		}
		// And it is a step that still RESOLVES, which is the property the
		// caller is relying on: an edge is immutable within a generation,
		// so replaying it is always allowed.
		n, err := fs.Lookup(ctx, parent, name)
		if err != nil || n.Inode != want.ino {
			t.Fatalf("replaying Edge(%d) as Lookup(%d, %q) gave inode %d, %v; want %d",
				want.ino, parent, name, n.Inode, err, want.ino)
		}
	}
}
