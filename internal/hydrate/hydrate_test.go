package hydrate_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"
	_ "modernc.org/sqlite"

	"github.com/bbockelm/pelfs/internal/cutdb"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/hydrate"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

const rootInode = uint64(meta.RootInode)

// newInner starts a fakeorigin-backed pelicanobj store rooted at /vol (the
// publish test pattern).
func newInner(t *testing.T) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner
}

// testVolume is a live JuiceFS volume the tests mutate and cut (the
// publish test pattern).
type testVolume struct {
	t        *testing.T
	metaPath string
	m        meta.Meta
	blob     object.ObjectStorage
	store    chunk.ChunkStore
}

func newTestVolume(t *testing.T, uuid string) *testVolume {
	t.Helper()
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format := &meta.Format{
		Name:      "hydrate-test",
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

// cut takes the publish-time metadata snapshot (VACUUM INTO).
func (v *testVolume) cut() string {
	v.t.Helper()
	dst := filepath.Join(v.t.TempDir(), "cut.db")
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

// walkEdges collects every edge of a metadata DB through the real meta
// client: (parent, name) -> node.
func walkEdges(t *testing.T, metaPath string) map[string]cutdb.Node {
	t.Helper()
	db, err := cutdb.Open(metaPath, cutdb.Options{})
	if err != nil {
		t.Fatalf("open %s: %v", metaPath, err)
	}
	defer db.Close() //nolint:errcheck
	out := make(map[string]cutdb.Node)
	if err := db.Walk(context.Background(), func(parent uint64, name string, n cutdb.Node) error {
		out[fmt.Sprintf("%d/%s", parent, name)] = n
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", metaPath, err)
	}
	return out
}

// readFile reads one file byte-exact through the real meta client and
// chunk-store read path over the given blob store.
func readFile(t *testing.T, db *cutdb.DB, ino, length uint64) []byte {
	t.Helper()
	rd, err := db.FileReader(context.Background(), ino, length)
	if err != nil {
		t.Fatalf("file reader for %d: %v", ino, err)
	}
	data, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("read inode %d: %v", ino, err)
	}
	return data
}

func counterValue(t *testing.T, metaPath, name string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+metaPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	var v int64
	if err := db.QueryRow(`SELECT value FROM jfs_counter WHERE name = ?`, name).Scan(&v); err != nil {
		t.Fatalf("counter %s: %v", name, err)
	}
	return v
}

func TestHydrateRoundTrip(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "3f2c8a1e-5b4d-4e6f-9a0b-1c2d3e4f5a6b")

	bigContent := pseudorandom(6<<20, 42)
	smallContent := []byte("hello inline world")
	hardContent := pseudorandom(100, 7)

	dirIno := v.mkdir(rootInode, "dir")
	v.setxattr(dirIno, "user.dircolor", []byte("green"))
	smallIno := v.create(dirIno, "small.txt")
	v.write(smallIno, smallContent)
	v.setxattr(smallIno, "user.color", []byte("blue"))
	linkIno := v.symlink(dirIno, "link", "small.txt")
	emptyIno := v.create(dirIno, "empty")
	bigIno := v.create(rootInode, "big.bin")
	v.write(bigIno, bigContent)
	hardIno := v.create(rootInode, "hard1")
	v.write(hardIno, hardContent)
	v.link(hardIno, dirIno, "hard2")
	cutPath := v.cut()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := publish.Publish(ctx, publish.Options{
		CutPath:    cutPath,
		Blob:       v.blob,
		CacheDir:   t.TempDir(),
		Inner:      inner,
		SpoolDir:   t.TempDir(),
		SigningKey: priv,
		SMax:       1000, // force /dir into a nested catalog
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// The caller does trust: decode the ref bytes and verify before
	// handing the superblock to Hydrate.
	sb, err := superblock.Decode(res.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("verify superblock: %v", err)
	}

	metaPath := filepath.Join(t.TempDir(), "hydrated.db")
	sidecarPath := filepath.Join(t.TempDir(), "sidecar.db")
	hres, err := hydrate.Hydrate(ctx, hydrate.Options{
		Inner:       inner,
		SB:          sb,
		MetaPath:    metaPath,
		SidecarPath: sidecarPath,
		CacheDir:    t.TempDir(),
		VolumeName:  "restored",
	})
	if err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if hres.Dirs != 2 || hres.Files != 4 || hres.Symlinks != 1 {
		t.Fatalf("result = %+v, want 2 dirs / 4 files / 1 symlink", hres)
	}
	if hres.InlineFiles != 2 || hres.ChunkedFiles != 1 {
		t.Fatalf("result = %+v, want 2 inline / 1 chunked", hres)
	}

	// Full metadata equality through the REAL meta client: names, exact
	// inodes, types, lengths, nlink, and mtimes all preserved.
	src := walkEdges(t, cutPath)
	got := walkEdges(t, metaPath)
	if len(got) != len(src) {
		t.Fatalf("hydrated tree has %d edges, source has %d", len(got), len(src))
	}
	for key, sn := range src {
		gn, ok := got[key]
		if !ok {
			t.Fatalf("edge %s missing from the hydrated tree", key)
		}
		if gn != sn {
			t.Fatalf("edge %s: hydrated node %+v != source %+v", key, gn, sn)
		}
	}
	for name, want := range map[string]uint64{"dir": dirIno, "small.txt": smallIno, "link": linkIno,
		"empty": emptyIno, "big.bin": bigIno, "hard1": hardIno} {
		found := false
		for key, n := range got {
			if strings.HasSuffix(key, "/"+name) && n.Inode == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s did not keep inode %d", name, want)
		}
	}
	// Hardlink pair: both names resolve to the same inode, nlink 2.
	h1 := got[fmt.Sprintf("%d/hard1", rootInode)]
	h2 := got[fmt.Sprintf("%d/hard2", dirIno)]
	if h1.Inode != hardIno || h2.Inode != hardIno {
		t.Fatalf("hardlink inodes: hard1=%d hard2=%d, want both %d", h1.Inode, h2.Inode, hardIno)
	}
	if h1.Nlink != 2 || h2.Nlink != 2 {
		t.Fatalf("hardlink nlink: %d/%d, want 2/2", h1.Nlink, h2.Nlink)
	}

	// Symlink target and xattrs through the real client.
	mdb, err := cutdb.Open(metaPath, cutdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer mdb.Close() //nolint:errcheck
	if target, err := mdb.Readlink(ctx, linkIno); err != nil || target != "small.txt" {
		t.Fatalf("symlink target = %q (%v)", target, err)
	}
	if xa, err := mdb.Xattrs(ctx, smallIno); err != nil || string(xa["user.color"]) != "blue" {
		t.Fatalf("small.txt xattrs = %v (%v)", xa, err)
	}
	if xa, err := mdb.Xattrs(ctx, dirIno); err != nil || string(xa["user.dircolor"]) != "green" {
		t.Fatalf("dir xattrs = %v (%v)", xa, err)
	}

	// Data path: a chunk.CachedStore over NewBlob (via the cutdb reader,
	// which is exactly that plus meta.Read) serves hydrated content from
	// packs, byte-exact.
	sessionBlob, err := object.CreateStorage("mem", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := hydrate.NewBlob(sessionBlob, inner, sidecarPath, nil, filepath.Join(t.TempDir(), "chunk-cache"))
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	ddb, err := cutdb.Open(metaPath, cutdb.Options{Blob: blob, CacheDir: filepath.Join(t.TempDir(), "block-cache")})
	if err != nil {
		t.Fatal(err)
	}
	defer ddb.Close() //nolint:errcheck
	if data := readFile(t, ddb, bigIno, uint64(len(bigContent))); !bytes.Equal(data, bigContent) {
		t.Fatalf("big.bin content mismatch (%d bytes)", len(data))
	}
	if data := readFile(t, ddb, smallIno, uint64(len(smallContent))); !bytes.Equal(data, smallContent) {
		t.Fatalf("small.txt = %q", data)
	}
	if data := readFile(t, ddb, hardIno, uint64(len(hardContent))); !bytes.Equal(data, hardContent) {
		t.Fatalf("hardlink content mismatch (%d bytes)", len(data))
	}
	if data := readFile(t, ddb, emptyIno, 0); len(data) != 0 {
		t.Fatalf("empty file read %d bytes", len(data))
	}

	// Write-continuation: counters clear every hydrated id, and a
	// read-write session's fresh allocations never collide.
	if ni := counterValue(t, metaPath, "nextInode"); uint64(ni) != hres.NextInode || uint64(ni) < sb.NextInode || uint64(ni) <= hardIno {
		t.Fatalf("nextInode = %d (result %d, superblock %d, max inode %d)", ni, hres.NextInode, sb.NextInode, hardIno)
	}
	if nc := counterValue(t, metaPath, "nextChunk"); uint64(nc) != hres.NextChunk || int(nc) <= hres.Slices {
		t.Fatalf("nextChunk = %d (result %d, %d hydrated slices)", nc, hres.NextChunk, hres.Slices)
	}
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	if _, err := m.Load(true); err != nil {
		t.Fatalf("load hydrated volume: %v", err)
	}
	if err := m.NewSession(true); err != nil {
		t.Fatalf("session on hydrated volume: %v", err)
	}
	defer m.CloseSession() //nolint:errcheck
	var ino meta.Ino
	var attr meta.Attr
	if st := m.Create(meta.WrapContext(ctx), meta.RootInode, "new.txt", 0644, 0, 0, &ino, &attr); st != 0 {
		t.Fatalf("create on hydrated volume: %s", st)
	}
	if uint64(ino) < hres.NextInode {
		t.Fatalf("new file got inode %d, colliding with hydrated inode space (< %d)", ino, hres.NextInode)
	}
	var sliceID uint64
	if st := m.NewSlice(meta.WrapContext(ctx), &sliceID); st != 0 {
		t.Fatalf("new slice on hydrated volume: %s", st)
	}
	if sliceID < hres.NextChunk {
		t.Fatalf("new slice id %d collides with hydrated slice space (< %d)", sliceID, hres.NextChunk)
	}
}

func TestHydrateEncrypted(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	v := newTestVolume(t, "aaaabbbb-cccc-dddd-eeee-ffff00001111")

	secret := []byte("the inline secret")
	blobContent := pseudorandom(5<<20/2, 99) // 2.5 MiB, chunked
	dirIno := v.mkdir(rootInode, "enc")
	secretIno := v.create(dirIno, "secret.txt")
	v.write(secretIno, secret)
	blobIno := v.create(rootInode, "blob.bin")
	v.write(blobIno, blobContent)
	cutPath := v.cut()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dek := pseudorandom(32, 1)
	idKey := pseudorandom(32, 2)
	res, err := publish.Publish(ctx, publish.Options{
		CutPath:     cutPath,
		Blob:        v.blob,
		CacheDir:    t.TempDir(),
		Inner:       inner,
		SpoolDir:    t.TempDir(),
		SigningKey:  priv,
		IdentityKey: idKey,
		DEK:         dek,
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
		},
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	sb := res.Superblock
	if err := sb.Verify(pub); err != nil {
		t.Fatal(err)
	}

	// The wrong DEK fails at the root catalog with a clear error.
	wrongDEK := pseudorandom(32, 3)
	_, err = hydrate.Hydrate(ctx, hydrate.Options{
		Inner:       inner,
		SB:          sb,
		DEK:         wrongDEK,
		MetaPath:    filepath.Join(t.TempDir(), "wrong.db"),
		SidecarPath: filepath.Join(t.TempDir(), "wrong-sidecar.db"),
	})
	if err == nil || !strings.Contains(err.Error(), "root catalog") {
		t.Fatalf("wrong DEK: err = %v, want a root-catalog decode failure", err)
	}
	// No DEK at all is rejected up front.
	_, err = hydrate.Hydrate(ctx, hydrate.Options{
		Inner:       inner,
		SB:          sb,
		MetaPath:    filepath.Join(t.TempDir(), "nodek.db"),
		SidecarPath: filepath.Join(t.TempDir(), "nodek-sidecar.db"),
	})
	if err == nil || !strings.Contains(err.Error(), "DEK is required") {
		t.Fatalf("missing DEK: err = %v", err)
	}

	metaPath := filepath.Join(t.TempDir(), "hydrated.db")
	sidecarPath := filepath.Join(t.TempDir(), "sidecar.db")
	hres, err := hydrate.Hydrate(ctx, hydrate.Options{
		Inner:       inner,
		SB:          sb,
		DEK:         dek,
		MetaPath:    metaPath,
		SidecarPath: sidecarPath,
		VolumeName:  "restored-enc",
	})
	if err != nil {
		t.Fatalf("Hydrate: %v", err)
	}
	if hres.Files != 2 || hres.InlineFiles != 1 || hres.ChunkedFiles != 1 {
		t.Fatalf("result = %+v", hres)
	}

	src := walkEdges(t, cutPath)
	got := walkEdges(t, metaPath)
	if len(got) != len(src) {
		t.Fatalf("hydrated tree has %d edges, source has %d", len(got), len(src))
	}
	for key, sn := range src {
		if gn := got[key]; gn != sn {
			t.Fatalf("edge %s: hydrated node %+v != source %+v", key, gn, sn)
		}
	}

	sessionBlob, err := object.CreateStorage("mem", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := hydrate.NewBlob(sessionBlob, inner, sidecarPath, dek, "")
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	ddb, err := cutdb.Open(metaPath, cutdb.Options{Blob: blob, CacheDir: filepath.Join(t.TempDir(), "block-cache")})
	if err != nil {
		t.Fatal(err)
	}
	defer ddb.Close() //nolint:errcheck
	if data := readFile(t, ddb, blobIno, uint64(len(blobContent))); !bytes.Equal(data, blobContent) {
		t.Fatalf("blob.bin content mismatch (%d bytes)", len(data))
	}
	if data := readFile(t, ddb, secretIno, uint64(len(secret))); !bytes.Equal(data, secret) {
		t.Fatalf("secret.txt = %q", data)
	}
}
