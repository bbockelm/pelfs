package vfsbilly_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The fixture publishes a fixed base tree over fakeorigin exactly as the
// genfs and overlay tests do, then drives the billy adapter over it.

const rootIno = genfs.RootInode

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

// testVolume is a live JuiceFS volume the fixture mutates and cuts.
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
		Name:      "vfsbilly-test",
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

func (v *testVolume) symlink(parent uint64, name, target string) uint64 {
	v.t.Helper()
	var ino meta.Ino
	var attr meta.Attr
	if st := v.m.Symlink(v.ctx(), meta.Ino(parent), name, target, &ino, &attr); st != 0 {
		v.t.Fatalf("symlink %s: %s", name, st)
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
//	/base.txt          small text
//	/big.bin           64 KiB pseudorandom (chunked)
//	/huge.bin          6 MiB pseudorandom (many chunks, several packs)
//	/link              symlink -> base.txt
//	/dir/child.txt
//	/dir/inner/leaf.txt
//	/tagged.txt        xattrs user.color=blue, user.keep=yes
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
	fx.body["huge.bin"] = pseudorandom(6<<20, 7)
	fx.body["dir/child.txt"] = []byte("child body")
	fx.body["dir/inner/leaf.txt"] = []byte("leaf body")
	fx.body["tagged.txt"] = []byte("tagged body")

	fx.ino["base.txt"] = v.create(rootIno, "base.txt")
	fx.ino["big.bin"] = v.create(rootIno, "big.bin")
	fx.ino["huge.bin"] = v.create(rootIno, "huge.bin")
	fx.ino["dir"] = v.mkdir(rootIno, "dir")
	fx.ino["dir/child.txt"] = v.create(fx.ino["dir"], "child.txt")
	fx.ino["dir/inner"] = v.mkdir(fx.ino["dir"], "inner")
	fx.ino["dir/inner/leaf.txt"] = v.create(fx.ino["dir/inner"], "leaf.txt")
	fx.ino["tagged.txt"] = v.create(rootIno, "tagged.txt")
	for p, b := range fx.body {
		v.write(fx.ino[p], b)
	}
	fx.ino["link"] = v.symlink(rootIno, "link", "base.txt")
	if st := v.m.SetXattr(v.ctx(), meta.Ino(fx.ino["tagged.txt"]), "user.color", []byte("blue"), 0); st != 0 {
		t.Fatalf("setxattr: %s", st)
	}

	fx.res = publishVolume(t, v, inner, publish.Options{TargetPackSize: 2 << 20})
	fx.base = openBase(t, inner, fx.res.Superblock)
	return fx
}

func openOverlay(t testing.TB, fx *fixture) *overlay.FS {
	t.Helper()
	ov, err := overlay.Open(t.TempDir(), fx.base, overlay.Options{
		NextInode:      fx.res.Superblock.NextInode,
		BaseRoot:       fx.res.Superblock.RootCatalog,
		BaseGeneration: fx.res.Superblock.Generation,
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = ov.Close() })
	return ov
}
