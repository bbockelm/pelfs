package vfsbilly_test

import (
	"context"
	mrand "math/rand"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
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

func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
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
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	fx := &fixture{inner: inner, ino: map[string]uint64{}, body: map[string][]byte{}}
	fx.body["base.txt"] = []byte("the base file body, generation zero")
	fx.body["big.bin"] = pseudorandom(64<<10, 42)
	fx.body["huge.bin"] = pseudorandom(6<<20, 7)
	fx.body["dir/child.txt"] = []byte("child body")
	fx.body["dir/inner/leaf.txt"] = []byte("leaf body")
	fx.body["tagged.txt"] = []byte("tagged body")

	fx.ino["base.txt"] = v.WriteFile(rootIno, "base.txt", fx.body["base.txt"])
	fx.ino["big.bin"] = v.WriteFile(rootIno, "big.bin", fx.body["big.bin"])
	fx.ino["huge.bin"] = v.WriteFile(rootIno, "huge.bin", fx.body["huge.bin"])
	fx.ino["dir"] = v.Mkdir(rootIno, "dir")
	fx.ino["dir/child.txt"] = v.WriteFile(fx.ino["dir"], "child.txt", fx.body["dir/child.txt"])
	fx.ino["dir/inner"] = v.Mkdir(fx.ino["dir"], "inner")
	fx.ino["dir/inner/leaf.txt"] = v.WriteFile(fx.ino["dir/inner"], "leaf.txt", fx.body["dir/inner/leaf.txt"])
	fx.ino["tagged.txt"] = v.WriteFile(rootIno, "tagged.txt", fx.body["tagged.txt"])
	fx.ino["link"] = v.Symlink(rootIno, "link", "base.txt")
	v.SetXattr(fx.ino["tagged.txt"], "user.color", []byte("blue"))

	fx.res = v.Publish(publish.Options{TargetPackSize: 2 << 20})
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
