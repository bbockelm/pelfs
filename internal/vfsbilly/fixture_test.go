package vfsbilly_test

import (
	"context"
	mrand "math/rand"
	"net/http/httptest"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
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

// fixtureCred is the identity these fixtures are mounted as, and it is 0:0
// on purpose. testvol stamps every node it creates with uid 0 / gid 0,
// while publish.InitVolume owns the ROOT as the process that ran it — so a
// fixture tree is a volume whose content belongs to root and whose root
// directory belongs to whoever ran `go test`. Mounted as the test process,
// every file in it is other-class and unwritable, which is not a quirk of
// the check added in perm.go: it is exactly what the kernel does to the
// FUSE frontend today, for the same tree, from the same attributes.
//
// Mounting as 0:0 makes the fixture self-consistent, the way a real volume
// is: the identity that wrote the content is the identity that mounts it.
// Tests that want a non-owner build one explicitly (perm_test.go).
var fixtureCred = vfsbilly.Cred{UID: 0, GID: 0}

// newBilly is vfsbilly.New for the fixtures — see fixtureCred.
func newBilly(ov *overlay.FS) billy.Filesystem { return vfsbilly.NewAs(ov, fixtureCred) }

// newBillyReadOnly is vfsbilly.NewReadOnly for the fixtures.
func newBillyReadOnly(fs *genfs.FS) billy.Filesystem {
	return vfsbilly.NewReadOnlyAs(fs, fixtureCred)
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
