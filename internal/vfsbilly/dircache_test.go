package vfsbilly_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
	nfsfile "github.com/willscott/go-nfs/file"
)

// fileid reports the inode a path resolves to, which is the only way to
// see WHICH object an answer came from — the question a memoized descent
// has to keep getting right.
func fileid(t *testing.T, fi os.FileInfo) uint64 {
	t.Helper()
	id := nfsfile.GetInfo(fi)
	if id == nil {
		t.Fatalf("FileInfo carries no nfs identity: %#v", fi)
	}
	return id.Fileid
}

// A directory replaced by a fresh one of the same name must resolve to the
// NEW inode, and everything below it to the new subtree.
func TestDirCacheFollowsReplacedDirectory(t *testing.T) {
	bfs, _ := newRW(t, "1bbb1111-2222-3333-4444-555566667777")

	if err := bfs.MkdirAll("/p/q", 0755); err != nil {
		t.Fatal(err)
	}
	writeWhole(t, bfs, "/p/q/old.txt", []byte("first"))
	first, err := bfs.Stat("/p/q")
	if err != nil {
		t.Fatal(err)
	}

	if err := bfs.Remove("/p/q/old.txt"); err != nil {
		t.Fatal(err)
	}
	if err := bfs.Remove("/p/q"); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/p/q"); !os.IsNotExist(err) {
		t.Fatalf("Stat of a removed dir = %v, want not-exist", err)
	}
	if err := bfs.MkdirAll("/p/q", 0755); err != nil {
		t.Fatal(err)
	}
	second, err := bfs.Stat("/p/q")
	if err != nil {
		t.Fatal(err)
	}
	if fileid(t, first) == fileid(t, second) {
		t.Fatalf("the replacement dir reused inode %d", fileid(t, first))
	}
	if _, err := bfs.Stat("/p/q/old.txt"); !os.IsNotExist(err) {
		t.Fatalf("a child of the OLD directory resolved through the new one: %v", err)
	}
	writeWhole(t, bfs, "/p/q/new.txt", []byte("second"))
	if got := readWhole(t, bfs, "/p/q/new.txt"); string(got) != "second" {
		t.Fatalf("content under the replacement dir = %q", got)
	}
}

// A directory replaced by a FILE of the same name must stop being
// traversable, rather than remaining a remembered edge.
func TestDirCacheFollowsDirectoryReplacedByFile(t *testing.T) {
	bfs, _ := newRW(t, "2bbb1111-2222-3333-4444-555566667777")

	if err := bfs.MkdirAll("/swap/inner", 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/swap/inner"); err != nil {
		t.Fatal(err)
	}
	if err := bfs.Remove("/swap/inner"); err != nil {
		t.Fatal(err)
	}
	writeWhole(t, bfs, "/swap/inner", []byte("now a file"))

	if _, err := bfs.Stat("/swap/inner/child"); !errors.Is(err, syscall.ENOTDIR) && !os.IsNotExist(err) {
		t.Fatalf("descent through a file = %v, want ENOTDIR or not-exist", err)
	}
	if err := bfs.MkdirAll("/swap/inner/child", 0755); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("MkdirAll through a file = %v, want ENOTDIR", err)
	}
	if got := readWhole(t, bfs, "/swap/inner"); string(got) != "now a file" {
		t.Fatalf("replacement file content = %q", got)
	}
}

// A renamed directory keeps its identity, so the subtree under it must
// resolve unchanged at the new name and not at all at the old one.
func TestDirCacheFollowsRenamedDirectory(t *testing.T) {
	bfs, _ := newRW(t, "3bbb1111-2222-3333-4444-555566667777")

	if err := bfs.MkdirAll("/one/two/three", 0755); err != nil {
		t.Fatal(err)
	}
	writeWhole(t, bfs, "/one/two/three/f.txt", []byte("body"))
	before, err := bfs.Stat("/one/two/three")
	if err != nil {
		t.Fatal(err)
	}

	if err := bfs.Rename("/one/two", "/one/moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/one/two/three/f.txt"); !os.IsNotExist(err) {
		t.Fatalf("the old path still resolves after rename: %v", err)
	}
	after, err := bfs.Stat("/one/moved/three")
	if err != nil {
		t.Fatal(err)
	}
	if fileid(t, before) != fileid(t, after) {
		t.Fatalf("rename changed the subtree's identity: %d -> %d", fileid(t, before), fileid(t, after))
	}
	if got := readWhole(t, bfs, "/one/moved/three/f.txt"); string(got) != "body" {
		t.Fatalf("content under the renamed dir = %q", got)
	}

	// Renaming a directory ONTO an existing empty one rebinds the target
	// name to a different inode.
	if err := bfs.MkdirAll("/one/target", 0755); err != nil {
		t.Fatal(err)
	}
	victim, err := bfs.Stat("/one/target")
	if err != nil {
		t.Fatal(err)
	}
	if err := bfs.Rename("/one/moved", "/one/target"); err != nil {
		t.Fatal(err)
	}
	now, err := bfs.Stat("/one/target")
	if err != nil {
		t.Fatal(err)
	}
	if fileid(t, now) == fileid(t, victim) {
		t.Fatalf("/one/target still resolves to the replaced inode %d", fileid(t, victim))
	}
	if got := readWhole(t, bfs, "/one/target/three/f.txt"); string(got) != "body" {
		t.Fatalf("content under the rename target = %q", got)
	}
}

// Residency is bounded on the NFS binding, so a memoized descent WILL
// eventually reach an inode the layer below has forgotten. That must
// re-walk rather than surface ESTALE to the client.
func TestDirCacheSurvivesResidencyEviction(t *testing.T) {
	c := context.Background()
	fx := newFixture(t, "4bbb1111-2222-3333-4444-555566667777")
	base, err := genfs.Open(c, genfs.Options{
		Inner: fx.inner, SB: fx.res.Superblock, CacheDir: t.TempDir(),
		// Small enough that walking the fixture twice evicts the first
		// walk's directories.
		MaxResident: 2,
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	bfs := vfsbilly.NewReadOnly(base)

	want := fx.body["dir/inner/leaf.txt"]
	for i := 0; i < 20; i++ {
		// Churn other paths between reads so the leaf's ancestors are
		// pushed out of residency each time round.
		for _, p := range []string{"/base.txt", "/big.bin", "/tagged.txt", "/dir/child.txt"} {
			if _, err := bfs.Stat(p); err != nil {
				t.Fatalf("iteration %d: Stat %s: %v", i, p, err)
			}
		}
		fi, err := bfs.Stat("/dir/inner/leaf.txt")
		if err != nil {
			t.Fatalf("iteration %d: Stat leaf: %v", i, err)
		}
		if fileid(t, fi) != fx.ino["dir/inner/leaf.txt"] {
			t.Fatalf("iteration %d: leaf resolved to inode %d", i, fileid(t, fi))
		}
		if got := readWhole(t, bfs, "/dir/inner/leaf.txt"); string(got) != string(want) {
			t.Fatalf("iteration %d: leaf content = %q", i, got)
		}
		if got := names(mustReadDir(t, bfs, "/dir/inner")); len(got) != 1 || got[0] != "leaf.txt" {
			t.Fatalf("iteration %d: ReadDir /dir/inner = %v", i, got)
		}
	}
}

func mustReadDir(t *testing.T, bfs interface {
	ReadDir(string) ([]os.FileInfo, error)
}, p string) []os.FileInfo {
	t.Helper()
	fis, err := bfs.ReadDir(p)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", p, err)
	}
	return fis
}

// A wide tree built and then re-read end to end: the memoized descent has
// to give the same answer for hundreds of sibling directories, not just
// the last one walked.
func TestDirCacheWideTree(t *testing.T) {
	bfs, _ := newRW(t, "5bbb1111-2222-3333-4444-555566667777")

	const dirs = 400
	for i := 0; i < dirs; i++ {
		p := fmt.Sprintf("/wide/d%d/inner", i)
		if err := bfs.MkdirAll(p, 0755); err != nil {
			t.Fatalf("MkdirAll %s: %v", p, err)
		}
		writeWhole(t, bfs, p+"/f.txt", []byte(fmt.Sprintf("body %d", i)))
	}
	for i := 0; i < dirs; i++ {
		p := fmt.Sprintf("/wide/d%d/inner/f.txt", i)
		if got := readWhole(t, bfs, p); string(got) != fmt.Sprintf("body %d", i) {
			t.Fatalf("%s = %q", p, got)
		}
	}
}
