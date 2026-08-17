package vfsbilly_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// Residency is bounded on the NFS binding (mount-gen sets MaxResident),
// so a long extraction is guaranteed to operate on inodes the base
// generation has forgotten. TestDirCacheSurvivesResidencyEviction pins
// that for reads; this pins it for the sequence a tar actually issues,
// which is where an ESTALE would be least visible -- go-nfs has no status
// for it, so it would reach the client as EIO on a create that in fact
// succeeded.
func TestExtractionSurvivesResidencyEviction(t *testing.T) {
	c := context.Background()
	fx := newFixture(t, "6ccc1111-2222-3333-4444-555566667777")
	base, err := genfs.Open(c, genfs.Options{
		Inner: fx.inner, SB: fx.res.Superblock, CacheDir: t.TempDir(),
		// Two resident inodes: every descent past the root evicts the
		// previous one, so nothing is ever resident when it is needed.
		MaxResident: 2,
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      fx.res.Superblock.NextInode,
		BaseRoot:       fx.res.Superblock.RootCatalog,
		BaseGeneration: fx.res.Superblock.Generation,
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = ov.Close() })

	bfs := vfsbilly.New(ov)
	ch := bfs.(billy.Change)
	mode := uint32(0o644)
	when := time.Unix(1700000000, 0)

	for i := 0; i < 60; i++ {
		dir := fmt.Sprintf("/dir/inner/deep%d/nested", i)
		if err := bfs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("%d: mkdir: %v", i, err)
		}
		name := fmt.Sprintf("%s/f%d.c", dir, i)
		writeWhole(t, bfs, name, []byte(fmt.Sprintf("body %d", i)))

		// The tail of a tar entry, and the part that go-nfs runs through
		// SetFileAttributes.Apply: an ESTALE from any of it is an EIO.
		attrs := &nfs.SetFileAttributes{SetMode: &mode, SetMtime: &when, SetAtime: &when}
		if err := attrs.Apply(ch, bfs, name); err != nil {
			t.Fatalf("%d: apply: %v", i, err)
		}
		// Touch the base tree in between so the churn keeps evicting.
		if _, err := bfs.Stat("/dir/inner/leaf.txt"); err != nil {
			t.Fatalf("%d: stat base leaf: %v", i, err)
		}
		if _, err := bfs.Stat("/base.txt"); err != nil {
			t.Fatalf("%d: stat base file: %v", i, err)
		}
	}

	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("/dir/inner/deep%d/nested/f%d.c", i, i)
		if got := readWhole(t, bfs, name); string(got) != fmt.Sprintf("body %d", i) {
			t.Fatalf("%s = %q", name, got)
		}
		fi, err := bfs.Lstat(name)
		if err != nil {
			t.Fatalf("lstat %s: %v", name, err)
		}
		if fi.Mode().Perm() != 0o644 || !fi.ModTime().Equal(when) {
			t.Fatalf("%s attributes = %v %v", name, fi.Mode(), fi.ModTime())
		}
	}
}
