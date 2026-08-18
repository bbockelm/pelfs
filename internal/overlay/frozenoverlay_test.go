package overlay_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
)

func openMemtableOverlay(t *testing.T, fx *fixture) (*overlay.FS, *memtable.Store) {
	t.Helper()
	store, _, closeStore, err := overlay.OpenContentStore(t.TempDir(), memtable.Options{
		TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeStore() }) //nolint:errcheck
	opts := fx.options()
	opts.Memtable = store
	ov, err := overlay.Open(t.TempDir(), fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ov.Close() }) //nolint:errcheck
	return ov, store
}

// A checkpoint over a memtable-backed overlay: the mount keeps writing,
// and the frozen view keeps answering with the instant it captured.
//
// This is the same isolation the staging store buys with pinned files, a
// hand-over protocol and a scratch directory — and here it is a copy of
// the extent maps, because extents are append-only.
func TestMemtableOverlaySnapshotIsolatesTheInstant(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "f202e0a0-0001-4000-8000-000000000001")
	ov, _ := openMemtableOverlay(t, fx)

	n, err := ov.Create(ctx, rootIno, "written.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	atInstant := pseudorandom(90000, 91)
	if _, err := ov.Write(ctx, n.Inode, 0, atInstant); err != nil {
		t.Fatal(err)
	}
	// A base file, adopted by reference and patched before the instant.
	baseIno := lookupPath(t, ov, "big.bin").Inode
	patch := pseudorandom(300, 92)
	if _, err := ov.Write(ctx, baseIno, 500, patch); err != nil {
		t.Fatal(err)
	}
	baseAtInstant := append([]byte(nil), fx.body["big.bin"]...)
	copy(baseAtInstant[500:], patch)

	snap, err := ov.Snapshot(ctx, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatalf("Snapshot of a memtable-backed overlay: %v", err)
	}
	defer snap.Close() //nolint:errcheck

	// The mount keeps working, in every shape that could leak through.
	if _, err := ov.Write(ctx, n.Inode, 1000, pseudorandom(600, 93)); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, n.Inode, int64(len(atInstant)), pseudorandom(5000, 94)); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, baseIno, 20000, pseudorandom(400, 95)); err != nil {
		t.Fatal(err)
	}
	after, err := ov.Create(ctx, rootIno, "after.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, after.Inode, 0, pseudorandom(3000, 96)); err != nil {
		t.Fatal(err)
	}
	small := int64(10)
	if _, err := ov.SetAttr(ctx, n.Inode, overlay.SetAttrIn{Size: &small}); err != nil {
		t.Fatal(err)
	}

	mustBody(t, snap, "written.bin", atInstant)
	mustBody(t, snap, "big.bin", baseAtInstant)
	if _, err := lookupPathErr(snap, "after.bin"); err == nil {
		t.Error("the frozen view sees a file created after the instant")
	}

	// The scratch holds no content: an append-only store has nothing to
	// copy out, which is the whole reason this is cheap.
	ents, err := os.ReadDir(filepath.Join(snapDirs[snap], "staging"))
	if err == nil && len(ents) != 0 {
		t.Errorf("the frozen view copied %d files into its scratch", len(ents))
	}
}

// The freeze itself must be cheap, because it runs with the overlay
// locked and the mount is that lock. The expensive half — flushing the
// ring — happens before it, with the mount still serving.
func TestMemtableOverlaySnapshotDoesNotCopyContent(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "f202e0a0-0002-4000-8000-000000000002")
	ov, store := openMemtableOverlay(t, fx)

	for i := 0; i < 200; i++ {
		n, err := ov.Create(ctx, rootIno, "f"+string(rune('a'+i%26))+string(rune('a'+i/26)), 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, pseudorandom(4000, int64(i))); err != nil {
			t.Fatal(err)
		}
	}
	before := store.Stats()
	snap, err := ov.Snapshot(ctx, filepath.Join(t.TempDir(), "snap"))
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close() //nolint:errcheck
	after := store.Stats()

	// Freezing writes nothing new: the flush it performs is the session's
	// own content going out, which was going out anyway.
	if after.WrittenBytes != before.WrittenBytes {
		t.Errorf("freezing wrote %d new bytes into the ring", after.WrittenBytes-before.WrittenBytes)
	}
	// Nothing was copied into the scratch, which is the structural form of
	// the claim: the freeze's content half is a map copy, and its cost
	// does not follow the number of files.
	ents, err := os.ReadDir(filepath.Join(snapDirs[snap], "staging"))
	if err == nil && len(ents) != 0 {
		t.Errorf("the freeze put %d files in its scratch", len(ents))
	}
	cost := snap.Cost()
	if cost.Freeze > cost.Vacuum {
		t.Errorf("freezing %d inodes of content took %v, longer than the VACUUM (%v); "+
			"the content half is supposed to be a map copy", cost.Staged, cost.Freeze, cost.Vacuum)
	}
	t.Logf("froze %d staged inodes in %v (vacuum %v, content %v, namespace %v)",
		cost.Staged, cost.Total(), cost.Vacuum, cost.Freeze, cost.Edges)
}
