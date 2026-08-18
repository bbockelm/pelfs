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

// A memtable-backed overlay, crashed and reopened. Nothing carries over in
// memory: the store is rebuilt from the journal on disk and the ring file
// beside it, exactly as a remount would rebuild it.
//
// The shapes here are the ones a replay can get wrong: a write landing
// inside an earlier one, a file inherited from the base and then patched,
// a truncate, and a file removed outright. All of it spans a flush, so
// some content is in packs and some is still in the ring — the split a
// crash actually finds.
func TestMemtableOverlaySurvivesACrash(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "10c0a1ed-0001-4000-8000-000000000001")
	contentDir := t.TempDir()
	overlayDir := t.TempDir()

	memOpts := memtable.Options{
		TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	}
	store, rep, closeStore, err := overlay.OpenContentStore(contentDir, memOpts)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Loss() {
		t.Fatalf("a fresh content store reported loss:\n%s", rep)
	}
	opts := fx.options()
	opts.Memtable = store
	ov, err := overlay.Open(overlayDir, fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]byte{}

	// A file this session creates, patched in the middle.
	fresh, err := ov.Create(ctx, rootIno, "fresh.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := pseudorandom(120000, 71)
	if _, err := ov.Write(ctx, fresh.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	patch := pseudorandom(500, 72)
	if _, err := ov.Write(ctx, fresh.Inode, 4000, patch); err != nil {
		t.Fatal(err)
	}
	copy(body[4000:], patch)
	want["fresh.bin"] = body

	// A file inherited from the base, patched: adopted by reference, so
	// the journal has to record the reference and not the bytes.
	inherited := lookupPath(t, ov, "big.bin").Inode
	basePatch := pseudorandom(200, 73)
	if _, err := ov.Write(ctx, inherited, 700, basePatch); err != nil {
		t.Fatal(err)
	}
	inheritedWant := append([]byte(nil), fx.body["big.bin"]...)
	copy(inheritedWant[700:], basePatch)
	want["big.bin"] = inheritedWant

	// Half the content reaches packs; the rest stays in the ring.
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tail := pseudorandom(7000, 74)
	if _, err := ov.Write(ctx, fresh.Inode, int64(len(want["fresh.bin"])), tail); err != nil {
		t.Fatal(err)
	}
	want["fresh.bin"] = append(want["fresh.bin"], tail...)

	// A truncate and a removal, both of which a replay must reproduce.
	trunc, err := ov.Create(ctx, rootIno, "trunc.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, trunc.Inode, 0, pseudorandom(30000, 75)); err != nil {
		t.Fatal(err)
	}
	small := int64(1234)
	if _, err := ov.SetAttr(ctx, trunc.Inode, overlay.SetAttrIn{Size: &small}); err != nil {
		t.Fatal(err)
	}
	want["trunc.bin"] = readAllFS(t, ov, trunc.Inode, int(small))

	doomed, err := ov.Create(ctx, rootIno, "doomed.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, doomed.Inode, 0, pseudorandom(9000, 76)); err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "doomed.bin"); err != nil {
		t.Fatal(err)
	}

	// The crash: everything in memory is gone, both databases and the ring
	// file are whatever they were.
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closeStore(); err != nil {
		t.Fatal(err)
	}

	store2, rep2, closeStore2, err := overlay.OpenContentStore(contentDir, memOpts)
	if err != nil {
		t.Fatalf("reopen the content store: %v", err)
	}
	defer closeStore2() //nolint:errcheck
	if rep2.Loss() {
		t.Fatalf("reopening after a clean close reported loss:\n%s", rep2)
	}
	opts2 := fx.options()
	opts2.Memtable = store2
	ov2, err := overlay.Open(overlayDir, fx.base, opts2)
	if err != nil {
		t.Fatal(err)
	}
	defer ov2.Close() //nolint:errcheck

	for name, body := range want {
		mustBody(t, ov2, name, body)
	}
	if _, err := lookupPathErr(ov2, "doomed.bin"); err == nil {
		t.Error("a removed file came back after recovery")
	}
}

// The journal is a separate database file on purpose (see journal.go).
// This pins the arrangement, because sharing the overlay's single
// connection is a deadlock rather than a slowdown.
func TestContentJournalIsItsOwnDatabase(t *testing.T) {
	fx := newFixture(t, "10c0a1ed-0002-4000-8000-000000000002")
	dir := t.TempDir()
	_, _, closeStore, err := overlay.OpenContentStore(dir, memtable.Options{
		TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore() //nolint:errcheck
	if _, err := os.Stat(filepath.Join(dir, "content.db")); err != nil {
		t.Fatalf("the content journal is not where it says it is: %v", err)
	}
}
