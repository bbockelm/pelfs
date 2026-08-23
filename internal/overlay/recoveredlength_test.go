package overlay_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// A file's length lives in two places and only one of them is what a
// reader sees, so a recovery that cut the content store's extent map has
// to cut the overlay's node row with it.
//
// The crash is simulated the way memtable's own recovery tests do it —
// Store.Durable minus the location record one flush's crash would not have
// written — because that is the state, and reaching it by killing
// something would only add a race to the reproduction. What is being held
// here is the OTHER half: stat answers out of onode.length and Read clamps
// to it, so a node row that still believes the old length turns a cut
// extent map back into a hole and serves the missing range as zeros.
func TestARecoveredCutIsAppliedToTheNodeLength(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "c0f0c0f0-0009-4000-8000-000000000009")
	memDir := t.TempDir()
	ovDir := t.TempDir()
	memOpts := memtable.Options{
		Dir: memDir, TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	}

	store, err := memtable.New(memOpts)
	if err != nil {
		t.Fatal(err)
	}
	opts := fx.options()
	opts.Memtable = store
	ov, err := overlay.Open(ovDir, fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ov.Create(ctx, rootIno, "crashed.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := pseudorandom(12000, 9)
	if _, err := ov.Write(ctx, n.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	if got, err := ov.GetAttr(ctx, n.Inode); err != nil || got.Length != 12000 {
		t.Fatalf("before the crash: length %d, err %v", got.Length, err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// Everything the flush recorded, dropped: the crash landed between the
	// batch's publish and its location record.
	d := store.Durable()
	if len(d.Handles) == 0 {
		t.Fatal("the flush recorded no locations, so there is nothing for a crash to lose")
	}
	crashed := memtable.Durable{Rows: d.Rows, Chunks: d.Chunks, Packs: d.Packs,
		Adopted: d.Adopted, AdoptedRefs: d.AdoptedRefs}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, rep, err := memtable.Recover(memOpts, crashed)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close() //nolint:errcheck
	if !rep.Loss() {
		t.Fatal("the crash reported no loss")
	}
	opts = fx.options()
	opts.Memtable = recovered
	ov2, err := overlay.Open(ovDir, fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer ov2.Close() //nolint:errcheck

	got, err := ov2.GetAttr(ctx, n.Inode)
	if err != nil {
		t.Fatal(err)
	}
	if got.Length != 0 {
		// The failure this test exists for: the node still claims the full
		// length after everything under it was lost, so stat reports a
		// whole file and every byte a reader gets out of it is one the
		// extent map does not hold.
		buf := make([]byte, got.Length)
		read, rerr := ov2.Read(ctx, n.Inode, 0, buf)
		t.Fatalf("the recovered node is still %d bytes long after its content was lost; "+
			"a read of it returned %d bytes (all zeros: %v), err %v",
			got.Length, read, bytes.Equal(buf[:read], make([]byte, read)), rerr)
	}
	if body := readAllFS(t, ov2, n.Inode, 0); len(body) != 0 {
		t.Fatalf("the cut node read %d bytes", len(body))
	}
}
