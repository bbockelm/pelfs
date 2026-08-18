package memtable

import (
	"context"
	"strings"
	"testing"
)

// The two defaults that turned a mount into a stop-start machine, pinned.
//
// Promotion is used-minus-distance, so a ring no larger than the distance
// can never age anything out — and the only path left is the one where a
// writer has already blocked on a full ring. The mount then stops for the
// length of an upload, over and over, which is what a kernel untar found.
func TestDefaultsLeaveRunwayForAging(t *testing.T) {
	if DefaultTableSize <= DefaultPromotionDistance {
		t.Fatalf("a %d-byte ring with a %d-byte promotion distance can never promote by age",
			DefaultTableSize, DefaultPromotionDistance)
	}
	runway := int64(DefaultTableSize) - int64(DefaultPromotionDistance)
	if cap := int64(MaxRecord(DefaultTableSize)); runway <= cap {
		t.Fatalf("runway %d does not clear the %d-byte record cap", runway, cap)
	}
}

// And a configuration that gets it wrong must be refused rather than
// silently stall: the failure mode is a slow mount, which is the hardest
// kind of bug to attribute.
func TestAStoreWithNoRunwayIsRefused(t *testing.T) {
	obj := newCountingStore()
	_, err := New(Options{
		Dir: t.TempDir(), TableSize: 1 << 20, PromotionDistance: 1 << 20, Obj: obj, Chunk: smallChunks,
	})
	if err == nil {
		t.Fatal("a ring equal to its promotion distance was accepted")
	}
	if !strings.Contains(err.Error(), "runway") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

// Packs are cut at the FORMAT's size, not the ring's. A pack is not
// readable or reclaimable until the whole of it lands, so cutting at the
// ring size made every upload a monolith the mount had to wait behind.
func TestPacksAreCutAtThePackTarget(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 8 << 20, Obj: obj, Chunk: smallChunks,
		PackTarget: 256 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck
	for ino := uint64(1); ino <= 8; ino++ {
		if err := s.Write(ctx, ino, 0, fill(400<<10, ino)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	packs := s.Packs()
	if len(packs) < 8 {
		t.Errorf("%d packs for 3.2 MiB at a 256 KiB cut; the target is not being applied", len(packs))
	}
	for _, p := range packs {
		if p.Size > 4*(256<<10) {
			t.Errorf("pack %s is %d bytes against a 256 KiB target", p.Name, p.Size)
		}
	}
	t.Logf("3.2 MiB cut into %d packs", len(packs))
}
