package memtable

import (
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// A session writes in whatever sizes the kernel hands it — 4 KiB at a
// time for an untar — and the packer must not turn that into one pack per
// write.
//
// Promotable is used-distance, so a run leaves the residue at zero and
// the next write makes it exactly that write's size. Starting a run on
// "anything has aged" therefore cut ONE BATCH PER WRITE. Against a real
// federation that meant thousands of 3-6 KiB packs, each a round trip of
// several seconds, and a seal that moved 25 MB of a 1.7 GB tree in two
// minutes. Federation cost is per object before it is per byte.
//
// The assertion is on the RATIO, not on a count: what matters is that
// batches scale with bytes written rather than with writes issued.
//
// The test PACES the writer behind the packer, which is the regime the
// bug lives in and the one an in-memory benchmark never reaches. When
// writes outrun flushes, a batch is "everything that arrived while the
// last flush ran" and comes out a healthy 2 MiB; when the packer keeps
// up — a real uplink, a real untar at 10 MB/s — that same rule makes the
// batch "everything that arrived since a moment ago", and it collapses
// toward one write. It is self-reinforcing: a smaller batch flushes
// faster, which makes the next batch smaller still. The session that
// found this averaged 38 KB per pack against a 2 MiB target.
func TestPromotionBatchesAPackAtATime(t *testing.T) {
	const (
		ring      = 8 << 20
		distance  = 4 << 20
		target    = 1 << 20
		writeSize = 4 << 10
		// Well past the ring, so it stays SATURATED: the pathology needs
		// used to sit just above the distance write after write, which is
		// what a long untar does and what a short one never reaches.
		total = 64 << 20
	)
	obj := newCountingStore()
	s, err := New(Options{
		Dir:               t.TempDir(),
		TableSize:         ring,
		PromotionDistance: distance,
		PackTarget:        target,
		Obj:               obj,
		Chunk:             chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	ctx := context.Background()
	buf := make([]byte, writeSize)
	var off int64
	for written := 0; written < total; written += writeSize {
		// Incompressible and distinct, so nothing dedups away and the
		// bytes really do age through the ring.
		for i := range buf {
			buf[i] = byte(written>>8) ^ byte(i*7)
		}
		if err := s.Write(ctx, 1, off, buf); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
		off += writeSize
		s.awaitIdlePacker()
	}

	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	writes := int64(total / writeSize)
	flushes := s.Stats().Flushes
	// A batch per write is the bug; a batch per pack's worth is the fix.
	// The bound is generous — the blocked-writer path may add runs of its
	// own under pressure — and still an order of magnitude under "one
	// each".
	if ceiling := 4 * int64(total/target); flushes > ceiling {
		t.Fatalf("%d writes of %d bytes produced %d pack runs (ceiling %d); "+
			"the packer is batching per write rather than per pack",
			writes, writeSize, flushes, ceiling)
	}
	t.Logf("%d writes of %d bytes -> %d pack runs (%d writes per run)", writes, writeSize, flushes, writes/max(flushes, 1))
}

// The threshold must never exceed the runway between the promotion
// distance and the ring, or aging can never reach it and packing falls
// back to the blocked-writer path — the stop-start mount the runway
// exists to prevent.
func TestPromoteThresholdIsCappedByTheRunway(t *testing.T) {
	s, err := New(Options{
		Dir:               t.TempDir(),
		TableSize:         8 << 20,
		PromotionDistance: 6 << 20, // 2 MiB of runway
		PackTarget:        64 << 20,
		Obj:               newCountingStore(),
		Chunk:             smallChunks,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck
	if runway := int64(8<<20) - int64(6<<20); s.promoteAt > runway/2 {
		t.Fatalf("a %d-byte pack target with %d bytes of runway promotes at %d; aging can never reach it",
			64<<20, runway, s.promoteAt)
	}
	t.Logf("pack target 64 MiB, runway 2 MiB -> promoting at %d bytes", s.promoteAt)
}

// awaitIdlePacker blocks until no pack run is in flight, so the next
// write lands in a store the packer has already caught up with. That is
// the pacing the production regime has and an in-memory loop does not.
func (s *Store) awaitIdlePacker() {
	s.mu.Lock()
	for s.packing {
		s.cond.Wait()
	}
	s.mu.Unlock()
}
