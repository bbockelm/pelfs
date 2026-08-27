package memtable

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// A session writes in whatever sizes the kernel hands it — 4 KiB at a
// time for an untar — and the packer must not turn that into one pack per
// write.
//
// A run takes everything that has aged and is not already claimed by an
// earlier run, so it leaves that quantity at zero and the next write makes
// it exactly that write's size. Starting a run on "anything has aged"
// therefore cut ONE BATCH PER WRITE. Against a real
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
		// The bytes age through the ring, which is what this measures,
		// and they REPEAT: byte(written>>8) at 4 KiB a write comes back
		// around every sixteenth write, so the chunker sees content it
		// has already placed and the packer skips the upload. That is
		// deliberate and it is left alone, because the assertion here is
		// on the number of pack RUNS and a run is started by the ring's
		// aging rule, which cannot see chunk identity at all. Filling
		// this with distinct bytes instead costs six times the runtime,
		// measured back to back, for a figure that barely moves (61 runs
		// rather than 72); the frozen-tail test below is the one that
		// needs real bytes and uses fillDistinct for them.
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

// THE REGION AWAITING ITS LOCATED RECORD IS NOT PROMOTABLE, and this is
// the deterministic form of the test above.
//
// TestPromotionBatchesAPackAtATime asserts the right thing and cannot
// prove it on an idle machine: it measures a ratio at the end of a run
// that packs, uploads and journals as fast as the local disk allows, so
// the tail keeps up with the writer and the trigger is never asked the
// question that matters. It failed on macos-latest and passed on every
// re-run, which is the signature of an assertion whose sensitivity is the
// runner's load.
//
// The question that matters is what "promotable" counts. A batch's ring
// region is held until its Located record is durable, so between publish
// and that record the region is occupied by bytes that have already been
// packed. A trigger measuring OCCUPANCY (head-tail-distance) counts them,
// stays satisfied for as long as the record is in flight, and starts a run
// on every write — each cutting the one extent that aged since the last.
// One batch per write, which is the pathology the test above is named for.
//
// So the record is held here on purpose, for the whole write loop, with no
// sleep and no timing anywhere: the tail CANNOT move, and the run count
// must not care. Under the occupancy rule this fails by two orders of
// magnitude; under a trigger that measures the span the cut would actually
// take, it is the same handful of runs it would be with an instant uplink.
func TestAFrozenTailDoesNotMakeEveryWriteAPackRun(t *testing.T) {
	const (
		ring     = 8 << 20
		distance = 4 << 20
		target   = 1 << 20
		write    = 4 << 10
		// Deliberately under the ring: with the tail frozen nothing is
		// ever reclaimed, so a larger total would block the writer and
		// this would be a backpressure test instead.
		total = 6 << 20
	)
	j := &gatedJournal{memJournal: newMemJournal(), gate: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(j.gate) }) }

	s, err := New(Options{
		Dir:               t.TempDir(),
		TableSize:         ring,
		PromotionDistance: distance,
		PackTarget:        target,
		Obj:               newCountingStore(),
		Journal:           j,
		Chunk:             chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Close first, release second, so that the LIFO order runs release
	// FIRST. Close waits on the flusher goroutines and every one of them
	// is parked in Located; unwinding the other way round hangs the
	// package instead of reporting a number, which is what a failing run
	// of this test did before the order was fixed.
	defer s.Close() //nolint:errcheck
	defer release()

	ctx := context.Background()
	buf := make([]byte, write)
	var off int64
	for written := 0; written < total; written += write {
		fillDistinct(buf, int64(written))
		if err := s.Write(ctx, 1, off, buf); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
		off += write
		s.awaitIdlePacker()
	}
	runs := s.Stats().Flushes

	// THE PREMISE, checked rather than assumed, and checked against state
	// the writer's own lock orders. A pass here means nothing unless a
	// batch really did publish and really is stuck, so both halves are
	// asserted — and neither may be read off the flusher's progress. The
	// obvious form, "Located has been called at least once", is a RACE:
	// publish releases the packing flag, and only after that does the
	// flusher wait for its uploads and call Located, so the write loop can
	// finish before the flusher has arrived. It failed three times in two
	// thousand runs under load, which is exactly the kind of test this
	// branch exists to stop shipping.
	//
	// s.locating carries no such race: publish appends to it and clears
	// packing in ONE lock hold, so a batch that has published is on this
	// queue before awaitIdlePacker can return.
	s.mu.Lock()
	published := len(s.locating)
	s.mu.Unlock()
	if published == 0 {
		t.Fatal("no batch published, so no region was ever stuck waiting for a Located record " +
			"and this test asked the trigger nothing")
	}
	if got := s.ring.Tail(); got != 0 {
		t.Fatalf("the tail advanced to %d with every Located record still held; "+
			"this test proves nothing unless the region really is stuck", got)
	}
	// Two runs' worth of slack over the ideal (total-distance)/target, and
	// still two orders of magnitude under one-per-write.
	ceiling := int64((total-distance)/target) + 2
	if runs > ceiling {
		t.Fatalf("%d bytes written with the tail frozen produced %d pack runs (ceiling %d): "+
			"promotion is counting the region of a batch that is already packed and merely "+
			"waiting for its Located record, so every write starts a run of one extent",
			total, runs, ceiling)
	}
	t.Logf("%d bytes with a frozen tail -> %d pack runs (ceiling %d)", total, runs, ceiling)

	// And the held records really do land once they are let go, so the
	// gate modelled a slow uplink rather than a broken journal. Flush
	// waits for every outstanding Located record, so both checks below are
	// ordered by it and neither is a guess about the flusher's progress.
	release()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if j.locatedCalls() == 0 {
		t.Fatal("the gate was released and flushed and no Located record was ever attempted")
	}
	if s.ring.Tail() == 0 {
		t.Fatal("the tail never moved after the records landed, so the gate was a broken " +
			"journal and not a slow uplink")
	}
}

// gatedJournal holds every Located record until it is released. The store
// calls Located OFF its own lock, from the flusher, so holding one here
// stops the ring's tail without stopping the writer — which is exactly the
// production window a slow uplink opens.
type gatedJournal struct {
	*memJournal
	gate  chan struct{}
	calls atomic.Int64
}

func (j *gatedJournal) Located(l Location) error {
	j.calls.Add(1)
	<-j.gate
	return j.memJournal.Located(l)
}

func (j *gatedJournal) locatedCalls() int64 { return j.calls.Load() }

// fillDistinct writes a buffer no other offset produces.
//
// Repeated content still ages through the ring — dedup happens at pack
// time and the ring never sees it — so it does not change a run COUNT.
// What it changes is what a run costs: a repeat is recognised, skipped,
// and never uploaded, so a fixture built out of repeats exercises the
// aging rule and almost nothing below it. The obvious one-byte counter is
// such a fixture without saying so: at 4 KiB a write, byte(off>>8) comes
// back around every sixteenth write.
func fillDistinct(buf []byte, off int64) {
	lo, hi := byte(off>>12), byte(off>>20)
	for i := range buf {
		buf[i] = lo ^ hi ^ byte(i*7)
	}
}
