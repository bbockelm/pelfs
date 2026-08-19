package reach

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// feed builds a synthetic volume's worth of placements and references —
// n distinct identities, each placed once and referenced once — and joins
// them, returning the heap the join itself needed.
func feed(t *testing.T, n, budget int) (heapMiB uint64) {
	t.Helper()
	dir := t.TempDir()
	places := newSorter(dir, "places", idLen, placeLen, budget)
	refs := newSorter(dir, "refs", idLen, idLen, budget)
	defer places.Close() //nolint:errcheck
	defer refs.Close()   //nolint:errcheck

	batch := make([]byte, 0, 512*placeLen)
	rbatch := make([]byte, 0, 512*idLen)
	var id [32]byte
	flush := func() {
		if err := places.Add(batch); err != nil {
			t.Fatal(err)
		}
		if err := refs.Add(rbatch); err != nil {
			t.Fatal(err)
		}
		batch, rbatch = batch[:0], rbatch[:0]
	}
	for i := range n {
		// Identities are hashes, so successive ones land far apart and the
		// runs interleave in the merge rather than concatenating.
		binary.BigEndian.PutUint64(id[:], uint64(i)*0x9E3779B97F4A7C15)
		binary.BigEndian.PutUint64(id[8:], uint64(i))
		var rec [placeLen]byte
		putPlace(rec[:], id, i%100_000, 4096, 0)
		batch = append(batch, rec[:]...)
		rbatch = append(rbatch, id[:]...)
		if len(batch) == cap(batch) {
			flush()
		}
	}
	flush()

	s := &sweeper{packs: make([]Pack, 100_000), places: places, refs: refs}
	rep := &Report{}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s.join(rep)
	runtime.ReadMemStats(&after)

	if len(s.failures) > 0 {
		t.Fatalf("join failed: %v", s.failures)
	}
	var live int64
	for _, p := range s.packs {
		live += p.LiveEntries
	}
	if live != int64(n) {
		t.Fatalf("%d entries credited, want %d", live, n)
	}
	if rep.Unresolved != 0 {
		t.Fatalf("%d references resolved in no pack", rep.Unresolved)
	}
	return (after.HeapInuse - min(after.HeapInuse, before.HeapInuse)) >> 20
}

// The point of streaming is that memory stops tracking object count. This
// joins four times as much and asserts the heap does not follow — the one
// property that decides whether a hundred-million-object volume can be
// swept at all.
//
// Skipped in -short: it writes a few hundred MB of runs.
func TestJoinMemoryDoesNotTrackObjectCount(t *testing.T) {
	if testing.Short() {
		t.Skip("scale measurement")
	}
	const budget = 4 << 20
	small := feed(t, 500_000, budget)
	large := feed(t, 2_000_000, budget)
	t.Logf("500k objects: join heap %d MiB; 2M objects: %d MiB (buffer %d MiB)", small, large, budget>>20)
	// Four times the objects. A resident index would be four times the
	// memory. A merge is the buffer plus one read buffer per run, and runs
	// are bytes/budget — so the growth term here is 256 KiB per additional
	// run and not 45 bytes per additional object, which is the whole
	// difference. The bound is loose on purpose: it is meant to catch
	// something being HELD, not to pin the run arithmetic.
	if large > small+32 {
		t.Fatalf("joining 4x the objects cost %d MiB more heap (%d -> %d); the join is holding something",
			large-small, small, large)
	}
}
