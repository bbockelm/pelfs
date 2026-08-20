package memtable

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// A blocked write says so exactly once inside the window, and the
// occurrences it swallows cost nothing and are not forgotten.
//
// Both halves matter. A blocked write is never one write — the ring stays
// full for as long as the uplink is behind, so every writer that arrives
// blocks too — so a line per occurrence would bury the terminal in the
// one situation where the user most needs to read it, and formatting one
// per blocked writer would charge the stall for its own reporting.
func TestBlockedWriteWarnsOnceAndCostsNothingAfter(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()
	blockedReportedAt.Store(0)
	blockedSuppressed.Store(0)

	reportBlockedWrite(64 << 20)
	first := out.String()
	if !strings.Contains(first, "writes are pacing against the uplink") {
		t.Fatalf("the first blocked write said nothing useful: %q", first)
	}
	if !strings.Contains(first, "64.0 MiB") {
		t.Errorf("the notice does not say how far behind the uplink is: %q", first)
	}
	out.Reset()

	if n := testing.AllocsPerRun(200, func() { reportBlockedWrite(64 << 20) }); n != 0 {
		t.Errorf("a suppressed backpressure notice allocates %v times per call", n)
	}
	if out.Len() != 0 {
		t.Errorf("spoke again inside the rate-limit window: %q", out.String())
	}
	if blockedSuppressed.Load() == 0 {
		t.Fatal("suppressed occurrences were not counted")
	}

	// The next line that gets through carries what it swallowed, which is
	// the only remaining signal that this is happening in bulk.
	blockedReportedAt.Store(time.Now().Add(-2 * blockedReportEvery).UnixNano())
	reportBlockedWrite(96 << 20)
	second := out.String()
	if !strings.Contains(second, "other writes waited since the last notice") {
		t.Errorf("the report dropped the suppressed count: %q", second)
	}
	if blockedSuppressed.Load() != 0 {
		t.Error("the suppressed count was not cleared by the report that carried it")
	}
}

// The ring's own occupancy is reportable, which is the leading indicator
// for the blocked writes above: a ring at 5% free is a session about to
// pace against its uplink, and until it was surfaced the only signal was
// the stall itself.
func TestStatsReportTheRing(t *testing.T) {
	s, _ := newTestStore(t, 0, Hooks{})
	st := s.Stats()
	if st.RingUsed != 0 {
		t.Errorf("a fresh store reports %d bytes used", st.RingUsed)
	}
	if st.RingFree <= 0 {
		t.Fatalf("a fresh store reports %d bytes free; the ring is not being read", st.RingFree)
	}
	size := st.RingUsed + st.RingFree

	if err := s.Write(context.Background(), 1, 0, bytes.Repeat([]byte("x"), 4096)); err != nil {
		t.Fatal(err)
	}
	st = s.Stats()
	if st.RingUsed < 4096 {
		t.Errorf("after a 4 KiB write the ring reports %d bytes used", st.RingUsed)
	}
	if st.RingFree >= size {
		t.Errorf("free space did not fall after a write: %d of %d", st.RingFree, size)
	}
	// The pair is a partition of a fixed ring, so it has to keep summing
	// to the same number — a free count that drifts is worse than none.
	if got := st.RingUsed + st.RingFree; got != size {
		t.Errorf("used+free = %d after a write, was %d", got, size)
	}
}

// locationEntries is how many published handles the store is holding
// locations for. It is the map that used to grow with WRITE CALLS for the
// life of a session.
func locationEntries(s *Store) (handles, chunks, refs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.handleLoc), len(s.chunkLoc), len(s.locRefs)
}

// TestPublishedLocationsGoWhenNothingNamesThem is the C2 claim for the
// write path: handleLoc scaled with write CALLS, not bytes, and nothing
// ever freed it — so a session that wrote a million files carried their
// location entries to the end even after a checkpoint had published them
// and the overlay had forgotten the inodes.
//
// A handle is reachable ONLY from a content row, so an entry no row names
// can go. What must NOT go with it is the chunk half of the map: the
// seal's multi-pack index and the cross-flush dedup check both ask about
// chunks no current row names, and that is the whole point of them.
func TestPublishedLocationsGoWhenNothingNamesThem(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 0, Hooks{})

	body := bytes.Repeat([]byte("published extents"), 512)
	const files = 12
	for ino := uint64(1); ino <= files; ino++ {
		if err := s.Write(ctx, ino, 0, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	handles, chunks, refs := locationEntries(s)
	if handles < files {
		t.Fatalf("%d location entries after publishing %d files", handles, files)
	}
	if refs != handles {
		t.Errorf("%d location entries but %d reference counts; the two must agree", handles, refs)
	}
	if chunks == 0 {
		t.Fatal("no chunk locations after a flush")
	}

	// What a checkpoint does: the overlay drops the rows of the inodes it
	// returned to clean, and the content store forgets them.
	for ino := uint64(1); ino <= files; ino++ {
		if err := s.Forget(ino); err != nil {
			t.Fatal(err)
		}
	}
	afterHandles, afterChunks, afterRefs := locationEntries(s)
	if afterHandles != 0 {
		t.Errorf("%d location entries survive with no content row naming them", afterHandles)
	}
	if afterRefs != 0 {
		t.Errorf("%d reference counts survive their entries", afterRefs)
	}
	if afterChunks != chunks {
		t.Errorf("chunk locations fell from %d to %d: the multi-pack index and cross-flush "+
			"dedup both depend on chunks no current row names", chunks, afterChunks)
	}
	// The packs are still listed, because retention decides when those go
	// — not a file being deleted in a session that has not sealed yet.
	if len(s.Packs()) == 0 {
		t.Error("forgetting the inodes dropped the session's packs")
	}
}

// A superseded extent's location goes; the surviving one's stays, and the
// file still reads back. This is the partial case the reference count
// exists for — a whole-file Forget would pass with a much cruder rule.
func TestSupersededExtentLocationGoes(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 0, Hooks{})

	first := bytes.Repeat([]byte("A"), 4096)
	second := bytes.Repeat([]byte("B"), 4096)
	if err := s.Write(ctx, 1, 0, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, 2, 0, second); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	before, _, _ := locationEntries(s)

	// Overwrite inode 1 completely: its published extent loses its last
	// reference while inode 2's keeps hers.
	over := bytes.Repeat([]byte("C"), 4096)
	if err := s.Write(ctx, 1, 0, over); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	after, _, refs := locationEntries(s)
	if after != before {
		t.Errorf("location entries went %d -> %d across an overwrite; the superseded extent's "+
			"entry should have gone as the new one arrived", before, after)
	}
	if refs != after {
		t.Errorf("%d entries, %d reference counts", after, refs)
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, over) {
		t.Error("the overwritten file does not read back as the new content")
	}
	if got := readAll(t, s, 2); !bytes.Equal(got, second) {
		t.Error("the untouched file does not read back byte-exact")
	}
}
