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
