package repack

import (
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// These are in the INTERNAL test package because the thing under test is
// the pacing decision itself, and driving it through Execute would mean
// building a volume with more dead packs than the ledger's budget holds —
// minutes of fixture for arithmetic that is twenty lines.

// candidateName is the shape a real pack wears — `p-<nanos>-<rand>`, 23
// characters — because what a candidate consumes is what its ledger ROW
// costs, and a row's cost is the length of its name plus a timestamp.
func candidateName(i int) string { return fmt.Sprintf("p-%016x-0001", i) }

// packRowsThatFit is how many candidates of that shape the ledger's byte
// budget holds when nothing is carried. Under a row cap this was the
// constant 512; in bytes it is ~927, because a pack row costs 53 bytes
// against the 95 a hash-named ref row costs and the share is the same.
func packRowsThatFit(now time.Time) int {
	return int(superblock.CondemnedPackRoom(nil) / superblock.CondemnedRowBytes(candidateName(0), now))
}

func candidates(n int) []PackCandidate {
	out := make([]PackCandidate, n)
	for i := range out {
		out[i] = PackCandidate{
			Name: candidateName(i),
			// Ascending reclaim, so "kept the best" is distinguishable from
			// "kept the first".
			Reclaim: int64(i + 1),
			Move:    1 << 20,
			Size:    2 << 20,
		}
	}
	return out
}

// INVARIANT: a repack never condemns a pack the ledger has no room for.
//
// A condemned pack is named by no live superblock and is old by its own
// name — the exact pair of conditions retention deletes on — so the ledger
// entry is the whole of its protection. An entry the cap drops is not a
// missing log line; it is a pack the next gc deletes while a reader pinned
// to the pre-repack generation is still reading it. So the plan is paced to
// what the ledger carries, and the rest waits for the next run.
func TestARepackCondemnsNoMorePacksThanTheLedgerCarries(t *testing.T) {
	now := time.Now()
	fit := packRowsThatFit(now)
	plan := &Plan{Packs: candidates(fit + 300), IntoPacks: 7}

	held := trimToLedger(plan, nil, now, 72*time.Hour)

	if held != 300 {
		t.Errorf("trimToLedger held back %d candidates, want 300", held)
	}
	if len(plan.Packs) != fit {
		t.Fatalf("the plan still condemns %d packs against a ledger with room for %d; every row past the "+
			"budget is a pack that loses its grace window", len(plan.Packs), fit)
	}
	// The reason the units changed: a pack row is 53 bytes and the share
	// was sized for 95-byte rows, so pacing in rows made a volume take two
	// runs — two full sweeps and rewrites — to spend budget it already had.
	if fit <= 512 {
		t.Errorf("the pack ledger's %d-byte share holds %d rows; under the old 512-row cap it held 512, "+
			"so the change bought nothing", int64(superblock.CondemnedBudgetBytes), fit)
	}
	// The bytes come back soonest, and a repack that is interrupted forever
	// still converges: what is left for later is what has least to give.
	for _, c := range plan.Packs {
		if c.Reclaim <= 300 {
			t.Fatalf("pack %s (reclaim %d) was kept while better candidates were held back", c.Name, c.Reclaim)
		}
	}
	if plan.Notes == nil {
		t.Error("nothing in the plan says packs were held back, so a user sees a short plan and no reason")
	}
}

// The ledger the plan has to fit into is the one this generation CARRIES,
// not an empty one: entries a previous repack wrote are still protecting
// packs, and a plan sized against a clean ledger would push them out.
func TestPacingCountsTheEntriesAlreadyOnTheLedger(t *testing.T) {
	now := time.Now()
	// Sized so the answer is a round number: room for exactly 40 more.
	carried := packRowsThatFit(now) - 40
	prev := make([]superblock.CondemnedPack, carried)
	for i := range prev {
		prev[i] = superblock.CondemnedPack{
			Name:            fmt.Sprintf("p-%016x-9999", i),
			CondemnedAtUnix: now.Add(-time.Hour).Unix(),
		}
	}
	plan := &Plan{Packs: candidates(100)}

	held := trimToLedger(plan, prev, now, 72*time.Hour)

	const room = 40
	if len(plan.Packs) != room {
		t.Errorf("the plan condemns %d packs with %d already on the ledger; only %d more fit its %d-byte "+
			"share", len(plan.Packs), carried, room, int64(superblock.CondemnedBudgetBytes))
	}
	if held != 100-room {
		t.Errorf("held back %d, want %d", held, 100-room)
	}
}

// Entries past the grace window are not carried, so they are not competing
// for room either. This is the property that makes pacing CONVERGE rather
// than deadlock: wait out the window and the next run has the ledger back.
func TestAgedEntriesGiveTheirRoomBack(t *testing.T) {
	now := time.Now()
	prev := make([]superblock.CondemnedPack, packRowsThatFit(now))
	for i := range prev {
		prev[i] = superblock.CondemnedPack{
			Name:            fmt.Sprintf("p-%016x-9999", i),
			CondemnedAtUnix: now.Add(-100 * time.Hour).Unix(),
		}
	}
	plan := &Plan{Packs: candidates(50)}

	if held := trimToLedger(plan, prev, now, 72*time.Hour); held != 0 {
		t.Errorf("held back %d candidates against a ledger whose every entry has aged out; a repack that "+
			"waited the window out must find the room it waited for", held)
	}
	if len(plan.Packs) != 50 {
		t.Errorf("the plan lost %d candidates to a ledger of expired entries", 50-len(plan.Packs))
	}
}

// A full ledger of LIVE entries means there is no room at all, and doing
// nothing is the right answer — but it has to be a visible one.
func TestAFullLedgerHoldsTheWholePlanAndSaysSo(t *testing.T) {
	now := time.Now()
	prev := make([]superblock.CondemnedPack, packRowsThatFit(now))
	for i := range prev {
		prev[i] = superblock.CondemnedPack{
			Name:            fmt.Sprintf("p-%016x-9999", i),
			CondemnedAtUnix: now.Add(-time.Minute).Unix(),
		}
	}
	plan := &Plan{Packs: candidates(10), IntoPacks: 3}

	if held := trimToLedger(plan, prev, now, 72*time.Hour); held != 10 {
		t.Errorf("held back %d of 10 against a ledger with no room", held)
	}
	if !plan.Empty() {
		t.Error("the plan is not empty, so Execute would rewrite packs it cannot protect")
	}
	if plan.IntoPacks != 0 {
		t.Errorf("the plan still promises to land bytes in %d packs while moving none", plan.IntoPacks)
	}
	if len(plan.Notes) == 0 {
		t.Error("a repack that did nothing must say why; there is no note")
	}
}

// THE PACER AND THE LEDGER MUST AGREE TO THE BYTE. They are two pieces of
// arithmetic over the same budget, run at different times over different
// inputs — the pacer sums candidate rows before anything is rewritten, the
// builder encodes the real ledger after — and the builder REFUSES rather
// than truncating, because a truncated pack row is deleted data. So a
// disagreement of one byte at the boundary is not a rounding error: it is
// a repack that rewrites a volume's packs and then throws the work away.
//
// Checked either side of the boundary and on it, since an off-by-one in
// the room calculation only shows up there.
func TestPacingAndTheLedgerAgreeAtTheByteBoundary(t *testing.T) {
	now := time.Now()
	fit := packRowsThatFit(now)
	for _, tc := range []struct {
		what     string
		proposed int
		wantHeld int
	}{
		{"one under the boundary", fit - 1, 0},
		{"exactly on it", fit, 0},
		{"one over", fit + 1, 1},
		{"well over", fit + 200, 200},
	} {
		plan := &Plan{Packs: candidates(tc.proposed)}
		if held := trimToLedger(plan, nil, now, 72*time.Hour); held != tc.wantHeld {
			t.Errorf("%s: held back %d of %d, want %d", tc.what, held, tc.proposed, tc.wantHeld)
			continue
		}
		dropped := make([]string, len(plan.Packs))
		for i, c := range plan.Packs {
			dropped[i] = c.Name
		}
		// The builder's ERROR rule, on exactly what the pacer allowed.
		out, err := condemnPacks(nil, dropped, nil, now, 72*time.Hour)
		if err != nil {
			t.Errorf("%s: the ledger builder refused a plan the pacer had already sized to fit: %v",
				tc.what, err)
			continue
		}
		if len(out) != len(plan.Packs) {
			t.Errorf("%s: %d packs condemned, %d rows on the ledger", tc.what, len(plan.Packs), len(out))
		}
		if n := superblock.EncodedLen(out); n > superblock.CondemnedBudgetBytes {
			t.Errorf("%s: the paced plan's ledger encodes to %d bytes against a %d-byte share",
				tc.what, n, int64(superblock.CondemnedBudgetBytes))
		}
	}
}
