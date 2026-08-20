package repack

import (
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// These are in the INTERNAL test package because the thing under test is
// the pacing decision itself, and driving it through Execute would mean
// building a volume with more than MaxCondemnedEntries dead packs — minutes
// of fixture for arithmetic that is twenty lines.

func candidates(n int) []PackCandidate {
	out := make([]PackCandidate, n)
	for i := range out {
		out[i] = PackCandidate{
			Name: fmt.Sprintf("p-%016x-0001", i),
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
	plan := &Plan{Packs: candidates(superblock.MaxCondemnedEntries + 300), IntoPacks: 7}

	held := trimToLedger(plan, nil, now, 72*time.Hour)

	if held != 300 {
		t.Errorf("trimToLedger held back %d candidates, want 300", held)
	}
	if len(plan.Packs) != superblock.MaxCondemnedEntries {
		t.Fatalf("the plan still condemns %d packs against a %d-entry ledger; every entry past the cap is "+
			"a pack that loses its grace window", len(plan.Packs), superblock.MaxCondemnedEntries)
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
	const carried = 500
	prev := make([]superblock.CondemnedPack, carried)
	for i := range prev {
		prev[i] = superblock.CondemnedPack{
			Name:            fmt.Sprintf("p-%016x-9999", i),
			CondemnedAtUnix: now.Add(-time.Hour).Unix(),
		}
	}
	plan := &Plan{Packs: candidates(100)}

	held := trimToLedger(plan, prev, now, 72*time.Hour)

	room := superblock.MaxCondemnedEntries - carried
	if len(plan.Packs) != room {
		t.Errorf("the plan condemns %d packs with %d already on the ledger; only %d fit under the %d-entry cap",
			len(plan.Packs), carried, room, superblock.MaxCondemnedEntries)
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
	prev := make([]superblock.CondemnedPack, superblock.MaxCondemnedEntries)
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
	prev := make([]superblock.CondemnedPack, superblock.MaxCondemnedEntries)
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
