package repack

import (
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// Index retirement is PACED by the condemned-index ledger, for the same
// reason a pack plan is (trimToLedger): a retired index is hash-named, so
// retention ages it by an mtime that expired long ago, and the ledger row
// is the only thing keeping it while a retired generation still names it. A
// row that does not fit is not a lost line in a log — it is an object
// deleted out from under a reader.
//
// So what does not fit is NOT RETIRED. The index stays listed, the next run
// sees it again, and a repack is resumable by construction.
//
// Internal test package for the reason ledgercap_test.go gives: the
// decision is arithmetic, and driving it through Execute would mean a
// fixture with more stale index segments than a 48 KiB ledger holds.

func refName(i int) string { return fmt.Sprintf("%064x", i) }

// headWithIndexes is a parent listing n index segments, with a ledger the
// caller has already filled to whatever degree the case needs.
func headWithIndexes(n int, ledger []superblock.CondemnedRef) *superblock.Superblock {
	sb := &superblock.Superblock{CondemnedIndexes: ledger}
	for i := range n {
		sb.PackIndexes = append(sb.PackIndexes, superblock.IndexRef{Name: refName(i), Size: 1024})
	}
	return sb
}

func indexPlan(n int) *Plan {
	p := &Plan{}
	for i := range n {
		p.Refs = append(p.Refs, RefCandidate{Kind: RefIndex, Name: refName(i), Size: 1024, LiveFraction: 0.1})
	}
	return p
}

func TestIndexRetirementTakesWhatTheLedgerHolds(t *testing.T) {
	now := time.Now()
	// Room for everything: all four proposals are retired.
	if got := retiredIndexes(indexPlan(4), headWithIndexes(4, nil), now); len(got) != 4 {
		t.Fatalf("with an empty ledger %d of 4 proposed indexes were retired", len(got))
	}

	// A ledger already full of rows INSIDE their window has no room, so
	// nothing is retired this run. The rows are stamped now, so the carry
	// rule keeps every one of them.
	var full []superblock.CondemnedRef
	for i := 0; i < 4000; i++ {
		full = append(full, superblock.CondemnedRef{Name: refName(10000 + i), CondemnedAtUnix: now.Unix()})
	}
	carried, _ := superblock.CarryCondemnedRefs(full, nil, nil, now, 72*time.Hour)
	// Room for less than one row, which is what "full" means here: the cap
	// stops at the first row that will not fit rather than skipping it, so a
	// full ledger leaves a few unspendable bytes behind.
	if room := superblock.CondemnedPackRoom(condemnedAsPacks(carried)); room >= superblock.CondemnedRowBytes(refName(0), now) {
		t.Fatalf("fixture: the ledger has %d bytes free, room for another row, so this proves nothing "+
			"about pacing", room)
	}
	if got := retiredIndexes(indexPlan(4), headWithIndexes(4, full), now); len(got) != 0 {
		t.Fatalf("%d indexes were retired against a full ledger; each of them is an object dropped from "+
			"the list with nothing on the ledger to speak for it, which the next sweep deletes while "+
			"readers pinned to the pre-repack generation are still resolving through it", len(got))
	}

	// And aged rows give their room back, exactly as they do for packs: the
	// same ledger, one window later, retires again.
	var aged []superblock.CondemnedRef
	for i := 0; i < 4000; i++ {
		aged = append(aged, superblock.CondemnedRef{Name: refName(10000 + i), CondemnedAtUnix: now.Add(-100 * time.Hour).Unix()})
	}
	if got := retiredIndexes(indexPlan(4), headWithIndexes(4, aged), now); len(got) != 4 {
		t.Fatalf("%d of 4 indexes were retired against a ledger of rows that have all aged out; the room "+
			"they occupied is room this run is entitled to", len(got))
	}
}

// A candidate the head does not list is not retired: the plan may have been
// computed against a generation whose index list has since changed, and
// condemning a name this document never listed would put a row on the
// ledger for an object no reader can reach through it.
func TestOnlyListedIndexesAreRetired(t *testing.T) {
	now := time.Now()
	plan := indexPlan(3)
	plan.Refs = append(plan.Refs, RefCandidate{Kind: RefIndex, Name: refName(99), Size: 1024})
	// And a manifest candidate, which this path must ignore entirely: a
	// repack rewrites the manifest whole and condemns its segments there.
	plan.Refs = append(plan.Refs, RefCandidate{Kind: RefManifest, Name: refName(0), Size: 1024})

	got := retiredIndexes(plan, headWithIndexes(3, nil), now)
	if len(got) != 3 {
		t.Fatalf("retired %d refs, want the 3 the head actually lists", len(got))
	}
	if got[refName(99)] {
		t.Error("an index the head does not list was condemned")
	}
}
