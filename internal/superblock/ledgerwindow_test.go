package superblock

import (
	"fmt"
	"testing"
	"time"
)

// The interaction between the grace window and the ledger cap, pinned.
//
// T_grace is a per-volume parameter now, so a user can ask for a window the
// condemned ledgers cannot hold: they are capped in BYTES (they share the
// superblock's write budget) and they grow at one row per checkpoint, so
// the rows a window asks for are grace/interval. Past capacity the cap
// binds first and the volume behaves as though its window were
// capacity x interval. `pelfs init` says so at the moment the number is
// chosen, and LedgerWindow is the arithmetic behind that sentence.

// INVARIANT: LedgerWindow's capacity is what the ledger rule actually
// keeps, not a number in a comment.
//
// This is the half worth testing. rows is a division; capacity is a claim
// about capOldestFirst, and a claim about another function's behaviour goes
// stale silently. So it is checked against that function: hand the rule
// more rows than it can carry and count the survivors.
func TestTheLedgerCarriesAsManyRowsAsLedgerWindowClaims(t *testing.T) {
	_, capacity := LedgerWindow(72*time.Hour, 5*time.Minute)
	if capacity <= 0 {
		t.Fatalf("capacity = %d", capacity)
	}
	now := time.Now()
	dropped := make([]string, 0, capacity+200)
	for i := int64(0); i < capacity+200; i++ {
		dropped = append(dropped, fmt.Sprintf("%064x", i))
	}
	kept, overflow := CarryCondemnedRefs(nil, dropped, nil, now, 72*time.Hour)
	if int64(len(kept)) != capacity {
		t.Fatalf("the ledger kept %d rows and LedgerWindow says it holds %d; `pelfs init` quotes that "+
			"number to a user choosing a grace window, so the two must be the same number",
			len(kept), capacity)
	}
	if overflow != 200 {
		t.Fatalf("overflow = %d, want the 200 rows over capacity", overflow)
	}
}

// INVARIANT: the collision is reported exactly when it happens — at the
// defaults it ALREADY does, which is the fact the notice exists to make
// visible.
func TestTheDefaultWindowAlreadyOutrunsTheLedger(t *testing.T) {
	rows, capacity := LedgerWindow(DefaultTGrace, 5*time.Minute)
	if rows <= capacity {
		t.Fatalf("72h at a 5m checkpoint asks for %d rows against a capacity of %d; if that ever stops "+
			"binding, the cost of a large --grace changes and both condemn.go and the init notice are "+
			"describing a volume that no longer exists", rows, capacity)
	}
	// And a window the ledger can hold does not report a collision.
	rows, capacity = LedgerWindow(8*time.Hour, time.Hour)
	if rows > capacity {
		t.Fatalf("8h at an hourly checkpoint asks for %d rows against %d: the notice would fire on a "+
			"volume with nothing wrong with it", rows, capacity)
	}
	// A volume that never checkpoints has no ledger growth to bound, and
	// asking for a window is then free.
	if rows, _ := LedgerWindow(30*24*time.Hour, 0); rows != 0 {
		t.Fatalf("with no checkpoint interval the ledgers gain nothing; rows = %d", rows)
	}
}
