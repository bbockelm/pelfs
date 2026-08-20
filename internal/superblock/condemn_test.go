package superblock_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

const testGrace = 72 * time.Hour

func refNamesOf(rows []superblock.CondemnedRef) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Name
	}
	return out
}

// LISTED WINS, and this is the rule repack did not have: a repack that
// rebuilds a manifest into the same bytes produces the same content hash,
// so the segment it "replaced" is the segment it is listing. Condemning it
// puts the generation's own pack list on a deletion clock.
func TestCarryCondemnedNeverCondemnsAListedName(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	out, _ := superblock.CarryCondemnedRefs(
		[]superblock.CondemnedRef{{Name: "kept", CondemnedAtUnix: now.Add(-time.Hour).Unix()}},
		[]string{"kept", "gone"}, []string{"kept"}, now, testGrace)
	for _, r := range out {
		if r.Name == "kept" {
			t.Fatal("a ref the generation still lists was condemned; its object is now on a deletion clock")
		}
	}
	if len(out) != 1 || out[0].Name != "gone" {
		t.Fatalf("ledger = %v, want just the dropped ref", refNamesOf(out))
	}
}

// FIRST TIMESTAMP WINS. Re-stamping on carry-forward restarts the clock
// every seal, and an entry that never ages off is a ledger that grows for
// the life of the volume.
func TestCarryCondemnedKeepsTheOriginalTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	first := now.Add(-2 * time.Hour).Unix()
	out, _ := superblock.CarryCondemnedRefs(
		[]superblock.CondemnedRef{{Name: "a", CondemnedAtUnix: first}},
		[]string{"a"}, nil, now, testGrace)
	if len(out) != 1 {
		t.Fatalf("ledger = %v, want one entry — a name dropped twice is one entry", refNamesOf(out))
	}
	if out[0].CondemnedAtUnix != first {
		t.Fatalf("condemned-at re-stamped %d -> %d", first, out[0].CondemnedAtUnix)
	}
}

func TestCarryCondemnedDropsAgedEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	out, _ := superblock.CarryCondemnedRefs([]superblock.CondemnedRef{
		{Name: "fresh", CondemnedAtUnix: now.Add(-time.Hour).Unix()},
		{Name: "aged", CondemnedAtUnix: now.Add(-100 * time.Hour).Unix()},
	}, nil, nil, now, testGrace)
	if got := refNamesOf(out); len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("ledger = %v, want only the entry inside the window", got)
	}
}

// hashName is the shape a derived ref really wears on the ledger: a
// 64-character content hash. Row size is what the budget is spent in, so a
// test that means "a full ledger" has to say it in rows of a stated shape.
func hashName(i int) string { return fmt.Sprintf("%064d", i) }

// packName is the other shape — `p-<nanos>-<rand>`, 23 characters — and
// the whole reason the budget is bytes: it costs 53 bytes a row against a
// hash name's 95.
func packName(i int) string { return fmt.Sprintf("p-%016x-9999", i) }

// rowsThatFit is how many rows of one shape a ledger's budget holds. Under
// a row cap this was a constant; under a byte budget it is a consequence
// of what the rows weigh, which is the point of the change.
func rowsThatFit(name string, at time.Time) int {
	return int(superblock.CondemnedPackRoom(nil) / superblock.CondemnedRowBytes(name, at))
}

// The cap is the brick guard: without it a short checkpoint interval fills
// the 1 MiB read cap with ledger in about three days. Oldest first,
// because those entries are the ones about to age off anyway.
func TestCarryCondemnedCapsOldestFirst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fit := rowsThatFit(hashName(0), now)
	var prev []superblock.CondemnedRef
	total := fit + 40
	for i := 0; i < total; i++ {
		// i == 0 is the oldest.
		prev = append(prev, superblock.CondemnedRef{
			Name:            hashName(i),
			CondemnedAtUnix: now.Add(-time.Duration(total-i) * time.Minute).Unix(),
		})
	}
	out, overflow := superblock.CarryCondemnedRefs(prev, nil, nil, now, testGrace)
	if len(out) != fit {
		t.Fatalf("ledger kept %d rows, and %d rows of this shape fit its %d-byte budget",
			len(out), fit, int64(superblock.CondemnedBudgetBytes))
	}
	// The budget is spent in the encoding, so that is what has to be under
	// it — not a count standing in for it.
	if n := superblock.EncodedLen(out); n > superblock.CondemnedBudgetBytes {
		t.Fatalf("the capped ledger encodes to %d bytes against a %d-byte budget",
			n, int64(superblock.CondemnedBudgetBytes))
	}
	if overflow != 40 {
		t.Fatalf("overflow reported as %d, want 40; nothing else tells a user their interval is too short", overflow)
	}
	if out[0].Name != hashName(40) {
		t.Fatalf("oldest survivor is %s; the cap must drop from the OLD end", out[0].Name)
	}
	// Carried order preserved, so a seal that overflows does not re-encode
	// entries nothing happened to.
	for i := 1; i < len(out); i++ {
		if out[i-1].CondemnedAtUnix > out[i].CondemnedAtUnix {
			t.Fatalf("survivors were re-ordered at index %d", i)
		}
	}
}

// THE POINT OF BUDGETING IN BYTES. The two ledgers do not agree on what a
// row costs — 53 bytes for a pack name, 95 for a content hash — so the
// same share buys the pack ledger 1.8x the rows. Under a row cap the pack
// ledger spent 27 KiB of a share it was allowed 48 KiB of, and repack
// paced itself to the smaller number.
func TestTheBudgetBuysMoreShortRowsThanLongOnes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	packs, hashes := rowsThatFit(packName(0), now), rowsThatFit(hashName(0), now)
	if packs <= hashes {
		t.Fatalf("%d pack rows and %d hash rows fit the same budget; a 53-byte row must buy more "+
			"of a byte budget than a 95-byte one, or the units have not actually changed", packs, hashes)
	}
	// Both really fill it: the ledger that holds more rows is not doing so
	// by weighing less.
	for _, c := range []struct {
		what string
		name func(int) string
		n    int
	}{{"pack", packName, packs}, {"hash", hashName, hashes}} {
		prev := make([]superblock.CondemnedPack, c.n)
		for i := range prev {
			prev[i] = superblock.CondemnedPack{Name: c.name(i), CondemnedAtUnix: now.Add(-time.Minute).Unix()}
		}
		out, overflow := superblock.CarryCondemnedPacks(prev, nil, nil, now, testGrace)
		if overflow != 0 || len(out) != c.n {
			t.Errorf("%d %s rows were meant to fit exactly; %d dropped", c.n, c.what, overflow)
		}
		if n := superblock.EncodedLen(out); n > superblock.CondemnedBudgetBytes ||
			n < superblock.CondemnedBudgetBytes-superblock.CondemnedRowBytes(c.name(0), now) {
			t.Errorf("a full %s ledger encodes to %d bytes; it should fill the %d-byte budget to within "+
				"one row", c.what, n, int64(superblock.CondemnedBudgetBytes))
		}
	}
}

// A ledger whose rows are not all one size still fills to its budget
// rather than to some count derived from the largest row — the case a row
// cap could not express at all. Repack writes pack names and the ref
// ledgers write hash names, so a MIXED ledger is not a real document; what
// is real is that the rule charges each row what it costs.
func TestAMixedLedgerFillsItsByteBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// Alternating shapes, oldest first, well past the budget.
	total := 2 * rowsThatFit(packName(0), now)
	prev := make([]superblock.CondemnedPack, total)
	for i := range prev {
		name := packName(i)
		if i%2 == 1 {
			name = hashName(i)
		}
		prev[i] = superblock.CondemnedPack{Name: name,
			CondemnedAtUnix: now.Add(-time.Duration(total-i) * time.Minute).Unix()}
	}
	out, overflow := superblock.CarryCondemnedPacks(prev, nil, nil, now, testGrace)
	if overflow == 0 {
		t.Fatal("nothing was dropped from a ledger built to be over budget")
	}
	n := superblock.EncodedLen(out)
	if n > superblock.CondemnedBudgetBytes {
		t.Fatalf("the capped ledger encodes to %d bytes against a %d-byte budget",
			n, int64(superblock.CondemnedBudgetBytes))
	}
	// Filled, not merely under: the whole complaint about row units was
	// that a ledger stopped well short of the bytes it was allowed. One
	// long row of slack is the documented cost of stopping rather than
	// skipping.
	if slack := superblock.CondemnedBudgetBytes - n; slack > superblock.CondemnedRowBytes(hashName(0), now)+8 {
		t.Errorf("a full ledger left %d bytes of its %d-byte budget unspent", slack,
			int64(superblock.CondemnedBudgetBytes))
	}
	// Oldest-first survives the mixture: no short old row was kept by
	// stepping over a long newer one.
	if out[0].CondemnedAtUnix <= prev[0].CondemnedAtUnix {
		t.Error("the oldest row survived a cap that had to drop something")
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].CondemnedAtUnix > out[i].CondemnedAtUnix {
			t.Fatalf("survivors were re-ordered at index %d", i)
		}
	}
}

// A new entry that arrives at a full ledger must not be able to push out
// something newer than itself, and the whole result must be a pure
// function of the inputs — a superblock that encoded differently on two
// runs of the same seal would break lineage hashing.
func TestCarryCondemnedIsDeterministicAtTheCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var prev []superblock.CondemnedRef
	for i := 0; i < rowsThatFit(hashName(0), now); i++ {
		prev = append(prev, superblock.CondemnedRef{
			Name:            hashName(i),
			CondemnedAtUnix: now.Add(-time.Duration(i+1) * time.Minute).Unix(),
		})
	}
	dropped := []string{"new-b", "new-a", "new-c"}
	first, _ := superblock.CarryCondemnedRefs(prev, dropped, nil, now, testGrace)
	second, _ := superblock.CarryCondemnedRefs(prev, dropped, nil, now, testGrace)
	if fmt.Sprint(refNamesOf(first)) != fmt.Sprint(refNamesOf(second)) {
		t.Fatal("the same inputs produced two different ledgers")
	}
	got := map[string]bool{}
	for _, r := range first {
		got[r.Name] = true
	}
	for _, name := range dropped {
		if !got[name] {
			t.Errorf("%s was condemned this generation and did not make the ledger; "+
				"the newest entries are the ones that must survive", name)
		}
	}
}

// The pack ledger is the same rule, and it has to be: retention reads
// sb.Condemned exactly as it reads the ref ledgers.
func TestCarryCondemnedPacksSharesTheRule(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	out, _ := superblock.CarryCondemnedPacks([]superblock.CondemnedPack{
		{Name: "listed-again", CondemnedAtUnix: now.Add(-time.Hour).Unix()},
		{Name: "aged", CondemnedAtUnix: now.Add(-100 * time.Hour).Unix()},
		{Name: "fresh", CondemnedAtUnix: now.Add(-time.Hour).Unix()},
	}, []string{"fresh", "newly-dropped"}, []string{"listed-again"}, now, testGrace)
	names := map[string]int64{}
	for _, c := range out {
		names[c.Name] = c.CondemnedAtUnix
	}
	if _, ok := names["listed-again"]; ok {
		t.Error("a pack the generation lists was condemned")
	}
	if _, ok := names["aged"]; ok {
		t.Error("a pack condemned past the grace window is still carried")
	}
	if at := names["fresh"]; at != now.Add(-time.Hour).Unix() {
		t.Errorf("a pack dropped again was re-stamped or duplicated: %v", out)
	}
	if len(out) != 2 {
		t.Errorf("ledger = %v, want the carried entry and the new one", out)
	}
}
