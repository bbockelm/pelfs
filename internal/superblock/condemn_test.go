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

// The cap is the brick guard: without it a short checkpoint interval fills
// the 1 MiB read cap with ledger in about three days. Oldest first,
// because those entries are the ones about to age off anyway.
func TestCarryCondemnedCapsOldestFirst(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var prev []superblock.CondemnedRef
	total := superblock.MaxCondemnedEntries + 40
	for i := 0; i < total; i++ {
		// i == 0 is the oldest.
		prev = append(prev, superblock.CondemnedRef{
			Name:            fmt.Sprintf("ref-%05d", i),
			CondemnedAtUnix: now.Add(-time.Duration(total-i) * time.Minute).Unix(),
		})
	}
	out, overflow := superblock.CarryCondemnedRefs(prev, nil, nil, now, testGrace)
	if len(out) != superblock.MaxCondemnedEntries {
		t.Fatalf("ledger kept %d entries, cap is %d", len(out), superblock.MaxCondemnedEntries)
	}
	if overflow != 40 {
		t.Fatalf("overflow reported as %d, want 40; nothing else tells a user their interval is too short", overflow)
	}
	if out[0].Name != fmt.Sprintf("ref-%05d", 40) {
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

// A new entry that arrives at a full ledger must not be able to push out
// something newer than itself, and the whole result must be a pure
// function of the inputs — a superblock that encoded differently on two
// runs of the same seal would break lineage hashing.
func TestCarryCondemnedIsDeterministicAtTheCap(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var prev []superblock.CondemnedRef
	for i := 0; i < superblock.MaxCondemnedEntries; i++ {
		prev = append(prev, superblock.CondemnedRef{
			Name:            fmt.Sprintf("old-%05d", i),
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
