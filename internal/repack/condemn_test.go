package repack_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// A repack writes the same condemned ledgers a seal does, and for a long
// time it wrote them under its own rules: carry what is inside the window,
// append what was dropped, and nothing else. No dedup, so a name condemned
// by two consecutive repacks appeared twice; and no listed-wins, so a
// repack whose rebuilt manifest hashed to a name the parent already listed
// condemned the very segment its own superblock names — a generation with
// its own pack list on a deletion clock.
//
// The rule now lives in superblock.CarryCondemned*; this is that call site
// exercised through a real repack.
func TestARepackWritesTheSharedLedgerRule(t *testing.T) {
	ctx := context.Background()
	inner, v, head, want := rewrittenVolume(t, "cccc7777-2222-3333-4444-555555555555")

	// Seed the parent's ref ledger with one entry inside the grace window
	// and one past it, then re-sign: this is the parent a long-lived volume
	// hands a repack, and nothing else in this package produces one.
	fresh := superblock.CondemnedRef{Name: "fresh" + hexish(60), CondemnedAtUnix: time.Now().Add(-time.Hour).Unix()}
	stale := superblock.CondemnedRef{Name: "stale" + hexish(60), CondemnedAtUnix: time.Now().Add(-aged).Unix()}
	seeded := reheadCondemned(t, inner, v, head, []superblock.CondemnedRef{fresh, stale})

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{seeded}, Head: seeded,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Plan.Refused() || res.Plan.Empty() {
		t.Fatalf("the fixture produced no work to do: %s", res.Plan.Refusal)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch the repacked head: %v", err)
	}
	sb := f.Superblock

	// LISTED WINS: whatever this run replaced, the segment the generation
	// names is not on the ledger.
	listed := map[string]bool{}
	for _, m := range sb.Manifests {
		listed[m.Name] = true
	}
	seen := map[string]int{}
	for _, c := range sb.CondemnedManifests {
		seen[c.Name]++
		if listed[c.Name] {
			t.Errorf("manifest %s is both listed by this generation and condemned by it; "+
				"the generation's own pack list is now on a deletion clock", c.Name[:12])
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("manifest %s appears %d times on the ledger", name[:12], n)
		}
	}
	// AGED FALLS OFF, CARRIED KEEPS ITS TIMESTAMP.
	at, carried := int64(0), false
	for _, c := range sb.CondemnedManifests {
		if c.Name == stale.Name {
			t.Error("an entry condemned 200h ago survived a 72h window; a ledger that never sheds grows forever")
		}
		if c.Name == fresh.Name {
			carried, at = true, c.CondemnedAtUnix
		}
	}
	if !carried {
		t.Error("an entry condemned an hour ago fell off the ledger; the object it names is one sweep from deletion")
	} else if at != fresh.CondemnedAtUnix {
		t.Errorf("carried entry re-stamped %d -> %d; the clock must not restart on carry-forward",
			fresh.CondemnedAtUnix, at)
	}

	// And a condemned PACK is never one the new generation names — the
	// same rule on the other key space.
	condemned := map[string]bool{}
	for _, c := range sb.Condemned {
		condemned[c.Name] = true
	}
	for _, pe := range packsOf(t, inner, sb) {
		if condemned[pe.Name] {
			t.Errorf("pack %s is listed by this generation and condemned by it", pe.Name)
		}
	}

	// The volume still reads, which is the only thing that makes any of
	// the above worth having.
	readsBack(t, inner, sb, want, "after the ledger rules")
}

// reheadCondemned republishes the head with a seeded manifest ledger,
// signed by the volume's key, and returns it. The bytes on the branch are
// what a repack reads, so the ledger has to get there through the ref.
func reheadCondemned(t *testing.T, inner pelicanobj.Store, v *testvol.Volume,
	head *superblock.Superblock, ledger []superblock.CondemnedRef) *superblock.Superblock {
	t.Helper()
	seeded := *head
	seeded.CondemnedManifests = append(append([]superblock.CondemnedRef{}, head.CondemnedManifests...), ledger...)
	if err := seeded.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := seeded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := inner.Put(context.Background(), "refs/main", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return &seeded
}

// hexish pads a fixture name out to the length of a real content hash, so
// the ledger entries weigh what real ones weigh.
func hexish(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + i%10)
	}
	return string(b)
}
