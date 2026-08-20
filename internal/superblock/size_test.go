package superblock_test

import (
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The write budget is stated in the format package and the read cap in the
// object store, because the format package must not depend on the
// transport — so the relationship between them is a comment, and a comment
// is not enforcement. This is.
//
// If the cap moves and the budget does not, the guard stops guarding
// anything: a writer would happily flip a superblock the reader refuses,
// which is the unrecoverable state the whole file exists to prevent.
func TestTheWriteBudgetIsHalfTheReadCap(t *testing.T) {
	if got, want := int64(2*superblock.MaxEncodedBytes), int64(pelicanobj.MaxMutableObject); got != want {
		t.Fatalf("the write budget is %d bytes and the read cap %d; the budget must stay half the cap",
			int64(superblock.MaxEncodedBytes), want)
	}
	if superblock.CatalogBudgetBytes >= superblock.MaxEncodedBytes {
		t.Fatalf("the catalog list may take %d bytes of a %d-byte budget, so trimming it can never be "+
			"what brings a superblock back under", int64(superblock.CatalogBudgetBytes), int64(superblock.MaxEncodedBytes))
	}
}

func TestCheckSizeAcceptsWhatFits(t *testing.T) {
	sb := &superblock.Superblock{Generation: 3}
	if err := sb.CheckSize(superblock.MaxEncodedBytes); err != nil {
		t.Fatalf("a superblock exactly at the budget was refused: %v", err)
	}
}

// "Too big" is not actionable; "too big and it is the condemned-manifest
// ledger" says to lengthen the checkpoint interval, while the same
// sentence ending in the pack list says to repack. The guard has to name
// the contributor or the user has no next step.
func TestCheckSizeNamesTheLargestContributor(t *testing.T) {
	sb := &superblock.Superblock{Generation: 9}
	for i := 0; i < 6000; i++ {
		sb.CondemnedManifests = append(sb.CondemnedManifests, superblock.CondemnedRef{
			Name:            strings.Repeat("a", 63) + string(rune('a'+i%26)),
			CondemnedAtUnix: int64(1700000000 + i),
		})
	}
	sb.PackList = []superblock.PackEntry{{Name: "0000000001", Size: 1}}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	err = sb.CheckSize(len(raw))
	if err == nil {
		t.Fatalf("a %d-byte superblock passed a %d-byte budget", len(raw), int64(superblock.MaxEncodedBytes))
	}
	for _, want := range []string{"generation 9", "condemned_manifests", "6000 entries", "--snapshot-interval"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// Ordered by weight, or the "largest contributor" is whichever field
	// happens to be listed first.
	if top := sb.Contributors()[0]; top.Field != "condemned_manifests" {
		t.Errorf("largest contributor reported as %s (%d bytes); the ledger is the big field here",
			top.Field, top.Bytes)
	}
}

// Trimming is the writer's escape valve, so it must fire only when it has
// to: a volume whose catalog list fits keeps the list, and with it the
// carry-forward that makes a seal cost the change rather than the tree.
func TestTrimCatalogsKeepsAListThatFits(t *testing.T) {
	sb := &superblock.Superblock{Catalogs: []superblock.CatalogEntry{
		{Inode: 1, Path: "/", Weight: 10}, {Inode: 2, Path: "/d", Weight: 20},
	}}
	if n := sb.TrimCatalogs(); n != 0 {
		t.Fatalf("a two-entry catalog list was dropped as %d bytes", n)
	}
	if len(sb.Catalogs) != 2 {
		t.Fatalf("catalog list is %d entries after a trim that kept it", len(sb.Catalogs))
	}
}

func TestTrimCatalogsDropsAListOverBudget(t *testing.T) {
	sb := &superblock.Superblock{}
	for i := 0; i < 20000; i++ {
		sb.Catalogs = append(sb.Catalogs, superblock.CatalogEntry{
			Inode: uint64(i), Path: "/some/reasonably/long/path/number/" + strings.Repeat("x", i%17), Weight: int64(i),
		})
	}
	n := sb.TrimCatalogs()
	if n <= superblock.CatalogBudgetBytes {
		t.Fatalf("trim reported %d bytes dropped, which is inside the %d-byte budget",
			n, int64(superblock.CatalogBudgetBytes))
	}
	if sb.Catalogs != nil {
		t.Fatal("the oversized catalog list survived the trim")
	}
	// The point of trimming: what is left encodes small enough to flip.
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.CheckSize(len(raw)); err != nil {
		t.Fatalf("a superblock whose only bulk was the catalog list is still over budget after the trim: %v", err)
	}
}
