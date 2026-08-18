package publish_test

import (
	"testing"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// listedPack returns the generation's entry for a pack, or nil when it
// does not list one.
func listedPack(sb *superblock.Superblock, name string) *superblock.PackEntry {
	for i := range sb.PackList {
		if sb.PackList[i].Name == name {
			return &sb.PackList[i]
		}
	}
	return nil
}

// Publish knows where it put the root catalog at the instant it puts it
// there, and nothing downstream can work it out again without reading pack
// trailers — which is the round trip per pack a cold mount was paying. So
// it records the location as a hint (superblock.RootHint), which must at
// minimum describe an extent inside a pack this generation lists.
func TestPublishRecordsRootCatalogHint(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xd0, 0x0d, 0x11, 0x01})
	v.smax = splitTreeSMax
	v.splitTree()
	first := v.checkpoint()

	h := first.Superblock.RootCatalogHint
	if h == nil {
		t.Fatal("a seal that wrote the root catalog recorded no hint to where it put it")
	}
	pe := listedPack(first.Superblock, h.Pack)
	if pe == nil {
		t.Fatalf("the hint names pack %q, which this generation does not list", h.Pack)
	}
	if h.Off < 0 || h.Length <= 0 || h.Off+h.Length > pe.Size {
		t.Fatalf("the hint is [%d,+%d) in a %d-byte pack", h.Off, h.Length, pe.Size)
	}

	// A seal that changes nothing carries every catalog forward by
	// reference, the root among them. The hint has to be carried with it:
	// the location is still true, and this seal has no way to recompute it.
	second := v.checkpoint()
	if second.Superblock.RootCatalog != first.Superblock.RootCatalog {
		t.Fatal("fixture: the second seal rebuilt the root catalog, so there was nothing to carry")
	}
	h2 := second.Superblock.RootCatalogHint
	if h2 == nil || *h2 != *h {
		t.Fatalf("a carried-forward root catalog lost its hint: %+v, want %+v", h2, h)
	}
	if listedPack(second.Superblock, h2.Pack) == nil {
		t.Fatalf("the carried hint names pack %q, which the new generation no longer lists", h2.Pack)
	}

	// And a seal that DOES rewrite the root replaces the hint rather than
	// carrying a location that now describes the previous root's bytes.
	v.create(publishRootInode, "new.txt", []byte("a change at the root"))
	third := v.checkpoint()
	if third.Superblock.RootCatalog == first.Superblock.RootCatalog {
		t.Fatal("fixture: the third seal did not rewrite the root catalog")
	}
	h3 := third.Superblock.RootCatalogHint
	if h3 == nil {
		t.Fatal("a seal that rewrote the root catalog recorded no hint")
	}
	if *h3 == *h {
		t.Fatal("the hint still points at the previous generation's root catalog")
	}
	if pe := listedPack(third.Superblock, h3.Pack); pe == nil || h3.Off+h3.Length > pe.Size {
		t.Fatalf("the new hint is [%d,+%d) in pack %q", h3.Off, h3.Length, h3.Pack)
	}
}
