package publish_test

import (
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// TestSealWithStaticCatalogsReadsBack publishes a real generation in the
// packed catalog format and reads it back through genfs, which is the
// only thing that proves the format works end to end: the writer, the
// sniffing dispatch in catalog.OpenReader, and every read path a mount
// uses.
//
// It reuses the split-tree fixture, so the generation spans several
// catalogs with nested transition points rather than one flat catalog.
func TestSealWithStaticCatalogsReadsBack(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x57, 0xa7, 0x1c})
	v.static = true
	v.smax = splitTreeSMax
	v.splitTree()
	res := v.checkpoint()

	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, res.Superblock, nil)))
}

// TestSealMixesCatalogEncodings is the migration property. A volume
// published under SQLite and then sealed again with the static writer
// holds BOTH encodings at once -- carried-forward catalogs keep their
// original bytes and identity, and only what changed is rewritten. A
// reader must serve the merged tree without knowing or caring.
func TestSealMixesCatalogEncodings(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x71, 0x1e, 0xd0})
	v.smax = splitTreeSMax
	v.splitTree()
	first := v.checkpoint() // generation 1: every catalog is SQLite

	// Touch one file, then publish in the new format. Everything outside
	// that subtree is carried by reference and stays SQLite, so the second
	// generation references both encodings at once.
	ino := v.create(overlay.RootInode, "added-under-static.txt", []byte("new"))
	_ = ino
	v.static = true
	second := v.checkpoint()
	if second.Superblock.Generation <= first.Superblock.Generation {
		t.Fatalf("second checkpoint did not advance the generation")
	}

	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}
