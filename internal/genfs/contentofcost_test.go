package genfs_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// ContentOf is the seal's carry-forward check, and it used to answer the
// question by building the WHOLE location map: one trailer fetch per pack
// in the generation, before the first record could be handed out. That is
// what made a metadata-only checkpoint — a rename — download tens of
// megabytes of pack trailers and read none of them, and it is the cost
// this asserts is gone.
//
// The unit is requests, and every object is counted rather than only
// packs: an answer that merely moved the round trips into the index's key
// space would be no saving at all.
func TestContentOfDoesNotIndexTheGeneration(t *testing.T) {
	ctx := context.Background()
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000f1")
	packs := len(packsOf(t, inner, sb))

	fs := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	inner.reset()
	for _, p := range files {
		n, err := fs.LookupPath(ctx, p)
		if err != nil {
			t.Fatalf("lookup %s: %v", p, err)
		}
		c, err := fs.ContentOf(ctx, n.Inode)
		if err != nil {
			t.Fatalf("ContentOf %s: %v", p, err)
		}
		if len(c.Refs) == 0 {
			t.Fatalf("%s came back with no chunk refs", p)
		}
	}
	requests, packGets := inner.all.Load(), inner.gets.Load()
	t.Logf("%d files confirmed across %d packs: %d request(s), %d against packs, %d pack(s) indexed",
		len(files), packs, requests, packGets, fs.IndexedPacks())

	// The sweep is one trailer fetch per pack. Confirming EVERY file in the
	// volume must cost less than that, or the carry-forward check is still
	// paying for the generation rather than for what it was asked about.
	if requests >= int64(packs) {
		t.Errorf("confirming %d files cost %d request(s) over a %d-pack generation: "+
			"the carry-forward check is still indexing the whole generation",
			len(files), requests, packs)
	}
	if fs.IndexedPacks() >= packs {
		t.Errorf("the mount folded in %d of %d packs' trailers to confirm content it did not read",
			fs.IndexedPacks(), packs)
	}
}

// The other half of the same change, and the one that must not be traded
// away: a chunk in a pack the generation no longer lists is ABSENT, and
// saying so is what stops a seal signing a record that points at bytes
// retention has taken.
//
// The shortcut this exercises is the index one. The multi-pack index still
// names the dropped pack — indexes are carried forward, retention sweeps
// packs — so an implementation that read an index hit as presence without
// holding the name against the SIGNED pack list would call this content
// live. It is exactly the false positive the pack-list check in
// packIndex.hintsName exists to prevent, and the failure it would cause is
// silent: a signed generation naming bytes nobody can read.
func TestContentOfStillReportsASweptPackAsAbsent(t *testing.T) {
	ctx := context.Background()
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000f2")

	fs := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	node, err := fs.LookupPath(ctx, files[0])
	if err != nil {
		t.Fatalf("lookup %s: %v", files[0], err)
	}
	c, err := fs.ContentOf(ctx, node.Inode)
	if err != nil {
		t.Fatalf("ContentOf %s: %v", files[0], err)
	}
	if len(c.Refs) == 0 || c.Refs[0].Identity == nil {
		t.Fatalf("%s has no chunk to lose", files[0])
	}
	placed, ok := fs.Placed(ctx, chunkid.Identity(c.Refs[0].Identity))
	if !ok {
		t.Fatalf("the mount cannot say where %s's first chunk is", files[0])
	}

	swept := withoutPack(t, inner, sb, placed.Pack)
	if len(swept.PackIndexes) == 0 {
		t.Fatal("the fixture lists no multi-pack index, so this proves nothing about the index shortcut")
	}
	after := openFS(t, inner, swept, genfs.Options{CacheDir: t.TempDir()})
	n2, err := after.LookupPath(ctx, files[0])
	if err != nil {
		t.Fatalf("lookup %s after the sweep: %v", files[0], err)
	}
	_, err = after.ContentOf(ctx, n2.Inode)
	if err == nil {
		t.Fatalf("ContentOf reported %s as carryable after pack %s left the list",
			files[0], placed.Pack)
	}
	if !strings.Contains(err.Error(), "present in no listed pack") {
		t.Errorf("ContentOf failed for the wrong reason: %v", err)
	}
}

// withoutPack is the generation as retention would leave it: the same
// tree, the same indexes, one pack no longer listed.
//
// The list is restated INLINE rather than by rewriting the manifest
// objects, which is a shape every reader still accepts (superblock.
// PacksAreInManifests) and keeps the fixture to a struct copy.
func withoutPack(t *testing.T, inner *packGetStore, sb *superblock.Superblock,
	drop string) *superblock.Superblock {
	t.Helper()
	cp := *sb
	cp.Manifests = nil
	cp.PackList = nil
	for _, pe := range packsOf(t, inner, sb) {
		if pe.Name != drop {
			cp.PackList = append(cp.PackList, pe)
		}
	}
	if len(cp.PackList) != len(packsOf(t, inner, sb))-1 {
		t.Fatalf("pack %s was not in the generation's list", drop)
	}
	return &cp
}
