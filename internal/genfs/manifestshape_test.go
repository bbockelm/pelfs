package genfs_test

import (
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// inlineShape returns the generation as a pre-manifest writer would have
// written it: the same packs, listed in the superblock, naming no
// manifest. The signature does not survive the rewrite, which is fine
// here — genfs is handed a superblock its CALLER verified, and this test
// is about the two shapes serving the same tree.
func inlineShape(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock) *superblock.Superblock {
	t.Helper()
	cp := *sb
	cp.PackList = packsOf(t, inner, sb)
	cp.Manifests = nil
	return &cp
}

// The compatibility claim, checked rather than asserted: a generation
// that names its packs through a manifest and the same generation with
// them inline mount the same and serve the same bytes. The old shape is
// what every generation written before this change has, and it has to
// keep working forever.
func TestBothPackListShapesServeTheSameTree(t *testing.T) {
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000d1")
	if !sb.PacksAreInManifests() {
		t.Fatal("fixture: publish did not name its packs through a manifest")
	}
	if len(sb.PackList) != 0 {
		t.Fatalf("fixture: the generation also inlines %d packs", len(sb.PackList))
	}

	named := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	want := walkAndRead(t, named, files[:5])

	old := inlineShape(t, inner, sb)
	if len(old.PackList) == 0 {
		t.Fatal("the inline shape names no packs")
	}
	inline := openFS(t, inner, old, genfs.Options{CacheDir: t.TempDir()})
	if got := walkAndRead(t, inline, files[:5]); !equalStrings(got, want) {
		t.Errorf("the inline-shaped generation served a different tree:\n got %v\nwant %v", got, want)
	}
	t.Logf("%d packs served identically from a manifest and from an inline list", len(old.PackList))
}

// A mount that cannot resolve the pack set must say so. The failure this
// guards against is not an error, it is the ABSENCE of one: falling
// through to an empty pack set mounts a volume that looks empty rather
// than unreadable, and "your data is gone" is the worst answer this code
// can give.
func TestAMountRefusesAGenerationWhoseManifestIsMissing(t *testing.T) {
	ctx := context.Background()
	inner, sb, _ := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000d2")
	for _, ref := range sb.Manifests {
		if err := inner.Delete(ctx, manifest.Dir+"/"+ref.Name); err != nil {
			t.Fatal(err)
		}
	}
	_, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: sb, CacheDir: t.TempDir()})
	if err == nil {
		t.Fatal("mounted a generation whose pack set could not be read")
	}
	// Legible: it must name the key space the list moved to, so the reader
	// of the error knows what is missing rather than seeing a bare
	// not-found.
	if !strings.Contains(err.Error(), manifest.Dir) {
		t.Errorf("the error does not say where the pack list lives: %v", err)
	}
	t.Logf("refused, with: %v", err)
}
