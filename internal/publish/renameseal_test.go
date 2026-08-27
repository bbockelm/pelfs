package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The gate for a METADATA-ONLY seal: a change that moves no bytes must
// not read the volume back to publish itself.
//
// It exists because a rename did. Renaming one file through the browser UI
// on a mounted volume took 54.7 s, of which 40.8 s was the publish and
// 19.9 MiB was DOWNLOADED — to write a change that moves no file content
// at all. The download was the seal's carry-forward check
// (genfs.ContentOf), which proved every reused chunk still had a home by
// building the whole location map: one pack-trailer fetch per pack in the
// generation, so the cost of publishing a rename was set by the size of
// the volume and not by the size of the change.
//
// The assertion is a COUNT, deliberately. Wall clock over a federation is
// not reproducible and a timing bound on this would flake until someone
// raised it into meaninglessness; the number of objects a seal fetches is
// decided by the code and is the same on every machine. So the claim is
// stated the way it is true: a metadata-only seal fetches a fixed handful
// of objects, and the fixture is built with enough packs that the old
// behaviour cannot fit inside the bound.
//
// The fixture is MANY PACKS and ONE CATALOG, which is not an oversight and
// makes the bound harder rather than easier: with a single catalog the
// seal derives content records for every file in the volume, so the
// carry-forward check is asked about every chunk there is. Catalog reuse —
// the other half of an incremental seal, and the half that was working —
// has its own measurement in TestBigTreeSealCost, which needs tens of
// thousands of files to split at all and is gated behind PELFS_BIGSEAL for
// it. The log line below therefore reports "1 catalog written, 0 reused",
// and that is the fixture, not a regression.
const (
	// metadataSealObjects is what a rename may fetch. What it is made of,
	// measured, is: the generation's manifest and index segments (2 + 2),
	// the pack holding the base catalogs the walk reads, one trailer to
	// locate that pack, and the two ref reads the superblock flip does.
	// The bound is roughly double that, which leaves room for a catalog
	// split landing differently without leaving room for a sweep.
	metadataSealObjects = 20
	// metadataSealBytes is the same bound in the other unit, because a
	// count alone cannot see one request that fetched the volume.
	metadataSealBytes = 8 << 20
	// renamePackCut keeps the fixture's packs small so it holds many of
	// them cheaply: the point of the fixture is pack COUNT, and the old
	// behaviour cost one request per pack.
	renamePackCut = 96 << 10
)

func TestMetadataOnlySealDoesNotFetchTheVolume(t *testing.T) {
	ctx := context.Background()
	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	index := filepath.Join(state, "dedup.db")

	head, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0x4e, 0xa3, 0x9e, 0xd1}, DedupIndexPath: index,
		TargetPackSize: renamePackCut,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	gfs, ov := renameLayers(t, inner, head.Superblock, state, 1)
	dirs := buildRenameTree(t, ov)
	head = renameSeal(t, inner, ov, head, priv, index)
	packs := len(packsOf(t, inner, head.Superblock))
	t.Logf("fixture: %d packs after the initial seal", packs)

	// The bound only means something if a sweep would blow through it.
	// Without this the test could pass on a one-pack volume while the
	// whole-generation sweep was still there.
	if packs < 4*metadataSealObjects {
		t.Fatalf("the fixture holds %d packs; a whole-generation sweep would cost %d requests, "+
			"which is inside the %d-object bound, so the bound proves nothing. Make the fixture bigger.",
			packs, packs, metadataSealObjects)
	}

	// Reopen the way a fresh mount does — a new genfs over the sealed
	// generation with an empty cache, a new overlay on top. This is the
	// state the owner's checkpoint ran in, and the one where a seal that
	// reads the volume back has to go to the federation for it.
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gfs.Close(); err != nil {
		t.Fatal(err)
	}
	gfs, ov = renameLayers(t, inner, head.Superblock, state, 2)
	defer func() { _ = ov.Close(); _ = gfs.Close() }()

	// Descend by NAME from the root: a fresh mount has no residency for an
	// inode number carried over from the session that made it, which is the
	// same rule the kernel plays by.
	dirName := dirs[len(dirs)/2]
	dirNode, err := ov.Lookup(ctx, 1, dirName)
	if err != nil {
		t.Fatalf("lookup %s: %v", dirName, err)
	}
	dir := dirNode.Inode
	if _, err := ov.Lookup(ctx, dir, "f00.bin"); err != nil {
		t.Fatalf("lookup the file to rename: %v", err)
	}
	if err := ov.Rename(ctx, dir, "f00.bin", dir, "renamed.bin"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	mark := inner.snapshot()
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: inner, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: head.Superblock, PrevRaw: head.Raw,
		DedupIndexPath: index, TargetPackSize: renamePackCut,
	})
	if err != nil {
		t.Fatalf("seal the rename: %v", err)
	}
	gets := inner.gets.Load() - mark.gets
	bytes := inner.getB.Load() - mark.getB
	t.Logf("rename of one file in a %d-pack volume: %d GET (%s), %d PUT (%s), %d catalogs written, %d reused",
		packs, gets, human(bytes), inner.puts.Load()-mark.puts, human(inner.putB.Load()-mark.putB),
		res.Stats.Catalogs, res.Stats.CatalogsReused)

	if gets > metadataSealObjects {
		t.Errorf("publishing a rename fetched %d objects from a %d-pack volume, want at most %d — "+
			"a metadata-only seal is reading the volume back (%s downloaded)",
			gets, packs, metadataSealObjects, human(bytes))
	}
	if bytes > metadataSealBytes {
		t.Errorf("publishing a rename downloaded %s from a %d-pack volume, want at most %s",
			human(bytes), packs, human(metadataSealBytes))
	}

	// And the rename must actually have been published, or the cheapest
	// possible seal is one that did nothing.
	verifyRenamed(t, inner, res.Superblock, dirName)
}

// verifyRenamed reads the sealed generation back through a cold cache and
// checks the new name is there, the old one is gone, and the file still
// has its bytes — the three ways a cheap seal could be cheap by being
// wrong.
func verifyRenamed(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, dirName string) {
	t.Helper()
	ctx := context.Background()
	fs := openGenfs(t, inner, sb, nil)
	defer fs.Close() //nolint:errcheck
	dn, err := fs.Lookup(ctx, 1, dirName)
	if err != nil {
		t.Fatalf("lookup %s in the sealed generation: %v", dirName, err)
	}
	dir := dn.Inode
	if _, err := fs.Lookup(ctx, dir, "f00.bin"); err == nil {
		t.Error("the sealed generation still names the file the rename moved away from")
	}
	n, err := fs.Lookup(ctx, dir, "renamed.bin")
	if err != nil {
		t.Fatalf("the sealed generation does not hold the new name: %v", err)
	}
	if n.Length != renameFileSize {
		t.Errorf("the renamed file is %d bytes, was %d", n.Length, renameFileSize)
	}
	if got := readWhole(t, fs, n.Inode, n.Length); len(got) != renameFileSize {
		t.Errorf("read %d bytes of the renamed file, want %d", len(got), renameFileSize)
	}
}

// renameFileSize is comfortably over the inline threshold, so every file
// in the fixture has chunk refs in a pack — which is what makes the
// carry-forward check ask about packs at all.
const renameFileSize = 48 << 10

func buildRenameTree(t *testing.T, ov *overlay.FS) []string {
	t.Helper()
	ctx := context.Background()
	body := pseudorandomBody(renameFileSize)
	var dirs []string
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("d%02d", i)
		d, err := ov.Mkdir(ctx, 1, name, 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		dirs = append(dirs, name)
		for j := 0; j < 12; j++ {
			n, err := ov.Create(ctx, d.Inode, fmt.Sprintf("f%02d.bin", j), 0644, 0, 0)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			// Distinct bytes per file, so nothing dedups into one pack and
			// the fixture really does spread across the pack count it
			// reports.
			b := append([]byte(nil), body...)
			b[0], b[1] = byte(i), byte(j)
			if _, err := ov.Write(ctx, n.Inode, 0, b); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}
	return dirs
}

func pseudorandomBody(n int) []byte {
	b := make([]byte, n)
	x := uint64(0x9e3779b97f4a7c15)
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	return b
}

func renameSeal(t *testing.T, inner pelicanobj.Store, ov *overlay.FS, prev *publish.Result,
	priv ed25519.PrivateKey, index string) *publish.Result {
	t.Helper()
	res, err := publish.Seal(context.Background(), publish.Options{
		Overlay: ov, Inner: inner, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: prev.Superblock, PrevRaw: prev.Raw,
		DedupIndexPath: index, TargetPackSize: renamePackCut,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return res
}

// renameLayers opens a genfs and an overlay with a cache directory of
// their own, so each phase is the cold mount a checkpoint actually runs
// in rather than one warmed by the phase before it.
func renameLayers(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock,
	state string, seq int) (*genfs.FS, *overlay.FS) {
	t.Helper()
	gfs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: sb, CacheDir: filepath.Join(state, "gencache", strconv.Itoa(seq)),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	ov, err := overlay.Open(filepath.Join(state, "overlay", strconv.Itoa(seq)), gfs, overlay.Options{
		NextInode:      gfs.NextInode(),
		BaseRoot:       gfs.RootCatalog(),
		BaseGeneration: gfs.Generation(),
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	return gfs, ov
}
