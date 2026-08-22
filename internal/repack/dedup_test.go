package repack_test

// A repack and the publish dedup sidecar.
//
// The sidecar says "these chunk identities are already stored", and a seal
// that loads one skips the upload of everything it names. A repack breaks
// that in both directions at once: it publishes a new generation, so the
// stamp no longer matches and the whole file is ignored, and it drops
// packs, so some of what the file names is no longer stored. Carrying it
// across means doing both halves — restamp AND filter — and these tests
// hold each half to what a user can see: bytes on the wire.

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// federationBytes is every byte the volume occupies in the object store.
// It is the measurement the claim is actually about — "the first seal
// after a repack re-uploads everything it would have deduplicated" is a
// statement about uploads, not about a row count in a sidecar.
func federationBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err //nolint:nilerr // a walk error is the test's problem
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		total += fi.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("measuring the federation: %v", err)
	}
	return total
}

// THE USER-VISIBLE CLAIM: seal, repack, seal again, and the second seal
// must still deduplicate against what the first one stored. Before the
// sidecar was carried across a repack, this test's final seal re-uploaded
// every byte of a 3 MiB file that was already sitting in a pack the
// generation lists.
//
// ISOLATING THE SIDECAR, which takes some care. A seal already
// deduplicates against the chunkrefs it CARRIES FORWARD during its own
// walk (rememberReusedChunks), so a copy of a file sitting in the same
// directory would be spared the upload whether the sidecar existed or not,
// and the test would pass on a volume where the sidecar is never read. So
// the original lives in a subtree this last seal does not walk at all —
// its catalog is carried by reference — while the copy is written
// somewhere else. Nothing but the sidecar knows those bytes are stored.
func TestASealAfterARepackStillDeduplicates(t *testing.T) {
	ctx := context.Background()
	inner, volDir := newInner(t)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID: testvol.ParseUUID(t, "dedb0000-1111-2222-3333-444444444444"),
	})
	index := filepath.Join(t.TempDir(), "v2-dedup.db")
	opts := publishOpts
	opts.DedupIndexPath = index
	// A catalog split threshold small enough that the cold subtree gets a
	// catalog of its own, which is what lets the last seal carry it by
	// reference instead of walking it. Measured: without this the final
	// seal deduplicates from carried-forward chunkrefs and the sidecar is
	// never consulted, so the test would pass with the sidecar deleted.
	opts.SMax = 200

	// Four files, three of them then rewritten: the rewrite is what makes
	// the old packs mostly garbage, so there is something to repack, AND
	// what puts DEAD chunks into the sidecar — the rows for content no
	// generation references any more.
	const files = 4
	shared := pseudorandom(3<<20, 42)
	cold := v.Mkdir(rootIno, "cold")
	v.WriteFile(cold, "keep.bin", shared)
	for i := range 8 {
		v.WriteFile(cold, fmt.Sprintf("filler%d.txt", i), []byte("a name long enough to fill a catalog"))
	}
	for i := 1; i < files; i++ {
		v.WriteFile(rootIno, dedupFile(i), pseudorandom(2<<20, int64(100+i)))
	}
	first := v.Publish(opts)
	if first.Stats.ChunksAdded == 0 {
		t.Fatal("the first seal stored no chunks")
	}
	for i := 1; i < files; i++ {
		v.Write(v.Lookup(rootIno, dedupFile(i)), pseudorandom(2<<20, int64(200+i)))
	}
	head := v.Publish(opts).Superblock

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: v.Branch(), SigningKey: v.SigningKey(),
		SpoolDir: t.TempDir(), DedupIndexPath: index,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res.CondemnedPacks) == 0 {
		t.Fatal("nothing was condemned; this fixture cannot say anything about the sidecar")
	}
	// THE SECOND HALF OF THE DEFECT: the sidecar never dropped a dead
	// chunk. Three files were overwritten, so their original chunks are
	// referenced by nothing and their rows must not survive the rewrite.
	// Reported rather than fatal, so that a run which gets this wrong
	// still reaches the wire measurement below — the two halves of the
	// defect are separate claims and a failure should say which broke.
	if res.DedupDropped == 0 {
		t.Error("the repack kept every sidecar row although three files' worth of chunks are dead")
	}
	if res.DedupKept == 0 {
		t.Error("the repack carried no sidecar row at all; nothing is left to deduplicate against")
	}

	// Re-seat on what the repack published, the way a mount does when it
	// notices the branch moved, and then write a NEW file holding content
	// the volume already stores.
	moved, err := rstore.Fetch(ctx, v.Branch())
	if err != nil {
		t.Fatal(err)
	}
	v.Adopt(moved.Superblock, moved.Raw)
	before := federationBytes(t, volDir)
	v.WriteFile(rootIno, "copy.bin", shared)
	after := v.Publish(opts)
	if after.Stats.CatalogsReused == 0 {
		t.Fatal("this seal walked the whole tree, so it could have deduplicated from carried-forward " +
			"chunkrefs; the fixture no longer isolates the sidecar")
	}

	// Every assertion from here on is reported rather than fatal: they are
	// four views of one claim, and a run that breaks it should say which
	// of them still hold.
	if after.Stats.DedupIndexChunks == 0 || after.Stats.DedupIndexChunks != res.DedupKept {
		t.Errorf("the seal after the repack loaded %d sidecar rows and the repack carried %d; the "+
			"sidecar the seal read is not the one the repack wrote",
			after.Stats.DedupIndexChunks, res.DedupKept)
	}
	if after.Stats.ChunksAdded != 0 {
		t.Errorf("the seal after the repack stored %d chunks for content the volume already holds; "+
			"the sidecar was not carried across the repack", after.Stats.ChunksAdded)
	}
	if after.Stats.ChunksDeduped == 0 {
		t.Error("the seal after the repack deduplicated nothing")
	}
	// The wire measurement, which is the claim itself. A deduplicated seal
	// still uploads catalogs and a superblock; what it must not upload is
	// the 3 MiB of file content it already has. Half of that is a
	// generous ceiling for a namespace this small and an unmissable floor
	// for a re-upload.
	grew := federationBytes(t, volDir) - before
	if grew > int64(len(shared))/2 {
		t.Errorf("the seal after the repack put %d bytes on the wire for a %d-byte file the volume "+
			"already stored: it re-uploaded what the sidecar should have spared it", grew, len(shared))
	}
	t.Logf("carried %d sidecar rows, dropped %d; the post-repack seal deduplicated %d chunks and "+
		"uploaded %d bytes for a %d-byte file",
		res.DedupKept, res.DedupDropped, after.Stats.ChunksDeduped, grew, len(shared))
}

// dedupFile names the fixture files this test rewrites.
func dedupFile(i int) string { return "f" + string(rune('0'+i)) + ".bin" }

// A sidecar that belongs to somebody else is left exactly as it is. The
// stamp is what makes the file safe to trust, so a repack that rewrote a
// file stamped for another volume or another branch would be forging one.
func TestARepackLeavesAForeignSidecarAlone(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID: testvol.ParseUUID(t, "dedb1111-1111-2222-3333-444444444444"),
	})
	index := filepath.Join(t.TempDir(), "v2-dedup.db")
	opts := publishOpts
	opts.DedupIndexPath = index
	// A catalog split threshold small enough that the cold subtree gets a
	// catalog of its own, which is what lets the last seal carry it by
	// reference instead of walking it. Measured: without this the final
	// seal deduplicates from carried-forward chunkrefs and the sidecar is
	// never consulted, so the test would pass with the sidecar deleted.
	opts.SMax = 200
	v.WriteFile(rootIno, "a.bin", pseudorandom(1<<20, 7))
	head := v.Publish(opts).Superblock
	mine, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}

	got, err := publish.RestampDedupIndex(index, publish.RestampOptions{
		VolumeID: [16]byte{0xff}, Branch: head.Branch,
		PrevGen: head.Generation, NewGen: head.Generation + 1,
		Live: func([]byte) bool { return true },
	})
	if err != nil {
		t.Fatalf("RestampDedupIndex: %v", err)
	}
	if got.Rewritten {
		t.Fatal("a sidecar stamped for another volume was rewritten")
	}
	now, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if len(now) != len(mine) {
		t.Fatalf("the file changed size (%d -> %d) although nothing was carried", len(mine), len(now))
	}
}

// A restamp needs a liveness oracle. Without one the operation would be
// "trust every row for a generation that has just dropped packs", which is
// the one thing this must never write.
func TestARestampWithoutALivenessOracleIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v2-dedup.db")
	if err := os.WriteFile(path, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := publish.RestampDedupIndex(path, publish.RestampOptions{NewGen: 2}); err == nil {
		t.Fatal("a restamp with no liveness oracle was accepted")
	}
}

// No sidecar is the ordinary case for a `pelfs repack` run from a
// throwaway state directory, and it is not an error.
func TestARestampWithNoSidecarIsQuiet(t *testing.T) {
	got, err := publish.RestampDedupIndex(filepath.Join(t.TempDir(), "absent.db"),
		publish.RestampOptions{NewGen: 2, Live: func([]byte) bool { return true }})
	if err != nil {
		t.Fatalf("restamping a sidecar that does not exist: %v", err)
	}
	if got.Rewritten {
		t.Fatal("a sidecar that does not exist was reported as rewritten")
	}
}
