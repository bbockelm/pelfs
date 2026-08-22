package publish_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/reach"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// catalogFor returns the entry a generation recorded for one path, or fails
// naming what it did record — a test that silently found no catalog where it
// expected one is a test that asserts nothing.
func catalogFor(t *testing.T, sb *superblock.Superblock, pth string) superblock.CatalogEntry {
	t.Helper()
	var paths []string
	for _, ce := range sb.Catalogs {
		if ce.Path == pth {
			return ce
		}
		paths = append(paths, ce.Path)
	}
	t.Fatalf("generation %d has no catalog rooted at %q; it has %v", sb.Generation, pth, paths)
	return superblock.CatalogEntry{}
}

// lookupOv resolves one name through the merged view, which after a
// remount is the only way to reach an inode the previous session created.
func lookupOv(t *testing.T, v *reuseVol, parent uint64, name string) uint64 {
	t.Helper()
	n, err := v.ov.Lookup(context.Background(), parent, name)
	if err != nil {
		t.Fatalf("lookup %q under inode %d: %v", name, parent, err)
	}
	return n.Inode
}

// TestUnlinkedHardlinkFixesTheNlinkInACatalogNOTHINGELSETOUCHED is the
// hardlink half of the nlink finding, at the layer that decides whether a
// correction reaches the bytes at all.
//
// The setup is two directories large enough to be their own catalogs, with
// one inode named from both. Removing the name in `there` leaves `here`
// untouched by every measure the reuse plan has: no edge of it changed, no
// name under it changed, and its catalog covers the same path with the same
// weight. The only thing that can force it to be rebuilt is the SURVIVING
// INODE appearing in the dirty set — which is what materializing the
// decremented onode row on the unlink does (internal/overlay,
// dropNodeRefLocked).
//
// This is what rules out the other candidate fix. Having the SEAL count
// surviving file edges the way it already counts subdirectories for
// directories cannot work on its own, because carry-or-rebuild is settled
// per catalog BEFORE anything is counted (planReuse), from the dirty set.
// With no row written, `here` is not dirty, its catalog is carried forward
// verbatim, and the stale count is republished by reference — the count
// never even reaches the code that would have recomputed it.
func TestUnlinkedHardlinkFixesTheNlinkInACatalogNothingElseTouched(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x6e, 0x11, 0x14})
	// Small enough that each directory below peels into its own catalog.
	v.smax = 4000

	here, err := v.ov.Mkdir(ctx, publishRootInode, "here", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	there, err := v.ov.Mkdir(ctx, publishRootInode, "there", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A third directory nothing in this test ever names. It is the control:
	// its catalog must be CARRIED by the second seal, which is how the test
	// knows the reuse machinery was armed and working when it declined to
	// carry /here.
	elsewhere, err := v.ov.Mkdir(ctx, publishRootInode, "elsewhere", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Filler so none of them is small enough to be merged back into the
	// root's own catalog.
	for i := 0; i < 24; i++ {
		v.create(here.Inode, fmt.Sprintf("h%02d.txt", i), []byte("filler under here"))
		v.create(there.Inode, fmt.Sprintf("t%02d.txt", i), []byte("filler under there"))
		v.create(elsewhere.Inode, fmt.Sprintf("e%02d.txt", i), []byte("filler under elsewhere"))
	}
	// Well above the inline threshold and incompressible, so the hardlinked
	// file's bytes live in PACK CHUNKS rather than inside a catalog. That is
	// what makes the reachability assertion below mean anything: inline
	// bytes are reachable by virtue of the catalog holding them, and could
	// not be lost by a sweep that mis-routes an inode.
	body := pseudorandom(3<<20, 1114)
	keep := v.create(here.Inode, "keep.dat", body)
	if _, err := v.ov.Link(ctx, keep, there.Inode, "drop.dat"); err != nil {
		t.Fatalf("link across directories: %v", err)
	}
	first := v.checkpoint()
	hereCat := catalogFor(t, first.Superblock, "/here")
	if hereCat.Promoted == 0 {
		t.Fatalf("/here's catalog records %d promoted inodes; keep.dat has two names, so it should record one",
			hereCat.Promoted)
	}

	// A fresh session: nothing in memory says this process ever resolved
	// any of these inodes, so the seal has to reach them from the walk.
	v.remount()

	// Descend to both, exactly as a kernel would: the seal's placement of a
	// changed inode leans on what the session resolved.
	lookupOv(t, v, publishRootInode, "here")
	thereIno := lookupOv(t, v, publishRootInode, "there")
	if err := v.ov.Unlink(ctx, thereIno, "drop.dat"); err != nil {
		t.Fatalf("unlink the name in the other directory: %v", err)
	}
	second := v.checkpoint()

	// The control. If /elsewhere was not carried then reuse was disarmed
	// altogether, and /here being rebuilt would prove nothing.
	if second.Stats.CatalogsReused == 0 {
		t.Fatalf("this seal carried no catalog forward at all (%d catalogs, %d reused); "+
			"reuse was disarmed, so nothing here is a test of it",
			len(second.Superblock.Catalogs), second.Stats.CatalogsReused)
	}
	if before, after := catalogFor(t, first.Superblock, "/elsewhere"),
		catalogFor(t, second.Superblock, "/elsewhere"); before.Identity != after.Identity {
		t.Errorf("/elsewhere's catalog was rebuilt; nothing touched it, so it should have been carried")
	}

	cold := openCold(t, v.inner.Store, second.Superblock)
	defer cold.Close() //nolint:errcheck
	n, err := cold.LookupPath(ctx, "here/keep.dat")
	if err != nil {
		t.Fatalf("cold open of the sealed generation: lookup here/keep.dat: %v", err)
	}
	if n.Nlink != 1 {
		t.Errorf("here/keep.dat in the SEALED generation, read back cold: nlink %d, want 1.\n"+
			"    /here was never itself touched, so its catalog was carried forward with "+
			"the count the previous generation published.", n.Nlink)
	}
	if n.Inode != keep {
		t.Errorf("here/keep.dat resolves to inode %d, want %d", n.Inode, keep)
	}
	got := make([]byte, len(body))
	if _, err := cold.Read(ctx, n.Inode, 0, got); err != nil {
		// A file that stops being promoted moves its content records out of
		// the inode shard and into its path catalog; if only one half of
		// that move lands, this is where it shows.
		t.Fatalf("cold read of here/keep.dat after it stopped being promoted: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("here/keep.dat reads back different bytes than were written")
	}
	if _, err := cold.LookupPath(ctx, "there/drop.dat"); err == nil {
		t.Error("there/drop.dat still resolves in the sealed generation")
	}
	if second.Stats.PromotedInodes != 0 {
		t.Errorf("the sealed generation promoted %d inodes; nothing in it has two names",
			second.Stats.PromotedInodes)
	}
	// The catalog that used to hold a promoted inode must stop saying so,
	// or every later generation keeps paying to walk it (pruneSubtree
	// refuses to skip a span with a promoted inode in it).
	if ce := catalogFor(t, second.Superblock, "/here"); ce.Promoted != 0 {
		t.Errorf("/here's catalog still records %d promoted inodes after the second name went away; "+
			"the span can never be pruned again", ce.Promoted)
	}

	// THE SEVERITY QUESTION: can a wrong nlink make the reachability sweep
	// drop LIVE data? It can, and this is where it would show.
	//
	// nlink is not only a number a stat returns, it is a ROUTING KEY. A
	// file with nlink > 1 keeps its content records in an inode SHARD, and
	// both the publisher and the sweep decide "shard or path catalog" by
	// reading that same published count (publish.go, "Promoted (nlink > 1)
	// inodes"; reach/walk.go, "Promoted: the content records are in an
	// inode shard"). Agreeing keeps them safe. The moment the count a
	// catalog PUBLISHES and the count the shard set was BUILT from
	// disagree, the sweep asks a shard that holds no record for this
	// inode, collects no chunk identities for it, and reports its live
	// bytes as unreferenced — after which a deleting gc frees the bytes of
	// a file that is still named. keep.dat is the only object in this
	// volume large enough to be chunked, so if its chunks stopped being
	// reachable the sweep's live byte count collapses.
	rep, err := reach.Sweep(ctx, reach.Options{
		Inner:    v.inner.Store,
		Live:     []*superblock.Superblock{second.Superblock},
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("reachability sweep of the sealed generation: %v", err)
	}
	defer rep.Close() //nolint:errcheck
	if rep.Unresolved != 0 {
		t.Errorf("the sweep found %d referenced chunk identities in no pack", rep.Unresolved)
	}
	if rep.LiveBytes < int64(len(body))/2 {
		t.Errorf("the sweep says only %d bytes of this volume are live, and keep.dat alone is %d "+
			"incompressible bytes that are still named.\n"+
			"    A deleting gc would free the bytes of a file the namespace still holds.",
			rep.LiveBytes, len(body))
	}
}
