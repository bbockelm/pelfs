package overlay_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
)

// sealSnapshotAndSwap is what a mid-session checkpoint actually does, in
// the order it does it: freeze an instant, publish THAT instant while the
// mount keeps serving, then move the served base onto what was published.
//
// sealAndSwap (snapshot_test.go) seals the LIVE overlay, which is only
// sound when nothing mutates between the freeze and the seal. The bug this
// file pins lives precisely in that window, so it needs the frozen view to
// be the seal's input while the live overlay moves on underneath it.
func sealSnapshotAndSwap(t *testing.T, fx *fixture, snap *overlay.Snapshot) *publish.Result {
	t.Helper()
	ctx := context.Background()
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap,
		Inner:           fx.inner,
		SpoolDir:        t.TempDir(),
		SigningKey:      fx.key,
		Prev:            fx.head.Superblock,
		PrevRaw:         fx.head.Raw,
		TargetPackSize:  1 << 20,
	})
	if err != nil {
		t.Fatalf("Seal the frozen view: %v", err)
	}
	if _, err := fx.base.Swap(ctx, res.Superblock); err != nil {
		t.Fatalf("Swap base onto the sealed generation: %v", err)
	}
	fx.head = res
	return res
}

// quietCheckpoint runs a whole checkpoint with nothing mutating across it,
// which is how a directory a session created becomes a directory the BASE
// generation holds. Every test here needs that first: a parent the overlay
// invented and has never published has no base half, so its listing comes
// from the overlay edges alone and nothing underneath can show through.
// The second and later checkpoints of a long session are the interesting
// ones, and this is the cheapest way to be in one.
func quietCheckpoint(t *testing.T, fx *fixture, ov *overlay.FS) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snap")
	snap, err := ov.Snapshot(context.Background(), dir)
	if err != nil {
		t.Fatalf("quiet checkpoint snapshot: %v", err)
	}
	defer snap.Close() //nolint:errcheck
	res := sealSnapshotAndSwap(t, fx, snap)
	rebase(t, ov, snap.Seq(), res)
}

// dirNames lists a directory in the merged view.
func dirNames(t *testing.T, ov readView, ino uint64) []string {
	t.Helper()
	es, err := ov.Readdir(context.Background(), ino)
	if err != nil {
		t.Fatalf("Readdir(%d): %v", ino, err)
	}
	out := entryNames(es)
	sort.Strings(out)
	return out
}

// wantMergedNames fails with the ghost named, not with a diff the reader has to
// decode: a listing that gained a name is the whole symptom.
func wantMergedNames(t *testing.T, what string, got, want []string) {
	t.Helper()
	inWant := make(map[string]bool, len(want))
	for _, n := range want {
		inWant[n] = true
	}
	inGot := make(map[string]bool, len(got))
	var ghosts []string
	for _, n := range got {
		if inGot[n] {
			ghosts = append(ghosts, n+" (listed twice)")
			continue
		}
		inGot[n] = true
		if !inWant[n] {
			ghosts = append(ghosts, n)
		}
	}
	var missing []string
	for _, n := range want {
		if !inGot[n] {
			missing = append(missing, n)
		}
	}
	if len(ghosts) == 0 && len(missing) == 0 {
		return
	}
	msg := what + ": the merged listing disagrees with what the session asked for"
	if len(ghosts) > 0 {
		msg += fmt.Sprintf("\n    GHOST entries the session removed but the mount still shows: %s",
			strings.Join(ghosts, ", "))
	}
	if len(missing) > 0 {
		msg += fmt.Sprintf("\n    MISSING entries the session kept but the mount does not show: %s",
			strings.Join(missing, ", "))
	}
	t.Errorf("%s\n    mount:     %v\n    should be: %v", msg, got, want)
}

// TestRenameAcrossCheckpointLeavesNoGhost is the rename-ghost regression,
// made a certainty instead of a race.
//
// A checkpoint is snapshot -> seal the frozen view -> swap the base ->
// rebase, and the mount keeps serving for all of it. A name created BEFORE
// the freeze is in the generation the seal publishes; if the session
// renames it away DURING the seal, the overlay deletes its edge row and
// asks the base whether a whiteout is needed. The base it asks is the OLD
// one, which never had the name — so no whiteout is written, and the swap
// then puts a generation underneath that DOES have it. Both names resolve.
//
// The hostile exerciser found this at a 100ms snapshot cadence, roughly two
// runs in three. Here the window is not a cadence: the rename is issued
// between the freeze and the swap, by hand, so a passing run means the
// merge is right rather than that the timing was kind.
func TestRenameAcrossCheckpointLeavesNoGhost(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0001-4000-8000-000000000001")
	ov := openOverlay(t, fx, "")

	sub, err := ov.Mkdir(ctx, rootIno, "sub", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)

	n, err := ov.Create(ctx, sub.Inode, "c013.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte("created before the checkpoint")); err != nil {
		t.Fatal(err)
	}

	// The checkpoint's instant. c013.dat is in it, so the generation the
	// seal is about to publish will have it.
	snap := takeSnapshot(t, ov)

	// The mount serves this while the seal runs.
	if err := ov.Rename(ctx, sub.Inode, "c013.dat", sub.Inode, "m013.dat"); err != nil {
		t.Fatalf("rename during the seal: %v", err)
	}

	res := sealSnapshotAndSwap(t, fx, snap)
	wantMergedNames(t, "after the swap, before the rebase", dirNames(t, ov, sub.Inode), []string{"m013.dat"})
	rebase(t, ov, snap.Seq(), res)
	wantMergedNames(t, "after the rebase", dirNames(t, ov, sub.Inode), []string{"m013.dat"})

	if _, err := ov.Lookup(ctx, sub.Inode, "c013.dat"); err == nil {
		t.Error("the rename SOURCE still resolves by name after the checkpoint")
	}
}

// TestRemovalsAcrossCheckpointLeaveNoGhost is the sibling shape: every way
// a session can take a name away while a seal is publishing it. The
// mechanism is the same wrong question — "does the base have this name
// now?" instead of "will the base I am about to sit on have it?" — so a
// fix that only knows about rename is not a fix.
func TestRemovalsAcrossCheckpointLeaveNoGhost(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0002-4000-8000-000000000002")
	ov := openOverlay(t, fx, "")

	sub, err := ov.Mkdir(ctx, rootIno, "sub", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)
	mk := func(name string) uint64 {
		t.Helper()
		n, err := ov.Create(ctx, sub.Inode, name, 0644, 0, 0)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, []byte(name)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return n.Inode
	}
	unlinked := mk("unlinked.dat")
	linked := mk("linked.dat")
	replaced := mk("replaced.dat")
	mk("survivor.dat")
	if _, err := ov.Link(ctx, linked, sub.Inode, "extra.dat"); err != nil {
		t.Fatalf("link: %v", err)
	}
	doomed, err := ov.Mkdir(ctx, sub.Inode, "doomed", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = doomed
	_ = unlinked
	_ = replaced

	snap := takeSnapshot(t, ov)

	// Everything below lands while the seal is publishing the names above.
	if err := ov.Unlink(ctx, sub.Inode, "unlinked.dat"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := ov.Unlink(ctx, sub.Inode, "extra.dat"); err != nil {
		t.Fatalf("unlink the second link: %v", err)
	}
	if err := ov.Rmdir(ctx, sub.Inode, "doomed"); err != nil {
		t.Fatalf("rmdir: %v", err)
	}
	// Recreate over the hole an unlink just made: the new inode's edge
	// must shadow the base name the seal is about to publish, not sit
	// beside it.
	if _, err := ov.Create(ctx, sub.Inode, "unlinked.dat", 0644, 0, 0); err != nil {
		t.Fatalf("recreate over the whiteout: %v", err)
	}

	res := sealSnapshotAndSwap(t, fx, snap)
	want := []string{"linked.dat", "replaced.dat", "survivor.dat", "unlinked.dat"}
	wantMergedNames(t, "after the swap, before the rebase", dirNames(t, ov, sub.Inode), want)
	rebase(t, ov, snap.Seq(), res)
	wantMergedNames(t, "after the rebase", dirNames(t, ov, sub.Inode), want)

	// The recreated name must be the NEW inode, not the published one.
	got, err := ov.Lookup(ctx, sub.Inode, "unlinked.dat")
	if err != nil {
		t.Fatalf("lookup the recreated name: %v", err)
	}
	if got.Inode == unlinked {
		t.Errorf("unlinked.dat resolves to the inode the seal published (%d); the recreate did not shadow it", unlinked)
	}
	if got.Length != 0 {
		t.Errorf("unlinked.dat is %d bytes: the merged view is serving the published body, not the empty recreate", got.Length)
	}
}

// TestChurnAcrossManyCheckpoints is the corpus plan's shape, deterministic
// and at length: twenty rounds of create-rename-delete with a checkpoint
// sealing across each one, in a directory that also holds entries nothing
// ever touches.
//
// Both of the exerciser's symptoms live here. One stray name per round is
// what accumulated into a directory holding 3,080 entries where the
// reference held 7; and the untouched entries are the control for the other
// half of its report — directories MISSING entries nobody had touched — so
// that a fix which only stops the listing from GROWING cannot pass.
func TestChurnAcrossManyCheckpoints(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0003-4000-8000-000000000003")
	ov := openOverlay(t, fx, "")

	sub, err := ov.Mkdir(ctx, rootIno, "sub", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Entries no round below ever names. Their job is to still be here at
	// the end, and to still be here in the untouched subdirectory too.
	want := map[string]bool{}
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("keep%02d.txt", i)
		if _, err := ov.Create(ctx, sub.Inode, name, 0644, 0, 0); err != nil {
			t.Fatal(err)
		}
		want[name] = true
	}
	quiet, err := ov.Mkdir(ctx, sub.Inode, "quiet", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want["quiet"] = true
	wantQuiet := map[string]bool{}
	for i := 0; i < 7; i++ {
		name := fmt.Sprintf("q%02d.txt", i)
		if _, err := ov.Create(ctx, quiet.Inode, name, 0644, 0, 0); err != nil {
			t.Fatal(err)
		}
		wantQuiet[name] = true
	}
	quietCheckpoint(t, fx, ov)

	sorted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}

	for round := 0; round < 20; round++ {
		src := fmt.Sprintf("c%03d.dat", round)
		dst := fmt.Sprintf("m%03d.dat", round)
		n, err := ov.Create(ctx, sub.Inode, src, 0644, 0, 0)
		if err != nil {
			t.Fatalf("round %d create: %v", round, err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, []byte(src)); err != nil {
			t.Fatalf("round %d write: %v", round, err)
		}
		// A directory renamed across the same boundary, with a child, so
		// the subtree has to follow its parent's new name and nothing else.
		dsrc := fmt.Sprintf("d%03d", round)
		ddst := fmt.Sprintf("d%03d.renamed", round)
		dn, err := ov.Mkdir(ctx, sub.Inode, dsrc, 0755, 0, 0)
		if err != nil {
			t.Fatalf("round %d mkdir: %v", round, err)
		}
		if _, err := ov.Create(ctx, dn.Inode, "inside.txt", 0644, 0, 0); err != nil {
			t.Fatalf("round %d create inside: %v", round, err)
		}

		dir := filepath.Join(t.TempDir(), "snap")
		snap, err := ov.Snapshot(ctx, dir)
		if err != nil {
			t.Fatalf("round %d snapshot: %v", round, err)
		}
		if err := ov.Rename(ctx, sub.Inode, src, sub.Inode, dst); err != nil {
			t.Fatalf("round %d rename: %v", round, err)
		}
		if err := ov.Rename(ctx, sub.Inode, dsrc, sub.Inode, ddst); err != nil {
			t.Fatalf("round %d rename the directory: %v", round, err)
		}
		// Delete what the PREVIOUS round published, across this boundary:
		// the removal a long session interleaves with everything else.
		if round > 0 {
			prev := fmt.Sprintf("m%03d.dat", round-1)
			if err := ov.Unlink(ctx, sub.Inode, prev); err != nil {
				t.Fatalf("round %d unlink %s: %v", round, prev, err)
			}
			delete(want, prev)
			prevDir := fmt.Sprintf("d%03d.renamed", round-1)
			if err := ov.Unlink(ctx, lookupChild(t, ov, sub.Inode, prevDir), "inside.txt"); err != nil {
				t.Fatalf("round %d unlink inside %s: %v", round, prevDir, err)
			}
			if err := ov.Rmdir(ctx, sub.Inode, prevDir); err != nil {
				t.Fatalf("round %d rmdir %s: %v", round, prevDir, err)
			}
			delete(want, prevDir)
		}
		res := sealSnapshotAndSwap(t, fx, snap)
		rebase(t, ov, snap.Seq(), res)
		if err := snap.Close(); err != nil {
			t.Fatalf("round %d snapshot close: %v", round, err)
		}
		want[dst] = true
		want[ddst] = true

		wantMergedNames(t, fmt.Sprintf("sub after round %d", round),
			dirNames(t, ov, sub.Inode), sorted(want))
		wantMergedNames(t, fmt.Sprintf("the untouched subdirectory after round %d", round),
			dirNames(t, ov, quiet.Inode), sorted(wantQuiet))
		if t.Failed() {
			t.FailNow()
		}
	}
}

// lookupChild resolves one name and fails the test if it is not there.
func lookupChild(t *testing.T, ov *overlay.FS, parent uint64, name string) uint64 {
	t.Helper()
	n, err := ov.Lookup(context.Background(), parent, name)
	if err != nil {
		t.Fatalf("lookup %q under inode %d: %v", name, parent, err)
	}
	return n.Inode
}

// TestRecreateOverWhiteoutAcrossCheckpoint is the other polarity of the
// same window, and it has to keep working after the fix rather than merely
// not regress: a name the snapshot published and the session then removed
// now leaves a whiteout, so recreating that name has to REPLACE the
// whiteout and serve the new inode — not resurrect the published one, and
// not leave the name hidden.
func TestRecreateOverWhiteoutAcrossCheckpoint(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0004-4000-8000-000000000004")
	ov := openOverlay(t, fx, "")

	sub, err := ov.Mkdir(ctx, rootIno, "sub", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)

	first, err := ov.Create(ctx, sub.Inode, "swap.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, first.Inode, 0, []byte("the body the checkpoint published")); err != nil {
		t.Fatal(err)
	}
	snap := takeSnapshot(t, ov)

	// Remove and recreate the same name while the seal is publishing it.
	if err := ov.Unlink(ctx, sub.Inode, "swap.dat"); err != nil {
		t.Fatalf("unlink during the seal: %v", err)
	}
	second, err := ov.Create(ctx, sub.Inode, "swap.dat", 0644, 0, 0)
	if err != nil {
		t.Fatalf("recreate during the seal: %v", err)
	}
	body := []byte("the body the session actually wants")
	if _, err := ov.Write(ctx, second.Inode, 0, body); err != nil {
		t.Fatal(err)
	}

	res := sealSnapshotAndSwap(t, fx, snap)
	rebase(t, ov, snap.Seq(), res)

	wantMergedNames(t, "after the checkpoint", dirNames(t, ov, sub.Inode), []string{"swap.dat"})
	n, err := ov.Lookup(ctx, sub.Inode, "swap.dat")
	if err != nil {
		t.Fatalf("the recreated name does not resolve: %v", err)
	}
	if n.Inode != second.Inode {
		t.Errorf("swap.dat resolves to inode %d, want the recreated %d", n.Inode, second.Inode)
	}
	mustBody(t, ov, "sub/swap.dat", body)
}

// TestRenameOntoPublishedNameAcrossCheckpoint replaces an existing name
// rather than moving into a free one, and moves between two parents. Both
// halves of a rename touch the window: the destination's oedge has to
// shadow what the seal published there, and the source has to be whited out
// under a DIFFERENT parent from the one the destination lands in.
func TestRenameOntoPublishedNameAcrossCheckpoint(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0005-4000-8000-000000000005")
	ov := openOverlay(t, fx, "")

	from, err := ov.Mkdir(ctx, rootIno, "from", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	to, err := ov.Mkdir(ctx, rootIno, "to", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)

	mover, err := ov.Create(ctx, from.Inode, "mover.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("the body that moves")
	if _, err := ov.Write(ctx, mover.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	victim, err := ov.Create(ctx, to.Inode, "target.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, victim.Inode, 0, []byte("the body that is replaced")); err != nil {
		t.Fatal(err)
	}
	snap := takeSnapshot(t, ov)

	if err := ov.Rename(ctx, from.Inode, "mover.dat", to.Inode, "target.dat"); err != nil {
		t.Fatalf("rename during the seal: %v", err)
	}

	res := sealSnapshotAndSwap(t, fx, snap)
	rebase(t, ov, snap.Seq(), res)

	wantMergedNames(t, "the source directory", dirNames(t, ov, from.Inode), nil)
	wantMergedNames(t, "the destination directory", dirNames(t, ov, to.Inode), []string{"target.dat"})
	n, err := ov.Lookup(ctx, to.Inode, "target.dat")
	if err != nil {
		t.Fatalf("the destination does not resolve: %v", err)
	}
	if n.Inode != mover.Inode {
		t.Errorf("to/target.dat resolves to inode %d, want the moved %d", n.Inode, mover.Inode)
	}
	mustBody(t, ov, "to/target.dat", body)
}
