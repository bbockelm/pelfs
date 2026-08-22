package overlay_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
)

// A file's link count is a stored attribute, unlike a directory's, which
// the seal recomputes from the edges it walked (publish.go, "A directory's
// link count is a function of the namespace"). So whatever the overlay
// reports for a FILE is what gets published, and these tests read it back
// out of the SEALED generation through a cold genfs — a live assertion
// alone would not have caught the bug they pin, which was published.

// coldNlink opens the published generation with an empty cache and returns
// what it says about one path. Cold is the point: it proves the number is
// in the catalog bytes rather than in some live view's memory.
func coldNlink(t *testing.T, fx *fixture, res *publish.Result, path string) genfs.Node {
	t.Helper()
	cold := openBase(t, fx.inner, res.Superblock)
	n, err := cold.LookupPath(context.Background(), path)
	if err != nil {
		t.Fatalf("cold open of the sealed generation: lookup %s: %v", path, err)
	}
	return n
}

// coldAbsent asserts a path is gone from the published generation.
func coldAbsent(t *testing.T, fx *fixture, res *publish.Result, path string) {
	t.Helper()
	cold := openBase(t, fx.inner, res.Superblock)
	if n, err := cold.LookupPath(context.Background(), path); err == nil {
		t.Errorf("cold open of the sealed generation: %s still resolves (inode %d, nlink %d); it was unlinked",
			path, n.Inode, n.Nlink)
	} else if !errors.Is(err, genfs.ErrNotExist) {
		t.Fatalf("cold open of the sealed generation: lookup %s: %v", path, err)
	}
}

func coldBody(t *testing.T, fx *fixture, res *publish.Result, path string, want []byte) {
	t.Helper()
	cold := openBase(t, fx.inner, res.Superblock)
	n, err := cold.LookupPath(context.Background(), path)
	if err != nil {
		t.Fatalf("cold open of the sealed generation: lookup %s: %v", path, err)
	}
	got := make([]byte, len(want))
	if _, err := cold.Read(context.Background(), n.Inode, 0, got); err != nil {
		t.Fatalf("cold open of the sealed generation: read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s in the sealed generation: body = %q, want %q", path, got, want)
	}
}

// wantNlink names the count and the direction it is wrong in, because
// "nlink 2, want 1" is the whole finding.
func wantNlink(t *testing.T, what string, got, want uint32) {
	t.Helper()
	if got == want {
		return
	}
	verb := "over-counted"
	if got < want {
		verb = "under-counted"
	}
	t.Errorf("%s: nlink %d, want %d (%s: the link count does not match the surviving names)",
		what, got, want, verb)
}

// hardlinkedPair leaves a fixture holding /links/one.dat and /links/two.dat
// as two names for one CLEAN file: both names live in the base generation
// and the inode has no overlay row at all, which is the state the bug needs
// (an unlink of a dirty inode has always decremented correctly).
func hardlinkedPair(t *testing.T, fx *fixture, ov *overlay.FS, body []byte) (dir, file uint64) {
	t.Helper()
	ctx := context.Background()
	d, err := ov.Mkdir(ctx, rootIno, "links", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ov.Create(ctx, d.Inode, "one.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, f.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Link(ctx, f.Inode, d.Inode, "two.dat"); err != nil {
		t.Fatalf("link: %v", err)
	}
	// One whole checkpoint with nothing moving across it: the pair becomes
	// what the BASE generation holds, and the overlay forgets it.
	quietCheckpoint(t, fx, ov)
	mustDirty(t, ov, f.Inode, false, "the hardlinked pair after a quiet checkpoint")
	n, err := ov.GetAttr(ctx, f.Inode)
	if err != nil {
		t.Fatal(err)
	}
	wantNlink(t, "the clean pair before anything is removed", n.Nlink, 2)
	return d.Inode, f.Inode
}

// TestUnlinkOfCleanHardlinkPublishesDecrementedNlink is the finding the
// sibling hunt left open, made deterministic.
//
// Removing one name of a hardlinked file whose inode is CLEAN used to
// change nothing about the inode: dropNodeRefLocked found no onode row and
// returned, on the grounds that the whiteout expresses the deletion and the
// seal recomputes nlink from surviving edges. The seal does that for
// directories only. For a file it publishes the count the merged view
// reported, and for a clean base-backed inode that is the base's stale one
// — so the mount served nlink 2 for a file with one name, AND the next
// generation carried the 2 into its catalog bytes.
//
// The cold open is the assertion that matters. A live view could have been
// repaired by anything downstream; the sealed generation cannot.
func TestUnlinkOfCleanHardlinkPublishesDecrementedNlink(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0011-4000-8000-000000000011")
	ov := openOverlay(t, fx, "")
	body := []byte("one body, two names, and then one name")
	dir, file := hardlinkedPair(t, fx, ov, body)

	if err := ov.Unlink(ctx, dir, "two.dat"); err != nil {
		t.Fatalf("unlink the second name: %v", err)
	}
	live, err := ov.GetAttr(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	wantNlink(t, "the mount, right after the unlink", live.Nlink, 1)
	// The surviving name still reads through the mount: a file that stops
	// being promoted moves its content records out of the inode shard and
	// into the path catalog, and both halves of that move have to land in
	// the same generation.
	mustBody(t, ov, "links/one.dat", body)

	res := sealAndSwap(t, fx, ov)

	cold := coldNlink(t, fx, res, "links/one.dat")
	wantNlink(t, "links/one.dat in the SEALED generation, read back cold", cold.Nlink, 1)
	coldAbsent(t, fx, res, "links/two.dat")
	coldBody(t, fx, res, "links/one.dat", body)
	if res.Stats.PromotedInodes != 0 {
		t.Errorf("the sealed generation promoted %d inodes; nothing in it has two names",
			res.Stats.PromotedInodes)
	}
}

// TestUnlinkOfCleanHardlinkInAnotherDirectory is the same removal with the
// two names in DIFFERENT directories, which is the case that decides how
// the count may be maintained at all.
//
// The directory losing a name is dirty because it gained a whiteout, so a
// seal rebuilds its catalog no matter what. The directory KEEPING a name is
// touched by nothing: no edge of its changed, no row under it changed. The
// only thing that makes a seal look at it again is the surviving inode's
// own row appearing in the dirty set — which is what materializing the
// decremented onode row does. Counting surviving edges at seal time
// instead would leave this directory's catalog carried forward verbatim,
// stale count and all, because carry-or-rebuild is decided BEFORE anything
// is counted (publish/catalogreuse.go, planReuse).
func TestUnlinkOfCleanHardlinkInAnotherDirectory(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0014-4000-8000-000000000014")
	ov := openOverlay(t, fx, "")
	body := []byte("two directories, one inode")

	here, err := ov.Mkdir(ctx, rootIno, "here", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	there, err := ov.Mkdir(ctx, rootIno, "there", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ov.Create(ctx, here.Inode, "keep.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, f.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Link(ctx, f.Inode, there.Inode, "drop.dat"); err != nil {
		t.Fatalf("link into the other directory: %v", err)
	}
	quietCheckpoint(t, fx, ov)
	mustDirty(t, ov, f.Inode, false, "the cross-directory pair after a quiet checkpoint")

	if err := ov.Unlink(ctx, there.Inode, "drop.dat"); err != nil {
		t.Fatalf("unlink the name in the other directory: %v", err)
	}
	res := sealAndSwap(t, fx, ov)

	cold := coldNlink(t, fx, res, "here/keep.dat")
	wantNlink(t, "here/keep.dat in the SEALED generation, read back cold "+
		"(the directory that kept its name was never itself touched)", cold.Nlink, 1)
	coldAbsent(t, fx, res, "there/drop.dat")
	coldBody(t, fx, res, "here/keep.dat", body)
}

// TestLinkToCleanFilePublishesIncrementedNlink is the other direction over
// the same clean inode. It passed before the fix and has to keep passing
// after it: Link already materializes the onode row, and a fix that made
// the seal count edges instead would have had to get this right from a
// walk rather than from a row.
func TestLinkToCleanFilePublishesIncrementedNlink(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0012-4000-8000-000000000012")
	ov := openOverlay(t, fx, "")

	// base.txt has been in the base generation since generation zero, so
	// it is as clean as an inode gets.
	base := lookupPath(t, ov, "base.txt")
	mustDirty(t, ov, base.Inode, false, "base.txt before anything touches it")
	wantNlink(t, "base.txt in the base generation", base.Nlink, 1)

	d, err := ov.Mkdir(ctx, rootIno, "links", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Link(ctx, base.Inode, d.Inode, "alias.txt"); err != nil {
		t.Fatalf("link a clean base file: %v", err)
	}
	res := sealAndSwap(t, fx, ov)

	for _, p := range []string{"base.txt", "links/alias.txt"} {
		n := coldNlink(t, fx, res, p)
		wantNlink(t, p+" in the SEALED generation, read back cold", n.Nlink, 2)
		if n.Inode != base.Inode {
			t.Errorf("%s resolves to inode %d, want the linked %d", p, n.Inode, base.Inode)
		}
		coldBody(t, fx, res, p, fx.body["base.txt"])
	}
}

// TestUnlinkCleanHardlinksToZeroRemovesTheFile takes the same clean pair
// all the way down. Both names go, in two separate operations, and the
// second one is the interesting half: by then the inode is at nlink 1 and
// the removal has to purge it rather than leave a promoted inode with no
// names, which is a shard record and a chunk reference nothing can reach
// and nothing can free.
func TestUnlinkCleanHardlinksToZeroRemovesTheFile(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0013-4000-8000-000000000013")
	ov := openOverlay(t, fx, "")
	dir, file := hardlinkedPair(t, fx, ov, []byte("a body with a countdown on it"))

	if err := ov.Unlink(ctx, dir, "two.dat"); err != nil {
		t.Fatalf("unlink the second name: %v", err)
	}
	if err := ov.Unlink(ctx, dir, "one.dat"); err != nil {
		t.Fatalf("unlink the last name: %v", err)
	}
	if names := dirNames(t, ov, dir); len(names) != 0 {
		t.Errorf("the directory still lists %v after both names went away", names)
	}
	// The inode number itself still answers out of the base generation —
	// nothing whites out an inode, only names — so what has to be true is
	// that no NAME reaches it and no shard record survives for it.
	_ = file

	res := sealAndSwap(t, fx, ov)

	coldAbsent(t, fx, res, "links/one.dat")
	coldAbsent(t, fx, res, "links/two.dat")
	if res.Stats.PromotedInodes != 0 {
		t.Errorf("the sealed generation promoted %d inodes; the only hardlinked file is gone",
			res.Stats.PromotedInodes)
	}
}
