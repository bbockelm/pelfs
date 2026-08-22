package overlay_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// link(2) is the ONE namespace operation that names its subject by BARE
// INODE and resolves no name: the kernel sends the source as
// LinkIn.Oldnodeid and internal/rawfuse passes it straight to
// overlay.Link (rawfuse/rw.go). Every other mutating operation either
// carries a (parent, name) pair the overlay resolves on the way in, or
// operates on an inode whose base residency it is allowed to find missing.
//
// That makes Link the only caller of persistChainLocked that can arrive
// with no descent of its own behind it -- and persistChainLocked used to
// read the base descent step out of fs.prov ALONE, treating a miss as
// impossible ("detaching an inode requires having looked it up"). The
// checkpoint's provenance sweep (rebase.go) made the miss ordinary: it
// drops prov for every inode a published generation cleaned, on the
// correct grounds that prov is a cache. A cache whose miss is a hard
// error is not a cache, and the error was
//
//	overlay: no base provenance for inode N
//
// These tests drive overlay.Link with a bare inode across a checkpoint,
// which is the FUSE frontend's own call shape. The path frontends
// (vfsbilly, and NFS through it) resolve by name and cannot reach it.
//
// WHEN A REAL MOUNT REACHES IT, which is narrower than the original
// report said and worth writing down because the two mechanisms have to
// line up. The link only fails if no LOOKUP intervenes, so the kernel must
// be answering from a dentry it still holds -- and the TTL on that dentry
// comes from rawfuse's dirty set, which is STICKY for the life of a mount
// ("Dirt is sticky for an overlay's lifetime", rawfuse/rw.go). So inside
// ONE session the two conditions exclude each other: an inode whose prov
// the sweep drops is by definition one this session dirtied, so rawfuse
// has it marked forever and stamps every later reply with dirtyValidity
// (ONE SECOND) -- the dentry expires and the link re-looks-up.
//
// It lines up in two ways, and both are ordinary:
//
//   - ACROSS SESSIONS. A new mount starts with an empty dirty set, so the
//     first lookup of a file an earlier session published is stamped CLEAN
//     -- entryValidity, ten years. Writing to it afterwards makes it dirty
//     but cannot un-cache the dentry the kernel already holds. Then a
//     checkpoint sweeps its provenance and the link arrives with nothing
//     behind it. That is: mount, read a file, edit it, keep working, hard-
//     link it. TestLinkAfterASecondSessionEditedAPublishedFile.
//   - WITHIN one session, in the sub-second window after a checkpoint,
//     where the one-second dentry stamped before it has not yet expired.
//     Checkpoints are asynchronous, so this is a race rather than a
//     sequence, which is why the pin is at this layer and not in the
//     hostile exerciser: a plan cannot insist on what the kernel's dcache
//     does. Driving overlay.Link directly is the same call with the timing
//     question removed.

// cleanFileAcrossCheckpoint leaves the fixture holding one CLEAN file --
// published by a checkpoint, swept out of prov by it -- and returns the
// bare inode the kernel would still be holding for it.
func cleanFileAcrossCheckpoint(t *testing.T, fx *fixture, ov *overlay.FS, dirName, fileName string, body []byte) uint64 {
	t.Helper()
	ctx := context.Background()
	d, err := ov.Mkdir(ctx, rootIno, dirName, 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ov.Create(ctx, d.Inode, fileName, 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, f.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)
	mustDirty(t, ov, f.Inode, false, dirName+"/"+fileName+" after the checkpoint that published it")
	return f.Inode
}

// wantLinked fails with the product's own sentence when the operation
// refused for the reason this file exists, so a regression is
// self-describing rather than a bare non-nil error.
func wantLinked(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "no base provenance") {
		t.Fatalf("%s: %v\n"+
			"A link names its source by bare inode, so nothing refilled the provenance "+
			"cache the checkpoint swept; persistChainLocked has to fall back to the "+
			"base's own copy of the descent step.", what, err)
	}
	t.Fatalf("%s: %v", what, err)
}

// TestLinkOfACleanFileWithoutALookup is the bug, minimally: one file, one
// checkpoint, one link by bare inode, no lookup anywhere in between.
func TestLinkOfACleanFileWithoutALookup(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0031-4000-8000-000000000031")
	ov := openOverlay(t, fx, "")
	body := []byte("a file that has been sitting still, which is the one you hard-link")
	file := cleanFileAcrossCheckpoint(t, fx, ov, "hl", "src.dat", body)

	// THE OPERATION. No Lookup, no GetAttr-by-path, nothing that would
	// re-descend the base: just the inode number the kernel kept in its
	// cached dentry, which is all LINK carries.
	n, err := ov.Link(ctx, file, rootIno, "alias.dat")
	wantLinked(t, err, "link a clean file by bare inode after the checkpoint that published it")
	if n.Inode != file {
		t.Fatalf("the link resolves to inode %d, want the linked %d", n.Inode, file)
	}

	// The link is REAL in the merged view: both names, one inode, nlink 2.
	wantNlink(t, "the linked file in the live merged view", n.Nlink, 2)
	for _, p := range []string{"hl/src.dat", "alias.dat"} {
		got := lookupPath(t, ov, p)
		if got.Inode != file {
			t.Errorf("%s resolves to inode %d, want the linked %d", p, got.Inode, file)
		}
		wantNlink(t, p+" in the live merged view", got.Nlink, 2)
	}

	// And in the SEALED generation, read back cold: a link count that is
	// only right in memory is the bug a sibling just finished fixing.
	res := sealAndSwap(t, fx, ov)
	for _, p := range []string{"hl/src.dat", "alias.dat"} {
		cold := coldNlink(t, fx, res, p)
		wantNlink(t, p+" in the SEALED generation, read back cold", cold.Nlink, 2)
		if cold.Inode != file {
			t.Errorf("the sealed %s is inode %d, want the linked %d (the names came apart)", p, cold.Inode, file)
		}
		coldBody(t, fx, res, p, body)
	}
}

// TestLinkOfACleanFileWithoutALookupNeedsTheWholeChain puts the file two
// directories deep, so the descent step the link has to recover is not
// just the file's own: persistChainLocked walks to the root, and every
// ancestor the checkpoint cleaned was swept out of prov too.
func TestLinkOfACleanFileWithoutALookupNeedsTheWholeChain(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0032-4000-8000-000000000032")
	ov := openOverlay(t, fx, "")

	outer, err := ov.Mkdir(ctx, rootIno, "outer", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := ov.Mkdir(ctx, outer.Inode, "inner", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ov.Create(ctx, inner.Inode, "deep.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("three edges from the root, all of them cleaned by one checkpoint")
	if _, err := ov.Write(ctx, f.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	quietCheckpoint(t, fx, ov)
	for _, ino := range []uint64{outer.Inode, inner.Inode, f.Inode} {
		mustDirty(t, ov, ino, false, "an inode the checkpoint published")
	}

	n, err := ov.Link(ctx, f.Inode, rootIno, "deep-alias.dat")
	wantLinked(t, err, "link a clean file three edges down by bare inode")
	wantNlink(t, "the deep file in the live merged view", n.Nlink, 2)

	res := sealAndSwap(t, fx, ov)
	for _, p := range []string{"outer/inner/deep.dat", "deep-alias.dat"} {
		cold := coldNlink(t, fx, res, p)
		wantNlink(t, p+" in the SEALED generation, read back cold", cold.Nlink, 2)
		if cold.Inode != f.Inode {
			t.Errorf("the sealed %s is inode %d, want the linked %d", p, cold.Inode, f.Inode)
		}
		coldBody(t, fx, res, p, body)
	}
}

// TestLinkOfACleanFileSurvivesASecondCheckpoint is the shape a long-lived
// mount actually has: the link itself is published, and then the linked
// inode -- now with two names, one of them the overlay's -- gets linked a
// THIRD time from a bare inode after another checkpoint. The second link
// exercises the fallback over an inode whose base copy of the descent step
// is the one the last seal wrote, not the one the session first saw.
func TestLinkOfACleanFileSurvivesASecondCheckpoint(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0033-4000-8000-000000000033")
	ov := openOverlay(t, fx, "")
	body := []byte("linked once, published, linked again")
	file := cleanFileAcrossCheckpoint(t, fx, ov, "hl", "src.dat", body)

	if _, err := ov.Link(ctx, file, rootIno, "second.dat"); err != nil {
		wantLinked(t, err, "the first link")
	}
	quietCheckpoint(t, fx, ov)
	mustDirty(t, ov, file, false, "the twice-named file after the checkpoint that published both names")

	n, err := ov.Link(ctx, file, rootIno, "third.dat")
	wantLinked(t, err, "link the same clean inode again after a second checkpoint")
	wantNlink(t, "the thrice-named file in the live merged view", n.Nlink, 3)

	res := sealAndSwap(t, fx, ov)
	for _, p := range []string{"hl/src.dat", "second.dat", "third.dat"} {
		cold := coldNlink(t, fx, res, p)
		wantNlink(t, p+" in the SEALED generation, read back cold", cold.Nlink, 3)
		if cold.Inode != file {
			t.Errorf("the sealed %s is inode %d, want the linked %d", p, cold.Inode, file)
		}
		coldBody(t, fx, res, p, body)
	}
}

// TestLinkOfAnInodeNothingEverDescendedIsStale is the boundary the fix
// must NOT cross, pinned so a later "helpful" version of the fallback does
// not cross it. An inode no descent in this generation ever reached has no
// residency, so the base cannot name it, so the link is refused — and that
// is correct, not a remaining half of the bug. There is no reverse index
// from inode to name (the catalog is a locator by descent, by design), and
// inventing one would mean scanning the generation's edges on an operation
// that is supposed to be cheap.
//
// It is also not reachable from a mount: FUSE node ids are valid only
// within one mount session, so the kernel cannot send LINK for an inode it
// has not looked up SINCE this session started. The bug was never "the
// kernel knows an inode we do not" — it was "we threw away the answer for
// an inode we still had residency for".
func TestLinkOfAnInodeNothingEverDescendedIsStale(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0034-4000-8000-000000000034")
	ov := openOverlay(t, fx, "")

	// Known from the fixture, never looked up through this overlay.
	file := fx.ino["dir/inner/leaf.txt"]

	_, err := ov.Link(ctx, file, rootIno, "leaf-alias.txt")
	if !errors.Is(err, overlay.ErrStale) {
		t.Fatalf("link of an inode nothing ever descended returned %v, want ErrStale: "+
			"an inode with no residency is one nothing here can name, and the honest "+
			"answer is ESTALE rather than a scan of the generation", err)
	}

	// One lookup and the same call succeeds, which is the difference the
	// whole file is about: the descent is what makes the inode nameable,
	// and after a checkpoint had swept prov the descent's answer was still
	// there to be asked for.
	if n := lookupPath(t, ov, "dir/inner/leaf.txt"); n.Inode != file {
		t.Fatalf("dir/inner/leaf.txt is inode %d, want %d", n.Inode, file)
	}
	if _, err := ov.Link(ctx, file, rootIno, "leaf-alias.txt"); err != nil {
		t.Fatalf("link after the lookup that made it resident: %v", err)
	}
}

// TestLinkAfterASecondSessionEditedAPublishedFile is the shape a real FUSE
// mount reaches without any race, and the reason this bug was worth fixing
// rather than documenting. See the TTL reasoning at the top of this file:
// a second session's first lookup of an inherited file is stamped CLEAN, so
// the kernel holds a ten-year dentry that the later write cannot un-cache
// and the later checkpoint sweeps provenance underneath.
//
// Reopening the same overlay directory is exactly what `pelfs mount-gen
// --rw` does on the second mount of a state directory, and it is the state
// every file in the volume is in for a session that did not create it.
func TestLinkAfterASecondSessionEditedAPublishedFile(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "6e057e57-0035-4000-8000-000000000035")
	dir := t.TempDir()
	ov := openOverlay(t, fx, dir)

	body := []byte("published by one session, edited and hard-linked by the next")
	file := cleanFileAcrossCheckpoint(t, fx, ov, "hl", "src.dat", body)
	if err := ov.Close(); err != nil {
		t.Fatalf("close the first session: %v", err)
	}

	// SECOND session over the same state: empty provenance cache, empty
	// dirty set, and a file the base generation already holds.
	ov2 := openOverlay(t, fx, dir)
	if n := lookupPath(t, ov2, "hl/src.dat"); n.Inode != file {
		t.Fatalf("hl/src.dat is inode %d, want %d", n.Inode, file)
	}
	// The edit. It dirties the inode -- and on a mount it does NOT cost a
	// lookup, because the dentry from the line above is still valid.
	patch := []byte("EDITED")
	if _, err := ov2.Write(ctx, file, 4, patch); err != nil {
		t.Fatal(err)
	}
	copy(body[4:], patch)
	// The checkpoint that publishes the edit is what sweeps the provenance
	// the lookup above recorded.
	quietCheckpoint(t, fx, ov2)
	mustDirty(t, ov2, file, false, "the edited file after the checkpoint that published it")

	n, err := ov2.Link(ctx, file, rootIno, "alias.dat")
	wantLinked(t, err, "link a file a second session edited and a checkpoint published")
	wantNlink(t, "the linked file in the live merged view", n.Nlink, 2)

	res := sealAndSwap(t, fx, ov2)
	for _, p := range []string{"hl/src.dat", "alias.dat"} {
		cold := coldNlink(t, fx, res, p)
		wantNlink(t, p+" in the SEALED generation, read back cold", cold.Nlink, 2)
		if cold.Inode != file {
			t.Errorf("the sealed %s is inode %d, want the linked %d", p, cold.Inode, file)
		}
		coldBody(t, fx, res, p, body)
	}
}
