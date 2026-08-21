package overlay_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// The whiteout state machine under the sequence a repair actually
// produces: delete a base file, restore it (git checkout, tar -x, an
// editor's write-and-rename), then delete it again.
//
// The seam is that the second unlink removes an OVERLAY edge, not a base
// one, so the whiteout that expressed the first deletion is gone --
// consumed by the recreate, which replaced it. Nothing else hides the base
// name, so failing to write a fresh whiteout resurrects the base file: it
// reappears in the merged view, every unlink of it "succeeds", and the
// rmdir behind it refuses forever.
//
// Three shapes, because the state the second unlink reads differs in each:
// within one session; with a checkpoint in between (which republishes the
// recreated file and drops the edges it published); and across a
// close/reopen of the overlay, which is the shape a user hits when the
// repair was one session and the deletion is the next.

// deletedEverywhere is the assertion all three share: absent from both
// readdir surfaces, ENOENT to Lookup, and the parent then empties.
func deletedEverywhere(t *testing.T, ov *overlay.FS, parent uint64, name, path string) {
	t.Helper()
	ctx := context.Background()

	if _, err := lookupPathErr(ov, path); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("%s: lookup after unlink = %v, want ErrNotExist", path, err)
	}
	if _, err := ov.Lookup(ctx, parent, name); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("%s: Lookup(%d, %q) = %v, want ErrNotExist", path, parent, name, err)
	}
	for _, r := range []struct {
		what string
		fn   func(context.Context, uint64) ([]overlay.DirEntry, error)
	}{
		{"Readdir", ov.Readdir},
		// ReaddirRetain is the seal's bulk path, and it reaches base
		// entries by a different route than the per-entry Lookup above. A
		// whiteout one of them honors and the other does not is a deletion
		// that survives the merged view and is republished anyway.
		{"ReaddirRetain", ov.ReaddirRetain},
	} {
		es, err := r.fn(ctx, parent)
		if err != nil {
			t.Fatalf("%s(%d): %v", r.what, parent, err)
		}
		for _, e := range es {
			if e.Name == name {
				t.Errorf("%s: %s still lists %q (inode %d)", path, r.what, name, e.Node.Inode)
			}
		}
	}
}

func TestUnlinkRecreateUnlinkInOneSession(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "3b1e0000-0001-4000-8000-000000000001")
	ov := openOverlay(t, fx, "")

	dirIno := lookupPath(t, ov, "dir").Inode
	innerIno := lookupPath(t, ov, "dir/inner").Inode

	// (1) delete the base file: a whiteout over the base edge.
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatalf("first unlink: %v", err)
	}
	// (2) restore it: the new oedge REPLACES the whiteout.
	n, err := ov.Create(ctx, innerIno, "leaf.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte("restored body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// (3) delete it again: an OVERLAY edge goes, and the base name
	// underneath needs a whiteout of its own.
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatalf("second unlink: %v", err)
	}

	deletedEverywhere(t, ov, innerIno, "leaf.txt", "dir/inner/leaf.txt")
	if err := ov.Rmdir(ctx, dirIno, "inner"); err != nil {
		t.Fatalf("the emptied directory would not go: %v", err)
	}
}

func TestUnlinkRecreateUnlinkAcrossACheckpoint(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "3b1e0000-0002-4000-8000-000000000002")
	ov := openOverlay(t, fx, "")

	innerIno := lookupPath(t, ov, "dir/inner").Inode
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatalf("first unlink: %v", err)
	}
	n, err := ov.Create(ctx, innerIno, "leaf.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	restored := []byte("restored, then published")
	if _, err := ov.Write(ctx, n.Inode, 0, restored); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The checkpoint: the recreated file is published, so the generation
	// under the overlay now HAS it at that name, and the rebase drops the
	// edge that named it.
	snap := takeSnapshot(t, ov)
	seq := snap.Seq()
	res := sealAndSwap(t, fx, ov)
	rebase(t, ov, seq, res)
	_ = snap.Close()
	mustBody(t, ov, "dir/inner/leaf.txt", restored)

	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatalf("unlink after the checkpoint: %v", err)
	}
	deletedEverywhere(t, ov, innerIno, "leaf.txt", "dir/inner/leaf.txt")

	// And the deletion must survive being published in its turn.
	snap2 := takeSnapshot(t, ov)
	seq2 := snap2.Seq()
	res2 := sealAndSwap(t, fx, ov)
	rebase(t, ov, seq2, res2)
	_ = snap2.Close()
	deletedEverywhere(t, ov, innerIno, "leaf.txt", "dir/inner/leaf.txt")
}

// The owner's actual shape: the repair was sealed in one session, and the
// deletion happens in the NEXT one, over a reopened overlay that carries
// none of the first session's in-memory state.
func TestUnlinkRecreateUnlinkAcrossAReopen(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "3b1e0000-0003-4000-8000-000000000003")
	dir := t.TempDir()
	ov := openOverlay(t, fx, dir)

	innerIno := lookupPath(t, ov, "dir/inner").Inode
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatalf("first unlink: %v", err)
	}
	n, err := ov.Create(ctx, innerIno, "leaf.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("recreate: %v", err)
	}
	restored := []byte("restored in the previous session")
	if _, err := ov.Write(ctx, n.Inode, 0, restored); err != nil {
		t.Fatalf("write: %v", err)
	}
	snap := takeSnapshot(t, ov)
	seq := snap.Seq()
	res := sealAndSwap(t, fx, ov)
	rebase(t, ov, seq, res)
	_ = snap.Close()
	if err := ov.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Session two, same overlay directory over the sealed generation.
	ov2 := openOverlay(t, fx, dir)
	mustBody(t, ov2, "dir/inner/leaf.txt", restored)
	inner2 := lookupPath(t, ov2, "dir/inner").Inode
	if err := ov2.Unlink(ctx, inner2, "leaf.txt"); err != nil {
		t.Fatalf("unlink in the second session: %v", err)
	}
	deletedEverywhere(t, ov2, inner2, "leaf.txt", "dir/inner/leaf.txt")

	// Session three: the deletion is on disk, not merely in memory.
	snap2 := takeSnapshot(t, ov2)
	seq2 := snap2.Seq()
	res2 := sealAndSwap(t, fx, ov2)
	rebase(t, ov2, seq2, res2)
	_ = snap2.Close()
	if err := ov2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ov3 := openOverlay(t, fx, dir)
	inner3 := lookupPath(t, ov3, "dir/inner").Inode
	deletedEverywhere(t, ov3, inner3, "leaf.txt", "dir/inner/leaf.txt")
	names := entryNames(mustReaddir(t, ov3, inner3))
	if len(names) != 0 {
		t.Errorf("dir/inner after the deletion was published = %v, want empty", names)
	}
}

// The same sequence on a SYMLINK, which is what the owner's survivors
// were: recreating a link over its own whiteout and deleting it again
// must leave nothing behind either.
func TestUnlinkRecreateUnlinkOfASymlink(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "3b1e0000-0004-4000-8000-000000000004")
	ov := openOverlay(t, fx, "")

	dirIno := lookupPath(t, ov, "dir").Inode
	if _, err := ov.Symlink(ctx, dirIno, "alias", "child.txt", 0, 0); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := ov.Unlink(ctx, dirIno, "alias"); err != nil {
		t.Fatalf("unlink of the link: %v", err)
	}
	if _, err := ov.Symlink(ctx, dirIno, "alias", "child.txt", 0, 0); err != nil {
		t.Fatalf("re-symlink: %v", err)
	}
	if err := ov.Unlink(ctx, dirIno, "alias"); err != nil {
		t.Fatalf("second unlink of the link: %v", err)
	}
	deletedEverywhere(t, ov, dirIno, "alias", "dir/alias")
	if names := entryNames(mustReaddir(t, ov, dirIno)); !reflect.DeepEqual(names, []string{"child.txt", "inner"}) {
		t.Errorf("dir = %v, want [child.txt inner]", names)
	}
	// The target the link named is untouched.
	mustBody(t, ov, "dir/child.txt", fx.body["dir/child.txt"])
}
