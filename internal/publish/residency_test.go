package publish_test

import (
	"context"
	"fmt"
	"testing"
)

// A seal walks the whole tree by definition, so it must not depend on the
// accident of which inodes the base generation happens to hold residency
// for. It used to: a mount with a bounded residency map (the NFS backend
// caps it) evicts in least-recently-used order, which is roughly the order
// a descent established it, so the seal's second pass — xattrs, then
// content — asked about the very inodes the descent had already pushed
// out. On a real volume that failed at the first one:
//
//	publish: xattrs of inode 2: genfs: stale inode (no residency)
//
// and the volume then could not be sealed at all.
const residencyCap = 24

// sealBeyondResidency builds a tree with more inodes than the base
// generation will hold residency for and seals it.
func sealBeyondResidency(t *testing.T, v *reuseVol) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	body := make(map[string][]byte)
	for d := 0; d < 4; d++ {
		dir, err := v.ov.Mkdir(ctx, publishRootInode, fmt.Sprintf("d%d", d), 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < 12; f++ {
			p := fmt.Sprintf("d%d/f%d", d, f)
			body[p] = []byte(fmt.Sprintf("body of %s, long enough to be worth a chunkref", p))
			v.create(dir.Inode, fmt.Sprintf("f%d", f), body[p])
		}
	}
	// One xattr, because the failure surfaced on the xattr pass first.
	if err := v.ov.SetXattr(ctx, v.ov.RootInode(), "user.origin", []byte("seal test")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	return body
}

// A tree larger than the residency bound must seal, and the generation
// must read back.
func TestSealTreeLargerThanResidency(t *testing.T) {
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x01}, residencyCap)
	body := sealBeyondResidency(t, v)
	first := v.checkpoint()
	v.verifyBodies(first, body)

	// The second seal is the one that actually stresses it: everything is
	// clean now, so every inode's xattrs AND content resolve through the
	// base generation, which is exactly what eviction had made
	// unanswerable.
	//
	// One directory attribute is touched first, and it is load-bearing for
	// this test rather than incidental: a seal that finds NOTHING dirty
	// carries every catalog forward and never reaches the content path at
	// all. Dirtying the root makes its catalog — the only one this small
	// tree has — a rebuild, so all 48 files' records are resolved through
	// the evicted base, which is the failure this test exists to pin.
	if err := v.ov.SetXattr(context.Background(), v.ov.RootInode(), "user.touched", []byte("1")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	second := v.checkpoint()
	if second.Stats.ReusedFiles != len(body) {
		t.Errorf("reused %d files, want %d", second.Stats.ReusedFiles, len(body))
	}
	v.verifyBodies(second, body)
}

// The same, with a change on top, after a mid-session checkpoint has
// already swapped the base generation underneath the overlay.
func TestSealAfterCheckpointWithBoundedResidency(t *testing.T) {
	ctx := context.Background()
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x02}, residencyCap)
	body := sealBeyondResidency(t, v)
	v.checkpoint()

	n, err := v.ov.Create(ctx, publishRootInode, "no.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create no.txt: %v", err)
	}
	body["no.txt"] = []byte("one file touched in a whole volume")
	if _, err := v.ov.Write(ctx, n.Inode, 0, body["no.txt"]); err != nil {
		t.Fatalf("write no.txt: %v", err)
	}
	res := v.checkpoint()
	v.verifyBodies(res, body)
}

// A namespace change interacts with the residency bound through the
// listing itself: a directory read now makes its whole listing resident in
// one pass, including base entries the overlay hides or replaces. Those
// entries take slots in a bounded residency map, so a seal over a tree
// past the bound must still resolve everything it does keep — after
// unlinks (whiteouts), renames (a base name replaced), and a recreate over
// a hidden name.
func TestSealBeyondResidencyAfterNamespaceChanges(t *testing.T) {
	ctx := context.Background()
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x03}, residencyCap)
	body := sealBeyondResidency(t, v)
	first := v.checkpoint()
	v.verifyBodies(first, body)

	d0 := lookupPath(t, v.ov, "d0")
	d1 := lookupPath(t, v.ov, "d1")
	if err := v.ov.Unlink(ctx, d0.Inode, "f0"); err != nil {
		t.Fatalf("unlink d0/f0: %v", err)
	}
	delete(body, "d0/f0")
	if err := v.ov.Rename(ctx, d1.Inode, "f1", d0.Inode, "f1moved"); err != nil {
		t.Fatalf("rename d1/f1: %v", err)
	}
	body["d0/f1moved"] = body["d1/f1"]
	delete(body, "d1/f1")
	// Recreating over a whiteout is the case where the base entry is both
	// hidden and replaced, so the listing carries a name whose base inode
	// must not be what the seal publishes.
	body["d0/f0"] = []byte("a different body under a name the base still holds")
	v.create(d0.Inode, "f0", body["d0/f0"])

	second := v.checkpoint()
	v.verifyBodies(second, body)
	sealed := openGenfs(t, v.inner, second.Superblock, nil)
	gone := lookupPath(t, sealed, "d1")
	if _, err := sealed.Lookup(ctx, gone.Inode, "f1"); err == nil {
		t.Fatal("a renamed-away name still resolves in the sealed generation")
	}
}
