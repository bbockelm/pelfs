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
