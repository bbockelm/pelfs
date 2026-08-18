package publish_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
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
//
// Extended attributes sit on a MINORITY of the tree, which is the shape
// the read path optimizes for: a catalog records at open whether it holds
// any xattr row at all and answers "none" for its whole span from that,
// without ever locating the inode. Both halves of that answer have to be
// walked — the catalogs that hold rows and the ones that hold none — so a
// seal past the residency bound exercises the fast path in both
// directions.
func sealBeyondResidency(t *testing.T, v *reuseVol) (map[string][]byte, map[string]map[string]string) {
	t.Helper()
	ctx := context.Background()
	body := make(map[string][]byte)
	xattrs := map[string]map[string]string{
		"": {"user.origin": "seal test"}, // the root
	}
	for d := 0; d < 4; d++ {
		dir, err := v.ov.Mkdir(ctx, publishRootInode, fmt.Sprintf("d%d", d), 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < 12; f++ {
			p := fmt.Sprintf("d%d/f%d", d, f)
			body[p] = []byte(fmt.Sprintf("body of %s, long enough to be worth a chunkref", p))
			ino := v.create(dir.Inode, fmt.Sprintf("f%d", f), body[p])
			if d == 0 && f%5 == 0 {
				if err := v.ov.SetXattr(ctx, ino, "user.tag", []byte(p)); err != nil {
					t.Fatalf("setxattr %s: %v", p, err)
				}
				xattrs[p] = map[string]string{"user.tag": p}
			}
		}
	}
	// The root's own attribute, because the failure surfaced on the xattr
	// pass first and the root is where that pass starts.
	if err := v.ov.SetXattr(ctx, v.ov.RootInode(), "user.origin", []byte("seal test")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	return body, xattrs
}

// verifyXattrs reads a sealed generation's extended attributes back
// through a cold genfs and checks both directions: every attribute the
// fixture set is present, and every path it did not name has none.
func verifyXattrs(t *testing.T, v *reuseVol, res *publish.Result, body map[string][]byte, want map[string]map[string]string) {
	t.Helper()
	ctx := context.Background()
	sealed := openGenfs(t, v.inner, res.Superblock, nil)
	check := func(p string, ino uint64) {
		names, err := sealed.ListXattr(ctx, ino)
		if err != nil {
			t.Fatalf("listxattr %q: %v", p, err)
		}
		w := want[p]
		if len(names) != len(w) {
			t.Errorf("%q has xattrs %v, want %v", p, names, w)
			return
		}
		for name, value := range w {
			got, err := sealed.GetXattr(ctx, ino, name)
			if err != nil {
				t.Errorf("getxattr %q %s: %v", p, name, err)
				continue
			}
			if string(got) != value {
				t.Errorf("%q %s = %q, want %q", p, name, got, value)
			}
		}
	}
	check("", publishRootInode)
	for p := range body {
		check(p, lookupPath(t, sealed, p).Inode)
	}
}

// A tree larger than the residency bound must seal, and the generation
// must read back.
func TestSealTreeLargerThanResidency(t *testing.T) {
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x01}, residencyCap)
	body, xattrs := sealBeyondResidency(t, v)
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
	xattrs[""]["user.touched"] = "1"
	second := v.checkpoint()
	if second.Stats.ReusedFiles != len(body) {
		t.Errorf("reused %d files, want %d", second.Stats.ReusedFiles, len(body))
	}
	v.verifyBodies(second, body)
	verifyXattrs(t, v, second, body, xattrs)
}

// The same, with a change on top, after a mid-session checkpoint has
// already swapped the base generation underneath the overlay.
func TestSealAfterCheckpointWithBoundedResidency(t *testing.T) {
	ctx := context.Background()
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x02}, residencyCap)
	body, xattrs := sealBeyondResidency(t, v)
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
	verifyXattrs(t, v, res, body, xattrs)
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
	body, xattrs := sealBeyondResidency(t, v)
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
	// The recreated file is a new inode under a name whose base inode
	// carried an attribute; inheriting it would mean the seal published the
	// hidden inode's rows.
	delete(xattrs, "d0/f0")

	second := v.checkpoint()
	v.verifyBodies(second, body)
	verifyXattrs(t, v, second, body, xattrs)
	sealed := openGenfs(t, v.inner, second.Superblock, nil)
	gone := lookupPath(t, sealed, "d1")
	if _, err := sealed.Lookup(ctx, gone.Inode, "f1"); err == nil {
		t.Fatal("a renamed-away name still resolves in the sealed generation")
	}
}

// The failure's actual shape: a NEW SESSION over a volume it did not
// write. Every same-session test above is blind to it, because a
// checkpoint's rebase re-pins provenance for everything the session wrote,
// so the walk inherits a full set of base descent steps it never had to
// record. A fresh mount inherits none, which is the situation anyone
// remounting an 85k-inode volume is in.
//
// The walk must therefore record its own: it lists a directory and makes
// its entries resident in one pass, and residency past the bound is
// temporary — the second pass asks about inodes the descent has since
// evicted, and can only get them back by replaying the descent that
// reached them.
func TestSealAfterRemountBeyondResidency(t *testing.T) {
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x04}, residencyCap)
	// A tree of catalogs rather than one flat catalog, so the xattr fast
	// path answers "none" from a whole catalog for some of the walk and has
	// to fall through to a query for the rest.
	v.smax = splitTreeSMax
	body, xattrs := sealBeyondResidency(t, v)
	first := v.checkpoint()
	if first.Stats.Catalogs < 2 {
		t.Fatalf("the fixture published %d catalog(s); the xattr fast path would answer "+
			"the whole tree from one fact", first.Stats.Catalogs)
	}
	v.verifyBodies(first, body)

	v.remount()

	// One new file, plus an attribute on every top-level directory. The
	// attribute is what makes the test walk anything at all: a change
	// confined to the root leaves every subtree carryable, and the plan then
	// prunes the descent to a handful of inodes — well inside the bound, and
	// so blind to the eviction this test is about.
	body["no.txt"] = []byte("one file touched in a whole volume")
	v.create(publishRootInode, "no.txt", body["no.txt"])
	for d := 0; d < 4; d++ {
		dir := lookupPath(t, v.ov, fmt.Sprintf("d%d", d))
		mode := uint32(0750)
		if _, err := v.ov.SetAttr(context.Background(), dir.Inode, overlay.SetAttrIn{Mode: &mode}); err != nil {
			t.Fatalf("chmod d%d: %v", d, err)
		}
	}

	second := v.checkpoint()
	if second.Stats.ReusedFiles != len(body)-1 {
		t.Errorf("reused %d files, want %d: the walk did not reach the whole tree",
			second.Stats.ReusedFiles, len(body)-1)
	}
	v.verifyBodies(second, body)
	verifyXattrs(t, v, second, body, xattrs)
}

// The same fresh session, sealing a volume it has not changed at all
// beyond one attribute — so every inode's xattrs AND content resolve
// through a base that has evicted most of them, with no dirty row anywhere
// to answer from instead.
func TestSealAfterRemountWithNothingDirty(t *testing.T) {
	ctx := context.Background()
	v := newReuseVolResident(t, [16]byte{0x5e, 0xa1, 0x05}, residencyCap)
	body, xattrs := sealBeyondResidency(t, v)
	v.checkpoint()

	v.remount()

	// Dirtying the root forces its catalog to be rebuilt; a seal that finds
	// nothing dirty carries every catalog forward and never reads the tree.
	if err := v.ov.SetXattr(ctx, v.ov.RootInode(), "user.touched", []byte("1")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	xattrs[""]["user.touched"] = "1"

	second := v.checkpoint()
	if second.Stats.ReusedFiles != len(body) {
		t.Errorf("reused %d files, want %d", second.Stats.ReusedFiles, len(body))
	}
	v.verifyBodies(second, body)
	verifyXattrs(t, v, second, body, xattrs)
}
