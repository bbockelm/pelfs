package merge_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/merge"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

const rootIno uint64 = 1

var publishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

func newInner(t testing.TB) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

func body(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// forked builds the shape every case here needs: a base generation, then
// two branches that advanced from it independently. onOurs and onTheirs
// each get a volume already seated on the base.
func forked(t *testing.T, uuid string, onOurs, onTheirs func(v *testvol.Volume)) (pelicanobj.Store, *superblock.Superblock, *superblock.Superblock, *superblock.Superblock) {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	v.Mkdir(rootIno, "shared")
	v.WriteFile(rootIno, "base.bin", body(4096, 1))
	base := v.Publish(publishOpts).Superblock
	baseRaw := v.Raw()

	// "theirs" advances on a second branch, which is what `pelfs branch`
	// creates: a name over this generation that then moves on its own.
	v.SetBranch("dev")
	onTheirs(v)
	theirs := v.Publish(publishOpts).Superblock

	// "ours" advances on the original branch, from the same base.
	v.Adopt(base, baseRaw)
	v.SetBranch("main")
	onOurs(v)
	ours := v.Publish(publishOpts).Superblock
	return inner, base, ours, theirs
}

func compute(t *testing.T, inner pelicanobj.Store, base, ours, theirs *superblock.Superblock) *merge.Plan {
	t.Helper()
	p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: base, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return p
}

// Two branches that touched different files conflict nowhere. This is the
// case the recursive scheme exists for, and the one that has to be cheap
// and clean or nothing else matters.
func TestDisjointChangesMergeCleanly(t *testing.T) {
	inner, base, ours, theirs := forked(t, "11111111-1111-1111-1111-111111111111",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 2)) },
		func(v *testvol.Volume) {
			d := v.Lookup(rootIno, "shared")
			v.WriteFile(d, "theirs-only.bin", body(4096, 3))
		})
	p := compute(t, inner, base, ours, theirs)
	if p.Refusal != "" {
		t.Fatalf("refused: %s", p.Refusal)
	}
	for _, c := range p.Conflicts {
		t.Errorf("unexpected conflict: %s", c)
	}
	if p.TookOurs == 0 || p.TookTheirs == 0 {
		t.Errorf("a merge of two one-sided changes took %d from ours and %d from theirs",
			p.TookOurs, p.TookTheirs)
	}
	if !p.Mergeable() {
		t.Errorf("disjoint changes are not mergeable: %d conflicts, %d collisions",
			len(p.Conflicts), len(p.Collisions))
	}
	t.Logf("clean: %d unchanged, %d ours, %d theirs", p.Unchanged, p.TookOurs, p.TookTheirs)
}

// The ordinary conflict. Both sides changed one file to different content,
// and nothing in the trees says which is wanted.
func TestBothModifiedIsAConflict(t *testing.T) {
	inner, base, ours, theirs := forked(t, "22222222-2222-2222-2222-222222222222",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 10)) },
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 11)) })
	p := compute(t, inner, base, ours, theirs)
	if want := 1; len(p.Conflicts) != want {
		t.Fatalf("%d conflicts, want %d: %v", len(p.Conflicts), want, p.Conflicts)
	}
	if got := p.Conflicts[0]; got.Kind != merge.BothModified || got.Path != "/base.bin" {
		t.Errorf("conflict = %s, want both-modified on /base.bin", got)
	}
	if p.Mergeable() {
		t.Error("a both-modified conflict reports as mergeable")
	}
}

// Both sides changing a file to the SAME content is not a conflict:
// content addressing makes that comparison free and exact, and calling it
// a conflict would make every parallel rebuild of the same artifact one.
func TestTheSameChangeOnBothSidesIsNotAConflict(t *testing.T) {
	same := body(4096, 42)
	inner, base, ours, theirs := forked(t, "33333333-3333-3333-3333-333333333333",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), same) },
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), same) })
	p := compute(t, inner, base, ours, theirs)
	for _, c := range p.Conflicts {
		t.Errorf("identical edits conflicted: %s", c)
	}
}

// One side edits, the other deletes. Not comparable: nothing about the
// edit says whether the deletion was the point.
func TestModifyAgainstDeleteIsAConflict(t *testing.T) {
	inner, base, ours, theirs := forked(t, "44444444-4444-4444-4444-444444444444",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 20)) },
		func(v *testvol.Volume) { v.Unlink(rootIno, "base.bin") })
	p := compute(t, inner, base, ours, theirs)
	if len(p.Conflicts) != 1 || p.Conflicts[0].Kind != merge.ModifyDelete {
		t.Fatalf("conflicts = %v, want one modify-delete", p.Conflicts)
	}
}

// A file only one side ever had, deleted by nobody, is simply taken.
func TestADeletionOfAnUntouchedFileIsHonoured(t *testing.T) {
	inner, base, ours, theirs := forked(t, "55555555-5555-5555-5555-555555555555",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "ours-only.bin", body(4096, 30)) },
		func(v *testvol.Volume) { v.Unlink(rootIno, "base.bin") })
	p := compute(t, inner, base, ours, theirs)
	for _, c := range p.Conflicts {
		t.Errorf("unexpected conflict: %s", c)
	}
}

// Both sides creating the same path with different content has no base to
// three-way against, so it is a conflict rather than a guess.
func TestAddAddIsAConflict(t *testing.T) {
	inner, base, ours, theirs := forked(t, "66666666-6666-6666-6666-666666666666",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "both.bin", body(4096, 40)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "both.bin", body(4096, 41)) })
	p := compute(t, inner, base, ours, theirs)
	if len(p.Conflicts) == 0 {
		t.Fatal("both sides created the same path with different content and nothing conflicted")
	}
	if got := p.Conflicts[0].Kind; got != merge.AddAdd {
		t.Errorf("conflict kind = %s, want add-add", got)
	}
}

// The inode problem, which is the reason merge was out of scope. Both
// branches allocate from the same high-water mark, so any file each
// creates after the fork takes a number the other also took — and a
// merged tree would then have one number for two files.
func TestInodesAllocatedOnBothSidesCollide(t *testing.T) {
	inner, base, ours, theirs := forked(t, "77777777-7777-7777-7777-777777777777",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "ours-new.bin", body(4096, 50)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "theirs-new.bin", body(4096, 51)) })
	p := compute(t, inner, base, ours, theirs)
	if len(p.Collisions) == 0 {
		t.Fatal("both sides created a file after the fork and no inode collision was reported")
	}
	c := p.Collisions[0]
	if c.Inode < base.NextInode {
		t.Errorf("inode %d is at or below the base's high-water mark %d; it cannot be a collision",
			c.Inode, base.NextInode)
	}
	if c.OursPath == c.TheirsPath {
		t.Errorf("collision names the same path on both sides (%s), which would be the same file", c.OursPath)
	}
	if p.Mergeable() {
		t.Error("a plan with inode collisions reports as mergeable")
	}
	if p.FirstFreeInode < ours.NextInode || p.FirstFreeInode < theirs.NextInode {
		t.Errorf("FirstFreeInode %d is not above both sides (%d, %d)",
			p.FirstFreeInode, ours.NextInode, theirs.NextInode)
	}
	t.Logf("%d collisions; %s and %s both took inode %d; renumber above %d",
		len(p.Collisions), c.OursPath, c.TheirsPath, c.Inode, p.FirstFreeInode)
}

// A side that never moved needs no merge at all, and saying so without
// walking is what makes the common case free.
func TestAnUnmovedSideIsAFastForward(t *testing.T) {
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "88888888-8888-8888-8888-888888888888")})
	v.WriteFile(rootIno, "base.bin", body(4096, 1))
	base := v.Publish(publishOpts).Superblock
	baseRaw := v.Raw()

	v.SetBranch("dev")
	v.WriteFile(rootIno, "theirs.bin", body(4096, 2))
	theirs := v.Publish(publishOpts).Superblock

	// Ours is still the base.
	v.Adopt(base, baseRaw)
	p := compute(t, inner, base, base, theirs)
	if !p.FastForward || p.Direction != "theirs" {
		t.Fatalf("plan = %+v, want a fast-forward to theirs", p)
	}
	if p2 := compute(t, inner, base, theirs, base); !p2.FastForward || p2.Direction != "ours" {
		t.Fatalf("plan = %+v, want a fast-forward to ours", p2)
	}
	if p3 := compute(t, inner, base, theirs, theirs); !p3.FastForward {
		t.Fatalf("two identical heads are not a fast-forward: %+v", p3)
	}
}

// The checks a NAMED base can be held to. Ancestry is not among them —
// see the package comment — so what is ruled out is what can be.
func TestInputsThatCannotBeAMergeAreRefused(t *testing.T) {
	inner, base, ours, theirs := forked(t, "99999999-9999-9999-9999-999999999999",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "a", body(64, 1)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "b", body(64, 2)) })

	// A base that does not precede both sides.
	if p := compute(t, inner, ours, base, theirs); p.Refusal == "" {
		t.Error("a base newer than a side was accepted")
	}
	// A different volume.
	other := *base
	other.VolumeID = testvol.ParseUUID(t, "aaaaaaaa-9999-9999-9999-999999999999")
	if p := compute(t, inner, &other, ours, theirs); p.Refusal == "" {
		t.Error("a base from another volume was accepted")
	}
	if _, err := merge.Compute(context.Background(), merge.Options{Inner: inner, Ours: ours, Theirs: theirs}); err == nil {
		t.Error("a missing base was accepted")
	}
}

// A directory added by only one side still has to be scanned, or the
// inodes inside it never reach the collision check.
func TestASubtreeOnlyOneSideHasIsStillScanned(t *testing.T) {
	inner, base, ours, theirs := forked(t, "bbbbbbbb-1111-2222-3333-444444444444",
		func(v *testvol.Volume) {
			d := v.Mkdir(rootIno, "ours-dir")
			for i := range 3 {
				v.WriteFile(d, fmt.Sprintf("f%d", i), body(64, int64(60+i)))
			}
		},
		func(v *testvol.Volume) {
			d := v.Mkdir(rootIno, "theirs-dir")
			for i := range 3 {
				v.WriteFile(d, fmt.Sprintf("f%d", i), body(64, int64(70+i)))
			}
		})
	p := compute(t, inner, base, ours, theirs)
	// Four inodes each side (the directory and three files), all past the
	// base's mark, so every one of them collides.
	if len(p.Collisions) < 4 {
		t.Errorf("%d collisions across two 4-inode subtrees; the one-sided subtree was not scanned",
			len(p.Collisions))
	}
}

// The subtle one. Theirs deletes a directory; ours changed a file inside
// it. Comparing the DIRECTORIES cannot see that: sameContent calls two
// directories equal whenever their metadata matches, because directories
// are compared by their entries. A merge that decided the deletion from
// that would discard our work silently.
//
// The descent has to happen anyway for the inode pass, and it is what
// makes this land as a conflict against the file that actually changed.
func TestADeletedDirectoryWithOurChangesInsideConflicts(t *testing.T) {
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "cccccccc-1111-2222-3333-444444444444")})
	d := v.Mkdir(rootIno, "doomed")
	v.WriteFile(d, "keeper.bin", body(4096, 1))
	base := v.Publish(publishOpts).Superblock
	baseRaw := v.Raw()

	// Theirs removes the whole directory.
	v.SetBranch("dev")
	v.Unlink(v.Lookup(rootIno, "doomed"), "keeper.bin")
	v.Rmdir(rootIno, "doomed")
	theirs := v.Publish(publishOpts).Superblock

	// Ours edits the file inside it.
	v.Adopt(base, baseRaw)
	v.SetBranch("main")
	v.Write(v.Lookup(v.Lookup(rootIno, "doomed"), "keeper.bin"), body(4096, 2))
	ours := v.Publish(publishOpts).Superblock

	p := compute(t, inner, base, ours, theirs)
	if len(p.Conflicts) == 0 {
		t.Fatal("a deleted directory holding our modified file merged without a conflict")
	}
	c := p.Conflicts[0]
	if c.Kind != merge.ModifyDelete {
		t.Errorf("conflict kind = %s, want modify-delete", c.Kind)
	}
	// Against the FILE, not the directory: that is the path a human has to
	// look at.
	if c.Path != "/doomed/keeper.bin" {
		t.Errorf("conflict path = %s, want /doomed/keeper.bin", c.Path)
	}
}

// And its benign twin: the same deletion with nothing changed inside is
// simply honoured, or a merge could never delete a directory at all.
func TestADeletedDirectoryWithNoChangesInsideIsHonoured(t *testing.T) {
	inner, base, ours, theirs := forked(t, "dddddddd-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "elsewhere.bin", body(64, 9)) },
		func(v *testvol.Volume) { v.Rmdir(rootIno, "shared") })
	p := compute(t, inner, base, ours, theirs)
	for _, c := range p.Conflicts {
		t.Errorf("unexpected conflict deleting an untouched directory: %s", c)
	}
}

// forkedProperly builds the shape `pelfs branch` now produces: the child
// branch's first generation records where it was cut from and takes its
// own inode lineage. It returns the base's bytes too, because verifying
// the base against that record is the point.
func forkedProperly(t *testing.T, uuid string, onOurs, onTheirs func(v *testvol.Volume)) (
	pelicanobj.Store, *superblock.Superblock, []byte, *superblock.Superblock, *superblock.Superblock,
	ed25519.PrivateKey) {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	v.WriteFile(rootIno, "base.bin", body(4096, 1))
	base := v.Publish(publishOpts).Superblock
	baseRaw := v.Raw()

	// The fork generation, as the command writes it: same tree, its own
	// lineage, a record of the base.
	fork := *base
	fork.Generation = base.Generation + 1
	fork.PrevHash = superblock.Hash(baseRaw)
	fork.Fork = &superblock.Fork{
		Base: superblock.Hash(baseRaw), BaseGeneration: base.Generation,
		BaseNextInode: base.NextInode, From: "main", Lineage: 7,
	}
	fork.NextInode = superblock.FirstInode(7)
	fork.Signature = [64]byte{}
	if err := fork.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	forkRaw, err := fork.Encode()
	if err != nil {
		t.Fatal(err)
	}
	v.Adopt(&fork, forkRaw)
	v.SetBranch("dev")
	onTheirs(v)
	theirs := v.Publish(publishOpts).Superblock

	v.Adopt(base, baseRaw)
	v.SetBranch("main")
	onOurs(v)
	ours := v.Publish(publishOpts).Superblock
	return inner, base, baseRaw, ours, theirs, v.SigningKey()
}

// The payoff of the fork record: a branch with its own inode lineage
// creates files that cannot collide with the other side's, so a merge of
// two branches that both added files has nothing to renumber.
func TestAForkedLineageHasNoInodeCollisions(t *testing.T) {
	inner, base, baseRaw, ours, theirs, _ := forkedProperly(t, "eeeeeeee-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "ours-new.bin", body(4096, 50)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "theirs-new.bin", body(4096, 51)) })

	p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal != "" {
		t.Fatalf("refused: %s", p.Refusal)
	}
	if len(p.Collisions) != 0 {
		t.Fatalf("a forked lineage still collided: %+v", p.Collisions)
	}
	if !p.Mergeable() {
		t.Fatalf("not mergeable: %d conflicts, %d collisions", len(p.Conflicts), len(p.Collisions))
	}
	t.Logf("both sides added files, no collisions: %d ours, %d theirs", p.TookOurs, p.TookTheirs)
}

// And the sharpest edge, now blunted: a caller who names the WRONG base
// is told so, instead of getting a plausible tree that is nobody's
// intent.
func TestAWrongBaseIsRefusedWhenTheForkRecordSaysSo(t *testing.T) {
	inner, base, baseRaw, ours, theirs, _ := forkedProperly(t, "ffffffff-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "a.bin", body(64, 1)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "b.bin", body(64, 2)) })

	// The right base still works, which is what makes the refusal below
	// mean something.
	if p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	}); err != nil || p.Refusal != "" {
		t.Fatalf("the correct base was refused: %v %v", err, p)
	}

	// Bytes that are a real, signed generation of this volume — just not
	// the one the branch was cut from.
	wrongRaw, err := ours.Encode()
	if err != nil {
		t.Fatal(err)
	}
	p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: base, BaseRaw: wrongRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal == "" {
		t.Fatal("a base that is not the recorded fork point was accepted")
	}
	t.Logf("refused: %s", p.Refusal)
}

// Two branches cut from different points have no common fork to merge
// against, and their trees merging cleanly by accident would be the worst
// way to find that out.
func TestBranchesCutFromDifferentPointsAreRefused(t *testing.T) {
	inner, base, baseRaw, ours, theirs, _ := forkedProperly(t, "0a0a0a0a-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "a.bin", body(64, 1)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "b.bin", body(64, 2)) })

	// Give ours a fork record from somewhere else entirely.
	elsewhere := *ours
	elsewhere.Fork = &superblock.Fork{
		Base: [32]byte{0xde, 0xad}, BaseGeneration: 99, BaseNextInode: 1000, Lineage: 9,
	}
	p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: &elsewhere, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Refusal == "" {
		t.Fatal("two branches cut from different generations were merged anyway")
	}
}

// A merge that brings in content from a THIRD lineage must not report it
// as a collision.
//
// This is what the e2e caught. Merge dev into main, then branch again from
// the merged main: the new branch's tree holds dev's inodes, which are
// numerically far above the new fork's mark and present in both trees. The
// numeric cut called one inherited file a collision with itself.
//
// Two branches with different lineages cannot collide at all — each
// allocates only from its own range — so the check does not run.
func TestInheritedInodesFromAThirdLineageAreNotCollisions(t *testing.T) {
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "7b7b7b7b-1111-2222-3333-444444444444")})
	v.WriteFile(rootIno, "base.bin", body(4096, 1))
	first := v.Publish(publishOpts).Superblock
	firstRaw := v.Raw()

	// A branch in lineage 7 that adds a file, standing in for content a
	// previous merge brought into the trunk.
	imported := forkAt(t, v, first, firstRaw, 7, func(v *testvol.Volume) {
		v.WriteFile(rootIno, "from-lineage-7.bin", body(4096, 2))
	})

	// Now two branches cut from THAT, in their own lineages.
	ours := forkAt(t, v, imported, encode(t, imported), 11, func(v *testvol.Volume) {
		v.WriteFile(rootIno, "ours.bin", body(4096, 3))
	})
	theirs := forkAt(t, v, imported, encode(t, imported), 12, func(v *testvol.Volume) {
		v.WriteFile(rootIno, "theirs.bin", body(4096, 4))
	})

	p, err := merge.Compute(context.Background(), merge.Options{
		Inner: inner, Base: imported, BaseRaw: encode(t, imported),
		Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Collisions {
		t.Errorf("inherited inode %d reported as a collision: %s here, %s there",
			c.Inode, c.OursPath, c.TheirsPath)
	}
	if !p.Mergeable() {
		t.Fatalf("not mergeable: %d conflicts, %d collisions", len(p.Conflicts), len(p.Collisions))
	}
}

// forkAt publishes a fork generation in the named lineage and then one
// generation of work on it, returning the head.
func forkAt(t *testing.T, v *testvol.Volume, base *superblock.Superblock, baseRaw []byte,
	lineage uint32, work func(*testvol.Volume)) *superblock.Superblock {
	t.Helper()
	fork := *base
	fork.Generation = base.Generation + 1
	fork.PrevHash = superblock.Hash(baseRaw)
	fork.Fork = &superblock.Fork{
		Base: superblock.Hash(baseRaw), BaseGeneration: base.Generation,
		BaseNextInode: base.NextInode, Lineage: lineage,
	}
	fork.NextInode = superblock.FirstInode(lineage)
	fork.Signature = [64]byte{}
	if err := fork.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := fork.Encode()
	if err != nil {
		t.Fatal(err)
	}
	v.Adopt(&fork, raw)
	v.SetBranch(fmt.Sprintf("lineage-%d", lineage))
	work(v)
	return v.Publish(publishOpts).Superblock
}

func encode(t *testing.T, sb *superblock.Superblock) []byte {
	t.Helper()
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
