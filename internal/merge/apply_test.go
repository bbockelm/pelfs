package merge_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/merge"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// The whole point, executed: two branches that changed different things
// become one tree holding both changes, and every file reads back.
//
// No content moves. Both sides' files are already chunked and in packs, so
// the source hands publish the chunkrefs it already has — a merge that
// downloaded anything would be re-deriving identities the generations
// already record.
func TestApplyMergesTwoBranchesIntoOneTree(t *testing.T) {
	ctx := context.Background()
	inner, base, baseRaw, ours, theirs, key := forkedProperly(t, "1b1b1b1b-1111-2222-3333-444444444444",
		func(v *testvol.Volume) {
			d := v.Mkdir(rootIno, "ours-dir")
			v.WriteFile(d, "ours-only.bin", body(4096, 60))
		},
		func(v *testvol.Volume) {
			d := v.Mkdir(rootIno, "theirs-dir")
			v.WriteFile(d, "theirs-only.bin", body(4096, 61))
		})

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture publishes ours onto main last, so main is ours.
	opts := merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	}
	plan, err := merge.Compute(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Mergeable() {
		t.Fatalf("not mergeable: %+v", plan)
	}

	res, err := merge.Apply(ctx, merge.ApplyOptions{
		Plan: plan, Base: base, Ours: ours, Theirs: theirs,
		Inner: inner, Refs: rstore, Branch: "main", SigningKey: key,
		CacheDir: t.TempDir(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	merged := res.Superblock
	if merged.Generation <= ours.Generation {
		t.Errorf("merged generation %d does not follow ours %d", merged.Generation, ours.Generation)
	}

	// BOTH sides' work is present, and readable.
	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: merged, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close() //nolint:errcheck
	for _, path := range []string{"/base.bin", "/ours-dir/ours-only.bin", "/theirs-dir/theirs-only.bin"} {
		n, err := fs.LookupPath(ctx, path)
		if err != nil {
			t.Fatalf("%s is missing from the merged tree: %v", path, err)
		}
		if n.Length == 0 {
			t.Errorf("%s is empty in the merged tree", path)
		}
	}

	// And the generation verifies, which is stronger than reading the
	// three paths a test happens to name: fsck walks the whole thing and
	// checks every chunkref resolves at the recorded length.
	rep, err := fsck.Check(ctx, fsck.Options{
		Inner: inner, SB: merged, CacheDir: t.TempDir(), Deep: true, Workers: 4,
	})
	if err != nil {
		t.Fatalf("fsck: %v", err)
	}
	if !rep.OK() {
		for _, p := range rep.Problems {
			t.Errorf("fsck: %s %s: %s", p.Kind, p.Path, p.Detail)
		}
		t.Fatal("the merged generation does not verify")
	}
	t.Logf("merged generation %d: %d files, %d chunks verified, %d packs",
		merged.Generation, rep.Files, rep.ChunksVerified, rep.Packs)
}

// A file changed on one side only comes across with THEIR content, even
// though it predates the fork and so carries the same inode on both
// sides. Routing by lineage alone would answer from ours and silently
// publish the wrong bytes under the right name.
func TestApplyTakesTheirChangeToASharedInode(t *testing.T) {
	ctx := context.Background()
	want := body(4096, 71)
	inner, base, baseRaw, ours, theirs, key := forkedProperly(t, "2c2c2c2c-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "ours-side.bin", body(4096, 70)) },
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), want) })

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := merge.Compute(ctx, merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.TookTheirs == 0 {
		t.Fatalf("the plan took nothing from theirs, so this test proves nothing: %+v", plan)
	}
	res, err := merge.Apply(ctx, merge.ApplyOptions{
		Plan: plan, Base: base, Ours: ours, Theirs: theirs,
		Inner: inner, Refs: rstore, Branch: "main", SigningKey: key,
		CacheDir: t.TempDir(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: res.Superblock, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close() //nolint:errcheck
	n, err := fs.LookupPath(ctx, "/base.bin")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := fs.Read(ctx, n.Inode, 0, got); err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("/base.bin differs at byte %d: the merge published ours' bytes under theirs' change", i)
		}
	}
	// Ours' own addition survived too.
	if _, err := fs.LookupPath(ctx, "/ours-side.bin"); err != nil {
		t.Errorf("ours' file is missing from the merged tree: %v", err)
	}
}

// Apply refuses a plan it was not given, or one that is not clean: the
// decision is the part a human has to see, and inventing an answer for a
// contested path is exactly what a merge must not do.
func TestApplyRefusesWhatItMustNotDecide(t *testing.T) {
	ctx := context.Background()
	inner, base, baseRaw, ours, theirs, key := forkedProperly(t, "3d3d3d3d-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 80)) },
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 81)) })
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := merge.Compute(ctx, merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mergeable() {
		t.Fatal("a both-modified fixture came out mergeable")
	}
	if _, err := merge.Apply(ctx, merge.ApplyOptions{
		Plan: plan, Base: base, Ours: ours, Theirs: theirs,
		Inner: inner, Refs: rstore, Branch: "main", SigningKey: key,
		CacheDir: t.TempDir(), SpoolDir: t.TempDir(),
	}); err == nil {
		t.Fatal("Apply carried out a plan with conflicts")
	}
	if _, err := merge.Apply(ctx, merge.ApplyOptions{Ours: ours, Theirs: theirs}); err == nil {
		t.Fatal("Apply ran with no plan at all")
	}
}

// After a merge, the branch must keep allocating inodes from ITS OWN
// lineage. The merged tree contains the other branch's inodes, which are
// in a different, higher range — and publish's fallback for a source with
// no counter is max-inode-seen plus one, which would put this branch's
// allocator inside the other branch's range.
//
// That is not a cosmetic drift. The other branch's next allocation is in
// that same neighbourhood, so the two would hand out adjacent numbers in
// one range and collide on the next file each created — the exact problem
// per-branch lineages exist to prevent, reintroduced by merging.
func TestAMergedBranchKeepsAllocatingFromItsOwnLineage(t *testing.T) {
	ctx := context.Background()
	inner, base, baseRaw, ours, theirs, key := forkedProperly(t, "4e4e4e4e-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.WriteFile(rootIno, "ours-new.bin", body(4096, 90)) },
		func(v *testvol.Volume) { v.WriteFile(rootIno, "theirs-new.bin", body(4096, 91)) })
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := merge.Compute(ctx, merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := merge.Apply(ctx, merge.ApplyOptions{
		Plan: plan, Base: base, Ours: ours, Theirs: theirs,
		Inner: inner, Refs: rstore, Branch: "main", SigningKey: key,
		CacheDir: t.TempDir(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	merged := res.Superblock
	ourLineage := superblock.LineageOf(ours.NextInode)
	if got := superblock.LineageOf(merged.NextInode); got != ourLineage {
		t.Fatalf("after merging, main allocates from lineage %d (inode %d); it must stay in its own %d. "+
			"theirs allocates from %d, so the two would collide on their next file",
			got, merged.NextInode, ourLineage, superblock.LineageOf(theirs.NextInode))
	}
	if merged.NextInode < ours.NextInode {
		t.Errorf("the allocator mark went backwards: %d, was %d", merged.NextInode, ours.NextInode)
	}
}

// Dropbox's answer: keep both versions rather than refuse. A conflicted
// merge completes and nothing is lost, at the cost of a second file.
//
// It is the right shape for a FILESYSTEM. There is nowhere to put conflict
// markers in a byte stream that anything would still be able to read, so
// the two versions have to be two files.
func TestApplyCanKeepBothSidesOfAConflict(t *testing.T) {
	ctx := context.Background()
	oursBody, theirsBody := body(4096, 100), body(4096, 101)
	inner, base, baseRaw, ours, theirs, key := forkedProperly(t, "5f5f5f5f-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), oursBody) },
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), theirsBody) })
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	opts := merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs,
		CacheDir: t.TempDir(), OnConflict: merge.KeepBoth, TheirBranch: "dev",
	}
	plan, err := merge.Compute(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	// The conflict became a resolution, and the plan says what it will be
	// called — so a dry run tells the user the filename that will appear.
	if len(plan.Conflicts) != 0 {
		t.Fatalf("KeepBoth still reported conflicts: %v", plan.Conflicts)
	}
	if len(plan.Kept) != 1 {
		t.Fatalf("%d kept copies, want 1: %+v", len(plan.Kept), plan.Kept)
	}
	if got, want := plan.Kept[0].As, "/base (from dev).bin"; got != want {
		t.Errorf("kept copy is %q, want %q", got, want)
	}
	if !plan.Mergeable() {
		t.Fatal("a plan that keeps both is not mergeable")
	}

	res, err := merge.Apply(ctx, merge.ApplyOptions{
		Plan: plan, Base: base, Ours: ours, Theirs: theirs, TheirBranch: "dev",
		Inner: inner, Refs: rstore, Branch: "main", SigningKey: key,
		CacheDir: t.TempDir(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: res.Superblock, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close() //nolint:errcheck

	read := func(path string) ([]byte, uint64) {
		n, err := fs.LookupPath(ctx, path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		buf := make([]byte, n.Length)
		if _, err := fs.Read(ctx, n.Inode, 0, buf); err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return buf, n.Inode
	}
	gotOurs, ourIno := read("/base.bin")
	gotTheirs, theirIno := read("/base (from dev).bin")

	// EACH NAME HOLDS ITS OWN SIDE'S BYTES. This is the assertion the
	// whole feature is: keeping both is worthless if both names resolve to
	// the same content.
	if !bytes.Equal(gotOurs, oursBody) {
		t.Error("/base.bin does not hold ours' version")
	}
	if !bytes.Equal(gotTheirs, theirsBody) {
		t.Error("the kept copy does not hold theirs' version")
	}
	// And they are two FILES, not one file with two names. A shared inode
	// would be a hard link, and a hard link cannot hold two contents — so
	// this is what makes the test above possible at all.
	if ourIno == theirIno {
		t.Fatalf("both names resolve to inode %d; a kept copy needs its own", ourIno)
	}
	if superblock.LineageOf(theirIno) != superblock.LineageOf(ours.NextInode) {
		t.Errorf("the kept copy took inode %d from lineage %d; a generation published on our branch "+
			"must allocate from ours (%d)",
			theirIno, superblock.LineageOf(theirIno), superblock.LineageOf(ours.NextInode))
	}

	rep, err := fsck.Check(ctx, fsck.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(), Deep: true, Workers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		for _, p := range rep.Problems {
			t.Errorf("fsck: %s %s: %s", p.Kind, p.Path, p.Detail)
		}
		t.Fatal("the merged generation does not verify")
	}
	t.Logf("kept both: %s and %s, %d chunks verified", "/base.bin", plan.Kept[0].As, rep.ChunksVerified)
}

// What KeepBoth cannot do, and says so rather than inventing an answer: a
// modify/delete has one version, so "both" would mean resurrecting a file
// one side deleted under a name nobody chose.
func TestKeepBothStillRefusesWhatItCannotDuplicate(t *testing.T) {
	ctx := context.Background()
	inner, base, baseRaw, ours, theirs, _ := forkedProperly(t, "6a6a6a6a-1111-2222-3333-444444444444",
		func(v *testvol.Volume) { v.Write(v.Lookup(rootIno, "base.bin"), body(4096, 110)) },
		func(v *testvol.Volume) { v.Unlink(rootIno, "base.bin") })
	plan, err := merge.Compute(ctx, merge.Options{
		Inner: inner, Base: base, BaseRaw: baseRaw, Ours: ours, Theirs: theirs,
		CacheDir: t.TempDir(), OnConflict: merge.KeepBoth, TheirBranch: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Kept) != 0 {
		t.Errorf("a modify/delete was kept as two files: %+v", plan.Kept)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0].Kind != merge.ModifyDelete {
		t.Fatalf("conflicts = %+v, want one modify-delete", plan.Conflicts)
	}
}
