package merge_test

import (
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/merge"
	"github.com/bbockelm/pelfs/internal/refs"
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
