package repack_test

// WHAT A SIBLING BRANCH DOES TO THE STALE-PLAN GUARD.
//
// A repack is two phases with a gap between them: Compute measures the
// volume, Execute rewrites and flips. The guard across that gap is
// "is the branch head still the generation this plan was computed
// against" — because if it moved, the plan's liveness numbers describe a
// volume that no longer exists, and a pack it calls dead may be one the
// NEW head references.
//
// That guard used to ask its question of the LIVE SET, by generation
// number and volume id. On a one-branch volume that was sound: a matching
// number could only be the branch itself. With two it is not, because
// generation numbers count steps along a lineage and both children of
// generation N seal N+1 — so a sibling sitting at the same number answered
// for a head that had moved, the guard passed, and the repack went on to
// condemn packs measured before the new head existed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// THE GUARD, WITH A SIBLING STANDING WHERE THE HEAD USED TO BE.
//
// dev is one generation AHEAD of main when the plan is computed, so the
// live set already holds a document at N+1. main then seals N+1 of its own
// — the head has MOVED, the plan is stale, and the sibling is sitting on
// exactly the number the check is about to look for. Execute must refuse.
//
// Nothing about the refusal is optional: the alternative is a repack that
// rewrites gigabytes against measurements taken before the generation it
// is about to overwrite, and the flip's own CAS guard cannot save it —
// Execute re-fetches the head and flips against THAT etag, so the write
// succeeds and the damage is in what the new generation stopped naming.
//
// Run against the old by-the-numbers check this test does not refuse
// (checked; the mutation is in the branch commit message).
func TestAStalePlanIsRefusedEvenWhenASiblingSharesTheGeneration(t *testing.T) {
	ctx := context.Background()
	inner, v, head, _ := rewrittenVolume(t, "6b1e7c4a-0000-4000-8000-000000000001")
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// A second branch at the same generation, created the way `pelfs
	// branch` creates one: the verified head's bytes under a second name.
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(ctx, "dev", f.Raw, ""); err != nil {
		t.Fatalf("create branch dev: %v", err)
	}
	// dev seals ONE generation of its own, so it sits at N+1 while main is
	// still at N. That is the arrangement the by-the-numbers check cannot
	// survive: when main later reaches N+1 too, the sibling already in the
	// live set answers for it.
	seatOn(t, v, rs, "dev")
	v.Write(v.Lookup(rootIno, "f1.bin"), pseudorandom(2<<20, 777))
	sibling := v.Publish(publishOpts).Superblock
	if sibling.Generation != head.Generation+1 {
		t.Fatalf("fixture: dev is at generation %d, want %d", sibling.Generation, head.Generation+1)
	}

	// The plan is computed against BOTH heads, which is what a repack on a
	// multi-branch volume must do (cmd/pelfs liveGenerations).
	live := []*superblock.Superblock{head, sibling}

	// ...and then main moves, to the number the sibling already holds.
	seatOn(t, v, rs, "main")
	v.Write(v.Lookup(rootIno, "f0.bin"), pseudorandom(2<<20, 999))
	moved := v.Publish(publishOpts).Superblock
	if moved.Generation != sibling.Generation {
		t.Fatalf("fixture: main reached generation %d and the sibling is at %d; they have to collide "+
			"for this test to be about anything", moved.Generation, sibling.Generation)
	}

	_, err = repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: live, Head: head, CacheDir: t.TempDir(),
			Workers: 4, Now: time.Now().Add(400 * time.Hour),
		},
		Refs: rs, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("a repack executed a plan computed against a head that had moved, because a SIBLING " +
			"branch happened to sit at the same generation number; the packs it condemned were measured " +
			"against a volume that no longer existed")
	}
	if !errors.Is(err, refs.ErrStaleFlip) {
		t.Fatalf("the refusal is not the stale-plan one: %v", err)
	}

	// And the branch really is untouched: the refusal came before anything
	// was flipped.
	after, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if after.Superblock.Generation != moved.Generation {
		t.Fatalf("the refused repack moved the branch anyway (generation %d, want %d)",
			after.Superblock.Generation, moved.Generation)
	}
}

// The other half: a plan that is NOT stale must still execute, or the
// guard above would be indistinguishable from a repack that never works
// on a volume with two branches.
func TestAFreshPlanStillExecutesWithASiblingPresent(t *testing.T) {
	ctx := context.Background()
	inner, v, head, want := rewrittenVolume(t, "6b1e7c4a-0000-4000-8000-000000000002")
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(ctx, "dev", f.Raw, ""); err != nil {
		t.Fatalf("create branch dev: %v", err)
	}

	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head, f.Superblock}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(400 * time.Hour),
		},
		Refs: rs, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("a repack with a sibling branch present refused a plan that was not stale: %v", err)
	}
	if len(res.CondemnedPacks) == 0 {
		t.Fatal("the repack condemned nothing, so it cannot be said to have executed")
	}
	after, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	readsBack(t, inner, after.Superblock, want, "after a repack beside a sibling branch")
	// The sibling still reads its own generation, which is the same
	// generation main grew from: the repack carried what it referenced.
	readsBack(t, inner, mustFetchSB(t, rs, "dev"), want, "the untouched sibling")
}

// seatOn re-seats the volume on a branch's head and points its next
// publish at that ref. Both halves are needed: publishing onto a branch
// means building on its head AND flipping its name.
func seatOn(t *testing.T, v *testvol.Volume, rs *refs.Store, branch string) {
	t.Helper()
	f, err := rs.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	v.SetBranch(branch)
	v.Adopt(f.Superblock, f.Raw)
}

func mustFetchSB(t *testing.T, rs *refs.Store, branch string) *superblock.Superblock {
	t.Helper()
	f, err := rs.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	return f.Superblock
}

// A REPACKED HEAD SAYS WHICH BRANCH IT WAS PUBLISHED ONTO.
//
// A repack builds its generation from a COPY of the parent, so every field
// it does not overwrite it inherits — and `pelfs branch dev` creates a
// branch by writing main's head verbatim under a second name, which makes
// "the parent says main" the ordinary state of a young branch rather than
// a corner case. A repack that inherited it would leave dev's head
// claiming to be main's, and would go on claiming it for as long as
// nothing else sealed on dev.
//
// It costs nothing today: a repack writes no superblock BACKUP, so nothing
// it produces is ever scavenged by the retain-window scan, and the
// generation it grew from is covered by the condemned-ledger floor instead
// (retention.retainedSet). What it costs tomorrow is every reader that
// takes a head's own statement about its branch at face value — starting
// with the seal after this one, which is the document the window scan DOES
// read.
func TestARepackedHeadCarriesTheBranchItPublishedOnto(t *testing.T) {
	ctx := context.Background()
	inner, v, head, want := rewrittenVolume(t, "6b1e7c4a-0000-4000-8000-000000000003")
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if f.Superblock.Branch != "main" {
		t.Fatalf("fixture: the volume's head was sealed onto %q", f.Superblock.Branch)
	}
	// dev is main's head under a second name — so its head says "main", and
	// truthfully: main is what sealed those bytes.
	if err := rs.Flip(ctx, "dev", f.Raw, ""); err != nil {
		t.Fatalf("create branch dev: %v", err)
	}

	// The first writer dev ever has is a repack.
	if _, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head, f.Superblock}, Head: f.Superblock,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(400 * time.Hour),
		},
		Refs: rs, Branch: "dev", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("repack onto dev: %v", err)
	}

	after := mustFetchSB(t, rs, "dev")
	if after.Branch != "dev" {
		t.Errorf("the head at refs/dev was published by a repack onto dev and says it belongs to %q; a head "+
			"that names a branch it was not published onto is a statement every later reader has to "+
			"disbelieve", after.Branch)
	}
	// And it is still the same volume, tree for tree: the stamp is not an
	// excuse to have rewritten anything else.
	readsBack(t, inner, after, want, "after a repack that was dev's first writer")
	if main := mustFetchSB(t, rs, "main"); main.Branch != "main" {
		t.Errorf("the untouched branch main now says %q", main.Branch)
	}
}
