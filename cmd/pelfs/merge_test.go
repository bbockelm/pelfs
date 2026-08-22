package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/testvol"
)

// The whole arc through the verbs a user types: seal on main, branch dev,
// divergent seals on both, then ask what merging would take.
//
// It drives cmdMerge and cmdBranch directly rather than a built binary,
// which is how the branch tests work too: the commands ARE the surface
// under test, and the dispatch in main.go is one line.
func TestMergeReportsWhatBringingABranchBackWouldTake(t *testing.T) {
	b := newBranchVolume(t, 71)
	b.write(t, "shared.bin")
	b.seal(t)

	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}

	// Divergent work: each side adds its own file.
	b.onBranch(t, "dev")
	b.write(t, "theirs.bin")
	b.seal(t)
	b.onBranch(t, "main")
	b.write(t, "ours.bin")
	b.seal(t)

	out, code := captureMerge(t, "--state-dir", b.stateDir, b.prefix, "dev")
	if code != 0 {
		t.Fatalf("merge reported not mergeable (%d):\n%s", code, out)
	}
	for _, want := range []string{"merging dev into main", "mergeable with no conflicts"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	// The base was FOUND: nothing named it on the command line, and the
	// fork record is the only thing that could have.
	if strings.Contains(out, "--base") {
		t.Errorf("the base had to be named by hand:\n%s", out)
	}
	// And no collisions, because dev allocates from its own lineage. This
	// is the payoff of the fork record, seen from the command.
	if strings.Contains(out, "inode collisions") {
		t.Errorf("a properly forked branch collided:\n%s", out)
	}
	t.Logf("\n%s", out)
}

// A path both sides changed is reported as a conflict, and the command
// exits nonzero: a script that treated "cannot merge" as "merged" would
// lose work.
func TestMergeReportsAConflictAndExitsNonzero(t *testing.T) {
	b := newBranchVolume(t, 72)
	b.write(t, "contested.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}

	// b.want makes write() modify rather than create, which is what
	// "both sides changed the same file" needs.
	b.want["contested.bin"] = nil
	b.onBranch(t, "dev")
	b.write(t, "contested.bin")
	b.seal(t)
	b.onBranch(t, "main")
	b.write(t, "contested.bin")
	b.seal(t)

	out, code := captureMerge(t, "--state-dir", b.stateDir, b.prefix, "dev")
	if code == 0 {
		t.Fatalf("a both-modified conflict reported as mergeable:\n%s", out)
	}
	for _, want := range []string{"CONFLICT", "both-modified", "/contested.bin", "not mergeable"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	t.Logf("the report a user sees:\n%s", out)
}

// A branch that has not moved needs no merge, and saying so costs no
// walk.
func TestMergeSaysWhenItIsAFastForward(t *testing.T) {
	b := newBranchVolume(t, 73)
	b.write(t, "a.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.onBranch(t, "dev")
	b.write(t, "theirs.bin")
	b.seal(t)

	// main never moved past the fork.
	out, code := captureMerge(t, "--state-dir", b.stateDir, b.prefix, "dev")
	if code != 0 {
		t.Fatalf("a fast-forward exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "fast-forward") {
		t.Errorf("the report does not identify a fast-forward:\n%s", out)
	}
}

// Merging a branch into itself is a typo, not an operation.
func TestMergeRefusesABranchIntoItself(t *testing.T) {
	b := newBranchVolume(t, 74)
	b.write(t, "a.bin")
	b.seal(t)
	if _, code := captureMerge(t, "--state-dir", b.stateDir, "--into", "main", b.prefix, "main"); code == 0 {
		t.Fatal("merging main into main succeeded")
	}
}

// A base named by hand is verified against the fork record, because a
// hand-typed base is the one most likely to be wrong and the failure it
// causes is silent.
func TestMergeRefusesABaseThatIsNotTheForkPoint(t *testing.T) {
	b := newBranchVolume(t, 75)
	b.write(t, "a.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.onBranch(t, "dev")
	b.write(t, "theirs.bin")
	b.seal(t)
	b.onBranch(t, "main")
	b.write(t, "ours.bin")
	moved := b.seal(t).Superblock

	// Tag main's CURRENT head, which is not where dev was cut from.
	if _, code := captureLog(t, func() int {
		return cmdTag([]string{"--state-dir", b.stateDir, b.prefix, "not-the-fork"})
	}); code != 0 {
		t.Fatal("tag failed")
	}
	_ = moved

	out, code := captureMerge(t, "--state-dir", b.stateDir, "--base", "not-the-fork", b.prefix, "dev")
	if code == 0 {
		t.Fatalf("a base that is not the fork point was accepted:\n%s", out)
	}
}

// captureMerge runs cmdMerge with both its report and its log captured,
// since it writes to each.
func captureMerge(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var report bytes.Buffer
	log, code := captureLog(t, func() int {
		return runMergeInto(&report, args)
	})
	return report.String() + log, code
}

// runMergeInto is cmdMerge with the report redirected, which is the only
// thing a test needs that the command itself does not.
func runMergeInto(w *bytes.Buffer, args []string) int {
	prevStdout := mergeReportWriter
	mergeReportWriter = w
	defer func() { mergeReportWriter = prevStdout }()
	return cmdMerge(args)
}

var _ = context.Background
var _ = testvol.RootInode

// Applying a fast-forward: the branch being merged into has not moved, so
// the other side's tree is the answer whole.
//
// It publishes a generation rather than moving the ref, because two
// superblock fields are statements about the BRANCH and not about the
// bytes: Branch, which retention reads for its per-branch window, and
// Fork, which would otherwise have main claiming it was forked from main.
func TestMergeAppliesAFastForward(t *testing.T) {
	b := newBranchVolume(t, 76)
	b.write(t, "a.bin")
	mainHead := b.seal(t).Superblock
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.onBranch(t, "dev")
	devFile := b.write(t, "theirs.bin")
	devHead := b.seal(t).Superblock

	out, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", b.prefix, "dev")
	if code != 0 {
		t.Fatalf("apply exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "fast-forwarded main to dev") {
		t.Errorf("the report does not say what it did:\n%s", out)
	}

	after := mustFetch(t, b.rstore, "main")
	// The TREE is dev's.
	if after.RootCatalog != devHead.RootCatalog {
		t.Errorf("main's tree is %x, dev's is %x", after.RootCatalog[:4], devHead.RootCatalog[:4])
	}
	// The IDENTITY is main's. Both halves matter: a head on main claiming
	// it was sealed onto dev makes retention's per-branch window wrong.
	if after.Branch != "main" {
		t.Errorf("main's head says it was sealed onto %q", after.Branch)
	}
	if after.Fork != nil {
		t.Errorf("main adopted dev's fork record, so it now claims to be forked from main: %+v", after.Fork)
	}
	if after.Generation <= devHead.Generation {
		t.Errorf("generation %d does not follow dev's %d", after.Generation, devHead.Generation)
	}
	if after.NextInode != mainHead.NextInode {
		t.Errorf("the inode mark moved to %d; lineages are disjoint, so main keeps its own %d",
			after.NextInode, mainHead.NextInode)
	}
	// And the content is readable through the new head.
	if err := coldRead(t, b.inner, after, map[string][]byte{"theirs.bin": devFile}); err != nil {
		t.Fatalf("the fast-forwarded head does not serve dev's file: %v", err)
	}
}

// A diverged merge, carried out through the command: both sides' work
// ends up on main, and the generation verifies.
func TestMergeAppliesADivergedTree(t *testing.T) {
	b := newBranchVolume(t, 78)
	b.write(t, "shared.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.onBranch(t, "dev")
	theirFile := b.write(t, "theirs.bin")
	b.seal(t)
	b.onBranch(t, "main")
	ourFile := b.write(t, "ours.bin")
	b.seal(t)

	out, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", b.prefix, "dev")
	if code != 0 {
		t.Fatalf("apply exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "merged dev into main") {
		t.Errorf("the report does not say what it did:\n%s", out)
	}
	// Both sides' work, read cold from the published generation.
	after := mustFetch(t, b.rstore, "main")
	if err := coldRead(t, b.inner, after, map[string][]byte{
		"ours.bin": ourFile, "theirs.bin": theirFile,
	}); err != nil {
		t.Fatalf("the merged head does not serve both sides: %v", err)
	}
	if after.Branch != "main" {
		t.Errorf("the merged head says it was sealed onto %q", after.Branch)
	}
	t.Logf("\n%s", out)
}

// A merge that needs a decision is refused by --apply rather than
// resolved by taking a side, which would be a discard wearing a merge's
// name.
func TestMergeApplyRefusesADivergedTree(t *testing.T) {
	b := newBranchVolume(t, 77)
	b.write(t, "contested.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	// Both sides change the SAME file, which is the case no tree can
	// resolve on its own.
	b.want["contested.bin"] = nil
	b.onBranch(t, "dev")
	b.write(t, "contested.bin")
	b.seal(t)
	b.onBranch(t, "main")
	b.write(t, "contested.bin")
	moved := b.seal(t).Superblock

	out, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", b.prefix, "dev")
	if code == 0 {
		t.Fatalf("a conflicting merge was applied:\n%s", out)
	}
	if after := mustFetch(t, b.rstore, "main"); after.RootCatalog != moved.RootCatalog {
		t.Error("the refused merge moved main anyway")
	}
}

// --keep-both, through the command: a conflicted merge completes, both
// versions are in the tree, and the report named the second one before it
// was written.
func TestMergeKeepBothResolvesAConflict(t *testing.T) {
	b := newBranchVolume(t, 79)
	b.write(t, "contested.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.want["contested.bin"] = nil
	b.onBranch(t, "dev")
	theirBody := b.write(t, "contested.bin")
	b.seal(t)
	b.onBranch(t, "main")
	ourBody := b.write(t, "contested.bin")
	b.seal(t)

	// Refused without the flag, which is what makes the flag a choice.
	if _, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", b.prefix, "dev"); code == 0 {
		t.Fatal("a conflicted merge applied without --keep-both")
	}

	out, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", "--keep-both", b.prefix, "dev")
	if code != 0 {
		t.Fatalf("--keep-both exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "contested (from dev).bin") {
		t.Errorf("the report does not name the kept copy:\n%s", out)
	}
	after := mustFetch(t, b.rstore, "main")
	if err := coldRead(t, b.inner, after, map[string][]byte{
		"contested.bin":            ourBody,
		"contested (from dev).bin": theirBody,
	}); err != nil {
		t.Fatalf("the merged head does not serve both versions: %v", err)
	}
	t.Logf("\n%s", out)
}
