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
