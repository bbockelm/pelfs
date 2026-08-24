package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/fsck"
)

// `pelfs fsck`'s exit status and last line, which together are the
// contract every script that runs it depends on. What is pinned here:
//
//   - A healthy volume exits 0 and says so, as it always did.
//   - Damage exits 1, as it always did, and keeps doing so however many
//     warnings sit beside it — damage dominates.
//   - Warnings ALONE exit 0. A warning is not damage, and every existing
//     caller (scripts/e2e-test.sh, scripts/unprivileged-test.sh,
//     scripts/crash-recovery-docker.sh, scripts/bench-untar-nfs-docker.sh,
//     the hostile harness's phases D and E) reads a nonzero status as
//     "fsck rejected the generation this run published". A healthy volume
//     must never produce that.
//   - --strict is how an operator opts INTO failing on a warning, and it
//     fails with 1: 2 is pelfs's usage status (exitErr), so a code of its
//     own would have to be 3+ and would make a typo'd flag look like a
//     finding.
//   - No run loses a finding to the summary line: "consistent" never
//     appears without the warnings that came with it.

func warning(path string) fsck.Problem {
	// Kind is a stand-in until the first real warning kind lands with the
	// feature that produces it; the exit contract is driven by Severity.
	return fsck.Problem{Kind: "stale-graft", Severity: fsck.SeverityWarning, Path: path, Detail: "source moved"}
}

func damage(path string) fsck.Problem {
	return fsck.Problem{Kind: fsck.KindMissingChunk, Severity: fsck.SeverityError, Path: path, Detail: "resolves in no listed pack"}
}

func TestFsckExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name     string
		problems []fsck.Problem
		strict   bool
		want     int
	}{
		{name: "healthy", want: 0},
		{name: "healthy, strict", strict: true, want: 0},
		{name: "warnings only", problems: []fsck.Problem{warning("/ext/a"), warning("/ext/b")}, want: 0},
		{name: "warnings only, strict", problems: []fsck.Problem{warning("/ext/a")}, strict: true, want: 1},
		{name: "damage", problems: []fsck.Problem{damage("/a")}, want: 1},
		{name: "damage, strict", problems: []fsck.Problem{damage("/a")}, strict: true, want: 1},
		{name: "mixed: damage dominates", problems: []fsck.Problem{damage("/a"), warning("/ext/b")}, want: 1},
		{name: "mixed, strict", problems: []fsck.Problem{damage("/a"), warning("/ext/b")}, strict: true, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := &fsck.Report{Problems: tc.problems}
			if got := fsckExit(rep, tc.strict); got != tc.want {
				t.Fatalf("fsckExit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFsckSummaryNeverHidesAWarning(t *testing.T) {
	for _, tc := range []struct {
		name     string
		problems []fsck.Problem
		strict   bool
		wants    []string
	}{
		{
			name:  "healthy",
			wants: []string{"generation is consistent"},
		},
		{
			// The phrase stays — it is what the e2e and hostile greps
			// match, and on a warning-only volume it is true — but it
			// never stands alone, so no reader takes it for "nothing to
			// see".
			name:     "warnings only",
			problems: []fsck.Problem{warning("/ext/a"), warning("/ext/b")},
			wants:    []string{"generation is consistent", "2 warnings", "not damage"},
		},
		{
			name:     "warnings only, strict",
			problems: []fsck.Problem{warning("/ext/a")},
			strict:   true,
			wants:    []string{"generation is consistent", "1 warning", "--strict"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fsckSummary(&fsck.Report{Problems: tc.problems}, tc.strict)
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("summary %q does not contain %q", got, want)
				}
			}
		})
	}
}

func TestFsckReportLeadsEveryFindingWithItsSeverity(t *testing.T) {
	var buf bytes.Buffer
	rep := &fsck.Report{
		Packs:    3,
		Problems: []fsck.Problem{damage("/a"), warning("/ext/b")},
	}
	printFsckReport(&buf, 7, false, rep)
	out := buf.String()

	// A grep that lifts one line out of the report still knows whether it
	// is damage, and the kind/path/detail chain a reader already greps for
	// is intact behind the new word.
	if !strings.Contains(out, "  error: missing-chunk: /a: resolves in no listed pack\n") {
		t.Errorf("damage line missing or reshaped:\n%s", out)
	}
	if !strings.Contains(out, "  warning: stale-graft: /ext/b: source moved\n") {
		t.Errorf("warning line missing or reshaped:\n%s", out)
	}
	if !strings.Contains(out, "generation 7") || !strings.Contains(out, "3 packs") {
		t.Errorf("the counts a script parses are gone:\n%s", out)
	}
}
