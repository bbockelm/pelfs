package main

import (
	"bytes"
	"flag"
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
	// A source that moved on: the warning the axis was built for, and now
	// a real kind rather than a stand-in.
	return fsck.Problem{Kind: fsck.KindGraftSourceChanged, Severity: fsck.SeverityWarning,
		Path: path, Detail: "source moved"}
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
	if !strings.Contains(out, "  warning: graft-source-changed: /ext/b: source moved\n") {
		t.Errorf("warning line missing or reshaped:\n%s", out)
	}
	if !strings.Contains(out, "generation 7") || !strings.Contains(out, "3 packs") {
		t.Errorf("the counts a script parses are gone:\n%s", out)
	}
}

// TestGraftClaimSaysWhatWasActuallyDone — the report line for the graft
// half of a check.
//
// The two depths differ by four orders of magnitude, and a report that
// called both of them "checked" would invite a reader to believe the
// expensive claim after paying for the cheap one. So each states exactly
// what it did, and the cheap one states what it cannot see.
func TestGraftClaimSaysWhatWasActuallyDone(t *testing.T) {
	head := graftClaim(&fsck.Report{
		GraftDepth: fsck.GraftHead, GraftObjectsChecked: 100000, GraftObjects: 100000,
	})
	if !strings.Contains(head, "100000 source objects") || !strings.Contains(head, "HEAD") {
		t.Errorf("the cheap claim does not say what it counted: %q", head)
	}
	if !strings.Contains(head, "same-length edit is invisible") {
		t.Errorf("the cheap claim does not say what it cannot see: %q", head)
	}
	if strings.Contains(head, "re-hashed") {
		t.Errorf("the cheap claim borrows the expensive mode's word: %q", head)
	}

	deep := graftClaim(&fsck.Report{
		GraftDepth: fsck.GraftDeep, GraftBlocksVerified: 10485760,
		GraftBytesVerified: 10 << 40, GraftObjectsChecked: 100000,
	})
	if !strings.Contains(deep, "re-hashed") || !strings.Contains(deep, "10995116277760 bytes") {
		t.Errorf("the deep claim does not say what it moved: %q", deep)
	}

	none := graftClaim(&fsck.Report{GraftDepth: fsck.GraftNone})
	if !strings.Contains(none, "no source was contacted") {
		t.Errorf("the none claim does not say it looked at nothing: %q", none)
	}
}

// TestTheGraftReportLinesAppearOnlyForAGraftedVolume. A volume with no
// grafts must print exactly what it printed before: this work is not a
// reason for every other volume's report to grow two lines.
func TestTheGraftReportLinesAppearOnlyForAGraftedVolume(t *testing.T) {
	var plain, grafted bytes.Buffer
	printFsckReport(&plain, 3, false, &fsck.Report{Packs: 2})
	printFsckReport(&grafted, 3, false, &fsck.Report{
		Packs: 2, Grafts: 1, GraftChunks: 4096, GraftObjects: 12,
		GraftDepth: fsck.GraftHead, GraftObjectsChecked: 12,
	})
	if strings.Contains(plain.String(), "grafts:") || strings.Contains(plain.String(), "source:") {
		t.Errorf("an ungrafted volume grew graft lines:\n%s", plain.String())
	}
	for _, want := range []string{"1 root", "4096 external chunks", "12 source objects", "source:"} {
		if !strings.Contains(grafted.String(), want) {
			t.Errorf("the grafted report does not contain %q:\n%s", want, grafted.String())
		}
	}
}

// TestDeepImpliesGraftDeepUnlessTold. `--deep` means the bytes, in
// whichever layer holds them: a 95%-graft volume answering `--deep` with
// "every chunk fetched and verified" while having read none of the bytes
// anyone stores there would be a lie by omission. Saying --grafts wins,
// because declining a 10 TB re-read over somebody else's network while
// still verifying this volume's own packs is a reasonable thing to want.
func TestDeepImpliesGraftDeepUnlessTold(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want fsck.GraftDepth
	}{
		{args: nil, want: fsck.GraftHead},
		{args: []string{"--deep"}, want: fsck.GraftDeep},
		{args: []string{"--deep", "--grafts=head"}, want: fsck.GraftHead},
		{args: []string{"--deep", "--grafts=none"}, want: fsck.GraftNone},
		{args: []string{"--grafts=deep"}, want: fsck.GraftDeep},
	} {
		fs := flag.NewFlagSet("fsck", flag.ContinueOnError)
		deep := fs.Bool("deep", false, "")
		grafts := fs.String("grafts", "head", "")
		if err := fs.Parse(tc.args); err != nil {
			t.Fatal(err)
		}
		depth, err := fsck.ParseGraftDepth(*grafts)
		if err != nil {
			t.Fatal(err)
		}
		if *deep && !flagWasSet(fs, "grafts") {
			depth = fsck.GraftDeep
		}
		if depth != tc.want {
			t.Errorf("%v gave graft depth %v, want %v", tc.args, depth, tc.want)
		}
	}
}

func TestParseGraftDepthRefusesNonsense(t *testing.T) {
	if _, err := fsck.ParseGraftDepth("shallow"); err == nil {
		t.Fatal("--grafts=shallow was accepted")
	}
}
