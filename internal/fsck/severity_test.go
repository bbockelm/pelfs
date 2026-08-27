package fsck

import (
	"sort"
	"strings"
	"testing"
)

// The severity axis, which is a contract: what an operator's script does
// with a finding follows from it. Three properties are pinned here.
//
//  1. Every Kind this package ships is damage. The axis was added for
//     findings that do not exist yet (a stale graft, an unverifiable
//     reference), and nothing already reported was quietly reclassified
//     into it — a check that used to fail a volume still fails it.
//  2. An unstated severity is damage. The zero value is SeverityError so
//     that the failure mode of a forgotten severity is a warning treated
//     as damage, never damage treated as a warning.
//  3. Damage leads the report and the exit status. A mixed report sorts
//     its errors first, and Damaged() is true regardless of how many
//     warnings sit beside them.

// allKinds is every Kind the package exports. A new kind added without a
// deliberate severity decision shows up here as a missing entry.
var allKinds = []string{
	KindMissingPack, KindMissingManifest, KindPackTrailer, KindPackSize,
	KindMissingCatalog, KindBadCatalog, KindMissingShard, KindBadShard,
	KindIdentity, KindDanglingDirent, KindTypeMismatch, KindTransition,
	KindCycle, KindShardRouting, KindChunkRefs, KindContent,
	KindMissingChunk, KindChunk,
}

func TestEveryShippedKindIsDamage(t *testing.T) {
	for _, kind := range allKinds {
		if got := SeverityOf(kind); got != SeverityError {
			t.Errorf("SeverityOf(%q) = %v, want error: every failure this package "+
				"reports is a generation contradicting itself, and reclassifying one "+
				"silently would stop a script failing on real damage", kind, got)
		}
	}
	// One warning kind ships, and it is named here so that a SECOND one
	// arriving without a decision still fails this test. The list above is
	// the damage half; this is the whole of the other half.
	want := map[string]struct{}{KindUnsigned: {}}
	if len(warningKinds) != len(want) {
		t.Fatalf("warningKinds has %d entries, want %d: a kind became a warning, which is a change to "+
			"what `pelfs fsck --strict` exits on. Say so in the CHANGELOG and name it here",
			len(warningKinds), len(want))
	}
	for k := range want {
		if SeverityOf(k) != SeverityWarning {
			t.Errorf("SeverityOf(%q) = %v, want warning", k, SeverityOf(k))
		}
	}
}

// TestUnsignedIsAWarningNotDamage pins the one reclassification: a volume
// created with `pelfs init --unsigned` is not broken, so a check of it must
// still say "generation is consistent" and exit 0 — otherwise every script
// that runs fsck on a throwaway volume goes red and the operator learns
// that fsck cries wolf.
func TestUnsignedIsAWarningNotDamage(t *testing.T) {
	rep := &Report{Problems: []Problem{
		{Kind: KindUnsigned, Severity: SeverityOf(KindUnsigned), Path: "/"},
	}}
	if rep.Damaged() {
		t.Fatal("an unsigned volume must not be reported as damaged: nothing about it contradicts itself")
	}
	if rep.Warnings() != 1 || rep.Errors() != 0 {
		t.Fatalf("want 1 warning and 0 errors, got %d/%d", rep.Warnings(), rep.Errors())
	}
}

func TestAnUnstatedSeverityIsDamage(t *testing.T) {
	var p Problem // as a decoder, or a forgetful caller, would leave it
	if p.Severity != SeverityError {
		t.Fatalf("zero-value Problem.Severity = %v, want error", p.Severity)
	}
	if got := SeverityOf("a-kind-from-a-later-version"); got != SeverityError {
		t.Fatalf("SeverityOf(unknown kind) = %v, want error", got)
	}
	if SeverityError.String() != "error" || SeverityWarning.String() != "warning" {
		t.Fatalf("severity words are %q/%q; they are what a script greps for",
			SeverityError, SeverityWarning)
	}
}

// kindTestWarning stands in for the first real warning kind (a stale
// graft), which lands with the feature that produces it. Registering it
// here exercises the plumbing that feature will use: problem() stamping a
// severity from the registry, and sortProblems ordering by it.
const kindTestWarning = "test-warning"

func withWarningKind(t *testing.T) {
	t.Helper()
	warningKinds[kindTestWarning] = struct{}{}
	t.Cleanup(func() { delete(warningKinds, kindTestWarning) })
}

func TestProblemStampsTheSeverityOfItsKind(t *testing.T) {
	withWarningKind(t)
	c := &checker{rep: &Report{}}
	c.problem(KindMissingChunk, "/a", "gone")
	c.problem(kindTestWarning, "/b", "moved")

	if got := c.rep.Problems[0].Severity; got != SeverityError {
		t.Errorf("missing-chunk severity = %v, want error", got)
	}
	if got := c.rep.Problems[1].Severity; got != SeverityWarning {
		t.Errorf("registered warning kind severity = %v, want warning", got)
	}
}

func TestDamageLeadsTheReport(t *testing.T) {
	withWarningKind(t)
	c := &checker{rep: &Report{}}
	// Deliberately out of order, and with the warning on the path that
	// sorts FIRST: severity has to outrank path, or the damage lands
	// under the advice in a long report.
	c.problem(kindTestWarning, "/aaa", "moved")
	c.problem(KindMissingChunk, "/zzz", "gone")
	c.problem(KindContent, "/mmm", "short")
	c.sortProblems()

	var got []string
	for _, p := range c.rep.Problems {
		got = append(got, p.Severity.String()+" "+p.Path)
	}
	want := "error /mmm, error /zzz, warning /aaa"
	if strings.Join(got, ", ") != want {
		t.Fatalf("report order = %q, want %q", strings.Join(got, ", "), want)
	}
	if !sort.SliceIsSorted(c.rep.Problems, func(i, j int) bool {
		return c.rep.Problems[i].Severity < c.rep.Problems[j].Severity
	}) {
		t.Fatal("problems are not grouped by severity")
	}
}

// The report predicates, over the four volumes the axis distinguishes.
func TestReportPredicates(t *testing.T) {
	err1 := Problem{Kind: KindMissingChunk, Severity: SeverityError, Path: "/a"}
	err2 := Problem{Kind: KindContent, Severity: SeverityError, Path: "/b"}
	warn1 := Problem{Kind: kindTestWarning, Severity: SeverityWarning, Path: "/c"}
	warn2 := Problem{Kind: kindTestWarning, Severity: SeverityWarning, Path: "/d"}

	for _, tc := range []struct {
		name             string
		problems         []Problem
		errors, warnings int
		damaged, clean   bool
	}{
		{name: "healthy", clean: true},
		{name: "warnings only", problems: []Problem{warn1, warn2}, warnings: 2},
		{name: "damage only", problems: []Problem{err1, err2}, errors: 2, damaged: true},
		{name: "mixed", problems: []Problem{err1, warn1, warn2}, errors: 1, warnings: 2, damaged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Problems: tc.problems}
			if got := r.Errors(); got != tc.errors {
				t.Errorf("Errors() = %d, want %d", got, tc.errors)
			}
			if got := r.Warnings(); got != tc.warnings {
				t.Errorf("Warnings() = %d, want %d", got, tc.warnings)
			}
			if got := r.Damaged(); got != tc.damaged {
				t.Errorf("Damaged() = %v, want %v", got, tc.damaged)
			}
			if got := r.Clean(); got != tc.clean {
				t.Errorf("Clean() = %v, want %v", got, tc.clean)
			}
		})
	}
}
