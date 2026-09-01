package fsck

import (
	"sort"
	"strings"
	"testing"
)

// The severity axis, which is a contract: what an operator's script does
// with a finding follows from it. Four properties are pinned here.
//
//  1. THE ASSIGNMENT ITSELF, kind by kind, with the reason each one has
//     the severity it has written beside it. This is the table the graft
//     work exists to get right; the plumbing under it is checked in
//     graft_test.go.
//  2. Nothing that was already reported got reclassified. Every kind that
//     shipped before grafts is still damage — a check that used to fail a
//     volume still fails it.
//  3. An unstated severity is damage. The zero value is SeverityError so
//     that the failure mode of a forgotten severity is a warning treated
//     as damage, never damage treated as a warning.
//  4. Damage leads the report and the exit status. A mixed report sorts
//     its errors first, and Damaged() is true regardless of how many
//     warnings sit beside them.

// preGraftKinds is every Kind that shipped before fsck knew about grafts.
var preGraftKinds = []string{
	KindMissingPack, KindMissingManifest, KindPackTrailer, KindPackSize,
	KindMissingCatalog, KindBadCatalog, KindMissingShard, KindBadShard,
	KindIdentity, KindDanglingDirent, KindTypeMismatch, KindTransition,
	KindCycle, KindShardRouting, KindChunkRefs, KindContent,
	KindMissingChunk, KindChunk,
}

// severityMatrix is the whole of the axis, stated once. A kind absent
// from it fails the completeness check below, which is how a future kind
// gets a deliberate severity decision rather than a default one.
var severityMatrix = []struct {
	kind string
	want Severity
	why  string
}{
	// The volume's own objects. Damage means: something this generation
	// states about itself is not true of the objects behind it, a reader
	// gets an error where data was promised, and only this volume's
	// operator can fix it.
	{KindGraftIndex, SeverityError,
		"the index is one of THIS volume's objects, hash-named under its own prefix and " +
			"covered by the signature; without it no reader can locate a single grafted byte"},
	{KindGraftEntry, SeverityError,
		"the signed entry contradicts the hash-named object it names, or names a " +
			"configuration (an encrypted volume) that no reader will serve at all"},
	{KindGraftBlock, SeverityError,
		"the catalog and the index disagree about a block, so the generation cannot be " +
			"turned into the file it describes — a self-contradiction, like a chunkref " +
			"whose length disagrees with its pack"},

	// A third party's objects. Not damage: pelfs never held those bytes,
	// the fix is `pelfs graft --refresh` rather than a restore, and an
	// fsck that failed here would go red the first time an upstream
	// maintainer republished a file, which is the event a graft is FOR.
	{KindGraftSourceChanged, SeverityWarning,
		"an upstream republish is the ordinary life of a graft source; calling it damage " +
			"would fail a healthy volume's cron on somebody else's routine maintenance"},
	{KindGraftSourceMissing, SeverityWarning,
		"still not this volume's damage: pelfs never stored those bytes, and fsck cannot " +
			"tell a deletion from an expired token, a maintenance window or a partition " +
			"at this reader's position — an outage must not be reported as corruption"},
	{KindGraftUnchecked, SeverityWarning,
		"\"I could not ask\" is not \"I asked and it was wrong\"; it is a fact about the " +
			"check, not about the generation, and it must not be silence either"},

	// Facts worth knowing that no reader resolves through.
	{KindGraftUnreferenced, SeverityWarning,
		"a graft nothing reads costs a leaked index object and a dependency on a third " +
			"party, and no byte"},
	{KindGraftMetadata, SeverityWarning,
		"Path, a duplicate path and the recorded block policy are read by `--list` and by " +
			"a future --refresh; nothing routes by them, so they cannot make a read wrong"},

	// Not a graft, and the only warning that is about this volume: the
	// volume is exactly as its owner made it and every invariant holds, so
	// nothing contradicts itself -- but a person who inherits it must not
	// have to read a superblock to learn it has no integrity root.
	{KindUnsigned, SeverityWarning,
		"an unsigned generation is not damaged; it is unauthenticated, which is a fact " +
			"about how it was made rather than a fact about whether it is intact"},
}

func TestTheSeverityMatrix(t *testing.T) {
	for _, tc := range severityMatrix {
		if got := SeverityOf(tc.kind); got != tc.want {
			t.Errorf("SeverityOf(%q) = %v, want %v — %s", tc.kind, got, tc.want, tc.why)
		}
	}
	// Completeness, in both directions: every warning kind is in the
	// matrix, and every kind in the matrix that is not a warning is
	// registered nowhere.
	inMatrix := make(map[string]bool, len(severityMatrix))
	for _, tc := range severityMatrix {
		inMatrix[tc.kind] = true
	}
	for kind := range warningKinds {
		if !inMatrix[kind] {
			t.Errorf("%q is a warning and is not in severityMatrix: a kind whose severity is "+
				"not argued for in one place is a kind two callers will disagree about", kind)
		}
	}
}

func TestEveryPreGraftKindIsStillDamage(t *testing.T) {
	for _, kind := range preGraftKinds {
		if got := SeverityOf(kind); got != SeverityError {
			t.Errorf("SeverityOf(%q) = %v, want error: this kind failed a volume before "+
				"grafts existed, and reclassifying one silently would stop a script "+
				"failing on real damage", kind, got)
		}
	}
	// The warning set is exactly the graft findings that are about a
	// third party or about reportage. If something else appears here, the
	// line this package draws has moved and the argument in
	// internal/fsck/graft.go no longer describes the code.
	want := map[string]bool{
		KindUnsigned:           true,
		KindGraftSourceMissing: true, KindGraftSourceChanged: true,
		KindGraftUnchecked: true, KindGraftUnreferenced: true, KindGraftMetadata: true,
	}
	if len(warningKinds) != len(want) {
		t.Errorf("warningKinds holds %d entries, want %d", len(warningKinds), len(want))
	}
	for kind := range warningKinds {
		if !want[kind] {
			t.Errorf("%q became a warning: that is a change to what `pelfs fsck` exits on, "+
				"so say it in the CHANGELOG and argue it in severityMatrix", kind)
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

// kindTestWarning was a stand-in for the first real warning kind while
// there were none. It is now a real one — a source that moved is the
// warning the axis was built for — and the plumbing tests below use it
// directly: problem() stamping a severity from the registry, and
// sortProblems ordering by it.
const kindTestWarning = KindGraftSourceChanged

func TestProblemStampsTheSeverityOfItsKind(t *testing.T) {
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
