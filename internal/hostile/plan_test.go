package hostile

// Tests for the PURE half of the exerciser: the vocabulary, the
// determinism the "print the seed" promise rests on, and the corpus
// round-trip that carries a finding forward. None of this touches a
// filesystem, so none of it is behind the `hostile` tag and all of it runs
// in the ordinary unit lane — which is the point. The corpus is the one
// artifact of a hostile run that outlives the container, and a corpus
// nothing parses in normal CI is a corpus that rots.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/entrycodec"
)

func TestGenerateIsDeterministic(t *testing.T) {
	opt := DefaultOptions()
	a := Generate(0xfeedface, opt)
	b := Generate(0xfeedface, opt)
	if a.String() != b.String() {
		t.Fatal("the same seed produced two different plans; a printed seed would be a lie")
	}
	c := Generate(0xfeedfad0, opt)
	if a.String() == c.String() {
		t.Fatal("two different seeds produced the same plan")
	}
}

func TestPlanRoundTripsThroughText(t *testing.T) {
	// Several seeds, because the ops that carry unusual fields (fill bytes,
	// modes, negative-looking offsets, max-length names, symlink targets
	// with slashes) do not all appear in any one plan.
	for _, seed := range []uint64{1, 2, 7, 99, 0xdeadbeef, 0x5eed} {
		plan := Generate(seed, DefaultOptions())
		back, err := ParsePlan(plan.String())
		if err != nil {
			t.Fatalf("seed %d: parse: %v", seed, err)
		}
		if back.Seed != plan.Seed {
			t.Errorf("seed %d: header lost the seed, got %d", seed, back.Seed)
		}
		if len(back.Ops) != len(plan.Ops) {
			t.Fatalf("seed %d: %d ops in, %d out", seed, len(plan.Ops), len(back.Ops))
		}
		for i := range plan.Ops {
			if plan.Ops[i] != back.Ops[i] {
				t.Fatalf("seed %d op %d:\n  in:  %#v\n  out: %#v", seed, i, plan.Ops[i], back.Ops[i])
			}
		}
		if back.String() != plan.String() {
			t.Fatalf("seed %d: text is not stable across a round trip", seed)
		}
	}
}

// The vocabulary is the whole reason this package exists, so it is pinned:
// every shape that bit during release week must be reachable, and a run
// long enough to be worth doing must contain all of them. A refactor that
// silently drops a shape is the failure this test exists to catch.
func TestEveryShapeIsReachable(t *testing.T) {
	seen := map[string]bool{}
	// Generate across many seeds rather than one long plan: a shape with a
	// small weight should not need a huge run to appear.
	for seed := uint64(0); seed < 40; seed++ {
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			if op.Note != "" {
				seen[op.Note] = true
			}
			seen["kind:"+op.Kind.String()] = true
		}
	}
	// One marker note per shape, taken from the shape's first op.
	wantNotes := []string{
		"compressible body, to be partly overwritten once a checkpoint has packed it",
		"partial overwrite of a PACKED compressible chunk: this is what makes a seal re-chunk",
		"identical zero bodies: many files, one chunk identity",
		"a run of zeros punched into incompressible bytes",
		"a run of zeros written across where the cut fell; no cut can land inside one",
		"symlink forest",
		"sparse train: extents out of order, with gaps",
		"whiteout cycle",
		"dangling and looping links",
		"truncate up and down mid-train",
		"attributes immediately after close",
		"hardlink web",
		"rename storm across directories",
		"thousands of entries, mutated during enumeration",
		"deep nesting and max-length names",
	}
	for _, n := range wantNotes {
		if !seen[n] {
			t.Errorf("shape never generated: %q", n)
		}
	}
	// And every primitive op kind must actually be emitted by something.
	for k := OpKind(0); k < numOpKinds; k++ {
		if !seen["kind:"+k.String()] {
			t.Errorf("op kind %s is in the vocabulary but no shape emits it", k)
		}
	}
}

// ------------------------------------------------------------ fill kinds

// The fill kinds are a CLAIM about what the storage layer will do with
// the bytes, so they are checked against the volume's own codec rather
// than against an idea of compressibility. This is the test that would
// have made the release-week rechunk bug findable: it says out loud that
// the old vocabulary's bodies are the one case where a chunk's stored
// length equals its logical length, which is why a row that copied one
// into the other looked right.
func TestFillKindsAreWhatTheyClaimAgainstTheRealCodec(t *testing.T) {
	const n = 64 << 10
	for _, tc := range []struct {
		kind    FillKind
		variant byte
		wantAlg uint8
		minRat  float64
	}{
		{FillRandom, 0x41, entrycodec.AlgNone, 0}, // stored verbatim: CLen == LLen
		{FillText, 0x41, entrycodec.AlgZstd, 2},
		{FillZero, 0, entrycodec.AlgZstd, 100},
	} {
		body := Body(tc.kind, tc.variant, 0, n)
		if int64(len(body)) != n {
			t.Fatalf("%s: %d bytes, want %d", tc.kind, len(body), n)
		}
		enc, alg, err := entrycodec.Encode(body, nil)
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.kind, err)
		}
		if alg != tc.wantAlg {
			t.Errorf("%s: the codec chose alg %d, want %d", tc.kind, alg, tc.wantAlg)
		}
		ratio := float64(n) / float64(len(enc))
		switch {
		case tc.minRat == 0:
			// The incompressible case, and the load-bearing half of it: a
			// stored entry the same size as its plaintext is exactly the
			// coincidence that hid the bug.
			if len(enc) != n {
				t.Errorf("%s: stored %d bytes for a %d-byte body; this kind must be the one "+
					"where CLen == LLen, or the vocabulary no longer has an incompressible case",
					tc.kind, len(enc), n)
			}
		case ratio < tc.minRat:
			t.Errorf("%s: compresses only %.2fx, want at least %.0fx -- this kind exists to make "+
				"CLen differ from LLen and it barely does", tc.kind, ratio, tc.minRat)
		default:
			t.Logf("%s: %d -> %d bytes (%.2fx), alg %d", tc.kind, n, len(enc), ratio, alg)
		}
		// And on an ENCRYPTED volume every kind's stored length differs
		// from its logical one, whatever the compressor did, because the
		// nonce and the GCM tag are always there. That is why the bug this
		// vocabulary chases was "never true on an encrypted volume".
		keyed, _, err := entrycodec.Encode(body, make([]byte, 32))
		if err != nil {
			t.Fatalf("%s: keyed encode: %v", tc.kind, err)
		}
		if int64(len(keyed)) == n {
			t.Errorf("%s: a sealed entry is the same length as its plaintext, which cannot be", tc.kind)
		}
	}
}

// Both trees must get the same bytes or the comparison means nothing, and
// the keying must be on the ABSOLUTE offset or an overlapping rewrite is
// undetectable. Both predate the fill kinds and both have to survive them.
func TestEveryFillIsDeterministicAndOffsetKeyed(t *testing.T) {
	for k := FillKind(0); k < numFillKinds; k++ {
		a := Body(k, 0x33, 4096, 8192)
		if !bytes.Equal(a, Body(k, 0x33, 4096, 8192)) {
			t.Errorf("%s: two calls, two answers", k)
		}
		// A window read out of a longer body must match the same window
		// generated on its own: a pwrite lays down bytes continuous with
		// whatever a create put around them.
		whole := Body(k, 0x33, 0, 20000)
		part := Body(k, 0x33, 7777, 3333)
		if !bytes.Equal(whole[7777:7777+3333], part) {
			t.Errorf("%s: a body is not a window onto the same stream; a partial overwrite "+
				"would write bytes that do not belong where they land", k)
		}
		if k == FillZero {
			continue // zeros have no variant, on purpose: that is the dedup case
		}
		if bytes.Equal(a, Body(k, 0x34, 4096, 8192)) {
			t.Errorf("%s: two variants produced identical bytes", k)
		}
		if bytes.Equal(a, Body(k, 0x33, 8192, 8192)) {
			t.Errorf("%s: the same variant at a different offset produced identical bytes, so "+
				"an overlapping rewrite would be invisible", k)
		}
	}
}

// The corpus is written in this syntax and some of it was written before
// the fill kinds existed. `fill=NN` must keep meaning exactly what it
// always meant, or every committed entry silently changes what it tests.
func TestTheByteLiteralFillSyntaxStillMeansWhatItDid(t *testing.T) {
	op, ok, err := ParseOp("create a/b.dat len=256 fill=41")
	if err != nil || !ok {
		t.Fatalf("parse: %v", err)
	}
	if op.FillKind != FillRandom || op.Fill != 0x41 {
		t.Fatalf("fill=41 parsed as kind %v variant %#x; want the incompressible byte literal 0x41",
			op.FillKind, op.Fill)
	}
	if got := op.String(); got != "create a/b.dat len=256 fill=41" {
		t.Errorf("re-rendered as %q; a corpus entry must round-trip byte-identical", got)
	}
}

func TestFillKindsRoundTripThroughText(t *testing.T) {
	for _, tc := range []struct {
		text string
		kind FillKind
		v    byte
	}{
		{"pwrite a off=0 len=8 fill=00", FillRandom, 0},
		{"pwrite a off=0 len=8 fill=ff", FillRandom, 0xff},
		{"pwrite a off=0 len=8 fill=zero", FillZero, 0},
		{"pwrite a off=0 len=8 fill=text:00", FillText, 0},
		{"pwrite a off=0 len=8 fill=text:9c", FillText, 0x9c},
	} {
		op, ok, err := ParseOp(tc.text)
		if err != nil || !ok {
			t.Fatalf("%q: %v", tc.text, err)
		}
		if op.FillKind != tc.kind || op.Fill != tc.v {
			t.Errorf("%q parsed as kind %v variant %#x, want %v/%#x", tc.text, op.FillKind, op.Fill, tc.kind, tc.v)
		}
		if got := op.String(); got != tc.text {
			t.Errorf("%q re-rendered as %q", tc.text, got)
		}
	}
	// `fill=text` with no variant is legible shorthand and must parse; it
	// renders back in the explicit form, which is the one the generator
	// writes.
	op, _, err := ParseOp("create a len=4 fill=text")
	if err != nil || op.FillKind != FillText || op.Fill != 0 {
		t.Errorf("bare fill=text: %v, kind %v", err, op.FillKind)
	}
}

func TestParseRejectsFillsThatCannotMean(t *testing.T) {
	for _, bad := range []string{
		"create a len=4 fill=zero:41", // zeros have no variant
		"create a len=4 fill=nosuch",
		"create a len=4 fill=nosuch:41",
		"create a len=4 fill=text:zz",
		"create a len=4 fill=1234", // not a byte
	} {
		if _, _, err := ParseOp(bad); err == nil {
			t.Errorf("accepted %q, want an error", bad)
		}
	}
}

// THE SHAPE THE RECHUNK BUG LIVED IN, asserted rather than hoped for. A
// compressible body is not enough on its own: what makes a seal take the
// re-chunk path is a piece covering only PART of a chunk that is already
// in a pack, so the sequence has to be create -> checkpoint -> partial
// overwrite, in that order, on the same path. A generator that emitted
// only fresh compressible writes would look like it had closed the blind
// spot and would not have.
func TestTheGeneratorOverwritesCompressibleContentAfterACheckpoint(t *testing.T) {
	found, seeds := 0, 0
	for seed := uint64(0); seed < 40; seed++ {
		type born struct {
			size    int64
			settles int
		}
		compressible := map[string]born{}
		settles := 0
		hit := false
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			switch op.Kind {
			case OpSettle:
				settles++
			case OpCreate:
				if op.FillKind != FillRandom && op.Len > 0 {
					compressible[op.Path] = born{op.Len, settles}
				} else {
					delete(compressible, op.Path)
				}
			case OpPwrite:
				b, ok := compressible[op.Path]
				// Strictly inside the file: a write that starts at 0 or
				// runs past the end replaces or appends, and neither
				// leaves a chunk straddling the rewrite.
				if ok && b.settles < settles && op.Off > 0 && op.Off+op.Len < b.size {
					hit = true
				}
			}
		}
		if hit {
			found++
		}
		seeds++
	}
	// Two thirds rather than all of them: a plan is bounded in OPS, not in
	// shape draws, and one big-directory draw can spend most of the budget
	// at once, so some seeds simply never draw this shape. What makes that
	// acceptable is that the deterministic guarantee lives elsewhere --
	// testdata/corpus/rechunk-compressible-rewrite.plan is replayed on
	// both frontends by every single run.
	if found*3 < seeds*2 {
		t.Errorf("only %d of %d seeds produced a partial overwrite of compressible content that a "+
			"checkpoint had already packed -- that sequence IS the re-chunk path, and without it "+
			"this vocabulary is compressible-looking rather than compressible", found, seeds)
	}
	t.Logf("%d of %d seeds re-chunk compressible content", found, seeds)
}

// Every kind must actually be emitted, or one of them is decoration.
func TestEveryFillKindIsGenerated(t *testing.T) {
	seen := map[FillKind]int{}
	for seed := uint64(0); seed < 20; seed++ {
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			// Bodies only. The big-directory shape mints thousands of
			// EMPTY files, and counting those would make the balance check
			// below true no matter what the vocabulary did.
			if (op.Kind == OpCreate || op.Kind == OpPwrite) && op.Len > 0 {
				seen[op.FillKind]++
			}
		}
	}
	for k := FillKind(0); k < numFillKinds; k++ {
		if seen[k] == 0 {
			t.Errorf("fill kind %s is in the vocabulary but no shape emits it", k)
		}
	}
	// And incompressible stays the plurality: it is what gives the packer
	// real work and what stops the whole tree deduping into one chunk.
	if seen[FillRandom] < seen[FillText]+seen[FillZero] {
		t.Errorf("compressible writes (%d) now outnumber incompressible ones (%d); the packer "+
			"should still be doing real work most of the time",
			seen[FillText]+seen[FillZero], seen[FillRandom])
	}
	t.Logf("fills generated: random=%d text=%d zero=%d", seen[FillRandom], seen[FillText], seen[FillZero])
}

// The one expensive body in the vocabulary is capped at one per plan, and
// the cap is what keeps it in the CI budget. LargeFileBytes=0 removes it
// entirely, which is the lever a budget squeeze reaches for first.
func TestTheChunkBoundaryFileIsOnePerPlanAndOptional(t *testing.T) {
	for seed := uint64(0); seed < 12; seed++ {
		n := 0
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			if op.Kind == OpCreate && op.Len >= 1<<20 {
				n++
			}
		}
		if n > 1 {
			t.Errorf("seed %d emitted %d files over 1 MiB; the budget allows one", seed, n)
		}
		opt := DefaultOptions()
		opt.LargeFileBytes = 0
		for _, op := range Generate(seed, opt).Ops {
			if op.Kind == OpCreate && op.Len >= 1<<20 {
				t.Errorf("seed %d emitted a %d-byte file with LargeFileBytes=0", seed, op.Len)
			}
		}
	}
}

// Containment, at the vocabulary level: no operation may name a path that
// leaves the sandbox. Symlink TARGETS are exempt and deliberately hostile
// (that is a case worth generating); everything the harness itself opens,
// creates, renames or deletes must be a plain relative path, so that the
// executor's os.Root has something it can refuse to be tricked by rather
// than a path it must sanitize.
func TestNoOperandEverLeavesTheSandbox(t *testing.T) {
	for seed := uint64(0); seed < 60; seed++ {
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			for i, p := range []string{op.Path, op.Path2} {
				if p == "" {
					continue
				}
				// Path2 of a symlink is the raw target: exempt by design.
				if op.Kind == OpSymlink && i == 1 {
					continue
				}
				if strings.HasPrefix(p, "/") {
					t.Fatalf("seed %d: %s names an absolute path %q", seed, op.Kind, p)
				}
				for _, seg := range strings.Split(p, "/") {
					if seg == ".." {
						t.Fatalf("seed %d: %s names %q, which climbs out", seed, op.Kind, p)
					}
				}
			}
		}
	}
}

// And the hostile targets ARE generated: a plan that never aims a symlink
// out of the tree is not exercising the thing that broke.
func TestHostileSymlinkTargetsAreGenerated(t *testing.T) {
	var absolute, climbing, dangling, loop bool
	for seed := uint64(0); seed < 40; seed++ {
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			if op.Kind != OpSymlink {
				continue
			}
			switch {
			case strings.HasPrefix(op.Path2, "/"):
				absolute = true
			case strings.HasPrefix(op.Path2, "../"):
				climbing = true
			case op.Path2 == "no-such-target":
				dangling = true
			case op.Path2 == "loop_a" || op.Path2 == "loop_b" || op.Path2 == "self":
				loop = true
			}
		}
	}
	if !absolute || !climbing || !dangling || !loop {
		t.Errorf("missing hostile link targets: absolute=%v climbing=%v dangling=%v loop=%v",
			absolute, climbing, dangling, loop)
	}
}

func TestNamesReachTheLinuxComponentLimit(t *testing.T) {
	longest := 0
	for seed := uint64(0); seed < 30; seed++ {
		for _, op := range Generate(seed, DefaultOptions()).Ops {
			for _, seg := range strings.Split(op.Path, "/") {
				if len(seg) > longest {
					longest = len(seg)
				}
			}
			if len(op.Path) > 4000 {
				t.Fatalf("seed %d: path of %d bytes exceeds what a filesystem must accept", seed, len(op.Path))
			}
		}
	}
	if longest != 255 {
		t.Errorf("longest generated component is %d bytes; the boundary worth testing is 255", longest)
	}
}

func TestOptionsBoundThePlan(t *testing.T) {
	opt := Options{Ops: 40, MaxNameLen: 16, MaxDepth: 3, BigDirEntries: 5}
	plan := Generate(4242, opt)
	if len(plan.Ops) < opt.Ops {
		t.Fatalf("asked for %d ops, got %d", opt.Ops, len(plan.Ops))
	}
	// Shapes are emitted whole, so an overshoot is expected -- but a large
	// one means a shape is unbounded, which would blow a CI budget.
	if len(plan.Ops) > opt.Ops*3 {
		t.Errorf("asked for %d ops, got %d: a shape is not respecting the budget", opt.Ops, len(plan.Ops))
	}
	// MaxNameLen governs the deliberately-long component, not the fixed
	// legible names the other shapes use; what must hold universally is
	// the filesystem limit itself.
	for _, op := range plan.Ops {
		for _, seg := range strings.Split(op.Path, "/") {
			if len(seg) > 255 {
				t.Errorf("component of %d bytes in %q exceeds the Linux limit", len(seg), op.Path)
			}
		}
	}
}

func TestParseRejectsWhatItShould(t *testing.T) {
	for _, bad := range []string{
		"nosuchop a/b",
		"unlink /etc/passwd",
		"unlink ../../escape",
		"rename a/b -> ../../elsewhere",
		"pwrite a/b off=notanumber len=1",
		"pwrite a/b wat=1",
		"unlink a/b extra-operand",
		"rename a/b ->",
	} {
		if _, _, err := ParseOp(bad); err == nil {
			t.Errorf("accepted %q, want an error", bad)
		}
	}
	for _, skip := range []string{"", "   ", "# a comment"} {
		op, ok, err := ParseOp(skip)
		if err != nil || ok {
			t.Errorf("ParseOp(%q) = %v, %v, %v; want skipped", skip, op, ok, err)
		}
	}
}

func TestSymlinkTargetsSurviveParsing(t *testing.T) {
	// The parser must NOT sanitize a link target -- these are the cases
	// the exerciser exists to generate.
	for _, tgt := range []string{"/etc/shadow", "../../../../etc/passwd", "no-such-target", "self"} {
		op, ok, err := ParseOp("symlink d/l -> " + tgt)
		if err != nil || !ok {
			t.Fatalf("symlink target %q: %v", tgt, err)
		}
		if op.Path2 != tgt {
			t.Errorf("target %q parsed as %q", tgt, op.Path2)
		}
	}
}

// The regression corpus: every sequence that ever found a bug, replayed by
// every run forever. This test does not RUN them (that needs a mount and a
// container); it holds them to being parseable and non-empty, so a corpus
// entry cannot rot into a file the executor silently skips.
func TestTheRegressionCorpusParses(t *testing.T) {
	dir := filepath.Join("testdata", "corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v (the corpus is the point; it must exist)", err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".plan") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		plan, err := ParsePlan(string(body))
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		if len(plan.Ops) == 0 {
			t.Errorf("%s: no ops; an empty corpus entry replays nothing", e.Name())
		}
		// A corpus entry must end in a comparison, or replaying it checks
		// nothing. The executor also compares at the end of every run, but
		// an entry that says so is an entry whose intent is legible.
		if plan.Ops[len(plan.Ops)-1].Kind != OpCompare {
			t.Errorf("%s: does not end in `compare`", e.Name())
		}
		n++
	}
	if n == 0 {
		t.Fatal("no .plan files in the corpus")
	}
	t.Logf("%d corpus entries parse", n)
}

func TestSortedNamesIsRmOrder(t *testing.T) {
	// The reported bug depended entirely on rm(1) walking sorted, so the
	// target sorted ahead of the links that named it. If this stops being
	// a sort, the symlink-forest shape stops reproducing anything.
	in := []string{"lib_eventlog_rotation_9.run", "aaa_base.run", "lib_eventlog_rotation_1.run"}
	got := SortedNames(in)
	if got[0] != "aaa_base.run" {
		t.Fatalf("the shared target must sort first, got %q", got[0])
	}
	if in[0] != "lib_eventlog_rotation_9.run" {
		t.Error("SortedNames mutated its argument")
	}
}
