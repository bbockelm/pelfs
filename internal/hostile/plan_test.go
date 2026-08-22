package hostile

// Tests for the PURE half of the exerciser: the vocabulary, the
// determinism the "print the seed" promise rests on, and the corpus
// round-trip that carries a finding forward. None of this touches a
// filesystem, so none of it is behind the `hostile` tag and all of it runs
// in the ordinary unit lane — which is the point. The corpus is the one
// artifact of a hostile run that outlives the container, and a corpus
// nothing parses in normal CI is a corpus that rots.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
