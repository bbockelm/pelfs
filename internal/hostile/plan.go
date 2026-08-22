// Package hostile builds adversarial filesystem operation plans: the
// impolite user, written down.
//
// WHY THIS EXISTS. Every correctness bug in the v0.1.0 release week was
// found by a human at a shell prompt and none by a gate, because every
// gate writes polite tar-shaped data — files created once, written front
// to back, closed, never revisited. The bugs lived in the shapes a real
// tree has and a tarball does not: symlinks whose target is deleted
// first, write trains an NFS client flushed out of order, a file grown
// with truncate(1), a name unlinked and recreated, thousands of entries
// mutated while something enumerates them.
//
// This file is the VOCABULARY, and it is deliberately pure: a seed and an
// op count in, a []Op out, no filesystem anywhere. That split is what
// makes a finding portable. A plan prints as text, parses back byte-
// identical, and can be shrunk by deleting lines — so a sequence that
// found a bug becomes a corpus file that every future run replays, the
// regression-corpus discipline the parser fuzzers already have.
//
// The EXECUTOR is somewhere else on purpose: internal/hostile/exec_test.go,
// behind the `hostile` build tag and an environment gate, because running
// a plan needs a real mount and a real mount needs containment. Nothing in
// this file can touch a filesystem, so nothing in this file needs a tag.
package hostile

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
)

// OpKind is one primitive operation. A plan is a flat sequence of these:
// the interesting SHAPES (a symlink forest, a sparse train) are emitted by
// the generator as bursts of primitives rather than modeled as compound
// ops, so that minimizing a finding is line deletion and nothing cleverer.
type OpKind uint8

const (
	OpCreate OpKind = iota // create+write a whole small file, then close
	OpMkdir
	OpSymlink // Path is the link, Path2 the raw target string
	OpUnlink
	OpRmdir
	OpRename
	OpLink // Path is an existing file, Path2 the new name
	OpPwrite
	OpTruncate
	OpChmod
	OpChown
	OpUtimes
	OpReaddirMutate // enumerate a directory while mutating it
	OpRmrf          // recursive delete in sorted order, rm(1)-fashion
	OpCompare       // checkpoint: whole-tree byte+metadata comparison
	OpSettle        // wait, so a --snapshot-interval checkpoint can land
	numOpKinds
)

var opNames = [numOpKinds]string{
	OpCreate:        "create",
	OpMkdir:         "mkdir",
	OpSymlink:       "symlink",
	OpUnlink:        "unlink",
	OpRmdir:         "rmdir",
	OpRename:        "rename",
	OpLink:          "link",
	OpPwrite:        "pwrite",
	OpTruncate:      "truncate",
	OpChmod:         "chmod",
	OpChown:         "chown",
	OpUtimes:        "utimes",
	OpReaddirMutate: "readdir-mutate",
	OpRmrf:          "rmrf",
	OpCompare:       "compare",
	OpSettle:        "settle",
}

func (k OpKind) String() string {
	if k < numOpKinds && opNames[k] != "" {
		return opNames[k]
	}
	return "op" + strconv.Itoa(int(k))
}

func kindByName(s string) (OpKind, bool) {
	for i, n := range opNames {
		if n == s {
			return OpKind(i), true
		}
	}
	return 0, false
}

// Op is one line of a plan. Paths are always relative, slash-separated,
// and never contain ".." — the executor puts them through an os.Root, which
// would refuse them anyway, but a generator that emits them is a generator
// bug and the parser says so rather than relying on the executor to.
type Op struct {
	Kind  OpKind
	Path  string
	Path2 string
	Off   int64
	Len   int64
	Size  int64
	Mode  uint32
	UID   int
	GID   int
	MTime int64  // unix seconds, for OpUtimes
	Count int    // OpReaddirMutate: how many entries to disturb
	Fill  byte   // OpPwrite/OpCreate: the byte the body is made of
	Wait  int    // OpSettle: milliseconds
	Note  string // why the generator emitted this, for the failure message
}

// String renders one op as a corpus line. Round-trips through ParseOp.
func (o Op) String() string {
	var b strings.Builder
	b.WriteString(o.Kind.String())
	if o.Path != "" {
		b.WriteString(" ")
		b.WriteString(o.Path)
	}
	if o.Path2 != "" {
		b.WriteString(" -> ")
		b.WriteString(o.Path2)
	}
	kv := func(k string, v int64) {
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strconv.FormatInt(v, 10))
	}
	switch o.Kind {
	case OpPwrite:
		kv("off", o.Off)
		kv("len", o.Len)
		fmt.Fprintf(&b, " fill=%02x", o.Fill)
	case OpCreate:
		kv("len", o.Len)
		fmt.Fprintf(&b, " fill=%02x", o.Fill)
	case OpTruncate:
		kv("size", o.Size)
	case OpChmod:
		fmt.Fprintf(&b, " mode=%04o", o.Mode)
	case OpMkdir:
		if o.Mode != 0 {
			fmt.Fprintf(&b, " mode=%04o", o.Mode)
		}
	case OpChown:
		kv("uid", int64(o.UID))
		kv("gid", int64(o.GID))
	case OpUtimes:
		kv("mtime", o.MTime)
	case OpReaddirMutate:
		kv("n", int64(o.Count))
	case OpSettle:
		kv("ms", int64(o.Wait))
	}
	if o.Note != "" {
		b.WriteString(" # ")
		b.WriteString(o.Note)
	}
	return b.String()
}

// ParseOp reads one corpus line. Empty lines and full-line comments give
// ok=false with no error, so a corpus file can be annotated.
func ParseOp(line string) (Op, bool, error) {
	// The note is informational; keep it so a replay prints the same text.
	var note string
	if i := strings.Index(line, " # "); i >= 0 {
		note = strings.TrimSpace(line[i+3:])
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Op{}, false, nil
	}
	fields := strings.Fields(line)
	kind, ok := kindByName(fields[0])
	if !ok {
		return Op{}, false, fmt.Errorf("unknown op %q", fields[0])
	}
	op := Op{Kind: kind, Note: note}
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "->":
			if i+1 >= len(fields) {
				return Op{}, false, fmt.Errorf("%s: trailing -> with no operand", kind)
			}
			i++
			op.Path2 = fields[i]
		case strings.ContainsRune(f, '='):
			k, v, _ := strings.Cut(f, "=")
			base := 10
			if k == "mode" || k == "fill" {
				base = 16
			}
			if k == "mode" {
				base = 8
			}
			n, err := strconv.ParseInt(v, base, 64)
			if err != nil {
				return Op{}, false, fmt.Errorf("%s: bad %s=%q: %w", kind, k, v, err)
			}
			switch k {
			case "off":
				op.Off = n
			case "len":
				op.Len = n
			case "size":
				op.Size = n
			case "mode":
				op.Mode = uint32(n)
			case "uid":
				op.UID = int(n)
			case "gid":
				op.GID = int(n)
			case "mtime":
				op.MTime = n
			case "n":
				op.Count = int(n)
			case "ms":
				op.Wait = int(n)
			case "fill":
				op.Fill = byte(n)
			default:
				return Op{}, false, fmt.Errorf("%s: unknown key %q", kind, k)
			}
		case op.Path == "":
			op.Path = f
		default:
			return Op{}, false, fmt.Errorf("%s: unexpected operand %q", kind, f)
		}
	}
	for _, p := range []string{op.Path, op.Path2} {
		if err := checkRelPath(op.Kind, p); err != nil {
			return Op{}, false, err
		}
	}
	return op, true, nil
}

// checkRelPath refuses anything that could aim an operation out of the
// sandbox. A symlink TARGET is exempt: pointing one at /etc/passwd or at
// ../../.. is a case this exerciser exists to generate, and the executor's
// os.Root is what makes generating it safe (os.Root will not traverse a
// link that leaves the root, and documents that it does not validate the
// target at creation time).
func checkRelPath(kind OpKind, p string) error {
	if p == "" || kind == OpSymlink {
		return nil
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("%s: absolute path %q", kind, p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("%s: %q escapes with ..", kind, p)
		}
	}
	return nil
}

// Plan is a seeded, replayable sequence.
type Plan struct {
	Seed uint64
	Ops  []Op
	// KnownOpen names the backends on which this entry is EXPECTED to
	// diverge, because it pins a finding that has not been fixed yet.
	// Written in a corpus file as `# expect: known-open nfs`.
	//
	// The replayer treats a known-open entry as: report the divergence
	// loudly, do not fail -- but FAIL if the divergence stops happening.
	// That is the direction a corpus rots in. An entry for an open finding
	// that failed the build outright would only make the gate red until
	// someone had time for it, which is how gates get switched off; an
	// entry that passed silently would stop testing anything the moment
	// the bug was fixed. This does neither.
	KnownOpen []string
	// Flaky marks a known-open finding that is a RACE, so it reproduces
	// only sometimes. Written as `# expect: flaky-open fuse`.
	//
	// Such an entry is replayed and its divergence reported loudly when it
	// fires, but neither its presence NOR its absence fails the build --
	// because for a race, both are true observations and neither is a
	// regression. The alternative was making the gate red two runs in
	// three, which is the same as switching it off. What keeps this honest
	// is that it is never SILENT: a fired entry prints the divergence, and
	// the amplifier that raises the hit rate is documented next to it, so
	// whoever triages can reproduce it on demand rather than waiting.
	Flaky bool
}

// IsKnownOpen reports whether this entry expects to diverge on a backend.
func (p Plan) IsKnownOpen(backend string) bool {
	for _, b := range p.KnownOpen {
		if b == backend || b == "all" {
			return true
		}
	}
	return false
}

// String renders a plan as a corpus file: a header naming the seed, then
// one op per line.
func (p Plan) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# hostile plan: seed=%d ops=%d\n", p.Seed, len(p.Ops))
	if len(p.KnownOpen) > 0 {
		marker := "known-open"
		if p.Flaky {
			marker = "flaky-open"
		}
		fmt.Fprintf(&b, "# expect: %s %s\n", marker, strings.Join(p.KnownOpen, " "))
	}
	for _, o := range p.Ops {
		b.WriteString(o.String())
		b.WriteString("\n")
	}
	return b.String()
}

// ParsePlan reads a corpus file. The seed is recovered from the header if
// present, purely so a replay can print where the sequence came from; the
// ops are taken from the file, never regenerated from the seed (a
// minimized corpus entry is not what any seed produces).
func ParsePlan(text string) (Plan, error) {
	var p Plan
	for i, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "#") {
			if _, after, found := strings.Cut(s, "seed="); found {
				if n, err := strconv.ParseUint(strings.Fields(after)[0], 10, 64); err == nil {
					p.Seed = n
				}
			}
			for _, marker := range []string{"expect: known-open", "expect: flaky-open"} {
				_, after, found := strings.Cut(s, marker)
				if !found {
					continue
				}
				backends := strings.Fields(after)
				if len(backends) == 0 {
					return Plan{}, fmt.Errorf("line %d: `%s` names no backend "+
						"(use `all` to mean every backend)", i+1, marker)
				}
				for _, b := range backends {
					switch b {
					case "fuse", "nfs", "all":
						p.KnownOpen = append(p.KnownOpen, b)
					default:
						return Plan{}, fmt.Errorf("line %d: unknown backend %q in %s", i+1, b, marker)
					}
				}
				if marker == "expect: flaky-open" {
					p.Flaky = true
				}
			}
			continue
		}
		op, ok, err := ParseOp(line)
		if err != nil {
			return Plan{}, fmt.Errorf("line %d: %w", i+1, err)
		}
		if ok {
			p.Ops = append(p.Ops, op)
		}
	}
	return p, nil
}

// Options tunes how long a plan is and how often it stops to check itself.
type Options struct {
	// Ops is the target number of primitive operations. Shapes are emitted
	// whole, so the real count overshoots slightly.
	Ops int
	// CompareEvery inserts a whole-tree comparison after roughly this many
	// ops. Zero means compare only at the end (the executor always does).
	CompareEvery int
	// SettleEvery inserts a wait after roughly this many ops, so that a
	// mount running --snapshot-interval 1s actually publishes a checkpoint
	// mid-run rather than only at the seal.
	SettleEvery int
	// MaxNameLen is the length of the deliberately-longest path component
	// the deep-and-long shape mints. 255 is the Linux limit and is
	// deliberately the default: the longest name a filesystem must accept
	// is a boundary, and boundaries are where the bugs are. It is not a
	// global cap — the other shapes use fixed, legible names, because a
	// failure message naming lib_eventlog_rotation_7.run is worth more
	// than one naming nnnnnnnn….
	MaxNameLen int
	// MaxDepth caps directory nesting.
	MaxDepth int
	// BigDirEntries is how many entries a "thousands of entries" directory
	// gets. CI runs this small; the manual mode does not.
	BigDirEntries int
}

// DefaultOptions is the shape of a short run: enough of every hostile
// shape to be worth running, small enough for a CI budget.
func DefaultOptions() Options {
	return Options{
		Ops:           400,
		CompareEvery:  120,
		SettleEvery:   150,
		MaxNameLen:    255,
		MaxDepth:      8,
		BigDirEntries: 1200,
	}
}

// shape is one hostile idiom. Each returns the ops it wants appended.
// Every shape is listed in the table below with a WEIGHT, and the weights
// are the whole policy: the shapes that bit this month are common, the
// filler that gives them something to bite is cheap.
type shape struct {
	name   string
	weight int
	emit   func(g *gen) []Op
}

var shapes = []shape{
	// The five that bit in release week, first and heaviest.
	{"symlink-forest", 10, shapeSymlinkForest},
	{"sparse-train", 10, shapeSparseTrain},
	{"whiteout-cycle", 8, shapeWhiteoutCycle},
	{"dangling-and-loops", 8, shapeDanglingAndLoops},
	{"truncate-train", 7, shapeTruncateTrain},
	// The rest of the vocabulary.
	{"attrs-after-close", 6, shapeAttrsAfterClose},
	{"hardlink-web", 6, shapeHardlinkWeb},
	{"rename-storm", 6, shapeRenameStorm},
	{"big-dir-mutate", 4, shapeBigDirMutate},
	{"deep-and-long", 4, shapeDeepAndLong},
	{"plain-tree", 8, shapePlainTree},
}

// gen carries the generator's PREDICTED namespace. It is a prediction and
// not a model: the executor never consults it, and an op the prediction
// got wrong is not a problem — it becomes an operation that fails, which
// must fail the same way on both trees, which is exactly the comparison
// worth making. (opfuzz needs a real model because its oracle is
// in-memory; here the oracle is a tmpfs tree, so the model can be a
// guess.)
type gen struct {
	rnd   *rand.Rand
	opt   Options
	dirs  []string
	files []string
	links []string
	n     int // names minted, for uniqueness
}

func (g *gen) pick(from []string) (string, bool) {
	if len(from) == 0 {
		return "", false
	}
	return from[g.rnd.IntN(len(from))], true
}

func (g *gen) pickDir() string {
	d, ok := g.pick(g.dirs)
	if !ok {
		return "."
	}
	return d
}

func (g *gen) name(prefix string) string {
	g.n++
	return fmt.Sprintf("%s%d", prefix, g.n)
}

func (g *gen) join(dir, name string) string {
	if dir == "." || dir == "" {
		return name
	}
	return dir + "/" + name
}

func (g *gen) addDir(p string) {
	if depth(p) < g.opt.MaxDepth {
		g.dirs = append(g.dirs, p)
	}
}

func depth(p string) int {
	if p == "." || p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// forget drops a path and everything under it from the prediction. Called
// after a delete so the generator mostly stops naming what it removed —
// mostly, because naming a deleted path occasionally is a case worth
// generating (that is an ENOENT both trees must agree on).
func (g *gen) forget(p string) {
	keep := func(list []string) []string {
		out := list[:0]
		for _, e := range list {
			if e != p && !strings.HasPrefix(e, p+"/") {
				out = append(out, e)
			}
		}
		return out
	}
	g.dirs = keep(g.dirs)
	g.files = keep(g.files)
	g.links = keep(g.links)
}

// Generate builds a plan. Same seed and options, same ops, forever: that
// is the contract the corpus and the "print the seed" promise both rest
// on, and TestGenerateIsDeterministic pins it.
func Generate(seed uint64, opt Options) Plan {
	if opt.Ops <= 0 {
		opt = DefaultOptions()
	}
	if opt.MaxNameLen <= 0 {
		opt.MaxNameLen = 255
	}
	if opt.MaxDepth <= 0 {
		opt.MaxDepth = 8
	}
	if opt.BigDirEntries <= 0 {
		opt.BigDirEntries = 64
	}
	g := &gen{
		rnd: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		opt: opt,
	}
	total := 0
	for _, s := range shapes {
		total += s.weight
	}

	p := Plan{Seed: seed}
	sinceCompare, sinceSettle := 0, 0
	for len(p.Ops) < opt.Ops {
		r := g.rnd.IntN(total)
		var chosen shape
		for _, s := range shapes {
			if r -= s.weight; r < 0 {
				chosen = s
				break
			}
		}
		before := len(p.Ops)
		p.Ops = append(p.Ops, chosen.emit(g)...)
		grew := len(p.Ops) - before
		sinceCompare += grew
		sinceSettle += grew

		if opt.SettleEvery > 0 && sinceSettle >= opt.SettleEvery {
			sinceSettle = 0
			p.Ops = append(p.Ops, Op{Kind: OpSettle, Wait: 1100,
				Note: "let a --snapshot-interval checkpoint publish mid-run"})
		}
		if opt.CompareEvery > 0 && sinceCompare >= opt.CompareEvery {
			sinceCompare = 0
			p.Ops = append(p.Ops, Op{Kind: OpCompare, Note: chosen.name})
		}
	}
	return p
}

// ---------------------------------------------------------------- shapes

// shapeSymlinkForest is the reported bug, written as a generator: one
// target whose name sorts AHEAD of every link that names it, N links, and
// then an rm -rf of the containing directory. rm(1) walks sorted, so the
// target is unlinked first and every link is dangling by the time its own
// turn comes. A REMOVE that stats its operand through the link sees ENOENT
// for a link that is plainly there, answers "already gone", and unlinks
// nothing; the rmdir behind it then refuses, identically on every retry.
func shapeSymlinkForest(g *gen) []Op {
	dir := g.join(g.pickDir(), g.name("forest"))
	ops := []Op{{Kind: OpMkdir, Path: dir, Mode: 0o755, Note: "symlink forest"}}
	// "aaa_" so it sorts first in any sane collation.
	target := g.join(dir, "aaa_base.run")
	ops = append(ops, Op{Kind: OpCreate, Path: target, Len: 64, Fill: 0x41,
		Note: "the target every link names; sorts first"})
	n := 3 + g.rnd.IntN(21)
	for i := 0; i < n; i++ {
		ops = append(ops, Op{Kind: OpSymlink,
			Path:  g.join(dir, fmt.Sprintf("lib_eventlog_rotation_%d.run", i)),
			Path2: "aaa_base.run"})
	}
	// Delete the shared target FIRST, by hand, so the forest is dangling
	// even if the rmrf below happens to walk in another order.
	ops = append(ops,
		Op{Kind: OpUnlink, Path: target, Note: "shared target deleted first"},
		Op{Kind: OpRmrf, Path: dir, Note: "one pass must empty a forest of dangling links"})
	g.forget(dir)
	return ops
}

// shapeSparseTrain writes a file's extents in the wrong order with gaps
// between them — what an NFS client produces on its own when it flushes a
// write train out of order, and what left a signed generation holding a
// file whose chunk lengths summed short of its length.
func shapeSparseTrain(g *gen) []Op {
	dir := g.pickDir()
	f := g.join(dir, g.name("train")+".dat")
	ops := []Op{{Kind: OpCreate, Path: f, Len: 0, Fill: 0,
		Note: "sparse train: extents out of order, with gaps"}}

	const block = 16384
	// Offsets chosen as a shuffled subset of a grid, so gaps are certain
	// and the highest offset is often written first (the "seek past the
	// end and write" case).
	grid := make([]int64, 3+g.rnd.IntN(6))
	for i := range grid {
		grid[i] = int64(i) * block
	}
	g.rnd.Shuffle(len(grid), func(i, j int) { grid[i], grid[j] = grid[j], grid[i] })
	// Drop one or two, which is what makes a hole rather than a reorder.
	if len(grid) > 3 {
		grid = grid[:len(grid)-1-g.rnd.IntN(2)]
	}
	for i, off := range grid {
		ln := int64(block)
		if g.rnd.IntN(4) == 0 {
			// An overlapping, unaligned write: the extent list has to
			// merge rather than append.
			off += int64(g.rnd.IntN(block))
			ln = int64(1 + g.rnd.IntN(block))
		}
		ops = append(ops, Op{Kind: OpPwrite, Path: f, Off: off, Len: ln,
			Fill: byte(0x50 + i)})
	}
	g.files = append(g.files, f)
	return ops
}

// shapeTruncateTrain grows a file with truncate(1) — a length with no
// bytes behind it at all — and shrinks one mid-train, so the extents a
// row already holds name bytes past the end.
func shapeTruncateTrain(g *gen) []Op {
	dir := g.pickDir()
	f := g.join(dir, g.name("trunc")+".dat")
	ops := []Op{
		{Kind: OpCreate, Path: f, Len: int64(1 + g.rnd.IntN(30000)), Fill: 0x77,
			Note: "truncate up and down mid-train"},
		{Kind: OpPwrite, Path: f, Off: int64(g.rnd.IntN(40000)), Len: int64(1 + g.rnd.IntN(9000)), Fill: 0x78},
	}
	up := int64(32768 + g.rnd.IntN(65536))
	ops = append(ops, Op{Kind: OpTruncate, Path: f, Size: up, Note: "grow: a tail hole with no bytes behind it"})
	// A write into the fresh hole, then a shrink that cuts an extent in
	// half, then a regrow — the sequence that leaves refs naming bytes
	// past the end if a resize only sets the size.
	ops = append(ops,
		Op{Kind: OpPwrite, Path: f, Off: up - 4096, Len: 4096, Fill: 0x79},
		Op{Kind: OpTruncate, Path: f, Size: up / 3, Note: "shrink through the middle of an extent"},
		Op{Kind: OpTruncate, Path: f, Size: up, Note: "regrow: the cut bytes must read as zeros"},
	)
	if g.rnd.IntN(3) == 0 {
		ops = append(ops, Op{Kind: OpTruncate, Path: f, Size: 0, Note: "to zero: no ref may outlive it"})
	}
	g.files = append(g.files, f)
	return ops
}

// shapeWhiteoutCycle is unlink/recreate/unlink over the same name: the
// shape a repair in one session and a deletion in the next produces, and
// the one where a whiteout can be left describing the wrong thing.
func shapeWhiteoutCycle(g *gen) []Op {
	dir := g.pickDir()
	name := g.join(dir, g.name("cycle")+".txt")
	ops := []Op{{Kind: OpCreate, Path: name, Len: 128, Fill: 0x61, Note: "whiteout cycle"}}
	for i := 0; i < 2+g.rnd.IntN(3); i++ {
		ops = append(ops,
			Op{Kind: OpUnlink, Path: name},
			Op{Kind: OpCreate, Path: name, Len: int64(64 + i*97), Fill: byte(0x62 + i),
				Note: "recreate over the whiteout"},
		)
	}
	if g.rnd.IntN(2) == 0 {
		// Ending unlinked is the other half: the whiteout must survive.
		ops = append(ops, Op{Kind: OpUnlink, Path: name, Note: "and stay gone"})
	} else {
		g.files = append(g.files, name)
	}
	// A directory taking the same name after the file is gone.
	if g.rnd.IntN(3) == 0 {
		d := name + ".d"
		ops = append(ops,
			Op{Kind: OpMkdir, Path: d, Mode: 0o755},
			Op{Kind: OpRmdir, Path: d},
			Op{Kind: OpMkdir, Path: d, Mode: 0o700, Note: "recreate a directory over its own whiteout"},
		)
		g.addDir(d)
	}
	return ops
}

// shapeDanglingAndLoops makes links nothing can resolve: a dangling one, a
// two-hop loop, a self-loop, and one aimed clean out of the tree. The last
// is safe precisely because the executor works through an os.Root, which
// refuses to traverse a link that leaves the root — so generating it tests
// the filesystem's handling of an absolute target without ever letting the
// harness follow it anywhere.
func shapeDanglingAndLoops(g *gen) []Op {
	dir := g.join(g.pickDir(), g.name("links"))
	ops := []Op{{Kind: OpMkdir, Path: dir, Mode: 0o755, Note: "dangling and looping links"}}
	a, b := g.join(dir, "loop_a"), g.join(dir, "loop_b")
	ops = append(ops,
		Op{Kind: OpSymlink, Path: g.join(dir, "dangling"), Path2: "no-such-target"},
		Op{Kind: OpSymlink, Path: a, Path2: "loop_b"},
		Op{Kind: OpSymlink, Path: b, Path2: "loop_a", Note: "two-hop loop"},
		Op{Kind: OpSymlink, Path: g.join(dir, "self"), Path2: "self", Note: "self-loop"},
		Op{Kind: OpSymlink, Path: g.join(dir, "escapee"), Path2: "../../../../../../etc/passwd",
			Note: "aimed out of the tree; os.Root must refuse to follow it"},
		Op{Kind: OpSymlink, Path: g.join(dir, "absolute"), Path2: "/etc/shadow",
			Note: "absolute target; readlink must return it verbatim"},
	)
	g.links = append(g.links, a, b)
	// Unlinking a dangling link must take the LINK. Sometimes leave them
	// for a later rmrf to trip over instead.
	if g.rnd.IntN(2) == 0 {
		ops = append(ops, Op{Kind: OpUnlink, Path: g.join(dir, "dangling")})
	}
	if g.rnd.IntN(3) == 0 {
		ops = append(ops, Op{Kind: OpRmrf, Path: dir, Note: "rm -rf over a loop must terminate"})
		g.forget(dir)
	} else {
		g.addDir(dir)
	}
	return ops
}

// shapeAttrsAfterClose sets mode, owner and times the instant after a
// close — before any flush or checkpoint has had a chance to run, which is
// where an attribute set against a still-in-flight inode gets lost.
func shapeAttrsAfterClose(g *gen) []Op {
	dir := g.pickDir()
	f := g.join(dir, g.name("attr")+".bin")
	modes := []uint32{0o600, 0o640, 0o444, 0o755, 0o400, 0o666}
	ops := []Op{
		{Kind: OpCreate, Path: f, Len: int64(1 + g.rnd.IntN(20000)), Fill: 0x2b,
			Note: "attributes immediately after close"},
		{Kind: OpChmod, Path: f, Mode: modes[g.rnd.IntN(len(modes))]},
		{Kind: OpUtimes, Path: f, MTime: 1000000000 + int64(g.rnd.IntN(700000000))},
		{Kind: OpChown, Path: f, UID: 65534, GID: 65534},
	}
	// And again after more data, so the second set has to survive a write.
	ops = append(ops,
		Op{Kind: OpPwrite, Path: f, Off: int64(g.rnd.IntN(30000)), Len: 512, Fill: 0x2c},
		Op{Kind: OpChmod, Path: f, Mode: modes[g.rnd.IntN(len(modes))], Note: "after a write, not a create"},
		Op{Kind: OpUtimes, Path: f, MTime: 1400000000 + int64(g.rnd.IntN(200000000))},
	)
	g.files = append(g.files, f)
	return ops
}

// shapeHardlinkWeb builds several names for one inode across directories,
// then takes some away. nlink is the thing that goes wrong.
func shapeHardlinkWeb(g *gen) []Op {
	dir := g.pickDir()
	base := g.join(dir, g.name("web")+".dat")
	ops := []Op{{Kind: OpCreate, Path: base, Len: int64(300 + g.rnd.IntN(5000)), Fill: 0x33,
		Note: "hardlink web"}}
	var names []string
	for i := 0; i < 2+g.rnd.IntN(4); i++ {
		d := g.pickDir()
		n := g.join(d, g.name("hl")+".dat")
		ops = append(ops, Op{Kind: OpLink, Path: base, Path2: n})
		names = append(names, n)
	}
	// Write through ONE name; every other name must see it.
	ops = append(ops, Op{Kind: OpPwrite, Path: base, Off: 64, Len: 256, Fill: 0x34,
		Note: "write through one name, visible through all"})
	g.rnd.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	for _, n := range names[:len(names)/2] {
		ops = append(ops, Op{Kind: OpUnlink, Path: n, Note: "drop a name, keep the inode"})
	}
	// Rename one of the survivors: a link count must not move.
	if len(names) > 0 {
		last := names[len(names)-1]
		ops = append(ops, Op{Kind: OpRename, Path: last, Path2: last + ".moved"})
		g.files = append(g.files, last+".moved")
	}
	g.files = append(g.files, base)
	return ops
}

// shapeRenameStorm moves names between directories, over existing names,
// and onto themselves. The self-rename is here because it is the case a
// model gets wrong by unlinking the source and then binding a name to the
// inode it just removed.
func shapeRenameStorm(g *gen) []Op {
	d1 := g.join(g.pickDir(), g.name("storm"))
	d2 := g.join(g.pickDir(), g.name("storm"))
	ops := []Op{
		{Kind: OpMkdir, Path: d1, Mode: 0o755, Note: "rename storm across directories"},
		{Kind: OpMkdir, Path: d2, Mode: 0o755},
	}
	var live []string
	n := 4 + g.rnd.IntN(10)
	for i := 0; i < n; i++ {
		p := g.join(d1, fmt.Sprintf("r%02d.dat", i))
		ops = append(ops, Op{Kind: OpCreate, Path: p, Len: int64(50 + i*11), Fill: byte(0x80 + i)})
		live = append(live, p)
	}
	for i := 0; i < n; i++ {
		if len(live) == 0 {
			break
		}
		j := g.rnd.IntN(len(live))
		src := live[j]
		var dst string
		switch g.rnd.IntN(4) {
		case 0:
			dst = src // self-rename: a no-op that must not destroy anything
		case 1, 2:
			dst = g.join(d2, fmt.Sprintf("r%02d.dat", g.rnd.IntN(n)))
		default:
			dst = g.join(d1, fmt.Sprintf("r%02d.dat", g.rnd.IntN(n)))
		}
		note := ""
		if dst == src {
			note = "self-rename"
		}
		ops = append(ops, Op{Kind: OpRename, Path: src, Path2: dst, Note: note})
		live[j] = dst
	}
	// And a directory rename, which moves a subtree.
	ops = append(ops, Op{Kind: OpRename, Path: d1, Path2: d1 + ".renamed",
		Note: "move a whole subtree"})
	g.forget(d1)
	g.addDir(d1 + ".renamed")
	g.addDir(d2)
	return ops
}

// shapeBigDirMutate builds a directory large enough to need many READDIR
// round trips and then mutates it WHILE enumerating: entries unlinked and
// created between pages, which is the only way a positional readdir cookie
// can be caught shifting entries a client has not been shown yet.
func shapeBigDirMutate(g *gen) []Op {
	dir := g.join(g.pickDir(), g.name("bigdir"))
	ops := []Op{{Kind: OpMkdir, Path: dir, Mode: 0o755,
		Note: "thousands of entries, mutated during enumeration"}}
	n := g.opt.BigDirEntries
	for i := 0; i < n; i++ {
		ops = append(ops, Op{Kind: OpCreate, Path: g.join(dir, fmt.Sprintf("e%05d", i)), Len: 0})
	}
	ops = append(ops,
		Op{Kind: OpReaddirMutate, Path: dir, Count: 1 + n/8},
		Op{Kind: OpRmrf, Path: dir, Note: "and one pass must empty it"},
	)
	g.forget(dir)
	return ops
}

// shapeDeepAndLong goes as deep as the options allow with components at
// the 255-byte limit, then does ordinary work at the bottom.
func shapeDeepAndLong(g *gen) []Op {
	long := strings.Repeat("n", g.opt.MaxNameLen)
	p := g.name("deep")
	ops := []Op{{Kind: OpMkdir, Path: p, Mode: 0o755, Note: "deep nesting and max-length names"}}
	for i := 1; i < g.opt.MaxDepth; i++ {
		seg := fmt.Sprintf("d%d", i)
		if i == g.opt.MaxDepth/2 {
			seg = long // one component at the limit, mid-path
		}
		p = g.join(p, seg)
		ops = append(ops, Op{Kind: OpMkdir, Path: p, Mode: 0o755})
	}
	f := g.join(p, long[:g.opt.MaxNameLen-4]+".dat")
	ops = append(ops,
		Op{Kind: OpCreate, Path: f, Len: int64(1 + g.rnd.IntN(9000)), Fill: 0x5f,
			Note: "a max-length name at the bottom of a deep path"},
		Op{Kind: OpSymlink, Path: g.join(p, "up"), Path2: strings.Repeat("../", g.opt.MaxDepth+3) + "escaped",
			Note: "a link that climbs past the root"},
	)
	g.files = append(g.files, f)
	g.addDir(p)
	return ops
}

// shapePlainTree is the polite filler: ordinary files and directories, so
// the hostile shapes have a real tree to be hostile inside of.
func shapePlainTree(g *gen) []Op {
	dir := g.pickDir()
	var ops []Op
	if g.rnd.IntN(3) == 0 {
		d := g.join(dir, g.name("d"))
		ops = append(ops, Op{Kind: OpMkdir, Path: d, Mode: 0o755})
		g.addDir(d)
		dir = d
	}
	for i := 0; i < 1+g.rnd.IntN(4); i++ {
		f := g.join(dir, g.name("f")+".txt")
		ops = append(ops, Op{Kind: OpCreate, Path: f,
			Len: int64(g.rnd.IntN(70000)), Fill: byte(g.rnd.IntN(256))})
		g.files = append(g.files, f)
	}
	// Occasionally delete something at random, so the tree is not
	// monotonically growing.
	if f, ok := g.pick(g.files); ok && g.rnd.IntN(3) == 0 {
		ops = append(ops, Op{Kind: OpUnlink, Path: f})
		g.forget(f)
	}
	return ops
}

// SortedNames is the order rm(1) walks a directory in. The executor uses
// it for OpRmrf so that a shared symlink target is unlinked before the
// links that name it — the ordering the reported bug depended on.
func SortedNames(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	return out
}
