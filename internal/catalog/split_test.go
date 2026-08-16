package catalog

import (
	"reflect"
	"testing"
)

// weightOf recomputes a chosen root's residual catalog weight given the set
// of peeled roots: peeled subtrees contribute one transition row instead of
// their weight.
func weightOf(d *DirNode, peeled map[*DirNode]bool) int64 {
	w := d.OwnWeight
	for _, c := range d.Children {
		if peeled[c] {
			w += TransitionWeight
		} else {
			w += weightOf(c, peeled)
		}
	}
	return w
}

func TestSplitDefaults(t *testing.T) {
	if SMax != 8<<20 {
		t.Errorf("SMax = %d, want 8 MiB", SMax)
	}
	if SMin != 1<<20 {
		t.Errorf("SMin = %d, want 1 MiB", SMin)
	}
}

// A directory of many medium children must peel largest-first and end at or
// under smax — the naive detach-the-whole-directory alternative would ship
// it 10-15x over threshold.
func TestSplitPeelsLargestFirst(t *testing.T) {
	const smax, smin = 2000, 250
	a := &DirNode{OwnWeight: 900}
	b := &DirNode{OwnWeight: 800}
	c := &DirNode{OwnWeight: 700}
	root := &DirNode{OwnWeight: 400, Children: []*DirNode{c, a, b}}
	// Total 2800 > 2000: peel a (900) -> 2100, peel b (800) -> 1500, fits.
	// c (700) stays attached: peeling stops as soon as the dir fits.
	roots := Split(root, smax, smin)
	want := []*DirNode{a, b, root}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("Split roots = %v, want [a b root]", roots)
	}
	peeled := map[*DirNode]bool{a: true, b: true}
	if w := weightOf(root, peeled); w != 1500 || w > smax {
		t.Errorf("residual root weight = %d, want 1500 <= smax", w)
	}
}

// Many equal medium children: keep peeling until under smax, and every
// chosen root must be within threshold.
func TestSplitManyMediumChildren(t *testing.T) {
	const smax, smin = 10000, 1250
	root := &DirNode{OwnWeight: 20 * TransitionWeight}
	for i := 0; i < 20; i++ {
		root.Children = append(root.Children, &DirNode{OwnWeight: 1000})
	}
	roots := Split(root, smax, smin)
	peeled := make(map[*DirNode]bool)
	for _, r := range roots[:len(roots)-1] {
		peeled[r] = true
	}
	if roots[len(roots)-1] != root {
		t.Fatal("tree root must be the last chosen root")
	}
	if w := weightOf(root, peeled); w > smax {
		t.Errorf("residual root weight %d exceeds smax %d", w, smax)
	}
	for _, r := range roots[:len(roots)-1] {
		if w := weightOf(r, peeled); w > smax {
			t.Errorf("peeled root weight %d exceeds smax %d", w, smax)
		}
	}
	// 4000 + 20*1000 = 24000; each peel trades 1000 for a 200 row, so
	// after k peels w = 24000 - 800k. w <= 10000 needs k >= 17.5: exactly
	// 18 children peel, two stay attached, residual 9600.
	if len(roots) != 19 {
		t.Errorf("chose %d roots, want 19 (18 peeled + root)", len(roots))
	}
	if w := weightOf(root, peeled); w != 9600 {
		t.Errorf("residual root weight = %d, want 9600", w)
	}
}

// A flat directory whose own rows exceed smax cannot split and stays one
// oversized catalog — the allowed pathology (@mui/icons-material case).
func TestSplitFlatDirPathology(t *testing.T) {
	root := &DirNode{OwnWeight: 3 * SMax}
	roots := Split(root, SMax, SMin)
	if len(roots) != 1 || roots[0] != root {
		t.Fatalf("Split roots = %v, want just the oversized root", roots)
	}
}

// Transition-row accounting: a peeled child costs its parent exactly one
// 200-byte row, and that residue propagates to the grandparent's decision.
func TestSplitTransitionRowAccounting(t *testing.T) {
	const smax, smin = 1000, 100
	a := &DirNode{OwnWeight: 850}
	d := &DirNode{OwnWeight: 700, Children: []*DirNode{a}}
	p := &DirNode{OwnWeight: 300, Children: []*DirNode{d}}
	// d: 700+850 = 1550 > 1000, peel a -> 700+200 = 900, fits.
	// p: 300+900 = 1200 > 1000, peel d -> 300+200 = 500, fits.
	// With a zero-cost transition d would weigh 700 and p 1000 = smax:
	// three roots come out only if the 200-byte row is charged.
	roots := Split(p, smax, smin)
	want := []*DirNode{a, d, p}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("Split roots = %v, want [a d p]", roots)
	}
}

// Peeling a child no heavier than its transition row cannot shrink the
// parent; such children stay attached even when the parent is over smax.
func TestSplitSkipsUnprofitablePeel(t *testing.T) {
	const smax, smin = 1000, 100
	tiny := &DirNode{OwnWeight: 150}
	root := &DirNode{OwnWeight: 1200, Children: []*DirNode{tiny}}
	roots := Split(root, smax, smin)
	if len(roots) != 1 || roots[0] != root {
		t.Fatalf("Split roots = %v, want just root (peeling 150 for a 200 row loses)", roots)
	}
}

// Equal-weight ties break to the lowest child index, and repeated runs
// return the identical root order.
func TestSplitDeterministic(t *testing.T) {
	const smax, smin = 2000, 250
	build := func() (*DirNode, []*DirNode) {
		var kids []*DirNode
		for i := 0; i < 4; i++ {
			kids = append(kids, &DirNode{OwnWeight: 900})
		}
		return &DirNode{OwnWeight: 800, Children: kids}, kids
	}
	root, kids := build()
	first := Split(root, smax, smin)
	// 800 + 4*900 = 4400: peel kids[0] -> 3700, kids[1] -> 3000,
	// kids[2] -> 2300, kids[3] -> 1600, fits.
	want := []*DirNode{kids[0], kids[1], kids[2], kids[3], root}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("Split roots not in tie-to-lowest-index order: %v", first)
	}
	for run := 0; run < 5; run++ {
		if again := Split(root, smax, smin); !reflect.DeepEqual(again, first) {
			t.Fatalf("run %d: Split output differs across runs", run)
		}
	}
}

func TestShouldMerge(t *testing.T) {
	const smax, smin = 1000, 100
	cases := []struct {
		child, parent int64
		want          bool
	}{
		{50, 900, true},   // under floor, parent absorbs: 900+50-200 = 750
		{150, 500, false}, // child at/over smin never merges
		{50, 1180, false}, // parent would land at 1030 > smax
		{99, 1101, true},  // boundary: 1101+99-200 = 1000 = smax
	}
	for _, tc := range cases {
		if got := ShouldMerge(tc.child, tc.parent, smax, smin); got != tc.want {
			t.Errorf("ShouldMerge(%d, %d) = %v, want %v", tc.child, tc.parent, got, tc.want)
		}
	}
}
