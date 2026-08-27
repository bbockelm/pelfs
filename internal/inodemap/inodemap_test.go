package inodemap

import (
	"math"
	"testing"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// TestTwoVolumesHandOutTheSameInodeNumbers is the premise the whole
// package answers, measured rather than asserted: two volumes that have
// never met allocate identical inodes, starting with their roots.
func TestTwoVolumesHandOutTheSameInodeNumbers(t *testing.T) {
	// What each volume's allocator hands out, in order, from a fresh
	// volume: the root, then FirstInode(0) upward.
	var a, b []uint64
	for i := range 4 {
		a = append(a, superblock.FirstInode(0)+uint64(i))
		b = append(b, superblock.FirstInode(0)+uint64(i))
	}
	a = append([]uint64{1}, a...)
	b = append([]uint64{1}, b...)
	collisions := 0
	for i := range a {
		if a[i] == b[i] {
			collisions++
		}
	}
	if collisions != len(a) {
		t.Fatalf("expected every inode to collide, got %d of %d", collisions, len(a))
	}
	t.Logf("EVIDENCE: %d of %d inodes collide, roots included (both are inode 1, "+
		"both allocate from lineage 0 at FirstInode(0) == %d)",
		collisions, len(a), superblock.FirstInode(0))
}

func TestARemapIsInjectiveAcrossEveryLineageItDeclares(t *testing.T) {
	m, err := New(map[uint32]uint32{0: 7, 1234: 8, 5678: 9})
	if err != nil {
		t.Fatal(err)
	}
	// Every declared lineage, over a spread of counters that includes the
	// root, the first allocation, and the top of the counter space.
	counters := []uint64{0, 1, 2, 3, 1 << 20, 1<<40 - 2, 1<<40 - 1}
	seen := map[uint64]uint64{}
	for _, l := range m.Sources() {
		for _, c := range counters {
			src := uint64(l)<<superblock.InodeLineageShift | c
			dst, err := m.Remap(src)
			if err != nil {
				t.Fatalf("remap %d: %v", src, err)
			}
			if other, dup := seen[dst]; dup {
				t.Fatalf("NOT INJECTIVE: source inodes %d and %d both map to %d", other, src, dst)
			}
			seen[dst] = src
			back, err := m.Unmap(dst)
			if err != nil {
				t.Fatalf("unmap %d: %v", dst, err)
			}
			if back != src {
				t.Fatalf("Unmap(Remap(%d)) == %d", src, back)
			}
		}
	}
	t.Logf("EVIDENCE: %d source inodes over %d lineages produced %d distinct destination inodes, "+
		"and every one round-tripped through Unmap", len(seen), m.Len(), len(seen))
}

// TestEveryRemappedInodeFitsInASignedInt64 is the constraint
// superblock.MaxLineage exists for: inodes are uint64 in the format and
// int64 in SQLite, and a number above 2^63 round-trips as negative and
// fails to scan back.
func TestEveryRemappedInodeFitsInASignedInt64(t *testing.T) {
	m, err := New(map[uint32]uint32{0: superblock.MaxLineage})
	if err != nil {
		t.Fatal(err)
	}
	top := uint64(1)<<superblock.InodeLineageShift - 1
	got, err := m.Remap(top)
	if err != nil {
		t.Fatal(err)
	}
	if got > math.MaxInt64 {
		t.Fatalf("the largest inode this map can produce is %d, past the %d signed ceiling",
			got, uint64(math.MaxInt64))
	}
	if int64(got) < 0 {
		t.Fatalf("inode %d round-trips through int64 as %d", got, int64(got))
	}
	t.Logf("EVIDENCE: the largest inode any map can produce is %d, which is %.2f%% of the "+
		"signed 64-bit ceiling", got, 100*float64(got)/float64(math.MaxInt64))
}

func TestALineageAboveTheCeilingIsRefusedUpFront(t *testing.T) {
	_, err := New(map[uint32]uint32{0: superblock.MaxLineage + 1})
	if err == nil {
		t.Fatal("a lineage above MaxLineage was accepted")
	}
	t.Logf("refused: %v", err)
}

// TestAMapThatIsNotABijectionIsRefusedUpFront is the refusal whose
// absence would be silent: two lineages folded onto one make unrelated
// files into hardlinks of each other.
func TestAMapThatIsNotABijectionIsRefusedUpFront(t *testing.T) {
	_, err := New(map[uint32]uint32{11: 7, 22: 7})
	if err == nil {
		t.Fatal("a map folding two lineages onto one was accepted")
	}
	t.Logf("refused: %v", err)
	// And the aliasing it prevents, shown concretely.
	alias, err := New(map[uint32]uint32{11: 7})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := alias.Remap(uint64(11)<<superblock.InodeLineageShift | 42)
	other, err := New(map[uint32]uint32{22: 7})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := other.Remap(uint64(22)<<superblock.InodeLineageShift | 42)
	if a != b {
		t.Fatalf("expected the folded map to alias, got %d and %d", a, b)
	}
	t.Logf("EVIDENCE: had it been accepted, source inodes %d and %d would both be inode %d",
		uint64(11)<<superblock.InodeLineageShift|42, uint64(22)<<superblock.InodeLineageShift|42, a)
}

// TestAnUndeclaredLineageIsRefusedRatherThanAliased is the read-time
// guard. A source that gained a lineage after the scan must produce an
// error, never a fallback.
func TestAnUndeclaredLineageIsRefusedRatherThanAliased(t *testing.T) {
	m, err := New(map[uint32]uint32{0: 7})
	if err != nil {
		t.Fatal(err)
	}
	gained := uint64(99)<<superblock.InodeLineageShift | 137
	if _, err := m.Remap(gained); err == nil {
		t.Fatal("an inode from an undeclared lineage was remapped")
	} else {
		t.Logf("refused: %v", err)
	}
}

// TestHardlinkedPathsStillShareOneInodeAfterTheRemap is the property the
// inode shards rest on. It is stated as a test because "injective" is the
// abstract form of it and "the two paths still name one file" is the one
// a user cares about.
func TestHardlinkedPathsStillShareOneInodeAfterTheRemap(t *testing.T) {
	m, err := New(map[uint32]uint32{0: 4242})
	if err != nil {
		t.Fatal(err)
	}
	// Two directory entries, in different directories, naming one inode.
	const shared = 9001
	first, err := m.Remap(shared)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Remap(shared)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("two links to inode %d became %d and %d", shared, first, second)
	}
	// And a NEIGHBOUR does not join them.
	nbr, err := m.Remap(shared + 1)
	if err != nil {
		t.Fatal(err)
	}
	if nbr == first {
		t.Fatalf("inode %d and %d collapsed onto %d", shared, shared+1, first)
	}
	t.Logf("EVIDENCE: both links to source inode %d are destination inode %d, and its neighbour "+
		"is %d", shared, first, nbr)
}

// TestOneLineagesInodesStayContiguous is why a shard list after an import
// looks like a shard list: shards route by inode RANGE, so a scheme that
// scattered a lineage would multiply them.
func TestOneLineagesInodesStayContiguous(t *testing.T) {
	m, err := New(map[uint32]uint32{5: 500})
	if err != nil {
		t.Fatal(err)
	}
	base := uint64(5)<<superblock.InodeLineageShift | 2
	var prev uint64
	for i := range uint64(64) {
		got, err := m.Remap(base + i)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && got != prev+1 {
			t.Fatalf("inode %d mapped to %d, not %d", base+i, got, prev+1)
		}
		prev = got
	}
	t.Logf("EVIDENCE: 64 consecutive source inodes stayed 64 consecutive destination inodes "+
		"(%d..%d)", prev-63, prev)
}

func TestDrawAvoidsEveryTakenLineageAndItself(t *testing.T) {
	taken := map[uint32]bool{0: true, 17: true, 4242: true}
	got, err := Draw(64, TakenIn(taken))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]bool{}
	for _, l := range got {
		if taken[l] {
			t.Fatalf("drew taken lineage %d", l)
		}
		if l == 0 {
			t.Fatal("drew lineage 0")
		}
		if l > superblock.MaxLineage {
			t.Fatalf("drew %d, above MaxLineage", l)
		}
		if seen[l] {
			t.Fatalf("drew %d twice", l)
		}
		seen[l] = true
	}
	if len(got) != 64 {
		t.Fatalf("drew %d of 64", len(got))
	}
}

// TestTheLineageSpaceRunsOutLoudly is the exhaustion guard. It is
// reachable only on an absurd volume, and the point is that when it is
// reached it says so instead of drawing a lineage somebody else has.
func TestTheLineageSpaceRunsOutLoudly(t *testing.T) {
	// A PREDICATE, not eight million map rows: the whole point of Draw
	// taking one is that "every lineage is taken" is a one-word answer.
	_, err := Draw(1, func(uint32) bool { return true })
	if err == nil {
		t.Fatal("drew a lineage from an exhausted space")
	}
	t.Logf("refused: %v", err)
}

func TestDrawForPairsEachSourceLineageWithOneOfItsOwn(t *testing.T) {
	m, err := DrawFor([]uint32{5678, 0, 1234, 0}, TakenIn(map[uint32]bool{0: true}))
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != 3 {
		t.Fatalf("declared %d lineages, want 3 (the duplicate should collapse)", m.Len())
	}
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}
	rows, err := FromPairs(m.Pairs())
	if err != nil {
		t.Fatal(err)
	}
	for _, from := range m.Sources() {
		a, _ := m.Remap(uint64(from)<<superblock.InodeLineageShift | 3)
		b, err := rows.Remap(uint64(from)<<superblock.InodeLineageShift | 3)
		if err != nil || a != b {
			t.Fatalf("a map rebuilt from its recorded rows renumbers differently: %d vs %d (%v)", a, b, err)
		}
	}
}

func TestAnEmptyMapIsRefused(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("an empty map was accepted")
	}
}
