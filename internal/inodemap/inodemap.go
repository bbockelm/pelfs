// Package inodemap renumbers one volume's inodes into lineages another
// volume owns.
//
// # Why this exists
//
// An inode is a lineage in its high bits and a counter in its low 40
// (superblock.InodeLineageShift). Every volume starts allocating from
// lineage 0 at superblock.FirstInode(0) == 2, so TWO VOLUMES COLLIDE BY
// CONSTRUCTION: their roots are both inode 1, their first files are both
// inode 2, and nothing about either number says which volume meant it.
// Anything that carries a tree from one volume into another — `pelfs
// import`, and the renumbering docs/known-issues.md KL-7 has been waiting
// for — has to renumber one side before the two trees can share a
// namespace.
//
// # The scheme
//
// One destination lineage per SOURCE lineage, and the low 40 bits are
// left alone:
//
//	Remap(ino) = uint64(to[LineageOf(ino)])<<InodeLineageShift | (ino & counterMask)
//
// That is the whole of it, and three properties follow immediately rather
// than needing an argument.
//
//   - INJECTIVE. The counter half is carried through untouched, and the
//     lineage half is a bijection on the lineages the map declares. So
//     Remap(a) == Remap(b) forces both halves equal, which forces a == b.
//     Injectivity is the property hardlinks rest on: two paths naming one
//     inode still name one inode afterwards, which is what makes the
//     destination's seal promote it into an inode shard exactly as the
//     source did. It is also what keeps the destination's directory
//     structure a tree rather than a graph.
//   - SIGNED-64-BIT SAFE. Destination lineages are drawn at or below
//     superblock.MaxLineage, which is 23 bits precisely so that every
//     inode fits in an int64 — inodes are uint64 in the format and int64
//     in SQLite, and a lineage with the top bit set round-trips as a
//     negative number and fails to scan back. Draw refuses anything
//     above it and Check refuses a map that carries one, so a map that
//     verifies cannot produce an inode a catalog cannot store.
//   - ORDER-PRESERVING WITHIN A LINEAGE. Shards route promoted inodes by
//     contiguous inode RANGE, so a scheme that scattered one lineage's
//     inodes would turn one shard into many. Carrying the counter
//     through keeps a source lineage's inodes contiguous in the
//     destination, which is why a shard list after an import looks like
//     a shard list.
//
// # Why not a contiguous slab
//
// The cheap alternative is to reserve a slab and map their L to base + L,
// which needs only their highest lineage. It is refused: lineages are
// DRAWN BY HASHING (cmd/pelfs/branch.go pickLineage), so they are large
// and sparse by construction, and a source whose highest lineage happened
// to be 5678 would consume 5,679 of the destination's. A row per lineage
// actually used costs a few bytes each and consumes exactly what the
// source contains.
//
// # The guard, which is the part that fails closed
//
// Nothing in the format records the set of lineages a tree contains.
// Fork.Lineage names the lineage a generation ALLOCATES FROM;
// Catalogs[].Inode samples whichever directories happen to root a
// catalog; Shards cover only promoted inodes. A tree that was merged from
// a third branch holds that branch's lineage and no field mentions it. So
// the map cannot be derived from a superblock and has to come from
// WALKING the source's catalogs — and a walk can be raced by the source
// gaining a lineage between the scan and the copy.
//
// Remap therefore takes the map as a closed set and REFUSES an inode
// whose lineage it does not declare. Never a fallback, never a default
// lineage: passing an unmapped inode through untranslated is silent
// aliasing, and a loud refusal is recoverable where a quiet alias is not.
package inodemap

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// counterMask is the low half of an inode: the allocation counter, which
// a remap carries through unchanged.
const counterMask = uint64(1)<<superblock.InodeLineageShift - 1

// ErrUndeclaredLineage is what Remap returns for an inode in a lineage
// the map does not declare. It is a sentinel because the callers that
// have something to say about it — a scan that can be re-run, an import
// that must stop — need to tell it apart from an I/O error.
var ErrUndeclaredLineage = errors.New("inodemap: source inode is in a lineage this map does not declare")

// Map is one renumbering: a total function from the source lineages it
// declares onto destination lineages, and undefined everywhere else.
//
// It is deliberately not a map[uint64]uint64 over inodes. A tree has
// hundreds of millions of inodes and a handful of lineages, so the
// per-lineage form is the difference between a few dozen bytes in a
// signed superblock and a table nothing could carry.
type Map struct {
	to map[uint32]uint32
}

// New builds a map from source-lineage to destination-lineage pairs and
// checks it before returning it. A map that does not verify never exists,
// so no caller has to remember to check one.
func New(pairs map[uint32]uint32) (*Map, error) {
	m := &Map{to: make(map[uint32]uint32, len(pairs))}
	for from, to := range pairs {
		m.to[from] = to
	}
	if err := m.Check(); err != nil {
		return nil, err
	}
	return m, nil
}

// Check refuses a map that is not a bijection onto lineages that fit, and
// names which pair is at fault.
//
// A NON-INJECTIVE MAP IS THE ONE FAILURE WORTH REFUSING UP FRONT, because
// its symptom is not an error. Two source lineages folded onto one
// destination lineage produce two distinct source inodes with equal
// counters landing on the same destination inode: two unrelated files
// silently become hardlinks of each other, in a signed generation that
// mounts and reads. Nothing downstream can detect it — an inode number
// that two paths share IS what a hardlink is.
func (m *Map) Check() error {
	if len(m.to) == 0 {
		return errors.New("inodemap: the map declares no lineages, so it can renumber nothing")
	}
	seen := make(map[uint32]uint32, len(m.to))
	for _, from := range m.sources() {
		to := m.to[from]
		if to > superblock.MaxLineage {
			return fmt.Errorf("inodemap: lineage %d maps to %d, above the %d ceiling that keeps every "+
				"inode inside a signed 64-bit integer (inodes are int64 in SQLite)",
				from, to, superblock.MaxLineage)
		}
		if other, dup := seen[to]; dup {
			return fmt.Errorf("inodemap: lineages %d and %d both map to %d; folding two lineages onto "+
				"one makes unrelated files with equal counters into hardlinks of each other, which "+
				"nothing downstream can detect", other, from, to)
		}
		seen[to] = from
	}
	return nil
}

// Remap is the renumbering. It refuses an inode whose lineage the map
// does not declare rather than passing it through or folding it into a
// default, for the reason the package comment gives.
func (m *Map) Remap(ino uint64) (uint64, error) {
	from := superblock.LineageOf(ino)
	to, ok := m.to[from]
	if !ok {
		return 0, fmt.Errorf("%w: inode %d is in lineage %d (declared: %v); re-scan the source to "+
			"pick up the lineages it has gained since the map was built",
			ErrUndeclaredLineage, ino, from, m.sources())
	}
	return uint64(to)<<superblock.InodeLineageShift | ino&counterMask, nil
}

// Declares reports whether the map covers a source lineage.
func (m *Map) Declares(lineage uint32) bool { _, ok := m.to[lineage]; return ok }

// Len is how many lineages the map declares.
func (m *Map) Len() int { return len(m.to) }

// Sources are the source lineages, ascending.
func (m *Map) Sources() []uint32 { return m.sources() }

func (m *Map) sources() []uint32 {
	out := make([]uint32, 0, len(m.to))
	for from := range m.to {
		out = append(out, from)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Destinations are the destination lineages, ascending. They are what the
// importing volume must record as taken, or a later `pelfs branch` will
// draw one of them and start handing out numbers this tree already uses.
func (m *Map) Destinations() []uint32 {
	out := make([]uint32, 0, len(m.to))
	for _, from := range m.sources() {
		out = append(out, m.to[from])
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Pairs is the map as rows, ascending by source, for recording in a
// superblock.
func (m *Map) Pairs() []superblock.LineagePair {
	out := make([]superblock.LineagePair, 0, len(m.to))
	for _, from := range m.sources() {
		out = append(out, superblock.LineagePair{From: from, To: m.to[from]})
	}
	return out
}

// FromPairs rebuilds a map from what a superblock recorded.
func FromPairs(rows []superblock.LineagePair) (*Map, error) {
	pairs := make(map[uint32]uint32, len(rows))
	for _, r := range rows {
		if _, dup := pairs[r.From]; dup {
			return nil, fmt.Errorf("inodemap: lineage %d is mapped twice", r.From)
		}
		pairs[r.From] = r.To
	}
	return New(pairs)
}

// MarkAbove is the allocator high-water mark a tree renumbered by this map
// requires: one past the highest inode any of its lineages can hold that
// the source had actually allocated.
//
// It takes the source's own mark per lineage rather than inferring from
// what the tree contains, for the reason publish.InodeMarker exists: a
// number the source burned on a file it then deleted is a number that must
// stay burned, and a walk cannot see it.
//
// The mark it returns is in the DESTINATION's numbering and is only ever a
// floor — publish floors it again against the previous generation's, which
// is what keeps a branch from ever reusing a number it has handed out.
func (m *Map) MarkAbove(sourceMark uint64) (uint64, error) {
	if sourceMark == 0 {
		return 0, nil
	}
	// The source's mark belongs to the lineage the source allocates from.
	// If the map does not declare that lineage — a source whose allocator
	// sits in a lineage no file in the tree happens to use — the mark
	// cannot be translated and the caller falls back to max-inode-seen,
	// which publish computes for itself.
	from := superblock.LineageOf(sourceMark)
	if !m.Declares(from) {
		return 0, nil
	}
	return m.Remap(sourceMark)
}

// Draw picks n destination lineages that taken rejects and that do not
// repeat each other, and returns them ascending.
//
// It is the SAME draw cmd/pelfs/branch.go pickLineage makes, and it must
// stay that way: random rather than counted, because a counter would have
// to live somewhere two writers can both see and be incremented under a
// lock neither holds, and not name-derived, because a name reused would
// draw a slice whose numbers a tag still names.
//
// taken is a PREDICATE rather than a set, and that is not decoration.
// The set it stands for is 23 bits wide, so a caller that has to answer
// "is every lineage taken" — the exhaustion case, and the only case where
// the answer is interesting — would otherwise have to materialize eight
// million rows to ask a question with a one-word answer.
//
// Lineage 0 is never drawn whatever the predicate says: it is every
// volume's original lineage and is taken by construction on every volume
// there has ever been.
func Draw(n int, taken func(uint32) bool) ([]uint32, error) {
	if n <= 0 {
		return nil, nil
	}
	if taken == nil {
		taken = func(uint32) bool { return false }
	}
	// 23 bits of lineage is 8,388,607 draws; a volume with a hundred taken
	// collides about once in 84,000 tries. The bound is for correctness,
	// not for luck, and it scales with n so that drawing many at once is
	// not held to a budget sized for drawing one.
	budget := 1000 * n
	out := make([]uint32, 0, n)
	drawn := make(map[uint32]bool, n)
	for range budget {
		if len(out) == n {
			break
		}
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		l := binary.BigEndian.Uint32(b[:]) & superblock.MaxLineage
		if l == 0 || drawn[l] || taken(l) {
			continue
		}
		drawn[l] = true
		out = append(out, l)
	}
	if len(out) != n {
		return nil, fmt.Errorf("inodemap: could only draw %d of %d unused inode lineages in %d "+
			"attempts against the %d that exist; this volume's branches, tags and imports have "+
			"taken so many that a random draw no longer finds a free one",
			len(out), n, budget, superblock.MaxLineage)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// TakenIn turns a set of taken lineages into the predicate Draw wants.
// It is here rather than at each call site because every caller has a set
// and the closure is the same three words each time.
func TakenIn(set map[uint32]bool) func(uint32) bool {
	return func(l uint32) bool { return set[l] }
}

// DrawFor builds a map that renumbers each of sources into a lineage
// taken names as free. The pairing is ascending-to-ascending, which makes
// a map reproducible from its inputs for anything that has to report one.
func DrawFor(sources []uint32, taken func(uint32) bool) (*Map, error) {
	uniq := make(map[uint32]bool, len(sources))
	var ordered []uint32
	for _, s := range sources {
		if !uniq[s] {
			uniq[s] = true
			ordered = append(ordered, s)
		}
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	drawn, err := Draw(len(ordered), taken)
	if err != nil {
		return nil, err
	}
	pairs := make(map[uint32]uint32, len(ordered))
	for i, s := range ordered {
		pairs[s] = drawn[i]
	}
	return New(pairs)
}

// Unmap is Remap's inverse: the source inode a renumbered inode came
// from. It exists because the renumbered tree is served BY the source —
// every Readdir, Stat, Readlink and read of an imported inode has to be
// asked of the source volume under the number the source knows it by.
//
// It is well defined precisely because Remap is injective, which Check
// guarantees before a map exists.
func (m *Map) Unmap(ino uint64) (uint64, error) {
	to := superblock.LineageOf(ino)
	for from, cand := range m.to {
		if cand == to {
			return uint64(from)<<superblock.InodeLineageShift | ino&counterMask, nil
		}
	}
	return 0, fmt.Errorf("inodemap: inode %d is in destination lineage %d, which this map did not "+
		"produce (produced: %v)", ino, to, m.Destinations())
}

// Holds reports whether an inode is one this map produced — the routing
// question a splice asks of every inode it is handed: "is this one of
// mine, or the destination volume's own?".
//
// It is a lineage test rather than an arithmetic comparison, which is the
// difference between this and a graft splice's shifted range. The lineages
// a map draws are ones the destination volume does not use, so the two
// spaces are disjoint by construction and the test cannot be fooled by a
// tree that grew.
func (m *Map) Holds(ino uint64) bool {
	to := superblock.LineageOf(ino)
	for _, cand := range m.to {
		if cand == to {
			return true
		}
	}
	return false
}
