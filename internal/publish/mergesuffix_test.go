package publish

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/superblock"
)

func sizedRefs(sizes ...int64) []superblock.IndexRef {
	refs := make([]superblock.IndexRef, len(sizes))
	for i, s := range sizes {
		refs[i] = superblock.IndexRef{Name: fmt.Sprintf("ref%d", i), Size: s}
	}
	return refs
}

// The tiering rule, checked where it is decided: on sizes alone, before
// anything is fetched. Getting this wrong is not a wrong answer, it is a
// seal quietly re-uploading megabytes every few minutes.
func TestMergeableSuffixTiers(t *testing.T) {
	const (
		k = 1 << 10
		m = 1 << 20
	)
	for _, tc := range []struct {
		what  string
		sizes []int64
		want  int
	}{
		{"dust merges without waiting to be balanced", []int64{4 * k, 4 * k, 4 * k}, 0},
		{"and dust is absorbed by anything still under the floor",
			[]int64{200 * k, 4 * k}, 0},
		{"a tier past the floor is not re-downloaded to absorb dust",
			[]int64{1 * m, 4 * k, 4 * k}, 1},
		{"nor is a large one", []int64{8 * m, 4 * k, 4 * k}, 1},
		// The tier rule proper: an older ref is worth rewriting exactly when
		// the refs behind it weigh what it does.
		{"a tier absorbs the one ahead of it once they balance", []int64{8 * m, 8 * m}, 0},
		{"and not before", []int64{8 * m, 4 * m}, 1},
		{"the sum stops at the ceiling", []int64{40 * m, 40 * m}, 1},
		{"a sizeless ref stops the scan, since its cost is unknown",
			[]int64{4 * k, 0, 4 * k}, 2},
		{"nothing to merge", nil, 0},
	} {
		t.Run(tc.what, func(t *testing.T) {
			refs := sizedRefs(tc.sizes...)
			if got := mergeableSuffix(refs); got != tc.want {
				t.Errorf("mergeableSuffix(%v) = %d, want %d", tc.sizes, got, tc.want)
			}
		})
	}
}

// Whatever it selects, a seal's merge downloads at most one ceiling's
// worth and uploads at most one more. That bound is what makes it safe
// for a small generation to tidy up after itself at all.
func TestMergeableSuffixIsBoundedInBytes(t *testing.T) {
	sizes := make([]int64, 64)
	for i := range sizes {
		sizes[i] = int64(i%7+1) * (4 << 20)
	}
	refs := sizedRefs(sizes...)
	var total int64
	for _, r := range refs[mergeableSuffix(refs):] {
		total += r.Size
	}
	if total > refTargetBytes {
		t.Errorf("a seal would fetch %d bytes of index; the ceiling is %d", total, refTargetBytes)
	}
}

// A merge that cannot be written — a spool with nowhere to put the
// records, a fetch that failed — must leave the refs LISTED. Dropping the
// inputs of a merge that did not happen loses their coverage permanently,
// and for a manifest it loses the packs themselves.
func TestAMergeThatCannotBeWrittenLeavesTheRefsListed(t *testing.T) {
	refs := sizedRefs(4<<10, 4<<10, 4<<10)
	if start := mergeableSuffix(refs); start != 0 {
		t.Fatalf("the fixture does not merge (suffix starts at %d); the test would prove nothing", start)
	}
	out := consolidate(context.Background(), refs, "pack index",
		func(context.Context, []superblock.IndexRef) (superblock.IndexRef, error) {
			return superblock.IndexRef{}, errors.New("spool: no space left on device")
		})
	if len(out) != len(refs) {
		t.Fatalf("a failed merge left %d of %d refs listed", len(out), len(refs))
	}
	for i := range refs {
		if out[i].Name != refs[i].Name {
			t.Errorf("ref %d is %s, want %s: the list was reordered by a merge that did not happen",
				i, out[i].Name, refs[i].Name)
		}
	}
}

// identity is a stand-in for a chunk identity; only the first KeyLen
// bytes reach an index, and the rest is what a caller checks a hit
// against.
func identity(n uint64) [32]byte {
	var id [32]byte
	binary.BigEndian.PutUint64(id[:8], n*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(id[24:], n)
	return id
}

// A tiered consolidation must answer for everything its inputs answered
// for, and answer with the NEWEST placement. A superseded ref is dropped
// from the list and nothing rebuilds it, so coverage lost here is lost
// permanently — and an entry that survived with a stale pack name is
// worse than one that did not survive at all, because the reader stops at
// the first hit and never falls back.
//
// This drives the policy over real indexes, deep enough for the balance
// rule to fire rather than only the dust floor: the end-to-end test in
// indextiers_test.go publishes fixtures whose whole index fits under the
// floor.
func TestTieredConsolidationKeepsEveryIdentityAndTheNewestPlacement(t *testing.T) {
	objects := map[string][]byte{}
	put := func(raw []byte) superblock.IndexRef {
		hash := blake3.Sum256(raw)
		name := hex.EncodeToString(hash[:])
		objects[name] = raw
		return superblock.IndexRef{Name: name, Hash: hash, Size: int64(len(raw))}
	}
	open := func(refs []superblock.IndexRef) []*mpi.Index {
		t.Helper()
		out := make([]*mpi.Index, len(refs))
		for i, r := range refs {
			ix, err := mpi.Open(objects[r.Name])
			if err != nil {
				t.Fatalf("open %s: %v", r.Name[:12], err)
			}
			out[i] = ix
		}
		return out
	}
	merge := func(_ context.Context, refs []superblock.IndexRef) (superblock.IndexRef, error) {
		raw := mpi.Merge(open(refs))
		if raw == nil {
			return superblock.IndexRef{}, errors.New("merge produced nothing")
		}
		return put(raw), nil
	}

	const (
		generations = 60
		perGen      = 2000
		replaced    = 200
	)
	want := map[[32]byte]string{}
	var refs []superblock.IndexRef
	next := uint64(0)
	for gen := 1; gen <= generations; gen++ {
		b := mpi.NewBuilder()
		for i := 0; i < perGen; i++ {
			id, pack := identity(next), fmt.Sprintf("p-%03d-%d", gen, i/500)
			b.Add(id, pack)
			want[id] = pack
			next++
		}
		// Some of the previous generation's objects are written again, which
		// is what makes newest-wins a rule rather than a formality.
		for i := 0; gen > 1 && i < replaced; i++ {
			id, pack := identity(next-2*perGen+uint64(i)), fmt.Sprintf("p-%03d-r", gen)
			b.Add(id, pack)
			want[id] = pack
		}
		refs = consolidate(context.Background(), carryForward(refs, put(b.Encode())), "pack index", merge)
	}

	var listed, largest int64
	for _, r := range refs {
		listed += r.Size
		largest = max(largest, r.Size)
	}
	t.Logf("%d identities over %d generations: %d refs, %s listed, largest %s",
		len(want), generations, len(refs), byteSize(listed), byteSize(largest))
	if largest <= refTierBase {
		t.Fatalf("the largest ref is %s, still under the %s floor: no tier merge happened and this proves nothing",
			byteSize(largest), byteSize(refTierBase))
	}

	set := mpi.NewSet(open(refs))
	for id, pack := range want {
		packs, ok := set.Lookup(id)
		if !ok {
			t.Fatalf("%x was indexed and the consolidated list no longer answers for it", id[:8])
		}
		if len(packs) != 1 || packs[0] != pack {
			t.Fatalf("%x resolves to %v; %s placed it last", id[:8], packs, pack)
		}
	}
}

// tierStats is what a seal spends, accumulated over a volume's life.
type tierStats struct {
	merges int
	// moved is downloaded plus uploaded bytes, which is what a merge costs
	// the seal that performs it.
	moved int64
	// worst is the largest single merge, which is what one unlucky seal
	// waits for.
	worst int64
}

func (s *tierStats) record(total int64) {
	s.merges++
	s.moved += 2 * total
	if total > s.worst {
		s.worst = total
	}
}

// seal appends one generation's index ref and consolidates, under the
// rule that ships. The merged size is the sum of the inputs, which is the
// upper bound the policy itself reasons with — a real merge collapses
// duplicate keys and interns repeated pack names, so it lands under this.
func seal(refs []superblock.IndexRef, size int64, st *tierStats) []superblock.IndexRef {
	added := superblock.IndexRef{Name: fmt.Sprintf("g%d-%d", len(refs), st.merges), Size: size}
	return consolidate(context.Background(), carryForward(refs, added), "pack index",
		func(_ context.Context, in []superblock.IndexRef) (superblock.IndexRef, error) {
			var total int64
			for _, r := range in {
				total += r.Size
			}
			st.record(total)
			return superblock.IndexRef{Name: fmt.Sprintf("m%d", st.merges), Size: total}, nil
		})
}

// frozenAtTarget is the rule this replaced, kept so the measurement below
// has a before column: merge the newest run of refs that are all under
// half a 2 MiB target and sum to within it, which freezes a ref at about
// a megabyte and never touches it again.
func frozenAtTarget(refs []superblock.IndexRef) int {
	const (
		target   = 2 << 20
		maxInput = target / 2
	)
	start, total := len(refs), int64(0)
	for i := len(refs) - 1; i >= 0; i-- {
		if size := refs[i].Size; size <= 0 || size > maxInput || total+size > target {
			break
		}
		total += refs[i].Size
		start = i
	}
	return start
}

func sealFrozen(refs []superblock.IndexRef, size int64, st *tierStats) []superblock.IndexRef {
	refs = carryForward(refs, superblock.IndexRef{Name: fmt.Sprintf("g%d-%d", len(refs), st.merges), Size: size})
	start := frozenAtTarget(refs)
	if len(refs)-start < 2 {
		return refs
	}
	var total int64
	for _, r := range refs[start:] {
		total += r.Size
	}
	st.record(total)
	return append(append([]superblock.IndexRef{}, refs[:start]...),
		superblock.IndexRef{Name: fmt.Sprintf("m%d", st.merges), Size: total})
}

// THE NUMBER THIS CHANGE IS ABOUT: how many refs a generation lists
// against how large the volume is.
//
// Every listed ref is an object a mount fetches, so the ref count is what
// a mount pays in round trips before it can answer anything. Freezing a
// ref at the target stopped the list growing with GENERATIONS but left it
// growing with SIZE — one ref per megabyte of index, hundreds of parallel
// fetches at a hundred million objects. Tiers make it the logarithm of
// the size instead, up to the ceiling.
//
// The volume is driven by index BYTES, at the 16 bytes per entry the
// format costs (mpi), so the object counts in the table are real ones.
func TestRefCountGrowsWithTheLogOfVolumeSize(t *testing.T) {
	const (
		perGeneration = 64 << 10 // ~4,000 objects published per seal
		entryBytes    = 16
		generations   = 25600 // 1.6 GB of index: a hundred million objects
	)
	var tiered, frozen []superblock.IndexRef
	var tieredStats, frozenStats tierStats

	type row struct{ at, tiered, frozen int }
	var rows []row
	milestone := int64(1 << 20)
	for g := 1; g <= generations; g++ {
		tiered = seal(tiered, perGeneration, &tieredStats)
		frozen = sealFrozen(frozen, perGeneration, &frozenStats)
		if total := int64(g) * perGeneration; total >= milestone {
			rows = append(rows, row{int(total), len(tiered), len(frozen)})
			milestone *= 4
		}
	}
	rows = append(rows, row{generations * perGeneration, len(tiered), len(frozen)})

	t.Logf("%-12s %-14s %-10s %s", "index bytes", "objects", "refs (was)", "refs (now)")
	for _, r := range rows {
		t.Logf("%-12s %-14d %-10d %d", byteSize(int64(r.at)), int64(r.at)/entryBytes, r.frozen, r.tiered)
	}
	t.Logf("over %d generations: %d merges moving %s (was %d merges moving %s)",
		generations, tieredStats.merges, byteSize(tieredStats.moved),
		frozenStats.merges, byteSize(frozenStats.moved))
	t.Logf("largest single merge: %s (was %s)", byteSize(tieredStats.worst), byteSize(frozenStats.worst))

	last := rows[len(rows)-1]
	if last.tiered*10 > last.frozen {
		t.Errorf("at %s of index the tiered list is %d refs and the frozen one %d; tiers bought nothing",
			byteSize(int64(last.at)), last.tiered, last.frozen)
	}
	// The shape, measured where the ceiling is not yet in play: 64x the
	// volume must not be 64x the refs. Six is log2(64) with room for the
	// partially filled tiers a list carries between merges.
	var small, large int
	for _, r := range rows {
		if r.at == 4<<20 {
			small = r.tiered
		}
		if r.at == 256<<20 {
			large = r.tiered
		}
	}
	if small == 0 || large == 0 {
		t.Fatal("the milestones the shape is measured between were not reached")
	}
	if large > small+6 {
		t.Errorf("4 MiB of index lists %d refs and 256 MiB lists %d: 64x the volume added %d refs, which is not logarithmic",
			small, large, large-small)
	}
	if tieredStats.worst > refTargetBytes {
		t.Errorf("one seal merged %s, past the %s a seal is allowed to pay",
			byteSize(tieredStats.worst), byteSize(refTargetBytes))
	}
	if tieredStats.moved > frozenStats.moved {
		t.Errorf("tiering moved %s against the frozen rule's %s; it is meant to rewrite each byte fewer times",
			byteSize(tieredStats.moved), byteSize(frozenStats.moved))
	}
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
