package publish

import (
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/mpi"
)

func sizedRefs(sizes ...int64) []mpi.Ref {
	refs := make([]mpi.Ref, len(sizes))
	for i, s := range sizes {
		refs[i] = mpi.Ref{Name: fmt.Sprintf("ref%d", i), Size: s}
	}
	return refs
}

// The refusals the consolidation rule is built out of, checked where they
// are decided: on sizes alone, before anything is fetched. Getting this
// wrong is not a wrong answer, it is a seal quietly re-uploading megabytes
// every few minutes.
func TestMergeableSuffixRefusals(t *testing.T) {
	const k = 1 << 10
	for _, tc := range []struct {
		what  string
		sizes []int64
		want  int
	}{
		{"small refs all merge", []int64{4 * k, 4 * k, 4 * k}, 0},
		{"a large tier is not re-downloaded to absorb a small one",
			[]int64{4 * k, indexMergeMaxInput + 1, 4 * k, 4 * k}, 2},
		// The scan stops at the newest ref, so the smaller ones behind it
		// stay listed: merging them would reach past a newer ref, and
		// lookups are newest-wins.
		{"a large newest ref merges with nothing",
			[]int64{4 * k, 4 * k, indexMergeMaxInput + 1}, 3},
		{"the sum stops at the target",
			[]int64{700 * k, 700 * k, 700 * k, 700 * k}, 2},
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

// Whatever it selects, a seal's merge downloads at most one index's worth
// and uploads at most one more. That bound is the whole reason a small
// generation can afford to tidy up after itself.
func TestMergeableSuffixIsBoundedInBytes(t *testing.T) {
	sizes := make([]int64, 64)
	for i := range sizes {
		sizes[i] = int64(i%7+1) * (64 << 10)
	}
	refs := sizedRefs(sizes...)
	var total int64
	for _, r := range refs[mergeableSuffix(refs):] {
		total += r.Size
	}
	if total > indexTargetBytes {
		t.Errorf("a seal would fetch %d bytes of index; the target is %d", total, indexTargetBytes)
	}
}
