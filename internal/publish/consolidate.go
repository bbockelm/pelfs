package publish

import (
	"context"

	"github.com/bbockelm/pelfs/internal/ui"
)

// Tiering the derived key spaces: which refs a seal folds together,
// written once and applied to both of them.
//
// A superblock lists pack indexes (internal/mpi) and pack manifests
// (internal/manifest) the same way — a growing list of hash-named,
// size-tiered segments, each generation appending its own and carrying
// its predecessor's forward. They answer different questions, but none of
// the reasons a seal must not spend much tidying that list depend on
// which one it is: the cost of a long list is a round trip per ref at
// mount, and the cost of shortening it is a download and an upload. So
// the policy lives here, generic over the ref, and each key space
// supplies only what actually differs — how to merge its objects.
//
// What a ref must offer is what the policy reads WITHOUT fetching: a name
// and a size. Both come off the superblock structs as methods rather than
// fields, because a Go type parameter can call the one and not reach the
// other (superblock.IndexRef).
type sizedRef interface {
	RefName() string
	RefSize() int64
}

// refTargetBytes is the size consolidation aims a merged object at.
//
// It is the pack cut for a reason: an index or a manifest is fetched
// WHOLE today, so its size is what consulting it costs, and holding it
// near a pack keeps that comparable to fetching one pack. When these are
// read through ranged windows instead, this is the number that should
// grow.
const refTargetBytes = 2 << 20

// refMergeMaxInput is the largest ref consolidation will fold in: past
// half the target a ref counts as a large tier rather than a small one
// waiting to be absorbed. Half, so that two candidates always still fit.
const refMergeMaxInput = refTargetBytes / 2

// consolidate merges the newest refs into one and returns the list the
// superblock should record — refs it merged are simply no longer listed.
//
// NOT DELETED. Retention decides when one of these objects goes, and a
// generation still inside the retain window names the ones this list
// drops; deleting them here would break a generation that is still
// perfectly live.
//
// BOUNDING THE WORK. A small generation must never pay a large re-upload
// to tidy the list, so the rule is stated as what it refuses to do:
//
//   - It refuses to touch a ref that is already large — past half the
//     target. Absorbing a 4 KiB generation into a 2 MiB tier would
//     re-download and re-upload 2 MiB to save one round trip, and a
//     checkpointing mount would pay that every few minutes forever. The
//     scan STOPS at such a ref rather than skipping past it.
//   - It refuses to produce an object past the target. Inputs are taken
//     newest-first only while their sizes sum to within it, and that sum
//     is an upper bound on the result: a merge's keys are the union of
//     its inputs' and its values a subset of theirs.
//   - It refuses to merge anything but a SUFFIX of the list. Lookups are
//     newest-wins in both key spaces (mpi.Set, manifest.Set), so a merge
//     that reached past a ref would move older answers ahead of newer
//     ones.
//
// So a seal downloads at most one target's worth — in parallel, one round
// trip of latency — and uploads at most one more, per key space. That is
// the cost a seal pays to tidy up after itself, and it is why the bound
// is stated in bytes rather than in refs.
//
// What this does NOT do: grow tiers geometrically. Once a ref reaches the
// target it is frozen here, so the list stops growing with the number of
// GENERATIONS and starts growing with the volume's size instead. Merging
// those into larger tiers means a merge that outgrows memory, which wants
// the spooling encoder neither mpi.Merge nor manifest.Merge has.
func consolidate[T sizedRef](ctx context.Context, refs []T, what string, merge func(context.Context, []T) (T, error)) []T {
	start := mergeableSuffix(refs)
	if len(refs)-start < 2 {
		return refs
	}
	merged, err := merge(ctx, refs[start:])
	if err != nil {
		// A failed merge costs this generation a longer list and nothing
		// else: the unmerged refs still name objects that still answer, and
		// the next seal tries again. That holds for manifests too, where
		// the refs are not optional — consolidation only ever CHANGES how
		// the same pack set is named, so declining to change it is safe in
		// a way that failing to write one is not.
		ui.Warn("publish: {what} refs not consolidated ({error}); this generation lists them unmerged",
			"what", what, "error", err)
		return refs
	}
	return append(append([]T{}, refs[:start]...), merged)
}

// mergeableSuffix is where the refs worth merging start: the newest run
// that is all small and sums to within the target. It reads sizes alone,
// so the decision costs nothing — the fetch only happens once the answer
// says two or more refs are worth it.
func mergeableSuffix[T sizedRef](refs []T) int {
	start, total := len(refs), int64(0)
	for i := len(refs) - 1; i >= 0; i-- {
		if size := refs[i].RefSize(); size <= 0 || size > refMergeMaxInput || total+size > refTargetBytes {
			break
		}
		total += refs[i].RefSize()
		start = i
	}
	return start
}

// carryForward is what the superblock records: the previous generation's
// refs, plus this one's.
//
// Carrying forward is not bookkeeping. For an index it is the same rule
// as the pack list once was — an index a live generation names must not
// be swept, and the packs a carried index covers are exactly the packs
// this generation carried forward. For a manifest it is stronger still:
// the carried refs ARE how this generation names the packs it inherited,
// so dropping one does not cost speed, it drops packs out of the live set
// and lets the next sweep delete live data.
func carryForward[T sizedRef](prev []T, added T) []T {
	var out []T
	out = append(out, prev...)
	if added.RefName() == "" {
		return out
	}
	// Content-addressed: a generation that produced the same bytes produced
	// the same name, and listing it twice would make a reader fetch it
	// twice.
	for _, r := range out {
		if r.RefName() == added.RefName() {
			return out
		}
	}
	return append(out, added)
}
