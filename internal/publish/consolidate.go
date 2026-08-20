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

// refTargetBytes is the LARGEST object consolidation will build, and so
// the most a single seal can be asked to download and upload per key
// space. Tiers grow geometrically up to it and freeze there.
//
// It is not the pack cut any more, and the reason it was — an index is
// fetched WHOLE today, so its size is what consulting it costs — turns
// out not to argue for small tiers at all: a mount fetches EVERY ref it
// is listed, so the bytes it moves are the whole index set however that
// set is cut up. What tiering changes is the number of round trips, and
// there a large tier is strictly better.
//
// What the ceiling is really set by is the seal, in two ways. It is what
// one seal may spend — download, merge, upload — on work it did not ask
// for, in the middle of a checkpoint a user is waiting on. And it is the
// seal's peak memory, though no longer because of the OUTPUT: mergeIndexes
// and mergeManifests spool the merged object to a file, hash it on the way
// through and upload from that file, so the result never sits in memory
// whatever size it reaches. What does sit in memory is the INPUTS, because
// mpi.FetchAll and manifest.FetchAll read each segment whole to verify it
// against the hash the superblock signed — a merge therefore holds up to
// refTargetBytes of inputs at once, and that is the binding constraint on
// raising this number. Verifying a segment without holding it (a windowed,
// incrementally-checked read, which the packidx form already supports for
// LOOKUPS) is what a larger ceiling would have to address first, and with
// it the frozen tail below.
const refTargetBytes = 64 << 20

// refTierBase is the size below which refs are dust: a run summing to
// within it merges unconditionally, without waiting for the balance rule.
//
// Without a floor the rule below turns a volume's first hundred small
// generations into a binary counter — several refs where one would do,
// each of them kilobytes, which is round trips spent on nothing. With a
// floor a volume whose whole index fits in one keeps the single-ref
// behaviour it has today, and geometry starts where the sizes do.
//
// The floor is NOT free, and its cost is why it is 256 KiB rather than
// the 2 MiB the old target was. Inside it the old policy is still in
// force: every seal re-merges the whole run, so each byte below the floor
// is rewritten about (floor / generation) times. Measured over 25,600
// generations, a 2 MiB floor moved 59 GiB and a 256 KiB floor 19.5 GiB
// for exactly the same ref counts (TestRefCountGrowsWithTheLogOfVolumeSize).
const refTierBase = 256 << 10

// consolidate merges the newest refs into one and returns the list the
// superblock should record — refs it merged are simply no longer listed.
//
// NOT DELETED. Retention decides when one of these objects goes, and a
// generation still inside the retain window names the ones this list
// drops; deleting them here would break a generation that is still
// perfectly live.
//
// THE RULE, which is one sentence and three guards. Scanning from the
// NEWEST ref backwards, a seal takes refs while:
//
//   - The older ref weighs NO MORE than everything newer than it in the
//     scan already does. That is the tiering rule and the whole of it: a
//     ref is only worth rewriting once the refs behind it are worth as
//     much as it is. It leaves every surviving ref at least as large as
//     the sum of all newer ones, so sizes at least DOUBLE from the newest
//     end and the list is logarithmic in the volume rather than linear.
//     Dust is exempt — a run summing to within refTierBase merges
//     regardless, so a small volume still lists one ref.
//   - The sum stays within refTargetBytes. That sum is an upper bound on
//     the result: a merge's keys are the union of its inputs' and its
//     values a subset of theirs.
//   - The ref's size is KNOWN. A sizeless ref stops the scan, since the
//     one thing this decides on is cost.
//
// And it merges only a SUFFIX of the list, which is not policy but
// correctness: lookups are newest-wins in both key spaces (mpi.Set,
// manifest.Set), so a merge that reached past a ref would move older
// answers ahead of newer ones — a resolvable identity pointing at a
// swept pack.
//
// WHAT ONE SEAL PAYS, worst case: refTargetBytes downloaded — in
// parallel, one round trip of latency — and at most refTargetBytes
// uploaded, per key space, and it holds the merged object in memory
// while doing it. That worst case is rare by construction: a merge that
// large only happens when the refs behind a ceiling-sized tier have
// themselves grown to a ceiling's worth, which is once per refTargetBytes
// of index the volume writes. The steady state is a few kilobytes.
//
// Fewer refs did NOT have to mean more work, but it easily could have:
// merging more means rewriting more. It does not here because the rule it
// replaced spent most of its bytes below the target rather than above it
// — re-merging the same sub-megabyte run on every seal until it froze.
// Geometry rewrites each byte once per tier it climbs, about
// log2(ceiling/floor) times in total, which measures out LOWER: 19.5 GiB
// moved against 27.9 GiB over the same 25,600 generations, for 60x fewer
// refs.
//
// What this does NOT do: keep the list logarithmic past the ceiling. A
// ref that reaches refTargetBytes is frozen exactly as before, so a
// volume larger than about a hundred million objects goes back to one ref
// per ceiling — 25 of them at 1.6 GB of index, against the ~1,600 the old
// rule left. Removing that last linear term means either a merge bigger
// than a seal should perform inline (which wants a background compactor,
// not a bigger constant) or an upload path that streams from a spool
// rather than a []byte.
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
// the tiering rule accepts. It reads sizes alone, so the decision costs
// nothing — the fetch only happens once the answer says two or more refs
// are worth it.
//
// The scan runs newest-first because that is the only end a merge may
// start from, and total is what the refs newer than refs[i] weigh.
func mergeableSuffix[T sizedRef](refs []T) int {
	start, total := len(refs), int64(0)
	for i := len(refs) - 1; i >= 0; i-- {
		size := refs[i].RefSize()
		if size <= 0 || total+size > refTargetBytes {
			break
		}
		// The newest ref has nothing behind it to be balanced against, so it
		// joins unconditionally; every older one must be worth no more than
		// what the scan has already picked up, or be dust.
		if i < len(refs)-1 && size > total && total+size > refTierBase {
			break
		}
		total += size
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
