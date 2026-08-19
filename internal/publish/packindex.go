package publish

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The multi-pack index a publish leaves behind (internal/mpi,
// docs/design-packfs.md "Locating things").
//
// A pack's trailer is its own index, so a reader with no idea which pack
// holds an object consults them all — one federation round trip per pack,
// before a mount can serve its first call. This is the object that answers
// the same question for every pack at once.
//
// ONE INDEX PER GENERATION, covering the packs that generation created,
// and the previous generation's refs carried forward beside it. Not one
// global index: a merge streams (mpi.Merge), so a large index is never
// built, only merged, and the write path stays proportional to what this
// publish wrote rather than to the volume.
//
// A seal then CONSOLIDATES the newest of those refs into one index of
// roughly a pack's size (see consolidateIndexes), because carrying one
// small index per generation is one object a mount fetches per seal the
// volume has ever done — in parallel, but still one object each, and a
// checkpointing mount seals every few minutes. Retiring an index whose
// packs are mostly gone is a separate job: it asks what is still live,
// which only a reachability sweep knows, and is NOT implemented here.
//
// A ContentProvider's packs are covered too, and that matters more than
// it sounds: on a writable mount the memtable uploads nearly all the
// content itself, so an index built from this packer alone would answer
// for catalogs and shards and miss the data — leaving a reader on the
// trailer fallback for exactly the lookups the index exists to answer.
// The source reports what it placed (ProvidedEntries) rather than the
// seal re-deriving it from trailers, which would be the round trips this
// is here to avoid.
//
// Carried-forward packs are not re-indexed: the generation that created
// them already did, and carrying its refs forward is the whole of that
// coverage story.

// identityKey parses one pack entry key as the 32-byte identity the index
// is keyed by. Pack keys are identity hex today; anything else is skipped
// rather than refused, because an unindexed entry costs a reader the
// trailer fallback and an index that failed to build costs everyone.
func identityKey(key string) ([32]byte, bool) {
	var id [32]byte
	if len(key) != 2*len(id) {
		return id, false
	}
	if _, err := hex.Decode(id[:], []byte(key)); err != nil {
		return id, false
	}
	return id, true
}

// publishPackIndex uploads this generation's index and returns the ref the
// superblock lists it by, or a zero ref when there is nothing to publish.
//
// It runs after the last pack is sealed (every entry needs a pack name)
// and before the flip, so a reader that sees the new ref can already fetch
// what it names.
//
// An upload failure is reported and swallowed. The index is DERIVED: a
// generation without one is complete, readable, and merely slower, so
// failing a seal that has already packed and uploaded everything — over an
// optimization — would trade a real loss for a speed one. The same
// reasoning as the dedup sidecar, and the same treatment.
func (p *pipeline) publishPackIndex(ctx context.Context) mpi.Ref {
	// Whatever the source packed for itself, before measuring emptiness:
	// a seal of a memtable-backed overlay may have packed nothing of its
	// own and still have a generation's worth of content to index.
	if cp, ok := p.src.(ContentProvider); ok {
		cp.ProvidedEntries(func(key, pack string) {
			if id, ok := identityKey(key); ok {
				p.pk.idx.Add(id, pack)
			}
		})
	}
	if p.pk.idx.Len() == 0 {
		return mpi.Ref{}
	}
	ref, err := p.putIndex(ctx, p.pk.idx.Encode(), uint32(p.pk.idx.Len()), uint32(p.pk.idx.Packs()))
	if err != nil {
		ui.Warn("publish: pack index not uploaded ({error}); this generation falls back to pack trailers",
			"error", err)
		return mpi.Ref{}
	}
	return ref
}

// putIndex uploads one index object and returns the ref naming it.
//
// Content-addressed, like everything else that is not a ref: two publishes
// that produced the same index write the same object, and an interrupted
// upload is retried rather than left half-named.
func (p *pipeline) putIndex(ctx context.Context, raw []byte, entries, packs uint32) (mpi.Ref, error) {
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return mpi.Ref{}, fmt.Errorf("%s: %w", name, err)
	}
	return mpi.Ref{
		Name:    name,
		Hash:    hash,
		Size:    int64(len(raw)),
		Entries: entries,
		Packs:   packs,
	}, nil
}

// prevPackIndexes are the refs the previous generation listed, which is
// what this one carries forward.
func (p *pipeline) prevPackIndexes() []mpi.Ref {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.PackIndexes
}

// sealPackIndexes publishes this generation's index and returns the refs
// the superblock records: the carried set plus this one, consolidated.
func (p *pipeline) sealPackIndexes(ctx context.Context) []mpi.Ref {
	return p.consolidateIndexes(ctx, packIndexList(p.prevPackIndexes(), p.publishPackIndex(ctx)))
}

// indexTargetBytes is the size consolidation aims a merged index at.
//
// It is the pack cut for a reason: an index is fetched WHOLE today, so its
// size is what consulting it costs, and holding it near a pack keeps that
// comparable to fetching one pack. When indexes are read through ranged
// windows instead, this is the number that should grow.
const indexTargetBytes = 2 << 20

// indexMergeMaxInput is the largest ref consolidation will fold in: past
// half the target a ref counts as a large tier rather than a small one
// waiting to be absorbed. Half, so that two candidates always still fit.
const indexMergeMaxInput = indexTargetBytes / 2

// consolidateIndexes merges the newest refs into one, and returns the list
// the superblock should record — refs it merged are simply no longer
// listed.
//
// NOT DELETED. Retention decides when an index object goes, and a
// generation still inside the retain window names the ones this list drops;
// deleting them here would strand a reader on the trailer fallback for a
// generation that is still perfectly live.
//
// BOUNDING THE WORK. A small generation must never pay a large re-upload
// to tidy the index set, so the rule is stated as what it refuses to do:
//
//   - It refuses to touch a ref that is already large — past half the
//     target. Absorbing a 4 KiB generation into a 2 MiB tier would
//     re-download and re-upload 2 MiB to save one round trip, and a
//     checkpointing mount would pay that every few minutes forever. The
//     scan STOPS at such a ref rather than skipping past it.
//   - It refuses to produce an object past the target. Inputs are taken
//     newest-first only while their sizes sum to within it, and that sum
//     is an upper bound on the result: a merge's keys are the union of its
//     inputs' and its pack names a subset of theirs.
//   - It refuses to merge anything but a SUFFIX of the list. Lookups are
//     newest-wins (mpi.Set), so a merge that reached past a ref would move
//     older placements ahead of newer ones.
//
// So a seal downloads at most one target's worth of index — in parallel,
// one round trip of latency — and uploads at most one more. That is the
// cost a seal pays to tidy up after itself, and it is why the bound is
// stated in bytes rather than in refs.
//
// What this does NOT do: grow tiers geometrically. Once a ref reaches the
// target it is frozen here, so the list stops growing with the number of
// GENERATIONS and starts growing with the volume's size instead. Merging
// those into larger tiers means a merge that outgrows memory, which wants
// the spooling encoder mpi.Merge admits it does not have.
func (p *pipeline) consolidateIndexes(ctx context.Context, refs []mpi.Ref) []mpi.Ref {
	start := mergeableSuffix(refs)
	if len(refs)-start < 2 {
		return refs
	}
	merged, err := p.mergeIndexes(ctx, refs[start:])
	if err != nil {
		// Consolidation is an optimization on top of a structure that is
		// itself an optimization: the unmerged refs still name objects that
		// still answer, so a failed merge costs this generation a longer
		// list and nothing else. The next seal tries again.
		ui.Warn("publish: pack indexes not consolidated ({error}); this generation lists them unmerged",
			"error", err)
		return refs
	}
	return append(append([]mpi.Ref{}, refs[:start]...), merged)
}

// mergeableSuffix is where the refs worth merging start: the newest run
// that is all small and sums to within the target. It reads sizes alone,
// so the decision costs nothing — the fetch only happens once the answer
// says two or more refs are worth it.
func mergeableSuffix(refs []mpi.Ref) int {
	start, total := len(refs), int64(0)
	for i := len(refs) - 1; i >= 0; i-- {
		if refs[i].Size <= 0 || refs[i].Size > indexMergeMaxInput || total+refs[i].Size > indexTargetBytes {
			break
		}
		total += refs[i].Size
		start = i
	}
	return start
}

// mergeIndexes fetches the given refs, merges them and uploads the result.
func (p *pipeline) mergeIndexes(ctx context.Context, refs []mpi.Ref) (mpi.Ref, error) {
	indexes, err := mpi.FetchAll(ctx, p.o.Inner, refs)
	if err != nil {
		return mpi.Ref{}, err
	}
	// ALL of them or none: FetchAll returns what verified, which is the
	// right answer for a mount and the wrong one here. Dropping the refs a
	// partial merge superseded would lose the coverage of whatever failed
	// to fetch, silently and permanently.
	if len(indexes) != len(refs) {
		return mpi.Ref{}, fmt.Errorf("%d of %d indexes fetched", len(indexes), len(refs))
	}
	// Oldest first, which is the order the list is already in: mpi.Merge
	// lets later inputs win, and later here means newer.
	raw := mpi.Merge(indexes)
	if len(raw) > indexTargetBytes {
		// The summed input sizes said this would fit. If it ever does not,
		// listing the inputs unmerged is cheaper than being wrong about the
		// one number this whole policy is written in terms of.
		return mpi.Ref{}, fmt.Errorf("merged index is %d bytes, past the %d-byte target", len(raw), indexTargetBytes)
	}
	ix, err := mpi.Open(raw)
	if err != nil {
		return mpi.Ref{}, err
	}
	return p.putIndex(ctx, raw, uint32(ix.Len()), uint32(len(ix.Packs())))
}

// packIndexList is what the superblock records: the previous generation's
// indexes, plus this one's.
//
// Carrying forward is not bookkeeping, it is the same rule as the pack
// list — an index a live generation names must not be swept, and the
// packs a carried index covers are exactly the packs this generation
// carried forward. Dropping one costs speed rather than correctness, but
// it costs it silently and permanently, since nothing rebuilds an index
// that was merely forgotten.
func packIndexList(prev []mpi.Ref, added mpi.Ref) []mpi.Ref {
	var out []mpi.Ref
	out = append(out, prev...)
	if added.Name == "" {
		return out
	}
	// A generation that wrote the same entries into the same packs
	// produces the same index bytes and so the same name; listing it twice
	// would make a reader fetch it twice.
	for _, r := range out {
		if r.Name == added.Name {
			return out
		}
	}
	return append(out, added)
}
