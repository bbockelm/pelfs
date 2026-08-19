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
// publish wrote rather than to the volume. Consolidating those per-
// generation indexes into geometric tiers, and retiring one whose packs
// are mostly gone, is repack's job and is NOT implemented here — the
// policy is written down in the design doc, and until something does it a
// long-lived volume accumulates one small index per generation.
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
	raw := p.pk.idx.Encode()
	hash := blake3.Sum256(raw)
	// Content-addressed, like everything else that is not a ref: two
	// publishes that produced the same index write the same object, and an
	// interrupted upload is retried rather than left half-named.
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		ui.Warn("publish: pack index not uploaded ({error}); this generation falls back to pack trailers",
			"error", fmt.Errorf("%s: %w", name, err))
		return mpi.Ref{}
	}
	return mpi.Ref{
		Name:    name,
		Hash:    hash,
		Size:    int64(len(raw)),
		Entries: uint32(p.pk.idx.Len()),
		Packs:   uint32(p.pk.idx.Packs()),
	}
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
