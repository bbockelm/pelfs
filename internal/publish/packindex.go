package publish

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/superblock"
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
// roughly a pack's size (consolidate.go), because carrying one
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
func (p *pipeline) publishPackIndex(ctx context.Context) superblock.IndexRef {
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
		return superblock.IndexRef{}
	}
	ref, err := p.putIndex(ctx, p.pk.idx.Encode(), uint32(p.pk.idx.Len()), uint32(p.pk.idx.Packs()))
	if err != nil {
		ui.Warn("publish: pack index not uploaded ({error}); this generation falls back to pack trailers",
			"error", err)
		return superblock.IndexRef{}
	}
	return ref
}

// putIndex uploads one index object and returns the ref naming it.
//
// Content-addressed, like everything else that is not a ref: two publishes
// that produced the same index write the same object, and an interrupted
// upload is retried rather than left half-named.
func (p *pipeline) putIndex(ctx context.Context, raw []byte, entries, packs uint32) (superblock.IndexRef, error) {
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.IndexRef{}, fmt.Errorf("%s: %w", name, err)
	}
	return superblock.IndexRef{
		Name:    name,
		Hash:    hash,
		Size:    int64(len(raw)),
		Entries: entries,
		Packs:   packs,
	}, nil
}

// prevPackIndexes are the refs the previous generation listed, which is
// what this one carries forward.
func (p *pipeline) prevPackIndexes() []superblock.IndexRef {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.PackIndexes
}

// prevCondemnedIndexes is the parent's ledger of dropped index refs,
// which this generation carries forward until the entries age out
// (condemnedrefs.go).
func (p *pipeline) prevCondemnedIndexes() []superblock.CondemnedRef {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.CondemnedIndexes
}

// sealPackIndexes publishes this generation's index and returns the refs
// the superblock records: the carried set plus this one, consolidated
// under the shared tiering policy (consolidate.go).
//
// It also records what consolidation stopped listing. A merged-away index
// is still named by generations inside the retain window, and those
// generations are not enumerable, so without the ledger the object is
// swept as soon as it ages and those readers quietly lose the index they
// were promised (condemnedrefs.go).
func (p *pipeline) sealPackIndexes(ctx context.Context) []superblock.IndexRef {
	prev := p.prevPackIndexes()
	after := consolidate(ctx, carryForward(prev, p.publishPackIndex(ctx)), "pack index", p.mergeIndexes)
	p.droppedIndexes = append(p.droppedIndexes, droppedRefs(prev, after)...)
	return after
}

// mergeIndexes fetches the given refs, merges them and uploads the result.
func (p *pipeline) mergeIndexes(ctx context.Context, refs []superblock.IndexRef) (superblock.IndexRef, error) {
	indexes, err := mpi.FetchAll(ctx, p.o.Inner, refs)
	if err != nil {
		return superblock.IndexRef{}, err
	}
	// ALL of them or none: FetchAll returns what verified, which is the
	// right answer for a mount and the wrong one here. Dropping the refs a
	// partial merge superseded would lose the coverage of whatever failed
	// to fetch, silently and permanently.
	if len(indexes) != len(refs) {
		return superblock.IndexRef{}, fmt.Errorf("%d of %d indexes fetched", len(indexes), len(refs))
	}
	// Oldest first, which is the order the list is already in: the merge
	// lets later inputs win, and later here means newer.
	//
	// It goes to a FILE rather than to memory, and is hashed as it is
	// written. Materializing the result was what set the ceiling this
	// policy merges up to: holding the inputs and the output at once
	// doubles the peak for no reason, since the object is only ever
	// hashed and uploaded. What remains in memory is the inputs, which
	// FetchAll still reads whole — that is now the binding constraint,
	// and it is what a larger ceiling would have to address next.
	out, err := os.CreateTemp(p.tmpDir, "mergeidx-*")
	if err != nil {
		return superblock.IndexRef{}, err
	}
	defer os.Remove(out.Name()) //nolint:errcheck
	defer out.Close()           //nolint:errcheck
	spool, err := os.CreateTemp(p.tmpDir, "mergespool-*")
	if err != nil {
		return superblock.IndexRef{}, err
	}
	defer os.Remove(spool.Name()) //nolint:errcheck
	defer spool.Close()           //nolint:errcheck

	h := blake3.New(32, nil)
	entries, packs, err := mpi.MergeTo(io.MultiWriter(out, h), spool, indexes)
	if err != nil {
		return superblock.IndexRef{}, err
	}
	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return superblock.IndexRef{}, err
	}
	if size > refTargetBytes {
		// The summed input sizes said this would fit. If it ever does not,
		// listing the inputs unmerged is cheaper than being wrong about the
		// one number this whole policy is written in terms of.
		return superblock.IndexRef{}, fmt.Errorf("merged index is %d bytes, past the %d-byte ceiling", size, refTargetBytes)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return superblock.IndexRef{}, err
	}
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, mpi.Dir+"/"+name, out); err != nil {
		return superblock.IndexRef{}, fmt.Errorf("%s: %w", name, err)
	}
	return superblock.IndexRef{
		Name: name, Hash: hash, Size: size,
		Entries: uint32(entries), Packs: uint32(packs),
	}, nil
}
