package genfs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The location layer, resolved on demand.
//
// A catalog names an entry's IDENTITY; a pack trailer maps that identity to
// an offset and a length inside one pack. The two are not duplicates, but
// the trailer's job is narrow: under the whole-pack policy (packfetch.go)
// the offset is always read out of a local copy of the pack, so the only
// question a trailer answers across the network is WHICH pack — and once
// that pack is local, its trailer came down with it.
//
// So a mount does not need the generation's trailers. It needs the root
// catalog, which lives in exactly one of them. Indexing every pack at Open
// was one round trip per pack before the mount could answer anything, and
// a generation has one pack per cut size however large it grows — the cost
// scaled with the volume rather than with the question.
//
// Probing runs NEWEST PACK FIRST. Publish appends this generation's packs
// after the ones it carried forward and writes the root catalog last, so
// the pack a cold mount is looking for is normally the final entry of the
// list and the first one probed.
//
// One rule is not negotiable: "present in no listed pack" may only be
// returned once EVERY listed pack has been indexed. That answer fails a
// read, and a caller like fsck or a seal's carry-forward check would read
// it as "this content is gone" — an incomplete map must never be able to
// say it.
type packIndex struct {
	fs    *FS
	packs []superblock.PackEntry

	// loadMu serializes the trailer work, so concurrent misses index a
	// pack once between them rather than once each.
	loadMu sync.Mutex

	mu      sync.Mutex
	byKey   map[string]packLoc
	sizes   map[string]int64
	indexed map[string]bool
}

// newPackIndex builds the empty index for a generation's pack list. It
// makes no requests: the pack list alone gives every pack's signed size,
// which is all the whole-pack cache needs to hold a local copy to account.
func newPackIndex(fs *FS, packs []superblock.PackEntry) *packIndex {
	x := &packIndex{
		fs:      fs,
		packs:   packs,
		byKey:   make(map[string]packLoc),
		sizes:   make(map[string]int64, len(packs)),
		indexed: make(map[string]bool, len(packs)),
	}
	for _, pe := range packs {
		x.sizes[pe.Name] = pe.Size
	}
	return x
}

// size reports a pack's SIGNED length — the only whole-object check a
// cached copy can be held to.
func (x *packIndex) size(pack string) int64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.sizes[pack]
}

func (x *packIndex) lookup(key string) (packLoc, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	loc, ok := x.byKey[key]
	return loc, ok
}

// merge folds one pack's trailer into the map. Identical content dedups at
// publish, so a key appearing in several packs names the same bytes; the
// first merge wins, and callers merge newest-first, so the winner is the
// most recently written copy no matter which order the fetches completed
// in.
func (x *packIndex) merge(pe superblock.PackEntry, entries []packstore.PackEntry) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.indexed[pe.Name] {
		return
	}
	x.indexed[pe.Name] = true
	for _, e := range entries {
		if _, dup := x.byKey[e.Key]; dup {
			continue
		}
		x.byKey[e.Key] = packLoc{pack: pe.Name, off: e.Off, length: e.Length}
	}
}

func (x *packIndex) isIndexed(pack string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.indexed[pack]
}

// locate resolves one entry identity, indexing packs newest-first until it
// finds one that holds it.
//
// A trailer that will not load is remembered as an ERROR, not as an
// absence: if the scan runs out of packs having failed to read some, it
// reports the failure rather than "not present", because those are
// different facts and only one of them means the content is missing.
func (x *packIndex) locate(ctx context.Context, key string) (packLoc, error) {
	if loc, ok := x.lookup(key); ok {
		return loc, nil
	}
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	if loc, ok := x.lookup(key); ok {
		return loc, nil
	}
	var failed error
	for i := len(x.packs) - 1; i >= 0; i-- {
		pe := x.packs[i]
		if x.isIndexed(pe.Name) {
			continue
		}
		entries, err := x.fs.trailerEntries(ctx, pe)
		if err != nil {
			if failed == nil {
				failed = fmt.Errorf("genfs: index pack %s: %w", pe.Name, err)
			}
			continue
		}
		x.merge(pe, entries)
		if loc, ok := x.lookup(key); ok {
			return loc, nil
		}
	}
	if failed != nil {
		return packLoc{}, failed
	}
	return packLoc{}, fmt.Errorf("genfs: %s not present in any listed pack", key)
}

// LoadPackIndex resolves the location of every entry the generation holds,
// fetching whatever pack trailers are not already local.
//
// Reads never need this: they resolve the pack they are about to fetch and
// nothing else, which is why mounting no longer costs a round trip per
// pack. It is for the callers that reason about content they are NOT about
// to read — a check for absence, an inventory, a warm-up — and for a
// caller that would simply rather pay the cost somewhere it has chosen.
// Answering "not present" from a partially resolved map would be a lie
// with consequences: a failed read, a re-upload, or deleted live data.
func (fs *FS) LoadPackIndex(ctx context.Context) error {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.packIndex.all(ctx)
}

// indexWorkers bounds concurrent trailer fetches when a caller asks for the
// whole map. The packs are independent, so the only reason to do them one
// at a time is politeness to the federation.
const indexWorkers = 8

// all populates the index from every listed pack.
//
// It exists for the callers that need to reason about content they are not
// about to read: fsck, a seal checking which chunk identities this
// generation still carries, and a prefetch that wants the volume local.
// Those callers must ask for it — no read path builds it, and one that
// consulted a partial map would answer "missing" for content that is
// merely un-probed.
func (x *packIndex) all(ctx context.Context) error {
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	results := make([][]packstore.PackEntry, len(x.packs))
	errs := make([]error, len(x.packs))
	sem := make(chan struct{}, indexWorkers)
	var wg sync.WaitGroup
	for i, pe := range x.packs {
		if x.isIndexed(pe.Name) {
			continue
		}
		wg.Add(1)
		go func(i int, pe superblock.PackEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i], errs[i] = x.fs.trailerEntries(ctx, pe)
		}(i, pe)
	}
	wg.Wait()
	// Newest-first, so a key in several packs resolves to the same copy a
	// lazy probe would have found.
	for i := len(x.packs) - 1; i >= 0; i-- {
		pe := x.packs[i]
		if errs[i] != nil {
			return fmt.Errorf("genfs: index pack %s: %w", pe.Name, errs[i])
		}
		if results[i] != nil {
			x.merge(pe, results[i])
		}
	}
	return nil
}

// trailerEntries returns one pack's entries, from whatever local copy the
// mount already has and from the federation otherwise. Every source is held
// to the same standard — the stored bytes must hash to the TrailerHash the
// signed pack list records — so a corrupt, truncated, or substituted local
// file is not a hazard, only a wasted read that falls through.
//
// The order is by cost. A saved trailer is a few kilobytes. A whole pack in
// the cache already contains its trailer, so reading it there is free and,
// under the whole-pack policy, is the common case after the first touch. A
// federation range read is last.
func (fs *FS) trailerEntries(ctx context.Context, pe superblock.PackEntry) ([]packstore.PackEntry, error) {
	fp := filepath.Join(fs.trailerDir, pe.Name)
	if stored, err := os.ReadFile(fp); err == nil {
		if entries, ok := verifiedTrailer(stored, pe.TrailerHash); ok {
			return entries, nil
		}
		os.Remove(fp) //nolint:errcheck
	}
	if entries, stored, ok := fs.trailerFromCachedPack(pe); ok {
		_ = writeAtomic(fp, stored)
		return entries, nil
	}
	entries, stored, err := packstore.FetchTrailerStoredVerified(ctx, fs.inner, pe.Name, pe.Size, pe.TrailerHash)
	if err != nil {
		return nil, err
	}
	// Best effort: a mount that cannot write its cache still mounts.
	_ = writeAtomic(fp, stored)
	return entries, nil
}

// trailerFromCachedPack reads a pack's trailer out of the local whole-pack
// cache. Reports false for anything at all wrong, so the caller goes to the
// federation — a cache must never turn into a mount failure.
func (fs *FS) trailerFromCachedPack(pe superblock.PackEntry) ([]packstore.PackEntry, []byte, bool) {
	if fs.packCacheCap <= 0 || !fs.packCachedLocally(pe.Name, pe.Size) {
		return nil, nil, false
	}
	f, err := os.Open(fs.packPath(pe.Name))
	if err != nil {
		return nil, nil, false
	}
	defer f.Close() //nolint:errcheck
	stored, err := packstore.StoredTrailerFrom(f, pe.Size)
	if err != nil {
		return nil, nil, false
	}
	entries, ok := verifiedTrailer(stored, pe.TrailerHash)
	return entries, stored, ok
}

// verifiedTrailer authenticates stored trailer bytes against the signed
// pack list and parses them. It is the single gate every trailer source
// passes through, so no source can drift into being trusted more.
func verifiedTrailer(stored []byte, want [32]byte) ([]packstore.PackEntry, bool) {
	if blake3.Sum256(stored) != want {
		return nil, false
	}
	entries, err := packstore.ParseStoredTrailer(stored)
	if err != nil {
		return nil, false
	}
	return entries, true
}
