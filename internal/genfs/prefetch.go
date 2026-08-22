package genfs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// Prefetch makes a whole generation LOCAL.
//
// It serves the batch disposition: an HTCondor job that wants every byte
// on the node before it starts, so a mid-job federation failure cannot
// stall it — and, in strict mode, that refuses to run at all rather than
// discover something missing halfway through.
//
// "Local" means PACKS local. Under the whole-pack policy (packfetch.go) a
// pack is the unit of transfer and of storage, and everything a read needs
// — chunk bytes, catalogs, the pack's own trailer — comes out of one. So
// this pass downloads the pack set the generation's live tree references
// and stops there. It used to pull every chunk through readChunkAt, which
// DECODED each one (zstd, and AES-GCM on an encrypted volume) and wrote a
// plaintext file per chunk into gencache/chunks/. That cost a full decode
// of the volume up front, for a decode the mount then usually repeated
// anyway after the chunk file was evicted, and it turned "I want the data
// local" into "I want the data local, unpacked, and taking twice the disk".
//
// It still walks catalogs rather than taking the pack list wholesale. The
// pack list includes catalogs, shards and superblock backups, and after a
// repack it can still name packs holding chunks no live file references;
// walking the tree names exactly the packs the generation's files and
// catalogs are made of. On a freshly published volume the two sets are
// nearly the same; after a repack they are not, and the difference is
// transfer nobody asked for.
//
// The budget is checked BEFORE anything is fetched. A generation whose
// pack set does not fit in the local cache cannot be made local: fetching
// it anyway would evict the front of the set to make room for the back and
// leave the mount both slow and incomplete. That is a refusal with the two
// numbers in it, not a churn.

// PrefetchReport summarizes a warm-up pass. It counts PACKS, because a
// pack is what the pass moves.
type PrefetchReport struct {
	Files int // files the walk visited
	// Packs is how many packs this pass downloaded, Cached how many were
	// already on disk, and Bytes the size of the whole referenced set now
	// resident. Fetched is what actually went over the network.
	Packs   int
	Cached  int
	Bytes   int64
	Fetched int64
	// Failed counts packs the pass could not make local, Sample carries
	// the first few reasons for a human.
	Failed int
	Sample []string
	// Skipped counts refs with nothing to fetch: holes, and files stored
	// inline in a catalog.
	Skipped int
}

// PrefetchBudgetError is the refusal a generation too large for the local
// cache earns. It is a distinct type because the two callers want opposite
// things from it: strict mode fails the mount with the numbers, background
// mode logs them and serves anyway from the federation.
type PrefetchBudgetError struct {
	Need   int64 // bytes of the referenced pack set
	Budget int64 // bytes the cache may hold
	Packs  int
}

func (e *PrefetchBudgetError) Error() string {
	return fmt.Sprintf("genfs: the generation is %d bytes in %d packs, the local cache budget is %d bytes; "+
		"it cannot be made local (raise --cache-size above %d, or drop --prefetch all)",
		e.Need, e.Packs, e.Budget, e.Need)
}

// ErrPrefetchNeedsPackCache is the refusal when whole-pack caching is off.
// Nothing can be made local pack-at-a-time in that mode, so a prefetch
// would be a lie rather than a slow success.
var ErrPrefetchNeedsPackCache = errors.New("genfs: --prefetch needs the whole-pack cache, which this mount has turned off")

// Prefetch downloads the generation's referenced pack set using workers
// concurrent transfers. It stops early and returns the error only when ctx
// is cancelled or the set cannot fit; per-pack failures are counted so a
// caller can decide whether "mostly local" is good enough (background
// mode) or not (strict mode).
func (fs *FS) Prefetch(ctx context.Context, workers int) (*PrefetchReport, error) {
	if workers <= 0 {
		workers = 8
	}
	rep := &PrefetchReport{}
	if fs.packCacheCap <= 0 {
		return rep, ErrPrefetchNeedsPackCache
	}
	// Prefetch is one of the callers that must ask for the WHOLE location
	// map. A read fills it in as it goes, one pack at a time; a pass that
	// intends to make the entire generation local would then discover each
	// pack serially, in whatever order the walk happened to reach it — and
	// worse, could not tell "this chunk is in a pack nobody probed yet"
	// from "this chunk is in no listed pack", which is the difference
	// between a warm cache and a refusal.
	if err := func() error {
		fs.swapMu.RLock()
		defer fs.swapMu.RUnlock()
		return fs.packIndex.all(ctx)
	}(); err != nil {
		return rep, err
	}

	packs, err := fs.referencedPacks(ctx, rep)
	if err != nil {
		return rep, err
	}
	names := make([]string, 0, len(packs))
	for name := range packs {
		names = append(names, name)
	}
	sort.Strings(names)

	// Sizes and the budget, before a byte moves. wholePackWanted is the
	// same gate reads use, so a pack this refuses is one a read would not
	// have served out of the cache either — caching it would be disk spent
	// on nothing.
	var need int64
	sizes := make(map[string]int64, len(names))
	fit := names[:0:0]
	for _, name := range names {
		size := fs.packIndex.size(name)
		if !fs.wholePackWanted(fs.packIndex, name) {
			fs.noteFailure(rep, fmt.Sprintf("%s: %d bytes, too large to cache whole", name, size))
			continue
		}
		sizes[name] = size
		need += size
		fit = append(fit, name)
	}
	names = fit
	if limit := fs.prefetchBudget(); limit > 0 && need > limit {
		return rep, &PrefetchBudgetError{Need: need, Budget: limit, Packs: len(names)}
	}

	// What is already here, counted BEFORE anything is fetched, or the
	// downloads below would make every pack look like it had been cached
	// all along.
	var want []string
	for _, name := range names {
		if fs.packCachedLocally(name, sizes[name]) {
			rep.Cached++
			rep.Bytes += sizes[name]
			continue
		}
		want = append(want, name)
	}

	var mu sync.Mutex
	tasks := make([]func(), 0, len(want))
	for _, name := range want {
		name := name
		tasks = append(tasks, func() {
			err := func() error {
				fs.swapMu.RLock()
				defer fs.swapMu.RUnlock()
				f, _, err := fs.openCachedPack(ctx, fs.packIndex, name)
				if err != nil {
					return err
				}
				return f.Close()
			}()
			mu.Lock()
			defer mu.Unlock()
			// openCachedPack degrades to ranged reads for its callers when
			// a download fails, so its error is advisory; the check that
			// decides this pass is the one below, on the file itself.
			switch {
			case err != nil && !fs.packCachedLocally(name, sizes[name]):
				fs.noteFailure(rep, fmt.Sprintf("%s: %v", name, err))
			case !fs.packCachedLocally(name, sizes[name]):
				fs.noteFailure(rep, fmt.Sprintf("%s: not present or wrong length after download", name))
			default:
				rep.Packs++
				rep.Bytes += sizes[name]
				rep.Fetched += sizes[name]
			}
		})
	}
	runBounded(ctx, tasks, workers)
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	return rep, nil
}

// prefetchBudget is the byte ceiling a prefetched pack set is held to: the
// level an eviction pass sweeps DOWN to, not the cap it triggers at.
//
// Measuring against the cap would admit a set that fits exactly and is then
// evicted from by the next catalog spill, which is the churn this check
// exists to prevent. The low-water mark leaves the same headroom eviction
// itself does, and the cache holds catalogs and trailers besides packs.
func (fs *FS) prefetchBudget() int64 {
	low := fs.cacheLow()
	if low <= 0 {
		return 0
	}
	// The decoded-chunk arena is a fixed reservation out of the same
	// budget and no sweep can reclaim it, so it is not room a pack set can
	// be promised.
	if n := fs.arena.bytes(); n > 0 {
		low -= n
	}
	if low < 0 {
		low = 0
	}
	return low
}

// noteFailure records one thing the pass could not make local. Callers
// hold whatever lock protects rep.
func (fs *FS) noteFailure(rep *PrefetchReport, msg string) {
	rep.Failed++
	if len(rep.Sample) < 5 {
		rep.Sample = append(rep.Sample, msg)
	}
}

// referencedPacks walks the generation and returns the set of packs its
// live tree is made of: the packs holding its chunks, and the packs
// holding the catalogs and inode shards those chunks are named from.
//
// The catalogs matter as much as the chunks. A mount whose packs are all
// local but whose catalogs are not still goes to the federation the first
// time it descends anywhere it has not been, which is precisely the stall
// strict mode exists to rule out.
//
// It records only pack NAMES, never the chunk identities. The old pass
// collected a deduplicated set of every identity in the generation before
// it fetched anything — tens of millions of 32-byte keys on a large volume,
// resident at once, to derive a few hundred pack names.
func (fs *FS) referencedPacks(ctx context.Context, rep *PrefetchReport) (map[string]struct{}, error) {
	packs := make(map[string]struct{})
	// locateInto resolves one entry identity to its pack. The whole
	// location map is loaded by the time this runs, so a miss is a genuine
	// absence and the caller's problem to report.
	locateInto := func(idHex, what string) {
		if loc, ok := fs.packIndex.lookup(idHex); ok {
			packs[loc.pack] = struct{}{}
			return
		}
		fs.noteFailure(rep, fmt.Sprintf("%s %s: present in no listed pack", what, idHex[:min(16, len(idHex))]))
	}
	locateInto(fs.cats.rootHex, "root catalog")

	var walk func(ino uint64) error
	walk = func(ino uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := fs.Readdir(ctx, ino)
		if err != nil {
			return err
		}
		for _, e := range entries {
			// Descent establishes residency; Readdir alone does not.
			n, err := fs.Lookup(ctx, ino, e.Name)
			if err != nil {
				return fmt.Errorf("prefetch: lookup %q: %w", e.Name, err)
			}
			// The catalog this child resolves in. Equal to the parent's
			// except at a transition point, where it is the nested catalog
			// the descent just crossed into — the one a cold mount would
			// have to fetch.
			if catHex, err := fs.residencyOf(n.Inode); err == nil {
				locateInto(catHex, "catalog")
			}
			switch {
			case n.Type == catalog.TypeDir:
				if err := walk(n.Inode); err != nil {
					return err
				}
			case n.Type == catalog.TypeFile:
				rep.Files++
				// A promoted (hardlinked) file's content records live in an
				// inode shard, which is a catalog in a pack of its own.
				if n.Nlink > 1 {
					if shardHex, err := fs.shardHexFor(n.Inode); err == nil {
						locateInto(shardHex, "inode shard")
					}
				}
				ext, err := func() (*extents, error) {
					fs.swapMu.RLock()
					defer fs.swapMu.RUnlock()
					return fs.extentsOf(ctx, n.Inode)
				}()
				if err != nil {
					return fmt.Errorf("prefetch: extents of %q: %w", e.Name, err)
				}
				for i := range ext.refs {
					r := &ext.refs[i]
					if len(r.Identity) == 0 {
						rep.Skipped++ // hole or inline: nothing to fetch
						continue
					}
					locateInto(hex.EncodeToString(r.Identity), "chunk")
				}
			}
		}
		return nil
	}
	if err := walk(RootInode); err != nil {
		return nil, err
	}
	return packs, nil
}
