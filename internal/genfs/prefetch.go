package genfs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/superblock"
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
	// Grafted counts chunk references this pass CANNOT make local, and
	// GraftedBytes their logical size, because they live at a foreign
	// prefix rather than in a pack (graft.go).
	//
	// They are counted rather than failed, and the distinction is the
	// whole of the prefetch/graft question. A pack that will not download
	// is DAMAGE or an outage; a grafted block is working exactly as
	// designed and simply cannot be moved by a pass that moves packs —
	// there is no pack to cache. Reporting it as a failure (which is what
	// this pass used to do, and it refused the mount) said the volume was
	// broken when it was not.
	//
	// What a caller may NOT do is treat a report with Grafted > 0 as
	// "everything is local". Making those bytes local means WRITING them
	// into local packs, which is a materialization — a new generation,
	// the lease, and the publish path — not a prefetch.
	Grafted      int
	GraftedBytes int64
	// GraftLocal is how many of those chunks are on this machine's disk
	// when the pass returns, and GraftLocalBytes what they weigh.
	// GraftFetched is what this pass moved to get there — zero on a
	// re-run over a warm cache.
	GraftLocal      int
	GraftLocalBytes int64
	GraftFetched    int64
	// GraftRoots names the grafts those chunks belong to, so a refusal or
	// a warning can name what it is talking about instead of printing a
	// list of hashes.
	GraftRoots []superblock.GraftEntry
}

// FullyLocal reports whether the generation was entirely on this machine
// when the pass returned. It is deliberately the ONLY way to ask, so that
// no caller can conclude "local" from a zero failure count while grafted
// bytes are still one federation away.
//
// WHEN, not forever, and the distinction is real rather than pedantic. A
// cached graft block is evictable — it has to be, or a graft larger than
// the disk could wedge the cache — so this is a statement about the
// moment, exactly as it already was for packs. What makes it a useful
// statement anyway is that eviction PREFERS everything else first
// (gencache.go), and that when it does take a prefetched blob it records
// the fact (GraftCacheStats.PinnedEvicted) instead of letting the earlier
// report quietly become a lie.
func (r *PrefetchReport) FullyLocal() bool {
	return r.Failed == 0 && r.GraftLocal == r.Grafted
}

// PrefetchBudgetError is the refusal a generation too large for the local
// cache earns. It is a distinct type because the two callers want opposite
// things from it: strict mode fails the mount with the numbers, background
// mode logs them and serves anyway from the federation.
type PrefetchBudgetError struct {
	Need   int64 // bytes of the referenced pack set PLUS the grafted content
	Budget int64 // bytes the cache may hold
	Packs  int
	// GraftBytes is how much of Need is grafted content, and GraftRoots
	// which grafts it belongs to. A refusal that says "10 TB does not fit
	// in 100 GB" is actionable; one that says "grafts cannot be
	// prefetched" is not, and is also untrue.
	GraftBytes int64
	GraftRoots []superblock.GraftEntry
}

func (e *PrefetchBudgetError) Error() string {
	if e.GraftBytes == 0 {
		return fmt.Sprintf("genfs: the generation is %d bytes in %d packs, the local cache budget is %d bytes; "+
			"it cannot be made local (raise --cache-size above %d, or drop --prefetch all)",
			e.Need, e.Packs, e.Budget, e.Need)
	}
	var names []string
	for _, g := range e.GraftRoots {
		names = append(names, fmt.Sprintf("%s <- %s (%d bytes)", g.Path, g.Source, g.Bytes))
	}
	// The pack clause is omitted when the graft alone already blows the
	// budget, because that check runs off the signed superblock BEFORE
	// anything is walked — "0 bytes in 0 packs" there would be a fact
	// about the walk that never happened rather than about the volume.
	packs := ""
	if e.Packs > 0 {
		packs = fmt.Sprintf("%d bytes in %d packs and ", e.Need-e.GraftBytes, e.Packs)
	}
	return fmt.Sprintf("genfs: making this generation local needs %d bytes — %s%d bytes grafted from %s — "+
		"and the local cache budget is %d bytes (raise --cache-size above %d, or use "+
		"--prefetch packs to make the packed content local and read the grafted content "+
		"from its source)",
		e.Need, packs, e.GraftBytes, strings.Join(names, ", "), e.Budget, e.Need)
}

// ErrPrefetchNeedsPackCache is the refusal when whole-pack caching is off.
// Nothing can be made local pack-at-a-time in that mode, so a prefetch
// would be a lie rather than a slow success.
var ErrPrefetchNeedsPackCache = errors.New("genfs: --prefetch needs the whole-pack cache, which this mount has turned off")

// PrefetchOptions configures a warm-up pass.
type PrefetchOptions struct {
	// Workers bounds concurrent transfers; zero takes 8.
	Workers int
	// Grafts asks the pass to fetch GRAFTED blocks into the local cache
	// too, so that later reads under a graft do not touch the source.
	//
	// It is a separate flag from the pack work because the two make
	// different promises and one of them can be kept when the other
	// cannot: a volume whose grafted content does not fit the cache can
	// still have every pack made local. It is NOT a materialization —
	// nothing is written to the volume, no generation is produced, and the
	// files stay grafted (graftcache.go).
	Grafts bool
}

// Prefetch downloads the generation's referenced pack set, and — when
// Options.Grafts is set — its grafted blocks, using Workers concurrent
// transfers. It stops early and returns the error only when ctx is
// cancelled or the set cannot fit; per-pack failures are counted so a
// caller can decide whether "mostly local" is good enough (background
// mode) or not (strict mode).
func (fs *FS) Prefetch(ctx context.Context, o PrefetchOptions) (*PrefetchReport, error) {
	workers := o.Workers
	if workers <= 0 {
		workers = 8
	}
	rep := &PrefetchReport{}
	if fs.packCacheCap <= 0 {
		return rep, ErrPrefetchNeedsPackCache
	}
	// THE CHEAP REFUSAL, before anything is walked. The signed superblock
	// already says how large each graft is (GraftEntry.Bytes, recorded for
	// exactly this), so the 10-TB-graft-into-a-100-GB-cache case is
	// answered without touching a catalog. The exact combined check
	// happens below, once the pack set is known.
	if o.Grafts {
		var graftBytes int64
		roots := fs.Grafts()
		for _, g := range roots {
			graftBytes += g.Bytes
		}
		if limit := fs.prefetchBudget(); limit > 0 && graftBytes > limit {
			return rep, &PrefetchBudgetError{
				Need: graftBytes, Budget: limit,
				GraftBytes: graftBytes, GraftRoots: roots,
			}
		}
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

	packs, wantGrafts, err := fs.referencedPacks(ctx, rep, o.Grafts)
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
	// Grafted bytes count against the budget only when this pass intends
	// to FETCH them. A packs-only prefetch on a volume whose graft is far
	// larger than the cache is a perfectly reasonable thing to do, and
	// refusing it because of bytes nobody asked for would leave that
	// volume with no working prefetch mode at all.
	graftNeed := int64(0)
	if o.Grafts {
		graftNeed = rep.GraftedBytes
	}
	if limit := fs.prefetchBudget(); limit > 0 && need+graftNeed > limit {
		return rep, &PrefetchBudgetError{
			Need: need + graftNeed, Budget: limit, Packs: len(names),
			GraftBytes: graftNeed, GraftRoots: rep.GraftRoots,
		}
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
	if err := fs.prefetchGrafts(ctx, rep, wantGrafts, workers); err != nil {
		return rep, err
	}
	return rep, nil
}

// graftWant is one grafted block a prefetch has to make local.
type graftWant struct {
	e     *graftEntry
	loc   graft.Loc
	idHex string
}

// prefetchGrafts fetches, verifies and caches the grafted blocks.
//
// It is deliberately the SAME code the read path uses — readGraftChunk,
// with the pin flag set — so a prefetched block is verified against the
// identity the signed catalog names before it is written, and there is no
// second path on which an unverified byte could reach the disk. What ends
// up cached is what a read would have accepted.
//
// A failure is counted rather than fatal, exactly as a pack failure is.
// The bytes are re-fetchable, so a graft block that would not come down is
// a slower mount and not a broken one; what it is NOT is fully local, and
// the report says so through GraftLocal.
func (fs *FS) prefetchGrafts(ctx context.Context, rep *PrefetchReport, want []graftWant, workers int) error {
	if len(want) == 0 {
		return nil
	}
	var (
		mu    sync.Mutex
		tasks = make([]func(), 0, len(want))
	)
	for _, w := range want {
		w := w
		tasks = append(tasks, func() {
			if fs.graftCache.holds(w.idHex) {
				mu.Lock()
				rep.GraftLocal++
				rep.GraftLocalBytes += w.loc.Length
				mu.Unlock()
				return
			}
			_, err := fs.readGraftChunk(ctx, w.e, w.loc, w.idHex, true)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fs.noteFailure(rep, err.Error())
				return
			}
			rep.GraftLocal++
			rep.GraftLocalBytes += w.loc.Length
			rep.GraftFetched += w.loc.Length
		})
	}
	runBounded(ctx, tasks, workers)
	// Finalize the open blob, or the bytes this pass just paid for are an
	// abandoned temp file the moment the process exits.
	fs.graftCache.flush()
	return ctx.Err()
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
func (fs *FS) referencedPacks(ctx context.Context, rep *PrefetchReport, collectGrafts bool) (map[string]struct{}, []graftWant, error) {
	packs := make(map[string]struct{})
	var wantGrafts []graftWant
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
	// Grafted refs are counted, not failed. The graft table is asked
	// FIRST for the same reason the read path asks it first: a grafted
	// identity is in no pack by construction, and packIndex.lookup would
	// answer "absent" — the sentence that means damage everywhere else.
	seenGraft := make(map[string]struct{})
	graftedRef := func(ctx context.Context, r *catalog.ChunkRef) (bool, error) {
		if fs.grafts == nil {
			return false, nil
		}
		e, loc, ok, err := fs.grafts.locate(ctx, r.Identity)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		idHex := hex.EncodeToString(r.Identity)
		if _, dup := seenGraft[idHex]; dup {
			// Counted once. Two files sharing a block — which a graft
			// dedups within itself — is one thing to fetch, not two, and
			// double-counting would make the budget refuse a set that
			// fits.
			return true, nil
		}
		seenGraft[idHex] = struct{}{}
		rep.Grafted++
		rep.GraftedBytes += r.LLen
		if collectGrafts {
			wantGrafts = append(wantGrafts, graftWant{e: e, loc: loc, idHex: idHex})
		}
		named := false
		for _, g := range rep.GraftRoots {
			if g.Path == e.sb.Path {
				named = true
			}
		}
		if !named {
			rep.GraftRoots = append(rep.GraftRoots, e.sb)
		}
		return true, nil
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
					grafted, err := graftedRef(ctx, r)
					if err != nil {
						return fmt.Errorf("prefetch: %q: %w", e.Name, err)
					}
					if grafted {
						continue
					}
					locateInto(hex.EncodeToString(r.Identity), "chunk")
				}
			}
		}
		return nil
	}
	if err := walk(RootInode); err != nil {
		return nil, nil, err
	}
	return packs, wantGrafts, nil
}
