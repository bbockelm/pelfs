package genfs

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// Pack fetching: a pack is fetched WHOLE, or not at all.
//
// The obvious policy is one ranged GET per chunk. Measured on a real
// federation session that costs 429 MB across 40,029 requests, about
// 10.7 KB each — one full round trip per CDC chunk. Bandwidth is never
// the constraint there; latency is, one chunk at a time.
//
// The obvious repair is to fetch a pack whole once there is evidence a
// reader is consuming one — a byte ratio, an entry ratio, a floor on
// distinct entries, and a bound on how far ahead of the reader it may
// speculate. That works, and it is unpredictable: the same read costs a
// kilobyte or sixty-four megabytes depending on what the mount happened
// to have asked for earlier, and tuning it means tuning four constants
// against a workload nobody can name in advance.
//
// So the unit of transfer is the unit of storage instead. A pack is
// immutable and content-addressed, so it is the natural cache object; the
// cost of pulling one is bounded by the PUBLISHER's cut size, which is a
// number a volume owner can actually choose, rather than by a heuristic a
// reader has to get right. Granularity is a publish-side question now, and
// publish.DefaultTargetPackSize carries the sweep that answers it.
//
// Where this LOSES, plainly: a reader taking single small files from all
// over a tree moves several times the bytes ranged reads would (twice, at
// the shipped cut size; seventeen times at a 64 MiB one). It is faster
// even then, because it is fewer round trips — so the loss lands on a
// bandwidth-bound link and not on a latency-bound one. A reader with less
// disk than bandwidth turns it off.
//
// Ranged reads do not disappear, and where they remain they are scoped:
//
//   - COALESCE and PARALLELIZE serve only the mount that has switched
//     whole-pack caching OFF (PackCacheBytes negative — less disk than
//     bandwidth) and the fallback when a download fails. Neither may
//     become a read error.
//   - The pack cache is bounded and evicts, because a large volume does
//     not fit on a client. It shares ONE budget with the decoded chunks,
//     the spilled catalogs and the trailers (gencache.go): a cached pack
//     makes the chunks in it free to re-derive, so the four directories
//     are substitutes and a split between them would be a guess.
//
// Integrity is unchanged. A cached pack is not trusted as a unit: only its
// LENGTH is checked against the signed pack list, and every entry taken out
// of it — data chunk, catalog, or trailer — is verified exactly as one
// arriving from a ranged read is.

const (
	// maxCoalesceGap is how much unwanted payload is worth reading to
	// avoid a second round trip, on the ranged-read path.
	maxCoalesceGap = 1 << 20
	// maxSpanBytes bounds one coalesced request, so a single reader
	// neither buffers hundreds of megabytes nor holds a worker for the
	// length of a whole pack.
	maxSpanBytes = 8 << 20
	// fetchWorkers bounds concurrent range reads within one fill.
	fetchWorkers = 8

	// maxWholePackBytes refuses whole-pack caching for an outsized pack:
	// one long transfer that would stall every read queued behind it. A
	// publisher cutting at a sane size never reaches it; a generation
	// carrying one enormous entry does, and falls back to ranged reads.
	maxWholePackBytes = 256 << 20

	// DefaultPackCacheBytes is what the pack cache alone used to be
	// bounded to. The budget it names now covers the whole of CacheDir —
	// see DefaultCacheBytes and gencache.go, which is where evictPacks
	// went when the other three directories stopped being unbounded.
	DefaultPackCacheBytes = DefaultCacheBytes
)

// packTmpMaxAge is how long a leftover download temp file is tolerated. A
// killed process leaves one behind, and nothing will ever finish it; an
// hour is far longer than any transfer and short enough that the junk does
// not accumulate. A LIVE download by a second process reading the same
// state directory is younger than this and is left alone.
const packTmpMaxAge = time.Hour

// packTouchInterval is how stale a cached pack's mtime may get before a
// read refreshes it. Eviction only ever compares packs against each other,
// so minute-grained recency is plenty.
const packTouchInterval = time.Minute

// sweepPackTmp removes abandoned download temp files. The cache survives
// process exit on purpose — packs are immutable and content-addressed, so
// remounting a volume must not re-fetch what the last session already
// pulled down — which also means nothing else ever cleans up after a
// crash.
func (fs *FS) sweepPackTmp() {
	entries, err := os.ReadDir(fs.packDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-packTmpMaxAge)
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), ".tmp") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(fs.packDir, e.Name())) //nolint:errcheck
		}
	}
}

// pendingChunk is one chunk a fill has to produce.
type pendingChunk struct {
	id  string
	ref catalog.ChunkRef
	loc packLoc
}

// span is one coalesced pack range together with the entries inside it.
type span struct {
	off, length int64
	entries     []pendingChunk
}

// chunkResident reports whether the decoded-chunk arena already holds the
// chunk, so a batched fill can skip it. With the tier off nothing is ever
// resident.
func (fs *FS) chunkResident(idHex string, _ int64) bool {
	return fs.arena.has(idHex)
}

// fillChunks brings every missing chunk in refs into the decoded cache,
// batched by pack.
//
// Best effort by contract: anything it fails to produce is left to the
// ordinary single-chunk path, which owns the error and the diagnostics.
// Callers hold swapMu.
func (fs *FS) fillChunks(ctx context.Context, refs []catalog.ChunkRef) {
	seen := make(map[string]struct{}, len(refs))
	byPack := make(map[string][]pendingChunk)
	for i := range refs {
		r := refs[i]
		if len(r.Identity) == 0 {
			continue // a hole stores nothing
		}
		id := hex.EncodeToString(r.Identity)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if fs.chunkResident(id, r.LLen) {
			continue
		}
		loc, err := fs.packIndex.locate(ctx, id)
		if err != nil {
			continue // reported by the single-chunk path, in context
		}
		byPack[loc.pack] = append(byPack[loc.pack], pendingChunk{id: id, ref: r, loc: loc})
	}
	if len(byPack) == 0 {
		return
	}
	packs := make([]string, 0, len(byPack))
	for pack := range byPack {
		packs = append(packs, pack)
	}
	sort.Strings(packs)

	var tasks []func()
	for _, pack := range packs {
		want := byPack[pack]
		sort.Slice(want, func(i, j int) bool { return want[i].loc.off < want[j].loc.off })
		if fs.wholePackWanted(fs.packIndex, pack) {
			pack, want := pack, want
			tasks = append(tasks, func() { fs.fillWholePack(ctx, fs.packIndex, pack, want) })
			continue
		}
		if fs.arena == nil {
			// Ranged coalescing exists to fill the decoded-chunk tier
			// ahead of the reads that want it. With no tier to fill, the
			// bytes would be fetched, decoded and thrown away.
			continue
		}
		for _, sp := range coalesce(want) {
			pack, sp := pack, sp
			tasks = append(tasks, func() { fs.fillSpan(ctx, pack, sp) })
		}
	}
	runBounded(ctx, tasks, fetchWorkers)
}

// coalesce merges offset-sorted entries into as few ranges as the gap and
// span limits allow.
func coalesce(want []pendingChunk) []span {
	var out []span
	for _, w := range want {
		end := w.loc.off + w.loc.length
		if n := len(out); n > 0 {
			cur := &out[n-1]
			gap := w.loc.off - (cur.off + cur.length)
			if gap >= 0 && gap <= maxCoalesceGap && end-cur.off <= maxSpanBytes {
				cur.length = end - cur.off
				cur.entries = append(cur.entries, w)
				continue
			}
		}
		out = append(out, span{off: w.loc.off, length: w.loc.length, entries: []pendingChunk{w}})
	}
	return out
}

// fillSpan reads one coalesced range and decodes every entry in it.
func (fs *FS) fillSpan(ctx context.Context, pack string, sp span) {
	buf, err := fs.readPackRange(ctx, packLoc{pack: pack, off: sp.off, length: sp.length})
	if err != nil {
		return
	}
	for _, w := range sp.entries {
		lo := w.loc.off - sp.off
		fs.storeChunk(w.id, &w.ref, buf[lo:lo+w.loc.length])
	}
}

// fillWholePack serves the wanted entries out of a locally cached copy of
// the pack, fetching it first. Any failure degrades to ranged reads rather
// than to a read error.
func (fs *FS) fillWholePack(ctx context.Context, idx *packIndex, pack string, want []pendingChunk) {
	f, size, err := fs.openCachedPack(ctx, idx, pack)
	if err != nil {
		if fs.arena == nil {
			return
		}
		for _, sp := range coalesce(want) {
			fs.fillSpan(ctx, pack, sp)
		}
		return
	}
	defer f.Close() //nolint:errcheck
	if fs.arena == nil {
		// The pack is local, which is the whole of a batched fill when
		// there is no decoded tier to fill: each read decodes the entry it
		// wants out of it, and pre-decoding the rest would be work thrown
		// away.
		return
	}
	var missed []pendingChunk
	for _, w := range want {
		if w.loc.off+w.loc.length > size {
			missed = append(missed, w)
			continue
		}
		buf := make([]byte, w.loc.length)
		if _, err := f.ReadAt(buf, w.loc.off); err != nil {
			missed = append(missed, w)
			continue
		}
		fs.storeChunk(w.id, &w.ref, buf)
	}
	for _, sp := range coalesce(missed) {
		fs.fillSpan(ctx, pack, sp)
	}
}

// wholePackWanted reports whether this pack may be fetched whole. There is
// no per-read judgement left in it: the answer depends on the mount's
// configuration and the pack's signed size, never on what has been read.
func (fs *FS) wholePackWanted(idx *packIndex, pack string) bool {
	if fs.packCacheCap <= 0 {
		return false
	}
	size := idx.size(pack)
	// A pack larger than the whole cache budget would be evicted by its
	// own arrival, one chunk read at a time, forever.
	return size > 0 && size <= maxWholePackBytes && size <= fs.cacheCap
}

func (fs *FS) packPath(pack string) string { return filepath.Join(fs.packDir, pack) }

// packCachedLocally reports whether a COMPLETE copy of the pack is on
// disk. Length is the only whole-object check available — the signed pack
// list carries a trailer hash, not a hash of the whole object — so a
// partial copy is what this exists to reject. Every entry read out of it
// is still verified individually at decode.
func (fs *FS) packCachedLocally(pack string, size int64) bool {
	fi, err := os.Stat(fs.packPath(pack))
	return err == nil && fi.Size() == size
}

// openCachedPack returns an open handle to the locally cached pack,
// downloading it whole if it is not there yet.
func (fs *FS) openCachedPack(ctx context.Context, idx *packIndex, pack string) (*os.File, int64, error) {
	size := idx.size(pack)
	if size <= 0 {
		return nil, 0, fmt.Errorf("genfs: pack %s has no recorded size", pack)
	}
	fp := fs.packPath(pack)
	open := func() (*os.File, int64, error) {
		f, err := os.Open(fp)
		if err != nil {
			return nil, 0, err
		}
		fi, err := f.Stat()
		if err != nil || fi.Size() != size {
			f.Close() //nolint:errcheck
			if err == nil {
				err = fmt.Errorf("genfs: cached pack %s is %d bytes, want %d", pack, fi.Size(), size)
			}
			return nil, 0, err
		}
		// mtime is the eviction clock: unlike atime it is not silently
		// disabled by a relatime mount. Refreshing it is a write syscall
		// and every chunk served out of this pack comes through here, so
		// it is only worth doing at eviction-decision granularity.
		if now := time.Now(); now.Sub(fi.ModTime()) > packTouchInterval {
			os.Chtimes(fp, now, now) //nolint:errcheck
		}
		return f, fi.Size(), nil
	}
	if f, n, err := open(); err == nil {
		return f, n, nil
	}
	unlock := fs.lockFill("pack:" + pack)
	defer unlock()
	if f, n, err := open(); err == nil {
		return f, n, nil
	}
	if err := fs.downloadPack(ctx, pack, size); err != nil {
		return nil, 0, err
	}
	return open()
}

// downloadPack fetches a whole pack into the cache via temp file and
// rename, so no reader can ever observe a partial one, and refuses a body
// whose length disagrees with the signed pack list.
func (fs *FS) downloadPack(ctx context.Context, pack string, size int64) error {
	if err := os.MkdirAll(fs.packDir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(fs.packDir, pack+".tmp*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()        //nolint:errcheck
		os.Remove(tmpName) //nolint:errcheck
		return err
	}
	rc, err := fs.inner.Get(ctx, packstore.PackDirKey+"/"+pack, 0, -1)
	if err != nil {
		return fail(err)
	}
	// LimitReader at size+1 so an over-long body is detected rather than
	// silently truncated to the expected length.
	n, cerr := io.Copy(tmp, io.LimitReader(rc, size+1))
	if closeErr := rc.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		return fail(cerr)
	}
	if n != size {
		return fail(fmt.Errorf("genfs: pack %s downloaded %d bytes, pack list says %d", pack, n, size))
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return err
	}
	if err := os.Rename(tmpName, fs.packPath(pack)); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return err
	}
	// A pack is the largest single thing this cache takes, so it is the
	// one most likely to put the budget over on its own. Eviction is no
	// longer the pack directory's private business: one budget covers
	// every directory under CacheDir, and this pack now competes for it
	// with the decoded chunks, the spilled catalogs and the trailers
	// (gencache.go, which is where evictPacks went).
	fs.noteCached(size)
	return nil
}

// packRead returns one pack entry's stored bytes, out of a local copy of
// the whole pack — downloading it if this is the first entry anyone has
// wanted from it. Ranged reads are the fallback, not the plan.
func (fs *FS) packRead(ctx context.Context, idx *packIndex, key string, loc packLoc) ([]byte, error) {
	if fs.wholePackWanted(idx, loc.pack) {
		if buf, ok := fs.readFromCachedPack(ctx, idx, loc); ok {
			return buf, nil
		}
	}
	return fs.readPackRange(ctx, loc)
}

// readFromCachedPack serves one entry out of the whole-pack cache,
// downloading the pack first if it is not there. Any failure reports false
// — the caller goes to the federation, because a cache must never turn into
// a read error.
func (fs *FS) readFromCachedPack(ctx context.Context, idx *packIndex, loc packLoc) ([]byte, bool) {
	f, _, err := fs.openCachedPack(ctx, idx, loc.pack)
	if err != nil {
		return nil, false
	}
	defer f.Close() //nolint:errcheck
	buf := make([]byte, loc.length)
	if _, err := f.ReadAt(buf, loc.off); err != nil {
		return nil, false
	}
	return buf, true
}

// runBounded executes tasks with at most workers of them in flight.
func runBounded(ctx context.Context, tasks []func(), workers int) {
	if len(tasks) == 0 {
		return
	}
	if len(tasks) == 1 {
		tasks[0]()
		return
	}
	if workers > len(tasks) {
		workers = len(tasks)
	}
	ch := make(chan func())
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				t()
			}
		}()
	}
	for _, t := range tasks {
		select {
		case ch <- t:
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return
		}
	}
	close(ch)
	wg.Wait()
}
