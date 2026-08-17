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

// Bulk chunk fetching.
//
// A chunk read used to be exactly one ranged GET. Measured on a real
// federation session: 429 MB across 40,029 requests, about 10.7 KB each —
// one full round trip per CDC chunk. Bandwidth was never the constraint;
// latency was, one chunk at a time.
//
// Three mechanisms address that, in increasing order of aggression, and
// the order matters because the last one can LOSE:
//
//  1. COALESCE. The chunks one read needs from a pack are usually
//     adjacent — publish appends a file's chunks in order — and the pack
//     trailer gives every entry's offset and length up front, so the
//     spans are known before the first request instead of discovered one
//     at a time. Swallowing a little unwanted payload to avoid a round
//     trip is a good trade at any realistic bandwidth-delay product.
//  2. PARALLELIZE. Spans are independent. A bounded pool keeps several in
//     flight without turning one reader into a bandwidth stampede that
//     starves the user I/O the same mount is serving.
//  3. WHOLE PACK. Packs are immutable and content-addressed, which makes
//     them ideal cache units — but fetching 64 MB to serve one 10 KB read
//     is a serious regression for a mount doing scattered reads over a
//     large volume, and that is the common interactive case. So it is
//     never speculative: it waits for EVIDENCE, or for a bulk consumer's
//     explicit declaration (Prefetch is asking for the whole generation by
//     definition).
//
// Coalescing alone does not cover the workload that produced those
// numbers, and it is worth being precise about why. The chunker averages
// 4 MiB, so a big file is a handful of chunks — but any file between the
// inline threshold and the minimum chunk size is exactly ONE chunk, and a
// source tree is tens of thousands of those. There is nothing to coalesce
// within one file's read; the locality is ACROSS files, which arrive as
// separate reads. Whole-pack caching is what captures it, because publish
// lays a directory's files out next to each other in the same pack.
//
// Integrity is unchanged by any of it. A cached pack is not trusted as a
// unit: only its LENGTH is checked against the signed pack list, and every
// entry taken out of it is decoded and verified exactly as one arriving
// from a ranged read is. Nor may a cache problem become a read failure —
// every path here falls back to the federation.

const (
	// maxCoalesceGap is how much unwanted payload is worth reading to
	// avoid a second round trip.
	maxCoalesceGap = 1 << 20
	// maxSpanBytes bounds one coalesced request, so a single reader
	// neither buffers hundreds of megabytes nor holds a worker for the
	// length of a whole pack.
	maxSpanBytes = 8 << 20
	// fetchWorkers bounds concurrent range reads within one fill.
	fetchWorkers = 8

	// The whole-pack promotion policy. A pack is worth fetching whole once
	// a reader has demonstrably started consuming it, by either measure:
	//
	//   - BYTES: a quarter of the pack already pulled piecemeal. This is
	//     the multi-megabyte-chunk case, where a few requests already
	//     represent most of the pack.
	//   - ENTRIES: a sixteenth of the pack's entries already fetched, with
	//     an absolute floor. This is the many-small-files case, where the
	//     bytes stay small no matter how many round trips are spent.
	//
	// The entry rule is the aggressive one, so it carries a bound on how
	// wrong it can be: the remaining bytes may not exceed
	// maxSpeculationRatio times what the reader has already committed to
	// this pack. A user who opens a dozen scattered small files therefore
	// pays nothing extra — the ratio guard refuses — while a walk through
	// a directory converges on one transfer.
	packPromoteBytesNumer = 1
	packPromoteBytesDenom = 4
	packPromoteEntryNumer = 1
	packPromoteEntryDenom = 16
	minPromoteEntries     = 16
	maxSpeculationRatio   = 32
	// bulkPackNumer/bulkPackDenom is the test for a caller that has
	// declared bulk intent: it already knows what it needs, so the only
	// question is whether one transfer beats several.
	bulkPackNumer = 1
	bulkPackDenom = 2

	// maxWholePackBytes refuses whole-pack caching for packs far larger
	// than the 64 MiB publish target: an outsized pack is one long
	// transfer that would stall everything behind it.
	maxWholePackBytes = 256 << 20

	// DefaultPackCacheBytes bounds the whole-pack cache on disk. Packs are
	// large and a big volume will not fit; past the cap the least recently
	// used ones go.
	DefaultPackCacheBytes = 4 << 30
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

// packUse is the per-pack evidence whole-pack caching waits for: how many
// stored bytes this mount has pulled out of the pack in pieces. Entries
// are counted once, so re-reading a chunk the cache dropped does not
// inflate the case for downloading the pack.
type packUse struct {
	fetched int64
	counted map[string]struct{}
}

// notePackFetch records that entries were pulled out of pack piecemeal.
func (fs *FS) notePackFetch(pack string, keys []string, lengths []int64) {
	fs.packMu.Lock()
	defer fs.packMu.Unlock()
	u := fs.packUses[pack]
	if u == nil {
		u = &packUse{counted: make(map[string]struct{})}
		fs.packUses[pack] = u
	}
	for i, k := range keys {
		if _, dup := u.counted[k]; dup {
			continue
		}
		u.counted[k] = struct{}{}
		u.fetched += lengths[i]
	}
}

// packConsumed reports the bytes and the distinct entries this mount has
// pulled out of the pack one range at a time.
func (fs *FS) packConsumed(pack string) (bytes int64, entries int) {
	fs.packMu.Lock()
	defer fs.packMu.Unlock()
	if u := fs.packUses[pack]; u != nil {
		return u.fetched, len(u.counted)
	}
	return 0, 0
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

// chunkResident reports whether the decoded-chunk cache already holds the
// whole chunk. A short file is a torn fill and counts as absent.
func (fs *FS) chunkResident(idHex string, llen int64) bool {
	fi, err := os.Stat(filepath.Join(fs.chunkDir, idHex))
	return err == nil && fi.Size() == llen
}

// fillChunks brings every missing chunk in refs into the decoded cache,
// batched by pack. bulk declares that the caller wants all of this content
// regardless of what it reads next, which lowers the bar for fetching a
// pack whole.
//
// Best effort by contract: anything it fails to produce is left to the
// ordinary single-chunk path, which owns the error and the diagnostics.
// Callers hold swapMu.
func (fs *FS) fillChunks(ctx context.Context, refs []catalog.ChunkRef, bulk bool) {
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
		loc, ok := fs.packIndex[id]
		if !ok {
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
		if fs.wholePackWanted(pack, neededBytes(want), len(want), bulk) {
			pack, want := pack, want
			tasks = append(tasks, func() { fs.fillWholePack(ctx, pack, want) })
			continue
		}
		for _, sp := range coalesce(want) {
			pack, sp := pack, sp
			tasks = append(tasks, func() { fs.fillSpan(ctx, pack, sp) })
		}
	}
	runBounded(ctx, tasks, fetchWorkers)
}

func neededBytes(want []pendingChunk) int64 {
	var n int64
	for _, w := range want {
		n += w.loc.length
	}
	return n
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
	keys := make([]string, 0, len(sp.entries))
	lengths := make([]int64, 0, len(sp.entries))
	for _, w := range sp.entries {
		lo := w.loc.off - sp.off
		fs.storeChunk(w.id, &w.ref, buf[lo:lo+w.loc.length])
		keys = append(keys, w.id)
		lengths = append(lengths, w.loc.length)
	}
	fs.notePackFetch(pack, keys, lengths)
}

// fillWholePack serves the wanted entries out of a locally cached copy of
// the pack, fetching it first. Any failure degrades to ranged reads rather
// than to a read error.
func (fs *FS) fillWholePack(ctx context.Context, pack string, want []pendingChunk) {
	f, size, err := fs.openCachedPack(ctx, pack)
	if err != nil {
		for _, sp := range coalesce(want) {
			fs.fillSpan(ctx, pack, sp)
		}
		return
	}
	defer f.Close() //nolint:errcheck
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

// wholePackWanted applies the promotion policy. need/needEntries describe
// what the current fill is about to fetch from this pack, which counts
// towards the evidence. Callers hold swapMu.
func (fs *FS) wholePackWanted(pack string, need int64, needEntries int, bulk bool) bool {
	if fs.packCacheCap <= 0 {
		return false
	}
	size := fs.packSize[pack]
	if size <= 0 || size > maxWholePackBytes || size > fs.packCacheCap {
		return false
	}
	if fs.packCachedLocally(pack, size) {
		return true // already paid for; reading it beats going out again
	}
	if bulk {
		return need*bulkPackDenom >= size*bulkPackNumer
	}
	gotBytes, gotEntries := fs.packConsumed(pack)
	gotBytes += need
	gotEntries += needEntries
	total := fs.packEntries[pack]
	// A minimum number of DISTINCT entries is required whichever rule
	// fires, and it is the load-bearing guard. Chunks average 4 MiB, so a
	// couple of scattered 4 KiB reads already pull a quarter of a small
	// pack — bytes alone would call that "bulk consumption" when the
	// reader wanted twelve kilobytes. Distinct entries cannot be inflated
	// that way: it takes many separate requests to reach the floor, and
	// many separate requests to one pack is what bulk consumption is.
	if total <= 0 || gotEntries < minPromoteEntries {
		return false
	}
	byBytes := gotBytes*packPromoteBytesDenom >= size*packPromoteBytesNumer
	byEntries := gotEntries*packPromoteEntryDenom >= total*packPromoteEntryNumer
	if !byBytes && !byEntries {
		return false
	}
	// The bound on being wrong: never speculate on more than
	// maxSpeculationRatio times the bytes already committed to this pack.
	return size-gotBytes <= maxSpeculationRatio*gotBytes
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
func (fs *FS) openCachedPack(ctx context.Context, pack string) (*os.File, int64, error) {
	size := fs.packSize[pack]
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
	fs.evictPacks()
	return nil
}

// evictPacks trims the whole-pack cache to its byte cap, least recently
// used first. Removing a pack another goroutine is reading is safe: the
// open descriptor keeps the bytes alive, and the next reader that misses
// falls back to a ranged read.
func (fs *FS) evictPacks() {
	fs.evictMu.Lock()
	defer fs.evictMu.Unlock()
	entries, err := os.ReadDir(fs.packDir)
	if err != nil {
		return
	}
	type cached struct {
		name string
		size int64
		age  time.Time
	}
	var files []cached
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, cached{name: e.Name(), size: fi.Size(), age: fi.ModTime()})
		total += fi.Size()
	}
	if total <= fs.packCacheCap {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].age.Before(files[j].age) })
	for _, f := range files {
		if total <= fs.packCacheCap {
			return
		}
		if err := os.Remove(filepath.Join(fs.packDir, f.name)); err == nil {
			total -= f.size
		}
	}
}

// packRead returns one pack entry's stored bytes: from a locally cached
// whole pack when there is one, otherwise by ranged read — promoting the
// pack first if the evidence has piled up.
//
// The promotion check lives here, on the MISS path, rather than in the
// batched fill. It has to: a file between the inline threshold and the
// minimum chunk size is exactly one chunk, so a whole directory of small
// files arrives here one entry at a time and never through a batch at
// all. That is the workload whole-pack caching exists for, and checking
// only in the batch path would mean never checking for it.
func (fs *FS) packRead(ctx context.Context, key string, loc packLoc) ([]byte, error) {
	if fs.packCacheCap > 0 {
		if buf, ok := fs.readFromCachedPack(ctx, loc, false); ok {
			return buf, nil
		}
		if fs.wholePackWanted(loc.pack, loc.length, 1, false) {
			if buf, ok := fs.readFromCachedPack(ctx, loc, true); ok {
				fs.notePackFetch(loc.pack, []string{key}, []int64{loc.length})
				return buf, nil
			}
		}
	}
	buf, err := fs.readPackRange(ctx, loc)
	if err == nil {
		fs.notePackFetch(loc.pack, []string{key}, []int64{loc.length})
	}
	return buf, err
}

// readFromCachedPack serves one entry out of the whole-pack cache. With
// fetch set it will download the pack first; without, it only uses a copy
// already on disk. Any failure reports false — the caller goes to the
// federation, because a cache must never turn into a read error.
func (fs *FS) readFromCachedPack(ctx context.Context, loc packLoc, fetch bool) ([]byte, bool) {
	size := fs.packSize[loc.pack]
	if size <= 0 {
		return nil, false
	}
	if !fetch && !fs.packCachedLocally(loc.pack, size) {
		return nil, false
	}
	f, _, err := fs.openCachedPack(ctx, loc.pack)
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
