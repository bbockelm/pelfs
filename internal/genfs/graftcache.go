package genfs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The local cache of grafted blocks: what makes `--prefetch all` mean
// something on a grafted volume, and what keeps a re-read off a third
// party's storage.
//
// # Prefetching a graft is NOT materializing it
//
// The two were conflated once and the distinction is the whole reason
// this file exists:
//
//	MATERIALIZE writes grafted bytes into PUBLISHED packs. It needs the
//	write lease, it produces a new generation, and the file stops being
//	grafted forever. It changes the volume, so it is `pelfs graft
//	--materialize` and not a mount flag.
//
//	PREFETCH puts the bytes in the LOCAL CACHE. No lease, no publish, no
//	generation, nothing ungrafted, the volume unchanged. It is a read-side
//	operation on this machine, and it is exactly what a user who typed
//	`--prefetch all` asked for.
//
// # Storage shape, and the lesson it must not undo
//
// NOT one file per block. That is the inode explosion chunkarena.go was
// built to end (6,646 files down to 1 on a 166 MiB tree), and a graft is
// where it would be worst: 10 TB at the 1 MiB floor is ten and a half
// million blocks.
//
// NOT the arena either. The arena is a bounded DECODE cache — a fixed
// mmap'd reservation, 256 MiB by default, capped at CacheBytes/8, with a
// cursor that overwrites. A prefetch is not a decode cache: it is asked to
// hold what it was told to hold.
//
// So: BLOBS under packs/, alongside the cached packs, cut at the same
// order of size a pack is. Each blob is ONE FILE holding many verified
// blocks, self-describing — payload, then a table, then a footer:
//
//	[block bytes ...][n × {32-byte identity, u64 offset, u32 length}][footer]
//
// One file rather than a blob plus a sidecar index, because eviction
// deletes files and a pair can be split; a self-describing blob cannot
// lose its own index. And under packs/ rather than a directory of its own,
// because everything that already accounts for the cache — the LRU sweep,
// the byte budget, DirUsage reporting, `pelfs cache` — walks
// cacheDirNames and keeps working with no change at all. A blob is named
// `g-<hex>.gcache`, which cannot collide with a pack (`p-<time>-<hex>`).
//
// # The index is RESIDENT, and it is bounded by the CACHE, not the graft
//
// identity -> (blob, offset, length), in memory. That sounds like the
// thing internal/graft's windowed reader exists to avoid, and it is not:
// this map describes what is ON THIS DISK, so it is bounded by the cache
// budget divided by the block size. A 100 GB cache at the 1 MiB floor is
// ~100,000 entries, about 5 MB. The graft may be 10 TB; the cache is not.
//
// # Every read is verified, cached or not
//
// A block served from here is hashed against the identity the signed
// catalog names, exactly as one off the wire is (readGraftChunk). That is
// not belt-and-braces: it is what lets this whole file be a pure HINT. A
// corrupt blob, a stale index entry, a truncated file, a blob half-written
// by a killed process — every one of them produces a hash that does not
// match, which is treated as a MISS and refetched from the source. The
// cache can make a read slow. It cannot make a read wrong, and it cannot
// make a read fail.
//
// The one distinction that has to be kept, and it is kept in
// readGraftChunk: a mismatch from the CACHE is a miss, and a mismatch from
// the SOURCE is "the graft source has changed" and fails closed. Blurring
// them would either hide a changed source behind a refetch loop or
// accuse a third party of changing when a local file rotted.

const (
	// graftBlobSuffix names a cache blob. Distinct from a pack, which is
	// `p-<unixnano>-<hex>`.
	graftBlobSuffix = ".gcache"
	// graftBlobTarget is how large a blob grows before it is finalized and
	// a new one started. It is the same order as maxWholePackBytes for the
	// same two reasons: eviction should take back a bounded unit rather
	// than the whole prefetch, and a process killed mid-prefetch should
	// lose a bounded unit rather than an hour.
	graftBlobTarget = 256 << 20
	// graftRecordLen is one table entry: identity, offset, length.
	graftRecordLen = 32 + 8 + 4
	// graftFooterLen is fixed and 8-byte aligned.
	graftFooterLen = 32
	graftMagic     = "PELFSGC1"
)

// graftLoc is where one cached block lives on this disk.
type graftLoc struct {
	path   string // absolute; a blob still being written is at its .tmp path
	off    int64
	length int64
}

// graftBlob is one cache file being written.
type graftBlob struct {
	f     *os.File
	tmp   string // path being written
	final string // path it is renamed to
	// off, recs and ids are guarded by graftCache.mu.
	off  int64
	recs []byte
	ids  []string
	// pin is set when this blob was filled by a prefetch, which asked for
	// these bytes to be here and should not have them swept out from under
	// it by the next catalog spill.
	pin bool
	// wg counts writes in flight into this blob, so a finalize cannot
	// append the table over a block still being written.
	wg sync.WaitGroup
}

// graftCache is the disk tier for grafted blocks.
type graftCache struct {
	dir string

	mu     sync.Mutex
	loaded bool
	idx    map[string]graftLoc
	// pinned names finalized blobs a prefetch filled, by BASE name so the
	// eviction sweep can match on the name it has.
	pinned map[string]struct{}
	cur    *graftBlob

	hits          atomic.Int64
	misses        atomic.Int64
	stored        atomic.Int64
	storedBytes   atomic.Int64
	pinnedEvicted atomic.Int64
}

// GraftCacheStats is what the graft disk tier did this session.
type GraftCacheStats struct {
	// Blocks is how many distinct blocks are cached on this disk and
	// Bytes what they weigh.
	Blocks int
	Bytes  int64
	// Hits and Misses count graft block reads answered from the disk and
	// not, since Open.
	Hits, Misses int64
	// Stored counts blocks written into the cache this session.
	Stored      int64
	StoredBytes int64
	// PinnedEvicted counts prefetched blocks a later eviction had to take
	// back anyway. It is the number that says a `--prefetch all` promise
	// stopped being true, and it is zero in every healthy session.
	PinnedEvicted int64
}

func newGraftCache(dir string) *graftCache {
	return &graftCache{dir: dir, idx: map[string]graftLoc{}, pinned: map[string]struct{}{}}
}

// load reads the blobs left by earlier sessions. It is lazy: a mount that
// never reads a grafted byte never pays for it.
//
// The cache survives process exit on purpose, exactly as the pack cache
// does — remounting a volume must not re-fetch what the last session
// pulled down, and for a graft that is somebody else's bandwidth as well
// as yours. Nothing that comes back from disk is TRUSTED by being here;
// it is verified on the way out like everything else.
func (c *graftCache) load() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded {
		return
	}
	c.loaded = true
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, graftBlobSuffix) {
			continue
		}
		path := filepath.Join(c.dir, name)
		if err := c.adoptLocked(path); err != nil {
			// A blob whose footer does not check out is a blob a killed
			// process left behind, or one that rotted. It is a cache, so
			// nothing else owns it and the right answer is to remove it —
			// a partially written one would otherwise be read as a
			// successful miss forever.
			os.Remove(path) //nolint:errcheck
		}
	}
}

// adoptLocked reads one finalized blob's table. Callers hold mu.
func (c *graftCache) adoptLocked(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size < graftFooterLen {
		return fmt.Errorf("genfs: %s is too short to be a graft cache blob", path)
	}
	var foot [graftFooterLen]byte
	if _, err := f.ReadAt(foot[:], size-graftFooterLen); err != nil {
		return err
	}
	if string(foot[0:8]) != graftMagic {
		return fmt.Errorf("genfs: %s is not a graft cache blob", path)
	}
	if v := binary.LittleEndian.Uint32(foot[8:]); v != 1 {
		return fmt.Errorf("genfs: %s is version %d", path, v)
	}
	count := int64(binary.LittleEndian.Uint32(foot[12:]))
	tableOff := int64(binary.LittleEndian.Uint64(foot[16:]))
	// Every length off the disk is held against the file's own size before
	// anything is allocated, for the same reason the windowed index reader
	// holds them against the signed size: a bad number must not turn into
	// a large allocation.
	if count < 0 || tableOff < 0 || tableOff+count*graftRecordLen+graftFooterLen != size {
		return fmt.Errorf("genfs: %s claims %d records at %d in a %d-byte file",
			path, count, tableOff, size)
	}
	table := make([]byte, count*graftRecordLen)
	if _, err := f.ReadAt(table, tableOff); err != nil {
		return err
	}
	for i := int64(0); i < count; i++ {
		rec := table[i*graftRecordLen:]
		off := int64(binary.LittleEndian.Uint64(rec[32:]))
		length := int64(binary.LittleEndian.Uint32(rec[40:]))
		if off < 0 || length < 0 || off+length > tableOff {
			return fmt.Errorf("genfs: %s record %d is outside its own payload", path, i)
		}
		c.idx[hex.EncodeToString(rec[:32])] = graftLoc{path: path, off: off, length: length}
	}
	return nil
}

// get serves one block from disk. The bytes are NOT verified here — the
// caller does that, on the cached path and the network path alike, which
// is what makes a corrupt blob a miss rather than a wrong read.
func (c *graftCache) get(idHex string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.load()
	c.mu.Lock()
	loc, ok := c.idx[idHex]
	c.mu.Unlock()
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	f, err := os.Open(loc.path)
	if err != nil {
		c.forget(idHex)
		c.misses.Add(1)
		return nil, false
	}
	defer f.Close() //nolint:errcheck
	buf := make([]byte, loc.length)
	if _, err := f.ReadAt(buf, loc.off); err != nil {
		c.forget(idHex)
		c.misses.Add(1)
		return nil, false
	}
	// mtime is the eviction clock (gencache.go uses it rather than atime,
	// which a relatime mount silently disables), so a blob being read must
	// look recently used or the sweep will take the hot one first.
	if fi, err := f.Stat(); err == nil {
		if now := time.Now(); now.Sub(fi.ModTime()) > packTouchInterval {
			os.Chtimes(loc.path, now, now) //nolint:errcheck
		}
	}
	c.hits.Add(1)
	return buf, true
}

// forget drops an entry whose blob turned out not to serve it.
func (c *graftCache) forget(idHex string) {
	c.mu.Lock()
	delete(c.idx, idHex)
	c.mu.Unlock()
}

// put stores one verified block. pin marks it as prefetched, which asks
// the eviction sweep to take other things first.
//
// Errors are swallowed on purpose: this is a cache, and a disk that will
// not take a block must not turn a read that already succeeded into a
// failure.
func (c *graftCache) put(idHex string, buf []byte, pin bool) {
	if c == nil || len(buf) == 0 {
		return
	}
	c.load()
	var (
		blob *graftBlob
		off  int64
		full *graftBlob
	)
	c.mu.Lock()
	if _, dup := c.idx[idHex]; dup {
		c.mu.Unlock()
		return
	}
	if c.cur == nil {
		if err := c.openLocked(pin); err != nil {
			c.mu.Unlock()
			return
		}
	}
	blob = c.cur
	// A prefetch that lands in a blob a read started keeps the whole blob:
	// pinning is per FILE because eviction is per file, so the union is
	// the only answer that does not lie in one direction or the other.
	blob.pin = blob.pin || pin
	off = blob.off
	blob.off += int64(len(buf))
	id, err := hex.DecodeString(idHex)
	if err != nil || len(id) != 32 {
		c.mu.Unlock()
		return
	}
	var rec [graftRecordLen]byte
	copy(rec[0:], id)
	binary.LittleEndian.PutUint64(rec[32:], uint64(off))
	binary.LittleEndian.PutUint32(rec[40:], uint32(len(buf)))
	blob.recs = append(blob.recs, rec[:]...)
	blob.ids = append(blob.ids, idHex)
	c.idx[idHex] = graftLoc{path: blob.tmp, off: off, length: int64(len(buf))}
	blob.wg.Add(1)
	if blob.off >= graftBlobTarget {
		full, c.cur = blob, nil
	}
	c.mu.Unlock()

	// Outside the lock, so that a prefetch's workers write into one blob
	// in parallel rather than queueing behind each other.
	_, werr := blob.f.WriteAt(buf, off)
	blob.wg.Done()
	if werr != nil {
		c.forget(idHex)
	} else {
		c.stored.Add(1)
		c.storedBytes.Add(int64(len(buf)))
	}
	if full != nil {
		c.finalize(full)
	}
}

// openLocked starts a new blob. Callers hold mu.
func (c *graftCache) openLocked(pin bool) error {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	final := filepath.Join(c.dir, "g-"+hex.EncodeToString(b[:])+graftBlobSuffix)
	// The .tmp in the name is load-bearing twice over: the eviction sweep
	// skips it (an in-flight write is not a candidate) and sweepPackTmp
	// removes it if a process dies holding it.
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	c.cur = &graftBlob{f: f, tmp: tmp, final: final, pin: pin}
	return nil
}

// finalize appends the table and footer, renames the blob into place, and
// re-points its entries at the name eviction will see.
func (c *graftCache) finalize(b *graftBlob) {
	b.wg.Wait()
	c.mu.Lock()
	recs, ids, off := b.recs, b.ids, b.off
	c.mu.Unlock()

	fail := func() {
		b.f.Close()      //nolint:errcheck
		os.Remove(b.tmp) //nolint:errcheck
		c.mu.Lock()
		for _, id := range ids {
			if loc, ok := c.idx[id]; ok && loc.path == b.tmp {
				delete(c.idx, id)
			}
		}
		c.mu.Unlock()
	}
	var foot [graftFooterLen]byte
	copy(foot[0:8], graftMagic)
	binary.LittleEndian.PutUint32(foot[8:], 1)
	binary.LittleEndian.PutUint32(foot[12:], uint32(len(ids)))
	binary.LittleEndian.PutUint64(foot[16:], uint64(off))
	if _, err := b.f.WriteAt(recs, off); err != nil {
		fail()
		return
	}
	if _, err := b.f.WriteAt(foot[:], off+int64(len(recs))); err != nil {
		fail()
		return
	}
	// Synced before the rename, so a crash cannot leave a NAMED blob whose
	// footer never reached the disk. A blob is worth an fsync: it is up to
	// 256 MiB of somebody else's bandwidth.
	if err := b.f.Sync(); err != nil {
		fail()
		return
	}
	if err := b.f.Close(); err != nil {
		fail()
		return
	}
	if err := os.Rename(b.tmp, b.final); err != nil {
		fail()
		return
	}
	c.mu.Lock()
	for _, id := range ids {
		if loc, ok := c.idx[id]; ok && loc.path == b.tmp {
			loc.path = b.final
			c.idx[id] = loc
		}
	}
	if b.pin {
		c.pinned[filepath.Base(b.final)] = struct{}{}
	}
	c.mu.Unlock()
}

// flush finalizes whatever blob is open, so that the bytes a prefetch just
// fetched survive this process. A prefetch calls it; so does Close.
func (c *graftCache) flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	b := c.cur
	c.cur = nil
	c.mu.Unlock()
	if b != nil {
		c.finalize(b)
	}
}

// pinnedBlobs is the set of blob file names a prefetch asked for, by base
// name, for the eviction sweep.
func (c *graftCache) pinnedBlobs() map[string]struct{} {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pinned) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(c.pinned))
	for k := range c.pinned {
		out[k] = struct{}{}
	}
	return out
}

// notePinnedEvicted records that the sweep had to take back bytes a
// prefetch was promised, which is the one thing that makes a `--prefetch
// all` report stop being true.
func (c *graftCache) notePinnedEvicted(name string, n int64) {
	if c == nil {
		return
	}
	c.pinnedEvicted.Add(n)
	c.mu.Lock()
	delete(c.pinned, name)
	for id, loc := range c.idx {
		if filepath.Base(loc.path) == name {
			delete(c.idx, id)
		}
	}
	c.mu.Unlock()
}

// holds reports whether a block is on this disk, which is what a prefetch
// checks before deciding to fetch it.
func (c *graftCache) holds(idHex string) bool {
	if c == nil {
		return false
	}
	c.load()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.idx[idHex]
	return ok
}

// stats snapshots the tier.
func (c *graftCache) stats() GraftCacheStats {
	if c == nil {
		return GraftCacheStats{}
	}
	c.load()
	c.mu.Lock()
	blocks := len(c.idx)
	var bytes int64
	for _, loc := range c.idx {
		bytes += loc.length
	}
	c.mu.Unlock()
	return GraftCacheStats{
		Blocks: blocks, Bytes: bytes,
		Hits: c.hits.Load(), Misses: c.misses.Load(),
		Stored: c.stored.Load(), StoredBytes: c.storedBytes.Load(),
		PinnedEvicted: c.pinnedEvicted.Load(),
	}
}

// blobNames lists the finalized blobs, sorted, for tests and reports.
func (c *graftCache) blobNames() []string {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), graftBlobSuffix) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
