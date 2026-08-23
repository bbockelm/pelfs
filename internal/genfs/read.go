package genfs

import (
	"container/list"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/entrycodec"
)

// extentCacheCap bounds the per-inode resolved extent maps kept in memory.
// Resolution is one Stat plus one Chunks/Inline query, so eviction is cheap.
const extentCacheCap = 128

// extents is one file's resolved content map: either inline bytes or a
// chunk list with logical offsets (prefix sums) filled in.
type extents struct {
	length int64
	inline []byte
	refs   []catalog.ChunkRef
}

type extentCache struct {
	cap  int
	mu   sync.Mutex
	byIn map[uint64]*list.Element
	lru  *list.List // element values are *extentEntry
}

type extentEntry struct {
	ino uint64
	ext *extents
}

func newExtentCache(capacity int) *extentCache {
	return &extentCache{cap: capacity, byIn: make(map[uint64]*list.Element), lru: list.New()}
}

func (c *extentCache) get(ino uint64) *extents {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byIn[ino]; ok {
		c.lru.MoveToFront(e)
		return e.Value.(*extentEntry).ext
	}
	return nil
}

func (c *extentCache) put(ino uint64, ext *extents) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byIn[ino]; ok {
		c.lru.MoveToFront(e)
		e.Value.(*extentEntry).ext = ext
		return
	}
	c.byIn[ino] = c.lru.PushFront(&extentEntry{ino: ino, ext: ext})
	for c.lru.Len() > c.cap {
		back := c.lru.Back()
		delete(c.byIn, back.Value.(*extentEntry).ino)
		c.lru.Remove(back)
	}
}

func (c *extentCache) drop(ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byIn[ino]; ok {
		delete(c.byIn, ino)
		c.lru.Remove(e)
	}
}

// extentsOf resolves ino's content map, from cache when possible. Requires
// residency (ErrStale otherwise).
func (fs *FS) extentsOf(ctx context.Context, ino uint64) (*extents, error) {
	// A cache hit still requires residency: extents outliving Forget must
	// not resurrect a stale inode.
	if _, err := fs.residencyOf(ino); err != nil {
		return nil, err
	}
	if e := fs.ext.get(ino); e != nil {
		return e, nil
	}
	cat, release, n, err := fs.acquireContent(ctx, ino)
	if err != nil {
		return nil, err
	}
	defer release()
	if n.Type != catalog.TypeFile {
		return nil, fmt.Errorf("genfs: read on non-file inode %d (type %d)", ino, n.Type)
	}
	e := &extents{length: n.Length}
	inline, err := cat.Inline(int64(ino))
	if err != nil {
		return nil, err
	}
	if inline != nil {
		if int64(len(inline)) != n.Length {
			return nil, fmt.Errorf("genfs: inode %d inline is %d bytes, node length %d", ino, len(inline), n.Length)
		}
		e.inline = inline
	} else {
		refs, err := cat.Chunks(int64(ino))
		if err != nil {
			return nil, err
		}
		if refs == nil && n.Length > 0 {
			return nil, fmt.Errorf("genfs: inode %d has length %d but no content records", ino, n.Length)
		}
		e.refs = refs
	}
	fs.ext.put(ino, e)
	return e, nil
}

// Content is one file's stored content records: inline bytes, or the
// chunk list, exactly as this generation's catalog holds them.
type Content struct {
	// Length is the node row's length, for the caller to reconcile
	// against whatever it believes the file's size to be.
	Length int64
	// Inline is the whole body of a file stored in the catalog; nil for a
	// chunked file.
	Inline []byte
	// Refs is a chunked file's list, in logical order. A nil Identity is
	// a hole. Nil for an inline file.
	Refs []catalog.ChunkRef
	// External reports that at least one of Refs resolves through a GRAFT
	// rather than through this volume's packs (graft.go).
	//
	// It is one bool for the whole file rather than one per ref, because
	// both consumers act on the file: a copy-up materializes the file, and
	// the dedup set admits or refuses the file's identities. Neither has a
	// use for "the third extent is external".
	//
	// Every caller that carries these records forward MUST look at it. The
	// records are valid only in a generation that also states the graft
	// locating them, and their identities must never enter a dedup set —
	// see publish's reuseContent and memtable.Adopt for the two things
	// that go wrong otherwise.
	External bool
}

// ContentOf returns ino's content records WITHOUT reading a byte of file
// data. It exists for the seal: a file whose bytes are unchanged since
// this generation already has chunk identities published here, and
// recomputing them means downloading the file back from the federation
// just to rediscover what the catalog already says.
//
// Every non-hole identity is checked against this generation's pack index
// before it is handed out, so a caller carrying these records into a new
// generation can only carry records some listed pack actually holds.
//
// That check is why this is one of the few callers that asks for the WHOLE
// location map. A read only ever needs to find the pack it is about to
// fetch, so the map fills in lazily; a check for ABSENCE needs every pack
// indexed, or it would report content missing that has merely not been
// probed for — and the caller's response to "missing" is to re-upload a
// file it already has, or to refuse the seal. The map is built once per
// mount and the trailers are cached across mounts, so a seal pays it once.
func (fs *FS) ContentOf(ctx context.Context, ino uint64) (Content, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	if err := fs.packIndex.all(ctx); err != nil {
		return Content{}, err
	}
	e, err := fs.extentsOf(ctx, ino)
	if err != nil {
		return Content{}, err
	}
	out := Content{Length: e.length}
	if e.inline != nil {
		out.Inline = append([]byte(nil), e.inline...)
		return out, nil
	}
	if e.refs == nil {
		return out, nil
	}
	// The extent cache hands out one shared *extents to every reader, so
	// the list and its identities are copied rather than aliased.
	out.Refs = make([]catalog.ChunkRef, len(e.refs))
	for i := range e.refs {
		r := e.refs[i]
		if r.Identity != nil {
			idHex := hex.EncodeToString(r.Identity)
			// A graft holds it, or a pack does. The graft is asked first
			// for the same reason the read path asks it first (graft.go),
			// and asking at all is what keeps a copy-up of a grafted file
			// from being reported as damage: memtable.Adopt calls this,
			// and "present in no listed pack" would abort every seal over
			// a grafted subtree.
			//
			// A caller carrying these records forward must therefore also
			// carry the GRAFT that locates them — see publish's Grafts
			// option. Records whose location the next generation does not
			// state are exactly the hazard this check exists to prevent;
			// grafts move the boundary of "listed", they do not remove it.
			if fs.graftHolds(r.Identity) {
				out.External = true
			} else if _, ok := fs.packIndex.lookup(idHex); !ok {
				return Content{}, fmt.Errorf("genfs: inode %d references chunk %s, present in no listed pack", ino, idHex)
			}
			r.Identity = append([]byte(nil), r.Identity...)
		}
		out.Refs[i] = r
	}
	return out, nil
}

// Read fills dst from ino at off, returning the byte count: the full
// min(len(dst), EOF-off) — short only at EOF, 0 at or past it. Holes (NULL
// identity chunk rows) read as zeros. Chunks are served from the decoded
// arena under CacheDir, decoded out of a local pack on miss.
func (fs *FS) Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("genfs: negative read offset %d", off)
	}
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	e, err := fs.extentsOf(ctx, ino)
	if err != nil {
		return 0, err
	}
	if off >= e.length || len(dst) == 0 {
		return 0, nil
	}
	n := int64(len(dst))
	if off+n > e.length {
		n = e.length - off
	}
	if e.inline != nil {
		copy(dst[:n], e.inline[off:off+n])
		return int(n), nil
	}
	// A read spanning several chunks used to be one round trip per chunk,
	// issued serially by the loop below. Fill them together first: the
	// chunks of one file are laid out adjacently in their pack, so the
	// whole span is usually one request.
	if need := overlapping(e.refs, off, off+n); len(need) > 1 {
		fs.fillChunks(ctx, need)
	}
	for i := range e.refs {
		r := &e.refs[i]
		if r.LogicalOffset+r.LLen <= off || r.LogicalOffset >= off+n {
			continue
		}
		lo := max64(off, r.LogicalOffset)
		hi := min64(off+n, r.LogicalOffset+r.LLen)
		window := dst[lo-off : hi-off]
		if r.Identity == nil {
			for j := range window {
				window[j] = 0
			}
			continue
		}
		if err := fs.readChunkAt(ctx, r, lo-r.LogicalOffset, window); err != nil {
			return 0, err
		}
	}
	return int(n), nil
}

// overlapping collects the non-hole refs a read of [off, end) touches.
func overlapping(refs []catalog.ChunkRef, off, end int64) []catalog.ChunkRef {
	var out []catalog.ChunkRef
	for i := range refs {
		r := &refs[i]
		if r.Identity == nil || r.LogicalOffset+r.LLen <= off || r.LogicalOffset >= end {
			continue
		}
		out = append(out, *r)
	}
	return out
}

// chunkCounters is what the decoded-chunk tier is doing: how often a read
// was served out of it, how often it had to be filled, and the decode work
// a fill costs. It is the evidence for whether the tier earns its keep.
type chunkCounters struct {
	hits         atomic.Int64
	misses       atomic.Int64
	decodes      atomic.Int64
	decodedBytes atomic.Int64
}

// ChunkStats is a snapshot of the decoded-chunk tier's counters.
type ChunkStats struct {
	// Hits are chunk reads served from a decoded cache file, Misses ones
	// that had to go to the pack. With the tier off every read is a miss
	// by definition.
	Hits, Misses int64
	// Decodes and DecodedBytes are the zstd/AES-GCM work the misses cost,
	// which is precisely what the tier exists to avoid repeating.
	Decodes, DecodedBytes int64
}

// ChunkStats reports the decoded-chunk tier's counters since Open.
func (fs *FS) ChunkStats() ChunkStats {
	return ChunkStats{
		Hits:         fs.chunkStats.hits.Load(),
		Misses:       fs.chunkStats.misses.Load(),
		Decodes:      fs.chunkStats.decodes.Load(),
		DecodedBytes: fs.chunkStats.decodedBytes.Load(),
	}
}

// readChunkAt fills window with chunk bytes starting at chunkOff. Cache
// files hold verified decoded bytes and are trusted on hit (identity is
// checked once, at fill — see the package comment for the encrypted-volume
// caveat where the GCM tag stands in for the keyed identity).
func (fs *FS) readChunkAt(ctx context.Context, r *catalog.ChunkRef, chunkOff int64, window []byte) error {
	idHex := hex.EncodeToString(r.Identity)
	if fs.arena.read(idHex, chunkOff, window) {
		fs.chunkStats.hits.Add(1)
		return nil
	}
	if fs.arena != nil {
		// Serialize the fill per identity, so a burst of readers of one
		// chunk costs one decode between them rather than one each — a
		// 4 MiB chunk is milliseconds of zstd.
		unlock := fs.lockFill("chunk:" + idHex)
		defer unlock()
		if fs.arena.read(idHex, chunkOff, window) {
			fs.chunkStats.hits.Add(1)
			return nil
		}
	}
	fs.chunkStats.misses.Add(1)
	// The graft table first (graft.go): it is an in-memory lookup, and
	// packIndex.locate is only entitled to say "absent" after indexing
	// every pack — so the other order would sweep a whole generation's
	// trailers before every grafted read.
	if fs.grafts != nil {
		if e, gl, ok := fs.grafts.locate(r.Identity); ok {
			return fs.graftChunkAt(ctx, e, gl, idHex, chunkOff, window)
		}
	}
	loc, err := fs.packIndex.locate(ctx, idHex)
	if err != nil {
		return fmt.Errorf("genfs: chunk %s: %w", idHex, err)
	}
	stored, err := fs.packRead(ctx, fs.packIndex, idHex, loc)
	if err != nil {
		return err
	}
	plain, err := fs.decodeChunk(idHex, r, stored)
	if err != nil {
		return err
	}
	// Into the arena, not into a file of its own (chunkarena.go). The
	// decoded copy is worth keeping and the inode it used to cost was not.
	fs.arena.put(idHex, plain)
	copy(window, plain[chunkOff:chunkOff+int64(len(window))])
	return nil
}

// decodeChunk turns one pack entry's stored bytes into verified plaintext.
// It is the single place chunk integrity is established, so the batched
// fill path and the single-chunk path cannot drift apart on it.
func (fs *FS) decodeChunk(idHex string, r *catalog.ChunkRef, stored []byte) ([]byte, error) {
	if int64(len(stored)) != r.CLen {
		return nil, fmt.Errorf("genfs: chunk %s: stored %d bytes, chunkref clen %d", idHex, len(stored), r.CLen)
	}
	var key []byte
	if r.KeyID != 0 {
		if len(fs.dek) == 0 {
			return nil, fmt.Errorf("genfs: chunk %s is encrypted (keyid %d) but no DEK was provided", idHex, r.KeyID)
		}
		key = fs.dek
	}
	plain, err := entrycodec.Decode(stored, uint8(r.Alg), key)
	if err != nil {
		return nil, fmt.Errorf("genfs: decode chunk %s: %w", idHex, err)
	}
	fs.chunkStats.decodes.Add(1)
	fs.chunkStats.decodedBytes.Add(int64(len(plain)))
	if int64(len(plain)) != r.LLen {
		return nil, fmt.Errorf("genfs: chunk %s: decoded %d bytes, chunkref llen %d", idHex, len(plain), r.LLen)
	}
	if fs.verify {
		if id := fs.hasher.Sum(plain); id.Hex() != idHex {
			return nil, fmt.Errorf("genfs: chunk identity mismatch: got %s, want %s", id.Hex(), idHex)
		}
	}
	return plain, nil
}

// storeChunk publishes one decoded chunk into the cache. Failures are
// dropped on purpose: this is the batched path, and whatever it does not
// produce is fetched again by readChunkAt, which reports the error with
// the read that actually needed it.
func (fs *FS) storeChunk(idHex string, r *catalog.ChunkRef, stored []byte) {
	if fs.arena == nil {
		return
	}
	plain, err := fs.decodeChunk(idHex, r, stored)
	if err != nil {
		return
	}
	fs.arena.put(idHex, plain)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// clear drops every cached extent map. A generation swap invalidates all
// of them: the same inode may name different chunks now.
func (e *extentCache) clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.byIn = make(map[uint64]*list.Element)
	e.lru.Init()
}
