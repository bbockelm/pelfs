package genfs

import (
	"container/list"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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

// Read fills dst from ino at off, returning the byte count: the full
// min(len(dst), EOF-off) — short only at EOF, 0 at or past it. Holes (NULL
// identity chunk rows) read as zeros. Chunks are served from the decoded
// cache under CacheDir, filled by pack range reads on miss.
func (fs *FS) Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("genfs: negative read offset %d", off)
	}
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

// readChunkAt fills window with chunk bytes starting at chunkOff. Cache
// files hold verified decoded bytes and are trusted on hit (identity is
// checked once, at fill — see the package comment for the encrypted-volume
// caveat where the GCM tag stands in for the keyed identity).
func (fs *FS) readChunkAt(ctx context.Context, r *catalog.ChunkRef, chunkOff int64, window []byte) error {
	idHex := hex.EncodeToString(r.Identity)
	fp := filepath.Join(fs.chunkDir, idHex)
	if readAtFile(fp, chunkOff, window) {
		return nil
	}
	unlock := fs.lockFill("chunk:" + idHex)
	defer unlock()
	if readAtFile(fp, chunkOff, window) {
		return nil
	}
	loc, ok := fs.packIndex[idHex]
	if !ok {
		return fmt.Errorf("genfs: chunk %s not present in any listed pack", idHex)
	}
	stored, err := fs.readPackRange(ctx, loc)
	if err != nil {
		return err
	}
	if int64(len(stored)) != r.CLen {
		return fmt.Errorf("genfs: chunk %s: stored %d bytes, chunkref clen %d", idHex, len(stored), r.CLen)
	}
	var key []byte
	if r.KeyID != 0 {
		if len(fs.dek) == 0 {
			return fmt.Errorf("genfs: chunk %s is encrypted (keyid %d) but no DEK was provided", idHex, r.KeyID)
		}
		key = fs.dek
	}
	plain, err := entrycodec.Decode(stored, uint8(r.Alg), key)
	if err != nil {
		return fmt.Errorf("genfs: decode chunk %s: %w", idHex, err)
	}
	if int64(len(plain)) != r.LLen {
		return fmt.Errorf("genfs: chunk %s: decoded %d bytes, chunkref llen %d", idHex, len(plain), r.LLen)
	}
	if fs.verify {
		if id := fs.hasher.Sum(plain); id.Hex() != idHex {
			return fmt.Errorf("genfs: chunk identity mismatch: got %s, want %s", id.Hex(), idHex)
		}
	}
	if err := writeAtomic(fp, plain); err != nil {
		return err
	}
	copy(window, plain[chunkOff:chunkOff+int64(len(window))])
	return nil
}

// readAtFile serves window from a cache file; any failure (missing,
// truncated) reports false so the caller refills.
func readAtFile(fp string, off int64, window []byte) bool {
	f, err := os.Open(fp)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck
	_, err = f.ReadAt(window, off)
	return err == nil
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
