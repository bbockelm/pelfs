package genfs

import (
	"container/list"
	"context"
	"sync"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// catCache is the LRU of open catalog handles, keyed by identity hex. The
// cap bounds OPEN handles; evicted handles close, but their spill files
// stay in CacheDir (reopen is one catalog.Open away). The root catalog is
// pinned outside the LRU and never counts against the cap.
//
// Handles are refcounted so an eviction never closes a catalog mid-query;
// the cap is soft — when every handle is in use the cache overflows and
// shrinks back on release.
type catCache struct {
	fs      *FS
	cap     int
	rootHex string
	root    catalog.Reader

	mu   sync.Mutex
	byID map[string]*catHandle
	lru  *list.List // front = MRU; element values are *catHandle
}

type catHandle struct {
	id   string
	cat  catalog.Reader
	refs int
	elem *list.Element
}

func newCatCache(fs *FS, capacity int, rootHex string, root catalog.Reader) *catCache {
	return &catCache{
		fs:      fs,
		cap:     capacity,
		rootHex: rootHex,
		root:    root,
		byID:    make(map[string]*catHandle),
		lru:     list.New(),
	}
}

// acquire returns an open handle for the catalog with the given identity,
// fetching/spilling/opening it on miss. The returned release func MUST be
// called when the caller is done with the handle.
func (c *catCache) acquire(ctx context.Context, idHex string) (catalog.Reader, func(), error) {
	if idHex == c.rootHex {
		return c.root, func() {}, nil
	}
	c.mu.Lock()
	if h := c.byID[idHex]; h != nil {
		h.refs++
		c.lru.MoveToFront(h.elem)
		c.mu.Unlock()
		return h.cat, func() { c.release(h) }, nil
	}
	c.mu.Unlock()

	// Serialize misses per identity so one goroutine fetches and opens.
	unlock := c.fs.lockFill("catopen:" + idHex)
	defer unlock()
	c.mu.Lock()
	if h := c.byID[idHex]; h != nil {
		h.refs++
		c.lru.MoveToFront(h.elem)
		c.mu.Unlock()
		return h.cat, func() { c.release(h) }, nil
	}
	c.mu.Unlock()

	fp, err := c.fs.spillCatalog(ctx, idHex)
	if err != nil {
		return nil, nil, err
	}
	cat, err := catalog.OpenReader(fp)
	if err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	h := &catHandle{id: idHex, cat: cat, refs: 1}
	h.elem = c.lru.PushFront(h)
	c.byID[idHex] = h
	c.evictLocked()
	c.mu.Unlock()
	return h.cat, func() { c.release(h) }, nil
}

func (c *catCache) release(h *catHandle) {
	c.mu.Lock()
	h.refs--
	c.evictLocked()
	c.mu.Unlock()
}

// evictLocked closes least-recently-used idle handles until the cache fits
// the cap. In-use handles are skipped; they close on a later release.
func (c *catCache) evictLocked() {
	for c.lru.Len() > c.cap {
		var victim *catHandle
		for e := c.lru.Back(); e != nil; e = e.Prev() {
			if h := e.Value.(*catHandle); h.refs == 0 {
				victim = h
				break
			}
		}
		if victim == nil {
			return
		}
		c.lru.Remove(victim.elem)
		delete(c.byID, victim.id)
		victim.cat.Close() //nolint:errcheck
	}
}

// openSet is the identities this cache currently holds OPEN, the pinned
// root included.
//
// Cache eviction consults it and skips those spill files. Every other file
// under CacheDir is safe to unlink under a reader — an open descriptor
// keeps the bytes alive on POSIX, and every reader treats a missing cache
// file as a miss and refills — but a catalog is opened by PATH, and by
// SQLite, which is entitled to reopen it for its own reasons. The handles
// listed here are exactly the ones a reader can still reach without going
// back through the spill path, so they are exactly the ones a sweep must
// leave alone.
func (c *catCache) openSet() map[string]struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]struct{}, len(c.byID)+1)
	out[c.rootHex] = struct{}{}
	for id := range c.byID {
		out[id] = struct{}{}
	}
	return out
}

// closeAll closes every handle including the pinned root.
func (c *catCache) closeAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var first error
	for e := c.lru.Front(); e != nil; e = e.Next() {
		if err := e.Value.(*catHandle).cat.Close(); err != nil && first == nil {
			first = err
		}
	}
	c.lru.Init()
	c.byID = make(map[string]*catHandle)
	if err := c.root.Close(); err != nil && first == nil {
		first = err
	}
	return first
}
