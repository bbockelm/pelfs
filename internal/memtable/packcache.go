package memtable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// packCache is the local copy of packs this session can read without the
// federation.
//
// It is filled from two directions, and the first is the one that
// matters: a pack this session WROTE is retained rather than deleted
// after its upload (packstore.PackWriter.Retain), so content the user
// wrote is still local the moment it leaves the ring. That is what keeps
// a seal from having to fetch back bytes it uploaded minutes earlier in
// order to re-chunk a rewrite (see Sealer) — without it, a partial
// rewrite could make publishing depend on the network for content that
// never left this machine.
//
// The second direction is ordinary reads: a miss fetches the pack WHOLE
// and keeps it. Whole rather than ranged is the format's own policy
// (docs/design-packfs.md — a reader fetches packs whole, and the cut size
// is what bounds what that costs), and it is also what makes a subsequent
// seal of the same file free: reading a file to edit it is what pulls in
// the chunks the edit will straddle.
//
// Eviction is oldest-first against a byte cap, and it is deliberately not
// clever about what a seal might need. A cache miss costs a fetch, never
// correctness: the seal still gets its bytes, just slowly.
type packCache struct {
	dir string
	max int64

	mu    sync.Mutex
	size  int64
	order []string         // admission order, oldest first
	have  map[string]int64 // name -> bytes on disk
}

// DefaultPackCacheBytes is the local cache's ceiling. A session's own
// packs are the ones worth keeping, so the useful size is "what this
// session uploaded" — and packs are compressed and deduplicated, which is
// why this can be smaller than the staging directory it replaces and
// still hold more of the session.
const DefaultPackCacheBytes = 1 << 30

// PackCacheDisabled turns the local cache off (Options.PackCacheBytes).
// Zero means the default, so "off" needs a value of its own.
const PackCacheDisabled = -1

func newPackCache(dir string, max int64) (*packCache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	// A directory left by a previous session holds packs whose locations
	// this one has no map for. They are not readable and not free, so the
	// cache starts empty on disk as well as in memory.
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		os.Remove(filepath.Join(dir, e.Name())) //nolint:errcheck
	}
	return &packCache{dir: dir, max: max, have: make(map[string]int64)}, nil
}

func (c *packCache) path(name string) string { return filepath.Join(c.dir, name) }

// admit records a pack already written at path(name) and evicts until the
// cache fits. The pack just admitted is never the eviction victim.
func (c *packCache) admit(name string, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.have[name]; ok {
		return
	}
	c.have[name] = size
	c.order = append(c.order, name)
	c.size += size
	for c.size > c.max && len(c.order) > 1 {
		victim := c.order[0]
		c.order = c.order[1:]
		c.size -= c.have[victim]
		delete(c.have, victim)
		// Removing a file some reader still holds open is safe: the
		// descriptor keeps the bytes alive until it is closed.
		os.Remove(c.path(victim)) //nolint:errcheck
	}
}

// drop forgets a pack, for the upload that failed after its spool was
// retained: nothing published references it, so it is garbage.
func (c *packCache) drop(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if size, ok := c.have[name]; ok {
		c.size -= size
		delete(c.have, name)
		for i, n := range c.order {
			if n == name {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	os.Remove(c.path(name)) //nolint:errcheck
}

// open returns a reader for a cached pack, or false when it is not held.
func (c *packCache) open(name string) (*os.File, bool) {
	c.mu.Lock()
	_, ok := c.have[name]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	f, err := os.Open(c.path(name))
	if err != nil {
		return nil, false
	}
	return f, true
}

// fetch downloads a whole pack and admits it, returning the open file.
func (c *packCache) fetch(ctx context.Context, obj pelicanobj.Store, name string) (*os.File, error) {
	key := packstore.PackDirKey + "/" + name
	rc, err := obj.Get(ctx, key, 0, -1)
	if err != nil {
		return nil, err
	}
	defer rc.Close() //nolint:errcheck
	tmp, err := os.CreateTemp(c.dir, "fetch.*")
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(tmp, rc)
	if err == nil {
		err = tmp.Sync()
	}
	if err != nil {
		tmp.Close()           //nolint:errcheck
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, fmt.Errorf("memtable: fetch pack %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, err
	}
	if err := os.Rename(tmp.Name(), c.path(name)); err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, err
	}
	c.admit(name, n)
	f, ok := c.open(name)
	if !ok {
		// Admitted and immediately evicted: the cache is smaller than one
		// pack. Nothing to serve from, and saying so is better than
		// looping on a fetch that can never stick.
		return nil, errors.New("memtable: pack cache is too small to hold one pack")
	}
	return f, nil
}
