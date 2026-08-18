package vfsbilly

import (
	"os"
	"sync"
)

// noDirCache disables memoization, restoring a full descent per operation.
// It is the bisection switch for a suspected staleness bug on a real
// mount: if a workload misbehaves with memoization on and behaves with
// PELFS_NFS_NO_DESCENT_CACHE=1, this is implicated; if it misbehaves
// either way, the cause is elsewhere.
var noDirCache = os.Getenv("PELFS_NFS_NO_DESCENT_CACHE") == "1"

// dirCache memoizes DIRECTORY edges — (parent inode, name) -> child inode
// — so a path does not cost one catalog lookup per component.
//
// The NFS frontend is path-based: every RPC arrives as a handle that
// go-nfs has already turned back into a path, and the layer below is
// inode-based, so each operation re-walks the path from the root. A
// create-heavy workload issues six-odd RPCs per file and each one walks
// the same directories again, which is where the server's CPU goes.
//
// Only directory edges are cached, and only the edge — never attributes.
// The terminal component of every path is always resolved for real, so
// size, mtime and mode are never served from here. That is what makes the
// cache safe to hold indefinitely: a directory's IDENTITY changes only
// when the name is unlinked or renamed, both of which invalidate, whereas
// its attributes change constantly and are never consulted here.
//
// Correctness rests on three properties of the layer below:
//
//   - inode numbers are never recycled (the overlay's allocator only ever
//     moves forward), so a stale edge can only fail, never silently
//     resolve to a different object;
//   - a checkpoint preserves inode identity for every edge it rebases, so
//     sealing mid-session does not invalidate anything here;
//   - this binding is the only mutator of the namespace it serves.
//
// A miss is free and a stale entry is self-healing (see resolve), so the
// eviction policy only has to bound memory. Two generations do that
// without per-hit bookkeeping: lookups check the young map, then the old
// one (promoting), and an overflow retires young to old wholesale. The
// working set therefore survives at least one full turnover.
type dirCache struct {
	mu       sync.Mutex
	limit    int
	disabled bool
	young    map[dirKey]uint64
	old      map[dirKey]uint64
}

type dirKey struct {
	parent uint64
	name   string
}

// dirCacheLimit is the per-generation bound, so up to twice this many
// edges are retained. Directories are a small fraction of a tree and each
// entry is a few dozen bytes, so this is tens of megabytes at worst for a
// tree far larger than anything a scratch volume holds.
const dirCacheLimit = 1 << 16

func newDirCache() *dirCache {
	return &dirCache{limit: dirCacheLimit, disabled: noDirCache, young: make(map[dirKey]uint64)}
}

func (c *dirCache) get(parent uint64, name string) (uint64, bool) {
	if c.disabled {
		return 0, false
	}
	k := dirKey{parent, name}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ino, ok := c.young[k]; ok {
		return ino, true
	}
	if ino, ok := c.old[k]; ok {
		c.young[k] = ino
		return ino, true
	}
	return 0, false
}

func (c *dirCache) put(parent uint64, name string, ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.young) >= c.limit {
		c.old, c.young = c.young, make(map[dirKey]uint64)
	}
	c.young[dirKey{parent, name}] = ino
}

// forget drops one edge. Every namespace mutation that can unbind a name
// from a directory must call this — unlink, rmdir, and both ends of a
// rename — including for names that are not directories, since the caller
// cannot always know which it had without an extra lookup.
func (c *dirCache) forget(parent uint64, name string) {
	k := dirKey{parent, name}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.young, k)
	delete(c.old, k)
}
