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
// A second map holds the permission-relevant ATTRIBUTES of the directories
// whose edges are cached, which is the one exception to "never attributes"
// above and needs its own justification. Search permission has to be
// checked on every component of every path (perm.go), and re-reading three
// or four directory nodes per RPC to answer a question whose answer almost
// never changes would undo what this cache is for. Unlike size and mtime, a
// directory's mode and ownership change only through THIS binding's
// Chmod/Chown — the same property the edges already rest on — so the
// invalidation is exact rather than a timeout: setAttr drops the entry for
// the inode it changed. Nothing else can make it stale.
type dirCache struct {
	mu       sync.Mutex
	limit    int
	disabled bool
	young    map[dirKey]uint64
	old      map[dirKey]uint64
	// perms is keyed by inode, and holds only directories.
	perms map[uint64]dirPerm
}

type dirKey struct {
	parent uint64
	name   string
}

// dirPerm is everything the permission check needs about a directory: its
// mode and its ownership, as the catalog stores them (the idmap
// translation is applied by the caller, which is where the mount's
// reporting policy lives).
type dirPerm struct {
	mode uint32
	uid  uint32
	gid  uint32
}

// dirCacheLimit is the per-generation bound, so up to twice this many
// edges are retained. Directories are a small fraction of a tree and each
// entry is a few dozen bytes, so this is tens of megabytes at worst for a
// tree far larger than anything a scratch volume holds.
const dirCacheLimit = 1 << 16

func newDirCache() *dirCache {
	return &dirCache{limit: dirCacheLimit, disabled: noDirCache,
		young: make(map[dirKey]uint64), perms: make(map[uint64]dirPerm)}
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

// perm returns a directory's cached permission attributes.
func (c *dirCache) perm(ino uint64) (dirPerm, bool) {
	if c.disabled {
		return dirPerm{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.perms[ino]
	return p, ok
}

// putPerm records a directory's permission attributes. The bound is the
// same one the edges use, and overflow drops the whole map rather than
// half of it: a miss costs one GetAttr and the working set refills in the
// same walk that emptied it.
func (c *dirCache) putPerm(ino uint64, p dirPerm) {
	if c.disabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.perms) >= c.limit {
		c.perms = make(map[uint64]dirPerm, c.limit/2)
	}
	c.perms[ino] = p
}

// forgetPerm drops one directory's attributes. Every change to a
// directory's mode or ownership must call it, which is what makes the
// entries above safe to hold without a timeout.
func (c *dirCache) forgetPerm(ino uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.perms, ino)
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
