package genfs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// The local generation cache, and the one budget over all of it.
//
// Everything a mount reads is written down under CacheDir, in four
// directories with four lifetimes and, until this existed, one bound
// between them:
//
//	packs/     whole packs, as fetched (packfetch.go). Bounded since it
//	           was written, because a pack is tens of megabytes and a
//	           volume is not going to fit on a laptop.
//	chunks/    DECODED PLAINTEXT, one file per chunk ever read
//	           (read.go). Unbounded: reading an N-byte volume cost N
//	           bytes of local disk, forever, and remounting did not
//	           reclaim it because the cache survives the process on
//	           purpose.
//	catalogs/  spilled SQLite catalogs (genfs.go). Unbounded, and the
//	           file the catalog handle cache opens.
//	trailers/  one small file per pack listed (packindex.go).
//	           Unbounded, and proportional to the whole generation
//	           rather than to what was read.
//
// So the cache had one cap covering the one directory whose growth a user
// could have predicted, and none over the three that grow with what the
// filesystem is actually used for. A day of reading filled a disk, and
// nothing in the mount could say which directory did it.
//
// One byte budget covers all four now, evicting least-recently-used files
// across the whole cache rather than per directory. Per-directory caps
// were the alternative and they are worse: the four are substitutes, not
// separate resources — a cached pack makes both the chunks in it and its
// trailer re-derivable for free, and a chunk read out of a pack makes the
// pack expendable — so any split of the budget is a guess that starves one
// use to protect another. A single LRU spends the disk on whatever the
// mount is doing this hour.
//
// Nothing here is ever load-bearing. Every file under CacheDir can be
// re-derived from the federation, so the only cost of evicting the wrong
// one is fetching it again; that is what makes an LRU by modification time
// good enough, and why eviction never has to be exact.

// DefaultCacheBytes is the whole local cache budget when none is
// configured. It is what the pack cache alone used to take, so a mount
// that says nothing about the cache uses no more disk than it did before
// the other three directories were bounded — it just stops using more.
const DefaultCacheBytes = 4 << 30

// cacheLowWaterShift sets how far below the cap an eviction pass sweeps:
// cap - cap>>4, i.e. 1/16th of the budget.
//
// Evicting to exactly the cap would mean a directory scan per chunk
// written from the moment the cache first fills, because the very next
// write is over the cap again. Sweeping a slice off instead buys that many
// bytes of quiet, so a session scans once per 1/16th of its budget: 256 MiB
// at the default, which is 64 chunk writes at the average chunk size and
// a few hundred scans over a session that reads a hundred gigabytes.
const cacheLowWaterShift = 4

// cacheUsageMaxAge is how stale a reported cache usage may be. The numbers
// exist so a full disk is diagnosable from the statistics file, which is
// rewritten every 30 s; recomputing them per request would put a directory
// walk on the control socket.
const cacheUsageMaxAge = 30 * time.Second

// cacheDirNames are the subdirectories of CacheDir the budget covers, in
// report order. Names live here rather than at their four use sites so
// that `pelfs cache` and the mount cannot disagree about what the cache
// is made of.
var cacheDirNames = []string{"chunks", "catalogs", "trailers", "packs"}

// DirUsage is one cache directory's contribution.
type DirUsage struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
	Files int    `json:"files"`
}

// CacheUsage is what the local generation cache holds right now, split by
// directory, together with the budget it is held against.
type CacheUsage struct {
	Dirs  []DirUsage `json:"dirs"`
	Bytes int64      `json:"bytes"`
	Files int        `json:"files"`
	// Limit is the byte budget in force. Zero in a report produced
	// outside a mount (`pelfs cache`), which reads the directory without
	// knowing what the mount that filled it was configured with.
	Limit int64 `json:"limit,omitempty"`
	// EvictedFiles and EvictedBytes count what this session has removed
	// to stay inside the budget. A cache at its limit with a large
	// eviction count is a mount whose working set does not fit, which
	// reads as a performance problem rather than a disk problem.
	EvictedFiles int64 `json:"evicted_files,omitempty"`
	EvictedBytes int64 `json:"evicted_bytes,omitempty"`
	// Pinned counts files an eviction pass had to skip because something
	// held them open — open catalogs, in practice. It is a diagnostic for
	// the one way this cache can exceed its budget and stay there.
	Pinned int `json:"pinned,omitempty"`
}

// Bytes reports the total, so callers can size a cache without walking
// the per-directory list.
func (u CacheUsage) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d bytes in %d files", u.Bytes, u.Files)
	for _, d := range u.Dirs {
		fmt.Fprintf(&b, ", %s %d", d.Name, d.Bytes)
	}
	return b.String()
}

// cacheFile is one candidate for eviction.
type cacheFile struct {
	dir  string
	name string
	path string
	size int64
	age  time.Time
}

// cacheState is the eviction bookkeeping. It is deliberately NOT a map of
// the cache's contents: the cache outlives the process and is shared with
// any other session pointed at the same state directory, so the directory
// is the only honest record of what is in it. What is held here is a
// running TOTAL, which is enough to decide WHEN to go and look.
type cacheState struct {
	// used is the best current estimate of the cache's size: exact just
	// after a scan, then advanced by every file written. Read and written
	// without the eviction lock, which is why it is atomic.
	used atomic.Int64
	// usage is the last scan's per-directory breakdown, with the moment
	// it was taken, for reporting.
	usage    atomic.Pointer[CacheUsage]
	scannedA atomic.Int64 // UnixNano of the last scan

	evictedFiles atomic.Int64
	evictedBytes atomic.Int64
}

// noteCached records that n bytes were added to the cache and evicts when
// that puts it over budget. Every path that writes a file under CacheDir
// calls it; the one that does not is the pack trailer writer, whose files
// are small and are collected by whichever scan the next chunk triggers.
func (fs *FS) noteCached(n int64) {
	if n <= 0 || fs.cacheCap <= 0 {
		return
	}
	if fs.cache.used.Add(n) > fs.cacheCap {
		fs.evictCache()
	}
}

// evictCache trims the whole cache to its budget, least recently used
// first, and refreshes the reported usage. It scans rather than trusting
// its own running total, because the directory is shared with other
// sessions and outlives this one.
//
// Removing a file another goroutine is reading is safe by construction —
// an open descriptor keeps the bytes alive on POSIX, and every reader
// here treats a missing cache file as a miss and refills — with ONE
// exception, which this handles explicitly: a spilled catalog is opened
// by path, and by SQLite, so an open catalog is pinned and skipped.
func (fs *FS) evictCache() {
	fs.evictMu.Lock()
	defer fs.evictMu.Unlock()
	if fs.cacheCap <= 0 {
		return
	}
	// A queued caller whose eviction someone else already performed. The
	// scan below is the expensive part, and there is no point running it
	// once per goroutine that noticed the same overrun. The first call of
	// a session always scans, whatever the running total says: the cache
	// outlives the process, so at Open that total is a fiction — and a
	// cache left behind by a session with a bigger budget is exactly what
	// the first scan is for.
	if fs.cache.scannedA.Load() != 0 && fs.cache.used.Load() <= fs.cacheLow() {
		return
	}
	files, usage := fs.scanCacheLocked()
	total := usage.Bytes
	// The scan is the authority on what is there, so its answer replaces
	// the running estimate whether or not anything is evicted.
	fs.cache.used.Store(total)
	if total <= fs.cacheCap {
		fs.storeUsage(usage)
		return
	}
	low := fs.cacheLow()
	// Oldest first. mtime rather than atime because atime is silently
	// disabled by a relatime mount, which is most of them; every read of a
	// cached pack refreshes its mtime for exactly this reason
	// (packTouchInterval, packfetch.go).
	sort.Slice(files, func(i, j int) bool { return files[i].age.Before(files[j].age) })
	pinned := fs.pinnedCatalogs()
	skipped := 0
	for _, f := range files {
		if total <= low {
			break
		}
		if strings.Contains(f.name, ".tmp") {
			// An in-flight download by this or another session. The tmp
			// sweeper owns these (packfetch.go); deleting one here would
			// only make its owner fail.
			continue
		}
		if f.dir == "catalogs" {
			id := strings.TrimSuffix(f.name, ".db")
			if _, open := pinned[id]; open {
				skipped++
				continue
			}
			// Not open in the handle cache, but another goroutine may be
			// between spilling this file and opening it — the two happen
			// under one fill gate (catcache.go), so taking that gate is
			// what makes the deletion safe. Never WAIT for it: the holder
			// may be downloading a pack and end up waiting on this very
			// lock.
			unlock, ok := fs.tryLockFill("catopen:" + id)
			if !ok {
				skipped++
				continue
			}
			removed := os.Remove(f.path) == nil
			unlock()
			if removed {
				total -= f.size
				fs.cache.evictedFiles.Add(1)
				fs.cache.evictedBytes.Add(f.size)
			}
			continue
		}
		if err := os.Remove(f.path); err == nil {
			total -= f.size
			fs.cache.evictedFiles.Add(1)
			fs.cache.evictedBytes.Add(f.size)
		}
	}
	fs.cache.used.Store(total)
	// Re-derive the breakdown from what the sweep actually removed rather
	// than scanning again: the numbers are a report, and one more walk of
	// the whole cache is a poor way to produce them.
	fs.storeUsage(fs.recountLocked(files, total, skipped))
}

// cacheLow is the byte count an eviction pass sweeps down to.
func (fs *FS) cacheLow() int64 {
	if fs.cacheCap <= 0 {
		return 0
	}
	return fs.cacheCap - fs.cacheCap>>cacheLowWaterShift
}

// scanCacheLocked walks the cache directories and returns every file in
// them with the totals. Callers hold evictMu.
func (fs *FS) scanCacheLocked() ([]cacheFile, CacheUsage) {
	usage := CacheUsage{Limit: fs.cacheCap}
	var files []cacheFile
	for _, name := range cacheDirNames {
		dir := filepath.Join(fs.cacheDir, name)
		entries, err := os.ReadDir(dir)
		if err != nil {
			usage.Dirs = append(usage.Dirs, DirUsage{Name: name})
			continue
		}
		du := DirUsage{Name: name}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			du.Bytes += fi.Size()
			du.Files++
			files = append(files, cacheFile{
				dir:  name,
				name: e.Name(),
				path: filepath.Join(dir, e.Name()),
				size: fi.Size(),
				age:  fi.ModTime(),
			})
		}
		usage.Dirs = append(usage.Dirs, du)
		usage.Bytes += du.Bytes
		usage.Files += du.Files
	}
	return files, usage
}

// recountLocked rebuilds the per-directory breakdown after a sweep, using
// the files that are still there. total is the sweep's own running sum and
// is authoritative for the whole.
func (fs *FS) recountLocked(files []cacheFile, total int64, pinned int) CacheUsage {
	usage := CacheUsage{Limit: fs.cacheCap, Pinned: pinned}
	byDir := make(map[string]*DirUsage, len(cacheDirNames))
	for _, name := range cacheDirNames {
		usage.Dirs = append(usage.Dirs, DirUsage{Name: name})
	}
	for i := range usage.Dirs {
		byDir[usage.Dirs[i].Name] = &usage.Dirs[i]
	}
	for _, f := range files {
		if _, err := os.Stat(f.path); err != nil {
			continue // evicted by this pass
		}
		if d := byDir[f.dir]; d != nil {
			d.Bytes += f.size
			d.Files++
			usage.Files++
		}
	}
	usage.Bytes = total
	return usage
}

func (fs *FS) storeUsage(u CacheUsage) {
	u.EvictedFiles = fs.cache.evictedFiles.Load()
	u.EvictedBytes = fs.cache.evictedBytes.Load()
	fs.cache.usage.Store(&u)
	fs.cache.scannedA.Store(time.Now().UnixNano())
}

// CacheUsage reports what the local cache holds, rescanning only when the
// last answer has gone stale. It is what a mount publishes in its
// statistics file so that "the disk filled up" is answerable without
// attaching to the process.
//
// Stale means one of two things, and the first is why the age alone will
// not do: the cache has been WRITTEN to since the scan, which the running
// total knows about and the snapshot does not. Drift past a small
// fraction of the budget forces a rescan, so the report tracks what the
// mount is doing while the scan rate stays proportional to the budget
// rather than to the read rate — at the default cap that is one directory
// walk per 64 MiB cached, and in a test with a tiny cap it is nearly every
// call, which is what a test wants.
func (fs *FS) CacheUsage() CacheUsage {
	if u := fs.cache.usage.Load(); u != nil {
		drift := fs.cache.used.Load() - u.Bytes
		if drift < 0 {
			drift = -drift
		}
		if drift <= fs.usageDrift() && time.Since(time.Unix(0, fs.cache.scannedA.Load())) < cacheUsageMaxAge {
			return *u
		}
	}
	fs.evictMu.Lock()
	defer fs.evictMu.Unlock()
	_, usage := fs.scanCacheLocked()
	fs.cache.used.Store(usage.Bytes)
	fs.storeUsage(usage)
	return usage
}

// CacheLimit reports the byte budget this mount holds its cache to.
func (fs *FS) CacheLimit() int64 { return fs.cacheCap }

// usageDrift is how far the reported usage may lag what has been written
// before a report goes back and looks: 1/64th of the budget, floored so a
// tiny cache does not turn every report into a walk of a directory that is
// almost empty anyway.
func (fs *FS) usageDrift() int64 {
	if d := fs.cacheCap >> 6; d > 64<<10 {
		return d
	}
	return 64 << 10
}

// pinnedCatalogs is the set of catalog identities the handle cache
// currently has open, including the pinned root. Their spill files are the
// one thing under CacheDir that is not safely removable: SQLite opened
// them by path.
func (fs *FS) pinnedCatalogs() map[string]struct{} {
	if fs.cats == nil {
		return nil
	}
	return fs.cats.openSet()
}

// tryLockFill takes the fill gate for key if it is free. It never blocks,
// because the caller (eviction) may be holding a lock the gate's current
// holder is about to want.
func (fs *FS) tryLockFill(key string) (func(), bool) {
	fs.fillMu.Lock()
	g := fs.fills[key]
	if g == nil {
		g = &fillGate{}
		fs.fills[key] = g
	}
	g.refs++
	fs.fillMu.Unlock()
	if !g.mu.TryLock() {
		fs.fillMu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(fs.fills, key)
		}
		fs.fillMu.Unlock()
		return nil, false
	}
	return func() {
		g.mu.Unlock()
		fs.fillMu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(fs.fills, key)
		}
		fs.fillMu.Unlock()
	}, true
}

// InspectCache reports what the cache under dir holds, without opening a
// volume or touching the federation. It is `pelfs cache`, and it is also
// how a test asks what a mount left behind.
func InspectCache(dir string) (CacheUsage, error) {
	usage := CacheUsage{}
	var missing int
	for _, name := range cacheDirNames {
		sub := filepath.Join(dir, name)
		entries, err := os.ReadDir(sub)
		if err != nil {
			missing++
			usage.Dirs = append(usage.Dirs, DirUsage{Name: name})
			continue
		}
		du := DirUsage{Name: name}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if fi, err := e.Info(); err == nil {
				du.Bytes += fi.Size()
				du.Files++
			}
		}
		usage.Dirs = append(usage.Dirs, du)
		usage.Bytes += du.Bytes
		usage.Files += du.Files
	}
	if missing == len(cacheDirNames) {
		if _, err := os.Stat(dir); err != nil {
			return usage, err
		}
	}
	return usage, nil
}

// ClearCache removes every cached file under dir and reports what went.
// The directories themselves stay, so a mount that is opening right now
// does not lose the tree underneath it — and everything removed is
// re-derivable from the federation, which is what makes this safe to do
// to a cache at all.
//
// It is NOT safe to do to a cache a mount is actively reading: a catalog
// SQLite has open would be unlinked. Refusing that is the caller's job,
// and `pelfs cache clear` does it by declining to run against a live
// mount.
func ClearCache(dir string) (CacheUsage, error) {
	usage, err := InspectCache(dir)
	if err != nil {
		return usage, err
	}
	for _, name := range cacheDirNames {
		sub := filepath.Join(dir, name)
		entries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if err := os.Remove(filepath.Join(sub, e.Name())); err != nil {
				return usage, err
			}
		}
	}
	return usage, nil
}
