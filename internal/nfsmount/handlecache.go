package nfsmount

import (
	"sync"
	"syscall"
	"time"

	jfs "github.com/juicedata/juicefs/pkg/fs"
	"github.com/juicedata/juicefs/pkg/meta"
)

func errnoErr(errno syscall.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

// The go-nfs server opens, writes, and closes the backing file on EVERY
// WRITE RPC (nfs_onwrite.go). Each jfs.File.Close flushes the JuiceFS
// writer, so without intervention every 32KB NFS write becomes its own
// slice — and every slice its own tiny object in the federation, instead of
// coalescing into 4MiB blocks.
//
// handleCache absorbs that pattern: write-capable handles are kept open and
// shared across RPCs, so consecutive writes land in one JuiceFS writer and
// coalesce properly. A janitor closes (and thereby flushes) handles that
// have been idle for handleIdleClose. Because buffered data is invisible to
// path-based Stat until flush, the cache also tracks the highest written
// offset per handle so Stat can present a fresh size without forcing a
// fragmenting flush (go-nfs stats the file before every WRITE).
const (
	handleIdleClose  = 2 * time.Second
	janitorInterval  = 500 * time.Millisecond
	handleCacheLimit = 64 // open write handles; beyond this, oldest idle is closed
)

type handleCache struct {
	ctx meta.Context

	mu       sync.Mutex
	entries  map[string]*cachedHandle
	stop     chan struct{}
	stopOnce sync.Once
}

type cachedHandle struct {
	name string
	f    *jfs.File
	// flushMu serializes flushes of this handle and, critically, blocks a
	// reader until an in-flight flush has completed. JuiceFS clamps reads
	// to the file length captured when the reading handle was opened, so a
	// reader that opens while buffered writes are still in flight sees a
	// short file — the "premature end of pack file" a git clone hits.
	flushMu sync.Mutex
	refs    int
	dirty   bool
	size    int64 // highest byte written through this handle
	lastUse time.Time
	evicted bool // dropped from the map; close on last release
}

func newHandleCache(ctx meta.Context) *handleCache {
	hc := &handleCache{
		ctx:     ctx,
		entries: make(map[string]*cachedHandle),
		stop:    make(chan struct{}),
	}
	go hc.janitor()
	return hc
}

// knownSize is the freshest length view for a cached handle: the highest
// buffered write, or the size recorded at open.
func (hc *handleCache) knownSize(e *cachedHandle) int64 {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	return e.size
}

// acquire returns the cached write handle for name (bumping its refcount),
// or nil when none is cached.
func (hc *handleCache) acquire(name string) *cachedHandle {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	e := hc.entries[name]
	if e == nil {
		return nil
	}
	e.refs++
	e.lastUse = time.Now()
	return e
}

// add registers a freshly opened write handle (refcount 1). An existing
// entry for the same path is evicted first (its holders finish on the old
// handle; new opens see the new one).
func (hc *handleCache) add(name string, f *jfs.File, size int64) *cachedHandle {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if old := hc.entries[name]; old != nil {
		hc.evictLocked(old)
	}
	e := &cachedHandle{name: name, f: f, refs: 1, size: size, lastUse: time.Now()}
	hc.entries[name] = e
	if len(hc.entries) > handleCacheLimit {
		hc.closeOldestIdleLocked()
	}
	return e
}

// release drops one reference. Entries stay cached (open) until the janitor
// closes them after idling, so the next WRITE RPC reuses the handle.
func (hc *handleCache) release(e *cachedHandle) error {
	hc.mu.Lock()
	e.refs--
	e.lastUse = time.Now()
	shouldClose := e.evicted && e.refs <= 0
	hc.mu.Unlock()
	if shouldClose {
		return errnoErr(e.f.Close(hc.ctx))
	}
	return nil
}

// noteWrite records bytes written through a cached handle.
func (hc *handleCache) noteWrite(e *cachedHandle, end int64) {
	hc.mu.Lock()
	e.dirty = true
	if end > e.size {
		e.size = end
	}
	e.lastUse = time.Now()
	hc.mu.Unlock()
}

// noteTruncate records an explicit size change.
func (hc *handleCache) noteTruncate(e *cachedHandle, size int64) {
	hc.mu.Lock()
	e.dirty = true
	e.size = size
	e.lastUse = time.Now()
	hc.mu.Unlock()
}

// statOverlay reports the freshest known size/mtime for name when a dirty
// cached handle exists: buffered writes are invisible to path-based Stat
// until flushed.
func (hc *handleCache) statOverlay(name string) (size int64, mtime time.Time, ok bool) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if e := hc.entries[name]; e != nil && e.dirty {
		return e.size, e.lastUse, true
	}
	return 0, time.Time{}, false
}

// flushIfDirty commits buffered writes for name (without closing the
// handle), so a reader opening its own handle sees current data.
//
// Concurrent callers serialize on the entry's flushMu and only return once
// the flush covering the writes they need has finished: returning early
// because another goroutine had already cleared the dirty flag would let a
// reader open the file mid-flush and read a stale, short length.
func (hc *handleCache) flushIfDirty(name string) error {
	hc.mu.Lock()
	e := hc.entries[name]
	if e == nil {
		hc.mu.Unlock()
		return nil
	}
	e.refs++ // pin: the janitor must not close this handle under us
	hc.mu.Unlock()
	defer func() { _ = hc.release(e) }()

	e.flushMu.Lock()
	defer e.flushMu.Unlock()

	hc.mu.Lock()
	dirty := e.dirty
	hc.mu.Unlock()
	if !dirty {
		return nil
	}
	if err := errnoErr(e.f.Flush(hc.ctx)); err != nil {
		return err // stays dirty: a failed flush must be retried
	}
	hc.mu.Lock()
	e.dirty = false
	hc.mu.Unlock()
	return nil
}

// sync flushes the cached handle for name regardless of the dirty flag,
// implementing NFSv3 COMMIT semantics for callers that need durability.
func (hc *handleCache) sync(name string) error {
	return hc.flushIfDirty(name)
}

// invalidate flushes and removes the entry for name (before Remove, Rename,
// or an O_TRUNC/O_EXCL open). In-flight holders keep the orphaned handle
// alive until their release.
func (hc *handleCache) invalidate(name string) error {
	hc.mu.Lock()
	e := hc.entries[name]
	if e == nil {
		hc.mu.Unlock()
		return nil
	}
	hc.evictLocked(e)
	needClose := e.refs <= 0
	hc.mu.Unlock()
	if needClose {
		return errnoErr(e.f.Close(hc.ctx))
	}
	return nil
}

// evictLocked removes e from the map; the caller decides whether to close.
func (hc *handleCache) evictLocked(e *cachedHandle) {
	delete(hc.entries, e.name)
	e.evicted = true
}

func (hc *handleCache) closeOldestIdleLocked() {
	var oldest *cachedHandle
	for _, e := range hc.entries {
		if e.refs > 0 {
			continue
		}
		if oldest == nil || e.lastUse.Before(oldest.lastUse) {
			oldest = e
		}
	}
	if oldest != nil {
		hc.evictLocked(oldest)
		// Close outside the lock is preferable, but this path is rare
		// (cache overflow) and Close on an idle handle is quick.
		_ = oldest.f.Close(hc.ctx)
	}
}

// closeAll stops the janitor and closes every cached handle, flushing the
// buffered writes they hold. This MUST run before the filesystem is torn
// down: jfs.FileSystem.Flush() only flushes the log buffer and the session
// heartbeat, NOT open file writers, so anything still buffered would simply
// be lost — silently truncating every file written in the last few seconds.
//
// It returns the first close error so shutdown can report data loss rather
// than exiting successfully on a short file.
func (hc *handleCache) closeAll() error {
	hc.stopOnce.Do(func() { close(hc.stop) })

	hc.mu.Lock()
	var toClose []*cachedHandle
	for _, e := range hc.entries {
		hc.evictLocked(e)
		toClose = append(toClose, e)
	}
	hc.mu.Unlock()

	var firstErr error
	for _, e := range toClose {
		// Wait out any in-flight flush before closing this handle.
		e.flushMu.Lock()
		err := errnoErr(e.f.Close(hc.ctx))
		e.flushMu.Unlock()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (hc *handleCache) janitor() {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-hc.stop:
			return
		case <-t.C:
			hc.mu.Lock()
			var toClose []*cachedHandle
			now := time.Now()
			for _, e := range hc.entries {
				if e.refs <= 0 && now.Sub(e.lastUse) > handleIdleClose {
					hc.evictLocked(e)
					toClose = append(toClose, e)
				}
			}
			hc.mu.Unlock()
			for _, e := range toClose {
				_ = e.f.Close(hc.ctx)
			}
		}
	}
}
