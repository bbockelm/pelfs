package nfsmount

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io/fs"
	"net"
	"strings"
	"sync"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
)

// handles is the file-handle table go-nfs asks for: every RPC arrives as
// an opaque handle and must be turned back into a (filesystem, path).
//
// It exists because helpers.CachingHandler cannot be used at scale. Its
// FromHandle walks EVERY live handle — Keys() allocates the whole key set,
// then Peek+hasPrefix each one — to bump the recency of the target's
// ancestors. That is O(live handles) per RPC, and a create-heavy workload
// mints a handle per file, so the cost grows with the tree: measured at
// 22% of server CPU after only 8k files, and rising. Same job here, but a
// path already names its ancestors, so the bump is O(depth) map lookups
// with no allocation.
//
// Handles are 16 bytes: an 8-byte per-server boot value and an 8-byte
// counter. The boot value means a handle minted by a previous server
// instance is reported stale rather than silently resolving to whatever
// path now holds that counter.
type handles struct {
	nfs.Handler // Mount/Change/FSStat come from the wrapped handler

	boot [8]byte

	mu     sync.Mutex
	byID   map[uint64]*handleEntry
	byPath map[string]*handleEntry
	order  *list.List // *handleEntry, most recently used at the front
	next   uint64
	limit  int

	verifiers   map[uint64][]fs.FileInfo
	verifyOrder *list.List // uint64, most recently used at the front
	verifyElem  map[uint64]*list.Element
	verifyLimit int
	// verifyEntries is the number of fs.FileInfo values the cache
	// currently retains, across every listing (see verifyEntryLimit).
	verifyEntries int
}

// The verifier cache is bounded separately from the handle table, and by
// BYTES as much as by count.
//
// A handle retains a path; a verifier retains a whole directory LISTING —
// one fs.FileInfo per entry, measured at ~85 bytes each. Sizing the two
// alike — a verifier bound at the handle limit of 1<<20 — puts no useful
// ceiling on the second: a million cached listings of a thousand entries
// is 84 GB. Measured on a 100k-file / 2000-directory tree, one `find`
// left 11 MB of listings pinned for the life of the mount.
//
// Nothing needs them for that long. A verifier exists to keep ONE client's
// READDIR continuation self-consistent while the directory changes under
// it, which lasts milliseconds; and losing one is not an error — go-nfs
// re-reads the directory and recomputes the verifier, which still matches
// whenever the directory has not changed, and yields NFS3ERR_BAD_COOKIE
// (a restarted scan) only when it has.
const (
	// verifyLimit bounds concurrent in-flight directory scans.
	verifyLimit = 1024
	// verifyEntryLimit bounds the total retained listing entries, so one
	// scan of a huge directory cannot pin an unbounded amount on its own.
	// At ~85 bytes per entry this is roughly 22 MB.
	verifyEntryLimit = 256 << 10
)

type handleEntry struct {
	id   uint64
	f    billy.Filesystem
	p    []string
	key  string // f.Join(p...): the reverse-map key, and its own ancestry
	elem *list.Element
}

// newHandles wraps h with a handle table bounded at limit entries.
func newHandles(h nfs.Handler, limit int) *handles {
	if limit < 2 {
		limit = 2
	}
	t := &handles{
		Handler:     h,
		byID:        make(map[uint64]*handleEntry),
		byPath:      make(map[string]*handleEntry),
		order:       list.New(),
		limit:       limit,
		verifiers:   make(map[uint64][]fs.FileInfo),
		verifyOrder: list.New(),
		verifyElem:  make(map[uint64]*list.Element),
		verifyLimit: verifyLimit,
	}
	if _, err := rand.Read(t.boot[:]); err != nil {
		// A predictable boot value only weakens the staleness check for
		// handles from a previous instance; it is not worth failing a
		// mount over.
		binary.BigEndian.PutUint64(t.boot[:], 0x70656c6673000001)
	}
	return t
}

func (t *handles) HandleLimit() int { return t.limit }

// ToHandle returns the handle for (f, path), minting one on first use.
func (t *handles) ToHandle(f billy.Filesystem, path []string) []byte {
	key := f.Join(path...)

	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.byPath[key]; ok && sameFS(e.f, f) {
		t.order.MoveToFront(e.elem)
		return t.encode(e.id)
	}

	t.next++
	e := &handleEntry{id: t.next, f: f, p: append([]string(nil), path...), key: key}
	e.elem = t.order.PushFront(e)
	t.byID[e.id] = e
	// A path maps to one handle. Displacing an incumbent (a different
	// filesystem under the same name) drops only the reverse mapping: the
	// old id keeps resolving until it ages out, so a client still holding
	// it is not handed a stale handle mid-operation.
	t.byPath[key] = e
	for t.order.Len() > t.limit {
		t.evictLocked(t.order.Back().Value.(*handleEntry))
	}
	return t.encode(e.id)
}

// FromHandle resolves a handle to the (filesystem, path) it was minted
// for, refreshing the whole ancestor chain: a directory handle evicted
// while its children are in active use would go stale under a client that
// still holds it.
func (t *handles) FromHandle(fh []byte) (billy.Filesystem, []string, error) {
	id, ok := t.decode(fh)
	if !ok {
		return nil, []string{}, &nfs.NFSStatusError{NFSStatus: nfs.NFSStatusStale}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.byID[id]
	if e == nil {
		return nil, []string{}, &nfs.NFSStatusError{NFSStatus: nfs.NFSStatusStale}
	}
	t.order.MoveToFront(e.elem)
	t.bumpAncestorsLocked(e.key)
	return e.f, append([]string(nil), e.p...), nil
}

func (t *handles) InvalidateHandle(_ billy.Filesystem, fh []byte) error {
	id, ok := t.decode(fh)
	if !ok {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.byID[id]; e != nil {
		t.evictLocked(e)
	}
	return nil
}

// bumpAncestorsLocked refreshes every proper ancestor of key. Joined paths
// are slash-separated with no trailing slash and the root is the empty
// string, so trimming at the last slash walks the chain without
// allocating.
func (t *handles) bumpAncestorsLocked(key string) {
	for key != "" {
		if i := strings.LastIndexByte(key, '/'); i >= 0 {
			key = key[:i]
		} else {
			key = ""
		}
		if e, ok := t.byPath[key]; ok {
			t.order.MoveToFront(e.elem)
		}
	}
}

func (t *handles) evictLocked(e *handleEntry) {
	t.order.Remove(e.elem)
	delete(t.byID, e.id)
	// Only drop the reverse entry if it still points at this handle; a
	// newer one for the same path must survive its predecessor.
	if cur, ok := t.byPath[e.key]; ok && cur == e {
		delete(t.byPath, e.key)
	}
}

func (t *handles) encode(id uint64) []byte {
	b := make([]byte, 16)
	copy(b, t.boot[:])
	binary.BigEndian.PutUint64(b[8:], id)
	return b
}

func (t *handles) decode(fh []byte) (uint64, bool) {
	if len(fh) != 16 || string(fh[:8]) != string(t.boot[:]) {
		return 0, false
	}
	return binary.BigEndian.Uint64(fh[8:]), true
}

// sameFS reports whether two billy.Filesystem values are the same object.
// Both implementations served here are pointers, so identity is the whole
// question; anything else is treated as different, which only costs an
// extra handle.
func sameFS(a, b billy.Filesystem) bool { return a == b }

// Verifier cache — READDIR cookies. go-nfs hands out a verifier for a
// directory listing and expects the same listing back for continuation
// requests, so that a directory changing mid-scan does not silently skip
// or duplicate entries.

func (t *handles) VerifierFor(path string, contents []fs.FileInfo) uint64 {
	id := hashPathAndContents(path, contents)
	t.mu.Lock()
	defer t.mu.Unlock()
	if elem, ok := t.verifyElem[id]; ok {
		t.verifyOrder.MoveToFront(elem)
		t.verifyEntries += len(contents) - len(t.verifiers[id])
		t.verifiers[id] = contents
		return id
	}
	t.verifiers[id] = contents
	t.verifyEntries += len(contents)
	t.verifyElem[id] = t.verifyOrder.PushFront(id)
	// Evict least-recently-used listings until BOTH bounds hold, but
	// never the one just cached: the caller is about to serve from it,
	// and a single directory larger than the entry budget must still be
	// listable.
	for t.verifyOrder.Len() > 1 &&
		(t.verifyOrder.Len() > t.verifyLimit || t.verifyEntries > verifyEntryLimit) {
		back := t.verifyOrder.Back()
		old := back.Value.(uint64)
		t.verifyOrder.Remove(back)
		delete(t.verifyElem, old)
		t.verifyEntries -= len(t.verifiers[old])
		delete(t.verifiers, old)
	}
	return id
}

func (t *handles) DataForVerifier(_ string, id uint64) []fs.FileInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	if elem, ok := t.verifyElem[id]; ok {
		t.verifyOrder.MoveToFront(elem)
	}
	return t.verifiers[id]
}

func hashPathAndContents(path string, contents []fs.FileInfo) uint64 {
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(path))))
	h.Write([]byte(path))
	for _, c := range contents {
		h.Write([]byte(c.Name()))
	}
	return binary.BigEndian.Uint64(h.Sum(nil)[:8])
}

// The remaining Handler methods are the wrapped handler's, but Mount must
// be named explicitly: nfs.Handler embeds it and Go would otherwise
// promote it ambiguously alongside the interface's own declaration.
func (t *handles) Mount(ctx context.Context, c net.Conn, r nfs.MountRequest) (nfs.MountStatus, billy.Filesystem, []nfs.AuthFlavor) {
	return t.Handler.Mount(ctx, c, r)
}
