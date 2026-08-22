package genfs

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// The decoded-chunk tier: ONE file, not one file per chunk.
//
// It used to be gencache/chunks/, a flat directory holding a plaintext file
// per chunk anyone had ever read. Measured on a 166 MiB source-shaped tree
// that is 6,646 files and 6,646 inodes in one directory, and a volume is
// not 166 MiB — the shape does not have an upper bound that a filesystem
// would recognize as reasonable. Filling it also cost more than it saved
// on the workload it was supposed to help: a cold read of the whole tree
// ran 2.3x SLOWER with the tier on than with it off, because writing 6,646
// small files is more work than decoding 166 MiB.
//
// What it did buy is real, and it is why this is not simply deleted. zstd
// runs at about 1.3 GiB/s here and AES-GCM adds only ~5%, so a decode is
// not free — and the smaller the chunk the worse the rate gets, 0.5 GiB/s
// at 4 KiB against 1.3 GiB/s at 4 MiB. Worse, a kernel-sized read decodes
// a WHOLE chunk to serve 128 KiB of it, so an uncached re-read of that
// tree decodes 461 MiB to deliver 166 MiB. With no decode tier at all the
// same tree costs 0.89 s to scan, 0.89 s to re-scan, and 1.43 s for
// twenty thousand scattered 4 KiB reads.
//
// This shape costs 0.55 s, 13 ms and 32 ms for the same three, in one
// inode. It beats BOTH the directory it replaced and no cache at all, on
// every workload measured — the directory won on re-reads and lost on
// fills, and an arena fill is a memcpy into a mapping.
//
// So the tier stays and the SHAPE changes. One preallocated, mmap'd file:
//
//   - one inode and one directory entry, whatever the volume holds;
//   - the page cache is the memory tier, so hot chunks are a memcpy away
//     and cold ones cost the kernel a page fault, with no read(2) per
//     chunk and no filesystem metadata per chunk;
//   - the index is in MEMORY and is never written down. A crash therefore
//     loses decode work and nothing else, which is the only thing in here
//     that was ever at stake — every byte of it is re-derivable from a
//     pack.
//
// Space is allocated by a bump cursor that WRAPS, so there is no
// fragmentation to manage and allocation is O(1). Wrapping over live
// chunks is the eviction: FIFO, which for this cache is not the
// compromise it sounds like — the arena's own numbers say so.
//
// A ristretto (TinyLFU) index was built first, because a scan-resistant
// admission policy is the obviously right answer to "what belongs in a
// cache", and it lost to a plain map by a wide margin on every workload
// measured: 28% hit rate on a hot re-read against 100%, and 8% on
// scattered reads against 100%. The reason is not the POLICY, it is the
// visibility. ristretto's Set is asynchronous — it queues, and a Get
// issued before the queue drains misses — and the single most common
// event in this cache is a chunk being read again microseconds after it
// was decoded, because a 500 KiB chunk serves a 128 KiB kernel read four
// times over. A cache that cannot answer for what it was just given
// cannot serve that, and no eviction policy compensates. The index is a
// sharded map, and it answers the moment the bytes are in.
//
// PLAINTEXT AT REST, unchanged. On an encrypted volume this file holds
// decrypted chunk bytes, exactly as the chunks/ directory did — the
// exposure is neither widened nor narrowed here, it moves from many files
// to one, under the same state directory and the same 0600 mode. What
// does change for the better is lifetime: the index dies with the process
// and the file is truncated at the next Open, where a chunks/ directory
// persisted plaintext across mounts until something evicted it. A volume
// whose plaintext must not touch local disk at all still needs
// ChunkArenaBytes negative, and that is still true of the pack cache for
// ciphertext.
//
// Concurrency is the part worth reading carefully. A reader copies bytes
// out of the mapping while, in principle, the cursor is about to write over
// them. Every slot carries an RWMutex; a reader holds it shared for the
// length of one memcpy, a filler holds it exclusively while it writes, and
// the allocator takes it exclusively to declare a slot dead before it hands
// the space away. So an eviction WAITS for the readers inside the region it
// is taking — the parked-read discipline gencache_test.go pins for the file
// cache — and no two goroutines are ever inside the same bytes.

// DefaultChunkArenaBytes is the decoded-chunk arena's size when nothing
// says otherwise.
//
// Modest on purpose, and much smaller than the share of a 4 GiB cache the
// old chunks/ directory could grow to take. The tier is an amortizer, not
// a store: it only ever saves a DECODE, the packs behind it are local and
// bounded by their own budget, and a working set that does not fit here
// still reads correctly at pack speed. Spending gigabytes to hold a second
// plaintext copy of a volume whose packs are already on the disk is the
// trade the old shape made by accident.
const DefaultChunkArenaBytes = 256 << 20

// chunkArenaShare bounds the arena to a fraction of the whole cache budget,
// so a mount told to use 64 MiB of disk does not spend 256 MiB of it here.
const chunkArenaShare = 8

// arenaSlot is one decoded chunk's place in the mapping.
//
// mu guards BOTH the bytes and the flags, which is what makes the mapping
// safe to share: a filler holds it exclusively while it writes, a reader
// shared while it copies, and the allocator exclusively when it takes the
// space back. dead is one-way — a slot never comes back to life, and the
// space is described by a NEW slot when it is handed out again — so a
// reader that finds a live slot and copies under the read lock has read
// bytes nobody was writing.
type arenaSlot struct {
	off    int64
	length int64
	mu     sync.RWMutex
	filled bool // the bytes are there
	dead   bool // the space has been given to someone else
}

// chunkArena is the tier: the mapping, the cursor, and the index.
type chunkArena struct {
	f    *os.File
	mm   []byte
	size int64

	// idx maps identity to place. Sharded because every read consults it
	// and a single lock across a mount's readers would be the cache's own
	// bottleneck; a map rather than something cleverer because it has to
	// answer SYNCHRONOUSLY (see the note above) and because the ring is
	// what bounds it — an entry exists exactly while the cursor has not
	// come back round to its bytes.
	idx [arenaShards]arenaShard

	// mu guards the cursor and the allocation queue. It is never held
	// across a decode or a federation read, and readers never take it.
	mu sync.Mutex
	// next is the bump cursor: the offset the next allocation starts at.
	next int64
	// q is the slots in allocation order, oldest first — the eviction
	// order, and the only record of what occupies the mapping. head is the
	// index of the oldest slot still in it.
	q    []*arenaSlot
	keys []string
	head int

	// Counters, atomic because the fill path touches them from every
	// reader goroutine and must not serialize on anything.
	fills, evicted, rejected atomic.Int64
}

// arenaShards is how many pieces the index is cut into. A power of two so
// the shard is a mask of the identity's own first bytes, which are already
// a hash.
const arenaShards = 64

type arenaShard struct {
	mu   sync.RWMutex
	byID map[string]*arenaSlot
}

// shard picks an entry's shard from the identity hex, which is BLAKE3
// output and therefore already uniform; hashing it again would buy
// nothing.
func (a *chunkArena) shard(idHex string) *arenaShard {
	if len(idHex) < 2 {
		return &a.idx[0]
	}
	return &a.idx[(int(idHex[0])^int(idHex[1])<<3)&(arenaShards-1)]
}

// arenaPath is where the mapping lives. A single name, so a v0.1.0 state
// directory's chunks/ tree is recognizably a different thing and can be
// swept (sweepLegacyChunkDir).
const arenaName = "chunks.arena"

// newChunkArena creates (or recreates) the mapping and its index.
//
// The file is TRUNCATED at open, not reused. The index is in memory, so a
// mapping inherited from a previous process describes nothing this one
// knows about; keeping the bytes would only mean holding disk for data
// that can never be read again.
func newChunkArena(dir string, size int64) (*chunkArena, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := arenaFilePath(dir)
	if size <= 0 {
		// Off — and a previous session's mapping is not a file this one may
		// leave lying about. It is charged against the same cache budget,
		// nothing can read it (the index died with that process), and no
		// sweep will take it, because the arena is never an eviction
		// candidate. A mount opened with a smaller budget than the last one
		// lands here, and used to inherit an arena it had not agreed to.
		os.Remove(path) //nolint:errcheck
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(size); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	mm, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("genfs: mmap chunk arena %s: %w", path, err)
	}
	a := &chunkArena{f: f, mm: mm, size: size}
	for i := range a.idx {
		a.idx[i].byID = make(map[string]*arenaSlot)
	}
	return a, nil
}

func arenaFilePath(dir string) string { return dir + string(os.PathSeparator) + arenaName }

// Close unmaps and closes the mapping. The file is left behind; the next
// Open truncates it.
func (a *chunkArena) Close() error {
	if a == nil {
		return nil
	}
	if err := unix.Munmap(a.mm); err != nil {
		a.f.Close() //nolint:errcheck
		return err
	}
	return a.f.Close()
}

// kill declares a slot's space no longer its own. It is idempotent, it
// takes no lock but the slot's, and it BLOCKS until every reader inside
// the slot has left — which is exactly what makes the space safe to reuse.
func (a *chunkArena) kill(s *arenaSlot) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.dead = true
	s.mu.Unlock()
}

// read serves window from the chunk with this identity, reporting whether
// it was there. A false is always safe: the caller decodes from the pack.
func (a *chunkArena) read(idHex string, off int64, window []byte) bool {
	if a == nil {
		return false
	}
	sh := a.shard(idHex)
	sh.mu.RLock()
	s := sh.byID[idHex]
	sh.mu.RUnlock()
	if s == nil {
		return false
	}
	s.mu.RLock()
	// filled and not dead, checked INSIDE the lock the allocator has to
	// take before it can hand this space to anyone else. Past this point
	// the bytes cannot move until the copy is done.
	if !s.filled || s.dead || off < 0 || off+int64(len(window)) > s.length {
		s.mu.RUnlock()
		return false
	}
	copy(window, a.mm[s.off+off:s.off+off+int64(len(window))])
	s.mu.RUnlock()
	return true
}

// put copies one decoded chunk into the mapping and publishes it.
//
// Failure is never reported, because there is no failure a caller could do
// anything about: a chunk too large for the arena, an arena the admission
// policy would rather spend on something else, a slot the cursor reclaimed
// before this goroutine got to fill it — every one of them means the next
// read of this chunk decodes it again, which is what happens without a
// tier at all.
func (a *chunkArena) put(idHex string, plain []byte) {
	if a == nil || int64(len(plain)) > a.size || len(plain) == 0 {
		return
	}
	// Already here — two readers missed the same chunk and both decoded it,
	// which the fill gate makes rare and does not make impossible. Taking
	// space for the second copy would cost the cursor a lap for nothing.
	sh := a.shard(idHex)
	sh.mu.RLock()
	dup := sh.byID[idHex]
	sh.mu.RUnlock()
	if dup != nil {
		a.rejected.Add(1)
		return
	}
	s, evicted := a.alloc(idHex, int64(len(plain)))
	if s == nil {
		return
	}
	// The keys the cursor ran over, dropped AFTER the allocation lock is
	// back down: their slots are already declared dead, so a reader that
	// still holds one of these keys gets a miss, never wrong bytes.
	for _, k := range evicted {
		a.forget(k)
	}
	s.mu.Lock()
	if s.dead {
		// The cursor came all the way round and gave this space to someone
		// else while we were queued behind their readers. Nothing to undo:
		// the slot was never published.
		s.mu.Unlock()
		return
	}
	copy(a.mm[s.off:s.off+s.length], plain)
	s.filled = true
	s.mu.Unlock()
	sh.mu.Lock()
	// Published only if it is STILL alive: the cursor may have lapped
	// between the copy above and this line.
	if !s.dead {
		sh.byID[idHex] = s
	}
	sh.mu.Unlock()
	a.fills.Add(1)
}

// forget removes a key whose slot the cursor has taken back — and only if
// the map still names THAT slot, since a concurrent fill may already have
// published a fresh copy of the same chunk somewhere else in the mapping.
func (a *chunkArena) forget(key string) {
	sh := a.shard(key)
	sh.mu.Lock()
	if s := sh.byID[key]; s != nil && s.dead {
		delete(sh.byID, key)
	}
	sh.mu.Unlock()
}

// alloc reserves length bytes at the cursor for key, and returns the keys
// whose slots the cursor ran over for the caller to remove from the index.
//
// Wrapping is the eviction. There is no free list and no fragmentation:
// the cursor advances, and whatever it reaches is the oldest thing in the
// mapping by construction. A request that will not fit in the tail
// restarts at zero rather than splitting, which strands a few bytes and
// keeps every slot contiguous — so a reader is one memcpy, never two.
//
// It kills its victims while holding the allocation lock, and killing
// waits for the readers inside them. That wait is the length of one
// memcpy, and it is not optional: handing the space out while somebody is
// still reading it is the one bug this whole structure exists to not have.
func (a *chunkArena) alloc(key string, length int64) (*arenaSlot, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if length > a.size {
		return nil, nil
	}
	if a.next+length > a.size {
		a.next = 0
	}
	s := &arenaSlot{off: a.next, length: length}
	end := a.next + length
	var evicted []string
	// Oldest first, for as long as the oldest is in the way. The queue is
	// in allocation order, which is address order everywhere except across
	// the wrap — and across the wrap the slots at high addresses are the
	// NEWEST, so they sit at the back and the front-of-queue test still
	// names the right victim.
	for a.head < len(a.q) {
		v := a.q[a.head]
		if v.off >= end || v.off+v.length <= a.next {
			break
		}
		a.kill(v)
		evicted = append(evicted, a.keys[a.head])
		a.head++
		a.evicted.Add(1)
	}
	// Compact when the dead prefix is most of the queue, so a long session
	// does not grow it without bound.
	if a.head > 0 && a.head*2 >= len(a.q) {
		a.q = append(a.q[:0], a.q[a.head:]...)
		a.keys = append(a.keys[:0], a.keys[a.head:]...)
		a.head = 0
	}
	a.q = append(a.q, s)
	a.keys = append(a.keys, key)
	a.next = end
	return s, evicted
}

// stats is what the tier is doing, for `pelfs cache` and the statistics
// file.
func (a *chunkArena) stats() (fills, evicted, rejected int64) {
	if a == nil {
		return 0, 0, 0
	}
	return a.fills.Load(), a.evicted.Load(), a.rejected.Load()
}

// has reports whether the identity is in the index right now. It is the
// batched fill path's "do not bother" test; a false costs a decode that
// would have happened anyway.
func (a *chunkArena) has(idHex string) bool {
	if a == nil {
		return false
	}
	sh := a.shard(idHex)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.byID[idHex] != nil
}

// bytes is the disk the arena holds. It is the whole mapping, always: the
// file is preallocated, so this is a reservation and not a measurement,
// and reporting anything else would understate what the cache is costing.
func (a *chunkArena) bytes() int64 {
	if a == nil {
		return 0
	}
	return a.size
}

// chunkArenaBytes resolves the arena's size from what the caller asked for
// and what the whole cache is allowed to use.
//
// The share matters more than the default. A mount told its entire cache
// may be 64 MiB should not find a quarter of it gone to a reservation it
// never asked for, and the arena only ever saves a DECODE — the packs it
// decodes from are what actually has to fit.
func chunkArenaBytes(want, cacheCap int64) int64 {
	if want < 0 {
		return 0 // the tier is off
	}
	if want == 0 {
		want = DefaultChunkArenaBytes
	}
	if cacheCap > 0 {
		if share := cacheCap / chunkArenaShare; share < want {
			want = share
		}
	}
	// Below a megabyte there is nothing an arena can hold that a single
	// chunk would not evict, so it is not worth the mapping.
	if want < 1<<20 {
		return 0
	}
	return want
}

// sweepLegacyChunkDir removes the v0.1.0 decoded-chunk directory and
// reports what was in it.
//
// gencache/chunks/ held one plaintext file per chunk the mount had ever
// read, unbounded until the shared budget arrived and flat however many
// there were. Nothing reads it now. It is a cache in the strict sense —
// every byte re-derivable from a pack — so deleting it cannot lose
// anything, and NOT deleting it would leave disk that no budget in this
// process covers and no command in the tool reclaims.
//
// Failures are ignored on purpose: a mount that cannot tidy up still
// mounts, and it will try again next time.
func sweepLegacyChunkDir(cacheDir string) (files int, bytes int64) {
	dir := cacheDir + string(os.PathSeparator) + "chunks"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if fi, err := e.Info(); err == nil {
			bytes += fi.Size()
		}
		if os.Remove(dir+string(os.PathSeparator)+e.Name()) == nil {
			files++
		}
	}
	os.Remove(dir) //nolint:errcheck
	return files, bytes
}

// clear empties the tier: every entry out of the index and the cursor back
// to the start. It is what a generation swap and a test that wants a cold
// decode path both need, and it is cheap — the mapping's bytes are not
// touched, they simply stop being described by anything.
func (a *chunkArena) clear() {
	if a == nil {
		return
	}
	a.mu.Lock()
	// Dead first, then unmapped from the index: a reader between the two
	// sees a slot it is told is dead, which is a miss, which is correct.
	for i := a.head; i < len(a.q); i++ {
		a.kill(a.q[i])
	}
	a.q, a.keys, a.head, a.next = nil, nil, 0, 0
	a.mu.Unlock()
	for i := range a.idx {
		a.idx[i].mu.Lock()
		a.idx[i].byID = make(map[string]*arenaSlot)
		a.idx[i].mu.Unlock()
	}
}
