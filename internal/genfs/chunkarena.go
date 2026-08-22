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
// fragmentation to manage and allocation is O(1). Wrapping over live chunks
// is the eviction: FIFO, and there are two of them, because FIFO alone
// thrashes as soon as the volume does not fit in the mapping (see ADMISSION
// below).
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
//
// The one flag that is read WITHOUT the slot lock is dead, and it is atomic
// for it. Two places need to know whether a slot is a corpse while they hold
// a SHARD lock: the tail of put, deciding whether the fill it just made is
// still worth publishing, and forget, deciding whether the entry it found is
// the one it came to remove. Neither may take the slot lock to ask, because
// an eviction holds that lock across its wait for readers and a shard lock
// held behind that wait would stall every reader in the shard. So they load
// it, and because they load it outside the lock kill stores it atomically.
// What that buys is race-freedom and NOT ordering: a slot can die between
// the load and the use, so put publishes and then looks again, and whichever
// of the two goroutines sees the corpse in the index takes it out.
//
// ADMISSION, and the mapping is in TWO REGIONS because of it.
//
// One wrapping cursor over the whole mapping thrashes as soon as the working
// set does not fit: every miss admits, every admit evicts something about to
// be wanted, and a scan defeats itself. Measured on the 166 MiB corpus, a
// bare cursor re-scans at 10% however much it is given short of the whole
// thing — 10% at a 32 MiB arena, and still 10% at 150 MiB, an arena a HAIR
// smaller than the working set, where nearly everything would have fitted.
// That second number is the interesting one: it is the textbook cyclic
// cliff, where the cursor evicts each chunk one access before it is wanted,
// and it does not improve as the arena grows. It improves when the arena
// exceeds the working set, and not before.
//
// The 10% it does serve is worth naming, because it is what any policy here
// has to keep: a 128 KiB kernel read of a 500 KiB chunk decodes the WHOLE
// chunk, so the next three reads of that chunk are hits. Those hits are
// nearly all of what the tier buys on a cold pass, they arrive microseconds
// after the fill, and a policy that holds a new chunk at arm's length to see
// whether it deserves the space throws every one of them away. That is what
// killed the two obvious answers (docs/TODO.md, admission-agent): a
// second-touch doorkeeper, and admitting only chunks a ghost table had seen
// before. Both cost more on the cold and scattered passes than they bought
// on the re-scan, and the ghost variant deadlocked itself — with nothing
// admitted nothing is evicted, so nothing enters the ghost table, so nothing
// is ever admitted again.
//
// So NOTHING IS EVER REFUSED. The gate does not decide whether a chunk is
// cached, only WHERE, and the mapping is split so there is a where:
//
//	probation — a sixteenth of the mapping, its own wrapping cursor. Every
//	            chunk lands here. A scan churns this and only this, and a
//	            sixteenth is many chunks deep, so the sub-reads of the chunk
//	            being streamed are still hits.
//	protected — the rest, its own wrapping cursor, and a scan cannot touch
//	            it. A chunk gets in by having been RE-READ: when the cursor
//	            takes back a slot that somebody read from offset zero while
//	            it was resident, the identity goes into a small ghost table,
//	            and the miss that follows admits it here.
//
// Offset zero is the whole discrimination, and it is free: a read at a
// NONZERO offset is the next kernel window of a chunk being streamed, a read
// at zero of a chunk already resident is somebody coming back to it. Count
// hits instead and a scan promotes itself, which is the failure the shipped
// FIFO had by another name.
//
// While the protected cursor has never lapped it takes everything directly,
// so a working set that fits ends up entirely inside it having paid nothing
// at all for the policy — same hit rates, zero evictions, and the numbers
// this file quotes above are still the numbers. What it buys, on the same
// corpus and against the bare cursor:
//
//	arena             re-scan hit rate      scattered 4 KiB
//	256 MiB (fits)    100% ->  100%         100% -> 100%
//	150 MiB (1.1x)     10% ->   88%          90% ->  92%
//	 32 MiB (0.2x)     10% ->   27%          18% ->  20%
//
// and the number behind those: after a re-scan at 32 MiB, the bare cursor's
// resident 32 MiB contains 0% that anybody has re-read, while this holds
// 94%. It is the same mapping, full of chunks somebody wants instead of
// chunks that happened to be decoded last.
//
// The ghost table is consulted and updated with atomics on the MISS path,
// under the allocation lock, next to a decode that costs microseconds. A HIT
// is the same map lookup and memcpy it always was plus one flag check, which
// is not an accident: the hot re-scan is 100% hits, and an instruction added
// there is paid a hundred times for every time the gate changes a decision.

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
// mu guards the BYTES, which is what makes the mapping safe to share: a
// filler holds it exclusively while it writes, a reader shared while it
// copies, and the allocator exclusively when it takes the space back. dead
// is one-way — a slot never comes back to life, and the space is described
// by a NEW slot when it is handed out again — so a reader that finds a live
// slot and copies under the read lock has read bytes nobody was writing.
//
// dead is ATOMIC as well as being set under mu, and the two are not the same
// requirement: the lock is what makes an eviction WAIT for the readers
// inside the slot, and the atomic is what lets put's publish and forget ask
// whether a slot is a corpse while they hold a shard lock instead (see the
// note at the top of the file). A plain bool read there is a data race with
// kill, and it was one — docs/TODO.md, arenarace-agent.
type arenaSlot struct {
	off    int64
	length int64
	mu     sync.RWMutex
	filled bool        // the bytes are there, guarded by mu
	dead   atomic.Bool // the space has been given to someone else

	// served records that this slot answered at least one read since it
	// was filled, and reused that one of those reads started at offset
	// zero — a whole-chunk re-read rather than the next kernel-sized
	// window of a chunk being streamed. Written under the slot's READ
	// lock, so they are atomic and are checked before being set: eight
	// readers inside one hot chunk must not trade a cache line for a bit
	// that is already the value they want. Nothing reads them but the
	// residency report; they are how "what fraction of the arena is
	// serving repeat reads" gets answered with a number.
	served atomic.Bool
	reused atomic.Bool
}

// arenaRegion is a wrapping bump cursor over one span of the mapping, and
// the queue of what that span currently holds.
//
// There are two, probation and protected, and each is a plain FIFO in its
// own span of the mapping — a chunk never moves between them, so a promotion
// costs a decode and never a memcpy, and every slot stays contiguous.
//
// lapped is the gate's other input: false means the cursor has never
// wrapped, so there is virgin space ahead of it and taking some cannot cost
// anybody their bytes. It is also how the protected region knows to stop
// accepting new chunks directly, which is the moment the policy starts
// existing at all.
type arenaRegion struct {
	base   int64 // where the region starts in the mapping
	size   int64
	next   int64 // the cursor, region-relative
	lapped bool  // the cursor has wrapped at least once: it is full
	q      []*arenaSlot
	keys   []string
	head   int
}

// chunkArena is the tier: the mapping, its two cursors, the index, and the
// gate that chooses between them.
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

	// mu guards the cursors and the allocation queues. It is never held
	// across a decode or a federation read, and readers never take it.
	mu sync.Mutex
	// main is the protected region — the bulk of the mapping, which a scan
	// cannot reach — and probation the sixteenth in front of it that every
	// new chunk goes into.
	main      arenaRegion
	probation arenaRegion

	// ghost remembers the identities of chunks that had earned the
	// protected region when the cursor took them back, so the miss that
	// follows can tell a chunk coming BACK from a chunk arriving. Lock-free.
	ghost *arenaFilter

	// Counters, atomic because the fill path touches them from every
	// reader goroutine and must not serialize on anything.
	fills, evicted, rejected, promoted atomic.Int64
}

// probationShare is the fraction of the mapping new chunks land in, and
// segProbationFloor the least it may come to.
//
// A sixteenth, measured. The share is a straight trade: probation is the
// buffer a scan churns instead of the cache, and every byte of it is a byte
// the protected region does not have. Bigger probation admits more chunks to
// the proving ground and holds fewer proven ones — at a quarter the 1.1x
// re-scan serves 74%, at a sixteenth 88%, at a thirty-second 90%. The knee is
// at a sixteenth and the last two points are worth less than the risk on the
// other side of the trade, which is a probation region too small to hold the
// chunk being streamed through it (see gate).
//
// The floor is what keeps a small arena from having a probation region that
// no chunk fits in. Below it the split stops being a split: a mapping this
// size holds a handful of chunks however they are divided.
const (
	probationShare = 16
	probationFloor = 1 << 20
)

// probationBytes divides the mapping.
func probationBytes(size int64) int64 {
	p := size / probationShare
	if p < probationFloor {
		p = probationFloor
	}
	if p > size/2 {
		p = size / 2
	}
	return p
}

// arenaFilter is a fixed-size, lock-free set of identities seen lately.
//
// It is one uint32 tag per bucket, and its decay is that a bucket holds
// exactly one identity: a tag survives until another identity hashes to the
// same place, which for a table sized to the arena's own entry count is
// about one lap's worth of traffic. That is the horizon this wants — an
// identity the cursor let go of a whole working set ago is not evidence of
// anything, and remembering it forever is how a doorkeeper re-admits an
// entire scan on its second pass.
//
// It is approximate in both directions and that is fine. A false positive
// (two identities, one bucket) admits one chunk that had not earned it; a
// false negative refuses one that had, and costs a decode that the version
// without a filter at all was paying every time.
type arenaFilter struct {
	mask uint64
	tags []atomic.Uint32
}

func newArenaFilter(entries int) *arenaFilter {
	n := 4096
	for n < entries && n < 1<<20 {
		n <<= 1
	}
	return &arenaFilter{mask: uint64(n - 1), tags: make([]atomic.Uint32, n)}
}

// filterHash splits an identity into a bucket and a tag. FNV-1a over the
// first sixteen hex characters: that is sixty-four bits of BLAKE3 output,
// which is more than a table of a million buckets can use, and it is a
// dozen instructions rather than a hash of a 64-byte string.
func filterHash(key string) (uint64, uint32) {
	h := uint64(14695981039346656037)
	n := len(key)
	if n > 16 {
		n = 16
	}
	for i := 0; i < n; i++ {
		h = (h ^ uint64(key[i])) * 1099511628211
	}
	// Never zero: zero is how an untouched bucket reads.
	return h, uint32(h>>32) | 1
}

// note records an identity.
func (f *arenaFilter) note(key string) {
	h, tag := filterHash(key)
	f.tags[h&f.mask].Store(tag)
}

// take reports whether the filter remembers this identity, and forgets it
// if so. Single-use on purpose: the evidence is spent by the admission it
// justifies, so one eviction buys one re-entry and a chunk that came back
// has to earn its next return the same way.
func (f *arenaFilter) take(key string) bool {
	h, tag := filterHash(key)
	b := &f.tags[h&f.mask]
	if b.Load() != tag {
		return false
	}
	b.Store(0)
	return true
}

func (f *arenaFilter) clear() {
	for i := range f.tags {
		f.tags[i].Store(0)
	}
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
	p := probationBytes(size)
	a.probation = arenaRegion{base: 0, size: p}
	a.main = arenaRegion{base: p, size: size - p}
	// The ghost table is sized to the arena's own entry count, so its
	// horizon is about one lap. Chunks are not a fixed size, so the count
	// has to be assumed: eight kilobytes is well under the smallest thing
	// worth caching and errs toward a table too big, which costs memory
	// and nothing else.
	a.ghost = newArenaFilter(int(size / (8 << 10)))
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
	s.dead.Store(true)
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
	if !s.filled || s.dead.Load() || off < 0 || off+int64(len(window)) > s.length {
		s.mu.RUnlock()
		return false
	}
	copy(window, a.mm[s.off+off:s.off+off+int64(len(window))])
	if !s.served.Load() {
		s.served.Store(true)
	}
	if off == 0 && !s.reused.Load() {
		// A read from the START of a chunk that is already here is a
		// genuine re-read. A read at a nonzero offset is the next
		// kernel-sized window of a chunk being streamed, which is reuse of
		// a decode and not evidence of anything about the future.
		s.reused.Store(true)
	}
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
	if s.dead.Load() {
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
	live := !s.dead.Load()
	if live {
		sh.byID[idHex] = s
	}
	sh.mu.Unlock()
	a.fills.Add(1)
	if live && s.dead.Load() {
		// And it died between that check and the publish. Normally the
		// killer takes its victims out of the index itself, but its forget
		// runs after its kill and may already have looked at this shard and
		// found nothing — this fill had not published yet. In that one
		// interleaving nobody else is left to notice, and an index entry
		// naming a dead slot is permanent: every read of it misses, and
		// put's own duplicate check refuses to ever cache the chunk again.
		//
		// It cannot serve wrong bytes — read re-checks dead under mu, which
		// kill holds — so this is the tier quietly losing a chunk, not the
		// mapping losing its integrity. It is still a leak, and the fill
		// that made it is the one that can clean it up.
		a.forget(idHex)
	}
}

// forget removes a key whose slot the cursor has taken back — and only if
// the entry it finds is itself dead, since a concurrent fill may already
// have published a fresh copy of the same chunk somewhere else in the
// mapping, and that copy is nobody's to remove but its own killer's.
//
// The entry it finds may be a slot this goroutine never touched, so the
// deadness test is an atomic load and not a read under the slot's lock:
// this is holding a shard lock, and a shard lock must not wait on a slot
// lock that an eviction holds across its wait for readers.
func (a *chunkArena) forget(key string) {
	sh := a.shard(key)
	sh.mu.Lock()
	if s := sh.byID[key]; s != nil && s.dead.Load() {
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
	r := a.gate(key, length)
	if length > r.size {
		return nil, nil
	}
	var evicted []string
	if r.next+length > r.size {
		// The tail cannot hold this chunk, so the cursor restarts at zero
		// and the bytes between here and the end of the region are
		// stranded. THE SLOTS STILL IN THEM HAVE TO BE TAKEN BACK NOW.
		//
		// They belong to the previous lap and sit at the head of the queue,
		// and the cursor will not reach their addresses again for a whole
		// lap. Leave them there and every eviction for that entire lap
		// finds a head slot that does not overlap the allocation and stops
		// — so the cursor writes over live slots without declaring them
		// dead, the index goes on naming them, and a reader is handed
		// another chunk's bytes under its own identity. That was the
		// v0.1.0 behaviour, invisible on a volume whose chunks all happen
		// to be the same size (nothing is ever stranded) and reproduced by
		// TestArenaSlotsNeverOverlap on one whose chunks vary.
		evicted = append(evicted, a.reclaim(r, r.next, r.size)...)
		r.next = 0
		r.lapped = true
	}
	s := &arenaSlot{off: r.base + r.next, length: length}
	end := r.next + length
	evicted = append(evicted, a.reclaim(r, r.next, end)...)
	// Compact when the dead prefix is most of the queue, so a long session
	// does not grow it without bound.
	if r.head > 0 && r.head*2 >= len(r.q) {
		r.q = append(r.q[:0], r.q[r.head:]...)
		r.keys = append(r.keys[:0], r.keys[r.head:]...)
		r.head = 0
	}
	r.q = append(r.q, s)
	r.keys = append(r.keys, key)
	r.next = end
	return s, evicted
}

// reclaim takes back every slot at the head of the region's queue that
// overlaps [lo, hi), and returns their keys for the caller to unpublish.
//
// Oldest first, for as long as the oldest is in the way. The queue is in
// allocation order, which is address order everywhere except across the
// wrap — and across the wrap the slots at high addresses are the NEWEST, so
// they sit at the back and the front-of-queue test still names the right
// victim. That holds only because a wrap reclaims the stranded tail as it
// happens (see alloc): the head of the queue is always the lowest address
// the cursor has not yet come back to.
//
// Called with a.mu held.
func (a *chunkArena) reclaim(r *arenaRegion, lo, hi int64) []string {
	var out []string
	for r.head < len(r.q) {
		v := r.q[r.head]
		vo := v.off - r.base
		if vo >= hi || vo+v.length <= lo {
			break
		}
		a.kill(v)
		// The gate's memory: what the cursor let go of, so a miss on it
		// later can be told apart from a miss on something new.
		if a.remembers(v) {
			a.ghost.note(r.keys[r.head])
		}
		out = append(out, r.keys[r.head])
		r.head++
		a.evicted.Add(1)
	}
	return out
}

// gate decides which region a freshly decoded chunk goes in. It never
// decides NOT to cache it, which is the property that keeps the cold and
// scattered workloads exactly where they were.
//
// Called with a.mu held, from the allocation path and nowhere else — so it
// is on the MISS path, next to a decode that costs microseconds, and never
// on a hit.
func (a *chunkArena) gate(key string, length int64) *arenaRegion {
	switch {
	case !a.main.lapped:
		// Nothing has had to be evicted yet, so there is nothing to protect
		// FROM and no reason to hold a chunk at arm's length. Fill straight
		// into the protected region: a working set that fits ends up
		// entirely inside it, having paid nothing for the policy.
		return &a.main
	case a.ghost.take(key):
		// Here before, gone, and wanted again — and it left having proved
		// itself. Straight to protected. The evidence is spent by this
		// admission, so the chunk has to earn its next return the same way.
		a.promoted.Add(1)
		return &a.main
	case length > a.probation.size:
		// Too big for probation. Protected is the only region that can hold
		// it, and refusing to cache it would cost every sub-read of a chunk
		// that is, by construction, large enough to be read in pieces. A
		// chunk too big for BOTH regions is not cached at all, exactly as a
		// chunk too big for the whole mapping was not.
		return &a.main
	default:
		return &a.probation
	}
}

// remembers reports whether an evicted slot's identity goes into the ghost
// table — whether, in other words, this chunk had earned a second chance.
//
// The proof is a whole-chunk RE-READ, not merely a hit. A chunk being
// streamed is hit two, three, four times as the kernel walks its windows,
// and those hits are why the tier pays for itself on a cold pass; treating
// them as evidence of reuse would promote an entire scan into the protected
// region and there would be nothing left of the policy. A read that starts
// at offset zero on a chunk that is already resident is a different event:
// somebody came back to the beginning of this chunk.
func (a *chunkArena) remembers(v *arenaSlot) bool { return v.reused.Load() }

// regions is both regions, for the walks that do not care which.
func (a *chunkArena) regions() []*arenaRegion { return []*arenaRegion{&a.main, &a.probation} }

// stats is what the tier is doing, for `pelfs cache` and the statistics
// file. promoted is how often the ghost table let a chunk back into the
// protected region, which is the number that says the policy is adapting
// rather than merely holding whatever it saw first.
func (a *chunkArena) stats() (fills, evicted, rejected, promoted int64) {
	if a == nil {
		return 0, 0, 0, 0
	}
	return a.fills.Load(), a.evicted.Load(), a.rejected.Load(), a.promoted.Load()
}

// arenaResidency is what the mapping is HOLDING, as opposed to what has
// passed through it: the question "is the arena full of chunks anybody
// reads again", answered with a number.
type arenaResidency struct {
	// Slots and Bytes are what is resident.
	Slots int
	Bytes int64
	// Served and Reused are the resident slots that have answered any read
	// since they were filled, and the ones that answered a read starting at
	// offset zero — a whole-chunk re-read rather than the streaming
	// continuation of the read that filled them.
	Served, Reused           int
	ServedBytes, ReusedBytes int64
}

func (a *chunkArena) residency() arenaResidency {
	var out arenaResidency
	if a == nil {
		return out
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.regions() {
		for i := r.head; i < len(r.q); i++ {
			s := r.q[i]
			out.Slots++
			out.Bytes += s.length
			if s.served.Load() {
				out.Served++
				out.ServedBytes += s.length
			}
			if s.reused.Load() {
				out.Reused++
				out.ReusedBytes += s.length
			}
		}
	}
	return out
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
	for _, r := range a.regions() {
		for i := r.head; i < len(r.q); i++ {
			a.kill(r.q[i])
		}
		r.q, r.keys, r.head, r.next, r.lapped = nil, nil, 0, 0, false
	}
	// And the gate forgets too: every identity it remembered named a slot
	// in a generation that is no longer the one being read.
	a.ghost.clear()
	a.mu.Unlock()
	for i := range a.idx {
		a.idx[i].mu.Lock()
		a.idx[i].byID = make(map[string]*arenaSlot)
		a.idx[i].mu.Unlock()
	}
}
