package memtable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// DefaultTableSize is the memtable capacity. The design says to start at
// the pack target so the common case produces full packs; it is one knob
// here rather than two for exactly that reason.
const DefaultTableSize = 64 << 20

// Options configures a Store.
type Options struct {
	// Dir is the state directory holding buffer files.
	Dir string
	// TableSize is the ring's capacity in bytes, headers included.
	TableSize int
	// PromotionDistance is how far behind the head an extent must fall
	// before the packer takes it. Zero packs whatever is there, which is
	// what a flush wants; DefaultPromotionDistance is what a session
	// wants, so churn has a chance to die before anything is sent.
	PromotionDistance uint64
	// Obj is the federation. Flushes upload packs to packs/<name>.
	Obj pelicanobj.Store
	// PackCacheBytes bounds the local copy of packs (see packCache). Zero
	// takes DefaultPackCacheBytes; PackCacheDisabled turns it off, which
	// makes every read of packed content a federation round trip.
	PackCacheBytes int64
	// Chunk configures the CDC pass. Zero fields take chunkid's defaults.
	Chunk chunkid.Options
	// Hasher binds chunk identity (keyed for encrypted volumes).
	Hasher chunkid.Hasher
	// Hooks are test seams; all fields may be nil.
	Hooks Hooks
}

// Hooks let a test observe the inside of a flush, which is the only way
// to assert on states that exist for microseconds in production — a pack
// uploaded but its locations not yet published, for instance.
type Hooks struct {
	// FlushStarted runs on the flusher goroutine once the live set has
	// been snapshotted and before any chunking.
	FlushStarted func(seq uint64)
	// BeforePublish runs after every pack of a flush is durable and
	// before any location is installed. Returning an error aborts the
	// flush there, simulating a crash in that window.
	BeforePublish func(seq uint64) error
}

// Stats is what the prototype is for. Every field is a count the design
// makes a claim about.
type Stats struct {
	WrittenBytes int64 // bytes handed to Write
	Extents      int64 // extents appended
	Flushes      int64
	// DeadExtents and DeadBytes are extents that were wholly superseded
	// before their table flushed and therefore never left the machine.
	DeadExtents int64
	DeadBytes   int64
	// UploadedBytes counts pack entry bytes actually sent, trailers
	// excluded, so it compares directly against WrittenBytes.
	UploadedBytes  int64
	UploadedChunks int64
	Packs          int64
	// ReclaimErrors counts ring regions a completed pack could not
	// release. That costs space, never correctness, so it is a statistic
	// rather than a failure.
	ReclaimErrors int64
	// RechunkedSpans and RechunkedBytes count what a seal could not
	// express as whole chunks and had to chunk again (see Sealer). They
	// are the price of keeping "whole chunks, end to end" in the format,
	// and the claim they check is that it is proportional to the REWRITE
	// rather than to the file.
	RechunkedSpans int64
	RechunkedBytes int64
	// BlockedWrites counts writes that had to wait for a flush to finish
	// — the backpressure rule firing.
	BlockedWrites int64
	// LostHandles counts extents a recovery could not find. Nonzero means
	// data loss and the caller must say so out loud.
	LostHandles int64
	// PackReadsLocal and PackReadsRemote split reads of packed content by
	// where the bytes came from. The claim they check is the one that
	// decides whether staging can go away: content this session wrote
	// stays readable — and re-chunkable at seal — without the network.
	PackReadsLocal  int64
	PackReadsRemote int64
}

// Store is the write path: one active memtable, at most one flushing
// memtable, and a location map naming what has reached the federation.
type Store struct {
	dir       string
	tableSize int
	obj       pelicanobj.Store
	chunkOpts chunkid.Options
	hasher    chunkid.Hasher
	hooks     Hooks

	// promotion is how far behind the head an extent must fall before it
	// is packed. Zero means pack everything, which is what a flush asks
	// for.
	promotion uint64

	mu   sync.Mutex
	cond *sync.Cond

	// ring is the whole write buffer. There is no active/frozen pair: a
	// writer appends at the head while the packer consumes the tail, and
	// the region a pack covered is reclaimed as soon as its locations are
	// published.
	ring  *Ring
	index map[Handle]Record // handle -> its record, position absolute
	live  map[Handle]int    // content references per handle
	order []Handle          // handles in ring order, oldest first

	// cache is the local copy of packs this session wrote or read. It is
	// what lets a seal re-chunk a rewrite without fetching back bytes it
	// uploaded minutes ago.
	cache *packCache

	packing bool // a pack run is in flight
	// reclaimTo is the furthest position a completed pack has asked the
	// tail to reach. It is remembered because a reader's pin can hold the
	// tail short of it, and nothing else would ever try again — a writer
	// waiting for exactly that space would wait forever.
	reclaimTo uint64
	flushErr  error

	nextHandle Handle
	nextSeq    uint64

	// content stands in for the overlay's ocontent rows. Nothing here is
	// rewritten by a flush; that is the property the design rests on, and
	// keeping it in one place makes it checkable.
	content map[uint64]*content

	// The two halves of the location map. A handle resolves to slices of
	// chunks; a chunk resolves to a place in a pack. Both bind at flush,
	// and neither touches a content row.
	handleLoc map[Handle][]ChunkSlice
	chunkLoc  map[string]PackLoc
	packs     []packstore.SealedPack

	stats  Stats
	closed bool
	wg     sync.WaitGroup
}

// ChunkSlice maps part of an extent to part of a chunk. An extent's
// slices are ordered and cover it exactly: CDC boundaries are chosen from
// content, so they do not respect extent boundaries in either direction.
type ChunkSlice struct {
	ID       chunkid.Identity
	ChunkOff int // where in the chunk the extent's bytes start
	Length   int
}

// PackLoc is where a chunk landed: the second half of the location map,
// and the half the format already has — a pack name and an offset,
// reachable from the superblock's pack list through pack trailers.
type PackLoc struct {
	Pack   string
	Off    int64
	Length int64
}

func bufferName(seq uint64) string { return fmt.Sprintf("mem-%06d.buf", seq) }

// New creates a store in dir. An existing state directory is NOT
// recovered here; use Recover, which reports what it could not find.
func New(opts Options) (*Store, error) {
	s, err := newStore(opts)
	if err != nil {
		return nil, err
	}
	if err := s.openActive(); err != nil {
		return nil, err
	}
	return s, nil
}

func newStore(opts Options) (*Store, error) {
	if opts.TableSize == 0 {
		opts.TableSize = DefaultTableSize
	}
	if opts.TableSize <= recordHeader {
		return nil, fmt.Errorf("memtable: table size %d leaves no room for a record", opts.TableSize)
	}
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, err
	}
	if opts.PackCacheBytes == 0 {
		opts.PackCacheBytes = DefaultPackCacheBytes
	}
	s := &Store{
		dir:       opts.Dir,
		tableSize: opts.TableSize,
		promotion: opts.PromotionDistance,
		index:     make(map[Handle]Record),
		live:      make(map[Handle]int),
		obj:       opts.Obj,
		chunkOpts: opts.Chunk,
		hasher:    opts.Hasher,
		hooks:     opts.Hooks,
		content:   make(map[uint64]*content),
		handleLoc: make(map[Handle][]ChunkSlice),
		chunkLoc:  make(map[string]PackLoc),
	}
	s.cond = sync.NewCond(&s.mu)
	if opts.PackCacheBytes > 0 {
		c, err := newPackCache(filepath.Join(opts.Dir, "packs"), opts.PackCacheBytes)
		if err != nil {
			return nil, err
		}
		s.cache = c
	}
	return s, nil
}

func (s *Store) openActive() error {
	r, err := CreateRing(filepath.Join(s.dir, bufferName(s.nextSeq)), s.tableSize)
	if err != nil {
		return err
	}
	s.nextSeq++
	s.ring = r
	return nil
}

// maxPayload is the largest single record. A write longer than this is
// split, which the write path must do regardless because one write() can
// be arbitrarily large — and the ring refuses an oversized record with a
// distinct error precisely so a caller cannot mistake it for something
// waiting will fix.
func (s *Store) maxPayload() int { return MaxRecord(s.tableSize) }

// Write appends p at off in ino. It blocks only when the ring has no room
// and the packer has not yet freed any — the design's backpressure rule,
// and the only place a write waits on the network.
func (s *Store) Write(ctx context.Context, ino uint64, off int64, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("memtable: store is closed")
	}
	for len(p) > 0 {
		n := min(len(p), s.maxPayload())
		h := s.nextHandle
		rec := Record{Handle: h, Inode: ino, FileOff: off}
		pos, err := s.appendLocked(ctx, &rec, p[:n])
		if err != nil {
			return err
		}
		s.nextHandle++
		rec.Off = int(pos)
		rec.Length = n
		s.index[h] = rec
		s.order = append(s.order, h)
		s.live[h]++
		s.applyLocked(s.contentFor(ino).place(off, n, h))
		s.stats.WrittenBytes += int64(n)
		s.stats.Extents++
		off += int64(n)
		p = p[n:]
	}
	// Promotion by AGE, checked on the write that made something old
	// rather than on a timer: an extent more than PromotionDistance behind
	// the head has survived long enough that rewriting it is unlikely, so
	// it is packed and sent. Doing it here is what keeps the uplink busy
	// during a session instead of leaving the whole cost to the seal, and
	// it is what the runway between the distance and the ring's size buys
	// — packing starts while the writer still has room.
	if s.promotion > 0 && !s.packing && s.ring.Promotable(s.promotion) > 0 {
		s.startPackLocked(ctx, s.promotion)
	}
	return nil
}

// appendLocked puts one record in the ring, waiting for the packer when
// there is no room. This is the backpressure rule and the only place a
// write waits: the ring refusing an append IS the signal, and it is
// gradual rather than a cliff because the tail advances continuously
// instead of in whole-table steps.
func (s *Store) appendLocked(ctx context.Context, rec *Record, payload []byte) (uint64, error) {
	waited := false
	for {
		pos, err := s.ring.Append(rec, payload)
		if err == nil {
			return pos, nil
		}
		if !errors.Is(err, ErrRingFull) {
			// ErrRecordTooLarge and friends are not waitable. Returning
			// here rather than looping is what stops a writer spinning
			// forever on something no packer can fix.
			return 0, err
		}
		if s.flushErr != nil {
			return 0, s.flushErr
		}
		if !s.packing {
			// Nothing is draining the ring, so start a run that takes
			// everything: waiting on a packer that was never launched is
			// the deadlock this branch exists to prevent.
			s.startPackLocked(ctx, 0)
		}
		if !waited {
			// Counted before the wait, not after: a caller watching for
			// backpressure needs to see it while it is happening.
			waited = true
			s.stats.BlockedWrites++
		}
		s.cond.Wait()
		if s.closed {
			return 0, errors.New("memtable: store is closed")
		}
	}
}

// Truncate resizes ino, dropping content past the new size.
func (s *Store) Truncate(ino uint64, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := make(map[Handle]int)
	s.contentFor(ino).truncate(size, dropped)
	s.applyLocked(dropped)
}

// Size reports ino's current length.
func (s *Store) Size(ino uint64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.content[ino]; ok {
		return c.size
	}
	return 0
}

func (s *Store) contentFor(ino uint64) *content {
	c, ok := s.content[ino]
	if !ok {
		c = &content{}
		s.content[ino] = c
	}
	return c
}

// place inserts an extent and returns the reference-count deltas.
func (c *content) place(off int64, length int, h Handle) map[Handle]int {
	d := make(map[Handle]int)
	c.insert(off, length, h, d)
	return d
}

// applyLocked pushes reference-count deltas onto handles still in the
// ring. A handle already packed and reclaimed is not here; losing its
// last reference makes it garbage in a pack, which is a repack's problem
// and not this path's.
func (s *Store) applyLocked(d map[Handle]int) {
	for h, delta := range d {
		if _, ok := s.index[h]; !ok {
			continue
		}
		s.live[h] += delta
		if s.live[h] <= 0 {
			delete(s.live, h)
		}
	}
}

// cutLocked takes the records at the tail that are old enough to pack.
// distance is how far behind the head an extent must fall; zero takes
// everything, which is what a flush asks for.
//
// It is a decision, not a copy: the records stay exactly where they are
// in the ring until their locations are published, because until then the
// ring is the only place they exist.
func (s *Store) cutLocked(distance uint64) *batch {
	_, to := s.ring.PromotableRange(distance)
	if distance == 0 {
		to = s.ring.Head()
	}
	b := &batch{
		seq:    s.nextSeq,
		live:   make(map[Handle]int),
		inodes: make(map[uint64]struct{}),
		from:   s.ring.Tail(),
		to:     to,
	}
	s.nextSeq++
	for _, h := range s.order {
		rec, ok := s.index[h]
		if !ok {
			continue
		}
		end := uint64(rec.Off) + uint64(ringRecHdr) + uint64(rec.Length)
		if end > to {
			break // ring order: everything after this is younger still
		}
		b.recs = append(b.recs, rec)
		b.inodes[rec.Inode] = struct{}{}
		if n := s.live[h]; n > 0 {
			b.live[h] = n
		}
	}
	if len(b.recs) > 0 {
		last := b.recs[len(b.recs)-1]
		b.to = uint64(last.Off) + uint64(ringRecHdr) + uint64(last.Length)
	}
	return b
}

// releaseLocked retries a reclaim a pin held off, and wakes anyone
// waiting for the space. Reclaim clamps to the oldest pin rather than
// failing, so a pack that published while a read was in flight leaves the
// tail short of where its bytes actually died; this is the only thing
// that ever picks that up again.
func (s *Store) releaseLocked() {
	if s.ring == nil || s.reclaimTo <= s.ring.Tail() {
		return
	}
	if _, err := s.ring.Reclaim(s.reclaimTo); err != nil {
		s.stats.ReclaimErrors++
		return
	}
	s.cond.Broadcast()
}

// startPackLocked launches a pack run over whatever is old enough.
func (s *Store) startPackLocked(ctx context.Context, distance uint64) {
	if s.packing {
		return
	}
	b := s.cutLocked(distance)
	if b.empty() {
		return
	}
	s.packing = true
	s.stats.Flushes++
	s.wg.Go(func() { s.runFlush(ctx, b) })
}

// Flush packs everything in the ring and waits for it to land. This
// is what a checkpoint or a seal calls, and it is the only user-visible
// operation that blocks on the network by design.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed pack left its records in the ring and still authoritative.
	// Retrying is the recovery; discarding would lose them.
	s.flushErr = nil
	for {
		if err := s.waitPackLocked(); err != nil {
			return err
		}
		if s.ring == nil || s.ring.Used() == 0 {
			return nil
		}
		s.startPackLocked(ctx, 0)
		if !s.packing {
			// Nothing was eligible and nothing is running: the ring holds
			// only records no content row references any more.
			return nil
		}
	}
}

// waitPackLocked waits for any pack run in flight.
func (s *Store) waitPackLocked() error {
	for s.packing {
		if s.flushErr != nil {
			return s.flushErr
		}
		s.cond.Wait()
	}
	return s.flushErr
}

// Packs returns the packs this store has uploaded, for a superblock's
// pack list.
func (s *Store) Packs() []packstore.SealedPack {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]packstore.SealedPack(nil), s.packs...)
}

// Stats returns a snapshot of the counters.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Close waits for in-flight flushes and unmaps everything. It does NOT
// flush: a caller that wants its bytes in the federation calls Flush
// first, and one that is discarding a failed job should not pay for an
// upload on the way out.
//
// Callers must have quiesced their readers. Close unmaps regardless of
// pins, because the alternative is a lifecycle call that can block
// forever on a stuck read, and a mount that has finished serving has
// nobody left to protect.
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.ring != nil {
		err = s.ring.Close()
		s.ring = nil
	}
	return err
}

// source is where a range of bytes lives right now. It is produced under
// the store's lock and consumed outside it. A ring source holds a PIN on
// its position, because immutable bytes are still bytes the writer gets
// handed back the moment the tail passes them.
type source struct {
	ring   bool
	pos    uint64
	off    int
	length int
	slices []packSlice
}

// ringAt reads a record's payload out of the ring. The caller holds a pin
// on the position, so the region cannot be reclaimed underneath it.
func (s *Store) ringAt(pos uint64, length int) []byte {
	b, ok := s.ring.At(pos, length)
	if !ok {
		return make([]byte, length) // unreachable while pinned; never a wild read
	}
	return b
}

type packSlice struct {
	pack   string
	off    int64
	length int
}

type readPart struct {
	dst int
	src source
}

// Read fills p from ino at off. Resolution happens under the lock and the
// bytes are read outside it.
func (s *Store) Read(ctx context.Context, ino uint64, off int64, p []byte) (int, error) {
	parts, n, err := s.plan(ino, off, len(p))
	if err != nil {
		return 0, err
	}
	defer func() {
		s.mu.Lock()
		for _, part := range parts {
			if part.src.ring {
				s.ring.Unpin(part.src.pos)
			}
		}
		// Dropping the last pin on a region a pack already published is
		// what finally frees it, and a writer may be blocked on exactly
		// those bytes.
		s.releaseLocked()
		s.mu.Unlock()
	}()
	clear(p[:n]) // holes and gaps read as zeros
	for _, part := range parts {
		dst := p[part.dst : part.dst+part.src.len()]
		if part.src.ring {
			b, ok := s.ring.At(part.src.pos, part.src.off+part.src.length)
			if !ok {
				return 0, fmt.Errorf("memtable: pinned extent at %d vanished", part.src.pos)
			}
			copy(dst, b[part.src.off:part.src.off+part.src.length])
			continue
		}
		at := 0
		for _, sl := range part.src.slices {
			if err := s.readPack(ctx, sl, dst[at:at+sl.length]); err != nil {
				return 0, err
			}
			at += sl.length
		}
	}
	return n, nil
}

func (src source) len() int {
	if src.ring {
		return src.length
	}
	n := 0
	for _, sl := range src.slices {
		n += sl.length
	}
	return n
}

// readPack reads one slice of one pack, from the local copy when there is
// one. A miss fetches the pack WHOLE and keeps it, which is the format's
// own read policy and also what makes a later seal of the same file free:
// reading a file to edit it pulls in the chunks the edit will straddle.
func (s *Store) readPack(ctx context.Context, sl packSlice, dst []byte) error {
	if s.cache != nil {
		f, ok := s.cache.open(sl.pack)
		if !ok {
			var err error
			if f, err = s.cache.fetch(ctx, s.obj, sl.pack); err != nil {
				return err
			}
			s.countPackRead(false)
		} else {
			s.countPackRead(true)
		}
		defer f.Close() //nolint:errcheck
		_, err := f.ReadAt(dst, sl.off)
		return err
	}
	s.countPackRead(false)
	rc, err := s.obj.Get(ctx, packstore.PackDirKey+"/"+sl.pack, sl.off, int64(sl.length))
	if err != nil {
		return err
	}
	defer rc.Close() //nolint:errcheck
	_, err = io.ReadFull(rc, dst)
	return err
}

func (s *Store) countPackRead(local bool) {
	s.mu.Lock()
	if local {
		s.stats.PackReadsLocal++
	} else {
		s.stats.PackReadsRemote++
	}
	s.mu.Unlock()
}

// plan resolves a read to sources under the lock. The ordering — active
// table, flushing table, location map — is what makes a flush completing
// mid-read invisible: whichever level answered, its bytes are already
// final.
func (s *Store) plan(ino uint64, off int64, n int) ([]readPart, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.content[ino]
	if !ok {
		return nil, 0, nil
	}
	if off >= c.size {
		return nil, 0, nil
	}
	if int64(n) > c.size-off {
		n = int(c.size - off)
	}
	var parts []readPart
	for _, r := range c.overlapping(off, int64(n)) {
		lo := max(r.FileOff, off)
		hi := min(r.end(), off+int64(n))
		if hi <= lo {
			continue
		}
		src, err := s.resolveLocked(r.Handle, r.Skip+int(lo-r.FileOff), int(hi-lo))
		if err != nil {
			for _, p := range parts {
				if p.src.ring {
					s.ring.Unpin(p.src.pos)
				}
			}
			return nil, 0, err
		}
		parts = append(parts, readPart{dst: int(lo - off), src: src})
	}
	return parts, n, nil
}

// resolveLocked turns a handle plus an intra-extent range into a source.
func (s *Store) resolveLocked(h Handle, skip, length int) (source, error) {
	if rec, ok := s.index[h]; ok {
		// Pinning here is what makes reading outside the lock safe: the
		// packer may reclaim while this read is in flight, and the ring
		// refuses to let the tail pass a pinned position.
		s.ring.Pin(uint64(rec.Off))
		return source{ring: true, pos: uint64(rec.Off), off: skip, length: length}, nil
	}
	slices, ok := s.handleLoc[h]
	if !ok {
		return source{}, fmt.Errorf("memtable: extent %d is gone: it was neither in a memtable nor published", h)
	}
	var out []packSlice
	pos := 0
	want := skip
	remaining := length
	for _, cs := range slices {
		if remaining == 0 {
			break
		}
		if pos+cs.Length <= want {
			pos += cs.Length
			continue
		}
		delta := max(want-pos, 0)
		take := min(cs.Length-delta, remaining)
		loc, ok := s.chunkLoc[cs.ID.Hex()]
		if !ok {
			return source{}, fmt.Errorf("memtable: chunk %s has no location", cs.ID)
		}
		out = append(out, packSlice{
			pack:   loc.Pack,
			off:    loc.Off + int64(cs.ChunkOff+delta),
			length: take,
		})
		want += take
		remaining -= take
		pos += cs.Length
	}
	if remaining != 0 {
		return source{}, fmt.Errorf("memtable: extent %d resolves %d bytes short", h, remaining)
	}
	return source{slices: out}, nil
}
