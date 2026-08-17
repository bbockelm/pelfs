package memtable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
	// TableSize is one memtable's capacity in bytes, headers included.
	TableSize int
	// Obj is the federation. Flushes upload packs to packs/<name>.
	Obj pelicanobj.Store
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
	// BlockedWrites counts writes that had to wait for a flush to finish
	// — the backpressure rule firing.
	BlockedWrites int64
	// AbandonedFlushes counts flushes that gave up the rest of their CDC
	// pass under that pressure; RawChunks counts the chunks they emitted
	// without a boundary search.
	AbandonedFlushes int64
	RawChunks        int64
	// LostHandles counts extents a recovery could not find. Nonzero means
	// data loss and the caller must say so out loud.
	LostHandles int64
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

	mu   sync.Mutex
	cond *sync.Cond

	active   *table
	flushing *table
	flushErr error

	// recovered holds tables a crash left behind. They are already frozen,
	// so the set only shrinks: Flush drains them one at a time before the
	// active table rotates, and reads consult them last.
	recovered []*table

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
	s := &Store{
		dir:       opts.Dir,
		tableSize: opts.TableSize,
		obj:       opts.Obj,
		chunkOpts: opts.Chunk,
		hasher:    opts.Hasher,
		hooks:     opts.Hooks,
		content:   make(map[uint64]*content),
		handleLoc: make(map[Handle][]ChunkSlice),
		chunkLoc:  make(map[string]PackLoc),
	}
	s.cond = sync.NewCond(&s.mu)
	return s, nil
}

func (s *Store) openActive() error {
	t, err := newTable(s.dir, s.nextSeq, s.tableSize)
	if err != nil {
		return err
	}
	s.nextSeq++
	s.active = t
	return nil
}

// maxPayload is the largest extent a table can hold. A write larger than
// this is split across extents rather than refused: the memtable size is
// a resource decision and must not become a limit on write(2).
func (s *Store) maxPayload() int { return s.tableSize - recordHeader }

// Write appends p at off in ino. It blocks only if the active table is
// full and the previous flush has not finished — the design's
// backpressure rule, and the only place a write waits on the network.
func (s *Store) Write(ctx context.Context, ino uint64, off int64, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("memtable: store is closed")
	}
	for len(p) > 0 {
		n := min(len(p), s.maxPayload())
		if !s.active.buf.Room(n) {
			if err := s.rotateLocked(ctx); err != nil {
				return err
			}
		}
		h := s.nextHandle
		s.nextHandle++
		rec := Record{Handle: h, Inode: ino, FileOff: off}
		if err := s.active.append(&rec, p[:n]); err != nil {
			return err
		}
		s.applyLocked(s.contentFor(ino).place(off, n, h))
		s.active.acquire(h)
		s.stats.WrittenBytes += int64(n)
		s.stats.Extents++
		off += int64(n)
		p = p[n:]
	}
	return nil
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

// applyLocked pushes reference-count deltas onto the tables that own the
// handles. A handle below the oldest live table has already been
// published; losing its last reference makes it garbage in a pack, which
// is a repack's problem and not this path's.
func (s *Store) applyLocked(d map[Handle]int) {
	for h, delta := range d {
		t := s.tableForLocked(h)
		if t == nil {
			continue
		}
		for ; delta > 0; delta-- {
			t.acquire(h)
		}
		for ; delta < 0; delta++ {
			t.release(h)
		}
	}
}

// levelsLocked lists the memory levels in resolution order: the active
// table, then the flushing one, then anything a recovery left behind. A
// handle found at an earlier level is the same bytes as at a later one —
// there is no shadowing here, only a search — so the order is about cost,
// not correctness.
func (s *Store) levelsLocked() []*table {
	out := make([]*table, 0, 2+len(s.recovered))
	if s.active != nil {
		out = append(out, s.active)
	}
	if s.flushing != nil {
		out = append(out, s.flushing)
	}
	return append(out, s.recovered...)
}

// tableForLocked finds the table holding a handle.
func (s *Store) tableForLocked(h Handle) *table {
	for _, t := range s.levelsLocked() {
		if _, ok := t.index[h]; ok {
			return t
		}
	}
	return nil
}

// rotateLocked freezes the active table and starts its flush. It waits if
// a flush is already in flight: the bound is two tables, and a session
// that outruns the federation must slow down rather than accumulate
// unbounded local state.
func (s *Store) rotateLocked(ctx context.Context) error {
	waited := false
	for s.flushing != nil {
		if s.flushErr != nil {
			return s.flushErr
		}
		// The in-flight flush's remaining CDC is optional work standing
		// between this writer and a free table. Tell it to stop before
		// settling in to wait, not after.
		s.flushing.abandon.Store(true)
		if !waited {
			// Counted before the wait, not after: a caller watching for
			// backpressure needs to see it while it is happening.
			waited = true
			s.stats.BlockedWrites++
		}
		s.cond.Wait()
	}
	if s.active.buf.Used() == 0 {
		return nil
	}
	frozen := s.active
	s.active = nil
	if err := s.openActive(); err != nil {
		s.active = frozen
		return err
	}
	s.flushing = frozen
	s.stats.Flushes++
	s.startFlushLocked(ctx, frozen)
	return nil
}

func (s *Store) startFlushLocked(ctx context.Context, t *table) {
	s.wg.Go(func() { s.runFlush(ctx, t) })
}

// Flush freezes the active table and waits for every flush to land. This
// is what a checkpoint or a seal calls, and it is the only user-visible
// operation that blocks on the network by design.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A previous flush that failed left its table in place and still
	// authoritative. Retrying it is the recovery, not discarding it.
	if s.flushing != nil && s.flushErr != nil {
		s.flushErr = nil
		s.flushing.abandon.Store(false)
		s.startFlushLocked(ctx, s.flushing)
	}
	// Tables a crash left behind go first: they are older than anything
	// the active table holds, and leaving them behind a fresh flush would
	// keep their buffer files pinned for no reason.
	for len(s.recovered) > 0 {
		if err := s.waitFlushLocked(); err != nil {
			return err
		}
		t := s.recovered[0]
		s.recovered = s.recovered[1:]
		s.flushing = t
		s.stats.Flushes++
		s.startFlushLocked(ctx, t)
	}
	if s.active != nil && s.active.buf.Used() > 0 {
		if err := s.rotateLocked(ctx); err != nil {
			return err
		}
	}
	return s.waitFlushLocked()
}

func (s *Store) waitFlushLocked() error {
	for s.flushing != nil && s.flushErr == nil {
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
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	for _, t := range s.levelsLocked() {
		if cerr := t.buf.Close(); err == nil {
			err = cerr
		}
	}
	s.active, s.flushing, s.recovered = nil, nil, nil
	return err
}

// source is where a range of bytes lives right now. It is produced under
// the store's lock and consumed outside it. A memtable source holds a pin
// on its table, because immutable bytes are still bytes that get unmapped
// when the table is recycled.
type source struct {
	tab    *table
	off    int
	length int
	slices []packSlice
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
		for _, part := range parts {
			if part.src.tab != nil {
				part.src.tab.unpin()
			}
		}
	}()
	clear(p[:n]) // holes and gaps read as zeros
	for _, part := range parts {
		dst := p[part.dst : part.dst+part.src.len()]
		if part.src.tab != nil {
			copy(dst, part.src.tab.buf.At(part.src.off, part.src.length))
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
	if src.tab != nil {
		return src.length
	}
	n := 0
	for _, sl := range src.slices {
		n += sl.length
	}
	return n
}

func (s *Store) readPack(ctx context.Context, sl packSlice, dst []byte) error {
	rc, err := s.obj.Get(ctx, packstore.PackDirKey+"/"+sl.pack, sl.off, int64(sl.length))
	if err != nil {
		return err
	}
	defer rc.Close() //nolint:errcheck
	_, err = io.ReadFull(rc, dst)
	return err
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
				if p.src.tab != nil {
					p.src.tab.unpin()
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
	for _, t := range s.levelsLocked() {
		if rec, ok := t.index[h]; ok {
			t.pin()
			return source{tab: t, off: rec.Off + skip, length: length}, nil
		}
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
