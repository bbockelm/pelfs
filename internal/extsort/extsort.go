// Package extsort sorts more fixed-width records than fit in memory, and
// hands them back as a stream or as a searchable table.
//
// Maintenance keeps asking questions about a hundred million objects, and
// keeps reaching for a map to answer them. internal/reach needs to know
// which identities something still references and where each one sits —
// two sets keyed by identity, which is a MERGE and not a lookup.
// internal/fsck needs to resolve every chunkref it walks past against
// every entry the packs hold — which IS a lookup, but not one whose table
// has to be resident. Both were bounded by the same wall: an identity map
// at that scale is tens of gigabytes before anything is computed.
//
// Records are FIXED WIDTH and the key is their prefix. That is the whole
// trick: a run sorts by swapping bytes in place with no per-record
// allocation and no pointers to chase, which is what makes sorting a
// hundred million of them a few seconds of CPU rather than a
// garbage-collector problem.
//
// A Sorter accumulates into a buffer, sorts and spills a run when the
// buffer fills, and offers two ways to read the result back:
//
//   - Sorted, a k-way merge — one pass, for a caller doing a merge join.
//   - Table, the merge materialized into one file and MAPPED, so lookups
//     are a binary search over pages rather than over a heap. Locally
//     mapped, sort.Search over fixed-width records beats a sampled index
//     (internal/packidx) precisely because there are no range requests to
//     bound: packidx exists to make a REMOTE reader ask for a small
//     window, and that cost does not apply here.
//
// Memory is the buffer plus one read buffer per run, either way.
package extsort

import (
	"bufio"
	"bytes"
	"container/heap"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// DefaultBytes is how much a sorter buffers before spilling a run.
//
// The memory a sort costs is the buffer plus one read buffer per run, and
// runs are bytes/budget — so total is budget + runReadBytes*bytes/budget,
// minimised at sqrt(bytes*runReadBytes). A hundred-million-object volume
// spills about 4.5 GB of placements, which puts the optimum near 34 MiB
// and the cost curve flat around it; 64 MiB sits on that flat, at about
// seventy runs and under 90 MiB held, and leaves headroom for a volume
// several times larger before the fanout is worth thinking about again.
const DefaultBytes = 64 << 20

// runReadBytes is the read buffer given to each run in the final merge.
// The merge is sequential per run, so this is about amortizing syscalls,
// not about hit rates.
const runReadBytes = 256 << 10

// sorter accumulates fixed-width records and streams them back in key
// order. Safe for concurrent Add.
type Sorter struct {
	dir    string
	name   string
	recLen int
	keyLen int
	budget int

	mu   sync.Mutex
	buf  []byte
	runs []string
	seq  int
	// count is every record accepted, duplicates included.
	count int64
	// done guards against adding after the merge has started, which would
	// silently drop records into a buffer nobody will read again.
	done bool
}

// New starts a sorter over recLen-byte records keyed by their first
// keyLen bytes, spilling runs into dir under names beginning with name. A
// zero budget takes DefaultBytes.
func New(dir, name string, keyLen, recLen, budget int) *Sorter {
	if budget <= 0 {
		budget = DefaultBytes
	}
	// Round the budget down to whole records so a flush never splits one.
	if budget < recLen {
		budget = recLen
	}
	budget -= budget % recLen
	return &Sorter{
		dir: dir, name: name,
		keyLen: keyLen, recLen: recLen, budget: budget,
		buf: make([]byte, 0, budget),
	}
}

// Add appends one batch of already-concatenated records. Callers
// accumulate a whole trailer's or a whole catalog's worth locally and hand
// them over once, so the lock is taken per object rather than per
// identity.
func (s *Sorter) Add(recs []byte) error {
	if len(recs) == 0 {
		return nil
	}
	if len(recs)%s.recLen != 0 {
		return fmt.Errorf("extsort: %s batch is %d bytes, not a multiple of the %d-byte record",
			s.name, len(recs), s.recLen)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return fmt.Errorf("extsort: %s was added to after its merge began", s.name)
	}
	s.count += int64(len(recs) / s.recLen)
	// A batch larger than the whole budget is spilled in budget-sized
	// pieces rather than growing the buffer to hold it: the buffer's size
	// is the memory bound this whole structure exists to enforce.
	for len(recs) > 0 {
		room := s.budget - len(s.buf)
		n := min(room, len(recs))
		s.buf = append(s.buf, recs[:n]...)
		recs = recs[n:]
		if len(s.buf) >= s.budget {
			if err := s.flushLocked(); err != nil {
				return err
			}
		}
	}
	return nil
}

// flushLocked sorts the buffer and writes it out as one run.
func (s *Sorter) flushLocked() error {
	if len(s.buf) == 0 {
		return nil
	}
	s.sortBuf()
	fp := filepath.Join(s.dir, fmt.Sprintf("%s-%03d.run", s.name, s.seq))
	s.seq++
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(s.buf)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	s.runs = append(s.runs, fp)
	s.buf = s.buf[:0]
	return nil
}

func (s *Sorter) sortBuf() {
	sort.Sort(&recSlice{b: s.buf, recLen: s.recLen, keyLen: s.keyLen, tmp: make([]byte, s.recLen)})
}

// Count is every record accepted, duplicates included.
func (s *Sorter) Count() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Sorted closes the sorter and returns a cursor over every record in key
// order. A sorter whose records never filled the buffer is served from
// memory: most sweeps are small, and writing a run to spool a few hundred
// records back would be the wrong default.
func (s *Sorter) Sorted() (*Merged, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if len(s.runs) == 0 {
		s.sortBuf()
		return &Merged{recLen: s.recLen, mem: s.buf}, nil
	}
	if err := s.flushLocked(); err != nil {
		return nil, err
	}
	m := &Merged{recLen: s.recLen, keyLen: s.keyLen}
	m.heap.keyLen = s.keyLen
	for _, fp := range s.runs {
		f, err := os.Open(fp)
		if err != nil {
			m.Close() //nolint:errcheck
			return nil, err
		}
		c := &cursor{f: f, r: bufio.NewReaderSize(f, runReadBytes), rec: make([]byte, s.recLen)}
		if err := c.next(); err != nil {
			m.Close() //nolint:errcheck
			return nil, err
		}
		if c.live {
			m.heap.c = append(m.heap.c, c)
		} else {
			c.Close() //nolint:errcheck
		}
	}
	heap.Init(&m.heap)
	return m, nil
}

// Close drops the runs. The sweep removes its whole spill directory too;
// this is what keeps a long sweep's disk use bounded by the sorter that is
// still in use rather than by every sorter it has ever opened.
func (s *Sorter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.buf = nil
	var first error
	for _, fp := range s.runs {
		if err := os.Remove(fp); err != nil && first == nil {
			first = err
		}
	}
	s.runs = nil
	return first
}

// recSlice sorts fixed-width records in place by their key prefix.
type recSlice struct {
	b      []byte
	recLen int
	keyLen int
	tmp    []byte
}

func (r *recSlice) Len() int        { return len(r.b) / r.recLen }
func (r *recSlice) at(i int) []byte { return r.b[i*r.recLen : (i+1)*r.recLen] }
func (r *recSlice) Less(i, j int) bool {
	return bytes.Compare(r.at(i)[:r.keyLen], r.at(j)[:r.keyLen]) < 0
}
func (r *recSlice) Swap(i, j int) {
	a, b := r.at(i), r.at(j)
	copy(r.tmp, a)
	copy(a, b)
	copy(b, r.tmp)
}

// cursor is one run being read back.
type cursor struct {
	f    *os.File
	r    *bufio.Reader
	rec  []byte
	live bool
}

func (c *cursor) next() error {
	if _, err := io.ReadFull(c.r, c.rec); err != nil {
		if err == io.EOF {
			c.live = false
			return nil
		}
		return err
	}
	c.live = true
	return nil
}

func (c *cursor) Close() error { return c.f.Close() }

// cursorHeap orders runs by their current record's key.
type cursorHeap struct {
	c      []*cursor
	keyLen int
}

func (h cursorHeap) Len() int { return len(h.c) }
func (h cursorHeap) Less(i, j int) bool {
	return bytes.Compare(h.c[i].rec[:h.keyLen], h.c[j].rec[:h.keyLen]) < 0
}
func (h cursorHeap) Swap(i, j int) { h.c[i], h.c[j] = h.c[j], h.c[i] }
func (h *cursorHeap) Push(x any)   { h.c = append(h.c, x.(*cursor)) }
func (h *cursorHeap) Pop() any     { old := h.c; n := len(old); x := old[n-1]; h.c = old[:n-1]; return x }

// merged streams records in key order, from memory when the sorter never
// spilled and from a k-way merge over its runs when it did.
type Merged struct {
	recLen int
	keyLen int

	mem []byte // set when nothing spilled
	at  int

	heap cursorHeap
	cur  []byte
	err  error
}

// Next returns the next record in key order. The slice is valid until the
// following call. A merge that hits a read error stops early and reports
// it from Err, which the sweep turns into a failure — an incomplete sweep
// rather than a short one, because a truncated join would under-count
// liveness and that is the direction that deletes data.
func (m *Merged) Next() ([]byte, bool) {
	if m.err != nil {
		return nil, false
	}
	if m.mem != nil {
		if m.at+m.recLen > len(m.mem) {
			return nil, false
		}
		rec := m.mem[m.at : m.at+m.recLen]
		m.at += m.recLen
		return rec, true
	}
	if m.heap.Len() == 0 {
		return nil, false
	}
	top := m.heap.c[0]
	if m.cur == nil {
		m.cur = make([]byte, m.recLen)
	}
	copy(m.cur, top.rec)
	if err := top.next(); err != nil {
		m.err = err
		return nil, false
	}
	if top.live {
		heap.Fix(&m.heap, 0)
	} else {
		heap.Pop(&m.heap)
		top.Close() //nolint:errcheck
	}
	return m.cur, true
}

// Err is the read error that ended the merge early, if any.
func (m *Merged) Err() error { return m.err }

func (m *Merged) Close() error {
	var first error
	for _, c := range m.heap.c {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	m.heap.c = nil
	return first
}

// heap.Interface is implemented on *cursorHeap; the merge holds one by
// value inside itself and takes its address at every call site.
var _ heap.Interface = (*cursorHeap)(nil)
