package memtable

import (
	"path/filepath"
	"sync"
)

// table is one level of the tree: a buffer file plus the in-memory index
// that names what is in it. Only the active table accepts appends; a
// frozen table is read-only for the rest of its life, which is what makes
// it safe to hand its bytes to a reader outside the store's lock.
type table struct {
	seq   uint64
	buf   *Buffer
	index map[Handle]Record

	// live counts content references to each handle. A handle whose count
	// reaches zero before the flusher walks it is an extent that died in
	// memory and is never uploaded — the design's central claim. The count
	// is not a boolean because one write can split an earlier extent in
	// two, leaving two content refs naming the same handle.
	live map[Handle]int

	// inodes is the set of inodes with at least one extent here, so a
	// flush can find the content it must consult without walking every
	// inode in the session.
	inodes map[uint64]struct{}

	// pins guards the mapping against a reader that resolved a source
	// under the store's lock and is still reading it. Immutability of the
	// bytes is not enough: the buffer is unmapped when the table is
	// recycled, and unmapping under a reader is a segfault, not a stale
	// read.
	mu      sync.Mutex
	pins    int
	retired bool
}

func newTable(dir string, seq uint64, size int) (*table, error) {
	buf, err := CreateBuffer(filepath.Join(dir, bufferName(seq)), size, seq)
	if err != nil {
		return nil, err
	}
	return &table{
		seq:    seq,
		buf:    buf,
		index:  make(map[Handle]Record),
		live:   make(map[Handle]int),
		inodes: make(map[uint64]struct{}),
	}, nil
}

// append records one extent. The caller holds the store's lock.
func (t *table) append(rec *Record, payload []byte) error {
	if err := t.buf.Append(rec, payload); err != nil {
		return err
	}
	t.index[rec.Handle] = *rec
	t.inodes[rec.Inode] = struct{}{}
	return nil
}

func (t *table) acquire(h Handle) { t.live[h]++ }

func (t *table) release(h Handle) {
	if n := t.live[h]; n <= 1 {
		delete(t.live, h)
	} else {
		t.live[h] = n - 1
	}
}

// pin marks the table in use by a reader outside the store's lock.
func (t *table) pin() {
	t.mu.Lock()
	t.pins++
	t.mu.Unlock()
}

func (t *table) unpin() {
	t.mu.Lock()
	t.pins--
	free := t.retired && t.pins == 0
	t.mu.Unlock()
	if free {
		_ = t.buf.Remove()
	}
}

// retire reclaims the table's space once no reader holds it. Called only
// after the table's contents are resolvable somewhere else.
func (t *table) retire() {
	t.mu.Lock()
	t.retired = true
	free := t.pins == 0
	t.mu.Unlock()
	if free {
		_ = t.buf.Remove()
	}
}
