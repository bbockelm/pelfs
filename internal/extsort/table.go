package extsort

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/bbockelm/pelfs/internal/mmapfile"
)

// Table is a sorted result materialized once and searched many times.
//
// It is what a caller wants when the answer is needed INLINE — fsck
// resolves each chunkref as it walks past it, so that the problem it
// reports carries the path the reference came from, and a merge join
// would have to defer every finding to a second pass and reunite it with
// its path afterwards.
//
// The records are mapped rather than read, so what is resident is page
// cache the kernel can reclaim rather than heap it cannot. A lookup is a
// binary search: log2(100M) is 27 probes, each landing in a page that is
// almost certainly already warm from the probes before it, since a binary
// search revisits the same upper levels every time.
type Table struct {
	recLen int
	keyLen int

	// mapped is the whole file, or nil when the records never left memory.
	mapped *mmapfile.Mapping
	// mem is the sorter's buffer, borrowed when nothing spilled.
	mem  []byte
	path string
	n    int
}

// Table merges the runs into one file, maps it, and returns it for
// searching. The sorter is closed: its runs are consumed into the table
// and there is nothing further to add.
//
// A sorter that never spilled keeps its records where they are. Writing a
// few hundred records to a file only to map them back would be the wrong
// default, and most callers — a small volume, a test — never spill.
func (s *Sorter) Table() (*Table, error) {
	m, err := s.Sorted()
	if err != nil {
		return nil, err
	}
	defer m.Close() //nolint:errcheck

	t := &Table{recLen: s.recLen, keyLen: s.keyLen}
	if m.mem != nil {
		t.mem = m.mem
		t.n = len(m.mem) / s.recLen
		return t, nil
	}

	t.path = filepath.Join(s.dir, s.name+".table")
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	w := newFlushWriter(f)
	for {
		rec, ok := m.Next()
		if !ok {
			break
		}
		if _, err := w.Write(rec); err != nil {
			os.Remove(t.path) //nolint:errcheck
			return nil, err
		}
		t.n++
	}
	if err := m.Err(); err != nil {
		os.Remove(t.path) //nolint:errcheck
		return nil, err
	}
	if err := w.Flush(); err != nil {
		os.Remove(t.path) //nolint:errcheck
		return nil, err
	}
	// The runs are consumed; drop them before mapping, so peak disk is the
	// runs OR the table rather than both for the life of the caller.
	if err := s.Close(); err != nil {
		os.Remove(t.path) //nolint:errcheck
		return nil, err
	}
	if t.n == 0 {
		// Mapping refuses a zero length on every platform — mmap by rule,
		// Windows because a zero-length file has no section — and an empty
		// table needs no map anyway.
		return t, nil
	}
	// WHAT THIS SITE RELIES ON, since Windows mappings are stricter than
	// mmap in three ways (internal/mmapfile):
	//
	//   - The file is COMPLETE before it is mapped. Every record has been
	//     written and the buffer flushed, so the file's size is exactly
	//     t.n*t.recLen and it never changes again. Nothing here resizes a
	//     mapped file, which Windows cannot do at all.
	//   - The mapping OUTLIVES the *os.File. f is closed by the defer
	//     above the moment Table returns, and the mapping stays valid:
	//     Windows keeps the file alive through the section object, as Unix
	//     does through the fd the kernel holds.
	//   - The file is REMOVED while nothing maps it. Close unmaps first
	//     and removes second (see there), because on Windows a live
	//     mapping pins the file and the remove would fail.
	mm, err := mmapfile.Map(f, t.n*t.recLen, mmapfile.ReadOnly)
	if err != nil {
		os.Remove(t.path) //nolint:errcheck
		return nil, fmt.Errorf("extsort: %w", err)
	}
	t.mapped = mm
	return t, nil
}

// Len is how many records the table holds, duplicates included.
func (t *Table) Len() int { return t.n }

// At returns the i'th record in key order. The slice aliases the table
// and stays valid until Close.
func (t *Table) At(i int) []byte {
	b := t.mapped.Bytes()
	if b == nil {
		b = t.mem
	}
	return b[i*t.recLen : (i+1)*t.recLen]
}

// Lookup returns the FIRST record whose key matches, and how many records
// share that key. Duplicates are kept — the same identity placed in two
// packs is two records — so a caller that cares about all of them walks
// At(i) through At(i+n).
func (t *Table) Lookup(key []byte) (rec []byte, i, n int) {
	i = sort.Search(t.n, func(j int) bool {
		return bytes.Compare(t.At(j)[:t.keyLen], key) >= 0
	})
	if i == t.n || !bytes.Equal(t.At(i)[:t.keyLen], key) {
		return nil, 0, 0
	}
	for j := i; j < t.n && bytes.Equal(t.At(j)[:t.keyLen], key); j++ {
		n++
	}
	return t.At(i), i, n
}

// Close unmaps and removes the table, IN THAT ORDER: on Windows a live
// mapping pins its backing file, so removing first would fail with a
// sharing violation and leave the table behind.
func (t *Table) Close() error {
	var first error
	if t.mapped != nil {
		if err := t.mapped.Close(); err != nil {
			first = err
		}
		t.mapped = nil
	}
	t.mem = nil
	if t.path != "" {
		if err := os.Remove(t.path); err != nil && first == nil {
			first = err
		}
		t.path = ""
	}
	t.n = 0
	return first
}

// flushWriter is a small buffered writer. bufio would do, but the table
// is written once in one pass and this keeps the dependency surface of a
// mapped file down to what it actually needs.
type flushWriter struct {
	w   io.Writer
	buf []byte
}

func newFlushWriter(w io.Writer) *flushWriter {
	return &flushWriter{w: w, buf: make([]byte, 0, runReadBytes)}
}

func (f *flushWriter) Write(p []byte) (int, error) {
	if len(f.buf)+len(p) > cap(f.buf) {
		if err := f.Flush(); err != nil {
			return 0, err
		}
	}
	if len(p) > cap(f.buf) {
		return f.w.Write(p)
	}
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *flushWriter) Flush() error {
	if len(f.buf) == 0 {
		return nil
	}
	if _, err := f.w.Write(f.buf); err != nil {
		return err
	}
	f.buf = f.buf[:0]
	return nil
}
