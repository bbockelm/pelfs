// Package packidx is the sorted lookup table the format uses to answer
// "where does this identity live" — inside a pack's trailer, and across
// packs in a multi-pack index.
//
// Three decisions shape it, and each was a correction of the last:
//
// RECORDS ARE INTERLEAVED, key beside value. Separate key and value
// arrays are right for a mapped local file, which is what git's .idx is;
// they are wrong for a table read by RANGE REQUEST, where one lookup then
// needs two distant reads instead of one contiguous one. This table is
// meant to be read remotely at sizes where fetching it whole is out of
// the question.
//
// THERE IS NO FANOUT. A fanout on the first byte assumes the key
// distribution, which for a cryptographic hash is safe but unnecessary:
// position is already predictable from the key itself. What a remote
// reader actually needs is not a better guess but a BOUND on the extent
// to ask for, so the table carries a sample every stride entries. A
// lookup reads the samples once, learns a window of exactly stride
// records, and fetches that. The cost is N/stride keys rather than a
// fixed 256 or 65,536 buckets, and it holds regardless of distribution.
//
// KEYS MAY BE TRUNCATED. A multi-pack index stores 12 bytes of identity,
// not 32, because a short key can only ever produce a FALSE POSITIVE:
// the caller checks what it finds against the full identity it already
// has. At 96 bits and 100 million entries a collision is a ~10^-13
// event, and the caller's answer to one is to look in both places. The
// table therefore takes key length as a parameter and never assumes it
// is complete.
package packidx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	magic = "PELFSIX2"
	// headerLen is fixed and 8-byte aligned so records land aligned: this
	// is meant to be mapped as well as ranged.
	headerLen = 32
	// KeySize is a full identity, which a pack's own trailer uses.
	KeySize = 32
	// DefaultStride is how many records one sample covers. 4096 records is
	// a 64 KiB window at a 16-byte entry — one range read, and small
	// enough that reading a window to find one key is not wasteful. The
	// samples themselves cost N/4096 keys: 293 KB for 100 million.
	DefaultStride = 4096
)

// ErrFormat reports bytes that are not a table this build understands.
var ErrFormat = fmt.Errorf("packidx: unrecognized table")

// Builder accumulates entries and encodes them sorted.
type Builder struct {
	keyLen    int
	recordLen int
	stride    int
	entries   [][]byte // each keyLen+recordLen bytes
}

// NewBuilder starts a table over keyLen-byte keys and recordLen-byte
// values. A zero stride takes DefaultStride.
func NewBuilder(keyLen, recordLen, stride int) *Builder {
	if stride <= 0 {
		stride = DefaultStride
	}
	return &Builder{keyLen: keyLen, recordLen: recordLen, stride: stride}
}

// Add records one entry. Later duplicates of a key REPLACE earlier ones,
// which is safe because an identity names content.
func (b *Builder) Add(key, value []byte) error {
	if len(key) != b.keyLen {
		return fmt.Errorf("packidx: key is %d bytes, want %d", len(key), b.keyLen)
	}
	if len(value) != b.recordLen {
		return fmt.Errorf("packidx: value is %d bytes, want %d", len(value), b.recordLen)
	}
	rec := make([]byte, 0, b.keyLen+b.recordLen)
	rec = append(rec, key...)
	rec = append(rec, value...)
	b.entries = append(b.entries, rec)
	return nil
}

// Len is how many entries have been added, duplicates included.
func (b *Builder) Len() int { return len(b.entries) }

// Encode sorts and writes the table.
func (b *Builder) Encode() []byte {
	sort.SliceStable(b.entries, func(i, j int) bool {
		return bytes.Compare(b.entries[i][:b.keyLen], b.entries[j][:b.keyLen]) < 0
	})
	// Keep the last of each run of equal keys.
	kept := b.entries[:0]
	for i, e := range b.entries {
		if i+1 < len(b.entries) && bytes.Equal(b.entries[i+1][:b.keyLen], e[:b.keyLen]) {
			continue
		}
		kept = append(kept, e)
	}
	return encodeRecords(b.keyLen, b.recordLen, b.stride, len(kept), func(i int) []byte { return kept[i] })
}

// putHeader writes the fixed header into the front of out, which must be
// at least headerLen bytes. It is shared with the streaming merge, whose
// only difference is that it learns count last rather than first.
func putHeader(out []byte, keyLen, recordLen, stride, count, samples int) {
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint16(out[8:], uint16(keyLen))
	binary.LittleEndian.PutUint16(out[10:], uint16(recordLen))
	binary.LittleEndian.PutUint32(out[12:], uint32(count))
	binary.LittleEndian.PutUint32(out[16:], uint32(stride))
	binary.LittleEndian.PutUint32(out[20:], uint32(samples))
}

// sampleCount is how many samples a table of count records carries.
func sampleCount(count, stride int) int {
	if count <= 0 {
		return 0
	}
	return (count + stride - 1) / stride
}

// encodeRecords writes a table from records already in sorted order, for
// a caller that holds them all. A caller that does not holds a
// StreamWriter instead.
func encodeRecords(keyLen, recordLen, stride, count int, at func(int) []byte) []byte {
	entryLen := keyLen + recordLen
	samples := sampleCount(count, stride)
	out := make([]byte, headerLen+samples*keyLen+count*entryLen)
	putHeader(out, keyLen, recordLen, stride, count, samples)

	sampleAt := out[headerLen:]
	records := out[headerLen+samples*keyLen:]
	for i := 0; i < count; i++ {
		rec := at(i)
		copy(records[i*entryLen:], rec)
		if i%stride == 0 {
			copy(sampleAt[(i/stride)*keyLen:], rec[:keyLen])
		}
	}
	return out
}

// Header is a table's shape and its samples, which is everything needed
// to compute WHICH BYTES a lookup will need — without the records.
//
// It exists for the remote case: a reader fetches the header once, keeps
// it, and thereafter asks for one window per lookup. At 100 million
// entries that is a few hundred KB held, and 64 KB moved per lookup,
// against 1.6 GB fetched whole.
type Header struct {
	KeyLen    int
	RecordLen int
	Count     int
	Stride    int
	samples   []byte
	base      int64 // byte offset of the first record within the object
}

// ParseHeader reads the header and samples from the front of a table.
// prefix must hold at least HeaderSize bytes of it; SampleBytes says how
// much more to fetch when it does not.
func ParseHeader(prefix []byte) (*Header, error) {
	if len(prefix) < headerLen || string(prefix[0:8]) != magic {
		return nil, ErrFormat
	}
	h := &Header{
		KeyLen:    int(binary.LittleEndian.Uint16(prefix[8:])),
		RecordLen: int(binary.LittleEndian.Uint16(prefix[10:])),
		Count:     int(binary.LittleEndian.Uint32(prefix[12:])),
		Stride:    int(binary.LittleEndian.Uint32(prefix[16:])),
	}
	samples := int(binary.LittleEndian.Uint32(prefix[20:]))
	if h.KeyLen <= 0 || h.RecordLen < 0 || h.Stride <= 0 || h.Count < 0 {
		return nil, ErrFormat
	}
	if want := headerLen + samples*h.KeyLen; len(prefix) < want {
		return nil, fmt.Errorf("%w: %d samples need %d bytes, have %d", ErrFormat, samples, want, len(prefix))
	}
	h.samples = prefix[headerLen : headerLen+samples*h.KeyLen]
	h.base = int64(headerLen + samples*h.KeyLen)
	return h, nil
}

// HeaderSize is the fixed part; a caller fetching a header blind should
// ask for this plus a guess at the samples, then check SampleBytes.
const HeaderSize = headerLen

// SampleBytes is how many bytes the header and samples occupy.
func (h *Header) SampleBytes() int64 { return h.base }

// SampleExtent is SampleBytes read from the FIXED part alone — how much
// of an object a reader must have before ParseHeader can succeed.
//
// It exists because the two are a chicken and an egg over a range
// request: the sample count lives in the fixed header, and ParseHeader
// refuses a prefix that does not already carry the samples it names. A
// remote reader asks for a guess, calls this on what came back, and knows
// exactly what a second request must ask for — so a blind fetch converges
// in at most two round trips instead of doubling.
//
// The result is UNVALIDATED against any object: samples is a uint32 off
// the wire, so a hostile or corrupt header can name an extent far larger
// than the object. Callers hold it against the size they know.
func SampleExtent(head []byte) (int64, error) {
	if len(head) < headerLen || string(head[0:8]) != magic {
		return 0, ErrFormat
	}
	keyLen := int64(binary.LittleEndian.Uint16(head[8:]))
	samples := int64(binary.LittleEndian.Uint32(head[20:]))
	if keyLen <= 0 {
		return 0, ErrFormat
	}
	return int64(headerLen) + samples*keyLen, nil
}

// Window is the byte extent within the table that could hold key, or ok
// false when the table cannot. The extent is at most Stride records.
func (h *Header) Window(key []byte) (off, length int64, ok bool) {
	if h.Count == 0 || len(key) != h.KeyLen {
		return 0, 0, false
	}
	n := len(h.samples) / h.KeyLen
	// The last sample not greater than key bounds the window below.
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(h.sampleAt(i), key) > 0
	}) - 1
	if i < 0 {
		// Before the first record: the key cannot be here at all, since
		// the first record IS the first sample.
		return 0, 0, false
	}
	first := i * h.Stride
	last := min(first+h.Stride, h.Count) // exclusive
	entry := int64(h.KeyLen + h.RecordLen)
	return h.base + int64(first)*entry, int64(last-first) * entry, true
}

func (h *Header) sampleAt(i int) []byte { return h.samples[i*h.KeyLen : (i+1)*h.KeyLen] }

// LookupWindow searches records fetched for a Window.
func (h *Header) LookupWindow(window, key []byte) ([]byte, bool) {
	entry := h.KeyLen + h.RecordLen
	n := len(window) / entry
	i := sort.Search(n, func(i int) bool {
		return bytes.Compare(window[i*entry:i*entry+h.KeyLen], key) >= 0
	})
	if i >= n || !bytes.Equal(window[i*entry:i*entry+h.KeyLen], key) {
		return nil, false
	}
	return window[i*entry+h.KeyLen : (i+1)*entry], true
}

// Table is a whole table read in place, for a caller that has all the
// bytes — a mapped file, a cached download, or a pack's own trailer.
type Table struct {
	h       *Header
	records []byte
}

// Open validates the structure without reading the entries.
func Open(b []byte) (*Table, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	entry := h.KeyLen + h.RecordLen
	want := h.base + int64(h.Count)*int64(entry)
	if int64(len(b)) < want {
		return nil, fmt.Errorf("%w: %d entries need %d bytes, have %d", ErrFormat, h.Count, want, len(b))
	}
	return &Table{h: h, records: b[h.base:want]}, nil
}

func (t *Table) Len() int       { return t.h.Count }
func (t *Table) KeyLen() int    { return t.h.KeyLen }
func (t *Table) RecordLen() int { return t.h.RecordLen }

// Lookup finds one key. The returned slice aliases the table.
//
// Sort order is NOT verified at open: that is a pass over every entry,
// which is the cost this structure exists to avoid. A table out of order
// answers "not found" for some keys, degrading to the caller's fallback
// rather than to a wrong answer.
func (t *Table) Lookup(key []byte) ([]byte, bool) {
	if len(key) != t.h.KeyLen {
		return nil, false
	}
	return t.h.LookupWindow(t.records, key)
}

// At returns the i'th entry in sorted order, for a caller enumerating the
// table rather than searching it — a merge, or a rebuild.
func (t *Table) At(i int) (key, value []byte) {
	entry := t.h.KeyLen + t.h.RecordLen
	rec := t.records[i*entry : (i+1)*entry]
	return rec[:t.h.KeyLen], rec[t.h.KeyLen:]
}

// MergeKeys walks several sorted tables in key order, oldest FIRST,
// calling fn once per distinct key with the record the LAST table holding
// it gives — which is what makes a consolidation agree with the newest
// placement.
//
// It holds one cursor per input rather than the inputs' contents, so
// walking indexes that together describe a hundred million objects costs
// memory proportional to the number of indexes. That is the property that
// makes a global index buildable at all: it is never built at once, only
// merged.
//
// fn is told WHICH input supplied the record, for a caller whose values
// mean something only relative to their own table — mpi's records are
// offsets into that index's strings blob, so the winner's identity is not
// a convenience there but the difference between a pack name and a wrong
// one. Key and value alias the input table and stay valid only for the
// call.
func MergeKeys(tables []*Table, fn func(from int, key, value []byte) error) error {
	at := make([]int, len(tables))
	for {
		best, bestKey := -1, []byte(nil)
		for i, t := range tables {
			if at[i] >= t.Len() {
				continue
			}
			k, _ := t.At(at[i])
			if best < 0 || bytes.Compare(k, bestKey) < 0 {
				best, bestKey = i, k
			}
		}
		if best < 0 {
			return nil
		}
		// Every input holding this key advances; the last one to hold it
		// supplies the record, since tables are given oldest first.
		from, key, value := -1, []byte(nil), []byte(nil)
		for i, t := range tables {
			if at[i] < t.Len() {
				if k, v := t.At(at[i]); bytes.Equal(k, bestKey) {
					from, key, value = i, k, v
					at[i]++
				}
			}
		}
		if err := fn(from, key, value); err != nil {
			return err
		}
	}
}

// StreamWriter encodes a table from records handed to it in ascending key
// order, without holding them.
//
// The header must state the record COUNT, and a merge only knows it after
// the last record — which is why the obvious encoder assembles the whole
// output in memory, and why that bounds a merge to what one process can
// hold. A StreamWriter instead parks the records in a SPOOL as they
// arrive, keeps only the samples, and copies the spool through once the
// header can be written.
//
// Memory is then O(samples): N/stride keys, 293 KB at a hundred million
// entries, against the 1.6 GB the records themselves would be. The cost
// is that the output is written twice — once to the spool, once to the
// destination — which is the trade a merge that does not fit in memory
// has to make.
type StreamWriter struct {
	keyLen    int
	recordLen int
	stride    int
	spool     io.ReadWriteSeeker
	buf       *bufio.Writer
	count     int
	samples   []byte
	last      []byte
	err       error
}

// Len is how many records have been accepted so far, which is what a
// caller naming the finished object records without reading it back.
func (w *StreamWriter) Len() int { return w.count }

// NewStreamWriter starts a table over spool, which must be empty and
// positioned at its start: an os.File in the caller's spool directory, or
// MemSpool for a merge small enough not to want a file. A zero stride
// takes DefaultStride.
//
// The spool is written and then read back from offset zero; nothing else
// may write to it in between, and the caller owns closing and removing
// it.
func NewStreamWriter(spool io.ReadWriteSeeker, keyLen, recordLen, stride int) *StreamWriter {
	if stride <= 0 {
		stride = DefaultStride
	}
	return &StreamWriter{
		keyLen: keyLen, recordLen: recordLen, stride: stride,
		spool: spool,
		// Records are 16 bytes; a write syscall each would make the spool
		// the cost of the merge rather than a detail of it.
		buf: bufio.NewWriterSize(spool, 64<<10),
	}
}

// Add appends one record. Keys must ARRIVE SORTED and distinct: a
// StreamWriter cannot sort what it has already spooled, so an out-of-order
// key is refused here rather than encoded into a table that answers "not
// found" for keys it holds.
func (s *StreamWriter) Add(key, value []byte) error {
	if s.err != nil {
		return s.err
	}
	if len(key) != s.keyLen {
		return fmt.Errorf("packidx: key is %d bytes, want %d", len(key), s.keyLen)
	}
	if len(value) != s.recordLen {
		return fmt.Errorf("packidx: value is %d bytes, want %d", len(value), s.recordLen)
	}
	if s.count > 0 && bytes.Compare(key, s.last) <= 0 {
		return fmt.Errorf("packidx: key %x arrived after %x; a streaming table cannot reorder", key, s.last)
	}
	if s.count%s.stride == 0 {
		s.samples = append(s.samples, key...)
	}
	if _, err := s.buf.Write(key); err != nil {
		s.err = err
		return err
	}
	if _, err := s.buf.Write(value); err != nil {
		s.err = err
		return err
	}
	s.last = append(s.last[:0], key...)
	s.count++
	return nil
}

// Count is how many records have been added.
func (s *StreamWriter) Count() int { return s.count }

// Finish writes the header, the samples and then the spooled records to
// w, and reports how many bytes that was.
//
// A failure leaves w holding a PREFIX of a table, which the caller must
// discard: there is nothing here that can repair a half-written one, and
// every caller writing to object storage is content-addressing the result
// anyway, so a partial write is named differently and never confused for
// the whole.
func (s *StreamWriter) Finish(w io.Writer) (int64, error) {
	if s.err != nil {
		return 0, s.err
	}
	if err := s.buf.Flush(); err != nil {
		return 0, err
	}
	head := make([]byte, headerLen+len(s.samples))
	putHeader(head, s.keyLen, s.recordLen, s.stride, s.count, sampleCount(s.count, s.stride))
	copy(head[headerLen:], s.samples)
	n, err := w.Write(head)
	if err != nil {
		return int64(n), err
	}
	if _, err := s.spool.Seek(0, io.SeekStart); err != nil {
		return int64(n), err
	}
	// CopyN rather than Copy: the record count is what the header just
	// promised, so a spool that somehow holds more must not extend the
	// table past it.
	m, err := io.CopyN(w, s.spool, int64(s.count)*int64(s.keyLen+s.recordLen))
	return int64(n) + m, err
}

// MergeTo merges sorted tables into w, newest LAST, spooling the records
// rather than holding them. It is Merge for an output too large to keep.
func MergeTo(w io.Writer, spool io.ReadWriteSeeker, keyLen, recordLen, stride int, tables []*Table) error {
	for _, t := range tables {
		if t.h.KeyLen != keyLen || t.h.RecordLen != recordLen {
			return fmt.Errorf("packidx: cannot merge a %d/%d table into a %d/%d one",
				t.h.KeyLen, t.h.RecordLen, keyLen, recordLen)
		}
	}
	sw := NewStreamWriter(spool, keyLen, recordLen, stride)
	if err := MergeKeys(tables, func(_ int, key, value []byte) error { return sw.Add(key, value) }); err != nil {
		return err
	}
	_, err := sw.Finish(w)
	return err
}

// Merge is MergeTo into memory, which is what a small merge wants: most
// of them are one generation's index folded into the tier ahead of it,
// kilobytes at a time, and asking a caller for a temp file to move
// kilobytes would be the wrong default. It is a thin wrapper rather than
// a second encoder so that the two cannot drift.
func Merge(keyLen, recordLen, stride int, tables []*Table) ([]byte, error) {
	var out bytes.Buffer
	if err := MergeTo(&out, MemSpool(), keyLen, recordLen, stride, tables); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// MemSpool is a spool backed by memory, for a merge small enough not to
// want a file. Writing to it cannot fail, so a caller that uses one has
// no new error to handle beyond the ones its inputs already produce.
func MemSpool() io.ReadWriteSeeker { return &memSpool{} }

type memSpool struct {
	buf []byte
	pos int64
}

func (m *memSpool) Write(p []byte) (int, error) {
	// The append-at-the-end case is the only one a merge uses, and taking
	// it directly leaves the growth to append rather than to a temporary
	// per flush.
	if m.pos == int64(len(m.buf)) {
		m.buf = append(m.buf, p...)
		m.pos += int64(len(p))
		return len(p), nil
	}
	if end := m.pos + int64(len(p)); end > int64(len(m.buf)) {
		m.buf = append(m.buf, make([]byte, end-int64(len(m.buf)))...)
	}
	copy(m.buf[m.pos:], p)
	m.pos += int64(len(p))
	return len(p), nil
}

func (m *memSpool) Read(p []byte) (int, error) {
	if m.pos >= int64(len(m.buf)) {
		return 0, io.EOF
	}
	n := copy(p, m.buf[m.pos:])
	m.pos += int64(n)
	return n, nil
}

func (m *memSpool) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		m.pos = off
	case io.SeekCurrent:
		m.pos += off
	case io.SeekEnd:
		m.pos = int64(len(m.buf)) + off
	default:
		return 0, fmt.Errorf("packidx: unknown seek whence %d", whence)
	}
	if m.pos < 0 {
		return 0, fmt.Errorf("packidx: seek to %d, before the start of the spool", m.pos)
	}
	return m.pos, nil
}
