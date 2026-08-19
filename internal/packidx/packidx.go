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
	"bytes"
	"encoding/binary"
	"fmt"
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

// encodeRecords writes a table from records already in sorted order. It
// is shared with the streaming merge, which never holds them all.
func encodeRecords(keyLen, recordLen, stride, count int, at func(int) []byte) []byte {
	entryLen := keyLen + recordLen
	samples := 0
	if count > 0 {
		samples = (count + stride - 1) / stride
	}
	out := make([]byte, headerLen+samples*keyLen+count*entryLen)
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint16(out[8:], uint16(keyLen))
	binary.LittleEndian.PutUint16(out[10:], uint16(recordLen))
	binary.LittleEndian.PutUint32(out[12:], uint32(count))
	binary.LittleEndian.PutUint32(out[16:], uint32(stride))
	binary.LittleEndian.PutUint32(out[20:], uint32(samples))

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

// Merge streams several sorted tables into one, newest LAST: where a key
// appears more than once the later table wins, which is what makes a
// consolidation agree with the newest placement.
//
// It holds one cursor per input rather than the inputs' contents, so
// merging indexes that together describe a hundred million objects costs
// memory proportional to the number of indexes. That is the property
// that makes a global index buildable at all: it is never built at once,
// only merged.
func Merge(keyLen, recordLen, stride int, tables []*Table) ([]byte, error) {
	for _, t := range tables {
		if t.h.KeyLen != keyLen || t.h.RecordLen != recordLen {
			return nil, fmt.Errorf("packidx: cannot merge a %d/%d table into a %d/%d one",
				t.h.KeyLen, t.h.RecordLen, keyLen, recordLen)
		}
	}
	if stride <= 0 {
		stride = DefaultStride
	}
	at := make([]int, len(tables))
	entry := keyLen + recordLen
	var out [][]byte
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
			break
		}
		// Every input holding this key advances; the LAST one to hold it
		// supplies the record, since tables are given oldest first.
		var rec []byte
		for i, t := range tables {
			if at[i] < t.Len() {
				if k, v := t.At(at[i]); bytes.Equal(k, bestKey) {
					rec = append(append(make([]byte, 0, entry), k...), v...)
					at[i]++
				}
			}
		}
		out = append(out, rec)
	}
	return encodeRecords(keyLen, recordLen, stride, len(out), func(i int) []byte { return out[i] }), nil
}
