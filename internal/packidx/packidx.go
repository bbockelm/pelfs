// Package packidx is the sorted lookup table the format uses to answer
// "where does this identity live" — once inside a pack's trailer, and
// again across packs in a multi-pack index.
//
// The shape is git's .idx, for git's reason. A reader looking for one
// object should not have to parse a document describing every object: it
// should land on the answer. So the table is fixed-width, sorted by
// identity, and prefixed by a 256-entry fanout on the first byte, which
// turns a lookup into one indexed read plus a binary search over a
// handful of cache lines. Nothing is decompressed and nothing is parsed.
//
// What that replaces is a zstd-compressed JSON array. Compressed JSON is
// smaller on the wire and far more expensive to consult: the whole
// document has to be decompressed and every entry parsed before the first
// question can be answered, and a mount asks that question once per pack.
//
// Keys are 32-byte identities because every key in this format is one:
// chunk identities, catalog identities, shard identities and the
// superblock backup's hash. Storing them raw rather than hex halves the
// key space and removes a decode step.
//
// A table is READ IN PLACE. Open borrows the caller's bytes and every
// lookup returns a subslice of them, so a mapped file or a cached
// download is consulted without a copy.
package packidx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	magic = "PELFSIX1"
	// headerLen is fixed and 8-byte aligned so the fanout, the keys and
	// the values all start aligned: this is meant to be mapped.
	headerLen = 32
	fanoutLen = 256 * 4
	// KeySize is the identity width every key in this format has.
	KeySize = 32
)

// ErrFormat reports bytes that are not a table this build understands.
var ErrFormat = fmt.Errorf("packidx: unrecognized table")

// Builder accumulates entries and encodes them sorted.
type Builder struct {
	recordLen int
	keys      [][KeySize]byte
	values    []byte
}

// NewBuilder starts a table whose values are recordLen bytes each.
func NewBuilder(recordLen int) *Builder {
	return &Builder{recordLen: recordLen}
}

// Add records one entry. value must be exactly the builder's record
// length. Later duplicates of a key REPLACE earlier ones, which is safe
// because an identity names content: two entries under one identity
// describe the same bytes, so either answer is correct and the newest is
// the one most likely to still be there.
func (b *Builder) Add(key [KeySize]byte, value []byte) error {
	if len(value) != b.recordLen {
		return fmt.Errorf("packidx: value is %d bytes, want %d", len(value), b.recordLen)
	}
	b.keys = append(b.keys, key)
	b.values = append(b.values, value...)
	return nil
}

// Len is how many entries have been added, duplicates included.
func (b *Builder) Len() int { return len(b.keys) }

// Encode sorts and writes the table.
func (b *Builder) Encode() []byte {
	idx := make([]int, len(b.keys))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(i, j int) bool {
		c := bytes.Compare(b.keys[idx[i]][:], b.keys[idx[j]][:])
		if c != 0 {
			return c < 0
		}
		// Equal keys: the later addition sorts last, so the dedup below
		// keeps it.
		return idx[i] < idx[j]
	})
	// Drop all but the last of each run of equal keys.
	kept := idx[:0]
	for i, at := range idx {
		if i+1 < len(idx) && b.keys[idx[i+1]] == b.keys[at] {
			continue
		}
		kept = append(kept, at)
	}

	count := len(kept)
	out := make([]byte, headerLen+fanoutLen+count*(KeySize+b.recordLen))
	copy(out[0:8], magic)
	binary.LittleEndian.PutUint32(out[8:], 1)
	binary.LittleEndian.PutUint32(out[12:], uint32(b.recordLen))
	binary.LittleEndian.PutUint32(out[16:], uint32(count))

	fanout := out[headerLen : headerLen+fanoutLen]
	keys := out[headerLen+fanoutLen:]
	values := keys[count*KeySize:]
	for i, at := range kept {
		copy(keys[i*KeySize:], b.keys[at][:])
		copy(values[i*b.recordLen:], b.values[at*b.recordLen:(at+1)*b.recordLen])
	}
	// fanout[i] is the number of keys whose first byte is <= i, which is
	// also the end of bucket i — so a lookup reads two adjacent entries
	// and has its search bounds.
	at := 0
	for bucket := 0; bucket < 256; bucket++ {
		for at < count && keys[at*KeySize] == byte(bucket) {
			at++
		}
		binary.LittleEndian.PutUint32(fanout[bucket*4:], uint32(at))
	}
	return out
}

// Table is a table read in place. Its methods return subslices of the
// bytes handed to Open.
type Table struct {
	recordLen int
	count     int
	fanout    []byte
	keys      []byte
	values    []byte
}

// Open validates a table's structure without reading its entries. The
// bytes must outlive the Table.
func Open(b []byte) (*Table, error) {
	if len(b) < headerLen+fanoutLen || string(b[0:8]) != magic {
		return nil, ErrFormat
	}
	if v := binary.LittleEndian.Uint32(b[8:]); v != 1 {
		return nil, fmt.Errorf("%w: version %d", ErrFormat, v)
	}
	recordLen := int(binary.LittleEndian.Uint32(b[12:]))
	count := int(binary.LittleEndian.Uint32(b[16:]))
	if recordLen <= 0 || count < 0 {
		return nil, ErrFormat
	}
	want := headerLen + fanoutLen + count*(KeySize+recordLen)
	if len(b) < want {
		return nil, fmt.Errorf("%w: %d entries need %d bytes, have %d", ErrFormat, count, want, len(b))
	}
	keys := b[headerLen+fanoutLen:]
	return &Table{
		recordLen: recordLen,
		count:     count,
		fanout:    b[headerLen : headerLen+fanoutLen],
		keys:      keys[:count*KeySize],
		values:    keys[count*KeySize : count*(KeySize+recordLen)],
	}, nil
}

// Len is the number of entries.
func (t *Table) Len() int { return t.count }

// RecordLen is the width of one value.
func (t *Table) RecordLen() int { return t.recordLen }

// Lookup finds one identity. The returned slice aliases the table.
//
// Sort order is NOT verified at open — that would be a pass over every
// entry, which is exactly the cost this structure exists to avoid. A
// table whose order is wrong answers "not found" for some keys, which
// degrades to the caller's fallback rather than to a wrong answer.
func (t *Table) Lookup(key [KeySize]byte) ([]byte, bool) {
	lo := 0
	if key[0] > 0 {
		lo = int(binary.LittleEndian.Uint32(t.fanout[(int(key[0])-1)*4:]))
	}
	hi := int(binary.LittleEndian.Uint32(t.fanout[int(key[0])*4:]))
	if lo < 0 || hi > t.count || lo > hi {
		return nil, false
	}
	i := lo + sort.Search(hi-lo, func(i int) bool {
		return bytes.Compare(t.keyAt(lo+i), key[:]) >= 0
	})
	if i >= hi || !bytes.Equal(t.keyAt(i), key[:]) {
		return nil, false
	}
	return t.values[i*t.recordLen : (i+1)*t.recordLen], true
}

// At returns the i'th entry in sorted order, for a caller enumerating the
// table rather than searching it.
func (t *Table) At(i int) ([KeySize]byte, []byte) {
	var key [KeySize]byte
	copy(key[:], t.keyAt(i))
	return key, t.values[i*t.recordLen : (i+1)*t.recordLen]
}

func (t *Table) keyAt(i int) []byte { return t.keys[i*KeySize : (i+1)*KeySize] }
