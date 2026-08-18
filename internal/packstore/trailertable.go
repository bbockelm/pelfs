package packstore

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/bbockelm/pelfs/internal/packidx"
)

// The table form of a pack trailer (PELFSPK3): a small header, the dead
// list, then a sorted lookup table of identity -> extent.
//
// A trailer answers one question — where is this identity — and the JSON
// forms make a reader decompress and parse the whole document to answer
// it. A mount pays that once per pack. This form is read in place: one
// fanout lookup and a binary search, over bytes nobody had to transform.
const (
	tableMagic = "PELFSTB1"
	// tableHeader is 8-byte aligned so the table that follows the dead
	// list can be mapped and searched where it lies.
	tableHeader = 24
	// tableRecord is what one entry resolves to: offset, length, type.
	tableRecord = 8 + 8 + 1
)

func isTable(stored []byte) bool {
	return len(stored) >= len(tableMagic) && string(stored[:len(tableMagic)]) == tableMagic
}

// encodeTable writes the table form, or reports why it cannot.
func encodeTable(tr *trailer) ([]byte, error) {
	b := packidx.NewBuilder(tableRecord)
	for _, e := range tr.Entries {
		id, err := hex.DecodeString(e.Key)
		if err != nil || len(id) != packidx.KeySize {
			// Not a 32-byte identity. Every key this format writes is one,
			// so this means a producer we do not know about — and dropping
			// its entry would be worse than writing a slower trailer.
			return nil, fmt.Errorf("packstore: entry key %q is not a 32-byte identity", e.Key)
		}
		if e.Off < 0 || e.Length < 0 {
			return nil, fmt.Errorf("packstore: entry %q has extent [%d,+%d)", e.Key, e.Off, e.Length)
		}
		var key [packidx.KeySize]byte
		copy(key[:], id)
		var v [tableRecord]byte
		binary.LittleEndian.PutUint64(v[0:], uint64(e.Off))
		binary.LittleEndian.PutUint64(v[8:], uint64(e.Length))
		v[16] = entryTypeCode(e.Type)
		if err := b.Add(key, v[:]); err != nil {
			return nil, err
		}
	}
	dead := make([]byte, 0, 16*len(tr.Dead))
	for _, d := range tr.Dead {
		dead = binary.LittleEndian.AppendUint16(dead, uint16(len(d)))
		dead = append(dead, d...)
	}
	table := b.Encode()
	out := make([]byte, tableHeader+len(dead)+len(table))
	copy(out[0:8], tableMagic)
	binary.LittleEndian.PutUint64(out[8:], uint64(tr.Created))
	binary.LittleEndian.PutUint32(out[16:], uint32(len(dead)))
	binary.LittleEndian.PutUint32(out[20:], uint32(len(tr.Dead)))
	copy(out[tableHeader:], dead)
	copy(out[tableHeader+len(dead):], table)
	return out, nil
}

// decodeTable materializes every entry, for the callers that want the
// whole list. A caller that wants ONE entry should use LookupStored and
// touch nothing else.
func decodeTable(stored []byte) (*trailer, error) {
	tbl, tr, err := openTable(stored)
	if err != nil {
		return nil, err
	}
	tr.Entries = make([]PackEntry, 0, tbl.Len())
	for i := 0; i < tbl.Len(); i++ {
		id, v := tbl.At(i)
		tr.Entries = append(tr.Entries, PackEntry{
			Key:    hex.EncodeToString(id[:]),
			Off:    int64(binary.LittleEndian.Uint64(v[0:])),
			Length: int64(binary.LittleEndian.Uint64(v[8:])),
			Type:   entryTypeName(v[16]),
		})
	}
	return tr, nil
}

func openTable(stored []byte) (*packidx.Table, *trailer, error) {
	if !isTable(stored) || len(stored) < tableHeader {
		return nil, nil, fmt.Errorf("packstore: not a table trailer")
	}
	deadBytes := int(binary.LittleEndian.Uint32(stored[16:]))
	deadCount := int(binary.LittleEndian.Uint32(stored[20:]))
	if tableHeader+deadBytes > len(stored) {
		return nil, nil, fmt.Errorf("packstore: trailer says %d bytes of dead names, holds %d",
			deadBytes, len(stored)-tableHeader)
	}
	tr := &trailer{Version: 1, Created: int64(binary.LittleEndian.Uint64(stored[8:]))}
	names := stored[tableHeader : tableHeader+deadBytes]
	for len(names) > 0 {
		if len(names) < 2 {
			return nil, nil, fmt.Errorf("packstore: truncated dead list")
		}
		n := int(binary.LittleEndian.Uint16(names))
		names = names[2:]
		if n > len(names) {
			return nil, nil, fmt.Errorf("packstore: truncated dead list")
		}
		tr.Dead = append(tr.Dead, string(names[:n]))
		names = names[n:]
	}
	if len(tr.Dead) != deadCount {
		return nil, nil, fmt.Errorf("packstore: trailer says %d dead packs, names hold %d", deadCount, len(tr.Dead))
	}
	tbl, err := packidx.Open(stored[tableHeader+deadBytes:])
	if err != nil {
		return nil, nil, err
	}
	return tbl, tr, nil
}

// LookupStored answers one identity from stored trailer bytes without
// materializing the rest, and reports false for a trailer in a form that
// cannot do that — whose caller should parse it the ordinary way.
//
// This is the whole point of the table: a reader locating one object
// touches a fanout entry and a few keys, rather than decompressing a
// document about every object in the pack.
func LookupStored(stored []byte, id [32]byte) (PackEntry, bool) {
	tbl, _, err := openTable(stored)
	if err != nil {
		return PackEntry{}, false
	}
	v, ok := tbl.Lookup(id)
	if !ok {
		return PackEntry{}, false
	}
	return PackEntry{
		Key:    hex.EncodeToString(id[:]),
		Off:    int64(binary.LittleEndian.Uint64(v[0:])),
		Length: int64(binary.LittleEndian.Uint64(v[8:])),
		Type:   entryTypeName(v[16]),
	}, true
}

// Entry types travel as a byte rather than the JSON form's string. The
// mapping is closed, and an unknown code reads back as a data chunk —
// which is what an absent type has always meant.
func entryTypeCode(t string) byte {
	switch t {
	case EntryCatalog:
		return 1
	case EntryShard:
		return 2
	case EntrySuperblock:
		return 3
	default:
		return 0
	}
}

func entryTypeName(c byte) string {
	switch c {
	case 1:
		return EntryCatalog
	case 2:
		return EntryShard
	case 3:
		return EntrySuperblock
	default:
		return EntryData
	}
}
