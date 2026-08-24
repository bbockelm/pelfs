package packstore

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/bbockelm/pelfs/internal/packidx"
)

func idHex(n uint64) string {
	var k [32]byte
	binary.BigEndian.PutUint64(k[:8], n*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(k[24:], n)
	return hex.EncodeToString(k[:])
}

func idBytes(n uint64) [32]byte {
	var k [32]byte
	b, _ := hex.DecodeString(idHex(n))
	copy(k[:], b)
	return k
}

// Every form a pack in the wild might carry must still decode: packs are
// immutable, so PELFSPK1 and PELFSPK2 objects live for as long as the
// generations naming them do.
func TestEveryTrailerFormRoundTrips(t *testing.T) {
	tr := &trailer{Version: 1, Created: 1234567, Dead: []string{"p-dead-1", "p-dead-2"}}
	for i := uint64(0); i < 500; i++ {
		typ := EntryData
		switch i % 4 {
		case 1:
			typ = EntryCatalog
		case 2:
			typ = EntryShard
		case 3:
			typ = EntrySuperblock
		}
		tr.Entries = append(tr.Entries, PackEntry{Key: idHex(i), Off: int64(i * 100), Length: 100, Type: typ})
	}

	stored, footer, err := encodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(footer[8:]); got != magicT {
		t.Fatalf("footer magic is %q, want the table form %q", got, magicT)
	}

	got, err := decodeTrailer(stored, magicT)
	if err != nil {
		t.Fatal(err)
	}
	if got.Created != tr.Created {
		t.Errorf("created = %d, want %d", got.Created, tr.Created)
	}
	if len(got.Dead) != len(tr.Dead) || got.Dead[0] != tr.Dead[0] || got.Dead[1] != tr.Dead[1] {
		t.Errorf("dead list = %v, want %v", got.Dead, tr.Dead)
	}
	if len(got.Entries) != len(tr.Entries) {
		t.Fatalf("%d entries, want %d", len(got.Entries), len(tr.Entries))
	}
	byKey := map[string]PackEntry{}
	for _, e := range got.Entries {
		byKey[e.Key] = e
	}
	for _, want := range tr.Entries {
		e, ok := byKey[want.Key]
		if !ok {
			t.Fatalf("entry %s is missing", want.Key)
		}
		if e.Off != want.Off || e.Length != want.Length || e.Type != want.Type {
			t.Fatalf("entry %s = %+v, want %+v", want.Key, e, want)
		}
	}

	// ParseStoredTrailer works from the bytes alone, with no footer to say
	// which form they are.
	entries, err := ParseStoredTrailer(stored)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(tr.Entries) {
		t.Fatalf("ParseStoredTrailer returned %d entries, want %d", len(entries), len(tr.Entries))
	}
}

// The reason the form exists: locating one entry must not require reading
// the rest.
func TestLookupStoredFindsOneEntry(t *testing.T) {
	tr := &trailer{Version: 1, Created: 1}
	for i := uint64(0); i < 1000; i++ {
		tr.Entries = append(tr.Entries, PackEntry{Key: idHex(i), Off: int64(i * 7), Length: 7, Type: EntryData})
	}
	stored, _, err := encodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < 1000; i += 97 {
		e, ok := LookupStored(stored, idBytes(i))
		if !ok {
			t.Fatalf("entry %d is missing", i)
		}
		if e.Off != int64(i*7) || e.Length != 7 {
			t.Fatalf("entry %d = %+v", i, e)
		}
	}
	if _, ok := LookupStored(stored, idBytes(999999)); ok {
		t.Error("an identity that is not in the pack resolved")
	}
}

// A key that is not a 32-byte identity cannot go in the table. Writing a
// slower trailer is right; dropping the entry is not.
func TestANonIdentityKeyFallsBackToJSON(t *testing.T) {
	tr := &trailer{Version: 1, Created: 1, Entries: []PackEntry{
		{Key: "not-an-identity", Off: 0, Length: 1},
	}}
	stored, footer, err := encodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(footer[8:]); got != magicZ {
		t.Fatalf("footer magic is %q, want the JSON form %q", got, magicZ)
	}
	got, err := decodeTrailer(stored, magicZ)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 || got.Entries[0].Key != "not-an-identity" {
		t.Fatalf("entry did not survive the fallback: %+v", got.Entries)
	}
	if _, ok := LookupStored(stored, idBytes(1)); ok {
		t.Error("LookupStored claimed to answer from a JSON trailer")
	}
}

func TestTruncatedTableTrailerIsRefused(t *testing.T) {
	tr := &trailer{Version: 1, Created: 1}
	for i := uint64(0); i < 50; i++ {
		tr.Entries = append(tr.Entries, PackEntry{Key: idHex(i), Off: int64(i), Length: 1})
	}
	stored, _, err := encodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 7, tableHeader - 1, tableHeader, len(stored) - 1} {
		if _, err := decodeTrailer(stored[:n], magicT); err == nil {
			t.Errorf("a %d-byte prefix of a %d-byte trailer was accepted", n, len(stored))
		}
	}
}

// The table form reads an entry as offset/length/type at fixed offsets
// inside a record whose WIDTH the untrusted bytes declare. A table
// announcing a narrower record (or a shorter key) would have every reader
// index past the end of what Lookup and At hand back, so the shape is
// checked once, where the trailer is opened.
func TestATableTrailerWithTheWrongShapeIsRefused(t *testing.T) {
	shapes := []struct {
		name              string
		keyLen, recordLen int
	}{
		{"no record at all", packidx.KeySize, 0},
		{"record too short for the type byte", packidx.KeySize, 16},
		{"truncated keys", 12, tableRecord},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			b := packidx.NewBuilder(sh.keyLen, sh.recordLen, 0)
			key := idBytes(1)
			if err := b.Add(key[:sh.keyLen], make([]byte, sh.recordLen)); err != nil {
				t.Fatal(err)
			}
			table := b.Encode()
			stored := make([]byte, tableHeader+len(table))
			copy(stored[0:8], tableMagic)
			copy(stored[tableHeader:], table)

			if _, err := decodeTrailer(stored, magicT); err == nil {
				t.Errorf("decodeTrailer accepted a table of %d-byte keys and %d-byte records",
					sh.keyLen, sh.recordLen)
			}
			if _, ok := LookupStored(stored, key); ok {
				t.Errorf("LookupStored answered from a table of %d-byte keys and %d-byte records",
					sh.keyLen, sh.recordLen)
			}
		})
	}
}

// Extents in the table form are raw uint64s, so the sign check the JSON
// path had always done has to cover this form too — it lives above the
// form now. An entry whose length reads back negative must not reach a
// range read by either door.
func TestATableEntryWithANegativeExtentIsRefused(t *testing.T) {
	tr := &trailer{Version: 1, Created: 1}
	tr.Entries = append(tr.Entries, PackEntry{Key: idHex(7), Off: 0, Length: 4})
	stored, _, err := encodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	// The key appears twice — once as the table's sample, once at the head
	// of the record. The record is the later of the two, and its value
	// follows the key.
	key := idBytes(7)
	at := bytes.LastIndex(stored, key[:])
	if at < 0 {
		t.Fatal("the entry's key is not in the encoded table")
	}
	for _, field := range []struct {
		name string
		off  int
	}{{"offset", 0}, {"length", 8}} {
		t.Run(field.name, func(t *testing.T) {
			bad := bytes.Clone(stored)
			binary.LittleEndian.PutUint64(bad[at+packidx.KeySize+field.off:], 1<<63)
			if _, err := decodeTrailer(bad, magicT); err == nil {
				t.Errorf("decodeTrailer accepted a negative %s", field.name)
			}
			if e, ok := LookupStored(bad, key); ok {
				t.Errorf("LookupStored answered with %+v, whose %s is negative", e, field.name)
			}
		})
	}
}
