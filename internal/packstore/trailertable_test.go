package packstore

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
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
