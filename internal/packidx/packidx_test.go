package packidx

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func key(n uint64) [KeySize]byte {
	var k [KeySize]byte
	binary.BigEndian.PutUint64(k[:8], n*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(k[8:16], n)
	return k
}

func value(n uint64, width int) []byte {
	v := make([]byte, width)
	binary.LittleEndian.PutUint64(v, n)
	return v
}

func TestLookupFindsEveryEntryAndNothingElse(t *testing.T) {
	const n = 5000
	b := NewBuilder(16)
	for i := uint64(0); i < n; i++ {
		if err := b.Add(key(i), value(i, 16)); err != nil {
			t.Fatal(err)
		}
	}
	tbl, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != n {
		t.Fatalf("table holds %d entries, want %d", tbl.Len(), n)
	}
	for i := uint64(0); i < n; i++ {
		v, ok := tbl.Lookup(key(i))
		if !ok {
			t.Fatalf("key %d is missing", i)
		}
		if got := binary.LittleEndian.Uint64(v); got != i {
			t.Fatalf("key %d resolved to value %d", i, got)
		}
	}
	for i := uint64(n); i < n+500; i++ {
		if _, ok := tbl.Lookup(key(i)); ok {
			t.Fatalf("key %d was never added but was found", i)
		}
	}
}

// The fanout is an index on the first byte, so keys that all share one —
// and keys spread across every one — are the two shapes that break a
// bucket calculation.
func TestLookupAcrossFanoutBuckets(t *testing.T) {
	b := NewBuilder(8)
	var want [][KeySize]byte
	for bucket := 0; bucket < 256; bucket++ {
		for j := 0; j < 3; j++ {
			var k [KeySize]byte
			k[0] = byte(bucket)
			k[1] = byte(j)
			want = append(want, k)
			if err := b.Add(k, value(uint64(bucket*3+j), 8)); err != nil {
				t.Fatal(err)
			}
		}
	}
	tbl, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range want {
		if _, ok := tbl.Lookup(k); !ok {
			t.Fatalf("key with first byte %d, second %d is missing", k[0], k[1])
		}
	}
	// A key in a populated bucket that was never added must not resolve to
	// its neighbour.
	var miss [KeySize]byte
	miss[0], miss[1] = 7, 200
	if _, ok := tbl.Lookup(miss); ok {
		t.Fatal("a key that was never added resolved inside a populated bucket")
	}
}

// An identity names content, so two entries under one identity describe
// the same bytes and either answer is right. The table keeps one, and
// keeping the LAST is what makes a rebuilt index agree with the newest
// placement.
func TestDuplicateKeysCollapseToTheLast(t *testing.T) {
	b := NewBuilder(8)
	k := key(42)
	if err := b.Add(k, value(1, 8)); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(k, value(2, 8)); err != nil {
		t.Fatal(err)
	}
	tbl, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 1 {
		t.Fatalf("%d entries for one repeated key", tbl.Len())
	}
	v, ok := tbl.Lookup(k)
	if !ok {
		t.Fatal("the repeated key is missing")
	}
	if got := binary.LittleEndian.Uint64(v); got != 2 {
		t.Fatalf("resolved to %d, want the later value 2", got)
	}
}

func TestEmptyTable(t *testing.T) {
	tbl, err := Open(NewBuilder(4).Encode())
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 0 {
		t.Fatalf("empty builder produced %d entries", tbl.Len())
	}
	if _, ok := tbl.Lookup(key(1)); ok {
		t.Fatal("an empty table answered a lookup")
	}
}

// Truncation is the failure a range read produces, and a table is read
// from bytes somebody else fetched: it must refuse rather than index off
// the end of the slice.
func TestTruncatedTableIsRefused(t *testing.T) {
	b := NewBuilder(8)
	for i := uint64(0); i < 100; i++ {
		if err := b.Add(key(i), value(i, 8)); err != nil {
			t.Fatal(err)
		}
	}
	full := b.Encode()
	for _, n := range []int{0, 7, headerLen, headerLen + fanoutLen, len(full) - 1} {
		if _, err := Open(full[:n]); err == nil {
			t.Errorf("a %d-byte prefix of a %d-byte table was accepted", n, len(full))
		}
	}
}

// The table is read in place: a lookup must alias the caller's bytes
// rather than copy them, because the caller may have mapped a file.
func TestValuesAliasTheInput(t *testing.T) {
	b := NewBuilder(8)
	if err := b.Add(key(1), value(7, 8)); err != nil {
		t.Fatal(err)
	}
	raw := b.Encode()
	tbl, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := tbl.Lookup(key(1))
	if !ok {
		t.Fatal("missing key")
	}
	v[0] = 0xff
	if raw[len(raw)-8] != 0xff {
		t.Fatal("the value was copied out of the table rather than aliased")
	}
}

func BenchmarkLookup(b *testing.B) {
	const n = 50000
	bld := NewBuilder(24)
	for i := uint64(0); i < n; i++ {
		if err := bld.Add(key(i), value(i, 24)); err != nil {
			b.Fatal(err)
		}
	}
	tbl, err := Open(bld.Encode())
	if err != nil {
		b.Fatal(err)
	}
	r := rand.New(rand.NewPCG(1, 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := tbl.Lookup(key(r.Uint64() % n)); !ok {
			b.Fatal("missing")
		}
	}
}
