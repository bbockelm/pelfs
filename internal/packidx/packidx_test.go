package packidx

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func key(n uint64, width int) []byte {
	k := make([]byte, width)
	binary.BigEndian.PutUint64(k, n*0x9e3779b97f4a7c15)
	if width > 8 {
		binary.BigEndian.PutUint64(k[width-8:], n)
	}
	return k
}

func value(n uint64, width int) []byte {
	v := make([]byte, width)
	binary.LittleEndian.PutUint32(v, uint32(n))
	return v
}

func build(t *testing.T, n int, keyLen, recLen, stride int) *Table {
	t.Helper()
	b := NewBuilder(keyLen, recLen, stride)
	for i := 0; i < n; i++ {
		if err := b.Add(key(uint64(i), keyLen), value(uint64(i), recLen)); err != nil {
			t.Fatal(err)
		}
	}
	tbl, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func TestLookupFindsEveryEntryAndNothingElse(t *testing.T) {
	const n = 20000
	tbl := build(t, n, 12, 4, 512)
	if tbl.Len() != n {
		t.Fatalf("table holds %d entries, want %d", tbl.Len(), n)
	}
	for i := 0; i < n; i++ {
		v, ok := tbl.Lookup(key(uint64(i), 12))
		if !ok {
			t.Fatalf("key %d is missing", i)
		}
		if got := binary.LittleEndian.Uint32(v); got != uint32(i) {
			t.Fatalf("key %d resolved to %d", i, got)
		}
	}
	for i := n; i < n+200; i++ {
		if _, ok := tbl.Lookup(key(uint64(i), 12)); ok {
			t.Fatalf("key %d was never added but was found", i)
		}
	}
}

// The point of the samples: a reader that holds only the header can say
// exactly which bytes to ask for, and that window is bounded by the
// stride no matter how the keys fall.
func TestWindowBoundsWhatAReaderMustFetch(t *testing.T) {
	const (
		n      = 50000
		stride = 4096
		keyLen = 12
		recLen = 4
	)
	b := NewBuilder(keyLen, recLen, stride)
	for i := 0; i < n; i++ {
		if err := b.Add(key(uint64(i), keyLen), value(uint64(i), recLen)); err != nil {
			t.Fatal(err)
		}
	}
	raw := b.Encode()
	h, err := ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) <= h.SampleBytes() {
		t.Fatal("the table is all header")
	}
	t.Logf("%d entries: %d bytes total, %d of header and samples (%.2f%%)",
		n, len(raw), h.SampleBytes(), 100*float64(h.SampleBytes())/float64(len(raw)))

	maxWindow := int64(stride * (keyLen + recLen))
	for i := 0; i < n; i += 37 {
		k := key(uint64(i), keyLen)
		off, length, ok := h.Window(k)
		if !ok {
			t.Fatalf("no window for key %d", i)
		}
		if length > maxWindow {
			t.Fatalf("window for key %d is %d bytes, over the %d-byte stride bound", i, length, maxWindow)
		}
		v, found := h.LookupWindow(raw[off:off+length], k)
		if !found {
			t.Fatalf("key %d is not in the window the header named", i)
		}
		if got := binary.LittleEndian.Uint32(v); got != uint32(i) {
			t.Fatalf("key %d resolved to %d through its window", i, got)
		}
	}
}

// A short key can only be a false positive, so the table must not care
// how long the key is — the caller checks what it finds.
func TestTruncatedKeysAreJustShorterKeys(t *testing.T) {
	for _, keyLen := range []int{8, 12, 20, 32} {
		tbl := build(t, 5000, keyLen, 4, 256)
		for i := 0; i < 5000; i += 13 {
			if _, ok := tbl.Lookup(key(uint64(i), keyLen)); !ok {
				t.Fatalf("keyLen %d: key %d is missing", keyLen, i)
			}
		}
	}
}

func TestDuplicateKeysCollapseToTheLast(t *testing.T) {
	b := NewBuilder(12, 4, 64)
	k := key(42, 12)
	if err := b.Add(k, value(1, 4)); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(k, value(2, 4)); err != nil {
		t.Fatal(err)
	}
	tbl, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 1 {
		t.Fatalf("%d entries for one repeated key", tbl.Len())
	}
	v, _ := tbl.Lookup(k)
	if got := binary.LittleEndian.Uint32(v); got != 2 {
		t.Fatalf("resolved to %d, want the later value 2", got)
	}
}

// Merging is how a global index is built without ever holding one: a
// cursor per input, newest last.
func TestMergeTakesTheNewestAndStreams(t *testing.T) {
	older := NewBuilder(12, 4, 128)
	newer := NewBuilder(12, 4, 128)
	for i := 0; i < 3000; i++ {
		if err := older.Add(key(uint64(i), 12), value(uint64(i), 4)); err != nil {
			t.Fatal(err)
		}
	}
	// Overlapping range, different values, plus keys only the newer has.
	for i := 1500; i < 4500; i++ {
		if err := newer.Add(key(uint64(i), 12), value(uint64(i)+1000000, 4)); err != nil {
			t.Fatal(err)
		}
	}
	o, err := Open(older.Encode())
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(newer.Encode())
	if err != nil {
		t.Fatal(err)
	}
	mergedRaw, err := Merge(12, 4, 128, []*Table{o, n})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Open(mergedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Len() != 4500 {
		t.Fatalf("merged table holds %d entries, want 4500", merged.Len())
	}
	for i := 0; i < 4500; i++ {
		v, ok := merged.Lookup(key(uint64(i), 12))
		if !ok {
			t.Fatalf("key %d is missing from the merge", i)
		}
		want := uint32(i)
		if i >= 1500 {
			want = uint32(i + 1000000)
		}
		if got := binary.LittleEndian.Uint32(v); got != want {
			t.Fatalf("key %d = %d, want %d (newest wins)", i, got, want)
		}
	}
}

func TestEmptyAndTruncated(t *testing.T) {
	tbl, err := Open(NewBuilder(12, 4, 64).Encode())
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 0 {
		t.Fatalf("empty builder produced %d entries", tbl.Len())
	}
	if _, ok := tbl.Lookup(key(1, 12)); ok {
		t.Fatal("an empty table answered a lookup")
	}

	b := NewBuilder(12, 4, 64)
	for i := 0; i < 500; i++ {
		if err := b.Add(key(uint64(i), 12), value(uint64(i), 4)); err != nil {
			t.Fatal(err)
		}
	}
	full := b.Encode()
	for _, n := range []int{0, 7, headerLen - 1, headerLen, len(full) - 1} {
		if _, err := Open(full[:n]); err == nil {
			t.Errorf("a %d-byte prefix of a %d-byte table was accepted", n, len(full))
		}
	}
}

func TestValuesAliasTheInput(t *testing.T) {
	b := NewBuilder(12, 4, 64)
	if err := b.Add(key(1, 12), value(7, 4)); err != nil {
		t.Fatal(err)
	}
	raw := b.Encode()
	tbl, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := tbl.Lookup(key(1, 12))
	if !ok {
		t.Fatal("missing key")
	}
	v[0] = 0xff
	if !bytes.Contains(raw, []byte{0xff}) {
		t.Fatal("the value was copied out of the table rather than aliased")
	}
}

func BenchmarkLookup(b *testing.B) {
	const n = 200000
	bld := NewBuilder(12, 4, DefaultStride)
	for i := 0; i < n; i++ {
		if err := bld.Add(key(uint64(i), 12), value(uint64(i), 4)); err != nil {
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
		if _, ok := tbl.Lookup(key(r.Uint64()%n, 12)); !ok {
			b.Fatal("missing")
		}
	}
}
