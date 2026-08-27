package packidx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// A table is read from bytes nobody in this process wrote: a pack's
// trailer (internal/packstore), a multi-pack index (internal/mpi), a
// graft's object index (internal/graft) — all of them federation objects
// a corrupt or hostile origin can shape. Every one of the four numbers in
// the header (key length, record length, count, stride) reaches an index
// or a range request, so the contract under fuzzing is that nothing here
// panics and nothing reads outside the buffer.
//
// This target exists because the shape it hunts is one that got through:
// a length taken from the bytes, used as a bound without being held
// against the object's real size, is what panicked packstore.parseTail —
// and packidx is the ONE parser both index formats go through.
//
//	go test -fuzz FuzzOpenTable ./internal/packidx/
func FuzzOpenTable(f *testing.F) {
	b := NewBuilder(KeySize, 17, 4)
	for i := 0; i < 9; i++ {
		var k [KeySize]byte
		binary.BigEndian.PutUint64(k[:8], uint64(i)*0x9e3779b97f4a7c15)
		if err := b.Add(k[:], bytes.Repeat([]byte{byte(i)}, 17)); err != nil {
			f.Fatal(err)
		}
	}
	table := b.Encode()
	f.Add(table)
	f.Add(table[:headerLen]) // header with no samples and no records
	f.Add([]byte(magic))
	f.Add([]byte{})
	// A header claiming far more than it carries, which is the shape a
	// truncated download and a hostile origin produce alike.
	huge := bytes.Clone(table)
	binary.LittleEndian.PutUint32(huge[12:], ^uint32(0)) // count
	binary.LittleEndian.PutUint32(huge[20:], ^uint32(0)) // samples
	f.Add(huge)

	f.Fuzz(func(t *testing.T, data []byte) {
		// SampleExtent and ParseHeader answer from a PREFIX, for a reader
		// deciding what to ask a range server for. Their answers become
		// offsets, so an answer shorter than the fixed header is one no
		// caller can subtract from safely.
		if n, err := SampleExtent(data); err == nil && n < int64(headerLen) {
			t.Fatalf("SampleExtent returned %d, shorter than the %d-byte header", n, headerLen)
		}
		if h, err := ParseHeader(data); err == nil {
			if h.SampleBytes() < headerLen || h.SampleBytes() > int64(len(data)) {
				t.Fatalf("ParseHeader accepted %d bytes of samples out of %d", h.SampleBytes(), len(data))
			}
			key := bytes.Repeat([]byte{0xa5}, h.KeyLen)
			if off, length, ok := h.Window(key); ok {
				if off < 0 || length < 0 {
					t.Fatalf("Window returned [%d,+%d)", off, length)
				}
				// A window that came back SHORT is the ordinary case with a
				// lying header, and searching it must not read past it.
				for _, short := range []int{0, 1, int(min(length, 64))} {
					_, _ = h.LookupWindow(make([]byte, short), key)
				}
			}
			_, _ = h.LookupWindow(data, key)
		}

		tbl, err := Open(data)
		if err != nil {
			return
		}
		// Open succeeded, so every record it claims must be inside the
		// bytes it was given — At and Lookup index with multiplication and
		// have nothing else standing between them and the buffer.
		for i := 0; i < tbl.Len(); i++ {
			k, v := tbl.At(i)
			if len(k) != tbl.KeyLen() || len(v) != tbl.RecordLen() {
				t.Fatalf("entry %d is %d/%d bytes, table says %d/%d",
					i, len(k), len(v), tbl.KeyLen(), tbl.RecordLen())
			}
		}
		_, _ = tbl.Lookup(bytes.Repeat([]byte{0x00}, tbl.KeyLen()))
		_, _ = tbl.Lookup(bytes.Repeat([]byte{0xff}, tbl.KeyLen()))
		_, _ = tbl.Lookup(nil)
	})
}
