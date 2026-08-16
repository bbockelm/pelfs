package hydrate

import (
	"encoding/binary"
	"testing"

	"github.com/juicedata/juicefs/pkg/meta"
)

type rec struct {
	pos  uint32
	id   uint64
	size uint32
	off  uint32
	len  uint32
}

func decodeRecs(t *testing.T, blob []byte) []rec {
	t.Helper()
	if len(blob)%sliceRecBytes != 0 {
		t.Fatalf("blob length %d is not a multiple of %d", len(blob), sliceRecBytes)
	}
	var out []rec
	for i := 0; i < len(blob); i += sliceRecBytes {
		out = append(out, rec{
			pos:  binary.BigEndian.Uint32(blob[i : i+4]),
			id:   binary.BigEndian.Uint64(blob[i+4 : i+12]),
			size: binary.BigEndian.Uint32(blob[i+12 : i+16]),
			off:  binary.BigEndian.Uint32(blob[i+16 : i+20]),
			len:  binary.BigEndian.Uint32(blob[i+20 : i+24]),
		})
	}
	return out
}

// TestAppendSliceSpans covers the chunk-boundary cases the end-to-end tests
// cannot cheaply reach: a chunkref straddling the 64 MiB boundary (same
// slice id, split off/len) and holes consuming position without records.
func TestAppendSliceSpans(t *testing.T) {
	const cs = int64(meta.ChunkSize)
	blobs := make(map[uint32][]byte)

	// A 2 MiB chunk after a 1 MiB hole (the hole emits nothing upstream).
	appendSliceSpans(blobs, 1<<20, 7, 2<<20)
	// A 3 MiB chunk straddling the first chunk boundary at 64 MiB - 1 MiB.
	appendSliceSpans(blobs, cs-1<<20, 8, 3<<20)

	c0 := decodeRecs(t, blobs[0])
	if len(c0) != 2 {
		t.Fatalf("chunk 0 has %d records, want 2: %+v", len(c0), c0)
	}
	if want := (rec{pos: 1 << 20, id: 7, size: 2 << 20, off: 0, len: 2 << 20}); c0[0] != want {
		t.Fatalf("chunk 0 rec 0 = %+v, want %+v", c0[0], want)
	}
	if want := (rec{pos: uint32(cs - 1<<20), id: 8, size: 3 << 20, off: 0, len: 1 << 20}); c0[1] != want {
		t.Fatalf("chunk 0 rec 1 = %+v, want %+v", c0[1], want)
	}
	c1 := decodeRecs(t, blobs[1])
	if len(c1) != 1 {
		t.Fatalf("chunk 1 has %d records, want 1: %+v", len(c1), c1)
	}
	if want := (rec{pos: 0, id: 8, size: 3 << 20, off: 1 << 20, len: 2 << 20}); c1[0] != want {
		t.Fatalf("chunk 1 rec 0 = %+v, want %+v", c1[0], want)
	}
	if len(blobs) != 2 {
		t.Fatalf("records landed in %d chunks, want 2", len(blobs))
	}
}
