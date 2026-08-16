package chunkid

import (
	"bytes"
	"io"
	"testing"
)

// The chunker's cut decisions define chunk identity forever; on arbitrary
// input it must terminate, respect [Min, Max] bounds, reassemble exactly,
// and be deterministic.
//
//	go test -tags nogspt,notikv -fuzz FuzzChunker ./internal/chunkid/
func FuzzChunker(f *testing.F) {
	f.Add([]byte("small"))
	f.Add(bytes.Repeat([]byte{0}, 5000))
	f.Add(bytes.Repeat([]byte("abcd"), 3000))
	f.Add([]byte{})

	// Small parameters so fuzz inputs of a few KB exercise multi-chunk
	// paths (the format constants stay untouched — Options are explicit).
	opts := Options{MinSize: 64, AvgSize: 256, MaxSize: 1024}

	f.Fuzz(func(t *testing.T, data []byte) {
		split := func() [][]byte {
			var out [][]byte
			c := NewChunker(bytes.NewReader(data), opts)
			for {
				ch, err := c.Next()
				if err == io.EOF {
					return out
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(ch.Data) == 0 || len(ch.Data) > opts.MaxSize {
					t.Fatalf("chunk size %d out of (0, %d]", len(ch.Data), opts.MaxSize)
				}
				out = append(out, ch.Data)
			}
		}
		a := split()
		var rejoined []byte
		for i, ch := range a {
			if i < len(a)-1 && len(ch) < opts.MinSize {
				t.Fatalf("non-final chunk %d below MinSize: %d", i, len(ch))
			}
			rejoined = append(rejoined, ch...)
		}
		if !bytes.Equal(rejoined, data) {
			t.Fatalf("reassembly mismatch: %d vs %d bytes", len(rejoined), len(data))
		}
		b := split()
		if len(a) != len(b) {
			t.Fatalf("nondeterministic chunk count: %d vs %d", len(a), len(b))
		}
	})
}
