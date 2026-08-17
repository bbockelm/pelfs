package chunkid

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"

	"lukechampine.com/blake3"
)

// randStream returns n pseudorandom bytes from a fixed seed. Seeded
// math/rand keeps every run byte-identical, so cut points asserted here
// are stable across runs and machines.
func randStream(t *testing.T, seed int64, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.New(rand.NewSource(seed)).Read(b); err != nil {
		t.Fatalf("rand read: %v", err)
	}
	return b
}

// chunkAll drains a Chunker, verifying offsets are contiguous and the
// concatenated chunks reproduce the input length.
func chunkAll(t *testing.T, data []byte, opts Options) []Chunk {
	t.Helper()
	c := NewChunker(bytes.NewReader(data), opts)
	var chunks []Chunk
	var off int64
	for {
		ch, err := c.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if ch.Offset != off {
			t.Fatalf("chunk %d: offset %d, want %d", len(chunks), ch.Offset, off)
		}
		if len(ch.Data) == 0 {
			t.Fatalf("chunk %d: empty data", len(chunks))
		}
		off += int64(len(ch.Data))
		chunks = append(chunks, ch)
	}
	if off != int64(len(data)) {
		t.Fatalf("chunks cover %d bytes, want %d", off, len(data))
	}
	return chunks
}

func identities(h Hasher, chunks []Chunk) []Identity {
	ids := make([]Identity, len(chunks))
	for i, ch := range chunks {
		ids[i] = h.Sum(ch.Data)
	}
	return ids
}

func TestChunkerDeterminism(t *testing.T) {
	data := randStream(t, 1, 64<<20)
	h := NewHasher(nil)

	a := chunkAll(t, data, Options{})
	b := chunkAll(t, data, Options{})
	if len(a) != len(b) {
		t.Fatalf("chunk counts differ: %d vs %d", len(a), len(b))
	}
	idsA, idsB := identities(h, a), identities(h, b)
	var reassembled []byte
	for i := range a {
		if a[i].Offset != b[i].Offset || len(a[i].Data) != len(b[i].Data) {
			t.Errorf("chunk %d: cut points differ: (%d,%d) vs (%d,%d)",
				i, a[i].Offset, len(a[i].Data), b[i].Offset, len(b[i].Data))
		}
		if idsA[i] != idsB[i] {
			t.Errorf("chunk %d: identities differ", i)
		}
		reassembled = append(reassembled, a[i].Data...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Fatal("concatenated chunks do not reproduce the input")
	}
}

func TestChunkerSizeBounds(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		size int
	}{
		{"defaults", Options{}, 64 << 20},
		{"small-params", Options{MinSize: 64 << 10, AvgSize: 256 << 10, MaxSize: 1 << 20}, 64 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			min, avg, max := tt.opts.MinSize, tt.opts.AvgSize, tt.opts.MaxSize
			if min == 0 {
				min, avg, max = DefaultMinSize, DefaultAvgSize, DefaultMaxSize
			}
			data := randStream(t, 2, tt.size)
			chunks := chunkAll(t, data, tt.opts)
			for i, ch := range chunks {
				if len(ch.Data) > max {
					t.Errorf("chunk %d: size %d exceeds max %d", i, len(ch.Data), max)
				}
				// The final chunk is whatever the stream had left and may
				// legitimately be under min.
				if len(ch.Data) < min && i != len(chunks)-1 {
					t.Errorf("chunk %d: size %d under min %d", i, len(ch.Data), min)
				}
			}
			mean := tt.size / len(chunks)
			if mean < avg/2 || mean > avg*2 {
				t.Errorf("mean chunk size %d not within 2x of target %d (%d chunks)", mean, avg, len(chunks))
			}
		})
	}
}

func TestChunkerEditLocality(t *testing.T) {
	// An insertion must only disturb chunks near the edit: cut points
	// re-synchronize because they depend on a ~64-byte window, not on
	// absolute position.
	tests := []struct {
		name string
		opts Options
	}{
		{"defaults", Options{}},
		// Smaller chunks give ~250 chunks in 64 MiB, so the >90% bound is
		// statistically comfortable rather than seed-lucky.
		{"small-params", Options{MinSize: 64 << 10, AvgSize: 256 << 10, MaxSize: 1 << 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := randStream(t, 3, 64<<20)
			insert := randStream(t, 4, 100)
			mid := len(orig) / 2
			edited := make([]byte, 0, len(orig)+len(insert))
			edited = append(edited, orig[:mid]...)
			edited = append(edited, insert...)
			edited = append(edited, orig[mid:]...)

			h := NewHasher(nil)
			origIDs := identities(h, chunkAll(t, orig, tt.opts))
			editedIDs := identities(h, chunkAll(t, edited, tt.opts))

			editedSet := make(map[Identity]int, len(editedIDs))
			for _, id := range editedIDs {
				editedSet[id]++
			}
			shared := 0
			for _, id := range origIDs {
				if editedSet[id] > 0 {
					editedSet[id]--
					shared++
				}
			}
			frac := float64(shared) / float64(len(origIDs))
			t.Logf("%d/%d original chunk identities shared (%.1f%%)", shared, len(origIDs), 100*frac)
			if frac <= 0.9 {
				t.Errorf("only %.1f%% of chunk identities shared after 100-byte insertion, want >90%%", 100*frac)
			}
		})
	}
}

func TestChunkerEmptyInput(t *testing.T) {
	c := NewChunker(bytes.NewReader(nil), Options{})
	if _, err := c.Next(); err != io.EOF {
		t.Fatalf("Next on empty input: got %v, want io.EOF", err)
	}
	// EOF must be sticky.
	if _, err := c.Next(); err != io.EOF {
		t.Fatalf("second Next: got %v, want io.EOF", err)
	}
}

func TestChunkerSubMinimumInput(t *testing.T) {
	sizes := []int{1, 4 << 10, DefaultMinSize - 1, DefaultMinSize}
	for _, n := range sizes {
		data := randStream(t, 5, n)
		chunks := chunkAll(t, data, Options{})
		if len(chunks) != 1 {
			t.Errorf("size %d: got %d chunks, want 1", n, len(chunks))
			continue
		}
		if !bytes.Equal(chunks[0].Data, data) {
			t.Errorf("size %d: chunk data does not match input", n)
		}
	}
}

// errReader fails after serving its prefix, to check that reader errors
// propagate instead of yielding a partial chunk.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestChunkerReaderError(t *testing.T) {
	want := errors.New("backend failed")
	c := NewChunker(&errReader{data: randStream(t, 6, 1000), err: want}, Options{})
	if _, err := c.Next(); !errors.Is(err, want) {
		t.Fatalf("Next: got %v, want %v", err, want)
	}
}

func TestChunkerInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"avg-not-power-of-two", Options{MinSize: 1 << 20, AvgSize: 3 << 20, MaxSize: 16 << 20}},
		{"min-not-below-avg", Options{MinSize: 4 << 20, AvgSize: 4 << 20, MaxSize: 16 << 20}},
		{"max-not-above-avg", Options{MinSize: 1 << 20, AvgSize: 4 << 20, MaxSize: 4 << 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("NewChunker did not panic")
				}
			}()
			NewChunker(bytes.NewReader(nil), tt.opts)
		})
	}
}

func TestHasherKeyedModes(t *testing.T) {
	data := []byte("the same chunk plaintext")
	keyA := bytes.Repeat([]byte{0xa5}, 32)
	keyB := bytes.Repeat([]byte{0x5a}, 32)

	plain := NewHasher(nil).Sum(data)
	plainEmpty := NewHasher([]byte{}).Sum(data)
	keyedA := NewHasher(keyA).Sum(data)
	keyedB := NewHasher(keyB).Sum(data)

	if plain != plainEmpty {
		t.Error("nil key and empty key must both select plain BLAKE3")
	}
	if plain != Identity(blake3.Sum256(data)) {
		t.Error("unkeyed Sum does not match blake3.Sum256")
	}
	if plain == keyedA {
		t.Error("keyed identity equals unkeyed identity")
	}
	if keyedA == keyedB {
		t.Error("identities under different keys are equal")
	}
	// The Hasher must have copied the key: mutating the caller's slice
	// must not change identities.
	h := NewHasher(keyA)
	before := h.Sum(data)
	keyA[0] ^= 0xff
	if h.Sum(data) != before {
		t.Error("mutating the caller's key slice changed the identity")
	}
}

func TestHasherBadKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHasher did not panic on 16-byte key")
		}
	}()
	NewHasher(make([]byte, 16))
}

func TestIdentityHexRoundTrip(t *testing.T) {
	id := NewHasher(nil).Sum([]byte("round trip"))
	s := id.Hex()
	if len(s) != 64 {
		t.Fatalf("Hex length %d, want 64", len(s))
	}
	if id.String() != s {
		t.Error("String and Hex disagree")
	}
	got, err := ParseIdentity(s)
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}
	if got != id {
		t.Error("round trip changed the identity")
	}

	for _, bad := range []string{"", "abc", s[:63], s + "00", "zz" + s[2:]} {
		if _, err := ParseIdentity(bad); err == nil {
			t.Errorf("ParseIdentity(%q): expected error", bad)
		}
	}
}

// A Chunker must not reserve MaxSize before it knows the stream needs it.
// publish builds one per file, so a 16 MiB window per 8 KiB file was 84%
// of the live heap at a seal's peak (see initialWindow).
func TestChunkerWindowGrowsWithTheStream(t *testing.T) {
	small := randStream(t, 11, 8000)
	c := NewChunker(bytes.NewReader(small), Options{})
	if _, err := c.Next(); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got := cap(c.buf); got > initialWindow {
		t.Fatalf("chunking %d bytes reserved a %d-byte window", len(small), got)
	}

	// A stream that does reach MaxSize still gets the full window, or the
	// cut search would not see far enough ahead for a forced cut.
	big := randStream(t, 12, DefaultMaxSize*2)
	c = NewChunker(bytes.NewReader(big), Options{})
	if _, err := c.Next(); err != nil {
		t.Fatal(err)
	}
	if got := len(c.buf); got != DefaultMaxSize {
		t.Fatalf("window grew to %d, want MaxSize %d", got, DefaultMaxSize)
	}
}

// The growth loop must deliver the same window as a single ReadFull did,
// however grudgingly the reader hands bytes over: cut points define the
// volume's dedup domain and may not depend on read granularity.
func TestChunkerCutsIndependentOfReadGranularity(t *testing.T) {
	data := randStream(t, 13, 6<<20)
	whole := chunkAll(t, data, Options{})

	c := NewChunker(oneByteReader{bytes.NewReader(data)}, Options{})
	var dribbled []Chunk
	for {
		ch, err := c.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		dribbled = append(dribbled, ch)
	}
	if len(whole) != len(dribbled) {
		t.Fatalf("chunk counts differ: %d whole vs %d one byte at a time", len(whole), len(dribbled))
	}
	for i := range whole {
		if whole[i].Offset != dribbled[i].Offset || len(whole[i].Data) != len(dribbled[i].Data) {
			t.Fatalf("chunk %d: (%d,%d) vs (%d,%d)", i,
				whole[i].Offset, len(whole[i].Data), dribbled[i].Offset, len(dribbled[i].Data))
		}
	}
}

// oneByteReader hands over one byte per Read, so every growth step of the
// window is exercised.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}
