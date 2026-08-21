package memtable

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// A re-chunked span's row has to carry the STORED numbers, not the
// plaintext's. CLen is the length of the entry in the pack and Alg says
// how to decode it, and the two diverge from the logical length the
// moment zstd shrinks the bytes — which is to say for every span of
// zeros — or a volume key seals them, which is every span on an
// encrypted volume. A row copied from the plaintext sends a reader to
// read a chunk that is not the size the row claims.
func TestRechunkedRowsCarryTheStoredNumbers(t *testing.T) {
	ctx := context.Background()
	const w = 16384
	dek := bytes.Repeat([]byte{0x5a}, 32)
	for _, tc := range []struct {
		name  string
		dek   []byte
		keyID int64
	}{
		{"plaintext volume", nil, 0},
		{"encrypted volume", dek, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := newCountingStore()
			s, err := New(Options{
				Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
				Hasher: chunkid.NewHasher(nil), DEK: tc.dek, KeyID: tc.keyID,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close() //nolint:errcheck

			// Compressible, and disturbed so the seal has to re-chunk it.
			want := compressible(4 * w)
			mustWrite(t, s, 1, 0, want)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			patch := compressible(300)
			mustWrite(t, s, 1, 5000, patch)
			copy(want[5000:], patch)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			refs := sealRefs(t, s, 1)
			mustCover(t, refs, s.Size(1))
			if st := s.Stats(); st.RechunkedSpans == 0 {
				t.Fatal("nothing was re-chunked, so this test proved nothing")
			}
			var compressed int
			for _, r := range refs {
				if r.CLen < r.LLen {
					compressed++
				}
				if r.KeyID != tc.keyID {
					t.Fatalf("a row names key %d, want the volume's %d", r.KeyID, tc.keyID)
				}
			}
			if compressed == 0 {
				t.Fatal("no row reports a stored length below its logical one; the rows are copying the plaintext")
			}
			if got := readThroughFormatKeyed(t, obj, s.Packs(), refs, tc.dek); !bytes.Equal(got, want) {
				t.Fatal("re-chunked rows do not read back through the format")
			}
		})
	}
}
