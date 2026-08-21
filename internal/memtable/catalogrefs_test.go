package memtable

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// readThroughFormat reconstructs a file the long way round: catalog rows,
// pack trailers fetched from the federation, range reads. Nothing in this
// path knows the memtable exists, which is the point — if the packs this
// write path produces are not the format's packs, this is where it shows.
func readThroughFormat(t *testing.T, obj *countingStore, packs []packstore.SealedPack, refs []catalog.ChunkRef) []byte {
	t.Helper()
	return readThroughFormatKeyed(t, obj, packs, refs, nil)
}

// readThroughFormatKeyed is the same for an encrypted volume, where the
// entries decode only with the volume's key.
func readThroughFormatKeyed(t *testing.T, obj *countingStore, packs []packstore.SealedPack,
	refs []catalog.ChunkRef, dek []byte) []byte {
	t.Helper()
	ctx := context.Background()
	index := make(map[string]packstore.PackEntry)
	owner := make(map[string]string)
	for _, sp := range packs {
		entries, err := packstore.FetchTrailerVerified(ctx, obj, sp.Name, sp.Size, sp.TrailerHash)
		if err != nil {
			t.Fatalf("fetch trailer for %s: %v", sp.Name, err)
		}
		for _, e := range entries {
			index[e.Key] = e
			owner[e.Key] = sp.Name
		}
	}
	var out []byte
	for _, r := range refs {
		idHex := hex.EncodeToString(r.Identity)
		e, ok := index[idHex]
		if !ok {
			t.Fatalf("chunk %s is in no listed pack", idHex)
		}
		if int64(len(out)) != r.LogicalOffset {
			t.Fatalf("chunk at logical offset %d does not follow %d bytes of content", r.LogicalOffset, len(out))
		}
		rc, err := obj.Get(ctx, packstore.PackDirKey+"/"+owner[idHex], e.Off, e.Length)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		rc.Close() //nolint:errcheck
		if err != nil {
			t.Fatal(err)
		}
		// Against CLen and through the codec, which is what a reader does.
		// Comparing the STORED bytes against LLen instead was a hole in this
		// helper for as long as every test body was incompressible: it made
		// a row whose CLen and Alg were copied from the plaintext look
		// correct, and those rows are exactly the ones a reader refuses.
		if int64(len(data)) != r.CLen {
			t.Fatalf("chunk %s: pack holds %d bytes, chunkref says clen %d", idHex, len(data), r.CLen)
		}
		plain, err := entrycodec.Decode(data, uint8(r.Alg), dek)
		if err != nil {
			t.Fatalf("chunk %s: decode with alg %d: %v", idHex, r.Alg, err)
		}
		if int64(len(plain)) != r.LLen {
			t.Fatalf("chunk %s: decodes to %d bytes, chunkref says llen %d", idHex, len(plain), r.LLen)
		}
		out = append(out, plain...)
	}
	return out
}

// sealRefs renders one inode the way a seal does and returns the rows.
func sealRefs(t *testing.T, s *Store, ino uint64) []catalog.ChunkRef {
	t.Helper()
	ctx := context.Background()
	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, ino)
	if err != nil {
		t.Fatalf("seal inode %d: %v", ino, err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatalf("finish seal: %v", err)
	}
	return refs
}

// mustCover fails unless the rows account for exactly the file's length.
func mustCover(t *testing.T, refs []catalog.ChunkRef, size int64) {
	t.Helper()
	var sum, at int64
	for i, r := range refs {
		if r.LogicalOffset != at {
			t.Fatalf("row %d starts at %d, want %d", i, r.LogicalOffset, at)
		}
		sum += r.LLen
		at += r.LLen
	}
	if sum != size {
		t.Fatalf("chunk lengths sum to %d, node length is %d", sum, size)
	}
}

func mustWrite(t *testing.T, s *Store, ino uint64, off int64, p []byte) {
	t.Helper()
	if err := s.Write(context.Background(), ino, off, p); err != nil {
		t.Fatalf("write inode %d at %d: %v", ino, off, err)
	}
}

// The whole vertical slice, ending in the format rather than in the
// prototype's own resolver.
func TestSealProducesCatalogRowsThatReadBack(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 256<<10, Hooks{})

	want := make(map[uint64][]byte)
	for ino := uint64(1); ino <= 30; ino++ {
		want[ino] = fill(int(3000+ino*700), ino)
		if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
			t.Fatal(err)
		}
		// Rewrite a third of them, so most of what was written must not
		// appear in any pack this test then reads.
		if ino%3 == 0 {
			want[ino] = fill(int(2000+ino*500), ino+1000)
			if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
				t.Fatal(err)
			}
			s.Truncate(ino, int64(len(want[ino])))
		}
	}

	// The seal: flush, then render catalog rows. No content moves in the
	// second step, which is the claim.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := obj.stats()
	packs := s.Packs()
	for ino := uint64(1); ino <= 30; ino++ {
		refs, err := s.ChunkRefs(ino)
		if err != nil {
			t.Fatalf("inode %d: %v", ino, err)
		}
		if got := readThroughFormat(t, obj, packs, refs); !bytes.Equal(got, want[ino]) {
			t.Fatalf("inode %d does not read back through the format", ino)
		}
	}
	after, _ := obj.stats()
	if after != before {
		t.Errorf("rendering catalog rows uploaded %d objects; a seal must move no content", after-before)
	}
}

// The design says a content row can name a handle and never be rewritten.
// It cannot, for a file whose live bytes do not tile onto whole chunks —
// the catalog format has no offset-into-a-chunk field. This test pins the
// case down rather than leaving it as an assertion in a report.
func TestCatalogCannotExpressAPartiallyOverwrittenExtent(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})

	if err := s.Write(ctx, 1, 0, fill(20000, 1)); err != nil {
		t.Fatal(err)
	}
	// A write landing inside the first extent splits it. Both halves are
	// still wanted; the chunk CDC produced spans both plus the middle.
	if err := s.Write(ctx, 1, 5000, fill(300, 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// The prototype's own resolver handles it, because ChunkSlice carries
	// an offset into the chunk that catalog.ChunkRef does not have.
	if got := readAll(t, s, 1); len(got) != 20000 {
		t.Fatalf("read back %d bytes, want 20000", len(got))
	}
	_, err := s.ChunkRefs(1)
	if !errors.Is(err, ErrNotTiled) {
		t.Fatalf("ChunkRefs error = %v, want ErrNotTiled", err)
	}
	t.Logf("as designed, a seal cannot write this row: %v", err)
}

// Identity binds at flush, so a seal has to flush first. Asking earlier
// must fail loudly rather than inventing an identity.
func TestChunkRefsRefusesUnflushedContent(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})
	if err := s.Write(ctx, 1, 0, fill(100, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChunkRefs(1); !errors.Is(err, ErrNotFlushed) {
		t.Fatalf("ChunkRefs error = %v, want ErrNotFlushed", err)
	}
}
