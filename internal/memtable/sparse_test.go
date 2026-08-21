package memtable

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// An extent map is SPARSE. A write past the end of the file and a
// truncate that grows one both leave a range no extent covers, the read
// path answers zeros for it without an extent existing, and nothing in
// the write path ever materializes those zeros — that is the whole point
// of a map of handles.
//
// A catalog cannot be sparse in the same way. Its chunk lengths must
// account for exactly the node's length, and a reader refuses a file
// where they do not: "chunk lengths sum to X, node length is Y". So the
// render is where the two representations have to meet, and until they
// did, a seal turned a hole into a file that was shorter than it said it
// was — published, signed, and only discovered when someone read it.
//
// The bound this fixes to is the staging store it replaces, which had no
// choice in the matter: ftruncate and pwrite make the zeros real, and the
// seal chunked them like any other bytes. So does this.

// zerosAt splices holes into the body a sparse file should read back as.
func zerosAt(size int64) []byte { return make([]byte, size) }

func TestSealCoversHolesInTheExtentMap(t *testing.T) {
	ctx := context.Background()
	const w = 16384
	cases := []struct {
		name string
		make func(t *testing.T, s *Store) []byte
	}{
		{"hole in the middle", func(t *testing.T, s *Store) []byte {
			want := zerosAt(3 * w)
			head, tail := fill(w, 1), fill(w, 2)
			mustWrite(t, s, 1, 0, head)
			mustWrite(t, s, 1, 2*w, tail)
			copy(want, head)
			copy(want[2*w:], tail)
			return want
		}},
		{"hole at the head", func(t *testing.T, s *Store) []byte {
			want := zerosAt(2 * w)
			body := fill(w, 3)
			mustWrite(t, s, 1, w, body)
			copy(want[w:], body)
			return want
		}},
		{"hole at the tail, from a truncate that grows", func(t *testing.T, s *Store) []byte {
			want := zerosAt(3 * w)
			body := fill(2*w, 4)
			mustWrite(t, s, 1, 0, body)
			if err := s.Truncate(1, 3*w); err != nil {
				t.Fatal(err)
			}
			copy(want, body)
			return want
		}},
		{"a file that is nothing but a hole", func(t *testing.T, s *Store) []byte {
			if err := s.Truncate(1, 2*w); err != nil {
				t.Fatal(err)
			}
			return zerosAt(2 * w)
		}},
		{"several holes", func(t *testing.T, s *Store) []byte {
			want := zerosAt(7 * w)
			for i, off := range []int64{0, 2 * w, 5 * w} {
				b := fill(w, uint64(10+i))
				mustWrite(t, s, 1, off, b)
				copy(want[off:], b)
			}
			if err := s.Truncate(1, 7*w); err != nil {
				t.Fatal(err)
			}
			return want
		}},
		{"a hole beside a partial overwrite", func(t *testing.T, s *Store) []byte {
			want := zerosAt(4 * w)
			body := fill(2*w, 20)
			mustWrite(t, s, 1, 0, body)
			copy(want, body)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			patch := fill(300, 21)
			mustWrite(t, s, 1, 5000, patch)
			copy(want[5000:], patch)
			tail := fill(w, 22)
			mustWrite(t, s, 1, 3*w, tail)
			copy(want[3*w:], tail)
			return want
		}},
		{"a hole spanning a flush boundary", func(t *testing.T, s *Store) []byte {
			want := zerosAt(4 * w)
			head := fill(w, 30)
			mustWrite(t, s, 1, 0, head)
			copy(want, head)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			tail := fill(w, 31)
			mustWrite(t, s, 1, 3*w, tail)
			copy(want[3*w:], tail)
			return want
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, obj := newTestStore(t, 1<<20, Hooks{})
			want := tc.make(t, s)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			if got := readAll(t, s, 1); !bytes.Equal(got, want) {
				t.Fatal("the store's own read path does not answer zeros for the hole")
			}
			refs := sealRefs(t, s, 1)
			mustCover(t, refs, s.Size(1))
			if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
				t.Fatal("the sealed rows do not read back through the format")
			}
		})
	}
}

// The frozen render is the same function over a copied map, so a
// checkpoint of a sparse file must produce the same total rows a seal of
// the live one does.
func TestFrozenSealCoversHoles(t *testing.T) {
	ctx := context.Background()
	const w = 16384
	s, obj := newTestStore(t, 1<<20, Hooks{})
	want := zerosAt(3 * w)
	head := fill(w, 40)
	mustWrite(t, s, 1, 0, head)
	copy(want, head)
	tail := fill(w, 41)
	mustWrite(t, s, 1, 2*w, tail)
	copy(want[2*w:], tail)

	f, err := s.Freeze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release()
	sl := s.NewSealer()
	refs, err := f.Records(ctx, sl, 1)
	if err != nil {
		t.Fatalf("frozen records: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	mustCover(t, refs, f.Size(1))
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("the frozen rows do not read back through the format")
	}
}

// The strict renderer has to say so out loud. Both extents below tile
// onto whole chunks on their own — they flush separately, so neither
// straddles anything — and judging them one at a time accepted a list
// that sums short of the file. Refusing is what makes ChunkRefs a check
// rather than a coincidence.
func TestChunkRefsRefusesAGapBetweenWholeChunks(t *testing.T) {
	ctx := context.Background()
	const w = 16384
	s, _ := newTestStore(t, 1<<20, Hooks{})
	mustWrite(t, s, 1, 0, fill(w, 50))
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, s, 1, 2*w, fill(w, 51))
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := s.ChunkRefs(1)
	if !errors.Is(err, ErrNotTiled) {
		t.Fatalf("ChunkRefs error = %v, want ErrNotTiled", err)
	}
	t.Logf("refused, as it must: %v", err)

	// And a trailing gap, which no whole-chunk test would ever notice.
	if err := s.Truncate(1, 4*w); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, s, 1, 2*w, fill(2*w, 52))
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Truncate(1, 6*w); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChunkRefs(1); !errors.Is(err, ErrNotTiled) {
		t.Fatalf("ChunkRefs accepted a trailing gap: %v", err)
	}
}

// A hole's zeros are re-chunked into ordinary chunks, and they must not
// cost what they would if each were stored: identical zero chunks are the
// same identity, so a large hole is a handful of objects however big it
// gets. This is the cost claim the zero-fill answer rests on.
func TestALargeHoleDedupsToAlmostNothing(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	const size = 4 << 20
	mustWrite(t, s, 1, 0, fill(1000, 60))
	if err := s.Truncate(1, size); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	refs := sealRefs(t, s, 1)
	mustCover(t, refs, size)
	_, sent := obj.stats()
	if sent > size/8 {
		t.Errorf("a %d-byte hole cost %d bytes on the wire; identical zero chunks should collapse", size, sent)
	}
	t.Logf("a %d-byte hole sealed as %d rows for %d bytes on the wire", size, len(refs), sent)
}

// A remount is where a stuck overlay gets its second chance, so the
// question this answers is a support question: an overlay whose content
// rows describe a sparse file — the state a seal used to refuse — must
// come back as the same sparse file and must now seal.
//
// What it does NOT do is recover the missing bytes. They were never in
// the ring, never in a pack, and named by no ref; the gap has always
// read as zeros and it seals as zeros. A file damaged before the fix
// comes back the right LENGTH with zeros in the gap, which is a file
// whose content is wrong and whose only repair is to write it again.
func TestASparseFileSurvivesAReopenAndSeals(t *testing.T) {
	ctx := context.Background()
	const w = 16384
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil)})
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 3*w)
	head, tail := fill(w, 70), fill(w, 71)
	mustWrite(t, s, 1, 0, head)
	mustWrite(t, s, 1, 2*w, tail)
	copy(want, head)
	copy(want[2*w:], tail)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	s2, rep := reopen(t, s, obj, dir, 1<<20)
	if rep.Loss() {
		t.Fatalf("reopening a sparse file reported loss:\n%s", rep)
	}
	if got := s2.Size(1); got != 3*w {
		t.Fatalf("length after the reopen is %d, want %d", got, 3*w)
	}
	if got := readAll(t, s2, 1); !bytes.Equal(got, want) {
		t.Fatal("the reopened file does not read back with zeros in the gap")
	}
	refs := sealRefs(t, s2, 1)
	mustCover(t, refs, 3*w)
	if got := readThroughFormat(t, obj, s2.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("the reopened file's sealed rows do not read back through the format")
	}
}
