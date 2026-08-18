package memtable

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// fakeBase is a published generation: bodies, and the content records
// that generation would have written for them. It counts the bytes it is
// asked to serve, because the claim under test is about how few of them
// there are.
type fakeBase struct {
	body      map[uint64][]byte
	chunkSize int
	readBytes int64
}

func newFakeBase() *fakeBase {
	return &fakeBase{body: map[uint64][]byte{}, chunkSize: 8 << 10}
}

func (b *fakeBase) put(ino uint64, body []byte) { b.body[ino] = body }

func (b *fakeBase) ContentOf(_ context.Context, ino uint64) (genfs.Content, error) {
	body, ok := b.body[ino]
	if !ok {
		return genfs.Content{}, fmt.Errorf("no inode %d", ino)
	}
	out := genfs.Content{Length: int64(len(body))}
	h := chunkid.NewHasher(nil)
	for off := 0; off < len(body); off += b.chunkSize {
		end := min(off+b.chunkSize, len(body))
		id := h.Sum(body[off:end])
		out.Refs = append(out.Refs, catalog.ChunkRef{
			Identity:      append([]byte(nil), id[:]...),
			LLen:          int64(end - off),
			CLen:          int64(end - off),
			LogicalOffset: int64(off),
		})
	}
	return out, nil
}

func (b *fakeBase) Read(_ context.Context, ino uint64, off int64, dst []byte) (int, error) {
	body, ok := b.body[ino]
	if !ok {
		return 0, fmt.Errorf("no inode %d", ino)
	}
	if off >= int64(len(body)) {
		return 0, nil
	}
	n := copy(dst, body[off:])
	b.readBytes += int64(n)
	return n, nil
}

func newBaseStore(t *testing.T, base Base) (*Store, *countingStore) {
	t.Helper()
	obj := newCountingStore()
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj, Base: base,
		Chunk: smallChunks, Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() }) //nolint:errcheck
	return s, obj
}

// The cost the write path exists to remove. The staging store makes a
// clean file writable by COPYING it — the whole file, on the first dirty
// byte, and for a file only the federation holds that copy is a download.
// Adopting it takes the records instead and moves nothing.
func TestAdoptTakesTheBaseByReferenceNotByCopy(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	body := fill(200000, 42)
	base.put(7, body)
	s, _ := newBaseStore(t, base)

	if err := s.Adopt(ctx, 7, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if base.readBytes != 0 {
		t.Errorf("adopting read %d bytes of the base; it should have read none", base.readBytes)
	}
	if st := s.Stats(); st.AdoptedFiles != 1 || st.AdoptedBytes != int64(len(body)) {
		t.Errorf("stats = %d files / %d bytes, want 1 / %d", st.AdoptedFiles, st.AdoptedBytes, len(body))
	}
	if got := s.Size(7); got != int64(len(body)) {
		t.Errorf("size = %d, want %d", got, len(body))
	}

	// It seals with no work at all: the base's records tile, because that
	// is how the base published them.
	refs, err := s.ChunkRefs(7)
	if err != nil {
		t.Fatalf("ChunkRefs on an untouched adopted file: %v", err)
	}
	want, err := base.ContentOf(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != len(want.Refs) {
		t.Fatalf("%d rows, want the base's %d", len(refs), len(want.Refs))
	}
	for i, r := range refs {
		w := want.Refs[i]
		if !bytes.Equal(r.Identity, w.Identity) || r.LLen != w.LLen || r.CLen != w.CLen || r.LogicalOffset != w.LogicalOffset {
			t.Fatalf("row %d = %+v, want the base's %+v", i, r, w)
		}
	}
	// And it reads back through the store, which is what a mount does.
	if got := readAll(t, s, 7); !bytes.Equal(got, body) {
		t.Fatal("an adopted file does not read back byte-exact")
	}
}

// A write into an adopted file costs the rewrite, not the file: the
// chunks it did not touch stay the base's own rows, and only the span it
// disturbed is chunked again.
func TestWritingIntoAnAdoptedFileCostsOnlyTheRewrite(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	body := fill(200000, 43)
	base.put(9, body)
	s, obj := newBaseStore(t, base)

	if err := s.Adopt(ctx, 9, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	patch := fill(300, 44)
	if err := s.Write(ctx, 9, 5000, patch); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), body...)
	copy(want[5000:], patch)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 9)
	if err != nil {
		t.Fatalf("seal inode 9: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}

	// The rows must cover the file exactly, in order.
	var at int64
	for i, r := range refs {
		if r.LogicalOffset != at {
			t.Fatalf("row %d starts at %d, want %d", i, r.LogicalOffset, at)
		}
		at += r.LLen
	}
	if at != int64(len(want)) {
		t.Fatalf("rows cover %d bytes, want %d", at, len(want))
	}

	// Most of them are still the base's own rows: identity for identity.
	baseContent, err := base.ContentOf(ctx, 9)
	if err != nil {
		t.Fatal(err)
	}
	fromBase := map[string]bool{}
	for _, r := range baseContent.Refs {
		fromBase[hex.EncodeToString(r.Identity)] = true
	}
	carried := 0
	for _, r := range refs {
		if fromBase[hex.EncodeToString(r.Identity)] {
			carried++
		}
	}
	if carried < len(baseContent.Refs)-2 {
		t.Errorf("only %d of %d base rows survived a 300-byte patch", carried, len(baseContent.Refs))
	}

	st := s.Stats()
	t.Logf("a %d-byte patch in an adopted %d-byte file: %d bytes re-chunked, %d base rows of %d carried",
		len(patch), len(body), st.RechunkedBytes, carried, len(baseContent.Refs))
	if bound := int64(len(patch)) + 2*int64(base.chunkSize); st.RechunkedBytes > bound {
		t.Errorf("re-chunked %d bytes, bound is %d", st.RechunkedBytes, bound)
	}
	// The only base bytes read are the ones re-chunking needed.
	if base.readBytes > st.RechunkedBytes {
		t.Errorf("read %d base bytes to re-chunk %d", base.readBytes, st.RechunkedBytes)
	}
	if got := readAll(t, s, 9); !bytes.Equal(got, want) {
		t.Fatal("an adopted-and-patched file does not read back byte-exact")
	}
	_ = obj
}

// Overwriting an adopted file completely must leave nothing of the base
// behind — the whole point of the extent map is that superseded ranges
// stop being referenced.
func TestOverwritingAnAdoptedFileDropsTheBaseEntirely(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	base.put(3, fill(40000, 45))
	s, _ := newBaseStore(t, base)

	if err := s.Adopt(ctx, 3, 40000); err != nil {
		t.Fatal(err)
	}
	want := fill(40000, 46)
	if err := s.Write(ctx, 3, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChunkRefs(3); err != nil {
		t.Fatalf("a wholly rewritten file should tile on its own: %v", err)
	}
	if st := s.Stats(); st.RechunkedSpans != 0 {
		t.Errorf("re-chunked %d spans for a file that was replaced outright", st.RechunkedSpans)
	}
	if got := readAll(t, s, 3); !bytes.Equal(got, want) {
		t.Fatal("the rewritten file does not read back byte-exact")
	}
}

// Truncating an adopted file to a shorter length keeps the surviving
// prefix by reference. A shrink that landed inside a chunk is the same
// partial-chunk problem a write makes, and gets the same answer.
func TestAdoptRespectsATruncatedLength(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	body := fill(100000, 47)
	base.put(5, body)
	s, _ := newBaseStore(t, base)

	const keep = 30000
	if err := s.Adopt(ctx, 5, keep); err != nil {
		t.Fatal(err)
	}
	if got := s.Size(5); got != keep {
		t.Fatalf("size = %d, want %d", got, keep)
	}
	if got := readAll(t, s, 5); !bytes.Equal(got, body[:keep]) {
		t.Fatal("the truncated prefix does not read back")
	}
	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	var at int64
	for _, r := range refs {
		at += r.LLen
	}
	if at != keep {
		t.Fatalf("rows cover %d bytes, want %d", at, keep)
	}
}

// adoptedCount is len(baseRefs) under the lock. The state this is about
// is invisible from outside the package, which is exactly why nothing
// noticed it accumulating.
func adoptedCount(s *Store) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.baseRefs)
}

// A baseRefs entry has no other owner: nothing on the federation has ever
// heard of an adopted handle, so an entry the store does not collect is
// one per file the session ever adopted, held until unmount.
func TestAdoptedExtentsAreCollectedWhenNothingNamesThem(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	for ino := uint64(1); ino <= 4; ino++ {
		base.put(ino, fill(20000, ino))
	}
	s, _ := newBaseStore(t, base)
	for ino := uint64(1); ino <= 4; ino++ {
		if err := s.Adopt(ctx, ino, 20000); err != nil {
			t.Fatal(err)
		}
	}
	if n := adoptedCount(s); n != 4 {
		t.Fatalf("%d adopted extents after adopting four files", n)
	}

	// The three ways a handle loses its last reference.
	if err := s.Write(ctx, 1, 0, fill(20000, 101)); err != nil {
		t.Fatal(err)
	}
	if err := s.Truncate(2, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(3); err != nil {
		t.Fatal(err)
	}
	if n := adoptedCount(s); n != 1 {
		t.Fatalf("%d adopted extents after overwriting, truncating and forgetting three of the four", n)
	}

	// A patch in the middle SPLITS the ref in two and both still name the
	// handle, so a scheme that collected on the first delta would strand
	// the surviving ranges.
	patch := fill(100, 104)
	if err := s.Write(ctx, 4, 8000, patch); err != nil {
		t.Fatal(err)
	}
	if n := adoptedCount(s); n != 1 {
		t.Fatalf("%d adopted extents after a patch that left most of the file adopted", n)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), base.body[4]...)
	copy(want[8000:], patch)
	if got := readAll(t, s, 4); !bytes.Equal(got, want) {
		t.Fatal("the patched adopted file does not read back byte-exact")
	}

	if err := s.Truncate(4, 0); err != nil {
		t.Fatal(err)
	}
	if n := adoptedCount(s); n != 0 {
		t.Errorf("%d adopted extents left after every file that used one was replaced", n)
	}
}

// A frozen view names extents the live map may have dropped since, so
// collection counts its copies too. Without that a checkpoint could not
// render a file the mount overwrote while it ran — the view would resolve
// to an adopted handle the store had already forgotten it borrowed.
func TestAFrozenViewKeepsAnAdoptedExtentAlive(t *testing.T) {
	ctx := context.Background()
	base := newFakeBase()
	body := fill(30000, 61)
	base.put(7, body)
	s, _ := newBaseStore(t, base)

	if err := s.Adopt(ctx, 7, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	f, err := s.Freeze(ctx)
	if err != nil {
		t.Fatal(err)
	}

	replacement := fill(30000, 62)
	if err := s.Write(ctx, 7, 0, replacement); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := adoptedCount(s); n != 1 {
		t.Fatalf("%d adopted extents while a frozen view still names one", n)
	}

	got := make([]byte, f.Size(7))
	if _, err := f.Read(ctx, 7, 0, got); err != nil {
		t.Fatalf("reading the frozen view after the live file was replaced: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("the frozen view does not resolve to the adopted bytes")
	}
	if live := readAll(t, s, 7); !bytes.Equal(live, replacement) {
		t.Fatal("the live file does not read back as the replacement")
	}

	f.Release()
	if n := adoptedCount(s); n != 0 {
		t.Errorf("%d adopted extents after the last view of one was released", n)
	}
}

// A store with no base cannot adopt, and must say so rather than
// inventing empty content.
func TestAdoptWithoutABaseIsAnError(t *testing.T) {
	s, _ := newTestStore(t, 1<<20, Hooks{})
	if err := s.Adopt(context.Background(), 1, 10); err == nil {
		t.Fatal("adopting without a base succeeded")
	}
}
