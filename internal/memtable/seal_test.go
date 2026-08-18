package memtable

import (
	"bytes"
	"context"
	"testing"
)

// The case ChunkRefs refuses, sealed. A write landing inside an already
// packed extent leaves the file wanting part of a chunk, which no
// ChunkRef can say — so the seal re-chunks that span from the bytes as
// they now read, and the file goes out whole.
//
// The assertion that matters is not that it works but that it is CHEAP:
// re-chunking is bounded by the rewrite plus the chunks straddling its
// ends, so a 300-byte patch in the middle of a 200 KiB file must not cost
// anything like 200 KiB of re-chunking. If that bound ever breaks, this
// path is just staging's whole-file re-chunk wearing a different name.
func TestSealRechunksAPartiallyOverwrittenExtent(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})

	want := fill(200000, 1)
	if err := s.Write(ctx, 1, 0, want); err != nil {
		t.Fatal(err)
	}
	patch := fill(300, 2)
	if err := s.Write(ctx, 1, 5000, patch); err != nil {
		t.Fatal(err)
	}
	copy(want[5000:], patch)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChunkRefs(1); err == nil {
		t.Fatal("ChunkRefs rendered a partially overwritten extent; it is supposed to refuse one")
	}

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatalf("seal inode 1: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("the sealed rows do not read back through the format")
	}

	st := s.Stats()
	if st.RechunkedSpans == 0 {
		t.Fatal("nothing was re-chunked, so this test proved nothing")
	}
	t.Logf("a %d-byte patch in a %d-byte file re-chunked %d bytes across %d spans",
		len(patch), len(want), st.RechunkedBytes, st.RechunkedSpans)
	// The span is the patch plus the two chunks straddling its ends, and
	// MaxSize bounds a chunk. Anything beyond that means the repair is
	// following the file rather than the rewrite.
	bound := int64(len(patch)) + 2*int64(smallChunks.MaxSize)
	if st.RechunkedBytes > bound {
		t.Errorf("re-chunked %d bytes for a %d-byte patch; the bound is %d (patch + two straddling chunks)",
			st.RechunkedBytes, len(patch), bound)
	}
	// And the content still reads back through the store itself, which is
	// what a mount would be doing while all this happened.
	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("the store's own read path disagrees with the sealed rows")
	}
}

// A seal must survive a file that is nothing but rewrites, and it must
// still be the rewrite that bounds the work rather than the file. Every
// version here is written before any flush, so the ring collapses them —
// the one that survives is the only one that can be sealed.
func TestSealRechunksRepeatedRewritesOnce(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})

	want := fill(120000, 7)
	if err := s.Write(ctx, 2, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// Three scattered patches, each landing inside a published chunk.
	for i, off := range []int64{1000, 40000, 90000} {
		p := fill(500, uint64(100+i))
		if err := s.Write(ctx, 2, off, p); err != nil {
			t.Fatal(err)
		}
		copy(want[off:], p)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 2)
	if err != nil {
		t.Fatalf("seal inode 2: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("the sealed rows do not read back through the format")
	}
	st := s.Stats()
	if st.RechunkedSpans == 0 {
		t.Fatal("nothing was re-chunked, so this test proved nothing")
	}
	t.Logf("three 500-byte patches in a %d-byte file re-chunked %d bytes across %d spans",
		len(want), st.RechunkedBytes, st.RechunkedSpans)
	bound := 3 * (500 + 2*int64(smallChunks.MaxSize))
	if st.RechunkedBytes > bound {
		t.Errorf("re-chunked %d bytes for three 500-byte patches; the bound is %d", st.RechunkedBytes, bound)
	}
}

// An append to a published file is the same shape with only a tail chunk,
// and it is the common one — so it had better not re-chunk the file.
func TestSealAppendsWithoutRechunkingTheFile(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})

	head := fill(150000, 3)
	if err := s.Write(ctx, 3, 0, head); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tail := fill(4000, 4)
	if err := s.Write(ctx, 3, int64(len(head)), tail); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 3)
	if err != nil {
		t.Fatalf("seal inode 3: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), head...), tail...)
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("an appended file does not read back through the format")
	}
	st := s.Stats()
	t.Logf("a %d-byte append to a %d-byte file re-chunked %d bytes across %d spans",
		len(tail), len(head), st.RechunkedBytes, st.RechunkedSpans)
	if st.RechunkedBytes > int64(len(tail))+2*int64(smallChunks.MaxSize) {
		t.Errorf("an append re-chunked %d bytes of a %d-byte file", st.RechunkedBytes, len(want))
	}
}

// A file nothing has disturbed must seal without re-chunking at all: the
// whole point of binding identity at flush is that a seal of untouched
// content moves no bytes.
func TestSealMovesNoBytesForUndisturbedContent(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	want := fill(90000, 5)
	if err := s.Write(ctx, 4, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := obj.stats()

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 4)
	if err != nil {
		t.Fatalf("seal inode 4: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.RechunkedSpans != 0 {
		t.Errorf("undisturbed content re-chunked %d spans (%d bytes)", st.RechunkedSpans, st.RechunkedBytes)
	}
	if after, _ := obj.stats(); after != before {
		t.Errorf("sealing undisturbed content uploaded %d objects", after-before)
	}
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("undisturbed content does not read back through the format")
	}
}
