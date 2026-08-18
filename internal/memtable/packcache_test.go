package memtable

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The claim that decides whether the staging directory can go away: once
// content has left the ring, it is still readable — and still
// RE-CHUNKABLE at seal — without the federation. Staging gives that for
// free today by keeping every dirty file on local disk; the write path
// has to give it some other way, and the way is that a pack this session
// wrote is kept rather than deleted after its upload.
//
// Counting Gets is the only honest form of this test. Everything here
// works whether or not the bytes come off the wire; the point is that
// they do not.
func TestSealNeverFetchesBackWhatThisSessionWrote(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})

	want := fill(200000, 11)
	if err := s.Write(ctx, 1, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// A patch landing inside a chunk that is already packed and uploaded:
	// the seal must re-chunk it, which means reading the straddling chunk
	// back from somewhere.
	patch := fill(300, 12)
	if err := s.Write(ctx, 1, 5000, patch); err != nil {
		t.Fatal(err)
	}
	copy(want[5000:], patch)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	before := obj.getCount()
	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if got := obj.getCount(); got != before {
		t.Errorf("the seal fetched %d objects to re-chunk content this session wrote", got-before)
	}
	if st := s.Stats(); st.RechunkedSpans == 0 {
		t.Fatal("nothing was re-chunked, so this test proved nothing")
	} else if st.PackReadsRemote != 0 {
		t.Errorf("%d pack reads went to the federation", st.PackReadsRemote)
	}

	// readThroughFormat goes to the federation on purpose — it is the
	// check that the packs really are the format's packs — so it runs
	// after the accounting above.
	if got := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(got, want) {
		t.Fatal("the sealed rows do not read back through the format")
	}
}

// Reading packed content is served locally too, which is what makes the
// same guarantee hold for a file this session did not write: opening it
// to edit it is what pulls its chunks in.
func TestReadsOfPackedContentAreServedLocally(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	want := fill(150000, 21)
	if err := s.Write(ctx, 2, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	before := obj.getCount()
	for i := 0; i < 3; i++ {
		if got := readAll(t, s, 2); !bytes.Equal(got, want) {
			t.Fatal("packed content does not read back")
		}
	}
	if got := obj.getCount(); got != before {
		t.Errorf("%d federation reads for content this session wrote", got-before)
	}
	if st := s.Stats(); st.PackReadsLocal == 0 {
		t.Error("nothing was read from the local copy, so this test proved nothing")
	}
}

// A cache smaller than the session evicts, and eviction must cost speed
// rather than correctness: the content still reads, from the federation.
func TestPackCacheEvictsAndFallsBackToTheFederation(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	dir := t.TempDir()
	s, err := New(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
		// Room for roughly one pack, so writing several evicts the rest.
		PackCacheBytes: 8 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	want := make(map[uint64][]byte)
	for ino := uint64(1); ino <= 6; ino++ {
		want[ino] = fill(40000, ino)
		if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ents, err := os.ReadDir(filepath.Join(dir, "packs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) >= len(want) {
		t.Errorf("the cache kept %d packs against a cap of about one; it is not evicting", len(ents))
	}
	for ino, v := range want {
		if got := readAll(t, s, ino); !bytes.Equal(got, v) {
			t.Fatalf("inode %d does not read back after its pack was evicted", ino)
		}
	}
	if st := s.Stats(); st.PackReadsRemote == 0 {
		t.Error("nothing came back off the wire, so eviction was not exercised")
	}
}

// Turning the cache off must leave a working store, because the federation
// is always the authority — the cache is only ever an optimization.
func TestPackCacheCanBeDisabled(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	dir := t.TempDir()
	s, err := New(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
		PackCacheBytes: PackCacheDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck
	want := fill(50000, 31)
	if err := s.Write(ctx, 1, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "packs")); !os.IsNotExist(err) {
		t.Errorf("a disabled cache still made a pack directory (%v)", err)
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("content does not read back with the cache off")
	}
	if st := s.Stats(); st.PackReadsLocal != 0 {
		t.Errorf("%d reads were served locally with the cache off", st.PackReadsLocal)
	}
}
