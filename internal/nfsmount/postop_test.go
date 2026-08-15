package nfsmount

import (
	"io"
	"os"
	"testing"
)

// TestLstatReportsBufferedSize is the regression test for the git-clone
// truncation.
//
// go-nfs builds the post-op attributes of every WRITE reply with tryStat,
// which calls Lstat — not Stat. NFS clients treat those attributes as
// authoritative for a file's size and clamp their page cache to it. While a
// handle stays cached nothing flushes, so the metadata length stays at 0
// for the whole write (observed: meta=0 across a 59MB pack). An Lstat that
// skipped the buffered-size overlay therefore told the client the file was
// empty after every single write, and every later read hit a phantom EOF —
// which is what git reported as "premature end of pack file".
func TestLstatReportsBufferedSize(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	f, err := bfs.Create("/pack.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	const chunk = 32 << 10
	const rounds = 4
	payload := make([]byte, chunk)

	for i := 0; i < rounds; i++ {
		wf, err := bfs.OpenFile("/pack.tmp", os.O_RDWR, 0644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wf.(io.WriterAt).WriteAt(payload, int64(i*chunk)); err != nil {
			t.Fatal(err)
		}
		if err := wf.Close(); err != nil {
			t.Fatal(err)
		}

		want := int64((i + 1) * chunk)
		// Both must agree: Stat is what go-nfs sizes a READ from, Lstat is
		// what it reports to the client after a WRITE.
		st, err := bfs.Stat("/pack.tmp")
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != want {
			t.Fatalf("round %d: Stat size = %d, want %d", i, st.Size(), want)
		}
		lst, err := bfs.Lstat("/pack.tmp")
		if err != nil {
			t.Fatal(err)
		}
		if lst.Size() != want {
			t.Fatalf("round %d: Lstat size = %d, want %d — post-op attrs would tell "+
				"the client the file is this short, truncating it", i, lst.Size(), want)
		}
	}
}

// TestLstatMtimeTracksWritesOnly guards the other half of the post-op
// attributes: clients decide whether their cached pages are still valid by
// comparing mtime, so it must move when data changes and stay put when it
// does not.
func TestLstatMtimeTracksWritesOnly(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	f, err := bfs.Create("/m.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	first, err := bfs.Lstat("/m.bin")
	if err != nil {
		t.Fatal(err)
	}

	// A read-only open must not look like a modification.
	rf, err := bfs.Open("/m.bin")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(rf)
	rf.Close()

	after, err := bfs.Lstat("/m.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(first.ModTime()) {
		t.Fatalf("mtime moved on a read (%v -> %v); a client would treat its cached "+
			"pages as invalidated by another writer", first.ModTime(), after.ModTime())
	}
}
