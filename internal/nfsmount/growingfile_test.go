package nfsmount

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestReadBackWhileGrowing reproduces the git-clone failure ("premature end
// of pack file, N bytes missing", several at once from index-pack's
// threads). index-pack writes the pack and reads earlier offsets back while
// it is still being written, so the file grows between reads.
//
// JuiceFS clamps reads twice — to the length a handle recorded when it was
// opened, and to the length its reader recorded when that was opened — so
// any handle or reader that outlives a growth sees a short file.
func TestReadBackWhileGrowing(t *testing.T) {
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
	const rounds = 8
	payload := bytes.Repeat([]byte("G"), chunk)

	for i := 0; i < rounds; i++ {
		// Append one NFS-sized chunk the way onWrite does.
		wf, err := bfs.OpenFile("/pack.tmp", os.O_RDWR, 0644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wf.(io.Seeker).Seek(int64(i*chunk), io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := wf.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := wf.Close(); err != nil {
			t.Fatal(err)
		}

		want := int64((i + 1) * chunk)

		// Stat must report the new length...
		fi, err := bfs.Stat("/pack.tmp")
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != want {
			t.Fatalf("round %d: Stat size = %d, want %d", i, fi.Size(), want)
		}

		// ...and reading it back must return that many bytes. This is the
		// invariant git depends on and the one that was failing.
		got := readAll(t, bfs, "/pack.tmp")
		if int64(len(got)) != want {
			t.Fatalf("round %d: read %d bytes, want %d (%d missing) — "+
				"a stale handle/reader length is truncating the read",
				i, len(got), want, want-int64(len(got)))
		}

		// A ranged read of the freshly written tail must also work: this is
		// what index-pack does when resolving deltas.
		rf, err := bfs.Open("/pack.tmp")
		if err != nil {
			t.Fatal(err)
		}
		tail := make([]byte, 4096)
		n, err := rf.(io.ReaderAt).ReadAt(tail, want-int64(len(tail)))
		rf.Close()
		if err != nil && err != io.EOF {
			t.Fatalf("round %d: ReadAt tail: %v", i, err)
		}
		if n != len(tail) {
			t.Fatalf("round %d: ReadAt tail returned %d of %d bytes", i, n, len(tail))
		}
	}
}
