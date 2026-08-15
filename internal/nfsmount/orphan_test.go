package nfsmount

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
)

// TestConcurrentFirstWritesShareOneHandle reproduces the git-clone
// truncation, which the PELFS_NFS_NO_HANDLE_CACHE bisect pinned on the
// write-handle cache.
//
// A kernel NFS client issues concurrent WRITE RPCs for one file. When none
// of them finds a cached handle yet, each opens its own, and only the last
// one wins the cache; the others become orphans. Writes through an orphan
// are invisible to the cached handle's length view (jfs.File caches the
// length it saw at open and only advances it for its own writes), and
// pread clamps every read to that stale length — so the file reads back
// short even though every byte was written.
func TestConcurrentFirstWritesShareOneHandle(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	f, err := bfs.Create("/pack.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	const chunk = 32 << 10
	const writers = 8
	want := make([]byte, writers*chunk)
	for i := range want {
		want[i] = byte(i % 251)
	}

	// All writers start together, mimicking concurrent WRITE RPCs on a file
	// that has no cached handle yet.
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < writers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			wf, err := bfs.OpenFile("/pack.bin", os.O_RDWR, 0644)
			if err != nil {
				t.Errorf("writer %d open: %v", i, err)
				return
			}
			off := int64(i * chunk)
			if _, err := wf.(io.WriterAt).WriteAt(want[off:off+chunk], off); err != nil {
				t.Errorf("writer %d write: %v", i, err)
			}
			if err := wf.Close(); err != nil {
				t.Errorf("writer %d close: %v", i, err)
			}
		}(i)
	}
	start.Done()
	done.Wait()

	// Exactly one handle may be cached for the path; orphans are the bug.
	bfs.hc.mu.Lock()
	cached := len(bfs.hc.entries)
	bfs.hc.mu.Unlock()
	if cached > 1 {
		t.Fatalf("%d handles cached for one path; orphaned handles hide writes", cached)
	}

	fi, err := bfs.Stat("/pack.bin")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(want)) {
		t.Fatalf("Stat size = %d, want %d", fi.Size(), len(want))
	}
	got := readAll(t, bfs, "/pack.bin")
	if len(got) != len(want) {
		t.Fatalf("read %d bytes, wrote %d (%d missing) — a stale handle length is truncating the read",
			len(got), len(want), len(want)-len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("content mismatch")
	}
}
