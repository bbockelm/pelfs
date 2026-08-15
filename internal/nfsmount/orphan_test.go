package nfsmount

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/juicedata/juicefs/pkg/vfs"
)

// TestAddRefusesSecondHandle pins the single-handle invariant directly,
// without depending on hitting the (very narrow) race window in OpenFile:
// once a path has a cached handle, a second one offered for the same path
// must be refused so the caller closes it, because writes through a second
// handle are invisible to the first handle's length view.
func TestAddRefusesSecondHandle(t *testing.T) {
	if nfsNoHandleCache {
		t.Skip("handle cache disabled via PELFS_NFS_NO_HANDLE_CACHE")
	}
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	if f, err := bfs.Create("/x.bin"); err != nil {
		t.Fatal(err)
	} else if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Create leaves its own handle cached; drop it so this test starts from
	// an empty cache for the path.
	if err := bfs.hc.invalidate("/x.bin"); err != nil {
		t.Fatal(err)
	}

	h1, errno := bfs.fs.Open(bfs.ctx, "/x.bin", vfs.MODE_MASK_W)
	if errno != 0 {
		t.Fatal(errno)
	}
	h2, errno := bfs.fs.Open(bfs.ctx, "/x.bin", vfs.MODE_MASK_W)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer h2.Close(bfs.ctx)

	e1, mine := bfs.hc.add("/x.bin", h1, 0)
	if !mine || e1 == nil {
		t.Fatal("first handle for a path must be cached")
	}
	e2, mine := bfs.hc.add("/x.bin", h2, 0)
	if mine {
		t.Fatal("second handle for the same path was cached; its writes would be " +
			"invisible to the first handle and reads would clamp short")
	}
	if e2 != e1 {
		t.Fatal("the incumbent handle must be returned so the caller can use it")
	}
}

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
