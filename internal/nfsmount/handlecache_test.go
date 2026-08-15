package nfsmount

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// nfsWritePattern simulates go-nfs's onWrite: open, seek, write one wsize
// chunk, close — for every RPC.
func nfsWritePattern(t *testing.T, bfs *billyFS, name string, data []byte, wsize int) {
	t.Helper()
	for off := 0; off < len(data); off += wsize {
		end := off + wsize
		if end > len(data) {
			end = len(data)
		}
		f, err := bfs.OpenFile(name, os.O_RDWR, 0644)
		if err != nil {
			t.Fatalf("open at %d: %v", off, err)
		}
		if _, err := f.(io.Seeker).Seek(int64(off), io.SeekStart); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close at %d: %v", off, err)
		}
	}
}

// TestWriteCoalescing is the regression test for the 32KB-objects bug:
// go-nfs's open-write-close-per-RPC pattern must not flush a tiny slice per
// 32KB write. With the handle cache, a 2MiB file written as 64 separate
// RPCs must land in the federation as a few large objects, not 64 tiny ones.
func TestWriteCoalescing(t *testing.T) {
	fsys, originRoot := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)

	// Create the file (as the NFS CREATE would), then stream 2MiB in 32KB
	// writes through fresh handles.
	f, err := bfs.Create("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), 2<<20/16)
	nfsWritePattern(t, bfs, "/big.bin", data, 32<<10)

	// Stat must reflect buffered writes without forcing a flush.
	fi, err := bfs.Stat("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(data)) {
		t.Fatalf("Stat size = %d before flush, want %d", fi.Size(), len(data))
	}

	// Read-back through a fresh read handle must see current data (this
	// also exercises the flush-on-read path).
	rf, err := bfs.Open("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("read-back mismatch: %d bytes", len(got))
	}

	// Let the janitor close the idle handle, then inspect what actually
	// landed in the federation.
	bfs.hc.closeAll()
	time.Sleep(100 * time.Millisecond)

	var objects, tiny int
	var largest int64
	err = filepath.Walk(filepath.Join(originRoot, "vol", "chunks"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		objects++
		if info.Size() <= 64<<10 {
			tiny++
		}
		if info.Size() > largest {
			largest = info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk origin: %v", err)
	}
	t.Logf("federation objects: %d (largest %d bytes, %d tiny)", objects, largest, tiny)
	// 2MiB coalesced: at most a handful of objects, dominated by large
	// blocks. The broken behavior produced 64 objects of 32KB each.
	if objects > 8 {
		t.Fatalf("write fragmentation: %d objects for a 2MiB file (want <= 8)", objects)
	}
	if largest < 1<<20 {
		t.Fatalf("largest object only %d bytes; writes are not coalescing", largest)
	}
}

// TestHandleCacheInvalidation covers rename/remove/truncate interaction
// with cached write handles.
func TestHandleCacheInvalidation(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)

	f, err := bfs.Create("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("buffered contents")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Rename with a dirty cached handle: data must follow the file.
	if err := bfs.Rename("/a.txt", "/b.txt"); err != nil {
		t.Fatal(err)
	}
	rf, err := bfs.Open("/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rf)
	rf.Close()
	if string(got) != "buffered contents" {
		t.Fatalf("after rename: %q", got)
	}

	// O_TRUNC reopen must not resurrect stale buffered state.
	f2, err := bfs.OpenFile("/b.txt", os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := f2.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := bfs.Stat("/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 3 {
		t.Fatalf("size after truncate+write = %d, want 3", fi.Size())
	}

	if err := bfs.Remove("/b.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/b.txt"); err == nil {
		t.Fatal("file still present after Remove")
	}
	bfs.hc.closeAll()
}
