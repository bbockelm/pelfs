package nfsmount

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"
)

// readAll opens name for reading the way go-nfs's READ handler does and
// returns the bytes it can retrieve.
func readAll(t *testing.T, bfs *billyFS, name string) []byte {
	t.Helper()
	f, err := bfs.Open(name)
	if err != nil {
		t.Fatalf("open for read: %v", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return data
}

// TestReadAfterBufferedWrite is the regression test for the truncated
// git-clone pack ("premature end of pack file, N bytes missing").
//
// The handle cache leaves writes buffered in the JuiceFS writer, and
// JuiceFS clamps reads to the length captured when the *reading* handle was
// opened. A reader that opens while a flush is still in flight therefore
// saw a short file. The invariant asserted here is the one git relies on:
// whatever size a Stat reports, reading the file must return at least that
// many bytes.
func TestReadAfterBufferedWrite(t *testing.T) {
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

	// Write like git receives a pack: many small NFS-sized writes, each
	// through its own open/write/close cycle, with no explicit sync.
	data := bytes.Repeat([]byte("pelfs-pack-data!"), 512<<10/16) // 512KiB
	nfsWritePattern(t, bfs, "/pack.tmp", data, 32<<10)

	// Immediately (no flush, no idle wait) the file must read back whole.
	fi, err := bfs.Stat("/pack.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(data)) {
		t.Fatalf("Stat size = %d, want %d", fi.Size(), len(data))
	}
	got := readAll(t, bfs, "/pack.tmp")
	if len(got) != len(data) {
		t.Fatalf("read %d bytes, Stat promised %d (%d missing)",
			len(got), fi.Size(), fi.Size()-int64(len(got)))
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch after buffered write")
	}
}

// TestCloseFlushesBufferedWrites covers the shutdown data-loss path: the
// handle cache holds writes in the JuiceFS writer, and
// jfs.FileSystem.Flush() does not flush open file writers, so tearing the
// mount down without closing the cache silently truncates every file
// written in the last few seconds.
func TestCloseFlushesBufferedWrites(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)

	f, err := bfs.Create("/tail.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("z"), 200<<10)
	nfsWritePattern(t, bfs, "/tail.bin", data, 32<<10)

	// Shut down immediately: the janitor has not run and nothing else has
	// flushed. Close must commit the buffered tail.
	if err := bfs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := readAll(t, bfs, "/tail.bin")
	if len(got) != len(data) {
		t.Fatalf("after shutdown flush: %d bytes, want %d (%d lost)",
			len(got), len(data), len(data)-len(got))
	}
}

// TestBillyFSExposesClose guards the untyped interface assertion the mount
// shutdown uses to find this method: if the assertion stops matching, the
// flush silently turns into a no-op and writes are lost again.
func TestBillyFSExposesClose(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	var bfs interface{} = NewBillyFS(fsys, 0, 0)
	if _, ok := bfs.(interface{ Close() error }); !ok {
		t.Fatal("billyFS no longer satisfies interface{ Close() error }; " +
			"mountfs.closeNFS would skip the buffered-write flush")
	}
}

// TestConcurrentReadDuringWrite drives readers against a file that is still
// being written, which is what surfaced the flush race: several readers
// arriving together could each skip the flush another had merely started.
// Run with -race for full value.
func TestConcurrentReadDuringWrite(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	f, err := bfs.Create("/live.bin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	const chunk = 32 << 10
	const chunks = 32
	payload := bytes.Repeat([]byte("A"), chunk)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	fail := make(chan string, 8)

	// Readers: continuously stat, then read, asserting no short read.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				fi, err := bfs.Stat("/live.bin")
				if err != nil {
					continue
				}
				promised := fi.Size()
				rf, err := bfs.Open("/live.bin")
				if err != nil {
					continue
				}
				data, err := io.ReadAll(rf)
				rf.Close()
				if err != nil {
					continue
				}
				if int64(len(data)) < promised {
					select {
					case fail <- fmt.Sprintf("short read: got %d bytes, Stat promised %d",
						len(data), promised):
					default:
					}
					return
				}
			}
		}()
	}

	// Writer: NFS-style open/write/close per chunk.
	for i := 0; i < chunks; i++ {
		wf, err := bfs.OpenFile("/live.bin", os.O_RDWR, 0644)
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
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-fail:
		t.Fatal(msg)
	default:
	}

	// Final state must be complete.
	got := readAll(t, bfs, "/live.bin")
	if len(got) != chunk*chunks {
		t.Fatalf("final size %d, want %d", len(got), chunk*chunks)
	}
}
