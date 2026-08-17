package nfsmount

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"

	nfs "github.com/willscott/go-nfs"
	nfsc "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// serveTestFS starts the real go-nfs server on our billyFS and returns a
// dialer for independent client connections, so goroutines can issue truly
// concurrent RPCs the way a kernel client's threads do.
func serveTestFS(t *testing.T) (dial func() *nfsc.Target, bfs *billyFS) {
	t.Helper()
	fsys, _ := newTestVolumeWithRoot(t)
	bfs = NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	t.Cleanup(func() { _ = bfs.Close() })
	if f, err := bfs.Create("/.anchor"); err == nil {
		f.Close()
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	handler := newHandles(nfshelper.NewNullAuthHandler(bfs), 1024)
	go func() { _ = nfs.Serve(ln, handler) }()

	addr := ln.Addr().(*net.TCPAddr).String()
	return func() *nfsc.Target {
		// go-nfs-client binds a local port explicitly, so repeated runs can
		// transiently collide with one in TIME_WAIT; retry rather than
		// reporting a port clash as a filesystem failure.
		var c *rpc.Client
		var err error
		for attempt := 0; attempt < 50; attempt++ {
			c, err = rpc.DialTCP("tcp", addr, false)
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		var mounter nfsc.Mount
		mounter.Client = c
		target, err := mounter.Mount("/", rpc.AuthNull)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mounter.Unmount() })
		return target
	}, bfs
}

// TestProtocolConcurrentReadDuringWrite is the closest reproduction of the
// git-clone failure available without a kernel mount: index-pack appends to
// the pack while several threads read earlier offsets back, so the server
// sees concurrent WRITE and READ RPCs on one growing file. Each reader
// asserts the invariant git depends on — a read of a range that is entirely
// within the file must return every byte, because go-nfs turns a short read
// at the end of a request into an EOF the client believes.
func TestProtocolConcurrentReadDuringWrite(t *testing.T) {
	dial, _ := serveTestFS(t)

	const chunk = 64 << 10
	const rounds = 24
	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	writer := dial()
	w, err := writer.OpenFile("/pack.bin", 0644)
	if err != nil {
		t.Fatal(err)
	}

	var written int64 // bytes durably requested so far
	var mu sync.RWMutex
	stop := make(chan struct{})
	errs := make(chan string, 16)
	var wg sync.WaitGroup

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			target := dial()
			for {
				select {
				case <-stop:
					return
				default:
				}
				mu.RLock()
				size := written
				mu.RUnlock()
				if size == 0 {
					continue
				}
				rf, err := target.Open("/pack.bin")
				if err != nil {
					continue
				}
				got, err := io.ReadAll(rf)
				rf.Close()
				if err != nil {
					continue
				}
				// The file is only ever appended to, so a read must never
				// come back shorter than what was already written.
				if int64(len(got)) < size {
					select {
					case errs <- fmt.Sprintf("reader %d: read %d bytes, at least %d were written (%d missing)",
						id, len(got), size, size-int64(len(got))):
					default:
					}
					return
				}
			}
		}(r)
	}

	for i := 0; i < rounds; i++ {
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		mu.Lock()
		written = int64((i + 1) * chunk)
		mu.Unlock()
	}
	close(stop)
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-errs:
		t.Fatal(msg)
	default:
	}

	// Final content must be exactly what we wrote.
	final := dial()
	rf, err := final.Open("/pack.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat(payload, rounds)
	if len(got) != len(want) {
		t.Fatalf("final read %d bytes, wrote %d (%d missing)", len(got), len(want), len(want)-len(got))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("final content mismatch")
	}
}
