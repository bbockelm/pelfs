package nfsmount

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestReadAtHonorsContract is the reproduction for the git-clone failure
// ("premature end of pack file, N bytes missing", several at once).
//
// io.ReaderAt requires ReadAt to fill the buffer or return a non-nil error.
// go-nfs's READ handler depends on that: it issues a single ReadAt and, on a
// request whose range reaches the end of the file, marks the reply EOF. A
// short count with a nil error is therefore reported to the client as
// "the file ends here" — truncating it from the client's point of view.
//
// jfs.File.Pread does not honor the contract: it can stop at a block
// boundary and return a short count with no error.
func TestReadAtHonorsContract(t *testing.T) {
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	defer bfs.hc.closeAll()

	// The test volume uses 4 MiB blocks; write enough to span several.
	const blockSize = 4 << 20
	const size = 3 * blockSize
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}

	f, err := bfs.Create("/spanning.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// Commit so reads come from the object store rather than the writer.
	if err := bfs.hc.closeAll(); err != nil {
		t.Fatal(err)
	}

	// Read buffers that straddle block boundaries — where JuiceFS is free to
	// return a partial count.
	for _, tc := range []struct {
		name string
		off  int64
		size int
	}{
		{"across first boundary", blockSize - 8<<10, 64 << 10},
		{"across second boundary", 2*blockSize - 32<<10, 128 << 10},
		{"large span", blockSize / 2, 2 * blockSize},
		{"tail of file", size - 64<<10, 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rf, err := bfs.Open("/spanning.bin")
			if err != nil {
				t.Fatal(err)
			}
			defer rf.Close()

			buf := make([]byte, tc.size)
			n, err := rf.(io.ReaderAt).ReadAt(buf, tc.off)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt: %v", err)
			}
			// The range is entirely within the file, so the contract
			// requires a full read with a nil error.
			if n != tc.size {
				t.Fatalf("ReadAt returned %d of %d bytes with err=%v; "+
					"go-nfs reports this to the client as EOF, truncating the file",
					n, tc.size, err)
			}
			if !bytes.Equal(buf, data[tc.off:tc.off+int64(tc.size)]) {
				t.Fatal("ReadAt returned wrong bytes")
			}
		})
	}
}
