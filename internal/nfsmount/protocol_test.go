package nfsmount

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"

	nfs "github.com/willscott/go-nfs"
	nfsc "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// dialTestServer runs the real go-nfs server over a real socket against our
// billyFS and returns a connected NFS client. Every earlier test in this
// package drove billyFS directly, bypassing go-nfs's own handlers — which is
// exactly where the write/read/EOF logic that git trips over lives.
func dialTestServer(t *testing.T) (*nfsc.Target, *billyFS) {
	t.Helper()
	fsys, _ := newTestVolumeWithRoot(t)
	bfs := NewBillyFS(fsys, uint32(os.Getuid()), uint32(os.Getgid())).(*billyFS)
	t.Cleanup(func() { _ = bfs.Close() })

	// The root must exist for the handler to resolve it.
	if f, err := bfs.Create("/.anchor"); err == nil {
		f.Close()
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	handler := nfshelper.NewCachingHandler(nfshelper.NewNullAuthHandler(bfs), 1024)
	go func() { _ = nfs.Serve(ln, handler) }()

	// go-nfs-client binds a local port explicitly, so repeated runs can
	// collide with one in TIME_WAIT; retry rather than reporting a port
	// clash as a filesystem failure.
	var c *rpc.Client
	for attempt := 0; attempt < 50; attempt++ {
		if c, err = rpc.DialTCP(ln.Addr().Network(), ln.Addr().(*net.TCPAddr).String(), false); err == nil {
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
	return target, bfs
}

// TestProtocolWriteThenReadBack drives a file through the real NFS protocol
// the way git does: many small writes, then a full read-back. A short read
// here is the server telling the client the file ends early — the
// "premature end of pack file" a git clone reports.
func TestProtocolWriteThenReadBack(t *testing.T) {
	target, _ := dialTestServer(t)

	const size = 2 << 20
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}

	w, err := target.OpenFile("/pack.bin", 0644)
	if err != nil {
		t.Fatalf("open for write: %v", err)
	}
	// io.Copy issues a sequence of NFS WRITE RPCs, as the kernel client does.
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close after write: %v", err)
	}

	r, err := target.Open("/pack.bin")
	if err != nil {
		t.Fatalf("open for read: %v", err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("read %d bytes over NFS, wrote %d (%d missing)",
			len(got), len(data), len(data)-len(got))
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch over NFS")
	}
}

// TestProtocolInterleavedWriteRead mimics index-pack: read earlier offsets
// back while the file is still being appended to.
func TestProtocolInterleavedWriteRead(t *testing.T) {
	target, _ := dialTestServer(t)

	const chunk = 64 << 10
	const rounds = 16
	payload := make([]byte, chunk)
	for i := range payload {
		payload[i] = byte(i % 253)
	}

	w, err := target.OpenFile("/live.bin", 0644)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rounds; i++ {
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("round %d write: %v", i, err)
		}
		want := (i + 1) * chunk

		// Read the whole file back mid-stream, as index-pack does.
		r, err := target.Open("/live.bin")
		if err != nil {
			t.Fatalf("round %d open: %v", i, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("round %d read: %v", i, err)
		}
		if len(got) != want {
			t.Fatalf("round %d: read %d bytes over NFS, file should be %d (%d missing)",
				i, len(got), want, want-len(got))
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
