package nfsmount

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	jfs "github.com/juicedata/juicefs/pkg/fs"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/version"
	"github.com/juicedata/juicefs/pkg/vfs"
	"github.com/prometheus/client_golang/prometheus"
	nfsfile "github.com/willscott/go-nfs/file"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// newTestVolume formats a JuiceFS volume against a fakeorigin and returns
// its pkg/fs layer.
func newTestVolume(t *testing.T) *jfs.FileSystem {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	store, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatal(err)
	}

	metaConf := meta.DefaultConf()
	metaConf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+filepath.Join(t.TempDir(), "meta.db"), metaConf)
	format := &meta.Format{
		Name:      "nfstest",
		UUID:      "00000000-0000-0000-0000-00000000000f",
		Storage:   "pelican",
		Bucket:    srv.URL + "/vol",
		BlockSize: 4096,
		DirStats:  true,
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	loaded, err := m.Load(true)
	if err != nil {
		t.Fatal(err)
	}

	chunkConf := chunk.Config{
		BlockSize:  loaded.BlockSize * 1024,
		GetTimeout: time.Minute, PutTimeout: time.Minute,
		MaxUpload: 4, MaxDownload: 4, MaxRetries: 2,
		BufferSize: 32 << 20,
		CacheDir:   t.TempDir(), CacheSize: 100 << 20, FreeSpace: 0.01,
		CacheMode: 0600, CacheFullBlock: true, CacheChecksum: "full",
		CacheEviction: "2-random", AutoCreate: true,
	}
	chunkConf.SelfCheck(loaded.UUID)
	registry := prometheus.NewRegistry()
	cstore := chunk.NewCachedStore(store, chunkConf, nil)
	m.OnMsg(meta.DeleteSlice, func(args ...interface{}) error {
		return cstore.Remove(args[0].(uint64), int(args[1].(uint32)))
	})
	m.OnMsg(meta.CompactChunk, func(args ...interface{}) error {
		return vfs.Compact(chunkConf, cstore, args[0].([]meta.Slice), args[1].(uint64), args[2].(uint8))
	})
	if err := m.NewSession(true); err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { _ = m.CloseSession() })

	vfsConf := &vfs.Config{
		Meta:     metaConf,
		Format:   *loaded,
		Version:  version.Version(),
		Chunk:    &chunkConf,
		Security: &vfs.SecurityConfig{},
		Port:     &vfs.Port{},
		Pid:      os.Getpid(),
		PPid:     os.Getppid(),
		UMask:    0022,
	}
	fsys, err := jfs.NewFileSystem(vfsConf, m, cstore, registry)
	if err != nil {
		t.Fatalf("NewFileSystem: %v", err)
	}
	return fsys
}

func TestBillyFSRoundtrip(t *testing.T) {
	b := NewBillyFS(newTestVolume(t), uint32(os.Getuid()), uint32(os.Getgid()))

	// Create + write + read back.
	f, err := b.Create("/hello.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("hello nfs world")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err = b.Open("/hello.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := io.ReadAll(f)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAll: %v", err)
	}
	f.Close()
	if string(data) != "hello nfs world" {
		t.Fatalf("roundtrip = %q", data)
	}

	// ReadAt at an offset.
	f, _ = b.Open("/hello.txt")
	buf := make([]byte, 3)
	if n, err := f.ReadAt(buf, 6); err != nil && err != io.EOF || n != 3 {
		t.Fatalf("ReadAt: n=%d err=%v", n, err)
	}
	f.Close()
	if string(buf) != "nfs" {
		t.Fatalf("ReadAt = %q", buf)
	}

	// Directories, rename, remove, stat.
	if err := b.MkdirAll("/a/b/c", 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := b.Rename("/hello.txt", "/a/b/c/moved.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	fi, err := b.Stat("/a/b/c/moved.txt")
	if err != nil || fi.Size() != 15 {
		t.Fatalf("Stat after rename: fi=%v err=%v", fi, err)
	}
	entries, err := b.ReadDir("/a/b/c")
	if err != nil || len(entries) != 1 || entries[0].Name() != "moved.txt" {
		t.Fatalf("ReadDir = %v, %v", entries, err)
	}
	if _, err := b.Stat("/hello.txt"); !os.IsNotExist(err) {
		t.Fatalf("old name should be gone, got %v", err)
	}

	// Symlinks.
	if err := b.Symlink("a/b/c/moved.txt", "/link"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if target, err := b.Readlink("/link"); err != nil || target != "a/b/c/moved.txt" {
		t.Fatalf("Readlink = %q, %v", target, err)
	}

	// Truncate + append semantics.
	f, err = b.OpenFile("/a/b/c/moved.txt", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("OpenFile append: %v", err)
	}
	if _, err := f.Write([]byte("!")); err != nil {
		t.Fatalf("append Write: %v", err)
	}
	f.Close()
	if fi, _ := b.Stat("/a/b/c/moved.txt"); fi.Size() != 16 {
		t.Fatalf("append size = %d", fi.Size())
	}

	// Chtimes (SETATTR path).
	when := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := b.(interface {
		Chtimes(string, time.Time, time.Time) error
	}).Chtimes("/a/b/c/moved.txt", when, when); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	if fi, _ := b.Stat("/a/b/c/moved.txt"); !fi.ModTime().Equal(when) {
		t.Fatalf("mtime = %v, want %v", fi.ModTime(), when)
	}

	// Remove file and directory.
	if err := b.Remove("/a/b/c/moved.txt"); err != nil {
		t.Fatalf("Remove file: %v", err)
	}
	if err := b.Remove("/a/b/c"); err != nil {
		t.Fatalf("Remove dir: %v", err)
	}
	if err := b.Remove("/no/such"); !os.IsNotExist(err) {
		t.Fatalf("Remove missing: %v", err)
	}
}

// TestBillyFSTempFile exercises the O_EXCL create path go-nfs uses.
func TestBillyFSTempFile(t *testing.T) {
	b := NewBillyFS(newTestVolume(t), uint32(os.Getuid()), uint32(os.Getgid()))
	f, err := b.TempFile("/", "tmp-")
	if err != nil {
		t.Fatalf("TempFile: %v", err)
	}
	name := f.Name()
	f.Close()
	if _, err := b.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600); !os.IsExist(err) {
		t.Fatalf("O_EXCL on existing file: %v", err)
	}
}

// TestForeignOwnedFileWritable is the vim-on-macOS regression: files created
// by other sessions (e.g. the Docker fallback, which runs as root) carry
// foreign uids in the volume metadata. The NFS adapter must still be able to
// write them — it operates as superuser and presents ownership as the
// mounting user.
func TestForeignOwnedFileWritable(t *testing.T) {
	fsys := newTestVolume(t)

	// Create a file owned by a foreign uid (simulating a root/other-session
	// creation), mode 0644.
	foreign := meta.NewContext(uint32(os.Getpid()), 12345, []uint32{12345})
	f, errno := fsys.Create(foreign, "/docker-made.txt", 0644, 022)
	if errno != 0 {
		t.Fatalf("foreign create: %v", errno)
	}
	if _, errno := f.Pwrite(foreign, []byte("original"), 0); errno != 0 {
		t.Fatalf("foreign write: %v", errno)
	}
	if errno := f.Close(foreign); errno != 0 {
		t.Fatalf("foreign close: %v", errno)
	}

	b := NewBillyFS(fsys, 501, 20)

	// Append through the adapter (what `echo foo >> file` does).
	bf, err := b.OpenFile("/docker-made.txt", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("adapter open for append: %v", err)
	}
	if _, err := bf.Write([]byte(" appended")); err != nil {
		t.Fatalf("adapter append: %v", err)
	}
	bf.Close()

	// Truncate-rewrite through the adapter (what vim's save does).
	bf, err = b.OpenFile("/docker-made.txt", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("adapter open for truncate: %v", err)
	}
	if _, err := bf.Write([]byte("rewritten")); err != nil {
		t.Fatalf("adapter rewrite: %v", err)
	}
	bf.Close()

	bf, _ = b.Open("/docker-made.txt")
	data, err := io.ReadAll(bf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	bf.Close()
	if string(data) != "rewritten" {
		t.Fatalf("content = %q, want %q", data, "rewritten")
	}

	// Ownership is presented as the mounting user, with a real inode.
	fi, err := b.Stat("/docker-made.txt")
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := fi.Sys().(*nfsfile.FileInfo)
	if !ok {
		t.Fatalf("Sys() type = %T, want *nfsfile.FileInfo", fi.Sys())
	}
	if sys.UID != 501 || sys.GID != 20 {
		t.Fatalf("presented owner = %d:%d, want 501:20", sys.UID, sys.GID)
	}
	if sys.Fileid == 0 {
		t.Fatal("Fileid should be the real inode, not zero")
	}
}
