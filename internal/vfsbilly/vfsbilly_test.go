package vfsbilly_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	nfsfile "github.com/willscott/go-nfs/file"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

func newRW(t *testing.T, uuid string) (billy.Filesystem, *fixture) {
	t.Helper()
	fx := newFixture(t, uuid)
	return newBilly(openOverlay(t, fx)), fx
}

// newRWAs is newRW mounted as some other identity, for a test that needs a
// capability the ordinary fixture mount deliberately does not hold.
func newRWAs(t *testing.T, uuid string, cred vfsbilly.Cred) (billy.Filesystem, *fixture) {
	t.Helper()
	fx := newFixture(t, uuid)
	return vfsbilly.NewAs(openOverlay(t, fx), cred), fx
}

func names(fis []os.FileInfo) []string {
	out := make([]string, 0, len(fis))
	for _, fi := range fis {
		out = append(out, fi.Name())
	}
	return out
}

func readWhole(t *testing.T, bfs billy.Filesystem, name string) []byte {
	t.Helper()
	f, err := bfs.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close() //nolint:errcheck
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func writeWhole(t *testing.T, bfs billy.Filesystem, name string, data []byte) {
	t.Helper()
	f, err := bfs.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func TestStatLstatReadDir(t *testing.T) {
	bfs, fx := newRW(t, "1aaa1111-2222-3333-4444-555566667777")

	fi, err := bfs.Stat("/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Name() != "base.txt" || fi.IsDir() || fi.Size() != int64(len(fx.body["base.txt"])) {
		t.Fatalf("Stat /base.txt = %q dir=%v size=%d", fi.Name(), fi.IsDir(), fi.Size())
	}
	if fi.Mode().Perm() != 0644 || fi.Mode()&os.ModeType != 0 {
		t.Fatalf("Stat /base.txt mode = %v", fi.Mode())
	}
	if fi.ModTime().IsZero() || fi.ModTime().After(time.Now().Add(time.Minute)) {
		t.Fatalf("Stat /base.txt modtime = %v", fi.ModTime())
	}
	// The fileid go-nfs puts on the wire must be the real inode, not a
	// path hash: it has to survive a rename.
	if id := nfsfile.GetInfo(fi); id == nil || id.Fileid != fx.ino["base.txt"] {
		t.Fatalf("Sys() fileid = %+v, want inode %d", id, fx.ino["base.txt"])
	}

	if fi, err = bfs.Stat("/dir"); err != nil || !fi.IsDir() {
		t.Fatalf("Stat /dir = %v, %v", fi, err)
	}

	// Lstat stops at the link; Stat follows it.
	li, err := bfs.Lstat("/link")
	if err != nil {
		t.Fatal(err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat /link mode = %v, want symlink", li.Mode())
	}
	si, err := bfs.Stat("/link")
	if err != nil {
		t.Fatal(err)
	}
	if si.Mode()&os.ModeSymlink != 0 || si.Size() != int64(len(fx.body["base.txt"])) {
		t.Fatalf("Stat /link = mode %v size %d, want the target's", si.Mode(), si.Size())
	}

	got, err := bfs.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"base.txt", "big.bin", "dir", "huge.bin", "link", "tagged.txt"}
	if strings.Join(names(got), ",") != strings.Join(want, ",") {
		t.Fatalf("ReadDir / = %v, want %v", names(got), want)
	}
	if got, err = bfs.ReadDir("/dir"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(names(got), ",") != "child.txt,inner" {
		t.Fatalf("ReadDir /dir = %v", names(got))
	}

	if _, err := bfs.Stat("/nope"); !os.IsNotExist(err) {
		t.Fatalf("Stat /nope = %v, want not-exist", err)
	}
	if _, err := bfs.ReadDir("/base.txt"); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("ReadDir /base.txt = %v, want ENOTDIR", err)
	}
}

func TestOpenReadBaseContent(t *testing.T) {
	bfs, fx := newRW(t, "2aaa1111-2222-3333-4444-555566667777")
	for _, p := range []string{"base.txt", "big.bin", "dir/child.txt", "dir/inner/leaf.txt"} {
		if got := readWhole(t, bfs, "/"+p); !bytes.Equal(got, fx.body[p]) {
			t.Fatalf("%s: read %d bytes, want %d (equal=%v)", p, len(got), len(fx.body[p]), bytes.Equal(got, fx.body[p]))
		}
	}
}

func TestReadlink(t *testing.T) {
	bfs, _ := newRW(t, "3aaa1111-2222-3333-4444-555566667777")
	target, err := bfs.Readlink("/link")
	if err != nil || target != "base.txt" {
		t.Fatalf("Readlink /link = %q, %v", target, err)
	}
	if err := bfs.Symlink("dir/child.txt", "/mylink"); err != nil {
		t.Fatal(err)
	}
	if target, err = bfs.Readlink("/mylink"); err != nil || target != "dir/child.txt" {
		t.Fatalf("Readlink /mylink = %q, %v", target, err)
	}
	if _, err := bfs.Readlink("/base.txt"); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Readlink of a regular file = %v, want EINVAL", err)
	}
}

func TestCreateWriteReadBack(t *testing.T) {
	bfs, _ := newRW(t, "4aaa1111-2222-3333-4444-555566667777")
	body := bytes.Repeat([]byte("pelfs-vfsbilly!"), 4096)
	writeWhole(t, bfs, "/new.txt", body)

	fi, err := bfs.Stat("/new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(body)) {
		t.Fatalf("Stat size = %d, want %d", fi.Size(), len(body))
	}
	if got := readWhole(t, bfs, "/new.txt"); !bytes.Equal(got, body) {
		t.Fatalf("read back %d bytes, want %d", len(got), len(body))
	}
	// A new name must appear in the merged listing.
	fis, err := bfs.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(names(fis), ","), "new.txt") {
		t.Fatalf("ReadDir / = %v, missing new.txt", names(fis))
	}

	// Overwriting a BASE file goes through content COW.
	writeWhole(t, bfs, "/base.txt", []byte("replaced"))
	if got := readWhole(t, bfs, "/base.txt"); string(got) != "replaced" {
		t.Fatalf("base.txt after overwrite = %q", got)
	}
}

func TestOpenFileFlags(t *testing.T) {
	bfs, _ := newRW(t, "5aaa1111-2222-3333-4444-555566667777")
	writeWhole(t, bfs, "/f.txt", []byte("hello"))

	f, err := bfs.OpenFile("/f.txt", os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(" world")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/f.txt"); string(got) != "hello world" {
		t.Fatalf("after O_APPEND = %q", got)
	}

	if f, err = bfs.OpenFile("/f.txt", os.O_WRONLY|os.O_TRUNC, 0644); err != nil {
		t.Fatal(err)
	}
	fi, err := bfs.Stat("/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("size after O_TRUNC = %d, want 0", fi.Size())
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/f.txt"); string(got) != "x" {
		t.Fatalf("after O_TRUNC+write = %q", got)
	}

	// O_EXCL must still refuse an existing name: go-nfs downgrades NFSv3
	// EXCLUSIVE to GUARDED, and this is the property GUARDED keeps.
	if _, err := bfs.OpenFile("/f.txt", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644); !os.IsExist(err) {
		t.Fatalf("O_EXCL on an existing name = %v, want exist", err)
	}
	if _, err := bfs.OpenFile("/absent.txt", os.O_RDONLY, 0); !os.IsNotExist(err) {
		t.Fatalf("O_RDONLY on a missing name = %v, want not-exist", err)
	}
	// A read-only handle refuses writes rather than silently dropping them.
	rf, err := bfs.Open("/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck
	if _, err := rf.Write([]byte("nope")); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("write to an O_RDONLY handle = %v, want EBADF", err)
	}
}

func TestTruncate(t *testing.T) {
	bfs, _ := newRW(t, "6aaa1111-2222-3333-4444-555566667777")
	writeWhole(t, bfs, "/t.bin", []byte("abcdefgh"))

	f, err := bfs.OpenFile("/t.bin", os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(3); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/t.bin"); string(got) != "abc" {
		t.Fatalf("after Truncate(3) = %q", got)
	}

	if f, err = bfs.OpenFile("/t.bin", os.O_RDWR, 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(6); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/t.bin"); !bytes.Equal(got, []byte("abc\x00\x00\x00")) {
		t.Fatalf("after Truncate(6) = %q, want zero-fill", got)
	}

	// Truncating a BASE file copies only the surviving prefix.
	if f, err = bfs.OpenFile("/dir/child.txt", os.O_RDWR, 0644); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(5); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/dir/child.txt"); string(got) != "child" {
		t.Fatalf("base file after Truncate(5) = %q", got)
	}
}

func TestMkdirAllRenameRemove(t *testing.T) {
	bfs, _ := newRW(t, "7aaa1111-2222-3333-4444-555566667777")

	if err := bfs.MkdirAll("/a/b/c", 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/a", "/a/b", "/a/b/c"} {
		fi, err := bfs.Stat(p)
		if err != nil || !fi.IsDir() {
			t.Fatalf("Stat %s = %v, %v", p, fi, err)
		}
	}
	// Idempotent, including over a base directory.
	if err := bfs.MkdirAll("/a/b/c", 0755); err != nil {
		t.Fatalf("MkdirAll again: %v", err)
	}
	if err := bfs.MkdirAll("/dir/inner/deep", 0755); err != nil {
		t.Fatalf("MkdirAll under a base dir: %v", err)
	}
	if err := bfs.MkdirAll("/base.txt/x", 0755); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("MkdirAll through a file = %v, want ENOTDIR", err)
	}

	writeWhole(t, bfs, "/a/b/c/f.txt", []byte("payload"))

	// File rename, including across directories.
	if err := bfs.Rename("/a/b/c/f.txt", "/a/b/f2.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/a/b/c/f.txt"); !os.IsNotExist(err) {
		t.Fatalf("old name after rename = %v", err)
	}
	if got := readWhole(t, bfs, "/a/b/f2.txt"); string(got) != "payload" {
		t.Fatalf("renamed content = %q", got)
	}

	// Directory rename: the subtree follows the moved inode.
	if err := bfs.Rename("/a/b", "/a/z"); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/a/z/f2.txt"); string(got) != "payload" {
		t.Fatalf("content under the renamed dir = %q", got)
	}
	if fi, err := bfs.Stat("/a/z/c"); err != nil || !fi.IsDir() {
		t.Fatalf("Stat /a/z/c = %v, %v", fi, err)
	}
	// Renaming a base entry works the same way.
	if err := bfs.Rename("/dir/child.txt", "/moved.txt"); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, "/moved.txt"); string(got) != "child body" {
		t.Fatalf("moved base file = %q", got)
	}
	if err := bfs.Rename("/a", "/a/z/sub"); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("rename of a dir into its own subtree = %v, want EINVAL", err)
	}

	// Remove: file, then non-empty dir, then the emptied dir.
	if err := bfs.Remove("/a/z/f2.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := bfs.Stat("/a/z/f2.txt"); !os.IsNotExist(err) {
		t.Fatalf("removed file still stats: %v", err)
	}
	if err := bfs.Remove("/a/z"); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("Remove of a non-empty dir = %v, want ENOTEMPTY", err)
	}
	if err := bfs.Remove("/a/z/c"); err != nil {
		t.Fatal(err)
	}
	if err := bfs.Remove("/a/z"); err != nil {
		t.Fatal(err)
	}
	if err := bfs.Remove("/nope"); !os.IsNotExist(err) {
		t.Fatalf("Remove of a missing name = %v", err)
	}
}

// TestRemoveNonEmptyBaseDir covers the merged-view emptiness check: /dir
// has only BASE children, so nothing in the overlay says it is occupied.
func TestRemoveNonEmptyBaseDir(t *testing.T) {
	bfs, _ := newRW(t, "8aaa1111-2222-3333-4444-555566667777")
	if err := bfs.Remove("/dir"); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("Remove /dir = %v, want ENOTEMPTY", err)
	}
}

// TestReadAtChunkBoundaries drives the io.ReaderAt contract across a
// multi-MiB chunked base file. go-nfs issues one ReadAt per READ and marks
// the reply EOF on a short count, so a partial read at a chunk boundary is
// reported to the client as a truncated file.
func TestReadAtChunkBoundaries(t *testing.T) {
	bfs, fx := newRW(t, "9aaa1111-2222-3333-4444-555566667777")
	want := fx.body["huge.bin"]
	size := int64(len(want))

	f, err := bfs.Open("/huge.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	ra, ok := f.(io.ReaderAt)
	if !ok {
		t.Fatal("billy.File does not implement io.ReaderAt")
	}

	for _, tc := range []struct {
		name string
		off  int64
		size int
	}{
		{"head", 0, 64 << 10},
		{"across 1MiB", (1 << 20) - (8 << 10), 64 << 10},
		{"across 2MiB", (2 << 20) - 3, 4 << 10},
		{"unaligned span", 1234567, 1 << 20},
		{"large span", 1 << 20, 3 << 20},
		{"tail", int64(len(want)) - (64 << 10), 64 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.size)
			n, err := ra.ReadAt(buf, tc.off)
			if err != nil {
				t.Fatalf("ReadAt(%d, %d): %v", tc.off, tc.size, err)
			}
			if n != tc.size {
				t.Fatalf("ReadAt returned %d of %d bytes with nil error; "+
					"go-nfs reports that to the client as EOF", n, tc.size)
			}
			if !bytes.Equal(buf, want[tc.off:tc.off+int64(tc.size)]) {
				t.Fatalf("ReadAt(%d, %d): content mismatch", tc.off, tc.size)
			}
		})
	}

	// Past the end is the one place a short count is correct, and it must
	// carry io.EOF.
	buf := make([]byte, 4096)
	if n, err := ra.ReadAt(buf, size-16); n != 16 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt past EOF = %d, %v; want 16, io.EOF", n, err)
	}
	if n, err := ra.ReadAt(buf, size); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at EOF = %d, %v; want 0, io.EOF", n, err)
	}
}

// TestReadAfterWrite pins the invariant a git clone depends on: whatever
// size Stat reports, a read returns at least that many bytes —
// immediately, with no flush and no close.
func TestReadAfterWrite(t *testing.T) {
	bfs, _ := newRW(t, "aaaa1111-2222-3333-4444-555566667777")
	data := bytes.Repeat([]byte("pelfs-pack-data!"), 512<<10/16) // 512 KiB

	f, err := bfs.Create("/pack.tmp")
	if err != nil {
		t.Fatal(err)
	}
	// Written the way go-nfs delivers a stream: many small WRITEs.
	for off := 0; off < len(data); off += 32 << 10 {
		end := off + 32<<10
		if end > len(data) {
			end = len(data)
		}
		if _, err := f.Write(data[off:end]); err != nil {
			t.Fatalf("write at %d: %v", off, err)
		}
	}

	fi, err := bfs.Stat("/pack.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != int64(len(data)) {
		t.Fatalf("Stat size = %d, want %d", fi.Size(), len(data))
	}

	// Read back through the SAME still-open handle.
	buf := make([]byte, len(data))
	n, err := f.(io.ReaderAt).ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt on the writing handle: %v", err)
	}
	if n != len(data) || !bytes.Equal(buf, data) {
		t.Fatalf("same-handle read got %d of %d bytes", n, len(data))
	}
	// And through a second handle opened while the first is still open.
	if got := readWhole(t, bfs, "/pack.tmp"); !bytes.Equal(got, data) {
		t.Fatalf("second-handle read got %d bytes, Stat promised %d", len(got), fi.Size())
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTempFileAndChange(t *testing.T) {
	// CAP_CHOWN: this test gives a file away to a uid nobody is, which is
	// the one thing in it that ownership alone does not permit (perm.go).
	// The permission matrix itself is perm_test.go's business.
	cred := fixtureCred
	cred.Caps |= vfsbilly.CapChown
	bfs, _ := newRWAs(t, "baaa1111-2222-3333-4444-555566667777", cred)
	f, err := bfs.TempFile("/dir", "tmp-")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.Name(), "/dir/tmp-") {
		t.Fatalf("TempFile name = %q", f.Name())
	}
	if _, err := f.Write([]byte("scratch")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, bfs, f.Name()); string(got) != "scratch" {
		t.Fatalf("temp file content = %q", got)
	}

	ch, ok := bfs.(billy.Change)
	if !ok {
		t.Fatal("filesystem does not implement billy.Change")
	}
	if err := ch.Chmod("/base.txt", 0600); err != nil {
		t.Fatal(err)
	}
	fi, err := bfs.Stat("/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mode after Chmod = %v", fi.Mode())
	}
	when := time.Unix(1700000000, 0)
	if err := ch.Chtimes("/base.txt", when, when); err != nil {
		t.Fatal(err)
	}
	if fi, err = bfs.Stat("/base.txt"); err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(when) {
		t.Fatalf("mtime after Chtimes = %v, want %v", fi.ModTime(), when)
	}
	if err := ch.Chown("/base.txt", 4242, 4343); err != nil {
		t.Fatal(err)
	}
	if fi, err = bfs.Stat("/base.txt"); err != nil {
		t.Fatal(err)
	}
	if id := nfsfile.GetInfo(fi); id == nil || id.UID != 4242 || id.GID != 4343 {
		t.Fatalf("ownership after Chown = %+v", id)
	}
}

func TestReadOnly(t *testing.T) {
	fx := newFixture(t, "caaa1111-2222-3333-4444-555566667777")
	bfs := newBillyReadOnly(fx.base)

	// Reads work.
	if got := readWhole(t, bfs, "/dir/inner/leaf.txt"); !bytes.Equal(got, fx.body["dir/inner/leaf.txt"]) {
		t.Fatalf("read-only read = %q", got)
	}
	if fis, err := bfs.ReadDir("/dir"); err != nil || strings.Join(names(fis), ",") != "child.txt,inner" {
		t.Fatalf("read-only ReadDir = %v, %v", fis, err)
	}
	if _, err := bfs.Stat("/base.txt"); err != nil {
		t.Fatal(err)
	}
	if target, err := bfs.Readlink("/link"); err != nil || target != "base.txt" {
		t.Fatalf("read-only Readlink = %q, %v", target, err)
	}
	if caps := billy.Capabilities(bfs); caps&billy.WriteCapability != 0 {
		t.Fatalf("read-only capabilities advertise writes: %v", caps)
	}

	ch := bfs.(billy.Change)
	mutations := map[string]func() error{
		"Create":   func() error { _, err := bfs.Create("/x"); return err },
		"OpenFile": func() error { _, err := bfs.OpenFile("/x", os.O_RDWR|os.O_CREATE, 0644); return err },
		"OpenTrunc": func() error {
			_, err := bfs.OpenFile("/base.txt", os.O_RDONLY|os.O_TRUNC, 0)
			return err
		},
		"TempFile": func() error { _, err := bfs.TempFile("/", "t-"); return err },
		"MkdirAll": func() error { return bfs.MkdirAll("/x/y", 0755) },
		"Rename":   func() error { return bfs.Rename("/base.txt", "/other.txt") },
		"Remove":   func() error { return bfs.Remove("/base.txt") },
		"Symlink":  func() error { return bfs.Symlink("base.txt", "/l2") },
		"Chmod":    func() error { return ch.Chmod("/base.txt", 0600) },
		"Chown":    func() error { return ch.Chown("/base.txt", 1, 1) },
		"Lchown":   func() error { return ch.Lchown("/base.txt", 1, 1) },
		"Chtimes":  func() error { return ch.Chtimes("/base.txt", time.Now(), time.Now()) },
	}
	for name, fn := range mutations {
		err := fn()
		if !errors.Is(err, os.ErrPermission) || !os.IsPermission(err) {
			t.Fatalf("%s on a read-only filesystem = %v, want a permission error", name, err)
		}
	}

	f, err := bfs.Open("/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Write([]byte("x")); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("write on a read-only handle = %v", err)
	}
	if err := f.Truncate(0); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("truncate on a read-only handle = %v", err)
	}
	// Nothing above may have modified the generation.
	if got := readWhole(t, bfs, "/base.txt"); !bytes.Equal(got, fx.body["base.txt"]) {
		t.Fatalf("base.txt changed under a read-only filesystem")
	}
}

// TestResolutionIsByDescent is the residency contract. genfs serves an
// inode only after a Lookup descent reached it; an adapter that
// remembered inode numbers and called GetAttr on them would get ErrStale
// for a path nothing has visited. The assertion below establishes that
// the inode really is non-resident first, so the Stat that follows can
// only work by descending.
func TestResolutionIsByDescent(t *testing.T) {
	c := context.Background()
	fx := newFixture(t, "daaa1111-2222-3333-4444-555566667777")
	leaf := fx.ino["dir/inner/leaf.txt"]

	if _, err := fx.base.GetAttr(c, leaf); !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("GetAttr on an unvisited inode = %v, want ErrStale "+
			"(the fixture is not exercising the descent contract)", err)
	}

	for _, bfs := range []billy.Filesystem{
		newBillyReadOnly(fx.base),
		newBilly(openOverlay(t, fx)),
	} {
		fi, err := bfs.Stat("/dir/inner/leaf.txt")
		if err != nil {
			t.Fatalf("Stat of a never-looked-up path: %v", err)
		}
		if id := nfsfile.GetInfo(fi); id == nil || id.Fileid != leaf {
			t.Fatalf("Stat fileid = %+v, want inode %d", id, leaf)
		}
		if got := readWhole(t, bfs, "/dir/inner/leaf.txt"); !bytes.Equal(got, fx.body["dir/inner/leaf.txt"]) {
			t.Fatalf("read of a never-looked-up path = %q", got)
		}
	}
}

func TestJoinRootChroot(t *testing.T) {
	bfs, _ := newRW(t, "eaaa1111-2222-3333-4444-555566667777")
	if got := bfs.Join("a", "b", "c"); got != "a/b/c" {
		t.Fatalf("Join = %q", got)
	}
	if bfs.Root() != "/" {
		t.Fatalf("Root = %q", bfs.Root())
	}
	sub, err := bfs.Chroot("/dir")
	if err != nil {
		t.Fatal(err)
	}
	if got := readWhole(t, sub, "/child.txt"); string(got) != "child body" {
		t.Fatalf("chrooted read = %q", got)
	}
	if fis, err := sub.ReadDir("/"); err != nil || strings.Join(names(fis), ",") != "child.txt,inner" {
		t.Fatalf("chrooted ReadDir = %v, %v", fis, err)
	}
}

func TestSeek(t *testing.T) {
	bfs, _ := newRW(t, "faaa1111-2222-3333-4444-555566667777")
	writeWhole(t, bfs, "/s.txt", []byte("0123456789"))
	f, err := bfs.Open("/s.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if off, err := f.Seek(4, io.SeekStart); err != nil || off != 4 {
		t.Fatalf("Seek start = %d, %v", off, err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(f, buf); err != nil || string(buf) != "456" {
		t.Fatalf("read after seek = %q, %v", buf, err)
	}
	if off, err := f.Seek(-2, io.SeekEnd); err != nil || off != 8 {
		t.Fatalf("Seek end = %d, %v", off, err)
	}
	if _, err := io.ReadFull(f, buf[:2]); err != nil || string(buf[:2]) != "89" {
		t.Fatalf("read after SeekEnd = %q, %v", buf[:2], err)
	}
}
