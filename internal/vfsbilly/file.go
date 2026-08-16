package vfsbilly

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// file is one open handle. It holds no buffered state: overlay.Write
// commits to the staging file before it returns, so read-after-write
// through this handle — or through a second one opened concurrently — is
// automatic, and Close has nothing to flush.
type file struct {
	fs   *billyFS
	name string
	ino  uint64
	flag int

	mu     sync.Mutex
	pos    int64
	closed bool
}

var _ billy.File = (*file)(nil)

func (f *file) Name() string { return f.name }

// writable reports whether this handle may mutate, refusing with the
// error the caller should return.
func (f *file) writable(op string) error {
	if f.fs.ov == nil {
		return roErr(op, f.name)
	}
	if f.flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND) == 0 {
		return &os.PathError{Op: op, Path: f.name, Err: syscall.EBADF}
	}
	return nil
}

func (f *file) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: os.ErrClosed}
	}
	n, err := f.readAt(p, f.pos)
	f.pos += int64(n)
	return n, err
}

func (f *file) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, &os.PathError{Op: "read", Path: f.name, Err: os.ErrClosed}
	}
	return f.readAt(p, off)
}

// readAt fills p or returns a non-nil error, as io.ReaderAt requires.
// go-nfs's READ handler leans on that contract: it issues one ReadAt and
// marks the reply EOF when the request reaches the end of the file, so a
// short count with a nil error is reported to the client as "the file
// ends here" — the shape of a truncated file.
func (f *file) readAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(p) {
		n, err := f.fs.rd.Read(ctx(), f.ino, off+int64(total), p[total:])
		if err != nil {
			return total, pe("read", f.name, err)
		}
		if n == 0 {
			return total, io.EOF
		}
		total += n
	}
	return total, nil
}

func (f *file) Write(p []byte) (int, error) {
	if err := f.writable("write"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: os.ErrClosed}
	}
	off := f.pos
	if f.flag&os.O_APPEND != 0 {
		// O_APPEND lands every write at the current end of file, which
		// another handle may have moved since this one opened.
		n, err := f.fs.rd.GetAttr(ctx(), f.ino)
		if err != nil {
			return 0, pe("write", f.name, err)
		}
		off = n.Length
	}
	n, err := f.fs.ov.Write(ctx(), f.ino, off, p)
	f.pos = off + int64(n)
	return n, pe("write", f.name, err)
}

// WriteAt is not part of billy.File (a v6 TODO upstream) but is what a
// positional NFS WRITE actually means; io.WriterAt costs nothing here.
func (f *file) WriteAt(p []byte, off int64) (int, error) {
	if err := f.writable("write"); err != nil {
		return 0, err
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, &os.PathError{Op: "write", Path: f.name, Err: os.ErrClosed}
	}
	n, err := f.fs.ov.Write(ctx(), f.ino, off, p)
	return n, pe("write", f.name, err)
}

func (f *file) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch whence {
	case io.SeekStart:
		f.pos = offset
	case io.SeekCurrent:
		f.pos += offset
	case io.SeekEnd:
		n, err := f.fs.rd.GetAttr(ctx(), f.ino)
		if err != nil {
			return 0, pe("seek", f.name, err)
		}
		f.pos = n.Length + offset
	default:
		return 0, &os.PathError{Op: "seek", Path: f.name, Err: syscall.EINVAL}
	}
	if f.pos < 0 {
		f.pos = 0
		return 0, &os.PathError{Op: "seek", Path: f.name, Err: syscall.EINVAL}
	}
	return f.pos, nil
}

func (f *file) Truncate(size int64) error {
	if err := f.writable("truncate"); err != nil {
		return err
	}
	_, err := f.fs.ov.SetAttr(ctx(), f.ino, overlay.SetAttrIn{Size: &size})
	return pe("truncate", f.name, err)
}

func (f *file) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return &os.PathError{Op: "close", Path: f.name, Err: os.ErrClosed}
	}
	f.closed = true
	return nil
}

// Lock/Unlock: advisory locks are not served (the volume mounts nolocks).
func (f *file) Lock() error   { return nil }
func (f *file) Unlock() error { return nil }

func randomSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}
