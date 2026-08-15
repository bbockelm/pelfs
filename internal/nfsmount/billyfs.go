// Package nfsmount serves a JuiceFS volume over NFSv3 on 127.0.0.1 and
// mounts it with the operating system's built-in NFS client. On macOS this
// provides a kext-free, install-free alternative to macFUSE: mount_nfs works
// unprivileged, and the server side is pure Go (the same trick FUSE-T plays,
// without the closed-source middleman).
//
// This file adapts JuiceFS's path-based filesystem layer (pkg/fs — the same
// API backing its S3 gateway and WebDAV server) to billy.Filesystem, the
// interface the go-nfs server consumes.
package nfsmount

import (
	"io"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/helper/chroot"
	jfs "github.com/juicedata/juicefs/pkg/fs"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/vfs"
	nfsfile "github.com/willscott/go-nfs/file"
)

const defaultUmask = 022

// billyFS adapts *jfs.FileSystem to billy.Filesystem (plus billy.Change and
// billy.Capable, which go-nfs detects for SETATTR support and capability
// advertisement).
type billyFS struct {
	fs  *jfs.FileSystem
	ctx meta.Context
	uid uint32 // ownership presented to the NFS client
	gid uint32
	// hc keeps write handles open across go-nfs's open-write-close-per-RPC
	// pattern so writes coalesce into full-size blocks; see handlecache.go.
	hc *handleCache
}

var (
	_ billy.Filesystem = (*billyFS)(nil)
	_ billy.Change     = (*billyFS)(nil)
	_ billy.Capable    = (*billyFS)(nil)
)

// NewBillyFS wraps a JuiceFS filesystem for the go-nfs server.
//
// Operations run with a superuser context: a pelfs volume is a single-user
// scratch space, but its files may carry uids from other sessions (the
// Docker fallback runs as root, so files it created are uid-0 in the
// metadata). Running the local mount under the invoking user's uid would
// make those files silently unwritable — vim's save would fail server-side
// while the client page cache made it look fine. The given uid/gid are used
// only for presentation: every file is reported to the NFS client as owned
// by the mounting user.
func NewBillyFS(fs *jfs.FileSystem, uid, gid uint32) billy.Filesystem {
	ctx := meta.NewContext(uint32(os.Getpid()), 0, []uint32{0})
	return &billyFS{
		fs:  fs,
		ctx: ctx,
		uid: uid,
		gid: gid,
		hc:  newHandleCache(ctx),
	}
}

// Close flushes and closes every handle the write cache still holds. The
// caller MUST invoke this after the NFS server stops and before the
// underlying filesystem is torn down, or buffered writes are lost.
func (b *billyFS) Close() error {
	return b.hc.closeAll()
}

// wrapFI presents a jfs FileInfo to go-nfs with the mount user as owner and
// the real JuiceFS inode as the NFS fileid (stable across renames, unlike
// go-nfs's path-hash fallback).
func (b *billyFS) wrapFI(fi os.FileInfo) os.FileInfo {
	fstat, ok := fi.(*jfs.FileStat)
	if !ok {
		return fi
	}
	nlink := uint32(1)
	if attr, ok := fstat.Sys().(*meta.Attr); ok && attr != nil && attr.Nlink > 0 {
		nlink = attr.Nlink
	}
	return &ownedFileInfo{
		FileInfo: fi,
		sys: nfsfile.FileInfo{
			Nlink:  nlink,
			UID:    b.uid,
			GID:    b.gid,
			Fileid: uint64(fstat.Inode()),
		},
	}
}

// ownedFileInfo overrides Sys() with the go-nfs file.FileInfo type so
// ToFileAttribute picks up our ownership and fileid.
type ownedFileInfo struct {
	os.FileInfo
	sys nfsfile.FileInfo
}

func (o *ownedFileInfo) Sys() interface{} { return &o.sys }

// pe converts a JuiceFS syscall.Errno into a *fs.PathError so callers (and
// go-nfs's error mapping) can use errors.Is/os.IsNotExist tests.
func pe(op, p string, errno syscall.Errno) error {
	if errno == 0 {
		return nil
	}
	return &os.PathError{Op: op, Path: p, Err: errno}
}

func clean(p string) string {
	p = path.Clean("/" + strings.TrimRight(p, "/"))
	return p
}

func (b *billyFS) Create(filename string) (billy.File, error) {
	return b.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (b *billyFS) Open(filename string) (billy.File, error) {
	return b.OpenFile(filename, os.O_RDONLY, 0)
}

func (b *billyFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	name := clean(filename)
	writeIntent := flag&(os.O_APPEND|os.O_RDWR|os.O_WRONLY) != 0

	if writeIntent {
		if flag&(os.O_TRUNC|os.O_EXCL) != 0 {
			// A truncating or must-create open must not resume a cached
			// handle's buffered state.
			_ = b.hc.invalidate(name)
		} else if e := b.hc.acquire(name); e != nil {
			// Reuse the cached write handle so consecutive NFS WRITE RPCs
			// coalesce in one JuiceFS writer instead of flushing a tiny
			// slice per RPC.
			bf := &billyFile{name: name, f: e.f, ctx: b.ctx, ch: e, hc: b.hc}
			if flag&os.O_APPEND != 0 {
				atomic.StoreInt64(&bf.pos, b.hc.knownSize(e))
			}
			return bf, nil
		}
	} else if e := b.hc.acquire(name); e != nil {
		// Serve the read from the cached handle that holds the buffered
		// writes. JuiceFS clamps reads to the length captured when the
		// reading handle was opened, and pread flushes that handle's own
		// pending writes first — so reading through this handle is always
		// consistent, whereas opening a fresh one depends on the flush and
		// the attribute cache having already caught up.
		return &billyFile{name: name, f: e.f, ctx: b.ctx, ch: e, hc: b.hc}, nil
	}

	var mode int
	if flag&os.O_WRONLY == 0 {
		mode |= vfs.MODE_MASK_R
	}
	if writeIntent {
		mode |= vfs.MODE_MASK_W
	}
	f, errno := b.fs.Open(b.ctx, name, uint32(mode))
	if errno != 0 {
		if errno == syscall.ENOENT && flag&os.O_CREATE != 0 {
			f, errno = b.fs.Create(b.ctx, name, uint16(perm.Perm()), defaultUmask)
		}
		if errno != 0 {
			return nil, pe("open", name, errno)
		}
	} else {
		if flag&os.O_EXCL != 0 && flag&os.O_CREATE != 0 {
			_ = f.Close(b.ctx)
			return nil, pe("open", name, syscall.EEXIST)
		}
		if flag&os.O_TRUNC != 0 {
			if errno := f.Truncate(b.ctx, 0); errno != 0 {
				_ = f.Close(b.ctx)
				return nil, pe("truncate", name, errno)
			}
		}
	}
	size := int64(0)
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	if flag&os.O_TRUNC != 0 {
		size = 0
	}

	bf := &billyFile{name: name, f: f, ctx: b.ctx}
	if writeIntent {
		e, mine := b.hc.add(name, f, size)
		if e != nil && !mine {
			// Another caller cached a handle for this path while we were
			// opening ours. Ours must not survive: writes through it would
			// be invisible to the cached handle's length view. Hand the
			// work to the incumbent and drop the redundant handle.
			nfsDebugf("OpenFile %s: discarding redundant handle, using incumbent", name)
			if errno := f.Close(b.ctx); errno != 0 {
				_ = b.hc.release(e)
				return nil, pe("close", name, errno)
			}
			bf = &billyFile{name: name, f: e.f, ctx: b.ctx, ch: e, hc: b.hc}
			size = b.hc.knownSize(e)
		} else if e != nil {
			bf.ch, bf.hc = e, b.hc
		}
	}
	if flag&os.O_APPEND != 0 {
		atomic.StoreInt64(&bf.pos, size)
	}
	return bf, nil
}

func (b *billyFS) Stat(filename string) (os.FileInfo, error) {
	name := clean(filename)
	fi, errno := b.fs.Stat(b.ctx, name)
	if errno != 0 {
		return nil, pe("stat", filename, errno)
	}
	wrapped := b.wrapFI(fi)
	// Buffered writes are invisible to path-based Stat until the handle
	// flushes; overlay the freshest known size so go-nfs's per-WRITE stat
	// (and the client's post-op attribute checks) see current state without
	// forcing a slice-fragmenting flush.
	if size, mtime, ok := b.hc.statOverlay(name); ok && size > wrapped.Size() {
		nfsDebugf("Stat %s: meta=%d buffered=%d (overlaying)", name, wrapped.Size(), size)
		wrapped = &overlaidFileInfo{FileInfo: wrapped, size: size, mtime: mtime}
	}
	return wrapped, nil
}

// overlaidFileInfo overrides size/mtime while preserving the wrapped Sys().
type overlaidFileInfo struct {
	os.FileInfo
	size  int64
	mtime time.Time
}

func (o *overlaidFileInfo) Size() int64        { return o.size }
func (o *overlaidFileInfo) ModTime() time.Time { return o.mtime }

func (b *billyFS) Lstat(filename string) (os.FileInfo, error) {
	fi, errno := b.fs.Lstat(b.ctx, clean(filename))
	if errno != 0 {
		return nil, pe("lstat", filename, errno)
	}
	return b.wrapFI(fi), nil
}

func (b *billyFS) Rename(oldpath, newpath string) error {
	// Flush+drop cached handles on both ends so no buffered data lands
	// under the old identity after the rename. A failed flush here means
	// buffered bytes would be lost, so it fails the rename rather than
	// silently renaming a short file (git relies on write-then-rename).
	if err := b.hc.invalidate(clean(oldpath)); err != nil {
		return err
	}
	if err := b.hc.invalidate(clean(newpath)); err != nil {
		return err
	}
	return pe("rename", oldpath, b.fs.Rename(b.ctx, clean(oldpath), clean(newpath), 0))
}

func (b *billyFS) Remove(filename string) error {
	name := clean(filename)
	_ = b.hc.invalidate(name)
	fi, errno := b.fs.Lstat(b.ctx, name)
	if errno != 0 {
		return pe("remove", name, errno)
	}
	if fi.IsDir() {
		return pe("remove", name, b.fs.Rmdir(b.ctx, name))
	}
	return pe("remove", name, b.fs.Unlink(b.ctx, name))
}

func (b *billyFS) Join(elem ...string) string {
	return path.Join(elem...)
}

func (b *billyFS) TempFile(dir, prefix string) (billy.File, error) {
	for i := 0; i < 10000; i++ {
		name := path.Join(clean(dir), prefix+randomSuffix())
		f, err := b.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			return f, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
	}
	return nil, pe("tempfile", dir, syscall.EEXIST)
}

func (b *billyFS) ReadDir(p string) ([]os.FileInfo, error) {
	name := clean(p)
	f, errno := b.fs.Open(b.ctx, name, vfs.MODE_MASK_R)
	if errno != 0 {
		return nil, pe("readdir", name, errno)
	}
	defer f.Close(b.ctx)
	// A fresh handle starts at offset 0; count<=0 returns everything.
	// pkg/fs already strips "." and "..".
	fis, errno := f.Readdir(b.ctx, 0)
	if errno != 0 {
		return nil, pe("readdir", name, errno)
	}
	wrapped := make([]os.FileInfo, len(fis))
	for i, fi := range fis {
		wrapped[i] = b.wrapFI(fi)
	}
	return wrapped, nil
}

func (b *billyFS) MkdirAll(filename string, perm os.FileMode) error {
	return pe("mkdir", filename, b.fs.MkdirAll(b.ctx, clean(filename), uint16(perm.Perm()), defaultUmask))
}

func (b *billyFS) Symlink(target, link string) error {
	return pe("symlink", link, b.fs.Symlink(b.ctx, target, clean(link)))
}

func (b *billyFS) Readlink(link string) (string, error) {
	target, errno := b.fs.Readlink(b.ctx, clean(link))
	if errno != 0 {
		return "", pe("readlink", link, errno)
	}
	return string(target), nil
}

func (b *billyFS) Chroot(p string) (billy.Filesystem, error) {
	return chroot.New(b, clean(p)), nil
}

func (b *billyFS) Root() string { return "/" }

// Capabilities: everything but locking (the volume is mounted nolocks).
func (b *billyFS) Capabilities() billy.Capability {
	return billy.WriteCapability | billy.ReadCapability |
		billy.ReadAndWriteCapability | billy.SeekCapability |
		billy.TruncateCapability
}

// billy.Change — SETATTR support.

func (b *billyFS) withFile(op, name string, fn func(*jfs.File) syscall.Errno) error {
	f, errno := b.fs.Lopen(b.ctx, clean(name), 0)
	if errno != 0 {
		return pe(op, name, errno)
	}
	defer f.Close(b.ctx)
	return pe(op, name, fn(f))
}

func (b *billyFS) Chmod(name string, mode os.FileMode) error {
	return b.withFile("chmod", name, func(f *jfs.File) syscall.Errno {
		return f.Chmod(b.ctx, uint16(mode.Perm()))
	})
}

func (b *billyFS) Chown(name string, uid, gid int) error {
	return b.withFile("chown", name, func(f *jfs.File) syscall.Errno {
		return f.Chown(b.ctx, uint32(uid), uint32(gid))
	})
}

func (b *billyFS) Lchown(name string, uid, gid int) error {
	return b.Chown(name, uid, gid)
}

func (b *billyFS) Chtimes(name string, atime, mtime time.Time) error {
	// Commit buffered writes first: an explicitly-set mtime must stick, and
	// the Stat overlay (which reports last-write time while a handle is
	// dirty) must stand down in its favor.
	if err := b.hc.flushIfDirty(clean(name)); err != nil {
		return err
	}
	return b.withFile("chtimes", name, func(f *jfs.File) syscall.Errno {
		return f.Utime(b.ctx, atime.UnixMilli(), mtime.UnixMilli())
	})
}

// billyFile adapts *jfs.File to billy.File. The NFS server issues
// offset-tagged reads/writes, which map to Pread/Pwrite; the sequential
// Read/Write/Seek methods maintain their own position so a single handle
// behaves like an *os.File.
type billyFile struct {
	name string
	f    *jfs.File
	ctx  meta.Context
	pos  int64
	// ch/hc are set when f is a shared cached write handle: Close releases
	// the reference instead of closing (the janitor flushes after idle).
	ch *cachedHandle
	hc *handleCache
}

var _ billy.File = (*billyFile)(nil)

func (f *billyFile) Name() string { return f.name }

func (f *billyFile) Read(p []byte) (int, error) {
	n, err := f.f.Pread(f.ctx, p, atomic.LoadInt64(&f.pos))
	atomic.AddInt64(&f.pos, int64(n))
	return n, err
}

func (f *billyFile) ReadAt(p []byte, off int64) (int, error) {
	// io.ReaderAt requires the buffer to be filled unless a non-nil error is
	// returned, and go-nfs's READ handler depends on that: it issues a
	// single ReadAt and, when the request reaches the end of the file,
	// marks the reply EOF. A short count with a nil error would therefore
	// be reported to the client as "the file ends here". jfs.Pread makes no
	// such guarantee, so loop.
	total := 0
	for total < len(p) {
		n, err := f.f.Pread(f.ctx, p[total:], off+int64(total))
		total += n
		if err != nil {
			if total == len(p) && err == io.EOF {
				return total, nil
			}
			nfsDebugf("ReadAt %s off=%d want=%d got=%d: %v", f.name, off, len(p), total, err)
			return total, err
		}
		if n == 0 {
			nfsDebugf("ReadAt %s off=%d want=%d got=%d: short read with no error",
				f.name, off, len(p), total)
			return total, io.EOF
		}
	}
	return total, nil
}

func (f *billyFile) Write(p []byte) (int, error) {
	off := atomic.LoadInt64(&f.pos)
	n, errno := f.f.Pwrite(f.ctx, p, off)
	atomic.AddInt64(&f.pos, int64(n))
	if errno == 0 && f.ch != nil {
		f.hc.noteWrite(f.ch, off+int64(n))
	}
	return n, pe("write", f.name, errno)
}

func (f *billyFile) WriteAt(p []byte, off int64) (int, error) {
	n, errno := f.f.Pwrite(f.ctx, p, off)
	if errno == 0 && f.ch != nil {
		f.hc.noteWrite(f.ch, off+int64(n))
	}
	if errno != 0 || n != len(p) {
		nfsDebugf("WriteAt %s off=%d want=%d got=%d errno=%v", f.name, off, len(p), n, errno)
	}
	return n, pe("write", f.name, errno)
}

func (f *billyFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		atomic.StoreInt64(&f.pos, offset)
	case 1:
		offset = atomic.AddInt64(&f.pos, offset)
	case 2:
		fi, err := f.f.Stat()
		if err != nil {
			return 0, err
		}
		offset += fi.Size()
		atomic.StoreInt64(&f.pos, offset)
	}
	return atomic.LoadInt64(&f.pos), nil
}

func (f *billyFile) Truncate(size int64) error {
	errno := f.f.Truncate(f.ctx, uint64(size))
	if errno == 0 && f.ch != nil {
		f.hc.noteTruncate(f.ch, size)
	}
	return pe("truncate", f.name, errno)
}

func (f *billyFile) Close() error {
	if f.ch != nil {
		return f.hc.release(f.ch)
	}
	return pe("close", f.name, f.f.Close(f.ctx))
}

// Sync commits buffered writes without closing the handle.
//
// Nothing calls this today: go-nfs's COMMIT handler is a no-op, so an
// fsync() through this mount does not reach us. Durability instead comes
// from the janitor, from Rename/Remove (git's write-then-rename is what
// matters in practice), and from the flush at unmount. This is the method
// a fixed COMMIT would call — see docs/go-nfs-patches.md.
func (f *billyFile) Sync() error {
	if f.ch != nil {
		return f.hc.sync(f.name)
	}
	return pe("sync", f.name, f.f.Fsync(f.ctx))
}

// Lock/Unlock: advisory locks are not served (mounted with nolocks).
func (f *billyFile) Lock() error   { return nil }
func (f *billyFile) Unlock() error { return nil }
