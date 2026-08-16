// Package vfsbilly adapts the phase-3 catalog-native stack to
// billy.Filesystem, the interface the go-nfs server consumes
// (internal/nfsmount.Serve). It is the phase-3 counterpart of
// internal/nfsmount's JuiceFS adapter, and the piece that lets the
// catalog-native stack be mounted on macOS with the OS NFS client — no
// macFUSE, no JuiceFS.
//
// Path resolution is by DESCENT. genfs serves an inode only once a Lookup
// has established residency for it, so every path handed to this adapter
// is walked from the root, parent before child. No path -> inode map
// short-circuits that walk: an inode remembered from an earlier operation
// is not on its own resident, and the layer below answers ErrStale for it.
//
// Unlike the v1 adapter there is no handle cache. The overlay commits each
// Write to its staging file before returning, so a handle carries no
// buffered state and nothing has to reconcile a metadata length with bytes
// still in flight — the entire class of truncation bugs that cache exists
// to prevent (see internal/nfsmount/handlecache.go) does not arise here.
package vfsbilly

import (
	"context"
	"errors"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/helper/chroot"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// maxSymlinkHops bounds terminal-symlink following in Stat. Intermediate
// path components are NOT followed: an NFS client resolves a path one
// LOOKUP at a time and handles NF3LNK itself.
const maxSymlinkHops = 8

// reader is the read surface both layers implement: genfs.FS over a clean
// generation and overlay.FS over the merged view. overlay's Node and
// DirEntry are genfs aliases, so one shape serves both.
type reader interface {
	Lookup(ctx context.Context, parent uint64, name string) (genfs.Node, error)
	GetAttr(ctx context.Context, ino uint64) (genfs.Node, error)
	Readdir(ctx context.Context, ino uint64) ([]genfs.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
}

// billyFS binds one layer to billy. ov nil means a read-only binding:
// every mutating call is refused with a permission error, the op
// understood and denied rather than unimplemented.
type billyFS struct {
	rd  reader
	ov  *overlay.FS
	uid uint32
	gid uint32
}

var (
	_ billy.Filesystem = (*billyFS)(nil)
	_ billy.Change     = (*billyFS)(nil)
	_ billy.Capable    = (*billyFS)(nil)
)

// New returns a billy.Filesystem over a read-write overlay. Nodes it
// creates are owned by the invoking user: the volume is a single-user
// scratch space and the mount must be able to write what it made.
func New(ov *overlay.FS) billy.Filesystem {
	return &billyFS{rd: ov, ov: ov, uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
}

// NewReadOnly returns a billy.Filesystem over an immutable generation.
func NewReadOnly(fs *genfs.FS) billy.Filesystem {
	return &billyFS{rd: fs, uid: uint32(os.Getuid()), gid: uint32(os.Getgid())}
}

// ctx is the request context. billy carries none, and neither layer
// cancels mid-operation on behalf of an NFS client.
func ctx() context.Context { return context.Background() }

// clean normalizes a billy path to rooted slash form.
func clean(p string) string {
	return path.Clean("/" + strings.TrimRight(p, "/"))
}

// components splits a cleaned path into its names; nil for the root.
func components(p string) []string {
	trimmed := strings.Trim(clean(p), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// resolve walks p from the root, one Lookup per component. The descent IS
// the residency contract — genfs answers ErrStale for an inode it was
// never asked to look up — so no step may be skipped and no result may be
// cached in its place.
func (b *billyFS) resolve(c context.Context, p string) (genfs.Node, error) {
	n, err := b.rd.GetAttr(c, genfs.RootInode)
	if err != nil {
		return genfs.Node{}, err
	}
	for _, part := range components(p) {
		if n.Type != catalog.TypeDir {
			return genfs.Node{}, overlay.ErrNotDir
		}
		if n, err = b.rd.Lookup(c, n.Inode, part); err != nil {
			return genfs.Node{}, err
		}
	}
	return n, nil
}

// resolveFollow resolves p and follows a terminal symlink chain: the
// difference between Stat and Lstat.
func (b *billyFS) resolveFollow(c context.Context, p string) (genfs.Node, error) {
	name := clean(p)
	for hop := 0; ; hop++ {
		n, err := b.resolve(c, name)
		if err != nil || n.Type != catalog.TypeSymlink {
			return n, err
		}
		if hop == maxSymlinkHops {
			return genfs.Node{}, syscall.ELOOP
		}
		target, err := b.rd.Readlink(c, n.Inode)
		if err != nil {
			return genfs.Node{}, err
		}
		if path.IsAbs(target) {
			name = clean(target)
		} else {
			name = clean(path.Join(path.Dir(name), target))
		}
	}
}

// resolveParent descends to p's parent directory and returns it with p's
// final component — the (parent inode, name) pair every namespace
// operation on the layer below takes.
func (b *billyFS) resolveParent(c context.Context, p string) (genfs.Node, string, error) {
	parts := components(p)
	if len(parts) == 0 {
		return genfs.Node{}, "", syscall.EINVAL // the root has no parent edge
	}
	dir, err := b.resolve(c, path.Dir(clean(p)))
	if err != nil {
		return genfs.Node{}, "", err
	}
	if dir.Type != catalog.TypeDir {
		return genfs.Node{}, "", overlay.ErrNotDir
	}
	return dir, parts[len(parts)-1], nil
}

// pe wraps a layer error as an *os.PathError carrying the sentinel go-nfs
// maps to an NFS status. go-nfs tests both errors.Is and the os.IsX
// helpers, which unwrap differently, so the sentinels chosen here satisfy
// both.
func pe(op, p string, err error) error {
	if err == nil {
		return nil
	}
	return &os.PathError{Op: op, Path: p, Err: sentinel(err)}
}

func sentinel(err error) error {
	switch {
	case errors.Is(err, genfs.ErrNotExist):
		return os.ErrNotExist
	case errors.Is(err, genfs.ErrStale):
		return syscall.ESTALE
	case errors.Is(err, overlay.ErrExist):
		return os.ErrExist
	case errors.Is(err, overlay.ErrNotEmpty):
		return syscall.ENOTEMPTY
	case errors.Is(err, overlay.ErrNotDir):
		return syscall.ENOTDIR
	case errors.Is(err, overlay.ErrIsDir):
		return syscall.EISDIR
	}
	return err
}

// roErr refuses a mutating call on a read-only binding. EPERM, not a bare
// os.ErrPermission: it satisfies errors.Is(err, os.ErrPermission) AND
// os.IsPermission, and go-nfs uses both.
func roErr(op, p string) error {
	return &os.PathError{Op: op, Path: clean(p), Err: syscall.EPERM}
}

// Basic.

func (b *billyFS) Create(filename string) (billy.File, error) {
	return b.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
}

func (b *billyFS) Open(filename string) (billy.File, error) {
	return b.OpenFile(filename, os.O_RDONLY, 0)
}

func (b *billyFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	c := ctx()
	name := clean(filename)
	mutates := flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0
	if mutates && b.ov == nil {
		return nil, roErr("open", name)
	}

	n, err := b.resolve(c, name)
	switch {
	case err == nil:
		// O_EXCL still fails on an existing name. go-nfs does not implement
		// NFSv3 EXCLUSIVE mode and falls back to GUARDED (see the
		// quietLogger note in internal/nfsmount/nfsmount.go), which
		// preserves exactly this property.
		if flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL {
			return nil, pe("open", name, overlay.ErrExist)
		}
		if n.Type == catalog.TypeDir && mutates {
			return nil, pe("open", name, overlay.ErrIsDir)
		}
	case errors.Is(err, genfs.ErrNotExist) && flag&os.O_CREATE != 0:
		dir, base, derr := b.resolveParent(c, name)
		if derr != nil {
			return nil, pe("open", name, derr)
		}
		if n, err = b.ov.Create(c, dir.Inode, base, uint32(perm.Perm()), b.uid, b.gid); err != nil {
			return nil, pe("open", name, err)
		}
	default:
		return nil, pe("open", name, err)
	}

	if flag&os.O_TRUNC != 0 && n.Length != 0 {
		zero := int64(0)
		if n, err = b.ov.SetAttr(c, n.Inode, overlay.SetAttrIn{Size: &zero}); err != nil {
			return nil, pe("truncate", name, err)
		}
	}
	f := &file{fs: b, name: name, ino: n.Inode, flag: flag}
	if flag&os.O_APPEND != 0 {
		f.pos = n.Length
	}
	return f, nil
}

func (b *billyFS) Stat(filename string) (os.FileInfo, error) {
	n, err := b.resolveFollow(ctx(), filename)
	if err != nil {
		return nil, pe("stat", filename, err)
	}
	return newInfo(path.Base(clean(filename)), n), nil
}

func (b *billyFS) Lstat(filename string) (os.FileInfo, error) {
	n, err := b.resolve(ctx(), filename)
	if err != nil {
		return nil, pe("lstat", filename, err)
	}
	return newInfo(path.Base(clean(filename)), n), nil
}

func (b *billyFS) Rename(oldpath, newpath string) error {
	if b.ov == nil {
		return roErr("rename", oldpath)
	}
	c := ctx()
	src, srcName, err := b.resolveParent(c, oldpath)
	if err != nil {
		return pe("rename", oldpath, err)
	}
	dst, dstName, err := b.resolveParent(c, newpath)
	if err != nil {
		return pe("rename", newpath, err)
	}
	// Loop prevention is the binding's job (overlay.Rename documents it):
	// moving a directory under itself would orphan the subtree. Both
	// operands are paths here, so the prefix test is exact.
	from, to := clean(oldpath), clean(newpath)
	if from != "/" && strings.HasPrefix(to+"/", from+"/") {
		return pe("rename", newpath, syscall.EINVAL)
	}
	return pe("rename", oldpath, b.ov.Rename(c, src.Inode, srcName, dst.Inode, dstName))
}

func (b *billyFS) Remove(filename string) error {
	if b.ov == nil {
		return roErr("remove", filename)
	}
	c := ctx()
	dir, name, err := b.resolveParent(c, filename)
	if err != nil {
		return pe("remove", filename, err)
	}
	n, err := b.rd.Lookup(c, dir.Inode, name)
	if err != nil {
		return pe("remove", filename, err)
	}
	if n.Type == catalog.TypeDir {
		return pe("remove", filename, b.ov.Rmdir(c, dir.Inode, name))
	}
	return pe("remove", filename, b.ov.Unlink(c, dir.Inode, name))
}

func (b *billyFS) Join(elem ...string) string { return path.Join(elem...) }

// TempFile.

func (b *billyFS) TempFile(dir, prefix string) (billy.File, error) {
	if b.ov == nil {
		return nil, roErr("tempfile", dir)
	}
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
	return nil, pe("tempfile", dir, overlay.ErrExist)
}

// Dir.

func (b *billyFS) ReadDir(p string) ([]os.FileInfo, error) {
	c := ctx()
	n, err := b.resolve(c, p)
	if err != nil {
		return nil, pe("readdir", p, err)
	}
	if n.Type != catalog.TypeDir {
		return nil, pe("readdir", p, overlay.ErrNotDir)
	}
	entries, err := b.rd.Readdir(c, n.Inode)
	if err != nil {
		return nil, pe("readdir", p, err)
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, newInfo(e.Name, e.Node))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func (b *billyFS) MkdirAll(filename string, perm os.FileMode) error {
	if b.ov == nil {
		return roErr("mkdir", filename)
	}
	c := ctx()
	name := clean(filename)
	dir, err := b.rd.GetAttr(c, genfs.RootInode)
	if err != nil {
		return pe("mkdir", name, err)
	}
	for _, part := range components(name) {
		child, err := b.rd.Lookup(c, dir.Inode, part)
		if errors.Is(err, genfs.ErrNotExist) {
			child, err = b.ov.Mkdir(c, dir.Inode, part, uint32(perm.Perm()), b.uid, b.gid)
			if errors.Is(err, overlay.ErrExist) {
				// Someone else created it in between; an existing name is
				// all MkdirAll promises.
				child, err = b.rd.Lookup(c, dir.Inode, part)
			}
		}
		if err != nil {
			return pe("mkdir", name, err)
		}
		if child.Type != catalog.TypeDir {
			return pe("mkdir", name, overlay.ErrNotDir)
		}
		dir = child
	}
	return nil
}

// Symlink.

func (b *billyFS) Symlink(target, link string) error {
	if b.ov == nil {
		return roErr("symlink", link)
	}
	c := ctx()
	dir, name, err := b.resolveParent(c, link)
	if err != nil {
		return pe("symlink", link, err)
	}
	_, err = b.ov.Symlink(c, dir.Inode, name, target, b.uid, b.gid)
	return pe("symlink", link, err)
}

func (b *billyFS) Readlink(link string) (string, error) {
	c := ctx()
	n, err := b.resolve(c, link)
	if err != nil {
		return "", pe("readlink", link, err)
	}
	if n.Type != catalog.TypeSymlink {
		return "", pe("readlink", link, syscall.EINVAL)
	}
	target, err := b.rd.Readlink(c, n.Inode)
	if err != nil {
		return "", pe("readlink", link, err)
	}
	return target, nil
}

// Chroot.

func (b *billyFS) Chroot(p string) (billy.Filesystem, error) {
	return chroot.New(b, clean(p)), nil
}

func (b *billyFS) Root() string { return "/" }

// Capable. Locking is absent on purpose: the volume is mounted nolocks.

func (b *billyFS) Capabilities() billy.Capability {
	caps := billy.ReadCapability | billy.SeekCapability
	if b.ov != nil {
		caps |= billy.WriteCapability | billy.ReadAndWriteCapability | billy.TruncateCapability
	}
	return caps
}

// Change — SETATTR support.

// setAttr resolves name and applies one attribute change. follow selects
// chmod/chown semantics (through a terminal symlink) over lchown's.
func (b *billyFS) setAttr(op, name string, follow bool, in overlay.SetAttrIn) error {
	if b.ov == nil {
		return roErr(op, name)
	}
	c := ctx()
	var n genfs.Node
	var err error
	if follow {
		n, err = b.resolveFollow(c, name)
	} else {
		n, err = b.resolve(c, name)
	}
	if err != nil {
		return pe(op, name, err)
	}
	_, err = b.ov.SetAttr(c, n.Inode, in)
	return pe(op, name, err)
}

func (b *billyFS) Chmod(name string, mode os.FileMode) error {
	m := unixMode(mode)
	return b.setAttr("chmod", name, true, overlay.SetAttrIn{Mode: &m})
}

func (b *billyFS) Chown(name string, uid, gid int) error {
	u, g := uint32(uid), uint32(gid)
	return b.setAttr("chown", name, true, overlay.SetAttrIn{UID: &u, GID: &g})
}

func (b *billyFS) Lchown(name string, uid, gid int) error {
	u, g := uint32(uid), uint32(gid)
	return b.setAttr("lchown", name, false, overlay.SetAttrIn{UID: &u, GID: &g})
}

// Chtimes sets mtime only: catalogs carry no atime by design, and mtime
// stands in for it everywhere else in the stack.
func (b *billyFS) Chtimes(name string, atime, mtime time.Time) error {
	ns := mtime.UnixNano()
	return b.setAttr("chtimes", name, true, overlay.SetAttrIn{MtimeNS: &ns})
}
