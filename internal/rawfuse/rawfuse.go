// Package rawfuse is the phase-3 raw FUSE binding (docs/design-packfs.md,
// "Phase 3 VFS architecture"): fuse.RawFileSystem mapped 1:1 onto the genfs
// generation resolver. Read-only in this iteration — the write overlay is a
// separate layer — so every mutating op returns EROFS (the op is understood
// and refused, not unimplemented).
//
// The immutability dividend: within a generation clean inodes never change,
// so every EntryOut/AttrOut carries an effectively infinite validity and the
// kernel is the dentry/attr cache. Residency is FORGET-driven: Lookup (and
// each entry a ReadDirPlus emits) counts as one nlookup against genfs;
// Forget retires it. Plain ReadDir creates no residency.
package rawfuse

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// entryValidity is the entry/attr TTL stamped on every reply: ~10 years,
// effectively infinite. Clean inodes never change within a generation; a
// generation swap invalidates by notification, not by TTL expiry.
const entryValidity = 10 * 365 * 24 * time.Hour

// errStale maps genfs.ErrStale: the kernel references an inode it never
// looked up (or already forgot).
var errStale = fuse.Status(syscall.ESTALE)

// Bind wraps a genfs generation as a raw FUSE filesystem.
func Bind(fs *genfs.FS) fuse.RawFileSystem {
	return &raw{
		RawFileSystem: fuse.NewDefaultRawFileSystem(),
		fs:            fs,
		dirs:          make(map[uint64]*dirHandle),
	}
}

// Mount serves fs at mountpoint (Linux FUSE / macFUSE) and returns the
// running server once the mount is complete.
func Mount(mountpoint string, fs *genfs.FS, debug bool) (*fuse.Server, error) {
	opts := &fuse.MountOptions{
		AllowOther: false,
		FsName:     "pelfs",
		Name:       "pelfs",
		Debug:      debug,
		// Access stays ENOSYS: with default_permissions the kernel checks
		// permissions itself from the (infinitely cached) attrs.
		Options: []string{"ro", "default_permissions"},
	}
	srv, err := fuse.NewServer(Bind(fs), mountpoint, opts)
	if err != nil {
		return nil, err
	}
	go srv.Serve()
	if err := srv.WaitMount(); err != nil {
		srv.Unmount() //nolint:errcheck
		return nil, err
	}
	return srv, nil
}

// dirHandle caches one opendir's merged listing; ReadDir/ReadDirPlus page
// through it by entry index ("." and ".." occupy indices 0 and 1).
type dirHandle struct {
	ino     uint64
	entries []genfs.DirEntry
}

// raw binds genfs to the raw FUSE protocol. Ops not implemented here come
// from NewDefaultRawFileSystem (ENOSYS), except the mutating set below.
type raw struct {
	fuse.RawFileSystem
	fs *genfs.FS

	lastFh atomic.Uint64
	mu     sync.Mutex
	dirs   map[uint64]*dirHandle
}

func (r *raw) String() string { return "pelfs" }

// cancelCtx adapts a raw-FUSE cancel channel to context.Context without
// spawning a goroutine per request. A nil channel never cancels.
type cancelCtx struct {
	done <-chan struct{}
}

func (c cancelCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c cancelCtx) Done() <-chan struct{}       { return c.done }
func (c cancelCtx) Value(any) any               { return nil }
func (c cancelCtx) Err() error {
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

func ctxOf(cancel <-chan struct{}) context.Context { return cancelCtx{done: cancel} }

func errStatus(err error) fuse.Status {
	switch {
	case errors.Is(err, genfs.ErrNotExist):
		return fuse.ENOENT
	case errors.Is(err, genfs.ErrStale):
		return errStale
	case errors.Is(err, context.Canceled):
		return fuse.EINTR
	}
	return fuse.EIO
}

// typeBits maps a catalog entry type to stat's S_IFMT bits.
func typeBits(t uint8) uint32 {
	switch t {
	case catalog.TypeFile:
		return syscall.S_IFREG
	case catalog.TypeDir:
		return syscall.S_IFDIR
	case catalog.TypeSymlink:
		return syscall.S_IFLNK
	case catalog.TypeFIFO:
		return syscall.S_IFIFO
	case catalog.TypeBlockDev:
		return syscall.S_IFBLK
	case catalog.TypeCharDev:
		return syscall.S_IFCHR
	case catalog.TypeSocket:
		return syscall.S_IFSOCK
	}
	return 0
}

// fillAttr projects a genfs node onto a FUSE Attr. Catalogs carry no atime
// (by design); mtime stands in.
func fillAttr(n *genfs.Node, a *fuse.Attr) {
	a.Ino = n.Inode
	a.Size = uint64(n.Length)
	a.Blocks = uint64(n.Length+511) / 512
	a.Mode = typeBits(n.Type) | (n.Mode &^ uint32(syscall.S_IFMT))
	a.Nlink = n.Nlink
	a.Uid = n.UID
	a.Gid = n.GID
	a.Rdev = n.Rdev
	a.Blksize = 4096
	a.Mtime = uint64(n.MtimeNS / 1e9)
	a.Mtimensec = uint32(n.MtimeNS % 1e9)
	a.Ctime = uint64(n.CtimeNS / 1e9)
	a.Ctimensec = uint32(n.CtimeNS % 1e9)
	a.Atime = a.Mtime
	a.Atimensec = a.Mtimensec
}

// fillEntry completes an EntryOut: stable inode as NodeId (inodes NEVER
// recycle within a mount, hence Generation 0) and infinite validity.
func fillEntry(n *genfs.Node, out *fuse.EntryOut) {
	out.NodeId = n.Inode
	out.Generation = 0
	fillAttr(n, &out.Attr)
	out.SetEntryTimeout(entryValidity)
	out.SetAttrTimeout(entryValidity)
}

func (r *raw) Lookup(cancel <-chan struct{}, header *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	n, err := r.fs.Lookup(ctxOf(cancel), header.NodeId, name)
	if err != nil {
		return errStatus(err)
	}
	fillEntry(&n, out)
	return fuse.OK
}

// Forget passes nlookup through to genfs; the server dispatches
// BATCH_FORGET here per node.
func (r *raw) Forget(nodeid, nlookup uint64) {
	r.fs.Forget(nodeid, nlookup)
}

func (r *raw) GetAttr(cancel <-chan struct{}, input *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	n, err := r.fs.GetAttr(ctxOf(cancel), input.NodeId)
	if err != nil {
		return errStatus(err)
	}
	fillAttr(&n, &out.Attr)
	out.SetTimeout(entryValidity)
	return fuse.OK
}

// Open is stateless (Fh 0): content is immutable, so there is no per-handle
// state and the page cache survives close/open (FOPEN_KEEP_CACHE). Any
// write-access flag is refused up front.
func (r *raw) Open(cancel <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	if input.Flags&fuse.O_ANYWRITE != 0 {
		return fuse.EROFS
	}
	out.Fh = 0
	out.OpenFlags |= fuse.FOPEN_KEEP_CACHE
	return fuse.OK
}

// Read serves from the decoded-chunk cache via genfs into the kernel
// buffer. Splice from the cache file (ReadResultFd) is a later step.
func (r *raw) Read(cancel <-chan struct{}, input *fuse.ReadIn, buf []byte) (fuse.ReadResult, fuse.Status) {
	n, err := r.fs.Read(ctxOf(cancel), input.NodeId, int64(input.Offset), buf)
	if err != nil {
		return nil, errStatus(err)
	}
	return fuse.ReadResultData(buf[:n]), fuse.OK
}

func (r *raw) Release(cancel <-chan struct{}, input *fuse.ReleaseIn) {}

// OpenDir lists once per opendir: the merged listing is snapshotted on the
// handle and paged by ReadDir/ReadDirPlus.
func (r *raw) OpenDir(cancel <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	entries, err := r.fs.Readdir(ctxOf(cancel), input.NodeId)
	if err != nil {
		return errStatus(err)
	}
	fh := r.lastFh.Add(1)
	r.mu.Lock()
	r.dirs[fh] = &dirHandle{ino: input.NodeId, entries: entries}
	r.mu.Unlock()
	out.Fh = fh
	return fuse.OK
}

func (r *raw) dirHandleOf(fh uint64) *dirHandle {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dirs[fh]
}

// rowAt returns the listing row at entry index i: "." and ".." first (Ino 0
// becomes FUSE_UNKNOWN_INO in the dirent), then the cached entries.
func (h *dirHandle) rowAt(i int) (fuse.DirEntry, *genfs.DirEntry, bool) {
	switch {
	case i == 0:
		return fuse.DirEntry{Name: ".", Ino: h.ino, Mode: syscall.S_IFDIR}, nil, true
	case i == 1:
		return fuse.DirEntry{Name: "..", Ino: 0, Mode: syscall.S_IFDIR}, nil, true
	case i-2 < len(h.entries):
		e := &h.entries[i-2]
		return fuse.DirEntry{Name: e.Name, Ino: e.Node.Inode, Mode: typeBits(e.Node.Type)}, e, true
	}
	return fuse.DirEntry{}, nil, false
}

// ReadDir pages the cached listing by entry index. It creates NO residency:
// the kernel Lookups before operating on any entry it saw here.
func (r *raw) ReadDir(cancel <-chan struct{}, input *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	h := r.dirHandleOf(input.Fh)
	if h == nil {
		return fuse.EBADF
	}
	for i := int(input.Offset); ; i++ {
		de, _, ok := h.rowAt(i)
		if !ok {
			break
		}
		if !out.AddDirEntry(de) {
			break
		}
	}
	return fuse.OK
}

// ReadDirPlus fills entries and attributes in one pass. Every real entry
// emitted counts as a lookup — genfs.Lookup increments its nlookup, and the
// kernel will Forget each — so residency exactly tracks kernel-live inodes.
// "." and ".." carry a zeroed EntryOut (NodeId 0: kernel ignores the attrs).
func (r *raw) ReadDirPlus(cancel <-chan struct{}, input *fuse.ReadIn, out *fuse.DirEntryList) fuse.Status {
	h := r.dirHandleOf(input.Fh)
	if h == nil {
		return fuse.EBADF
	}
	ctx := ctxOf(cancel)
	for i := int(input.Offset); ; i++ {
		de, ge, ok := h.rowAt(i)
		if !ok {
			break
		}
		eo := out.AddDirLookupEntry(de)
		if eo == nil {
			break
		}
		if ge == nil {
			continue
		}
		n, err := r.fs.Lookup(ctx, h.ino, ge.Name)
		if err != nil {
			// Immutable generation: an entry cannot vanish mid-listing.
			// Emit it uncached rather than fail the whole page.
			continue
		}
		fillEntry(&n, eo)
	}
	return fuse.OK
}

func (r *raw) ReleaseDir(input *fuse.ReleaseIn) {
	r.mu.Lock()
	delete(r.dirs, input.Fh)
	r.mu.Unlock()
}

func (r *raw) Readlink(cancel <-chan struct{}, header *fuse.InHeader) ([]byte, fuse.Status) {
	target, err := r.fs.Readlink(ctxOf(cancel), header.NodeId)
	if err != nil {
		return nil, errStatus(err)
	}
	return []byte(target), fuse.OK
}

func (r *raw) GetXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string, dest []byte) (uint32, fuse.Status) {
	val, err := r.fs.GetXattr(ctxOf(cancel), header.NodeId, attr)
	if errors.Is(err, genfs.ErrNotExist) {
		return 0, errNoXattr
	}
	if err != nil {
		return 0, errStatus(err)
	}
	if len(val) > len(dest) {
		return uint32(len(val)), fuse.ERANGE
	}
	copy(dest, val)
	return uint32(len(val)), fuse.OK
}

func (r *raw) ListXAttr(cancel <-chan struct{}, header *fuse.InHeader, dest []byte) (uint32, fuse.Status) {
	names, err := r.fs.ListXattr(ctxOf(cancel), header.NodeId)
	if err != nil {
		return 0, errStatus(err)
	}
	total := 0
	for _, n := range names {
		total += len(n) + 1
	}
	if total > len(dest) {
		return uint32(total), fuse.ERANGE
	}
	pos := 0
	for _, n := range names {
		pos += copy(dest[pos:], n)
		dest[pos] = 0
		pos++
	}
	return uint32(total), fuse.OK
}

// StatFs is synthetic: the volume is a published generation, not a device.
func (r *raw) StatFs(cancel <-chan struct{}, input *fuse.InHeader, out *fuse.StatfsOut) fuse.Status {
	out.Bsize = 4096
	out.Frsize = 4096
	out.NameLen = 255
	out.Blocks = 1 << 40
	out.Bfree = 1 << 40
	out.Bavail = 1 << 40
	return fuse.OK
}

// Mutating ops: EROFS — a read-only mount refuses them, it does not fail to
// understand them.

func (r *raw) SetAttr(cancel <-chan struct{}, input *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Mknod(cancel <-chan struct{}, input *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Mkdir(cancel <-chan struct{}, input *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Unlink(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Rmdir(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Rename(cancel <-chan struct{}, input *fuse.RenameIn, oldName, newName string) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Link(cancel <-chan struct{}, input *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Symlink(cancel <-chan struct{}, header *fuse.InHeader, pointedTo, linkName string, out *fuse.EntryOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Create(cancel <-chan struct{}, input *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Write(cancel <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	return 0, fuse.EROFS
}

func (r *raw) SetXAttr(cancel <-chan struct{}, input *fuse.SetXAttrIn, attr string, data []byte) fuse.Status {
	return fuse.EROFS
}

func (r *raw) RemoveXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string) fuse.Status {
	return fuse.EROFS
}

func (r *raw) Fallocate(cancel <-chan struct{}, in *fuse.FallocateIn) fuse.Status {
	return fuse.EROFS
}

func (r *raw) CopyFileRange(cancel <-chan struct{}, input *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	return 0, fuse.EROFS
}
