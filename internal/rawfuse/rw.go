//go:build !windows

package rawfuse

import (
	"context"
	"errors"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fsperm"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// Statuses the fuse package does not name.
const (
	errExist    = fuse.Status(syscall.EEXIST)
	errNotEmpty = fuse.Status(syscall.ENOTEMPTY)
)

// BindRW binds a read-write overlay over one base generation. The read
// half behaves exactly as Bind's — the overlay serves the merged view
// through the same read interface — and mutating ops go to the overlay.
func BindRW(ov *overlay.FS) fuse.RawFileSystem {
	return newRaw(ov, ov, nil)
}

// BindRWChecked is BindRW for a mount whose options pelfs did not choose;
// see BindChecked and perm.go.
func BindRWChecked(ov *overlay.FS) fuse.RawFileSystem {
	cred := fsperm.ProcessCred()
	return newRaw(ov, ov, &cred)
}

// BindRWCheckedAs is BindRWChecked with the identity named explicitly; see
// BindCheckedAs.
func BindRWCheckedAs(ov *overlay.FS, cred fsperm.Cred) fuse.RawFileSystem {
	return newRaw(ov, ov, &cred)
}

// MountRW serves ov at mountpoint read-write and returns the running
// server once the mount is complete.
func MountRW(mountpoint string, ov *overlay.FS, debug bool) (*fuse.Server, error) {
	if PassedFD(mountpoint) {
		return mount(mountpoint, BindRWChecked(ov), debug, false)
	}
	return mount(mountpoint, BindRW(ov), debug, false)
}

// dirtySet answers the TTL question "has the overlay touched this inode".
// Clean inodes get effectively infinite entry/attr validity (the kernel
// becomes the dentry cache); dirty ones get only dirtyValidity, so the
// kernel re-asks about anything the overlay is changing.
//
// The overlay is the authority (IsDirty: one indexed EXISTS), consulted
// lazily and cached positively. Dirt is sticky for an overlay's lifetime
// — rows persist until seal — so a positive answer never needs
// rechecking, and clean inodes cost one query the FIRST time the kernel
// looks them up and nothing after that, since the reply it caches is the
// infinite-TTL one. A query error is treated as dirty: correct and slow
// beats fast and stale.
type dirtySet struct {
	ov *overlay.FS

	mu  sync.RWMutex
	set map[uint64]struct{}
}

func newDirtySet(ov *overlay.FS) *dirtySet {
	return &dirtySet{ov: ov, set: make(map[uint64]struct{})}
}

func (d *dirtySet) has(ino uint64) bool {
	d.mu.RLock()
	_, ok := d.set[ino]
	d.mu.RUnlock()
	if ok {
		return true
	}
	dirty, err := d.ov.IsDirty(ino)
	if err != nil {
		return true
	}
	if dirty {
		d.mark(ino)
	}
	return dirty
}

// mark records inodes as dirty without consulting the overlay. Callers
// mark BEFORE a mutation whenever the inode number is already known, so
// no reply can slip out with an infinite TTL between the change and the
// marking; a spurious mark from a failed operation only costs TTL.
func (d *dirtySet) mark(inos ...uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ino := range inos {
		if ino != 0 {
			d.set[ino] = struct{}{}
		}
	}
}

// catalogType maps a mknod mode's S_IFMT bits to a catalog entry type. A
// bare mode with no type bits is a regular file (POSIX mknod).
func catalogType(mode uint32) (uint8, bool) {
	switch mode & syscall.S_IFMT {
	case 0, syscall.S_IFREG:
		return catalog.TypeFile, true
	case syscall.S_IFIFO:
		return catalog.TypeFIFO, true
	case syscall.S_IFBLK:
		return catalog.TypeBlockDev, true
	case syscall.S_IFCHR:
		return catalog.TypeCharDev, true
	case syscall.S_IFSOCK:
		return catalog.TypeSocket, true
	}
	return 0, false
}

// Create allocates the file and opens it in one round trip: EntryOut plus
// OpenOut, the latter WITHOUT FOPEN_KEEP_CACHE — immutability no longer
// holds for an inode this mount is about to write.
func (r *raw) Create(cancel <-chan struct{}, input *fuse.CreateIn, name string, out *fuse.CreateOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayCreateIn(ctx, &input.InHeader, input.NodeId); st != fuse.OK {
		return st
	}
	r.dirty.mark(input.NodeId)
	n, err := r.ov.Create(ctx, input.NodeId, name,
		input.Mode&^uint32(syscall.S_IFMT), input.Uid, input.Gid)
	if err != nil {
		return errStatus(err)
	}
	// The inode is new: nothing can have cached it, so marking after the
	// allocation is still airtight.
	r.dirty.mark(n.Inode)
	r.fillEntry(&n, &out.EntryOut)
	out.Fh = 0
	return fuse.OK
}

func (r *raw) Mknod(cancel <-chan struct{}, input *fuse.MknodIn, name string, out *fuse.EntryOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	typ, ok := catalogType(input.Mode)
	if !ok {
		return fuse.EINVAL // mknod of a directory or symlink
	}
	ctx := ctxOf(cancel)
	if st := r.mayCreateIn(ctx, &input.InHeader, input.NodeId); st != fuse.OK {
		return st
	}
	mode := input.Mode &^ uint32(syscall.S_IFMT)
	r.dirty.mark(input.NodeId)
	var n overlay.Node
	var err error
	if typ == catalog.TypeFile {
		n, err = r.ov.Create(ctx, input.NodeId, name, mode, input.Uid, input.Gid)
	} else {
		n, err = r.ov.Mknod(ctx, input.NodeId, name, typ, mode, input.Uid, input.Gid, input.Rdev)
	}
	if err != nil {
		return errStatus(err)
	}
	r.dirty.mark(n.Inode)
	r.fillEntry(&n, out)
	return fuse.OK
}

func (r *raw) Mkdir(cancel <-chan struct{}, input *fuse.MkdirIn, name string, out *fuse.EntryOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayCreateIn(ctx, &input.InHeader, input.NodeId); st != fuse.OK {
		return st
	}
	r.dirty.mark(input.NodeId)
	n, err := r.ov.Mkdir(ctx, input.NodeId, name,
		input.Mode&^uint32(syscall.S_IFMT), input.Uid, input.Gid)
	if err != nil {
		return errStatus(err)
	}
	r.dirty.mark(n.Inode)
	r.fillEntry(&n, out)
	return fuse.OK
}

func (r *raw) Symlink(cancel <-chan struct{}, header *fuse.InHeader, pointedTo, linkName string, out *fuse.EntryOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayCreateIn(ctx, header, header.NodeId); st != fuse.OK {
		return st
	}
	r.dirty.mark(header.NodeId)
	n, err := r.ov.Symlink(ctx, header.NodeId, linkName, pointedTo, header.Uid, header.Gid)
	if err != nil {
		return errStatus(err)
	}
	r.dirty.mark(n.Inode)
	r.fillEntry(&n, out)
	return fuse.OK
}

// Link hard-links Oldnodeid into (NodeId, name).
//
// This is the ONE request that names a non-directory by BARE INODE and
// resolves no name for it, which makes it the one place a layer below can
// be handed an inode with no descent behind it. Worth naming, because a
// bug was filed against exactly that (see persistChainLocked in
// internal/overlay): the write path cached a base descent step per inode,
// a checkpoint started sweeping the cache to bound its memory, and a plain
// `ln` of a file the kernel still had a cached dentry for arrived here with
// nothing to refill it. The dirty set below is half of when that happens —
// its stickiness is what keeps a dentry's TTL down to a second for
// anything THIS session touched, so the reachable shape is a second
// session over a file an earlier one published.
//
// The audit behind "the one": across every FUSE request struct, the only
// inode numbers are InHeader.NodeId (the operand or parent, which every
// handler here treats as such), LinkIn.Oldnodeid (this), RenameIn.Newdir
// — a destination DIRECTORY that always travels with newName, and
// overlay.Rename takes (parent, name) pairs, so its subject is resolved by
// construction — and CopyFileRangeIn.NodeIdOut, which is refused with
// EROFS (rawfuse.go) and would be the second door to this class if it were
// ever implemented. Everything else is a file handle, an offset, a length,
// a lock owner: Open hands out Fh 0, so there is no open-by-handle path at
// all, and a dir handle only ever remembers the NodeId its OPENDIR
// carried. FORGET is the other half of why the fallback is dependable
// here: overlay.Forget is a no-op, so base residency on a read-write mount
// outlives anything the kernel says about it.
func (r *raw) Link(cancel <-chan struct{}, input *fuse.LinkIn, name string, out *fuse.EntryOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayCreateIn(ctx, &input.InHeader, input.NodeId); st != fuse.OK {
		return st
	}
	r.dirty.mark(input.NodeId, input.Oldnodeid)
	n, err := r.ov.Link(ctx, input.Oldnodeid, input.NodeId, name)
	if err != nil {
		return errStatus(err)
	}
	r.fillEntry(&n, out)
	return fuse.OK
}

func (r *raw) Unlink(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayRemoveFrom(ctx, header, header.NodeId, name); st != fuse.OK {
		return st
	}
	r.dirty.mark(header.NodeId)
	if n, err := r.fs.Lookup(ctx, header.NodeId, name); err == nil {
		// A surviving hardlink keeps the inode addressable, so its nlink
		// is dirty even though this name is gone.
		r.dirty.mark(n.Inode)
	}
	if err := r.ov.Unlink(ctx, header.NodeId, name); err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

func (r *raw) Rmdir(cancel <-chan struct{}, header *fuse.InHeader, name string) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.mayRemoveFrom(ctx, header, header.NodeId, name); st != fuse.OK {
		return st
	}
	r.dirty.mark(header.NodeId)
	if err := r.ov.Rmdir(ctx, header.NodeId, name); err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

// Rename moves (NodeId, oldName) to (Newdir, newName), replacing an
// existing destination.
func (r *raw) Rename(cancel <-chan struct{}, input *fuse.RenameIn, oldName, newName string) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	if input.Flags != 0 {
		// RENAME_EXCHANGE/RENAME_NOREPLACE have no overlay primitive;
		// ENOSYS makes the kernel stop asking for the flagged form.
		return fuse.ENOSYS
	}
	ctx := ctxOf(cancel)
	// Both ends: the name leaves one directory and enters another, and the
	// sticky rule applies to the departure exactly as it does to an unlink.
	if st := r.mayRemoveFrom(ctx, &input.InHeader, input.NodeId, oldName); st != fuse.OK {
		return st
	}
	if st := r.mayRemoveFrom(ctx, &input.InHeader, input.Newdir, newName); st != fuse.OK {
		return st
	}
	src, err := r.fs.Lookup(ctx, input.NodeId, oldName)
	if err != nil {
		return errStatus(err)
	}
	if src.Type == catalog.TypeDir {
		// Documented deviation: the overlay defers loop prevention to the
		// binding, so the descendant check happens here.
		if r.descendantOf(ctx, src.Inode, input.Newdir) {
			return fuse.EINVAL
		}
	}
	r.dirty.mark(input.NodeId, input.Newdir, src.Inode)
	if dst, err := r.fs.Lookup(ctx, input.Newdir, newName); err == nil {
		r.dirty.mark(dst.Inode) // replaced: its last link may be going away
	}
	if err := r.ov.Rename(ctx, input.NodeId, oldName, input.Newdir, newName); err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

// descendantOf reports whether ino is root itself or lies under it. The
// catalog is a locator by DESCENT — no parent pointers, by design — so the
// walk goes down from root instead of up from ino.
//
// Unlistable directories are pruned rather than propagated as errors: the
// kernel named ino in the request, so it looked ino up, so every ancestor
// of ino is resident and listable. A directory this walk cannot list is
// therefore not on the path to ino, and skipping it cannot hide a loop.
// The same fact bounds the cost — the walk only ever descends resident
// subtrees, and only rename of a directory pays it.
func (r *raw) descendantOf(ctx context.Context, root, ino uint64) bool {
	if root == ino {
		return true
	}
	seen := map[uint64]bool{root: true}
	queue := []uint64{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		entries, err := r.fs.Readdir(ctx, dir)
		if err != nil {
			continue
		}
		for i := range entries {
			child := entries[i].Node
			if child.Type != catalog.TypeDir || seen[child.Inode] {
				continue
			}
			if child.Inode == ino {
				return true
			}
			seen[child.Inode] = true
			queue = append(queue, child.Inode)
		}
	}
	return false
}

// SetAttr translates the FATTR_* valid bits into the overlay's optional
// fields. ATIME (and ATIME_NOW) are accepted and DISCARDED: the format
// carries no atime by design — reads must never dirty metadata on a
// publish-what-changed filesystem — so utimensat's atime half has nowhere
// to land and failing the whole call would break `touch`.
func (r *raw) SetAttr(cancel <-chan struct{}, input *fuse.SetAttrIn, out *fuse.AttrOut) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.maySetAttr(ctx, input); st != fuse.OK {
		return st
	}
	var in overlay.SetAttrIn
	if mode, ok := input.GetMode(); ok {
		in.Mode = &mode
	}
	if uid, ok := input.GetUID(); ok {
		in.UID = &uid
	}
	if gid, ok := input.GetGID(); ok {
		in.GID = &gid
	}
	if size, ok := input.GetSize(); ok {
		sz := int64(size)
		in.Size = &sz
	}
	// GetMTime resolves FATTR_MTIME_NOW to the current time for us.
	if mtime, ok := input.GetMTime(); ok {
		ns := mtime.UnixNano()
		in.MtimeNS = &ns
	}
	r.dirty.mark(input.NodeId)
	n, err := r.ov.SetAttr(ctx, input.NodeId, in)
	if err != nil {
		return errStatus(err)
	}
	r.fillAttr(&n, &out.Attr)
	out.SetTimeout(r.validity(input.NodeId))
	return fuse.OK
}

// Write honors the header's Size against the payload the server handed us
// (a spliced read can carry a longer buffer) and reports the byte count
// the overlay committed.
func (r *raw) Write(cancel <-chan struct{}, input *fuse.WriteIn, data []byte) (uint32, fuse.Status) {
	if r.ov == nil {
		return 0, fuse.EROFS
	}
	if int(input.Size) < len(data) {
		data = data[:input.Size]
	}
	r.dirty.mark(input.NodeId)
	n, err := r.ov.Write(ctxOf(cancel), input.NodeId, int64(input.Offset), data)
	if err != nil {
		return 0, errStatus(err)
	}
	return uint32(n), fuse.OK
}

// SetXAttr ignores XATTR_CREATE/XATTR_REPLACE: the overlay's set is
// unconditional and has no guarded form (documented deviation).
func (r *raw) SetXAttr(cancel <-chan struct{}, input *fuse.SetXAttrIn, attr string, data []byte) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	// The kernel's xattr_permission: setting or removing one costs write
	// permission on the object.
	if st := r.may(ctx, &input.InHeader, input.NodeId, fsperm.PermWrite); st != fuse.OK {
		return st
	}
	r.dirty.mark(input.NodeId)
	if err := r.ov.SetXattr(ctx, input.NodeId, attr, data); err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

func (r *raw) RemoveXAttr(cancel <-chan struct{}, header *fuse.InHeader, attr string) fuse.Status {
	if r.ov == nil {
		return fuse.EROFS
	}
	ctx := ctxOf(cancel)
	if st := r.may(ctx, header, header.NodeId, fsperm.PermWrite); st != fuse.OK {
		return st
	}
	r.dirty.mark(header.NodeId)
	err := r.ov.RemoveXattr(ctx, header.NodeId, attr)
	if errors.Is(err, genfs.ErrNotExist) {
		// Absence of the attribute, not of the inode: the xattr protocol
		// spells that ENODATA/ENOATTR.
		return errNoXattr
	}
	if err != nil {
		return errStatus(err)
	}
	return fuse.OK
}

// Flush and Fsync succeed: the overlay commits one SQLite transaction per
// operation, so everything already returned is durable by the time these
// run. Neither op publishes — sealing the overlay into a new generation
// for the federation is a separate, explicit step.
func (r *raw) Flush(cancel <-chan struct{}, input *fuse.FlushIn) fuse.Status { return fuse.OK }

func (r *raw) Fsync(cancel <-chan struct{}, input *fuse.FsyncIn) fuse.Status { return fuse.OK }

func (r *raw) FsyncDir(cancel <-chan struct{}, input *fuse.FsyncIn) fuse.Status { return fuse.OK }
