// Package rawfuse is the raw FUSE binding (docs/design-packfs.md, on the
// catalog-native mount): fuse.RawFileSystem mapped 1:1 onto the genfs
// generation resolver (Bind, read-only) or onto the write overlay over that
// generation (BindRW, read-write). A read-only binding answers EROFS to
// every mutating op — the op is understood and refused, not unimplemented.
//
// The immutability dividend: within a generation CLEAN inodes never change,
// so their EntryOut/AttrOut carry an effectively infinite validity and the
// kernel is the dentry/attr cache. DIRTY inodes — anything the overlay has
// touched — carry only a short validity so the kernel comes back for them.
// That split is the load-bearing correctness rule of the design.
//
// Residency is FORGET-driven: Lookup (and each entry a ReadDirPlus emits)
// counts as one nlookup against the base; Forget retires it. Plain ReadDir
// creates no residency.
package rawfuse

import (
	"context"
	"runtime"
	"strings"

	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/ui"
)

// entryValidity is the entry/attr TTL stamped on every CLEAN reply: ~10
// years, effectively infinite. Clean inodes never change within a
// generation; a generation swap invalidates by notification, not by TTL
// expiry.
const entryValidity = 10 * 365 * 24 * time.Hour

// dirtyValidity is the entry/attr TTL stamped on a DIRTY reply: short,
// deliberately not zero. Zero is the maximally conservative answer and an
// unpack pays for it — with no attribute cache the kernel re-asks about
// every change it made itself, which measures 5 GETATTRs and 2 LOOKUPs
// per created file, 14 FUSE round trips for a file that needs 8.
//
// A short TTL is sound because the overlay has exactly one writer. The
// mount owns it exclusively (the database is opened locking_mode
// EXCLUSIVE), so nothing mutates an inode except an operation the kernel
// itself issued, and the reply to that operation refreshes the very cache
// entry in question. What the kernel can hold is therefore its own most
// recent view, never someone else's stale one.
//
// It stays short rather than infinite so that the one transition which
// does move state out from under the kernel — a mid-session checkpoint
// returning inodes to clean — converges on its own even if a
// notification is missed.
const dirtyValidity = time.Second

// errStale maps genfs.ErrStale: the kernel references an inode it never
// looked up (or already forgot).
var errStale = fuse.Status(syscall.ESTALE)

// reader is the read surface both layers implement: genfs.FS over a clean
// generation and overlay.FS over the merged view. overlay's Node/DirEntry
// are aliases of the genfs types, so one shape serves both.
type reader interface {
	Lookup(ctx context.Context, parent uint64, name string) (genfs.Node, error)
	GetAttr(ctx context.Context, ino uint64) (genfs.Node, error)
	Readdir(ctx context.Context, ino uint64) ([]genfs.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error)
	ListXattr(ctx context.Context, ino uint64) ([]string, error)
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
	Forget(ino uint64, nlookup uint64)
}

// Bind wraps a genfs generation as a read-only raw FUSE filesystem.
func Bind(fs *genfs.FS) fuse.RawFileSystem {
	return newRaw(fs, nil)
}

func newRaw(rd reader, ov *overlay.FS) *raw {
	r := &raw{
		RawFileSystem: fuse.NewDefaultRawFileSystem(),
		fs:            rd,
		ov:            ov,
		dirs:          make(map[uint64]*dirHandle),
	}
	if ov != nil {
		r.dirty = newDirtySet(ov)
	}
	return r
}

// Mount serves fs at mountpoint (Linux FUSE / macFUSE) read-only and
// returns the running server once the mount is complete.
func Mount(mountpoint string, fs *genfs.FS, debug bool) (*fuse.Server, error) {
	return mount(mountpoint, Bind(fs), debug, true)
}

func mount(mountpoint string, rfs fuse.RawFileSystem, debug, readOnly bool) (*fuse.Server, error) {
	// Access stays ENOSYS: with default_permissions the kernel checks
	// permissions itself from the attrs it already holds.
	options := []string{"default_permissions"}
	if readOnly {
		options = append([]string{"ro"}, options...)
	}
	opts := &fuse.MountOptions{
		AllowOther: false,
		FsName:     "pelfs",
		Name:       "pelfs",
		Debug:      debug,
		Options:    options,
	}
	srv, err := fuse.NewServer(rfs, mountpoint, opts)
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

// raw binds one layer to the raw FUSE protocol. Ops not implemented here
// come from NewDefaultRawFileSystem (ENOSYS), except the mutating set,
// which is refused with EROFS when ov is nil (read-only binding).
type raw struct {
	fuse.RawFileSystem
	fs reader
	// ov is the write half; nil means a read-only binding.
	ov *overlay.FS
	// dirty is the TTL predicate, nil alongside ov.
	dirty *dirtySet

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

// errStatus is the single error translator for both halves; the overlay's
// sentinels join genfs's. Anything unrecognized is EIO — the kernel must
// never see a Go error shape.
func errStatus(err error) fuse.Status {
	switch {
	case errors.Is(err, genfs.ErrNotExist):
		return fuse.ENOENT
	case errors.Is(err, genfs.ErrStale):
		return errStale
	case errors.Is(err, overlay.ErrExist):
		return errExist
	case errors.Is(err, overlay.ErrNotEmpty):
		return errNotEmpty
	case errors.Is(err, overlay.ErrNotDir):
		return fuse.ENOTDIR
	case errors.Is(err, overlay.ErrIsDir):
		return fuse.EISDIR
	case errors.Is(err, context.Canceled):
		return fuse.EINTR
	}
	// Anything unrecognized becomes EIO. Log it: a bare "Input/output
	// error" reaching a user through tar or cp, with no record anywhere
	// of what actually failed, is undebuggable -- and EIO is exactly the
	// status we return when we do not understand our own failure, so it
	// is the one that most needs explaining. These are meant to be rare;
	// if a workload produces them in bulk, the count carried by the next
	// report is the signal.
	logUnexpected(err)
	return fuse.EIO
}

// eioReportEvery bounds how often the EIO explainer speaks. One
// untranslatable error is almost never one operation -- a broken file
// answers every read a tar issues -- so this sits on a per-operation
// path, where naming the caller's frame and formatting a line cost
// orders of magnitude more than the reply itself. Suppressed
// occurrences are counted and reported by the next line that gets
// through, so bulk failure stays visible without being expensive.
const eioReportEvery = 10 * time.Second

var (
	eioSuppressed atomic.Int64
	eioReportedAt atomic.Int64 // unix nanos; zero reports the first one
)

// logUnexpected reports an error the binding could not translate,
// attributing it to the FUSE operation that produced it. The op name
// comes from the caller's frame rather than a parameter threaded through
// twenty call sites -- it is paid only by the lines actually emitted.
func logUnexpected(err error) {
	now := time.Now().UnixNano()
	last := eioReportedAt.Load()
	if now-last < int64(eioReportEvery) || !eioReportedAt.CompareAndSwap(last, now) {
		eioSuppressed.Add(1)
		return
	}
	op := "fuse"
	if pc, _, _, ok := runtime.Caller(2); ok {
		if fn := runtime.FuncForPC(pc); fn != nil {
			name := fn.Name()
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			op = name
		}
	}
	if n := eioSuppressed.Swap(0); n > 0 {
		ui.Error("{op}: returning EIO for an unrecognized error: {error} (and {suppressed} more like it since the last report)",
			"op", op, "error", err, "suppressed", n)
		return
	}
	ui.Error("{op}: returning EIO for an unrecognized error: {error}", "op", op, "error", err)
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

// validity is the TTL for one inode's reply: effectively infinite while
// the inode is clean (immutable within the generation), and briefly valid
// once the overlay has touched it (see dirtyValidity).
func (r *raw) validity(ino uint64) time.Duration {
	if r.isDirty(ino) {
		return dirtyValidity
	}
	return entryValidity
}

// isDirty is the overlay-touched predicate on its own. Page-cache
// retention keys off this rather than off the reply's TTL: the two
// policies answer different questions, and only one of them is a
// duration.
func (r *raw) isDirty(ino uint64) bool {
	return r.dirty != nil && r.dirty.has(ino)
}

// fillEntry completes an EntryOut: stable inode as NodeId (inodes NEVER
// recycle within a mount, hence Generation 0) and the inode's validity.
func (r *raw) fillEntry(n *genfs.Node, out *fuse.EntryOut) {
	out.NodeId = n.Inode
	out.Generation = 0
	fillAttr(n, &out.Attr)
	v := r.validity(n.Inode)
	out.SetEntryTimeout(v)
	out.SetAttrTimeout(v)
}

func (r *raw) Lookup(cancel <-chan struct{}, header *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	n, err := r.fs.Lookup(ctxOf(cancel), header.NodeId, name)
	if err != nil {
		return errStatus(err)
	}
	r.fillEntry(&n, out)
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
	out.SetTimeout(r.validity(input.NodeId))
	return fuse.OK
}

// Open is stateless (Fh 0). FOPEN_KEEP_CACHE holds the page cache across
// close/open, which is sound only while the content is immutable: a
// read-only binding always keeps it, a read-write one drops it for a
// writable open or an already-dirty inode. Write access itself is refused
// up front on a read-only binding.
func (r *raw) Open(cancel <-chan struct{}, input *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	writable := input.Flags&fuse.O_ANYWRITE != 0
	if writable && r.ov == nil {
		return fuse.EROFS
	}
	out.Fh = 0
	if !writable && !r.isDirty(input.NodeId) {
		out.OpenFlags |= fuse.FOPEN_KEEP_CACHE
	}
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
			// The listing is a snapshot; an entry can only vanish from
			// under it via this mount's own overlay. Emit it uncached
			// rather than fail the whole page.
			continue
		}
		r.fillEntry(&n, eo)
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

// The mutating ops live in rw.go: they refuse with EROFS when ov is nil (a
// read-only mount understands them, it does not fail to parse them) and
// forward to the overlay otherwise.

func (r *raw) Fallocate(cancel <-chan struct{}, in *fuse.FallocateIn) fuse.Status {
	// Not implemented even read-write: the overlay has no preallocation
	// primitive, and the format has no holes to reserve.
	return fuse.EROFS
}

func (r *raw) CopyFileRange(cancel <-chan struct{}, input *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	// Left to the kernel's read/write fallback; a server-side copy would
	// duplicate staging bytes for no gain in v0.
	return 0, fuse.EROFS
}
