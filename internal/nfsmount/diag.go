package nfsmount

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"

	"github.com/bbockelm/pelfs/internal/ui"
)

// This file gives the NFS frontend the diagnosis the FUSE binding already
// has (internal/rawfuse, errStatus/logUnexpected), and it has to be built
// differently because the translation it explains does not happen here.
//
// On the FUSE side we own the error-to-status switch, so an unrecognized
// error can be logged at the moment it becomes EIO. On the NFS side that
// switch lives inside go-nfs, one call site per RPC handler, and those
// handlers recognize exactly three error shapes: os.IsNotExist,
// os.IsExist, os.IsPermission (plus ENOSPC/EDQUOT/EFBIG on the write
// path, via statusFromWriteError). Anything else is discarded in favor of
// a fixed status the handler picked in advance -- usually NFS3ERR_IO,
// which is what a client reports as "Input/output error".
//
// The worst offender is SetFileAttributes.Apply, which every CREATE,
// MKDIR and SYMLINK runs to stamp the requested mode and times on the new
// object. It returns raw billy errors, and onCreate/onMkdir/onSymlink
// wrap whatever it returns in NFSStatusIO unconditionally. So a chmod
// that fails for a reason go-nfs cannot name turns a perfectly successful
// create into "Can't create: Input/output error", with nothing logged
// anywhere.
//
// The one place we can still see the error is the billy.Filesystem we
// hand go-nfs. Wrapping it puts an observer on the last edge before the
// information is lost, and it is a better vantage point than the FUSE one
// besides: the wrapper knows the operation and the path, so neither has
// to be recovered from a stack frame.

// eioReportEvery bounds how often the explainer speaks. One
// untranslatable error is rarely one operation -- a client retries, and a
// broken subtree answers every RPC a tar issues -- so this sits on a
// per-operation path where formatting a line costs orders of magnitude
// more than the reply itself. Suppressed occurrences are counted and
// reported by the next line that gets through, so bulk failure stays
// visible without being expensive.
const eioReportEvery = 10 * time.Second

var (
	eioSuppressed atomic.Int64
	eioReportedAt atomic.Int64 // unix nanos; zero reports the first one
)

// translatable reports whether go-nfs can turn err into an NFS status
// that says what actually happened. Everything outside this set reaches
// the client as whatever fixed status the handler settled on before it
// looked, which is why it is the set worth reporting.
//
// io.EOF is here because the READ handler tests for it explicitly; it is
// an end-of-file marker, not a failure.
//
// ENOTEMPTY is excluded FIRST because syscall.Errno.Is answers true for
// errors.Is(ENOTEMPTY, os.ErrExist) -- an alias that is fair for a caller
// asking "did this fail because something was already there" and a trap
// here, where it would name the wrong status. RMDIR is answered by go-nfs
// itself, which lists the directory before removing it; an ENOTEMPTY that
// still reaches this wrapper lost a race and is worth a line.
func translatable(err error) bool {
	if errors.Is(err, syscall.ENOTEMPTY) {
		return false
	}
	switch {
	case err == nil,
		errors.Is(err, os.ErrNotExist),
		errors.Is(err, os.ErrExist),
		errors.Is(err, os.ErrPermission),
		errors.Is(err, io.EOF),
		errors.Is(err, syscall.ENOSPC),
		errors.Is(err, syscall.EDQUOT),
		errors.Is(err, syscall.EFBIG):
		return true
	}
	return false
}

// statusOf is the NFS status that describes err. It is the mapping
// go-nfs's handlers would make if they made one; NFSStatusIO is the
// answer only when nothing else fits.
func statusOf(err error) nfs.NFSStatus {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nfs.NFSStatusNoEnt
	case errors.Is(err, syscall.ENOTEMPTY): // before ErrExist; see translatable
		return nfs.NFSStatusNotEmpty
	case errors.Is(err, os.ErrExist):
		return nfs.NFSStatusExist
	case errors.Is(err, os.ErrPermission):
		return nfs.NFSStatusAccess
	case errors.Is(err, syscall.ESTALE):
		return nfs.NFSStatusStale
	case errors.Is(err, syscall.ENOTDIR):
		return nfs.NFSStatusNotDir
	case errors.Is(err, syscall.EISDIR):
		return nfs.NFSStatusIsDir
	case errors.Is(err, syscall.EINVAL):
		return nfs.NFSStatusInval
	case errors.Is(err, syscall.ENOSPC):
		return nfs.NFSStatusNoSPC
	case errors.Is(err, syscall.EDQUOT):
		return nfs.NFSStatusDQuot
	case errors.Is(err, syscall.EFBIG):
		return nfs.NFSStatusFBig
	}
	return nfs.NFSStatusIO
}

// attrErr is the return path for the attribute setters. Their errors have
// exactly one consumer in go-nfs -- SetFileAttributes.Apply, which every
// SETATTR, CREATE, MKDIR, SYMLINK and LINK runs -- and Apply recognizes
// only os.ErrPermission, returning anything else RAW. What becomes of a
// raw error there depends on the RPC, and neither outcome is acceptable:
// onCreate, onMkdir and onSymlink wrap it in NFSStatusIO, while onSetAttr
// returns it as though it were already an NFS status, whereupon the
// response formatter finds a type it does not recognize and answers with
// an RPC-LEVEL system error -- a malformed reply rather than a status,
// which clients report as EIO with no status to explain it.
//
// Attaching a status here fixes the SETATTR case outright and reports the
// others. Wrapping keeps the error chain intact, so Apply's
// os.ErrPermission test still sees through it.
func attrErr(op, path string, err error) error {
	if err == nil {
		return nil
	}
	st := statusOf(err)
	if st == nfs.NFSStatusIO {
		report(op, path, toldEIO, err)
	}
	return &nfs.NFSStatusError{NFSStatus: st, WrappedErr: err}
}

// The status go-nfs answers when it cannot place an error, which differs
// by RPC and is what the report has to name if it is to be true. The
// handlers that reach each billy method are listed with the method.
const (
	// onGetattr, onRemove, onRmdir, onRename, onRead: anything unplaced
	// becomes NFS3ERR_IO.
	toldEIO = "EIO"
	// onCreate, onMkdir, onSymlink, onWrite's open, onRead's open,
	// onReadlink: unplaced errors become NFS3ERR_ACCES, which is no more
	// true than EIO and just as unexplained.
	toldEACCES = "EACCES"
	// onReaddir, onReaddirplus: NFS3ERR_NOTDIR for anything but a
	// permission error.
	toldENOTDIR = "ENOTDIR"
)

// explain returns err unchanged, reporting it first if go-nfs is about to
// discard it in favor of told. It is written to be wrapped around a return
// value so no call site grows a branch.
func explain(op, path, told string, err error) error {
	if translatable(err) {
		return err
	}
	report(op, path, told, err)
	return err
}

// report emits at most one line per eioReportEvery. The suppressed path
// must not allocate: a workload that trips this trips it thousands of
// times, and the reply it is delaying is the thing the client is waiting
// for.
func report(op, path, told string, err error) {
	now := time.Now().UnixNano()
	last := eioReportedAt.Load()
	if now-last < int64(eioReportEvery) || !eioReportedAt.CompareAndSwap(last, now) {
		eioSuppressed.Add(1)
		return
	}
	if n := eioSuppressed.Swap(0); n > 0 {
		ui.Error("nfs {op} {path}: no NFS status describes this error, so the client is told {told}: {error} (and {suppressed} more like it since the last report)",
			"op", op, "path", path, "told", told, "error", err, "suppressed", n)
		return
	}
	ui.Error("nfs {op} {path}: no NFS status describes this error, so the client is told {told}: {error}",
		"op", op, "path", path, "told", told, "error", err)
}

// diagnose wraps fs so that every error it returns passes the explainer
// before go-nfs gets a chance to discard it.
func diagnose(fs billy.Filesystem) billy.Filesystem {
	d := diagFS{Filesystem: fs}
	// Neither billy.Change nor nfs.HardLinker is part of billy.Filesystem,
	// and go-nfs decides whether SETATTR and LINK are supported at all by
	// type-asserting for them. A wrapper that always implemented them
	// would claim support the wrapped filesystem does not have, so the
	// assertions are answered by which type is returned.
	ch, changeable := fs.(billy.Change)
	ln, linkable := fs.(nfs.HardLinker)
	switch {
	case changeable && linkable:
		return &diagChangeLinkFS{diagChangeFS{diagFS: d, ch: ch}, diagLinker{ln}}
	case changeable:
		return &diagChangeFS{diagFS: d, ch: ch}
	case linkable:
		return &diagLinkFS{d, diagLinker{ln}}
	}
	return &d
}

type diagFS struct {
	billy.Filesystem
}

type diagChangeFS struct {
	diagFS
	ch billy.Change
}

// diagLinker carries the hard-link half, so the two wrapper shapes that
// need it share one implementation.
type diagLinker struct {
	ln nfs.HardLinker
}

func (d diagLinker) Link(oldname, newname string) error {
	return explain("link", newname, toldEIO, d.ln.Link(oldname, newname))
}

type diagLinkFS struct {
	diagFS
	diagLinker
}

type diagChangeLinkFS struct {
	diagChangeFS
	diagLinker
}

var (
	_ billy.Filesystem = (*diagFS)(nil)
	_ billy.Capable    = (*diagFS)(nil)
	_ billy.Change     = (*diagChangeFS)(nil)
	_ billy.Change     = (*diagChangeLinkFS)(nil)
	_ nfs.HardLinker   = (*diagLinkFS)(nil)
	_ nfs.HardLinker   = (*diagChangeLinkFS)(nil)
)

// Capabilities is forwarded explicitly: it is not part of
// billy.Filesystem, so embedding does not carry it, and go-nfs refuses
// every mutating RPC with ROFS on a filesystem that does not advertise
// WriteCapability. billy.Capabilities answers AllCapabilities for a
// filesystem that does not implement Capable, which is the same default
// go-nfs would have applied to the unwrapped value.
func (d *diagFS) Capabilities() billy.Capability {
	return billy.Capabilities(d.Filesystem)
}

func (d *diagFS) Create(filename string) (billy.File, error) {
	f, err := d.Filesystem.Create(filename)
	return d.wrap(f), explain("create", filename, toldEACCES, err)
}

func (d *diagFS) Open(filename string) (billy.File, error) {
	f, err := d.Filesystem.Open(filename)
	return d.wrap(f), explain("open", filename, toldEACCES, err)
}

func (d *diagFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	f, err := d.Filesystem.OpenFile(filename, flag, perm)
	return d.wrap(f), explain("open", filename, toldEACCES, err)
}

func (d *diagFS) Stat(filename string) (os.FileInfo, error) {
	fi, err := d.Filesystem.Stat(filename)
	return fi, explain("stat", filename, toldEIO, err)
}

func (d *diagFS) Rename(oldpath, newpath string) error {
	return explain("rename", oldpath, toldEIO, d.Filesystem.Rename(oldpath, newpath))
}

func (d *diagFS) Remove(filename string) error {
	return explain("remove", filename, toldEIO, d.Filesystem.Remove(filename))
}

func (d *diagFS) TempFile(dir, prefix string) (billy.File, error) {
	f, err := d.Filesystem.TempFile(dir, prefix)
	return d.wrap(f), explain("tempfile", dir, toldEACCES, err)
}

func (d *diagFS) ReadDir(path string) ([]os.FileInfo, error) {
	entries, err := d.Filesystem.ReadDir(path)
	return entries, explain("readdir", path, toldENOTDIR, err)
}

func (d *diagFS) MkdirAll(filename string, perm os.FileMode) error {
	return explain("mkdir", filename, toldEACCES, d.Filesystem.MkdirAll(filename, perm))
}

func (d *diagFS) Lstat(filename string) (os.FileInfo, error) {
	fi, err := d.Filesystem.Lstat(filename)
	return fi, explain("lstat", filename, toldEIO, err)
}

func (d *diagFS) Symlink(target, link string) error {
	return explain("symlink", link, toldEACCES, d.Filesystem.Symlink(target, link))
}

func (d *diagFS) Readlink(link string) (string, error) {
	target, err := d.Filesystem.Readlink(link)
	return target, explain("readlink", link, toldEACCES, err)
}

func (d *diagFS) Chroot(path string) (billy.Filesystem, error) {
	inner, err := d.Filesystem.Chroot(path)
	if err != nil {
		return nil, explain("chroot", path, toldEIO, err)
	}
	return diagnose(inner), nil
}

func (d *diagChangeFS) Chmod(name string, mode os.FileMode) error {
	return attrErr("chmod", name, d.ch.Chmod(name, mode))
}

func (d *diagChangeFS) Lchown(name string, uid, gid int) error {
	return attrErr("lchown", name, d.ch.Lchown(name, uid, gid))
}

func (d *diagChangeFS) Chown(name string, uid, gid int) error {
	return attrErr("chown", name, d.ch.Chown(name, uid, gid))
}

func (d *diagChangeFS) Chtimes(name string, atime, mtime time.Time) error {
	return attrErr("chtimes", name, d.ch.Chtimes(name, atime, mtime))
}

// diagFile carries the same observation onto the handle. go-nfs turns a
// Truncate or Close failure into EIO exactly as readily as an open
// failure -- Apply's SetSize branch does both, on the CREATE path.
type diagFile struct {
	billy.File
}

var _ billy.File = (*diagFile)(nil)

func (d *diagFS) wrap(f billy.File) billy.File {
	if f == nil {
		// A billy.File nil interface must stay nil: callers test it.
		return nil
	}
	return &diagFile{File: f}
}

func (f *diagFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	return n, explain("read", f.File.Name(), toldEIO, err)
}

func (f *diagFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.File.ReadAt(p, off)
	return n, explain("read", f.File.Name(), toldEIO, err)
}

func (f *diagFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	return n, explain("write", f.File.Name(), toldEIO, err)
}

func (f *diagFile) Seek(offset int64, whence int) (int64, error) {
	pos, err := f.File.Seek(offset, whence)
	return pos, explain("seek", f.File.Name(), toldEIO, err)
}

// Truncate takes the attribute path too: go-nfs calls it from exactly one
// place, Apply's SetSize branch, and returns its error as raw as it
// returns a Chmod's.
func (f *diagFile) Truncate(size int64) error {
	return attrErr("truncate", f.File.Name(), f.File.Truncate(size))
}

func (f *diagFile) Close() error {
	return explain("close", f.File.Name(), toldEIO, f.File.Close())
}
