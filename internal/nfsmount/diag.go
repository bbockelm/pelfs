package nfsmount

import (
	"errors"
	"io"
	"os"
	"path"
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
	// EPERM before the os.ErrPermission catch-all, which BOTH EPERM and
	// EACCES satisfy. They are not synonyms and a client reports them
	// differently: NFS3ERR_PERM is "you are not the owner", which is what
	// chmod, utimes, chown and the sticky-bit rule answer
	// (internal/vfsbilly/perm.go), while NFS3ERR_ACCES is "the mode bits
	// say no". Collapsing them would have `chown` on this mount report
	// "Permission denied" where the FUSE frontend — and every local
	// filesystem — says "Operation not permitted".
	case errors.Is(err, syscall.EPERM):
		return nfs.NFSStatusPerm
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
//
// hide, when non-nil, is asked about the last component of every path this
// filesystem is given, and a name it claims is a name the mount does not
// have: lookups answer ENOENT and attempts to create one answer EACCES.
// The filter rides in THIS wrapper rather than a second one because the
// wrapper shape below is the expensive part -- one type per combination of
// the optional interfaces go-nfs type-asserts for -- and a second wrapper
// that answered those assertions differently would silently change which
// RPCs the mount supports. What is filtered, and why, is finderfiles.go.
func diagnose(fs billy.Filesystem, hide func(string) bool) billy.Filesystem {
	d := diagFS{Filesystem: fs, hide: hide}
	// None of billy.Change, nfs.HardLinker, nfs.PermissionChecker or
	// nfs.Committer is part of billy.Filesystem, and go-nfs decides
	// whether SETATTR, LINK, an honest ACCESS and a real COMMIT are
	// available at all by type-asserting for them. A wrapper that always
	// implemented them would claim support the wrapped filesystem does not
	// have -- and for two of the four that is not merely a claim. go-nfs
	// would ask a permission checker that cannot answer, and every ACCESS
	// would come back denying everything; it would take a Committer to
	// mean the filesystem BUFFERS, and start answering UNSTABLE to writes
	// while the commit that was supposed to redeem them did nothing. So
	// the assertions are answered by which type is returned, one shape per
	// combination. Sixteen of them, which is the honest cost of four
	// independent optional interfaces in a language with no dynamic
	// composition; the alternative is a wrapper that lies about one.
	ch, changeable := fs.(billy.Change)
	ln, linkable := fs.(nfs.HardLinker)
	pc, checks := fs.(nfs.PermissionChecker)
	cm, commits := fs.(nfs.Committer)
	c := diagChangeFS{diagFS: d, ch: ch}
	l := diagLinker{ln: ln, hide: hide}
	p := diagPermitter{pc}
	m := diagCommitter{cm: cm, hide: hide}
	switch {
	case changeable && linkable && checks && commits:
		return &diagChangeLinkPermCommitFS{c, l, p, m}
	case changeable && linkable && checks:
		return &diagChangeLinkPermFS{c, l, p}
	case changeable && linkable && commits:
		return &diagChangeLinkCommitFS{c, l, m}
	case changeable && checks && commits:
		return &diagChangePermCommitFS{c, p, m}
	case linkable && checks && commits:
		return &diagLinkPermCommitFS{d, l, p, m}
	case changeable && linkable:
		return &diagChangeLinkFS{c, l}
	case changeable && checks:
		return &diagChangePermFS{c, p}
	case changeable && commits:
		return &diagChangeCommitFS{c, m}
	case linkable && checks:
		return &diagLinkPermFS{d, l, p}
	case linkable && commits:
		return &diagLinkCommitFS{d, l, m}
	case checks && commits:
		return &diagPermCommitFS{d, p, m}
	case changeable:
		return &c
	case linkable:
		return &diagLinkFS{d, l}
	case checks:
		return &diagPermFS{d, p}
	case commits:
		return &diagCommitFS{d, m}
	}
	return &d
}

type diagFS struct {
	billy.Filesystem
	// hide is nil on every mount but a browsable one; see diagnose.
	hide func(string) bool
}

// hidden reports whether p names something this mount refuses to have.
// The predicate is asked about the last component only, which is what
// makes it depth-independent and correct under Chroot.
func (d *diagFS) hidden(p string) bool {
	return hides(d.hide, p)
}

// hides is the shared test, so the wrapper halves that carry their own
// copy of the predicate (diagLinker, diagCommitter) apply exactly the
// rule diagFS applies.
func hides(hide func(string) bool, p string) bool {
	return hide != nil && hide(path.Base(path.Clean(p)))
}

// absent is the answer to a lookup of a hidden name, and refused is the
// answer to an attempt to create one. Both are shapes go-nfs can already
// translate -- NFS3ERR_NOENT and NFS3ERR_ACCES -- so neither reaches the
// explainer as an error nobody can place.
func absent(op, p string) error {
	return &os.PathError{Op: op, Path: p, Err: syscall.ENOENT}
}

func refused(op, p string) error {
	return &os.PathError{Op: op, Path: p, Err: syscall.EACCES}
}

type diagChangeFS struct {
	diagFS
	ch billy.Change
}

// diagLinker carries the hard-link half, so the two wrapper shapes that
// need it share one implementation.
type diagLinker struct {
	ln   nfs.HardLinker
	hide func(string) bool
}

func (d diagLinker) Link(oldname, newname string) error {
	// A hidden name cannot be linked TO -- it does not exist -- so only
	// the new name needs the check, and it gets the same refusal a create
	// would.
	if hides(d.hide, newname) {
		return refused("link", newname)
	}
	return explain("link", newname, toldEIO, d.ln.Link(oldname, newname))
}

// diagPermitter carries the ACCESS half. An error here is one go-nfs's
// ACCESS handler can only place if it is a permission error (which is an
// answer, not a failure) or ENOENT; anything else reaches the client as
// NFS3ERR_IO, so it goes through the explainer like the rest.
type diagPermitter struct {
	pc nfs.PermissionChecker
}

func (d diagPermitter) Permitted(path string) (nfs.Permission, error) {
	p, err := d.pc.Permitted(path)
	return p, explain("access", path, toldEIO, err)
}

// diagCommitter carries the COMMIT half. go-nfs places ENOSPC, EDQUOT and
// EFBIG from a commit (statusFromWriteError, the same mapping the write
// path uses) and answers NFS3ERR_IO for everything else, so the explainer
// applies here exactly as it does elsewhere -- and it matters more than
// most: a COMMIT is the only reply an application's fsync(2) is waiting
// on, so an unexplained EIO there is an fsync failure with no cause
// recorded anywhere.
type diagCommitter struct {
	cm   nfs.Committer
	hide func(string) bool
}

func (d diagCommitter) Commit(p string) error {
	// Unreachable through a client that was refused the open, and here so
	// that the rule has no exceptions: every method on a filtered mount
	// that takes a path answers as though the name did not exist.
	if hides(d.hide, p) {
		return absent("commit", p)
	}
	return explain("commit", p, toldEIO, d.cm.Commit(p))
}

type diagLinkFS struct {
	diagFS
	diagLinker
}

type diagPermFS struct {
	diagFS
	diagPermitter
}

type diagCommitFS struct {
	diagFS
	diagCommitter
}

type diagChangeLinkFS struct {
	diagChangeFS
	diagLinker
}

type diagChangePermFS struct {
	diagChangeFS
	diagPermitter
}

type diagChangeCommitFS struct {
	diagChangeFS
	diagCommitter
}

type diagLinkPermFS struct {
	diagFS
	diagLinker
	diagPermitter
}

type diagLinkCommitFS struct {
	diagFS
	diagLinker
	diagCommitter
}

type diagPermCommitFS struct {
	diagFS
	diagPermitter
	diagCommitter
}

type diagChangeLinkPermFS struct {
	diagChangeFS
	diagLinker
	diagPermitter
}

type diagChangeLinkCommitFS struct {
	diagChangeFS
	diagLinker
	diagCommitter
}

type diagChangePermCommitFS struct {
	diagChangeFS
	diagPermitter
	diagCommitter
}

type diagLinkPermCommitFS struct {
	diagFS
	diagLinker
	diagPermitter
	diagCommitter
}

type diagChangeLinkPermCommitFS struct {
	diagChangeFS
	diagLinker
	diagPermitter
	diagCommitter
}

var (
	_ billy.Filesystem      = (*diagFS)(nil)
	_ billy.Capable         = (*diagFS)(nil)
	_ billy.Change          = (*diagChangeFS)(nil)
	_ billy.Change          = (*diagChangeLinkFS)(nil)
	_ billy.Change          = (*diagChangePermFS)(nil)
	_ billy.Change          = (*diagChangeCommitFS)(nil)
	_ billy.Change          = (*diagChangeLinkPermFS)(nil)
	_ billy.Change          = (*diagChangeLinkCommitFS)(nil)
	_ billy.Change          = (*diagChangePermCommitFS)(nil)
	_ billy.Change          = (*diagChangeLinkPermCommitFS)(nil)
	_ nfs.HardLinker        = (*diagLinkFS)(nil)
	_ nfs.HardLinker        = (*diagChangeLinkFS)(nil)
	_ nfs.HardLinker        = (*diagLinkPermFS)(nil)
	_ nfs.HardLinker        = (*diagLinkCommitFS)(nil)
	_ nfs.HardLinker        = (*diagChangeLinkPermFS)(nil)
	_ nfs.HardLinker        = (*diagChangeLinkCommitFS)(nil)
	_ nfs.HardLinker        = (*diagLinkPermCommitFS)(nil)
	_ nfs.HardLinker        = (*diagChangeLinkPermCommitFS)(nil)
	_ nfs.PermissionChecker = (*diagPermFS)(nil)
	_ nfs.PermissionChecker = (*diagChangePermFS)(nil)
	_ nfs.PermissionChecker = (*diagLinkPermFS)(nil)
	_ nfs.PermissionChecker = (*diagPermCommitFS)(nil)
	_ nfs.PermissionChecker = (*diagChangeLinkPermFS)(nil)
	_ nfs.PermissionChecker = (*diagChangePermCommitFS)(nil)
	_ nfs.PermissionChecker = (*diagLinkPermCommitFS)(nil)
	_ nfs.PermissionChecker = (*diagChangeLinkPermCommitFS)(nil)
	_ nfs.Committer         = (*diagCommitFS)(nil)
	_ nfs.Committer         = (*diagChangeCommitFS)(nil)
	_ nfs.Committer         = (*diagLinkCommitFS)(nil)
	_ nfs.Committer         = (*diagPermCommitFS)(nil)
	_ nfs.Committer         = (*diagChangeLinkCommitFS)(nil)
	_ nfs.Committer         = (*diagChangePermCommitFS)(nil)
	_ nfs.Committer         = (*diagLinkPermCommitFS)(nil)
	_ nfs.Committer         = (*diagChangeLinkPermCommitFS)(nil)
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
	if d.hidden(filename) {
		return nil, refused("create", filename)
	}
	f, err := d.Filesystem.Create(filename)
	return d.wrap(f), explain("create", filename, toldEACCES, err)
}

func (d *diagFS) Open(filename string) (billy.File, error) {
	if d.hidden(filename) {
		return nil, absent("open", filename)
	}
	f, err := d.Filesystem.Open(filename)
	return d.wrap(f), explain("open", filename, toldEACCES, err)
}

func (d *diagFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	if d.hidden(filename) {
		// Which refusal depends on what was asked. An open for reading is
		// answered "there is no such file", the same as the lookup that
		// preceded it; an open that would CREATE the file is answered
		// "you may not", because saying ENOENT to a create invites the
		// client to retry it forever.
		if flag&os.O_CREATE != 0 {
			return nil, refused("open", filename)
		}
		return nil, absent("open", filename)
	}
	f, err := d.Filesystem.OpenFile(filename, flag, perm)
	return d.wrap(f), explain("open", filename, toldEACCES, err)
}

func (d *diagFS) Stat(filename string) (os.FileInfo, error) {
	if d.hidden(filename) {
		return nil, absent("stat", filename)
	}
	fi, err := d.Filesystem.Stat(filename)
	return fi, explain("stat", filename, toldEIO, err)
}

func (d *diagFS) Rename(oldpath, newpath string) error {
	if d.hidden(newpath) {
		return refused("rename", newpath)
	}
	if d.hidden(oldpath) {
		return absent("rename", oldpath)
	}
	return explain("rename", oldpath, toldEIO, d.Filesystem.Rename(oldpath, newpath))
}

func (d *diagFS) Remove(filename string) error {
	if d.hidden(filename) {
		return absent("remove", filename)
	}
	return explain("remove", filename, toldEIO, d.Filesystem.Remove(filename))
}

func (d *diagFS) TempFile(dir, prefix string) (billy.File, error) {
	f, err := d.Filesystem.TempFile(dir, prefix)
	return d.wrap(f), explain("tempfile", dir, toldEACCES, err)
}

// ReadDir hides rather than refuses: the directory is real and the listing
// is the user's, so what a filter does here is leave its own names out of
// it. A hidden name that is somehow already IN the volume -- committed by
// a Linux client, or by a pelfs old enough to have sealed one -- therefore
// stops being listed too, which is the consistent answer: every other
// method here says it does not exist.
func (d *diagFS) ReadDir(dir string) ([]os.FileInfo, error) {
	entries, err := d.Filesystem.ReadDir(dir)
	if err != nil || d.hide == nil {
		return entries, explain("readdir", dir, toldENOTDIR, err)
	}
	kept := make([]os.FileInfo, 0, len(entries))
	for _, fi := range entries {
		if d.hide(fi.Name()) {
			continue
		}
		kept = append(kept, fi)
	}
	return kept, nil
}

func (d *diagFS) MkdirAll(filename string, perm os.FileMode) error {
	if d.hidden(filename) {
		return refused("mkdir", filename)
	}
	return explain("mkdir", filename, toldEACCES, d.Filesystem.MkdirAll(filename, perm))
}

func (d *diagFS) Lstat(filename string) (os.FileInfo, error) {
	if d.hidden(filename) {
		return nil, absent("lstat", filename)
	}
	fi, err := d.Filesystem.Lstat(filename)
	return fi, explain("lstat", filename, toldEIO, err)
}

func (d *diagFS) Symlink(target, link string) error {
	if d.hidden(link) {
		return refused("symlink", link)
	}
	return explain("symlink", link, toldEACCES, d.Filesystem.Symlink(target, link))
}

func (d *diagFS) Readlink(link string) (string, error) {
	if d.hidden(link) {
		return "", absent("readlink", link)
	}
	target, err := d.Filesystem.Readlink(link)
	return target, explain("readlink", link, toldEACCES, err)
}

func (d *diagFS) Chroot(dir string) (billy.Filesystem, error) {
	inner, err := d.Filesystem.Chroot(dir)
	if err != nil {
		return nil, explain("chroot", dir, toldEIO, err)
	}
	// The filter follows the chroot unchanged: it matches on the last
	// component, which a change of root does not touch.
	return diagnose(inner, d.hide), nil
}

func (d *diagChangeFS) Chmod(name string, mode os.FileMode) error {
	if d.hidden(name) {
		return absent("chmod", name)
	}
	return attrErr("chmod", name, d.ch.Chmod(name, mode))
}

func (d *diagChangeFS) Lchown(name string, uid, gid int) error {
	if d.hidden(name) {
		return absent("lchown", name)
	}
	return attrErr("lchown", name, d.ch.Lchown(name, uid, gid))
}

func (d *diagChangeFS) Chown(name string, uid, gid int) error {
	if d.hidden(name) {
		return absent("chown", name)
	}
	return attrErr("chown", name, d.ch.Chown(name, uid, gid))
}

func (d *diagChangeFS) Chtimes(name string, atime, mtime time.Time) error {
	if d.hidden(name) {
		return absent("chtimes", name)
	}
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
