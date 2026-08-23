// Package vfsbilly adapts the catalog-native stack to billy.Filesystem,
// the interface the go-nfs server consumes (internal/nfsmount.Serve). It
// is the piece that lets the stack be mounted on macOS with the OS NFS
// client — no macFUSE, no kext.
//
// Path resolution is by DESCENT. genfs serves an inode only once a Lookup
// has established residency for it, so every path handed to this adapter
// is walked from the root, parent before child. The directory edges of
// that walk are memoized (dircache.go) because the frontend re-walks the
// same directories on every RPC, but the walk itself is never skipped:
// an inode remembered from an earlier operation is not on its own
// resident, so a memoized descent that hits ErrStale re-walks for real.
//
// Open handles hold no buffered state. The overlay commits each Write to
// its staging file before returning, so nothing has to reconcile a
// metadata length against bytes still in flight — the entire class of
// truncation bugs a write-back handle cache exists to prevent does not
// arise here.
//
// PERMISSIONS ARE CHECKED HERE, and they have to be: the FUSE frontend
// mounts with `default_permissions` and gets the ordinary mode check from
// the kernel for free, while NFSv3 puts that check on the server, so an
// adapter that consults no mode bit makes them advisory on one frontend and
// enforced on the other. Every path in this file therefore passes through
// perm.go, which holds the model and the reasoning: the identity is the
// SERVER PROCESS's (uid, gid, groups and capabilities), mapped through
// internal/idmap exactly as reported ownership is, and the wire's AUTH_UNIX
// credential is deliberately not consulted. It is fidelity, not access
// control — see the file comment in perm.go before changing any of it.
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
	nfs "github.com/willscott/go-nfs"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/idmap"
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
	// cred is the identity every request is evaluated as, and the one the
	// permission check in perm.go consults. uid/gid above are the same
	// numbers, kept separate because they are also what new nodes are
	// STAMPED with, which is a different question.
	cred Cred
	// ids translates the volume's own identity onto this process, so a
	// volume made under one uid is writable when mounted under another
	// (internal/idmap).
	ids  idmap.Map
	dirs *dirCache
	// openSem says who answered open(2) for this binding, which is the only
	// thing the owner override in mayOpen turns on. The zero value —
	// OpenAnsweredHere — grants nothing, so a frontend built by a future
	// constructor that forgets to name it is refused rather than let through.
	openSem OpenSemantics
}

var (
	_ billy.Filesystem = (*billyFS)(nil)
	_ billy.Change     = (*billyFS)(nil)
	_ billy.Capable    = (*billyFS)(nil)
	// LINK is dispatched on this interface, not on billy.Change, and a
	// signature that drifts from it would silently turn hard links back
	// into "not supported" rather than fail to build.
	_ nfs.HardLinker = (*billyFS)(nil)
	// ACCESS is answered through this one. A filesystem that does not
	// implement it gets go-nfs's historical reply, which grants whatever
	// the client asked about -- so a drifting signature would not fail to
	// build either; it would quietly go back to lying.
	_ nfs.PermissionChecker = (*billyFS)(nil)
)

// New returns a billy.Filesystem over a read-write overlay FOR THE NFS
// FRONTEND. Nodes it creates are owned by the invoking user: the volume is
// a single-user scratch space and the mount must be able to write what it
// made.
//
// It is the NFSv3 binding specifically — OpenAnsweredByClient, the owner
// override on the data path (mayOpen). A FRONTEND WITH A REAL OPEN MUST NOT
// USE THIS: call NewFor(ov, cred, OpenAnsweredHere) instead, and read
// OpenSemantics in perm.go for the one paragraph that says why. The
// call-site allowlist in owneroverride_test.go enforces it.
func New(ov *overlay.FS) billy.Filesystem { return NewAs(ov, ProcessCred()) }

// NewAs is New with the identity named explicitly — and, like New, the NFS
// binding. The mount serves, and checks permissions, as cred — see perm.go
// for why that identity is the server's own and not the caller's AUTH_UNIX
// credential. It exists so the permission matrix can be exercised at this
// interface without the test process having to BE four different users.
func NewAs(ov *overlay.FS, cred Cred) billy.Filesystem {
	return NewFor(ov, cred, OpenAnsweredByClient)
}

// NewFor is NewAs with the open semantics named too, which is what a
// frontend other than NFS must use: sem decides whether this layer grants
// knfsd's owner override on the data path, and only a protocol whose open
// was already answered on the client is entitled to it (OpenSemantics).
func NewFor(ov *overlay.FS, cred Cred, sem OpenSemantics) billy.Filesystem {
	return &billyFS{rd: ov, ov: ov, uid: cred.UID, gid: cred.GID, cred: cred,
		ids: volumeOwner(ov, cred), dirs: newDirCache(), openSem: sem}
}

// NewReadOnly returns a billy.Filesystem over an immutable generation, for
// the NFS frontend — see New.
func NewReadOnly(fs *genfs.FS) billy.Filesystem { return NewReadOnlyAs(fs, ProcessCred()) }

// NewReadOnlyAs is NewReadOnly with the identity named explicitly.
func NewReadOnlyAs(fs *genfs.FS, cred Cred) billy.Filesystem {
	return NewReadOnlyFor(fs, cred, OpenAnsweredByClient)
}

// NewReadOnlyFor is NewFor over an immutable generation.
func NewReadOnlyFor(fs *genfs.FS, cred Cred, sem OpenSemantics) billy.Filesystem {
	return &billyFS{rd: fs, uid: cred.UID, gid: cred.GID, cred: cred,
		ids: volumeOwner(fs, cred), dirs: newDirCache(), openSem: sem}
}

// volumeOwner reads the identity a volume was created under, from its
// root. A root that will not stat leaves the zero map, which translates
// uid 0 -- the identity most worth mapping, and the one a volume rooted
// at root would otherwise be stuck with.
func volumeOwner(rd reader, cred Cred) idmap.Map {
	n, err := rd.GetAttr(ctx(), genfs.RootInode)
	if err != nil {
		return idmap.OwnerTo(0, 0, cred.UID, cred.GID)
	}
	return idmap.OwnerTo(n.UID, n.GID, cred.UID, cred.GID)
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

// resolve walks p from the root and returns its node, with the terminal
// component always looked up for real so its attributes are current.
//
// The intermediate directories come from the edge cache when it has them
// (see dircache.go). Skipping their Lookup also skips the residency it
// establishes, and the layer below answers ErrStale for an inode whose
// residency has since been evicted — so a stale-or-not-a-directory answer
// falls back to the full descent, which both re-establishes residency and
// refreshes the cache. Any other error is the namespace's real answer and
// is returned as-is.
func (b *billyFS) resolve(c context.Context, p string) (genfs.Node, error) {
	parts := components(p)
	if len(parts) == 0 {
		return b.rd.GetAttr(c, genfs.RootInode)
	}
	dir, err := b.descend(c, parts[:len(parts)-1], true)
	if err == nil {
		var n genfs.Node
		if n, err = b.step(c, dir, parts[len(parts)-1]); err == nil {
			return n, nil
		}
	}
	if !staleDescent(err) {
		return genfs.Node{}, err
	}
	if dir, err = b.descend(c, parts[:len(parts)-1], false); err != nil {
		return genfs.Node{}, err
	}
	return b.step(c, dir, parts[len(parts)-1])
}

// step is one name resolution inside a directory, with the search
// permission that reaching a name through it requires. Every Lookup this
// binding makes goes through here or through descend, which makes the same
// check: an unsearchable directory has to hide its contents from LOOKUP
// exactly as it does from a path walk, or the frontend answers a question
// the kernel would have refused.
func (b *billyFS) step(c context.Context, dir uint64, name string) (genfs.Node, error) {
	if err := b.mayTraverse(c, dir); err != nil {
		return genfs.Node{}, err
	}
	return b.rd.Lookup(c, dir, name)
}

// resolveDir walks p from the root and returns its inode, requiring every
// component to be a directory. It is resolve without the terminal lookup:
// callers that only need a directory's identity (the parent of a
// namespace operation) get the whole path from the cache.
func (b *billyFS) resolveDir(c context.Context, p string) (uint64, error) {
	parts := components(p)
	ino, err := b.descend(c, parts, true)
	if err == nil || !staleDescent(err) {
		return ino, err
	}
	return b.descend(c, parts, false)
}

// descend walks a chain of directory names from the root. With cached
// set, an edge already known is taken without consulting the layer below.
func (b *billyFS) descend(c context.Context, parts []string, cached bool) (uint64, error) {
	ino := genfs.RootInode
	for _, part := range parts {
		// Search permission on the directory being entered, cached edge or
		// not: skipping the Lookup is an optimization, and skipping the
		// check with it would be a hole.
		if err := b.mayTraverse(c, ino); err != nil {
			return 0, err
		}
		if cached {
			if child, ok := b.dirs.get(ino, part); ok {
				ino = child
				continue
			}
		}
		n, err := b.rd.Lookup(c, ino, part)
		if err != nil {
			return 0, err
		}
		if n.Type != catalog.TypeDir {
			return 0, overlay.ErrNotDir
		}
		b.dirs.put(ino, part, n.Inode)
		b.dirs.putPerm(n.Inode, dirPerm{mode: n.Mode, uid: n.UID, gid: n.GID})
		ino = n.Inode
	}
	return ino, nil
}

// dirAttrs returns a directory's permission attributes, from the memo when
// it has them (dircache.go).
func (b *billyFS) dirAttrs(c context.Context, ino uint64) (dirPerm, error) {
	if p, ok := b.dirs.perm(ino); ok {
		return p, nil
	}
	n, err := b.rd.GetAttr(c, ino)
	if err != nil {
		return dirPerm{}, err
	}
	p := dirPerm{mode: n.Mode, uid: n.UID, gid: n.GID}
	if n.Type == catalog.TypeDir {
		b.dirs.putPerm(ino, p)
	}
	return p, nil
}

// mayTraverse checks search permission on one directory. It returns a bare
// errno; every caller is inside a descent whose error the caller wraps with
// the path the client actually named, which is the path the kernel would
// have reported EACCES for too.
//
// A GetAttr that answers ErrStale is passed through unchanged so the
// self-healing retry in resolve still fires: a permission check must not
// turn an evictable inode into a permanent refusal.
func (b *billyFS) mayTraverse(c context.Context, ino uint64) error {
	p, err := b.dirAttrs(c, ino)
	if err != nil {
		return err
	}
	if b.mayDir(p, permExec) {
		return nil
	}
	return syscall.EACCES
}

// mayDir applies the mode check to a directory, in the id space the mount
// reports (internal/idmap): the ownership a caller is compared against has
// to be the ownership the caller can SEE.
func (b *billyFS) mayDir(p dirPerm, want perm) bool {
	uid, gid := b.ids.Apply(p.uid, p.gid)
	return b.cred.Allowed(uid, gid, p.mode, true, want)
}

// mayNode is mayDir for an object named by node.
func (b *billyFS) mayNode(n genfs.Node, want perm) bool {
	uid, gid := b.ids.Apply(n.UID, n.GID)
	return b.cred.Allowed(uid, gid, n.Mode, n.Type == catalog.TypeDir, want)
}

// dirWritable resolves a directory's attributes and requires write and
// search on it — what creating, removing or renaming a name inside it
// costs. It returns the attributes because the sticky-bit rule needs them
// next and they are not worth fetching twice.
func (b *billyFS) dirWritable(c context.Context, op, path string, dir uint64) (dirPerm, error) {
	p, err := b.dirAttrs(c, dir)
	if err != nil {
		return dirPerm{}, pe(op, path, err)
	}
	if !b.mayDir(p, permWrite|permExec) {
		return dirPerm{}, accessErr(op, path)
	}
	return p, nil
}

// maySticky applies the sticky-bit rule to a name being removed from or
// renamed within dir: in a +t directory only the file's owner, the
// directory's owner, or CAP_FOWNER may unlink a name. It is what stops
// /tmp from being a free-for-all, and it is EPERM, not EACCES.
func (b *billyFS) maySticky(op, path string, dir dirPerm, target genfs.Node) error {
	if dir.mode&syscall.S_ISVTX == 0 {
		return nil
	}
	duid, _ := b.ids.Apply(dir.uid, dir.gid)
	tuid, _ := b.ids.Apply(target.UID, target.GID)
	if b.cred.UID == tuid || b.cred.UID == duid || b.cred.Caps.Has(CapFOwner) {
		return nil
	}
	return permErr(op, path)
}

// accessErr and permErr are the two refusals, kept apart because the
// kernel keeps them apart and a client reports them differently: EACCES is
// "the mode bits say no", EPERM is "you are not the owner". Both satisfy
// errors.Is(err, os.ErrPermission) and os.IsPermission, which go-nfs tests
// separately.
func accessErr(op, p string) error {
	return &os.PathError{Op: op, Path: clean(p), Err: syscall.EACCES}
}

func permErr(op, p string) error {
	return &os.PathError{Op: op, Path: clean(p), Err: syscall.EPERM}
}

// staleDescent reports whether an error is one a cached edge could have
// caused, and is therefore worth retrying against the layer below.
// ErrNotExist deliberately is not: an edge is only ever cached after a
// real lookup and is dropped when the name is unbound, so a miss at the
// end of a cached descent is the namespace's answer, not the cache's.
func staleDescent(err error) bool {
	return errors.Is(err, genfs.ErrStale) || errors.Is(err, overlay.ErrNotDir)
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
func (b *billyFS) resolveParent(c context.Context, p string) (uint64, string, error) {
	parts := components(p)
	if len(parts) == 0 {
		return 0, "", syscall.EINVAL // the root has no parent edge
	}
	dir, err := b.resolveDir(c, path.Dir(clean(p)))
	if err != nil {
		return 0, "", err
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
		if err := b.mayOpen(name, n, mutates); err != nil {
			return nil, err
		}
	case errors.Is(err, genfs.ErrNotExist) && flag&os.O_CREATE != 0:
		dir, base, derr := b.resolveParent(c, name)
		if derr != nil {
			return nil, pe("open", name, derr)
		}
		if _, derr := b.dirWritable(c, "open", name, dir); derr != nil {
			return nil, derr
		}
		if n, err = b.ov.Create(c, dir, base, uint32(perm.Perm()), b.uid, b.gid); err != nil {
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

// mayOpen is the check open(2) makes on an EXISTING file. A newly created
// one is not checked, which is not an omission: the kernel checks the
// parent directory for a create and never the mode the new file is being
// given, which is what lets `install -m 444` work at all.
//
// A mutating open asks for WRITE ONLY, never write-and-read, and that is
// deliberate. go-nfs's WRITE handler opens O_RDWR because billy has no
// positional writer without it, so demanding read as well would refuse
// every write to a file whose mode grants w and not r — an operation the
// kernel and the FUSE frontend both allow. Reads are checked where reads
// actually happen: go-nfs's READ handler opens O_RDONLY.
//
// # The owner override, and exactly how far it reaches
//
// It reaches only a binding whose CALLER asked for it
// (OpenAnsweredByClient — see OpenSemantics in perm.go). That is NFSv3 and
// nothing else, and the rest of this section is why the distinction is the
// whole justification rather than a detail of it.
//
// Every OpenFile the NFS frontend makes comes from the DATA PATH: READ
// opens O_RDONLY, WRITE opens O_RDWR, and SETATTR-with-a-size opens
// O_WRONLY|O_EXCL to truncate. NFSv3 has no OPEN operation at all, so
// none of these is the client's open(2) — that was answered on the client,
// from our ACCESS reply (Permitted below), before any of them was sent. A
// frontend that DOES have an open — WebDAV's PUT, SFTP's SSH_FXP_OPEN, an
// HTTP handler calling OpenFile — is in the opposite position: this check
// is the only open check there will ever be for it, so it gets
// OpenAnsweredHere and no override.
//
// So this is knfsd's nfsd_open, which passes NFSD_MAY_OWNER_OVERRIDE
// (fs/nfsd/vfs.c): the file's OWNER is allowed through whatever the mode
// bits say. The comment in the kernel says why, and it is the case tar -p
// produces on every read-only file it extracts — `open(O_CREAT|O_WRONLY,
// 0444)` and then writes, where the descriptor legitimately outlives the
// mode it was created with. A stateless server cannot see that descriptor;
// refusing its WRITEs second-guesses an open the client already made, and
// the file arrives empty. nfsd_setattr adds the same flag for a size
// change, which is the third route above.
//
// What it deliberately does NOT reach:
//
//   - ACCESS (Permitted), which never gets the flag in knfsd either
//     (nfsd_access calls nfsd_permission with the plain access map). That
//     is the half that refuses the client's open, and the only reason a
//     server can afford to trust the writes that follow one it allowed.
//     Grant it here and `test -w` starts lying about a 0444 file again.
//   - The namespace operations. Creating, removing or renaming a name
//     costs write and search on the DIRECTORY (NFSD_MAY_CREATE,
//     NFSD_MAY_REMOVE), neither of which carries the flag, and owning the
//     object being unlinked has never been what permits unlinking it.
//   - Search permission on the path (mayTraverse), which a client spends
//     one LOOKUP at a time and knfsd checks as plain NFSD_MAY_EXEC.
//   - Ownership itself: chmod, chown, utimes and the sticky-bit rule ask
//     who the owner IS (Cred.owns, mayChown), a question this cannot
//     change the answer to.
//   - Directories, which the data path never opens: knfsd's nfsd_open
//     takes the type it requires, and for READ and WRITE that is S_IFREG.
func (b *billyFS) mayOpen(name string, n genfs.Node, mutates bool) error {
	want := permRead
	if mutates {
		want = permWrite
	}
	if b.mayNode(n, want) {
		return nil
	}
	// And the override reaches only a binding that ASKED for it. A frontend
	// with a real open (WebDAV, SFTP) answers open(2) here and nowhere else,
	// so for it this check is the open check — see OpenSemantics in perm.go.
	if b.openSem == OpenAnsweredByClient && n.Type == catalog.TypeFile && b.ownsNode(n) {
		return nil
	}
	return accessErr("open", name)
}

// ownsNode reports whether the mount's identity is the object's owner, in
// the id space the mount reports. It is uid equality and nothing else:
// knfsd's owner override tests i_uid against the caller's fsuid, and
// CAP_FOWNER — which stands in for ownership where ownership is what an
// operation REQUIRES — is not consulted there.
func (b *billyFS) ownsNode(n genfs.Node) bool {
	uid, _ := b.ids.Apply(n.UID, n.GID)
	return uid == b.cred.UID
}

// Permitted answers NFSv3's ACCESS: which of read, write and execute this
// mount permits on one object. It is nfs.PermissionChecker, the hook
// go-nfs's ACCESS handler consults instead of echoing the mask the client
// asked about (docs/go-nfs-patches.md).
//
// This is the client-side half of the model — the reply a client turns
// into its answer for open(2), access(2) and `test -w`, since NFSv3 gives
// it nothing else to decide those with. It is therefore the ordinary mode
// check and NOTHING else: no owner override (see mayOpen), so a 0444 file
// reports "not writable" to its own owner, which is what the kernel says
// about the same file locally and what the FUSE frontend says through
// `default_permissions`.
//
// The object is named without following a terminal symlink, like every
// other operation whose object arrives as a file handle.
func (b *billyFS) Permitted(name string) (nfs.Permission, error) {
	n, err := b.resolve(ctx(), name)
	if err != nil {
		return 0, pe("access", name, err)
	}
	var granted nfs.Permission
	for _, want := range []struct {
		bit nfs.Permission
		p   perm
	}{
		{nfs.PermissionRead, permRead},
		{nfs.PermissionWrite, permWrite},
		{nfs.PermissionExecute, permExec},
	} {
		if b.mayNode(n, want.p) {
			granted |= want.bit
		}
	}
	return granted, nil
}

func (b *billyFS) Stat(filename string) (os.FileInfo, error) {
	n, err := b.resolveFollow(ctx(), filename)
	if err != nil {
		return nil, pe("stat", filename, err)
	}
	return newInfo(path.Base(clean(filename)), n, b.ids), nil
}

func (b *billyFS) Lstat(filename string) (os.FileInfo, error) {
	n, err := b.resolve(ctx(), filename)
	if err != nil {
		return nil, pe("lstat", filename, err)
	}
	return newInfo(path.Base(clean(filename)), n, b.ids), nil
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
	// A rename unbinds a name in one directory and binds one in another,
	// so it costs write+search in both — and the sticky rule applies to
	// the source name, and to the destination name when it is about to be
	// replaced.
	srcDir, err := b.dirWritable(c, "rename", oldpath, src)
	if err != nil {
		return err
	}
	dstDir, err := b.dirWritable(c, "rename", newpath, dst)
	if err != nil {
		return err
	}
	if srcDir.mode&syscall.S_ISVTX != 0 {
		n, lerr := b.rd.Lookup(c, src, srcName)
		if lerr != nil {
			return pe("rename", oldpath, lerr)
		}
		if serr := b.maySticky("rename", oldpath, srcDir, n); serr != nil {
			return serr
		}
	}
	if dstDir.mode&syscall.S_ISVTX != 0 {
		if n, lerr := b.rd.Lookup(c, dst, dstName); lerr == nil {
			if serr := b.maySticky("rename", newpath, dstDir, n); serr != nil {
				return serr
			}
		}
	}
	// Both edges change identity; the subtree under a renamed directory
	// does not, because the cache is keyed by parent INODE and the moved
	// directory keeps its own.
	b.dirs.forget(src, srcName)
	b.dirs.forget(dst, dstName)
	return pe("rename", oldpath, b.ov.Rename(c, src, srcName, dst, dstName))
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
	dirAttrs, err := b.dirWritable(c, "remove", filename, dir)
	if err != nil {
		return err
	}
	n, err := b.rd.Lookup(c, dir, name)
	if err != nil {
		return pe("remove", filename, err)
	}
	if err := b.maySticky("remove", filename, dirAttrs, n); err != nil {
		return err
	}
	b.dirs.forget(dir, name)
	b.dirs.forgetPerm(n.Inode)
	if n.Type == catalog.TypeDir {
		return pe("remove", filename, b.ov.Rmdir(c, dir, name))
	}
	return pe("remove", filename, b.ov.Unlink(c, dir, name))
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
	ino, err := b.resolveDir(c, p)
	if err != nil {
		return nil, pe("readdir", p, err)
	}
	// Listing a directory costs READ on it — the search permission the
	// descent already checked is what it costs to walk THROUGH.
	attrs, err := b.dirAttrs(c, ino)
	if err != nil {
		return nil, pe("readdir", p, err)
	}
	if !b.mayDir(attrs, permRead) {
		return nil, accessErr("readdir", p)
	}
	entries, err := b.rd.Readdir(c, ino)
	if err != nil {
		return nil, pe("readdir", p, err)
	}
	out := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, newInfo(e.Name, e.Node, b.ids))
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
	err := b.mkdirAll(c, components(name), perm, true)
	if staleDescent(err) {
		// Same self-healing retry resolve makes: a cached edge whose
		// residency has aged out is re-established by walking for real.
		err = b.mkdirAll(c, components(name), perm, false)
	}
	return pe("mkdir", name, err)
}

func (b *billyFS) mkdirAll(c context.Context, parts []string, perm os.FileMode, cached bool) error {
	dir := genfs.RootInode
	for _, part := range parts {
		if err := b.mayTraverse(c, dir); err != nil {
			return err
		}
		if cached {
			if child, ok := b.dirs.get(dir, part); ok {
				dir = child
				continue
			}
		}
		child, err := b.rd.Lookup(c, dir, part)
		if errors.Is(err, genfs.ErrNotExist) {
			// Only the component actually being created costs write
			// permission on its parent; the ones already there cost the
			// search the loop already paid for.
			if p, aerr := b.dirAttrs(c, dir); aerr != nil {
				return aerr
			} else if !b.mayDir(p, permWrite|permExec) {
				return syscall.EACCES
			}
			child, err = b.ov.Mkdir(c, dir, part, uint32(perm.Perm()), b.uid, b.gid)
			if errors.Is(err, overlay.ErrExist) {
				// Someone else created it in between; an existing name is
				// all MkdirAll promises.
				child, err = b.rd.Lookup(c, dir, part)
			}
		}
		if err != nil {
			return err
		}
		if child.Type != catalog.TypeDir {
			return overlay.ErrNotDir
		}
		b.dirs.put(dir, part, child.Inode)
		b.dirs.putPerm(child.Inode, dirPerm{mode: child.Mode, uid: child.UID, gid: child.GID})
		dir = child.Inode
	}
	return nil
}

// Link hard-links the inode already at oldname under newname. It is the
// operation go-nfs's LINK handler looks for on the filesystem itself
// (nfs.HardLinker), which is the only route that works here: the RPC
// names both its source and its destination directory by file handle,
// and the handler resolves each to a path before asking.
//
// The source is resolved WITHOUT following a terminal symlink, matching
// link(2) and the fact that a handle for a symlink names the symlink.
func (b *billyFS) Link(oldname, newname string) error {
	if b.ov == nil {
		return roErr("link", newname)
	}
	c := ctx()
	src, err := b.resolve(c, oldname)
	if err != nil {
		return pe("link", oldname, err)
	}
	dir, name, err := b.resolveParent(c, newname)
	if err != nil {
		return pe("link", newname, err)
	}
	if _, derr := b.dirWritable(c, "link", newname, dir); derr != nil {
		return derr
	}
	_, err = b.ov.Link(c, src.Inode, dir, name)
	return pe("link", newname, err)
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
	if _, derr := b.dirWritable(c, "symlink", link, dir); derr != nil {
		return derr
	}
	_, err = b.ov.Symlink(c, dir, name, target, b.uid, b.gid)
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
//
// NONE of these follow a terminal symlink, which is where they differ
// from the os package functions billy names them after.
//
// The reason is that the only caller is an NFS server, and every
// attribute change it makes names its object by FILE HANDLE: SETATTR
// carries one, and CREATE/MKDIR/SYMLINK apply the request's sattr3 to the
// object they just made (go-nfs does all four through
// SetFileAttributes.Apply, which reaches a symlink by path only because
// billy has no lchmod/lutimes to call). A handle for a symlink names the
// symlink. Following one would be wrong in both directions:
//
//   - on a symlink whose target exists, the change lands on the TARGET —
//     the wrong object, silently, with the operation reporting success;
//   - on a dangling symlink, which is every forward reference in a tarball
//     mid-extraction, it fails with ENOENT, and go-nfs turns that into
//     NFS3ERR_IO on the create path and an RPC-level system error on
//     SETATTR. Both reach the client as "Input/output error" on a file
//     that was in fact created correctly.

// setAttr resolves name — the link itself, never its target — and applies
// one attribute change, once permitted has agreed to it.
//
// permitted takes the node because every one of these operations is
// governed by the object's OWNERSHIP rather than by its mode bits, which
// is the half of the model that mode bits alone cannot express: a file
// mode 0777 is still only its owner's to chmod.
func (b *billyFS) setAttr(op, name string, in overlay.SetAttrIn, permitted func(genfs.Node) error) error {
	if b.ov == nil {
		return roErr(op, name)
	}
	c := ctx()
	n, err := b.resolve(c, name)
	if err != nil {
		return pe(op, name, err)
	}
	if err := permitted(n); err != nil {
		return &os.PathError{Op: op, Path: clean(name), Err: err}
	}
	_, err = b.ov.SetAttr(c, n.Inode, in)
	if err == nil && n.Type == catalog.TypeDir {
		// The memo in dircache.go holds a directory's mode and ownership,
		// and this is the only thing that can change them.
		b.dirs.forgetPerm(n.Inode)
	}
	return pe(op, name, err)
}

// owner is the ownership test shared by chmod and utimes: the owner, or
// CAP_FOWNER standing in for them.
func (b *billyFS) owner(n genfs.Node) error {
	uid, _ := b.ids.Apply(n.UID, n.GID)
	if b.cred.Owns(uid) {
		return nil
	}
	return syscall.EPERM
}

func (b *billyFS) Chmod(name string, mode os.FileMode) error {
	m := unixMode(mode)
	return b.setAttr("chmod", name, overlay.SetAttrIn{Mode: &m}, b.owner)
}

func (b *billyFS) Chown(name string, uid, gid int) error {
	return b.chown("chown", name, uid, gid)
}

func (b *billyFS) Lchown(name string, uid, gid int) error {
	return b.chown("lchown", name, uid, gid)
}

// chown applies whichever of the two ids was actually named. A negative
// operand means "unchanged", to chown(2) and to os.Lchown alike — this
// used to convert one to 0xffffffff and store it.
func (b *billyFS) chown(op, name string, uid, gid int) error {
	var in overlay.SetAttrIn
	if uid >= 0 {
		u := uint32(uid)
		in.UID = &u
	}
	if gid >= 0 {
		g := uint32(gid)
		in.GID = &g
	}
	return b.setAttr(op, name, in, b.chowner(uid, gid))
}

// chowner is the CAP_CHOWN rule, applied against the ownership the mount
// REPORTS — which is the ownership the client asked to change, since the
// uid it sends is the one it read back from a GETATTR.
func (b *billyFS) chowner(uid, gid int) func(genfs.Node) error {
	return func(n genfs.Node) error {
		cur, curg := b.ids.Apply(n.UID, n.GID)
		return b.cred.MayChown(cur, curg, uid, gid)
	}
}

// Chtimes sets mtime only: catalogs carry no atime by design, and mtime
// stands in for it everywhere else in the stack.
//
// Setting an explicit time is the owner's privilege (utimes(2) with a
// non-NULL argument), and NFSv3 SETATTR carries explicit times, so that is
// the rule applied. Write permission is enough only for the "set it to
// now" form, which never arrives here.
func (b *billyFS) Chtimes(name string, atime, mtime time.Time) error {
	ns := mtime.UnixNano()
	return b.setAttr("chtimes", name, overlay.SetAttrIn{MtimeNS: &ns}, b.owner)
}
