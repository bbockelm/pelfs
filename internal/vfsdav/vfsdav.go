// Package vfsdav serves a pelfs volume over WebDAV, by adapting
// internal/vfsbilly's billy.Filesystem to golang.org/x/net/webdav's
// FileSystem and File. It is work item U6 of docs/design-webui.md and D1 of
// docs/design-windows.md: external GUI clients — Cyberduck, Mountain Duck,
// WinSCP, rclone, macOS `mount_webdav`, the Windows redirector — on the same
// loopback listener the browser UI uses, with no FUSE and no kext.
//
// # What this package is, and is not
//
// It is an ADAPTER and an auth gate, and nothing else. The protocol is
// x/net/webdav's, whose handler is a bare method dispatch over five
// filesystem calls; the namespace, the permission model and the durability
// story are internal/vfsbilly's and internal/overlay's, unchanged. The
// measured ceiling for the protocol half is therefore upstream's own —
// litmus `basic 16/16 · copymove 13/13 · props 30/30 · locks 32/34` against
// `webdav.NewMemFS()`, recorded in scripts/webdav-litmus-docker.sh — and
// scripts/webdav-adapter-litmus-docker.sh runs the same suite against THIS
// package so a new failure in `basic`, `copymove` or `props` is reported as
// the adapter's.
//
// # No CORS headers, ever
//
// Nothing here emits an Access-Control-Allow-* header, and that is a
// structural defence rather than an omission. A cross-origin page cannot
// send PROPFIND, PUT, MKCOL, MOVE, COPY, DELETE, PROPPATCH, LOCK or UNLOCK
// without a successful preflight, and a preflight with no
// Access-Control-Allow-Methods fails — so the entire WebDAV WRITE surface is
// unreachable from another origin by construction. The only browser-reachable
// verbs are GET, HEAD and POST, which x/net serves read-only and which still
// need the credential. TestNoCORSHeaderOnAnyVerb pins it. If you are about to
// add a CORS header here to make something work in a browser: the browser
// surface is the JSON API (docs/design-webui.md, "The two-surface design"),
// not this one.
//
// # The credential, and the seam for Bearer
//
// Auth is an interface, not a policy: Basic covers every client that is not
// Cyberduck (and is Cyberduck's contingency), and Bearer is where U7's
// authorization server plugs a token verifier in without this package
// growing an opinion about OAuth. AnyOf mounts both. Nothing here reads
// X-Pelfs-Session: the browser session token is not a WebDAV credential and
// must not become one (docs/design-webui.md, A7).
//
// # What a pelfs volume has that WebDAV does not
//
//   - SYMLINKS. A link to a regular file is FOLLOWED, so `lib.so ->
//     lib.so.1` is the file it names rather than an empty one. A link to a
//     DIRECTORY is hidden and counted, which is narrower than
//     docs/design-windows.md's "follow within the volume": path resolution
//     in internal/vfsbilly is component-by-component and does not traverse a
//     symlinked directory component (resolveDir requires every component to
//     BE a directory), so a followed directory link would list as a
//     collection whose PROPFIND then failed. Hiding it is the honest answer
//     until that resolution exists. A dangling link is hidden too. Neither
//     can escape the volume: an absolute link target is resolved against the
//     VOLUME root (vfsbilly.resolveFollow), so there is no host path to
//     reach.
//   - FIFOs, SOCKETS AND DEVICE NODES, which have no representation a client
//     could render: omitted from listings and counted.
//   - HARD LINKS are left exactly as they are — every name is an independent
//     resource to the client, and a write through one is visible through the
//     other because they are one inode.
//
// Hidden entries are counted rather than swallowed: Counts reports them, so
// a caller can say so in a mount summary.
//
// # Dead properties live for the session only
//
// PROPPATCH is honoured through an IN-MEMORY store (props.go), not the
// volume's xattrs. litmus's `props` suite needs it — without a
// DeadPropsHolder every PROPPATCH is 403 and the suite drops well below the
// ceiling — and a client's own scratch properties are worth keeping for as
// long as the client is connected. They do NOT survive the process, and the
// Win32LastModifiedTime / Win32FileAttributes translation that would make
// them durable is docs/design-windows.md's own separate work item.
package vfsdav

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/go-git/go-billy/v5"
	"golang.org/x/net/webdav"
)

// FS adapts a billy.Filesystem to webdav.FileSystem.
//
// The billy layer it wraps must be built for a frontend that answers open(2)
// ITSELF — vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere). WebDAV has
// a real open, so the mode check in the layer below is the only open check
// there is; a binding carrying NFS's owner override would let a PUT truncate
// a 0444 file that the kernel, FUSE and the NFS ACCESS reply all refuse.
// vfsbilly.OpenSemantics has the whole argument.
type FS struct {
	fs    billy.Filesystem
	props *propStore

	// writable is billy's own answer, asked once. A read-only binding
	// refuses every mutation below anyway; this is what lets PROPPATCH say
	// 403 rather than accepting a property change to a volume nothing can
	// change.
	writable bool

	hiddenLinks   atomic.Int64
	hiddenDirCnt  atomic.Int64
	hiddenSpecial atomic.Int64
}

var _ webdav.FileSystem = (*FS)(nil)

// NewFS wraps a billy.Filesystem as a webdav.FileSystem.
func NewFS(bfs billy.Filesystem) *FS {
	return &FS{
		fs:       bfs,
		props:    newPropStore(),
		writable: billy.CapabilityCheck(bfs, billy.WriteCapability),
	}
}

// Counts reports what the adapter hid from clients, and why. Every one of
// these is a real entry in the volume that WebDAV cannot represent, so a
// mount summary should say the number out loud rather than let a tree look
// smaller than it is.
//
// They are OCCURRENCES, not distinct entries: a directory listed three times
// contributes its hidden entries three times. That is deliberate — the
// alternative is remembering every path ever listed, which on a volume of
// millions of entries is a leak — and it means the number answers "is
// anything being hidden here", not "how many things exist".
type Counts struct {
	// DanglingSymlinks is links whose target does not resolve.
	DanglingSymlinks int64
	// DirectorySymlinks is links to directories — see the package comment.
	DirectorySymlinks int64
	// SpecialFiles is fifos, sockets and device nodes.
	SpecialFiles int64
}

// Counts returns the running totals; safe to call at any time.
func (d *FS) Counts() Counts {
	return Counts{
		DanglingSymlinks:  d.hiddenLinks.Load(),
		DirectorySymlinks: d.hiddenDirCnt.Load(),
		SpecialFiles:      d.hiddenSpecial.Load(),
	}
}

// name normalizes a WebDAV name to the rooted slash path the billy layer
// takes. x/net has already cleaned what it passes (slashClean), but this
// package's exported surface is not only x/net, and a NUL byte is the one
// thing path.Clean will not save us from.
func name(op, p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", &os.PathError{Op: op, Path: p, Err: syscall.EINVAL}
	}
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	return path.Clean(p), nil
}

// mutates reports whether a set of open flags asks to change bytes.
func mutates(flag int) bool {
	return flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0
}

// propsOnly recognizes the open PROPPATCH makes: prop.patch opens
// O_RDWR to reach DeadPropsHolder (x/net/webdav prop.go), and on a
// DIRECTORY an honest O_RDWR is EISDIR — which is golang/go#43929, a
// PROPPATCH on a folder answered 500. Every open x/net makes to write BYTES
// carries O_CREATE|O_TRUNC (handlePut, copyFiles), so the two are
// distinguishable and the fix costs nothing: an O_RDWR with neither is
// served as a read handle whose Write is refused.
func propsOnly(flag int) bool {
	return mutates(flag) && flag&(os.O_CREATE|os.O_TRUNC|os.O_APPEND|os.O_EXCL) == 0
}

// OpenFile opens the object a client named — following a terminal symlink,
// which is what makes a link to a regular file readable rather than a handle
// on the link itself. The distinction is not cosmetic: an open of the link
// inode answers ErrStale on the first read, and x/net reads 512 bytes of
// every file whose extension has no MIME type (findContentType), so a
// listing that contained one would drop the entry entirely.
//
// The handle is on the RESOLVED path and Stat is asked of the REQUESTED one:
// the bytes must come from the target, and the name a client sees must be
// the name it asked for.
func (d *FS) OpenFile(_ context.Context, p string, flag int, perm os.FileMode) (webdav.File, error) {
	n, err := name("open", p)
	if err != nil {
		return nil, err
	}
	target, fi, ferr := d.follow(n)
	if !mutates(flag) || propsOnly(flag) {
		if ferr != nil {
			return nil, ferr
		}
		if fi.IsDir() {
			return &davDir{fs: d, name: n, dir: target}, nil
		}
		h, err := d.fs.OpenFile(target, os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		return &davFile{fs: d, name: n, h: h}, nil
	}
	// A write. A name that does not exist is created where the chain
	// stopped, which for a dangling symlink is its target — what open(2)
	// with O_CREAT does through one. Any other resolution failure is the
	// answer, not something to retry at the original name.
	if ferr != nil && !os.IsNotExist(ferr) {
		return nil, ferr
	}
	h, err := d.fs.OpenFile(target, flag, perm)
	if err != nil {
		return nil, err
	}
	return &davFile{fs: d, name: n, h: h, mayWrite: true}, nil
}

// maxSymlinkHops bounds a chain, as the layer below does for Stat.
const maxSymlinkHops = 8

// follow resolves a terminal symlink chain and returns the path it ends at,
// that path's attributes, and any error. THE PATH IS RETURNED EVEN ON
// ERROR: a create through a dangling link has to land on the target.
//
// Only the last component is followed. An intermediate symlinked directory
// is not traversable in the layer below (vfsbilly.resolveDir requires every
// component to BE a directory), which is why readDir hides links to
// directories instead of presenting them as collections.
func (d *FS) follow(n string) (string, os.FileInfo, error) {
	for hop := 0; ; hop++ {
		fi, err := d.lstat(n)
		if err != nil {
			return n, nil, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return n, fi, nil
		}
		if hop == maxSymlinkHops {
			return n, nil, &os.PathError{Op: "open", Path: n, Err: syscall.ELOOP}
		}
		target, err := d.readlink(n)
		if err != nil {
			return n, nil, err
		}
		if path.IsAbs(target) {
			// Rooted at the VOLUME, not the host: there is no host path a
			// link in a pelfs volume can name.
			n = path.Clean(target)
		} else {
			n = path.Clean(path.Join(path.Dir(n), target))
		}
	}
}

func (d *FS) Stat(_ context.Context, p string) (os.FileInfo, error) {
	n, err := name("stat", p)
	if err != nil {
		return nil, err
	}
	return d.fs.Stat(n)
}

// Mkdir is MKCOL, and its two error cases are the two statuses the protocol
// distinguishes: a missing (or non-directory) parent is os.ErrNotExist,
// which x/net turns into 409 Conflict, and an existing name is os.ErrExist,
// which becomes 405. billy has only MkdirAll, which would create the
// parents and answer 201 where the protocol requires 409, so the checks are
// here.
func (d *FS) Mkdir(_ context.Context, p string, perm os.FileMode) error {
	n, err := name("mkdir", p)
	if err != nil {
		return err
	}
	if n == "/" {
		return &os.PathError{Op: "mkdir", Path: n, Err: os.ErrExist}
	}
	parent := path.Dir(n)
	pfi, err := d.fs.Stat(parent)
	if err != nil {
		return err
	}
	if !pfi.IsDir() {
		return &os.PathError{Op: "mkdir", Path: n, Err: os.ErrNotExist}
	}
	if _, err := d.lstat(n); err == nil {
		return &os.PathError{Op: "mkdir", Path: n, Err: os.ErrExist}
	} else if !os.IsNotExist(err) {
		return err
	}
	return d.fs.MkdirAll(n, perm)
}

// Rename is MOVE. x/net has already deleted the destination when the client
// sent Overwrite: T, so this is the single-name rename billy performs.
func (d *FS) Rename(_ context.Context, oldName, newName string) error {
	from, err := name("rename", oldName)
	if err != nil {
		return err
	}
	to, err := name("rename", newName)
	if err != nil {
		return err
	}
	if from == "/" || to == "/" {
		return &os.PathError{Op: "rename", Path: from, Err: os.ErrInvalid}
	}
	if err := d.fs.Rename(from, to); err != nil {
		return err
	}
	d.props.rename(from, to)
	return nil
}

// RemoveAll is DELETE, which WebDAV defines as Depth: infinity on a
// collection. billy.Remove unlinks one name and refuses a non-empty
// directory, so the recursion is here — depth-first, and never on the root
// itself (x/net's own Dir refuses that too: a client that deletes the
// collection it is mounted on has nothing left to talk to).
func (d *FS) RemoveAll(_ context.Context, p string) error {
	n, err := name("remove", p)
	if err != nil {
		return err
	}
	if n == "/" {
		return &os.PathError{Op: "remove", Path: n, Err: os.ErrInvalid}
	}
	if err := d.removeAll(n); err != nil {
		return err
	}
	d.props.forgetTree(n)
	return nil
}

func (d *FS) removeAll(n string) error {
	fi, err := d.lstat(n)
	if err != nil {
		// "godoc os RemoveAll" says a missing path is not an error; x/net
		// Stats before it calls this, so a 404 is already accounted for.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// A symlink is removed as itself. Following one here would delete the
	// TARGET and leave the link, which is the one mistake a recursive
	// delete cannot take back.
	if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
		ents, err := d.fs.ReadDir(n)
		if err != nil {
			return err
		}
		for _, e := range ents {
			switch e.Name() {
			case ".", "..":
				continue
			}
			if err := d.removeAll(path.Join(n, e.Name())); err != nil {
				return err
			}
		}
	}
	return d.fs.Remove(n)
}

// lstatter is billy's symlink half, which vfsbilly implements. Lstat is not
// on billy.Filesystem, and the difference matters exactly where a symlink
// is the object of the operation rather than a step on the way to one.
type lstatter interface {
	Lstat(string) (os.FileInfo, error)
}

type readlinker interface {
	Readlink(string) (string, error)
}

func (d *FS) lstat(n string) (os.FileInfo, error) {
	if l, ok := d.fs.(lstatter); ok {
		return l.Lstat(n)
	}
	return d.fs.Stat(n)
}

// readlink is only ever reached for a name lstat called a symlink, so a
// filesystem that reports symlinks and cannot read them is a bug in that
// filesystem and is reported as one rather than papered over.
func (d *FS) readlink(n string) (string, error) {
	l, ok := d.fs.(readlinker)
	if !ok {
		return "", &os.PathError{Op: "readlink", Path: n, Err: syscall.ENOSYS}
	}
	return l.Readlink(n)
}

// readDir is one directory as a client may see it: symlinks to files
// followed, everything WebDAV cannot represent omitted and counted.
func (d *FS) readDir(n string) ([]fs.FileInfo, error) {
	ents, err := d.fs.ReadDir(n)
	if err != nil {
		return nil, err
	}
	out := make([]fs.FileInfo, 0, len(ents))
	for _, e := range ents {
		switch e.Name() {
		case ".", "..":
			continue
		}
		m := e.Mode()
		switch {
		case m&os.ModeSymlink != 0:
			_, fi, err := d.follow(path.Join(n, e.Name()))
			if err != nil {
				d.hiddenLinks.Add(1)
				continue
			}
			if fi.IsDir() {
				// See the package comment: a symlinked directory component
				// is not traversable in the layer below, so listing it as a
				// collection would promise a PROPFIND that fails.
				d.hiddenDirCnt.Add(1)
				continue
			}
			// The target's attributes under the LINK's name: x/net builds
			// each child's URL from Name() and stats it again, so a name
			// that is not the entry's is a listing of resources that are not
			// there.
			out = append(out, renamed{FileInfo: fi, name: e.Name()})
		case m.IsDir() || m.IsRegular():
			out = append(out, e)
		default:
			d.hiddenSpecial.Add(1)
		}
	}
	return out, nil
}

// renamed is one FileInfo under a different name — a followed symlink's
// target presented as the link.
type renamed struct {
	fs.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }
