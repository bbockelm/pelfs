//go:build !windows

package rawfuse

import (
	"context"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fsperm"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// The two refusals, kept apart because the kernel keeps them apart:
// EACCES is "the mode bits say no", EPERM is "you are not the owner".
const (
	errAccess = fuse.Status(syscall.EACCES)
	errPerm   = fuse.Status(syscall.EPERM)
)

// WHO CHECKS PERMISSIONS ON A FUSE MOUNT, AND WHEN IT HAS TO BE US.
//
// Normally: the kernel. `mount` asks for `default_permissions`, and the
// kernel then applies the ordinary mode check from the attributes we
// report, against the caller's real credential, over the path it really
// walked — before the request ever reaches this process. That is both
// cheaper and more faithful than anything a userspace server can do, which
// is why Access stayed ENOSYS for the whole of v0.1.0 and v0.2.0.
//
// The exception is a mount on a PASSED /dev/fuse descriptor — the
// apptainer `--fusemount` shape (docs/design-apptainer.md). Whoever opened
// the device called mount(2), so the mount options are theirs: go-fuse
// recognises the `/dev/fd/N` mountpoint and skips fusermount and mount(2)
// entirely (`fuse/server.go`, parseFuseFd), so `MountOptions.Options` —
// `ro` and `default_permissions` both — are never delivered to anything.
// Apptainer does not ask for `default_permissions`, so on that mount NO
// ONE is applying the mode bits unless this package does.
//
// v0.2.0 shipped POSIX permission enforcement as a headline change, on the
// argument that two frontends over one filesystem must not answer the same
// question differently. A mount that silently opts out of it is the same
// defect wearing a different hat, so when pelfs did not choose the mount
// options, pelfs does the checking: this file, over internal/fsperm — the
// SAME model internal/vfsbilly enforces for the NFS frontend.
//
// # Where the check is applied, and the two holes that leaves
//
// A userspace server can only check on requests the kernel actually sends
// it, and with `default_permissions` off the kernel checks nothing except
// "an exec needs SOME execute bit to exist" (fs/fuse/dir.c,
// fuse_permission). So the checks go where the kernel would have put them,
// on the requests that are always sent:
//
//   - OPEN and OPENDIR: read/write on the object. This is the load-bearing
//     one. It is what refuses `cat` on a 0000 file, and it is reliable
//     because the kernel never serves an open from cache.
//   - ACCESS: the access(2)/faccessat(2) reply, which the kernel sends
//     only when `default_permissions` is off — exactly our case.
//   - The namespace operations: write+search on the directory, the
//     sticky-bit rule, and the ownership rules for chmod/chown/utimes.
//     Always sent; never cached.
//   - LOOKUP: search permission on the parent directory.
//
// Two things this cannot reach, both documented in docs/design-apptainer.md
// rather than papered over:
//
//  1. PATH TRAVERSAL is enforced only on a dentry-cache MISS. The kernel
//     resolves a cached name without asking us, and this mount hands out
//     effectively infinite entry TTLs (entryValidity), so a directory
//     whose mode denies search still lets a name through that some
//     permitted caller looked up earlier. Closing that is precisely what
//     `default_permissions` is for.
//  2. A CALLER'S SUPPLEMENTARY GROUPS are not on the wire. The FUSE header
//     carries uid and gid and nothing else, and /proc/<pid> is not usable
//     for the rest — the pid is in the caller's namespace, not ours. For
//     the mount owner we substitute this process's own group set and
//     capabilities, which is exact; for any other uid the group class is
//     evaluated on the primary gid alone, which can deny what the kernel
//     would have allowed. A `--fusemount` driver serves one job's uid, so
//     in the shape this exists for the two coincide.
//
// READ and WRITE are deliberately NOT checked. They arrive against a file
// handle, and the open that produced it was checked; re-checking the mode
// at write time is the bug knfsd's owner override exists to avoid (see
// internal/vfsbilly's mayOpen) — `open(O_CREAT|O_WRONLY, 0444)` followed
// by writes is `tar -p` extracting a read-only file, and it must work.

// checker holds the identity this process is, which is the only part of a
// caller's credential the protocol does not carry.
type checker struct {
	self fsperm.Cred
}

// credOf is the identity to evaluate one request as.
//
// The kernel puts the caller's uid and gid in every request header, and
// they are authenticated — unlike the NFS frontend's AUTH_UNIX, this is
// the kernel speaking. What it does not put there is the supplementary
// group set or the capabilities, so:
//
//   - the mount owner (the overwhelmingly common case, and the only case
//     that arises without `allow_other`) is evaluated as this process,
//     with its real groups and its real CapEff;
//   - uid 0 is credited with the four DAC capabilities. On this mount that
//     is not a guess: a passed descriptor comes from a parent that mounted
//     inside a user namespace, and root in the namespace owning the mount
//     does hold them over these files (capable_wrt_inode_uidgid), which is
//     what `apptainer --fakeroot` relies on;
//   - anyone else gets their uid and primary gid, and no capabilities.
func (c *checker) credOf(h *fuse.InHeader) fsperm.Cred {
	if h.Uid == c.self.UID {
		return c.self
	}
	if h.Uid == 0 {
		return fsperm.Cred{UID: 0, GID: h.Gid, Caps: fsperm.AllCaps}
	}
	return fsperm.Cred{UID: h.Uid, GID: h.Gid}
}

// permitted is the mode check on one node, in the id space this mount
// REPORTS (internal/idmap) — a check against a number the mount does not
// report is a check against a fiction.
func (r *raw) permitted(h *fuse.InHeader, n *genfs.Node, want fsperm.Perm) fuse.Status {
	uid, gid := r.ids.Apply(n.UID, n.GID)
	if r.perm.credOf(h).Allowed(uid, gid, n.Mode&07777, n.Type == catalog.TypeDir, want) {
		return fuse.OK
	}
	return errAccess
}

// may checks want against one inode. It is fuse.OK immediately when the
// kernel is doing the checking, which is every mount but a passed-fd one.
func (r *raw) may(ctx context.Context, h *fuse.InHeader, ino uint64, want fsperm.Perm) fuse.Status {
	if r.perm == nil {
		return fuse.OK
	}
	n, err := r.fs.GetAttr(ctx, ino)
	if err != nil {
		return errStatus(err)
	}
	return r.permitted(h, &n, want)
}

// mayCreateIn is the check every operation that BINDS a name in a
// directory shares: write and search on the directory.
func (r *raw) mayCreateIn(ctx context.Context, h *fuse.InHeader, dir uint64) fuse.Status {
	return r.may(ctx, h, dir, fsperm.PermWrite|fsperm.PermExec)
}

// mayRemoveFrom is the check for UNBINDING name from dir: write and search
// on the directory, and then the sticky-bit rule, which in a +t directory
// admits only the file's owner, the directory's owner, or CAP_FOWNER. It
// is what stops /tmp from being a free-for-all, and it is EPERM, not
// EACCES.
//
// A name that will not resolve is left to the operation itself: this
// returns OK and the unlink reports the real ENOENT.
func (r *raw) mayRemoveFrom(ctx context.Context, h *fuse.InHeader, dir uint64, name string) fuse.Status {
	if r.perm == nil {
		return fuse.OK
	}
	p, err := r.fs.GetAttr(ctx, dir)
	if err != nil {
		return errStatus(err)
	}
	if st := r.permitted(h, &p, fsperm.PermWrite|fsperm.PermExec); st != fuse.OK {
		return st
	}
	if p.Mode&syscall.S_ISVTX == 0 {
		return fuse.OK
	}
	t, err := r.fs.Lookup(ctx, dir, name)
	if err != nil {
		return fuse.OK
	}
	cred := r.perm.credOf(h)
	duid, _ := r.ids.Apply(p.UID, p.GID)
	tuid, _ := r.ids.Apply(t.UID, t.GID)
	if cred.UID == tuid || cred.UID == duid || cred.Caps.Has(fsperm.CapFOwner) {
		return fuse.OK
	}
	return errPerm
}

// maySetAttr splits SETATTR by what each valid bit actually requires,
// because the answers differ:
//
//   - mode, and an EXPLICIT time, are the owner's privilege
//     (inode_owner_or_capable, and utimes(2) with a non-NULL argument);
//   - "set the time to now" — utimes(NULL), which is `touch` on someone
//     else's file — needs write permission instead;
//   - uid and gid go through the CAP_CHOWN rule (fsperm.MayChown), against
//     the ownership this mount REPORTS, since that is the ownership the
//     caller read back and asked to change;
//   - a size change is a write. Through a file handle it was already
//     authorized by the OPEN that produced the handle, which is what makes
//     ftruncate(2) on a 0444 file the caller created work.
func (r *raw) maySetAttr(ctx context.Context, input *fuse.SetAttrIn) fuse.Status {
	if r.perm == nil {
		return fuse.OK
	}
	n, err := r.fs.GetAttr(ctx, input.NodeId)
	if err != nil {
		return errStatus(err)
	}
	h := &input.InHeader
	cred := r.perm.credOf(h)
	uid, gid := r.ids.Apply(n.UID, n.GID)
	owner := cred.Owns(uid)

	if _, ok := input.GetMode(); ok && !owner {
		return errPerm
	}
	if input.Valid&fuse.FATTR_MTIME != 0 {
		if input.Valid&fuse.FATTR_MTIME_NOW != 0 {
			if st := r.permitted(h, &n, fsperm.PermWrite); st != fuse.OK && !owner {
				return st
			}
		} else if !owner {
			return errPerm
		}
	}
	if input.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) != 0 {
		newUID, newGID := -1, -1
		if u, ok := input.GetUID(); ok {
			newUID = int(u)
		}
		if g, ok := input.GetGID(); ok {
			newGID = int(g)
		}
		// MayChown's only refusal is EPERM, and errStatus does not
		// recognise a bare errno, so it is spelled here rather than
		// arriving as EIO.
		if cred.MayChown(uid, gid, newUID, newGID) != nil {
			return errPerm
		}
	}
	if _, ok := input.GetSize(); ok {
		if _, viaHandle := input.GetFh(); !viaHandle {
			if st := r.permitted(h, &n, fsperm.PermWrite); st != fuse.OK {
				return st
			}
		}
	}
	return fuse.OK
}

// Access answers access(2) and faccessat(2). The kernel sends it ONLY when
// default_permissions is off, so a mount that left the check to the kernel
// keeps answering ENOSYS and the kernel stops asking.
//
// F_OK — "does it exist" — carries no mode bits, and the GETATTR the check
// needs has already answered it.
func (r *raw) Access(cancel <-chan struct{}, input *fuse.AccessIn) fuse.Status {
	if r.perm == nil {
		return fuse.ENOSYS
	}
	return r.may(ctxOf(cancel), &input.InHeader, input.NodeId, fsperm.Perm(input.Mask)&7)
}

// openWant is the access an OPEN's flags ask for. O_TRUNC is a write even
// when the flags say O_RDONLY, which the kernel refuses outright; the
// overlay reports EROFS/EACCES from the same place either way.
func openWant(flags uint32) fsperm.Perm {
	var want fsperm.Perm
	switch flags & uint32(syscall.O_ACCMODE) {
	case syscall.O_WRONLY:
		want = fsperm.PermWrite
	case syscall.O_RDWR:
		want = fsperm.PermRead | fsperm.PermWrite
	default:
		want = fsperm.PermRead
	}
	if flags&uint32(syscall.O_TRUNC) != 0 {
		want |= fsperm.PermWrite
	}
	return want
}
