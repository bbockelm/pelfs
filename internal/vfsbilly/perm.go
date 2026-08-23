package vfsbilly

import (
	"github.com/bbockelm/pelfs/internal/fsperm"
)

// THE POSIX PERMISSION MODEL THIS FRONTEND ENFORCES, AND WHY IT HAS ONE.
//
// The model itself lives in internal/fsperm, because the FUSE frontend
// needs the same one on a mount whose options it did not choose
// (internal/rawfuse, a passed /dev/fuse descriptor). This file is what the
// NFS frontend adds to it: who the identity is, and where the check is
// asked. It is the NFS path's equivalent of `default_permissions`.
//
// # Who the user is
//
// The export is loopback (127.0.0.1, a port nobody is told), single-mount,
// and single-user: the person the server process belongs to. Every request
// is evaluated as THAT identity — the server's own uid, gid, supplementary
// groups and capabilities — mapped through internal/idmap exactly as the
// ownership the mount REPORTS is mapped, because a check against a number
// the mount does not report is a check against a fiction.
//
// The AUTH_UNIX credential that NFSv3 puts in every request is deliberately
// NOT the identity. Three reasons, in order of weight:
//
//  1. It is unauthenticated. Any local process can dial the loopback port
//     and claim any uid it likes, including the owner's. Honoring it would
//     not make the mount safer; it would only make the check look like a
//     security boundary, which it is not and cannot be. (The mount already
//     advertises AUTH_NULL — internal/nfsmount, NewNullAuthHandler — which
//     says exactly this on the wire.)
//  2. It never reaches here. go-nfs parses the credential into an
//     unexported request struct; billy.Filesystem carries no per-request
//     context, and the Handler interface passes none. Using it needs a
//     commit on the fork (docs/go-nfs-patches.md) whose only justification
//     would be a credential we have decided not to trust.
//  3. Nothing is lost. For the one user the export exists for, the
//     AUTH_UNIX uid IS the server's uid, so the two identities coincide in
//     every case that matters.
//
// This is the one place the two frontends legitimately differ: FUSE gets
// the caller's uid and gid from the kernel in every request header, so
// internal/rawfuse evaluates the CALLER, while this evaluates the server.
//
// # Where the model is asked, and the one bypass knfsd takes
//
// The same model answers two different questions, and they are asked in
// two places because knfsd asks them in two places:
//
//   - ACCESS (billyFS.Permitted) is the mode check ALONE. NFSv3 has no
//     OPEN, so this reply is how a client answers open(2), access(2) and
//     `test -w`; it is the equivalent of the kernel refusing the open
//     under `default_permissions`, and it must say no about a 0444 file
//     even to that file's owner.
//   - The data path (billyFS.mayOpen) gives the file's OWNER a bypass —
//     knfsd's NFSD_MAY_OWNER_OVERRIDE — because by the time a READ or
//     WRITE arrives, the open it belongs to was already decided by the
//     reply above. Without it `open(O_CREAT|O_WRONLY, 0444)` followed by
//     writes, which is `tar -p` extracting a read-only file, fails on the
//     WRITE: the descriptor legitimately outlives the mode, and a
//     stateless server cannot see it.
//
// Neither half is safe alone, and mayOpen documents exactly how far the
// bypass reaches (not the namespace operations, not the path walk, not
// the ownership questions, not directories).

// The model, under the names this package has always called it by. Aliases
// rather than a wrapper: Cred is part of this package's exported surface
// (NewAs, NewReadOnlyAs), and callers that build one should not have to
// care which package defines the fields.
type (
	Cred = fsperm.Cred
	Caps = fsperm.Caps
	perm = fsperm.Perm
)

const (
	CapChown         = fsperm.CapChown
	CapDACOverride   = fsperm.CapDACOverride
	CapDACReadSearch = fsperm.CapDACReadSearch
	CapFOwner        = fsperm.CapFOwner

	permExec  = fsperm.PermExec
	permWrite = fsperm.PermWrite
	permRead  = fsperm.PermRead
)

// ProcessCred reads the identity of this process; see fsperm.
func ProcessCred() Cred { return fsperm.ProcessCred() }
