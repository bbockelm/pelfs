// Package idmap decides whose name a mount puts on the files it serves.
//
// A pelfs volume is personal and portable: one namespace, mounted from a
// laptop, a login node and a batch worker, where the same human has three
// different uids. The catalog records the uid that WROTE each inode, which
// is the honest thing to store — and, reported verbatim, breaks the
// ordinary case completely.
//
// The root directory of a fresh volume is mode 0755 owned by whoever ran
// `pelfs init` (publish.InitVolume). Mount that volume as a different uid
// and the kernel — which does the checking, because the mount asks for
// `default_permissions` — denies every write in the root. What the user
// sees is:
//
//	fatal: could not create work tree dir 'htcondor': Permission denied
//
// on a filesystem they own, in a directory they created, with nothing to
// suggest that a number recorded on another machine is the reason.
//
// # Why not simply squash everything
//
// Reporting every inode as the mounting user is the obvious fix and it is
// too blunt. It makes chown INVISIBLE: `chown`, then `ls -l`, and nothing
// changed. Anything that sets ownership as part of its job — `tar -p`,
// `cp -a`, `rsync -a`, an installer — then appears to succeed and to have
// done nothing, which is worse than failing.
//
// # What it does instead
//
// One identity is translated: the volume's own. The root directory's
// stored uid and gid are what `pelfs init` recorded for the person whose
// volume it is, so those two numbers — and only those — are reported as
// the mounting process's. Every other id passes through untouched.
//
// This is sshfs's `idmap=user`, and it holds because it is the same
// claim: the remote's numbering for THIS user is not this machine's, and
// nothing is known about anyone else's.
//
//   - A volume made on a laptop as 501 and mounted on a cluster as 20114
//     is entirely writable, because everything in it was written as 501.
//   - A file deliberately chowned to 4242 still reads as 4242 anywhere.
//   - A volume whose root is owned by 0 — the shape publish.InitVolume
//     used to produce — becomes usable rather than read-only.
package idmap

import "os"

// Map is a mount's ownership policy: one uid and one gid translated, the
// rest passed through.
type Map struct {
	// FromUID/FromGID are the volume's own ids, as its root records them.
	FromUID, FromGID uint32
	// ToUID/ToGID are what they are reported as.
	ToUID, ToGID uint32
	// Preserve reports what the catalog stored and translates nothing.
	Preserve bool
}

// Owner maps the volume's identity — the root directory's stored
// ownership — onto this process.
//
// A caller that cannot read its own root passes zeroes, which is not a
// special case: uid 0 is exactly the identity that most needs mapping,
// since a volume rooted at uid 0 is unwritable by every ordinary user.
func Owner(rootUID, rootGID uint32) Map {
	return Map{
		FromUID: rootUID, FromGID: rootGID,
		ToUID: uint32(os.Getuid()), ToGID: uint32(os.Getgid()),
	}
}

// Apply maps one inode's stored ownership to what the mount reports.
func (m Map) Apply(uid, gid uint32) (uint32, uint32) {
	if m.Preserve {
		return uid, gid
	}
	if uid == m.FromUID {
		uid = m.ToUID
	}
	if gid == m.FromGID {
		gid = m.ToGID
	}
	return uid, gid
}

// Identity reports whether this map changes nothing, which is the common
// case: a volume mounted on the machine that made it.
func (m Map) Identity() bool {
	return m.Preserve || (m.FromUID == m.ToUID && m.FromGID == m.ToGID)
}
