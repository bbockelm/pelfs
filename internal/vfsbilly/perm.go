package vfsbilly

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// THE POSIX PERMISSION MODEL THIS FRONTEND ENFORCES, AND WHY IT HAS ONE.
//
// The FUSE frontend mounts with `default_permissions` (internal/rawfuse),
// which is a request to the KERNEL to apply the ordinary mode check from
// the attributes we report, before any operation reaches us. The NFS
// frontend had no equivalent: NFSv3 puts the check on the SERVER, go-nfs's
// handlers never look at a mode bit, and this adapter did not either — so a
// file chmod'd 0444 accepted a write through the mount and the bytes
// survived the seal, while the same write through FUSE was refused with
// EACCES. Two frontends over one filesystem answered the same question
// differently, which is the part that is indefensible however the question
// is answered. This file is the NFS path's equivalent of
// `default_permissions`.
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
// What the check buys, then, is not access control: it is FIDELITY. A
// program that probes permissions by attempting an operation — configure
// scripts, installers, `test -w`, anything that treats EACCES as an answer
// — gets the same answer through both frontends, and mode bits a user sets
// on their own files stop being advisory on one of them.
//
// # The root subtlety, and why capabilities are modelled rather than uid 0
//
// "uid 0 may write a 0444 file" is POSIX-correct and is NOT on its own a
// bug. But the kernel's actual rule is not "uid 0"; it is
// CAP_DAC_OVERRIDE, and the two come apart exactly where this bug was
// found. The hostile container runs as root with `--cap-drop ALL --cap-add
// SYS_ADMIN,CHOWN,FOWNER`: DAC_OVERRIDE is absent, so the tmpfs reference
// tree in that container REFUSED the write that our mount accepted, as did
// the kernel's FUSE check. A model that read "root" and stopped would have
// concluded there was nothing to fix.
//
// So the capabilities are modelled, and the credential carries the ones the
// server process actually holds (CapEff from /proc/self/status on Linux;
// elsewhere, where there are no capabilities, uid 0 stands for all four).
// That is the right set to read because the server is evaluating requests
// as itself: with CAP_CHOWN the chown succeeds, without it (the launcher's
// --drop-chown) it is refused, and both answers match what the same process
// gets from a local filesystem.
//
// # What is NOT modelled, and one thing knfsd does that we do not
//
// Linux's in-kernel NFS server gives the file's OWNER a bypass on the data
// path (NFSD_MAY_OWNER_OVERRIDE): a stateless server delegates the
// open-time check to a client it trusts, and without the bypass an
// `open(O_CREAT|O_WRONLY, 0444)` followed by writes — which is `tar -p`
// extracting a read-only file — would fail on the WRITE, since the client's
// fd outlives the mode. We do not take that bypass yet, because the
// open-time check it delegates to is driven by our ACCESS reply, and
// go-nfs's ACCESS handler echoes back whatever mask the client asked for
// (docs/go-nfs-patches.md, "Still open"). Delegating a check nobody
// performs is not delegating; it is skipping. When ACCESS becomes honest —
// a fork commit, not something reachable from here — the owner bypass
// should arrive in the same change, and this comment is the reason it is
// two halves of one design rather than an oversight.
//
// Also not modelled, deliberately: clearing S_ISUID/S_ISGID on chown and on
// a chmod by a non-member of the file's group. Both are real kernel
// behavior and neither changes an allow/deny answer, which is what the two
// frontends have to agree on.

// Caps is the part of the Linux capability set that changes a permission
// answer. Four bits, named for the capabilities they stand for, because a
// model that says "root" instead cannot express the container this bug was
// found in.
type Caps uint8

const (
	// CapChown: change a file's ownership arbitrarily.
	CapChown Caps = 1 << iota
	// CapDACOverride: bypass read, write and execute checks (on a regular
	// file, execute still requires at least one x bit to exist).
	CapDACOverride
	// CapDACReadSearch: bypass read checks on files, and read+search on
	// directories.
	CapDACReadSearch
	// CapFOwner: act as the owner for the operations that require
	// ownership — chmod, utimes, and the sticky-bit rule.
	CapFOwner
)

func (c Caps) has(want Caps) bool { return c&want != 0 }

// Cred is the identity a mount evaluates its requests as. It is fixed for
// the life of the mount; see the file comment for why it is the server's
// own identity and not the caller's AUTH_UNIX credential.
type Cred struct {
	UID, GID uint32
	// Groups are the supplementary groups, which the group class check
	// consults exactly as the kernel does.
	Groups []uint32
	Caps   Caps
}

// ProcessCred reads the identity of this process.
func ProcessCred() Cred {
	c := Cred{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	if gs, err := os.Getgroups(); err == nil {
		for _, g := range gs {
			if g >= 0 {
				c.Groups = append(c.Groups, uint32(g))
			}
		}
	}
	c.Caps = processCaps(c.UID)
	return c
}

// processCaps is the capability set this process holds.
//
// On Linux that is CapEff, which is the only honest source: a container
// that dropped CAP_DAC_OVERRIDE runs as uid 0 and is nonetheless refused by
// every local filesystem in it, and reading uid alone would model the
// opposite. Everywhere else there are no capabilities and uid 0 really is
// the whole of the superuser rule, so it stands for all four bits.
//
// A Linux process that cannot read its own /proc falls back to the same
// uid rule. That is the traditional model, it is what the platform without
// /proc gets, and it fails in the permissive direction only for uid 0 —
// which is the identity that could chmod its way past the check anyway.
func processCaps(uid uint32) Caps {
	if runtime.GOOS == "linux" {
		if c, ok := capsFromProcStatus("/proc/self/status"); ok {
			return c
		}
	}
	if uid == 0 {
		return CapChown | CapDACOverride | CapDACReadSearch | CapFOwner
	}
	return 0
}

// Linux capability numbers, from include/uapi/linux/capability.h. Only the
// four that change a permission answer are named.
const (
	capNumChown         = 0
	capNumDACOverride   = 1
	capNumDACReadSearch = 2
	capNumFOwner        = 3
)

// capsFromProcStatus parses the effective capability mask out of a
// /proc/<pid>/status file: one line, "CapEff:\t000000000000000f", a 64-bit
// hex mask with one bit per capability.
func capsFromProcStatus(path string) (Caps, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close() //nolint:errcheck
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "CapEff:")
		if !ok {
			continue
		}
		mask, err := strconv.ParseUint(strings.TrimSpace(rest), 16, 64)
		if err != nil {
			return 0, false
		}
		var c Caps
		for _, m := range []struct {
			bit uint
			cap Caps
		}{
			{capNumChown, CapChown},
			{capNumDACOverride, CapDACOverride},
			{capNumDACReadSearch, CapDACReadSearch},
			{capNumFOwner, CapFOwner},
		} {
			if mask&(1<<m.bit) != 0 {
				c |= m.cap
			}
		}
		return c, true
	}
	return 0, false
}

// perm is a request for access, in the same three bits a mode nibble uses,
// so a class's bits can be tested against it directly.
type perm uint32

const (
	permExec  perm = 1
	permWrite perm = 2
	permRead  perm = 4
)

func (p perm) String() string {
	var b strings.Builder
	for _, x := range []struct {
		bit  perm
		name byte
	}{{permRead, 'r'}, {permWrite, 'w'}, {permExec, 'x'}} {
		if p&x.bit != 0 {
			b.WriteByte(x.name)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func (c Cred) inGroup(gid uint32) bool {
	if c.GID == gid {
		return true
	}
	for _, g := range c.Groups {
		if g == gid {
			return true
		}
	}
	return false
}

// allowed answers the ordinary mode check for an object owned by uid:gid
// with permission bits mode, in the id space the mount reports.
//
// It is generic_permission() followed by capable_wrt_inode_uidgid(): one
// class (owner, else group, else other — never a union, and the first match
// wins even when a later class would grant more, which is the rule people
// are most often surprised by), then the two DAC capabilities as the
// fallback.
func (c Cred) allowed(uid, gid, mode uint32, isDir bool, want perm) bool {
	var bits perm
	switch {
	case c.UID == uid:
		bits = perm(mode>>6) & 7
	case c.inGroup(gid):
		bits = perm(mode>>3) & 7
	default:
		bits = perm(mode) & 7
	}
	if bits&want == want {
		return true
	}
	if isDir {
		if c.Caps.has(CapDACOverride) {
			return true
		}
		// DAC_READ_SEARCH covers reading and searching a directory, never
		// modifying it.
		return want&permWrite == 0 && c.Caps.has(CapDACReadSearch)
	}
	if c.Caps.has(CapDACOverride) {
		// The one thing DAC_OVERRIDE does not do is conjure an execute bit
		// onto a file that has none for anybody.
		if want&permExec == 0 || mode&0111 != 0 {
			return true
		}
	}
	return want&(permWrite|permExec) == 0 && c.Caps.has(CapDACReadSearch)
}

// owns is the "is this the file's owner" test the operations that change
// metadata require: inode_owner_or_capable().
func (c Cred) owns(uid uint32) bool { return c.UID == uid || c.Caps.has(CapFOwner) }

// mayChown answers chown(2)/chgrp(2) for a file currently owned by
// uid:gid. Either operand may be -1, meaning unchanged; go-nfs's SETATTR
// always fills both in from the current attributes, so in practice a
// chgrp arrives as a chown to the current uid, which is why "changing the
// owner to who it already is" has to be a permitted no-op rather than an
// operation requiring CAP_CHOWN.
//
// This is fs/attr.c setattr_prepare, verbatim in structure: an owner may
// give a file away only with CAP_CHOWN, and may change its group only to a
// group they are in.
func (c Cred) mayChown(uid, gid uint32, newUID, newGID int) error {
	if newUID >= 0 && uint32(newUID) != uid {
		if !c.Caps.has(CapChown) {
			return syscall.EPERM
		}
	}
	if newGID >= 0 && uint32(newGID) != gid {
		if (c.UID != uid || !c.inGroup(uint32(newGID))) && !c.Caps.has(CapChown) {
			return syscall.EPERM
		}
	}
	return nil
}
