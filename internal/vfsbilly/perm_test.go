package vfsbilly_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// The permission matrix this frontend enforces, at the frontend's own
// interface. It is the ordinary lane -- no Docker, no kernel mount -- and
// it is deterministic: a fixed tree, a named identity per case, and one
// billy call per assertion.
//
// It exists because the NFS frontend used to enforce nothing, so a file
// chmod'd 0444 accepted a write through the mount while the same write
// through FUSE was refused by the kernel, whose `default_permissions`
// answer is the one this file now pins on the other side. Every case below
// is written as the answer the KERNEL gives for the same tree, which is
// what "the two frontends agree" has to mean to be checkable.
//
// Identities are derived from the process uid rather than fixed, and that
// is load-bearing: internal/idmap translates the volume's OWN identity --
// the uid stored on the root directory, which publish.InitVolume sets to
// whoever created the volume -- onto the mounting user. A fixed 1000 would
// be the volume identity on a CI runner and an unrelated stranger on a
// laptop, and the same case would then be testing two different things.

// perms is one mount and the ids it is mounted with.
type perms struct {
	t    *testing.T
	ov   *overlay.FS
	me   uint32 // the mounting user
	grp  uint32 // their primary group
	they uint32 // somebody else
	thgr uint32 // a group the mounting user is NOT in
	both uint32 // a supplementary group they share
	seq  int
}

func newPerms(t *testing.T) *perms {
	t.Helper()
	fx := newFixture(t, "9e770000-1111-2222-3333-444455556666")
	base := uint32(os.Getuid())
	return &perms{
		t: t, ov: openOverlay(t, fx),
		me: base + 1001, grp: base + 2002,
		they: base + 3003, thgr: base + 4004, both: base + 5005,
	}
}

// mount returns the filesystem as the mounting user, holding caps.
func (p *perms) mount(caps vfsbilly.Caps) billy.Filesystem {
	return vfsbilly.NewAs(p.ov, vfsbilly.Cred{
		UID: p.me, GID: p.grp, Groups: []uint32{p.both}, Caps: caps,
	})
}

// dir creates a directory directly on the overlay -- setup goes UNDER the
// frontend so that what the frontend is asked is only ever the question
// being tested.
func (p *perms) dir(mode, uid, gid uint32) (uint64, string) {
	p.t.Helper()
	p.seq++
	name := fmt.Sprintf("d%d", p.seq)
	n, err := p.ov.Mkdir(context.Background(), 1, name, mode, uid, gid)
	if err != nil {
		p.t.Fatalf("setup mkdir %s: %v", name, err)
	}
	return n.Inode, "/" + name
}

// file creates a file with a body, under parent.
func (p *perms) file(parent uint64, prefix string, mode, uid, gid uint32, body []byte) string {
	p.t.Helper()
	p.seq++
	name := fmt.Sprintf("%s%d", prefix, p.seq)
	n, err := p.ov.Create(context.Background(), parent, name, mode, uid, gid)
	if err != nil {
		p.t.Fatalf("setup create %s: %v", name, err)
	}
	if len(body) > 0 {
		if _, err := p.ov.Write(context.Background(), n.Inode, 0, body); err != nil {
			p.t.Fatalf("setup write %s: %v", name, err)
		}
	}
	return name
}

// rootFile creates a file at the top of the tree and returns its path.
func (p *perms) rootFile(mode, uid, gid uint32, body []byte) string {
	return "/" + p.file(1, "f", mode, uid, gid, body)
}

// refused asserts that err is a refusal carrying want (EACCES or EPERM).
// Both halves matter: os.ErrPermission is what go-nfs tests to choose an
// NFS status at all, and the errno is what the client reports -- the kernel
// distinguishes "the mode bits say no" from "you are not the owner", so a
// frontend claiming to agree with it has to distinguish them too.
func refused(t *testing.T, what string, err error, want syscall.Errno) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: PERMITTED, want %v -- the frontend allowed an operation "+
			"the kernel refuses on the same tree", what, want)
	}
	if !errors.Is(err, os.ErrPermission) || !os.IsPermission(err) {
		t.Fatalf("%s: err = %v, want a permission error (go-nfs tests both "+
			"errors.Is and os.IsPermission)", what, err)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func allowed(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: REFUSED with %v, want permitted", what, err)
	}
}

func writeTo(fs billy.Filesystem, path string, body []byte) error {
	f, err := fs.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	return f.Close()
}

func readFrom(fs billy.Filesystem, path string) ([]byte, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return io.ReadAll(f)
}

// access asks the frontend the question NFSv3's ACCESS procedure asks --
// which of read, write and execute this mount permits on one object -- and
// renders the answer the way a mode nibble reads, so a case can state it
// as the string `ls` would show and the kernel would agree with.
//
// It is the reply a client turns into its answer for open(2), access(2)
// and `test -w`: NFSv3 has no OPEN, so there is nothing else for it to
// decide those with.
func access(t *testing.T, fs billy.Filesystem, path string) string {
	t.Helper()
	checker, ok := fs.(nfs.PermissionChecker)
	if !ok {
		t.Fatal("the frontend no longer implements nfs.PermissionChecker, so " +
			"go-nfs answers ACCESS by echoing back whatever the client asked about")
	}
	granted, err := checker.Permitted(path)
	if err != nil {
		t.Fatalf("ACCESS on %s: %v", path, err)
	}
	out := []byte("---")
	for i, bit := range []nfs.Permission{nfs.PermissionRead, nfs.PermissionWrite, nfs.PermissionExecute} {
		if granted&bit != 0 {
			out[i] = "rwx"[i]
		}
	}
	return string(out)
}

// THE FINDING, pinned. A file chmod'd 0444 accepted a write through the
// NFS frontend and the bytes survived the seal
// (internal/hostile/testdata/corpus/nfs-ignores-mode-bits.plan). Raw FUSE
// refused the same write with EACCES because the kernel applies the mode
// check before the request is sent.
//
// WHERE THE REFUSAL LIVES NOW, and why it moved. The reported case is a
// file the mount's own user owns, and a WRITE on one of those is allowed
// here on purpose: it is knfsd's owner override, without which `tar -p`
// cannot extract a read-only file at all (mayOpen documents the rule and
// its scope). What refuses the write is the half that arrives first — the
// ACCESS reply, which reports the file as not writable and which is how an
// NFSv3 client answers open(2). The client never sends the WRITE.
//
// So the finding is pinned in the two places it can now be true: ACCESS
// says no to the file's own owner, and the data path says no to everybody
// who is not. A regression in either one brings the bug back.
func TestAWriteTheModeForbidsIsRefusedAndNoBytesLand(t *testing.T) {
	p := newPerms(t)
	fs := p.mount(0)
	original := []byte("the body that must survive")
	ro := p.rootFile(0o444, p.me, p.grp, original)

	// The client's open(2) is decided by this reply and nothing else.
	if got := access(t, fs, ro); got != "r--" {
		t.Fatalf("ACCESS on a 0444 file = %q, want %q — a client told this "+
			"opens the file for writing, and the write follows", got, "r--")
	}

	// And where there is no owner override to reach, the data path itself
	// refuses: O_WRONLY and O_RDWR alike, since go-nfs's WRITE handler
	// opens O_RDWR and the check is on the mode, not on the flag spelling.
	theirs := p.rootFile(0o444, p.they, p.thgr, original)
	refused(t, "open O_WRONLY on somebody else's 0444 file",
		writeTo(fs, theirs, []byte("clobber")), syscall.EACCES)
	_, err := fs.OpenFile(theirs, os.O_RDWR, 0)
	refused(t, "open O_RDWR on somebody else's 0444 file", err, syscall.EACCES)

	// The bytes are the point: the original report's signature was
	// "ro.dat: byte 0 is 0x29 in the mount, 0xc2 in the reference".
	got, err := readFrom(fs, theirs)
	if err != nil {
		t.Fatalf("read back a 0444 file: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("the refused write landed anyway: %q, want %q", got, original)
	}
}

// The mode check itself: class selection, the first-match-wins rule, and
// the two DAC capabilities.
//
// Each case states BOTH answers, because they are two different questions
// and only one of them is the mode check. `access` is what ACCESS reports,
// which is the mode check and nothing else; wantWrite/wantRead are what
// the data path does, where a file's owner is allowed past their own mode
// (mayOpen's owner override). The one case where they disagree is marked,
// and that disagreement is knfsd's design rather than a wrinkle in this
// one: the client refuses the open, so the operation the server would
// have allowed is never sent.
func TestModeBitsDecideReadsAndWrites(t *testing.T) {
	p := newPerms(t)
	body := []byte("body")

	// owner is "me" or "them"; group is "theirs" (a group the mounting
	// user is not in) or "shared" (one of their supplementary groups).
	for _, tc := range []struct {
		name       string
		mode       uint32
		owner      string
		group      string
		caps       vfsbilly.Caps
		access     string // what ACCESS reports: the mode check, alone
		wantWrite  bool
		wantRead   bool
		wantErrno  syscall.Errno
		whyRefused string
	}{
		{name: "owner may write what owner-write permits", mode: 0o644,
			owner: "me", group: "theirs", access: "rw-", wantWrite: true, wantRead: true},
		{name: "the owner's own mode is what ACCESS reports, and the data path overrides it",
			mode: 0o444, owner: "me", group: "theirs",
			// The owner class denies w and the owner does not fall through
			// to other, so ACCESS says r-- and a client refuses the open.
			// The WRITE that would follow one it allowed is trusted:
			// NFSD_MAY_OWNER_OVERRIDE, and the reason `tar -p` works.
			access: "r--", wantWrite: true, wantRead: true},
		{name: "CAP_DAC_OVERRIDE is what lets root past a 0444 file", mode: 0o444,
			owner: "me", group: "theirs",
			caps: vfsbilly.CapDACOverride, access: "rw-", wantWrite: true, wantRead: true},
		{name: "other class grants what the owner's mode does not", mode: 0o606,
			owner: "them", group: "theirs", access: "rw-", wantWrite: true, wantRead: true},
		{name: "the group class is consulted for a supplementary group", mode: 0o060,
			owner: "them", group: "shared", access: "rw-", wantWrite: true, wantRead: true},
		{name: "the group class wins even when other would grant more", mode: 0o604,
			owner: "them", group: "shared", access: "---",
			wantWrite: false, wantRead: false, wantErrno: syscall.EACCES,
			whyRefused: "first matching class decides; group is ---, so other's r-- is never reached"},
		{name: "a mode nobody may read", mode: 0o000,
			owner: "them", group: "theirs", access: "---",
			wantWrite: false, wantRead: false, wantErrno: syscall.EACCES},
		{name: "CAP_DAC_READ_SEARCH reads but does not write", mode: 0o000,
			owner: "them", group: "theirs", access: "r--",
			caps: vfsbilly.CapDACReadSearch, wantWrite: false, wantRead: true,
			wantErrno: syscall.EACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid := p.me, p.grp
			if tc.owner == "them" {
				uid = p.they
			}
			switch tc.group {
			case "theirs":
				gid = p.thgr
			case "shared":
				gid = p.both
			default:
				t.Fatalf("case names a group %q that the fixture does not have", tc.group)
			}
			path := p.rootFile(tc.mode, uid, gid, body)
			fs := p.mount(tc.caps)

			if got := access(t, fs, path); got != tc.access {
				t.Errorf("ACCESS = %q, want %q — this is the answer a client "+
					"gives open(2), access(2) and `test -w`", got, tc.access)
			}

			err := writeTo(fs, path, []byte("xxxx"))
			if tc.wantWrite {
				allowed(t, "write", err)
			} else {
				refused(t, "write ("+tc.whyRefused+")", err, tc.wantErrno)
			}
			_, err = readFrom(fs, path)
			if tc.wantRead {
				allowed(t, "read", err)
			} else {
				refused(t, "read ("+tc.whyRefused+")", err, tc.wantErrno)
			}
		})
	}
}

// A truncate is a write, and it arrives by a different route: NFSv3
// SETATTR with a size, which go-nfs turns into OpenFile(O_WRONLY|O_EXCL)
// followed by Truncate. That route has to reach the same answer -- both
// halves of it, since knfsd gives a size change the same owner override it
// gives a WRITE (nfsd_setattr adds NFSD_MAY_OWNER_OVERRIDE for ATTR_SIZE).
func TestTruncateIsAWrite(t *testing.T) {
	p := newPerms(t)
	fs := p.mount(0)
	ro := p.rootFile(0o444, p.they, p.thgr, []byte("keep me"))

	_, err := fs.OpenFile(ro, os.O_WRONLY|os.O_EXCL, 0)
	refused(t, "SETATTR-size open of somebody else's 0444 file", err, syscall.EACCES)

	rw := p.rootFile(0o644, p.me, p.grp, []byte("keep me"))
	f, err := fs.OpenFile(rw, os.O_WRONLY|os.O_EXCL, 0)
	allowed(t, "SETATTR-size open of a 0644 file", err)
	allowed(t, "truncate", f.Truncate(0))
	allowed(t, "close", f.Close())

	// The owner's own read-only file: ACCESS says not writable, so a
	// client refuses ftruncate(2) before sending anything, and the SETATTR
	// that only arrives from one it allowed is carried out.
	mine := p.rootFile(0o444, p.me, p.grp, []byte("keep me"))
	if got := access(t, fs, mine); got != "r--" {
		t.Fatalf("ACCESS on my own 0444 file = %q, want %q", got, "r--")
	}
	f, err = fs.OpenFile(mine, os.O_WRONLY|os.O_EXCL, 0)
	allowed(t, "SETATTR-size open of my own 0444 file", err)
	allowed(t, "truncate", f.Truncate(0))
	allowed(t, "close", f.Close())
}

// THE ACCESS MATRIX: the answers a client turns into open(2), access(2),
// `test -w`, `test -x` and a path walk. Every case is written as the answer
// the KERNEL gives for the same file, which is what "the two frontends
// agree" has to mean -- the FUSE frontend gets these from the kernel's own
// mode check under `default_permissions`, and this is the NFS frontend
// saying the same thing on the wire.
//
// Before this, go-nfs echoed the mask the client asked about, so every
// answer below was "yes".
func TestAccessAnswersWhatTheKernelWouldSay(t *testing.T) {
	p := newPerms(t)

	for _, tc := range []struct {
		name  string
		mode  uint32
		dir   bool
		owner string
		caps  vfsbilly.Caps
		want  string
	}{
		{name: "test -w on a 0444 file is NO, for its own owner",
			mode: 0o444, owner: "me", want: "r--"},
		{name: "test -x on a 0644 file is NO",
			mode: 0o644, owner: "me", want: "rw-"},
		{name: "test -x on a 0755 file is YES",
			mode: 0o755, owner: "me", want: "rwx"},
		{name: "somebody else's 0600 file is nothing at all",
			mode: 0o600, owner: "them", want: "---"},
		{name: "a directory without x cannot be searched, whatever else it grants",
			mode: 0o644, dir: true, owner: "me", want: "rw-"},
		{name: "an ordinary directory",
			mode: 0o755, dir: true, owner: "me", want: "rwx"},
		{name: "a read-only directory searches and lists but does not change",
			mode: 0o555, dir: true, owner: "me", want: "r-x"},
		{name: "CAP_DAC_OVERRIDE grants write on a 0444 file and still no execute",
			mode: 0o444, owner: "me", caps: vfsbilly.CapDACOverride, want: "rw-"},
		{name: "CAP_DAC_OVERRIDE does not conjure an execute bit that exists for nobody",
			mode: 0o644, owner: "me", caps: vfsbilly.CapDACOverride, want: "rw-"},
		{name: "CAP_DAC_READ_SEARCH reads and searches a directory it may not change",
			mode: 0o000, dir: true, owner: "them", caps: vfsbilly.CapDACReadSearch, want: "r-x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid := p.me, p.grp
			if tc.owner == "them" {
				uid, gid = p.they, p.thgr
			}
			var path string
			if tc.dir {
				_, path = p.dir(tc.mode, uid, gid)
			} else {
				path = p.rootFile(tc.mode, uid, gid, []byte("body"))
			}
			if got := access(t, p.mount(tc.caps), path); got != tc.want {
				t.Errorf("ACCESS = %q, want %q", got, tc.want)
			}
		})
	}
}

// `tar -p` extracting a read-only file, which is the shape the owner
// override exists for. tar creates the file with the mode the archive
// records, writes the body through the descriptor it already holds, and
// closes it: `open(O_CREAT|O_WRONLY, 0444)` and then writes.
//
// A stateless server sees only the WRITE, on a file that by then is 0444.
// Refusing it second-guesses an open the client already made and the file
// arrives EMPTY -- and the client is not wrong, because the descriptor
// legitimately outlives the mode. knfsd allows it for the file's owner
// (NFSD_MAY_OWNER_OVERRIDE, fs/nfsd/vfs.c) and so does this.
func TestTarDashPExtractsAReadOnlyFile(t *testing.T) {
	p := newPerms(t)
	fs := p.mount(0)
	body := []byte("the body tar is about to write")

	// CREATE with the archive's mode. The new file's own mode is not
	// checked -- the kernel checks the parent directory for a create --
	// which is what makes `install -m 444` work anywhere.
	f, err := fs.Create("/extracted.txt")
	allowed(t, "tar creates the file", err)
	allowed(t, "close", f.Close())
	allowed(t, "tar applies the archived mode", fs.(billy.Change).Chmod("/extracted.txt", 0o444))

	// And now the WRITEs, which arrive on a file that is already 0444.
	// This is the operation that used to fail.
	allowed(t, "tar writes the body through the descriptor it opened",
		writeTo(fs, "/extracted.txt", body))

	got, err := readFrom(fs, "/extracted.txt")
	if err != nil {
		t.Fatalf("read back the extracted file: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("the extracted file holds %q, want %q", got, body)
	}

	// The override is the owner's and nobody else's: the same shape on a
	// file owned by somebody else is still refused, mode bits and all.
	theirs := p.rootFile(0o444, p.they, p.thgr, []byte("untouched"))
	refused(t, "the same write on somebody else's read-only file",
		writeTo(fs, theirs, body), syscall.EACCES)
}

// Creating, removing and renaming a NAME costs write and search on the
// DIRECTORY, and nothing on the object -- the classic surprise being that
// a read-only file in a writable directory can still be deleted.
func TestNamespaceOpsCostTheDirectory(t *testing.T) {
	p := newPerms(t)
	readonlyDir, roPath := p.dir(0o555, p.they, p.thgr)
	victim := p.file(readonlyDir, "v", 0o666, p.they, p.thgr, []byte("x"))
	writableDir, rwPath := p.dir(0o755, p.me, p.grp)
	spared := p.file(writableDir, "s", 0o444, p.they, p.thgr, []byte("x"))

	fs := p.mount(0)

	_, err := fs.Create(roPath + "/new.txt")
	refused(t, "create in a directory that denies write", err, syscall.EACCES)
	refused(t, "mkdir in a directory that denies write",
		fs.MkdirAll(roPath+"/sub", 0o755), syscall.EACCES)
	refused(t, "symlink in a directory that denies write",
		fs.Symlink("target", roPath+"/link"), syscall.EACCES)
	refused(t, "unlink in a directory that denies write",
		fs.Remove(roPath+"/"+victim), syscall.EACCES)
	refused(t, "rename out of a directory that denies write",
		fs.Rename(roPath+"/"+victim, rwPath+"/moved"), syscall.EACCES)
	refused(t, "rename into a directory that denies write",
		fs.Rename(rwPath+"/"+spared, roPath+"/moved"), syscall.EACCES)

	// The mode on the FILE is not consulted: a 0444 file owned by somebody
	// else is still deletable from a directory the caller may write.
	allowed(t, "unlink a read-only file from a writable directory",
		fs.Remove(rwPath+"/"+spared))

	// And CAP_DAC_OVERRIDE gets past the directory, as it does everywhere.
	root := p.mount(vfsbilly.CapDACOverride)
	allowed(t, "unlink with CAP_DAC_OVERRIDE", root.Remove(roPath+"/"+victim))
}

// The sticky bit: in a +t directory only the file's owner, the directory's
// owner, or CAP_FOWNER may unlink a name. It is EPERM, not EACCES.
func TestStickyDirectory(t *testing.T) {
	p := newPerms(t)
	sticky, path := p.dir(0o1777, p.they, p.thgr)
	theirs := p.file(sticky, "t", 0o666, p.they, p.thgr, []byte("x"))
	mine := p.file(sticky, "m", 0o666, p.me, p.grp, []byte("x"))
	alsoTheirs := p.file(sticky, "a", 0o666, p.they, p.thgr, []byte("x"))

	fs := p.mount(0)
	refused(t, "unlink somebody else's file from a sticky directory",
		fs.Remove(path+"/"+theirs), syscall.EPERM)
	refused(t, "rename somebody else's file out of a sticky directory",
		fs.Rename(path+"/"+theirs, "/moved"), syscall.EPERM)
	allowed(t, "unlink my own file from a sticky directory", fs.Remove(path+"/"+mine))

	owner := p.mount(vfsbilly.CapFOwner)
	allowed(t, "unlink with CAP_FOWNER", owner.Remove(path+"/"+alsoTheirs))
}

// Search permission on a directory hides everything below it, and read
// permission on a directory is a different bit from search.
func TestTraverseAndList(t *testing.T) {
	p := newPerms(t)
	noSearch, nsPath := p.dir(0o644, p.they, p.thgr) // r-- : listable, not enterable
	hidden := p.file(noSearch, "h", 0o666, p.me, p.grp, []byte("x"))
	noRead, nrPath := p.dir(0o111, p.they, p.thgr) // --x : enterable, not listable
	reachable := p.file(noRead, "r", 0o666, p.me, p.grp, []byte("body"))

	fs := p.mount(0)

	_, err := fs.Stat(nsPath + "/" + hidden)
	refused(t, "stat through a directory that denies search", err, syscall.EACCES)
	_, err = fs.Open(nsPath + "/" + hidden)
	refused(t, "open through a directory that denies search", err, syscall.EACCES)
	_, err = fs.ReadDir(nsPath)
	allowed(t, "list a directory that denies search but permits read", err)

	_, err = fs.ReadDir(nrPath)
	refused(t, "list a directory that denies read", err, syscall.EACCES)
	_, err = fs.Stat(nrPath + "/" + reachable)
	allowed(t, "stat a known name through a directory that denies read", err)

	// CAP_DAC_READ_SEARCH is exactly the capability for this.
	rs := p.mount(vfsbilly.CapDACReadSearch)
	_, err = rs.Stat(nsPath + "/" + hidden)
	allowed(t, "stat with CAP_DAC_READ_SEARCH", err)
	_, err = rs.ReadDir(nrPath)
	allowed(t, "list with CAP_DAC_READ_SEARCH", err)
}

// chmod and utimes are the OWNER's, not the writer's: a file mode 0777 is
// still only its owner's to chmod, which is the half of the model that
// mode bits alone cannot express.
func TestChmodAndUtimesRequireOwnership(t *testing.T) {
	p := newPerms(t)
	theirs := p.rootFile(0o777, p.they, p.thgr, nil)
	mine := p.rootFile(0o600, p.me, p.grp, nil)
	when := time.Unix(1700000000, 0)

	ch := p.mount(0).(billy.Change)
	refused(t, "chmod a file owned by somebody else", ch.Chmod(theirs, 0o600), syscall.EPERM)
	refused(t, "utimes a file owned by somebody else",
		ch.Chtimes(theirs, when, when), syscall.EPERM)
	allowed(t, "chmod my own file", ch.Chmod(mine, 0o640))
	allowed(t, "utimes my own file", ch.Chtimes(mine, when, when))

	fo := p.mount(vfsbilly.CapFOwner).(billy.Change)
	allowed(t, "chmod with CAP_FOWNER", fo.Chmod(theirs, 0o600))
	allowed(t, "utimes with CAP_FOWNER", fo.Chtimes(theirs, when, when))
}

// chown is CAP_CHOWN's, with the one exception the kernel makes: an owner
// may change their file's GROUP to a group they are in. This is the second
// symptom in the report -- with CAP_CHOWN dropped the NFS frontend
// performed a chown the kernel and the FUSE frontend both refused
// (scripts/hostile-docker.sh --drop-chown).
func TestChownRequiresTheCapability(t *testing.T) {
	p := newPerms(t)
	mine := p.rootFile(0o644, p.me, p.grp, nil)
	mine2 := p.rootFile(0o644, p.me, p.grp, nil)
	mine3 := p.rootFile(0o644, p.me, p.grp, nil)
	theirs := p.rootFile(0o644, p.they, p.thgr, nil)

	ch := p.mount(0).(billy.Change)
	refused(t, "give my own file away without CAP_CHOWN",
		ch.Lchown(mine, int(p.they), int(p.grp)), syscall.EPERM)
	refused(t, "chgrp to a group I am not in",
		ch.Lchown(mine, int(p.me), int(p.thgr)), syscall.EPERM)
	refused(t, "chgrp a file I do not own",
		ch.Lchown(theirs, int(p.they), int(p.both)), syscall.EPERM)
	allowed(t, "chgrp my own file to a supplementary group of mine",
		ch.Lchown(mine, int(p.me), int(p.both)))
	// go-nfs's SETATTR fills in the unchanged operand from the current
	// attributes, so "chown to who it already is" must be a no-op and not
	// an operation needing the capability.
	allowed(t, "a chown that changes nothing", ch.Lchown(mine2, int(p.me), int(p.grp)))
	allowed(t, "an operand of -1 is unchanged", ch.Lchown(mine2, -1, -1))

	chowner := p.mount(vfsbilly.CapChown).(billy.Change)
	allowed(t, "give a file away with CAP_CHOWN",
		chowner.Lchown(mine3, int(p.they), int(p.thgr)))
}

// A read-only mount refuses every mutation before the mode check is
// reached, and still applies the mode check to reads.
func TestReadOnlyMountStillChecksReads(t *testing.T) {
	fx := newFixture(t, "9e771111-1111-2222-3333-444455556666")
	base := uint32(os.Getuid())
	stranger := vfsbilly.Cred{UID: base + 6006, GID: base + 7007}
	fs := vfsbilly.NewReadOnlyAs(fx.base, stranger)

	// The fixture's own root maps onto the mounting user (internal/idmap),
	// so the tree is readable; its files are 0644 owned by uid 0, which the
	// map does not touch, and this identity is in neither class.
	if _, err := fs.Open("/base.txt"); err != nil {
		t.Fatalf("a 0644 file is other-readable: %v", err)
	}
	if err := fs.Remove("/base.txt"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("remove on a read-only mount = %v, want a permission error", err)
	}
}
