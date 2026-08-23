package rawfuse_test

import (
	"context"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/fsperm"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/bbockelm/pelfs/internal/testvol"
)

var (
	errAccess = fuse.Status(syscall.EACCES)
	errPerm   = fuse.Status(syscall.EPERM)
)

// The identity every fixture below is mounted as. Named rather than read
// from the process for the reason BindCheckedAs exists: a test whose answer
// depends on whether CI ran it as root is not a test of the model.
var (
	owner    = fsperm.Cred{UID: 4001, GID: 5001}
	stranger = uint32(4002)
)

// TestPassedFDMountpoint pins the parse three other things depend on:
// mount-gen must not mkdir such a "directory", must not try to unmount it,
// and must turn the permission check on for it. It mirrors go-fuse's
// parseFuseFd, so a divergence here is a silent loss of the check.
func TestPassedFDMountpoint(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"/dev/fd/3", true},
		{"/dev/fd/17", true},
		{"/dev/fd/0", false},  // stdin is never a mounted fuse device
		{"/dev/fd/-1", false},
		{"/dev/fd/", false},
		{"/dev/fd/3x", false},
		{"/dev/fd/3/sub", false},
		{"/dev/fuse", false},
		{"/mnt/pelfs", false},
		{"", false},
		{"dev/fd/3", false}, // relative: not the magic form
	} {
		if got := rawfuse.PassedFD(tc.in); got != tc.want {
			t.Errorf("PassedFD(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// --- fixture: a published tree with deliberate modes, behind a checked
// binding and an unchecked one over the same generation ---

type permFixture struct {
	checked   fuse.RawFileSystem
	unchecked fuse.RawFileSystem

	ino map[string]uint64
}

// newPermFixture publishes:
//
//	/open.txt    0644   readable by anyone, writable by the owner
//	/secret.txt  0000   readable by nobody without a capability
//	/script      0744   executable by the owner only
//	/priv/       0700   a directory only the owner may search or list
//	/priv/inside 0644
//	/pub/        0755
func newPermFixture(t *testing.T, uuid string) *permFixture {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})

	f := &permFixture{ino: map[string]uint64{}}
	f.ino["open.txt"] = v.WriteFile(rootIno, "open.txt", []byte("public"))
	f.ino["secret.txt"] = v.WriteFile(rootIno, "secret.txt", []byte("private"))
	f.ino["script"] = v.WriteFile(rootIno, "script", []byte("#!/bin/sh\n"))
	f.ino["priv"] = v.Mkdir(rootIno, "priv")
	f.ino["priv/inside"] = v.WriteFile(f.ino["priv"], "inside", []byte("under a 0700 dir"))
	f.ino["pub"] = v.Mkdir(rootIno, "pub")
	// The catalog stores an owner; internal/idmap translates only the
	// VOLUME's identity, so these are stored as the mount's identity
	// outright and the classes below mean what they say.
	for _, ino := range f.ino {
		v.Chown(ino, owner.UID, owner.GID)
	}
	v.Chmod(f.ino["open.txt"], 0644)
	v.Chmod(f.ino["secret.txt"], 0000)
	v.Chmod(f.ino["script"], 0744)
	v.Chmod(f.ino["priv"], 0700)
	v.Chmod(f.ino["pub"], 0755)

	res := v.Publish(publish.Options{TargetPackSize: 1 << 20})
	gfs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = gfs.Close() })
	f.checked = rawfuse.BindCheckedAs(gfs, owner)
	f.unchecked = rawfuse.Bind(gfs)
	// Residency is FORGET-driven, so walk the tree once (as the owner,
	// which every mode here permits) before naming inodes directly.
	for _, name := range []string{"open.txt", "secret.txt", "script", "priv", "pub"} {
		if st := f.checked.Lookup(nil, hdr(rootIno, owner.UID, owner.GID), name, &fuse.EntryOut{}); st != fuse.OK {
			t.Fatalf("warm-up Lookup(%q) = %v", name, st)
		}
	}
	if st := f.checked.Lookup(nil, hdr(f.ino["priv"], owner.UID, owner.GID), "inside", &fuse.EntryOut{}); st != fuse.OK {
		t.Fatalf("warm-up Lookup(priv/inside) = %v", st)
	}
	return f
}

func hdr(ino uint64, uid, gid uint32) *fuse.InHeader {
	return &fuse.InHeader{NodeId: ino, Caller: fuse.Caller{Owner: fuse.Owner{Uid: uid, Gid: gid}}}
}

func open(r fuse.RawFileSystem, ino uint64, uid uint32, flags uint32) fuse.Status {
	in := &fuse.OpenIn{InHeader: *hdr(ino, uid, 5001), Flags: flags}
	return r.Open(nil, in, &fuse.OpenOut{})
}

func access(r fuse.RawFileSystem, ino uint64, uid, mask uint32) fuse.Status {
	return r.Access(nil, &fuse.AccessIn{InHeader: *hdr(ino, uid, 5001), Mask: mask})
}

// A mount that asked for default_permissions must keep answering ENOSYS to
// ACCESS, or the kernel starts sending a request it does not need to and we
// answer a question it has already decided.
func TestUncheckedMountLeavesAccessToTheKernel(t *testing.T) {
	f := newPermFixture(t, "6f000000-0000-4000-8000-000000000001")
	if st := access(f.unchecked, f.ino["secret.txt"], owner.UID, 4); st != fuse.ENOSYS {
		t.Fatalf("Access on an unchecked binding = %v, want ENOSYS", st)
	}
	// And it opens a 0000 file, because refusing it is the kernel's job and
	// doing it here as well is how the tar -p case breaks.
	if st := open(f.unchecked, f.ino["secret.txt"], owner.UID, syscall.O_RDONLY); st != fuse.OK {
		t.Fatalf("Open on an unchecked binding = %v, want OK", st)
	}
}

// The headline: on a mount pelfs is checking, a mode-denying read is
// refused at the OPEN, which is the request the kernel never serves from
// cache and therefore the only place this can be made to hold.
func TestCheckedMountRefusesAModeDenyingOpen(t *testing.T) {
	f := newPermFixture(t, "6f000000-0000-4000-8000-000000000002")
	for _, tc := range []struct {
		name  string
		ino   uint64
		uid   uint32
		flags uint32
		want  fuse.Status
	}{
		{"the owner cannot read a 0000 file", f.ino["secret.txt"], owner.UID, syscall.O_RDONLY, errAccess},
		{"a stranger cannot read a 0000 file", f.ino["secret.txt"], stranger, syscall.O_RDONLY, errAccess},
		{"root reads it (CAP_DAC_OVERRIDE)", f.ino["secret.txt"], 0, syscall.O_RDONLY, fuse.OK},
		{"the owner reads a 0644 file", f.ino["open.txt"], owner.UID, syscall.O_RDONLY, fuse.OK},
		{"a stranger reads a 0644 file", f.ino["open.txt"], stranger, syscall.O_RDONLY, fuse.OK},
		{"a read-only binding refuses a write before the mode is even consulted",
			f.ino["open.txt"], owner.UID, syscall.O_WRONLY, fuse.EROFS},
	} {
		if st := open(f.checked, tc.ino, tc.uid, tc.flags); st != tc.want {
			t.Errorf("%s: Open = %v, want %v", tc.name, st, tc.want)
		}
	}
}

// ACCESS is the reply access(2) and `test -r` turn into their answer, and
// the kernel sends it only when default_permissions is off.
func TestCheckedMountAnswersAccess(t *testing.T) {
	f := newPermFixture(t, "6f000000-0000-4000-8000-000000000003")
	const (
		rOK = 4
		wOK = 2
		xOK = 1
	)
	for _, tc := range []struct {
		name string
		ino  uint64
		uid  uint32
		mask uint32
		want fuse.Status
	}{
		{"F_OK on anything that exists", f.ino["secret.txt"], owner.UID, 0, fuse.OK},
		{"R_OK on a 0000 file", f.ino["secret.txt"], owner.UID, rOK, errAccess},
		{"R_OK on a 0644 file, as the owner", f.ino["open.txt"], owner.UID, rOK, fuse.OK},
		{"W_OK on a 0644 file, as a stranger", f.ino["open.txt"], stranger, wOK, errAccess},
		{"X_OK on a 0744 file, as the owner", f.ino["script"], owner.UID, xOK, fuse.OK},
		{"X_OK on a 0744 file, as a stranger", f.ino["script"], stranger, xOK, errAccess},
		{"R_OK|X_OK on a 0700 directory, as the owner", f.ino["priv"], owner.UID, rOK | xOK, fuse.OK},
		{"R_OK on a 0700 directory, as a stranger", f.ino["priv"], stranger, rOK, errAccess},
	} {
		if st := access(f.checked, tc.ino, tc.uid, tc.mask); st != tc.want {
			t.Errorf("%s: Access = %v, want %v", tc.name, st, tc.want)
		}
	}
}

// Listing a directory is an OPENDIR, and searching one is a LOOKUP on a
// dcache miss. Both are checked; what the second cannot cover is written
// down in perm.go and in docs/design-apptainer.md.
func TestCheckedMountGatesDirectories(t *testing.T) {
	f := newPermFixture(t, "6f000000-0000-4000-8000-000000000004")
	opendirAs := func(ino uint64, uid uint32) fuse.Status {
		return f.checked.OpenDir(nil, &fuse.OpenIn{InHeader: *hdr(ino, uid, 5001)}, &fuse.OpenOut{})
	}
	if st := opendirAs(f.ino["priv"], owner.UID); st != fuse.OK {
		t.Errorf("the owner cannot list its own 0700 directory: %v", st)
	}
	if st := opendirAs(f.ino["priv"], stranger); st != errAccess {
		t.Errorf("a stranger listing a 0700 directory = %v, want EACCES", st)
	}
	lookupAs := func(parent uint64, name string, uid uint32) fuse.Status {
		return f.checked.Lookup(nil, hdr(parent, uid, 5001), name, &fuse.EntryOut{})
	}
	if st := lookupAs(f.ino["priv"], "inside", owner.UID); st != fuse.OK {
		t.Errorf("the owner cannot search its own 0700 directory: %v", st)
	}
	if st := lookupAs(f.ino["priv"], "inside", stranger); st != errAccess {
		t.Errorf("a stranger searching a 0700 directory = %v, want EACCES", st)
	}
	// The unchecked binding leaves all of this to the kernel.
	if st := f.unchecked.OpenDir(nil, &fuse.OpenIn{InHeader: *hdr(f.ino["priv"], stranger, 5001)}, &fuse.OpenOut{}); st != fuse.OK {
		t.Errorf("unchecked OpenDir = %v, want OK", st)
	}
}

// --- the write half, over an overlay ---

// newCheckedRW is the rw fixture's tree behind a CHECKED read-write
// binding, plus the modes the namespace rules need.
func newCheckedRW(t *testing.T, uuid string) (fuse.RawFileSystem, map[string]uint64) {
	t.Helper()
	inner := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	ino := map[string]uint64{}
	ino["ro"] = v.Mkdir(rootIno, "ro")
	ino["ro/file"] = v.WriteFile(ino["ro"], "file", []byte("x"))
	ino["rw"] = v.Mkdir(rootIno, "rw")
	ino["rw/file"] = v.WriteFile(ino["rw"], "file", []byte("y"))
	ino["sticky"] = v.Mkdir(rootIno, "sticky")
	ino["sticky/theirs"] = v.WriteFile(ino["sticky"], "theirs", []byte("z"))
	for _, i := range ino {
		v.Chown(i, owner.UID, owner.GID)
	}
	v.Chmod(ino["ro"], 0555)
	v.Chmod(ino["rw"], 0755)
	v.Chmod(ino["sticky"], 01777)
	v.Chmod(ino["sticky/theirs"], 0644)

	res := v.Publish(publish.Options{TargetPackSize: 1 << 20})
	base, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: res.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = base.Close() })
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      res.Superblock.NextInode,
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = ov.Close() })
	r := rawfuse.BindRWCheckedAs(ov, owner)
	// Residency is FORGET-driven: an inode the kernel never looked up is
	// ESTALE, so walk the tree once as the owner (which the modes permit)
	// before the checks below name inodes directly.
	for _, step := range []struct{ parent, name string }{
		{"", "ro"}, {"", "rw"}, {"", "sticky"},
		{"ro", "file"}, {"rw", "file"}, {"sticky", "theirs"},
	} {
		dir := rootIno
		if step.parent != "" {
			dir = ino[step.parent]
		}
		if st := r.Lookup(nil, hdr(dir, owner.UID, owner.GID), step.name, &fuse.EntryOut{}); st != fuse.OK {
			t.Fatalf("warm-up Lookup(%s/%s) = %v", step.parent, step.name, st)
		}
	}
	return r, ino
}

// The namespace operations: binding or unbinding a name costs write and
// search on the DIRECTORY, and owning the object has never been what
// permits unlinking it.
func TestCheckedMountGatesTheNamespace(t *testing.T) {
	r, ino := newCheckedRW(t, "6f000000-0000-4000-8000-000000000005")

	create := func(dir uint64, name string, uid uint32) fuse.Status {
		in := &fuse.CreateIn{InHeader: *hdr(dir, uid, 5001), Mode: 0644}
		return r.Create(nil, in, name, &fuse.CreateOut{})
	}
	if st := create(ino["rw"], "new", owner.UID); st != fuse.OK {
		t.Errorf("create in a 0755 directory owned by the mount = %v, want OK", st)
	}
	if st := create(ino["ro"], "new", owner.UID); st != errAccess {
		t.Errorf("create in a 0555 directory = %v, want EACCES", st)
	}
	if st := create(ino["ro"], "new", 0); st != fuse.OK {
		t.Errorf("create in a 0555 directory as root = %v, want OK", st)
	}
	if st := r.Mkdir(nil, &fuse.MkdirIn{InHeader: *hdr(ino["ro"], owner.UID, 5001), Mode: 0755}, "d", &fuse.EntryOut{}); st != errAccess {
		t.Errorf("mkdir in a 0555 directory = %v, want EACCES", st)
	}
	if st := r.Symlink(nil, hdr(ino["ro"], owner.UID, 5001), "target", "l", &fuse.EntryOut{}); st != errAccess {
		t.Errorf("symlink in a 0555 directory = %v, want EACCES", st)
	}
	if st := r.Unlink(nil, hdr(ino["ro"], owner.UID, 5001), "file"); st != errAccess {
		t.Errorf("unlink from a 0555 directory = %v, want EACCES", st)
	}
	if st := r.Unlink(nil, hdr(ino["rw"], owner.UID, 5001), "file"); st != fuse.OK {
		t.Errorf("unlink from a 0755 directory of ours = %v, want OK", st)
	}
	if st := r.Rmdir(nil, hdr(rootIno, stranger, 5001), "ro"); st != errAccess {
		t.Errorf("a stranger rmdir'ing in the volume root = %v, want EACCES", st)
	}
}

// The sticky bit: in a +t directory a stranger may create, and may not
// unlink somebody else's name. It is EPERM, not EACCES, exactly as the
// kernel reports it.
func TestCheckedMountAppliesTheStickyBit(t *testing.T) {
	r, ino := newCheckedRW(t, "6f000000-0000-4000-8000-000000000006")
	in := &fuse.CreateIn{InHeader: *hdr(ino["sticky"], stranger, 5001), Mode: 0644}
	if st := r.Create(nil, in, "mine", &fuse.CreateOut{}); st != fuse.OK {
		t.Fatalf("create in a 01777 directory as a stranger = %v, want OK", st)
	}
	if st := r.Unlink(nil, hdr(ino["sticky"], stranger, 5001), "theirs"); st != errPerm {
		t.Errorf("a stranger unlinking someone else's name from a sticky directory = %v, want EPERM", st)
	}
	// The directory's owner may, and so may the file's.
	if st := r.Unlink(nil, hdr(ino["sticky"], owner.UID, 5001), "theirs"); st != fuse.OK {
		t.Errorf("the sticky directory's owner unlinking a name in it = %v, want OK", st)
	}
}

// SETATTR splits by what each bit costs: mode and an explicit time are the
// owner's privilege (EPERM), a size change is a write (EACCES) — unless it
// arrives through a file handle, whose open was already authorized, which
// is what makes ftruncate on a file the caller created work.
func TestCheckedMountGatesSetAttr(t *testing.T) {
	r, ino := newCheckedRW(t, "6f000000-0000-4000-8000-000000000007")
	setattr := func(uid uint32, valid uint32, apply func(*fuse.SetAttrIn)) fuse.Status {
		in := &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{
			InHeader: *hdr(ino["rw/file"], uid, 5001), Valid: valid,
		}}
		if apply != nil {
			apply(in)
		}
		return r.SetAttr(nil, in, &fuse.AttrOut{})
	}
	if st := setattr(stranger, fuse.FATTR_MODE, func(in *fuse.SetAttrIn) { in.Mode = 0600 }); st != errPerm {
		t.Errorf("chmod by a non-owner = %v, want EPERM", st)
	}
	if st := setattr(owner.UID, fuse.FATTR_MODE, func(in *fuse.SetAttrIn) { in.Mode = 0600 }); st != fuse.OK {
		t.Errorf("chmod by the owner = %v, want OK", st)
	}
	if st := setattr(stranger, fuse.FATTR_MTIME, func(in *fuse.SetAttrIn) { in.Mtime = 1 }); st != errPerm {
		t.Errorf("utimes with an explicit time by a non-owner = %v, want EPERM", st)
	}
	// 0600 now, so a stranger has no write bit: a bare truncate is refused
	// and the same truncate through a file handle is not.
	if st := setattr(stranger, fuse.FATTR_SIZE, nil); st != errAccess {
		t.Errorf("truncate by a non-owner = %v, want EACCES", st)
	}
	if st := setattr(stranger, fuse.FATTR_SIZE|fuse.FATTR_FH, nil); st != fuse.OK {
		t.Errorf("truncate through an authorized handle = %v, want OK", st)
	}
	if st := setattr(stranger, fuse.FATTR_UID, func(in *fuse.SetAttrIn) { in.Uid = stranger }); st != errPerm {
		t.Errorf("chown to oneself by a non-owner = %v, want EPERM", st)
	}
}
