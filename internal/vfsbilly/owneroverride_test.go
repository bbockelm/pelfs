package vfsbilly_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/go-git/go-billy/v5"

	"github.com/bbockelm/pelfs/internal/vfsbilly"
)

// THE OWNER OVERRIDE IS THE NFS BINDING'S, AND ONLY ITS.
//
// mayOpen grants knfsd's NFSD_MAY_OWNER_OVERRIDE, and the justification is
// a property of NFSv3 alone: the client answered open(2) from our ACCESS
// reply, so a WRITE that arrives afterwards belongs to an open that was
// already decided correctly. WebDAV and SFTP have a REAL open. For them the
// check in mayOpen is the only open check there is, and an override there
// truncates a 0444 file that the kernel, FUSE's `default_permissions` and
// our own ACCESS reply all refuse -- the "two frontends disagree about the
// same file" defect internal/fsperm exists to prevent, arriving from
// inside.
//
// So the two bindings are asked the same question about the same file, and
// they must answer differently. The NFS one still extracts `tar -p`
// (TestTarDashPExtractsAReadOnlyFile, and scripts/mount-gate-test.sh over a
// real kernel mount); the other one refuses.
func TestOwnerOverrideReachesOnlyTheBindingThatAskedForIt(t *testing.T) {
	p := newPerms(t)
	original := []byte("the body a PUT must not be allowed to truncate")
	ro := p.rootFile(0o444, p.me, p.grp, original)

	// The NFS binding: today's behaviour, unchanged. This is the write
	// `tar -p` makes through a descriptor whose open predates the chmod.
	tarBody := []byte("TAR'S BODY, over the head of")
	allowed(t, "NFS data-path write to the owner's own 0444 file",
		writeTo(p.mount(0), ro, tarBody))
	// A write is not a truncate: what is on disk now is tar's bytes followed
	// by the tail of the original, and it is what the refused PUT below must
	// leave exactly as it is.
	want := append(append([]byte{}, tarBody...), original[len(tarBody):]...)

	// The WebDAV/SFTP binding: refused, in every spelling a frontend with a
	// real open uses. O_RDWR|O_CREATE|O_TRUNC is x/net/webdav's PUT
	// (webdav.go handlePut), which is the one that would have destroyed the
	// file before it ever reached the mode check on the write.
	dav := p.mountFor(vfsbilly.OpenAnsweredHere)
	refused(t, "PUT (O_RDWR|O_CREATE|O_TRUNC) on the owner's own 0444 file",
		errOf(dav.OpenFile(ro, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)), syscall.EACCES)
	refused(t, "O_WRONLY open of the owner's own 0444 file",
		errOf(dav.OpenFile(ro, os.O_WRONLY, 0)), syscall.EACCES)
	refused(t, "O_RDWR open of the owner's own 0444 file",
		errOf(dav.OpenFile(ro, os.O_RDWR, 0)), syscall.EACCES)
	refused(t, "O_TRUNC alone on the owner's own 0444 file",
		errOf(dav.OpenFile(ro, os.O_TRUNC, 0)), syscall.EACCES)

	// Reading it is still allowed: 0444 grants read to everybody, and the
	// refusal above is about the mode, not about the binding.
	body, err := readFrom(dav, ro)
	allowed(t, "read the same file through the same binding", err)
	if !bytes.Equal(body, want) {
		t.Fatalf("the refused PUT changed the file: %q", body)
	}

	// And the two bindings agree everywhere the override does not reach: a
	// file the mount does NOT own is refused by both, identically.
	theirs := p.rootFile(0o444, p.they, p.thgr, original)
	refused(t, "NFS: somebody else's 0444 file", writeTo(p.mount(0), theirs, []byte("x")),
		syscall.EACCES)
	refused(t, "DAV: somebody else's 0444 file", writeTo(dav, theirs, []byte("x")),
		syscall.EACCES)
}

// The zero value of OpenSemantics is the safe one. A future constructor
// that forgets to name the semantics, or a caller that builds the value
// from a config field nobody set, gets NO override rather than the NFS
// one -- which is the whole point of making it opt-in.
func TestZeroOpenSemanticsGrantsNoOverride(t *testing.T) {
	p := newPerms(t)
	var unset vfsbilly.OpenSemantics
	if unset != vfsbilly.OpenAnsweredHere {
		t.Fatalf("the zero OpenSemantics is %v, want OpenAnsweredHere -- a "+
			"frontend that names nothing must not inherit the NFS override", unset)
	}
	ro := p.rootFile(0o444, p.me, p.grp, []byte("body"))
	refused(t, "write through a binding whose semantics were never set",
		writeTo(p.mountFor(unset), ro, []byte("x")), syscall.EACCES)
}

// The NFS-only constructors, and who may call them.
//
// New, NewAs, NewReadOnly and NewReadOnlyAs bind OpenAnsweredByClient --
// the owner override -- because they exist for the NFS frontend and were
// written before there was a second frontend to confuse. The type system
// cannot stop a new frontend from calling the obvious constructor, so this
// does: a caller outside the list below fails here, with the reason.
//
// If you are reading this because it failed: you probably want
// vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere). Read OpenSemantics
// in perm.go first -- it is one paragraph and it says why the difference
// matters. Adding your file to the allowlist is the wrong fix unless your
// frontend genuinely has no open of its own.
func TestOnlyTheNFSFrontendCallsTheOverrideConstructors(t *testing.T) {
	// Paths are repo-relative, slash-separated.
	allowed := map[string]string{
		"cmd/pelfs/mountgen.go": "the NFS mount session (nfsmount.Serve)",
	}
	call := regexp.MustCompile(`vfsbilly\.(New|NewAs|NewReadOnly|NewReadOnlyAs)\(`)

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locate the repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skipf("no go.mod at %s: not a source checkout", root)
	}

	var offenders []string
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		// This package's own definitions and its wrappers are the point.
		if strings.HasPrefix(rel, "internal/vfsbilly/") {
			return nil
		}
		if _, ok := allowed[rel]; ok {
			return nil
		}
		src, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if m := call.FindStringSubmatch(string(src)); m != nil {
			offenders = append(offenders, rel+" calls vfsbilly."+m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(offenders) > 0 {
		t.Fatalf("these callers take the NFS owner override (mayOpen, "+
			"OpenAnsweredByClient) and are not the NFS frontend:\n  %s\n\n"+
			"A frontend with a real open -- WebDAV, SFTP, an HTTP handler -- "+
			"must call vfsbilly.NewFor(ov, cred, vfsbilly.OpenAnsweredHere) "+
			"instead, or it will truncate a 0444 file that every other "+
			"frontend refuses. See OpenSemantics in internal/vfsbilly/perm.go.",
			strings.Join(offenders, "\n  "))
	}
}

// mountFor is perms.mount with the open semantics named -- the constructor
// a frontend other than NFS has to use.
func (p *perms) mountFor(sem vfsbilly.OpenSemantics) billy.Filesystem {
	return vfsbilly.NewFor(p.ov, vfsbilly.Cred{
		UID: p.me, GID: p.grp, Groups: []uint32{p.both},
	}, sem)
}

// errOf drops a value and keeps the error, so an OpenFile that must be
// refused reads as one line.
func errOf(f billy.File, err error) error {
	if err == nil && f != nil {
		f.Close() //nolint:errcheck
	}
	return err
}
