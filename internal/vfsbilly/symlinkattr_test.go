package vfsbilly_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
)

// Extracting a tarball creates symlinks whose targets appear LATER in the
// archive -- Documentation/Changes -> process/changes.rst is exactly that
// -- so for a moment every one of them dangles. The client then sets the
// link's mode and times, by file handle, and a handle for a symlink names
// the symlink.
//
// Following it instead loses both ways, which is what this pins:
// a dangling target makes the operation fail (and go-nfs turns that
// failure into EIO, so a tar reports "Can't create" on a file it created
// perfectly well), and a resolvable target makes it SUCCEED against the
// wrong object.
func TestAttributesOfASymlinkStayOnTheSymlink(t *testing.T) {
	bfs, _ := newRW(t, "cb1b0000-1111-2222-3333-444455556666")
	ch := bfs.(billy.Change)

	if err := bfs.Symlink("does/not/exist/yet.rst", "/Changes"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	when := time.Unix(1700000000, 0)
	if err := ch.Chtimes("/Changes", when, when); err != nil {
		t.Fatalf("chtimes on a dangling symlink: %v", err)
	}
	if err := ch.Chmod("/Changes", 0o777); err != nil {
		t.Fatalf("chmod on a dangling symlink: %v", err)
	}
	li, err := bfs.Lstat("/Changes")
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !li.ModTime().Equal(when) {
		t.Errorf("mtime of the link = %v, want %v", li.ModTime(), when)
	}

	// And the resolvable case: the target must not have moved.
	before, err := bfs.Stat("/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := bfs.Symlink("base.txt", "/alias"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	other := time.Unix(1600000000, 0)
	if err := ch.Chtimes("/alias", other, other); err != nil {
		t.Fatalf("chtimes on a symlink: %v", err)
	}
	if err := ch.Chmod("/alias", 0o700); err != nil {
		t.Fatalf("chmod on a symlink: %v", err)
	}
	after, err := bfs.Stat("/base.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		t.Errorf("setting attributes on the link changed its TARGET: %v/%v -> %v/%v",
			before.Mode(), before.ModTime(), after.Mode(), after.ModTime())
	}
	if li, err = bfs.Lstat("/alias"); err != nil {
		t.Fatal(err)
	}
	if !li.ModTime().Equal(other) {
		t.Errorf("mtime of the link = %v, want %v", li.ModTime(), other)
	}
}

// The same case driven through the function that actually fails on a
// mount. go-nfs runs SetFileAttributes.Apply for every SETATTR, CREATE,
// MKDIR and SYMLINK; onSetAttr then returns whatever Apply returns as if
// it were already an NFS status, so an error of any other type leaves the
// server answering with an RPC-level system error instead of a status --
// which is a malformed reply, and reaches the client as EIO with nothing
// to explain it.
func TestApplyOnADanglingSymlinkSucceeds(t *testing.T) {
	bfs, _ := newRW(t, "cb1b0000-1111-2222-3333-444455556667")
	if err := bfs.Symlink("/nowhere/at/all", "/Changes"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	mode := uint32(0o777)
	when := time.Unix(1700000000, 0)
	attrs := &nfs.SetFileAttributes{SetMode: &mode, SetMtime: &when, SetAtime: &when}
	if err := attrs.Apply(bfs.(billy.Change), bfs, "/Changes"); err != nil {
		var st *nfs.NFSStatusError
		if errors.As(err, &st) {
			t.Fatalf("Apply on a dangling symlink: NFS status %v (%v)", st.NFSStatus, err)
		}
		t.Fatalf("Apply on a dangling symlink returned a non-status error, "+
			"which onSetAttr turns into an RPC system error: %#v", err)
	}
	li, err := bfs.Lstat("/Changes")
	if err != nil {
		t.Fatal(err)
	}
	if !li.ModTime().Equal(when) {
		t.Errorf("mtime of the link = %v, want %v", li.ModTime(), when)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link stopped being a link: %v", li.Mode())
	}
}
