package vfsbilly_test

import (
	"os"
	"testing"
)

// Remove names an ENTRY, never what a symlink at that entry points at.
//
// This is the other half of the audit that produced
// TestAttributesOfASymlinkStayOnTheSymlink: billy names its methods after
// the os functions, and those FOLLOW. Chmod/Chown/Chtimes were fixed then;
// Remove was not looked at, and the same reasoning applies to it verbatim
// -- an NFS REMOVE names its object by (directory handle, name), and a
// handle for a symlink names the symlink.
//
// Following would lose both ways, and the dangling case is the one that
// reached a user: `rm -rf` deletes a directory in sorted order, so a link
// whose target sorts before it is DANGLING by the time its own turn comes.
// A Remove that resolves through it answers ENOENT, rm reads that as
// "already gone", and the link survives -- the same links, every pass,
// with the rmdir behind them refusing forever.
func TestRemoveOfADanglingSymlinkRemovesTheLink(t *testing.T) {
	bfs, _ := newRW(t, "5e11c000-1111-2222-3333-444455556661")

	if err := bfs.Symlink("gone.txt", "/dangling"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := bfs.Remove("/dangling"); err != nil {
		t.Fatalf("remove of a dangling symlink: %v", err)
	}
	if _, err := bfs.Lstat("/dangling"); !os.IsNotExist(err) {
		t.Fatalf("the dangling symlink survived Remove (lstat: %v)", err)
	}
}

func TestRemoveOfASymlinkKeepsItsTarget(t *testing.T) {
	bfs, _ := newRW(t, "5e11c000-1111-2222-3333-444455556662")

	if err := bfs.Symlink("base.txt", "/alias"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := bfs.Remove("/alias"); err != nil {
		t.Fatalf("remove of a live symlink: %v", err)
	}
	if _, err := bfs.Lstat("/alias"); !os.IsNotExist(err) {
		t.Fatalf("the symlink survived Remove (lstat: %v)", err)
	}
	// The data-loss dual, and the one worth failing loudly: a Remove that
	// followed would have deleted this instead and reported success.
	if _, err := bfs.Stat("/base.txt"); err != nil {
		t.Fatalf("remove of a symlink deleted its TARGET: %v", err)
	}
}

func TestRemoveOfASymlinkToADirectoryKeepsTheDirectory(t *testing.T) {
	bfs, _ := newRW(t, "5e11c000-1111-2222-3333-444455556663")

	if err := bfs.Symlink("dir", "/dirlink"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Remove, not a directory removal: the entry is a symlink whatever it
	// names. Resolving it would make this an rmdir of a non-empty
	// directory, which is ENOTEMPTY -- on an entry that is not a directory
	// at all.
	if err := bfs.Remove("/dirlink"); err != nil {
		t.Fatalf("remove of a symlink to a directory: %v", err)
	}
	if _, err := bfs.Lstat("/dirlink"); !os.IsNotExist(err) {
		t.Fatalf("the symlink survived Remove (lstat: %v)", err)
	}
	if _, err := bfs.Stat("/dir/child.txt"); err != nil {
		t.Fatalf("remove of a symlink deleted the DIRECTORY it named: %v", err)
	}
}

// The shape the owner hit, at the layer that answers it: a directory whose
// entries are links to a target that sorts FIRST, deleted in sorted order.
// Every link dangles by the time it is reached, and one pass must empty
// the directory.
func TestRemoveEmptiesADirectoryOfLinksToADeletedTarget(t *testing.T) {
	bfs, _ := newRW(t, "5e11c000-1111-2222-3333-444455556664")

	if err := bfs.MkdirAll("/tests", 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := bfs.Create("/tests/aaa-base.run")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("the target every link names")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	const links = 23
	for i := 0; i < links; i++ {
		name := "/tests/" + linkName(i)
		if err := bfs.Symlink("aaa-base.run", name); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}

	// Sorted order, exactly as a directory walk hands them out.
	entries, err := bfs.ReadDir("/tests")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != links+1 {
		t.Fatalf("readdir returned %d entries, want %d", len(entries), links+1)
	}
	for _, e := range entries {
		if err := bfs.Remove("/tests/" + e.Name()); err != nil {
			t.Fatalf("remove %s: %v", e.Name(), err)
		}
	}

	left, err := bfs.ReadDir("/tests")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("one pass left %d entries behind: %v", len(left), names(left))
	}
	if err := bfs.Remove("/tests"); err != nil {
		t.Fatalf("the emptied directory would not go: %v", err)
	}
}

func linkName(i int) string {
	return string(rune('b'+i%20)) + string(rune('a'+i/20)) + "-link.run"
}
