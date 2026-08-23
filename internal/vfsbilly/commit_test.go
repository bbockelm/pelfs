package vfsbilly_test

import (
	"testing"

	"github.com/go-git/go-billy/v5"
	nfs "github.com/willscott/go-nfs"
)

// NFSv3 COMMIT is what an application's fsync(2) becomes on an NFS mount,
// and until the go-nfs fork grew nfs.Committer it never reached this
// filesystem at all: the handler answered NFSStatusOk and a write verifier
// without consulting anything (KI-10). These are the ordinary-lane half of
// that fix. The other half is on the wire and cannot be reached from here
// — see the commit gate in scripts/mount-gate-test.sh, which asserts
// against a real kernel client that a COMMIT is SENT, which is a claim
// about the WRITE reply's stability field rather than about this method.

// committer is the frontend as go-nfs sees it: the interface, not the
// concrete type. Asserting through billy.Filesystem is the same shape
// perm_test.go uses, and for the same reason — a signature that drifted
// would not fail to build, it would silently stop being found.
func committer(t *testing.T, fs billy.Filesystem) nfs.Committer {
	t.Helper()
	c, ok := fs.(nfs.Committer)
	if !ok {
		t.Fatal("the frontend no longer implements nfs.Committer, so go-nfs will go back to " +
			"answering COMMIT without asking, and every WRITE reply will claim FILE_SYNC")
	}
	return c
}

func writeThrough(t *testing.T, fs billy.Filesystem, name, body string) {
	t.Helper()
	f, err := fs.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

// A COMMIT has to reach overlay.Sync, and the evidence is the same
// three-counter one the FUSE side uses: a pass happened, and it cost real
// file syncs. Passes alone would be satisfied by a Sync that did nothing.
func TestACommitMakesTheSessionDurable(t *testing.T) {
	fx := newFixture(t, "9f0c1b2a-3d4e-5f60-8172-a3b4c5d6e7f8")
	ov := openOverlay(t, fx)
	fs := newBilly(ov)

	writeThrough(t, fs, "/committed.txt", "the bytes a COMMIT is answering for")

	before := ov.SyncStats()
	if err := committer(t, fs).Commit("/committed.txt"); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got := ov.SyncStats()
	if got.Passes != before.Passes+1 {
		t.Errorf("COMMIT made %d durability passes, want 1: %+v", got.Passes-before.Passes, got)
	}
	if got.Fsyncs <= before.Fsyncs {
		t.Errorf("COMMIT returned OK without fsyncing anything: %+v", got)
	}
}

// The cost promise. An NFSv3 client commits on close(2) as well as on
// fsync(2), so this is called about once per file written and a repeat
// with nothing between must be free — not cheaper, FREE: no pass at all.
func TestACommitWithNothingNewCostsNothing(t *testing.T) {
	fx := newFixture(t, "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9")
	ov := openOverlay(t, fx)
	fs := newBilly(ov)
	c := committer(t, fs)

	writeThrough(t, fs, "/repeat.txt", "written once")
	if err := c.Commit("/repeat.txt"); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	const storm = 200
	base := ov.SyncStats()
	for i := 0; i < storm; i++ {
		if err := c.Commit("/repeat.txt"); err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
	}
	got := ov.SyncStats()
	if got.Fsyncs != base.Fsyncs {
		t.Errorf("%d commits with nothing between them cost %d file syncs, want 0",
			storm, got.Fsyncs-base.Fsyncs)
	}
	if got.Passes != base.Passes {
		t.Errorf("%d commits with nothing between them made %d durability passes, want 0",
			storm, got.Passes-base.Passes)
	}
	if got.Coalesced != base.Coalesced+storm {
		t.Errorf("only %d of %d repeat commits were coalesced away", got.Coalesced-base.Coalesced, storm)
	}

	// And one more write reopens it: the coalescing is about there being
	// nothing new, not about the commit having been asked once.
	writeThrough(t, fs, "/repeat.txt", "written twice")
	if err := c.Commit("/repeat.txt"); err != nil {
		t.Fatalf("Commit after a change: %v", err)
	}
	if after := ov.SyncStats(); after.Passes != got.Passes+1 {
		t.Errorf("a commit after a change was coalesced away: %+v", after)
	}
}

// A client commits on close(2) even for a file it only read, so a
// read-only binding is asked and must answer OK. It has nothing of its own
// to sync — matching rawfuse's Fsync on the same binding.
func TestACommitOnAReadOnlyBindingSucceeds(t *testing.T) {
	fx := newFixture(t, "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901")
	fs := newBillyReadOnly(fx.base)
	if err := committer(t, fs).Commit("/base.txt"); err != nil {
		t.Fatalf("Commit on a read-only binding: %v", err)
	}
}

// The path is ignored, which is the interface's own allowance (RFC 1813
// 3.3.21) and this filesystem's only option: the durability unit is the
// session. Pinned so that a future per-path implementation is a deliberate
// change rather than an accident, and so that a commit naming a file that
// does not exist — a handle for something since removed — is not an error.
func TestACommitDoesNotDependOnThePathItNames(t *testing.T) {
	fx := newFixture(t, "3c4d5e6f-7081-4293-a4b5-c6d7e8f90123")
	ov := openOverlay(t, fx)
	fs := newBilly(ov)

	writeThrough(t, fs, "/named.txt", "durable")
	before := ov.SyncStats()
	if err := committer(t, fs).Commit("/gone.txt"); err != nil {
		t.Fatalf("Commit naming a path that does not exist: %v", err)
	}
	if got := ov.SyncStats(); got.Passes != before.Passes+1 {
		t.Errorf("the commit did no work: %+v", got)
	}
}
