//go:build !windows

package rawfuse_test

import (
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// `Fsync` and `FsyncDir` used to `return fuse.OK` with no body at all. An
// application that called fsync(2) and CHECKED THE RESULT — which is the
// only reason to call it — was told its data was safe when nothing
// whatsoever had been made durable. These hold the answer to being an
// answer.
//
// They run against the staging content store, which is what this fixture
// binds, and that is deliberate: `--no-memtable` is the path where a
// durability claim is easiest to make and forget, since a staged write is
// an ordinary `pwrite` into an ordinary file and looks safe already. It is
// not — a `pwrite` that nothing fsync'd is page cache — and `stagingContent`
// tracks what it owes so a sync costs writes-since-the-last-fsync rather
// than one call per dirty file.
//
// What fsync MEANS here is in internal/overlay's sync.go and in the comment
// on Fsync itself, including the part a user has to read twice: it is
// durability of THIS state directory, which on ephemeral job scratch is not
// federation durability at all.

func fsyncFile(t *testing.T, r fuse.RawFileSystem, ino uint64) fuse.Status {
	t.Helper()
	return r.Fsync(nil, &fuse.FsyncIn{InHeader: *header(ino)})
}

func fsyncDir(t *testing.T, r fuse.RawFileSystem, ino uint64) fuse.Status {
	t.Helper()
	return r.FsyncDir(nil, &fuse.FsyncIn{InHeader: *header(ino)})
}

func TestFsyncMakesSomethingDurableAndSaysSo(t *testing.T) {
	f := newRWFixture(t, "e5c0e5c0-0001-4000-8000-000000000001")
	out := mustCreate(t, f.raw, rootIno, "fsynced.txt", 0644)
	mustWrite(t, f.raw, out.NodeId, 0, []byte("bytes an application wants to keep"))

	if st := fsyncFile(t, f.raw, out.NodeId); st != fuse.OK {
		t.Fatalf("Fsync = %v, wanted OK", st)
	}
	if got := f.ov.SyncStats(); got.Passes != 1 || got.Fsyncs == 0 {
		t.Fatalf("Fsync returned OK without making anything durable: %+v", got)
	}
}

// The cost promise: a chatty application that fsyncs after every write
// must not pay for the ones with nothing behind them.
func TestARepeatedFsyncCostsNothing(t *testing.T) {
	f := newRWFixture(t, "e5c0e5c0-0002-4000-8000-000000000002")
	out := mustCreate(t, f.raw, rootIno, "chatty.txt", 0644)
	mustWrite(t, f.raw, out.NodeId, 0, []byte("one write, many fsyncs"))
	if st := fsyncFile(t, f.raw, out.NodeId); st != fuse.OK {
		t.Fatalf("Fsync = %v", st)
	}
	base := f.ov.SyncStats()

	const storm = 100
	for range storm {
		if st := fsyncFile(t, f.raw, out.NodeId); st != fuse.OK {
			t.Fatalf("Fsync = %v", st)
		}
	}
	got := f.ov.SyncStats()
	if got.Fsyncs != base.Fsyncs {
		t.Errorf("%d repeat fsyncs cost %d file syncs; nothing changed between them",
			storm, got.Fsyncs-base.Fsyncs)
	}
	if got.Coalesced != base.Coalesced+storm {
		t.Errorf("%d of %d repeat fsyncs were coalesced away", got.Coalesced-base.Coalesced, storm)
	}
}

// FsyncDir is namespace durability, and it carries the content with it
// because the two databases in a state directory may not be made durable
// in the other order (see FsyncDir's own comment). So it is a full pass,
// and asserting that is asserting the decision.
func TestFsyncDirMakesTheNamespaceDurableAndCarriesTheContent(t *testing.T) {
	f := newRWFixture(t, "e5c0e5c0-0003-4000-8000-000000000003")
	dir := mustMkdir(t, f.raw, rootIno, "newdir")
	out := mustCreate(t, f.raw, dir.NodeId, "inside.txt", 0644)
	mustWrite(t, f.raw, out.NodeId, 0, []byte("a name and a body, one directory"))

	if st := fsyncDir(t, f.raw, dir.NodeId); st != fuse.OK {
		t.Fatalf("FsyncDir = %v, wanted OK", st)
	}
	got := f.ov.SyncStats()
	if got.Passes != 1 || got.Fsyncs == 0 {
		t.Fatalf("FsyncDir returned OK without making anything durable: %+v", got)
	}
	// And it coalesces with a file fsync, which is the observable half of
	// "they are the same call": there is one durability unit here, not one
	// per inode.
	if st := fsyncFile(t, f.raw, out.NodeId); st != fuse.OK {
		t.Fatalf("Fsync = %v", st)
	}
	if after := f.ov.SyncStats(); after.Passes != got.Passes {
		t.Errorf("a file fsync after a directory fsync made another pass; "+
			"the directory fsync did not cover the content after all")
	}
}

// A read-only binding has nothing of its own to make durable — every byte
// it serves is already a signed object on the federation — and must not
// fail an fsync for it.
func TestFsyncOnAReadOnlyBindingSucceeds(t *testing.T) {
	ro := newFixture(t, "e5c0e5c0-0004-4000-8000-000000000004").raw
	if st := fsyncFile(t, ro, rootIno); st != fuse.OK {
		t.Errorf("Fsync on a read-only binding = %v, wanted OK", st)
	}
	if st := fsyncDir(t, ro, rootIno); st != fuse.OK {
		t.Errorf("FsyncDir on a read-only binding = %v, wanted OK", st)
	}
}
