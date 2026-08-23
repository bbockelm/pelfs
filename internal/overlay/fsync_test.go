package overlay_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// What fsync is allowed to claim, and how each half of the claim is
// checked.
//
// `FS.Sync` says two things. The first is MECHANICAL — the ring's mapping
// was msync'd and the two databases were fsync'd — and it is checked by
// counting: `SyncStats` for the file syncs, `memtable.Stats().RingSyncs`
// for the mapping. Counters rather than an assertion about the platter,
// because whether a page reached the platter is not observable from a Go
// test on any operating system this runs on; what IS observable is whether
// the call was made at all, and a Sync that makes no calls is the bug
// being fixed.
//
// The second is ORDERING, and that is what the recovery test below is for:
// at the moment fsync returns, the state directory's own records already
// describe every byte the application wrote, so nothing that runs
// afterwards is load-bearing. It is checked by never letting anything run
// afterwards — the live session is ABANDONED, never closed, and the
// recovery runs against a copy of the state directory taken the instant
// fsync came back. A graceful close would have been the wrong simulation
// in the most misleading way available: SQLite checkpoints its
// write-ahead log when the last connection closes, so a session that shut
// down cleanly would recover perfectly whether fsync had done anything or
// not.

// syncFixture is an overlay over a real content journal — which is the
// point, since the journal is half of what fsync makes durable and the
// tests that build a memtable.Store by hand have none.
type syncFixture struct {
	fx      *fixture
	memDir  string
	ovDir   string
	memOpts memtable.Options
	store   *memtable.Store
	ov      *overlay.FS
}

func newSyncFixture(t testing.TB, uuid string) *syncFixture {
	t.Helper()
	fx := newFixture(t, uuid)
	s := &syncFixture{fx: fx, memDir: t.TempDir(), ovDir: t.TempDir()}
	s.memOpts = memtable.Options{
		TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	}
	store, _, closeBoth, err := overlay.OpenContentStore(s.memDir, s.memOpts)
	if err != nil {
		t.Fatal(err)
	}
	s.store = store
	opts := fx.options()
	opts.Memtable = store
	ov, err := overlay.Open(s.ovDir, fx.base, opts)
	if err != nil {
		closeBoth() //nolint:errcheck
		t.Fatal(err)
	}
	s.ov = ov
	t.Cleanup(func() {
		if s.ov != nil {
			s.ov.Close() //nolint:errcheck
		}
		if s.store != nil {
			closeBoth() //nolint:errcheck
		}
	})
	return s
}

// abandon is the process dying: the handles are dropped without a close,
// so nothing graceful can run, and the state directories are copied as
// they stand. The copy is what a remount finds.
func (s *syncFixture) abandon(t *testing.T) (memDir, ovDir string) {
	t.Helper()
	memDir, ovDir = t.TempDir(), t.TempDir()
	copyTree(t, s.memDir, memDir)
	copyTree(t, s.ovDir, ovDir)
	return memDir, ovDir
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		src, dst := filepath.Join(from, e.Name()), filepath.Join(to, e.Name())
		if e.IsDir() {
			if err := os.MkdirAll(dst, 0700); err != nil {
				t.Fatal(err)
			}
			copyTree(t, src, dst)
			continue
		}
		in, err := os.Open(src)
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			in.Close() //nolint:errcheck
			t.Fatal(err)
		}
		_, cerr := io.Copy(out, in)
		in.Close()  //nolint:errcheck
		out.Close() //nolint:errcheck
		if cerr != nil {
			t.Fatal(cerr)
		}
	}
}

// An fsync makes the calls it says it makes: one pass, the ring msync'd,
// and both databases and both of their write-ahead logs fsync'd.
func TestAnFsyncMakesTheSessionDurable(t *testing.T) {
	ctx := context.Background()
	s := newSyncFixture(t, "d5f0d5f0-0001-4000-8000-000000000001")

	n, err := s.ov.Create(ctx, rootIno, "synced.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	body := pseudorandom(9000, 21)
	if _, err := s.ov.Write(ctx, n.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	before := s.store.Stats().RingSyncs
	if err := s.ov.Sync(); err != nil {
		t.Fatal(err)
	}
	st := s.ov.SyncStats()
	if st.Passes != 1 {
		t.Errorf("fsync made %d durability passes, wanted 1", st.Passes)
	}
	if st.Coalesced != 0 {
		t.Errorf("fsync coalesced %d calls away with a write outstanding", st.Coalesced)
	}
	// The metadata database and its write-ahead log.
	if st.Fsyncs != 2 {
		t.Errorf("fsync performed %d file syncs on the metadata, wanted 2 (the database and its log)", st.Fsyncs)
	}
	// And the two halves of the content, each counted where it is owned.
	cs := s.store.Stats()
	if cs.RingSyncs != before+1 {
		t.Errorf("the ring's mapping was msync'd %d times, wanted 1; "+
			"the bytes of an unflushed write live there and nowhere else", cs.RingSyncs-before)
	}
	if cs.JournalSyncs != 1 {
		t.Errorf("the content journal was synced %d times, wanted 1; without it the ring holds "+
			"bytes nothing durable says belong to a file", cs.JournalSyncs)
	}
}

// The claim itself: a process killed the instant after fsync returns comes
// back with everything fsync covered, out of the ring, with no flush and
// no upload in between.
func TestACrashAfterAnFsyncRecoversEverythingItCovered(t *testing.T) {
	ctx := context.Background()
	s := newSyncFixture(t, "d5f0d5f0-0002-4000-8000-000000000002")

	n, err := s.ov.Create(ctx, rootIno, "survives.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Three writes, and NO flush: every byte is in the ring, which is the
	// state fsync has to cover and the one a crash used to lose whole.
	var body []byte
	for i := 0; i < 3; i++ {
		part := pseudorandom(3000, int64(31+i))
		if _, err := s.ov.Write(ctx, n.Inode, int64(i*3000), part); err != nil {
			t.Fatal(err)
		}
		body = append(body, part...)
	}
	if err := s.ov.Sync(); err != nil {
		t.Fatal(err)
	}
	// The mechanical half, asserted here too: without it this test would
	// pass against a Sync that did nothing at all, because SQLite has
	// already COMMITTED everything and a copy of a committed database
	// reads back fine.
	if st := s.ov.SyncStats(); st.Passes != 1 || st.Fsyncs != 2 {
		t.Fatalf("fsync did not do its work: %+v", st)
	}
	if cs := s.store.Stats(); cs.RingSyncs == 0 || cs.JournalSyncs == 0 {
		t.Fatalf("fsync left the content behind: %d ring syncs, %d journal syncs",
			cs.RingSyncs, cs.JournalSyncs)
	}

	memDir, ovDir := s.abandon(t)
	memOpts := s.memOpts
	recovered, rep, closeBoth, err := overlay.OpenContentStore(memDir, memOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBoth() //nolint:errcheck
	if rep.Loss() {
		t.Fatalf("a crash right after an fsync lost %d bytes:\n%s", rep.LostBytes, rep)
	}
	if len(rep.Truncations) != 0 {
		t.Fatalf("a crash right after an fsync cut a file back: %+v", rep.Truncations)
	}
	opts := s.fx.options()
	opts.Memtable = recovered
	ov2, err := overlay.Open(ovDir, s.fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer ov2.Close() //nolint:errcheck

	got, err := ov2.GetAttr(ctx, n.Inode)
	if err != nil {
		t.Fatalf("the fsync'd file is not there after the crash: %v", err)
	}
	if got.Length != int64(len(body)) {
		t.Fatalf("the recovered file is %d bytes, wanted the %d fsync covered", got.Length, len(body))
	}
	back := make([]byte, len(body))
	if _, err := ov2.Read(ctx, n.Inode, 0, back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, body) {
		t.Fatal("the recovered file is not byte-exact; fsync said these bytes were safe")
	}
	// And the NAME survived with it, which is the metadata half.
	if _, err := ov2.Lookup(ctx, rootIno, "survives.dat"); err != nil {
		t.Fatalf("the fsync'd file lost its name: %v", err)
	}
}

// A chatty application must not pay for saying the same thing twice. With
// nothing written between two fsyncs the second one is a lock and a
// comparison: no msync, no fsync, no syscall of any kind.
func TestAnFsyncWithNothingNewCostsNothing(t *testing.T) {
	ctx := context.Background()
	s := newSyncFixture(t, "d5f0d5f0-0003-4000-8000-000000000003")

	n, err := s.ov.Create(ctx, rootIno, "chatty.dat", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ov.Write(ctx, n.Inode, 0, pseudorandom(4096, 41)); err != nil {
		t.Fatal(err)
	}
	if err := s.ov.Sync(); err != nil {
		t.Fatal(err)
	}
	base, baseContent := s.ov.SyncStats(), s.store.Stats()
	const storm = 200
	for i := 0; i < storm; i++ {
		if err := s.ov.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	st := s.ov.SyncStats()
	if st.Passes != base.Passes {
		t.Errorf("%d fsyncs with nothing between them made %d extra durability passes",
			storm, st.Passes-base.Passes)
	}
	if st.Fsyncs != base.Fsyncs {
		t.Errorf("%d fsyncs with nothing between them cost %d file syncs; a syscall storm "+
			"from a chatty application has to be free", storm, st.Fsyncs-base.Fsyncs)
	}
	if cs := s.store.Stats(); cs.RingSyncs != baseContent.RingSyncs || cs.JournalSyncs != baseContent.JournalSyncs {
		t.Errorf("%d fsyncs with nothing between them cost %d msyncs and %d journal syncs",
			storm, cs.RingSyncs-baseContent.RingSyncs, cs.JournalSyncs-baseContent.JournalSyncs)
	}
	if st.Coalesced != base.Coalesced+storm {
		t.Errorf("%d of %d repeat fsyncs were coalesced", st.Coalesced-base.Coalesced, storm)
	}
	// And one more WRITE reopens it: coalescing that never expires would
	// be a lie of a different shape.
	if _, err := s.ov.Write(ctx, n.Inode, 4096, pseudorandom(4096, 42)); err != nil {
		t.Fatal(err)
	}
	if err := s.ov.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := s.ov.SyncStats().Passes; got != base.Passes+1 {
		t.Errorf("an fsync after a new write made %d passes, wanted one more than %d",
			got, base.Passes)
	}
}

// The first fsync of a SESSION always works, even with nothing written
// through it: the mutation counter it coalesces on is this process's, and
// a resumed state directory may hold another session's unsynced bytes.
func TestTheFirstFsyncOfASessionIsNeverCoalescedAway(t *testing.T) {
	s := newSyncFixture(t, "d5f0d5f0-0004-4000-8000-000000000004")
	if err := s.ov.Sync(); err != nil {
		t.Fatal(err)
	}
	if st := s.ov.SyncStats(); st.Passes != 1 || st.Coalesced != 0 {
		t.Fatalf("the first fsync of a session was coalesced away: %+v", st)
	}
}

// What a chatty application actually pays, in nanoseconds rather than in
// syscall counts.
//
// The tests above assert that a repeat fsync makes ZERO syscalls, which is
// the correctness half. This is the cost half, and it is a BENCHMARK
// rather than a gated measurement because a per-call cost is exactly what
// a benchmark reports and there is no env var to remember. Run both:
//
//	go test ./internal/overlay -run XXX -bench Fsync -benchtime 2000x
//
// BenchmarkFsyncLoop is one write and then fsync forever, which is the
// shape the coalescing exists for — a database or an editor calling
// fsync(2) after every operation whether or not anything changed.
func BenchmarkFsyncLoop(b *testing.B) {
	ctx := context.Background()
	s := newSyncFixture(b, "d5f0d5f0-0005-4000-8000-000000000005")
	n, err := s.ov.Create(ctx, rootIno, "chatty.dat", 0644, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := s.ov.Write(ctx, n.Inode, 0, pseudorandom(4096, 71)); err != nil {
		b.Fatal(err)
	}
	// The one pass that has work to do, outside the timer.
	if err := s.ov.Sync(); err != nil {
		b.Fatal(err)
	}
	before := s.ov.SyncStats()
	b.ResetTimer()
	for b.Loop() {
		if err := s.ov.Sync(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	// Reported, not just timed: a fast loop that was quietly syncing would
	// be a measurement of a warm page cache rather than of the coalescing.
	b.ReportMetric(float64(s.ov.SyncStats().Fsyncs-before.Fsyncs), "extra-fsyncs")
}

// BenchmarkFsyncAfterEveryWrite is the other end of the same axis: a write
// between every fsync, so nothing coalesces and every call does the whole
// job. The ratio between the two is what the coalescing is worth.
func BenchmarkFsyncAfterEveryWrite(b *testing.B) {
	ctx := context.Background()
	s := newSyncFixture(b, "d5f0d5f0-0006-4000-8000-000000000006")
	n, err := s.ov.Create(ctx, rootIno, "busy.dat", 0644, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	buf := pseudorandom(4096, 72)
	off := int64(0)
	b.ResetTimer()
	for b.Loop() {
		if _, err := s.ov.Write(ctx, n.Inode, off, buf); err != nil {
			b.Fatal(err)
		}
		off += int64(len(buf))
		if err := s.ov.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}
