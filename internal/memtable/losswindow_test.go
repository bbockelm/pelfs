package memtable

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// The window KL-10 described, and the two halves of closing it.
//
// A flush used to be durable in two steps with a gap between them that
// lost data. `publish` installed the batch's locations, dropped its
// records from the ring index, and RECLAIMED the ring region they sat in —
// which moves the tail hint in the ring file header, so `OpenRing` would
// not walk them again. Only afterwards did `runFlush` wait for the packs
// and write the `Located` record binding handles to packs. A crash in
// between left a state directory whose operation log knew the file's
// LENGTH (Write journals OpPlace under the store's own lock) and whose
// location map had nothing behind part of it: one flush batch, 2 MiB at
// the shipped pack target, referenced by neither place.
//
// `704ae5c` made that honest — the file is cut back to its first lost byte
// and the loss reported, rather than served as zeros
// (holerecovery_test.go). These two tests are the other half: the loss
// does not happen at all, because the ring region is not reclaimed until
// the record that replaces it is durable.
//
// Neither test kills anything. The ordering is observable from inside the
// journal — the one call that stands between publishing a batch and
// releasing its bytes — so a journal that stalls there, or fails there, is
// the whole simulation.

// errLocatedNeverLanded is the process dying between the publish and the
// record. A journal that returns it has recorded nothing, which is exactly
// what a crash in the window leaves behind.
var errLocatedNeverLanded = errors.New("test: the Located record never landed")

// crashingJournal drops the Located record and says so.
type crashingJournal struct {
	*memJournal
	seen int
}

func (j *crashingJournal) Located(Location) error {
	j.mu.Lock()
	j.seen++
	j.mu.Unlock()
	return errLocatedNeverLanded
}

// gateJournal holds the Located call open, so a test can look at the ring
// at the one instant that used to be unsafe.
type gateJournal struct {
	*memJournal
	entered chan struct{}
	release chan struct{}
}

func (j *gateJournal) Located(l Location) error {
	j.entered <- struct{}{}
	<-j.release
	return j.memJournal.Located(l)
}

func losswindowOpts(dir string) Options {
	return Options{
		Dir: dir, TableSize: 1 << 20, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil),
	}
}

// The window is CLOSED: a crash between a batch's publish and its Located
// record loses nothing, because the extents are still in the ring.
//
// Before the fix this file came back at 0 bytes with a Truncation
// reported — honest, and still a lost batch. The assertion is byte-exact
// on purpose: "not zeros" was the previous bar, and this one is "not
// gone".
func TestACrashBeforeTheLocatedRecordLosesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	j := &crashingJournal{memJournal: newMemJournal()}
	opts := losswindowOpts(dir)
	opts.Obj, opts.Journal = obj, j
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	// Three writes, so the file is three extents the way a copy of it
	// through a mount would be.
	want := make([]byte, 0, 12000)
	for i := 0; i < 3; i++ {
		part := fill(4000, uint64(i+71))
		if err := s.Write(ctx, 1, int64(i*4000), part); err != nil {
			t.Fatal(err)
		}
		want = append(want, part...)
	}
	flushErr := s.Flush(ctx)
	d := j.durable()
	if len(d.Handles) != 0 {
		t.Fatalf("the Located record landed after all (%d handles); there is no crash window to test", len(d.Handles))
	}
	if j.seen == 0 {
		t.Fatal("the flush never reached its Located record")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, rep, err := Recover(losswindowOpts(dir), d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	if rep.Loss() {
		t.Fatalf("a crash before the Located record lost %d bytes; the ring still held them:\n%s",
			rep.LostBytes, rep)
	}
	if len(rep.Truncations) != 0 {
		t.Fatalf("the file was cut back although nothing was lost: %+v", rep.Truncations)
	}
	if got := s2.Size(1); got != 12000 {
		t.Fatalf("inode 1 came back at %d bytes, wanted the whole 12000 the operation log promised", got)
	}
	if got := readAll(t, s2, 1); !bytes.Equal(got, want) {
		t.Fatalf("the recovered file is not byte-exact (%d bytes back)", len(got))
	}
	// The records came back from the RING, which is the mechanism: the
	// location map was never made durable.
	if len(rep.Buffers) != 1 || rep.Buffers[0].Records == 0 {
		t.Fatalf("recovery read no records out of the ring: %+v", rep.Buffers)
	}
	// And the flush said so. A flush that reported success while its
	// Located record failed would leave a seal free to publish a
	// generation over content nothing durable describes.
	if !errors.Is(flushErr, errLocatedNeverLanded) {
		t.Fatalf("Flush returned %v; a failed Located record has to reach the caller", flushErr)
	}
}

// The ordering itself, at the ring: while the Located record is in flight
// the tail has not moved, and the records are still where OpenRing would
// find them. This is the invariant the test above depends on, asserted
// where it lives rather than through a recovery.
func TestTheRingIsNotReclaimedUntilTheLocatedRecordIsDurable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	j := &gateJournal{
		memJournal: newMemJournal(),
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	opts := losswindowOpts(dir)
	opts.Obj, opts.Journal = obj, j
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	for i := 0; i < 3; i++ {
		if err := s.Write(ctx, 1, int64(i*4000), fill(4000, uint64(i+81))); err != nil {
			t.Fatal(err)
		}
	}
	used := s.ring.Used()
	if used == 0 {
		t.Fatal("nothing in the ring to hold")
	}

	done := make(chan error, 1)
	go func() { done <- s.Flush(ctx) }()

	<-j.entered
	// The batch has been published — its locations are installed and its
	// records are out of the index — and the record that says where its
	// bytes went is not durable yet. This is the instant that used to
	// reclaim.
	if tail := s.ring.Tail(); tail != 0 {
		t.Errorf("the ring tail moved to %d before the Located record landed; "+
			"a crash here has nowhere left to find the batch", tail)
	}
	if got := s.ring.Used(); got != used {
		t.Errorf("the ring released %d bytes before the Located record landed", used-got)
	}
	close(j.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.ring.Used() != 0 {
		t.Errorf("the ring still holds %d bytes after the record landed; "+
			"a tail that never advances is a writer that never gets its space back", s.ring.Used())
	}
}

// A Located record that FAILS is a different animal from a failed pack run,
// and the difference is a hang.
//
// A failed pack leaves its records in the ring index, so Flush clears the
// error and packs them again — that is the recovery. A failed LOCATION
// record cannot be retried: publish has already taken those records out of
// the index, and the region they occupy can never be released, because it
// is still the only place those extents exist. So the ring fills and stays
// full, and a writer waiting for space is waiting for something that is
// not coming. Before the error was made sticky, that writer parked on the
// condition variable forever with no flush left alive to broadcast — a
// mount that hangs instead of a mount that reports EIO.
func TestAFailedLocationRecordFailsTheWriterInsteadOfHangingIt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	j := &crashingJournal{memJournal: newMemJournal()}
	opts := losswindowOpts(dir)
	opts.Obj, opts.Journal = obj, j
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	// NEARLY THE WHOLE 1 MiB ring, and the size is the point. The hang
	// needs a ring with no room AND nothing left to pack: 17 records of
	// 60,048 bytes is 1,021,632 of 1,048,576. Fill less and a blocked
	// writer finds its OWN later writes still in the index, cuts them,
	// gets the next flush's failure, and returns an answer — which is why
	// the first version of this test passed against the bug. The mutation
	// run is what said so.
	body := fill(60000, 91)
	for i := 0; i < 17; i++ {
		if err := s.Write(ctx, 1, int64(i*60000), body); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); !errors.Is(err, errLocatedNeverLanded) {
		t.Fatalf("the first Flush returned %v, wanted the journal's failure", err)
	}
	// Every LATER Flush says so again. Reporting success over a ring that
	// will never drain is what would let a seal publish on top of it — and
	// this call is also what clears flushErr, which is what leaves the
	// writer below with nothing but the sticky error to find.
	if err := s.Flush(ctx); !errors.Is(err, errLocatedNeverLanded) {
		t.Fatalf("a second Flush returned %v; the failure is not retryable and has to stay reported", err)
	}
	// So now: no room in the ring, nothing in the index to pack, and
	// flushErr cleared. Without the sticky error this write starts a pack
	// run that cuts an empty batch and then parks on the condition variable
	// with no flush left alive to broadcast — forever. Nothing here waits
	// on a timeout as an assertion; the hang IS the failure.
	if err := s.Write(ctx, 2, 0, body); !errors.Is(err, errLocatedNeverLanded) {
		t.Fatalf("a write into the frozen ring returned %v, wanted the journal's failure", err)
	}
}
