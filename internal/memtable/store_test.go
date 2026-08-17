package memtable

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func fill(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 0x9e3779b9))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func TestWriteReadBeforeAndAfterFlush(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})

	want := map[uint64][]byte{
		1: fill(50, 1),
		2: fill(9000, 2),
		3: fill(70000, 3),
	}
	for ino, data := range want {
		if err := s.Write(ctx, ino, 0, data); err != nil {
			t.Fatal(err)
		}
	}
	for ino, data := range want {
		if got := readAll(t, s, ino); !bytes.Equal(got, data) {
			t.Fatalf("inode %d before flush: %d bytes, want %d", ino, len(got), len(data))
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for ino, data := range want {
		if got := readAll(t, s, ino); !bytes.Equal(got, data) {
			t.Fatalf("inode %d after flush does not read back byte-exact", ino)
		}
	}
	if st := s.Stats(); st.Packs == 0 {
		t.Fatal("flush uploaded no packs")
	}
}

// Sparse and overlapping writes exercise the ref map: a write inside an
// earlier extent splits it, and both halves must still resolve through
// the same handle after the flush has moved the bytes into a pack.
func TestPartialOverwriteReadsBackExact(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})

	base := fill(20000, 7)
	if err := s.Write(ctx, 1, 0, base); err != nil {
		t.Fatal(err)
	}
	patch := fill(300, 8)
	if err := s.Write(ctx, 1, 5000, patch); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), base...)
	copy(want[5000:], patch)

	// A hole past the end must read as zeros.
	tail := fill(10, 9)
	if err := s.Write(ctx, 1, 30000, tail); err != nil {
		t.Fatal(err)
	}
	want = append(want, make([]byte, 30000-len(want))...)
	want = append(want, tail...)

	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("in-memory read does not match")
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("post-flush read does not match")
	}

	// Every sub-range must be readable on its own, since a partial read
	// takes a different path through the slice arithmetic than a whole
	// one.
	for _, r := range [][2]int{{0, 100}, {4990, 320}, {19990, 30}, {29990, 20}} {
		got := make([]byte, r[1])
		if _, err := s.Read(ctx, 1, int64(r[0]), got); err != nil {
			t.Fatalf("read at %d: %v", r[0], err)
		}
		if !bytes.Equal(got, want[r[0]:r[0]+r[1]]) {
			t.Fatalf("range read at %d/%d does not match", r[0], r[1])
		}
	}
}

// The design's central claim: an extent superseded before its table
// flushes is never uploaded. Asserted twice — once against the store's
// accounting, once against the bytes that reached the federation.
func TestDeadExtentsAreNeverUploaded(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 4<<20, Hooks{})

	const rounds = 8
	var dead [][]byte
	var survivor []byte
	for i := range rounds {
		v := fill(60000, uint64(100+i))
		if err := s.Write(ctx, 1, 0, v); err != nil {
			t.Fatal(err)
		}
		if i == rounds-1 {
			survivor = v
		} else {
			dead = append(dead, v)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()
	if st.DeadExtents != rounds-1 {
		t.Errorf("collapsed %d dead extents, want %d", st.DeadExtents, rounds-1)
	}
	if st.UploadedBytes != int64(len(survivor)) {
		t.Errorf("uploaded %d bytes, want exactly the surviving %d", st.UploadedBytes, len(survivor))
	}
	for i, v := range dead {
		if obj.contains(v[:1024]) {
			t.Errorf("version %d of the file reached the federation despite being overwritten", i)
		}
	}
	if !obj.contains(survivor[:1024]) {
		t.Fatal("the surviving version never reached the federation")
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, survivor) {
		t.Fatal("survivor does not read back byte-exact")
	}
}

// Backpressure: the bound is two tables. A writer that fills the active
// table while a flush is in flight waits, and never gets a third.
func TestBackpressureBlocksTheWriter(t *testing.T) {
	ctx := context.Background()
	release := make(chan struct{})
	var seen atomic.Int64
	s, _ := newTestStore(t, 128<<10, Hooks{
		BeforePublish: func(uint64) error {
			<-release
			return nil
		},
		FlushStarted: func(uint64) { seen.Add(1) },
	})

	// Fill and rotate once; that flush parks in BeforePublish.
	if err := s.Write(ctx, 1, 0, fill(120<<10, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, 1, 120<<10, fill(20<<10, 2)); err != nil {
		t.Fatal(err)
	}

	blocked := make(chan error, 1)
	go func() {
		// Enough to fill the fresh table and demand a second rotation,
		// which cannot proceed while the first flush is parked.
		blocked <- s.Write(ctx, 2, 0, fill(200<<10, 3))
	}()

	// Wait for the writer to actually be parked, then check that it is
	// still parked and that no third table appeared. Counting buffer
	// files is the assertion that matters: the bound is two, and a
	// design that grew a third would still pass a timing check.
	waitForBlocked(t, s)
	select {
	case err := <-blocked:
		t.Fatalf("writer finished (%v) while the only flush slot was occupied", err)
	default:
	}
	if n := bufferFiles(t, s); n > 2 {
		t.Fatalf("%d buffer files while a writer waits; the bound is two", n)
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.BlockedWrites == 0 {
		t.Error("no write was recorded as blocked")
	}
	if n := seen.Load(); n < 2 {
		t.Errorf("%d flushes started, want at least 2", n)
	}
}

// waitForBlocked spins until a writer has recorded that it is waiting on
// the flush slot. The counter is bumped before the wait precisely so a
// test can observe backpressure while it is happening.
func waitForBlocked(t *testing.T, s *Store) {
	t.Helper()
	for s.Stats().BlockedWrites == 0 {
		runtime.Gosched()
	}
}

func bufferFiles(t *testing.T, s *Store) int {
	t.Helper()
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "mem-") {
			n++
		}
	}
	return n
}

// CDC is optional for correctness, so a flush under pressure abandons it.
// The pack is worse deduped; the content still reads back byte-exact.
func TestAbandonedCDCStillProducesCorrectContent(t *testing.T) {
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	s, _ := newTestStore(t, 256<<10, Hooks{
		FlushStarted: func(seq uint64) {
			if seq == 0 {
				close(started)
				<-release
			}
		},
	})

	want := make(map[uint64][]byte)
	for ino := uint64(1); ino <= 4; ino++ {
		want[ino] = fill(60<<10, ino)
		if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
			t.Fatal(err)
		}
	}
	// Push past the table so the first flush starts and parks.
	if err := s.Write(ctx, 5, 0, fill(60<<10, 5)); err != nil {
		t.Fatal(err)
	}
	want[5] = nil
	<-started

	// A second writer now demands the flushing table, which is the signal
	// that makes the flusher give up chunking.
	blocked := make(chan error, 1)
	go func() { blocked <- s.Write(ctx, 6, 0, fill(300<<10, 6)) }()
	// The flusher must not be released until the blocked writer has set
	// the abandon flag, or there is no pressure to release from.
	waitForBlocked(t, s)
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()
	if st.AbandonedFlushes == 0 || st.RawChunks == 0 {
		t.Fatalf("expected an abandoned CDC pass, got %+v", st)
	}
	for ino := uint64(1); ino <= 4; ino++ {
		if got := readAll(t, s, ino); !bytes.Equal(got, want[ino]) {
			t.Fatalf("inode %d does not read back byte-exact after an abandoned CDC pass", ino)
		}
	}
}

// A crash between "the pack is durable" and "its locations are
// published" must lose nothing: until publication succeeds the memtable
// is the only authority, so it stays.
func TestCrashBetweenUploadAndPublish(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	fail := true
	boom := errors.New("simulated crash before publication")
	s, obj := newTestStore(t, 1<<20, Hooks{
		BeforePublish: func(uint64) error {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return boom
			}
			return nil
		},
	})

	want := fill(100000, 42)
	if err := s.Write(ctx, 1, 0, want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); !errors.Is(err, boom) {
		t.Fatalf("flush error = %v, want the injected failure", err)
	}
	if puts, _ := obj.stats(); puts == 0 {
		t.Fatal("the pack was never uploaded, so this is not the window under test")
	}
	// The locations were never installed, so the read must come from the
	// retained memtable — and must be exact.
	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("content lost when a flush failed after its upload")
	}

	mu.Lock()
	fail = false
	mu.Unlock()
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, want) {
		t.Fatal("content lost after a retried flush")
	}
}

// A truncate that shortens a file must drop the extents past the new end,
// and a truncate to zero must drop all of them.
func TestTruncateCollapsesExtents(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	doomed := fill(40000, 5)
	if err := s.Write(ctx, 1, 0, doomed); err != nil {
		t.Fatal(err)
	}
	s.Truncate(1, 0)
	kept := fill(1000, 6)
	if err := s.Write(ctx, 1, 0, kept); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if obj.contains(doomed[:1024]) {
		t.Error("content truncated away before flush was uploaded anyway")
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, kept) {
		t.Fatal("post-truncate content does not read back")
	}
}
