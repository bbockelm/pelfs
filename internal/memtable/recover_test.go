package memtable

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reopen simulates a crash: the durable state is what the overlay's
// database would have held, the buffer files are whatever survived, and
// nothing in memory carries over.
func reopen(t *testing.T, s *Store, obj *countingStore, dir string, tableSize int) (*Store, *Report) {
	t.Helper()
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, rep, err := Recover(Options{Dir: dir, TableSize: tableSize, Obj: obj, Chunk: smallChunks}, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() }) //nolint:errcheck
	return s2, rep
}

func TestRecoverIntactBuffer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint64][]byte{1: fill(3000, 1), 2: fill(120000, 2)}
	for ino, v := range want {
		if err := s.Write(ctx, ino, 0, v); err != nil {
			t.Fatal(err)
		}
	}

	s2, rep := reopen(t, s, obj, dir, 1<<20)
	if rep.Loss() {
		t.Fatalf("clean reopen reported loss:\n%s", rep)
	}
	for ino, v := range want {
		if got := readAll(t, s2, ino); !bytes.Equal(got, v) {
			t.Fatalf("inode %d does not read back after recovery", ino)
		}
	}
	// The recovered table must still be flushable, not merely readable.
	if err := s2.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for ino, v := range want {
		if got := readAll(t, s2, ino); !bytes.Equal(got, v) {
			t.Fatalf("inode %d does not read back after the recovered table flushed", ino)
		}
	}
}

// Content that already reached a pack survives a crash through the
// location map, not through the buffer file — the buffer is gone by
// then. That is the half of recovery the design's step 3 depends on.
func TestRecoverSplitsAcrossFlushedAndUnflushed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	flushed := fill(80000, 11)
	if err := s.Write(ctx, 1, 0, flushed); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	unflushed := fill(5000, 12)
	if err := s.Write(ctx, 2, 0, unflushed); err != nil {
		t.Fatal(err)
	}

	s2, rep := reopen(t, s, obj, dir, 1<<20)
	if rep.Loss() {
		t.Fatalf("reported loss with everything intact:\n%s", rep)
	}
	if got := readAll(t, s2, 1); !bytes.Equal(got, flushed) {
		t.Fatal("flushed inode does not read back through the location map")
	}
	if got := readAll(t, s2, 2); !bytes.Equal(got, unflushed) {
		t.Fatal("unflushed inode does not read back through the recovered buffer")
	}
}

// The case the design cares about: a buffer file cut short. Records
// before the cut come back, the torn tail does not, and every content
// row that named a lost extent is reported by inode and byte range.
func TestRecoverFromTruncatedBufferReportsLoss(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	const inodes = 12
	want := make(map[uint64][]byte)
	for ino := uint64(1); ino <= inodes; ino++ {
		want[ino] = fill(4000, ino)
		if err := s.Write(ctx, ino, 0, want[ino]); err != nil {
			t.Fatal(err)
		}
	}
	used := int(s.ring.Used())
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Cut the buffer roughly in half, inside a record.
	path := filepath.Join(dir, bufferName(0))
	if err := os.Truncate(path, int64(used/2)); err != nil {
		t.Fatal(err)
	}
	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	if !rep.Loss() {
		t.Fatal("a truncated buffer file reported no loss")
	}
	if len(rep.LostInodes) == 0 || len(rep.LostInodes) == inodes {
		t.Fatalf("%d inodes lost of %d; expected a partial loss", len(rep.LostInodes), inodes)
	}
	msg := rep.String()
	for _, want := range []string{"DATA LOST", "are gone"} {
		if !strings.Contains(msg, want) {
			t.Errorf("report does not mention %q:\n%s", want, msg)
		}
	}
	if !rep.Buffers[0].Truncated {
		t.Error("the truncated buffer was not flagged as short")
	}

	lost := make(map[uint64]bool)
	for _, l := range rep.LostInodes {
		lost[l] = true
	}
	// Everything not reported lost must read back byte-exact. A recovery
	// that reports honestly but returns wrong bytes is no better than a
	// silent one.
	for ino := uint64(1); ino <= inodes; ino++ {
		if lost[ino] {
			if got := readAll(t, s2, ino); len(got) != 0 && bytes.Equal(got, want[ino]) {
				t.Errorf("inode %d was reported lost but read back whole", ino)
			}
			continue
		}
		if got := readAll(t, s2, ino); !bytes.Equal(got, want[ino]) {
			t.Errorf("inode %d survived recovery but does not read back byte-exact", ino)
		}
	}
	if st := s2.Stats(); st.LostHandles == 0 {
		t.Error("LostHandles was not counted")
	}
}

// A buffer whose tail was overwritten with garbage rather than cut is
// the other torn shape, and it must be flagged as such.
func TestRecoverFlagsTornTail(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	for ino := uint64(1); ino <= 4; ino++ {
		if err := s.Write(ctx, ino, 0, fill(2000, ino)); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt the third record's payload in place.
	victim := s.index[2]
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, bufferName(0)), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xde, 0xad}, int64(ringFileHdr+victim.Off+7)); err != nil {
		t.Fatal(err)
	}
	f.Close() //nolint:errcheck

	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	if !rep.Buffers[0].Torn {
		t.Error("a corrupted record did not flag the buffer as torn")
	}
	if !rep.Loss() {
		t.Fatal("a corrupted record reported no loss")
	}
	// Inodes 1 and 2 are before the corruption and must be intact; 3 and
	// 4 are behind it and must be reported, not silently returned.
	if got := readAll(t, s2, 1); !bytes.Equal(got, fill(2000, 1)) {
		t.Error("inode before the corruption does not read back")
	}
	want := map[uint64]bool{3: true, 4: true}
	for _, ino := range rep.LostInodes {
		delete(want, ino)
	}
	if len(want) != 0 {
		t.Errorf("inodes %v were behind the corruption but not reported lost", want)
	}
}
