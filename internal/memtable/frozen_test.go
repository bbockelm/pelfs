package memtable

import (
	"bytes"
	"context"
	"testing"
)

// A checkpoint seals a frozen view while the mount keeps writing. The
// test is that the two disagree in exactly the right direction: the
// frozen view keeps answering with the instant it captured, no matter
// what lands afterwards.
func TestFrozenViewIgnoresWritesAfterTheInstant(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})

	first := fill(150000, 81)
	if err := s.Write(ctx, 1, 0, first); err != nil {
		t.Fatal(err)
	}
	f, err := s.Freeze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release()

	// Everything below happens "while the checkpoint runs".
	patch := fill(900, 82)
	if err := s.Write(ctx, 1, 2000, patch); err != nil {
		t.Fatal(err)
	}
	tail := fill(20000, 83)
	if err := s.Write(ctx, 1, int64(len(first)), tail); err != nil {
		t.Fatal(err)
	}
	fresh := fill(4000, 84)
	if err := s.Write(ctx, 2, 0, fresh); err != nil {
		t.Fatal(err)
	}
	if err := s.Truncate(1, 1000); err != nil {
		t.Fatal(err)
	}

	if got := f.Size(1); got != int64(len(first)) {
		t.Errorf("frozen size = %d, want %d", got, len(first))
	}
	if got := f.Size(2); got != 0 {
		t.Errorf("a file created after the instant has size %d in the frozen view", got)
	}
	got := make([]byte, len(first))
	if _, err := f.Read(ctx, 1, 0, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatal("the frozen view does not read the instant it captured")
	}

	// And it SEALS the instant: rows covering the frozen file exactly.
	sl := s.NewSealer()
	refs, err := f.Records(ctx, sl, 1)
	if err != nil {
		t.Fatalf("seal the frozen view: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if rendered := readThroughFormat(t, obj, s.Packs(), refs); !bytes.Equal(rendered, first) {
		t.Fatal("the frozen rows do not read back as the instant")
	}
	// The live store, meanwhile, is where the session left it.
	if got := s.Size(1); got != 1000 {
		t.Errorf("live size = %d, want the truncated 1000", got)
	}
}

// Freezing flushes, which is what makes the whole arrangement free of
// pins: after it, nothing a frozen map names is still in the ring, so
// nothing the live side does can recycle it.
func TestFreezingLeavesNothingInTheRing(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})
	if err := s.Write(ctx, 1, 0, fill(80000, 85)); err != nil {
		t.Fatal(err)
	}
	if used := s.ring.Used(); used == 0 {
		t.Fatal("the write did not reach the ring, so freezing proves nothing")
	}
	f, err := s.Freeze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release()
	s.mu.Lock()
	inRing := len(s.index)
	s.mu.Unlock()
	if inRing != 0 {
		t.Errorf("%d extents are still in the ring after a freeze", inRing)
	}
}

// An overwrite that supersedes an extent before its flush is never
// uploaded — the design's central claim — and a frozen view taken AFTER
// that overwrite must agree: it captures the file as it reads, not every
// version that was ever written.
func TestFrozenViewCapturesTheSurvivingVersion(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	dead := fill(60000, 86)
	if err := s.Write(ctx, 1, 0, dead); err != nil {
		t.Fatal(err)
	}
	live := fill(60000, 87)
	if err := s.Write(ctx, 1, 0, live); err != nil {
		t.Fatal(err)
	}
	f, err := s.Freeze(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release()

	got := make([]byte, len(live))
	if _, err := f.Read(ctx, 1, 0, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, live) {
		t.Fatal("the frozen view did not capture the surviving version")
	}
	if obj.contains(dead[:1024]) {
		t.Error("the superseded version reached the federation")
	}
}
