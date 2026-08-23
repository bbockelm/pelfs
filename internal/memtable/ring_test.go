package memtable

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func newRing(t *testing.T, size int) (*Ring, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ring")
	r, err := CreateRing(path, size)
	if err != nil {
		t.Fatalf("CreateRing: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, path
}

func appendN(t *testing.T, r *Ring, h Handle, payload []byte) uint64 {
	t.Helper()
	pos, err := r.Append(&Record{Handle: h, Inode: uint64(h), FileOff: 0}, payload)
	if err != nil {
		t.Fatalf("append %d: %v", h, err)
	}
	return pos
}

// TestRingWrapsAndReclaims is the behaviour a stack of tables does not
// have: space freed at the tail is reusable immediately, so a writer can
// lap the buffer indefinitely as long as packing keeps up.
func TestRingWrapsAndReclaims(t *testing.T) {
	const size = 32 << 10
	r, _ := newRing(t, size)

	payload := bytes.Repeat([]byte{0xab}, MaxRecord(size))
	var laps int
	for h := Handle(1); h <= 200; h++ {
		pos, err := r.Append(&Record{Handle: h, Inode: uint64(h)}, payload)
		if errors.Is(err, ErrRingFull) {
			// Reclaim everything: the point is that the ring keeps going.
			if _, err := r.Reclaim(r.Head()); err != nil {
				t.Fatal(err)
			}
			laps++
			pos = appendN(t, r, h, payload)
		} else if err != nil {
			t.Fatalf("append: %v", err)
		}
		got, ok := r.At(pos, len(payload))
		if !ok {
			t.Fatalf("record %d not readable at %d", h, pos)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("record %d read back wrong", h)
		}
	}
	if laps == 0 {
		t.Fatal("the ring never wrapped; the test proved nothing")
	}
	if r.Used() > uint64(size) {
		t.Fatalf("used %d exceeds the ring's %d", r.Used(), size)
	}
}

// A writer must be told to wait rather than overwrite bytes the tail has
// not released. That refusal IS the backpressure signal.
func TestRingRefusesToOverwriteLiveBytes(t *testing.T) {
	const size = 16 << 10
	r, _ := newRing(t, size)
	payload := bytes.Repeat([]byte{0x7f}, MaxRecord(size))
	var appended int
	for {
		if _, err := r.Append(&Record{Handle: Handle(appended)}, payload); err != nil {
			if errors.Is(err, ErrRingFull) {
				break
			}
			t.Fatalf("append: %v", err)
		}
		appended++
		if appended > 100 {
			t.Fatal("the ring never filled; it is overwriting live bytes")
		}
	}
	if appended == 0 {
		t.Fatal("the ring refused its first record")
	}
	// Releasing space lets the writer proceed again.
	if _, err := r.Reclaim(r.Head()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(&Record{Handle: 999}, payload); err != nil {
		t.Fatalf("append after reclaim: %v", err)
	}
}

// TestRingRecoveryStopsAtAStaleLap is the case an append-only log never
// faces. After wrapping, the bytes past the head are well-formed records
// from a previous lap with LOWER sequence numbers; recovery must stop
// there rather than reading them as live.
func TestRingRecoveryStopsAtAStaleLap(t *testing.T) {
	const size = 16 << 10
	path := filepath.Join(t.TempDir(), "ring")
	r, err := CreateRing(path, size)
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte{0x11}, MaxRecord(size))
	// Fill, reclaim, and lap so older records sit ahead of the head.
	for i := 0; i < 40; i++ {
		if _, err := r.Append(&Record{Handle: Handle(i), Inode: uint64(i)}, payload); errors.Is(err, ErrRingFull) {
			if _, err := r.Reclaim(r.Head()); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Append(&Record{Handle: Handle(i), Inode: uint64(i)}, payload); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	wantHead, wantTail := r.Head(), r.Tail()
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	r2, live, err := OpenRing(path)
	if err != nil {
		t.Fatalf("OpenRing: %v", err)
	}
	defer r2.Close() //nolint:errcheck

	if r2.Head() != wantHead {
		t.Errorf("recovered head %d, want %d — recovery walked into a stale lap or stopped early",
			r2.Head(), wantHead)
	}
	if r2.Tail() != wantTail {
		t.Errorf("recovered tail %d, want %d", r2.Tail(), wantTail)
	}
	// Every recovered record must read back the bytes it was written with.
	for _, rec := range live {
		got, ok := r2.At(uint64(rec.Off), rec.Length)
		if !ok {
			t.Fatalf("recovered record at %d is not readable", rec.Off)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("recovered record at %d has the wrong bytes", rec.Off)
		}
	}
}

// A torn record ends the run. Everything before it survives, which is
// what recovery owes the caller: the surviving prefix, and no silence
// about the rest.
func TestRingRecoveryStopsAtATornRecord(t *testing.T) {
	const size = 32 << 10
	path := filepath.Join(t.TempDir(), "ring")
	r, err := CreateRing(path, size)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x22}, MaxRecord(size))
	var positions []uint64
	for i := 0; i < 5; i++ {
		positions = append(positions, appendN(t, r, Handle(i), payload))
	}
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	// Corrupt the third record's payload in the mapping.
	off := positions[2]%r.size + ringRecHdr
	r.data[off] ^= 0xff
	if err := r.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, live, err := OpenRing(path)
	if err != nil {
		t.Fatalf("OpenRing: %v", err)
	}
	// Close it. A live mapping PINS its file on Windows, where unlink of an
	// open file is refused, so discarding this handle failed the test in
	// TempDir cleanup -- after the body had passed, naming a path instead of
	// a cause. Unix hid it: there, unlink of an open file is ordinary.
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close the reopened ring: %v", err)
		}
	}()
	if len(live) != 2 {
		t.Fatalf("recovered %d records, want the 2 before the torn one", len(live))
	}
	for i, rec := range live {
		if rec.Handle != Handle(i) {
			t.Fatalf("record %d has handle %d", i, rec.Handle)
		}
	}
}

// A payload that cannot fit before the seam is padded past it, so no
// record ever straddles — which is what lets At hand out one contiguous
// slice with no copy.
func TestRingPadsRatherThanStraddling(t *testing.T) {
	const size = 32 << 10
	r, _ := newRing(t, size)
	big := bytes.Repeat([]byte{0x33}, MaxRecord(size))
	var last uint64
	for i := 0; i < 3; i++ {
		last = appendN(t, r, Handle(i), big)
	}
	// The next record cannot fit before the seam; it must land at the
	// start of the mapping rather than wrapping around it.
	if _, err := r.Reclaim(r.Head()); err != nil {
		t.Fatal(err)
	}
	pos := appendN(t, r, 99, big)
	off := pos % r.size
	if off+uint64(ringRecHdr+len(big)) > r.size {
		t.Fatalf("record at %d (offset %d) straddles the seam of a %d-byte ring", pos, off, size)
	}
	got, ok := r.At(pos, len(big))
	if !ok || !bytes.Equal(got, big) {
		t.Fatalf("padded record did not read back (ok=%v)", ok)
	}
	_ = last
}

// Age is a subtraction, which is what makes the promotion rule cheap:
// an extent at position p is head-p bytes old.
func TestRingAgeIsDistanceBehindTheHead(t *testing.T) {
	const size = 64 << 10
	r, _ := newRing(t, size)
	payload := bytes.Repeat([]byte{0x44}, MaxRecord(size))
	first := appendN(t, r, 1, payload)
	for i := 2; i <= 10; i++ {
		appendN(t, r, Handle(i), payload)
	}
	age := r.Head() - first
	if want := uint64(10 * (ringRecHdr + len(payload))); age != want {
		t.Fatalf("age of the first record is %d, want %d", age, want)
	}
	if fmt.Sprint(r.Used()) != fmt.Sprint(age) {
		t.Fatalf("used %d and age %d should agree with nothing reclaimed", r.Used(), age)
	}
}

// TestRingSeparatesFullFromTooLarge is the deadlock guard. A writer that
// blocks until space frees is correct for a full ring and an infinite
// loop for a record that can never fit, so the two must be distinguishable
// with errors.Is rather than by message.
func TestRingSeparatesFullFromTooLarge(t *testing.T) {
	const size = 8 << 10
	r, _ := newRing(t, size)

	huge := bytes.Repeat([]byte{0x55}, size)
	_, err := r.Append(&Record{Handle: 1}, huge)
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized record: err = %v, want ErrRecordTooLarge", err)
	}
	if errors.Is(err, ErrRingFull) {
		t.Fatal("an impossible record reported itself as merely full; a waiting writer would spin forever")
	}

	// A legal record fills the ring and reports ErrRingFull, which IS
	// waitable: reclaiming lets it through.
	ok := bytes.Repeat([]byte{0x66}, MaxRecord(size))
	var full bool
	for i := 0; i < 100 && !full; i++ {
		if _, err := r.Append(&Record{Handle: Handle(i)}, ok); errors.Is(err, ErrRingFull) {
			full = true
		} else if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if !full {
		t.Fatal("the ring never reported full")
	}
	if _, err := r.Reclaim(r.Head()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Append(&Record{Handle: 999}, ok); err != nil {
		t.Fatalf("a maximum-size record must fit a drained ring, even after a pad: %v", err)
	}
}

// The trap the size cap closes: with a record near the ring's own size, a
// pad plus the record cannot fit even in a drained ring, so a writer
// waiting on a packer with nothing left to pack would wait forever. At
// the cap, a drained ring always admits a record whatever the seam.
func TestRingAlwaysAdmitsAMaxRecordWhenDrained(t *testing.T) {
	const size = 16 << 10
	r, _ := newRing(t, size)
	payload := bytes.Repeat([]byte{0x77}, MaxRecord(size))

	// Walk the head to many different offsets relative to the seam, and
	// require a drained ring to accept a full-size record at each.
	for i := 0; i < 40; i++ {
		if _, err := r.Append(&Record{Handle: Handle(i)}, payload); err != nil {
			if !errors.Is(err, ErrRingFull) {
				t.Fatalf("append %d: %v", i, err)
			}
			if _, err := r.Reclaim(r.Head()); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Append(&Record{Handle: Handle(i)}, payload); err != nil {
				t.Fatalf("drained ring refused a maximum-size record at head %d: %v", r.Head(), err)
			}
		}
	}
}

// TestRingReclaimStopsAtAPinnedReader pins the rule the caller used to
// own. Bytes behind the tail become writable immediately, so reclaiming
// past a reader is a torn read of live data rather than a stale answer —
// and the reader here is holding the OLDEST record, which is exactly the
// one a tail sweep would take first.
func TestRingReclaimStopsAtAPinnedReader(t *testing.T) {
	const size = 32 << 10
	r, _ := newRing(t, size)
	payload := bytes.Repeat([]byte{0x88}, MaxRecord(size))

	first := appendN(t, r, 1, payload)
	second := appendN(t, r, 2, payload)
	for i := 3; i <= 6; i++ {
		appendN(t, r, Handle(i), payload)
	}

	r.Pin(first)
	got, err := r.Reclaim(r.Head())
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if got != first {
		t.Fatalf("reclaimed to %d with a reader pinned at %d", got, first)
	}
	// The pinned record must still read back correctly.
	if b, ok := r.At(first, len(payload)); !ok || !bytes.Equal(b, payload) {
		t.Fatalf("pinned record became unreadable (ok=%v)", ok)
	}

	// Releasing the oldest pin lets the tail move to the next holder.
	r.Pin(second)
	r.Unpin(first)
	got, err = r.Reclaim(r.Head())
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if got != second {
		t.Fatalf("reclaimed to %d, want the next pinned position %d", got, second)
	}

	r.Unpin(second)
	got, err = r.Reclaim(r.Head())
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if got != r.Head() {
		t.Fatalf("with nothing pinned the tail should reach the head, got %d", got)
	}
}

// TestRingPromotionIsASubtraction pins the rule that replaced discrete
// levels: an extent's age is how far behind the head it sits, so what is
// eligible to pack is whatever exceeds the promotion distance. Nothing is
// copied between levels and nothing tracks a level count.
func TestRingPromotionIsASubtraction(t *testing.T) {
	const size = 64 << 10
	const distance = 16 << 10
	r, _ := newRing(t, size)
	payload := bytes.Repeat([]byte{0x99}, MaxRecord(size))
	unit := uint64(ringRecHdr + len(payload))

	// Below the distance nothing is old enough, which is the short-session
	// case: the seal at exit takes everything.
	for r.Used() < distance {
		appendN(t, r, 1, payload)
		if got := r.Promotable(distance); r.Used() <= distance && got != 0 {
			t.Fatalf("promotable %d with only %d used against a %d distance", got, r.Used(), distance)
		}
	}

	// Past it, exactly the excess is eligible, and it starts at the tail.
	appendN(t, r, 2, payload)
	want := r.Used() - distance
	if got := r.Promotable(distance); got != want {
		t.Fatalf("promotable %d, want %d", got, want)
	}
	from, to := r.PromotableRange(distance)
	if from != r.Tail() {
		t.Fatalf("promotion starts at %d, not the tail %d", from, r.Tail())
	}
	if to-from != want {
		t.Fatalf("promotion range covers %d bytes, want %d", to-from, want)
	}

	// Reclaiming what was promoted drops the ring back under the distance.
	if _, err := r.Reclaim(to); err != nil {
		t.Fatal(err)
	}
	if got := r.Promotable(distance); got != 0 {
		t.Fatalf("promotable %d after reclaiming the eligible range", got)
	}
	_ = unit
}

// The shipped sizes must leave a writer runway: a ring sized exactly at
// its trigger blocks the instant packing starts, every cycle.
func TestDefaultRingLeavesRunwayAboveThePromotionDistance(t *testing.T) {
	if DefaultRingSize <= DefaultPromotionDistance {
		t.Fatalf("ring %d must exceed the promotion distance %d", DefaultRingSize, DefaultPromotionDistance)
	}
	if runway := DefaultRingSize - DefaultPromotionDistance; runway < MaxRecord(DefaultRingSize) {
		t.Fatalf("runway %d is smaller than one maximum record %d", runway, MaxRecord(DefaultRingSize))
	}
}
