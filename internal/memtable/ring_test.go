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
	const size = 8 << 10
	r, _ := newRing(t, size)

	payload := bytes.Repeat([]byte{0xab}, 500)
	var laps int
	for h := Handle(1); h <= 200; h++ {
		pos, err := r.Append(&Record{Handle: h, Inode: uint64(h)}, payload)
		if errors.Is(err, ErrRingFull) {
			// Reclaim everything: the point is that the ring keeps going.
			if err := r.Reclaim(r.Head()); err != nil {
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
	r, _ := newRing(t, 4<<10)
	payload := bytes.Repeat([]byte{0x7f}, 900)
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
	if err := r.Reclaim(r.Head()); err != nil {
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
	const size = 4 << 10
	path := filepath.Join(t.TempDir(), "ring")
	r, err := CreateRing(path, size)
	if err != nil {
		t.Fatal(err)
	}

	payload := bytes.Repeat([]byte{0x11}, 400)
	// Fill, reclaim, and lap so older records sit ahead of the head.
	for i := 0; i < 40; i++ {
		if _, err := r.Append(&Record{Handle: Handle(i), Inode: uint64(i)}, payload); errors.Is(err, ErrRingFull) {
			if err := r.Reclaim(r.Head()); err != nil {
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
	const size = 8 << 10
	path := filepath.Join(t.TempDir(), "ring")
	r, err := CreateRing(path, size)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x22}, 300)
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

	_, live, err := OpenRing(path)
	if err != nil {
		t.Fatalf("OpenRing: %v", err)
	}
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
	const size = 4 << 10
	r, _ := newRing(t, size)
	big := bytes.Repeat([]byte{0x33}, 1200)
	var last uint64
	for i := 0; i < 3; i++ {
		last = appendN(t, r, Handle(i), big)
	}
	// The next record cannot fit before the seam; it must land at the
	// start of the mapping rather than wrapping around it.
	if err := r.Reclaim(r.Head()); err != nil {
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
	r, _ := newRing(t, 64<<10)
	payload := bytes.Repeat([]byte{0x44}, 1000)
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
