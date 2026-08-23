package memtable

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
	"time"
)

// What holding the ring across an upload costs a writer, measured rather
// than argued.
//
// The ring region a flush consumed used to be reclaimed the instant the
// batch's locations were installed — before its packs had landed — which
// left a window in which a crash lost the batch (docs/known-issues.md,
// KL-10). Closing that window means the tail cannot advance until the
// batch's Located record is durable, and the Located record waits for the
// uploads. So the fix trades a durability window for BACKPRESSURE, and the
// only honest way to size that trade is against a modelled uplink: on a
// free federation an upload costs nothing and "the writer never waited"
// is unfalsifiable.
//
//	PELFS_RINGHOLD_MEASURE=1 go test ./internal/memtable -run RingHold -v
//
// PELFS_RINGHOLD_LATENCY is the modelled per-PUT round trip in
// milliseconds (0 / 25 / 250 are the three the fix was sized against);
// PELFS_RINGHOLD_MIB is how much unique content to write. Unique content
// on purpose: dedup would make the uplink cheaper than the trade being
// measured.
//
// PELFS_RINGHOLD_RING sets the ring's size in MiB, holding the promotion
// distance fixed, which is to say it sets the RUNWAY. That is the knob the
// trade actually turns on: the runway divided by the pack target is how
// many batches can be published and unjournalled at once, and therefore
// how many uploads can be in flight — so a runway narrower than the
// upload worker count leaves workers idle waiting for a straggler's
// record, which is a pipeline bubble and not a bandwidth cost.
//
// Two numbers come out, and they answer different questions:
//
//   - WRITE THROUGHPUT is what an application sees while it is copying.
//   - TIME TO FIRST BACKPRESSURE is when the mount stops being a local
//     filesystem and starts being an uplink. A mount that streams and a
//     mount that stalls differ in this number, not in the first one.
//
// TOTAL is reported alongside both because it is the number that decides
// whether backpressure is a regression or an accounting change: the bytes
// have to reach the federation either way, and a queue that absorbs them
// early pays for it at the seal.
const (
	defaultHoldLatency = 25 * time.Millisecond
	defaultHoldMiB     = 192
	// holdWrite is the write size, near what a FUSE mount hands down.
	holdWrite = 128 << 10
	// holdFile is how much goes to one inode before moving to the next, so
	// the session looks like a copy of a tree of medium files rather than
	// one enormous append.
	holdFile = 1 << 20
)

type holdResult struct {
	latency time.Duration
	written int64
	write   time.Duration
	flush   time.Duration
	// firstBlockAt is how long the session ran before a write waited on
	// the ring, and firstBlockBytes is how much it had written by then.
	// Zero and -1 mean no write ever waited.
	firstBlockAt    time.Duration
	firstBlockBytes int64
	blocked         int64
	flushes         int64
	packs           int64
	uploadedAtWrite int64
	uploaded        int64
}

func (r holdResult) report(t *testing.T) {
	t.Helper()
	rate := func(n int64, d time.Duration) string {
		if d <= 0 {
			return "instant"
		}
		return fmt.Sprintf("%.2f MiB/s", float64(n)/(1<<20)/d.Seconds())
	}
	t.Logf("modelled per-PUT round trip: %s", r.latency)
	t.Logf("  write phase      %8.2fs  %s (%.2f MiB)",
		r.write.Seconds(), rate(r.written, r.write), float64(r.written)/(1<<20))
	t.Logf("  flush (seal)     %8.2fs", r.flush.Seconds())
	t.Logf("  TOTAL            %8.2fs  %s end to end",
		(r.write + r.flush).Seconds(), rate(r.written, r.write+r.flush))
	if r.firstBlockBytes < 0 {
		t.Logf("  first backpressure: never (no write waited on the ring)")
	} else {
		t.Logf("  first backpressure: %.2fs in, after %.2f MiB",
			r.firstBlockAt.Seconds(), float64(r.firstBlockBytes)/(1<<20))
	}
	t.Logf("  %d blocked writes, %d flushes, %d packs, %.2f MiB uploaded (%.2f MiB of it during the write phase)",
		r.blocked, r.flushes, r.packs,
		float64(r.uploaded)/(1<<20), float64(r.uploadedAtWrite)/(1<<20))
}

func TestMeasureRingHoldBackpressure(t *testing.T) {
	if os.Getenv("PELFS_RINGHOLD_MEASURE") == "" {
		t.Skip("set PELFS_RINGHOLD_MEASURE=1 to run the ring-hold backpressure measurement")
	}
	latency := defaultHoldLatency
	if v := os.Getenv("PELFS_RINGHOLD_LATENCY"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		latency = time.Duration(ms) * time.Millisecond
	}
	total := int64(defaultHoldMiB) << 20
	if v := os.Getenv("PELFS_RINGHOLD_MIB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		total = int64(n) << 20
	}
	ring := DefaultTableSize
	if v := os.Getenv("PELFS_RINGHOLD_RING"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		ring = n << 20
	}
	t.Logf("ring %d MiB, promotion distance %d MiB: %d MiB of runway, %d packs of it",
		ring>>20, DefaultPromotionDistance>>20,
		(ring-int(DefaultPromotionDistance))>>20,
		(int64(ring)-int64(DefaultPromotionDistance))/DefaultPackTarget)
	measureRingHold(t, latency, total, ring).report(t)
}

func measureRingHold(t *testing.T, latency time.Duration, total int64, ring int) holdResult {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	obj := &countingStore{objs: map[string][]byte{}, discard: true, latency: latency}
	s, err := New(Options{
		Dir: dir, TableSize: ring, PromotionDistance: DefaultPromotionDistance,
		Obj: obj, PackCacheBytes: PackCacheDisabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	res := holdResult{latency: latency, firstBlockBytes: -1}
	buf := make([]byte, holdWrite)
	r := rand.New(rand.NewPCG(0x1eafbeef, 0xf10a7))
	start := time.Now()
	var written int64
	for written < total {
		// Unique bytes, generated rather than stored: dedup against an
		// earlier flush would make the uplink cheaper than the trade.
		for i := 0; i < len(buf); i += 8 {
			v := r.Uint64()
			for j := 0; j < 8 && i+j < len(buf); j++ {
				buf[i+j] = byte(v >> (8 * j))
			}
		}
		ino := uint64(written/holdFile) + 1
		off := written % holdFile
		if err := s.Write(ctx, ino, off, buf); err != nil {
			t.Fatal(err)
		}
		written += int64(len(buf))
		if res.firstBlockBytes < 0 && s.Stats().BlockedWrites > 0 {
			res.firstBlockAt = time.Since(start)
			res.firstBlockBytes = written
		}
	}
	res.write = time.Since(start)
	res.written = written
	res.uploadedAtWrite = s.Stats().UploadedBytes

	t1 := time.Now()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	res.flush = time.Since(t1)

	st := s.Stats()
	res.blocked, res.flushes, res.packs, res.uploaded =
		st.BlockedWrites, st.Flushes, st.Packs, st.UploadedBytes
	return res
}
