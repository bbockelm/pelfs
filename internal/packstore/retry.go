package packstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// Operational robustness for federation I/O: retry with backoff on
// failure, and log every failed attempt and every slow operation. The
// pelican client retries some transport errors internally; this layer
// covers the failures that surface anyway — origin restarts, token
// refresh races, cache 5xxs — with capped exponential backoff plus
// jitter, honoring context cancellation.
const (
	defaultRetries = 8
	backoffBase    = 100 * time.Millisecond
	backoffCap     = 10 * time.Second
	slowThreshold  = 10 * time.Second
)

// The two numbers a sized transfer is judged by. They are vars rather
// than consts only so tests can compress the clock; nothing sets them at
// runtime, and they are not configuration.
var (
	// slowRateFloor is the throughput below which a SIZED transfer is
	// worth mentioning. A flat threshold called a 64 MiB upload slow at
	// 16s, which is simply what that many bytes cost from a home uplink;
	// reporting it teaches the reader to ignore the message. Size-aware,
	// that transfer is unremarkable while a four-minute one is not.
	//
	// It describes the whole UPLINK, not one stream, which is why
	// slowBudget divides it among the transfers sharing it.
	slowRateFloor float64 = 4 << 20 // bytes/second
	// slowLatencyGrace covers the fixed costs of any transfer — director
	// lookup, token, TLS, redirect — before throughput means anything.
	slowLatencyGrace = 5 * time.Second
)

// slowBudget is how long an operation may run before it is reported.
// Unsized operations keep the flat threshold, having nothing to scale
// against.
//
// sharers is how many sized transfers were in flight at once. Each may
// claim only its share of the floor, because a link does not get faster
// when a caller opens more streams across it: at the publish pipeline's
// concurrency of 4 on a 20 Mb/s uplink, every pack upload moves ~0.6
// MiB/s and every one of them was being reported as slow — the same
// cry-wolf the size-aware budget was written to end, one level down.
// Judged against its share, that same run is unremarkable, while a
// single stream that has the link to itself and still crawls is not.
func slowBudget(bytes int64, sharers int) time.Duration {
	if bytes <= 0 {
		return slowThreshold
	}
	if sharers < 1 {
		sharers = 1
	}
	return slowLatencyGrace + time.Duration(float64(bytes)*float64(sharers)/slowRateFloor*float64(time.Second))
}

// link accounts for the sized transfers crossing the uplink at the same
// time. packstore owns the count because packstore is where every
// federation transfer passes through — the publish pipeline knows its
// own concurrency, but a rate floor that only publish could correct
// would be wrong again the moment anything else uploaded in parallel.
var link = sharedLink{inFlight: make(map[*share]struct{})}

type sharedLink struct {
	mu       sync.Mutex
	inFlight map[*share]struct{}
}

// share is one transfer's claim on the link. It records the PEAK number
// of transfers that ran alongside it rather than the count at its start:
// uploads begin staggered, so the first one in would otherwise be judged
// as though it had the whole link to itself for a life it spent sharing.
type share struct{ peak int }

func (l *sharedLink) enter() *share {
	s := &share{}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.inFlight[s] = struct{}{}
	n := len(l.inFlight)
	for o := range l.inFlight {
		if o.peak < n {
			o.peak = n
		}
	}
	return s
}

// peak reports the most transfers s ever shared the link with, itself
// included. Read while s is still in flight, so it covers the whole of
// the transfer being judged.
func (l *sharedLink) peak(s *share) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return s.peak
}

func (l *sharedLink) leave(s *share) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.inFlight, s)
}

// mibPerSecond is throughput in the unit an uplink is judged by, rounded
// to the tenth that is worth reading.
func mibPerSecond(bytes int64, d time.Duration) float64 {
	if bytes <= 0 || d <= 0 {
		return 0
	}
	return math.Round(float64(bytes)/(1<<20)/d.Seconds()*10) / 10
}

// retryOn runs fn up to attempts times. Non-retryable failures (context
// end, not-found — a semantic answer, not a transport fault) return
// immediately. Every failed attempt and every completion slower than
// slowThreshold is logged; the final failure is logged with the attempt
// count.
func retryOn(ctx context.Context, op string, attempts int, fn func() error) error {
	return retryOnSized(ctx, op, 0, attempts, fn)
}

// retryOnSized is retryOn for transfers whose byte count is known, so
// "slow" can be judged against the work done rather than the clock.
func retryOnSized(ctx context.Context, op string, bytes int64, attempts int, fn func() error) error {
	if attempts <= 0 {
		attempts = defaultRetries
	}
	// Only sized transfers are judged by rate, so only they claim a share
	// of the link.
	var sh *share
	if bytes > 0 {
		sh = link.enter()
		defer link.leave(sh)
	}
	start := time.Now()
	backoff := backoffBase
	var err error
	for i := 1; ; i++ {
		err = fn()
		if err == nil {
			sharers := 1
			if sh != nil {
				sharers = link.peak(sh)
			}
			if d := time.Since(start); d > slowBudget(bytes, sharers) {
				switch {
				case bytes > 0 && sharers > 1:
					// A shared link says so: otherwise the reader cannot
					// tell a slow uplink from a busy one, and the rate on
					// the line looks like a tenth of the truth.
					ui.Warn("slow operation: {op} took {duration} for {bytes} at {rate} MiB/s, sharing the link with {others} ({attempts})",
						"op", op, "duration", d, "bytes", ui.ByteCount(bytes),
						"rate", mibPerSecond(bytes, d), "others", ui.Count(sharers-1, "other transfer"),
						"attempts", ui.Count(i, "attempt"))
				case bytes > 0:
					ui.Warn("slow operation: {op} took {duration} for {bytes} at {rate} MiB/s ({attempts})",
						"op", op, "duration", d, "bytes", ui.ByteCount(bytes),
						"rate", mibPerSecond(bytes, d), "attempts", ui.Count(i, "attempt"))
				default:
					ui.Warn("slow operation: {op} took {duration} ({attempts})",
						"op", op, "duration", d, "attempts", ui.Count(i, "attempt"))
				}
			}
			return nil
		}
		if !retryable(ctx, err) {
			// Semantic answers (not-found on a fresh volume, context end)
			// are the caller's to judge; logging FAILED here would cry
			// wolf on every legitimate 404 probe.
			return err
		}
		if i >= attempts {
			break
		}
		sleep := backoff + time.Duration(rand.Int63n(int64(backoff)/2+1))
		ui.Warn("{op} failed (attempt {attempt} of {attempts}, retrying in {backoff}): {error}",
			"op", op, "attempt", i, "attempts", attempts, "backoff", sleep, "error", err)
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (after %s)", op, ctx.Err(), ui.Count(i, "attempt"))
		}
		if backoff *= 2; backoff > backoffCap {
			backoff = backoffCap
		}
	}
	ui.Error("{op} FAILED after {duration} and {attempts}: {error}",
		"op", op, "duration", time.Since(start), "attempts", ui.Count(attempts, "attempt"), "error", err)
	return err
}

// retryable rejects context termination and semantic not-found answers;
// everything else is presumed transient. Not-found must NOT retry: the
// bootstrap probes brand-new volumes, and deletes race repack — both hit
// legitimate 404s that no amount of retrying changes.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if isNotExist(err) {
		return false
	}
	msg := err.Error()
	return !strings.Contains(msg, "404") && !strings.Contains(msg, "not found")
}
