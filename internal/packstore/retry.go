package packstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// Operational robustness for federation I/O: retry with backoff on
// failure, and log every failed attempt and every slow operation. The pelican client retries some transport
// errors internally; this layer covers the failures that surface anyway —
// origin restarts, token refresh races, cache 5xxs — with capped
// exponential backoff plus jitter, honoring context cancellation.
const (
	defaultRetries = 8
	backoffBase    = 100 * time.Millisecond
	backoffCap     = 10 * time.Second
	slowThreshold  = 10 * time.Second

	// slowRateFloor is the throughput below which a SIZED transfer is
	// worth mentioning. A flat threshold called a 64 MiB upload slow at
	// 16s, which is simply what that many bytes cost from a home uplink;
	// reporting it teaches the reader to ignore the message. Size-aware,
	// that transfer is unremarkable while a four-minute one is not.
	slowRateFloor = 4 << 20 // bytes/second
	// slowLatencyGrace covers the fixed costs of any transfer — director
	// lookup, token, TLS, redirect — before throughput means anything.
	slowLatencyGrace = 5 * time.Second
)

// slowBudget is how long an operation may run before it is reported.
// Unsized operations keep the flat threshold, having nothing to scale
// against.
func slowBudget(bytes int64) time.Duration {
	if bytes <= 0 {
		return slowThreshold
	}
	return slowLatencyGrace + time.Duration(float64(bytes)/slowRateFloor*float64(time.Second))
}

// plural renders a count with its noun. "(s)" in an operator-facing log
// is a refusal to decide.
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// stamp prefixes operational lines with a wall-clock time. They report
// things that take minutes and interleave with the user's own output, so
// "when did that happen" is the first question asked of them.
func stamp() string { return time.Now().Format("15:04:05") }

// rate renders throughput for a sized transfer, and nothing when the
// size is unknown.
func rate(bytes int64, d time.Duration) string {
	if bytes <= 0 || d <= 0 {
		return ""
	}
	mib := float64(bytes) / (1 << 20)
	return fmt.Sprintf(", %.1f MiB at %.1f MiB/s", mib, mib/d.Seconds())
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
	budget := slowBudget(bytes)
	start := time.Now()
	backoff := backoffBase
	var err error
	for i := 1; ; i++ {
		err = fn()
		if err == nil {
			if d := time.Since(start); d > budget {
				fmt.Fprintf(os.Stderr, "%s pelfs: slow operation: %s took %.1fs%s (%s)\n",
					stamp(), op, d.Seconds(), rate(bytes, d), plural(i, "attempt"))
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
		fmt.Fprintf(os.Stderr, "%s pelfs: %s failed (attempt %d of %d, retrying in %.1fs): %v\n",
			stamp(), op, i, attempts, sleep.Seconds(), err)
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (after %s)", op, ctx.Err(), plural(i, "attempt"))
		}
		if backoff *= 2; backoff > backoffCap {
			backoff = backoffCap
		}
	}
	fmt.Fprintf(os.Stderr, "%s pelfs: %s FAILED after %.1fs and %s: %v\n",
		stamp(), op, time.Since(start).Seconds(), plural(attempts, "attempt"), err)
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
