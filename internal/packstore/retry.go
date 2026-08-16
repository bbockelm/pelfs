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

// JuiceFS-style operational robustness for federation I/O (requested
// explicitly: retry-with-backoff on failures, log every failed attempt
// and every slow operation). The pelican client retries some transport
// errors internally; this layer covers the failures that surface anyway —
// origin restarts, token refresh races, cache 5xxs — with capped
// exponential backoff plus jitter, honoring context cancellation.
const (
	defaultRetries = 8
	backoffBase    = 100 * time.Millisecond
	backoffCap     = 10 * time.Second
	slowThreshold  = 10 * time.Second
)

// retryOn runs fn up to attempts times. Non-retryable failures (context
// end, not-found — a semantic answer, not a transport fault) return
// immediately. Every failed attempt and every completion slower than
// slowThreshold is logged; the final failure is logged with the attempt
// count.
func retryOn(ctx context.Context, op string, attempts int, fn func() error) error {
	if attempts <= 0 {
		attempts = defaultRetries
	}
	start := time.Now()
	backoff := backoffBase
	var err error
	for i := 1; ; i++ {
		err = fn()
		if err == nil {
			if d := time.Since(start); d > slowThreshold {
				fmt.Fprintf(os.Stderr, "pelfs: slow operation: %s took %.1fs (%d attempt(s))\n",
					op, d.Seconds(), i)
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
		fmt.Fprintf(os.Stderr, "pelfs: %s failed (attempt %d/%d, retrying in %.1fs): %v\n",
			op, i, attempts, sleep.Seconds(), err)
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return fmt.Errorf("%s: %w (after %d attempt(s))", op, ctx.Err(), i)
		}
		if backoff *= 2; backoff > backoffCap {
			backoff = backoffCap
		}
	}
	fmt.Fprintf(os.Stderr, "pelfs: %s FAILED after %.1fs: %v\n",
		op, time.Since(start).Seconds(), err)
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
