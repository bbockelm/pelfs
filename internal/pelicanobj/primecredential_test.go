package pelicanobj

import (
	"context"
	"testing"
	"time"
)

// TestPrimeCredentialIsBestEffort pins the one property that matters more
// than whether priming succeeds: it must never stop a mount.
//
// Priming is a convenience — it moves the OIDC device flow to mount time,
// where someone is watching, instead of letting it interrupt filesystem I/O
// later. Every operation still acquires its own credential if this does
// nothing. So each way it can fail (an unusable prefix, a federation that
// does not answer, a caller that has already given up) has to return quietly
// rather than propagate.
func TestPrimeCredentialIsBestEffort(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{"empty prefix", ""},
		{"not a URL", "://not a url"},
		{"unsupported scheme", "file:///tmp/nope"},
		{"federation that will not resolve", "pelican://pelfs-nonexistent.invalid/prefix"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Bound the attempt: a hostname that does not resolve should
			// fail fast, but the test must not hang if it does not.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			done := make(chan struct{})
			go func() {
				defer close(done)
				// The contract is the absence of a panic and of any return
				// value a caller could mistake for fatal.
				primeCredential(ctx, tc.prefix)
			}()

			select {
			case <-done:
			case <-time.After(45 * time.Second):
				t.Fatal("primeCredential blocked past its context deadline; a mount would hang here")
			}
		})
	}
}

// TestPrimeCredentialHonorsCancellation covers the shutdown case: a mount
// torn down while priming is still waiting on a federation must not be held
// up by it.
func TestPrimeCredentialHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already gone before we start

	done := make(chan struct{})
	go func() {
		defer close(done)
		primeCredential(ctx, "pelican://pelfs-nonexistent.invalid/prefix")
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("primeCredential ignored a cancelled context")
	}
}
