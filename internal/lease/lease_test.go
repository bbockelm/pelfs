package lease

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

func newStore(t *testing.T) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	s, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/ns"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// slowOpts uses a long TTL and renewal interval so the background loop
// stays quiet during the test.
func slowOpts(store pelicanobj.Store, session string) Options {
	return Options{Store: store, Session: session, TTL: time.Hour, RenewInterval: time.Hour}
}

func TestAcquireReleaseCycle(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	l, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := store.StatKey(ctx, Key); err != nil {
		t.Fatalf("lease object missing after acquire: %v", err)
	}
	if err := l.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := store.StatKey(ctx, Key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lease object should be gone after release, got %v", err)
	}
}

func TestSecondClientRefused(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	a, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(ctx)

	_, err = Acquire(ctx, slowOpts(store, "sess-b"))
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("second acquire: err = %v, want ErrHeld", err)
	}
	if !strings.Contains(err.Error(), "sess-a") {
		t.Fatalf("refusal should name the holder: %v", err)
	}
}

func TestExpiredLeaseTakenOver(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	opts := slowOpts(store, "sess-dead")
	opts.TTL = 100 * time.Millisecond
	opts.RenewInterval = time.Hour // never renews: simulates a dead client
	a, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	// Do not release: the holder "crashes".
	_ = a

	time.Sleep(250 * time.Millisecond) // outlive the TTL

	b, err := Acquire(ctx, slowOpts(store, "sess-b"))
	if err != nil {
		t.Fatalf("acquire after expiry: %v", err)
	}
	defer b.Release(ctx)
}

func TestStealLiveLease(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	a, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(ctx)

	opts := slowOpts(store, "sess-b")
	opts.Steal = true
	b, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatalf("steal: %v", err)
	}
	defer b.Release(ctx)
}

func TestRenewalDetectsConflict(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	var mu sync.Mutex
	var conflictHolder *Info
	conflicted := make(chan struct{})

	opts := Options{
		Store: store, Session: "sess-a",
		TTL: time.Hour, RenewInterval: 50 * time.Millisecond,
		OnConflict: func(h *Info) {
			mu.Lock()
			conflictHolder = h
			mu.Unlock()
			close(conflicted)
		},
	}
	a, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Another client steals the lease out from under us.
	time.Sleep(20 * time.Millisecond) // distinct mtime for a distinct ETag
	stealOpts := slowOpts(store, "sess-thief")
	stealOpts.Steal = true
	thief, err := Acquire(ctx, stealOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer thief.Release(ctx)

	select {
	case <-conflicted:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop never noticed the conflict")
	}
	if !a.Conflicted() {
		t.Fatal("Conflicted() should be true")
	}
	mu.Lock()
	holder := conflictHolder
	mu.Unlock()
	if holder == nil || holder.Session != "sess-thief" {
		t.Fatalf("conflict holder = %+v, want sess-thief", holder)
	}

	// Releasing after a conflict must NOT delete the thief's lease.
	if err := a.Release(ctx); err != nil {
		t.Fatalf("Release after conflict: %v", err)
	}
	if _, err := store.StatKey(ctx, Key); err != nil {
		t.Fatalf("thief's lease should survive our release: %v", err)
	}
}

// TestUnparseableLeaseStillLive: liveness must work off the server mtime
// even when the record cannot be parsed.
func TestUnparseableLeaseStillLive(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	if err := store.Put(ctx, Key, strings.NewReader("not json at all")); err != nil {
		t.Fatal(err)
	}
	_, err := Acquire(ctx, slowOpts(store, "sess-b"))
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("acquire over fresh unparseable lease: err = %v, want ErrHeld", err)
	}
}

// TestStealBeatsAnActiveRenewer drives the race that made
// TestRenewalDetectsConflict flaky on slower CI runners. A steal writes
// the record and reads it back to confirm it won, and the holder it is
// stealing from rewrites that same record every RenewInterval -- so the
// verify loses to routine renewal and reports a conflict that is not one.
//
// The holder here renews aggressively, making the collision near-certain
// rather than occasional. --steal-lease means "take it from whoever holds
// it", so losing to the holder's own heartbeat is never an acceptable
// answer.
func TestStealBeatsAnActiveRenewer(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		store := newStore(t)
		holder, err := Acquire(ctx, Options{
			Store: store, Session: "sess-holder",
			TTL: time.Hour, RenewInterval: 2 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("holder acquire: %v", err)
		}
		steal := Options{
			Store: store, Session: "sess-thief",
			TTL: time.Hour, RenewInterval: time.Hour, Steal: true,
		}
		thief, err := Acquire(ctx, steal)
		if err != nil {
			holder.Release(ctx) //nolint:errcheck
			t.Fatalf("iteration %d: steal lost to the holder's renewal loop: %v", i, err)
		}
		thief.Release(ctx)  //nolint:errcheck
		holder.Release(ctx) //nolint:errcheck
	}
}
