package lease

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

	// Another client steals the lease out from under us. The holder above
	// renews every 50ms, so this steal really does lose the occasional
	// race and take the retry path — which is how the thirty-minute
	// backoff was found, by hanging here in CI rather than failing.
	//
	// The bound is on the test's own wait: a steal that cannot finish in
	// 30 seconds has stalled, and should say so by name rather than sit
	// until Go's deadline shoots the whole package.
	time.Sleep(20 * time.Millisecond) // distinct mtime for a distinct ETag
	stealOpts := slowOpts(store, "sess-thief")
	stealOpts.Steal = true
	stealCtx, cancelSteal := context.WithTimeout(ctx, 30*time.Second)
	defer cancelSteal()
	thief, err := Acquire(stealCtx, stealOpts)
	if err != nil {
		t.Fatalf("steal: %v (a steal that cannot finish in 30s has STALLED, not lost)", err)
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

// loseOnceStore lets a competing write land between a steal's write and
// its verifying read — the exact interleaving Acquire's retry exists to
// survive — so the retry path can be exercised on demand rather than by
// luck. The natural race is real but narrow (it needs a renewal to fall
// inside one write-then-read), which is why the test that tried to
// provoke it by timing was dropped in df54b95 as vacuous and prone to
// hanging.
//
// This is a different question, and a decidable one: not "is the retry
// needed" but "when the retry runs, does it return in a sensible time".
type loseOnceStore struct {
	pelicanobj.Store
	mu      sync.Mutex
	armed   bool
	usurper []byte
}

func (s *loseOnceStore) Put(ctx context.Context, key string, r io.Reader) error {
	if err := s.Store.Put(ctx, key, r); err != nil {
		return err
	}
	s.mu.Lock()
	fire := s.armed && key == Key
	if fire {
		s.armed = false
	}
	s.mu.Unlock()
	if fire {
		// Somebody else's renewal, landing before our caller reads back.
		return s.Store.Put(ctx, Key, strings.NewReader(string(s.usurper)))
	}
	return nil
}

// TestStealRetriesWithoutStalling holds the steal retry to a wall-clock
// bound. The backoff used to be opts.RenewInterval/2, so a steal by a
// caller with a quiet renewal loop -- an hour, which is what slowOpts
// uses and what every other test in this file passes -- slept for THIRTY
// MINUTES between attempts. Nothing failed; the package simply stopped,
// and Go's test deadline eventually shot it. That is how the unit lane
// went down in CI run 32363030647.
//
// Losing the first race is forced here, so this runs the retry every
// time rather than on the unlucky runs that made the old failure look
// like a flake.
func TestStealRetriesWithoutStalling(t *testing.T) {
	ctx := context.Background()
	base := newStore(t)

	holder, err := Acquire(ctx, slowOpts(base, "sess-holder"))
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release(ctx)

	// The record a renewal by the holder would leave behind.
	usurper, err := json.MarshalIndent(&Info{
		Session: "sess-holder", Hostname: "elsewhere", PID: 1,
		Acquired: time.Now().UTC(), Renewed: time.Now().UTC(),
		TTLSecs: time.Hour.Seconds(),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	opts := slowOpts(&loseOnceStore{Store: base, armed: true, usurper: usurper}, "sess-thief")
	opts.Steal = true

	// The bound is the CONTEXT, and it is deliberately enormous relative
	// to the work: three backoffs of 100/200/400ms plus a handful of
	// round trips to a loopback httptest server. There is no assertion on
	// elapsed time, because that is the trap this package has fallen into
	// before (df54b95): a tight wall-clock bound turns a loaded machine
	// into a red build and teaches everyone to ignore it.
	//
	// What separates pass from fail here is three orders of magnitude,
	// not a margin. If the backoff is derived from opts.RenewInterval
	// again, this steal sleeps RenewInterval/2 — thirty minutes, with
	// slowOpts' one-hour interval — and no amount of load turns 700ms
	// into 30 seconds. So the test is decidable under any scheduling, and
	// it reports a STALL by name instead of hanging until Go's deadline
	// shoots the package.
	stealCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	start := time.Now()
	thief, err := Acquire(stealCtx, opts)
	if err != nil {
		t.Fatalf("steal after losing one race: %v\n"+
			"a steal that cannot finish in 30s has STALLED, not lost: the retry "+
			"backoff must not scale with the caller's own RenewInterval (it was "+
			"RenewInterval/2, an hour here, so 30m)", err)
	}
	defer thief.Release(ctx)
	t.Logf("steal retried and won in %s", time.Since(start).Round(time.Millisecond))
}
