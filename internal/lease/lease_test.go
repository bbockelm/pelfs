package lease

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path"
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
// stays quiet during the test. Every test that does not care which branch
// it is on takes "main".
func slowOpts(store pelicanobj.Store, session string) Options {
	return Options{Store: store, Session: session, Branch: "main", TTL: time.Hour, RenewInterval: time.Hour}
}

// mainKey is where slowOpts' lease lands.
func mainKey(t *testing.T) string {
	t.Helper()
	k, err := BranchKey("main")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAcquireReleaseCycle(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	key := mainKey(t)

	l, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if l.Key() != key {
		t.Fatalf("Key() = %q, want %q", l.Key(), key)
	}
	if _, err := store.StatKey(ctx, key); err != nil {
		t.Fatalf("lease object missing after acquire: %v", err)
	}
	// The v0.1.0 whole-volume object is NEVER written. Writing it too
	// would make two v0.2 writers on different branches exclude each other
	// through the legacy key — the exact false exclusion the per-branch
	// key exists to remove — so this is a rule, not an accident.
	if _, err := store.StatKey(ctx, VolumeKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acquiring a branch lease wrote the legacy volume lease (%s): %v", VolumeKey, err)
	}
	if err := l.Release(ctx); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := store.StatKey(ctx, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lease object should be gone after release, got %v", err)
	}
}

// TestDifferentBranchesDoNotExclude is the point of the per-branch key: two
// writers that will never touch the same ref no longer refuse each other.
//
// v0.1.0 kept one object for the whole prefix, so the second Acquire here
// returned ErrHeld naming the first — a refusal with no race behind it,
// which is what made `pelfs branch` ship with a warning attached.
func TestDifferentBranchesDoNotExclude(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	optsA := slowOpts(store, "sess-main")
	a, err := Acquire(ctx, optsA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(ctx)

	optsB := slowOpts(store, "sess-dev")
	optsB.Branch = "dev"
	b, err := Acquire(ctx, optsB)
	if err != nil {
		t.Fatalf("a writer on another branch was refused: %v", err)
	}
	defer b.Release(ctx)

	if a.Key() == b.Key() {
		t.Fatalf("both branches took the same object %q", a.Key())
	}
	// Both records are on the federation at once, each naming its own
	// branch: the concurrency is real rather than one holder having
	// silently displaced the other.
	for _, l := range []*Lease{a, b} {
		info, _, err := read(ctx, store, l.Key())
		if err != nil {
			t.Fatalf("read %s: %v", l.Key(), err)
		}
		if info.Session != l.info.Session || info.Branch != l.opts.Branch {
			t.Fatalf("%s holds %+v, want session %s on branch %s",
				l.Key(), info, l.info.Session, l.opts.Branch)
		}
	}
}

// TestBranchKeyRejectsWhatTheRefSpaceRejects: the lease key space borrows
// refs.ValidateName rather than growing a second rule that could drift
// from it. Two of the clauses matter here for reasons of their own — a
// separator would put the lease outside meta/ entirely, and a ".tmp"
// suffix is skipped by every listing that sweeps the key space, including
// the one that decides whether a prefix holds a retired-format volume.
func TestBranchKeyRejectsWhatTheRefSpaceRejects(t *testing.T) {
	for _, bad := range []string{"", "../refs/main", "a/b", ".", "..", "main.tmp", "ma\tin"} {
		if _, err := BranchKey(bad); err == nil {
			t.Errorf("BranchKey(%q) was accepted; a name the ref space refuses must not become a lease key", bad)
		}
	}
	// And a valid one lands under meta/, is not the legacy object, and is
	// recognized by the sweep that must not mistake it for retired
	// metadata.
	key, err := BranchKey("main")
	if err != nil {
		t.Fatal(err)
	}
	if key == VolumeKey {
		t.Fatal("a branch lease collided with the legacy volume lease")
	}
	if got, want := path.Dir(key), Dir; got != want {
		t.Fatalf("lease key %q is under %q, want %q", key, got, want)
	}
	if !IsLeaseObject(path.Base(key)) || !IsLeaseObject(path.Base(VolumeKey)) {
		t.Fatalf("IsLeaseObject does not recognize its own keys (%q, %q)", key, VolumeKey)
	}
	if IsLeaseObject("20260101T000000Z-host-deadbeef") {
		t.Fatal("IsLeaseObject claimed a retired-format session directory; that mistake initializes a new " +
			"volume over somebody's data")
	}
}

// TestAcquireRequiresABranch: there is no whole-volume lease to fall back
// on, so a caller that cannot say what it is about to move has nothing to
// lock, and silently locking "" would be a shared key by another name.
func TestAcquireRequiresABranch(t *testing.T) {
	store := newStore(t)
	opts := slowOpts(store, "sess-a")
	opts.Branch = ""
	if _, err := Acquire(context.Background(), opts); err == nil {
		t.Fatal("Acquire with no branch succeeded")
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
		Store: store, Session: "sess-a", Branch: "main",
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
	if _, err := store.StatKey(ctx, mainKey(t)); err != nil {
		t.Fatalf("thief's lease should survive our release: %v", err)
	}
}

// TestUnparseableLeaseStillLive: liveness must work off the server mtime
// even when the record cannot be parsed.
func TestUnparseableLeaseStillLive(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	if err := store.Put(ctx, mainKey(t), strings.NewReader("not json at all")); err != nil {
		t.Fatal(err)
	}
	_, err := Acquire(ctx, slowOpts(store, "sess-b"))
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("acquire over fresh unparseable lease: err = %v, want ErrHeld", err)
	}
}

// legacyHolder writes the v0.1.0 whole-volume lease record directly. There
// is no other way to produce one: this release never writes that key, so a
// mixed-version federation has to be simulated at the object level.
func legacyHolder(t *testing.T, store pelicanobj.Store, session string, ttl time.Duration) {
	t.Helper()
	// No Branch field, which is the whole difficulty: a v0.1.0 writer's
	// record does not say what it is writing, so it has to be assumed to
	// be writing anything.
	data, err := json.MarshalIndent(&Info{
		Session: session, Hostname: "v010-box", PID: 4242,
		Acquired: time.Now().UTC(), Renewed: time.Now().UTC(),
		TTLSecs: ttl.Seconds(),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), VolumeKey, strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
}

// TestLiveVolumeLeaseExcludesEveryBranch is the mixed-version rule's first
// half: a v0.1.0 writer holds one object for the whole prefix and its
// record names no branch, so it excludes everybody. Assuming otherwise
// would be guessing that the invisible client is somewhere else.
func TestLiveVolumeLeaseExcludesEveryBranch(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	legacyHolder(t, store, "v010-writer", time.Hour)

	for _, branch := range []string{"main", "dev"} {
		opts := slowOpts(store, "sess-new")
		opts.Branch = branch
		_, err := Acquire(ctx, opts)
		if !errors.Is(err, ErrHeld) {
			t.Fatalf("branch %s: err = %v, want ErrHeld", branch, err)
		}
		if !strings.Contains(err.Error(), "v010-box") {
			t.Errorf("branch %s: the refusal must name the holder, or a user cannot act on it: %v", branch, err)
		}
		if !strings.Contains(err.Error(), VolumeKey) {
			t.Errorf("branch %s: the refusal must name WHICH object is held, since --steal-lease will not "+
				"clear this one: %v", branch, err)
		}
	}
}

// TestStealLeaseDoesNotTouchTheVolumeLease: --steal-lease is about the
// branch in front of you. The legacy object locks a volume on behalf of a
// client whose branch is unknown, so proceeding past it is a different
// decision with a different blast radius and takes its own flag.
func TestStealLeaseDoesNotTouchTheVolumeLease(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	legacyHolder(t, store, "v010-writer", time.Hour)

	stealing := slowOpts(store, "sess-new")
	stealing.Steal = true
	if _, err := Acquire(ctx, stealing); !errors.Is(err, ErrHeld) {
		t.Fatalf("--steal-lease walked past the volume lease: err = %v, want ErrHeld", err)
	}

	ignoring := slowOpts(store, "sess-new")
	ignoring.IgnoreVolumeLease = true
	l, err := Acquire(ctx, ignoring)
	if err != nil {
		t.Fatalf("IgnoreVolumeLease: %v", err)
	}
	defer l.Release(ctx)

	// IGNORED, NOT STOLEN, and this is the conservative half of the rule:
	// the legacy record is left byte-for-byte where it was, so a v0.1.0
	// client that is merely slow rather than dead still holds what it
	// thinks it holds, and the next writer here is refused again unless it
	// too says so out loud.
	info, _, err := read(ctx, store, VolumeKey)
	if err != nil {
		t.Fatalf("the volume lease was disturbed: %v", err)
	}
	if info.Session != "v010-writer" || info.Hostname != "v010-box" {
		t.Fatalf("the volume lease was rewritten: %+v", info)
	}
}

// TestAnExpiredVolumeLeaseIsNoObstacle: the legacy object is judged by the
// same TTL rule as any other lease, so a v0.1.0 client that died leaves
// nothing permanent behind and no flag is needed once its TTL is out.
func TestAnExpiredVolumeLeaseIsNoObstacle(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	legacyHolder(t, store, "v010-dead", 100*time.Millisecond)
	time.Sleep(250 * time.Millisecond)

	l, err := Acquire(ctx, slowOpts(store, "sess-new"))
	if err != nil {
		t.Fatalf("acquire past an expired volume lease: %v", err)
	}
	defer l.Release(ctx)
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
	key     string // the lease object to fire on
	mu      sync.Mutex
	armed   bool
	usurper []byte
}

func (s *loseOnceStore) Put(ctx context.Context, key string, r io.Reader) error {
	if err := s.Store.Put(ctx, key, r); err != nil {
		return err
	}
	s.mu.Lock()
	fire := s.armed && key == s.key
	if fire {
		s.armed = false
	}
	s.mu.Unlock()
	if fire {
		// Somebody else's renewal, landing before our caller reads back.
		return s.Store.Put(ctx, s.key, strings.NewReader(string(s.usurper)))
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
		Session: "sess-holder", Hostname: "elsewhere", PID: 1, Branch: "main",
		Acquired: time.Now().UTC(), Renewed: time.Now().UTC(),
		TTLSecs: time.Hour.Seconds(),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	opts := slowOpts(&loseOnceStore{Store: base, key: mainKey(t), armed: true, usurper: usurper}, "sess-thief")
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
