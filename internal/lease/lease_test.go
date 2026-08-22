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

// ---- fencing: the seal-time gate, and the two ways a lease is lost ----

// expiredTTL is the deterministic stand-in for "this machine slept past its
// lease".
//
// A nanosecond, rather than a short duration plus a sleep. The gate's
// arithmetic is the same at 1ns as at two minutes — a gap since the last
// landed renewal, compared against the TTL — so a TTL this small makes every
// test below decidable the instant it runs, with no timer, no sleep and no
// wall-clock margin to lose on a loaded machine. It also makes the record
// this session writes read as EXPIRED to anybody else (isLive), which is
// exactly the state a suspended writer leaves behind.
const expiredTTL = time.Nanosecond

// sleepOpts is a session that has been asleep: it will never renew (the
// interval is an hour, so no tick fires during a test) and its lease is
// already past its TTL.
func sleepOpts(store pelicanobj.Store, session string) Options {
	o := slowOpts(store, session)
	o.TTL = expiredTTL
	return o
}

// countingStore counts the round trips a call makes, so "Fence is free while
// the lease is fresh" can be asserted as a fact rather than assumed from
// reading it.
type countingStore struct {
	pelicanobj.Store
	mu    sync.Mutex
	stats int
	puts  int
}

func (s *countingStore) StatKey(ctx context.Context, key string) (*pelicanobj.KeyInfo, error) {
	s.mu.Lock()
	s.stats++
	s.mu.Unlock()
	return s.Store.StatKey(ctx, key)
}

func (s *countingStore) Put(ctx context.Context, key string, r io.Reader) error {
	s.mu.Lock()
	s.puts++
	s.mu.Unlock()
	return s.Store.Put(ctx, key, r)
}

func (s *countingStore) trips() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats, s.puts
}

// fakeClock drives the freshness gate without sleeping. It is anchored at
// the real now so that the lease RECORDS this session writes stay plausible
// to the liveness rule, which reads a server mtime it cannot fake.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// headUnchanged and headMoved are the two answers a Guard can give. The
// comparison itself belongs to the caller (cmd/pelfs, which reads the ref
// and compares it against its seal anchor); what this package's tests pin is
// what it DOES with each answer.
func headUnchanged(context.Context) (bool, error) { return true, nil }
func headMoved(context.Context) (bool, error)     { return false, nil }

// TestFenceIsFreeWhileTheLeaseIsFresh: the gate must cost nothing on the
// path every healthy seal takes. If it ever costs a round trip, it is a
// round trip per checkpoint on every mount in the world.
func TestFenceIsFreeWhileTheLeaseIsFresh(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{Store: newStore(t)}
	l, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(ctx)

	statsBefore, putsBefore := store.trips()
	for i := 0; i < 5; i++ {
		if err := l.Fence(ctx, headUnchanged); err != nil {
			t.Fatalf("Fence on a fresh lease: %v", err)
		}
	}
	stats, puts := store.trips()
	if stats != statsBefore || puts != putsBefore {
		t.Fatalf("five Fence calls on a fresh lease cost %d stats and %d puts; a fresh, undisputed "+
			"lease must be answerable from memory", stats-statsBefore, puts-putsBefore)
	}
	if st := l.State(); st.Name() != "held" {
		t.Fatalf("state = %q, want held", st.Name())
	}
}

// TestFenceBoundaryIsExactlyTheTTL pins the comparison at the boundary,
// because the two sides of it are different behaviours and an off-by-one
// here is either a needless round trip on every seal or a seal that skips
// the check in the window that matters.
//
// AT the TTL the lease is still live by the same arithmetic every other
// client acquires under (isLive), so a seal must not be held to a stricter
// rule than the one that would let somebody else in.
func TestFenceBoundaryIsExactlyTheTTL(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{Store: newStore(t)}
	clk := newClock()
	opts := slowOpts(store, "sess-a")
	opts.TTL = 2 * time.Minute
	opts.now = clk.now
	l, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(ctx)

	// Exactly the TTL: fresh, no round trip.
	clk.advance(2 * time.Minute)
	statsBefore, _ := store.trips()
	if err := l.Fence(ctx, headUnchanged); err != nil {
		t.Fatalf("Fence at exactly the TTL: %v", err)
	}
	if stats, _ := store.trips(); stats != statsBefore {
		t.Fatalf("Fence revalidated AT the TTL (%d stats); the boundary is inclusive, because a lease "+
			"another client cannot yet take is one this session may still publish under", stats-statsBefore)
	}
	if l.State().Stale {
		t.Fatal("a lease exactly at its TTL reported itself stale")
	}

	// One nanosecond past it: revalidate.
	clk.advance(time.Nanosecond)
	if !l.State().Stale {
		t.Fatal("a lease one nanosecond past its TTL did not report itself stale")
	}
	statsBefore, putsBefore := store.trips()
	if err := l.Fence(ctx, headUnchanged); err != nil {
		t.Fatalf("Fence past the TTL: %v", err)
	}
	stats, puts := store.trips()
	if stats <= statsBefore || puts <= putsBefore {
		t.Fatalf("Fence past the TTL made %d stats and %d puts; it must re-run the renewal check and "+
			"renew, not assume", stats-statsBefore, puts-putsBefore)
	}
	if l.State().RevalidatedAt.IsZero() {
		t.Fatal("a synchronous revalidation left no trace; lease_revalidated_at is how a gap is " +
			"observable after the fact")
	}
}

// TestFenceRefusesWhenAnotherClientTookTheBranch is the sleep scenario's
// core, at this package's level: the usurper is STILL HOLDING when we wake.
//
// This is the case the renewal loop could already recognize — and the seal
// path never asked it. `Conflicted()` had exactly one consumer, a status
// field, so a session in precisely this state would go on to checkpoint,
// publish, and rely on the flip's check-then-put window: a window whose own
// documentation says it is narrow BECAUSE the lease keeps other writers out
// of it.
func TestFenceRefusesWhenAnotherClientTookTheBranch(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	// A holds an expired lease and is not renewing: asleep.
	a, err := Acquire(ctx, sleepOpts(store, "sess-asleep"))
	if err != nil {
		t.Fatal(err)
	}
	// B walks up, finds the lease expired, and takes it — no steal needed,
	// which is the point: B is entitled to it.
	b, err := Acquire(ctx, slowOpts(store, "sess-awake"))
	if err != nil {
		t.Fatalf("the second writer could not take an EXPIRED lease, so this test is not testing the "+
			"scenario it claims: %v", err)
	}
	defer b.Release(ctx)

	err = a.Fence(ctx, headUnchanged)
	if !errors.Is(err, ErrLost) {
		t.Fatalf("Fence after the branch was taken: err = %v, want ErrLost", err)
	}
	// The message has to name the other client and say the work survives,
	// because the only correct action from here is a remount and the user
	// has to be told that publishing nothing did not cost them anything.
	for _, want := range []string{"sess-awake", "main", "intact", "remount"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	if st := a.State(); st.Name() != "lost" || st.Holder == nil || st.Holder.Session != "sess-awake" {
		t.Errorf("state = %+v, want lost and naming sess-awake", st)
	}
	// A second Fence is refused from memory, with no further round trip:
	// once lost, the branch is not un-lost by asking again.
	if err := a.Fence(ctx, headUnchanged); !errors.Is(err, ErrLost) {
		t.Errorf("second Fence: err = %v, want ErrLost", err)
	}
	// And releasing must not delete B's lease.
	if err := a.Release(ctx); err != nil {
		t.Fatalf("Release after a lost lease: %v", err)
	}
	if _, err := store.StatKey(ctx, mainKey(t)); err != nil {
		t.Fatalf("the usurper's lease did not survive our release: %v", err)
	}
}

// TestVanishedLeaseIsResolvedAgainstTheHead is the COME-AND-GONE hole.
//
// B takes the expired lease, does its work, and RELEASES — and release
// DELETES the object, so the only trace of the whole episode is that our
// lease is not there any more. renewOnce used to read that absence as
// "someone deleted our lease; reclaim it below" and do exactly that,
// silently, which made the one interleaving that leaves no witness the one
// interleaving nothing detected.
//
// The absence alone cannot decide it: an operator clearing what looked like
// a stale lease produces the same absence, and making every deletion fatal
// would turn a tidy-up into a lost session. The branch head is what tells
// them apart, so that is what the resolution asks.
func TestVanishedLeaseIsResolvedAgainstTheHead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		head    Guard
		wantErr error
	}{
		{"an operator deleted a stale-looking lease and nothing was published", headUnchanged, nil},
		{"another writer took the lease, published, and released", headMoved, ErrLost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := newStore(t)
			a, err := Acquire(ctx, sleepOpts(store, "sess-asleep"))
			if err != nil {
				t.Fatal(err)
			}
			// Come, and gone: B acquires the expired lease and releases it,
			// which removes the object.
			b, err := Acquire(ctx, slowOpts(store, "sess-passer-by"))
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Release(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := store.StatKey(ctx, mainKey(t)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the setup did not leave the lease object absent: %v", err)
			}

			err = a.Fence(ctx, tc.head)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Fence with an unchanged head: %v (a deletion that published nothing over "+
						"us must be reclaimable)", err)
				}
				// Reclaimed, and reclaimed AS OURS: the record on the object
				// is this session's, so the lease is really held again and
				// Release will remove it.
				info, _, err := read(ctx, store, mainKey(t))
				if err != nil {
					t.Fatalf("the lease was not re-taken: %v", err)
				}
				if info.Session != "sess-asleep" {
					t.Fatalf("re-taken lease holds %q", info.Session)
				}
				if st := a.State(); st.Interrupted || st.Conflicted {
					t.Fatalf("state after a clean reclaim = %+v, want neither interrupted nor lost", st)
				}
				if !a.State().WasInterrupted {
					t.Error("the episode left no latched trace; lease_interrupted is how a session " +
						"reports that its lease object vanished at all")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Fence with a moved head: err = %v, want %v", err, tc.wantErr)
			}
			for _, want := range []string{"ADVANCED", "superseded", "intact", "remount"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal does not mention %q: %v", want, err)
				}
			}
			if st := a.State(); st.Name() != "lost" {
				t.Errorf("state = %q, want lost", st.Name())
			}
		})
	}
}

// TestRenewalRemembersAVanishedLease: the renewal loop still RECLAIMS, so an
// operator's tidy-up costs nothing, but it no longer forgets. After the
// reclaim the object's ETag is ours again and says nothing about who was
// there in between — so the interrupted state is the only thing that can
// make the next seal ask the head, and it must survive a renewal that looks
// entirely successful.
func TestRenewalRemembersAVanishedLease(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	l, err := Acquire(ctx, slowOpts(store, "sess-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(ctx)

	if err := store.Delete(ctx, mainKey(t)); err != nil {
		t.Fatal(err)
	}
	if done := l.renewOnce(); done {
		t.Fatal("renewOnce ended the loop over a deletion; an operator clearing a stale-looking lease " +
			"must not tear the session down")
	}
	if _, err := store.StatKey(ctx, mainKey(t)); err != nil {
		t.Fatalf("renewOnce did not reclaim the object: %v", err)
	}
	if !l.Interrupted() {
		t.Fatal("renewOnce reclaimed silently; the come-and-gone case has no other witness")
	}
	// The lease is FRESH — it was just renewed — so nothing but the
	// interrupted state can make this Fence look at the head.
	if l.State().Stale {
		t.Fatal("the reclaim did not refresh the lease, so this test is not testing what it claims")
	}
	if err := l.Fence(ctx, headMoved); !errors.Is(err, ErrLost) {
		t.Fatalf("Fence on a freshly-renewed but INTERRUPTED lease: err = %v, want ErrLost", err)
	}
}

// TestFenceFailsClosed: a check that cannot be made is not a check that
// passed. Both ways of not knowing — the federation not answering, and a
// caller with no head to compare — refuse, and refuse with their own
// sentinel so a caller can tell "you lost the branch" from "ask again".
func TestFenceFailsClosed(t *testing.T) {
	ctx := context.Background()
	base := newStore(t)
	deaf := &deafStore{Store: base}
	l, err := Acquire(ctx, sleepOpts(deaf, "sess-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		deaf.silence(false)
		_ = l.Release(ctx)
	}()

	deaf.silence(true)
	err = l.Fence(ctx, headUnchanged)
	if !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Fence with an unreachable federation: err = %v, want ErrUnconfirmed", err)
	}
	if errors.Is(err, ErrLost) {
		t.Error("an unreachable federation was reported as a lost lease; the two need different advice")
	}
	deaf.silence(false)

	// And the no-guard case: the lease object is gone, so the question is
	// live, and a caller that cannot answer it must not be told everything
	// is fine.
	if err := base.Delete(ctx, mainKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := l.Fence(ctx, nil); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Fence with no head comparison available: err = %v, want ErrUnconfirmed", err)
	}
}

// deafStore stops answering, which is what a federation looks like from a
// laptop that has woken up on a different network.
type deafStore struct {
	pelicanobj.Store
	mu   sync.Mutex
	deaf bool
}

func (s *deafStore) silence(on bool) {
	s.mu.Lock()
	s.deaf = on
	s.mu.Unlock()
}

func (s *deafStore) quiet() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deaf
}

func (s *deafStore) StatKey(ctx context.Context, key string) (*pelicanobj.KeyInfo, error) {
	if s.quiet() {
		return nil, errors.New("no route to host")
	}
	return s.Store.StatKey(ctx, key)
}

// TestNoLeaseIsUnfenced: a --no-lease session holds no lease, so there is
// nothing to fence with and it keeps exactly the behaviour it always had.
// A nil receiver rather than a flag, so no call site has to remember.
func TestNoLeaseIsUnfenced(t *testing.T) {
	var none *Lease
	if err := none.Fence(context.Background(), nil); err != nil {
		t.Fatalf("Fence on a --no-lease session: %v", err)
	}
	if st := none.State(); st.Name() != "held" || st.Key != "" {
		t.Fatalf("a nil lease reported %+v; the zero State must need no special case at the call site", st)
	}
}

// TestGapSinceSeesAWallClockGap.
//
// WHAT CANNOT BE TESTED HERE, said out loud so nobody "fixes" its absence:
// there is no way in-process to forge a time.Time whose monotonic and wall
// readings DISAGREE. Add shifts both; Round(0) removes the monotonic one
// entirely. So the case gapSince exists for — a suspend across which the
// monotonic clock stood still and the wall clock did not — cannot be built
// from Go's time API, and the max() that handles it is reasoned about at its
// definition rather than pinned here.
//
// What IS testable is that the wall half works at all: an injected clock
// carries no monotonic reading relative to the recorded stamp's, and the gap
// must still come out right rather than as zero.
func TestGapSinceSeesAWallClockGap(t *testing.T) {
	ctx := context.Background()
	clk := newClock()
	opts := slowOpts(newStore(t), "sess-a")
	opts.TTL = time.Minute
	opts.now = clk.now
	l, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(ctx)

	clk.advance(3 * time.Hour)
	if age := l.State().Age; age < 3*time.Hour {
		t.Fatalf("age after a three-hour gap = %s; a gap the process slept through is exactly the gap "+
			"that must not read as zero", age)
	}
}
