package main

// Seal on idle (U10), tested on an INJECTED CLOCK and driven one instant at
// a time.
//
// There is no time.Sleep in this file and there must never be one. The
// window under test is thirty seconds and the failure modes are all about
// order — a reconnect inside the window, a second tab, a suspended laptop,
// a retry after a failure — so a sleep-synchronised version would be slow,
// flaky, and green on a machine where the logic is wrong. This repo deleted
// a timing-based lease test as vacuous once; a sleep-based test of a
// duration nobody wants to wait for would have been worse.
//
// The tests call idleSealer.step directly, which is the real decision on the
// real state, with the clock and the two session calls (pressure, seal)
// injected. One test at the bottom drives the real run loop from a channel
// it owns, so the plumbing between the two is covered as well.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/browsesession"
)

// testClock is a clock a test moves. Mutex-guarded because the sealer's
// goroutine reads it in the loop test while the test writes it.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	// A fixed instant, not time.Now(): every assertion below is about
	// differences, and a test that reads the wall clock at all can fail on
	// a leap second or a suspended CI runner.
	return &testClock{at: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.at = c.at.Add(d)
	c.mu.Unlock()
}

// idleFixture is a browseServer with no volume behind it and a recorded
// seal, which is all the trigger needs: the seal itself is
// genSession.checkpoint and has its own tests.
type idleFixture struct {
	t   *testing.T
	clk *testClock
	b   *browseServer
	s   *idleSealer

	mu     sync.Mutex
	staged int64
	nodes  int
	seals  int
	sealed chan struct{} // one send per completed seal
	fail   error
}

func newIdleFixture(t *testing.T, interval time.Duration) *idleFixture {
	t.Helper()
	clk := newTestClock()
	m, err := browsesession.New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newBrowseServer("pelican://fed/pfx", browseArgs{branch: "main", rw: true}, interval, m, 49731, nil)
	if err != nil {
		t.Fatal(err)
	}
	b.now = clk.now
	// A session that is open, writable, and has nothing else to say. The
	// sealer never touches it except through the two injected functions,
	// which is what lets this run with no federation at all.
	b.g = &genSession{rw: true}
	b.phase = "ready"
	b.streamsIdleSince = clk.now()

	f := &idleFixture{t: t, clk: clk, b: b, staged: 4 << 20, nodes: 12, sealed: make(chan struct{}, 8)}
	f.s = &idleSealer{
		b:        b,
		pressure: f.pressure,
		seal:     f.seal,
		now:      clk.now,
		window:   idleQuietWindow(interval),
		interval: interval,
	}
	f.s.lastChange = clk.now()
	return f
}

func (f *idleFixture) pressure() (int64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.staged, f.nodes
}

func (f *idleFixture) seal(context.Context) (string, error) {
	f.mu.Lock()
	f.seals++
	err := f.fail
	f.mu.Unlock()
	select {
	case f.sealed <- struct{}{}:
	default:
	}
	if err != nil {
		return "", err
	}
	return "generation 88", nil
}

func (f *idleFixture) sealCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seals
}

// write moves the overlay's counters, which is how this code learns that
// something wrote on some surface.
func (f *idleFixture) write(bytes int64) {
	f.mu.Lock()
	f.staged += bytes
	f.nodes++
	f.mu.Unlock()
}

// attach and detach are what serveEvents does at its two ends.
func (f *idleFixture) attach() chan struct{} {
	ch, _ := f.b.subscribe()
	return ch
}

func (f *idleFixture) detach(ch chan struct{}) { f.b.unsubscribe(ch) }

// step runs one sample at the current instant.
func (f *idleFixture) step() { f.s.step(context.Background()) }

// TestIdleSealWaitsTheWindowAfterTheLastTabCloses is the base case: a tab
// that closes with staged work seals, and not before the window is up.
func TestIdleSealWaitsTheWindowAfterTheLastTabCloses(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	// Attached: no window is running, however long the session sits there.
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed with a tab attached (%d seals)", f.sealCount())
	}
	f.detach(ch)
	// One second short of the window is still not idle. The exact boundary
	// matters: an off-by-one here is a publish while somebody is typing.
	f.clk.advance(idleQuietWindowCap - time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed %v after the tab closed, before the %v window",
			idleQuietWindowCap-time.Second, idleQuietWindowCap)
	}
	f.clk.advance(time.Second)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("no seal at the window boundary (%d seals)", f.sealCount())
	}
	// And it does not seal again on the next sample: the successful seal
	// moved the quiet mark, so the window restarts.
	f.clk.advance(idleSampleInterval)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("sealed twice in one quiet window (%d seals)", f.sealCount())
	}
	// The page can see what happened, and it says who asked. Read from the
	// publish slot rather than state(), which samples a volume this
	// fixture deliberately does not have.
	f.b.mu.Lock()
	job := f.b.job
	f.b.mu.Unlock()
	if job == nil || job.Reason != "idle" || job.State != "done" {
		t.Fatalf("the idle seal is not on the publish slot: %+v", job)
	}
}

// TestReconnectingBrowserDoesNotTriggerASeal is the requirement that makes
// this mechanism usable at all. An SSE stream drops and re-establishes
// routinely — the page asks for `retry: 1000` — so a design that sealed on
// the close event would publish every time a laptop changed networks.
func TestReconnectingBrowserDoesNotTriggerASeal(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	// Twenty reconnects, each a second apart, spanning far more than the
	// window in total. Not one of them may seal.
	for i := 0; i < 20; i++ {
		f.detach(ch)
		f.clk.advance(time.Second)
		f.step()
		ch = f.attach()
		f.clk.advance(time.Second)
		f.step()
	}
	if f.sealCount() != 0 {
		t.Fatalf("a reconnecting browser triggered %d seal(s) over %v of flapping",
			f.sealCount(), 40*time.Second)
	}
	// The same session, once the tab really goes away, does seal — so the
	// test above is not passing because the trigger is broken.
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("after the last close, %d seals; want 1", f.sealCount())
	}
}

// TestTwoTabsAndOneClosingIsNotIdle: the window is started by the
// unsubscribe that EMPTIES the set, so a second window closing is not an
// event this code can see.
func TestTwoTabsAndOneClosingIsNotIdle(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	a := f.attach()
	b := f.attach()
	f.detach(a)
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed with a second tab still attached (%d seals)", f.sealCount())
	}
	if n, since, _ := f.b.idleSignal(); n != 1 || !since.IsZero() {
		t.Fatalf("idleSignal = (%d, %v); want one stream and no window", n, since)
	}
	f.detach(b)
	f.clk.advance(idleQuietWindowCap)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("the last tab closing did not seal (%d seals)", f.sealCount())
	}
}

// TestClosedLidEventuallySeals. A suspended process runs no ticks, so the
// window has to be compared against the clock rather than counted in
// samples: one tick after the lid opens, three hours have passed.
func TestClosedLidEventuallySeals(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	f.detach(ch)
	// No steps at all for three hours: that is what a suspended process
	// looks like from in here.
	f.clk.advance(3 * time.Hour)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("a session that slept for three hours did not seal (%d seals)", f.sealCount())
	}
}

// TestASealAlreadyRunningIsNotReEntered. genSession.checkpoint holds g.mu
// across the whole seal, so a second caller would block for minutes and
// then publish nothing. The idle sealer takes the same publish slot the
// button takes, and refuses when it cannot have it.
func TestASealAlreadyRunningIsNotReEntered(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap)
	// The button's job, still running.
	f.b.mu.Lock()
	f.b.job = &publishJob{ID: "click", State: "running", Reason: "user", Started: f.clk.now()}
	f.b.mu.Unlock()
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("the idle sealer re-entered a publish that was already running (%d seals)", f.sealCount())
	}
	// It also refuses while the session is going away: teardown's first
	// step is closeStreams, and sealAtExit publishes the rest.
	f.b.mu.Lock()
	f.b.job = nil
	f.b.mu.Unlock()
	f.b.closeStreams()
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("the idle sealer started a seal during teardown (%d seals)", f.sealCount())
	}
}

// TestIdleSealBacksOffLikeThePressurePath. The pressure path exists in this
// shape because one broken CAS produced "the same warning over and over,
// ~15 s apart, forever". An idle seal retrying every 30 s against a broken
// federation would reproduce it with nobody watching.
func TestIdleSealBacksOffLikeThePressurePath(t *testing.T) {
	interval := 2 * time.Minute
	f := newIdleFixture(t, interval)
	f.mu.Lock()
	f.fail = errors.New("the branch head moved under this seal")
	f.mu.Unlock()

	ch := f.attach()
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("no first attempt (%d seals)", f.sealCount())
	}
	// The first backoff is the window; then it doubles, with the snapshot
	// interval as the ceiling — checkpointPeriodically's expression, in the
	// same shape, for the same reason.
	want := []time.Duration{idleQuietWindowCap, 2 * idleQuietWindowCap, interval, interval}
	for i, d := range want {
		if got := f.s.backoff; got != d {
			t.Fatalf("attempt %d: backoff = %v, want %v", i+1, got, d)
		}
		// The failure did not clear the pressure — the staged bytes are
		// still there — so without a backoff the very next sample would
		// try again, which is the "same warning forever" failure this
		// exists to prevent.
		f.clk.advance(idleSampleInterval)
		f.step()
		if f.sealCount() != i+1 {
			t.Fatalf("attempt %d: retried on the next sample instead of backing off", i+1)
		}
		f.clk.advance(d - idleSampleInterval - time.Second)
		f.step()
		if f.sealCount() != i+1 {
			t.Fatalf("attempt %d: retried a second before the %v backoff was up", i+1, d)
		}
		f.clk.advance(time.Second)
		f.step()
		if f.sealCount() != i+2 {
			t.Fatalf("attempt %d: did not retry after %v", i+1, d)
		}
	}
	// A success clears it.
	f.mu.Lock()
	f.fail = nil
	f.mu.Unlock()
	f.clk.advance(interval)
	f.step()
	if f.s.backoff != 0 || !f.s.retryAfter.IsZero() {
		t.Fatalf("a successful seal left backoff %v / retryAfter %v", f.s.backoff, f.s.retryAfter)
	}
}

// TestBeaconShortensTheWaitAndNeverStartsOne. sendBeacon is best-effort by
// specification, so it is a hint: it may shorten a window that is already
// running and it may not start one. A beacon from a merely HIDDEN tab
// arrives with the stream still open, and must change nothing.
func TestBeaconShortensTheWaitAndNeverStartsOne(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	// visibilitychange on a tab the user switched away from: hint recorded,
	// stream still open, nothing happens however long we wait.
	f.b.mu.Lock()
	f.b.beaconAt = f.clk.now()
	f.b.mu.Unlock()
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("a beacon from a hidden tab triggered a seal (%d seals)", f.sealCount())
	}

	// Now the tab really goes: pagehide fires the beacon a moment BEFORE
	// the connection tears down, which is the ordering that matters.
	f.b.mu.Lock()
	f.b.beaconAt = f.clk.now()
	f.b.mu.Unlock()
	f.clk.advance(10 * time.Millisecond)
	f.detach(ch)
	f.clk.advance(idleHintedWindow - time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed before even the hinted window was up (%d seals)", f.sealCount())
	}
	f.clk.advance(time.Second)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("the hint did not shorten the wait to %v (%d seals)", idleHintedWindow, f.sealCount())
	}
}

// TestAStaleBeaconDoesNotShortenALaterWindow: a hint is about the tab that
// sent it. One from an earlier visit must not shorten a window that started
// long afterwards, or the "hint" would effectively be permanent.
func TestAStaleBeaconDoesNotShortenALaterWindow(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	f.b.mu.Lock()
	f.b.beaconAt = f.clk.now()
	f.b.mu.Unlock()
	ch := f.attach()
	f.clk.advance(10 * time.Minute)
	f.detach(ch)
	f.clk.advance(idleHintedWindow + time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("a ten-minute-old beacon shortened this window (%d seals)", f.sealCount())
	}
	f.clk.advance(idleQuietWindowCap)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("the full window did not seal (%d seals)", f.sealCount())
	}
}

// TestAWriteOnAnySurfaceRestartsTheWindow. "The last tab closed" is only
// half the trigger; the other half is that nothing is writing. A WebDAV
// client (U6) uploading into a session whose tab is closed is not idle, and
// the signal for that is the overlay's own counters moving — the same
// numbers the checkpoint policy already trusts.
func TestAWriteOnAnySurfaceRestartsTheWindow(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap - 5*time.Second)
	f.step()
	// Something wrote 20 s into the quiet window.
	f.write(8 << 20)
	f.clk.advance(5 * time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed while a surface was still writing (%d seals)", f.sealCount())
	}
	// The window now runs from the write, not from the close.
	f.clk.advance(idleQuietWindowCap - time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("the window did not restart at the write (%d seals)", f.sealCount())
	}
	f.clk.advance(time.Second)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("no seal a window after the last write (%d seals)", f.sealCount())
	}
}

// TestNothingStagedNeverSeals, and TestAnUnreadableOverlayNeverSeals: the
// two cases where there is nothing to publish or no way to tell.
func TestNothingStagedNeverSeals(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	f.mu.Lock()
	f.staged, f.nodes = 0, 0
	f.mu.Unlock()
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed a clean overlay (%d seals)", f.sealCount())
	}
}

func TestAnUnreadableOverlayNeverSeals(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	// pressure() answers (-1, -1) while the overlay is being sealed or is
	// gone. Neither is a moment to start another seal, and neither is a
	// write.
	f.mu.Lock()
	f.staged, f.nodes = -1, -1
	f.mu.Unlock()
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed on an unreadable overlay (%d seals)", f.sealCount())
	}
	if f.s.sampled || f.s.lastBytes != 0 {
		t.Fatalf("an unreadable sample was recorded as a baseline (sampled %v, bytes %d)",
			f.s.sampled, f.s.lastBytes)
	}
}

// TestSnapshotIntervalZeroDisablesIdleSealing. --snapshot-interval 0 means
// "seal only at unmount", which somebody types on purpose. Idle sealing is
// automatic publishing, so it is off there — and the page says so by
// omitting the field.
func TestSnapshotIntervalZeroDisablesIdleSealing(t *testing.T) {
	if w := idleQuietWindow(0); w != 0 {
		t.Fatalf("idleQuietWindow(0) = %v, want 0", w)
	}
	f := newIdleFixture(t, 0)
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(24 * time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("--snapshot-interval 0 published on its own (%d seals)", f.sealCount())
	}
	// state() samples the volume once one is open; this fixture has none,
	// so the document is read in its "connecting" form -- which is where
	// the idle-seal promise is filled in anyway.
	f.b.mu.Lock()
	f.b.g = nil
	f.b.mu.Unlock()
	if st := f.b.state(); st.IdleSealS != 0 {
		t.Errorf("idle_seal_s = %d with idle sealing off", st.IdleSealS)
	}
}

// TestAShortIntervalShortensTheWindow: the rule is min(30 s, interval), so
// a session checkpointing every ten seconds does not wait thirty to notice
// a closed tab.
func TestAShortIntervalShortensTheWindow(t *testing.T) {
	f := newIdleFixture(t, 10*time.Second)
	if f.s.window != 10*time.Second {
		t.Fatalf("window = %v, want the interval", f.s.window)
	}
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(9 * time.Second)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("sealed before the interval (%d seals)", f.sealCount())
	}
	f.clk.advance(time.Second)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("no seal at the interval (%d seals)", f.sealCount())
	}
	f.b.mu.Lock()
	f.b.g = nil
	f.b.mu.Unlock()
	if st := f.b.state(); st.IdleSealS != 10 {
		t.Errorf("idle_seal_s = %d, want 10", st.IdleSealS)
	}
}

// TestAReadOnlySessionNeverIdleSeals. A read-only browse session has
// nothing to publish and no lease to publish with; the slot refuses it.
func TestAReadOnlySessionNeverIdleSeals(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	f.b.mu.Lock()
	f.b.g = &genSession{rw: false}
	f.b.mu.Unlock()
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(time.Hour)
	f.step()
	if f.sealCount() != 0 {
		t.Fatalf("a read-only session published (%d seals)", f.sealCount())
	}
}

// TestASessionWhoseBrowserNeverAttachedIsIdle. `pelfs browse --rw` on a
// login node cannot open a browser, and once U6 lands a WebDAV client can
// write to this listener with no page at all. Both are idle in the sense
// that matters, and the window runs from the last write.
func TestASessionWhoseBrowserNeverAttachedIsIdle(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	f.write(1 << 20)
	f.clk.advance(idleQuietWindowCap)
	f.step()
	if f.sealCount() != 1 {
		t.Fatalf("a session with no browser never sealed (%d seals)", f.sealCount())
	}
}

// TestTheRunLoopSamplesAndStops covers the plumbing the tests above skip:
// that run() calls step on a tick, and that it returns on a cancelled
// context rather than on the next tick after one.
//
// It synchronises on the seal, never on a duration, so there is nothing to
// flake: the tick is a channel this test writes and the seal is a channel
// it reads.
func TestTheRunLoopSamplesAndStops(t *testing.T) {
	f := newIdleFixture(t, 5*time.Minute)
	ch := f.attach()
	f.detach(ch)
	f.clk.advance(idleQuietWindowCap)

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		f.s.run(ctx, ticks)
		close(done)
	}()
	ticks <- f.clk.now()
	<-f.sealed // the loop did the work; no sleep, no polling
	cancel()
	select {
	case <-done:
	case ticks <- f.clk.now():
		// The loop may take one more tick before it notices the
		// cancellation, since a ready timer and a cancelled context are
		// both ready cases. It must notice on that one.
		<-done
	}
	if got := f.sealCount(); got != 1 {
		t.Fatalf("%d seals after one tick and a cancel; want 1", got)
	}
}

// TestBeaconRouteNeedsAValidSessionInItsBody. sendBeacon cannot set
// X-Pelfs-Session, so the token is in the body — which means this handler,
// not the guard, is what authenticates it.
func TestBeaconRouteNeedsAValidSessionInItsBody(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	before := func() time.Time {
		_, _, hint := f.bs.idleSignal()
		return hint
	}
	if !before().IsZero() {
		t.Fatal("a fresh session already has a beacon hint")
	}
	res := f.do("POST", "/api/v1/beacon", `{"session":"not-a-session"}`, "")
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 401 {
		t.Fatalf("a bogus token got %d, want 401", res.StatusCode)
	}
	if !before().IsZero() {
		t.Fatal("an unauthenticated beacon moved the hint")
	}
	res = f.do("POST", "/api/v1/beacon", `{"session":"`+f.tok+`"}`, "")
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != 204 {
		t.Fatalf("a valid beacon got %d, want 204", res.StatusCode)
	}
	if before().IsZero() {
		t.Fatal("a valid beacon did not record the hint")
	}
}

// TestIdleSealPublishesForRealThroughTheSession is the one test here with a
// volume behind it: the same fixture the rest of browse_test.go uses, a
// real overlay with a real file in it, and genSession.checkpoint as the
// seal. It proves the wiring — that what the trigger calls actually
// publishes a generation — while the tests above prove the trigger.
func TestIdleSealPublishesForRealThroughTheSession(t *testing.T) {
	f := newBrowseFixture(t, true, false)
	clk := newTestClock()
	f.bs.now = clk.now
	f.bs.setReady(f.g, context.Background())
	before := f.g.gfs.Generation()
	writeFile(t, f.g.ov, "idle-seal.txt", strings.Repeat("x", 4096))

	s := newIdleSealer(f.bs, f.g, 5*time.Minute)
	s.now = clk.now
	s.lastChange = clk.now()
	// The page attached and then went away, and nothing wrote afterwards.
	ch, _ := f.bs.subscribe()
	f.bs.unsubscribe(ch)
	clk.advance(idleQuietWindowCap)
	s.step(context.Background())

	st := f.bs.state()
	if st.Publish == nil || st.Publish.Reason != "idle" {
		t.Fatalf("no idle publish job on the state document: %+v", st.Publish)
	}
	if st.Publish.State != "done" {
		t.Fatalf("the idle seal ended as %q: %s", st.Publish.State, st.Publish.Error)
	}
	if got := f.g.gfs.Generation(); got <= before {
		t.Fatalf("generation is still %d after an idle seal (was %d)", got, before)
	}
	if st.StagedFiles != 0 || st.DirtyNodes != 0 {
		t.Errorf("the overlay is still dirty after the idle seal: %d files, %d nodes",
			st.StagedFiles, st.DirtyNodes)
	}
}
