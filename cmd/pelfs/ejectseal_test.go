package main

// Eject, and how it meets the other thing that publishes on its own.
//
// A mount session can now end because the mount VANISHED — the Finder's
// eject button, or a `umount` from another terminal — and a browse session
// can already publish because nobody is looking at it (idleseal.go). The
// two are easy to mistake for one mechanism, so this file asserts the
// reconciliation rather than leaving it to the comments:
//
//  1. The eject watch does not seal. It contributes ONE EDGE to
//     awaitMountEnd, and everything after that edge is the teardown a
//     signal has always run. Nothing without --finder gains an edge.
//  2. The two triggers share exactly one fact, genSession.ending, so that
//     whichever ends the session, the other starts nothing new across the
//     line. That is the "idle during an eject" direction.
//  3. A teardown reached by an eject JOINS a publish that is already in
//     flight instead of racing it, on the same drain a signal uses. That is
//     the "eject during an idle seal" direction, and it is asserted against
//     a real session with a real checkpoint parked mid-seal.
//
// Nothing here mounts anything. The mount table is never consulted: the
// eject edge is a channel, which is what awaitMountEnd takes, and
// internal/nfsmount's own tests cover the getfsstat side.

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/refs"
)

// ---- 1. the edge -------------------------------------------------------

// Without --finder there is no eject channel, and awaitMountEnd must then
// behave exactly as the bare `<-sigs` it replaced: a nil channel blocks
// forever, so a signal is still the only way out. This is the assertion
// that keeps every scripted mount, every gate and every Linux user where
// they were.
func TestAwaitMountEndWithoutAnEjectWatchWaitsForItsSignal(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	done := make(chan mountEndReason, 1)
	go func() { done <- awaitMountEnd(sigs, nil) }()
	select {
	case r := <-done:
		t.Fatalf("awaitMountEnd returned %v with no signal and no eject watch", r)
	case <-time.After(50 * time.Millisecond):
	}
	sigs <- syscall.SIGTERM
	if r := <-done; r != endSignalled {
		t.Errorf("reason = %v, want endSignalled", r)
	}
}

func TestAwaitMountEndReportsAnEject(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	ejected := make(chan struct{})
	done := make(chan mountEndReason, 1)
	go func() { done <- awaitMountEnd(sigs, ejected) }()
	close(ejected)
	if r := <-done; r != endEjected {
		t.Errorf("reason = %v, want endEjected", r)
	}
}

// A signal and an eject arriving together is a select with two ready
// cases, which Go decides at random — and that is CORRECT here, because
// both answers run the same teardown. What must not happen is a third
// outcome: a block, a panic, or a reason that is neither. Asserted over
// enough rounds that a wedge on either edge shows up.
func TestAwaitMountEndSurvivesBothEdgesAtOnce(t *testing.T) {
	for i := 0; i < 200; i++ {
		sigs := make(chan os.Signal, 1)
		sigs <- syscall.SIGINT
		ejected := make(chan struct{})
		close(ejected)
		switch r := awaitMountEnd(sigs, ejected); r {
		case endSignalled, endEjected:
		default:
			t.Fatalf("round %d: reason = %v, want one of the two ends", i, r)
		}
	}
}

// ---- 2. the shared fact ------------------------------------------------

// beginTeardown is the ONE place the boundary is drawn, and every edge
// goes through it: the payload exiting, a signal, an eject, an outside
// unmount. So the fact every automatic-publish trigger reads has to be set
// there, once, and stay set.
func TestBeginTeardownMakesTheSessionEnding(t *testing.T) {
	g := newGenSession(t, true)
	if g.isEnding() {
		t.Fatal("a session that has not started tearing down reports that it is ending")
	}
	g.beginTeardown()
	if !g.isEnding() {
		t.Error("beginTeardown did not mark the session as ending")
	}
	// Idempotent, exactly as the clock is: two edges can notice at once,
	// and the second must not unset anything or redraw the line.
	g.beginTeardown()
	if !g.isEnding() {
		t.Error("a second beginTeardown unset the flag")
	}
	if (*genSession)(nil).isEnding() {
		t.Error("a nil session reports that it is ending")
	}
}

// IDLE DURING AN EJECT. The idle sealer is armed — the window has passed,
// there is staged work, nothing is attached — and then the session ends.
// It must start nothing: the exit path is about to seal exactly what this
// would have sealed, and a publish begun across the line is a wait nobody
// is left to care about, charged to the teardown instead of the session.
func TestIdleSealStopsOnceTheSessionIsEnding(t *testing.T) {
	f := newIdleFixture(t, 10*time.Second)
	ending := false
	f.s.ending = func() bool { return ending }

	// Armed, and proved armed: without this the test would pass on a
	// sealer that was never going to fire for some other reason.
	f.clk.advance(11 * time.Second)
	if !f.s.due() {
		t.Fatal("the idle sealer is not armed, so this test would assert nothing")
	}

	ending = true
	if f.s.due() {
		t.Error("the idle sealer is still due on a session that is ending")
	}
	f.step()
	if n := f.sealCount(); n != 0 {
		t.Errorf("%d automatic publishes started after the session began ending", n)
	}
	// And the publish slot was never taken, which is what the teardown's
	// own wait looks at: a claimed slot means the exit path joins a publish
	// that should never have started.
	if f.b.job != nil {
		t.Errorf("the publish slot was claimed on an ending session: %+v", f.b.job)
	}
}

// The same boundary reached through the REAL session, so the wiring is
// covered and not only the injected predicate: newIdleSealer takes
// genSession.isEnding, and a refactor that dropped it would leave every
// assertion above green.
func TestNewIdleSealerReadsTheSessionsOwnEndingFlag(t *testing.T) {
	f := newIdleFixture(t, 10*time.Second)
	g := newGenSession(t, true)
	s := newIdleSealer(f.b, g, 10*time.Second)
	if s.ending == nil {
		t.Fatal("newIdleSealer left the ending predicate nil, so no teardown can stop it")
	}
	if s.ending() {
		t.Error("a live session reports that it is ending")
	}
	g.beginTeardown()
	if !s.ending() {
		t.Error("the sealer's predicate did not follow the session into teardown")
	}
}

// ---- 3. eject during a publish that is already running -----------------

// EJECT DURING AN IDLE SEAL. The dangerous direction: work is on the wire
// when the user presses eject, and the teardown that follows must WAIT for
// it rather than walking past it — the next steps close the overlay, and a
// seal cut off there publishes nothing while the changes it was publishing
// sit in a state directory a wrapper is entitled to wipe.
//
// This is asserted against a real session with a real checkpoint parked
// mid-seal (the same gatePutsOn harness TestExitDrainsAnInFlightCheckpoint
// uses), reached through the EJECT edge rather than a signal, with an idle
// sealer attached to the same session so both triggers are live at once.
// The point of running both is that the teardown is the same code either
// way: there is one drain, one seal at exit, and one place that decides
// the session is over.
func TestEjectDuringASealDrainsItAndTheIdleSealerStandsAside(t *testing.T) {
	g := newGenSession(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.reclaimFn = func(string) {}

	rstore, err := refs.New(g.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := &gatePutsOn{
		Store:   g.inner,
		prefix:  "packs/",
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
	g.inner = gate

	// The other trigger, on the same session, armed and ready to fire.
	f := newIdleFixture(t, 10*time.Second)
	f.b.g = g
	f.s.ending = g.isEnding
	f.clk.advance(11 * time.Second)
	if !f.s.due() {
		t.Fatal("the idle sealer is not armed, so half of this test asserts nothing")
	}

	writeFile(t, g.ov, "in-flight.txt", "written before the user pressed eject")
	g.startCheckpointer(ctx, 10*time.Millisecond)
	select {
	case <-gate.held:
	case <-time.After(30 * time.Second * raceSlowdown):
		t.Fatal("no checkpoint ever reached the federation; there is nothing in flight to drain")
	}

	// EJECT. The mount is gone; the watch fires; awaitMountEnd says which
	// edge it was. Everything after this line is the teardown a signal has
	// always run, in the order runMountGen runs it.
	ejected := make(chan struct{})
	close(ejected)
	if r := awaitMountEnd(make(chan os.Signal, 1), ejected); r != endEjected {
		t.Fatalf("reason = %v, want endEjected", r)
	}
	g.beginTeardown()

	// The other trigger stands aside immediately, while the checkpoint it
	// would have collided with is still on the wire.
	if f.s.due() {
		t.Error("the idle sealer is still due after an eject began the teardown")
	}
	f.step()
	if n := f.sealCount(); n != 0 {
		t.Errorf("%d automatic publishes started after the eject", n)
	}

	// And the teardown joins the checkpoint rather than racing it.
	drained := make(chan struct{})
	go func() {
		g.drainCheckpoints()
		close(drained)
	}()
	const held = 500 * time.Millisecond
	select {
	case <-drained:
		t.Fatal("the eject teardown walked past a checkpoint that was still sealing; the next step closes the overlay")
	case <-time.After(held):
	}
	close(gate.release)
	select {
	case <-drained:
	case <-time.After(60 * time.Second * raceSlowdown):
		t.Fatal("the drain never returned")
	}

	// The generation landed: the checkpoint the eject interrupted ran to
	// completion, which is the whole property.
	head, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after the drain: %v", err)
	}
	if head.Superblock.Generation < 1 {
		t.Fatalf("the branch is still at generation %d; the drained checkpoint published nothing",
			head.Superblock.Generation)
	}
	sealed, err := genfs.Open(ctx, genfs.Options{
		Inner: gate.Store, SB: head.Superblock, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("open the drained checkpoint's generation: %v", err)
	}
	defer sealed.Close() //nolint:errcheck
	if _, err := sealed.Lookup(ctx, genfs.RootInode, "in-flight.txt"); err != nil {
		t.Errorf("the drained checkpoint's generation does not carry the write: %v", err)
	}
	// The wait is attributable, so a user who pressed eject and waited can
	// read what they waited on.
	if _, ok := phaseDuration(g.down, "checkpoint drain"); !ok {
		t.Errorf("the teardown breakdown has no drain phase: %q", g.down.sentence("torn down"))
	}
	if s := g.down.sentence("torn down"); !strings.Contains(s, "checkpoint drain") {
		t.Errorf("the teardown line does not name the drain: %s", s)
	}
}
