package mounterr

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("the latch never notified its subscriber")
		return Event{}
	}
}

// The whole point: a workload that trips the error path trips it per
// operation, and the supervisor must hear about it once.
func TestLatchFiresExactlyOnce(t *testing.T) {
	var l Latch
	got := make(chan Event, 16)
	l.OnFirst(func(ev Event) { got <- ev })

	first := errors.New("pack 3 is truncated")
	l.Fail(FrontendFUSE, first)
	for i := 0; i < 1000; i++ {
		l.Fail(FrontendFUSE, errors.New("another one"))
	}

	ev := waitFor(t, got)
	if !errors.Is(ev.Err, first) {
		t.Errorf("latched %v, want the first failure", ev.Err)
	}
	if ev.Frontend != FrontendFUSE {
		t.Errorf("frontend %q", ev.Frontend)
	}
	if ev.At.IsZero() {
		t.Error("no timestamp")
	}
	select {
	case extra := <-got:
		t.Fatalf("the latch fired a second time: %v", extra)
	default:
	}
}

// Concurrent failures from many FUSE handlers are one report, and the
// event that wins is complete.
func TestLatchIsSingularUnderConcurrency(t *testing.T) {
	var l Latch
	got := make(chan Event, 64)
	l.OnFirst(func(ev Event) { got <- ev })

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.Fail(FrontendNFS, errors.New("boom"))
			}
		}()
	}
	wg.Wait()
	ev := waitFor(t, got)
	if ev.Err == nil || ev.Frontend == "" || ev.At.IsZero() {
		t.Fatalf("an incomplete event was published: %+v", ev)
	}
	if len(got) != 0 {
		t.Fatalf("%d extra notifications", len(got))
	}
}

// A session that subscribes AFTER the mount has already failed still has
// to learn about it: the frontend is serving before the session finishes
// wiring itself up, and the first read can lose that race.
func TestLateSubscriberStillLearns(t *testing.T) {
	var l Latch
	l.Fail(FrontendFUSE, errors.New("early"))
	got := make(chan Event, 4)
	l.OnFirst(func(ev Event) { got <- ev })
	if ev := waitFor(t, got); ev.Err == nil || ev.Err.Error() != "early" {
		t.Fatalf("late subscriber got %v", ev.Err)
	}
}

// Fired is the synchronous read, for the exit path that has to decide an
// exit code without waiting on a goroutine.
func TestFired(t *testing.T) {
	var l Latch
	if _, ok := l.Fired(); ok {
		t.Fatal("a fresh latch reports a failure")
	}
	l.Fail(FrontendNFS, errors.New("x"))
	ev, ok := l.Fired()
	if !ok || ev.Frontend != FrontendNFS {
		t.Fatalf("Fired = %+v, %v", ev, ok)
	}
}

// Rearm is what a starting session calls, so a process that mounts more
// than once (a test binary, and a future pelfs that remounts) does not
// inherit an earlier mount's verdict.
func TestRearm(t *testing.T) {
	var l Latch
	fired := make(chan Event, 4)
	l.OnFirst(func(ev Event) { fired <- ev })
	l.Fail(FrontendFUSE, errors.New("first"))
	waitFor(t, fired)

	l.Rearm()
	if _, ok := l.Fired(); ok {
		t.Fatal("Rearm left the latch set")
	}
	again := make(chan Event, 4)
	l.OnFirst(func(ev Event) { again <- ev })
	if len(again) != 0 {
		t.Fatal("subscribing after Rearm replayed the old event")
	}
	l.Fail(FrontendNFS, errors.New("second"))
	if ev := waitFor(t, again); ev.Err.Error() != "second" {
		t.Fatalf("got %v", ev.Err)
	}
}

// The already-latched path sits inside every filesystem operation that
// fails. It must be a single atomic load: no formatting, no timestamp,
// no allocation.
func TestSuppressedFailuresAreFree(t *testing.T) {
	var l Latch
	l.Fail(FrontendFUSE, errors.New("first"))
	err := errors.New("and another")
	if n := testingAllocs(func() { l.Fail(FrontendFUSE, err) }); n != 0 {
		t.Errorf("a suppressed failure allocates %v times per call", n)
	}
}

// The package-level latch is what the frontends actually call.
func TestPackageLevelLatch(t *testing.T) {
	Rearm()
	t.Cleanup(Rearm)
	got := make(chan Event, 4)
	OnFirst(func(ev Event) { got <- ev })
	Fail(FrontendFUSE, errors.New("global"))
	if ev := waitFor(t, got); ev.Err.Error() != "global" {
		t.Fatalf("got %v", ev.Err)
	}
	if _, ok := Fired(); !ok {
		t.Error("the package latch did not record the event")
	}
}
