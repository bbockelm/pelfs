// Package mounterr latches the first moment a pelfs mount answered the
// PAYLOAD with an I/O error it could not explain.
//
// # Why this is a package and not a field
//
// The two frontends -- internal/rawfuse over /dev/fuse and
// internal/vfsbilly under the loopback NFS server -- each have exactly
// one place where a Go error they do not recognize is turned into the
// filesystem's "something broke" answer: EIO on FUSE, NFS3ERR_IO on NFS.
// Neither of them knows anything about HTCondor, and neither should; but
// that instant is the ONLY point in the program where the failure has
// already become the payload's problem, which is precisely the event a
// job supervisor needs to hear about. So the frontends report it here,
// and whoever is running the session subscribes.
//
// # Why it latches
//
// One untranslatable error is almost never one operation. A broken file
// answers every read a `tar` issues, and a workload can produce
// thousands of these in a second. What a supervisor needs is the FIRST
// one, with its message, exactly once -- so this records the first and
// silently drops the rest, and the fast path for "already fired" is a
// single atomic load with no allocation, because it sits on a
// per-operation path.
//
// # Why the subscriber runs on its own goroutine
//
// The handler ends up talking to a condor_starter over a socket. Calling
// it inline would put a network round trip inside a FUSE read handler,
// so a wedged starter would convert "the mount reported an error" into
// "the mount hung" -- the exact failure the reporting exists to catch.
// The handler therefore runs on a goroutine of its own, once.
package mounterr

import (
	"sync"
	"sync/atomic"
	"time"
)

// Frontend names the binding that produced the error, because the two
// answer through different kernel interfaces and an operator reading a
// hold reason wants to know which one they are looking at.
const (
	FrontendFUSE = "fuse"
	FrontendNFS  = "nfs"
)

// Event is the first failure a mount surfaced to its payload.
type Event struct {
	Frontend string
	Err      error
	At       time.Time
}

// Latch records the first Event and notifies at most one subscriber.
// The zero value is ready to use.
type Latch struct {
	// fired is read on every filesystem error, so it is the ONLY thing
	// the already-latched path touches.
	fired atomic.Bool

	mu sync.Mutex
	ev Event
	fn func(Event)
}

// Fail records that the mount answered err to the payload. Every call
// after the first is a single atomic load and allocates nothing.
func (l *Latch) Fail(frontend string, err error) {
	if l.fired.Load() {
		return
	}
	l.mu.Lock()
	if l.fired.Load() {
		l.mu.Unlock()
		return
	}
	ev := Event{Frontend: frontend, Err: err, At: time.Now()}
	l.ev = ev
	fn := l.fn
	// Published LAST, so a concurrent Fired() that sees true also sees a
	// complete event.
	l.fired.Store(true)
	l.mu.Unlock()
	if fn != nil {
		go fn(ev)
	}
}

// OnFirst registers fn as the handler for the first failure, replacing
// any previous one. If the latch has ALREADY fired, fn is called with
// the recorded event straight away -- a subscriber that arrives late
// still learns what happened, which matters because the mount is serving
// before the session finishes wiring itself up.
func (l *Latch) OnFirst(fn func(Event)) {
	l.mu.Lock()
	l.fn = fn
	fired, ev := l.fired.Load(), l.ev
	l.mu.Unlock()
	if fired && fn != nil {
		go fn(ev)
	}
}

// Fired returns the recorded event and whether there is one.
func (l *Latch) Fired() (Event, bool) {
	if !l.fired.Load() {
		return Event{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ev, true
}

// Rearm clears the latch and forgets the subscriber.
//
// It is called by a session as it starts serving, not only by tests: a
// process serves one mount, and a mount that has just come up has not
// failed yet regardless of what any earlier mount in this process did.
// (It is also what keeps a test binary, which mounts many times,
// honest.)
func (l *Latch) Rearm() {
	l.mu.Lock()
	l.fired.Store(false)
	l.ev = Event{}
	l.fn = nil
	l.mu.Unlock()
}

// std is the process-wide latch. There is one because there is one mount
// per pelfs process and the frontends have nothing to hang an instance
// off: a raw FUSE handler and a billy adapter are constructed in
// different packages, by different code paths, neither of which is given
// the session.
var std Latch

// Fail records the first error a mount surfaced to its payload.
func Fail(frontend string, err error) { std.Fail(frontend, err) }

// OnFirst subscribes to the process-wide latch.
func OnFirst(fn func(Event)) { std.OnFirst(fn) }

// Fired reports the process-wide latch's recorded event.
func Fired() (Event, bool) { return std.Fired() }

// Rearm resets the process-wide latch.
func Rearm() { std.Rearm() }
