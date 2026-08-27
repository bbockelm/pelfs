package main

// WHAT A `pelfs browse` SESSION DOES WHEN THE VOLUME WILL NOT OPEN.
//
// The report: "after Ctrl+C and deleting the overlay directory, whenever I
// start read-write, I just get a page that says 'reading the overlay…'.
// Never seems to progress."
//
// Neither half of that sentence was what it looked like. Deleting the
// overlay directory is RECOVERABLE and always was — the next session opens
// a fresh overlay over the published head and re-adopts whatever the
// content store still holds ("recovered N extents from the previous
// session"), which is exactly what it should do. What actually refuses is
// the BRANCH LEASE: a `--rw` session that did not exit cleanly leaves
// meta/lease-<branch>.json behind, it outlives its holder by a TTL, and
// every `--rw` start inside that window is refused by lease.Acquire.
//
// The refusal was correct and INVISIBLE. runBrowse prints the URL and
// serves the page BEFORE it opens the volume (deliberately: a device-flow
// prompt needs somewhere to appear), so by the time the open failed the
// browser was already on its way. The process then exited — inside the
// second it took the tab to attach — and what the user was left with was:
//
//   - a tab whose EventSource is retrying, once a second, against a closed
//     port, forever; and
//   - a durability panel that renders every phase that is not "ready" as
//     "reading the overlay…", so a failed open and a slow one are the same
//     sentence.
//
// The terminal had the reason all along. Nobody was looking at the
// terminal, because the whole point of the verb is that they do not have
// to be.
//
// # The rule this file implements
//
// A failed open is SERVED, not raced. The reason goes on the page, the
// listener stays up long enough for a browser to attach and show it, and
// the exit is orderly so every stream gets `event: bye` rather than a
// dropped connection. Bounded in every direction, because a `pelfs browse`
// that will not stop is a worse bug than the one being fixed:
//
//	no browser ever attaches   exit after browseFailGrace
//	a browser attaches         serve until the tab closes, then
//	                           browseFailLinger, then exit
//	Ctrl-C                     exit now, at any point
//
// The exit code does not change. A script that ran `pelfs browse` and read
// a non-zero status still reads it, a few seconds later.

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/ui"
)

const (
	// browseFailGrace is how long a failed session waits for a browser
	// that has not attached yet. It has to cover "the terminal printed a
	// URL and the user clicked it", or `--open` bringing a cold browser
	// up, and it is paid only on a session that has already failed.
	browseFailGrace = 15 * time.Second

	// browseFailLinger is how long the failed page keeps being served
	// after the last tab has gone. Long enough to survive a reload — the
	// page asks for a one-second EventSource retry, and a user who reads
	// "the branch is held by ..." will often reload before they act on it.
	browseFailLinger = 60 * time.Second

	// browseLingerSample is how often the wait looks at the stream set.
	// The same order as the event stream's own 500 ms sampling, so it adds
	// nothing measurable and bounds how late the exit is by half a second.
	browseLingerSample = 500 * time.Millisecond
)

// lingerAfterFailedOpen serves the failure until a browser has seen it, or
// until it is clear that none will.
//
// It registers its OWN signal handler rather than reusing runBrowse's,
// because runBrowse's is installed at step 4 — after the volume is open —
// and this runs instead of ever reaching it. signal.Stop on the way out
// keeps the registration from outliving the wait.
//
// browseStop is the test's door, the same one runBrowse's own select
// carries: nil in every real build, and a nil channel blocks forever in a
// select, so the case costs nothing.
func (b *browseServer) lingerAfterFailedOpen(origin string) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigs)

	ui.Warn("the volume did not open. This session is still serving {origin} so the page "+
		"can show you why; Ctrl-C to stop it, and it stops on its own once no browser is "+
		"watching.", "origin", origin)

	tick := time.NewTicker(browseLingerSample)
	defer tick.Stop()
	// last is the most recent instant a browser was attached, and it
	// starts now so that a session nobody ever opens still leaves. limit
	// is what that instant is measured against, and it lengthens the
	// first time a stream appears: before that this is waiting for a
	// browser, after it this is waiting for one to come back.
	last, limit := b.nowTime(), browseFailGrace
	for {
		select {
		case <-sigs:
			return
		case <-browseStop:
			return
		case <-tick.C:
			if streams, _, _ := b.idleSignal(); streams > 0 {
				last, limit = b.nowTime(), browseFailLinger
			}
			if b.nowTime().Sub(last) >= limit {
				return
			}
		}
	}
}

// browseOpenFailure names the state directory, and the next step, in a
// failure the PAGE will have to carry.
//
// A terminal error can afford to be a sentence, because the reader is
// standing in a shell with the state directory one command away. A page
// cannot: the reader has a browser and nothing else, and "ref main: ..."
// tells them nothing they can act on. So every failed open leaves here
// with the two facts that make it actionable — where this session's state
// lives, and what to do next — and it is done ONCE, at the one place every
// open failure passes through, rather than at each raise site.
//
// An error that already names the state directory is returned untouched:
// the overlay's generation refusal and the content store's unresolved
// adoptions both build a far better message than this could, naming the
// exact directories to move aside and what that costs. Repeating the path
// under them would only make the page longer.
func browseOpenFailure(err error, stateDir, prefix string) error {
	if err == nil || strings.Contains(err.Error(), stateDir) {
		return err
	}
	if errors.Is(err, lease.ErrHeld) {
		// The lease is the ordinary way into this function, and it is the
		// one failure that is usually not a failure at all: the holder is
		// the user's own killed session, and the answer is to wait or to
		// read instead. Naming BOTH is the point — a message that only
		// offered --steal-lease would teach the reflex that loses data
		// when the holder is real.
		return fmt.Errorf("%w\n"+
			"this session's state is %s.\n"+
			"if that holder is a pelfs you killed, it is gone but its lease is not: "+
			"wait for the expiry above and start again, or start read-only now "+
			"(`pelfs browse --ro`) to read what is published while you wait. "+
			"--steal-lease takes the branch, and is only safe when that client is "+
			"known dead — two writers on one branch corrupt each other",
			err, stateDir)
	}
	return fmt.Errorf("%w\n"+
		"this session's state is %s. `pelfs fsck %s` checks the volume itself; "+
		"moving that directory aside starts a clean session, and discards anything "+
		"this machine has written and not yet published",
		err, stateDir, prefix)
}
