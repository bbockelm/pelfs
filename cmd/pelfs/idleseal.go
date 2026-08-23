package main

// Seal on idle: work item U10 of docs/design-webui.md.
//
// # Why a browser can express this at all
//
// docs/design-guiclients.md concluded that seal-on-idle is expressible only
// over SFTP, because "HTTP is stateless and 'the client went away' is
// indistinguishable from 'the user is reading'". That is true of WebDAV and
// it is NOT true here, for one reason: the SPA holds an SSE stream open for
// the life of the tab. An SSE stream is a single long-lived response, so
// when the tab closes, navigates away, or the browser is killed, the TCP
// connection closes and serveEvents returns. "The tab went away" is a real
// event on the same footing as an SSH channel close, and browseServer
// already had to track the set of streams to push state to them.
//
// # What it buys, in the words of the problem it solves
//
// 200 documents at ~2 MB fires NEITHER write-pressure trigger (1 GiB
// staged, 200,000 dirty inodes), so a finished drag-and-drop can sit
// unpublished for up to five minutes — and a browser tab, unlike a mount,
// has no unmount. The user closes the laptop and tells a collaborator the
// data is there. Sealing when the last tab has been gone for half a minute
// closes exactly that window.
//
// # The four requirements, and where each one is met
//
//   - A RECONNECTING BROWSER MUST NOT TRIGGER A SEAL. An SSE stream drops
//     and re-establishes routinely (the page asks for `retry: 1000`), so
//     the trigger cannot be the close event. It is a quiet WINDOW measured
//     from the close, and any stream that appears inside the window clears
//     it: browseServer.streamsIdleSince is zeroed on subscribe and set on
//     the unsubscribe that empties the set. A one-second reconnect gap
//     against a thirty-second window is not close to a decision.
//   - A CLOSED LAPTOP LID MUST EVENTUALLY SEAL. A suspended process runs no
//     ticks, so the window is compared against the CLOCK rather than
//     counted in ticks: one tick after the lid opens, now - idleSince is
//     three hours and the seal runs.
//   - TWO WINDOWS OPEN MEANS ONE CLOSING IS NOT IDLE. idleSince is set only
//     by the unsubscribe that leaves the set EMPTY, so closing one of two
//     tabs is not an event this code can see at all.
//   - A SEAL ALREADY RUNNING MUST NOT BE RE-ENTERED. genSession.checkpoint
//     takes g.mu and holds it across the entire seal, so a second caller
//     would block for minutes and then publish nothing. Two things prevent
//     it: the idle seal runs INLINE on the sealer's own goroutine, so this
//     code can never have two of its own in flight, and it claims the
//     browseServer publish slot first, which is the same slot the
//     "Publish now" button takes and answers a second click with 409.
//
// # Why the pressure path's backoff and not a new one
//
// docs/design-webui.md is explicit that this is not optional. The periodic
// checkpointer already doubles its wait to the snapshot interval when a
// pressure checkpoint fails, because a federation refusing the flip turned
// into "the same warning over and over, ~15 s apart, forever". An idle seal
// retrying every 30 s against a broken federation would reproduce that
// failure exactly, with nobody watching the terminal. So the formula here
// is the same expression as checkpointPeriodically's, and nothing is lost
// by waiting: every change is already durable in the overlay and the seal
// at exit publishes whatever this did not.

import (
	"context"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// idleQuietWindowCap is the longest an idle session waits before sealing.
// docs/design-webui.md's rule is min(30 s, --snapshot-interval): a session
// checkpointing every 10 s should not wait 30 s to notice a closed tab, and
// a session checkpointing every hour still seals half a minute after the
// last tab closes.
const idleQuietWindowCap = 30 * time.Second

// idleHintedWindow is the window a sendBeacon hint shortens to.
//
// The beacon is a HINT AND NEVER THE TRIGGER, which is not caution but the
// specification: sendBeacon is best-effort, browsers drop it under memory
// pressure, and a durability decision must not rest on one. So all it does
// is shorten a wait that is already running — it cannot start one, because
// the window only runs while the stream set is empty, and a beacon from a
// tab that is merely hidden (visibilitychange) arrives while its stream is
// still open and therefore changes nothing.
const idleHintedWindow = 5 * time.Second

// idleHintLead is how long before the stream closed a beacon still counts.
//
// pagehide fires BEFORE the connection tears down, so the beacon's arrival
// almost always precedes the unsubscribe that starts the window by a few
// milliseconds. Comparing the two instants naively would discard every
// beacon that did its job.
const idleHintLead = 5 * time.Second

// idleSampleInterval is how often the sealer looks. It is the same order as
// the event stream's own 500 ms sampling of exactly the same numbers, so it
// adds no measurable load, and it bounds how late a seal can be by one
// second rather than by a fraction of the window.
const idleSampleInterval = time.Second

// idleQuietWindow is min(idleQuietWindowCap, interval), and zero when there
// is no interval at all.
//
// --snapshot-interval 0 means "seal only at unmount", and it is a thing a
// user types on purpose (a session that must publish exactly once, at a
// moment of its own choosing). Idle sealing is automatic publishing, so it
// is off there. A session that wants idle sealing and no periodic
// checkpoints has --snapshot-interval to make long rather than zero.
func idleQuietWindow(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	return min(idleQuietWindowCap, interval)
}

// idleSealer publishes a writable browse session's staged work once the
// last tab has been gone for a quiet window.
//
// Every field except the loop-local state is set at construction. The
// loop-local fields are touched ONLY from the goroutine running run (or,
// in tests, from the goroutine calling step), which is what makes them
// lock-free rather than lucky.
type idleSealer struct {
	b *browseServer
	// pressure is genSession.pressure: staged bytes and dirty inodes, or
	// (-1, -1) while the overlay is being sealed or is gone. Injected so
	// the tests can drive the decision without a volume.
	pressure func() (int64, int)
	// seal is genSession.checkpoint. Same reason.
	seal func(context.Context) (string, error)
	// now is the clock. Injected for the tests, which move it in whole
	// hours rather than sleeping: this repo deleted a timing-based lease
	// test as vacuous once, and a sleep-synchronised test of a
	// thirty-second window would be worse — slow, and green on a machine
	// where the logic is wrong.
	now func() time.Time
	// window is the quiet period; interval is --snapshot-interval, which
	// is the ceiling on the backoff exactly as it is for the pressure path.
	window   time.Duration
	interval time.Duration

	// ---- loop-local state ----

	// sampled is whether lastBytes/lastNodes hold a real reading yet. The
	// FIRST sample is a baseline and not a write: without this flag every
	// session's first sample would differ from the zero value and restart
	// the quiet window, which is a bug that hides itself -- it makes idle
	// sealing look like it works and simply never fires on a session that
	// staged its work before the first sample.
	sampled bool
	// lastBytes/lastNodes are the previous readable sample, and lastChange
	// is when it last differed. That difference is the "no write on any
	// surface" half of the trigger, and it is measured from the overlay
	// rather than from a hook on each surface for two reasons: it is the
	// same number the checkpoint policy already trusts, and it covers
	// surfaces that do not exist yet (U6's WebDAV writes through the same
	// overlay, so a WebDAV upload postpones an idle seal without U6
	// touching this file). A write that changes neither counter would be
	// missed, and the consequence of missing one is a seal that runs
	// sooner — the safe direction.
	lastBytes  int64
	lastNodes  int
	lastChange time.Time
	// backoff and retryAfter are the pressure path's, in the same shape.
	backoff    time.Duration
	retryAfter time.Time
}

func newIdleSealer(b *browseServer, g *genSession, interval time.Duration) *idleSealer {
	s := &idleSealer{
		b:        b,
		pressure: g.pressure,
		seal:     g.checkpoint,
		now:      b.nowTime,
		window:   idleQuietWindow(interval),
		interval: interval,
	}
	s.lastChange = s.now()
	return s
}

// run is the loop. The tick source is a parameter so a test can drive the
// real loop from a channel it controls; runBrowse passes a time.Ticker's.
//
// A closed tick channel ends the loop, and so does a cancelled context —
// and the context is re-checked after a tick, because a ready timer and a
// cancelled context are both ready cases and select picks between them at
// random. checkpointPeriodically makes the same check for the same reason.
func (s *idleSealer) run(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok || ctx.Err() != nil {
				return
			}
			s.step(ctx)
		}
	}
}

// step is one sample, and one seal if the sample says so. It is the whole
// decision, and it is a method rather than a closure inside run so the
// tests can call it directly and assert on one instant at a time.
func (s *idleSealer) step(ctx context.Context) {
	if !s.due() {
		return
	}
	job, _, sessionCtx, ok := s.b.claimIdleJob()
	if !ok {
		// Something else holds the publish slot (the button, or the
		// session is going away). Not an error, and not a state to back
		// off from: whatever holds it is publishing the same overlay.
		return
	}
	// A seal that has STARTED runs on a context the session's stop does not
	// reach, exactly as the periodic checkpointer's does: cancelling
	// mid-seal would abandon uploads already on the wire and leave the
	// branch where it was.
	if sessionCtx == nil {
		sessionCtx = ctx
	}
	summary, err := s.seal(context.WithoutCancel(sessionCtx))
	s.b.finishJob(job, summary, err)
	s.b.publishWG.Done()
	switch {
	case err != nil:
		// The pressure path's expression, character for character in
		// shape: double, floor at the window, ceiling at the interval.
		s.backoff = min(max(2*s.backoff, s.window), s.interval)
		s.retryAfter = s.now().Add(s.backoff)
		ui.Warn("the automatic publish that runs when the last browser tab closes failed, "+
			"retrying in {backoff} (your changes remain safe in the overlay, and Ctrl-C still seals): {error}",
			"backoff", s.backoff.Round(time.Second), "error", err)
	default:
		s.backoff, s.retryAfter = 0, time.Time{}
		// Said out loud, at info, because it is a publish nobody asked
		// for: the terminal is the only place a user who has closed the
		// tab can find out that it happened.
		ui.Info("no browser tab for {window}: published what this session had staged ({summary})",
			"window", s.window, "summary", summary)
		s.lastChange = s.now()
	}
}

// due answers the whole trigger, and it is deliberately one function: the
// four requirements in the file comment are four clauses here, and reading
// them in one place is how a later change keeps them all.
func (s *idleSealer) due() bool {
	if s.window <= 0 {
		return false
	}
	streams, idleSince, hint := s.b.idleSignal()
	// A tab is attached. Nothing else matters, and this is also the clause
	// that makes a reconnect harmless: the stream that came back is in the
	// set, and idleSince was zeroed when it did.
	if streams > 0 || idleSince.IsZero() {
		return false
	}
	staged, nodes := s.pressure()
	if staged < 0 || nodes < 0 {
		// The overlay is mid-seal or gone. Not idle, not dirty, not ours:
		// and the sample is NOT recorded, so a seal in progress cannot be
		// mistaken for a write.
		return false
	}
	now := s.now()
	switch {
	case !s.sampled:
		s.sampled, s.lastBytes, s.lastNodes = true, staged, nodes
	case staged != s.lastBytes || nodes != s.lastNodes:
		s.lastBytes, s.lastNodes, s.lastChange = staged, nodes, now
	}
	if staged == 0 && nodes == 0 {
		// Nothing to publish. checkpoint would fast-path this too, but it
		// would take g.mu to find out, and this runs every second.
		return false
	}
	if now.Before(s.retryAfter) {
		return false
	}
	window := s.window
	// The beacon shortens the wait, and only while the wait is running.
	if !hint.IsZero() && !hint.Before(idleSince.Add(-idleHintLead)) {
		window = min(window, idleHintedWindow)
	}
	// The window runs from whichever came later: the last tab closing, or
	// the last write. "No write on any surface" is a conjunct, not an
	// alternative — a WebDAV client uploading into a session whose tab is
	// closed is not idle.
	quietFrom := idleSince
	if s.lastChange.After(quietFrom) {
		quietFrom = s.lastChange
	}
	return now.Sub(quietFrom) >= window
}
