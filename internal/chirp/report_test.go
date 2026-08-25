package chirp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every name pelfs publishes has to survive CHIRP_DELAYED_UPDATE_PREFIX,
// whose shipped default is `Chirp*`. This is the test that stops someone
// renaming an attribute to the obvious `PelfsMountError` and shipping a
// feature that is refused on every stock pool -- refused, moreover,
// without the client being told (jic_shadow.cpp logs and returns a
// non-negative status).
func TestEveryAttributeSurvivesTheDefaultDelayedPrefix(t *testing.T) {
	all := append([]string{AttrMountError, AttrErrorReason}, PeriodicAttrs...)
	for _, name := range all {
		if !matchWild("Chirp*", name) {
			t.Errorf("%s does not match the default CHIRP_DELAYED_UPDATE_PREFIX", name)
		}
		if !strings.HasPrefix(name, "ChirpPelfs") {
			t.Errorf("%s is not in the ChirpPelfs namespace", name)
		}
		if !validName(name) {
			t.Errorf("%s is not a ClassAd identifier", name)
		}
	}
	if len(all) > 100 {
		t.Errorf("%d attributes exceeds CHIRP_DELAYED_UPDATE_MAX_ATTRS", len(all))
	}
}

// The cadence rule, asserted rather than merely documented: everything
// on the timer uses the DELAYED verb, which the starter batches into an
// update it was going to send anyway. An immediate set_job_attr is a
// synchronous round trip through the shadow to the schedd, and a
// thousand mounts doing that on a timer is a denial of service against
// somebody's queue.
func TestPeriodicPublishOnlyUsesDelayedUpdates(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	if err := r.Publish(Mount{Session: "abc", Generation: 7, BytesDown: 100}); err != nil {
		t.Fatal(err)
	}
	seen := s.seen()
	if len(seen) == 0 {
		t.Fatal("nothing was published")
	}
	for _, c := range seen {
		if c.verb != "set_job_attr_delayed" {
			t.Errorf("periodic publish used %q", c.verb)
		}
	}
	if v, ok := s.attr(AttrGeneration); !ok || v != "7" {
		t.Errorf("%s = %q, %v", AttrGeneration, v, ok)
	}
	if v, ok := s.attr(AttrSession); !ok || v != `"abc"` {
		t.Errorf("%s = %q, %v", AttrSession, v, ok)
	}
	if _, ok := s.attr(AttrHeartbeat); !ok {
		t.Error("no heartbeat was published")
	}
}

// An idle mount must not rewrite seven identical attributes a minute.
// Only the heartbeat moves on its own, so a cycle with no activity is
// one write.
func TestUnchangedAttributesAreNotResent(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	m := Mount{Session: "abc", Generation: 7, BytesDown: 100}
	if err := r.Publish(m); err != nil {
		t.Fatal(err)
	}
	first := len(s.seen())
	if first < len(PeriodicAttrs) {
		t.Fatalf("the first publish sent %d attributes, want %d", first, len(PeriodicAttrs))
	}
	// Force the heartbeat to look unchanged by publishing twice within
	// the same second is unreliable; instead check that everything EXCEPT
	// the heartbeat is silent on an unchanged sample.
	if err := r.Publish(m); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.seen()[first:] {
		if c.args[0] != AttrHeartbeat {
			t.Errorf("resent unchanged attribute %s", c.args[0])
		}
	}
	// A sample that HAS moved is sent.
	m.BytesDown = 200
	before := len(s.seen())
	if err := r.Publish(m); err != nil {
		t.Fatal(err)
	}
	var sawBytes bool
	for _, c := range s.seen()[before:] {
		if c.args[0] == AttrBytesDown && c.args[1] == "200" {
			sawBytes = true
		}
	}
	if !sawBytes {
		t.Error("a changed counter was not republished")
	}
}

// The error latch is the one thing that earns the synchronous verb, and
// it must also reach the user log -- the file a person reads without
// running condor_q.
func TestFailIsImmediateAndReachesTheUserLog(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	if err := r.Fail("read /data/x: pack 3 is truncated"); err != nil {
		t.Fatal(err)
	}
	var order []string
	var ulog string
	for _, c := range s.seen() {
		switch c.verb {
		case "ulog":
			ulog = c.args[0]
		case "set_job_attr":
			order = append(order, c.args[0])
		case "set_job_attr_delayed":
			t.Errorf("the error latch used the delayed verb for %s", c.args[0])
		}
	}
	if !strings.Contains(ulog, "pack 3 is truncated") {
		t.Errorf("user-log line was %q", ulog)
	}
	if len(order) != 2 || order[0] != AttrErrorReason || order[1] != AttrMountError {
		t.Fatalf("attribute order was %v; the reason must precede the flag", order)
	}
	if v, _ := s.attr(AttrMountError); v != "true" {
		t.Errorf("%s = %q", AttrMountError, v)
	}
	if v, _ := s.attr(AttrErrorReason); !strings.Contains(v, "truncated") {
		t.Errorf("%s = %q", AttrErrorReason, v)
	}
}

// A job that never wrote `+WantIOProxy = true` gets the immediate verb
// refused by the starter. The attribute still has to arrive -- a few
// minutes later, on the delayed channel -- because the alternative is a
// feature that silently does nothing for everyone who did not read the
// documentation, which is exactly the audience it is for.
func TestFailFallsBackToDelayedWhenUpdatesAreRefused(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.updates = false })
	r := reportFake(t, s, 2*time.Second)
	if err := r.Fail("the mount broke"); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if v, ok := s.attr(AttrMountError); !ok || v != "true" {
		t.Fatalf("%s = %q, %v; the delayed fallback did not land", AttrMountError, v, ok)
	}
	if v, ok := s.attr(AttrErrorReason); !ok || !strings.Contains(v, "the mount broke") {
		t.Fatalf("%s = %q, %v", AttrErrorReason, v, ok)
	}
	var delayedOrder []string
	for _, c := range s.seen() {
		if c.verb == "set_job_attr_delayed" {
			delayedOrder = append(delayedOrder, c.args[0])
		}
	}
	if len(delayedOrder) != 2 || delayedOrder[0] != AttrErrorReason {
		t.Errorf("fallback order was %v; the reason must still precede the flag", delayedOrder)
	}
}

// A pool that has turned delayed updates off as well leaves nothing to
// fall back to. That is an error the caller may report -- but it must
// not be a panic, a hang, or a silent success.
func TestFailWithEverythingRefused(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.updates, s.delayed = false, false })
	r := reportFake(t, s, 2*time.Second)
	err := r.Fail("the mount broke")
	var code Code
	if !errors.As(err, &code) {
		t.Fatalf("got %v, want a protocol code", err)
	}
}

// Latched: a workload that produces ten thousand EIOs must produce one
// report. Nothing else keeps a synchronous schedd write off a
// per-operation path.
func TestFailIsLatched(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	for i := 0; i < 5; i++ {
		if err := r.Fail("boom"); err != nil {
			t.Fatalf("Fail %d: %v", i, err)
		}
	}
	var sets int
	for _, c := range s.seen() {
		if c.verb == "set_job_attr" || c.verb == "set_job_attr_delayed" {
			sets++
		}
	}
	if sets != 2 {
		t.Fatalf("%d attribute writes for 5 failures; want 2", sets)
	}
	if !r.Failed() {
		t.Error("Failed() is false after a report")
	}
}

// Concurrency: Fail from many goroutines is one report.
func TestFailIsLatchedUnderConcurrency(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.Fail("boom") }()
	}
	wg.Wait()
	var sets int
	for _, c := range s.seen() {
		if strings.HasPrefix(c.verb, "set_job_attr") {
			sets++
		}
	}
	if sets != 2 {
		t.Fatalf("%d attribute writes from 16 concurrent failures; want 2", sets)
	}
}

// THE injection test. An error message carries whatever the payload put
// in a filename, so a value that reaches the job ad unquoted -- or
// quoted but still carrying a bare quote, a newline, or a space -- is an
// expression somebody else wrote into somebody else's job ad.
//
// Both layers are checked at once: the chirp word escaping must deliver
// the value as ONE argument (so the attribute name is not displaced and
// no extra argument appears), and the ClassAd quoting must round-trip
// the exact bytes.
func TestStringValuesCannotInjectIntoTheJobAd(t *testing.T) {
	nasty := []string{
		"plain",
		"has a space",
		"has\nnewline",
		"has\ttab",
		`has "quotes"`,
		`has\backslash`,
		`" || true || "`,
		`"; JobStatus = 5; "`,
		"trailing backslash\\",
		"\x00\x01\x1f\x7f control bytes",
		"unicode: héllo → ✓",
		strings.Repeat(`\"`, 40),
	}
	for _, in := range nasty {
		t.Run(strings.ToValidUTF8(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return '.'
			}
			return r
		}, in), "."), func(t *testing.T) {
			s := newFakeStarter(t)
			c := dialFake(t, s)
			if err := c.SetJobAttr("ChirpPelfsProbe", String(in)); err != nil {
				t.Fatalf("send: %v", err)
			}
			seen := s.seen()
			if len(seen) != 1 {
				t.Fatalf("one command produced %d", len(seen))
			}
			got := seen[0]
			if got.verb != "set_job_attr" {
				t.Fatalf("verb %q", got.verb)
			}
			if len(got.args) != 2 {
				t.Fatalf("the value split into %d arguments: %q", len(got.args)-1, got.args)
			}
			if got.args[0] != "ChirpPelfsProbe" {
				t.Fatalf("the attribute name became %q", got.args[0])
			}
			if back := unquoteClassAd(t, got.args[1]); back != in {
				t.Fatalf("round trip: sent %q, the job ad would hold %q", in, back)
			}
		})
	}
}

// The same guarantee for the value that actually carries attacker-shaped
// text in production: the error reason.
func TestErrorReasonIsQuoted(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	reason := `read "/data/a b" failed` + "\n" + `PelfsOwned = true`
	if err := r.Fail(reason); err != nil {
		t.Fatal(err)
	}
	v, ok := s.attr(AttrErrorReason)
	if !ok {
		t.Fatal("no reason attribute")
	}
	if back := unquoteClassAd(t, v); back != reason {
		t.Fatalf("round trip: sent %q, job ad holds %q", reason, back)
	}
}

// A message long enough to blow the starter's 993-byte delayed limit
// must be cut by us, not refused by it: the fallback path is the one a
// job without WantIOProxy takes, and losing the hold because the message
// was verbose would be absurd.
func TestLongReasonStillFitsTheDelayedLimit(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.updates = false })
	r := reportFake(t, s, 2*time.Second)
	if err := r.Fail(strings.Repeat("ünicode error text ", 500)); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	v, ok := s.attr(AttrErrorReason)
	if !ok {
		t.Fatal("the over-long reason was dropped entirely")
	}
	if len(v) > delayedExprMax {
		t.Fatalf("the quoted reason is %d bytes, over the starter's %d", len(v), delayedExprMax)
	}
	if !strings.HasPrefix(unquoteClassAd(t, v), "ünicode error text") {
		t.Error("the truncation lost the beginning of the message")
	}
}

// The ulog channel is a record-structured file, so a message with a
// newline in it would be a second, malformed record.
func TestULogMessagesAreSingleLine(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	if err := r.Fail("line one\nline two\r\nline three"); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.seen() {
		if c.verb != "ulog" {
			continue
		}
		if strings.ContainsAny(c.args[0], "\n\r") {
			t.Fatalf("ulog message contains a line break: %q", c.args[0])
		}
		if !strings.Contains(c.args[0], "line one line two line three") {
			t.Fatalf("ulog message lost its content: %q", c.args[0])
		}
	}
}

// Run does one push immediately: a job that dies in its first minute
// should still say which generation it was reading.
func TestRunPublishesBeforeItsFirstTick(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	published := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		r.Run(ctx, time.Hour, func() Mount {
			once.Do(func() { close(published) })
			return Mount{Session: "s", Generation: 3}
		}, func(err error) { t.Errorf("publish: %v", err) })
	}()
	<-published
	cancel()
	<-done
	if v, ok := s.attr(AttrGeneration); !ok || v != "3" {
		t.Fatalf("%s = %q, %v", AttrGeneration, v, ok)
	}
}

// The starter exports its own prefix setting, which is the only way a
// client can find out that a pool has narrowed it -- the refusal itself
// is invisible.
func TestDelayedPrefixAllows(t *testing.T) {
	t.Setenv("_CHIRP_DELAYED_UPDATE_PREFIX", "")
	if !DelayedPrefixAllows("Anything") {
		t.Error("with no setting exported, nothing should be refused on a guess")
	}
	t.Setenv("_CHIRP_DELAYED_UPDATE_PREFIX", "Chirp*")
	for _, name := range PeriodicAttrs {
		if !DelayedPrefixAllows(name) {
			t.Errorf("%s refused under the default prefix", name)
		}
	}
	if DelayedPrefixAllows("PelfsMountError") {
		t.Error("an unprefixed name was allowed under Chirp*")
	}
	t.Setenv("_CHIRP_DELAYED_UPDATE_PREFIX", "Foo*, Bar")
	if DelayedPrefixAllows(AttrMountError) {
		t.Error("a narrowed prefix did not refuse our namespace")
	}
	if !DelayedPrefixAllows("bar") {
		t.Error("the comparison is case sensitive; HTCondor's is not")
	}
}

func TestExprRendering(t *testing.T) {
	if got := Int(-5); got != "-5" {
		t.Errorf("Int(-5) = %q", got)
	}
	if got := Uint(uint64(1) << 63); got != "9223372036854775807" {
		t.Errorf("Uint clamp = %q", got)
	}
	if Bool(true) != "true" || Bool(false) != "false" {
		t.Error("Bool")
	}
	if got := String("a\nb"); got != `"a\nb"` {
		t.Errorf("String = %q", got)
	}
	if got := String("\x01"); got != `"\001"` {
		t.Errorf("control byte rendered as %q; a short octal escape can be extended by the next digit", got)
	}
	if got := String("\x012"); got != `"\0012"` {
		t.Errorf("String = %q", got)
	}
}

// The mount is still serving while the session tears itself down, so the
// error latch can fire after the reporter has been closed. That call must
// be a silent no-op and must not redial with a cookie Close has erased.
func TestReporterIsInertAfterClose(t *testing.T) {
	s := newFakeStarter(t)
	r := newReporter(s.config(t), 2*time.Second)
	if err := r.Publish(Mount{Session: "a"}); err != nil {
		t.Fatal(err)
	}
	before := len(s.seen())
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Publish(Mount{Session: "b"}); err != nil {
		t.Errorf("Publish after Close: %v", err)
	}
	if err := r.Fail("late failure"); err != nil {
		t.Errorf("Fail after Close: %v", err)
	}
	if n := len(s.seen()); n != before {
		t.Fatalf("%d commands reached the starter after Close", n-before)
	}
}

// The mount-error flag is STICKY: a chirp update is written into the
// schedd's job ad, so it survives the requeue that the recommended
// policy expression causes. Without a per-attempt reset, one bad run
// would requeue every later attempt on the strength of a failure that
// happened somewhere else an hour ago.
func TestBeginClearsAPreviousAttemptsFailure(t *testing.T) {
	s := newFakeStarter(t)

	failed := reportFake(t, s, 2*time.Second)
	if err := failed.Fail("pack 3 is truncated"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.attr(AttrMountError); v != "true" {
		t.Fatalf("%s = %q after a failure", AttrMountError, v)
	}

	// The next attempt of the same job, against the same queue entry.
	next := reportFake(t, s, 2*time.Second)
	if err := next.Begin(); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if v, ok := s.attr(AttrMountError); !ok || v != "false" {
		t.Fatalf("%s = %q, %v; a fresh attempt inherited the last one's verdict", AttrMountError, v, ok)
	}
	// And the reason is deliberately left: Fail writes it before the
	// flag, so a true flag always has this attempt's reason beside it,
	// and a false flag with a stale reason is read by nothing.
	if v, ok := s.attr(AttrErrorReason); !ok || !strings.Contains(v, "truncated") {
		t.Errorf("%s = %q, %v", AttrErrorReason, v, ok)
	}
}

// Begin and Fail must use the SAME channel. The delayed updates are a
// dictionary the starter flushes on its own schedule, so a `false`
// parked there while a `true` went out immediately would land in the
// wrong order and revert the failure in the queue.
func TestBeginAndFailShareOneChannel(t *testing.T) {
	for _, updates := range []bool{true, false} {
		name := "immediate"
		if !updates {
			name = "delayed fallback"
		}
		t.Run(name, func(t *testing.T) {
			s := newFakeStarter(t)
			s.set(func(s *fakeStarter) { s.updates = updates })
			r := reportFake(t, s, 2*time.Second)
			if err := r.Begin(); err != nil {
				t.Fatal(err)
			}
			if err := r.Fail("boom"); err != nil {
				t.Fatal(err)
			}
			var verbs []string
			for _, c := range s.seen() {
				if strings.HasPrefix(c.verb, "set_job_attr") && c.args[0] == AttrMountError {
					verbs = append(verbs, c.verb)
				}
			}
			if len(verbs) != 2 {
				t.Fatalf("%d writes of %s, want 2 (the reset and the failure)", len(verbs), AttrMountError)
			}
			if verbs[0] != verbs[1] {
				t.Fatalf("the reset went out as %q and the failure as %q; a delayed flush can "+
					"then revert the failure", verbs[0], verbs[1])
			}
			if v, _ := s.attr(AttrMountError); v != "true" {
				t.Fatalf("%s = %q after Begin then Fail", AttrMountError, v)
			}
		})
	}
}

// Begin is one write per attempt, not per cycle, and it must not be
// mistaken for a latch: it is called before any failure has happened.
func TestBeginDoesNotLatch(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	if err := r.Begin(); err != nil {
		t.Fatal(err)
	}
	if r.Failed() {
		t.Fatal("Begin set the failure latch")
	}
	if err := r.Fail("boom"); err != nil {
		t.Fatal(err)
	}
	if !r.Failed() {
		t.Fatal("Fail after Begin did not latch")
	}
}

// Inert reporters stay inert.
func TestBeginIsInertOutsideAJob(t *testing.T) {
	inEmptyDir(t)
	r, err := Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Begin(); err != nil {
		t.Errorf("Begin outside a job: %v", err)
	}
	var nilr *Reporter
	if err := nilr.Begin(); err != nil {
		t.Errorf("Begin on a nil reporter: %v", err)
	}
}
