package packstore

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// scaleSlowPolicy compresses the clock the slow judgement runs on so a
// test can spend milliseconds where a real uplink spends seconds. The
// ratios are what is under test, not the wall-clock numbers.
func scaleSlowPolicy(t *testing.T, floor float64, grace time.Duration) {
	t.Helper()
	oldFloor, oldGrace := slowRateFloor, slowLatencyGrace
	slowRateFloor, slowLatencyGrace = floor, grace
	t.Cleanup(func() { slowRateFloor, slowLatencyGrace = oldFloor, oldGrace })
}

// warnings captures what pelfs said while fn ran.
func warnings(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	defer ui.SetOutput(&buf, ui.Plain)()
	fn()
	return buf.String()
}

const (
	testFloor = 100 << 20 // bytes/second
	testGrace = 100 * time.Millisecond
	testBytes = 4 << 20 // one "pack"
)

// The defect this fixes: four uploads sharing one uplink each move a
// quarter of it, and each was reported as slow for doing exactly that.
// Every transfer here runs at precisely its fair share; not one of them
// is news.
func TestConcurrentUploadsShareTheRateFloor(t *testing.T) {
	scaleSlowPolicy(t, testFloor, testGrace)
	const conc = 4
	fair := time.Duration(float64(testBytes) * conc / testFloor * float64(time.Second))

	// The bound is only meaningful if the same run WOULD have been
	// reported under the whole-link rule this replaces.
	if solo := slowBudget(testBytes, 1); fair <= solo {
		t.Fatalf("test is vacuous: a fair-share transfer (%s) is under the whole-link budget (%s)", fair, solo)
	}

	var arrived sync.WaitGroup
	arrived.Add(conc)

	out := warnings(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = retryOnSized(context.Background(), "upload pack p-test", testBytes, 1, func() error {
					// Hold every transfer open until all of them are in
					// flight: staggered starts are exactly the case a
					// start-time count gets wrong.
					arrived.Done()
					arrived.Wait()
					time.Sleep(fair)
					return nil
				})
			}()
		}
		wg.Wait()
	})

	if out != "" {
		t.Errorf("transfers running at their fair share of the link were reported as slow:\n%s", out)
	}
}

// A transfer that has the link to itself and still crawls is the case
// the warning exists for, and sharing must not silence it.
func TestALoneCrawlingUploadStillWarns(t *testing.T) {
	scaleSlowPolicy(t, testFloor, testGrace)
	tenth := time.Duration(float64(testBytes) * 10 / testFloor * float64(time.Second))

	out := warnings(t, func() {
		_ = retryOnSized(context.Background(), "upload pack p-slow", testBytes, 1, func() error {
			time.Sleep(tenth)
			return nil
		})
	})

	if !strings.Contains(out, "slow operation") || !strings.Contains(out, "upload pack p-slow") {
		t.Errorf("a transfer at a tenth of the floor must still be reported; got:\n%s", out)
	}
	if strings.Contains(out, "sharing the link") {
		t.Errorf("a lone transfer must not claim it shared the link:\n%s", out)
	}
}

// When a shared link IS slow enough to report, the message says what it
// was judged against -- otherwise the reader cannot tell a slow uplink
// from a busy one.
func TestASharedSlowUploadNamesItsCompany(t *testing.T) {
	scaleSlowPolicy(t, testFloor, testGrace)
	const conc = 2
	crawl := time.Duration(float64(testBytes) * 20 / testFloor * float64(time.Second))

	var arrived sync.WaitGroup
	arrived.Add(conc)

	out := warnings(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < conc; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = retryOnSized(context.Background(), "upload pack p-busy", testBytes, 1, func() error {
					arrived.Done()
					arrived.Wait()
					time.Sleep(crawl)
					return nil
				})
			}()
		}
		wg.Wait()
	})

	if n := strings.Count(out, "slow operation"); n != conc {
		t.Fatalf("want %d reports, got %d:\n%s", conc, n, out)
	}
	if !strings.Contains(out, "sharing the link with 1 other transfer") {
		t.Errorf("the report does not say what the transfer was judged against:\n%s", out)
	}
}

// Unsized operations have nothing to scale against and keep the flat
// threshold, sharers or not.
func TestUnsizedOperationsKeepTheFlatThreshold(t *testing.T) {
	scaleSlowPolicy(t, testFloor, testGrace)
	for _, sharers := range []int{0, 1, 8} {
		if got := slowBudget(0, sharers); got != slowThreshold {
			t.Errorf("unsized budget with %d sharers is %s, want %s", sharers, got, slowThreshold)
		}
	}
}

// The budget scales linearly with the company a transfer keeps: two
// streams each get half the link, four a quarter.
func TestBudgetScalesWithSharers(t *testing.T) {
	scaleSlowPolicy(t, testFloor, testGrace)
	transfer := func(sharers int) time.Duration { return slowBudget(testBytes, sharers) - testGrace }
	one := transfer(1)
	for _, n := range []int{2, 4, 8} {
		if want, got := time.Duration(n)*one, transfer(n); got != want {
			t.Errorf("%d sharers get %s of transfer budget, want %s", n, got, want)
		}
	}
	// A count below one is the caller's bug, not license to divide by it.
	if got, want := slowBudget(testBytes, 0), slowBudget(testBytes, 1); got != want {
		t.Errorf("zero sharers budgeted %s, want the lone-transfer budget %s", got, want)
	}
}

// A transfer is judged by the MOST company it kept, not by what was in
// flight when it started: uploads begin staggered, and the first one in
// spends nearly all its life sharing.
func TestPeakConcurrencyIsRecordedForTransfersAlreadyRunning(t *testing.T) {
	var l = sharedLink{inFlight: make(map[*share]struct{})}
	first := l.enter()
	if got := l.peak(first); got != 1 {
		t.Fatalf("a transfer alone on the link peaked at %d, want 1", got)
	}
	rest := make([]*share, 0, 3)
	for i := 0; i < 3; i++ {
		rest = append(rest, l.enter())
	}
	if got := l.peak(first); got != 4 {
		t.Errorf("the first transfer saw a peak of %d, want 4", got)
	}
	for _, s := range rest {
		l.leave(s)
	}
	// Departures do not erase what the transfer already lived through.
	if got := l.peak(first); got != 4 {
		t.Errorf("peak fell to %d after the others left, want 4", got)
	}
	l.leave(first)
	if len(l.inFlight) != 0 {
		t.Errorf("%d transfers left in flight after all departed", len(l.inFlight))
	}
}
