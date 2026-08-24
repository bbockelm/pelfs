package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chirp"
	"github.com/bbockelm/pelfs/internal/mounterr"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The default has to be the safe one, and it has to be the safe one on
// every command: --on-mount-error lives in registerFlags, which every
// subcommand shares.
func TestOnMountErrorDefaultsToReport(t *testing.T) {
	o, _, err := parseArgs("shell", []string{"pelican://example/vol"}, 1, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.onMountError != onMountErrorReport {
		t.Fatalf("default is %q; killing a payload must never be what a user gets without asking", o.onMountError)
	}
}

func TestOnMountErrorFlagParsing(t *testing.T) {
	for _, v := range []string{"report", "hold", "ignore"} {
		o, _, err := parseArgs("shell", []string{"--on-mount-error=" + v, "pelican://example/vol"}, 1, 2, nil)
		if err != nil {
			t.Fatalf("--on-mount-error=%s: %v", v, err)
		}
		if string(o.onMountError) != v {
			t.Errorf("--on-mount-error=%s parsed as %q", v, o.onMountError)
		}
	}
	for _, v := range []string{"", "kill", "true", "Hold "} {
		if _, _, err := parseArgs("shell", []string{"--on-mount-error=" + v, "pelican://example/vol"}, 1, 2, nil); err == nil {
			t.Errorf("--on-mount-error=%q was accepted", v)
		}
	}
}

// `hold` overrides the payload's own status, INCLUDING a successful one.
// A payload that read a truncated file, got EIO, and exited 0 anyway is
// the exact case the feature exists for.
func TestMountErrorExit(t *testing.T) {
	cases := []struct {
		name   string
		policy mountErrorPolicy
		fired  bool
		code   int
		want   int
	}{
		{"report leaves a success alone", onMountErrorReport, true, 0, 0},
		{"report leaves a failure alone", onMountErrorReport, true, 3, 3},
		{"ignore leaves it alone", onMountErrorIgnore, true, 0, 0},
		{"hold with no failure leaves it alone", onMountErrorHold, false, 0, 0},
		{"hold overrides a success", onMountErrorHold, true, 0, exitMountError},
		{"hold overrides a failure", onMountErrorHold, true, 9, exitMountError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mounterr.Rearm()
			t.Cleanup(mounterr.Rearm)
			var out bytes.Buffer
			defer ui.SetOutput(&out, ui.Plain)()
			if c.fired {
				mounterr.Fail(mounterr.FrontendFUSE, errors.New("pack 3 is truncated"))
			}
			g := &genSession{onMountError: c.policy}
			if got := g.mountErrorExit(c.code); got != c.want {
				t.Fatalf("mountErrorExit(%d) = %d, want %d", c.code, got, c.want)
			}
		})
	}
}

// The latch's whole job at this layer: record it for the after-the-fact
// file, and (only under `hold`) ask for the payload to be stopped.
func TestOnMountFailureFollowsPolicy(t *testing.T) {
	cases := []struct {
		policy   mountErrorPolicy
		wantKill bool
		wantSaid bool
	}{
		{onMountErrorReport, false, true},
		{onMountErrorHold, true, true},
		{onMountErrorIgnore, false, false},
	}
	for _, c := range cases {
		t.Run(string(c.policy), func(t *testing.T) {
			var out bytes.Buffer
			defer ui.SetOutput(&out, ui.Plain)()
			g := &genSession{
				stats:        stats.New("pelican://f/p", "sess", filepath.Join(t.TempDir(), "s.json")),
				onMountError: c.policy,
				takeDown:     make(chan string, 1),
			}
			g.onMountFailure(mounterr.Event{
				Frontend: mounterr.FrontendNFS,
				Err:      errors.New("pack 3 trailer is truncated"),
				At:       time.Now(),
			})

			var sum stats.Summary
			g.stats.Update(func(s *stats.Summary) { sum = *s })
			if !sum.MountError {
				t.Error("the statistics file did not record the mount error")
			}
			if !strings.Contains(sum.MountErrorReason, "truncated") {
				t.Errorf("recorded reason %q", sum.MountErrorReason)
			}
			if sum.MountErrorAt.IsZero() {
				t.Error("no timestamp recorded")
			}

			select {
			case reason := <-g.takeDown:
				if !c.wantKill {
					t.Fatalf("policy %q asked for the payload to be stopped: %q", c.policy, reason)
				}
				if !strings.Contains(reason, "truncated") {
					t.Errorf("take-down reason %q", reason)
				}
			default:
				if c.wantKill {
					t.Fatalf("policy %q did not ask for the payload to be stopped", c.policy)
				}
			}

			said := strings.Contains(out.String(), "could not explain")
			if said != c.wantSaid {
				t.Errorf("output %q; wanted an error line: %v", out.String(), c.wantSaid)
			}
		})
	}
}

// The imperative route, end to end at the level pelfs owns: a running
// payload, a take-down request, and a process that is actually gone.
func TestTakeDownStopsThePayload(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()

	dir := t.TempDir()
	take := make(chan string, 1)
	// The payload writes a file and then sleeps far past the test. It is
	// stopped only if the take-down works.
	script := `echo running > ` + filepath.Join(dir, "started") + `; exec sleep 300`

	type result struct{ code int }
	done := make(chan result, 1)
	go func() {
		done <- result{runInMount(&cmdOpts{}, "pelican://fed/pfx", dir,
			[]string{"/bin/sh", "-c", script}, take)}
	}()

	// Wait for the payload to be up without sleeping on a guess.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the payload never started")
		}
		select {
		case r := <-done:
			t.Fatalf("the payload exited early with %d", r.code)
		case <-time.After(5 * time.Millisecond):
		}
	}

	take <- "nfs mount: pack 3 trailer is truncated"
	select {
	case r := <-done:
		// SIGTERM, reported the way every shell reports a signalled
		// child. runMountGen then rewrites this to exitMountError.
		if want := 128 + 15; r.code != want {
			t.Errorf("payload status %d, want %d (SIGTERM)", r.code, want)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the payload was never stopped")
	}
	if !strings.Contains(out.String(), "stopping the payload") {
		t.Errorf("nothing was said about the take-down: %q", out.String())
	}
}

// A payload that exits on its own must not leave a timer behind that
// signals a pid somebody else has been given by then.
func TestTakeDownAfterThePayloadExitedIsHarmless(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	defer ui.SetOutput(&bytes.Buffer{}, ui.Plain)()
	take := make(chan string, 1)
	take <- "late"
	code := runInMount(&cmdOpts{}, "pelican://fed/pfx", t.TempDir(),
		[]string{"/bin/sh", "-c", "exit 5"}, take)
	if code != 5 && code != 128+15 {
		t.Fatalf("status %d; the payload's own status or a SIGTERM, nothing else", code)
	}
}

// The declarative route, end to end: the latch reaches an actual chirp
// wire. This spins the starter's side of the protocol so the assertion
// is on bytes, not on a mock's expectations.
func TestMountFailureReachesTheJobAd(t *testing.T) {
	s := newTinyStarter(t)
	t.Setenv("_CONDOR_CHIRP_CONFIG", s.configFile(t))
	t.Setenv("_CONDOR_SCRATCH_DIR", "")
	defer ui.SetOutput(&bytes.Buffer{}, ui.Plain)()

	r, err := chirp.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if !r.InJob() {
		t.Fatal("the reporter did not find the configuration")
	}

	g := &genSession{
		stats:        stats.New("pelican://f/p", "sess", filepath.Join(t.TempDir(), "s.json")),
		chirp:        r,
		onMountError: onMountErrorReport,
		takeDown:     make(chan string, 1),
	}
	g.onMountFailure(mounterr.Event{
		Frontend: mounterr.FrontendFUSE,
		Err:      errors.New(`read "/data/a b": pack 3 is truncated`),
		At:       time.Now(),
	})

	lines := s.lines()
	var sawFlag, sawReason, sawULog bool
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "set_job_attr "+chirp.AttrMountError+" true"):
			sawFlag = true
		case strings.HasPrefix(l, "set_job_attr "+chirp.AttrErrorReason+" "):
			sawReason = true
			if strings.Contains(l, "\n") {
				t.Errorf("the reason was not sent as one line: %q", l)
			}
		case strings.HasPrefix(l, "ulog "):
			sawULog = true
		}
	}
	if !sawReason || !sawFlag || !sawULog {
		t.Fatalf("reason=%v flag=%v ulog=%v; lines were %q", sawReason, sawFlag, sawULog, lines)
	}
	// The reason must precede the flag, so a schedd evaluating
	// periodic_hold between the two writes never sees a hold with no
	// reason to put in it.
	if idxOf(lines, "set_job_attr "+chirp.AttrErrorReason) > idxOf(lines, "set_job_attr "+chirp.AttrMountError) {
		t.Errorf("the flag was sent before the reason: %q", lines)
	}
}

func idxOf(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return len(lines)
}

// tinyStarter is just enough of the condor_starter's IO proxy to accept
// a cookie and answer every command with success, recording the raw
// request lines. internal/chirp has the faithful one, including the
// refusal paths; this one exists so the wiring in THIS package can be
// checked against a real socket.
type tinyStarter struct {
	ln     net.Listener
	cookie string
	mu     sync.Mutex
	got    []string
	wg     sync.WaitGroup
}

func newTinyStarter(t *testing.T) *tinyStarter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &tinyStarter{ln: ln, cookie: "cookie-for-the-test"}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer conn.Close() //nolint:errcheck
				br := bufio.NewReader(conn)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimSuffix(line, "\n")
					if strings.HasPrefix(line, "cookie ") {
						if line != "cookie "+s.cookie {
							_, _ = conn.Write([]byte("-1\n"))
							continue
						}
					} else {
						s.mu.Lock()
						s.got = append(s.got, line)
						s.mu.Unlock()
					}
					if _, err := conn.Write([]byte("0\n")); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func (s *tinyStarter) configFile(t *testing.T) string {
	t.Helper()
	host, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), ".chirp.config")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%s %s %s\n", host, port, s.cookie)), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (s *tinyStarter) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.got...)
}
