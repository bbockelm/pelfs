package chirp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The overwhelmingly common case: pelfs is not in a job. It must cost
// nothing and, above all, must not look like a failure -- a caller that
// has to distinguish "no starter" from "the starter broke" at every call
// site will eventually get it wrong in the direction that fails a mount
// on a laptop.
func TestNoChirpConfigIsNotAnError(t *testing.T) {
	inEmptyDir(t)
	r, err := Open(t.Context())
	if err != nil {
		t.Fatalf("Open with no config: %v", err)
	}
	if r.InJob() {
		t.Error("InJob is true with no chirp config")
	}
	if err := r.Publish(Mount{Session: "s"}); err != nil {
		t.Errorf("Publish on an inert reporter: %v", err)
	}
	if err := r.Fail("boom"); err != nil {
		t.Errorf("Fail on an inert reporter: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close on an inert reporter: %v", err)
	}
}

// A nil *Reporter is the shape a caller ends up with when it stores the
// result of a constructor that failed. Every method has to survive it.
func TestNilReporterIsInert(t *testing.T) {
	var r *Reporter
	if r.InJob() || r.Failed() {
		t.Error("a nil reporter claims to be live")
	}
	if err := r.Publish(Mount{}); err != nil {
		t.Errorf("Publish: %v", err)
	}
	if err := r.Fail("x"); err != nil {
		t.Errorf("Fail: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	r.Run(t.Context(), time.Second, func() Mount { t.Error("sampled a nil reporter"); return Mount{} }, nil)
}

// A config file that exists but does not parse is the operator's
// problem, not a silent no-op: they asked for chirp and are entitled to
// know why they are not getting it.
func TestMalformedConfigIsReported(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"one field":    "localhost\n",
		"two fields":   "localhost 1234\n",
		"port is text": "localhost http cookie\n",
		"port zero":    "localhost 0 cookie\n",
		"port too big": "localhost 99999 cookie\n",
		"port signed":  "localhost -1 cookie\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := inEmptyDir(t)
			p := filepath.Join(dir, ".chirp.config")
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("_CONDOR_CHIRP_CONFIG", p)
			if _, err := FindConfig(); err == nil {
				t.Fatalf("accepted %q", body)
			} else if errors.Is(err, ErrNoJob) {
				t.Fatalf("reported a malformed config as absent: %v", err)
			}
			r, err := Open(t.Context())
			if err == nil {
				t.Error("Open accepted a malformed config")
			}
			if r.InJob() {
				t.Error("a reporter built from a malformed config claims to be live")
			}
		})
	}
}

// fscanf("%s %d %s") separates on any run of whitespace and ignores
// whatever follows the third field. Both are reproduced, the second so a
// starter that grows a fourth field does not break an older pelfs.
func TestConfigParsesTheReferenceFormat(t *testing.T) {
	for _, body := range []string{
		"host 42 cook\n",
		"  host\t42   cook  \n",
		"host 42 cook and something the future added\n",
		"host\n42\ncook\n",
	} {
		cfg, err := parseConfig([]byte(body), "p")
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if cfg.Host != "host" || cfg.Port != 42 || string(cfg.cookie) != "cook" {
			t.Errorf("%q parsed as %s cookie=%q", body, cfg, cfg.cookie)
		}
	}
}

// The starter exports an absolute path precisely because the payload's
// working directory is not guaranteed to be the scratch directory -- and
// under `pelfs shell` it is guaranteed NOT to be.
func TestConfigDiscoveryPrefersTheExportedPath(t *testing.T) {
	dir := inEmptyDir(t)
	scratch := t.TempDir()
	exported := filepath.Join(t.TempDir(), "elsewhere.config")

	write := func(p, host string) {
		if err := os.WriteFile(p, []byte(host+" 1 c\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, ".chirp.config"), "cwd")
	write(filepath.Join(scratch, ".chirp.config"), "scratch")
	write(exported, "exported")

	t.Setenv("_CONDOR_SCRATCH_DIR", scratch)
	t.Setenv("_CONDOR_CHIRP_CONFIG", exported)
	if cfg, err := FindConfig(); err != nil || cfg.Host != "exported" {
		t.Fatalf("got %v %v, want the exported path", cfg, err)
	}
	t.Setenv("_CONDOR_CHIRP_CONFIG", "")
	if cfg, err := FindConfig(); err != nil || cfg.Host != "scratch" {
		t.Fatalf("got %v %v, want the scratch directory", cfg, err)
	}
	t.Setenv("_CONDOR_SCRATCH_DIR", "")
	if cfg, err := FindConfig(); err != nil || cfg.Host != "cwd" {
		t.Fatalf("got %v %v, want the working directory", cfg, err)
	}
}

// The cookie is the whole of the job's authentication. It must not be
// reachable through the ordinary ways a struct ends up in a log line,
// and Close must actually erase it.
func TestCookieIsNeverRendered(t *testing.T) {
	cfg, err := parseConfig([]byte("h 1 s3cr3tc00kie\n"), "/p")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{cfg.String(), errors.New("wrapped: " + cfg.String()).Error()} {
		if strings.Contains(s, "s3cr3tc00kie") {
			t.Errorf("the cookie appears in %q", s)
		}
	}
	buf := cfg.cookie
	cfg.Zero()
	for _, b := range buf {
		if b != 0 {
			t.Fatalf("Zero left the cookie in memory: %q", buf)
		}
	}
}

func TestReporterCloseZeroesTheCookie(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 2*time.Second)
	buf := r.cfg.cookie
	if len(buf) == 0 {
		t.Fatal("no cookie to erase")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, b := range buf {
		if b != 0 {
			t.Fatalf("Close left the cookie in memory: %q", buf)
		}
	}
}

// The starter answers a wrong cookie with -1, sleeps a second first, and
// does NOT close the connection -- so this failure looks exactly like a
// slow idle socket unless the client reads the code.
func TestWrongCookieIsRejected(t *testing.T) {
	s := newFakeStarter(t)
	cfg := s.config(t)
	copy(cfg.cookie, strings.Repeat("x", len(cfg.cookie)))
	_, err := Dial(t.Context(), cfg, 2*time.Second)
	if err == nil {
		t.Fatal("a wrong cookie was accepted")
	}
	var code Code
	if !errors.As(err, &code) || code != ErrNotAuthenticated {
		t.Fatalf("got %v, want not-authenticated", err)
	}
	if strings.Contains(err.Error(), string(cfg.cookie)) {
		t.Error("the failure message quotes the cookie")
	}
}

// The failure this whole design is built around: a starter that is alive
// and reading and never answers. Without a deadline this call never
// returns, and it is called from a FUSE handler.
func TestStalledStarterTimesOut(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.stall = true })
	cfg := s.config(t)

	start := time.Now()
	_, err := Dial(t.Context(), cfg, 100*time.Millisecond)
	if err == nil {
		t.Fatal("a stalled starter was accepted")
	}
	if !isTimeout(err) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the deadline took %v to fire", d)
	}
}

// The same guarantee one layer up, on a connection that authenticated
// before the starter wedged.
func TestStalledStarterTimesOutMidSession(t *testing.T) {
	s := newFakeStarter(t)
	r := reportFake(t, s, 150*time.Millisecond)
	if err := r.Publish(Mount{Session: "a"}); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	s.set(func(s *fakeStarter) { s.stall = true })
	start := time.Now()
	err := r.Publish(Mount{Session: "b", BytesDown: 1})
	if err == nil {
		t.Fatal("a publish to a wedged starter succeeded")
	}
	if !isTimeout(err) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the deadline took %v to fire", d)
	}
	// And the reporter must not now hammer the wedged starter.
	if err := r.Publish(Mount{Session: "c"}); err == nil {
		t.Error("a publish straight after a fault reconnected immediately")
	}
}

// A starter that refuses everything (an admin who set ENABLE_CHIRP_* to
// false, an unknown verb) must surface as the protocol code, not as a
// hang and not as a nil error.
func TestRejectingStarter(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.forceCode = int(ErrNotAuthorized) })
	r := reportFake(t, s, 2*time.Second)
	err := r.Publish(Mount{Session: "s"})
	var code Code
	if !errors.As(err, &code) || code != ErrNotAuthorized {
		t.Fatalf("got %v, want not-authorized", err)
	}
	// A refusal is not a broken connection, so it must not trip the
	// reconnect backoff: the next cycle should still reach the starter.
	if n := len(s.seen()); n == 0 {
		t.Fatal("nothing reached the starter")
	}
	before := len(s.seen())
	_ = r.Publish(Mount{Session: "s2"})
	if len(s.seen()) == before {
		t.Error("a protocol refusal closed the connection")
	}
}

// A reply that is not a number at all. The reference client aborts the
// process here; a filesystem may not.
func TestUnparsableReplyIsAnError(t *testing.T) {
	s := newFakeStarter(t)
	s.set(func(s *fakeStarter) { s.garbage = "not a number" })
	cfg := s.config(t)
	if _, err := Dial(t.Context(), cfg, 2*time.Second); err == nil {
		t.Fatal("a garbage reply was accepted")
	}
}

// sscanf("%d") skips leading whitespace and ignores trailing text. Both
// matter: the first because put_line_raw is free to pad, the second
// because a starter that ever appends anything to a status line must not
// turn every reply into a protocol error.
func TestScanIntFollowsSscanf(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"0\n", 0, true},
		{"-8\n", -8, true},
		{"  -1\n", -1, true},
		{"\t42 trailing junk\n", 42, true},
		{"+7\n", 7, true},
		{"12abc\n", 12, true},
		{"\n", 0, false},
		{"abc\n", 0, false},
		{"-\n", 0, false},
		{"99999999999999999999\n", 0, false},
	}
	for _, c := range cases {
		got, ok := scanInt([]byte(c.in))
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("scanInt(%q) = %d,%v; want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// vsprintf_chirp and sscanf_chirp must be exact inverses, because the
// value on the far side of them is parsed as an expression.
func TestWordEscapingRoundTrips(t *testing.T) {
	for _, in := range []string{
		"plain",
		"with space",
		"with\ttab",
		"with\nnewline",
		"with\rcarriage",
		`with\backslash`,
		`"quoted string"`,
		`" a b \" c "`,
		`\\\ `,
		"unicode: héllo → ✓",
		strings.Repeat(`\ `, 50),
	} {
		line := string(appendWord(nil, []byte(in))) + " tail\n"
		verb, args, ok := parseChirp(strings.TrimSuffix(line, "\n"))
		if !ok {
			t.Fatalf("%q did not tokenize", in)
		}
		if verb != in {
			t.Errorf("round trip of %q gave %q", in, verb)
		}
		if len(args) != 1 || args[0] != "tail" {
			t.Errorf("%q swallowed the following word: %q", in, args)
		}
	}
}

// An oversized request is refused here rather than sent, because the
// starter answers CHIRP_ERROR_TOO_BIG and then closes the connection:
// getting this wrong costs the session, not the request.
func TestOversizeRequestIsRefusedLocally(t *testing.T) {
	s := newFakeStarter(t)
	c := dialFake(t, s)
	err := c.SetJobAttr("ChirpPelfsBig", String(strings.Repeat("x", LineMax)))
	if err == nil {
		t.Fatal("an oversized request was sent")
	}
	if !strings.Contains(err.Error(), "the limit is") {
		t.Fatalf("got %v, want a local size refusal", err)
	}
	// The connection survived, because nothing was written.
	if err := c.SetJobAttr("ChirpPelfsSmall", Int(1)); err != nil {
		t.Fatalf("the connection did not survive: %v", err)
	}
}

// The delayed verb has its own, much smaller limit, applied by the
// starter to the unescaped expression.
func TestDelayedExpressionLimit(t *testing.T) {
	s := newFakeStarter(t)
	c := dialFake(t, s)
	if err := c.SetJobAttrDelayed("ChirpPelfsX", String(strings.Repeat("y", delayedExprMax))); err == nil {
		t.Fatal("an over-long delayed expression was sent")
	}
	if err := c.SetJobAttrDelayed("ChirpPelfsX", String("y")); err != nil {
		t.Fatalf("a short delayed expression was refused: %v", err)
	}
}

// The wire has no representation for an empty argument: the starter's
// parse runs out of input and the command falls through to "invalid
// request". Refusing locally keeps that from looking like a server bug.
func TestEmptyExpressionIsRefused(t *testing.T) {
	s := newFakeStarter(t)
	c := dialFake(t, s)
	if err := c.SetJobAttr("ChirpPelfsX", ""); err == nil {
		t.Fatal("an empty expression was sent")
	}
	if err := c.ULog("   "); err == nil {
		t.Fatal("an empty ulog message was sent")
	}
}

// An attribute name is a whole word on the wire, so a name with a space
// in it would shift the VALUE into the name's position. It is also
// useless in a periodic_hold expression if it is not an identifier.
func TestAttributeNamesAreValidated(t *testing.T) {
	s := newFakeStarter(t)
	c := dialFake(t, s)
	for _, bad := range []string{"", "has space", "has\nnewline", "1leading", "has-dash", `x" || true || "`} {
		if err := c.SetJobAttr(bad, Int(1)); err == nil {
			t.Errorf("accepted attribute name %q", bad)
		}
		if err := c.SetJobAttrDelayed(bad, Int(1)); err == nil {
			t.Errorf("accepted delayed attribute name %q", bad)
		}
	}
	if err := c.SetJobAttr("ChirpPelfs_Ok9", Int(1)); err != nil {
		t.Errorf("rejected a valid name: %v", err)
	}
}

// get_job_attr is the one reply that is not a bare status line: a length
// and then that many raw bytes, with no terminator of their own.
func TestGetJobAttr(t *testing.T) {
	s := newFakeStarter(t)
	c := dialFake(t, s)
	if err := c.SetJobAttr("ChirpPelfsThing", String("a value with spaces")); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetJobAttr("ChirpPelfsThing")
	if err != nil {
		t.Fatal(err)
	}
	if want := `"a value with spaces"`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// And the connection is still framed correctly afterwards.
	if err := c.SetJobAttr("ChirpPelfsAfter", Int(1)); err != nil {
		t.Fatalf("the stream desynchronized after a body reply: %v", err)
	}
}

// inEmptyDir moves the test into a directory with no .chirp.config and
// clears the environment the discovery consults, so "not in a job" is
// actually what the test sees.
func inEmptyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("_CONDOR_CHIRP_CONFIG", "")
	t.Setenv("_CONDOR_SCRATCH_DIR", "")
	return dir
}
