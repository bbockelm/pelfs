package chirp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStarter is the condor_starter's IO proxy, reimplemented against
// src/condor_starter.V6.1/io_proxy_handler.cpp.
//
// It is not a mock: it does the parsing the real one does (sscanf_chirp,
// including the backslash unescaping), applies the same three gates
// (updates, delayed, and the delayed-update name prefix), answers with
// the same numeric status lines, and reproduces the two behaviours that
// are easy to get wrong from the client side and expensive to get wrong
// in production -- a WRONG COOKIE is answered -1 and the connection is
// KEPT, and an oversized request is answered CHIRP_ERROR_TOO_BIG and the
// connection is DROPPED.
type fakeStarter struct {
	t      *testing.T
	ln     net.Listener
	cookie string
	done   chan struct{}
	wg     sync.WaitGroup

	mu    sync.Mutex
	cmds  []cmd
	attrs map[string]string // what set_job_attr wrote, immediate or delayed

	// Knobs, all settable before or during a test under mu.
	stall     bool   // accept, read, and never answer
	updates   bool   // ENABLE_CHIRP_UPDATES && WantRemoteUpdates
	delayed   bool   // ENABLE_CHIRP_DELAYED && WantDelayedUpdates
	prefix    string // CHIRP_DELAYED_UPDATE_PREFIX
	forceCode int    // if < 0, answer this to every authenticated command
	garbage   string // if set, answer this line instead of a status code
}

// cmd is one request as the starter parsed it: the verb, and the
// arguments AFTER unescaping. Recording the unescaped form is the point
// -- it is what proves the client's escaping and the starter's
// unescaping are inverses.
type cmd struct {
	verb    string
	args    []string
	delayed bool
}

func newFakeStarter(t *testing.T) *fakeStarter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeStarter{
		t:       t,
		ln:      ln,
		cookie:  "b4f3a1c2d5e6f708",
		done:    make(chan struct{}),
		attrs:   map[string]string{},
		updates: true,
		delayed: true,
		prefix:  "Chirp*",
	}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.stop)
	return s
}

func (s *fakeStarter) stop() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.ln.Close()
	s.wg.Wait()
}

func (s *fakeStarter) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close() //nolint:errcheck
			s.handle(conn)
		}()
	}
}

// config writes the .chirp.config the starter would have written and
// returns a Config pointing at it.
func (s *fakeStarter) config(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".chirp.config")
	host, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatalf("addr: %v", err)
	}
	if err := os.WriteFile(p, []byte(fmt.Sprintf("%s %s %s\n", host, port, s.cookie)), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := parseConfig([]byte(fmt.Sprintf("%s %s %s\n", host, port, s.cookie)), p)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

// configPath writes the config file and returns its path, for the tests
// that go through discovery rather than constructing a Config.
func (s *fakeStarter) configPath(t *testing.T) string {
	t.Helper()
	cfg := s.config(t)
	return cfg.Path
}

func (s *fakeStarter) handle(conn net.Conn) {
	br := bufio.NewReaderSize(conn, LineMax+2)
	authed := false
	for {
		line, err := readLineRaw(br)
		if err != nil {
			return
		}
		if line == nil { // over the limit
			_, _ = conn.Write([]byte(strconv.Itoa(int(ErrTooBig)) + "\n"))
			return
		}
		s.mu.Lock()
		stall, garbage := s.stall, s.garbage
		s.mu.Unlock()
		if stall {
			// The starter is alive and reading, and nothing comes back.
			<-s.done
			return
		}
		var reply string
		if !authed {
			if v, args, ok := parseChirp(string(line)); ok && v == "cookie" && len(args) == 1 && args[0] == s.cookie {
				authed = true
				reply = "0"
			} else {
				// io_proxy_handler.cpp: a wrong cookie is answered and
				// the socket stays open for another attempt.
				reply = strconv.Itoa(int(ErrNotAuthenticated))
			}
		} else {
			reply = s.dispatch(string(line), conn)
			if reply == "" {
				continue // dispatch already wrote a framed reply
			}
		}
		if garbage != "" {
			reply = garbage
		}
		if _, err := conn.Write([]byte(reply + "\n")); err != nil {
			return
		}
	}
}

func (s *fakeStarter) dispatch(line string, conn net.Conn) string {
	verb, args, ok := parseChirp(line)
	if !ok {
		return strconv.Itoa(int(ErrInvalidRequest))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forceCode < 0 {
		s.cmds = append(s.cmds, cmd{verb: verb, args: args})
		return strconv.Itoa(s.forceCode)
	}
	switch {
	case verb == "set_job_attr_delayed" && len(args) >= 2:
		if !s.delayed {
			return strconv.Itoa(int(ErrInvalidRequest))
		}
		s.cmds = append(s.cmds, cmd{verb: verb, args: args[:2], delayed: true})
		// jic_shadow.cpp checks the prefix and, when it does not match,
		// LOGS and answers a non-negative status anyway. Reproduced,
		// because a client cannot tell the difference and must not be
		// written as though it can.
		if !matchWild(s.prefix, args[0]) {
			return "1"
		}
		if len(args[1]) > delayedExprMax {
			return strconv.Itoa(int(ErrInvalidRequest))
		}
		s.attrs[args[0]] = args[1]
		return "0"
	case verb == "set_job_attr" && len(args) >= 2:
		if !s.updates {
			return strconv.Itoa(int(ErrInvalidRequest))
		}
		s.cmds = append(s.cmds, cmd{verb: verb, args: args[:2]})
		s.attrs[args[0]] = args[1]
		return "0"
	case verb == "get_job_attr" && len(args) >= 1:
		if !s.updates {
			return strconv.Itoa(int(ErrInvalidRequest))
		}
		s.cmds = append(s.cmds, cmd{verb: verb, args: args[:1]})
		v, found := s.attrs[args[0]]
		if !found {
			v = "UNDEFINED"
		}
		// The length line, then the raw bytes with no terminator.
		_, _ = conn.Write([]byte(strconv.Itoa(len(v)) + "\n" + v))
		return ""
	case verb == "ulog" && len(args) >= 1:
		if !s.updates {
			return strconv.Itoa(int(ErrInvalidRequest))
		}
		s.cmds = append(s.cmds, cmd{verb: verb, args: args[:1]})
		return "0"
	}
	return strconv.Itoa(int(ErrInvalidRequest))
}

func (s *fakeStarter) seen() []cmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cmd(nil), s.cmds...)
}

func (s *fakeStarter) attr(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.attrs[name]
	return v, ok
}

func (s *fakeStarter) set(fn func(*fakeStarter)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// readLineRaw is ReliSock::get_line_raw: bytes up to a newline, which is
// consumed and dropped. A line longer than CHIRP_LINE_MAX comes back nil.
func readLineRaw(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		c, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == '\n' {
			return out, nil
		}
		out = append(out, c)
		if len(out) > LineMax {
			return nil, nil
		}
	}
}

// parseChirp is sscanf_chirp's %s tokenizer: words separated by
// unescaped whitespace, with one backslash stripped before whatever
// follows it.
func parseChirp(line string) (verb string, args []string, ok bool) {
	var words []string
	var b strings.Builder
	inWord := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' {
			i++
			if i >= len(line) {
				break
			}
			b.WriteByte(line[i])
			inWord = true
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			if inWord {
				words = append(words, b.String())
				b.Reset()
				inWord = false
			}
			continue
		}
		b.WriteByte(c)
		inWord = true
	}
	if inWord {
		words = append(words, b.String())
	}
	if len(words) == 0 {
		return "", nil, false
	}
	return words[0], words[1:], true
}

// unquoteClassAd reverses chirp.String. It exists so the escaping tests
// assert a ROUND TRIP and not merely that some bytes came out: a quoting
// scheme that is wrong in a self-consistent way passes an
// exact-bytes-only test.
func unquoteClassAd(t *testing.T, s string) string {
	t.Helper()
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		t.Fatalf("not a ClassAd string literal: %q", s)
	}
	body := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '"' {
			t.Fatalf("unescaped quote inside a string literal: %q", s)
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(body) {
			t.Fatalf("trailing backslash in %q", s)
		}
		switch e := body[i]; e {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		default:
			if e < '0' || e > '7' || i+2 >= len(body) {
				t.Fatalf("unknown escape \\%c in %q", e, s)
			}
			n, err := strconv.ParseUint(body[i:i+3], 8, 8)
			if err != nil {
				t.Fatalf("bad octal escape in %q: %v", s, err)
			}
			b.WriteByte(byte(n))
			i += 2
		}
	}
	return b.String()
}

// dialFake connects a client to s with a short timeout.
func dialFake(t *testing.T, s *fakeStarter) *Client {
	t.Helper()
	cfg := s.config(t)
	c, err := Dial(t.Context(), cfg, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// reportFake builds a Reporter already pointed at s.
func reportFake(t *testing.T, s *fakeStarter, timeout time.Duration) *Reporter {
	t.Helper()
	r := newReporter(s.config(t), timeout)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// isTimeout reports whether err is a deadline expiring, at any depth.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF)
}
