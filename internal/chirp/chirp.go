// Package chirp speaks the HTCondor Chirp protocol to the condor_starter
// that launched this process, so a pelfs mount can tell the JOB IT IS
// SERVING how it is doing -- while the job runs, rather than in a
// summary file read afterwards (internal/stats).
//
// # Why there is a hand-written client here
//
// There is no Go chirp client to import, and pelfs deliberately builds
// with CGO_ENABLED=0 and a tight go.mod, so linking the C one is not an
// option either. What follows is written against the reference
// implementation -- src/condor_chirp/chirp_client.c and
// src/condor_starter.V6.1/io_proxy_handler.cpp in the HTCondor tree --
// and the file comments record the parts of that wire format that are
// not guessable, because getting them wrong does not produce a clean
// failure: it produces a JOB THAT HANGS on a read that never returns.
//
// # The wire format
//
// The starter writes $_CONDOR_SCRATCH_DIR/.chirp.config holding
// `host port cookie`, whitespace separated. The client connects to that
// address over TCP and its FIRST command must be `cookie <cookie>`.
//
// Requests are single lines terminated by '\n'. Arguments that stand for
// a word are escaped: space, tab, newline, carriage return and backslash
// each get a leading backslash (chirp_client.c, vsprintf_chirp), and the
// starter reverses exactly that (io_proxy_handler.cpp, sscanf_chirp).
// One consequence worth stating out loud: an argument is a WORD, so an
// EMPTY argument does not exist on this wire -- the starter's parse
// simply runs out of input and the command falls through its if-chain to
// "invalid request".
//
// Replies are one line holding a decimal integer, read with sscanf
// "%d" -- so leading whitespace is skipped and trailing text on the line
// is ignored. A value >= 0 is success (for the verbs used here, always
// 0; for the file verbs, a byte count). A negative value is one of the
// CHIRP_ERROR_* codes in chirp_protocol.h, reproduced as Code below.
// Lines are bounded at 5120 bytes in both directions; a request longer
// than that is answered with CHIRP_ERROR_TOO_BIG and the starter then
// CLOSES the connection, which is the one error reply that is not
// recoverable in place.
//
// A rejected cookie is NOT a closed connection: the starter answers -1
// (not authenticated), sleeps a second first, and keeps the socket open
// waiting for another cookie. So a wrong cookie costs a second of
// wall-clock and then looks exactly like an idle connection, which is
// why every read here has a deadline rather than a "the server will tell
// us" assumption.
//
// # What the starter will actually let through
//
// Three gates, all of them checked at the starter and none of them
// visible to the client except as an "invalid request" reply:
//
//   - `set_job_attr_delayed` needs ENABLE_CHIRP_DELAYED (default true)
//     and the job ad's WantDelayedUpdates, which DEFAULTS TO TRUE. It
//     also needs the attribute name to match CHIRP_DELAYED_UPDATE_PREFIX,
//     which ships as `Chirp*`. That prefix is why every attribute this
//     package publishes is named ChirpPelfs<something> and not
//     Pelfs<something>: with the shipped default, `PelfsMountError` is
//     refused by the starter and `ChirpPelfsMountError` is not.
//
//   - `set_job_attr` (immediate) and `ulog` need ENABLE_CHIRP_UPDATES
//     (default true) AND the job ad's WantRemoteUpdates, which defaults
//     to WantIOProxy -- i.e. to FALSE unless the submit file says
//     `+WantIOProxy = true`.
//
// The practical shape of that: the periodic statistics work on an
// unmodified vanilla job, and the error latch's immediate update and its
// user-log line need one line in the submit file. Reporter falls back
// from the immediate form to the delayed form when the immediate one is
// refused, so the attribute still arrives on a job that did not opt in.
//
// And it arrives IN TIME. The starter drains its delayed-update
// dictionary into the job EXIT ad as well as into its periodic updates
// (jic_shadow.cpp, notifyJobExit -> publishUpdateAd), the shadow applies
// that ad before it calls the exit policy (pseudo_ops.cpp,
// pseudo_job_exit -> updateFromStarter -> resourceExit), and the
// shadow's job ad is the one UserPolicy evaluates. So an on_exit_remove
// or on_exit_hold expression written against these attributes works on a
// job with no submit-file changes at all; +WantIOProxy only makes the
// value visible DURING the run, which is what periodic_hold needs and
// what survives an eviction.
package chirp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LineMax is CHIRP_LINE_MAX: the starter reads a request with
// get_line_raw(line, CHIRP_LINE_MAX+1) and rejects anything longer.
const LineMax = 5120

// delayedExprMax is the starter's own limit on a delayed update's
// expression (jic_shadow.cpp: "Chirp update too long!"), applied to the
// UNESCAPED expression text.
const delayedExprMax = 993

// uLogMax is what a ulog message survives: GenericEvent::setInfoText
// copies into a fixed buffer. It is 1024 bytes in current HTCondor and
// was 128 in older releases, so the messages this package sends are
// written to say the useful part first and are capped well below either.
const uLogMax = 1023

// ErrNoJob means no chirp configuration was found, i.e. this process is
// not running under a condor_starter. It is the ORDINARY case -- every
// pelfs run on a laptop is one -- and callers are expected to treat it
// as "nothing to report to", never as a failure.
var ErrNoJob = errors.New("chirp: not running under an HTCondor starter")

// Code is a CHIRP_ERROR_* reply code from chirp_protocol.h. Only the
// negative values are errors; a reply of 0 or more is success.
type Code int

// The reply codes, verbatim from chirp_protocol.h.
const (
	ErrNotAuthenticated Code = -1
	ErrNotAuthorized    Code = -2
	ErrDoesntExist      Code = -3
	ErrAlreadyExists    Code = -4
	ErrTooBig           Code = -5
	ErrNoSpace          Code = -6
	ErrNoMemory         Code = -7
	ErrInvalidRequest   Code = -8
	ErrTooManyOpen      Code = -9
	ErrBusy             Code = -10
	ErrTryAgain         Code = -11
	ErrBadFD            Code = -12
	ErrIsDir            Code = -13
	ErrNotDir           Code = -14
	ErrNotEmpty         Code = -15
	ErrCrossDeviceLink  Code = -16
	ErrOffline          Code = -17
	ErrUnknown          Code = -127
)

var codeNames = map[Code]string{
	ErrNotAuthenticated: "not authenticated",
	ErrNotAuthorized:    "not authorized",
	ErrDoesntExist:      "does not exist",
	ErrAlreadyExists:    "already exists",
	ErrTooBig:           "too big",
	ErrNoSpace:          "no space",
	ErrNoMemory:         "no memory",
	ErrInvalidRequest:   "invalid request (the starter is not configured for this command, or the job ad did not ask for it)",
	ErrTooManyOpen:      "too many open",
	ErrBusy:             "busy",
	ErrTryAgain:         "try again",
	ErrBadFD:            "bad file descriptor",
	ErrIsDir:            "is a directory",
	ErrNotDir:           "not a directory",
	ErrNotEmpty:         "not empty",
	ErrCrossDeviceLink:  "cross-device link",
	ErrOffline:          "offline",
	ErrUnknown:          "unknown error",
}

func (c Code) Error() string {
	if s, ok := codeNames[c]; ok {
		return "chirp: " + s
	}
	return "chirp: error " + strconv.Itoa(int(c))
}

// Config is the address and credential from .chirp.config.
//
// The cookie is a SECRET -- it is the only thing standing between any
// process that can reach the starter's port and that job's queue entry --
// so it is held as a byte slice that Zero can actually erase, is never
// rendered by String, and never reaches a log line. (A Go string could
// not be erased at all.)
type Config struct {
	Host string
	Port int
	// Path is where the configuration was read from, for diagnostics.
	Path string

	cookie []byte
}

// String deliberately omits the cookie: this type ends up in error
// messages and log lines, and a credential that is only usually redacted
// is a credential that leaks.
func (c Config) String() string {
	return fmt.Sprintf("chirp %s:%d (from %s)", c.Host, c.Port, c.Path)
}

// Zero erases the cookie in place.
func (c *Config) Zero() {
	for i := range c.cookie {
		c.cookie[i] = 0
	}
	c.cookie = nil
}

// configPaths lists where the configuration may be, most authoritative
// first.
//
//  1. $_CONDOR_CHIRP_CONFIG -- an ABSOLUTE path the starter exports
//     (condor_starter.V6.1/starter.cpp) whenever it wrote a config at
//     all. Trusting it first is what makes this work no matter where the
//     payload's working directory ended up.
//  2. $_CONDOR_SCRATCH_DIR/.chirp.config -- the same file by
//     construction, for a starter old enough not to export the variable.
//  3. ./.chirp.config -- the reference client's only lookup. It is LAST
//     here, and it is the one pelfs cannot rely on: the whole point of
//     `pelfs shell` is that the payload's working directory is the
//     MOUNT, not the scratch directory, so a relative lookup finds
//     nothing exactly when it matters.
func configPaths() []string {
	var paths []string
	if p := os.Getenv("_CONDOR_CHIRP_CONFIG"); p != "" {
		paths = append(paths, p)
	}
	if d := os.Getenv("_CONDOR_SCRATCH_DIR"); d != "" {
		paths = append(paths, filepath.Join(d, ".chirp.config"))
	}
	return append(paths, ".chirp.config")
}

// FindConfig locates and parses the chirp configuration. It returns
// ErrNoJob when there is no configuration to find, which is not a
// failure; a configuration that exists but does not parse IS one, and is
// reported as such so the operator who expected chirp to work learns
// why.
func FindConfig() (Config, error) {
	var firstErr error
	for _, p := range configPaths() {
		data, err := os.ReadFile(p)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		cfg, err := parseConfig(data, p)
		// data held the cookie too; the parse copied what it needed.
		for i := range data {
			data[i] = 0
		}
		if err != nil {
			return Config{}, fmt.Errorf("chirp: %s: %w", p, err)
		}
		return cfg, nil
	}
	if firstErr != nil {
		return Config{}, fmt.Errorf("chirp: %w", firstErr)
	}
	return Config{}, ErrNoJob
}

// parseConfig reads `host port cookie`. The reference client parses it
// with fscanf("%s %d %s"), so: any run of whitespace separates fields,
// and anything after the third field is ignored. Both are reproduced
// here, including the last one -- a starter that grows a fourth field
// must not break a pelfs that predates it.
func parseConfig(data []byte, path string) (Config, error) {
	f := bytes.Fields(data)
	if len(f) < 3 {
		return Config{}, errors.New("expected `host port cookie`")
	}
	port, err := strconv.Atoi(string(f[1]))
	if err != nil || port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("bad port %q", f[1])
	}
	if len(f[0]) == 0 || len(f[2]) == 0 {
		return Config{}, errors.New("empty host or cookie")
	}
	cookie := make([]byte, len(f[2]))
	copy(cookie, f[2])
	return Config{Host: string(f[0]), Port: port, Path: path, cookie: cookie}, nil
}

// DefaultTimeout bounds every read and write.
//
// It has to exist, and it has to be short. This client is driven from a
// mount's error path, and the starter on the other end is a process that
// can be stopped, swapped out, or wedged; a blocking write to it would
// take the FUSE request that triggered the report down with it, which
// turns "the mount reported an error" into "the mount hung". Five
// seconds is generous for a loopback socket on the same machine and
// still short enough that a stalled starter costs a mount nothing it
// notices.
//
// Two of those seconds are spoken for by the protocol itself: the
// starter SLEEPS ONE SECOND before answering a wrong cookie, so any
// deadline near a second would report a credential mismatch as a
// timeout.
const DefaultTimeout = 5 * time.Second

// Client is one connection to the starter's IO proxy. It is not safe for
// concurrent use; Reporter owns one and serializes access to it.
type Client struct {
	conn net.Conn
	br   *bufio.Reader
	// buf is reused for every request line so that a report on the mount
	// error path does not allocate, and so that the cookie command can be
	// erased after it is sent.
	buf     []byte
	timeout time.Duration
}

// Dial connects, presents the cookie, and returns a ready client.
func Dial(ctx context.Context, cfg Config, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("chirp: connect %s:%d: %w", cfg.Host, cfg.Port, err)
	}
	// The reply buffer is bounded at one protocol line: a server that
	// never sends a newline must not be able to grow this without limit.
	c := &Client{
		conn:    conn,
		br:      bufio.NewReaderSize(conn, LineMax+2),
		buf:     make([]byte, 0, 256),
		timeout: timeout,
	}
	if err := c.cookie(cfg.cookie); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// cookie authenticates. The cookie never enters a string and the request
// buffer is erased immediately after the write, so the credential is not
// left sitting in a long-lived buffer for the rest of the session.
func (c *Client) cookie(cookie []byte) error {
	c.buf = append(c.buf[:0], "cookie "...)
	c.buf = appendWord(c.buf, cookie)
	c.buf = append(c.buf, '\n')
	err := c.roundTrip()
	for i := range c.buf {
		c.buf[i] = 0
	}
	c.buf = c.buf[:0]
	if err != nil {
		return fmt.Errorf("chirp: cookie: %w", err)
	}
	return nil
}

// Close shuts the connection down. It is safe on a nil client.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// SetJobAttr sets an attribute IMMEDIATELY: the starter forwards it to
// the shadow, which writes it to the schedd's queue, and only then does
// this call return. That round trip is why it is reserved for the one
// thing that must not wait -- see Reporter.
func (c *Client) SetJobAttr(name string, v Expr) error {
	return c.setAttr("set_job_attr", name, v, 0)
}

// SetJobAttrDelayed records an attribute for the starter to include in
// its NEXT periodic update to the shadow (STARTER_UPDATE_INTERVAL, five
// minutes by default). The call itself is a loopback round trip and
// costs the schedd nothing, which is what makes it the right verb for
// anything published on a timer.
//
// The starter refuses a name that does not match
// CHIRP_DELAYED_UPDATE_PREFIX (`Chirp*` as shipped) -- and refuses it in
// a way the client cannot see, so the check is duplicated in Reporter
// where a mismatch can be reported to whoever wrote the name.
func (c *Client) SetJobAttrDelayed(name string, v Expr) error {
	return c.setAttr("set_job_attr_delayed", name, v, delayedExprMax)
}

func (c *Client) setAttr(verb, name string, v Expr, exprMax int) error {
	if !validName(name) {
		return fmt.Errorf("chirp: %s: %q is not a ClassAd attribute name", verb, name)
	}
	if v == "" {
		// The wire has no representation for it; see the package comment.
		return fmt.Errorf("chirp: %s %s: empty expression", verb, name)
	}
	if exprMax > 0 && len(v) > exprMax {
		return fmt.Errorf("chirp: %s %s: expression is %d bytes, the starter accepts %d",
			verb, name, len(v), exprMax)
	}
	c.buf = append(c.buf[:0], verb...)
	c.buf = append(c.buf, ' ')
	c.buf = appendWord(c.buf, []byte(name))
	c.buf = append(c.buf, ' ')
	c.buf = appendWord(c.buf, []byte(v))
	c.buf = append(c.buf, '\n')
	return c.roundTrip()
}

// GetJobAttr reads one attribute back as an unparsed ClassAd
// expression. On success the starter answers with the LENGTH of the
// value and then that many raw bytes, with no newline of their own --
// the one reply in this client that is not a bare status line.
func (c *Client) GetJobAttr(name string) (string, error) {
	if !validName(name) {
		return "", fmt.Errorf("chirp: get_job_attr: %q is not a ClassAd attribute name", name)
	}
	c.buf = append(c.buf[:0], "get_job_attr "...)
	c.buf = appendWord(c.buf, []byte(name))
	c.buf = append(c.buf, '\n')
	n, err := c.command()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	if n > LineMax {
		return "", fmt.Errorf("chirp: get_job_attr %s: reply claims %d bytes", name, n)
	}
	body := make([]byte, n)
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", err
	}
	if _, err := readFull(c.br, body); err != nil {
		return "", fmt.Errorf("chirp: get_job_attr %s: %w", name, err)
	}
	return string(body), nil
}

// ULog appends a line to the job's USER LOG -- the file the submitter
// named with `log =`, the one `condor_wait` follows. It is the only
// channel here that a person reads without running condor_q, which is
// what makes it worth spending on a mount failure.
func (c *Client) ULog(msg string) error {
	msg = sanitizeULog(msg)
	if msg == "" {
		return errors.New("chirp: ulog: empty message")
	}
	c.buf = append(c.buf[:0], "ulog "...)
	c.buf = appendWord(c.buf, []byte(msg))
	c.buf = append(c.buf, '\n')
	return c.roundTrip()
}

// sanitizeULog makes a message safe to carry as one chirp word and
// readable once it lands. Newlines are turned into spaces rather than
// escaped: the user log is a record-structured file, and a message with
// an embedded newline in it would be a second, malformed record.
func sanitizeULog(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, msg)
	// Runs collapse: a CRLF would otherwise leave a double space in the
	// middle of every sentence a Windows-authored error produced.
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > uLogMax {
		msg = msg[:uLogMax]
	}
	return msg
}

// roundTrip sends c.buf and requires a success reply.
func (c *Client) roundTrip() error {
	_, err := c.command()
	return err
}

// command sends c.buf and returns the reply code, which is an error only
// when negative.
func (c *Client) command() (int, error) {
	if c.conn == nil {
		return 0, errors.New("chirp: connection is closed")
	}
	if len(c.buf) > LineMax {
		// The starter answers CHIRP_ERROR_TOO_BIG and then CLOSES the
		// connection, so this is worth refusing locally: an oversized
		// line costs the session, not just the request.
		return 0, fmt.Errorf("chirp: request is %d bytes, the limit is %d", len(c.buf), LineMax)
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(c.buf); err != nil {
		return 0, fmt.Errorf("chirp: write: %w", err)
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	line, err := c.br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return 0, fmt.Errorf("chirp: reply longer than %d bytes with no newline", LineMax)
		}
		return 0, fmt.Errorf("chirp: read: %w", err)
	}
	n, ok := scanInt(line)
	if !ok {
		return 0, fmt.Errorf("chirp: unparsable reply %q", trimLine(line))
	}
	if n < 0 {
		return 0, Code(n)
	}
	return n, nil
}

func trimLine(b []byte) string {
	return strings.TrimRight(string(b), "\r\n")
}

// scanInt reproduces sscanf(line, "%d"): leading whitespace is skipped,
// an optional sign and a run of decimal digits are consumed, and
// whatever follows on the line is ignored. Reimplemented rather than
// handed to strconv because the trailing-junk rule is load-bearing --
// a starter that ever appends anything to a status line must not turn
// every reply into a protocol error.
func scanInt(b []byte) (int, bool) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r' || b[i] == '\v' || b[i] == '\f') {
		i++
	}
	neg := false
	if i < len(b) && (b[i] == '+' || b[i] == '-') {
		neg = b[i] == '-'
		i++
	}
	start := i
	n := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		n = n*10 + int(b[i]-'0')
		if n > 1<<40 { // far past any legal reply; stop before overflow
			return 0, false
		}
		i++
	}
	if i == start {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

// readFull is io.ReadFull without the import, kept here so the deadline
// set by the caller governs the whole body read.
func readFull(r *bufio.Reader, p []byte) (int, error) {
	n := 0
	for n < len(p) {
		m, err := r.Read(p[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// appendWord escapes s as a chirp %s argument. The escape set is
// vsprintf_chirp's exactly: space, tab, newline, carriage return and
// backslash, each prefixed with a backslash. Anything else -- including
// quotes, which matter because every string value on this wire is a
// quoted ClassAd literal -- passes through untouched, and the starter's
// sscanf_chirp strips one backslash before any character it finds one
// on, which makes the pair exactly reversible.
func appendWord(b, s []byte) []byte {
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r', '\\':
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	return b
}
