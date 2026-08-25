package chirp

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// The attribute set pelfs publishes into the job ad.
//
// # Why every name starts with Chirp
//
// Because the starter makes it mandatory. `set_job_attr_delayed` is
// refused for any name that does not match CHIRP_DELAYED_UPDATE_PREFIX,
// whose shipped default is `Chirp*` (param_info.in), and refused
// silently as far as the client can tell. `PelfsMountError` would work
// only on a pool whose admin had changed that setting; `ChirpPelfs...`
// works on a stock pool, which is the whole point.
//
// # Why this set and not a fuller one
//
// internal/stats already publishes about ninety fields for the reader
// who has the file. These nine are the ones an operator can ACT on while
// the job is still running, and each earns its place by naming a
// different decision:
//
//   - Session identifies which pelfs session this job's mount was, so
//     the statistics file and the pelfs log lines can be found later.
//   - Generation is provenance: which published generation the payload
//     actually read. It is the first question asked about any result.
//   - Heartbeat is the only signal that catches a WEDGED mount. A mount
//     that has stopped answering produces no error at all, so no error
//     attribute can describe it; a timestamp that stops advancing can.
//   - BytesDown and BytesUp are progress. A job whose transfer counters
//     are flat for an hour is not slow, it is stuck.
//   - UploadBacklog is bytes cut into packs and not yet sent -- what is
//     LOST if the job is evicted right now, and the best predictor of
//     how long the seal after the payload will take.
//   - ObjectErrors counts transient federation failures that were
//     retried successfully. Rising here is a sick federation before it
//     is a failed job.
//   - MountError and MountErrorReason are the latch: the mount has
//     already answered the payload with an I/O error it could not
//     explain. This pair is the whole point of the feature, and what it
//     is for is spelled out at Fail.
//
// Everything else that was considered -- cache occupancy, eviction
// counts, per-phase splits, dedup ratios -- answers a question asked
// AFTER the job, and after the job the statistics file is a better
// answer than a job ad.
const (
	AttrSession       = "ChirpPelfsSession"
	AttrGeneration    = "ChirpPelfsGeneration"
	AttrHeartbeat     = "ChirpPelfsHeartbeat"
	AttrBytesDown     = "ChirpPelfsBytesDown"
	AttrBytesUp       = "ChirpPelfsBytesUp"
	AttrUploadBacklog = "ChirpPelfsUploadBacklog"
	AttrObjectErrors  = "ChirpPelfsObjectErrors"
	AttrMountError    = "ChirpPelfsMountError"
	AttrErrorReason   = "ChirpPelfsMountErrorReason"
)

// PeriodicAttrs is the set published on a timer, in the order it is
// sent. Exported so the documentation and the tests describe the same
// list this code sends.
var PeriodicAttrs = []string{
	AttrSession, AttrGeneration, AttrHeartbeat,
	AttrBytesDown, AttrBytesUp, AttrUploadBacklog, AttrObjectErrors,
}

// DefaultInterval is how often the periodic attributes are refreshed.
//
// The cadence question is not "how fresh can we make this" -- it is
// "what does a thousand mounts do to a schedd". The answer is set by
// which verb is used, not by this number: everything on the timer goes
// out with set_job_attr_delayed, which the starter accumulates locally
// and folds into the update it was going to send the shadow anyway
// (STARTER_UPDATE_INTERVAL, 300s by default). So the schedd sees pelfs's
// numbers at the starter's rate no matter what is chosen here, and this
// interval only governs loopback round trips to a process on the same
// machine.
//
// Given that, one minute: comfortably inside the starter's window, so no
// forwarded update ever carries a figure more than a minute stale; five
// times cheaper than riding the 30-second statistics tick; and slow
// enough that the whole feature is about a hundred short writes to a
// unix-domain-shaped TCP socket over a ten-hour job.
//
// The error latch does NOT ride this timer. It is the one thing that
// would be worthless five minutes late, so it uses the immediate verb
// and pays the synchronous trip to the schedd -- once per session, at
// most, because it is latched.
const DefaultInterval = time.Minute

// maxReasonBytes bounds the error text. The starter refuses a delayed
// expression over 993 bytes, and quoting can nearly double a pathological
// string, so the text is cut well below that; the interesting part of a
// mount error is its first line anyway.
const maxReasonBytes = 400

// Mount is the sample a session hands the reporter. It is a plain struct
// on purpose: this package must not depend on internal/stats, so that
// the client above stays a chirp client rather than a pelfs-shaped one.
type Mount struct {
	Session       string
	Generation    uint64
	BytesDown     int64
	BytesUp       int64
	UploadBacklog int64
	ObjectErrors  int64
}

// Reporter publishes a mount's health into the job ad. The zero value
// and a nil pointer are both usable and inert, which is what lets every
// caller skip the "am I in a job" branch -- and pelfs is USUALLY not in
// a job.
type Reporter struct {
	mu  sync.Mutex
	cfg Config
	c   *Client
	// timeout bounds every exchange; a field rather than the constant so
	// the tests can prove the stalled-starter path in milliseconds
	// instead of waiting out a real one.
	timeout time.Duration

	// last is what the job ad already holds, so an attribute whose value
	// has not moved costs nothing. On an idle mount that reduces a cycle
	// to the single heartbeat write.
	last map[string]Expr

	// failed latches the error report, so a Fail called twice cannot
	// produce two synchronous trips to the schedd.
	failed bool

	// nextDial rate-limits reconnection. A starter that has gone away
	// must not turn a periodic reporter into a connect loop.
	nextDial time.Time
	dead     bool

	// closed makes every method a no-op after Close. It matters because
	// the mount is still serving while the session tears itself down, so
	// the error latch can fire after the reporter has been shut: without
	// this, that call would redial with a cookie Close had already
	// erased.
	closed bool
}

// reconnectEvery bounds reconnection attempts after an I/O failure.
const reconnectEvery = 2 * time.Minute

// Open locates the chirp configuration and connects to the starter.
//
// A process that is not running under a starter -- every interactive
// pelfs, every test -- gets an INERT reporter and a nil error. That is
// not a convenience: making "no job" an error would put a branch at
// every call site whose common outcome is the uninteresting one, and the
// branch would eventually be written wrong.
//
// A configuration that exists but cannot be used is different, and comes
// back as an error alongside the inert reporter, so a caller can say so
// out loud without failing the mount over it.
func Open(ctx context.Context) (*Reporter, error) {
	cfg, err := FindConfig()
	if err != nil {
		if errors.Is(err, ErrNoJob) {
			return &Reporter{}, nil
		}
		return &Reporter{}, err
	}
	r := newReporter(cfg, DefaultTimeout)
	c, err := Dial(ctx, cfg, r.timeout)
	if err != nil {
		// Keep the configuration: the starter may simply not be ready
		// yet, and the next cycle will try again.
		r.nextDial = time.Now().Add(reconnectEvery)
		return r, err
	}
	r.c = c
	return r, nil
}

// newReporter builds an unconnected reporter for cfg.
func newReporter(cfg Config, timeout time.Duration) *Reporter {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Reporter{
		cfg:     cfg,
		timeout: timeout,
		last:    make(map[string]Expr, len(PeriodicAttrs)+2),
	}
}

// InJob reports whether a chirp configuration was found. It answers the
// question "will anything I report be seen", and nothing else.
func (r *Reporter) InJob() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg.Host != ""
}

// Config returns the discovered configuration, cookie omitted.
func (r *Reporter) Config() Config {
	if r == nil {
		return Config{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return Config{Host: r.cfg.Host, Port: r.cfg.Port, Path: r.cfg.Path}
}

// Close drops the connection and erases the cookie.
func (r *Reporter) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	err := r.c.Close()
	r.c = nil
	r.cfg.Zero()
	return err
}

// Begin stamps the start of this ATTEMPT by setting the mount-error flag
// to false.
//
// It exists because the attribute is STICKY. A chirp update is written
// into the schedd's copy of the job ad, so it survives the job being
// requeued -- and the recommended policy expression requeues a job whose
// mount failed. Without this call, one bad run would leave the flag true
// forever and every subsequent attempt would be requeued on the strength
// of a failure that happened on some other machine an hour ago, until
// the retry bound cut it off. With it, the flag means "THIS attempt's
// mount failed", which is what every expression a user writes assumes.
//
// It goes out on the same channel Fail uses -- immediate where the job
// ad allows it, delayed otherwise -- and that matters more than it
// looks: the delayed updates are a dictionary the starter flushes on its
// own schedule, so a `false` parked there and a `true` sent immediately
// would land in the wrong order and revert the failure. Using one
// channel for both makes the sequence unambiguous, because whether the
// immediate verb works is a property of the job ad and does not change
// mid-run.
//
// The REASON attribute is deliberately not cleared. Fail writes the
// reason before the flag, so "flag is true" implies "reason is this
// attempt's" at every instant, and a stale reason sitting beside a false
// flag is the previous attempt's diagnosis -- worth keeping, and read by
// nothing.
func (r *Reporter) Begin() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.Host == "" || r.closed {
		return nil
	}
	if err := r.connect(); err != nil {
		return err
	}
	if err := r.setNowOrLater(AttrMountError, Bool(false)); err != nil {
		r.faultLocked(err)
		return err
	}
	return nil
}

// Publish refreshes the periodic attributes. Unchanged values are not
// resent.
func (r *Reporter) Publish(m Mount) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.Host == "" || r.closed {
		return nil
	}
	if err := r.connect(); err != nil {
		return err
	}
	vals := map[string]Expr{
		AttrSession:       String(m.Session),
		AttrGeneration:    Uint(m.Generation),
		AttrHeartbeat:     Int(time.Now().Unix()),
		AttrBytesDown:     Int(m.BytesDown),
		AttrBytesUp:       Int(m.BytesUp),
		AttrUploadBacklog: Int(m.UploadBacklog),
		AttrObjectErrors:  Int(m.ObjectErrors),
	}
	for _, name := range PeriodicAttrs {
		v := vals[name]
		// Skipping what the ad already holds is what keeps an idle
		// mount's cycle down to the one attribute that moves on its own.
		if v == "" || r.last[name] == v {
			continue
		}
		if err := r.c.SetJobAttrDelayed(name, v); err != nil {
			// Stop at the first failure rather than sending the rest into
			// the same broken socket. Nothing is recorded in r.last, so
			// the next cycle sends the whole set again.
			r.faultLocked(err)
			return err
		}
		r.last[name] = v
	}
	return nil
}

// Fail reports, exactly once, that the mount has answered the payload
// with an I/O error.
//
// # What this is actually for
//
// The danger is not the error. The danger is EXIT 0 WITH A CORRUPT
// RESULT. Programs that read a filesystem overwhelmingly do not check
// read(2) for EIO -- there was no reason to think a read could fail --
// so a job that was handed one very often runs to completion, writes
// output, and exits successfully. Nothing downstream can tell that
// output apart from a correct answer, and the job's own exit status
// says it is fine.
//
// So this attribute exists to make that outcome un-recordable. A submit
// file that evaluates it in on_exit_remove sends the job round again;
// one that evaluates it in on_exit_hold stops it for a human. The cost
// asymmetry is what settles which way to lean: re-running a job costs
// some CPU, while recording a wrong scientific result costs whatever is
// built on top of it, possibly years later.
//
// The enforcement is the SCHEDD's, not this process's. A chirp update
// lands in the shadow's copy of the job ad (pseudo_ops.cpp:603 for the
// immediate path, remoteresource.cpp:1647 for the delayed one), and the
// shadow is what evaluates the exit policy -- so a policy expression
// works in every deployment shape, including the ones where pelfs is a
// --fusemount driver that never sees a payload process.
//
// Three things happen here and their ORDER is deliberate:
//
//  1. ulog, so the failure lands in the job's user log -- the file a
//     person reads without running condor_q, and the only one of these
//     three that survives the job being removed from the queue.
//  2. the REASON attribute, then
//  3. the FLAG attribute.
//
// Two and three are separate round trips, so a schedd evaluating
// periodic_hold between them would see the flag with no reason if they
// were sent the other way round -- and periodic_hold_reason is where the
// message the user actually reads comes from. Sending the reason first
// makes "flag is true" imply "reason is present" at every instant.
//
// The immediate verb needs `+WantIOProxy = true` in the submit file. If
// the starter refuses it, this falls back to the delayed verb -- and
// that fallback is stronger than it sounds: the starter drains its
// delayed-update dictionary into the JOB EXIT AD as well as into its
// periodic ones (jic_shadow.cpp, notifyJobExit -> publishUpdateAd), and
// the shadow applies that ad BEFORE it evaluates the exit policy
// (pseudo_ops.cpp, pseudo_job_exit). So an on_exit_remove or
// on_exit_hold expression fires correctly even on a job that never
// opted into anything. What +WantIOProxy buys is the value being in the
// queue DURING the run -- which is what a periodic_hold can act on, and
// what survives the job being evicted rather than exiting.
func (r *Reporter) Fail(reason string) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.Host == "" || r.closed || r.failed {
		return nil
	}
	if err := r.connect(); err != nil {
		return err
	}
	r.failed = true
	reason = truncate(reason, maxReasonBytes)
	if reason == "" {
		reason = "the pelfs mount returned an I/O error to the job"
	}

	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Best effort, and not fatal to the rest: ulog is gated on the same
	// WantIOProxy the immediate update is, and losing the log line is a
	// much smaller loss than losing the hold.
	note(ignoreRefusal(r.c.ULog("pelfs: mount I/O error: " + reason)))
	note(r.setNowOrLater(AttrErrorReason, String(reason)))
	note(r.setNowOrLater(AttrMountError, Bool(true)))
	if firstErr != nil {
		r.faultLocked(firstErr)
	}
	return firstErr
}

// Failed reports whether the error latch has already been sent.
func (r *Reporter) Failed() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed
}

// setNowOrLater tries the immediate verb and falls back to the delayed
// one when the starter refuses it -- which is what "the job ad did not
// say WantIOProxy" looks like from here.
func (r *Reporter) setNowOrLater(name string, v Expr) error {
	err := r.c.SetJobAttr(name, v)
	if err == nil {
		r.last[name] = v
		return nil
	}
	if !refused(err) {
		return err
	}
	if err := r.c.SetJobAttrDelayed(name, v); err != nil {
		return err
	}
	r.last[name] = v
	return nil
}

// refused reports whether err is the starter declining a command,
// as opposed to the connection failing. The starter answers a command
// it is not configured for by falling off the end of its dispatch chain,
// which is indistinguishable from an unknown verb: CHIRP_ERROR_INVALID_
// REQUEST. A shadow that declines the attribute answers NOT_AUTHORIZED.
func refused(err error) bool {
	var code Code
	if !errors.As(err, &code) {
		return false
	}
	return code == ErrInvalidRequest || code == ErrNotAuthorized || code == ErrNotAuthenticated
}

// ignoreRefusal swallows exactly the "your job did not ask for this"
// answers, and nothing else.
func ignoreRefusal(err error) error {
	if refused(err) {
		return nil
	}
	return err
}

// Run publishes on a timer until ctx is done. sample is called once per
// cycle and must not block. onErr, if given, is handed each publish
// failure; this package has no opinion about output, and a reporting
// channel that has quietly stopped working is exactly the thing a
// caller wants to say out loud once.
func (r *Reporter) Run(ctx context.Context, every time.Duration, sample func() Mount, onErr func(error)) {
	if r == nil || !r.InJob() {
		return
	}
	if every <= 0 {
		every = DefaultInterval
	}
	publish := func() {
		if err := r.Publish(sample()); err != nil && onErr != nil {
			onErr(err)
		}
	}
	// One push straight away: a job that dies in its first minute should
	// still carry the session id and the generation it was reading.
	publish()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			publish()
		}
	}
}

// connect ensures there is a live connection. Callers hold mu.
func (r *Reporter) connect() error {
	if r.c != nil {
		return nil
	}
	if r.dead && time.Now().Before(r.nextDial) {
		return errors.New("chirp: not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	c, err := Dial(ctx, r.cfg, r.timeout)
	if err != nil {
		r.dead = true
		r.nextDial = time.Now().Add(reconnectEvery)
		return err
	}
	r.c, r.dead = c, false
	// The starter keeps no memory of a connection that went away, so
	// everything has to be resent on the new one.
	clear(r.last)
	return nil
}

// faultLocked drops a connection that has stopped working. A protocol
// refusal is NOT a fault: the connection is fine, the starter simply
// said no, and reconnecting would change nothing.
func (r *Reporter) faultLocked(err error) {
	if refused(err) {
		return
	}
	_ = r.c.Close()
	r.c = nil
	r.dead = true
	r.nextDial = time.Now().Add(reconnectEvery)
}

// truncate cuts s to at most n bytes without splitting a rune.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// DelayedPrefixAllows reports whether name would survive the starter's
// CHIRP_DELAYED_UPDATE_PREFIX check, using the pattern list the starter
// exports as _CHIRP_DELAYED_UPDATE_PREFIX. With no such variable it
// answers true: the caller is then outside a job, or talking to a
// starter old enough not to export it, and refusing to report on a guess
// would be worse than trying.
//
// This exists so a pool that has narrowed the setting produces one clear
// warning rather than a session of silent no-ops -- the starter's own
// refusal is invisible to the client (see Reporter.setNowOrLater).
func DelayedPrefixAllows(name string) bool {
	pats := os.Getenv("_CHIRP_DELAYED_UPDATE_PREFIX")
	if strings.TrimSpace(pats) == "" {
		return true
	}
	for _, p := range strings.FieldsFunc(pats, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		if matchWild(p, name) {
			return true
		}
	}
	return false
}

// matchWild is HTCondor's contains_anycase_withwildcard rule: a
// case-insensitive comparison in which a single '*' in the pattern
// stands for any run of characters.
func matchWild(pat, s string) bool {
	pat, s = strings.ToLower(pat), strings.ToLower(s)
	star := strings.IndexByte(pat, '*')
	if star < 0 {
		return pat == s
	}
	head, tail := pat[:star], pat[star+1:]
	return len(s) >= len(head)+len(tail) &&
		strings.HasPrefix(s, head) && strings.HasSuffix(s, tail)
}
