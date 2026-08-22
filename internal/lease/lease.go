// Package lease implements an advisory write lease so concurrent writers on
// the same federation prefix are detected instead of silently corrupting
// each other.
//
// ONE OBJECT PER BRANCH, meta/lease-<branch>.json, names the current
// holder of that branch. The transport offers no compare-and-swap, so this
// is DETECTION rather than a hard mutex: acquisition is
// write-then-read-back, and every renewal first checks (via the object's
// server-side ETag) that nobody overwrote the lease since our last write.
// A holder that dies simply stops renewing and its lease expires after the
// TTL.
//
// That framing is worth keeping in view when reading the rest of this
// package: the lease is not what makes concurrent writes SAFE. The real
// guard is the seal's compare-and-swap against refs/<branch>, which
// refuses to publish over a ref that moved. What the lease buys is finding
// out at MOUNT time rather than after an hour of work that is about to be
// thrown away. Going per-branch narrows a FALSE exclusion — two writers
// who never touch the same ref no longer refuse each other — and adds no
// safety that was not already there.
//
// # The v0.1.0 volume lease
//
// v0.1.0 had one object for the whole prefix, meta/lease.json (VolumeKey),
// and a v0.1.0 writer holds it whatever branch it is on. So a v0.2 writer
// checks it, READ-ONLY, before taking its own branch lease: if a legacy
// volume lease is live, refuse, because that writer could be on any branch
// including ours.
//
// A v0.2 writer never WRITES the volume lease. It is tempting — it would
// make v0.1.0 clients see us — but two v0.2 writers on different branches
// would then exclude each other through the legacy object, which is
// exactly the false exclusion this change exists to remove. The
// consequence is stated plainly rather than hidden: a v0.1.0 client sees a
// v0.2 writer as UNLEASED. Its guard is then the seal refusal, which is
// the real guard anyway.
//
// Neither lease is read or written through the encryption wrapper — a
// client with a wrong or missing volume key must still see that the branch
// is in use.
package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/ui"
)

// VolumeKey is the v0.1.0 lease object: ONE record for the whole prefix,
// no matter which branch its holder was writing. This release never writes
// it; it reads it so a v0.1.0 writer is still detected. See the package
// comment for why writing it would reintroduce the exclusion.
const VolumeKey = "meta/lease.json"

// Dir is the key-space directory every lease object lives in.
const Dir = "meta"

// A branch lease is Dir/lease-<branch>.json. The wrapper is fixed on both
// sides, so the mapping from branch to key is injective and no branch name
// can produce VolumeKey (that would need "-<branch>." to equal ".").
const (
	branchKeyPrefix = "lease-"
	branchKeySuffix = ".json"
)

// BranchKey is where the lease for a branch lives, relative to the prefix.
//
// The name goes through refs.ValidateName — the SAME rule the ref and tag
// key spaces use, deliberately, rather than a second rule that could drift
// from it. Two of its clauses are load-bearing here and not cosmetic:
//
//   - No path separator, no "." or "..": a branch named "../refs/main"
//     would otherwise address an object outside meta/, and the lease is
//     written with the caller's credentials.
//   - No ".tmp" suffix: every listing that enumerates the key space skips
//     such a name (that is how a partial write announces itself), so a
//     lease under one would be invisible to anything sweeping meta/ —
//     including the check in `pelfs shell` that decides whether a prefix
//     holds a retired-format volume.
//
// A branch that cannot hold a ref cannot hold a lease either, which is the
// property worth having: there is no name that mounts but does not lock.
func BranchKey(branch string) (string, error) {
	if err := refs.ValidateName(branch); err != nil {
		return "", fmt.Errorf("lease: %w", err)
	}
	return Dir + "/" + branchKeyPrefix + branch + branchKeySuffix, nil
}

// IsLeaseObject reports whether a name directly under Dir is one of
// pelfs's lease objects — the legacy volume one or any branch's.
//
// It exists for the one caller that must tell "meta/ holds a lease" from
// "meta/ holds a retired block-and-snapshot volume", and gets that wrong
// in the direction that INITIALIZES A NEW VOLUME OVER SOMEBODY'S DATA if
// it is not kept in step with BranchKey.
func IsLeaseObject(name string) bool {
	return name == path.Base(VolumeKey) ||
		(strings.HasPrefix(name, branchKeyPrefix) && strings.HasSuffix(name, branchKeySuffix))
}

const (
	// DefaultTTL is how long a lease stays live without renewal.
	DefaultTTL = 2 * time.Minute
	opTimeout  = 30 * time.Second

	// stealRetryBackoff is the first pause between a steal's attempts, and
	// it doubles from there — 100ms, 200ms, 400ms, so a steal that loses
	// every race still returns inside a second.
	//
	// It is a fixed, short quantity ON PURPOSE. It used to be
	// opts.RenewInterval/2, which is the STEALER's own renew cadence and
	// has nothing whatever to do with the race being retried: the pause
	// exists only to let a renewal that is already in flight land before
	// we write again, and that takes one round trip, not a fraction of an
	// unrelated timer.
	//
	// Tying it to the caller's interval made the wait grow without bound
	// as the caller renewed less often. At the production default
	// (RenewInterval = TTL/4 = 30s) a steal that lost one race stalled 15
	// SECONDS for nothing; in lease_test.go, where slowOpts sets an hour
	// to keep the renewal loop quiet, it became a THIRTY MINUTE sleep,
	// which outlived Go's test deadline and hung the package. That is what
	// took out the unit lane: not a failure, a stall, and the goroutine
	// dump pointed straight at this select.
	stealRetryBackoff = 100 * time.Millisecond
)

// ErrHeld indicates another live client holds the lease.
var ErrHeld = errors.New("prefix is in use by another pelfs client")

// Info is the on-federation lease record.
//
// Branch was added with the per-branch key. It is redundant with the key
// the record was READ from and is written anyway, because the two places a
// record is quoted — a refusal message and `pelfs status` — are both about
// telling a person what the other client is doing, and because a v0.1.0
// record has no branch at all, which is itself the thing to report.
type Info struct {
	Session  string    `json:"session"`
	Hostname string    `json:"hostname"`
	PID      int       `json:"pid"`
	Branch   string    `json:"branch,omitempty"`
	Acquired time.Time `json:"acquired"`
	Renewed  time.Time `json:"renewed"`
	TTLSecs  float64   `json:"ttl_seconds"`
}

func (i *Info) ttl() time.Duration {
	if i == nil || i.TTLSecs <= 0 {
		return 0
	}
	return time.Duration(i.TTLSecs * float64(time.Second))
}

// Describe renders a holder for error and warning messages.
func (i *Info) Describe() string {
	if i == nil {
		return "an unknown client (unparseable lease record)"
	}
	where := ""
	if i.Branch != "" {
		where = fmt.Sprintf(", branch %s", i.Branch)
	}
	return fmt.Sprintf("%s (pid %d, session %s%s, renewed %s ago)",
		i.Hostname, i.PID, i.Session, where, time.Since(i.Renewed).Round(time.Second))
}

// Options configures Acquire.
type Options struct {
	Store   pelicanobj.Store
	Session string
	// Branch is the line of history this writer will advance; the lease it
	// takes is that branch's alone. Required — there is no whole-volume
	// lease to fall back on, and a writer that cannot say what it is about
	// to move has nothing to lock.
	Branch string
	// TTL after which a non-renewed lease is considered dead (DefaultTTL
	// when zero). RenewInterval defaults to TTL/4.
	TTL           time.Duration
	RenewInterval time.Duration
	// Steal takes over a live lease held by someone else — THIS BRANCH's
	// lease, and only that one. The v0.1.0 volume lease is a different
	// object with a different blast radius and takes IgnoreVolumeLease.
	Steal bool
	// IgnoreVolumeLease proceeds past a live v0.1.0 volume lease
	// (meta/lease.json) instead of refusing.
	//
	// It IGNORES rather than steals, and the difference is deliberate: a
	// steal writes the object, and this release never writes the volume
	// lease (see the package comment). So the object is left exactly where
	// it was, to expire on its own TTL or be renewed by a holder that is
	// still alive — in which case the next writer is refused again, which
	// is correct.
	IgnoreVolumeLease bool
	// OnConflict is called (once) if another client overwrites our lease
	// while we hold it.
	OnConflict func(holder *Info)
}

// Lease is a held write lease with a background renewal loop.
type Lease struct {
	store pelicanobj.Store
	key   string
	opts  Options
	info  Info

	mu         sync.Mutex
	lastETag   string
	conflicted bool

	stop chan struct{}
	done chan struct{}
}

// Key is the object this lease is held on. `pelfs status` and the session
// statistics both report it, so "which lease do I hold" is answerable
// without knowing this package's naming rule.
func (l *Lease) Key() string { return l.key }

// Acquire takes opts.Branch's lease for opts.Session, refusing with ErrHeld
// when a live lease belongs to someone else (unless opts.Steal). On success
// a background renewal loop runs until Release.
//
// It refuses on a live v0.1.0 VOLUME lease as well, and that check is not
// what opts.Steal covers. See the package comment for the whole
// mixed-version rule.
func Acquire(ctx context.Context, opts Options) (*Lease, error) {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.RenewInterval <= 0 {
		opts.RenewInterval = opts.TTL / 4
	}
	key, err := BranchKey(opts.Branch)
	if err != nil {
		return nil, err
	}
	// The lease is a mutable object rewritten on every renewal, and its
	// whole purpose is read-after-write: a cached copy would show a stale
	// holder and hand two writers the same branch. Enforced here so no
	// caller can forget it (see refs.New for the same guard).
	if d, ok := pelicanobj.AsDirectReader(opts.Store); ok {
		opts.Store = d.DirectVariant()
	}

	// The legacy volume lease FIRST, because it is the wider exclusion and
	// the more surprising one: a v0.1.0 client holding it may be writing
	// any branch, so it excludes everybody, and a message that named our
	// branch's holder instead would send the user after the wrong client.
	//
	// Read-only, always. Not stolen by --steal-lease, not rewritten, not
	// deleted. It costs one round trip per acquisition in a federation
	// where no v0.1.0 client will ever appear again, which is the price of
	// the interoperability window and is paid once at mount.
	if err := checkVolumeLease(ctx, opts); err != nil {
		return nil, err
	}

	holder, ki, err := read(ctx, opts.Store, key)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read lease: %w", err)
	}
	if ki != nil && !opts.Steal {
		if live, ttl := isLive(holder, ki, opts.TTL); live {
			return nil, fmt.Errorf("%w: branch %s is held by %s; expires in %s if that client is dead "+
				"(or pass --steal-lease, use --ro, or write a different branch — a lease covers ONE branch)",
				ErrHeld, opts.Branch, holder.Describe(), ttl.Round(time.Second))
		}
	}

	host, _ := os.Hostname()
	l := &Lease{
		store: opts.Store,
		key:   key,
		opts:  opts,
		info: Info{
			Session:  opts.Session,
			Hostname: host,
			PID:      os.Getpid(),
			Branch:   opts.Branch,
			Acquired: time.Now().UTC(),
			TTLSecs:  opts.TTL.Seconds(),
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	// Write, then read back: with no compare-and-swap, a racing writer may
	// have overwritten us in between — last writer wins, so if the record
	// is not ours, we lost.
	//
	// A STEAL retries that, because the writer it races is not contesting
	// the acquisition at all: the current holder rewrites the record every
	// renewal, so a single attempt loses to routine renewal and reports a
	// conflict that is not one. Retrying converges quickly, since the
	// holder's own verify sees our record and stops renewing — and each
	// attempt is an independent race over a window only as wide as our own
	// write-then-read, so the pause between them is short and fixed
	// (stealRetryBackoff) rather than a function of anybody's timer.
	//
	// A plain acquisition does NOT retry. Losing means another client
	// acquired the branch, and yielding is the point — two simultaneous
	// starters must not fight over it.
	attempts := 1
	if opts.Steal {
		attempts = 4
	}
	var lost error
	backoff := stealRetryBackoff
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			backoff *= 2
		}
		if err := l.write(ctx); err != nil {
			return nil, fmt.Errorf("write lease: %w", err)
		}
		after, ki2, err := read(ctx, opts.Store, key)
		if err != nil {
			return nil, fmt.Errorf("verify lease: %w", err)
		}
		if after != nil && after.Session == opts.Session {
			l.lastETag = ki2.ETag
			lost = nil
			break
		}
		lost = fmt.Errorf("%w: lost acquisition race to %s", ErrHeld, after.Describe())
	}
	if lost != nil {
		return nil, lost
	}

	go l.renewLoop()
	return l, nil
}

// checkVolumeLease refuses when a v0.1.0 client holds the whole-prefix
// lease.
//
// THE ASYMMETRY IS THE POINT AND IS NOT AN OVERSIGHT. A v0.1.0 writer
// excludes everyone, because its record says nothing about which branch it
// is on and guessing "probably not mine" is how two writers end up on one
// ref. A v0.2 writer excludes only its own branch, and is invisible to a
// v0.1.0 client, which will therefore mount straight past it. Nothing here
// can fix that second half — the old client reads one key and we are not
// allowed to write it — so it is written down in the docs instead, next to
// the observation that the seal's refusal to publish over a moved ref was
// always the guard that mattered.
//
// The check is skipped entirely on IgnoreVolumeLease, which is the only
// escape and is a separate flag from --steal-lease on purpose: the blast
// radius of ignoring this object is "some client on an unknown branch",
// and a user reaching for --steal-lease is thinking about the branch in
// front of them.
func checkVolumeLease(ctx context.Context, opts Options) error {
	if opts.IgnoreVolumeLease {
		return nil
	}
	holder, ki, err := read(ctx, opts.Store, VolumeKey)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read volume lease: %w", err)
	}
	if ki == nil {
		return nil
	}
	live, ttl := isLive(holder, ki, opts.TTL)
	if !live {
		return nil
	}
	return fmt.Errorf("%w: %s is held by %s — a pelfs v0.1.0 client, which locks the WHOLE VOLUME and "+
		"may be writing any branch, including %s.\n"+
		"it expires in %s if that client is dead; --steal-lease does NOT apply (it takes one branch's lease, "+
		"not this), so pass --ignore-volume-lease if you know what is holding it",
		ErrHeld, VolumeKey, holder.Describe(), opts.Branch, ttl.Round(time.Second))
}

// isLive reports whether a lease record is still within its TTL, preferring
// the server-side mtime (one clock) over the holder-written timestamps, and
// returns the remaining time.
func isLive(holder *Info, ki *pelicanobj.KeyInfo, fallbackTTL time.Duration) (bool, time.Duration) {
	freshest := ki.Mtime
	ttl := fallbackTTL
	if holder != nil {
		if holder.Renewed.After(freshest) {
			freshest = holder.Renewed
		}
		if t := holder.ttl(); t > 0 {
			ttl = t
		}
	}
	remaining := time.Until(freshest.Add(ttl))
	return remaining > 0, remaining
}

// read fetches one lease object. Both keys go through it — the branch
// lease and the legacy volume one — so the per-branch objects inherit
// ReadMutable's checksum fallback and the direct-read store exactly as the
// single object did.
func read(ctx context.Context, store pelicanobj.Store, key string) (*Info, *pelicanobj.KeyInfo, error) {
	ki, err := store.StatKey(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	// The lease is rewritten on every renewal, so it is exposed to an
	// origin that answers an overwritten object with a mismatched digest.
	// Reading it through ReadMutable keeps such an origin from turning an
	// ADVISORY lock into a hard failure; a bad lease body costs at most a
	// spurious conflict, which callers already tolerate.
	data, err := pelicanobj.ReadMutable(ctx, store, key)
	if err != nil {
		return nil, ki, err
	}
	var info Info
	if err := json.Unmarshal(data, &info); err != nil {
		// Unparseable (foreign?) lease: liveness still works off the mtime.
		return nil, ki, nil
	}
	return &info, ki, nil
}

func (l *Lease) write(ctx context.Context) error {
	l.info.Renewed = time.Now().UTC()
	data, err := json.MarshalIndent(&l.info, "", "  ")
	if err != nil {
		return err
	}
	if err := l.store.Put(ctx, l.key, strings.NewReader(string(data))); err != nil {
		return err
	}
	if ki, err := l.store.StatKey(ctx, l.key); err == nil {
		l.mu.Lock()
		l.lastETag = ki.ETag
		l.mu.Unlock()
	}
	return nil
}

func (l *Lease) renewLoop() {
	defer close(l.done)
	t := time.NewTicker(l.opts.RenewInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			if l.renewOnce() {
				return
			}
		}
	}
}

// renewOnce renews the lease; it returns true when a conflict ends the loop.
func (l *Lease) renewOnce() bool {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	ki, err := l.store.StatKey(ctx, l.key)
	switch {
	case err == nil:
		l.mu.Lock()
		mine := ki.ETag == "" || ki.ETag == l.lastETag
		l.mu.Unlock()
		if !mine {
			holder, _, _ := read(ctx, l.store, l.key)
			l.mu.Lock()
			l.conflicted = true
			l.mu.Unlock()
			if l.opts.OnConflict != nil {
				l.opts.OnConflict(holder)
			}
			return true
		}
	case errors.Is(err, os.ErrNotExist):
		// Someone deleted our lease; reclaim it below.
	default:
		ui.Warn("lease check failed (will retry): {error}", "error", err)
		return false
	}

	if err := l.write(ctx); err != nil {
		ui.Warn("lease renewal failed (will retry): {error}", "error", err)
	}
	return false
}

// Conflicted reports whether another client overwrote the lease while we
// held it.
func (l *Lease) Conflicted() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conflicted
}

// Release stops renewing and removes the lease if it is still ours. Safe to
// call once; returns nil when the lease was taken over by someone else.
func (l *Lease) Release(ctx context.Context) error {
	close(l.stop)
	<-l.done
	if l.Conflicted() {
		return nil
	}
	ki, err := l.store.StatKey(ctx, l.key)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	l.mu.Lock()
	mine := ki.ETag == "" || ki.ETag == l.lastETag
	l.mu.Unlock()
	if !mine {
		return nil
	}
	return l.store.Delete(ctx, l.key)
}
