// Package lease implements an advisory mount lease so concurrent writers on
// the same federation prefix are detected instead of silently corrupting
// each other.
//
// One well-known object, meta/lease.json, names the current holder. The
// transport offers no compare-and-swap, so this is detection rather than a
// hard mutex: acquisition is write-then-read-back, and every renewal first
// checks (via the object's server-side ETag) that nobody overwrote the
// lease since our last write. A holder that dies simply stops renewing and
// its lease expires after the TTL.
//
// The lease is read and written through the raw prefix store — never the
// encryption wrapper — so even a client with a wrong or missing volume key
// still sees that the prefix is in use.
package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// Key is the lease object's location relative to the prefix.
const Key = "meta/lease.json"

const (
	// DefaultTTL is how long a lease stays live without renewal.
	DefaultTTL = 2 * time.Minute
	opTimeout  = 30 * time.Second
)

// ErrHeld indicates another live client holds the lease.
var ErrHeld = errors.New("prefix is in use by another pelfs client")

// Info is the on-federation lease record.
type Info struct {
	Session  string    `json:"session"`
	Hostname string    `json:"hostname"`
	PID      int       `json:"pid"`
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
	return fmt.Sprintf("%s (pid %d, session %s, renewed %s ago)",
		i.Hostname, i.PID, i.Session, time.Since(i.Renewed).Round(time.Second))
}

// Options configures Acquire.
type Options struct {
	Store   pelicanobj.Store
	Session string
	// TTL after which a non-renewed lease is considered dead (DefaultTTL
	// when zero). RenewInterval defaults to TTL/4.
	TTL           time.Duration
	RenewInterval time.Duration
	// Steal takes over a live lease held by someone else.
	Steal bool
	// OnConflict is called (once) if another client overwrites our lease
	// while we hold it.
	OnConflict func(holder *Info)
}

// Lease is a held mount lease with a background renewal loop.
type Lease struct {
	store pelicanobj.Store
	opts  Options
	info  Info

	mu         sync.Mutex
	lastETag   string
	conflicted bool

	stop chan struct{}
	done chan struct{}
}

// Acquire takes the lease for opts.Session, refusing with ErrHeld when a
// live lease belongs to someone else (unless opts.Steal). On success a
// background renewal loop runs until Release.
func Acquire(ctx context.Context, opts Options) (*Lease, error) {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.RenewInterval <= 0 {
		opts.RenewInterval = opts.TTL / 4
	}
	// The lease is a mutable object rewritten on every renewal, and its
	// whole purpose is read-after-write: a cached copy would show a stale
	// holder and hand two writers the same volume. Enforced here so no
	// caller can forget it (see refs.New for the same guard).
	if d, ok := pelicanobj.AsDirectReader(opts.Store); ok {
		opts.Store = d.DirectVariant()
	}

	holder, ki, err := read(ctx, opts.Store)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read lease: %w", err)
	}
	if ki != nil && !opts.Steal {
		if live, ttl := isLive(holder, ki, opts.TTL); live {
			return nil, fmt.Errorf("%w: held by %s; expires in %s if that client is dead (or pass --steal-lease / use --ro)",
				ErrHeld, holder.Describe(), ttl.Round(time.Second))
		}
	}

	host, _ := os.Hostname()
	l := &Lease{
		store: opts.Store,
		opts:  opts,
		info: Info{
			Session:  opts.Session,
			Hostname: host,
			PID:      os.Getpid(),
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
	// RenewInterval, so a single attempt loses to routine renewal and
	// reports a conflict that is not one. Retrying converges quickly,
	// since the holder's own verify sees our record and stops renewing.
	//
	// A plain acquisition does NOT retry. Losing means another client
	// acquired the volume, and yielding is the point — two simultaneous
	// starters must not fight over it.
	attempts := 1
	if opts.Steal {
		attempts = 4
	}
	var lost error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(opts.RenewInterval / 2):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if err := l.write(ctx); err != nil {
			return nil, fmt.Errorf("write lease: %w", err)
		}
		after, ki2, err := read(ctx, opts.Store)
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

func read(ctx context.Context, store pelicanobj.Store) (*Info, *pelicanobj.KeyInfo, error) {
	ki, err := store.StatKey(ctx, Key)
	if err != nil {
		return nil, nil, err
	}
	// The lease is rewritten on every renewal, so it is exposed to an
	// origin that answers an overwritten object with a mismatched digest.
	// Reading it through ReadMutable keeps such an origin from turning an
	// ADVISORY lock into a hard failure; a bad lease body costs at most a
	// spurious conflict, which callers already tolerate.
	data, err := pelicanobj.ReadMutable(ctx, store, Key)
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
	if err := l.store.Put(ctx, Key, strings.NewReader(string(data))); err != nil {
		return err
	}
	if ki, err := l.store.StatKey(ctx, Key); err == nil {
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

	ki, err := l.store.StatKey(ctx, Key)
	switch {
	case err == nil:
		l.mu.Lock()
		mine := ki.ETag == "" || ki.ETag == l.lastETag
		l.mu.Unlock()
		if !mine {
			holder, _, _ := read(ctx, l.store)
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
		fmt.Fprintf(os.Stderr, "pelfs: lease check failed (will retry): %v\n", err)
		return false
	}

	if err := l.write(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "pelfs: lease renewal failed (will retry): %v\n", err)
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
	ki, err := l.store.StatKey(ctx, Key)
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
	return l.store.Delete(ctx, Key)
}
