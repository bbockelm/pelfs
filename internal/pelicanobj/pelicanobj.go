// Package pelicanobj stores objects in a Pelican federation beneath a
// fixed namespace prefix.
//
// Two transports are provided behind the Store interface:
//
//   - pelican:// and osdf:// prefixes use the Pelican client library
//     (client.PelicanFS and friends), inheriting its director handling,
//     endpoint failover, retries, and token acquisition machinery.
//   - http:// and https:// prefixes talk directly to a single server with a
//     small built-in HTTP client. This is the test/dev path (fakeorigin,
//     plain WebDAV servers) and performs no federation discovery.
//
// Objects live at <prefix>/<key>; metadata snapshots use StatKey's ETag to
// detect concurrent writers.
package pelicanobj

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pelicanplatform/pelican/error_codes"

	"github.com/bbockelm/pelfs/internal/ui"
)

const userAgent = "pelfs/0.1"

// Config controls construction of a Store.
type Config struct {
	// PrefixURL is the root under which all objects are stored:
	// pelican://<federation>/<path>, osdf://<path>, or (direct mode)
	// http(s)://<server>/<path>.
	PrefixURL string
	// TokenPath is an explicit bearer-token file. When empty, the Pelican
	// client's token discovery/acquisition is used (federation mode) or
	// WLCG bearer-token discovery (direct mode).
	TokenPath string
	// AcquireToken lets the Pelican client run token-acquisition flows
	// (e.g. OIDC) when no usable token is found. Federation mode only.
	AcquireToken bool
	// DirectRead forces reads to come from the origin (?directread),
	// bypassing federation caches. Required for MUTABLE objects — the
	// mount lease and metadata snapshots — where a cached stale copy
	// breaks read-after-write (e.g. lease acquisition verification).
	// Immutable data chunks should leave this off and enjoy the caches.
	DirectRead bool
	// Insecure skips TLS verification (for local test federations).
	Insecure bool
}

// engineWorkers caches the Pelican client's transfer-engine pool size
// (Client.WorkerCount), recorded once client config is initialized.
var engineWorkers atomic.Int64

// TransferWorkers reports how many block transfers the Pelican client runs
// concurrently — the value of the standard Client.WorkerCount config knob.
// Falls back to a small default before federation-mode initialization (e.g.
// direct http:// test stores).
func TransferWorkers() int {
	if n := engineWorkers.Load(); n > 0 {
		return int(n)
	}
	return 8
}

// KeyInfo is metadata about one object, including its ETag when the server
// provides one.
type KeyInfo struct {
	Size  int64
	Mtime time.Time
	ETag  string
}

// DirEntry describes one entry from ListDir.
type DirEntry struct {
	Name  string // base name, no slashes
	IsDir bool
	Size  int64
	Mtime time.Time
}

// Object is one object as a listing or a Head reports it.
type Object struct {
	Key   string
	Size  int64
	Mtime time.Time
	IsDir bool
}

// ObjectStore is the object surface a transport provides. It is
// deliberately the smallest set pelfs actually calls: everything in the
// format is immutable and content-addressed, so there is no rename, no
// copy, and no multipart upload to abstract over.
type ObjectStore interface {
	// String names the transport, for logs and error messages.
	String() string
	// Get reads key. A negative limit reads to the end.
	Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error)
	// Put writes key, replacing any previous object.
	Put(ctx context.Context, key string, in io.Reader) error
	// Delete removes key. A missing key is not an error.
	Delete(ctx context.Context, key string) error
	// Head reports one object's metadata.
	Head(ctx context.Context, key string) (*Object, error)
	// ListAll walks the prefix depth-first in sorted order, emitting every
	// object whose key begins with prefix and sorts after marker. A nil
	// value on the channel is the failure sentinel.
	ListAll(ctx context.Context, prefix, marker string) (<-chan *Object, error)
}

// Store is an ObjectStore over a Pelican prefix, extended with the
// directory and ETag operations the ref and pack layers need.
type Store interface {
	ObjectStore
	// ListDir lists the immediate children of dir (a key-space directory
	// relative to the prefix, "" for the prefix root).
	ListDir(ctx context.Context, dir string) ([]DirEntry, error)
	// StatKey returns size/mtime/ETag for one object.
	StatKey(ctx context.Context, key string) (*KeyInfo, error)
}

// DirectReader is implemented by transports that can produce a variant of
// themselves whose reads bypass federation caches. Callers that touch
// MUTABLE objects use it to enforce read-after-write: a cached copy of an
// object that was just overwritten is stale by construction, and on a
// cache that mis-reports object length it can even arrive truncated —
// which surfaces as a checksum mismatch rather than as anything obviously
// cache-shaped.
type DirectReader interface {
	// DirectVariant returns an equivalent store that never reads through
	// caches. Implementations may return the receiver when it already
	// bypasses them.
	DirectVariant() Store
}

// UnverifiedReader is implemented by transports that can read an object
// without comparing it against a server-advertised checksum. See
// ReadMutable for when that is appropriate, and fedStore.GetUnverified
// for why it exists at all.
type UnverifiedReader interface {
	GetUnverified(ctx context.Context, key string) (io.ReadCloser, error)
}

// Unwrapper is implemented by stores that DECORATE another store —
// statistics counters, the pack layer — and can hand back what they wrap.
//
// It exists because a decorator that embeds the Store interface silently
// drops every capability outside it. Both optional interfaces here are
// exactly that kind of capability, and both were quietly inert on the
// mount path for precisely this reason: the direct-read rule never
// applied, and the unverified-read fallback could not find a transport
// able to perform it. Probing a decorator without unwrapping does not
// fail loudly, it just does nothing, which is why these lookups go
// through the helpers below rather than a bare type assertion.
type Unwrapper interface {
	Unwrap() Store
}

// AsDirectReader finds the nearest store that can bypass caches,
// unwrapping decorators on the way down.
func AsDirectReader(s Store) (DirectReader, bool) {
	for s != nil {
		if d, ok := s.(DirectReader); ok {
			return d, true
		}
		u, ok := s.(Unwrapper)
		if !ok {
			return nil, false
		}
		s = u.Unwrap()
	}
	return nil, false
}

// AsUnverifiedReader finds the nearest store that can read without
// transport checksum verification, unwrapping decorators on the way down.
func AsUnverifiedReader(s Store) (UnverifiedReader, bool) {
	for s != nil {
		if u, ok := s.(UnverifiedReader); ok {
			return u, true
		}
		w, ok := s.(Unwrapper)
		if !ok {
			return nil, false
		}
		s = w.Unwrap()
	}
	return nil, false
}

// ReadMutable reads one small mutable object whole.
//
// It reads normally first, so a healthy federation keeps full checksum
// verification. Only when the server reports that its own advertised
// digest disagrees with the body it just sent does it retry without
// verification — a state no correct origin produces, and one the caller
// cannot route around, since those are the only bytes on offer.
//
// The retry is safe only because every caller re-checks the result by
// stronger means than a transport digest: refs verifies an Ed25519
// signature and refuses a generation older than one already accepted,
// and the lease is advisory, where the worst outcome is a spurious
// conflict warning.
func ReadMutable(ctx context.Context, s Store, key string) ([]byte, error) {
	raw, err := readWhole(func() (io.ReadCloser, error) {
		return s.Get(ctx, key, 0, -1)
	})
	if err == nil || !isChecksumMismatch(err) {
		return raw, err
	}
	u, ok := AsUnverifiedReader(s)
	if !ok {
		ui.Warn("origin served a body its own checksum does not describe ({key}), and this "+
			"transport cannot re-read without verification", "key", key)
		return nil, err
	}
	ui.Warn("origin's advertised checksum disagrees with the body it served for {key}: {error}; "+
		"re-reading without transport verification (signature and generation checks still apply)",
		"key", key, "error", err)
	raw, rerr := readWhole(func() (io.ReadCloser, error) {
		return u.GetUnverified(ctx, key)
	})
	if rerr != nil {
		// Say that the retry was tried and failed. Reporting only the
		// original error made these two outcomes -- "never attempted"
		// and "attempted, still refused" -- indistinguishable from the
		// outside, which cost a debugging round trip against a real
		// federation.
		ui.Warn("unverified re-read of {key} also failed: {error}", "key", key, "error", rerr)
		return nil, err
	}
	ui.Warn("unverified re-read of {key} succeeded; continuing on signature and generation checks",
		"key", key)
	return raw, nil
}

// readWhole reads an object with a hard ceiling, so a mutable object that
// is unexpectedly enormous is an error rather than a silent truncation or
// an unbounded allocation.
func readWhole(open func() (io.ReadCloser, error)) ([]byte, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(rc, MaxMutableObject+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > MaxMutableObject {
		return nil, fmt.Errorf("mutable object exceeds %d bytes", int64(MaxMutableObject))
	}
	return raw, nil
}

// isChecksumMismatch reports the one condition the fallback answers:
// Pelican's Transfer.ChecksumMismatch (6006).
//
// The typed check is the right one, but it is not sufficient on its own.
// The error crosses the PelicanFS boundary, where a transfer failure can
// be rebuilt as a plain error, and a lost type meant the fallback never
// ran against the deployment it was written for -- the failure looked
// exactly like having no fallback at all. So the code is matched
// textually too. That is ugly, and it is deliberate: this whole path is
// a temporary workaround for a misbehaving origin, and being unable to
// recognize the very condition it exists for is the worse failure.
func isChecksumMismatch(err error) bool {
	if err == nil {
		return false
	}
	var pe *error_codes.PelicanError
	if errors.As(err, &pe) {
		return pe.Code() == 6006
	}
	msg := err.Error()
	return strings.Contains(msg, "ChecksumMismatch") || strings.Contains(msg, "Error code 6006")
}

// New builds a Store for the given prefix URL, selecting the transport from
// the URL scheme.
func New(ctx context.Context, cfg Config) (Store, error) {
	u, err := url.Parse(cfg.PrefixURL)
	if err != nil {
		return nil, fmt.Errorf("parse prefix URL: %w", err)
	}
	switch u.Scheme {
	case "pelican", "osdf":
		return newFedStore(ctx, cfg)
	case "https", "http":
		return newDirectStore(ctx, cfg, u)
	default:
		return nil, fmt.Errorf("unsupported prefix URL scheme %q (want pelican:// or, for direct mode, https://)", u.Scheme)
	}
}

// listAll is the shared ObjectStore.ListAll implementation over ListDir.
// It is an inventory operation — never the mount data path, which
// resolves objects from a generation's pack list.
func listAll(ctx context.Context, s Store, prefix, marker string) (<-chan *Object, error) {
	ch := make(chan *Object, 64)
	go func() {
		defer close(ch)
		walk(ctx, s, "", prefix, marker, ch)
	}()
	return ch, nil
}

func walk(ctx context.Context, s Store, dir, prefix, marker string, ch chan<- *Object) {
	entries, err := s.ListDir(ctx, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		key := e.Name
		if dir != "" {
			key = dir + "/" + e.Name
		}
		if e.IsDir {
			// Skip subtrees that cannot contain matching keys.
			dirPrefix := key + "/"
			if prefix != "" && !strings.HasPrefix(dirPrefix, prefix) && !strings.HasPrefix(prefix, dirPrefix) {
				continue
			}
			walk(ctx, s, key, prefix, marker, ch)
			continue
		}
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		if marker != "" && key <= marker {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case ch <- &Object{Key: key, Size: e.Size, Mtime: e.Mtime}:
		}
	}
}
