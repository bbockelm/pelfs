// Package pelicanobj implements a JuiceFS object-storage backend that stores
// objects in a Pelican federation beneath a fixed namespace prefix.
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
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/juicedata/juicefs/pkg/object"
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

// Store is a JuiceFS object storage over a Pelican prefix, extended with the
// directory/ETag operations the snapshot manager needs.
type Store interface {
	object.ObjectStorage
	// ListDir lists the immediate children of dir (a key-space directory
	// relative to the prefix, "" for the prefix root).
	ListDir(ctx context.Context, dir string) ([]DirEntry, error)
	// StatKey returns size/mtime/ETag for one object.
	StatKey(ctx context.Context, key string) (*KeyInfo, error)
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

type pobj struct {
	key   string
	size  int64
	mtime time.Time
	isDir bool
}

func newObj(key string, size int64, mtime time.Time, isDir bool) object.Object {
	return &pobj{key: key, size: size, mtime: mtime, isDir: isDir}
}

func (o *pobj) Key() string          { return o.key }
func (o *pobj) Size() int64          { return o.size }
func (o *pobj) Mtime() time.Time     { return o.mtime }
func (o *pobj) IsDir() bool          { return o.isDir }
func (o *pobj) IsSymlink() bool      { return false }
func (o *pobj) StorageClass() string { return "" }
func (o *pobj) Status() string       { return "" }

// listAll walks the prefix depth-first in sorted order, emitting every
// object whose key begins with prefix and sorts after marker. Used by
// snapshot restore and by JuiceFS offline tools (gc/fsck), not by the mount
// data path.
func listAll(ctx context.Context, s Store, prefix, marker string) (<-chan object.Object, error) {
	ch := make(chan object.Object, 64)
	go func() {
		defer close(ch)
		walk(ctx, s, "", prefix, marker, ch)
	}()
	return ch, nil
}

func walk(ctx context.Context, s Store, dir, prefix, marker string, ch chan<- object.Object) {
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
		case ch <- newObj(key, e.Size, e.Mtime, false):
		}
	}
}
