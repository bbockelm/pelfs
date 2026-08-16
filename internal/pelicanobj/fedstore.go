package pelicanobj

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/juicedata/juicefs/pkg/object"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// fedStore stores objects in a Pelican federation via the Pelican client
// library, getting its director handling, endpoint failover, retries, and
// token acquisition for free.
type fedStore struct {
	object.DefaultObjectStorage
	// ctx is the long-lived context the PelicanFS (and its transfer engine)
	// is bound to. The Pelican fs API does not take per-operation contexts;
	// per-op cancellation is bounded by JuiceFS's chunk-store timeouts.
	ctx    context.Context
	prefix string // pelican://host/path, no trailing slash
	pfs    *client.PelicanFS
	opts   []client.TransferOption
	// directRead appends ?directread to every operation so reads bypass
	// federation caches — mandatory for mutable objects (lease, snapshots)
	// whose read-after-write semantics a stale cache copy would break.
	directRead bool
}

var _ Store = (*fedStore)(nil)

var (
	initClientOnce sync.Once
	initClientErr  error
)

func newFedStore(ctx context.Context, cfg Config) (*fedStore, error) {
	if cfg.Insecure {
		// Must be set before the client config is initialized.
		os.Setenv("PELICAN_TLSSKIPVERIFY", "true")
	}
	initClientOnce.Do(func() {
		if initClientErr = config.InitClient(); initClientErr != nil {
			return
		}
		// Object-storage PUT semantics are upsert: JuiceFS re-uploads keys
		// on retry and the snapshot manager overwrites its session object
		// in place (guarded by ETag checks).
		if initClientErr = param.Client_EnableOverwrites.Set(true); initClientErr != nil {
			return
		}
		// Every full-block transfer executes on the client's shared
		// TransferEngine worker pool, sized by the standard Pelican config
		// knob Client.WorkerCount (config file or PELICAN_CLIENT_WORKERCOUNT,
		// which the Docker fallback forwards). Record it so prefetch can
		// size its own pool to match.
		engineWorkers.Store(int64(param.Client_WorkerCount.GetInt()))
	})
	if initClientErr != nil {
		return nil, fmt.Errorf("initialize pelican client: %w", initClientErr)
	}

	var opts []client.TransferOption
	if cfg.TokenPath != "" {
		opts = append(opts, client.WithTokenLocation(cfg.TokenPath))
	}
	opts = append(opts, client.WithAcquireToken(cfg.AcquireToken))

	// Transfer-only options: accept either CRC32C (the client default) or
	// MD5 for transfer verification, since many deployed origins provide
	// only MD5. This must NOT be in the shared opts — DoStat interprets a
	// checksum request as "collect these digests during stat" and warns
	// whenever the server omits one, which would fire on every StatKey
	// (e.g. each 30s lease-renewal ETag check).
	pfsOpts := append(append([]client.TransferOption{}, opts...),
		client.WithRequestChecksums([]client.ChecksumType{client.AlgCRC32C, client.AlgMD5}))

	prefix := strings.TrimRight(cfg.PrefixURL, "/")
	return &fedStore{
		ctx:        ctx,
		prefix:     prefix,
		pfs:        client.NewPelicanFSWithPrefix(ctx, prefix, pfsOpts...),
		opts:       opts,
		directRead: cfg.DirectRead,
	}, nil
}

// querySuffix is appended to every object URL/path this store builds.
func (s *fedStore) querySuffix() string {
	if s.directRead {
		return "?directread"
	}
	return ""
}

// keyURL maps an object key to its absolute pelican:// URL.
func (s *fedStore) keyURL(key string) string {
	return s.prefix + "/" + strings.TrimLeft(key, "/") + s.querySuffix()
}

// mapNotFound folds the client's various not-found signals into
// os.ErrNotExist so JuiceFS's checks work.
func mapNotFound(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	msg := err.Error()
	if errors.Is(err, client.ErrObjectNotFound) ||
		strings.Contains(msg, "404") || strings.Contains(strings.ToLower(msg), "not found") {
		return fmt.Errorf("%w: %w", err, os.ErrNotExist)
	}
	return err
}

// stat resolves one object's metadata through the transfer engine, so the
// director response is taken from the engine's cache rather than re-queried.
// This is the hot path for mutable objects: the mount lease stats every 30s
// to check its ETag, and the snapshot manager stats before every overwrite.
// Cache entries are keyed by flavor (verb, routing, query), so this store's
// ?directread stats can never be answered with the cache-routed response the
// chunk store gets -- the isolation the lease depends on.
func (s *fedStore) stat(ctx context.Context, key string) (*client.FileInfo, error) {
	url := s.keyURL(key)
	if te := s.pfs.Engine(); te != nil {
		return te.Stat(ctx, url, s.opts...)
	}
	return client.DoStat(ctx, url, s.opts...)
}

func (s *fedStore) String() string {
	return s.prefix + "/"
}

func (s *fedStore) Limits() object.Limits {
	return object.Limits{IsSupportMultipartUpload: false}
}

func (s *fedStore) Create(ctx context.Context) error {
	// The namespace exists a priori in the federation; nothing to create.
	return nil
}

func (s *fedStore) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	f, err := s.pfs.OpenFile("/"+strings.TrimLeft(key, "/")+s.querySuffix(), os.O_RDONLY)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if off > 0 {
		if _, err := f.(io.Seeker).Seek(off, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	if limit > 0 {
		return struct {
			io.Reader
			io.Closer
		}{io.LimitReader(f.(io.Reader), limit), f}, nil
	}
	return f.(io.ReadCloser), nil
}

// DirectVariant returns a copy that appends ?directread to every read.
// The copy shares the PelicanFS handle and transfer options — only the
// query suffix differs — so this costs nothing at the transport layer.
func (s *fedStore) DirectVariant() Store {
	if s.directRead {
		return s
	}
	c := *s
	c.directRead = true
	return &c
}

func (s *fedStore) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
	// Retry safety: the PelicanFS write path streams through a pipe the
	// transfer engine cannot rewind — a mid-transfer retry re-reads a
	// half-consumed pipe and corrupts the object (a failure the writing
	// session never notices, because it reads its own blocks from the
	// local cache). When the caller hands us a real file — pack seals,
	// snapshot uploads — upload by path so retries reopen from byte zero.
	if lf, ok := in.(*os.File); ok && lf.Name() != "" {
		if _, err := client.DoPut(ctx, lf.Name(), s.prefix+"/"+strings.TrimLeft(key, "/"), false, s.opts...); err != nil {
			return fmt.Errorf("pelican put %q: %w", key, err)
		}
		return nil
	}
	f, err := s.pfs.OpenFile("/"+strings.TrimLeft(key, "/"), os.O_WRONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	w, ok := f.(io.Writer)
	if !ok {
		f.Close()
		return fmt.Errorf("pelican put %q: file handle is not writable", key)
	}
	if _, err := io.Copy(w, in); err != nil {
		f.Close()
		return fmt.Errorf("pelican put %q: %w", key, err)
	}
	// Close drains the upload pipe and reports the transfer result.
	if err := f.Close(); err != nil {
		return fmt.Errorf("pelican put %q: %w", key, err)
	}
	return nil
}

func (s *fedStore) Delete(ctx context.Context, key string, getters ...object.AttrGetter) error {
	err := s.deleteKey(ctx, key)
	if err != nil && errors.Is(mapNotFound(err), os.ErrNotExist) {
		// Deletes are idempotent per the ObjectStorage contract.
		return nil
	}
	return err
}

func (s *fedStore) Head(ctx context.Context, key string) (object.Object, error) {
	fi, err := s.stat(ctx, key)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return newObj(key, fi.Size, fi.ModTime, fi.IsCollection), nil
}

func (s *fedStore) StatKey(ctx context.Context, key string) (*KeyInfo, error) {
	fi, err := s.stat(ctx, key)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &KeyInfo{Size: fi.Size, Mtime: fi.ModTime, ETag: fi.ETag}, nil
}

// deleteKey and list mirror stat: they route through the transfer engine so
// the director response comes from its cache. Snapshot pruning deletes and
// lists many objects in one namespace at shutdown, which otherwise costs a
// director round trip -- and, for listings, a whole transfer engine built and
// torn down -- per object.
func (s *fedStore) deleteKey(ctx context.Context, key string) error {
	url := s.keyURL(key)
	if te := s.pfs.Engine(); te != nil {
		return te.Delete(ctx, url, false, s.opts...)
	}
	return client.DoDelete(ctx, url, false, s.opts...)
}

func (s *fedStore) list(ctx context.Context, dir string) ([]client.FileInfo, error) {
	url := s.keyURL(dir)
	if te := s.pfs.Engine(); te != nil {
		return te.List(ctx, url, s.opts...)
	}
	return client.DoList(ctx, url, s.opts...)
}

func (s *fedStore) ListDir(ctx context.Context, dir string) ([]DirEntry, error) {
	dir = strings.Trim(dir, "/")
	fis, err := s.list(ctx, dir)
	if err != nil {
		return nil, mapNotFound(err)
	}
	selfName := path.Base("/" + dir)
	entries := make([]DirEntry, 0, len(fis))
	for _, fi := range fis {
		name := path.Base(strings.TrimRight(fi.Name, "/"))
		if name == "" || name == "." || name == "/" {
			continue
		}
		// Some endpoints include the collection itself in the listing.
		if fi.IsCollection && name == selfName {
			continue
		}
		entries = append(entries, DirEntry{
			Name:  name,
			IsDir: fi.IsCollection,
			Size:  fi.Size,
			Mtime: fi.ModTime,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (s *fedStore) ListAll(ctx context.Context, prefix, marker string, followLink bool) (<-chan object.Object, error) {
	return listAll(ctx, s, prefix, marker)
}
