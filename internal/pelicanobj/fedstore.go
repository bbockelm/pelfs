package pelicanobj

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"

	"github.com/bbockelm/pelfs/internal/pelcred"
)

// fedStore stores objects in a Pelican federation via the Pelican client
// library, getting its director handling, endpoint failover, retries, and
// token acquisition for free.
type fedStore struct {
	// ctx is the long-lived context the PelicanFS (and its transfer engine)
	// is bound to. The Pelican fs API does not take per-operation contexts;
	// per-op cancellation is bounded by the caller's own timeouts.
	ctx    context.Context
	prefix string // pelican://host/path, no trailing slash
	pfs    *client.PelicanFS
	opts   []client.TransferOption
	// directRead appends ?directread to every operation so reads bypass
	// federation caches — mandatory for mutable objects (lease, snapshots)
	// whose read-after-write semantics a stale cache copy would break.
	directRead bool
	// rangeFS serves GetUnverified. It is a SECOND handle because the byte
	// range is fixed when the handle is built, and it must not apply to
	// ordinary reads, which stay checksum-verified.
	rangeOnce sync.Once
	rangeFS   *client.PelicanFS
}

// MaxMutableObject bounds an unverified read. Everything read that way is
// a superblock or a lease — hundreds of bytes — so this is a sanity limit,
// and hitting it is reported as an error rather than silently truncating.
const MaxMutableObject = 1 << 20

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
		// Object-storage PUT semantics are upsert: uploads are retried by
		// key, and the branch ref is overwritten in place on every flip
		// (guarded by ETag checks).
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

	if cfg.AcquireToken && cfg.TokenPath == "" {
		// Unlock the credential wallet from the macOS Keychain before
		// priming, so the device-flow-or-prompt decision below is made
		// with the wallet already open rather than behind a password
		// prompt. A no-op everywhere but macOS, and a no-op there when
		// the user has no stored password; the returned call offers to
		// remember one they had to type. See internal/pelcred.
		remember := pelcred.Unlock(ctx)
		primeCredential(ctx, strings.TrimRight(cfg.PrefixURL, "/"))
		remember()
	}

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

// primeCredential acquires one credential up front covering everything the
// filesystem will ever ask a Pelican origin to do: read objects, create them,
// and overwrite them.
//
// The Pelican client asks for exactly the scope the operation in hand needs,
// which is right for a CLI — `pelican object get` should not make a user
// approve write access — but wrong for us. A mount reads, then creates, then
// overwrites, and each first-of-its-kind operation whose scope the stored
// token lacks starts its own OIDC device flow: a URL to visit and a code to
// type, arriving in the middle of filesystem I/O rather than at mount time.
// Three approvals for one mount, at moments the user is not looking.
//
// The client's own scope mapping gives us the whole set if we ask for the
// whole set (TokenRead -> storage.read, TokenWrite -> storage.create,
// TokenDelete -> storage.modify), so a single request covers everything. The
// result lands in the credential wallet, and because the client checks a
// stored token against the scopes each later operation needs, this one
// satisfies all of them -- no further device flows.
//
// Best-effort by design. A failure here is not a mount failure: it may just
// mean nobody is at a terminal to approve anything (the device flow refuses
// to start when stdout is not a TTY), and every operation still acquires its
// own credential the way it always did. All this buys is doing it once, at a
// moment the user is watching.
func primeCredential(ctx context.Context, prefixURL string) {
	pUrl, err := client.ParseRemoteAsPUrl(ctx, prefixURL)
	if err != nil {
		slog.Debug("skipping credential priming: cannot parse prefix", "prefix", prefixURL, "err", err)
		return
	}

	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, http.MethodGet, "")
	if err != nil {
		slog.Debug("skipping credential priming: director lookup failed", "prefix", prefixURL, "err", err)
		return
	}

	opts := config.TokenGenerationOpts{
		Operation: config.TokenRead | config.TokenWrite | config.TokenDelete,
	}
	if _, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts); err != nil {
		slog.Debug("credential priming did not produce a token; operations will acquire their own",
			"prefix", prefixURL, "err", err)
		return
	}
	slog.Debug("acquired a credential covering read, create and modify", "prefix", prefixURL)
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
// os.ErrNotExist, the one thing callers test for.
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

func (s *fedStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
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

// DirectVariant returns a store that appends ?directread to every read.
// It shares the PelicanFS handle and transfer options — only the query
// suffix differs — so this costs nothing at the transport layer. Fields
// are named rather than copied wholesale because the range handle above
// is guarded by a sync.Once, which must not be copied.
func (s *fedStore) DirectVariant() Store {
	if s.directRead {
		return s
	}
	return &fedStore{ctx: s.ctx, prefix: s.prefix, pfs: s.pfs, opts: s.opts, directRead: true}
}

// GetUnverified reads an object through a RANGED transfer, which the
// Pelican client deliberately does not checksum: a server-advertised
// digest covers a whole object and cannot be applied to a range, so
// verification is skipped.
//
// It exists for ONE reason. An origin was observed answering for a
// mutable object with a body and a digest taken from different versions
// of it — in both directions, once with the digest a generation behind
// the body and once with the body older than the digest. Only objects
// pelfs overwrites in place can hit this; content-addressed packs and
// catalogs are written once, and they keep full verification.
//
// This is not a claim that the bytes are trustworthy. The superblock
// carries an Ed25519 signature, which is far stronger than a transport
// md5, and refs.Fetch additionally refuses a generation older than one it
// has already accepted. Those two checks — not this transfer — are what
// make an unverified read safe to act on.
//
// TEMPORARY: delete this, and the fallback in ReadMutable, once origins
// answer consistently for overwritten objects.
func (s *fedStore) GetUnverified(_ context.Context, key string) (io.ReadCloser, error) {
	s.rangeOnce.Do(func() {
		opts := append(append([]client.TransferOption{}, s.opts...),
			client.WithByteRange(0, MaxMutableObject-1))
		s.rangeFS = client.NewPelicanFSWithPrefix(s.ctx, s.prefix, opts...)
	})
	f, err := s.rangeFS.OpenFile("/"+strings.TrimLeft(key, "/")+s.querySuffix(), os.O_RDONLY)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return f.(io.ReadCloser), nil
}

func (s *fedStore) Put(ctx context.Context, key string, in io.Reader) error {
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

func (s *fedStore) Delete(ctx context.Context, key string) error {
	err := s.deleteKey(ctx, key)
	if err != nil && errors.Is(mapNotFound(err), os.ErrNotExist) {
		// Deletes are idempotent per the ObjectStorage contract.
		return nil
	}
	return err
}

func (s *fedStore) Head(ctx context.Context, key string) (*Object, error) {
	fi, err := s.stat(ctx, key)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &Object{Key: key, Size: fi.Size, Mtime: fi.ModTime, IsDir: fi.IsCollection}, nil
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

func (s *fedStore) ListAll(ctx context.Context, prefix, marker string) (<-chan *Object, error) {
	return listAll(ctx, s, prefix, marker)
}
