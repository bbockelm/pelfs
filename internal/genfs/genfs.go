// Package genfs is the FUSE-agnostic read-only core of the phase-3
// catalog-native VFS (docs/design-packfs.md, "Phase 3 VFS architecture"):
// generation resolver — catalog descent, inode residency, shard routing,
// chunk reads — resolved directly against v2 catalogs and packs. The API is
// kernel-shaped so a raw-FUSE binding maps onto it 1:1.
//
// Residency is built by descent, never by registry: the kernel always
// Lookups parent before child, so Lookup records inode -> catalog residency
// on the way down and Forget retires it by nlookup accounting. Operations
// on an inode with no residency return ErrStale — the kernel contract is
// that it Lookups first.
//
// Integrity: on unencrypted volumes (identity algo "blake3-256") every
// decoded catalog and chunk is verified against its plain-BLAKE3 identity
// once, at cache fill. On encrypted volumes identity is keyed BLAKE3 under
// the volume identity key, which genfs does NOT hold (only the unwrapped
// DEK arrives in Options) — there the AES-GCM tag, opened under the DEK,
// already authenticates every entry, so identity recomputation is skipped.
package genfs

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// RootInode is the volume root. It has implicit, permanent residency in the
// root catalog; Forget on it is a no-op.
const RootInode uint64 = 1

var (
	// ErrNotExist is returned when a name, inode row, xattr, or symlink
	// target is absent from the generation.
	ErrNotExist = errors.New("genfs: entry does not exist")
	// ErrStale is returned for operations on an inode with no residency:
	// the kernel never looked it up, or already forgot it.
	ErrStale = errors.New("genfs: stale inode (no residency)")
)

// Identity algo strings stamped into catalog_meta by publish.
const (
	identityAlgoPlain = "blake3-256"
	identityAlgoKeyed = "blake3-256-keyed"
)

// Options configures Open.
type Options struct {
	// Inner is the raw transport for pack range reads.
	Inner pelicanobj.Store
	// SB is the generation to serve. The caller has ALREADY verified its
	// signature; genfs trusts it as the integrity root.
	SB *superblock.Superblock
	// DEK is the unwrapped data-encryption key; nil for plaintext volumes.
	DEK []byte
	// CacheDir holds decoded-chunk cache files and catalog spill files.
	// Required. Contents persist across Open/Close (reopen is cheap).
	CacheDir string
	// MaxOpenCatalogs caps the LRU of open catalog handles (default 64).
	// The pinned root catalog does not count against it.
	MaxOpenCatalogs int
}

// Node is one inode's attributes: catalog.Node with a kernel-shaped uint64
// inode (the storage-internal keyid column is not surfaced).
type Node struct {
	Inode   uint64
	Type    uint8
	Mode    uint32
	UID     uint32
	GID     uint32
	MtimeNS int64
	CtimeNS int64
	Nlink   uint32
	Length  int64
	Rdev    uint32
	Flags   uint32
}

// DirEntry is one readdirplus-shaped directory entry: name plus attributes.
type DirEntry struct {
	Name string
	Node Node
}

// packLoc locates one pack entry: the identity index built at Open from the
// generation's pack trailers (the location layer; identity lives in
// catalogs).
type packLoc struct {
	pack   string
	off    int64
	length int64
}

// residency records which catalog an inode's node row resolves in, held
// while the kernel holds the inode (nlookup accounting).
type residency struct {
	cat     string // catalog identity, hex
	nlookup uint64
	// parent is the inode this one was reached through. Descent already
	// knows it, so recording it costs nothing and answers ".." — which a
	// kernel binding (and NFS export) cannot synthesize otherwise. A
	// directory has exactly one parent, so there is no ambiguity; for
	// hardlinked FILES the value is simply the most recent path used,
	// which is all POSIX promises.
	parent uint64
	// name is the edge this inode was reached by. With parent it forms
	// the descent step a generation swap replays to re-resolve the
	// inode in the new generation (catalog identities change; inodes do
	// not).
	name string
}

// FS serves one verified generation read-only. Safe for concurrent use.
type FS struct {
	inner    pelicanobj.Store
	sb       *superblock.Superblock
	dek      []byte
	chunkDir string
	catDir   string

	// verify: recompute plain-BLAKE3 identities at cache fill (unencrypted
	// volumes only; see the package comment).
	verify bool
	hasher chunkid.Hasher

	packIndex map[string]packLoc

	cats *catCache
	ext  *extentCache

	mu  sync.RWMutex
	res map[uint64]*residency

	fillMu sync.Mutex
	fills  map[string]*fillGate
}

// Open builds the identity index from the generation's pack trailers,
// fetches and pins the root catalog, and returns a ready filesystem. A
// wrong DEK fails here, at the root catalog's GCM open.
func Open(ctx context.Context, o Options) (*FS, error) {
	if o.Inner == nil || o.SB == nil {
		return nil, errors.New("genfs: Inner and SB are required")
	}
	if o.CacheDir == "" {
		return nil, errors.New("genfs: CacheDir is required")
	}
	if o.MaxOpenCatalogs <= 0 {
		o.MaxOpenCatalogs = 64
	}
	if o.SB.CatalogKeyID != 0 && len(o.DEK) == 0 {
		return nil, errors.New("genfs: volume catalogs are encrypted but no DEK was provided")
	}
	catDir := filepath.Join(o.CacheDir, "catalogs")
	chunkDir := filepath.Join(o.CacheDir, "chunks")
	for _, d := range []string{catDir, chunkDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("genfs: cache dir: %w", err)
		}
	}
	fs := &FS{
		inner:     o.Inner,
		sb:        o.SB,
		dek:       o.DEK,
		chunkDir:  chunkDir,
		catDir:    catDir,
		packIndex: make(map[string]packLoc),
		ext:       newExtentCache(extentCacheCap),
		res:       make(map[uint64]*residency),
		fills:     make(map[string]*fillGate),
	}
	// Identity index: every trailer in the generation's pack list, built
	// once, and no trailer's entries trusted until the stored bytes hash
	// to the value the SIGNED pack list records. Identical content dedups
	// at publish, so duplicate keys across packs reference the same
	// bytes; last writer wins harmlessly.
	for _, pe := range o.SB.PackList {
		entries, err := packstore.FetchTrailerVerified(ctx, o.Inner, pe.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			return nil, fmt.Errorf("genfs: index pack %s: %w", pe.Name, err)
		}
		for _, e := range entries {
			fs.packIndex[e.Key] = packLoc{pack: pe.Name, off: e.Off, length: e.Length}
		}
	}

	rootHex := hex.EncodeToString(o.SB.RootCatalog[:])
	rootPath, err := fs.spillCatalog(ctx, rootHex)
	if err != nil {
		return nil, fmt.Errorf("genfs: root catalog: %w", err)
	}
	root, err := catalog.Open(rootPath)
	if err != nil {
		return nil, fmt.Errorf("genfs: open root catalog: %w", err)
	}
	switch algo := root.Meta().IdentityAlgo; algo {
	case identityAlgoPlain:
		fs.verify = true
		fs.hasher = chunkid.NewHasher(nil)
		// The root was spilled before the algo was known; verify it now
		// (the spill file holds the decoded bytes).
		raw, err := os.ReadFile(rootPath)
		if err != nil {
			root.Close() //nolint:errcheck
			return nil, err
		}
		if id := fs.hasher.Sum(raw); id != chunkid.Identity(o.SB.RootCatalog) {
			root.Close() //nolint:errcheck
			return nil, fmt.Errorf("genfs: root catalog identity mismatch: got %s", id.Hex())
		}
	case identityAlgoKeyed:
		// Keyed identity; genfs holds no identity key. The GCM opens under
		// the DEK authenticate catalogs and encrypted chunks instead.
	default:
		root.Close() //nolint:errcheck
		return nil, fmt.Errorf("genfs: unknown identity algo %q", algo)
	}
	fs.cats = newCatCache(fs, o.MaxOpenCatalogs, rootHex, root)
	return fs, nil
}

// Close releases every open catalog handle. Spill and chunk cache files
// remain in CacheDir for the next Open.
func (fs *FS) Close() error {
	return fs.cats.closeAll()
}

// residencyOf returns the catalog identity (hex) an inode resolves in.
func (fs *FS) residencyOf(ino uint64) (string, error) {
	if ino == RootInode {
		return fs.cats.rootHex, nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	r := fs.res[ino]
	if r == nil {
		return "", ErrStale
	}
	return r.cat, nil
}

// retain records or bumps an inode's residency. Within a generation an
// inode's rows are immutable, so a second path reaching the same inode
// (hardlinks) keeps the first-recorded catalog — both carry the node row.
func (fs *FS) retain(ino uint64, catHex string, parent uint64, name string) {
	if ino == RootInode {
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if r := fs.res[ino]; r != nil {
		r.nlookup++
		r.parent, r.name = parent, name
		return
	}
	fs.res[ino] = &residency{cat: catHex, nlookup: 1, parent: parent, name: name}
}

// Lookup resolves name under parent, records the child's residency, and
// returns its attributes. A transition-point child (nested locator present)
// records the CHILD catalog as its residency: its attrs come from the
// parent catalog's node row, its entries resolve in the child.
func (fs *FS) Lookup(ctx context.Context, parent uint64, name string) (Node, error) {
	catHex, err := fs.residencyOf(parent)
	if err != nil {
		return Node{}, err
	}
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return Node{}, err
	}
	defer release()
	lr, err := cat.Lookup(int64(parent), []byte(name))
	if errors.Is(err, catalog.ErrNotExist) {
		return Node{}, ErrNotExist
	}
	if err != nil {
		return Node{}, err
	}
	if lr.Dirent == nil {
		return Node{}, fmt.Errorf("genfs: transition %q under inode %d has no dirent half", name, parent)
	}
	n, err := cat.Stat(lr.Dirent.Inode)
	if err != nil {
		return Node{}, fmt.Errorf("genfs: node row for %q (inode %d): %w", name, lr.Dirent.Inode, err)
	}
	childCat := catHex
	if lr.NestedIdentity != nil {
		childCat = hex.EncodeToString(lr.NestedIdentity)
	}
	fs.retain(uint64(lr.Dirent.Inode), childCat, parent, name)
	return nodeOf(n), nil
}

// Parent returns the inode this one was reached through, answering "..".
// The root is its own parent, as POSIX requires. ErrStale when the inode
// has no residency (the kernel looked nothing up).
func (fs *FS) Parent(ino uint64) (uint64, error) {
	if ino == RootInode {
		return RootInode, nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	r, ok := fs.res[ino]
	if !ok {
		return 0, ErrStale
	}
	if r.parent == 0 {
		return RootInode, nil
	}
	return r.parent, nil
}

// LookupPath descends from the root along a slash-separated path,
// establishing residency at every step, and returns the final node. It
// is how a caller re-attaches to an inode it knows only by path — the
// overlay reopening across sessions, or a binding resolving a stored
// handle — without genfs keeping a reverse index (the catalog is a
// locator BY DESCENT; a registry would rebuild the CVMFS hotspot).
func (fs *FS) LookupPath(ctx context.Context, p string) (Node, error) {
	ino := RootInode
	node, err := fs.GetAttr(ctx, ino)
	if err != nil {
		return Node{}, err
	}
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		node, err = fs.Lookup(ctx, ino, part)
		if err != nil {
			return Node{}, err
		}
		ino = node.Inode
	}
	return node, nil
}

// Generation reports the served generation number.
func (fs *FS) Generation() uint64 { return fs.sb.Generation }

// RootCatalog reports the generation's root catalog identity — the value
// an overlay pins to refuse reopening over a different generation.
func (fs *FS) RootCatalog() [32]byte { return fs.sb.RootCatalog }

// NextInode reports the generation's allocator high-water mark, so a
// writer layered above allocates inodes that never collide with the
// base's.
func (fs *FS) NextInode() uint64 { return fs.sb.NextInode }

// Usage reports total stored bytes and the allocator high-water mark,
// for synthesizing statfs. Bytes come from the generation's pack list
// (the only size the format actually knows); inode counts are bounded by
// NextInode, not counted — a true count would mean walking every
// catalog.
func (fs *FS) Usage() (bytes int64, inodes uint64) {
	for _, pe := range fs.sb.PackList {
		bytes += pe.Size
	}
	return bytes, fs.sb.NextInode
}

// GetAttr returns an inode's attributes from its residency catalog.
func (fs *FS) GetAttr(ctx context.Context, ino uint64) (Node, error) {
	catHex, err := fs.residencyOf(ino)
	if err != nil {
		return Node{}, err
	}
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return Node{}, err
	}
	defer release()
	n, err := cat.Stat(int64(ino))
	if errors.Is(err, catalog.ErrNotExist) {
		return Node{}, ErrNotExist
	}
	if err != nil {
		return Node{}, err
	}
	return nodeOf(n), nil
}

// Readdir lists a directory with attributes (readdirplus-shaped). The
// listing is complete from the residency catalog alone: transition
// directories carry their dirent (and node row) in the parent catalog, so
// no child catalog is fetched. "." and ".." are the binding's business.
// Readdir does not create residency — the kernel Lookups before operating
// on an entry.
func (fs *FS) Readdir(ctx context.Context, ino uint64) ([]DirEntry, error) {
	catHex, err := fs.residencyOf(ino)
	if err != nil {
		return nil, err
	}
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return nil, err
	}
	defer release()
	// One join instead of 1+N pager round trips: the kernel's readdirplus
	// wants names and attributes together anyway.
	plus, err := cat.ReaddirPlus(int64(ino))
	if err != nil {
		return nil, err
	}
	out := make([]DirEntry, 0, len(plus))
	for _, e := range plus {
		out = append(out, DirEntry{Name: string(e.Name), Node: nodeOf(e.Node)})
	}
	return out, nil
}

// Readlink returns a symlink's target.
func (fs *FS) Readlink(ctx context.Context, ino uint64) (string, error) {
	cat, release, _, err := fs.acquireContent(ctx, ino)
	if err != nil {
		return "", err
	}
	defer release()
	target, err := cat.Symlink(int64(ino))
	if errors.Is(err, catalog.ErrNotExist) {
		return "", ErrNotExist
	}
	if err != nil {
		return "", err
	}
	return string(target), nil
}

// GetXattr returns one extended attribute; ErrNotExist when the inode has
// no attribute of that name.
func (fs *FS) GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error) {
	cat, release, _, err := fs.acquireContent(ctx, ino)
	if err != nil {
		return nil, err
	}
	defer release()
	xs, err := cat.Xattrs(int64(ino))
	if err != nil {
		return nil, err
	}
	for _, x := range xs {
		if string(x.Name) == name {
			return x.Value, nil
		}
	}
	return nil, ErrNotExist
}

// ListXattr returns an inode's extended-attribute names, sorted.
func (fs *FS) ListXattr(ctx context.Context, ino uint64) ([]string, error) {
	cat, release, _, err := fs.acquireContent(ctx, ino)
	if err != nil {
		return nil, err
	}
	defer release()
	xs, err := cat.Xattrs(int64(ino))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(xs))
	for _, x := range xs {
		names = append(names, string(x.Name))
	}
	return names, nil
}

// Forget retires nlookup references to ino; residency (and the inode's
// resolved extents) drop at zero. Catalog handles and cache files are
// untouched. The root's residency is permanent.
func (fs *FS) Forget(ino uint64, nlookup uint64) {
	if ino == RootInode {
		return
	}
	fs.mu.Lock()
	dropped := false
	if r := fs.res[ino]; r != nil {
		if r.nlookup <= nlookup {
			delete(fs.res, ino)
			dropped = true
		} else {
			r.nlookup -= nlookup
		}
	}
	fs.mu.Unlock()
	if dropped {
		fs.ext.drop(ino)
	}
}

// acquireContent returns the catalog holding ino's CONTENT records
// (chunkrefs/inline/xattrs/symlink) plus the node row from the residency
// catalog. Promoted regular files (nlink > 1 <=> record lives in an inode
// shard) route to their shard; node attrs always come from the path
// catalog's row.
func (fs *FS) acquireContent(ctx context.Context, ino uint64) (*catalog.Catalog, func(), catalog.Node, error) {
	catHex, err := fs.residencyOf(ino)
	if err != nil {
		return nil, nil, catalog.Node{}, err
	}
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return nil, nil, catalog.Node{}, err
	}
	n, err := cat.Stat(int64(ino))
	if err != nil {
		release()
		if errors.Is(err, catalog.ErrNotExist) {
			return nil, nil, catalog.Node{}, ErrNotExist
		}
		return nil, nil, catalog.Node{}, err
	}
	if n.Type == catalog.TypeFile && n.Nlink > 1 {
		release()
		shardHex, err := fs.shardHexFor(ino)
		if err != nil {
			return nil, nil, catalog.Node{}, err
		}
		cat, release, err = fs.cats.acquire(ctx, shardHex)
		if err != nil {
			return nil, nil, catalog.Node{}, err
		}
	}
	return cat, release, n, nil
}

// shardHexFor finds the shard whose inode range covers ino. Ranges are
// inclusive and non-overlapping; a promoted inode must be covered.
func (fs *FS) shardHexFor(ino uint64) (string, error) {
	for i := range fs.sb.Shards {
		sh := &fs.sb.Shards[i]
		if sh.FirstInode <= ino && ino <= sh.LastInode {
			return hex.EncodeToString(sh.Identity[:]), nil
		}
	}
	return "", fmt.Errorf("genfs: promoted inode %d covered by no shard", ino)
}

// fillGate serializes concurrent fills of one cache key (catalog spill or
// decoded chunk) so the store is hit once.
type fillGate struct {
	mu   sync.Mutex
	refs int
}

// lockFill acquires the fill gate for key; the returned func releases it.
func (fs *FS) lockFill(key string) func() {
	fs.fillMu.Lock()
	g := fs.fills[key]
	if g == nil {
		g = &fillGate{}
		fs.fills[key] = g
	}
	g.refs++
	fs.fillMu.Unlock()
	g.mu.Lock()
	return func() {
		g.mu.Unlock()
		fs.fillMu.Lock()
		g.refs--
		if g.refs == 0 {
			delete(fs.fills, key)
		}
		fs.fillMu.Unlock()
	}
}

// readPackRange fetches one pack entry's stored bytes.
func (fs *FS) readPackRange(ctx context.Context, loc packLoc) ([]byte, error) {
	key := packstore.PackDirKey + "/" + loc.pack
	rc, err := fs.inner.Get(ctx, key, loc.off, loc.length)
	if err != nil {
		return nil, fmt.Errorf("genfs: read %s [%d,+%d): %w", key, loc.off, loc.length, err)
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, loc.length))
	// Transfer-engine transports may report failure only at Close; never
	// swallow it (the packstore lesson).
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("genfs: read %s [%d,+%d): %w", key, loc.off, loc.length, cerr)
	}
	if int64(len(buf)) != loc.length {
		return nil, fmt.Errorf("genfs: read %s [%d,+%d): short read (%d bytes)", key, loc.off, loc.length, len(buf))
	}
	return buf, nil
}

// catalogDEK is the key catalogs/shards decode under: the DEK when the
// superblock names a catalog key, nil for plaintext (their encoding is
// fixed by rule — always zstd, this one key — never sniffed).
func (fs *FS) catalogDEK() []byte {
	if fs.sb.CatalogKeyID != 0 {
		return fs.dek
	}
	return nil
}

// spillCatalog materializes a catalog/shard's decoded SQLite bytes under
// CacheDir and returns the file path. Existing spill files are reused
// (they were verified when written).
func (fs *FS) spillCatalog(ctx context.Context, idHex string) (string, error) {
	fp := filepath.Join(fs.catDir, idHex+".db")
	if _, err := os.Stat(fp); err == nil {
		return fp, nil
	}
	unlock := fs.lockFill("cat:" + idHex)
	defer unlock()
	if _, err := os.Stat(fp); err == nil {
		return fp, nil
	}
	loc, ok := fs.packIndex[idHex]
	if !ok {
		return "", fmt.Errorf("genfs: catalog %s not present in any listed pack", idHex)
	}
	stored, err := fs.readPackRange(ctx, loc)
	if err != nil {
		return "", err
	}
	plain, err := entrycodec.Decode(stored, entrycodec.AlgZstd, fs.catalogDEK())
	if err != nil {
		return "", fmt.Errorf("genfs: decode catalog %s: %w", idHex, err)
	}
	if fs.verify {
		if id := fs.hasher.Sum(plain); id.Hex() != idHex {
			return "", fmt.Errorf("genfs: catalog %s identity mismatch: got %s", idHex, id.Hex())
		}
	}
	if err := writeAtomic(fp, plain); err != nil {
		return "", err
	}
	return fp, nil
}

// writeAtomic publishes data at fp via temp-file + rename, so concurrent
// readers never observe a partial file.
func writeAtomic(fp string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(fp), filepath.Base(fp)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()      //nolint:errcheck
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	if err := os.Rename(tmp, fp); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return nil
}

func nodeOf(n catalog.Node) Node {
	return Node{
		Inode:   uint64(n.Inode),
		Type:    n.Type,
		Mode:    n.Mode,
		UID:     n.UID,
		GID:     n.GID,
		MtimeNS: n.MtimeNS,
		CtimeNS: n.CtimeNS,
		Nlink:   n.Nlink,
		Length:  n.Length,
		Rdev:    n.Rdev,
		Flags:   n.Flags,
	}
}
