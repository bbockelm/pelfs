// Package genfs is the FUSE-agnostic read-only core of the catalog-native
// VFS (docs/design-packfs.md, on the catalog-native mount): a
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
	"container/list"
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
	// MaxResident bounds the residency map, evicting least-recently-used
	// entries past the cap. Zero means unbounded, which is correct for a
	// FUSE binding: there the kernel owns the lifetime and tells us via
	// FORGET, so evicting behind its back would answer ESTALE for an
	// inode it still holds. Set it only for a PATH-based frontend (the
	// NFS adapter), which re-descends from the root on every operation
	// and therefore cannot be hurt by eviction — without it, residency
	// grows for the life of a long-running mount over a large tree.
	MaxResident int
	// PackCacheBytes bounds the whole-pack cache under CacheDir; zero
	// selects DefaultPackCacheBytes. A NEGATIVE value disables whole-pack
	// caching entirely, leaving reads on coalesced ranges — the right
	// setting where local space is scarcer than bandwidth, and the only
	// configuration in which a pack is read in pieces at all.
	PackCacheBytes int64
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

// packLoc locates one pack entry — which pack, and where inside it. It is
// the location layer; identity lives in catalogs.
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
	// elem is this inode's position in the eviction order, when the
	// residency map is bounded (MaxResident).
	elem *list.Element
}

// FS serves one verified generation read-only. Safe for concurrent use.
type FS struct {
	inner      pelicanobj.Store
	sb         *superblock.Superblock
	dek        []byte
	chunkDir   string
	catDir     string
	packDir    string
	trailerDir string

	// verify: recompute plain-BLAKE3 identities at cache fill (unencrypted
	// volumes only; see the package comment).
	verify bool
	hasher chunkid.Hasher

	// packIndex resolves entry identities to (pack, offset, length),
	// filling itself from pack trailers on demand (packindex.go).
	packIndex *packIndex

	// packCacheCap bounds the whole-pack cache (packfetch.go).
	packCacheCap int64
	evictMu      sync.Mutex

	cats *catCache
	ext  *extentCache

	// swapMu makes a generation swap atomic with respect to filesystem
	// operations: every operation holds it for READ for its whole
	// duration, Swap holds it for WRITE while it replaces the served
	// generation. Without it a swap is visible half-applied — it empties
	// the residency table before re-descending it, replaces the catalog
	// cache, and closes the old catalogs — so an operation straddling it
	// fails against state that belongs to neither generation. That is not
	// theoretical: a writable mount checkpoints on a timer, and every
	// checkpoint made a burst of concurrent creates fail with ESTALE (and,
	// where a catalog handle was yanked mid-read, EIO) for the tens of
	// milliseconds the swap took.
	//
	// Blocking is the right answer here rather than serving the old
	// generation through the window: a swap is bounded by residency, and
	// a paused operation is correct where a failed one is not.
	swapMu sync.RWMutex

	mu  sync.RWMutex
	res map[uint64]*residency
	// resLRU orders residency for eviction when maxResident is set;
	// front is most recently used.
	resLRU      *list.List
	maxResident int

	fillMu sync.Mutex
	fills  map[string]*fillGate
}

// Open fetches and pins the root catalog and returns a ready filesystem. A
// wrong DEK fails here, at the root catalog's GCM open.
//
// That is the whole of a cold mount: locate the root catalog and read it.
// The location layer fills in behind the reads that need it (packindex.go),
// so mounting costs what the first question costs, not what the generation
// is made of.
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
	if o.PackCacheBytes == 0 {
		o.PackCacheBytes = DefaultPackCacheBytes
	}
	catDir := filepath.Join(o.CacheDir, "catalogs")
	chunkDir := filepath.Join(o.CacheDir, "chunks")
	packDir := filepath.Join(o.CacheDir, "packs")
	trailerDir := filepath.Join(o.CacheDir, "trailers")
	dirs := []string{catDir, chunkDir, trailerDir}
	if o.PackCacheBytes > 0 {
		dirs = append(dirs, packDir)
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("genfs: cache dir: %w", err)
		}
	}
	fs := &FS{
		inner:        o.Inner,
		sb:           o.SB,
		dek:          o.DEK,
		chunkDir:     chunkDir,
		catDir:       catDir,
		packDir:      packDir,
		trailerDir:   trailerDir,
		packCacheCap: o.PackCacheBytes,
		ext:          newExtentCache(extentCacheCap),
		res:          make(map[uint64]*residency),
		resLRU:       list.New(),
		maxResident:  o.MaxResident,
		fills:        make(map[string]*fillGate),
	}
	fs.packIndex = newPackIndex(fs, o.SB.PackList)
	if o.PackCacheBytes > 0 {
		fs.sweepPackTmp()
	}

	rootHex := hex.EncodeToString(o.SB.RootCatalog[:])
	// The hint first (roothint.go): it names the pack holding the root
	// catalog, so a mount that follows it reads that pack and nothing else.
	// Without one — an older superblock, or a hint that no longer describes
	// where the bytes are — the root is located the ordinary way, which
	// means fetching pack trailers until one claims it.
	rootPath, ok := fs.spillRootFromHint(ctx, rootHex)
	if !ok {
		var err error
		if rootPath, err = fs.spillCatalog(ctx, rootHex); err != nil {
			return nil, fmt.Errorf("genfs: root catalog: %w", err)
		}
	}
	root, err := catalog.OpenReader(rootPath)
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
	fs.swapMu.Lock()
	defer fs.swapMu.Unlock()
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
	// Touch the parent: descending through a directory means it is in
	// active use, and evicting an ancestor would break the very descent
	// that residency exists to serve.
	if pr := fs.res[parent]; pr != nil && pr.elem != nil {
		fs.resLRU.MoveToFront(pr.elem)
	}
	if r := fs.res[ino]; r != nil {
		r.nlookup++
		r.parent, r.name = parent, name
		if r.elem != nil {
			fs.resLRU.MoveToFront(r.elem)
		}
		return
	}
	r := &residency{cat: catHex, nlookup: 1, parent: parent, name: name}
	fs.res[ino] = r
	if fs.maxResident > 0 {
		r.elem = fs.resLRU.PushFront(ino)
		for fs.resLRU.Len() > fs.maxResident {
			back := fs.resLRU.Back()
			evict := back.Value.(uint64)
			fs.resLRU.Remove(back)
			delete(fs.res, evict)
			fs.ext.drop(evict)
		}
	}
}

// Lookup resolves name under parent, records the child's residency, and
// returns its attributes. A transition-point child (nested locator present)
// records the CHILD catalog as its residency: its attrs come from the
// parent catalog's node row, its entries resolve in the child.
func (fs *FS) Lookup(ctx context.Context, parent uint64, name string) (Node, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.lookup(ctx, parent, name)
}

func (fs *FS) lookup(ctx context.Context, parent uint64, name string) (Node, error) {
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

// Resident reports whether ino can be operated on right now, i.e. whether
// a descent has established its residency and nothing has retired it.
//
// It exists because "I looked it up, so it stays" is NOT true here. Two
// things retire residency behind a caller's back: MaxResident eviction,
// and a generation Swap, which rebuilds the table from what it could
// re-descend. A layer that caches "I resolved this inode once" — the write
// overlay does, to avoid re-descending the base on every operation — has
// to be able to notice and redo the descent, and this is how it asks.
func (fs *FS) Resident(ino uint64) bool {
	if ino == RootInode {
		return true
	}
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.res[ino] != nil
}

// Parent returns the inode this one was reached through, answering "..".
// The root is its own parent, as POSIX requires. ErrStale when the inode
// has no residency (the kernel looked nothing up).
func (fs *FS) Parent(ino uint64) (uint64, error) {
	if ino == RootInode {
		return RootInode, nil
	}
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
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
	// One read lock for the whole descent: an intermediate step resolved
	// in a different generation than its successor is not a path.
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	ino := RootInode
	node, err := fs.getAttr(ctx, ino)
	if err != nil {
		return Node{}, err
	}
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		node, err = fs.lookup(ctx, ino, part)
		if err != nil {
			return Node{}, err
		}
		ino = node.Inode
	}
	return node, nil
}

// Generation reports the served generation number.
func (fs *FS) Generation() uint64 {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.sb.Generation
}

// RootCatalog reports the generation's root catalog identity — the value
// an overlay pins to refuse reopening over a different generation.
func (fs *FS) RootCatalog() [32]byte {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.sb.RootCatalog
}

// NextInode reports the generation's allocator high-water mark, so a
// writer layered above allocates inodes that never collide with the
// base's.
func (fs *FS) NextInode() uint64 {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.sb.NextInode
}

// Usage reports total stored bytes and the allocator high-water mark,
// for synthesizing statfs. Bytes come from the generation's pack list
// (the only size the format actually knows); inode counts are bounded by
// NextInode, not counted — a true count would mean walking every
// catalog.
func (fs *FS) Usage() (bytes int64, inodes uint64) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	for _, pe := range fs.sb.PackList {
		bytes += pe.Size
	}
	return bytes, fs.sb.NextInode
}

// GetAttr returns an inode's attributes from its residency catalog.
func (fs *FS) GetAttr(ctx context.Context, ino uint64) (Node, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.getAttr(ctx, ino)
}

func (fs *FS) getAttr(ctx context.Context, ino uint64) (Node, error) {
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
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.readdir(ctx, ino)
}

func (fs *FS) readdir(ctx context.Context, ino uint64) ([]DirEntry, error) {
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

// ReaddirRetain lists a directory AND establishes residency for every
// entry, which Readdir deliberately does not. It answers the one caller
// that descends a whole tree without a kernel to Lookup for it: a seal,
// which needs every entry operable, not merely named.
//
// The point is the query count. A Lookup per entry costs three catalog
// queries each — the edge, the nested probe, and the node row — to
// recompute what one ReaddirPlus already returned; over an 85k-inode tree
// that was the largest single item in the walk. This pays two queries per
// DIRECTORY instead, and retains exactly what the per-entry loop retained:
// same inodes, same catalogs, same order, so residency (including
// MaxResident eviction, which is driven by that order) behaves identically.
func (fs *FS) ReaddirRetain(ctx context.Context, ino uint64) ([]DirEntry, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	catHex, err := fs.residencyOf(ino)
	if err != nil {
		return nil, err
	}
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return nil, err
	}
	defer release()
	plus, err := cat.ReaddirPlus(int64(ino))
	if err != nil {
		return nil, err
	}
	nested, err := cat.NestedOf(int64(ino))
	if err != nil {
		return nil, err
	}
	var childCats map[string]string
	if len(nested) > 0 {
		childCats = make(map[string]string, len(nested))
		for _, n := range nested {
			childCats[string(n.Name)] = hex.EncodeToString(n.CatalogIdentity)
		}
	}
	out := make([]DirEntry, 0, len(plus))
	for _, e := range plus {
		name := string(e.Name)
		// A transition point's residency is the CHILD catalog: its attrs
		// come from the node row here, its entries resolve over there.
		childCat := catHex
		if h, ok := childCats[name]; ok {
			childCat = h
			delete(childCats, name)
		}
		fs.retain(uint64(e.Node.Inode), childCat, ino, name)
		out = append(out, DirEntry{Name: name, Node: nodeOf(e.Node)})
	}
	for name := range childCats {
		// Lookup rejects this shape rather than serving a directory with no
		// attributes; a listing must not quietly drop the entry instead.
		return nil, fmt.Errorf("genfs: transition %q under inode %d has no dirent half", name, ino)
	}
	return out, nil
}

// Readlink returns a symlink's target.
func (fs *FS) Readlink(ctx context.Context, ino uint64) (string, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
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

// noXattrsFor reports whether ino provably has NO extended attribute,
// decided from whole-catalog facts alone — no query, and in particular not
// the node-row query that finding an inode's content catalog otherwise
// costs. Almost no tree uses extended attributes, and a seal asks every
// inode in the tree; two map lookups is the honest price of "none".
//
// Both places an inode's xattr rows can live have to be empty: the
// residency catalog, and — if the inode falls in a shard's range, which is
// the only way it could be promoted — that shard. A false answer means
// only "ask properly", so the cost of the conservative direction is the
// query that would have run anyway.
func (fs *FS) noXattrsFor(ctx context.Context, ino uint64) (bool, error) {
	catHex, err := fs.residencyOf(ino)
	if err != nil {
		return false, err
	}
	empty, err := fs.catalogHasNoXattrs(ctx, catHex)
	if err != nil || !empty {
		return false, err
	}
	for i := range fs.sb.Shards {
		sh := &fs.sb.Shards[i]
		if sh.FirstInode <= ino && ino <= sh.LastInode {
			return fs.catalogHasNoXattrs(ctx, hex.EncodeToString(sh.Identity[:]))
		}
	}
	return true, nil
}

func (fs *FS) catalogHasNoXattrs(ctx context.Context, catHex string) (bool, error) {
	cat, release, err := fs.cats.acquire(ctx, catHex)
	if err != nil {
		return false, err
	}
	defer release()
	return !cat.HasXattrs(), nil
}

// GetXattr returns one extended attribute; ErrNotExist when the inode has
// no attribute of that name.
func (fs *FS) GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	if none, err := fs.noXattrsFor(ctx, ino); err != nil {
		return nil, err
	} else if none {
		return nil, ErrNotExist
	}
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
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	if none, err := fs.noXattrsFor(ctx, ino); err != nil {
		return nil, err
	} else if none {
		return nil, nil
	}
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
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	fs.mu.Lock()
	dropped := false
	if r := fs.res[ino]; r != nil {
		if r.nlookup <= nlookup {
			if r.elem != nil {
				fs.resLRU.Remove(r.elem)
			}
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
func (fs *FS) acquireContent(ctx context.Context, ino uint64) (catalog.Reader, func(), catalog.Node, error) {
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
// CacheDir and returns the file path, resolving it through the served
// generation's location layer.
func (fs *FS) spillCatalog(ctx context.Context, idHex string) (string, error) {
	return fs.spillCatalogFrom(ctx, fs.packIndex, fs.catalogDEK(), idHex)
}

// spillCatalogFrom is spillCatalog against a stated generation's location
// layer and catalog key rather than the served one. A swap uses it to prove
// the incoming generation's root catalog resolves, decodes, and verifies
// BEFORE anything served is replaced — the alternative is discovering it
// afterwards, with a mount already pointed at a generation it cannot read.
// Existing spill files are reused (they were verified when written).
func (fs *FS) spillCatalogFrom(ctx context.Context, idx *packIndex, dek []byte, idHex string) (string, error) {
	fp := filepath.Join(fs.catDir, idHex+".db")
	if _, err := os.Stat(fp); err == nil {
		return fp, nil
	}
	unlock := fs.lockFill("cat:" + idHex)
	defer unlock()
	if _, err := os.Stat(fp); err == nil {
		return fp, nil
	}
	loc, err := idx.locate(ctx, idHex)
	if err != nil {
		return "", fmt.Errorf("genfs: catalog %s: %w", idHex, err)
	}
	stored, err := fs.packRead(ctx, idx, idHex, loc)
	if err != nil {
		return "", err
	}
	plain, err := entrycodec.Decode(stored, entrycodec.AlgZstd, dek)
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
