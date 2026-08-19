// Package fsck verifies one published v2 generation end to end
// (docs/design-packfs.md): the signed pack list, catalog and inode-shard
// reachability, the structural invariants of the catalog schema, chunk
// presence, and — in deep mode — chunk content. It is the sibling of
// internal/retention, which is the GC half of the same maintenance pair.
//
// Reads go directly through packstore + entrycodec + catalog rather than
// through genfs, for two reasons. genfs.Open aborts at the FIRST pack
// whose trailer does not verify and the first undecodable catalog, while
// fsck must report every failure and keep going. And genfs builds inode
// residency BY DESCENT — operations on an inode it never looked up return
// ErrStale — which is right for a kernel binding and wrong for a
// systematic sweep that also has to reach inode-shard records and content
// rows the kernel would never ask for.
//
// Identity checking follows the rule genfs documents. On unencrypted
// volumes (identity algo "blake3-256") every catalog, shard, and
// deep-verified chunk is rehashed with plain BLAKE3 and compared against
// the identity that referenced it. On encrypted volumes identity is keyed
// BLAKE3 under the volume identity key, which fsck — like genfs — does
// NOT hold: only the unwrapped DEK arrives in Options. There the AES-GCM
// tag opened under the DEK is the authentication, and nothing is
// recomputed. That is weaker in exactly one way: GCM proves the bytes
// were sealed under the DEK, not that they are the bytes this identity
// names, so an entry correctly encrypted but stored under the wrong key
// in the pack index would pass. Every bit flip, truncation, and foreign
// substitution is still caught.
package fsck

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// rootInode is the volume root, as in genfs.
const rootInode uint64 = 1

// Identity algo strings stamped into catalog_meta by publish.
const (
	identityAlgoPlain = "blake3-256"
	identityAlgoKeyed = "blake3-256-keyed"
)

// Problem kinds. Every failure carries one of these so callers can filter
// without parsing prose; Detail holds the human half.
const (
	// KindMissingPack: a pack in the signed pack list is not in the
	// federation (or cannot be stat'd).
	KindMissingPack = "missing-pack"
	// KindMissingManifest: the generation states its pack set through
	// manifest segments (superblock.Manifests) and one could not be
	// fetched or did not verify. Distinct from a missing pack because it
	// is not damage to one object: nothing about the generation's contents
	// can be checked without it, so every later problem is downstream of
	// this one.
	KindMissingManifest = "missing-manifest"
	// KindPackTrailer: the pack exists but its trailer is unparseable, or
	// the stored trailer bytes do not hash to the value the SIGNED pack
	// list records — the location map does not match the generation.
	KindPackTrailer = "pack-trailer"
	// KindPackSize: the object's size differs from the signed pack list.
	KindPackSize = "pack-size"
	// KindMissingCatalog: a referenced catalog is in no listed pack.
	KindMissingCatalog = "missing-catalog"
	// KindBadCatalog: a catalog cannot be decoded or opened.
	KindBadCatalog = "bad-catalog"
	// KindMissingShard / KindBadShard: the same, for inode shards.
	KindMissingShard = "missing-shard"
	KindBadShard     = "bad-shard"
	// KindIdentity: recomputed BLAKE3 differs from the referencing
	// identity (unencrypted volumes only; see the package comment).
	KindIdentity = "identity"
	// KindDanglingDirent: a dirent names an inode with no node row.
	KindDanglingDirent = "dangling-dirent"
	// KindTypeMismatch: a dirent's type disagrees with its node row.
	KindTypeMismatch = "type-mismatch"
	// KindTransition: a transition point is missing one of its halves —
	// the format requires both the dirent and the nested locator.
	KindTransition = "transition"
	// KindCycle: a directory inode is reachable more than once inside one
	// catalog. The namespace is a tree; a cycle would hang a walker.
	KindCycle = "cycle"
	// KindShardRouting: a promoted (nlink > 1) inode is covered by no
	// shard, or has no record in the shard covering it; also overlapping
	// or inverted shard ranges.
	KindShardRouting = "shard-routing"
	// KindChunkRefs: chunkref rows that cannot describe a file — lengths
	// that do not sum to the node length, negative or overflowing
	// extents, a stored length disagreeing with the pack index.
	KindChunkRefs = "chunkrefs"
	// KindContent: a file's content records are absent or inconsistent
	// with its node row (inline length, missing symlink target).
	KindContent = "content"
	// KindMissingChunk: a chunk identity resolves in no listed pack.
	KindMissingChunk = "missing-chunk"
	// KindChunk: deep mode only — a chunk could not be fetched, decoded,
	// or (unencrypted volumes) did not hash to its identity.
	KindChunk = "chunk"
)

// Options configures Check.
type Options struct {
	// Inner is the raw transport for pack range reads.
	Inner pelicanobj.Store
	// SB is the generation to check. The caller has ALREADY verified its
	// signature; fsck treats it as the integrity root, exactly as genfs
	// does — a check rooted in an unverified superblock proves nothing.
	SB *superblock.Superblock
	// DEK is the unwrapped data-encryption key; nil for plaintext volumes.
	DEK []byte
	// CacheDir holds catalog spill files. Empty means a temporary
	// directory removed on return. Spills are written fresh and deleted
	// after use: a cached copy is a copy fsck has not verified.
	CacheDir string
	// Deep fetches and decodes every distinct chunk instead of only
	// checking that its identity resolves in the pack index.
	Deep bool
	// Workers bounds deep-mode concurrency (default 8).
	Workers int
}

// Problem is one failure. Path locates it: a namespace path for tree
// problems, "packs/<name>" for pack problems, "shards/<first>-<last>" for
// shard-routing problems.
type Problem struct {
	Kind   string
	Path   string
	Detail string
}

// Report summarizes one check. Counts cover what was successfully
// traversed, so they read alongside Problems rather than instead of it.
type Report struct {
	// Packs is the number of listed packs present and trailer-verified.
	Packs int
	// Catalogs and Shards count the objects opened during the sweep
	// (the root catalog included).
	Catalogs, Shards int
	// Dirs, Files, Symlinks count distinct INODES reached by descent,
	// matching how publish counts them (a hardlinked file is one file).
	Files, Dirs, Symlinks int
	// Chunks is the number of distinct chunk identities referenced;
	// ChunksVerified is how many were fetched and decoded (deep mode
	// only). InlineFiles counts files whose content is in the catalog.
	Chunks, ChunksVerified, InlineFiles int
	// Bytes is the logical size of the namespace: the sum of regular-file
	// lengths, counted once per inode.
	Bytes int64
	// Problems holds EVERY failure found, sorted by path then kind.
	Problems []Problem
}

// OK reports a generation with no problems.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

// packLoc locates one pack entry, from the identity index built out of the
// generation's verified pack trailers.
type packLoc struct {
	pack   string
	off    int64
	length int64
}

// errNotIndexed marks an identity that resolves in no listed pack, so the
// caller can report "missing" rather than "corrupt".
var errNotIndexed = errors.New("not present in any listed pack")

type checker struct {
	o        Options
	rep      *Report
	spillDir string

	index map[string]packLoc

	// verifyIdentity is set from the root catalog's identity algo:
	// plain BLAKE3 is recomputable, keyed BLAKE3 is not (see the package
	// comment).
	verifyIdentity bool
	hasher         chunkid.Hasher

	// shards holds open shard handles for the whole sweep — they are few
	// (one per inode range) and are revisited by every promoted inode.
	shards map[string]catalog.Reader

	// chunks records the distinct chunk identities the namespace
	// references; jobs is the deep-mode work list, one entry per identity.
	chunks map[string]struct{}
	jobs   []chunkJob

	mu sync.Mutex
}

// chunkJob is one distinct chunk to fetch and decode in deep mode. Alg and
// KeyID come from the chunkref that referenced it — never sniffed from the
// bytes (docs/design-packfs.md, "Codec marking").
type chunkJob struct {
	idHex string
	alg   int64
	keyID int64
	llen  int64
	path  string
}

// Check runs the full sweep. It returns a report listing every problem
// found; an error means the check could not be completed at all — bad
// options, or a root catalog that cannot be read, which makes every
// further check meaningless. The partial report is returned alongside the
// error so a caller can still show the pack-level findings.
func Check(ctx context.Context, o Options) (*Report, error) {
	if o.Inner == nil || o.SB == nil {
		return nil, errors.New("fsck: Inner and SB are required")
	}
	if o.SB.CatalogKeyID != 0 && len(o.DEK) == 0 {
		return nil, errors.New("fsck: volume catalogs are encrypted but no DEK was provided")
	}
	spillRoot := o.CacheDir
	if spillRoot == "" {
		tmp, err := os.MkdirTemp("", "pelfs-fsck-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp) //nolint:errcheck
		spillRoot = tmp
	}
	// A subdirectory of its own: genfs's spill files under the same cache
	// dir are trusted-on-hit, and fsck must never read one.
	spillDir := filepath.Join(spillRoot, "fsck")
	if err := os.MkdirAll(spillDir, 0700); err != nil {
		return nil, fmt.Errorf("fsck: spill dir: %w", err)
	}
	defer os.RemoveAll(spillDir) //nolint:errcheck

	c := &checker{
		o:        o,
		rep:      &Report{},
		spillDir: spillDir,
		index:    make(map[string]packLoc),
		shards:   make(map[string]catalog.Reader),
	}
	defer c.closeShards()

	c.checkPacks(ctx)

	root, rootHex, err := c.openRoot(ctx)
	if err != nil {
		c.sortProblems()
		return c.rep, err
	}
	c.checkShards(ctx)
	c.walk(ctx, root, rootHex)
	c.releaseCatalog(root, rootHex)

	if o.Deep {
		if err := c.verifyChunks(ctx); err != nil {
			c.sortProblems()
			return c.rep, err
		}
	}
	c.sortProblems()
	return c.rep, nil
}

func (c *checker) problem(kind, path, format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rep.Problems = append(c.rep.Problems, Problem{Kind: kind, Path: path, Detail: fmt.Sprintf(format, args...)})
}

func (c *checker) sortProblems() {
	sort.SliceStable(c.rep.Problems, func(i, j int) bool {
		a, b := c.rep.Problems[i], c.rep.Problems[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
}

// checkPacks builds the identity index from every pack in the signed pack
// list, verifying each trailer against the hash the list records. A pack
// that fails is reported and skipped: its entries are simply absent from
// the index, so everything referencing them surfaces as missing rather
// than aborting the sweep.
func (c *checker) checkPacks(ctx context.Context) {
	// The pack set comes from the manifest when the generation has one and
	// from the inline list otherwise (manifest.Packs). An unreadable
	// manifest is reported as one problem and leaves the index empty, so
	// everything downstream surfaces as missing — which is the truth: a
	// generation whose pack set cannot be read is a generation whose
	// content cannot be found. It is not a fatal error, because fsck's
	// contract is to report every failure rather than to stop at the
	// first.
	packs, err := manifest.Packs(ctx, c.o.Inner, c.o.SB)
	if err != nil {
		c.problem(KindMissingManifest, manifest.Dir, "%v", err)
		return
	}
	for _, pe := range packs {
		key := packstore.PackDirKey + "/" + pe.Name
		path := key
		size := pe.Size
		ki, err := c.o.Inner.StatKey(ctx, key)
		if err != nil {
			c.problem(KindMissingPack, path, "listed in the generation but not readable: %v", err)
			continue
		}
		if ki.Size != pe.Size {
			// Check the trailer against the object as it actually is: a
			// truncated pack fails below, and an appended-to one may still
			// parse, which is worth knowing separately.
			c.problem(KindPackSize, path, "object is %d bytes, the signed pack list says %d", ki.Size, pe.Size)
			size = ki.Size
		}
		entries, err := packstore.FetchTrailerVerified(ctx, c.o.Inner, pe.Name, size, pe.TrailerHash)
		if err != nil {
			c.problem(KindPackTrailer, path, "%v", err)
			continue
		}
		c.rep.Packs++
		for _, e := range entries {
			// Identical content dedups at publish, so a key may appear in
			// several packs naming the same bytes; last writer wins
			// harmlessly (the genfs index rule).
			c.index[e.Key] = packLoc{pack: pe.Name, off: e.Off, length: e.Length}
		}
	}
}

// openRoot opens the root catalog and settles the identity mode. The root
// is spilled before its algo is known, so it is verified retroactively —
// the same order genfs.Open uses.
func (c *checker) openRoot(ctx context.Context) (catalog.Reader, string, error) {
	rootHex := hex.EncodeToString(c.o.SB.RootCatalog[:])
	plain, err := c.decodeObject(ctx, rootHex)
	if err != nil {
		if errors.Is(err, errNotIndexed) {
			c.problem(KindMissingCatalog, "/", "root catalog %s is in no listed pack", rootHex)
			return nil, "", fmt.Errorf("fsck: root catalog %s is in no listed pack — nothing else can be checked", rootHex)
		}
		c.problem(KindBadCatalog, "/", "root catalog %s: %v", rootHex, err)
		return nil, "", fmt.Errorf("fsck: root catalog %s: %w", rootHex, err)
	}
	fp, err := c.spill(rootHex, plain)
	if err != nil {
		return nil, "", err
	}
	root, err := catalog.OpenReader(fp)
	if err != nil {
		os.Remove(fp) //nolint:errcheck
		c.problem(KindBadCatalog, "/", "root catalog %s: %v", rootHex, err)
		return nil, "", fmt.Errorf("fsck: open root catalog %s: %w", rootHex, err)
	}
	switch algo := root.Meta().IdentityAlgo; algo {
	case identityAlgoPlain:
		c.verifyIdentity = true
		c.hasher = chunkid.NewHasher(nil)
		if id := c.hasher.Sum(plain); id.Hex() != rootHex {
			c.problem(KindIdentity, "/", "root catalog hashes to %s, the superblock names %s", id.Hex(), rootHex)
		}
	case identityAlgoKeyed:
		// Keyed identity; fsck holds no identity key. The GCM open the
		// decode above already performed is the authentication.
	default:
		root.Close()  //nolint:errcheck
		os.Remove(fp) //nolint:errcheck
		return nil, "", fmt.Errorf("fsck: unknown identity algo %q in the root catalog", algo)
	}
	c.rep.Catalogs++
	return root, rootHex, nil
}

// checkShards verifies every shard the superblock routes to, whether or
// not a promoted inode reaches it: an unreferenced shard is still part of
// the signed generation, and a missing one is damage.
func (c *checker) checkShards(ctx context.Context) {
	prevLast := uint64(0)
	for i := range c.o.SB.Shards {
		sh := &c.o.SB.Shards[i]
		path := shardPath(sh)
		if sh.FirstInode > sh.LastInode {
			c.problem(KindShardRouting, path, "inverted inode range")
		}
		if i > 0 && sh.FirstInode <= prevLast {
			c.problem(KindShardRouting, path, "inode range overlaps the preceding shard (which ends at %d)", prevLast)
		}
		prevLast = sh.LastInode
		if cat := c.openShard(ctx, hex.EncodeToString(sh.Identity[:]), path); cat != nil {
			c.rep.Shards++
		}
	}
}

// openShard opens (and caches) one inode shard. Shards outlive the walk
// because every promoted inode routes through one.
func (c *checker) openShard(ctx context.Context, idHex, path string) catalog.Reader {
	if cat, ok := c.shards[idHex]; ok {
		return cat // nil is cached too: report the failure once
	}
	cat := c.openCatalogObject(ctx, idHex, path, KindMissingShard, KindBadShard)
	c.shards[idHex] = cat
	return cat
}

func (c *checker) closeShards() {
	for _, cat := range c.shards {
		if cat != nil {
			cat.Close() //nolint:errcheck
		}
	}
}

// openCatalogObject fetches, decodes, identity-checks, spills, and opens
// one catalog-class object (path catalog or inode shard), reporting rather
// than returning failures. A nil result means the object is unusable and
// the problem is already recorded.
func (c *checker) openCatalogObject(ctx context.Context, idHex, path, missingKind, badKind string) catalog.Reader {
	plain, err := c.decodeObject(ctx, idHex)
	if err != nil {
		if errors.Is(err, errNotIndexed) {
			c.problem(missingKind, path, "%s is in no listed pack", idHex)
		} else {
			c.problem(badKind, path, "%s: %v", idHex, err)
		}
		return nil
	}
	if c.verifyIdentity {
		if id := c.hasher.Sum(plain); id.Hex() != idHex {
			c.problem(KindIdentity, path, "%s hashes to %s", idHex, id.Hex())
		}
	}
	fp, err := c.spill(idHex, plain)
	if err != nil {
		c.problem(badKind, path, "%s: spill: %v", idHex, err)
		return nil
	}
	cat, err := catalog.OpenReader(fp)
	if err != nil {
		os.Remove(fp) //nolint:errcheck
		c.problem(badKind, path, "%s: %v", idHex, err)
		return nil
	}
	return cat
}

// decodeObject reads one catalog-class pack entry and decodes it. Their
// encoding is fixed by rule — always zstd, under the single key the
// superblock names — never sniffed (docs/design-packfs.md, "Codec
// marking").
func (c *checker) decodeObject(ctx context.Context, idHex string) ([]byte, error) {
	loc, ok := c.index[idHex]
	if !ok {
		return nil, errNotIndexed
	}
	stored, err := c.readPackRange(ctx, loc)
	if err != nil {
		return nil, err
	}
	return entrycodec.Decode(stored, entrycodec.AlgZstd, c.catalogDEK())
}

func (c *checker) catalogDEK() []byte {
	if c.o.SB.CatalogKeyID != 0 {
		return c.o.DEK
	}
	return nil
}

// spill materializes decoded SQLite bytes so catalog.Open can read them.
// The file is deleted by releaseCatalog once the sweep is done with it.
func (c *checker) spill(idHex string, plain []byte) (string, error) {
	fp := filepath.Join(c.spillDir, idHex+".db")
	if err := os.WriteFile(fp, plain, 0600); err != nil {
		return "", err
	}
	return fp, nil
}

// releaseCatalog closes a catalog and drops its spill file. Catalogs are
// visited exactly once by the descent, so nothing is kept open.
func (c *checker) releaseCatalog(cat catalog.Reader, idHex string) {
	if cat != nil {
		cat.Close() //nolint:errcheck
	}
	os.Remove(filepath.Join(c.spillDir, idHex+".db")) //nolint:errcheck
}

// readPackRange fetches one pack entry's stored bytes.
func (c *checker) readPackRange(ctx context.Context, loc packLoc) ([]byte, error) {
	key := packstore.PackDirKey + "/" + loc.pack
	rc, err := c.o.Inner.Get(ctx, key, loc.off, loc.length)
	if err != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, loc.off, loc.length, err)
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, loc.length))
	// Transfer-engine transports may report failure only at Close; never
	// swallow it (the packstore lesson).
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, loc.off, loc.length, cerr)
	}
	if int64(len(buf)) != loc.length {
		return nil, fmt.Errorf("read %s [%d,+%d): short read (%d bytes)", key, loc.off, loc.length, len(buf))
	}
	return buf, nil
}

func shardPath(sh *superblock.ShardEntry) string {
	return fmt.Sprintf("shards/%d-%d", sh.FirstInode, sh.LastInode)
}
