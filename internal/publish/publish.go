// Package publish implements the v2 publish pipeline. It reads a Source —
// a write overlay under seal, or the empty root of a new volume — and runs
// TRANSFORM (walk the tree, chunk file content, build split path catalogs
// and inode shards, append everything to packs), UPLOAD (pack seals), and
// FLIP (write the signed superblock to refs/<branch>). See
// docs/design-packfs.md, "Publish: the transactional pipeline" and "Phase 3
// VFS architecture" (write path = overlay + seal).
//
// For the cut source, CUT and RECONCILE are the session's job — by the time
// this package runs, the cut database exists and every block it references
// is durable in the session's blob store. For the overlay source there is
// no cut at all: publish IS the durability step for staged content, and
// nothing downstream of the walk changes.
//
// Simplifications, deliberate and marked at their sites:
//   - Full-tree TRANSFORM: every catalog and shard regenerates from the
//     source. Dirty-set tracking is a later optimization; content
//     addressing already makes an unchanged subtree's catalog hash to the
//     same bytes it did last generation. File CONTENT is the exception —
//     a source that can prove a file's bytes untouched hands back the
//     records the previous generation published (see ContentReuser), so
//     the walk never opens it.
//   - Chunk dedup is within-publish only (see packer) plus the local
//     sidecar index (dedup.go). A re-uploaded chunk is wasted bytes under
//     the same identity, never corruption.
//   - Holes materialize as zero bytes through the chunker instead of NULL
//     chunkref rows: content stays byte-exact, sparseness is not preserved.
//   - Promoted (nlink > 1) inodes keep their node row in every referencing
//     path catalog AND in their inode shard; only the content records
//     (chunkrefs, inline, xattrs) are shard-exclusive. Stat from a path
//     catalog needs no shard fetch, and the shard stays authoritative for
//     content.
package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// Defaults and policy constants.
const (
	// DefaultInlineMax is the inline threshold (one SQLite page; the design
	// doc's measured sweet spot).
	DefaultInlineMax = 4096
	// DefaultTargetPackSize matches the phase-1 middleware's pack target.
	DefaultTargetPackSize = 64 << 20
	// RefPrefix is the key-space directory of mutable branch heads.
	RefPrefix = "refs/"

	// entryWeight is the structural cost of one directory entry in the
	// catalog weight function W = 200·entries + inline_bytes (+ xattrs).
	entryWeight int64 = 200
	// chunkRowWeight approximates one chunkref row when sizing shards.
	chunkRowWeight int64 = 100
	// shardTargetWeight bounds one inode shard; the promoted-inode space
	// splits into contiguous ranges when it grows past this.
	shardTargetWeight int64 = 5 << 20

	// Retention defaults recorded in the superblock (design doc,
	// "Retention and GC").
	defaultTGraceSeconds int64  = 72 * 3600
	defaultRetainK       uint32 = 8
)

// Options configures one Publish run.
type Options struct {
	// Overlay is the write overlay this generation publishes: its merged
	// base+dirty view defines the contents. Prev is required — the
	// overlay sits over exactly that generation, which is where the
	// volume identity comes from. See Seal.
	Overlay *overlay.FS
	// OverlaySnapshot seals a frozen view instead of the live overlay.
	// A checkpoint uses this so the published generation corresponds to
	// an instant, which is the precondition for rebasing inodes back to
	// clean afterwards. Mutually exclusive with Overlay.
	OverlaySnapshot *overlay.Snapshot
	// Inner is the raw transport: pack uploads and the ref write.
	Inner pelicanobj.Store
	// SpoolDir holds pack spools and catalog build files.
	SpoolDir string
	// Branch is the ref name; default "main".
	Branch string
	// SigningKey signs the superblock.
	SigningKey ed25519.PrivateKey
	// IdentityKey selects keyed BLAKE3 chunk identity (encrypted volumes);
	// nil hashes unkeyed. Must be nil or 32 bytes.
	IdentityKey []byte
	// DEK encrypts pack entries (AES-256-GCM); nil writes plaintext.
	DEK []byte
	// KeyID is recorded in catalog chunkref rows when DEK is set. Key id 0
	// is reserved for plaintext.
	KeyID uint32
	// KeyTable is the prebuilt superblock key table; wrapping the DEK and
	// identity key under the user KEK is the caller's business.
	KeyTable []superblock.KeyEntry
	// Prev/PrevRaw are the previous generation and its wire bytes (for the
	// lineage hash); both nil for the first publish.
	Prev    *superblock.Superblock
	PrevRaw []byte
	// InlineMax is the inline threshold in bytes (default 4096).
	InlineMax int64
	// TargetPackSize cuts packs (default 64 MiB).
	TargetPackSize int64
	// SMax overrides the catalog split threshold; zero selects
	// catalog.SMax. Tests shrink it to force nested catalogs on small trees.
	SMax int64
	// CreatedUnixNano stamps the superblock; zero reads the clock.
	CreatedUnixNano int64
	// DedupIndexPath is the local cross-generation dedup sidecar (see
	// dedup.go); empty disables it. Missing/stale/foreign indexes are
	// ignored — re-uploads are harmless duplicates.
	DedupIndexPath string
	// VolumeID identifies a volume being created by InitVolume. Every
	// other path takes identity from the previous generation.
	VolumeID [16]byte

	// emptySource selects the empty-root source (InitVolume).
	emptySource bool
}

// Stats summarizes one publish.
type Stats struct {
	Dirs, Files, Symlinks, Specials int
	InlineFiles, ChunkedFiles       int
	PromotedInodes                  int
	ChunksAdded, ChunksDeduped      int
	DedupIndexChunks                int // identities preloaded from the sidecar
	// ReusedFiles/ReusedChunks count content carried forward from the
	// previous generation instead of read and re-chunked — the files this
	// seal never opened.
	ReusedFiles, ReusedChunks int
	ChunkBytes                int64
	Catalogs, Shards          int
	// CatalogsReused counts catalogs carried forward from the previous
	// generation by reference instead of rebuilt: the subtree they cover
	// did not change, so their bytes — already in a pack this generation
	// still lists — are referenced, never rewritten.
	CatalogsReused int
}

// Result is a successful publish.
type Result struct {
	Superblock *superblock.Superblock
	Raw        []byte // the wire bytes written to refs/<branch>
	NewPacks   []packstore.SealedPack
	Stats      Stats
}

// Seal publishes a write overlay into catalogs, packs, and a signed
// superblock. Options.Overlay and Options.Prev are required; everything
// downstream of the walk is the ordinary pipeline.
func Seal(ctx context.Context, o Options) (*Result, error) {
	if o.Overlay == nil && o.OverlaySnapshot == nil {
		return nil, errors.New("publish: Seal requires Options.Overlay")
	}
	return Publish(ctx, o)
}

// Publish runs TRANSFORM/UPLOAD/FLIP over the source and returns the
// flipped generation. On error nothing mutable has changed; any packs
// already uploaded are unreferenced orphans for GC (crash analysis in the
// design doc — publish is idempotent end to end).
func Publish(ctx context.Context, o Options) (*Result, error) {
	if err := applyDefaults(&o); err != nil {
		return nil, err
	}
	src, volUUID, closeSrc, err := openSource(o)
	if err != nil {
		return nil, err
	}
	defer closeSrc()

	volID, err := parseVolumeID(volUUID)
	if err != nil {
		return nil, err
	}
	gen := uint64(0)
	if o.Prev != nil {
		gen = o.Prev.Generation + 1
		if o.Prev.VolumeID != volID {
			return nil, fmt.Errorf("publish: source volume %x does not match previous generation's %x",
				volID, o.Prev.VolumeID)
		}
	}

	tmpDir, err := os.MkdirTemp(o.SpoolDir, "publish-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	p := &pipeline{
		o:           o,
		src:         src,
		pk:          newPacker(o.Inner, tmpDir, o.TargetPackSize),
		hasher:      chunkid.NewHasher(o.IdentityKey),
		gen:         gen,
		volUUID:     volUUID,
		volID:       volID,
		tmpDir:      tmpDir,
		dirs:        make(map[uint64][]edge),
		recs:        make(map[uint64]*rec),
		chunkSeen:   make(map[chunkid.Identity]chunkInfo),
		dnIno:       make(map[*catalog.DirNode]uint64),
		pathOf:      make(map[uint64]string),
		isCatRoot:   make(map[uint64]bool),
		catIdentity: make(map[uint64]chunkid.Identity),

		subtreeDirty: make(map[uint64]bool),
		carried:      make(map[uint64]superblock.CatalogEntry),
		catWeight:    make(map[uint64]int64),
		catPromoted:  make(map[uint64]int),
	}
	defer p.pk.abort()

	if err := p.walk(ctx); err != nil {
		return nil, err
	}
	if err := p.loadDedupIndex(); err != nil {
		return nil, err
	}
	// The plan runs before TRANSFORM so TRANSFORM can skip the content it
	// is about to discard; see catalogreuse.go.
	if err := p.plan(); err != nil {
		return nil, err
	}
	if err := p.transform(ctx); err != nil {
		return nil, err
	}
	shards, err := p.writeShards(ctx)
	if err != nil {
		return nil, err
	}
	rootID, err := p.writeCatalogs(ctx)
	if err != nil {
		return nil, err
	}

	// Superblock backup rides in the last pack (disaster recovery). It is
	// built before the final seal, so its pack list lacks the very pack
	// that carries it — rescue treats it as "the newest generation minus
	// its tail", exactly the documented fall-back-a-step behavior. Stored
	// raw (uncompressed, unencrypted): rescue must read it before holding
	// any keys, and the KEK-wrapped key table is harmless to expose.
	_, bkRaw, err := p.buildSuperblock(p.pk.sealedSoFar(), shards, rootID)
	if err != nil {
		return nil, err
	}
	bkHash := superblock.Hash(bkRaw)
	if err := p.pk.add(ctx, hex.EncodeToString(bkHash[:]), packstore.EntrySuperblock, bkRaw); err != nil {
		return nil, fmt.Errorf("publish: superblock backup: %w", err)
	}

	newPacks, err := p.pk.finish(ctx)
	if err != nil {
		return nil, fmt.Errorf("publish: seal pack: %w", err)
	}
	sb, raw, err := p.buildSuperblock(newPacks, shards, rootID)
	if err != nil {
		return nil, err
	}
	if err := flip(ctx, o, raw); err != nil {
		return nil, err
	}
	// The flip already happened: a sidecar write failure must not fail
	// the publish (the next run just re-uploads some chunks).
	if err := p.saveDedupIndex(sb.Generation); err != nil {
		ui.Warn("publish: dedup index not saved: {error}", "error", err)
	}
	return &Result{Superblock: sb, Raw: raw, NewPacks: newPacks, Stats: p.stats}, nil
}

// openSource opens the tree this publish reads and reports the volume
// UUID every catalog is stamped with. An overlay does not carry the
// superblock it shadows, so its identity comes from the previous
// generation. The returned func releases source resources.
func openSource(o Options) (Source, string, func(), error) {
	switch {
	case o.emptySource:
		return &emptyRoot{nextInode: 2}, formatVolumeID(o.VolumeID), func() {}, nil
	case o.OverlaySnapshot != nil:
		return &overlaySource{fs: o.OverlaySnapshot}, formatVolumeID(o.Prev.VolumeID), func() {}, nil
	default:
		return &overlaySource{fs: o.Overlay}, formatVolumeID(o.Prev.VolumeID), func() {}, nil
	}
}

func applyDefaults(o *Options) error {
	switch {
	case o.emptySource:
		// InitVolume supplies the tree itself.
	case o.Overlay == nil && o.OverlaySnapshot == nil:
		return errors.New("publish: Overlay or OverlaySnapshot is required")
	case o.Overlay != nil && o.OverlaySnapshot != nil:
		return errors.New("publish: Overlay and OverlaySnapshot are mutually exclusive")
	case o.Prev == nil:
		// An overlay always shadows a base generation; that generation is
		// the only place the volume identity and lineage come from.
		return errors.New("publish: sealing an overlay requires Prev (its base generation)")
	}
	if o.Inner == nil {
		return errors.New("publish: Inner store is required")
	}
	if o.SpoolDir == "" {
		return errors.New("publish: SpoolDir is required")
	}
	if len(o.SigningKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("publish: signing key is %d bytes, want %d", len(o.SigningKey), ed25519.PrivateKeySize)
	}
	if len(o.IdentityKey) != 0 && len(o.IdentityKey) != chunkid.IdentitySize {
		return fmt.Errorf("publish: identity key is %d bytes, want nil or %d", len(o.IdentityKey), chunkid.IdentitySize)
	}
	if len(o.DEK) != 0 && len(o.DEK) != entrycodec.KeySize {
		return fmt.Errorf("publish: DEK is %d bytes, want nil or %d", len(o.DEK), entrycodec.KeySize)
	}
	if len(o.DEK) != 0 && o.KeyID == 0 {
		return errors.New("publish: KeyID 0 is reserved for plaintext; encrypted publishes need a real key id")
	}
	if (o.Prev == nil) != (len(o.PrevRaw) == 0) {
		return errors.New("publish: Prev and PrevRaw must be supplied together")
	}
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.InlineMax <= 0 {
		o.InlineMax = DefaultInlineMax
	}
	if o.TargetPackSize <= 0 {
		o.TargetPackSize = DefaultTargetPackSize
	}
	if o.SMax <= 0 {
		o.SMax = catalog.SMax
	}
	if o.CreatedUnixNano == 0 {
		o.CreatedUnixNano = time.Now().UnixNano()
	}
	return nil
}

// edge is one directory entry from the source walk.
type edge struct {
	name  string
	inode uint64
	typ   uint8 // catalog.Type*
}

// rec is everything the pipeline knows about one inode.
type rec struct {
	n        SrcNode
	xattrs   []catalog.Xattr
	symlink  []byte
	inline   []byte
	chunks   []catalog.ChunkRef
	promoted bool // nlink > 1 regular file: content records live in a shard
}

type chunkInfo struct {
	clen  int64
	alg   uint8
	keyID int64 // the key the STORED bytes were encrypted under — a
	// chunk deduped across a DEK rotation keeps its original key id
}

type pipeline struct {
	o       Options
	src     Source
	pk      *packer
	hasher  chunkid.Hasher
	gen     uint64
	volUUID string
	volID   [16]byte
	tmpDir  string

	dirs     map[uint64][]edge
	recs     map[uint64]*rec
	maxInode uint64
	promoted []uint64

	chunkSeen   map[chunkid.Identity]chunkInfo
	dnIno       map[*catalog.DirNode]uint64
	pathOf      map[uint64]string
	isCatRoot   map[uint64]bool
	catIdentity map[uint64]chunkid.Identity

	// The plan (catalogreuse.go): what this seal must build rather than
	// carry forward. reuseArmed says the source and the previous
	// generation agree on enough for any of it to be sound; with it false
	// every inode reads as dirty and the whole tree is rebuilt.
	reuseArmed   bool
	dirty        map[uint64]struct{}
	subtreeDirty map[uint64]bool
	carried      map[uint64]superblock.CatalogEntry
	carriedList  []superblock.CatalogEntry
	writeOrder   []uint64
	needContent  map[uint64]bool
	catWeight    map[uint64]int64
	catPromoted  map[uint64]int

	stats Stats
}

// walk loads the source's tree into memory: per-directory edges, per-inode
// attributes, xattrs, symlink targets, and the promoted (nlink > 1) set.
// The descent is strictly parent-before-child (Readdir per directory) — the
// order a residency-by-lookup source requires; edges are sorted afterwards,
// so no source's own listing order is observable in the output.
func (p *pipeline) walk(ctx context.Context) error {
	rootIno := p.src.Root()
	root, err := p.src.Stat(ctx, rootIno)
	if err != nil {
		return fmt.Errorf("publish: stat root: %w", err)
	}
	p.recs[rootIno] = &rec{n: root}
	p.maxInode = rootIno
	expanded := make(map[uint64]bool)
	var descend func(ino uint64) error
	descend = func(ino uint64) error {
		if expanded[ino] {
			return nil
		}
		expanded[ino] = true
		entries, err := p.src.Readdir(ctx, ino)
		if err != nil {
			return fmt.Errorf("publish: readdir inode %d: %w", ino, err)
		}
		for _, e := range entries {
			n := e.Node
			p.dirs[ino] = append(p.dirs[ino], edge{name: e.Name, inode: n.Inode, typ: n.Type})
			if n.Inode > p.maxInode {
				p.maxInode = n.Inode
			}
			if _, ok := p.recs[n.Inode]; !ok {
				p.recs[n.Inode] = &rec{n: n}
			}
			if n.Type == catalog.TypeDir {
				if err := descend(n.Inode); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := descend(rootIno); err != nil {
		return err
	}
	// Sort edges by name so catalog row order — and therefore catalog
	// bytes and identities — is deterministic for identical trees.
	for _, es := range p.dirs {
		sort.Slice(es, func(i, j int) bool { return es[i].name < es[j].name })
	}
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		xa, err := p.src.Xattrs(ctx, ino)
		if err != nil {
			return fmt.Errorf("publish: xattrs of inode %d: %w", ino, err)
		}
		r.xattrs = sortedXattrs(xa)
		switch r.n.Type {
		case catalog.TypeDir:
			// A directory's link count is a function of the namespace
			// ("." and "..", plus one ".." per subdirectory), not a stored
			// attribute. Recomputing it from surviving edges is what makes
			// a sealed overlay — which deliberately does not maintain
			// parent link counts (internal/overlay, Mkdir) — and a
			// translated cut publish the same number.
			subdirs := 0
			for _, e := range p.dirs[ino] {
				if e.typ == catalog.TypeDir {
					subdirs++
				}
			}
			r.n.Nlink = uint32(2 + subdirs)
			p.stats.Dirs++
		case catalog.TypeSymlink:
			target, err := p.src.Readlink(ctx, ino)
			if err != nil {
				return fmt.Errorf("publish: readlink inode %d: %w", ino, err)
			}
			r.symlink = []byte(target)
			p.stats.Symlinks++
		case catalog.TypeFile:
			p.stats.Files++
			if r.n.Nlink > 1 {
				r.promoted = true
				p.promoted = append(p.promoted, ino)
			}
		default:
			p.stats.Specials++
		}
	}
	sort.Slice(p.promoted, func(i, j int) bool { return p.promoted[i] < p.promoted[j] })
	p.stats.PromotedInodes = len(p.promoted)
	return nil
}

// transform produces the content records this seal will actually write:
// inline bytes at or below the threshold, CDC chunk lists (with pack
// appends) above it. Files the source can prove untouched keep the
// records the previous generation already published, and are never opened
// at all; files inside a catalog being carried forward are not consulted
// at all, since the carried bytes already describe them (see the plan in
// catalogreuse.go).
func (p *pipeline) transform(ctx context.Context) error {
	reuse := p.contentReuser()
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		if r.n.Type != catalog.TypeFile || r.n.Length == 0 {
			continue
		}
		if !p.needsContent(ino) {
			// Every catalog that would hold this file's records is being
			// carried forward, records and all. Deriving them again would
			// mean proving the file untouched and fetching what the base
			// generation already says — to throw the answer away.
			continue
		}
		if reuse != nil {
			reused, err := p.reuseContent(ctx, reuse, r)
			if err != nil {
				return err
			}
			if reused {
				continue
			}
		}
		if r.n.Length <= p.o.InlineMax {
			rd, err := p.src.Open(ctx, ino, r.n.Length)
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			data, err := io.ReadAll(rd)
			rd.Close() //nolint:errcheck
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			if int64(len(data)) != r.n.Length {
				return fmt.Errorf("publish: inode %d read %d bytes, want %d", ino, len(data), r.n.Length)
			}
			r.inline = data
			p.stats.InlineFiles++
			continue
		}
		refs, err := p.chunkFile(ctx, ino, r.n.Length)
		if err != nil {
			return err
		}
		r.chunks = refs
		p.stats.ChunkedFiles++
	}
	return nil
}

// contentReuser reports the source's reuse capability, but only when the
// source answers from the EXACT generation this publish grows from.
//
// That equality is the whole safety argument for carrying content records
// forward. A chunkref names bytes by identity and nothing else; the bytes
// are locatable only through the pack list of a generation that holds
// them, and buildSuperblock carries Prev's pack list forward verbatim, so
// records reused from Prev are always locatable in what is being built.
// Records from any OTHER generation could name a pack this one does not
// list — and retention (internal/retention) deletes any pack no live
// superblock names, so the result would be a signed generation that
// becomes unreadable at the next sweep, discovered by a reader long after
// the seal that caused it.
func (p *pipeline) contentReuser() ContentReuser {
	if p.o.Prev == nil {
		return nil
	}
	cr, ok := p.src.(ContentReuser)
	if !ok {
		return nil
	}
	if cr.BaseGeneration() != p.o.Prev.RootCatalog {
		return nil
	}
	return cr
}

// reuseContent installs the previous generation's records for r when the
// source vouches for them, reporting whether it did. Anything unproven
// returns false and is chunked the ordinary way: a redundant re-chunk
// costs time, a wrong content record costs the file.
func (p *pipeline) reuseContent(ctx context.Context, cr ContentReuser, r *rec) (bool, error) {
	c, ok, err := cr.ExistingContent(ctx, r.n.Inode)
	if err != nil || !ok {
		return false, err
	}
	// Length is the one fact the source's proof does not itself compare.
	// It should never disagree — every overlay path that changes a length
	// also stages content — so this is a cheap standing check that the two
	// halves of the merged view describe the same file.
	if c.Length != r.n.Length {
		return false, nil
	}
	switch inlineNow := r.n.Length <= p.o.InlineMax; {
	case c.Inline != nil && inlineNow:
		r.inline = c.Inline
		p.stats.InlineFiles++
	case c.Refs != nil && !inlineNow:
		r.chunks = c.Refs
		p.rememberReusedChunks(c.Refs)
		p.stats.ChunkedFiles++
		p.stats.ReusedChunks += len(c.Refs)
	default:
		// The inline threshold moved since the base generation, so the
		// record on hand has the wrong shape for the catalog being built.
		// Rare enough to be worth re-reading rather than special-casing.
		return false, nil
	}
	p.stats.ReusedFiles++
	return true, nil
}

// rememberReusedChunks folds carried-forward identities into the
// within-publish dedup set. They live in packs this generation lists, so a
// NEWLY written file that happens to share one must not upload it again —
// and the sidecar index saved at the end is exactly this set, so dropping
// them would shrink the dedup domain a little more with every seal.
func (p *pipeline) rememberReusedChunks(refs []catalog.ChunkRef) {
	for _, ref := range refs {
		if len(ref.Identity) != chunkid.IdentitySize {
			continue // a hole, which stores nothing
		}
		id := chunkid.Identity(ref.Identity)
		if _, seen := p.chunkSeen[id]; seen {
			continue
		}
		p.chunkSeen[id] = chunkInfo{clen: ref.CLen, alg: uint8(ref.Alg), keyID: ref.KeyID}
	}
}

func (p *pipeline) chunkFile(ctx context.Context, ino uint64, length int64) ([]catalog.ChunkRef, error) {
	rd, err := p.src.Open(ctx, ino, length)
	if err != nil {
		return nil, fmt.Errorf("publish: read inode %d: %w", ino, err)
	}
	defer rd.Close() //nolint:errcheck
	ck := chunkid.NewChunker(rd, chunkid.Options{})
	var refs []catalog.ChunkRef
	var total int64
	for {
		c, err := ck.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("publish: chunk inode %d: %w", ino, err)
		}
		id := p.hasher.Sum(c.Data)
		info, ok := p.chunkSeen[id]
		if !ok {
			stored, alg, err := entrycodec.Encode(c.Data, p.o.DEK)
			if err != nil {
				return nil, fmt.Errorf("publish: encode chunk of inode %d: %w", ino, err)
			}
			if err := p.pk.add(ctx, id.Hex(), packstore.EntryData, stored); err != nil {
				return nil, fmt.Errorf("publish: pack chunk of inode %d: %w", ino, err)
			}
			info = chunkInfo{clen: int64(len(stored)), alg: alg, keyID: p.keyID()}
			p.chunkSeen[id] = info
			p.stats.ChunksAdded++
			p.stats.ChunkBytes += int64(len(c.Data))
		} else {
			p.stats.ChunksDeduped++
		}
		refs = append(refs, catalog.ChunkRef{
			Identity: append([]byte(nil), id[:]...),
			LLen:     int64(len(c.Data)),
			CLen:     info.clen,
			Alg:      int64(info.alg),
			KeyID:    info.keyID,
		})
		total += int64(len(c.Data))
	}
	if total != length {
		return nil, fmt.Errorf("publish: inode %d chunked %d bytes, want %d", ino, total, length)
	}
	return refs, nil
}

// writeShards partitions the promoted-inode space into contiguous ranges
// and writes one shard SQLite per range (inode-keyed tables only).
func (p *pipeline) writeShards(ctx context.Context) ([]superblock.ShardEntry, error) {
	if len(p.promoted) == 0 {
		return nil, nil
	}
	var parts [][]uint64
	var cur []uint64
	var w int64
	for _, ino := range p.promoted {
		iw := p.inodeShardWeight(ino)
		if len(cur) > 0 && w+iw > shardTargetWeight {
			parts = append(parts, cur)
			cur, w = nil, 0
		}
		cur = append(cur, ino)
		w += iw
	}
	parts = append(parts, cur)

	var out []superblock.ShardEntry
	for i, part := range parts {
		first, last := part[0], part[len(part)-1]
		fp := filepath.Join(p.tmpDir, fmt.Sprintf("shard-%d.db", i))
		cw, err := catalog.Create(fp, catalog.Meta{
			VolumeUUID:   p.volUUID,
			CoveredPath:  fmt.Sprintf("inodes:%d-%d", first, last),
			Generation:   p.gen,
			IdentityAlgo: p.identityAlgo(),
		})
		if err != nil {
			return nil, fmt.Errorf("publish: create shard: %w", err)
		}
		seen := make(map[uint64]bool)
		for _, ino := range part {
			if err := p.emitInode(cw, seen, ino, true); err != nil {
				cw.Close() //nolint:errcheck
				return nil, fmt.Errorf("publish: shard inode %d: %w", ino, err)
			}
		}
		id, err := p.packSQLite(ctx, cw, fp, packstore.EntryShard)
		if err != nil {
			return nil, fmt.Errorf("publish: pack shard: %w", err)
		}
		out = append(out, superblock.ShardEntry{FirstInode: first, LastInode: last, Identity: [32]byte(id)})
		p.stats.Shards++
	}
	return out, nil
}

// writeCatalogs builds the catalogs the plan says are not being carried
// forward, in the order it left them (descendants before ancestors — a
// parent records its children's identities), and returns the root catalog
// identity, which is a carried one when the whole tree is unchanged.
func (p *pipeline) writeCatalogs(ctx context.Context) (chunkid.Identity, error) {
	for _, ino := range p.writeOrder {
		id, err := p.writeCatalog(ctx, ino)
		if err != nil {
			return chunkid.Identity{}, err
		}
		p.catIdentity[ino] = id
	}
	rootID, ok := p.catIdentity[p.src.Root()]
	if !ok {
		return chunkid.Identity{}, errors.New("publish: no catalog was produced for the tree root")
	}
	return rootID, nil
}

// buildDirNode computes the catalog weight tree (W = 200·entries +
// inline_bytes + xattr bytes; promoted inodes' content weight lives in
// shards, so only their entry cost counts here) and, on the same descent,
// which subtrees hold anything the source changed.
//
// The inline contribution is read off the node's LENGTH rather than off
// bytes TRANSFORM produced: a file at or below the threshold contributes
// exactly its length by definition. That is what lets the split — and
// therefore the reuse plan — run before TRANSFORM instead of after it,
// which is the whole point of the plan.
func (p *pipeline) buildDirNode(ino uint64, pth string) *catalog.DirNode {
	d := &catalog.DirNode{}
	p.dnIno[d] = ino
	p.pathOf[ino] = pth
	d.OwnWeight = xattrBytes(p.recs[ino].xattrs)
	dirty := p.isDirty(ino)
	for _, e := range p.dirs[ino] {
		d.OwnWeight += entryWeight
		r := p.recs[e.inode]
		if p.isDirty(e.inode) {
			dirty = true
		}
		switch e.typ {
		case catalog.TypeDir:
			d.Children = append(d.Children, p.buildDirNode(e.inode, path.Join(pth, e.name)))
			if p.subtreeDirty[e.inode] {
				dirty = true
			}
		case catalog.TypeFile:
			if !r.promoted {
				d.OwnWeight += p.inlineLen(r) + xattrBytes(r.xattrs)
			}
		case catalog.TypeSymlink:
			d.OwnWeight += int64(len(r.symlink)) + xattrBytes(r.xattrs)
		default:
			d.OwnWeight += xattrBytes(r.xattrs)
		}
	}
	p.subtreeDirty[ino] = dirty
	return d
}

// inlineLen is the number of bytes a file will contribute to its
// catalog's inline table: its whole length at or below the threshold,
// nothing above it (those bytes go to packs as chunks).
func (p *pipeline) inlineLen(r *rec) int64 {
	if r.n.Type == catalog.TypeFile && r.n.Length <= p.o.InlineMax {
		return r.n.Length
	}
	return 0
}

func (p *pipeline) writeCatalog(ctx context.Context, rootIno uint64) (chunkid.Identity, error) {
	fp := filepath.Join(p.tmpDir, fmt.Sprintf("catalog-%d.db", rootIno))
	cw, err := catalog.Create(fp, catalog.Meta{
		VolumeUUID:   p.volUUID,
		CoveredPath:  p.pathOf[rootIno],
		Generation:   p.gen,
		IdentityAlgo: p.identityAlgo(),
	})
	if err != nil {
		return chunkid.Identity{}, fmt.Errorf("publish: create catalog %s: %w", p.pathOf[rootIno], err)
	}
	seen := make(map[uint64]bool)
	var emit func(ino uint64) error
	emit = func(ino uint64) error {
		if err := p.emitInode(cw, seen, ino, true); err != nil {
			return err
		}
		for _, e := range p.dirs[ino] {
			if e.typ == catalog.TypeDir && p.isCatRoot[e.inode] {
				id, ok := p.catIdentity[e.inode]
				if !ok {
					return fmt.Errorf("child catalog %s not yet written (split order bug)", p.pathOf[e.inode])
				}
				// A transition point carries BOTH halves in the parent:
				// the dirent and node row (lookup/stat of the directory
				// itself never fetch the child catalog) and the nested
				// locator (descending into its entries does). The child
				// catalog holds the directory's entries, not its identity.
				if err := cw.AddEdge(int64(ino), []byte(e.name), int64(e.inode), catalog.TypeDir); err != nil {
					return err
				}
				if err := p.emitInode(cw, seen, e.inode, true); err != nil {
					return err
				}
				if err := cw.AddNested(int64(ino), []byte(e.name), id[:]); err != nil {
					return err
				}
				continue
			}
			ct, err := catType(e.typ)
			if err != nil {
				return err
			}
			if err := cw.AddEdge(int64(ino), []byte(e.name), int64(e.inode), ct); err != nil {
				return err
			}
			if e.typ == catalog.TypeDir {
				if err := emit(e.inode); err != nil {
					return err
				}
			} else if err := p.emitInode(cw, seen, e.inode, !p.recs[e.inode].promoted); err != nil {
				return err
			}
		}
		return nil
	}
	if err := emit(rootIno); err != nil {
		cw.Close() //nolint:errcheck
		return chunkid.Identity{}, fmt.Errorf("publish: catalog %s: %w", p.pathOf[rootIno], err)
	}
	id, err := p.packSQLite(ctx, cw, fp, packstore.EntryCatalog)
	if err != nil {
		return chunkid.Identity{}, fmt.Errorf("publish: pack catalog %s: %w", p.pathOf[rootIno], err)
	}
	p.stats.Catalogs++
	return id, nil
}

// emitInode writes one inode's node row (once per writer) and, when
// content is true, its content records. Promoted inodes pass content=false
// in path catalogs — node row only — and content=true in their shard.
func (p *pipeline) emitInode(w *catalog.Writer, seen map[uint64]bool, ino uint64, content bool) error {
	if seen[ino] {
		return nil
	}
	seen[ino] = true
	r := p.recs[ino]
	typ, err := catType(r.n.Type)
	if err != nil {
		return err
	}
	if err := w.AddNode(catalog.Node{
		Inode:   int64(ino),
		Type:    typ,
		Mode:    r.n.Mode,
		UID:     r.n.UID,
		GID:     r.n.GID,
		MtimeNS: r.n.MtimeNS,
		CtimeNS: r.n.CtimeNS,
		Nlink:   r.n.Nlink,
		Length:  r.n.Length,
		Rdev:    r.n.Rdev,
	}); err != nil {
		return err
	}
	if !content {
		return nil
	}
	for _, x := range r.xattrs {
		if err := w.AddXattr(int64(ino), x.Name, x.Value); err != nil {
			return err
		}
	}
	switch r.n.Type {
	case catalog.TypeSymlink:
		return w.SetSymlink(int64(ino), r.symlink)
	case catalog.TypeFile:
		if r.inline != nil {
			return w.SetInline(int64(ino), r.inline)
		}
		if r.chunks != nil {
			return w.AddChunks(int64(ino), r.chunks)
		}
	}
	return nil
}

// packSQLite closes a catalog/shard writer, hashes the file bytes into its
// identity, encodes (always zstd — nested rows and the superblock carry no
// alg column, so the encoding must be fixed), and appends the pack entry.
func (p *pipeline) packSQLite(ctx context.Context, cw *catalog.Writer, fp, typ string) (chunkid.Identity, error) {
	if err := cw.Close(); err != nil {
		return chunkid.Identity{}, err
	}
	raw, err := os.ReadFile(fp)
	if err != nil {
		return chunkid.Identity{}, err
	}
	id := p.hasher.Sum(raw)
	stored, err := entrycodec.EncodeZstd(raw, p.o.DEK)
	if err != nil {
		return chunkid.Identity{}, err
	}
	if err := p.pk.add(ctx, id.Hex(), typ, stored); err != nil {
		return chunkid.Identity{}, err
	}
	_ = os.Remove(fp)
	return id, nil
}

func (p *pipeline) buildSuperblock(newPacks []packstore.SealedPack, shards []superblock.ShardEntry, rootID chunkid.Identity) (*superblock.Superblock, []byte, error) {
	var packList []superblock.PackEntry
	if p.o.Prev != nil {
		// Carry the previous generation's whole pack set forward; trimming
		// dead packs is repack's job, not publish's.
		//
		// Unconditional, and TRANSFORM's content reuse depends on it: a
		// carried-forward chunkref names bytes that live in one of Prev's
		// packs, and retention deletes any pack no live superblock lists.
		// If this ever grows a filter, reuse must be gated on the surviving
		// set (or dropped) in the same change.
		packList = append(packList, p.o.Prev.PackList...)
	}
	for _, sp := range newPacks {
		packList = append(packList, superblock.PackEntry{Name: sp.Name, TrailerHash: sp.TrailerHash, Size: sp.Size})
	}
	// The high-water mark prefers the source's real allocator counter;
	// max-inode-seen covers only sources that keep none (Source.NextInode
	// reports 0). Never regress below the previous generation's
	// (crash-burned numbers stay burned).
	nextInode := p.maxInode + 1
	if v := p.src.NextInode(); v > nextInode {
		nextInode = v
	}
	if p.o.Prev != nil && p.o.Prev.NextInode > nextInode {
		nextInode = p.o.Prev.NextInode
	}
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		VolumeID:        p.volID,
		Generation:      p.gen,
		CreatedUnixNano: p.o.CreatedUnixNano,
		RootCatalog:     [32]byte(rootID),
		PackList:        packList,
		Shards:          shards,
		NextInode:       nextInode,
		Catalogs:        p.catalogList(),
		Params: superblock.Params{
			SMaxBytes:     p.o.SMax,
			SMinBytes:     catalog.SMin,
			InlineMax:     p.o.InlineMax,
			TGraceSeconds: defaultTGraceSeconds,
			RetainK:       defaultRetainK,
		},
		KeyTable: p.o.KeyTable,
	}
	if p.o.DEK != nil {
		// Catalog/shard/backup entries have no per-entry keyid column;
		// the superblock states the one key that encrypts them all.
		sb.CatalogKeyID = p.o.KeyID
	}
	if p.o.Prev != nil {
		sb.PrevHash = superblock.Hash(p.o.PrevRaw)
	}
	if err := sb.Sign(p.o.SigningKey); err != nil {
		return nil, nil, fmt.Errorf("publish: %w", err)
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("publish: encode superblock: %w", err)
	}
	return sb, raw, nil
}

// flip writes the new generation to refs/<branch>. Best-effort CAS: the
// transport-level ETag If-Match guard lands with the pelicanobj wiring
// (StatKey already surfaces ETags); until then the current ref is compared
// against the generation this publish grew from, so a concurrent writer
// aborts loudly instead of being silently clobbered.
func flip(ctx context.Context, o Options, raw []byte) error {
	key := RefPrefix + o.Branch
	if o.Prev == nil {
		if _, err := o.Inner.StatKey(ctx, key); err == nil {
			return fmt.Errorf("publish: %s already exists; pass its current generation as Prev", key)
		}
	} else if cur, err := readRef(ctx, o.Inner, key); err == nil && !bytes.Equal(cur, o.PrevRaw) {
		// A missing ref is tolerated (recovering a lost ref is legitimate);
		// a DIFFERENT ref means a concurrent writer won.
		return fmt.Errorf("publish: %s changed since the previous generation was read (concurrent writer?)", key)
	}
	if err := o.Inner.Put(ctx, key, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("publish: flip %s: %w", key, err)
	}
	return nil
}

func readRef(ctx context.Context, s pelicanobj.Store, key string) ([]byte, error) {
	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		return nil, err
	}
	data, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	return data, nil
}

// ---- small helpers ----

func (p *pipeline) sortedInodes() []uint64 {
	out := make([]uint64, 0, len(p.recs))
	for ino := range p.recs {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (p *pipeline) keyID() int64 {
	if len(p.o.DEK) != 0 {
		return int64(p.o.KeyID)
	}
	return 0
}

func (p *pipeline) identityAlgo() string {
	if len(p.o.IdentityKey) != 0 {
		return "blake3-256-keyed"
	}
	return "blake3-256"
}

func (p *pipeline) inodeShardWeight(ino uint64) int64 {
	r := p.recs[ino]
	return entryWeight + int64(len(r.inline)) + xattrBytes(r.xattrs) + int64(len(r.chunks))*chunkRowWeight
}

func xattrBytes(xs []catalog.Xattr) int64 {
	var n int64
	for _, x := range xs {
		n += int64(len(x.Name) + len(x.Value))
	}
	return n
}

func sortedXattrs(m map[string][]byte) []catalog.Xattr {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]catalog.Xattr, 0, len(names))
	for _, name := range names {
		out = append(out, catalog.Xattr{Name: []byte(name), Value: m[name]})
	}
	return out
}

// catType range-checks a node type on its way into a catalog row. Sources
// already speak the catalog type space (see Source), so this is validation,
// not translation.
func catType(t uint8) (uint8, error) {
	switch t {
	case catalog.TypeFile, catalog.TypeDir, catalog.TypeSymlink, catalog.TypeFIFO,
		catalog.TypeBlockDev, catalog.TypeCharDev, catalog.TypeSocket:
		return t, nil
	}
	return 0, fmt.Errorf("publish: unknown inode type %d", t)
}

func parseVolumeID(uuid string) ([16]byte, error) {
	var id [16]byte
	h := strings.ReplaceAll(uuid, "-", "")
	if len(h) != 32 {
		return id, fmt.Errorf("publish: malformed volume UUID %q", uuid)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return id, fmt.Errorf("publish: malformed volume UUID %q: %w", uuid, err)
	}
	copy(id[:], b)
	return id, nil
}

// formatVolumeID renders a superblock volume id as the canonical dashed
// UUID catalog_meta records (parseVolumeID's inverse).
func formatVolumeID(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
