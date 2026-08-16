// Package publish implements the v2 publish pipeline over an
// already-created cut (docs/design-packfs.md, "Publish: the transactional
// pipeline"). CUT and RECONCILE are the session's job — by the time this
// package runs, the cut database exists and every block it references is
// durable in the session's blob store. What remains is TRANSFORM (walk the
// cut, chunk file content, build split path catalogs and inode shards,
// append everything to packs), UPLOAD (pack seals), and FLIP (write the
// signed superblock to refs/<branch>).
//
// Simplifications, deliberate and marked at their sites:
//   - Full-tree TRANSFORM: every catalog and shard regenerates from the
//     cut. Dirty-set tracking is a later optimization; content addressing
//     already makes an unchanged subtree's catalog hash to the same bytes
//     it did last generation.
//   - Chunk dedup is within-publish only (see packer). An unchanged file
//     re-uploads its chunks under the same identities across generations —
//     wasted bytes, never corruption.
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

	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/cutdb"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
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
	// CutPath is the VACUUM'd JuiceFS meta snapshot that defines this
	// generation's contents.
	CutPath string
	// Blob is the session's data store, for reading file content the cut
	// references.
	Blob object.ObjectStorage
	// CacheDir backs the cut reader's block cache (pass the session's
	// cache dir so TRANSFORM hits blocks the writer just produced).
	CacheDir string
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
	// ReadStaging serves cut content from the session's writeback staging
	// area (accumulate mode, where staged blocks never uploaded and the
	// publish IS the durability step).
	ReadStaging bool
}

// Stats summarizes one publish.
type Stats struct {
	Dirs, Files, Symlinks, Specials int
	InlineFiles, ChunkedFiles       int
	PromotedInodes                  int
	ChunksAdded, ChunksDeduped      int
	DedupIndexChunks                int // identities preloaded from the sidecar
	ChunkBytes                      int64
	Catalogs, Shards                int
}

// Result is a successful publish.
type Result struct {
	Superblock *superblock.Superblock
	Raw        []byte // the wire bytes written to refs/<branch>
	NewPacks   []packstore.SealedPack
	Stats      Stats
}

// Publish runs TRANSFORM/UPLOAD/FLIP over the cut and returns the flipped
// generation. On error nothing mutable has changed; any packs already
// uploaded are unreferenced orphans for GC (crash analysis in the design
// doc — publish is idempotent end to end).
func Publish(ctx context.Context, o Options) (*Result, error) {
	if err := applyDefaults(&o); err != nil {
		return nil, err
	}
	db, err := cutdb.Open(o.CutPath, cutdb.Options{Blob: o.Blob, CacheDir: o.CacheDir, Staging: o.ReadStaging})
	if err != nil {
		return nil, fmt.Errorf("publish: open cut: %w", err)
	}
	defer db.Close() //nolint:errcheck

	volID, err := parseVolumeID(db.Format().UUID)
	if err != nil {
		return nil, err
	}
	gen := uint64(0)
	if o.Prev != nil {
		gen = o.Prev.Generation + 1
		if o.Prev.VolumeID != volID {
			return nil, fmt.Errorf("publish: cut volume %x does not match previous generation's %x",
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
		db:          db,
		pk:          newPacker(o.Inner, tmpDir, o.TargetPackSize),
		hasher:      chunkid.NewHasher(o.IdentityKey),
		gen:         gen,
		volUUID:     db.Format().UUID,
		volID:       volID,
		tmpDir:      tmpDir,
		dirs:        make(map[uint64][]edge),
		recs:        make(map[uint64]*rec),
		chunkSeen:   make(map[chunkid.Identity]chunkInfo),
		dnIno:       make(map[*catalog.DirNode]uint64),
		pathOf:      make(map[uint64]string),
		isCatRoot:   make(map[uint64]bool),
		catIdentity: make(map[uint64]chunkid.Identity),
	}
	defer p.pk.abort()

	if err := p.walk(ctx); err != nil {
		return nil, err
	}
	if err := p.loadDedupIndex(); err != nil {
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
		fmt.Fprintf(os.Stderr, "pelfs: publish: dedup index not saved: %v\n", err)
	}
	return &Result{Superblock: sb, Raw: raw, NewPacks: newPacks, Stats: p.stats}, nil
}

func applyDefaults(o *Options) error {
	if o.CutPath == "" {
		return errors.New("publish: CutPath is required")
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

// edge is one directory entry from the cut walk.
type edge struct {
	name  string
	inode uint64
	typ   uint8 // meta.Type*
}

// rec is everything the pipeline knows about one inode.
type rec struct {
	n        cutdb.Node
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
	db      *cutdb.DB
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

	stats Stats
}

// walk loads the cut's tree into memory: per-directory edges, per-inode
// attributes, xattrs, symlink targets, and the promoted (nlink > 1) set.
func (p *pipeline) walk(ctx context.Context) error {
	root, err := p.db.Stat(ctx, cutdb.RootInode)
	if err != nil {
		return fmt.Errorf("publish: stat root: %w", err)
	}
	p.recs[root.Inode] = &rec{n: root}
	p.maxInode = root.Inode
	if err := p.db.Walk(ctx, func(parent uint64, name string, n cutdb.Node) error {
		p.dirs[parent] = append(p.dirs[parent], edge{name: name, inode: n.Inode, typ: n.Type})
		if n.Inode > p.maxInode {
			p.maxInode = n.Inode
		}
		if _, ok := p.recs[n.Inode]; !ok {
			p.recs[n.Inode] = &rec{n: n}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("publish: walk cut: %w", err)
	}
	// Sort edges by name so catalog row order — and therefore catalog
	// bytes and identities — is deterministic for identical trees.
	for _, es := range p.dirs {
		sort.Slice(es, func(i, j int) bool { return es[i].name < es[j].name })
	}
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		xa, err := p.db.Xattrs(ctx, ino)
		if err != nil {
			return fmt.Errorf("publish: xattrs of inode %d: %w", ino, err)
		}
		r.xattrs = sortedXattrs(xa)
		switch r.n.Type {
		case meta.TypeDirectory:
			p.stats.Dirs++
		case meta.TypeSymlink:
			target, err := p.db.Readlink(ctx, ino)
			if err != nil {
				return fmt.Errorf("publish: readlink inode %d: %w", ino, err)
			}
			r.symlink = []byte(target)
			p.stats.Symlinks++
		case meta.TypeFile:
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

// transform produces every file's content records: inline bytes at or
// below the threshold, CDC chunk lists (with pack appends) above it.
func (p *pipeline) transform(ctx context.Context) error {
	for _, ino := range p.sortedInodes() {
		r := p.recs[ino]
		if r.n.Type != meta.TypeFile || r.n.Length == 0 {
			continue
		}
		if int64(r.n.Length) <= p.o.InlineMax {
			rd, err := p.db.FileReader(ctx, ino, r.n.Length)
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			data, err := io.ReadAll(rd)
			if err != nil {
				return fmt.Errorf("publish: read inode %d: %w", ino, err)
			}
			if uint64(len(data)) != r.n.Length {
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

func (p *pipeline) chunkFile(ctx context.Context, ino, length uint64) ([]catalog.ChunkRef, error) {
	rd, err := p.db.FileReader(ctx, ino, length)
	if err != nil {
		return nil, fmt.Errorf("publish: read inode %d: %w", ino, err)
	}
	ck := chunkid.NewChunker(rd, chunkid.Options{})
	var refs []catalog.ChunkRef
	var total uint64
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
		total += uint64(len(c.Data))
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

// writeCatalogs weighs the tree, splits it into catalog roots, and writes
// catalogs bottom-up (Split returns peeled roots in post-order — every
// child catalog before any parent that references it — with the tree root
// last), returning the root catalog identity.
func (p *pipeline) writeCatalogs(ctx context.Context) (chunkid.Identity, error) {
	rootDN := p.buildDirNode(cutdb.RootInode, "/")
	roots := catalog.Split(rootDN, p.o.SMax, catalog.SMin)
	for _, dn := range roots {
		p.isCatRoot[p.dnIno[dn]] = true
	}
	var rootID chunkid.Identity
	for _, dn := range roots {
		ino := p.dnIno[dn]
		id, err := p.writeCatalog(ctx, ino)
		if err != nil {
			return chunkid.Identity{}, err
		}
		p.catIdentity[ino] = id
		rootID = id // the tree root is last
	}
	return rootID, nil
}

// buildDirNode computes the catalog weight tree (W = 200·entries +
// inline_bytes + xattr bytes; promoted inodes' content weight lives in
// shards, so only their entry cost counts here).
func (p *pipeline) buildDirNode(ino uint64, pth string) *catalog.DirNode {
	d := &catalog.DirNode{}
	p.dnIno[d] = ino
	p.pathOf[ino] = pth
	d.OwnWeight = xattrBytes(p.recs[ino].xattrs)
	for _, e := range p.dirs[ino] {
		d.OwnWeight += entryWeight
		r := p.recs[e.inode]
		switch e.typ {
		case meta.TypeDirectory:
			d.Children = append(d.Children, p.buildDirNode(e.inode, path.Join(pth, e.name)))
		case meta.TypeFile:
			if !r.promoted {
				d.OwnWeight += int64(len(r.inline)) + xattrBytes(r.xattrs)
			}
		case meta.TypeSymlink:
			d.OwnWeight += int64(len(r.symlink)) + xattrBytes(r.xattrs)
		default:
			d.OwnWeight += xattrBytes(r.xattrs)
		}
	}
	return d
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
			if e.typ == meta.TypeDirectory && p.isCatRoot[e.inode] {
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
			if e.typ == meta.TypeDirectory {
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
		Mode:    uint32(r.n.Mode),
		UID:     r.n.Uid,
		GID:     r.n.Gid,
		MtimeNS: r.n.MtimeNs,
		CtimeNS: r.n.CtimeNs,
		Nlink:   r.n.Nlink,
		Length:  int64(r.n.Length),
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
	case meta.TypeSymlink:
		return w.SetSymlink(int64(ino), r.symlink)
	case meta.TypeFile:
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
		packList = append(packList, p.o.Prev.PackList...)
	}
	for _, sp := range newPacks {
		packList = append(packList, superblock.PackEntry{Name: sp.Name, TrailerHash: sp.TrailerHash, Size: sp.Size})
	}
	// The cut does not expose the allocator counter, so the high-water mark
	// prefers the cut's real allocator counter; the max-inode-seen
	// fallback covers only a counter table the engine has not written
	// yet. Never regress below the previous generation's (crash-burned
	// numbers stay burned).
	nextInode := p.maxInode + 1
	if v, err := p.db.Counter("nextInode"); err == nil && uint64(v) > nextInode {
		nextInode = uint64(v)
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

func catType(t uint8) (uint8, error) {
	switch t {
	case meta.TypeFile:
		return catalog.TypeFile, nil
	case meta.TypeDirectory:
		return catalog.TypeDir, nil
	case meta.TypeSymlink:
		return catalog.TypeSymlink, nil
	case meta.TypeFIFO:
		return catalog.TypeFIFO, nil
	case meta.TypeBlockDev:
		return catalog.TypeBlockDev, nil
	case meta.TypeCharDev:
		return catalog.TypeCharDev, nil
	case meta.TypeSocket:
		return catalog.TypeSocket, nil
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
