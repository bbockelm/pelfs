// Package hydrate implements the v2 phase-2 restore path
// (docs/design-packfs.md, "Hydration (phase-2 decision)"): FULL metadata,
// LAZY data. Given a signed superblock the CALLER has already verified,
// Hydrate rebuilds a mountable JuiceFS metadata database from the
// generation's catalogs and inode shards — preserving exact inode numbers,
// which the meta client's public API cannot do — and records a slice-map
// sidecar so NewBlob can serve JuiceFS block reads of hydrated slices
// straight from packs (range-GETs, decoded on demand).
//
// Trust boundary: this package does no signature or lineage checking. The
// refs layer verifies the superblock; everything reached from it is
// integrity-covered by the hash tree (catalog identities, chunk
// identities). Encrypted entries additionally fail their GCM open under a
// wrong or missing DEK.
package hydrate

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/juicedata/juicefs/pkg/meta"
	_ "modernc.org/sqlite" // direct row inserts into the rebuilt DB

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// metaBlockSizeKiB is the Format.BlockSize of every rebuilt volume (KiB;
// 4 MiB blocks — the cutdb/publish test volumes use the same). The block
// byte size is recorded in the sidecar so NewBlob slices decoded chunks
// exactly the way the chunk store asks for them.
const metaBlockSizeKiB = 4096

// rootInode mirrors meta.RootInode for int64 call sites.
const rootInode = int64(meta.RootInode)

// Options configures one Hydrate run.
type Options struct {
	// Inner is the raw transport for pack range reads (never a packstore
	// wrapper: identities resolve from the GENERATION's pack list, not a
	// directory listing).
	Inner pelicanobj.Store
	// SB is the generation to hydrate, ALREADY VERIFIED by the caller
	// (the refs layer does trust; this package only reads).
	SB *superblock.Superblock
	// DEK decrypts pack entries; nil for plaintext volumes, else 32 bytes
	// (unwrapping the key table under the user KEK is the caller's
	// business).
	DEK []byte
	// MetaPath is where the JuiceFS sqlite database is created. Must not
	// exist.
	MetaPath string
	// SidecarPath is where the slice-map sidecar sqlite is created. Must
	// not exist.
	SidecarPath string
	// CacheDir, when set, holds the decoded catalog/shard temp files
	// during hydration (they are removed afterwards); empty uses the
	// system temp dir. NewBlob takes its chunk cache dir separately.
	CacheDir string
	// VolumeName is the JuiceFS Format.Name of the rebuilt DB (default
	// "pelfs").
	VolumeName string
}

// Result summarizes one hydration.
type Result struct {
	Files, Dirs, Symlinks, Specials int
	InlineFiles, ChunkedFiles       int
	Slices                          int // slice-map entries (dedup'd by identity)
	Xattrs                          int
	NextInode, NextChunk            uint64
}

// packLoc locates one entry inside a sealed pack.
type packLoc struct {
	pack        string
	off, length int64
}

type edgeRow struct {
	parent int64
	name   []byte
	inode  int64
	typ    uint8
}

type chunkRow struct {
	inode  int64
	indx   uint32
	slices []byte
}

type xattrRow struct {
	inode int64
	name  string
	value []byte
}

type shardCat struct {
	first, last uint64
	cat         *catalog.Catalog
}

type hydrator struct {
	ctx    context.Context
	o      Options
	catDEK []byte // DEK when SB.CatalogKeyID != 0, else nil

	idx    map[string]packLoc
	tmpDir string
	opened []*catalog.Catalog
	shards []shardCat

	seen     map[int64]bool
	nodes    map[int64]nodeRow
	maxInode uint64
	edges    []edgeRow
	chunks   []chunkRow
	symlinks map[int64][]byte
	xattrs   []xattrRow

	slices     []sliceRow
	byIdentity map[string]uint64 // identity hex -> slice id (dedup)
	nextSlice  uint64

	res Result
}

type nodeRow struct {
	n      catalog.Node
	parent int64
}

// Hydrate rebuilds a mountable JuiceFS metadata database (full metadata,
// lazy data) from an already-verified superblock. On success MetaPath
// opens with the real meta client and SidecarPath drives NewBlob.
func Hydrate(ctx context.Context, o Options) (*Result, error) {
	if err := checkOptions(&o); err != nil {
		return nil, err
	}
	h := &hydrator{
		ctx:        ctx,
		o:          o,
		seen:       make(map[int64]bool),
		nodes:      make(map[int64]nodeRow),
		symlinks:   make(map[int64][]byte),
		byIdentity: make(map[string]uint64),
		nextSlice:  1,
	}
	if o.SB.CatalogKeyID != 0 {
		if len(o.DEK) == 0 {
			return nil, fmt.Errorf("hydrate: generation %d encrypts catalogs under key id %d; a DEK is required",
				o.SB.Generation, o.SB.CatalogKeyID)
		}
		h.catDEK = o.DEK
	}
	tmpDir, err := os.MkdirTemp(o.CacheDir, "pelfs-hydrate-*")
	if err != nil {
		return nil, err
	}
	h.tmpDir = tmpDir
	defer h.cleanup()

	if err := h.buildIdentityIndex(); err != nil {
		return nil, err
	}
	if err := h.loadShards(); err != nil {
		return nil, err
	}
	root, err := h.loadCatalog(o.SB.RootCatalog[:], "root catalog")
	if err != nil {
		return nil, err
	}
	if err := h.walk(root); err != nil {
		return nil, err
	}
	if err := h.writeMetaDB(); err != nil {
		return nil, err
	}
	if err := writeSidecar(o.SidecarPath, metaBlockSizeKiB*1024, h.slices); err != nil {
		return nil, fmt.Errorf("hydrate: sidecar: %w", err)
	}
	if err := verifyMetaDB(h.ctx, o.MetaPath); err != nil {
		return nil, fmt.Errorf("hydrate: rebuilt DB failed verification: %w", err)
	}
	h.res.Slices = len(h.slices)
	return &h.res, nil
}

func checkOptions(o *Options) error {
	if o.Inner == nil {
		return errors.New("hydrate: Inner store is required")
	}
	if o.SB == nil {
		return errors.New("hydrate: superblock is required")
	}
	if len(o.DEK) != 0 && len(o.DEK) != entrycodec.KeySize {
		return fmt.Errorf("hydrate: DEK is %d bytes, want nil or %d", len(o.DEK), entrycodec.KeySize)
	}
	for _, p := range []struct{ what, path string }{
		{"MetaPath", o.MetaPath},
		{"SidecarPath", o.SidecarPath},
	} {
		if p.path == "" {
			return fmt.Errorf("hydrate: %s is required", p.what)
		}
		if _, err := os.Stat(p.path); err == nil {
			return fmt.Errorf("hydrate: %s %s already exists", p.what, p.path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if o.VolumeName == "" {
		o.VolumeName = "pelfs"
	}
	return nil
}

func (h *hydrator) cleanup() {
	for _, c := range h.opened {
		_ = c.Close()
	}
	_ = os.RemoveAll(h.tmpDir)
}

// buildIdentityIndex fetches every listed pack's trailer and maps identity
// hex -> (pack, offset, length). The pack list is the generation's location
// layer; a directory listing is never consulted.
//
// TODO(trailer verification): the pack list records the BLAKE3 of the
// stored trailer bytes, but FetchTrailer does not expose them; verifying
// needs a FetchTrailer variant that returns the raw trailer alongside the
// parsed entries.
func (h *hydrator) buildIdentityIndex() error {
	h.idx = make(map[string]packLoc)
	for _, pe := range h.o.SB.PackList {
		entries, err := packstore.FetchTrailer(h.ctx, h.o.Inner, pe.Name, pe.Size)
		if err != nil {
			return fmt.Errorf("hydrate: %w", err)
		}
		for _, e := range entries {
			// Later packs win; content addressing makes duplicates
			// identical bytes anyway.
			h.idx[e.Key] = packLoc{pack: pe.Name, off: e.Off, length: e.Length}
		}
	}
	return nil
}

// fetchEntry range-reads one identified entry out of its pack.
func (h *hydrator) fetchEntry(identity []byte, what string) ([]byte, packLoc, error) {
	key := hex.EncodeToString(identity)
	loc, ok := h.idx[key]
	if !ok {
		return nil, packLoc{}, fmt.Errorf("hydrate: %s %s not found in any pack of this generation", what, key)
	}
	data, err := readRange(h.ctx, h.o.Inner, packstore.PackDirKey+"/"+loc.pack, loc.off, loc.length)
	if err != nil {
		return nil, packLoc{}, fmt.Errorf("hydrate: %s %s: %w", what, key, err)
	}
	return data, loc, nil
}

// loadCatalog fetches, decodes (always zstd, under the superblock's single
// catalog key), and opens one catalog or shard.
//
// TODO(identity verification): recomputing the identity needs the identity
// key on keyed volumes, which Options does not carry; the GCM open (when
// encrypted) and the SQLite parse are the current guards.
func (h *hydrator) loadCatalog(identity []byte, what string) (*catalog.Catalog, error) {
	stored, _, err := h.fetchEntry(identity, what)
	if err != nil {
		return nil, err
	}
	plain, err := entrycodec.Decode(stored, entrycodec.AlgZstd, h.catDEK)
	if err != nil {
		return nil, fmt.Errorf("hydrate: decode %s %x (wrong DEK?): %w", what, identity, err)
	}
	fp := filepath.Join(h.tmpDir, fmt.Sprintf("cat-%d.db", len(h.opened)))
	if err := os.WriteFile(fp, plain, 0600); err != nil {
		return nil, err
	}
	c, err := catalog.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("hydrate: open %s %x: %w", what, identity, err)
	}
	h.opened = append(h.opened, c)
	return c, nil
}

func (h *hydrator) loadShards() error {
	for _, sh := range h.o.SB.Shards {
		c, err := h.loadCatalog(sh.Identity[:], fmt.Sprintf("shard [%d,%d]", sh.FirstInode, sh.LastInode))
		if err != nil {
			return err
		}
		h.shards = append(h.shards, shardCat{first: sh.FirstInode, last: sh.LastInode, cat: c})
	}
	return nil
}

func (h *hydrator) shardFor(ino int64) (*catalog.Catalog, error) {
	for _, sh := range h.shards {
		if uint64(ino) >= sh.first && uint64(ino) <= sh.last {
			return sh.cat, nil
		}
	}
	return nil, fmt.Errorf("hydrate: promoted inode %d not covered by any shard range", ino)
}

// ---- catalog walk ----

func (h *hydrator) walk(root *catalog.Catalog) error {
	n, err := root.Stat(rootInode)
	if err != nil {
		return fmt.Errorf("hydrate: root inode missing from root catalog: %w", err)
	}
	h.seen[rootInode] = true
	h.addNode(n, rootInode) // JuiceFS roots the root at itself
	h.res.Dirs++
	if err := h.addXattrsFrom(root, rootInode); err != nil {
		return err
	}
	return h.walkDir(root, rootInode)
}

func (h *hydrator) walkDir(cat *catalog.Catalog, dir int64) error {
	dirents, nesteds, err := cat.Readdir(dir)
	if err != nil {
		return fmt.Errorf("hydrate: readdir inode %d: %w", dir, err)
	}
	nestedBy := make(map[string][]byte, len(nesteds))
	for _, n := range nesteds {
		nestedBy[string(n.Name)] = n.CatalogIdentity
	}
	for _, d := range dirents {
		h.edges = append(h.edges, edgeRow{parent: dir, name: append([]byte(nil), d.Name...), inode: d.Inode, typ: d.Type})
		if !h.seen[d.Inode] {
			h.seen[d.Inode] = true
			if err := h.emitInode(cat, dir, d.Inode); err != nil {
				return fmt.Errorf("hydrate: inode %d (%q): %w", d.Inode, d.Name, err)
			}
		}
		if d.Type == catalog.TypeDir {
			child := cat
			if id, ok := nestedBy[string(d.Name)]; ok {
				// Transition point: the directory's own rows live here in
				// the parent; its ENTRIES live in the child catalog.
				if child, err = h.loadCatalog(id, fmt.Sprintf("nested catalog %q", d.Name)); err != nil {
					return err
				}
			}
			if err := h.walkDir(child, d.Inode); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitInode records one inode's node row and content records, the inverse
// of publish's emitInode: promoted (nlink > 1) files stat from the path
// catalog but take content (chunks/inline/xattrs) from their inode shard.
func (h *hydrator) emitInode(cat *catalog.Catalog, dir, ino int64) error {
	n, err := cat.Stat(ino)
	if err != nil {
		return err
	}
	parent := dir
	src := cat
	if n.Type == catalog.TypeFile && n.Nlink > 1 {
		parent = 0 // what sql.go's doLink writes for multi-parent files
		if src, err = h.shardFor(ino); err != nil {
			return err
		}
	}
	h.addNode(n, parent)
	if err := h.addXattrsFrom(src, ino); err != nil {
		return err
	}
	switch n.Type {
	case catalog.TypeDir:
		h.res.Dirs++
	case catalog.TypeSymlink:
		h.res.Symlinks++
		target, err := cat.Symlink(ino)
		if err != nil {
			return err
		}
		h.symlinks[ino] = target
	case catalog.TypeFile:
		h.res.Files++
		return h.addFileContent(src, n)
	default:
		h.res.Specials++
	}
	return nil
}

func (h *hydrator) addNode(n catalog.Node, parent int64) {
	h.nodes[n.Inode] = nodeRow{n: n, parent: parent}
	if uint64(n.Inode) > h.maxInode {
		h.maxInode = uint64(n.Inode)
	}
}

func (h *hydrator) addXattrsFrom(src *catalog.Catalog, ino int64) error {
	xs, err := src.Xattrs(ino)
	if err != nil {
		return err
	}
	for _, x := range xs {
		h.xattrs = append(h.xattrs, xattrRow{inode: ino, name: string(x.Name), value: x.Value})
	}
	h.res.Xattrs += len(xs)
	return nil
}

func (h *hydrator) addFileContent(src *catalog.Catalog, n catalog.Node) error {
	inline, err := src.Inline(n.Inode)
	if err != nil {
		return err
	}
	if inline != nil {
		if int64(len(inline)) != n.Length {
			return fmt.Errorf("inline is %d bytes, node length %d", len(inline), n.Length)
		}
		id := h.allocInlineSlice(inline)
		h.chunks = append(h.chunks, chunkRow{
			inode:  n.Inode,
			indx:   0,
			slices: appendSliceRec(nil, 0, id, uint32(len(inline)), 0, uint32(len(inline))),
		})
		h.res.InlineFiles++
		return nil
	}
	refs, err := src.Chunks(n.Inode)
	if err != nil {
		return err
	}
	if refs == nil {
		if n.Length != 0 {
			return fmt.Errorf("length %d but no inline data and no chunkrefs", n.Length)
		}
		return nil
	}
	blobs := make(map[uint32][]byte)
	for _, r := range refs {
		if r.Identity == nil {
			continue // hole: consumes logical offset, emits no slice
		}
		id, err := h.allocPackSlice(r)
		if err != nil {
			return err
		}
		appendSliceSpans(blobs, r.LogicalOffset, id, r.LLen)
	}
	idxs := make([]uint32, 0, len(blobs))
	for indx := range blobs {
		idxs = append(idxs, indx)
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })
	for _, indx := range idxs {
		h.chunks = append(h.chunks, chunkRow{inode: n.Inode, indx: indx, slices: blobs[indx]})
	}
	h.res.ChunkedFiles++
	return nil
}

// allocPackSlice assigns (or reuses — content addressing) the synthetic
// slice id serving one chunkref, recording its pack location and decode
// parameters in the sidecar rows.
func (h *hydrator) allocPackSlice(r catalog.ChunkRef) (uint64, error) {
	key := hex.EncodeToString(r.Identity)
	if id, ok := h.byIdentity[key]; ok {
		return id, nil
	}
	if r.KeyID != 0 && len(h.o.DEK) == 0 {
		return 0, fmt.Errorf("chunk %s is encrypted under key id %d but no DEK was supplied", key, r.KeyID)
	}
	if r.LLen <= 0 || r.LLen > int64(meta.ChunkSize) {
		return 0, fmt.Errorf("chunk %s has implausible logical length %d", key, r.LLen)
	}
	loc, ok := h.idx[key]
	if !ok {
		return 0, fmt.Errorf("chunk %s not found in any pack of this generation", key)
	}
	if loc.length != r.CLen {
		return 0, fmt.Errorf("chunk %s is %d stored bytes in pack %s, chunkref says %d", key, loc.length, loc.pack, r.CLen)
	}
	id := h.nextSlice
	h.nextSlice++
	h.byIdentity[key] = id
	h.slices = append(h.slices, sliceRow{
		id:       id,
		kind:     sliceKindPack,
		identity: append([]byte(nil), r.Identity...),
		pack:     loc.pack,
		off:      loc.off,
		length:   loc.length,
		clen:     r.CLen,
		alg:      r.Alg,
		keyid:    r.KeyID,
		llen:     r.LLen,
	})
	return id, nil
}

// allocInlineSlice assigns a slice id whose bytes live in the sidecar
// itself — no pack read ever happens for inline files.
func (h *hydrator) allocInlineSlice(data []byte) uint64 {
	id := h.nextSlice
	h.nextSlice++
	h.slices = append(h.slices, sliceRow{
		id:     id,
		kind:   sliceKindInline,
		llen:   int64(len(data)),
		inline: append([]byte(nil), data...),
	})
	return id
}

// ---- metadata rebuild ----

// writeMetaDB creates the JuiceFS database (meta client Init lays down the
// schema, format setting, root node, and counters), then inserts every row
// directly — the meta client allocates its own inode numbers and cannot
// reproduce the cut's, and stable inodes are a format guarantee.
func (h *hydrator) writeMetaDB() error {
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	m := meta.NewClient("sqlite3://"+h.o.MetaPath, conf)
	format := &meta.Format{
		Name:      h.o.VolumeName,
		UUID:      canonicalUUID(h.o.SB.VolumeID),
		Storage:   "mem",
		BlockSize: metaBlockSizeKiB,
	}
	if err := m.Init(format, false); err != nil {
		return fmt.Errorf("hydrate: init meta DB: %w", err)
	}
	if err := m.Shutdown(); err != nil {
		return fmt.Errorf("hydrate: close meta client: %w", err)
	}

	db, err := sql.Open("sqlite", "file:"+h.o.MetaPath)
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := h.insertRows(tx); err != nil {
		return fmt.Errorf("hydrate: rebuild rows: %w", err)
	}
	return tx.Commit()
}

func (h *hydrator) insertRows(tx *sql.Tx) error {
	// Node times: the catalog stores nanoseconds; jfs_node stores
	// microseconds plus a sub-microsecond nanosecond remainder. atime :=
	// mtime — catalogs persist no atime by design.
	nodeStmt, err := tx.Prepare(`INSERT OR REPLACE INTO jfs_node
		(inode, type, flags, mode, uid, gid,
		 atime, mtime, ctime, atimensec, mtimensec, ctimensec,
		 nlink, length, rdev, parent, access_acl_id, default_acl_id, tier_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)`)
	if err != nil {
		return err
	}
	defer nodeStmt.Close() //nolint:errcheck
	var usedSpace, totalInodes int64
	for _, ino := range h.sortedNodeInodes() {
		r := h.nodes[ino]
		if _, err := nodeStmt.Exec(
			r.n.Inode, r.n.Type, r.n.Flags, r.n.Mode, r.n.UID, r.n.GID,
			r.n.MtimeNS/1e3, r.n.MtimeNS/1e3, r.n.CtimeNS/1e3,
			r.n.MtimeNS%1e3, r.n.MtimeNS%1e3, r.n.CtimeNS%1e3,
			r.n.Nlink, r.n.Length, r.n.Rdev, r.parent,
		); err != nil {
			return fmt.Errorf("node %d: %w", ino, err)
		}
		if ino != rootInode {
			usedSpace += align4K(r.n.Length)
			totalInodes++
		}
	}
	edgeStmt, err := tx.Prepare(`INSERT INTO jfs_edge (parent, name, inode, type) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer edgeStmt.Close() //nolint:errcheck
	for _, e := range h.edges {
		if _, err := edgeStmt.Exec(e.parent, e.name, e.inode, e.typ); err != nil {
			return fmt.Errorf("edge %d/%q: %w", e.parent, e.name, err)
		}
	}
	chunkStmt, err := tx.Prepare(`INSERT INTO jfs_chunk (inode, indx, slices) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer chunkStmt.Close() //nolint:errcheck
	for _, c := range h.chunks {
		if _, err := chunkStmt.Exec(c.inode, c.indx, c.slices); err != nil {
			return fmt.Errorf("chunk %d/%d: %w", c.inode, c.indx, err)
		}
	}
	for ino, target := range h.symlinks {
		if _, err := tx.Exec(`INSERT INTO jfs_symlink (inode, target) VALUES (?, ?)`, ino, target); err != nil {
			return fmt.Errorf("symlink %d: %w", ino, err)
		}
	}
	for _, x := range h.xattrs {
		if _, err := tx.Exec(`INSERT INTO jfs_xattr (inode, name, value) VALUES (?, ?, ?)`, x.inode, x.name, x.value); err != nil {
			return fmt.Errorf("xattr %d/%s: %w", x.inode, x.name, err)
		}
	}

	// Counters: nextInode from the superblock's allocator high-water mark
	// (never below what this tree actually uses); nextChunk past every
	// synthetic slice id, so a read-write mount's NEW slices never collide
	// with hydrated ones.
	h.res.NextInode = h.o.SB.NextInode
	if h.maxInode+1 > h.res.NextInode {
		h.res.NextInode = h.maxInode + 1
	}
	h.res.NextChunk = h.nextSlice
	for name, v := range map[string]int64{
		"nextInode":   int64(h.res.NextInode),
		"nextChunk":   int64(h.res.NextChunk),
		"usedSpace":   usedSpace,
		"totalInodes": totalInodes,
	} {
		if _, err := tx.Exec(`UPDATE jfs_counter SET value = ? WHERE name = ?`, v, name); err != nil {
			return fmt.Errorf("counter %s: %w", name, err)
		}
	}
	return nil
}

func (h *hydrator) sortedNodeInodes() []int64 {
	out := make([]int64, 0, len(h.nodes))
	for ino := range h.nodes {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// verifyMetaDB opens the rebuilt database with the real meta client and
// reads the root directory — proof the engine accepts what we wrote.
func verifyMetaDB(ctx context.Context, metaPath string) error {
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	conf.ReadOnly = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	if _, err := m.Load(true); err != nil {
		return err
	}
	if err := m.NewSession(false); err != nil {
		return err
	}
	var entries []*meta.Entry
	st := m.Readdir(meta.WrapContext(ctx), meta.RootInode, 1, &entries)
	cerr := m.CloseSession()
	_ = m.Shutdown()
	if st != 0 {
		return fmt.Errorf("readdir of root: %s", st)
	}
	return cerr
}

// align4K mirrors meta's usedSpace accounting unit.
func align4K(length int64) int64 {
	if length <= 0 {
		return 4096
	}
	return (((length - 1) >> 12) + 1) << 12
}

func canonicalUUID(id [16]byte) string {
	x := hex.EncodeToString(id[:])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// readRange fetches one exact byte range (the packstore read discipline:
// Close errors are transfer failures and short reads are errors).
func readRange(ctx context.Context, s pelicanobj.Store, key string, off, length int64) ([]byte, error) {
	rc, err := s.Get(ctx, key, off, length)
	if err != nil {
		return nil, err
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, length))
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, off, length, cerr)
	}
	if int64(len(buf)) != length {
		return nil, fmt.Errorf("read %s [%d,+%d): short read (%d bytes)", key, off, length, len(buf))
	}
	return buf, nil
}
