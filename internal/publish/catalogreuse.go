package publish

import (
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Catalog reuse: the plan step between the walk and TRANSFORM.
//
// A catalog is a pure function of the subtree it covers — the node rows,
// edges, xattrs, and content records of every inode from its root down to
// the next catalog boundary, plus the identities of the catalogs at those
// boundaries. Nothing else varies: the volume UUID is the volume's, the
// covered path is the root's path, the format version and identity algo
// are the writer's, and row order is sorted. So if no inode in that span
// changed and the boundaries fell in the same places, the catalog this
// seal would build is the catalog the previous generation already
// published, and building it again is pure waste — up to tens of
// megabytes of SQLite, zstd, hashing, and upload per seal.
//
// Carrying it forward instead is the same move content reuse makes for
// chunks, and it inherits the same retention obligation: the bytes live
// in a pack of an OLDER generation, and retention deletes any pack no
// live superblock names. buildSuperblock carries the previous
// generation's whole pack list forward verbatim, which is what keeps
// them; catalogReuser refuses to engage unless this publish is building
// directly on that generation, so "the previous generation's packs" and
// "the packs this generation lists" are the same set. See
// TestCarriedCatalogsStayRetained, which runs a real deleting GC with a
// far-future clock — where only the pack list can save a pack — and then
// reads the generation back through a cold cache.
//
// The boundaries are not a hazard either, and that is a property of the
// split policy rather than luck: catalog.Split's peel decisions inside a
// subtree are a function of that subtree alone (see split.go). Two
// identical clean subtrees under the same SMax therefore split
// identically, so an unchanged subtree's internal catalog boundaries are
// unchanged too. A count-based or globally-ordered split would not have
// this property — inserting one inode would shift every boundary after it
// and no reuse logic could help.

// catalogReuser reports the source's reuse capability together with the
// previous generation's catalog tree, but only when every input the
// carried bytes were produced under still holds.
//
// The generation gate is the retention argument above. The parameter
// gates are narrower: SMax decides where catalogs end, InlineMax decides
// whether a small file's bytes sit in the catalog or in a pack, and the
// catalog key id decides what a reader must decrypt the bytes WITH — the
// superblock states one key for every catalog it names, so a generation
// may not mix carried catalogs encrypted under the old key with fresh
// ones under a new key. Any of them moving means the previous
// generation's catalogs are not what this one would write, so nothing is
// carried and the whole tree rebuilds under the new policy.
func (p *pipeline) catalogReuser() (CatalogReuser, map[uint64]superblock.CatalogEntry) {
	if p.o.Prev == nil || len(p.o.Prev.Catalogs) == 0 {
		return nil, nil
	}
	cr, ok := p.src.(CatalogReuser)
	if !ok {
		return nil, nil
	}
	if cr.BaseGeneration() != p.o.Prev.RootCatalog {
		return nil, nil
	}
	if p.o.SMax != p.o.Prev.Params.SMaxBytes || p.o.InlineMax != p.o.Prev.Params.InlineMax {
		return nil, nil
	}
	if p.catalogKeyID() != p.o.Prev.CatalogKeyID {
		return nil, nil
	}
	base := make(map[uint64]superblock.CatalogEntry, len(p.o.Prev.Catalogs))
	for _, ce := range p.o.Prev.Catalogs {
		base[ce.Inode] = ce
	}
	return cr, base
}

// catalogKeyID is the key id this publish would stamp into the
// superblock for catalog, shard, and backup entries (0 = plaintext).
func (p *pipeline) catalogKeyID() uint32 {
	if p.o.DEK != nil {
		return p.o.KeyID
	}
	return 0
}

// armReuse settles, before the walk starts, whether anything may be
// carried forward — and if so, what the walk is allowed to skip.
//
// It runs first because pruning is a decision about where NOT to go, and
// a walk cannot un-read a directory. The two inputs are different shapes
// of the same fact: DirtyInodes says which inodes changed, which decides
// per catalog rebuild-or-carry; DirtyScope places those inodes in the
// namespace, which decides per directory descend-or-stop. A source that
// cannot place them all leaves the scope nil and the walk complete —
// catalogs are still carried where the tree proves them unchanged, just
// after reading it.
func (p *pipeline) armReuse() error {
	reuser, baseCats := p.catalogReuser()
	if reuser == nil {
		return nil
	}
	dirty, err := reuser.DirtyInodes()
	if err != nil {
		return err
	}
	p.dirty = dirty
	p.baseCats = baseCats
	p.reuseArmed = true

	scope, ok, err := reuser.DirtyScope()
	if err != nil {
		return err
	}
	if ok {
		p.scope = scope
	}
	return nil
}

// pruneSubtree reports whether the walk may stop at a directory, and
// records the catalog it will be replaced by when it may.
//
// Three conditions, each covering a different way a skipped subtree could
// go wrong:
//
//   - Nothing changed anywhere below it (the dirty scope). The scope
//     contains every changed inode and every ancestor of one, so a
//     directory outside it has an unchanged subtree.
//   - The previous generation rooted a catalog exactly here, under this
//     path. That catalog is what stands in for the subtree — its bytes,
//     its recorded weight, and the nested tree inside it.
//   - The span holds no promoted (nlink > 1) inodes. Their content
//     records live in inode SHARDS, which are rebuilt whole from the walk
//     every generation; skipping one would drop its record from the new
//     shards and make the file unreadable. The same condition covers the
//     other multi-parent hazard: only hardlinked files have more than one
//     parent, so within a prunable span every inode is reachable by
//     exactly the path the scope reasoned about.
func (p *pipeline) pruneSubtree(ino uint64, pth string) bool {
	if p.scope == nil {
		return false
	}
	if _, inScope := p.scope[ino]; inScope {
		return false
	}
	ce, ok := p.baseCats[ino]
	if !ok || ce.Path != pth || ce.Promoted != 0 {
		return false
	}
	p.pruned[ino] = ce
	return true
}

// plan decides what this seal actually has to build: it weighs the tree,
// splits it into catalog roots, works out which of those catalogs the
// previous generation already published unchanged, and marks the inodes
// whose content records are still needed.
//
// It runs BEFORE transform, which is the point. Deriving a file's content
// records means proving the file untouched and fetching the records the
// base generation holds — per file, over the whole tree. Inside a catalog
// that is being carried forward those records are already in the carried
// bytes, so the work is not merely redundant, it is work whose result is
// discarded. Running the split first is possible because catalog weight
// is a function of node attributes alone: a file at or below the inline
// threshold contributes exactly its length, whether or not anyone has
// read it yet.
func (p *pipeline) plan() error {
	rootDN := p.buildDirNode(p.src.Root(), "/")
	roots := catalog.Split(rootDN, p.o.SMax, catalog.SMin)
	for _, dn := range roots {
		ino := p.dnIno[dn]
		p.isCatRoot[ino] = true
		p.catWeight[ino] = dn.Weight
	}
	p.planReuse(p.baseCats)
	p.planContent()
	p.countPromoted()
	return nil
}

// planReuse walks the catalog tree from its root and decides, per
// catalog, carry-forward or rebuild. Descent stops at a carried catalog:
// everything below it is carried with it, by the nested rows already
// inside its bytes.
//
// The order it leaves behind is descendants-before-ancestors, which is
// what writeCatalog needs — a parent records its children's identities,
// so the children must exist first.
func (p *pipeline) planReuse(baseCats map[uint64]superblock.CatalogEntry) {
	var byPath []superblock.CatalogEntry
	if p.reuseArmed {
		byPath = append(byPath, p.o.Prev.Catalogs...)
		sort.Slice(byPath, func(i, j int) bool { return byPath[i].Path < byPath[j].Path })
	}
	var visit func(root uint64)
	visit = func(root uint64) {
		if p.reuseArmed && !p.subtreeDirty[root] {
			// The path check is not paranoia about identity: a catalog
			// records the path it covers, and a subtree that moved wholesale
			// (a renamed ancestor) has unchanged CONTENTS under a changed
			// path. Carrying it would publish a catalog that misdescribes
			// itself to anything reassembling the tree from packs alone.
			if ce, ok := baseCats[root]; ok && ce.Path == p.pathOf[root] {
				p.catIdentity[root] = chunkid.Identity(ce.Identity)
				p.carried[root] = ce
				// The whole subtree comes with it, including catalogs this
				// publish will never look at. They stay live and must stay
				// recorded, or the next generation forgets they exist and
				// rebuilds them for nothing.
				p.carriedList = append(p.carriedList, subtreeEntries(byPath, ce.Path)...)
				return
			}
		}
		p.writeOrder = append(p.writeOrder, root)
		for _, child := range p.childRoots(root) {
			visit(child)
		}
	}
	visit(p.src.Root())
	p.stats.CatalogsReused = len(p.carriedList)
	for i, j := 0, len(p.writeOrder)-1; i < j; i, j = i+1, j-1 {
		p.writeOrder[i], p.writeOrder[j] = p.writeOrder[j], p.writeOrder[i]
	}
}

// childRoots lists the catalog roots directly nested beneath root — the
// transition points its catalog records.
func (p *pipeline) childRoots(root uint64) []uint64 {
	var out []uint64
	var walk func(ino uint64)
	walk = func(ino uint64) {
		for _, e := range p.dirs[ino] {
			if e.typ != catalog.TypeDir {
				continue
			}
			if p.isCatRoot[e.inode] {
				out = append(out, e.inode)
				continue
			}
			walk(e.inode)
		}
	}
	walk(root)
	return out
}

// planContent marks the inodes whose content records this seal must
// derive: everything in a catalog it is rebuilding, plus every promoted
// inode (their records live in shards, which are rebuilt whole).
//
// A nil map means "everything", which is both the no-reuse answer and the
// cheap one — the common case where nothing is carried should not pay for
// a set the size of the tree.
func (p *pipeline) planContent() {
	if p.stats.CatalogsReused == 0 {
		return
	}
	need := make(map[uint64]bool)
	for _, root := range p.writeOrder {
		p.spanWalk(root, func(ino uint64) { need[ino] = true })
	}
	for _, ino := range p.promoted {
		need[ino] = true
	}
	p.needContent = need
}

// spanWalk visits every inode whose rows belong to the catalog rooted at
// root: its own subtree down to, but not through, the next catalog
// boundary. A boundary directory itself is visited — the parent carries
// its dirent and node row — but nothing below it is.
func (p *pipeline) spanWalk(root uint64, fn func(ino uint64)) {
	fn(root)
	var walk func(ino uint64)
	walk = func(ino uint64) {
		for _, e := range p.dirs[ino] {
			fn(e.inode)
			if e.typ == catalog.TypeDir && !p.isCatRoot[e.inode] {
				walk(e.inode)
			}
		}
	}
	walk(root)
}

// isDirty reports whether the source touched an inode since the base
// generation. With reuse disarmed everything counts as touched, which
// makes every downstream decision fall back to "rebuild it".
func (p *pipeline) isDirty(ino uint64) bool {
	if !p.reuseArmed {
		return true
	}
	_, dirty := p.dirty[ino]
	return dirty
}

// needsContent reports whether TRANSFORM must derive this inode's content
// records, i.e. whether anything this seal WRITES will hold them.
func (p *pipeline) needsContent(ino uint64) bool {
	if p.needContent == nil {
		return true
	}
	return p.needContent[ino]
}

// catalogList is the catalog tree recorded in the new superblock, for the
// next generation to reuse against: one entry per live catalog.
//
// A carried catalog contributes not only itself but every catalog beneath
// it (planReuse collected those), so the record stays complete even for
// the parts of the tree this publish never looked at.
func (p *pipeline) catalogList() []superblock.CatalogEntry {
	out := make([]superblock.CatalogEntry, 0, len(p.writeOrder)+len(p.carriedList))
	for _, root := range p.writeOrder {
		id := p.catIdentity[root]
		out = append(out, superblock.CatalogEntry{
			Inode:    root,
			Identity: [32]byte(id),
			Path:     p.pathOf[root],
			Weight:   p.catWeight[root],
			Promoted: uint32(p.catPromoted[root]),
		})
	}
	out = append(out, p.carriedList...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// subtreeEntries returns the entries of a path-sorted catalog list that
// lie at or below root. Paths are real namespace paths, so "the catalogs
// beneath this one" is exactly the prefix range.
func subtreeEntries(byPath []superblock.CatalogEntry, root string) []superblock.CatalogEntry {
	prefix := root
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	i := sort.Search(len(byPath), func(i int) bool { return byPath[i].Path >= root })
	var out []superblock.CatalogEntry
	for ; i < len(byPath); i++ {
		if byPath[i].Path != root && !strings.HasPrefix(byPath[i].Path, prefix) {
			break
		}
		out = append(out, byPath[i])
	}
	return out
}

// countPromoted records, per catalog this seal writes, how many promoted
// inodes its span holds. A later generation reads it to decide whether
// skipping the span would cost the shard rebuild a record it needs.
func (p *pipeline) countPromoted() {
	if len(p.promoted) == 0 {
		return
	}
	promoted := make(map[uint64]bool, len(p.promoted))
	for _, ino := range p.promoted {
		promoted[ino] = true
	}
	for _, root := range p.writeOrder {
		n := 0
		p.spanWalk(root, func(ino uint64) {
			if promoted[ino] {
				n++
			}
		})
		p.catPromoted[root] = n
	}
}
