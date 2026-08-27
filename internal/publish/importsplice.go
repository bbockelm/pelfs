package publish

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/inodemap"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Importing another pelfs volume: a Source that SPLICES a foreign
// volume's tree into the previous generation at one path, renumbered into
// inode lineages this volume owns, with the bytes already copied into
// this volume's packs.
//
// # Why this is a sibling of graftsplice.go and not a use of it
//
// The two answer the same question — "publish the previous generation
// with one subtree replaced" — and the SPINE half is the same problem, so
// the same helpers serve both (splitGraftPath, underPath, typeWord,
// sampleNames, srcNodeFromGenfs, genfsReader). What differs is the
// subtree, on three counts that go all the way down:
//
//   - THE SUBTREE IS A PUBLISHED GENERATION, not a spider result. Every
//     node comes out of a real catalog, so an import gets exact fidelity
//     where a graft gets 0444/0555 and no symlinks: modes, owners, times,
//     xattrs, symlink targets, device numbers and hardlinks all survive,
//     because they were all recorded on the other side.
//   - ROUTING IS BY LINEAGE, not by arithmetic. A graft splice numbers
//     the grafted tree above the base's allocator mark and routes an
//     inode by comparing against it. An import cannot: the source's
//     inodes are what they are, and they are renumbered into lineages
//     this volume does not use, so "is this one of mine" is a lineage
//     test (inodemap.Map.Holds) and cannot be fooled by a tree that grew.
//   - THE BYTES ARE OURS. A graft's ProvidedContent is EXTERNAL —
//     resolved through a GraftEntry, kept out of the dedup set, copied up
//     on the first write. An import's is not external in any sense: the
//     entries were copied into packs this generation lists, so the
//     identities belong in the dedup set, a write is an ordinary write,
//     and nothing in the tree resolves anywhere but here. That is the
//     whole point of importing.
//
// # Inode numbering
//
// The base keeps its numbers. The imported tree is renumbered by
// inodemap.Map into lineages drawn from the same allocator branches and
// tags draw from, so the two spaces are disjoint by construction. The
// directories on the destination path that this volume does not already
// have are the one exception: they are new inodes of THIS volume, drawn
// from its own allocator mark upward, because they are this volume's
// directories and not the source's.

// ImportPlacement is what the import path held before this publish, which
// decides what the publish is allowed to do to it. Every value is a
// DECISION that was made rather than a state that was observed: the
// refusals are errors, so a placement that reaches a caller is one the
// caller may act on.
//
// It is the graft collision matrix minus the two cases that cannot arise.
// There is no refresh, because an import has no live link to its source
// to refresh from — re-importing is an ordinary import of a newer
// generation. And there is no "an import is already here", because an
// import leaves no locator at the path: what it leaves is an ordinary
// directory of this volume's own, and a second import over it is a
// populated directory like any other.
type ImportPlacement uint8

const (
	// ImportPlaceNew: nothing was at the path. Directories on the way to
	// it that the volume did not have are created.
	ImportPlaceNew ImportPlacement = iota + 1
	// ImportPlaceEmptyDir: an EMPTY directory was at the path, and the
	// imported tree takes its place. Allowed without a flag because
	// nothing is lost.
	ImportPlaceEmptyDir
	// ImportPlaceReplacedDir: a POPULATED directory was at the path and
	// Replace was set, so its entries are dropped from the new
	// generation. This is the one placement that can cost somebody data.
	ImportPlaceReplacedDir
	// ImportPlaceReplacedFile: a file (or symlink, or device) was at the
	// path and Replace was set.
	ImportPlaceReplacedFile
)

func (p ImportPlacement) String() string {
	switch p {
	case ImportPlaceNew:
		return "new"
	case ImportPlaceEmptyDir:
		return "into an empty directory"
	case ImportPlaceReplacedDir:
		return "replacing a populated directory"
	case ImportPlaceReplacedFile:
		return "replacing a file"
	default:
		return "unknown"
	}
}

// The refusals. Each is a thing that could have been done silently and is
// not, and each message ends in what to do instead.
var (
	// ErrImportPathNotDir: a component of the destination path is not a
	// directory, so there is nowhere to put the tree.
	ErrImportPathNotDir = errors.New("import: a component of the destination path is not a directory")
	// ErrImportPathOccupied: something that is not a directory is at the
	// path.
	ErrImportPathOccupied = errors.New("import: something else is already at the destination path")
	// ErrImportPathNotEmpty: a POPULATED directory is at the path. THE
	// WORST OUTCOME AVAILABLE would be merging into it silently — an
	// import is a replacement, not a merge — so this is a refusal and
	// --replace is the way to ask for it on purpose.
	ErrImportPathNotEmpty = errors.New("import: a directory with contents is already at the destination path")
	// ErrImportIntoGraft: the path is INSIDE a grafted subtree.
	ErrImportIntoGraft = errors.New("import: the destination path is inside a grafted subtree")
	// ErrImportOverGraft: the path CONTAINS a graft, which the imported
	// tree would hide.
	ErrImportOverGraft = errors.New("import: the destination path contains a graft")
	// ErrImportRootPath: the volume root. An import at "/" is not a
	// splice, it is a replacement of the volume.
	ErrImportRootPath = errors.New("import: refusing to import at the volume root")
)

// ImportSpliceOptions configures one import splice.
type ImportSpliceOptions struct {
	// Base is the generation being built on, opened for reading, and Prev
	// its superblock. Base must be that same generation: publish's reuse
	// gates check it by root-catalog identity.
	Base *genfs.FS
	Prev *superblock.Superblock
	// Src is the SOURCE volume's generation, opened for reading. It is
	// held for the whole publish, because the namespace is read from it
	// as the seal descends — the copy moved the file BYTES, not the tree.
	// Nil for a preflight, which answers what would happen at the path
	// before a byte has been read.
	Src *genfs.FS
	// Map renumbers the source's inodes into lineages this volume owns.
	// Nil for a preflight.
	Map *inodemap.Map
	// SourceMark is the source generation's allocator high-water mark
	// (its NextInode), renumbered to become part of ours. It matters for
	// the reason InodeMarker exists: a number the source burned on a file
	// it deleted must stay burned, and a walk cannot see it.
	SourceMark uint64
	// Mount is the path in this volume the tree lands at.
	Mount string
	// Replace permits replacing a populated directory, or a file, at the
	// path. Without it both are refused.
	Replace bool
	// Packs are the packs the copy uploaded, and Entries reports which
	// identities each holds. Both are this generation's statement of
	// LOCATION for the imported content: the records name bytes no
	// previous superblock lists, so this generation must list them itself
	// or it is signed and unreadable.
	Packs   []packstore.SealedPack
	Entries func(fn func(identityHex, pack string))
	// TranslateKeyID maps a source chunkref's key id to this volume's id
	// for the same key (importvol.Custody.Translate). Nil is the
	// plaintext case, where every id is 0 and there is nothing to map.
	TranslateKeyID func(int64) (int64, error)
}

// ImportSpliceSource is the Source publish walks.
type ImportSpliceSource struct {
	base *genfs.FS
	prev *superblock.Superblock
	src  *genfs.FS
	m    *inodemap.Map
	o    ImportSpliceOptions

	mount string
	comps []string
	// baseIno[d] is the base generation's inode for the directory at
	// comps[:d], with baseIno[0] the volume root; 0 means the base does
	// not have that directory. spineIno[d] is the inode the SPLICED tree
	// publishes there. Both have len(comps)+1 entries; index len(comps)
	// is the imported root itself.
	baseIno  []uint64
	spineIno []uint64
	// depthOf places a spine inode, so Readdir can tell "a directory on
	// the destination path" from "an ordinary base directory".
	depthOf map[uint64]int
	// synth is the next inode to mint for a directory on the path this
	// volume does not have, and synthTop one past the last minted.
	synth, synthTop uint64
	// synthNode is what each minted directory publishes as.
	synthNode map[uint64]SrcNode

	placement       ImportPlacement
	replacedType    uint8
	replacedEntries int
	mountNode       SrcNode
	dirty           map[uint64]struct{}
}

var (
	_ Source          = (*ImportSpliceSource)(nil)
	_ ContentProvider = (*ImportSpliceSource)(nil)
	_ ContentReuser   = (*ImportSpliceSource)(nil)
	_ CatalogReuser   = (*ImportSpliceSource)(nil)
	_ InodeMarker     = (*ImportSpliceSource)(nil)
)

// ImportPlan is what a preflight found: what is at the path, and
// therefore what the publish would do to it.
type ImportPlan struct {
	Placement ImportPlacement
	// DisplacedType is the catalog type of what the import would take the
	// place of (0 for nothing), and DisplacedEntries how many entries it
	// held if it was a directory.
	DisplacedType    uint8
	DisplacedEntries int
	// SyntheticDirs are the directories on the path the volume does not
	// have and the publish would create.
	SyntheticDirs []string
}

// ImportPreflight answers "what would happen at this path" with no source
// read and no publish.
//
// IT EXISTS TO BE RUN BEFORE THE COPY, and then again after it. An import
// reads and writes every byte of the source once, which at TB scale is
// hours, and "there is a populated directory at that path" is news that
// must arrive in the first second rather than the last. It is cheap — one
// directory listing per component of the path — so paying for it twice is
// free, and the second run is not optional: the branch may have moved
// while the copy ran, and splicing against a generation nobody looked at
// would silently revert everything a mount checkpointed in between.
func ImportPreflight(ctx context.Context, o ImportSpliceOptions) (*ImportPlan, error) {
	s, err := newImportSplice(ctx, o)
	if err != nil {
		return nil, err
	}
	return &ImportPlan{
		Placement: s.placement, DisplacedType: s.replacedType,
		DisplacedEntries: s.replacedEntries, SyntheticDirs: s.SyntheticDirs(),
	}, nil
}

// NewImportSpliceSource runs the preflight and builds the source.
func NewImportSpliceSource(ctx context.Context, o ImportSpliceOptions) (*ImportSpliceSource, error) {
	if o.Src == nil || o.Map == nil {
		return nil, errors.New("import: publishing a splice needs the source generation and the " +
			"inode map that renumbers it")
	}
	return newImportSplice(ctx, o)
}

func newImportSplice(ctx context.Context, o ImportSpliceOptions) (*ImportSpliceSource, error) {
	if o.Base == nil || o.Prev == nil {
		return nil, errors.New("import: a splice needs the generation it is built on (Base and Prev)")
	}
	mount := path.Clean("/" + strings.Trim(o.Mount, "/"))
	if mount == "/" {
		return nil, fmt.Errorf("%w: an import at / would replace the whole volume rather than "+
			"splice into it, and the two roots would have to become one inode. Name a "+
			"subdirectory — `pelfs import <volume> /where <source>` — and `pelfs branch` or a "+
			"fresh `pelfs init` if what you want is a copy of the volume", ErrImportRootPath)
	}
	s := &ImportSpliceSource{
		base: o.Base, prev: o.Prev, src: o.Src, m: o.Map, o: o,
		mount: mount, comps: splitGraftPath(mount),
		depthOf:   map[uint64]int{},
		synthNode: map[uint64]SrcNode{},
		dirty:     map[uint64]struct{}{},
	}
	// Directories on the path this volume does not have are THIS
	// volume's, not the source's, so they are numbered from this volume's
	// own allocator mark. The imported tree never lands in this range —
	// it lands in lineages this volume does not allocate from — so the
	// two cannot meet.
	s.synth = o.Prev.NextInode
	if s.synth < genfs.RootInode+1 {
		s.synth = genfs.RootInode + 1
	}
	s.synthTop = s.synth
	if err := s.checkGrafts(); err != nil {
		return nil, err
	}
	if err := s.descend(ctx); err != nil {
		return nil, err
	}
	if err := s.classify(ctx, o); err != nil {
		return nil, err
	}
	if err := s.wireSpine(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// checkGrafts settles the two ways an import path can collide with a
// graft this volume already serves, and BOTH ARE REFUSED BY NAME. The
// arguments are the graft design's own, applied in the other direction.
func (s *ImportSpliceSource) checkGrafts() error {
	for _, g := range s.prev.Grafts {
		switch {
		case g.Path == s.mount || underPath(s.mount, g.Path):
			return fmt.Errorf("%w: %s is at or inside the graft at %s (from %s). The graft's next "+
				"--refresh rebuilds that subtree from its source, and the imported tree would "+
				"simply stop being in the namespace. Import somewhere outside %s, or "+
				"`pelfs graft --remove <volume> %s` first",
				ErrImportIntoGraft, s.mount, g.Path, g.Source, g.Path, g.Path)
		case underPath(g.Path, s.mount):
			return fmt.Errorf("%w: the graft at %s (from %s) is under %s, and the imported tree "+
				"would cover it — its files would leave the namespace while the volume went on "+
				"naming that source. `pelfs graft --remove <volume> %s` first, or import at a path "+
				"that does not contain it", ErrImportOverGraft, g.Path, g.Source, s.mount, g.Path)
		}
	}
	return nil
}

// descend resolves the destination path against the base generation, one
// component at a time, establishing residency on the way down.
func (s *ImportSpliceSource) descend(ctx context.Context) error {
	s.baseIno = make([]uint64, len(s.comps)+1)
	s.baseIno[0] = genfs.RootInode
	for d, comp := range s.comps {
		parent := s.baseIno[d]
		if parent == 0 {
			// The base diverged higher up; everything below is new.
			break
		}
		ents, err := s.entries(ctx, parent)
		if err != nil {
			return err
		}
		e, ok := ents[comp]
		if !ok {
			break
		}
		if d+1 < len(s.comps) && e.Node.Type != catalog.TypeDir {
			here := "/" + strings.Join(s.comps[:d+1], "/")
			return fmt.Errorf("%w: %s is a %s, and %s would have to be inside it. Import somewhere "+
				"else, or remove %s first", ErrImportPathNotDir, here, typeWord(e.Node.Type),
				s.mount, here)
		}
		s.baseIno[d+1] = e.Node.Inode
	}
	return nil
}

// classify decides what happens at the path, and is where every refusal
// in the collision matrix is made.
func (s *ImportSpliceSource) classify(ctx context.Context, o ImportSpliceOptions) error {
	target := s.baseIno[len(s.comps)]
	if target == 0 {
		s.placement = ImportPlaceNew
		return nil
	}
	n, err := s.base.GetAttr(ctx, target)
	if err != nil {
		return fmt.Errorf("import: read %s from the previous generation: %w", s.mount, err)
	}
	if n.Type != catalog.TypeDir {
		if !o.Replace {
			return fmt.Errorf("%w: %s is a %s (%d bytes). An imported tree needs a directory of its "+
				"own: remove it, import somewhere else, or pass --replace to drop it from the next "+
				"generation", ErrImportPathOccupied, s.mount, typeWord(n.Type), n.Length)
		}
		s.placement, s.replacedType = ImportPlaceReplacedFile, n.Type
		return nil
	}
	ents, err := s.entries(ctx, target)
	if err != nil {
		return err
	}
	s.replacedType, s.replacedEntries = catalog.TypeDir, len(ents)
	if len(ents) == 0 {
		// Nothing is lost, so nothing is asked. An empty directory at the
		// path is the shape a user who prepared a mount point leaves
		// behind, and refusing it would be pedantry.
		s.placement = ImportPlaceEmptyDir
		return nil
	}
	if !o.Replace {
		return fmt.Errorf("%w: %s holds %d entries (%s). An import REPLACES the directory it lands "+
			"on rather than merging into it — the two trees have different inode numbering and "+
			"there is no rule that could merge them — so this would drop them from the next "+
			"generation. Import at a path of its own, or pass --replace to drop them on purpose",
			ErrImportPathNotEmpty, s.mount, len(ents), sampleNames(ents))
	}
	s.placement = ImportPlaceReplacedDir
	return nil
}

// wireSpine settles which inode the spliced tree publishes at each depth
// of the path.
//
// The base's inode wins wherever the base has the directory, and that is
// the whole of why an existing volume survives an import: a directory
// that keeps its inode keeps its attributes, its other entries, its
// xattrs, and its place in every catalog that names it.
func (s *ImportSpliceSource) wireSpine(ctx context.Context) error {
	s.spineIno = make([]uint64, len(s.comps)+1)
	for d := range s.comps {
		if s.baseIno[d] != 0 {
			s.spineIno[d] = s.baseIno[d]
		} else {
			s.spineIno[d] = s.mintDir()
		}
		s.depthOf[s.spineIno[d]] = d
		s.dirty[s.spineIno[d]] = struct{}{}
	}
	if s.src == nil {
		// A preflight, which is never walked.
		return nil
	}
	root, err := s.src.GetAttr(ctx, genfs.RootInode)
	if err != nil {
		return fmt.Errorf("import: read the source root: %w", err)
	}
	// The SOURCE ROOT becomes the directory at the destination path, with
	// its own mode, owner, times and xattrs — which is the fidelity an
	// import buys and a graft cannot.
	//
	// Its inode is inode 1 renumbered, and that number is one no
	// allocator will ever hand out: every lineage begins allocating at
	// FirstInode(l) == l<<shift + 2, so the +1 slot is reserved for the
	// root in every lineage's numbering and is free by construction.
	ino, err := s.m.Remap(genfs.RootInode)
	if err != nil {
		return fmt.Errorf("import: renumber the source root: %w", err)
	}
	s.spineIno[len(s.comps)] = ino
	s.mountNode = srcNodeFromGenfs(root)
	s.mountNode.Inode = ino
	s.dirty[ino] = struct{}{}
	if old := s.baseIno[len(s.comps)]; old != 0 {
		// The inode that was displaced is a change too, and saying so
		// keeps "what this publish touched" honest.
		s.dirty[old] = struct{}{}
	}
	return nil
}

// mintDir allocates one of this volume's own inodes for a directory on
// the destination path that the volume does not have.
func (s *ImportSpliceSource) mintDir() uint64 {
	ino := s.synthTop
	s.synthTop++
	return ino
}

// ---- reporting ----

// Placement is what happened at the path.
func (s *ImportSpliceSource) Placement() ImportPlacement { return s.placement }

// Displaced describes what the import took the place of.
func (s *ImportSpliceSource) Displaced() (typ uint8, entries int) {
	return s.replacedType, s.replacedEntries
}

// Mount is the path the tree lands at.
func (s *ImportSpliceSource) Mount() string { return s.mount }

// SyntheticDirs are the directories on the path the volume did not have
// and this publish creates. A user who mistyped a path is told this
// rather than discovering three empty directories later.
func (s *ImportSpliceSource) SyntheticDirs() []string {
	var out []string
	for d := 1; d < len(s.comps); d++ {
		if s.baseIno[d] == 0 {
			out = append(out, "/"+strings.Join(s.comps[:d], "/"))
		}
	}
	return out
}

// ---- Source ----

func (s *ImportSpliceSource) Root() uint64 { return genfs.RootInode }

// NextInode is the BASE's counter. The imported numbers are stated
// authoritatively by InodeMark instead, for the reason InodeMarker
// documents: a tree that contains inodes the source did not allocate
// cannot have its allocator inferred from what the tree happens to hold.
func (s *ImportSpliceSource) NextInode() uint64 { return s.prev.NextInode }

// InodeMark is the high-water mark this generation records, and it has to
// cover THREE allocators at once — which is the whole reason
// InodeMarker exists.
//
//   - This volume's own, which the directories minted on the destination
//     path advanced.
//   - The imported lineages', which are the source's own mark renumbered.
//     Taking max-inode-seen instead would put the mark BELOW numbers the
//     source has already burned, and the next import from the same source
//     would then hand out a number that source already used for a
//     different file.
//   - The previous generation's, which publish floors against anyway
//     because a branch may never reuse a number it has handed out.
//
// The mark is a single number and the lineages are disjoint slices of one
// space, so the largest of the three is the answer: it is above every
// number in every slice this generation used.
func (s *ImportSpliceSource) InodeMark() uint64 {
	mark := s.prev.NextInode
	if s.synthTop > mark {
		mark = s.synthTop
	}
	if s.m != nil && s.o.SourceMark != 0 {
		if m, err := s.m.MarkAbove(s.o.SourceMark); err == nil && m > mark {
			mark = m
		}
	}
	return mark
}

// imported reports whether an inode belongs to the spliced subtree. It is
// a LINEAGE test rather than an arithmetic one: the map's destination
// lineages are drawn from lineages this volume does not use, so the two
// spaces are disjoint by construction and this cannot be fooled by a tree
// that grew past a threshold.
func (s *ImportSpliceSource) imported(ino uint64) bool {
	return s.m != nil && s.m.Holds(ino)
}

func (s *ImportSpliceSource) Readdir(ctx context.Context, ino uint64) ([]SrcEntry, error) {
	if s.imported(ino) {
		return s.importedReaddir(ctx, ino)
	}
	d, onSpine := s.depthOf[ino]
	base := ino
	if onSpine {
		base = s.baseIno[d]
	}
	var out []SrcEntry
	if base != 0 {
		ents, err := s.entries(ctx, base)
		if err != nil {
			return nil, err
		}
		names := make([]string, 0, len(ents))
		for name := range ents {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if onSpine && name == s.comps[d] && (d+1 == len(s.comps) || s.baseIno[d+1] == 0) {
				// The one entry the splice owns: the imported root, or a
				// path component the base does not have under this name
				// as a directory. Dropped here and re-stated below.
				continue
			}
			// EVERY OTHER ENTRY IS THE BASE'S OWN, INCLUDING A SPINE
			// DIRECTORY THE VOLUME ALREADY HAS, and it is passed through
			// untouched rather than re-described. That is load-bearing:
			// publish records an inode's attributes from the LISTING that
			// named it, so a directory re-stated here from its inode and
			// type alone would be published with mode 0.
			out = append(out, SrcEntry{Name: name, Node: srcNodeFromGenfs(ents[name].Node)})
		}
	}
	if onSpine && s.spineNeedsStating(d) {
		out = append(out, SrcEntry{Name: s.comps[d], Node: s.spineNode(d + 1)})
	}
	return out, nil
}

// importedReaddir lists one directory of the SOURCE, with every child's
// inode renumbered.
//
// ReaddirRetain rather than Readdir, for the same reason the graft splice
// gives: a genfs inode that was merely LISTED is not operable, and the
// seal is about to Stat and read every one of these.
func (s *ImportSpliceSource) importedReaddir(ctx context.Context, ino uint64) ([]SrcEntry, error) {
	sino, err := s.m.Unmap(ino)
	if err != nil {
		return nil, err
	}
	des, err := s.src.ReaddirRetain(ctx, sino)
	if err != nil {
		return nil, fmt.Errorf("import: read source directory %d: %w", sino, err)
	}
	out := make([]SrcEntry, 0, len(des))
	for _, de := range des {
		n := srcNodeFromGenfs(de.Node)
		// THE GUARD, and it fails closed. An inode in a lineage the map
		// does not declare means the source gained a lineage since the
		// scan — a merge landed there while the copy ran, most plausibly.
		// Passing it through untranslated would alias it onto a number
		// this volume may already have handed out, silently, in a
		// generation that signs and mounts.
		n.Inode, err = s.m.Remap(de.Node.Inode)
		if err != nil {
			return nil, fmt.Errorf("import: %w", err)
		}
		out = append(out, SrcEntry{Name: de.Name, Node: n})
	}
	return out, nil
}

// spineNeedsStating reports whether the entry for depth d+1 has to be
// synthesized here rather than passed through from the base.
func (s *ImportSpliceSource) spineNeedsStating(d int) bool {
	if s.spineIno[d+1] == 0 {
		return false
	}
	return d+1 == len(s.comps) || s.baseIno[d+1] == 0
}

// spineNode is the node published for a directory the splice itself
// states: the imported root at the end of the path, or a directory on the
// way to it that the volume does not have.
func (s *ImportSpliceSource) spineNode(d int) SrcNode {
	if d == len(s.comps) {
		return s.mountNode
	}
	ino := s.spineIno[d]
	if n, ok := s.synthNode[ino]; ok {
		return n
	}
	// A directory this volume did not have, created for the path. Its
	// ownership is the imported root's, because the person who will own
	// what is inside it is the only sensible owner of the shell around
	// it, and 0755 because it is an ordinary directory of this volume —
	// nothing about it is read-only the way a graft's synthesized
	// directories are.
	n := SrcNode{
		Inode: ino, Type: catalog.TypeDir, Mode: 0755,
		UID: s.mountNode.UID, GID: s.mountNode.GID, Nlink: 2,
	}
	s.synthNode[ino] = n
	return n
}

func (s *ImportSpliceSource) Stat(ctx context.Context, ino uint64) (SrcNode, error) {
	if s.imported(ino) {
		sino, err := s.m.Unmap(ino)
		if err != nil {
			return SrcNode{}, err
		}
		n, err := s.src.GetAttr(ctx, sino)
		if err != nil {
			return SrcNode{}, fmt.Errorf("import: stat source inode %d: %w", sino, err)
		}
		out := srcNodeFromGenfs(n)
		out.Inode = ino
		return out, nil
	}
	if n, ok := s.synthNode[ino]; ok {
		return n, nil
	}
	n, err := s.base.GetAttr(ctx, ino)
	if err != nil {
		return SrcNode{}, fmt.Errorf("import: stat inode %d in the previous generation: %w", ino, err)
	}
	return srcNodeFromGenfs(n), nil
}

func (s *ImportSpliceSource) Readlink(ctx context.Context, ino uint64) (string, error) {
	if s.imported(ino) {
		sino, err := s.m.Unmap(ino)
		if err != nil {
			return "", err
		}
		return s.src.Readlink(ctx, sino)
	}
	return s.base.Readlink(ctx, ino)
}

func (s *ImportSpliceSource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	fs, target := s.base, ino
	if s.imported(ino) {
		sino, err := s.m.Unmap(ino)
		if err != nil {
			return nil, err
		}
		fs, target = s.src, sino
	} else if _, synthetic := s.synthNode[ino]; synthetic {
		return nil, nil
	}
	names, err := fs.ListXattr(ctx, target)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		v, err := fs.GetXattr(ctx, target, name)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// Open is the fallback path and should rarely run: an imported file
// answers through ProvidedContent and a base file through
// ExistingContent. It runs when the INLINE THRESHOLD differs between the
// two volumes — a file the source stored inline that this volume would
// chunk, or the reverse — and then the bytes have to be read to be
// re-derived. It reads them from the source generation, which is the only
// place they are in a shape anyone can read.
func (s *ImportSpliceSource) Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	if s.imported(ino) {
		sino, err := s.m.Unmap(ino)
		if err != nil {
			return nil, err
		}
		return &genfsReader{ctx: ctx, fs: s.src, ino: sino, length: length}, nil
	}
	return &genfsReader{ctx: ctx, fs: s.base, ino: ino, length: length}, nil
}

// ---- ContentProvider: the imported half ----

// ProvidedContent hands publish the records the SOURCE generation
// published, with the bytes they name now sitting in packs this
// generation lists.
//
// External is NOT set, and that is the whole difference from a graft.
// These identities belong in the dedup set — the invariant is "a pack
// this generation lists holds these bytes", and after the copy that is
// exactly true — and a later write to an imported file is an ordinary
// write rather than a copy-up, because there is nothing foreign left to
// copy up from.
func (s *ImportSpliceSource) ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if !s.imported(ino) {
		return genfs.Content{}, false, nil
	}
	sino, err := s.m.Unmap(ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	c, err := s.src.ContentOf(ctx, sino)
	if err != nil {
		return genfs.Content{}, false, fmt.Errorf("import: read the content records of source "+
			"inode %d: %w", sino, err)
	}
	if c.External {
		// The scan refuses a grafted source up front; this is the same
		// refusal at the one moment a record could still slip past it.
		return genfs.Content{}, false, fmt.Errorf("import: source inode %d resolves through a "+
			"graft, so its bytes were never in a pack and nothing was copied for it", sino)
	}
	if s.o.TranslateKeyID != nil && c.Refs != nil {
		refs := make([]catalog.ChunkRef, len(c.Refs))
		copy(refs, c.Refs)
		for i := range refs {
			id, err := s.o.TranslateKeyID(refs[i].KeyID)
			if err != nil {
				return genfs.Content{}, false, fmt.Errorf("import: source inode %d: %w", sino, err)
			}
			refs[i].KeyID = id
		}
		c.Refs = refs
	}
	c.External = false
	return c, true, nil
}

// ProvidedPacks are the packs the copy uploaded. This is the generation's
// statement of LOCATION for every imported byte: the records name packs
// no previous superblock lists, so this one must list them or it is
// signed and unreadable.
func (s *ImportSpliceSource) ProvidedPacks(context.Context) ([]packstore.SealedPack, error) {
	return s.o.Packs, nil
}

// ProvidedEntries feeds the generation's multi-pack index. Without it the
// index covers only what the SEAL packed, which for an import is almost
// nothing — leaving every read of an imported file to fall back to
// per-pack trailers, which is exactly the lookup the index exists to
// answer.
func (s *ImportSpliceSource) ProvidedEntries(fn func(identityHex, pack string)) {
	if s.o.Entries != nil {
		s.o.Entries(fn)
	}
}

// ---- ContentReuser: the base half ----

func (s *ImportSpliceSource) BaseGeneration() [32]byte { return s.prev.RootCatalog }

// ExistingContent hands publish the records the previous generation
// published for a base file, so no byte of THIS volume is re-read while
// the imported tree is spliced in.
func (s *ImportSpliceSource) ExistingContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if s.imported(ino) {
		return genfs.Content{}, false, nil
	}
	if _, synthetic := s.synthNode[ino]; synthetic {
		return genfs.Content{}, false, nil
	}
	c, err := s.base.ContentOf(ctx, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return c, true, nil
}

// ---- CatalogReuser: what changed ----

// DirtyInodes is the SPINE and the imported root, and nothing else, which
// is the claim that makes this cheap.
//
// Completeness is the safety property, so it is worth stating why the
// imported subtree's own inodes are not listed: they are in lineages this
// volume has never allocated from, so no entry in the previous
// generation's catalog list can be keyed by one of them, and the
// carry-forward test needs both a matching inode AND a matching path. An
// imported inode therefore cannot be mistaken for an unchanged one.
func (s *ImportSpliceSource) DirtyInodes() (map[uint64]struct{}, error) {
	out := make(map[uint64]struct{}, len(s.dirty))
	for ino := range s.dirty {
		out[ino] = struct{}{}
	}
	return out, nil
}

// DirtyScope is the same set: every inode on the spine, and every
// ancestor of one, is on the spine. The walk therefore stops at every
// catalog root outside the path — an import into a 10M-inode volume never
// reads the 10M inodes.
func (s *ImportSpliceSource) DirtyScope() (map[uint64]struct{}, bool, error) {
	out, err := s.DirtyInodes()
	return out, true, err
}

// ---- helpers ----

func (s *ImportSpliceSource) entries(ctx context.Context, ino uint64) (map[string]genfs.DirEntry, error) {
	des, err := s.base.ReaddirRetain(ctx, ino)
	if err != nil {
		return nil, fmt.Errorf("import: read directory %d of the previous generation: %w", ino, err)
	}
	out := make(map[string]genfs.DirEntry, len(des))
	for _, de := range des {
		out[de.Name] = de
	}
	return out, nil
}
