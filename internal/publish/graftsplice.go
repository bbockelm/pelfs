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
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Grafting into a POPULATED volume: a Source that SPLICES a spidered tree
// into the previous generation's tree at one path, and leaves everything
// else exactly as that generation published it.
//
// # Why this file exists at all
//
// GraftSource publishes a graft tree over an EMPTY root, which makes
// `pelfs graft` an `init`-then-`graft` operation and not the thing anybody
// wants. Someone with a volume wants a foreign tree spliced in at a path
// and everything else kept. That is the job merge's mergeSource does over
// two generations, and this is the same shape with a narrower question:
// one side is the previous generation, the other is a subtree, and they
// meet at exactly one place.
//
// # What is held, and what is not
//
// PROPORTIONAL TO THE PATH, not to the volume. The splice knows the
// directories on the mount path (its "spine"), and nothing else about the
// base: every other directory is read from the base generation as publish
// descends into it, and every unchanged catalog is carried forward by
// reference rather than rebuilt. A graft into a 10M-inode volume rewrites
// the catalogs from the graft to the root and nothing else — the git
// property CatalogReuser exists for.
//
// The three capabilities that make that true, and which half each answers:
//
//   - ContentReuser answers for BASE files: their chunkrefs are the ones
//     the previous generation published, in packs buildSuperblock carries
//     forward verbatim. No byte of the volume is re-read or re-chunked.
//   - ContentProvider answers for GRAFTED files: external chunkrefs
//     located by the GraftEntry rather than by a pack, exactly as
//     GraftSource does for a fresh volume.
//   - CatalogReuser says what changed — the spine, and the graft — so the
//     walk stops at every subtree it does not need to look at.
//
// # Inode numbering
//
// The base keeps its numbers. The grafted tree is numbered from the base
// generation's allocator mark upward, so the two ranges are disjoint by
// construction and no lookup is needed to route an inode to its side:
// anything at or above the mark is grafted.
//
// The cost of that simplicity is that a REFRESH renumbers the grafted
// subtree, since the mark has moved on. That is correct but not free —
// every catalog under the graft rebuilds even where nothing changed, and
// the allocator advances by the size of the graft each time. Preserving
// the numbers would mean walking the old subtree to recover its
// path→inode map; it is a real improvement and it is on the ranked work
// list in docs/design-graft.md rather than smuggled in here.

// GraftPlacement is what the graft path held before this publish, which
// decides what the publish is allowed to do to it. Every value is a
// DECISION that was made rather than a state that was observed: the
// refusals are errors (below), so a placement that reaches a caller is
// one the caller may act on.
type GraftPlacement uint8

const (
	// GraftPlaceNew: nothing was at the path. Directories on the way to
	// it that the volume did not have are synthesized.
	GraftPlaceNew GraftPlacement = iota + 1
	// GraftPlaceEmptyDir: an EMPTY directory was at the path, and the
	// graft takes its place. Allowed without a flag because nothing is
	// lost: an empty directory has no contents to replace.
	GraftPlaceEmptyDir
	// GraftPlaceReplacedDir: a POPULATED directory was at the path and
	// Replace was set, so its entries are dropped from the new
	// generation. This is the one placement that can cost somebody data,
	// which is why it cannot happen without being asked for.
	GraftPlaceReplacedDir
	// GraftPlaceReplacedFile: a file (or symlink, or device) was at the
	// path and Replace was set.
	GraftPlaceReplacedFile
	// GraftPlaceRefresh: a graft from the SAME source was already at the
	// path and Refresh was set. Re-grafting the same source is a refresh
	// and nothing else, so this is the only placement that reaches here
	// with an identical source.
	GraftPlaceRefresh
	// GraftPlaceReplacedGraft: a graft from a DIFFERENT source was at the
	// path. Allowed, because a graft's bytes were never in this volume
	// and nothing local is lost — but never quietly: the caller is
	// expected to say which source is being replaced by which.
	GraftPlaceReplacedGraft
	// GraftPlaceRemoved: the graft at the path is being removed and
	// nothing put in its place (`pelfs graft --remove`).
	GraftPlaceRemoved
)

func (p GraftPlacement) String() string {
	switch p {
	case GraftPlaceNew:
		return "new"
	case GraftPlaceEmptyDir:
		return "into an empty directory"
	case GraftPlaceReplacedDir:
		return "replacing a populated directory"
	case GraftPlaceReplacedFile:
		return "replacing a file"
	case GraftPlaceRefresh:
		return "refreshing the graft already there"
	case GraftPlaceReplacedGraft:
		return "replacing a graft from another source"
	case GraftPlaceRemoved:
		return "removing the graft"
	default:
		return "unknown"
	}
}

// The refusals. Each one is a thing that could have been done silently and
// is not, and each message has to end in what to do instead — a refusal
// that leaves somebody guessing is worse than the operation it prevented.
var (
	// ErrGraftPathNotDir: a component of the graft path is not a
	// directory in the volume, so there is nowhere to put the tree.
	ErrGraftPathNotDir = errors.New("graft: a component of the graft path is not a directory")
	// ErrGraftPathOccupied: something that is not a directory is at the
	// path.
	ErrGraftPathOccupied = errors.New("graft: something else is already at the graft path")
	// ErrGraftPathNotEmpty: a POPULATED directory is at the path. THE
	// WORST OUTCOME AVAILABLE would be replacing it silently, so this is
	// a refusal and --replace is the way to ask for it on purpose.
	ErrGraftPathNotEmpty = errors.New("graft: a directory with contents is already at the graft path")
	// ErrGraftSameSource: a graft from the same source is already at the
	// path, so this is a refresh whether or not it was called one.
	ErrGraftSameSource = errors.New("graft: this source is already grafted at this path")
	// ErrGraftNested: the path is INSIDE an existing graft.
	ErrGraftNested = errors.New("graft: the path is inside a grafted subtree")
	// ErrGraftSwallows: the path CONTAINS an existing graft, which the
	// new tree would hide.
	ErrGraftSwallows = errors.New("graft: the path contains another graft")
	// ErrGraftNotThere: --refresh or --remove named a path this
	// generation serves no graft at.
	ErrGraftNotThere = errors.New("graft: this generation serves no graft at that path")
	// ErrGraftRootPath: the volume root. Refused for the same reason
	// GraftSource refuses it: a graft at "/" is not a splice, it is a
	// replacement of the volume.
	ErrGraftRootPath = errors.New("graft: refusing to graft at the volume root")
)

// GraftSpliceOptions configures one splice.
type GraftSpliceOptions struct {
	// Base is the generation being built on, opened for reading. It must
	// be the same generation as Prev — publish's reuse gates check that
	// by root-catalog identity, and a mismatch silently disarms every
	// reuse rather than being wrong, but the splice would still be
	// describing a tree nobody asked for.
	Base *genfs.FS
	// Prev is that generation's superblock: the allocator mark the
	// grafted inodes are numbered above, and the graft list the nesting
	// checks are made against.
	Prev *superblock.Superblock
	// Graft is the spidered subtree. It is nil for a Remove, and nil for
	// a PREFLIGHT — GraftPreflight answers "what would happen at this
	// path" before a byte of the source has been read, which is the whole
	// reason the check is separable from the publish.
	Graft *GraftSource
	// Remove states the intent to drop the graft at Mount and put nothing
	// in its place. It is a field rather than "Graft is nil" so that a
	// preflight and a removal cannot be confused for each other.
	Remove bool
	// Source is the prefix the tree is (or would be) spidered from,
	// required unless Remove. It is what makes "the same source is already
	// grafted here" answerable, which is the difference between a refresh
	// and a replace.
	Source string
	// Mount is the path, required when Graft is nil and otherwise taken
	// from the graft itself.
	Mount string
	// Replace permits replacing a populated directory, or a file, at the
	// path. Without it both are refused.
	Replace bool
	// Refresh says the caller means to re-graft the same source at the
	// path. Without it that is refused, because "graft again" and
	// "refresh" are different intentions and only one of them re-reads
	// a source.
	Refresh bool
}

// GraftSpliceSource is the Source that publish walks.
type GraftSpliceSource struct {
	base *genfs.FS
	prev *superblock.Superblock
	g    *GraftSource
	// source is the prefix g was spidered from.
	source string
	// remove is set when the publish drops the graft at the path.
	remove bool
	// shift maps a graft-source inode to the inode it is published under:
	// published = graft + shift. Zero when there is no graft (a removal).
	shift uint64
	// mount is the cleaned path, comps its components.
	mount string
	comps []string
	// baseIno[d] is the base generation's inode for the directory at
	// comps[:d], with baseIno[0] the volume root; 0 means the base does
	// not have that directory. spineIno[d] is the inode the SPLICED tree
	// publishes there — the base's where it has one, a synthesized one
	// where it does not. Both have len(comps)+1 entries; index len(comps)
	// is the graft root itself, and is 0 for a removal.
	baseIno  []uint64
	spineIno []uint64
	// depthOf places a spine inode, so Readdir can tell "a directory on
	// the graft path" from "an ordinary base directory".
	depthOf map[uint64]int

	placement GraftPlacement
	// prior is the graft entry that was at the path, if any.
	prior *superblock.GraftEntry
	// replaced describes what was displaced, for the caller to report.
	replacedType    uint8
	replacedEntries int
	// mountNode is the node published at the graft path.
	mountNode SrcNode
	dirty     map[uint64]struct{}
}

var (
	_ Source          = (*GraftSpliceSource)(nil)
	_ ContentProvider = (*GraftSpliceSource)(nil)
	_ ContentReuser   = (*GraftSpliceSource)(nil)
	_ CatalogReuser   = (*GraftSpliceSource)(nil)
	_ InodeMarker     = (*GraftSpliceSource)(nil)
)

// NewGraftSpliceSource runs the PREFLIGHT and builds the source.
//
// The preflight is separate from the publish on purpose and is meant to be
// run twice: once before the spider, so that "there is a file at that
// path" arrives in a second rather than after hours of reading somebody
// else's storage, and once after it against the head as it is then, so a
// branch that moved in between is not spliced against a tree nobody looked
// at. It is cheap — one listing per component of the path — so paying for
// it twice is free.
func NewGraftSpliceSource(ctx context.Context, o GraftSpliceOptions) (*GraftSpliceSource, error) {
	if (o.Graft == nil) != o.Remove {
		return nil, errors.New("graft: publishing a splice needs either a spidered tree or " +
			"Remove, and exactly one of them")
	}
	return newSplice(ctx, o)
}

// GraftPlan is what a preflight found: what is at the path, and therefore
// what the publish would do to it.
type GraftPlan struct {
	Placement GraftPlacement
	// Prior is the graft that is already at the path, or nil.
	Prior *superblock.GraftEntry
	// DisplacedType is the catalog type of what the graft would take the
	// place of (0 for nothing), and DisplacedEntries how many entries it
	// held if it was a directory.
	DisplacedType    uint8
	DisplacedEntries int
	// SyntheticDirs are the directories on the path the volume does not
	// have and the publish would create.
	SyntheticDirs []string
}

// GraftPreflight answers "what would happen at this path" against a
// generation, with no spider result and no publish.
//
// It exists to be run BEFORE the walk. A graft reads every byte of the
// source once, which at TB scale is hours, and "there is a populated
// directory at that path" is news that must arrive in the first second
// rather than the last. It is cheap — one directory listing per component
// of the path — so `pelfs graft` runs it twice: once up front, and once
// against the head as it stands after the walk, since a branch that moved
// in between would otherwise be spliced against a tree nobody looked at.
func GraftPreflight(ctx context.Context, o GraftSpliceOptions) (*GraftPlan, error) {
	s, err := newSplice(ctx, o)
	if err != nil {
		return nil, err
	}
	typ, ents := s.Displaced()
	return &GraftPlan{
		Placement: s.Placement(), Prior: s.Prior(),
		DisplacedType: typ, DisplacedEntries: ents,
		SyntheticDirs: s.SyntheticDirs(),
	}, nil
}

func newSplice(ctx context.Context, o GraftSpliceOptions) (*GraftSpliceSource, error) {
	if o.Base == nil || o.Prev == nil {
		return nil, errors.New("graft: a splice needs the generation it is built on (Base and Prev)")
	}
	if !o.Remove && o.Source == "" {
		return nil, errors.New("graft: a splice needs the source the tree was spidered from, or it " +
			"cannot tell a refresh of the same source from a replacement by another")
	}
	mount := o.Mount
	if o.Graft != nil {
		mount = o.Graft.Mount()
	}
	mount = path.Clean("/" + strings.Trim(mount, "/"))
	if mount == "/" {
		return nil, fmt.Errorf("%w; name a subdirectory (`pelfs graft %s /where <source>`)",
			ErrGraftRootPath, "<volume>")
	}
	s := &GraftSpliceSource{
		base: o.Base, prev: o.Prev, g: o.Graft, source: o.Source, remove: o.Remove,
		mount: mount, comps: splitGraftPath(mount),
		depthOf: map[uint64]int{},
		dirty:   map[uint64]struct{}{},
	}
	if o.Graft != nil {
		// The base's allocator mark is the floor: publish will not lower
		// it, and numbering from it keeps the two inode ranges disjoint
		// so that routing an inode to its side is arithmetic and not a
		// lookup. GraftSource numbers from 1.
		mark := o.Prev.NextInode
		if mark < genfs.RootInode+1 {
			mark = genfs.RootInode + 1
		}
		s.shift = mark - 1
	}
	if err := s.checkNesting(); err != nil {
		return nil, err
	}
	if err := s.descend(ctx); err != nil {
		return nil, err
	}
	if err := s.classify(ctx, o); err != nil {
		return nil, err
	}
	s.wireSpine()
	return s, nil
}

// checkNesting settles the two ways a graft path can collide with a graft
// that is already there, and BOTH ARE REFUSED BY NAME.
//
//   - INSIDE an existing graft. The directory that would hold it is
//     synthesized from the outer graft's spider result, so the outer
//     graft's next `--refresh` rebuilds that subtree from the source and
//     the inner graft simply stops being in the namespace — a signed
//     generation quietly missing a tree somebody grafted. There is no
//     mechanism here that could keep it, so it is refused rather than
//     half-supported.
//   - CONTAINING an existing graft. The new tree covers the inner
//     graft's mount point, so the inner graft's files leave the
//     namespace while its GraftEntry stays in the superblock: a volume
//     that names a third party it no longer reads. Remove the inner
//     graft first and the outer one is an ordinary graft.
func (s *GraftSpliceSource) checkNesting() error {
	for i := range s.prev.Grafts {
		g := s.prev.Grafts[i]
		switch {
		case g.Path == s.mount:
			s.prior = &s.prev.Grafts[i]
		case underPath(s.mount, g.Path):
			return fmt.Errorf("%w: %s is inside the graft at %s (from %s). A graft inside a graft "+
				"cannot survive the outer graft's next --refresh, which rebuilds that subtree from "+
				"its source. Graft it at a path outside %s, or `pelfs graft --remove <volume> %s` first",
				ErrGraftNested, s.mount, g.Path, g.Source, g.Path, g.Path)
		case underPath(g.Path, s.mount):
			return fmt.Errorf("%w: the graft at %s (from %s) is under %s, and the new tree would cover "+
				"it — its files would leave the namespace while the volume went on naming that source. "+
				"`pelfs graft --remove <volume> %s` first, or graft at a path that does not contain it",
				ErrGraftSwallows, g.Path, g.Source, s.mount, g.Path)
		}
	}
	return nil
}

// descend resolves the graft path against the base generation, one
// component at a time, and establishes residency on the way down —
// ReaddirRetain rather than Readdir, for the reason merge's walker
// documents: a genfs inode that was merely LISTED is not operable.
func (s *GraftSpliceSource) descend(ctx context.Context) error {
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
			return fmt.Errorf("%w: %s is a %s, and %s would have to be inside it. Graft somewhere "+
				"else, or remove %s first",
				ErrGraftPathNotDir, "/"+strings.Join(s.comps[:d+1], "/"),
				typeWord(e.Node.Type), s.mount, "/"+strings.Join(s.comps[:d+1], "/"))
		}
		s.baseIno[d+1] = e.Node.Inode
	}
	return nil
}

// classify decides what happens at the path, and is where every refusal
// in the collision matrix is made. See docs/design-graft.md for the table
// this implements.
func (s *GraftSpliceSource) classify(ctx context.Context, o GraftSpliceOptions) error {
	target := s.baseIno[len(s.comps)]
	if o.Remove {
		// A removal. It has exactly one precondition and it is not about
		// what is at the path but about what the superblock says: without
		// a GraftEntry there is nothing to remove, and dropping a
		// directory because it looked grafted would be deleting a tree.
		if s.prior == nil {
			return fmt.Errorf("%w: %s (`pelfs graft --list <volume>` shows what it does serve)",
				ErrGraftNotThere, s.mount)
		}
		if target == 0 {
			return fmt.Errorf("%w: the superblock names a graft at %s but the tree has nothing there; "+
				"this generation contradicts itself and `pelfs fsck` is the tool for it",
				ErrGraftNotThere, s.mount)
		}
		s.placement = GraftPlaceRemoved
		return nil
	}
	if o.Refresh && s.prior == nil {
		return fmt.Errorf("%w: %s (`pelfs graft --list <volume>` shows what it does serve)",
			ErrGraftNotThere, s.mount)
	}
	// An existing graft at the path is settled FIRST, before the
	// "populated directory" rule, because a graft's directory is always
	// populated and the generic refusal would tell the user the wrong
	// thing to do about it.
	if s.prior != nil {
		switch {
		case s.prior.Source == s.source:
			if !o.Refresh {
				return fmt.Errorf("%w: %s already serves %s. Re-grafting the same source IS a "+
					"refresh: `pelfs graft --refresh <volume> %s` re-reads only what changed there, "+
					"and keeps the block rule this graft was cut with (a different rule moves every "+
					"identity in it)",
					ErrGraftSameSource, s.mount, s.prior.Source, s.mount)
			}
			s.placement = GraftPlaceRefresh
		default:
			// A REPLACE, allowed without a flag: a graft's bytes were
			// never in this volume, so nothing local is lost by pointing
			// the path at a different third party. The caller says so out
			// loud — that is what Prior() is for.
			s.placement = GraftPlaceReplacedGraft
		}
		s.replacedType = catalog.TypeDir
		return nil
	}
	if target == 0 {
		s.placement = GraftPlaceNew
		return nil
	}
	n, err := s.base.GetAttr(ctx, target)
	if err != nil {
		return fmt.Errorf("graft: read %s from the previous generation: %w", s.mount, err)
	}
	if n.Type != catalog.TypeDir {
		if !o.Replace {
			return fmt.Errorf("%w: %s is a %s (%d bytes). A graft needs a directory of its own: "+
				"remove it, graft somewhere else, or pass --replace to drop it from the next generation",
				ErrGraftPathOccupied, s.mount, typeWord(n.Type), n.Length)
		}
		s.placement, s.replacedType = GraftPlaceReplacedFile, n.Type
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
		s.placement = GraftPlaceEmptyDir
		return nil
	}
	if !o.Replace {
		return fmt.Errorf("%w: %s holds %d entries (%s). A graft REPLACES the directory it lands on "+
			"rather than merging into it, so this would drop them from the next generation. Graft at a "+
			"path of its own, or pass --replace to drop them on purpose",
			ErrGraftPathNotEmpty, s.mount, len(ents), sampleNames(ents))
	}
	s.placement = GraftPlaceReplacedDir
	return nil
}

// wireSpine settles which inode the spliced tree publishes at each depth
// of the path, and records the dirty set that follows from it.
//
// The base's inode wins wherever the base has the directory, and that is
// the whole of why an existing volume survives a graft: a directory that
// keeps its inode keeps its attributes, its other entries, its xattrs, and
// its place in every catalog that names it.
func (s *GraftSpliceSource) wireSpine() {
	s.spineIno = make([]uint64, len(s.comps)+1)
	for d := 0; d < len(s.comps); d++ {
		switch {
		case s.baseIno[d] != 0:
			s.spineIno[d] = s.baseIno[d]
		case s.g != nil:
			s.spineIno[d] = s.g.SpineInode(d-1) + s.shift
		default:
			// Unreachable: a removal's path exists by classify's check.
			// Left explicit rather than as a nil dereference.
			s.spineIno[d] = 0
		}
		if s.spineIno[d] == 0 {
			// Only reachable from a PREFLIGHT, which is never walked.
			continue
		}
		s.depthOf[s.spineIno[d]] = d
		s.dirty[s.spineIno[d]] = struct{}{}
	}
	if s.g != nil {
		s.spineIno[len(s.comps)] = s.g.MountInode() + s.shift
		s.mountNode = s.nodeOfGraft(s.g.MountInode())
		s.dirty[s.spineIno[len(s.comps)]] = struct{}{}
	}
	// The inode that was displaced is a change too, and saying so keeps
	// "what this publish touched" honest even though nothing downstream
	// consults an inode that is no longer in the tree.
	if old := s.baseIno[len(s.comps)]; old != 0 {
		s.dirty[old] = struct{}{}
	}
}

// ---- reporting ----

// Placement is what happened at the path.
func (s *GraftSpliceSource) Placement() GraftPlacement { return s.placement }

// Prior is the graft entry that was at the path, or nil.
func (s *GraftSpliceSource) Prior() *superblock.GraftEntry { return s.prior }

// Displaced describes what the graft took the place of: the catalog type
// and, for a directory, how many entries it held. Both zero when the path
// was empty.
func (s *GraftSpliceSource) Displaced() (typ uint8, entries int) {
	return s.replacedType, s.replacedEntries
}

// Mount is the path the tree lands at.
func (s *GraftSpliceSource) Mount() string { return s.mount }

// SyntheticDirs is how many directories on the path the volume did not
// have and this publish creates. A user who mistyped a path is told this
// number rather than discovering three empty directories later.
func (s *GraftSpliceSource) SyntheticDirs() []string {
	var out []string
	for d := 1; d < len(s.comps); d++ {
		if s.baseIno[d] == 0 {
			out = append(out, "/"+strings.Join(s.comps[:d], "/"))
		}
	}
	return out
}

// ---- Source ----

func (s *GraftSpliceSource) Root() uint64 { return genfs.RootInode }

// NextInode is the BASE's counter. The grafted numbers are stated
// authoritatively by InodeMark instead, for the reason mergeSource
// documents: a tree that contains inodes the source did not allocate
// cannot have its allocator inferred from what the tree happens to hold.
func (s *GraftSpliceSource) NextInode() uint64 { return s.prev.NextInode }

func (s *GraftSpliceSource) InodeMark() uint64 {
	mark := s.prev.NextInode
	if s.g != nil {
		if m := s.g.NextInode() + s.shift; m > mark {
			mark = m
		}
	}
	return mark
}

// grafted reports whether an inode belongs to the spliced subtree. The
// ranges are disjoint by construction (see the file comment), so this is
// arithmetic.
func (s *GraftSpliceSource) grafted(ino uint64) bool {
	return s.g != nil && ino > s.shift
}

func (s *GraftSpliceSource) Readdir(ctx context.Context, ino uint64) ([]SrcEntry, error) {
	if s.grafted(ino) {
		ents, err := s.g.Readdir(ctx, ino-s.shift)
		if err != nil {
			return nil, err
		}
		out := make([]SrcEntry, 0, len(ents))
		for _, e := range ents {
			e.Node.Inode += s.shift
			out = append(out, e)
		}
		return out, nil
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
				// The one entry the splice owns: the graft root itself, or
				// a path component the base does not have under this name
				// as a directory. Dropped here and re-stated below —
				// except for a removal, which drops it and states nothing.
				continue
			}
			// EVERY OTHER ENTRY IS THE BASE'S OWN, INCLUDING A SPINE
			// DIRECTORY THE VOLUME ALREADY HAS, and it is passed through
			// untouched rather than re-described.
			//
			// That is load-bearing and was a bug once: publish's walk
			// records an inode's attributes from the LISTING that named it
			// (only the root is Stat'ed), so a spine directory re-stated
			// here from its inode and type alone would be published with
			// mode 0 — an existing directory on the graft path made
			// inaccessible by grafting underneath it.
			out = append(out, SrcEntry{Name: name, Node: srcNodeFromGenfs(ents[name].Node)})
		}
	}
	if onSpine && s.spineNeedsStating(d) {
		out = append(out, SrcEntry{Name: s.comps[d], Node: s.spineNode(d + 1)})
	}
	return out, nil
}

// spineNeedsStating reports whether the entry for depth d+1 has to be
// synthesized here rather than passed through from the base.
func (s *GraftSpliceSource) spineNeedsStating(d int) bool {
	if s.spineIno[d+1] == 0 {
		return false
	}
	return d+1 == len(s.comps) || s.baseIno[d+1] == 0
}

// spineNode is the node published for a directory the splice itself
// states: the graft root at the end of the path, or a directory on the way
// to it that the volume does not have. A directory the volume DOES have is
// never described here — it comes through its parent's listing, with its
// own mode, owner and times (see Readdir).
func (s *GraftSpliceSource) spineNode(d int) SrcNode {
	if d == len(s.comps) {
		return s.mountNode
	}
	return s.nodeOfGraft(s.g.SpineInode(d - 1))
}

// nodeOfGraft is one graft-source node, published under its shifted
// inode.
func (s *GraftSpliceSource) nodeOfGraft(gino uint64) SrcNode {
	n, err := s.g.Stat(context.Background(), gino)
	if err != nil {
		return SrcNode{}
	}
	n.Inode += s.shift
	return n
}

func (s *GraftSpliceSource) Stat(ctx context.Context, ino uint64) (SrcNode, error) {
	if s.grafted(ino) {
		n, err := s.g.Stat(ctx, ino-s.shift)
		if err != nil {
			return SrcNode{}, err
		}
		n.Inode += s.shift
		return n, nil
	}
	n, err := s.base.GetAttr(ctx, ino)
	if err != nil {
		return SrcNode{}, fmt.Errorf("graft: stat inode %d in the previous generation: %w", ino, err)
	}
	return srcNodeFromGenfs(n), nil
}

func (s *GraftSpliceSource) Readlink(ctx context.Context, ino uint64) (string, error) {
	if s.grafted(ino) {
		return s.g.Readlink(ctx, ino-s.shift)
	}
	return s.base.Readlink(ctx, ino)
}

func (s *GraftSpliceSource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	if s.grafted(ino) {
		return s.g.Xattrs(ctx, ino-s.shift)
	}
	names, err := s.base.ListXattr(ctx, ino)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		v, err := s.base.GetXattr(ctx, ino, name)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// Open is the fallback path and should almost never run. A grafted file
// answers through ProvidedContent and a base file through
// ExistingContent, so reaching here means one of them declined — the
// inline threshold moved since the base generation, most plausibly — and
// the file has to be read to be re-chunked.
//
// It is implemented rather than refused (merge refuses it) because the two
// situations differ: merge has both sides' records by construction, while
// a splice's base half is a published generation whose records this
// process may legitimately not be able to reuse. Refusing would turn a
// parameter change into "you cannot graft into this volume".
func (s *GraftSpliceSource) Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	if s.grafted(ino) {
		return s.g.Open(ctx, ino-s.shift, length)
	}
	return &genfsReader{ctx: ctx, fs: s.base, ino: ino, length: length}, nil
}

// ---- ContentProvider: the grafted half ----

func (s *GraftSpliceSource) ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if !s.grafted(ino) {
		return genfs.Content{}, false, nil
	}
	return s.g.ProvidedContent(ctx, ino-s.shift)
}

// ProvidedPacks is empty for the same reason it is empty on GraftSource: a
// graft uploads no packs, and its location statement is the GraftEntry in
// Options.Grafts. The BASE's packs are not stated here either — publish
// carries Prev's pack list forward verbatim, which is the same mechanism
// content reuse rests on.
func (s *GraftSpliceSource) ProvidedPacks(context.Context) ([]packstore.SealedPack, error) {
	return nil, nil
}

func (s *GraftSpliceSource) ProvidedEntries(func(identityHex, pack string)) {}

// ---- ContentReuser: the base half ----

func (s *GraftSpliceSource) BaseGeneration() [32]byte { return s.prev.RootCatalog }

// ExistingContent hands publish the records the previous generation
// published for a base file, so no byte of the volume is re-read.
//
// ContentOf sets Content.External for a file whose refs resolve through a
// graft, which is what keeps an EXISTING graft's identities out of the
// dedup set when a second graft is added beside it. Losing that would let
// a locally written chunk be elided from upload because a third party
// happens to hold the same block.
func (s *GraftSpliceSource) ExistingContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if s.grafted(ino) {
		return genfs.Content{}, false, nil
	}
	c, err := s.base.ContentOf(ctx, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return c, true, nil
}

// ---- CatalogReuser: what changed ----

// DirtyInodes is the SPINE and the graft, and nothing else — which is the
// claim that makes this cheap. Completeness is the safety property, so it
// is worth stating why the grafted subtree's own inodes are not listed:
// they are numbered above the base generation's allocator mark, so no
// entry in the previous generation's catalog list can be keyed by one of
// them, and the carry-forward test (planReuse) needs both a matching inode
// AND a matching path. A grafted inode therefore cannot be mistaken for an
// unchanged one. Everything the base HAS published is either on the spine
// (dirty, rebuilt) or untouched by this publish.
func (s *GraftSpliceSource) DirtyInodes() (map[uint64]struct{}, error) {
	out := make(map[uint64]struct{}, len(s.dirty))
	for ino := range s.dirty {
		out[ino] = struct{}{}
	}
	return out, nil
}

// DirtyScope is the same set: every inode on the spine, and every
// ancestor of one, is on the spine. The walk therefore stops at every
// catalog root outside the path — a graft into a 10M-inode volume never
// reads the 10M inodes.
func (s *GraftSpliceSource) DirtyScope() (map[uint64]struct{}, bool, error) {
	out, err := s.DirtyInodes()
	return out, true, err
}

// ---- helpers ----

func (s *GraftSpliceSource) entries(ctx context.Context, ino uint64) (map[string]genfs.DirEntry, error) {
	des, err := s.base.ReaddirRetain(ctx, ino)
	if err != nil {
		return nil, fmt.Errorf("graft: read directory %d of the previous generation: %w", ino, err)
	}
	out := make(map[string]genfs.DirEntry, len(des))
	for _, de := range des {
		out[de.Name] = de
	}
	return out, nil
}

func srcNodeFromGenfs(n genfs.Node) SrcNode {
	return SrcNode{
		Inode: n.Inode, Type: n.Type, Mode: n.Mode, UID: n.UID, GID: n.GID,
		MtimeNS: n.MtimeNS, CtimeNS: n.CtimeNS, Nlink: n.Nlink,
		Length: n.Length, Rdev: n.Rdev,
	}
}

// underPath reports whether p is STRICTLY under root.
func underPath(p, root string) bool {
	if root == "/" {
		return p != "/"
	}
	return strings.HasPrefix(p, root+"/")
}

func typeWord(t uint8) string {
	switch t {
	case catalog.TypeDir:
		return "directory"
	case catalog.TypeFile:
		return "file"
	case catalog.TypeSymlink:
		return "symlink"
	case catalog.TypeFIFO:
		return "fifo"
	case catalog.TypeSocket:
		return "socket"
	case catalog.TypeBlockDev:
		return "block device"
	case catalog.TypeCharDev:
		return "character device"
	default:
		return "non-directory"
	}
}

// sampleNames names a few of the entries a refusal is about. A count alone
// leaves a user unsure whether they typed the wrong path or the right one;
// two names settle it immediately.
func sampleNames(ents map[string]genfs.DirEntry) string {
	names := make([]string, 0, len(ents))
	for name := range ents {
		names = append(names, name)
	}
	sort.Strings(names)
	switch {
	case len(names) == 0:
		return "none"
	case len(names) <= 2:
		return strings.Join(names, ", ")
	default:
		return strings.Join(names[:2], ", ") + ", ..."
	}
}

// genfsReader streams a base file sequentially out of the previous
// generation, for the Open fallback above.
type genfsReader struct {
	ctx    context.Context
	fs     *genfs.FS
	ino    uint64
	off    int64
	length int64
}

func (r *genfsReader) Read(p []byte) (int, error) {
	if r.off >= r.length {
		return 0, io.EOF
	}
	if int64(len(p)) > r.length-r.off {
		p = p[:r.length-r.off]
	}
	n, err := r.fs.Read(r.ctx, r.ino, r.off, p)
	r.off += int64(n)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return n, nil
}

func (r *genfsReader) Close() error { return nil }
