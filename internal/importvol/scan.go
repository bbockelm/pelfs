package importvol

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"sort"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/extsort"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// identityLen is the width of a chunk identity, and therefore the record
// width of the wanted set.
const identityLen = 32

// Scan is what one walk of the source's catalogs learned.
//
// THE WALK IS O(CATALOG BYTES), NOT O(DATA BYTES). It reads the source's
// namespace and its content RECORDS and never a byte of file content —
// which is what makes it affordable to do before deciding anything, and
// why the plan an import reports can be reported before the hours of
// copying start.
type Scan struct {
	// Lineages are the distinct inode lineages the tree contains,
	// ascending. THIS IS THE FINDING THE WALK EXISTS FOR: nothing in the
	// format records it. Fork.Lineage names the lineage a generation
	// ALLOCATES FROM, Catalogs[].Inode samples whichever directories
	// happen to root a catalog, and Shards cover only promoted inodes —
	// so a tree that was merged from a branch since deleted holds that
	// branch's lineage with no field mentioning it, and only a walk finds
	// it.
	Lineages []uint32
	// Counts of what is in the tree.
	Inodes, Dirs, Files, Symlinks, Specials uint64
	// Hardlinks is how many inodes carry nlink > 1 — the ones whose
	// content records live in inode shards and whose identity as one
	// inode across several paths is what the renumbering must not break.
	Hardlinks uint64
	// Bytes is the logical size of the tree. Chunks is how many DISTINCT
	// chunk identities it names — what the copy will carry — against
	// ChunkRefs, how many times they are named; the gap between them is
	// the content dedup that survives an import unchanged. InlineFiles
	// carry their whole body in a catalog and need no pack entry at all.
	Bytes       int64
	Chunks      uint64
	ChunkRefs   uint64
	InlineFiles uint64
	// Wants is the identity set the copy has to carry, sorted, on disk.
	// The caller closes it.
	Wants *extsort.Table
	// Root is the source's root directory node, which becomes the
	// directory at the destination path.
	Root genfs.Node
}

// ScanOptions configures one walk.
type ScanOptions struct {
	// FS is the source generation, open for reading.
	FS *genfs.FS
	// SB is that generation's superblock.
	SB *superblock.Superblock
	// SpoolDir is where the wanted set spills.
	SpoolDir string
	// SortBytes is the wanted set's memory budget; zero takes
	// extsort.DefaultBytes.
	SortBytes int
	// Progress is called on a timer with Phase "scanning".
	Progress func(Progress)
}

// Walk reads the source's namespace and content records and reports what
// an import of it would have to do.
//
// It refuses two things rather than discovering them later. A source that
// serves GRAFTS has files whose bytes are in no pack, so a copy would
// produce chunkrefs this volume cannot answer. And a file whose content
// records are EXTERNAL is such a file, caught individually in case a
// future generation carries one without a superblock entry.
func Walk(ctx context.Context, o ScanOptions) (_ *Scan, err error) {
	if o.FS == nil || o.SB == nil {
		return nil, fmt.Errorf("importvol: a scan needs the source generation and its superblock")
	}
	if len(o.SB.Grafts) > 0 {
		g := o.SB.Grafts[0]
		return nil, fmt.Errorf("%w: %s is served from %s, and a grafted file's bytes were never in "+
			"a pack — there is nothing for an import to copy. Remove the graft on the source "+
			"(`pelfs graft --remove`) and re-seal it, then import",
			ErrSourceGrafted, g.Path, g.Source)
	}
	budget := o.SortBytes
	if budget <= 0 {
		budget = extsort.DefaultBytes
	}
	sorter := extsort.New(o.SpoolDir, "import-wants", identityLen, identityLen, budget)
	defer func() {
		if err != nil {
			sorter.Close() //nolint:errcheck
		}
	}()

	s := &Scan{}
	root, err := o.FS.GetAttr(ctx, genfs.RootInode)
	if err != nil {
		return nil, fmt.Errorf("importvol: read the source root: %w", err)
	}
	s.Root = root

	lineages := map[uint32]bool{}
	seen := map[uint64]bool{}
	// expanded is separate from seen because they answer different
	// questions: seen is "has this inode been counted" (a hardlinked file
	// is reached once per link) and expanded is "has this directory been
	// listed". Folding them together made the cycle guard vacuous, since
	// counting an inode marked it seen before the descent test ran.
	expanded := map[uint64]bool{}
	tick := newTicker(o.Progress, 3*time.Second)

	// Strictly parent-before-child, through ReaddirRetain rather than
	// Readdir, for the reason merge's walker and the graft splice both
	// document: a genfs inode that was merely LISTED is not operable —
	// residency is established by the descent that reached it, and a Stat
	// or a read of an inode nothing descended to fails.
	var descend func(ino uint64, pth string) error
	descend = func(ino uint64, pth string) error {
		if err := checkCtx(ctx, "scanning "+pth); err != nil {
			return err
		}
		des, err := o.FS.ReaddirRetain(ctx, ino)
		if err != nil {
			return fmt.Errorf("importvol: read directory %s of the source: %w", pth, err)
		}
		for _, de := range des {
			child := path.Join(pth, de.Name)
			if err := s.note(ctx, o.FS, de.Node, child, lineages, seen, sorter); err != nil {
				return err
			}
			tick.tick(Progress{Phase: "scanning", Done: int64(s.Inodes)}, false)
			if de.Node.Type != catalog.TypeDir || expanded[de.Node.Inode] {
				// A directory reached twice is a cycle, which the format
				// cannot express and a corrupt catalog can still claim.
				// Stopping here makes the walk terminate on one anyway.
				continue
			}
			expanded[de.Node.Inode] = true
			if err := descend(de.Node.Inode, child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := s.note(ctx, o.FS, root, "/", lineages, seen, sorter); err != nil {
		return nil, err
	}
	expanded[genfs.RootInode] = true
	if err := descend(genfs.RootInode, "/"); err != nil {
		return nil, err
	}
	tick.tick(Progress{Phase: "scanning", Done: int64(s.Inodes)}, true)

	// The source's allocator mark contributes its lineage even when no
	// file in the tree happens to sit in it — a branch that has allocated
	// nothing since it was cut still OWNS its slice, and renumbering into
	// a map that did not declare it would refuse the first file the
	// source creates before the next import.
	lineages[superblock.LineageOf(o.SB.NextInode)] = true
	for l := range lineages {
		s.Lineages = append(s.Lineages, l)
	}
	sort.Slice(s.Lineages, func(i, j int) bool { return s.Lineages[i] < s.Lineages[j] })

	tbl, err := sorter.Table()
	if err != nil {
		return nil, fmt.Errorf("importvol: build the identity set: %w", err)
	}
	s.Wants = tbl
	// Chunks is DISTINCT identities, which is what the copy will carry.
	// The table keeps one record per chunk REFERENCE and the records are
	// in key order, so distinct is a single pass counting the runs — and
	// the gap between it and ChunkRefs is exactly the content dedup an
	// import inherits for free.
	s.Chunks = uint64(distinct(tbl))
	return s, nil
}

// note records one inode. A hardlinked file is reached once per link and
// is counted, walked and asked for its records exactly once — the seen
// set is what makes that true, and it is the same set that keeps a
// corrupt catalog's cycle from spinning the walk forever.
func (s *Scan) note(ctx context.Context, fs *genfs.FS, n genfs.Node, pth string,
	lineages map[uint32]bool, seen map[uint64]bool, sorter *extsort.Sorter) error {

	if seen[n.Inode] {
		return nil
	}
	seen[n.Inode] = true
	lineages[superblock.LineageOf(n.Inode)] = true
	s.Inodes++
	switch n.Type {
	case catalog.TypeDir:
		s.Dirs++
		return nil
	case catalog.TypeSymlink:
		s.Symlinks++
		return nil
	case catalog.TypeFile:
		s.Files++
	default:
		s.Specials++
		return nil
	}
	if n.Nlink > 1 {
		s.Hardlinks++
	}
	s.Bytes += n.Length
	if n.Length == 0 {
		return nil
	}
	c, err := fs.ContentOf(ctx, n.Inode)
	if err != nil {
		return fmt.Errorf("importvol: read the content records of %s: %w", pth, err)
	}
	if c.External {
		// Belt to the superblock's braces: a file whose refs resolve
		// through a graft, in a generation that did not say so.
		return fmt.Errorf("%w: %s resolves through a graft rather than a pack", ErrSourceGrafted, pth)
	}
	if c.Inline != nil {
		s.InlineFiles++
		return nil
	}
	for _, ref := range c.Refs {
		if len(ref.Identity) == 0 {
			// A hole — a chunkref with an empty identity. publish never
			// emits one and genfs serves it as zeroes; there is no pack
			// entry to copy, and the record carries across unchanged.
			continue
		}
		if len(ref.Identity) != identityLen {
			return fmt.Errorf("importvol: %s names a %d-byte chunk identity, want %d",
				pth, len(ref.Identity), identityLen)
		}
		if err := sorter.Add(ref.Identity); err != nil {
			return fmt.Errorf("importvol: record a wanted identity: %w", err)
		}
		s.ChunkRefs++
	}
	return nil
}

// distinct counts the runs of equal keys in a sorted table.
func distinct(t *extsort.Table) int {
	n := 0
	for i := range t.Len() {
		if i == 0 || !bytes.Equal(t.At(i)[:identityLen], t.At(i - 1)[:identityLen]) {
			n++
		}
	}
	return n
}
