package genfs

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sort"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Generation swap (docs/design-packfs.md, "Read-only mounts and update
// propagation"): replace the served generation in place and report
// exactly what a kernel must invalidate.
//
// The invalidation set is bounded by RESIDENCY, not by tree size, and
// that is the whole trick: residency is the set of inodes the kernel
// looked up, so it is (a superset of) what the kernel has cached. A
// generation swap therefore costs work proportional to what this mount
// is actually holding, never to what changed globally.
//
// Stable inodes are what make it work. Inode numbers never change across
// generations, so an unchanged file keeps its identity — the kernel's
// cached dentry and attributes stay valid and nothing is invalidated for
// it. This is precisely the CVMFS failure this format was designed to
// avoid: their inodes are assigned per catalog load, so every reload
// renumbers the world and breaks open files.

// Change reports one inode a swap invalidated.
type Change struct {
	Inode uint64
	// Attr is set when the node row differs (size, mode, times, nlink).
	Attr bool
	// Content is set when the file's data changed — a different chunk
	// list, inline body, or symlink target. The kernel must drop cached
	// pages, not just attributes.
	Content bool
	// Gone is set when the inode no longer resolves at its recorded
	// edge: deleted, or renamed away.
	Gone bool
}

// EntryChange reports one directory entry a swap invalidated. The kernel
// caches negative and positive dentries by (parent, name), so both
// additions and removals must be announced.
type EntryChange struct {
	Parent uint64
	Name   string
	// Gone is set when the name no longer exists in the new generation.
	Gone bool
}

// SwapReport is what a binding turns into kernel notifications.
type SwapReport struct {
	From, To uint64 // generation numbers
	Changes  []Change
	Entries  []EntryChange
	// Resident is how many inodes were re-resolved — the work the swap
	// actually did, for logging and tests.
	Resident int
}

// Swap replaces the served generation with sb, which the caller has
// ALREADY verified (signature and lineage — refs.Store does both). It
// re-resolves every resident inode against the new generation, drops
// caches that no longer apply, and returns the invalidation set.
//
// Concurrency: readers in flight during a swap either complete against
// the old catalogs (their handles are refcounted and outlive the swap)
// or see the new ones; neither yields a torn result, because catalogs
// and chunks are immutable and content-addressed — the same identity
// always names the same bytes.
func (fs *FS) Swap(ctx context.Context, sb *superblock.Superblock) (*SwapReport, error) {
	if sb == nil {
		return nil, fmt.Errorf("genfs: Swap requires a superblock")
	}
	if sb.VolumeID != fs.sb.VolumeID {
		return nil, fmt.Errorf("genfs: refusing to swap to a different volume (%x != %x)",
			sb.VolumeID, fs.sb.VolumeID)
	}
	if sb.CatalogKeyID != 0 && len(fs.dek) == 0 {
		return nil, fmt.Errorf("genfs: new generation is encrypted but this mount holds no DEK")
	}
	rep := &SwapReport{From: fs.sb.Generation, To: sb.Generation}
	if sb.RootCatalog == fs.sb.RootCatalog {
		return rep, nil // same tree; nothing to invalidate
	}

	// Resolve, decode, and verify the incoming root catalog against the
	// incoming pack list BEFORE anything served is touched, so a generation
	// this mount cannot read leaves it on the one it can. That used to be
	// what indexing every new trailer up front bought; the root catalog is
	// the part of it that actually proves the new generation is servable,
	// and the rest of the map fills in behind the reads that need it.
	packs, err := manifest.Packs(ctx, fs.inner, sb)
	if err != nil {
		// Same rule as Open, and it matters more here: a swap that fell
		// through to an empty pack set would replace a generation this
		// mount can serve with one it cannot read a byte of.
		return nil, fmt.Errorf("genfs: swap: %w", err)
	}
	newIndex := newPackIndex(fs, packs)
	// The incoming generation's own indexes, for the same reason Open
	// takes them: the swap resolves a root catalog it has never located,
	// and every read after it resolves against this map.
	newIndex.loadHints(ctx, sb.PackIndexes)
	newDEK := []byte(nil)
	if sb.CatalogKeyID != 0 {
		newDEK = fs.dek
	}
	rootHex := hex.EncodeToString(sb.RootCatalog[:])
	rootPath, err := fs.spillCatalogFrom(ctx, newIndex, newDEK, rootHex)
	if err != nil {
		return nil, fmt.Errorf("genfs: swap: root catalog: %w", err)
	}
	if fs.verify {
		raw, err := os.ReadFile(rootPath)
		if err != nil {
			return nil, err
		}
		if id := fs.hasher.Sum(raw); id != chunkid.Identity(sb.RootCatalog) {
			return nil, fmt.Errorf("genfs: swap: root catalog identity mismatch: got %s", id.Hex())
		}
	}
	root, err := catalog.OpenReader(rootPath)
	if err != nil {
		return nil, fmt.Errorf("genfs: swap: open root catalog: %w", err)
	}

	// Everything from here to the end of the re-descend replaces served
	// state, and none of it is atomic on its own: the residency table is
	// emptied before it is rebuilt, the catalog cache is replaced, and the
	// old catalogs are closed out from under whoever holds them. Hold the
	// swap lock across the lot so an operation runs entirely in one
	// generation or entirely in the other, never against the seam.
	fs.swapMu.Lock()
	defer fs.swapMu.Unlock()

	// Snapshot what the kernel holds, parent-first: a child's new
	// residency is resolved through its parent's, so order matters.
	type held struct {
		ino    uint64
		parent uint64
		name   string
	}
	fs.mu.RLock()
	order := make([]held, 0, len(fs.res))
	for ino, r := range fs.res {
		order = append(order, held{ino: ino, parent: r.parent, name: r.name})
	}
	fs.mu.RUnlock()
	sort.Slice(order, func(i, j int) bool {
		if order[i].parent != order[j].parent {
			return order[i].parent < order[j].parent
		}
		return order[i].name < order[j].name
	})
	rep.Resident = len(order)

	// Capture the pre-swap view of every resident inode, so the
	// comparison below is against what the kernel was actually told.
	before := make(map[uint64]Node, len(order))
	beforeDirs := make(map[uint64]map[string]uint64)
	for _, h := range order {
		if n, err := fs.getAttr(ctx, h.ino); err == nil {
			before[h.ino] = n
			if n.Type == catalog.TypeDir {
				if entries, err := fs.readdir(ctx, h.ino); err == nil {
					m := make(map[string]uint64, len(entries))
					for _, e := range entries {
						m[e.Name] = e.Node.Inode
					}
					beforeDirs[h.ino] = m
				}
			}
		}
	}
	if rootEntries, err := fs.readdir(ctx, RootInode); err == nil {
		m := make(map[string]uint64, len(rootEntries))
		for _, e := range rootEntries {
			m[e.Name] = e.Node.Inode
		}
		beforeDirs[RootInode] = m
	}

	// Install the new generation. Cached PACK FILES stay: packs are
	// immutable and content-addressed by name, so a copy on disk is as
	// valid for the new generation as for the old.
	oldCats := fs.cats
	fs.mu.Lock()
	fs.sb = sb
	fs.packIndex = newIndex
	fs.res = make(map[uint64]*residency, len(order))
	fs.resLRU.Init()
	fs.mu.Unlock()
	fs.ext.clear()
	fs.cats = newCatCache(fs, oldCats.cap, rootHex, root)
	oldCats.closeAll()

	// Re-descend the held set and diff it against the pre-swap view.
	for _, h := range order {
		node, err := fs.lookup(ctx, h.parent, h.name)
		if err != nil || node.Inode != h.ino {
			// The edge is gone, or now names a different inode: either
			// way the kernel's dentry for it is wrong.
			rep.Changes = append(rep.Changes, Change{Inode: h.ino, Gone: true})
			rep.Entries = append(rep.Entries, EntryChange{Parent: h.parent, Name: h.name, Gone: err != nil})
			continue
		}
		old, had := before[h.ino]
		if !had {
			continue
		}
		ch := Change{Inode: h.ino}
		if node != old {
			ch.Attr = true
		}
		// Length or mtime moving means the bytes moved; the kernel must
		// drop its page cache, not merely re-stat.
		if node.Length != old.Length || node.MtimeNS != old.MtimeNS {
			ch.Content = true
		}
		if ch.Attr || ch.Content {
			rep.Changes = append(rep.Changes, ch)
		}
	}

	// Directory listings: announce added and removed names so cached
	// dentries (including negative ones) do not outlive the swap.
	for dir, oldEntries := range beforeDirs {
		newEntries, err := fs.readdir(ctx, dir)
		if err != nil {
			continue // the directory itself is gone; already reported above
		}
		seen := make(map[string]struct{}, len(newEntries))
		for _, e := range newEntries {
			seen[e.Name] = struct{}{}
			if oldIno, existed := oldEntries[e.Name]; !existed || oldIno != e.Node.Inode {
				rep.Entries = append(rep.Entries, EntryChange{Parent: dir, Name: e.Name})
			}
		}
		for name := range oldEntries {
			if _, still := seen[name]; !still {
				rep.Entries = append(rep.Entries, EntryChange{Parent: dir, Name: name, Gone: true})
			}
		}
	}
	sort.Slice(rep.Changes, func(i, j int) bool { return rep.Changes[i].Inode < rep.Changes[j].Inode })
	sort.Slice(rep.Entries, func(i, j int) bool {
		if rep.Entries[i].Parent != rep.Entries[j].Parent {
			return rep.Entries[i].Parent < rep.Entries[j].Parent
		}
		return rep.Entries[i].Name < rep.Entries[j].Name
	})
	return rep, nil
}
