package merge

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Carrying out a merge that has a tree to build.
//
// The merged tree is presented to publish as a Source, so everything that
// makes a generation — catalogs, the superblock, the ref flip, the CAS
// guard — is the ordinary path. What this file supplies is only the answer
// to "what does the merged tree contain", one directory at a time.
//
// NOT A BYTE OF CONTENT IS READ. Both sides' files are already chunked and
// sitting in packs, so the source implements ContentProvider and hands
// publish the chunkrefs it already has. Open is never called, and returns
// an error if it is, because a merge that started downloading files would
// be re-deriving identities both generations already record.
//
// THE MERGED TREE IS ADDRESSED BY INODE, and the two sides number
// independently, which is the one thing here that needs care:
//
//   - A directory present on both sides gets OURS' inode, and the
//     counterparts are remembered so its entries can be merged when
//     publish descends into it. Publish walks strictly by descent, so a
//     directory is always recorded before it is read.
//   - A file the merge takes from THEIRS is remembered by inode. Routing
//     by lineage alone would be wrong for a file that predates the fork:
//     it has the same inode on both sides, and taking theirs' version
//     means taking theirs' attributes and content under that shared
//     number.
//   - Everything else answers from ours, falling back to theirs when ours
//     does not have it.
//
// So what is held is proportional to the DIVERGENCE — directories on the
// path through it, plus the files theirs contributed — and not to the
// tree.

// Apply builds the merged tree and publishes it onto the branch.
//
// It refuses a plan that is not mergeable. Deciding that is Compute's job,
// and a caller that skipped it would be asking this to invent an answer
// for a path two people changed.
func Apply(ctx context.Context, o ApplyOptions) (*publish.Result, error) {
	if o.Plan == nil {
		return nil, errors.New("merge: a plan is required; deciding and acting are separate on purpose")
	}
	if !o.Plan.Mergeable() {
		return nil, fmt.Errorf("merge: not mergeable (%d conflicts, %d inode collisions)",
			len(o.Plan.Conflicts), len(o.Plan.Collisions))
	}
	if o.Plan.FastForward {
		return nil, errors.New("merge: this is a fast-forward; FastForward publishes it without building a tree")
	}
	if o.Refs == nil || o.Branch == "" || len(o.SigningKey) == 0 {
		return nil, errors.New("merge: Refs, Branch and SigningKey are required to publish")
	}
	if o.Inner == nil {
		return nil, errors.New("merge: Inner is required")
	}

	// The head is re-read and checked, for the reason every publisher here
	// does it: a plan describes two generations, and publishing it onto a
	// third would merge against a tree nobody looked at.
	head, err := o.Refs.Fetch(ctx, o.Branch)
	if err != nil {
		return nil, fmt.Errorf("merge: read %s: %w", o.Branch, err)
	}
	if head.Superblock.RootCatalog != o.Ours.RootCatalog {
		return nil, fmt.Errorf("merge: %w: %s moved while this merge was planned",
			refs.ErrStaleFlip, o.Branch)
	}

	trees, err := openAll(ctx, Options{
		Inner: o.Inner, Base: o.Base, Ours: o.Ours, Theirs: o.Theirs,
		DEK: o.DEK, CacheDir: o.CacheDir,
	})
	if err != nil {
		return nil, err
	}
	defer trees.close()

	packs, err := packsOf(ctx, o.Inner, o.Theirs)
	if err != nil {
		return nil, err
	}
	src := &mergeSource{
		t: trees, ours: o.Ours, theirs: o.Theirs, theirPacks: packs,
		dirs:       map[uint64]triple{rootInode: {base: rootInode, ours: rootInode, theirs: rootInode}},
		fromTheirs: map[uint64]bool{},
	}
	res, err := publish.Publish(ctx, publish.Options{
		Source: src, Inner: o.Inner, SpoolDir: o.SpoolDir,
		Branch: o.Branch, SigningKey: o.SigningKey,
		Prev: head.Superblock, PrevRaw: head.Raw,
		DEK: o.DEK, IdentityKey: o.IdentityKey, KeyID: uint32(o.KeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	return res, nil
}

// packsOf resolves a generation's pack set, which the merged generation
// has to name or the incoming side's content is unreachable.
func packsOf(ctx context.Context, obj pelicanobj.Store, sb *superblock.Superblock) ([]packstore.SealedPack, error) {
	entries, err := manifest.Packs(ctx, obj, sb)
	if err != nil {
		return nil, fmt.Errorf("merge: resolve generation %d's pack set: %w", sb.Generation, err)
	}
	out := make([]packstore.SealedPack, 0, len(entries))
	for _, pe := range entries {
		out = append(out, packstore.SealedPack{Name: pe.Name, TrailerHash: pe.TrailerHash, Size: pe.Size})
	}
	return out, nil
}

// triple is one merged directory's counterparts. Zero means absent.
type triple struct{ base, ours, theirs uint64 }

type mergeSource struct {
	t            *trees
	ours, theirs *superblock.Superblock
	theirPacks   []packstore.SealedPack

	dirs       map[uint64]triple
	fromTheirs map[uint64]bool
}

var (
	_ publish.Source          = (*mergeSource)(nil)
	_ publish.ContentProvider = (*mergeSource)(nil)
)

func (m *mergeSource) Root() uint64 { return rootInode }

// NextInode stays OURS. Lineages are disjoint, so the two branches were
// never drawing from the same range: this branch keeps allocating from its
// own, the incoming tree keeps the numbers it has, and nothing collides.
func (m *mergeSource) NextInode() uint64 { return m.ours.NextInode }

func (m *mergeSource) Readdir(ctx context.Context, ino uint64) ([]publish.SrcEntry, error) {
	tr, ok := m.dirs[ino]
	if !ok {
		// Publish walks by descent, so every directory it reads was
		// recorded when its parent was read. Reaching here means the walk
		// order changed under an assumption this file makes, which is
		// worth failing on rather than guessing a side.
		return nil, fmt.Errorf("merge: asked for directory %d before its parent named it", ino)
	}
	base, err := entries(ctx, m.t.base, tr.base)
	if err != nil {
		return nil, err
	}
	ours, err := entries(ctx, m.t.ours, tr.ours)
	if err != nil {
		return nil, err
	}
	theirs, err := entries(ctx, m.t.theirs, tr.theirs)
	if err != nil {
		return nil, err
	}

	var out []publish.SrcEntry
	for _, name := range union(base, ours, theirs) {
		b, inBase := base[name]
		oe, inOurs := ours[name]
		te, inTheirs := theirs[name]
		switch out2, _, detail := decide(ctx, m.t, b, inBase, oe, inOurs, te, inTheirs); out2 {
		case Drop:
		case Conflicted:
			// Compute refused this plan already, so a conflict here is a
			// disagreement between the plan and the tree — the tree moved,
			// or the two walks saw different things. Either way, not
			// something to resolve silently.
			return nil, fmt.Errorf("merge: %s conflicts during apply (%s); re-plan", name, detail)
		case Descend:
			child, tri := m.mergedDir(b, inBase, oe, inOurs, te, inTheirs)
			child.Name = name
			m.dirs[child.Node.Inode] = tri
			out = append(out, child)
		case TakeTheirs:
			m.fromTheirs[te.Node.Inode] = true
			out = append(out, srcEntry(name, te))
		default: // TakeOurs, Same
			out = append(out, srcEntry(name, oe))
		}
	}
	return out, nil
}

// mergedDir picks the inode a directory present on one or both sides gets
// in the merged tree, and the counterparts to read it from.
//
// Ours wins when both have it, and the choice is free: a directory's
// identity in this format is its entries, so either number describes the
// same place. Taking ours keeps the merged tree's numbering closest to the
// branch being merged into, which is the tree that stays mounted.
func (m *mergeSource) mergedDir(b entry, inBase bool, oe entry, inOurs bool,
	te entry, inTheirs bool) (publish.SrcEntry, triple) {

	tr := triple{base: inoOf(b, inBase), ours: inoOf(oe, inOurs), theirs: inoOf(te, inTheirs)}
	if inOurs {
		return srcEntry("", oe), tr
	}
	// A directory only theirs has: its inode is theirs', and so is
	// everything about it.
	m.fromTheirs[te.Node.Inode] = true
	return srcEntry("", te), tr
}

func srcEntry(name string, e entry) publish.SrcEntry {
	return publish.SrcEntry{Name: name, Node: srcNode(e.Node)}
}

func srcNode(n genfs.Node) publish.SrcNode {
	return publish.SrcNode{
		Inode: n.Inode, Type: n.Type, Mode: n.Mode, UID: n.UID, GID: n.GID,
		MtimeNS: n.MtimeNS, CtimeNS: n.CtimeNS, Nlink: n.Nlink, Length: n.Length, Rdev: n.Rdev,
	}
}

// treeFor is the generation an inode's data comes from: theirs when the
// merge took it from theirs, and otherwise ours — falling back to theirs
// for an inode ours does not have at all.
func (m *mergeSource) treeFor(ino uint64) *genfs.FS {
	if m.fromTheirs[ino] {
		return m.t.theirs
	}
	if tr, ok := m.dirs[ino]; ok && tr.ours == 0 {
		return m.t.theirs
	}
	return m.t.ours
}

func (m *mergeSource) Stat(ctx context.Context, ino uint64) (publish.SrcNode, error) {
	n, err := m.treeFor(ino).GetAttr(ctx, ino)
	if err != nil {
		return publish.SrcNode{}, err
	}
	return srcNode(n), nil
}

func (m *mergeSource) Readlink(ctx context.Context, ino uint64) (string, error) {
	return m.treeFor(ino).Readlink(ctx, ino)
}

func (m *mergeSource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	fs := m.treeFor(ino)
	names, err := fs.ListXattr(ctx, ino)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		v, err := fs.GetXattr(ctx, ino, name)
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// Open is never called: ProvidedContent answers for every file, because
// every file's bytes are already chunked and in a pack. Reaching here
// would mean a merge had started downloading content to rediscover
// identities both generations already record.
func (m *mergeSource) Open(context.Context, uint64, int64) (io.ReadCloser, error) {
	return nil, errors.New("merge: a merge never reads file content; both sides are already packed")
}

func (m *mergeSource) ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	c, err := m.treeFor(ino).ContentOf(ctx, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return c, true, nil
}

// ProvidedPacks are the incoming side's packs. Ours' are carried forward
// by publish from Prev; theirs' have to be named here or every chunk the
// merge took from theirs is unreachable in the generation that names it.
func (m *mergeSource) ProvidedPacks(context.Context) ([]packstore.SealedPack, error) {
	return m.theirPacks, nil
}

// ProvidedEntries reports nothing, and the cost is bounded and known.
//
// A generation's multi-pack index is what spares a reader from probing
// per-pack trailers. Ours' index refs are carried forward, so content this
// branch already had resolves through the index; content taken from theirs
// does not, and falls back to trailers until the next repack or
// consolidation covers it. Slower, never wrong.
//
// Doing better means iterating theirs' index and re-emitting it, which
// needs an iterator internal/mpi does not export yet. Worth adding; not
// worth blocking a merge on.
func (m *mergeSource) ProvidedEntries(func(identityHex, pack string)) {}
