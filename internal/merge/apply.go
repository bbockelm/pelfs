package merge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
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
	if o.Plan.policy == KeepBoth && o.TheirBranch == "" {
		// The branch names the kept copies, and a plan that reported
		// "notes (from dev).txt" must not produce "notes (from
		// theirs).txt". Refused rather than defaulted, because the plan
		// already told a user a filename.
		return nil, errors.New("merge: TheirBranch is required when conflicts are kept, " +
			"or the kept copies get names the plan did not report")
	}
	if o.Plan.FastForward {
		return nil, errors.New("merge: this is a fast-forward; FastForward publishes it without building a tree")
	}
	if o.Refs == nil || o.Branch == "" {
		return nil, errors.New("merge: Refs and Branch are required to publish")
	}
	// The key is required unless the branch has none — an unsigned volume
	// merges unsigned, and publish refuses a key it was not meant to use.
	if len(o.SigningKey) == 0 && !o.Ours.IsUnsigned() {
		return nil, errors.New("merge: a signing key is required to publish")
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
	branch := o.TheirBranch
	if branch == "" {
		branch = "theirs"
	}
	src := &mergeSource{
		t: trees, ours: o.Ours, theirs: o.Theirs, theirPacks: packs, obj: o.Inner,
		policy: o.Plan.policy, theirBranch: branch,
		dirs:           map[uint64]triple{rootInode: {base: rootInode, ours: rootInode, theirs: rootInode}},
		fromTheirs:     map[uint64]bool{},
		copies:         map[uint64]uint64{},
		nextInode:      o.Ours.NextInode,
		tookIdentities: map[[32]byte]struct{}{},
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

	obj         pelicanobj.Store
	policy      Policy
	theirBranch string

	dirs       map[uint64]triple
	fromTheirs map[uint64]bool
	// copies maps a FRESH inode, allocated for a kept conflicting copy, to
	// the inode on theirs' side holding its data.
	//
	// A fresh number is required rather than tidy. A file that predates the
	// fork has the same inode on both sides, so writing theirs' version
	// beside ours under that same number would give one inode two names
	// with two contents — which is a hard link, and a hard link is one
	// file. The copy has to be a new inode or it is not a copy.
	copies map[uint64]uint64
	// nextInode allocates those, from OUR lineage: the merged generation
	// is published on our branch, so a number it hands out has to come
	// from the range our branch owns.
	nextInode uint64

	// tookIdentities are the chunk identities served from theirs, which
	// the merged generation's index has to cover or a reader falls back to
	// probing pack trailers for exactly the content the merge brought in.
	//
	// Held as identities rather than resolved as they arrive because the
	// resolution needs theirs' index, and fetching that is worth doing
	// once rather than per file. Bounded by what the merge took from
	// theirs, which is the divergence and not the tree.
	tookIdentities map[[32]byte]struct{}
	theirIndex     *mpi.Set
	indexErr       error
}

var (
	_ publish.Source          = (*mergeSource)(nil)
	_ publish.ContentProvider = (*mergeSource)(nil)
	_ publish.InodeMarker     = (*mergeSource)(nil)
)

func (m *mergeSource) Root() uint64 { return rootInode }

// NextInode stays OURS. Lineages are disjoint, so the two branches were
// never drawing from the same range: this branch keeps allocating from its
// own, the incoming tree keeps the numbers it has, and nothing collides.
func (m *mergeSource) NextInode() uint64 { return m.ours.NextInode }

// InodeMark says the same thing AUTHORITATIVELY, and it has to, because
// NextInode alone cannot lower publish's inference.
//
// Publish otherwise records max-inode-seen plus one, and the merged tree
// contains the other branch's inodes — a higher lineage. That would leave
// this branch allocating inside the other branch's range, whose next
// allocation is in the same neighbourhood: the two would collide on the
// next file each created, undoing the whole point of per-branch lineages.
// A test asserts the merged generation's mark is still in our lineage.
func (m *mergeSource) InodeMark() uint64 { return m.nextInode }

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
		case Descend:
			child, tri := m.mergedDir(b, inBase, oe, inOurs, te, inTheirs)
			child.Name = name
			m.dirs[child.Node.Inode] = tri
			out = append(out, child)
		case Conflicted:
			// Compute refused this plan unless the policy keeps both, so
			// reaching here with Refuse means the plan and the tree
			// disagree — the tree moved under it.
			if m.policy != KeepBoth {
				return nil, fmt.Errorf("merge: %s conflicts during apply (%s); re-plan", name, detail)
			}
			kept, ok := m.keepBoth(name, oe, inOurs, te, inTheirs)
			if !ok {
				return nil, fmt.Errorf("merge: %s conflicts and cannot be kept as two files (%s)", name, detail)
			}
			out = append(out, srcEntry(name, oe), kept)
		case TakeTheirs:
			m.fromTheirs[te.Node.Inode] = true
			out = append(out, srcEntry(name, te))
		default: // TakeOurs, Same
			out = append(out, srcEntry(name, oe))
		}
	}
	return out, nil
}

// keepBoth emits theirs' version beside ours, under a suffixed name and a
// fresh inode.
func (m *mergeSource) keepBoth(name string, oe entry, inOurs bool, te entry, inTheirs bool) (publish.SrcEntry, bool) {
	if !inOurs || !inTheirs ||
		oe.Node.Type == catalog.TypeDir || te.Node.Type == catalog.TypeDir {
		return publish.SrcEntry{}, false
	}
	ino := m.nextInode
	m.nextInode++
	m.copies[ino] = te.Node.Inode
	node := te.Node
	node.Inode = ino
	// A kept copy is its own file, so it is never a link to anything.
	node.Nlink = 1
	return publish.SrcEntry{Name: ConflictName(name, m.theirBranch), Node: srcNode(node)}, true
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
	if _, ok := m.copies[ino]; ok {
		return m.t.theirs
	}
	if m.fromTheirs[ino] {
		return m.t.theirs
	}
	if tr, ok := m.dirs[ino]; ok && tr.ours == 0 {
		return m.t.theirs
	}
	return m.t.ours
}

// dataInode is where an inode's bytes and attributes come from: itself,
// or the inode it was copied from.
func (m *mergeSource) dataInode(ino uint64) uint64 {
	if from, ok := m.copies[ino]; ok {
		return from
	}
	return ino
}

func (m *mergeSource) Stat(ctx context.Context, ino uint64) (publish.SrcNode, error) {
	n, err := m.treeFor(ino).GetAttr(ctx, m.dataInode(ino))
	if err != nil {
		return publish.SrcNode{}, err
	}
	return srcNode(n), nil
}

func (m *mergeSource) Readlink(ctx context.Context, ino uint64) (string, error) {
	return m.treeFor(ino).Readlink(ctx, m.dataInode(ino))
}

func (m *mergeSource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	fs, ino := m.treeFor(ino), m.dataInode(ino)
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
	fs, data := m.treeFor(ino), m.dataInode(ino)
	c, err := fs.ContentOf(ctx, data)
	if err != nil {
		return genfs.Content{}, false, err
	}
	if fs == m.t.theirs {
		// Remembered so the merged generation's index can cover it. Ours'
		// identities need nothing: publish carries our index refs forward.
		for _, ref := range c.Refs {
			if len(ref.Identity) == 32 {
				m.tookIdentities[[32]byte(ref.Identity)] = struct{}{}
			}
		}
	}
	return c, true, nil
}

// ProvidedPacks are the incoming side's packs. Ours' are carried forward
// by publish from Prev; theirs' have to be named here or every chunk the
// merge took from theirs is unreachable in the generation that names it.
func (m *mergeSource) ProvidedPacks(context.Context) ([]packstore.SealedPack, error) {
	return m.theirPacks, nil
}

// ProvidedEntries names the pack holding every identity the merge took
// from theirs, so the merged generation's index covers the content it
// brought in rather than leaving a reader to probe pack trailers for it.
//
// IT LOOKS UP RATHER THAN ITERATING, and it has to: an index stores
// TRUNCATED identities (mpi.KeyLen is 12 of 32 bytes), so walking theirs'
// index could never produce the full identity this reports. What makes
// the lookup possible is that the chunkrefs already went past — full
// identities, from the files the merge served — so the only thing missing
// was which pack each sits in, which is exactly what an index answers.
//
// A truncated-key collision returns more than one candidate, and all of
// them are emitted: that is what the format already expects a reader to
// do, and naming one arbitrarily would be naming the wrong one half the
// time. An identity the index cannot resolve is skipped, and falls back
// to trailers as before — slower, never wrong.
func (m *mergeSource) ProvidedEntries(fn func(identityHex, pack string)) {
	set := m.index()
	if set == nil {
		return
	}
	for id := range m.tookIdentities {
		packs, ok := set.Lookup(id)
		if !ok {
			continue
		}
		for _, p := range packs {
			fn(hex.EncodeToString(id[:]), p)
		}
	}
}

// index fetches theirs' index tiers once. A failure is not fatal: the
// index is derived, so a merge that cannot read it publishes a generation
// whose index covers less and reads a little slower.
func (m *mergeSource) index() *mpi.Set {
	if m.theirIndex != nil || m.indexErr != nil {
		return m.theirIndex
	}
	if len(m.theirs.PackIndexes) == 0 {
		m.indexErr = errors.New("the incoming generation lists no index")
		return nil
	}
	ixs, err := mpi.FetchAll(context.Background(), m.obj, m.theirs.PackIndexes)
	if err != nil || len(ixs) == 0 {
		m.indexErr = err
		if m.indexErr == nil {
			m.indexErr = errors.New("no index segment could be read")
		}
		return nil
	}
	m.theirIndex = mpi.NewSet(ixs)
	return m.theirIndex
}
