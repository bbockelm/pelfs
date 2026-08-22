// Package merge answers what it would take to bring two diverged
// branches back together, and refuses to guess.
//
// # The base is an input, not a discovery
//
// A three-way merge needs the generation the two branches diverged from,
// and this package will not find it for you. That is a deliberate limit
// rather than an omission, because nothing in the format can find it
// today:
//
//   - refs and tags are the only addressable entry points; there is no
//     way to fetch a generation BY HASH, so the PrevHash chains cannot be
//     walked back to where they meet.
//   - the superblock backups written into packs look like they would
//     serve, and do not: a backup is built with backupPackList(), naming
//     a pack set that excludes the pack carrying it, so its hash is not
//     the hash the next generation records as its PrevHash.
//   - `pelfs branch` copies the source head's signed bytes verbatim,
//     which is what keeps a branch rooted in verified content, and leaves
//     no room to record a fork point without re-signing.
//
// So the caller names the base. A tag is the durable way to have one —
// `pelfs branch --from-tag` starts a branch at a generation that stays
// addressable and stays retained — and that is the workflow to recommend
// until the format grows a fork record or a by-hash generation space.
//
// A WRONG BASE IS NOT DETECTABLE HERE, and it is worth being blunt about
// what that costs. It does not corrupt anything: every tree this reports
// on is a real, signed generation and every chunkref in it resolves. What
// it does is silently mis-attribute change — "theirs added this" when in
// truth both sides had it and one deleted it — so the merge it describes
// is a plausible tree that is nobody's intent. What can be checked is
// checked (one volume, one catalog key, a generation that precedes both),
// and the rest is reported in full so a human can see what was decided.
//
// # What it does not do yet
//
// It PLANS. Nothing here writes an object or moves a ref: the output is a
// description, and a merge that would produce conflicts or inode
// collisions has to say so before anything can sensibly act on it.
package merge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// rootInode is the volume root, as everywhere else.
const rootInode uint64 = 1

// Options names the three generations and how to read them.
type Options struct {
	Inner pelicanobj.Store
	// Base is the generation the two branches diverged from, Ours the
	// branch being merged INTO, Theirs the branch being merged in.
	Base, Ours, Theirs *superblock.Superblock
	// BaseRaw is the base's wire bytes. Supplying them is what turns "the
	// caller named a base" into "the caller named the RIGHT base": a
	// branch created by `pelfs branch` records the hash of the generation
	// it was cut from, so the claim is checkable rather than trusted.
	BaseRaw []byte
	// DEK unwraps catalogs on an encrypted volume.
	DEK []byte
	// CacheDir holds the three generations' local caches (empty: temp).
	CacheDir string
	// OnConflict is what to do with a path neither tree can resolve
	// (default Refuse). KeepBoth writes both versions and reports what it
	// named them, so a dry run says exactly what would appear in the tree.
	OnConflict Policy
	// TheirBranch names the incoming branch, used only to name kept
	// copies. Empty takes "theirs".
	TheirBranch string
}

// Kind names why a path could not be merged without a decision.
type Kind string

const (
	// BothModified is the ordinary conflict: each side changed the same
	// file to something different.
	BothModified Kind = "both-modified"
	// ModifyDelete is one side's edit against the other's removal. It
	// needs a human because the two are not comparable: nothing about the
	// edit says whether the deletion was the point.
	ModifyDelete Kind = "modify-delete"
	// AddAdd is both sides creating the same path with different content,
	// with nothing in the base to three-way against.
	AddAdd Kind = "add-add"
	// TypeChange is the same path being a file on one side and a
	// directory (or symlink) on the other.
	TypeChange Kind = "type-change"
)

// Conflict is one path that cannot be resolved by looking at the trees.
type Conflict struct {
	Path   string
	Kind   Kind
	Detail string
}

func (c Conflict) String() string { return string(c.Kind) + " " + c.Path + ": " + c.Detail }

// Collision is one inode number that both sides allocated independently
// after the fork, so it names a different file on each.
//
// This is not damage in either branch — inodes need uniqueness only
// within a mounted tree, and the two branches mount separately. It
// becomes a problem only here, and only because a merged tree would have
// one number for two files.
type Collision struct {
	Inode      uint64
	OursPath   string
	TheirsPath string
}

// Kept is one conflict resolved by writing both versions.
type Kept struct {
	// Path is where ours stays; As is where theirs was written.
	Path, As string
	Kind     Kind
}

func (k Kept) String() string { return k.Path + " -> also " + k.As + " (" + string(k.Kind) + ")" }

// Plan is what a merge would do.
type Plan struct {
	// Refusal is set when the inputs could not be used at all; every
	// other field is then zero.
	Refusal string

	// FastForward reports that no merge is needed: one side's tree is
	// already the other's, so bringing them together is a ref flip.
	FastForward bool
	// Direction says which way, when FastForward: "ours" means ours is
	// already at or past theirs and there is nothing to do.
	Direction string

	// Unchanged counts paths identical on both sides. TookOurs and
	// TookTheirs count the ones only one side changed — the merge's real
	// content. Added counts paths that exist on neither side of the base.
	Unchanged, TookOurs, TookTheirs int

	// Conflicts are the paths a human has to resolve. Empty under
	// KeepBoth, where they become Kept instead.
	Conflicts []Conflict
	// Kept is what KeepBoth would write: one entry per conflict, naming
	// the second copy. Reported so a plan says what will appear in the
	// tree rather than only that something will.
	Kept []Kept
	// Collisions are inode numbers both sides allocated after the fork.
	// A merge cannot proceed with any, and the repair is to renumber one
	// side rather than to resolve them one at a time.
	Collisions []Collision
	// FirstFreeInode is the number a renumbering would shift into: above
	// everything either side has allocated.
	FirstFreeInode uint64

	// policy is what Compute was told to do with conflicts, carried so
	// that Apply cannot act on a policy the plan was not made under —
	// which would resolve paths the report said were refused.
	policy Policy
}

// Mergeable reports whether the plan describes something that could be
// carried out without a human deciding anything.
func (p *Plan) Mergeable() bool {
	return p.Refusal == "" && len(p.Conflicts) == 0 && len(p.Collisions) == 0
}

// Compute walks the three trees and reports what a merge would do.
func Compute(ctx context.Context, o Options) (*Plan, error) {
	if o.Inner == nil {
		return nil, errors.New("merge: Inner is required")
	}
	if o.Base == nil || o.Ours == nil || o.Theirs == nil {
		return nil, errors.New("merge: Base, Ours and Theirs are all required (the base is not discovered; name a tag)")
	}
	if refusal := checkInputs(o); refusal != "" {
		return &Plan{Refusal: refusal}, nil
	}
	cut, refusal := inodeCut(o)
	if refusal != "" {
		return &Plan{Refusal: refusal}, nil
	}

	// Fast-forward first, because it is the common case for a personal
	// volume and it needs no walk: identical root catalogs mean identical
	// trees, content addressing being what it is.
	if o.Ours.RootCatalog == o.Theirs.RootCatalog {
		return &Plan{FastForward: true, Direction: "already equal"}, nil
	}
	if o.Ours.RootCatalog == o.Base.RootCatalog {
		// Ours never moved: theirs is the answer whole.
		return &Plan{FastForward: true, Direction: "theirs"}, nil
	}
	if o.Theirs.RootCatalog == o.Base.RootCatalog {
		return &Plan{FastForward: true, Direction: "ours"}, nil
	}

	trees, err := openAll(ctx, o)
	if err != nil {
		return nil, err
	}
	defer trees.close()

	if o.TheirBranch == "" {
		o.TheirBranch = "theirs"
	}
	p := &Plan{FirstFreeInode: max(o.Ours.NextInode, o.Theirs.NextInode), policy: o.OnConflict}
	w := &walker{o: o, t: trees, p: p, cut: cut,
		ourInodes: map[uint64]string{}, theirInodes: map[uint64]string{}}
	if err := w.dir(ctx, "/", rootInode, rootInode, rootInode); err != nil {
		return nil, err
	}
	w.findCollisions()
	sort.Slice(p.Conflicts, func(i, j int) bool { return p.Conflicts[i].Path < p.Conflicts[j].Path })
	sort.Slice(p.Collisions, func(i, j int) bool { return p.Collisions[i].Inode < p.Collisions[j].Inode })
	return p, nil
}

// checkInputs applies the checks a named base can be held to. It cannot
// prove ancestry — see the package comment — so what it rules out is
// inputs that could not possibly be a merge.
func checkInputs(o Options) string {
	if o.Ours.VolumeID != o.Theirs.VolumeID || o.Ours.VolumeID != o.Base.VolumeID {
		return "the three generations are not from one volume"
	}
	// Catalog-class entries carry no per-entry key id — the superblock
	// states the one key that encrypts them all — so three generations
	// spanning a rekey have no single answer for how to decode a catalog
	// two of them share. Refused rather than guessed, as reach does.
	if o.Ours.CatalogKeyID != o.Theirs.CatalogKeyID || o.Ours.CatalogKeyID != o.Base.CatalogKeyID {
		return "the three generations do not agree on the catalog key id; merge them either side of the rekey"
	}
	if o.Base.Generation > o.Ours.Generation || o.Base.Generation > o.Theirs.Generation {
		return fmt.Sprintf("generation %d cannot be the base of %d and %d: it does not precede both",
			o.Base.Generation, o.Ours.Generation, o.Theirs.Generation)
	}
	return ""
}

// inodeCut is the inode value at or below which a number meant the same
// file on both sides, and the refusal when the fork records disagree.
//
// A branch created by `pelfs branch` carries where it was cut from, and
// that record is what makes this exact rather than assumed. Three things
// come out of it:
//
//   - THE BASE IS VERIFIED. The record holds the wire hash of the
//     generation the branch started at, so a caller who names the wrong
//     base is told so instead of getting a plausible tree that is nobody's
//     intent. That was the sharpest edge on this whole operation.
//   - THE CUT IS THE FORK'S, not the supplied base's NextInode. They
//     agree when the base is right, and when it is wrong this is the one
//     that is still true.
//   - TWO BRANCHES CUT FROM DIFFERENT POINTS ARE REFUSED. Their trees may
//     merge cleanly by accident, and the result would be attributing
//     change against a base neither of them forked at.
//
// A generation with no fork record is from the original lineage, and
// falls back to the supplied base — which is the pre-fork-record
// behaviour, unverifiable and honest about it.
func inodeCut(o Options) (uint64, string) {
	of, tf := o.Ours.Fork, o.Theirs.Fork
	switch {
	case of == nil && tf == nil:
		return o.Base.NextInode, ""
	case of != nil && tf != nil && of.Base != tf.Base:
		return 0, fmt.Sprintf("the two branches were cut from different generations (%d and %d); "+
			"they have no common fork point to merge against",
			of.BaseGeneration, tf.BaseGeneration)
	}
	fork := of
	if fork == nil {
		fork = tf
	}
	if len(o.BaseRaw) > 0 {
		if got := superblock.Hash(o.BaseRaw); got != fork.Base {
			return 0, fmt.Sprintf("the named base is generation %d (%x), but the branch was cut from %x; "+
				"merging against the wrong base silently mis-attributes every change",
				o.Base.Generation, got[:6], fork.Base[:6])
		}
	}
	return fork.BaseNextInode, ""
}

type trees struct{ base, ours, theirs *genfs.FS }

func (t *trees) close() {
	for _, fs := range []*genfs.FS{t.base, t.ours, t.theirs} {
		if fs != nil {
			fs.Close() //nolint:errcheck
		}
	}
}

func openAll(ctx context.Context, o Options) (*trees, error) {
	t := &trees{}
	for _, spec := range []struct {
		sb  *superblock.Superblock
		dst **genfs.FS
		sub string
	}{
		{o.Base, &t.base, "base"},
		{o.Ours, &t.ours, "ours"},
		{o.Theirs, &t.theirs, "theirs"},
	} {
		fs, err := genfs.Open(ctx, genfs.Options{
			Inner: o.Inner, SB: spec.sb, DEK: o.DEK,
			CacheDir: cacheSub(o.CacheDir, spec.sub),
		})
		if err != nil {
			t.close()
			return nil, fmt.Errorf("merge: open %s (generation %d): %w", spec.sub, spec.sb.Generation, err)
		}
		*spec.dst = fs
	}
	return t, nil
}

func cacheSub(dir, name string) string {
	if dir == "" {
		return ""
	}
	return path.Join(dir, name)
}

// walker carries the three-way descent.
//
// It walks by PATH rather than by inode, because the two sides number
// independently: the same path is the only thing that means the same
// thing in both trees. Inodes are collected as it goes, for the collision
// pass, which is the one place their numbering matters.
type walker struct {
	o Options
	t *trees
	p *Plan
	// cut is the inode value at or below which a number meant the same
	// file on both sides (inodeCut).
	cut uint64
	// ourInodes and theirInodes map an inode allocated after the fork to
	// the path that holds it, which is what makes a collision report
	// actionable rather than a list of numbers.
	ourInodes, theirInodes map[uint64]string
}

// dir merges one directory, present in some subset of the three trees.
// An inode of 0 means the directory is absent from that tree.
func (w *walker) dir(ctx context.Context, p string, baseIno, ourIno, theirIno uint64) error {
	baseEnts, err := entries(ctx, w.t.base, baseIno)
	if err != nil {
		return err
	}
	ourEnts, err := entries(ctx, w.t.ours, ourIno)
	if err != nil {
		return err
	}
	theirEnts, err := entries(ctx, w.t.theirs, theirIno)
	if err != nil {
		return err
	}

	for _, name := range union(baseEnts, ourEnts, theirEnts) {
		child := path.Join(p, name)
		b, inBase := baseEnts[name]
		ours, inOurs := ourEnts[name]
		theirs, inTheirs := theirEnts[name]

		if inOurs && ours.Node.Inode >= w.cut {
			w.ourInodes[ours.Node.Inode] = child
		}
		if inTheirs && theirs.Node.Inode >= w.cut {
			w.theirInodes[theirs.Node.Inode] = child
		}

		out, kind, detail := decide(ctx, w.t, b, inBase, ours, inOurs, theirs, inTheirs)
		switch out {
		case Descend:
			// A directory on either side, including one the other side
			// deleted: descended because its inodes have to reach the
			// collision pass, and because "was it modified" cannot be
			// answered for a directory by comparing the directory —
			// sameContent calls two of them equal whenever their metadata
			// matches, since directories are compared by their ENTRIES.
			// Deciding a deletion from that would discard a subtree this
			// side had changed inside, so the descent decides per file and
			// reports against the file that actually changed.
			if err := w.dir(ctx, child, inoOf(b, inBase), inoOf(ours, inOurs), inoOf(theirs, inTheirs)); err != nil {
				return err
			}
		case Conflicted:
			if w.o.OnConflict == KeepBoth {
				// Kept rather than refused: ours stays where it is and
				// theirs is written beside it. A directory cannot be kept
				// this way — see keepBoth — so that one is still a conflict.
				if as, ok := w.keepBoth(child, name, ours, inOurs, theirs, inTheirs); ok {
					w.p.Kept = append(w.p.Kept, Kept{Path: child, As: as, Kind: kind})
					continue
				}
			}
			w.conflict(child, kind, detail)
		case Same:
			w.p.Unchanged++
		case TakeOurs:
			w.p.TookOurs++
		case TakeTheirs:
			w.p.TookTheirs++
		case Drop:
			// A deletion the other side did not contest. Counted as coming
			// from whichever side deleted it, because that side's change is
			// what the merged tree takes.
			if inOurs {
				w.p.TookTheirs++
			} else {
				w.p.TookOurs++
			}
		}
	}
	return nil
}

// inoOf is an entry's inode, or 0 when the tree does not have it — the
// signal dir() takes for "absent from this side".
func inoOf(e entry, present bool) uint64 {
	if !present {
		return 0
	}
	return e.Node.Inode
}

// keepBoth reports where theirs' copy would go, and whether the conflict
// can be resolved that way at all.
//
// It cannot when either side lacks the path. A modify/delete has only one
// version to keep, so writing "both" would mean resurrecting a file one
// side deleted under a name nobody chose — a decision, not a rescue. And a
// TYPE CHANGE where theirs is a directory would need a whole subtree
// re-parented under a generated name, which is a large surprise to hand
// someone who asked to keep a file.
func (w *walker) keepBoth(path, name string, ours entry, inOurs bool, theirs entry, inTheirs bool) (string, bool) {
	if !inOurs || !inTheirs {
		return "", false
	}
	if theirs.Node.Type == catalog.TypeDir || ours.Node.Type == catalog.TypeDir {
		return "", false
	}
	return pathJoin(path, ConflictName(name, w.o.TheirBranch)), true
}

// pathJoin replaces the last element of a path.
func pathJoin(full, name string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		return full[:i+1] + name
	}
	return name
}

func (w *walker) conflict(p string, k Kind, detail string) {
	w.p.Conflicts = append(w.p.Conflicts, Conflict{Path: p, Kind: k, Detail: detail})
}

// findCollisions reports inode numbers both sides allocated after the
// fork. The cut is exact: NextInode is a high-water mark that never
// reuses a number, so anything at or below the base's was allocated
// before the fork and means the same file on both sides.
func (w *walker) findCollisions() {
	for ino, ourPath := range w.ourInodes {
		if theirPath, ok := w.theirInodes[ino]; ok {
			w.p.Collisions = append(w.p.Collisions, Collision{
				Inode: ino, OursPath: ourPath, TheirsPath: theirPath,
			})
		}
	}
}

// entry is one directory entry with its node.
type entry struct{ Node genfs.Node }

// entries reads one directory, or nothing when the tree does not have it.
func entries(ctx context.Context, fs *genfs.FS, ino uint64) (map[string]entry, error) {
	out := map[string]entry{}
	if fs == nil || ino == 0 {
		return out, nil
	}
	// ReaddirRetain, not Readdir: plain Readdir names entries without
	// making them OPERABLE, because a kernel Lookups before it acts on
	// one. This walker has no kernel doing that for it, so an inode it
	// listed and then asked about would come back stale -- which is
	// exactly what happened. The retaining form is the one written for a
	// walker that descends a whole tree, and it costs two queries per
	// directory instead of three per entry.
	ents, err := fs.ReaddirRetain(ctx, ino)
	if err != nil {
		return nil, fmt.Errorf("merge: readdir inode %d: %w", ino, err)
	}
	for _, e := range ents {
		out[e.Name] = entry{Node: e.Node}
	}
	return out, nil
}

func union(maps ...map[string]entry) []string {
	seen := map[string]struct{}{}
	var names []string
	for _, m := range maps {
		for name := range m {
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// sameEntry compares one path across two trees without reading file
// bodies. It is used for "did this side change it", where an error has to
// mean "assume changed" rather than abort the whole plan: a file whose
// content cannot be read is exactly the case a human should look at.
func sameEntry(ctx context.Context, a *genfs.FS, ae entry, b *genfs.FS, be entry) bool {
	same, err := sameContent(ctx, a, ae, b, be)
	return err == nil && same
}

// sameContent reports whether two files hold the same bytes, WITHOUT
// reading them.
//
// Content addressing is what makes this free: identical content has
// identical chunk identities, so the comparison is over the chunkref
// lists. Metadata is compared too — mode and ownership are part of what a
// merge carries — but a metadata-only difference is still a difference,
// and treating it as one is what keeps `chmod` from being silently lost.
func sameContent(ctx context.Context, a *genfs.FS, ae entry, b *genfs.FS, be entry) (bool, error) {
	if ae.Node.Type != be.Node.Type || ae.Node.Length != be.Node.Length {
		return false, nil
	}
	if ae.Node.Mode != be.Node.Mode || ae.Node.UID != be.Node.UID || ae.Node.GID != be.Node.GID {
		return false, nil
	}
	switch ae.Node.Type {
	case catalog.TypeDir:
		return true, nil // directories are compared by their entries
	case catalog.TypeSymlink:
		at, err := a.Readlink(ctx, ae.Node.Inode)
		if err != nil {
			return false, err
		}
		bt, err := b.Readlink(ctx, be.Node.Inode)
		if err != nil {
			return false, err
		}
		return at == bt, nil
	}
	ac, err := a.ContentOf(ctx, ae.Node.Inode)
	if err != nil {
		return false, err
	}
	bc, err := b.ContentOf(ctx, be.Node.Inode)
	if err != nil {
		return false, err
	}
	return sameRecords(ac, bc), nil
}

func sameRecords(a, b genfs.Content) bool {
	if a.Length != b.Length {
		return false
	}
	if (a.Inline == nil) != (b.Inline == nil) {
		return false
	}
	if a.Inline != nil {
		return bytes.Equal(a.Inline, b.Inline)
	}
	if len(a.Refs) != len(b.Refs) {
		return false
	}
	for i := range a.Refs {
		if !sameRef(a.Refs[i], b.Refs[i]) {
			return false
		}
	}
	return true
}

// sameRef compares two chunkrefs by IDENTITY and extent, not by where the
// bytes sit: two branches that wrote the same content have the same
// identities in different packs, and a merge must call that equal.
func sameRef(a, b catalog.ChunkRef) bool {
	return bytes.Equal(a.Identity, b.Identity) && a.LLen == b.LLen &&
		a.LogicalOffset == b.LogicalOffset
}
