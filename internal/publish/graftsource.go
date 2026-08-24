package publish

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// GraftSource publishes a spidered graft tree as a generation.
//
// It is a Source plus a ContentProvider, and the pairing
// is exactly the shape publish already has a hook for: the write path's
// memtable is a ContentProvider because it packed its own bytes during the
// session, and a graft is a ContentProvider because it never intends to
// pack them at all. Both answer "here are this file's records, do not read
// or chunk it".
//
// The difference is what has to be true afterwards, and ContentProvider's
// own doc comment states it: provided records name bytes no previous
// superblock lists, "so the generation being built must list them itself
// or it is signed and unreadable". For the memtable that statement is
// ProvidedPacks. For a graft there are no packs, and the statement is the
// GraftEntry in publish.Options.Grafts. Which is why ProvidedPacks here
// returns nothing and is not a stub — it is the honest answer, and the
// location is stated somewhere else.
//
// ON ITS OWN it publishes the graft tree over an EMPTY root, which is only
// ever what `pelfs init` then `pelfs graft` wants. Grafting into a volume
// that already has content goes through GraftSpliceSource
// (graftsplice.go), which uses this for the SUBTREE and takes everything
// above it from the previous generation. This type stays the thing that
// turns a spider result into a publishable tree, and knows nothing about
// what it is being spliced into.
type GraftSource struct {
	// mount is the path the tree is grafted at, cleaned and absolute.
	mount string
	nodes map[uint64]*node
	// content is the spidered file per grafted inode; body holds the
	// whole file for the small ones the spider kept (graft.InlineKeep).
	//
	// The chunkref rows are built from it ON DEMAND rather than held: a
	// spider result carries block identities (32 bytes each) and publish
	// asks for one file's rows at a time, so materializing every row up
	// front would triple the resident cost of a large graft for no gain.
	content map[uint64]*graft.File
	body    map[uint64][]byte
	root    uint64
	next    uint64
	uid     uint32
	gid     uint32
	// spine is the inode of each directory ON the mount path, the volume
	// root excluded: spine[0] is the first component, spine[len-1] is the
	// graft root itself.
	//
	// A SPLICE needs them (graftsplice.go). Grafting into a populated
	// volume keeps the inode and the attributes of every directory on the
	// path that the volume ALREADY has, and creates only the ones it does
	// not — so the splice takes the directories it needs from here and
	// ignores the rest, rather than this source deciding.
	spine []uint64
}

type node struct {
	n        SrcNode
	children []SrcEntry
}

// SourceOptions configures the tree a spider result is published as.
type GraftSourceOptions struct {
	// Mount is the path inside the volume the tree lands at.
	Mount string
	// Result is what Spider produced.
	Result *graft.Result
	// UID/GID own every synthesized node. The default is the process
	// running the graft, which is what InitVolume does for a
	// fresh volume's root and for the same reason: ids left at zero make
	// the tree unreadable-or-unwritable to the person who just created it.
	UID, GID uint32
}

// Synthesized metadata. A spider learns size and mtime and nothing else —
// there is no uid, gid or mode at the other end of a Pelican GET.
//
//   - MODE is READ-ONLY, and that is a statement about the graft rather
//     than a default. A grafted file cannot be written in place: the first
//     byte written ungrafts it (memtable.Adopt), so a writable mode would
//     advertise something the tree does not do. 0444/0555 also sidesteps
//     fsperm's first-match-wins rule, which would let a mode like 0044
//     deny the owner (internal/fsperm, and CHANGELOG on the v0.2.0
//     permission change).
//   - OWNERSHIP is the GRAFTING user's, not the source's and not root's.
//     Reporting an upstream uid would be worse than useless: internal/idmap
//     translates exactly ONE identity, the volume root's, so any other
//     recorded uid falls into the other-class arm of the permission check
//     and a plausible upstream 0640 becomes unreadable on every machine.
//     Squashing is normally refused in this codebase because it makes
//     chown invisible (internal/idmap's package comment) — and that
//     objection does not reach here, because a read-only tree has no chown
//     to hide. It is the one place the argument against squashing does not
//     apply.
const (
	GraftFileMode uint32 = 0444
	GraftDirMode  uint32 = 0555
)

// NewSource builds the publishable tree for one spider result.
func NewGraftSource(o GraftSourceOptions) (*GraftSource, error) {
	if o.Result == nil {
		return nil, errors.New("graft: a spider result is required")
	}
	mount := path.Clean("/" + strings.Trim(o.Mount, "/"))
	if mount == "/" {
		return nil, errors.New("graft: refusing to graft at the volume root; name a subdirectory")
	}
	uid, gid := o.UID, o.GID
	if uid == 0 && gid == 0 {
		uid, gid = uint32(os.Getuid()), uint32(os.Getgid())
	}
	s := &GraftSource{
		mount:   mount,
		nodes:   make(map[uint64]*node),
		content: make(map[uint64]*graft.File),
		body:    make(map[uint64][]byte),
		root:    1,
		next:    2,
		uid:     uid,
		gid:     gid,
	}
	s.nodes[1] = &node{n: s.dirNode(1)}
	// Every path the tree needs, directories first so a file never lands
	// under a parent that does not exist yet.
	dirs := map[string]uint64{"/": 1}
	ensure := func(p string) (uint64, error) {
		if ino, ok := dirs[p]; ok {
			return ino, nil
		}
		parent, err := s.mkdirAll(dirs, path.Dir(p))
		if err != nil {
			return 0, err
		}
		return s.mkdir(dirs, parent, p)
	}
	if _, err := s.mkdirAll(dirs, mount); err != nil {
		return nil, err
	}
	comps := splitGraftPath(mount)
	for d := range comps {
		dir := "/" + strings.Join(comps[:d+1], "/")
		ino, ok := dirs[dir]
		if !ok {
			return nil, fmt.Errorf("graft: %s was not created on the mount path", dir)
		}
		s.spine = append(s.spine, ino)
	}
	for i := range o.Result.Files {
		f := &o.Result.Files[i]
		full := path.Join(mount, strings.TrimPrefix(f.Path, "/"))
		parent, err := ensure(path.Dir(full))
		if err != nil {
			return nil, err
		}
		ino := s.next
		s.next++
		n := SrcNode{
			Inode:   ino,
			Type:    catalog.TypeFile,
			Mode:    GraftFileMode,
			UID:     s.uid,
			GID:     s.gid,
			MtimeNS: f.MtimeNS,
			CtimeNS: f.MtimeNS,
			Nlink:   1,
			Length:  f.Size,
		}
		s.nodes[ino] = &node{n: n}
		if f.Body != nil {
			s.body[ino] = f.Body
		} else {
			s.content[ino] = f
		}
		pn := s.nodes[parent]
		pn.children = append(pn.children, SrcEntry{Name: path.Base(full), Node: n})
	}
	for _, nd := range s.nodes {
		sort.Slice(nd.children, func(i, j int) bool { return nd.children[i].Name < nd.children[j].Name })
	}
	return s, nil
}

func (s *GraftSource) dirNode(ino uint64) SrcNode {
	return SrcNode{
		Inode: ino,
		Type:  catalog.TypeDir,
		Mode:  GraftDirMode,
		UID:   s.uid,
		GID:   s.gid,
		Nlink: 2,
	}
}

func (s *GraftSource) mkdirAll(dirs map[string]uint64, p string) (uint64, error) {
	p = path.Clean(p)
	if ino, ok := dirs[p]; ok {
		return ino, nil
	}
	parent, err := s.mkdirAll(dirs, path.Dir(p))
	if err != nil {
		return 0, err
	}
	return s.mkdir(dirs, parent, p)
}

func (s *GraftSource) mkdir(dirs map[string]uint64, parent uint64, p string) (uint64, error) {
	ino := s.next
	s.next++
	n := s.dirNode(ino)
	s.nodes[ino] = &node{n: n}
	dirs[p] = ino
	pn, ok := s.nodes[parent]
	if !ok {
		return 0, fmt.Errorf("graft: no parent inode %d for %s", parent, p)
	}
	pn.children = append(pn.children, SrcEntry{Name: path.Base(p), Node: n})
	return ino, nil
}

// Mount is where the tree lands.
func (s *GraftSource) Mount() string { return s.mount }

// MountInode is the inode of the grafted tree's ROOT directory — the one
// that lands at Mount(). A splice publishes this subtree and nothing above
// it (graftsplice.go).
func (s *GraftSource) MountInode() uint64 {
	if len(s.spine) == 0 {
		return 0
	}
	return s.spine[len(s.spine)-1]
}

// SpineInode is the inode this source minted for the directory at depth d
// of the mount path (d == 0 is the first component). A splice uses it only
// for a directory the volume does not already have.
func (s *GraftSource) SpineInode(d int) uint64 {
	if d < 0 || d >= len(s.spine) {
		return 0
	}
	return s.spine[d]
}

// splitGraftPath is the mount path's components, root excluded.
func splitGraftPath(mount string) []string {
	t := strings.Trim(mount, "/")
	if t == "" {
		return nil
	}
	return strings.Split(t, "/")
}

// Files is how many grafted files the tree holds.
func (s *GraftSource) Files() int { return len(s.content) }

func (s *GraftSource) Root() uint64      { return s.root }
func (s *GraftSource) NextInode() uint64 { return s.next }

func (s *GraftSource) Readdir(_ context.Context, ino uint64) ([]SrcEntry, error) {
	nd, ok := s.nodes[ino]
	if !ok {
		return nil, fmt.Errorf("graft: no inode %d", ino)
	}
	return nd.children, nil
}

func (s *GraftSource) Stat(_ context.Context, ino uint64) (SrcNode, error) {
	nd, ok := s.nodes[ino]
	if !ok {
		return SrcNode{}, fmt.Errorf("graft: no inode %d", ino)
	}
	return nd.n, nil
}

func (s *GraftSource) Readlink(context.Context, uint64) (string, error) {
	// A spider sees objects, not links: Pelican's namespace has no symlink
	// to report. A grafted tree therefore has none, which is a real
	// fidelity loss where the source was made by publishing a POSIX tree,
	// and is called out in the design doc rather than papered over.
	return "", errors.New("graft: a grafted tree has no symlinks")
}

func (s *GraftSource) Xattrs(context.Context, uint64) (map[string][]byte, error) { return nil, nil }

// Open serves only the small files the spider kept whole
// (graft.InlineKeep). Every other file is answered by ProvidedContent, and
// a graft has no bytes to hand over for those — handing them over is
// precisely what it exists not to do.
//
// Reaching the error means a caller set InlineMax above what the spider
// retained, so publish wants to inline a file whose bytes nobody has. That
// is a configuration mismatch rather than a corrupt tree, and it says so.
func (s *GraftSource) Open(_ context.Context, ino uint64, _ int64) (io.ReadCloser, error) {
	if b, ok := s.body[ino]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return nil, fmt.Errorf("graft: publish asked to read inode %d, which the spider did not keep "+
		"whole (files over %d bytes are grafted, not inlined); lower InlineMax or raise "+
		"graft.InlineKeep", ino, graft.InlineKeep)
}

// ProvidedContent hands publish the grafted file's records.
//
// External is set, and it is the flag that makes the rest of the system
// behave: it keeps these identities out of the dedup set (publish's
// rememberExcept) and makes a later write to the file materialize it
// instead of adopting it by reference (memtable.Adopt).
func (s *GraftSource) ProvidedContent(_ context.Context, ino uint64) (genfs.Content, bool, error) {
	nd, known := s.nodes[ino]
	if !known {
		return genfs.Content{}, false, nil
	}
	if b, ok := s.body[ino]; ok {
		// Inlined, so NOT external: these bytes land in the catalog, are
		// covered by its identity and the superblock signature, and do not
		// depend on the source. Marking them external would wrongly keep
		// them out of the dedup set and wrongly force a copy-up on write.
		return genfs.Content{Length: nd.n.Length, Inline: b}, true, nil
	}
	f, ok := s.content[ino]
	if !ok {
		return genfs.Content{}, false, nil
	}
	return genfs.Content{Length: nd.n.Length, Refs: f.Refs(), External: true}, true, nil
}

// ProvidedPacks is empty, and that is the answer rather than a stub: a
// graft uploads no packs. Where the memtable's packs are this generation's
// statement of location, a graft's statement is publish.Options.Grafts.
func (s *GraftSource) ProvidedPacks(context.Context) ([]packstore.SealedPack, error) { return nil, nil }

// ProvidedEntries reports nothing, for the same reason. The multi-pack
// index answers "which pack holds this identity", and no pack does.
func (s *GraftSource) ProvidedEntries(func(identityHex, pack string)) {}

// InodeMark keeps the allocator honest: the tree's inodes were minted here
// rather than inferred from a walk.
func (s *GraftSource) InodeMark() uint64 { return s.next }

var (
	_ Source          = (*GraftSource)(nil)
	_ ContentProvider = (*GraftSource)(nil)
)
