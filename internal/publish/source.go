package publish

import (
	"context"
	"io"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// SrcNode is one inode as TRANSFORM needs it: the catalog's attribute
// set, no more. Type is in the catalog.Type* space — the space the
// persisted schema, genfs, and the overlay all speak — so a source over a
// foreign type space converts at its own edge.
type SrcNode struct {
	Inode   uint64
	Type    uint8
	Mode    uint32
	UID     uint32
	GID     uint32
	MtimeNS int64
	CtimeNS int64
	Nlink   uint32
	Length  int64
	Rdev    uint32
}

// SrcEntry is one directory entry with its child's attributes.
type SrcEntry struct {
	Name string
	Node SrcNode
}

// Source is the tree publish reads: the write overlay under seal, or the
// empty root of a brand-new volume. Implementations are walked strictly by
// descent — Root, then Readdir per directory — so a source whose residency
// comes from lookup order (the overlay over genfs) can establish it on the
// way down.
type Source interface {
	// Root is the inode the walk starts at.
	Root() uint64
	// Readdir lists one directory's entries with attributes. "." and ".."
	// are never included.
	Readdir(ctx context.Context, ino uint64) ([]SrcEntry, error)
	// Stat returns one inode's attributes.
	Stat(ctx context.Context, ino uint64) (SrcNode, error)
	// Readlink returns a symlink's target.
	Readlink(ctx context.Context, ino uint64) (string, error)
	// Xattrs returns an inode's extended attributes.
	Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error)
	// Open streams a file's content sequentially. length is the node's
	// recorded length; the reader must yield exactly that many bytes.
	Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error)
	// NextInode is the allocator high-water mark, or 0 when the source
	// keeps no counter (publish then falls back to max-inode-seen and the
	// previous generation's mark, which never regresses).
	NextInode() uint64
}

// ContentReuser is the optional Source capability that spares TRANSFORM
// from re-deriving content it already published. Without it, every file in
// the tree is opened and pushed through the CDC chunker on every seal —
// and for a source layered over a published generation, "opened" means
// downloading the file back from the federation to rediscover chunk
// identities that generation already records. A timer-driven checkpoint
// then pays that for the whole tree every interval.
//
// Sources that cannot prove a file is untouched simply do not implement
// it.
type ContentReuser interface {
	// BaseGeneration identifies the generation ExistingContent answers
	// from, by root-catalog identity. Publish reuses records only from the
	// generation it is building on; see pipeline.contentReuser for why
	// that restriction is load-bearing rather than tidy.
	BaseGeneration() [32]byte
	// ExistingContent returns ino's already-published content records when
	// the source can prove the file's BYTES are unchanged since
	// BaseGeneration. ok is false when it cannot prove it — attribute
	// changes do not count, a write or truncate does — and the caller
	// reads and re-chunks instead.
	ExistingContent(ctx context.Context, ino uint64) (genfs.Content, bool, error)
}

// ContentProvider is the optional Source capability of a source that has
// ALREADY chunked and uploaded its own content, so TRANSFORM neither
// reads it nor pushes it through CDC. The write path's memtable is the
// one that does this: it packs bytes as they are written, during the
// session, instead of leaving every byte of it to the seal.
//
// It is a sibling of ContentReuser rather than a use of it, and the
// difference is the whole safety argument. Reused records name bytes in
// PREV's packs, which buildSuperblock carries forward verbatim — that is
// why reuse is gated on the source answering from exactly the generation
// being built on. Provided records name bytes in packs THIS session
// uploaded, which no previous superblock lists, so the generation being
// built must list them itself or it is signed and unreadable: a chunkref
// pointing at a pack retention is entitled to delete.
//
// Sources that do not pack their own content simply do not implement it.
type ContentProvider interface {
	// ProvidedContent returns ino's content records when the source has
	// them. ok is false when it does not, and the caller reads and chunks
	// the ordinary way — a redundant chunking costs time, a missing record
	// costs the file.
	ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error)
	// ProvidedPacks are every pack holding bytes ProvidedContent named.
	// Called once, after the last ProvidedContent, because a provider may
	// still be cutting packs while it answers.
	ProvidedPacks(ctx context.Context) ([]packstore.SealedPack, error)
}

// CatalogReuser is the optional Source capability that spares TRANSFORM
// from rebuilding catalogs whose subtree did not change.
//
// ContentReuser stops the seal re-reading file BYTES it already published;
// this stops it re-deriving the STRUCTURE it already published. Without
// it, one new file in an 80k-inode tree rewrites and re-uploads every
// catalog in the volume — tens of megabytes, and the whole tree's worth of
// SQLite, for one row. Catalogs are this format's tree objects, and the
// git property is the target: a change writes the catalogs on the path
// from the changed directory to the root, and nothing else.
//
// Sources that cannot enumerate what they changed simply do not implement
// it.
type CatalogReuser interface {
	// BaseGeneration identifies the generation the answers are relative
	// to, by root-catalog identity — the same gate ContentReuser uses, for
	// the same reason (see pipeline.catalogReuser).
	BaseGeneration() [32]byte
	// DirtyInodes reports every inode the source has touched since
	// BaseGeneration. Completeness is the safety property: an inode
	// missing from this set is one the seal will publish exactly as the
	// base generation did, so a missing entry is a lost change.
	DirtyInodes() (map[uint64]struct{}, error)
	// DirtyScope places those inodes in the namespace: every changed inode
	// plus every ancestor of one. A directory outside it has an unchanged
	// subtree, so the walk can stop there instead of reading it. ok is
	// false when the source cannot place some changed inode, and the seal
	// must then walk everything — a scope with a hole in it would publish
	// a stale subtree silently.
	DirtyScope() (map[uint64]struct{}, bool, error)
}

// ---- overlay source ----

// overlaySource seals a write overlay: the merged base+dirty view IS the
// generation's contents, so the seal walks that view and nothing else.
//
// Residency is the one thing a listing does not carry: genfs serves an
// inode only after the descent that reached it, and an ordinary Readdir
// returns base entries without establishing it. The seal therefore reads
// directories through ReaddirRetain, which lists and makes resident in
// the same pass — the bulk form of the Lookup-per-entry loop the walk
// would otherwise run, at one round trip per name.
//
// overlayView is the read surface a seal walks. Both *overlay.FS and
// *overlay.Snapshot satisfy it, so a checkpoint can seal a FROZEN view
// while the mount keeps taking writes — which is what makes rebasing
// inodes back to clean safe (the published generation then corresponds
// to an instant, not to whatever the walk happened to observe).
type overlayView interface {
	RootInode() uint64
	NextInode() (uint64, error)
	PrepareSeal() error
	ReleaseSeal()
	GetAttr(ctx context.Context, ino uint64) (overlay.Node, error)
	ReaddirRetain(ctx context.Context, ino uint64) ([]overlay.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	AllXattrs(ctx context.Context, ino uint64) (map[string][]byte, error)
	OpenFile(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error)
	BaseRootCatalog() [32]byte
	BaseContent(ctx context.Context, ino uint64) (genfs.Content, bool, error)
	DirtyInodes() (map[uint64]struct{}, error)
	DirtyScope() (map[uint64]struct{}, bool, error)
}

type overlaySource struct {
	fs overlayView
}

// An overlay knows exactly which inodes it has touched, which is what
// makes the reuse capabilities answerable at all.
var (
	_ ContentProvider = (*overlaySource)(nil)
	_ ContentReuser   = (*overlaySource)(nil)
	_ CatalogReuser   = (*overlaySource)(nil)
)

func (s *overlaySource) Root() uint64 { return s.fs.RootInode() }

// NextInode reads the overlay's PERSISTED counter, which includes
// numbers burned by inodes created and then deleted in this session — a
// tree walk cannot see those, and reusing one would break the
// stable-inode contract across generations. Zero (an overlay too old to
// answer) falls back to max-inode-seen.
func (s *overlaySource) NextInode() uint64 {
	n, err := s.fs.NextInode()
	if err != nil {
		return 0
	}
	return n
}

func (s *overlaySource) Readdir(ctx context.Context, ino uint64) ([]SrcEntry, error) {
	des, err := s.fs.ReaddirRetain(ctx, ino)
	if err != nil {
		return nil, err
	}
	out := make([]SrcEntry, 0, len(des))
	for _, de := range des {
		out = append(out, SrcEntry{Name: de.Name, Node: srcNodeFromOverlay(de.Node)})
	}
	return out, nil
}

func (s *overlaySource) Stat(ctx context.Context, ino uint64) (SrcNode, error) {
	n, err := s.fs.GetAttr(ctx, ino)
	if err != nil {
		return SrcNode{}, err
	}
	return srcNodeFromOverlay(n), nil
}

func (s *overlaySource) Readlink(ctx context.Context, ino uint64) (string, error) {
	return s.fs.Readlink(ctx, ino)
}

func (s *overlaySource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	return s.fs.AllXattrs(ctx, ino)
}
func (s *overlaySource) Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	// Both the live overlay and a snapshot stream content themselves, so
	// there is no reason to hand-roll positional reads here.
	return s.fs.OpenFile(ctx, ino, length)
}

func (s *overlaySource) BaseGeneration() [32]byte { return s.fs.BaseRootCatalog() }

// records is the overlay's already-chunked content, when its content
// store has any. A staging overlay has none and the two methods below
// decline, which puts the seal back on the ordinary read-and-chunk path.
func (s *overlaySource) records() (overlay.ContentRecords, bool) {
	fs, ok := s.fs.(interface {
		ContentRecords() (overlay.ContentRecords, bool)
	})
	if !ok {
		return nil, false
	}
	return fs.ContentRecords()
}

func (s *overlaySource) ProvidedContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	r, ok := s.records()
	if !ok {
		return genfs.Content{}, false, nil
	}
	return r.Records(ctx, ino)
}

func (s *overlaySource) ProvidedPacks(ctx context.Context) ([]packstore.SealedPack, error) {
	r, ok := s.records()
	if !ok {
		return nil, nil
	}
	return r.Packs(ctx)
}

func (s *overlaySource) ExistingContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	return s.fs.BaseContent(ctx, ino)
}

func (s *overlaySource) DirtyInodes() (map[uint64]struct{}, error) { return s.fs.DirtyInodes() }

func (s *overlaySource) DirtyScope() (map[uint64]struct{}, bool, error) { return s.fs.DirtyScope() }

func srcNodeFromOverlay(n overlay.Node) SrcNode {
	return SrcNode{
		Inode:   n.Inode,
		Type:    n.Type,
		Mode:    n.Mode,
		UID:     n.UID,
		GID:     n.GID,
		MtimeNS: n.MtimeNS,
		CtimeNS: n.CtimeNS,
		Nlink:   n.Nlink,
		Length:  n.Length,
		Rdev:    n.Rdev,
	}
}

// overlayReader turns the overlay's positional Read into the sequential
// stream the chunker consumes, bounded by the node's recorded length.
