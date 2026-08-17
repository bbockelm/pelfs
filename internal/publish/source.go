package publish

import (
	"context"
	"fmt"
	"io"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
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
// empty root of a brand-new volume. Implementations are walked strictly
// by descent —
// Root, then Readdir per directory — so a source whose residency comes
// from lookup order (the overlay over genfs) can establish it on the way
// down.
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

// ---- overlay source ----

// overlaySource seals a phase-3 write overlay: the merged base+dirty view
// IS the generation's contents, so the seal walks it exactly like a cut.
//
// Residency comes from Lookup: genfs serves an inode only after the
// descent that reached it, and overlay.Readdir returns base entries
// WITHOUT establishing residency for them. Every entry is therefore
// re-resolved through Lookup before its inode is used for anything else.
// overlayView is the read surface a seal walks. Both *overlay.FS and
// *overlay.Snapshot satisfy it, so a checkpoint can seal a FROZEN view
// while the mount keeps taking writes — which is what makes rebasing
// inodes back to clean safe (the published generation then corresponds
// to an instant, not to whatever the walk happened to observe).
type overlayView interface {
	RootInode() uint64
	NextInode() (uint64, error)
	Lookup(ctx context.Context, parent uint64, name string) (overlay.Node, error)
	GetAttr(ctx context.Context, ino uint64) (overlay.Node, error)
	Readdir(ctx context.Context, ino uint64) ([]overlay.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	AllXattrs(ctx context.Context, ino uint64) (map[string][]byte, error)
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
	OpenFile(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error)
	BaseRootCatalog() [32]byte
	BaseContent(ctx context.Context, ino uint64) (genfs.Content, bool, error)
}

type overlaySource struct {
	fs overlayView
}

// An overlay knows exactly which inodes it has touched, which is what
// makes the reuse capability answerable at all.
var _ ContentReuser = (*overlaySource)(nil)

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
	des, err := s.fs.Readdir(ctx, ino)
	if err != nil {
		return nil, err
	}
	out := make([]SrcEntry, 0, len(des))
	for _, de := range des {
		n, err := s.fs.Lookup(ctx, ino, de.Name)
		if err != nil {
			return nil, fmt.Errorf("publish: seal lookup %d/%q: %w", ino, de.Name, err)
		}
		out = append(out, SrcEntry{Name: de.Name, Node: srcNodeFromOverlay(n)})
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
	// Both the live overlay and a snapshot stream content themselves;
	// this used to hand-roll positional reads.
	return s.fs.OpenFile(ctx, ino, length)
}

func (s *overlaySource) BaseGeneration() [32]byte { return s.fs.BaseRootCatalog() }

func (s *overlaySource) ExistingContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	return s.fs.BaseContent(ctx, ino)
}

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
