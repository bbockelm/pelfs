package publish

import (
	"context"
	"fmt"
	"io"

	"github.com/juicedata/juicefs/pkg/meta"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/cutdb"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// SrcNode is one inode as TRANSFORM needs it: the v2 catalog's attribute
// set, no more. Type is in the catalog.Type* space — the space the
// persisted schema, genfs, and the overlay all speak — so a source over a
// foreign type space (JuiceFS meta.Type*) converts at its own edge.
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

// Source is the tree publish reads: a JuiceFS cut today, a phase-3
// overlay under seal. Implementations are walked strictly by descent —
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

// ---- cut source ----

// cutSource reads a VACUUM'd JuiceFS metadata cut. cutdb exposes only a
// whole-tree BFS Walk, so the edge map is materialized once, on first
// Readdir, and served per directory afterwards; the pipeline sorts every
// directory by name, so BFS-vs-descent ordering is not observable.
type cutSource struct {
	db   *cutdb.DB
	dirs map[uint64][]SrcEntry
	next uint64
}

func newCutSource(db *cutdb.DB) *cutSource {
	s := &cutSource{db: db}
	// The cut's real allocator counter: reconstructing it as max-inode-seen
	// loses numbers burned by files deleted before the cut, and inode reuse
	// across generations would break the stable-inode contract. A counter
	// table the engine has not written yet leaves 0 (the fallback).
	if v, err := db.Counter("nextInode"); err == nil && v > 0 {
		s.next = uint64(v)
	}
	return s
}

func (s *cutSource) Root() uint64 { return cutdb.RootInode }

func (s *cutSource) NextInode() uint64 { return s.next }

func (s *cutSource) load(ctx context.Context) error {
	if s.dirs != nil {
		return nil
	}
	dirs := make(map[uint64][]SrcEntry)
	if err := s.db.Walk(ctx, func(parent uint64, name string, n cutdb.Node) error {
		sn, err := srcNodeFromCut(n)
		if err != nil {
			return err
		}
		dirs[parent] = append(dirs[parent], SrcEntry{Name: name, Node: sn})
		return nil
	}); err != nil {
		return err
	}
	s.dirs = dirs
	return nil
}

func (s *cutSource) Readdir(ctx context.Context, ino uint64) ([]SrcEntry, error) {
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return s.dirs[ino], nil
}

func (s *cutSource) Stat(ctx context.Context, ino uint64) (SrcNode, error) {
	n, err := s.db.Stat(ctx, ino)
	if err != nil {
		return SrcNode{}, err
	}
	return srcNodeFromCut(n)
}

func (s *cutSource) Readlink(ctx context.Context, ino uint64) (string, error) {
	return s.db.Readlink(ctx, ino)
}

func (s *cutSource) Xattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	return s.db.Xattrs(ctx, ino)
}

func (s *cutSource) Open(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	rd, err := s.db.FileReader(ctx, ino, uint64(length))
	if err != nil {
		return nil, err
	}
	return io.NopCloser(rd), nil
}

func srcNodeFromCut(n cutdb.Node) (SrcNode, error) {
	typ, err := catTypeFromMeta(n.Type)
	if err != nil {
		return SrcNode{}, err
	}
	return SrcNode{
		Inode:   n.Inode,
		Type:    typ,
		Mode:    uint32(n.Mode),
		UID:     n.Uid,
		GID:     n.Gid,
		MtimeNS: n.MtimeNs,
		CtimeNS: n.CtimeNs,
		Nlink:   n.Nlink,
		Length:  int64(n.Length),
		Rdev:    n.Rdev,
	}, nil
}

// catTypeFromMeta maps the JuiceFS type space onto the catalog's. The
// values coincide today; the switch is the contract, not an optimization.
func catTypeFromMeta(t uint8) (uint8, error) {
	switch t {
	case meta.TypeFile:
		return catalog.TypeFile, nil
	case meta.TypeDirectory:
		return catalog.TypeDir, nil
	case meta.TypeSymlink:
		return catalog.TypeSymlink, nil
	case meta.TypeFIFO:
		return catalog.TypeFIFO, nil
	case meta.TypeBlockDev:
		return catalog.TypeBlockDev, nil
	case meta.TypeCharDev:
		return catalog.TypeCharDev, nil
	case meta.TypeSocket:
		return catalog.TypeSocket, nil
	}
	return 0, fmt.Errorf("publish: unknown inode type %d", t)
}

// ---- overlay source ----

// overlaySource seals a phase-3 write overlay: the merged base+dirty view
// IS the generation's contents, so the seal walks it exactly like a cut.
//
// Residency comes from Lookup: genfs serves an inode only after the
// descent that reached it, and overlay.Readdir returns base entries
// WITHOUT establishing residency for them. Every entry is therefore
// re-resolved through Lookup before its inode is used for anything else.
type overlaySource struct {
	fs *overlay.FS
}

func (s *overlaySource) Root() uint64 { return overlay.RootInode }

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
	return &overlayReader{ctx: ctx, fs: s.fs, ino: ino, end: length}, nil
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
type overlayReader struct {
	ctx context.Context
	fs  *overlay.FS
	ino uint64
	off int64
	end int64
}

func (r *overlayReader) Read(p []byte) (int, error) {
	if r.off >= r.end {
		return 0, io.EOF
	}
	if int64(len(p)) > r.end-r.off {
		p = p[:r.end-r.off]
	}
	n, err := r.fs.Read(r.ctx, r.ino, r.off, p)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("publish: inode %d read 0 bytes at offset %d of %d", r.ino, r.off, r.end)
	}
	r.off += int64(n)
	return n, nil
}

func (r *overlayReader) Close() error { return nil }
