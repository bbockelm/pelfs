// Package cutdb reads a publish cut: the instant VACUUM-INTO copy of the
// JuiceFS SQLite metadata that defines what a v2 publish contains
// (docs/design-packfs.md, "the cut"). It exposes the tree walk, per-file
// extent maps, and sequential file content — everything the publish
// pipeline's RECONCILE and TRANSFORM stages consume — without mounting.
//
// The cut copy is private to the publishing session, so opening it with a
// (session-writing) meta client is safe; the original live database is
// never touched through this package.
package cutdb

import (
	"context"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/juicedata/juicefs/pkg/chunk"
	"github.com/juicedata/juicefs/pkg/meta"
	"github.com/juicedata/juicefs/pkg/object"
	"github.com/prometheus/client_golang/prometheus"
)

// Node is the subset of JuiceFS attributes the v2 catalog schema persists
// (no atime, by design).
type Node struct {
	Inode   uint64
	Type    uint8 // meta.TypeFile, TypeDirectory, TypeSymlink, ...
	Mode    uint16
	Uid     uint32
	Gid     uint32
	MtimeNs int64
	CtimeNs int64
	Nlink   uint32
	Length  uint64
	Rdev    uint32
}

// Extent is one resolved, visible run of file content: JuiceFS slice
// overlays are already flattened by the metadata engine, so extents are
// disjoint and in file order within each chunk. SliceID zero is a hole of
// Len zero bytes.
type Extent struct {
	SliceID   uint64
	SliceSize uint32 // full size of the backing slice object
	Off       uint32 // offset of this extent within the slice
	Len       uint32
}

// DB is an open cut.
type DB struct {
	m         meta.Meta
	format    *meta.Format
	store     chunk.ChunkStore
	chunkSize uint64
}

// Options configures Open.
type Options struct {
	// Blob is the block store the volume's slices live in (with the same
	// wrappers — packstore, encryption — the session applies). Required
	// only when file content will be read; nil is fine for pure metadata
	// walks.
	Blob object.ObjectStorage
	// CacheDir backs the chunk store's block cache. Publish should pass
	// the session's cache dir so TRANSFORM reads hit blocks the writer
	// just produced instead of re-fetching them.
	CacheDir string
}

// Open opens the cut database at metaPath.
func Open(metaPath string, o Options) (*DB, error) {
	conf := meta.DefaultConf()
	conf.NoBGJob = true
	conf.ReadOnly = true
	m := meta.NewClient("sqlite3://"+metaPath, conf)
	format, err := m.Load(true)
	if err != nil {
		return nil, fmt.Errorf("load cut metadata: %w", err)
	}
	if err := m.NewSession(false); err != nil {
		return nil, fmt.Errorf("cut metadata session: %w", err)
	}
	db := &DB{m: m, format: format, chunkSize: uint64(meta.ChunkSize)}
	if o.Blob != nil {
		cc := chunk.Config{
			BlockSize:  format.BlockSize * 1024,
			Compress:   format.Compression,
			HashPrefix: format.HashPrefix,

			GetTimeout:  time.Minute,
			MaxUpload:   1, // read-only consumer; the writer knob is unused
			MaxDownload: 100,
			MaxRetries:  10,
			BufferSize:  64 << 20,

			CacheDir:       o.CacheDir,
			CacheMode:      0600,
			CacheFullBlock: true,
		}
		if o.CacheDir == "" {
			cc.CacheDir = "memory"
			cc.CacheSize = 64 << 20
		}
		db.store = chunk.NewCachedStore(o.Blob, cc, prometheus.NewRegistry())
	}
	return db, nil
}

// Close releases the metadata session.
func (db *DB) Close() error {
	return db.m.CloseSession()
}

// Format reports the volume format of the cut.
func (db *DB) Format() *meta.Format { return db.format }

// RootInode is the tree root of every JuiceFS volume.
const RootInode = uint64(meta.RootInode)

// Walk visits every edge reachable from the root in breadth-first order:
// fn(parent, name, node) for each directory entry. Attributes ride along
// with the readdir, so a full-tree walk is one query per directory.
func (db *DB) Walk(ctx context.Context, fn func(parent uint64, name string, n Node) error) error {
	c := meta.WrapContext(ctx)
	queue := []meta.Ino{meta.RootInode}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		var entries []*meta.Entry
		if st := db.m.Readdir(c, dir, 1, &entries); st != 0 {
			return fmt.Errorf("readdir inode %d: %s", dir, st)
		}
		for _, e := range entries {
			name := string(e.Name)
			if name == "." || name == ".." {
				continue
			}
			n := nodeFromAttr(uint64(e.Inode), e.Attr)
			if err := fn(uint64(dir), name, n); err != nil {
				return err
			}
			if e.Attr.Typ == meta.TypeDirectory {
				queue = append(queue, e.Inode)
			}
		}
	}
	return nil
}

// Stat returns the attributes of one inode.
func (db *DB) Stat(ctx context.Context, inode uint64) (Node, error) {
	var attr meta.Attr
	if st := db.m.GetAttr(meta.WrapContext(ctx), meta.Ino(inode), &attr); st != 0 {
		return Node{}, fmt.Errorf("stat inode %d: %s", inode, st)
	}
	return nodeFromAttr(inode, &attr), nil
}

// Readlink returns a symlink's target.
func (db *DB) Readlink(ctx context.Context, inode uint64) (string, error) {
	var target []byte
	if st := db.m.ReadLink(meta.WrapContext(ctx), meta.Ino(inode), &target); st != 0 {
		return "", fmt.Errorf("readlink inode %d: %s", inode, st)
	}
	return string(target), nil
}

// Xattrs returns an inode's extended attributes.
func (db *DB) Xattrs(ctx context.Context, inode uint64) (map[string][]byte, error) {
	c := meta.WrapContext(ctx)
	var names []byte
	if st := db.m.ListXattr(c, meta.Ino(inode), &names); st != 0 {
		if st == meta.ENOATTR || st == syscall.ENODATA {
			return nil, nil
		}
		return nil, fmt.Errorf("listxattr inode %d: %s", inode, st)
	}
	out := make(map[string][]byte)
	start := 0
	for i := 0; i <= len(names); i++ {
		if i == len(names) || names[i] == 0 {
			if i > start {
				name := string(names[start:i])
				var value []byte
				if st := db.m.GetXattr(c, meta.Ino(inode), name, &value); st == 0 {
					out[name] = value
				}
			}
			start = i + 1
		}
	}
	return out, nil
}

// Extents returns the resolved extent list of a file, in file order,
// including explicit holes (SliceID zero). The sum of extent lengths
// always equals the file length.
func (db *DB) Extents(ctx context.Context, inode, length uint64) ([]Extent, error) {
	if length == 0 {
		return nil, nil
	}
	c := meta.WrapContext(ctx)
	var out []Extent
	nchunks := (length + db.chunkSize - 1) / db.chunkSize
	for indx := uint64(0); indx < nchunks; indx++ {
		want := db.chunkSize
		if indx == nchunks-1 {
			want = length - indx*db.chunkSize
		}
		var slices []meta.Slice
		if st := db.m.Read(c, meta.Ino(inode), uint32(indx), &slices); st != 0 && st != syscall.ENOENT {
			return nil, fmt.Errorf("read chunk map %d/%d: %s", inode, indx, st)
		}
		var got uint64
		for _, s := range slices {
			if got >= want {
				break
			}
			l := uint64(s.Len)
			if got+l > want {
				l = want - got
			}
			out = append(out, Extent{SliceID: s.Id, SliceSize: s.Size, Off: s.Off, Len: uint32(l)})
			got += l
		}
		if got < want {
			// Trailing hole the engine did not materialize as a slice.
			out = append(out, Extent{Len: uint32(want - got)})
		}
	}
	return out, nil
}

// FileReader streams a file's content sequentially (holes read as
// zeros). Requires Open with a Blob store.
func (db *DB) FileReader(ctx context.Context, inode, length uint64) (io.Reader, error) {
	if db.store == nil {
		return nil, fmt.Errorf("cut opened without a block store")
	}
	exts, err := db.Extents(ctx, inode, length)
	if err != nil {
		return nil, err
	}
	return &fileReader{ctx: ctx, store: db.store, extents: exts}, nil
}

const readSegment = 1 << 20

type fileReader struct {
	ctx     context.Context
	store   chunk.ChunkStore
	extents []Extent
	buf     []byte // unread tail of the current segment
}

func (r *fileReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if len(r.extents) == 0 {
			return 0, io.EOF
		}
		ext := &r.extents[0]
		if ext.Len == 0 {
			r.extents = r.extents[1:]
			continue
		}
		n := uint32(readSegment)
		if ext.Len < n {
			n = ext.Len
		}
		seg := make([]byte, n)
		if ext.SliceID == 0 {
			// Hole: zeros, no store round trip.
		} else {
			page := chunk.NewPage(seg)
			_, err := r.store.NewReader(ext.SliceID, int(ext.SliceSize)).ReadAt(r.ctx, page, int(ext.Off))
			page.Release()
			if err != nil {
				return 0, fmt.Errorf("read slice %d [%d,+%d): %w", ext.SliceID, ext.Off, n, err)
			}
		}
		ext.Off += n
		ext.Len -= n
		r.buf = seg
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func nodeFromAttr(inode uint64, a *meta.Attr) Node {
	return Node{
		Inode:   inode,
		Type:    a.Typ,
		Mode:    a.Mode,
		Uid:     a.Uid,
		Gid:     a.Gid,
		MtimeNs: a.Mtime*1e9 + int64(a.Mtimensec),
		CtimeNs: a.Ctime*1e9 + int64(a.Ctimensec),
		Nlink:   a.Nlink,
		Length:  a.Length,
		Rdev:    a.Rdev,
	}
}
