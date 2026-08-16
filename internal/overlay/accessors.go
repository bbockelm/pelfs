package overlay

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"strconv"
)

// Accessors that exist because consumers were forced to reimplement them:
// seal reconstructed the inode counter from the tree, the FUSE binding
// maintained its own dirty set to pick TTLs, and both built ad-hoc
// readers. Each one here replaces a documented workaround.

// NextInode reports the persisted allocator high-water mark. Seal records
// it in the superblock so the next generation's writers never reuse a
// number — including numbers burned by inodes this overlay created and
// then deleted, which a tree walk cannot see.
func (fs *FS) NextInode() (uint64, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var v string
	err := fs.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaNextInode).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, errors.New("overlay: next_inode missing from meta")
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// IsDirty reports whether this overlay has touched the inode: an attr
// override, staged content, an xattr change, or an edge naming it. The
// FUSE binding needs exactly this per Lookup to choose entry/attr
// validity — infinite for clean inodes, zero for dirty ones — and a full
// Dirty() dump is far too heavy for a per-lookup decision.
func (fs *FS) IsDirty(ino uint64) (bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	const q = `SELECT EXISTS(SELECT 1 FROM onode    WHERE inode  = ?1)
	             OR EXISTS(SELECT 1 FROM ocontent WHERE inode  = ?1)
	             OR EXISTS(SELECT 1 FROM oxattr   WHERE inode  = ?1)
	             OR EXISTS(SELECT 1 FROM oedge    WHERE inode  = ?1 OR parent = ?1)`
	var dirty bool
	if err := fs.db.QueryRow(q, ino).Scan(&dirty); err != nil {
		return false, err
	}
	return dirty, nil
}

// AllXattrs returns every visible xattr of an inode in one pass, honoring
// overlay tombstones. ListXattr followed by a GetXattr per name takes the
// filesystem lock once per attribute; seal reads every inode's xattrs, so
// that multiplied out across a whole tree.
func (fs *FS) AllXattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	names, err := fs.ListXattr(ctx, ino)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		v, err := fs.GetXattr(ctx, ino, name)
		if errors.Is(err, ErrNotExist) {
			continue // raced with a removal; absent is the honest answer
		}
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

// OpenFile returns a sequential reader over an inode's whole content,
// merged view. Callers that stream a file (seal chunking it into packs)
// otherwise hand-roll positional reads.
func (fs *FS) OpenFile(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	if _, err := fs.GetAttr(ctx, ino); err != nil {
		return nil, err
	}
	return &fileReader{ctx: ctx, fs: fs, ino: ino, remaining: length}, nil
}

type fileReader struct {
	ctx       context.Context
	fs        *FS
	ino       uint64
	off       int64
	remaining int64
}

func (r *fileReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.fs.Read(r.ctx, r.ino, r.off, p)
	r.off += int64(n)
	r.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return n, nil
}

func (r *fileReader) Close() error { return nil }
