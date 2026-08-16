package overlay

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"math"
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
	err := fs.q.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaNextInode).Scan(&v)
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
// override, staged content, an xattr change, or an edge naming it.
//
// Answered from memory, not SQL. The FUSE binding calls this on every
// lookup to choose entry/attr validity, and profiling showed the query
// form costing more than a whole Lookup (60% of it in SQLite's per-query
// fcntl locking). The overlay performs every mutation itself, so a set
// maintained under the same lock is exactly as authoritative as the
// tables — and it is small by construction: a session's changes, not a
// tree.
func (fs *FS) IsDirty(ino uint64) (bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if err := fs.loadDirtyLocked(); err != nil {
		return false, err
	}
	_, dirty := fs.dirtySet[ino]
	return dirty, nil
}

// loadDirtyLocked seeds the in-memory set on first use, from the tables
// this overlay reopened with (state a previous session left behind).
func (fs *FS) loadDirtyLocked() error {
	if fs.dirtySet != nil {
		return nil
	}
	set := make(map[uint64]struct{})
	for _, q := range []string{
		`SELECT inode FROM onode`,
		`SELECT inode FROM ocontent`,
		`SELECT inode FROM oxattr`,
		`SELECT inode FROM oedge WHERE inode != 0`,
		`SELECT parent FROM oedge`,
	} {
		rows, err := fs.q.Query(q)
		if err != nil {
			return err
		}
		for rows.Next() {
			var ino uint64
			if err := rows.Scan(&ino); err != nil {
				rows.Close() //nolint:errcheck
				return err
			}
			set[ino] = struct{}{}
		}
		if err := closeRows(rows); err != nil {
			return err
		}
	}
	fs.dirtySet = set
	return nil
}

// markDirtyLocked records inodes as dirty and stamps them with this
// operation's modification sequence. Every mutating path calls it with
// the inodes it touched, under the filesystem lock, so neither the set
// nor the sequence map disagrees with the tables.
func (fs *FS) markDirtyLocked(inos ...uint64) {
	fs.bumpSeqLocked(inos...)
	if fs.dirtySet == nil {
		// Not seeded yet; the first IsDirty will read the tables, which
		// by then include this mutation.
		return
	}
	for _, ino := range inos {
		if ino != 0 {
			fs.dirtySet[ino] = struct{}{}
		}
	}
}

// bumpSeqLocked stamps inos as modified by this operation without
// claiming they are dirty. It is the seq half of markDirtyLocked, for
// the inodes an operation REMOVES state from (an unlink target losing a
// link, a replaced rename destination): their rows changed, so a rebase
// must not treat them as published, but the dirty set is derived from
// rows that may no longer exist.
func (fs *FS) bumpSeqLocked(inos ...uint64) {
	fs.seq++
	for _, ino := range inos {
		if ino != 0 {
			fs.modSeq[ino] = fs.seq
		}
	}
}

// modSeqOfLocked reports when an inode was last modified. An inode with
// no entry is state this session did not write — dirt a previous session
// left behind, which no seal of THIS session's snapshots is known to have
// published — so it reads as modified more recently than any snapshot and
// is never rebased away. Conservative by construction: the cost is a
// resumed session keeping its inherited dirt at zero TTLs until it
// touches it again, never a dropped change.
func (fs *FS) modSeqOfLocked(ino uint64) uint64 {
	if v, ok := fs.modSeq[ino]; ok {
		return v
	}
	return math.MaxUint64
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
