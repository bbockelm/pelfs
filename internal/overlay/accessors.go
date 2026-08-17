package overlay

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"math"
	"strconv"

	"github.com/bbockelm/pelfs/internal/genfs"
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

// DirtyInodes reports every inode this overlay has touched since the base
// generation: attribute overrides, staged content, xattr changes, and
// both halves of every changed name (the parent whose listing moved, and
// the inode a name binds).
//
// A seal uses it for the converse of what the overlay usually answers: an
// inode NOT in this set is what the base generation published, so a
// catalog covering only such inodes is what the base generation published
// too, and can be carried forward by reference instead of rebuilt. That
// inference makes completeness load-bearing in a way IsDirty's use
// (picking a FUSE attribute TTL) never was — so this reads the tables
// instead of trusting the memoized set alone. Operations that REMOVE
// state, such as an unlink decrementing a surviving hardlink's nlink,
// write an onode row without adding to that set: harmless for a TTL, a
// lost change here. The union of both is the answer that cannot miss.
func (fs *FS) DirtyInodes() (map[uint64]struct{}, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	set, err := fs.rowDirtyLocked()
	if err != nil {
		return nil, err
	}
	for ino := range fs.dirtySet {
		set[ino] = struct{}{}
	}
	return set, nil
}

// DirtyScope reports the part of the namespace a seal has to descend
// into: every inode with a changed row, plus every ancestor of one. A
// directory outside it has nothing changed anywhere beneath it, so the
// seal can decline to read it at all.
//
// This is DirtyInodes turned into a shape a walk can use. It is built
// from the TABLES only, not from the memoized set: an inode that appears
// there with no row left is one whose overlay state was removed, which
// means it either left the namespace entirely or reverted to what the
// base holds — neither can change a catalog, and neither can be placed in
// the tree. Placement runs from each changed inode upward, through
// overlay edges first (the authority when a name moved), then the base
// edge this session descended, then the persisted base chain, then base
// residency.
//
// ok is false when some changed inode cannot be placed at all — an
// overlay reopened in a later session may have forgotten the descent that
// reached it. The caller must then walk everything; a scope with a hole
// in it would silently publish a stale subtree, which is the one outcome
// worth any amount of extra walking to avoid.
func (fs *FS) DirtyScope() (map[uint64]struct{}, bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	changed, err := fs.rowDirtyLocked()
	if err != nil {
		return nil, false, err
	}
	scope := make(map[uint64]struct{}, 4*len(changed))
	scope[RootInode] = struct{}{}
	var place func(ino uint64, depth int) (bool, error)
	place = func(ino uint64, depth int) (bool, error) {
		if _, seen := scope[ino]; seen {
			return true, nil
		}
		if depth > maxBaseChainDepth {
			return false, nil
		}
		parents, err := fs.parentsOfLocked(ino)
		if err != nil {
			return false, err
		}
		if len(parents) == 0 {
			return false, nil
		}
		scope[ino] = struct{}{}
		for _, parent := range parents {
			ok, err := place(parent, depth+1)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
	for ino := range changed {
		ok, err := place(ino, 0)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
	}
	return scope, true, nil
}

// rowDirtyLocked is the table half of DirtyInodes: inodes with a row that
// makes them differ from the base generation.
func (fs *FS) rowDirtyLocked() (map[uint64]struct{}, error) {
	if set, ok := fs.dirtyRowInodesLocked(); ok {
		return set, nil
	}
	set := make(map[uint64]struct{})
	for _, q := range []string{
		`SELECT inode FROM onode`,
		`SELECT inode FROM ocontent`,
		`SELECT inode FROM oxattr`,
		`SELECT inode FROM osymlink`,
		`SELECT inode FROM oedge WHERE inode != 0`,
		`SELECT parent FROM oedge`,
	} {
		rows, err := fs.q.Query(q)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ino uint64
			if err := rows.Scan(&ino); err != nil {
				rows.Close() //nolint:errcheck
				return nil, err
			}
			set[ino] = struct{}{}
		}
		if err := closeRows(rows); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// parentsOfLocked lists the directories that name ino in the merged view.
// Empty means "cannot say", never "none": the root answers itself.
//
// Every source is consulted, not the first that answers, because they can
// disagree legitimately — a hardlinked inode has several names, and an
// inode renamed away from its base path has both an overlay edge and a
// base chain. Over-reporting a parent only widens the scope.
func (fs *FS) parentsOfLocked(ino uint64) ([]uint64, error) {
	if ino == RootInode {
		return []uint64{RootInode}, nil
	}
	var out []uint64
	seen := make(map[uint64]bool)
	add := func(p uint64) {
		if p != 0 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	parents, err := fs.oedgeParentsLocked(ino)
	if err != nil {
		return nil, err
	}
	for _, parent := range parents {
		add(parent)
	}
	if pe, ok := fs.prov[ino]; ok {
		add(pe.parent)
	}
	if pe, ok, err := fs.obaseLocked(fs.q, ino); err != nil {
		return nil, err
	} else if ok {
		add(pe.parent)
	}
	if len(out) == 0 {
		if p, err := fs.base.Parent(ino); err == nil {
			add(p)
		}
	}
	return out, nil
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
// resumed session keeping its inherited dirt at the short dirty TTL
// until it touches it again, never a dropped change.
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

// BaseRootCatalog is the root-catalog identity of the generation this
// overlay shadows. A seal uses it to confirm that the generation it is
// building on is the same one BaseContent answers from.
func (fs *FS) BaseRootCatalog() [32]byte { return fs.base.RootCatalog() }

// BaseContent returns the base generation's content records for ino when
// this overlay has provably not changed the file's bytes; ok is false when
// it has, or when the overlay cannot prove it hasn't. The caller then reads
// and re-chunks, which is always correct and merely slower.
//
// The proof is structural, not a comparison of bytes:
//
//   - Every content mutation stages the file first (write.go,
//     materializeContentLocked): a write, a truncate in either direction,
//     and an overlay-created file all leave an ocontent row before the
//     mutation commits. No ocontent row therefore means no byte of this
//     inode has been written through this overlay.
//   - An overlay-NEW inode has no records in the base at all, so a
//     non-base onode row disqualifies it even though a fresh file always
//     stages too.
//
// Attribute-only changes — chmod, chown, utimens, a link count moving —
// materialize an onode row and no ocontent row, so they correctly do NOT
// force a re-chunk. The new catalog still records them: they come from the
// merged attributes the walk collected, not from here.
func (fs *FS) BaseContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	staged, err := fs.stagedLocked(fs.q, ino)
	if err != nil || staged {
		return genfs.Content{}, false, err
	}
	row, err := fs.onodeLocked(fs.q, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	if row != nil && !row.base {
		return genfs.Content{}, false, nil
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
		return genfs.Content{}, false, err
	}
	c, err := fs.base.ContentOf(ctx, ino)
	if err != nil {
		// Not softened into "cannot prove it": the fallback path reads the
		// same inode through the same base, so anything that fails here
		// fails there too, only after a download's worth of latency.
		return genfs.Content{}, false, err
	}
	return c, true, nil
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
