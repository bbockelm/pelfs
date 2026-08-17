package overlay

import (
	"database/sql"
	"errors"
)

// The overlay's dirty tables, read as SETS instead of queried per inode.
//
// A seal asks the same handful of questions about every inode in the tree
// — is there an attribute override, is content staged, are there xattrs,
// which directories name it — and each question was a point query. At
// 85,000 inodes that is hundreds of thousands of round trips through one
// SQLite connection, and the connection is the bottleneck: modernc's
// libc puts every allocation the engine makes behind one process-global
// mutex, so the fix is fewer and bigger queries, never more goroutines.
//
// Six full-table scans answer all of it. The tables hold a session's
// changes rather than a tree, so the scans are small in the ordinary case;
// in the case where they are not — an untar, or a chmod of everything —
// they are still one pass over exactly the rows the per-inode queries
// would have visited one at a time.
//
// The cache is armed explicitly (PrepareSeal) because it trades memory for
// queries, and only a caller that is about to read the whole tree should
// make that trade. It is dropped by every transaction, so no mutation can
// be served a stale row: withTx clears it before BEGIN, and re-arming
// needs the filesystem lock the mutation is holding.

type edgeKey struct {
	parent uint64
	name   string
}

// cachedEdge is one oedge row. A zero ino is a whiteout, as in the table.
type cachedEdge struct {
	name string
	ino  uint64
	typ  uint8
}

// cachedXattr is one oxattr row, tombstone included: removal of a base
// attribute is a row, not an absence.
type cachedXattr struct {
	name  string
	value []byte
	tomb  bool
}

type rowCache struct {
	node    map[uint64]onodeRow
	edge    map[edgeKey]cachedEdge
	edgeOf  map[uint64][]cachedEdge // parent -> its rows, sorted by name
	parents map[uint64][]uint64     // inode -> the parents naming it
	xattr   map[uint64][]cachedXattr
	symlink map[uint64]string
	content map[uint64]struct{}
	obase   map[uint64]provEdge
}

// PrepareSeal reads the dirty tables into memory and serves every
// subsequent read from there until ReleaseSeal, or until a mutation drops
// the cache.
//
// It is for a caller that is about to visit the whole tree — a seal — and
// nothing else: the cache is proportional to the dirty state, which after
// an untar is the tree. Arming it twice is a no-op; a mutation in between
// silently returns the filesystem to reading the tables, which is correct
// and merely slower.
func (fs *FS) PrepareSeal() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.rows != nil {
		return nil
	}
	c, err := fs.loadRowCache()
	if err != nil {
		return err
	}
	fs.rows = c
	return nil
}

// ReleaseSeal drops the cache PrepareSeal armed, and its memory with it.
func (fs *FS) ReleaseSeal() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.rows = nil
}

func (fs *FS) loadRowCache() (*rowCache, error) {
	c := &rowCache{
		node:    make(map[uint64]onodeRow),
		edge:    make(map[edgeKey]cachedEdge),
		edgeOf:  make(map[uint64][]cachedEdge),
		parents: make(map[uint64][]uint64),
		xattr:   make(map[uint64][]cachedXattr),
		symlink: make(map[uint64]string),
		content: make(map[uint64]struct{}),
		obase:   make(map[uint64]provEdge),
	}
	rows, err := fs.q.Query(`SELECT inode, type, mode, uid, gid, mtime_ns, ctime_ns,
		nlink, length, rdev, flags, base FROM onode`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r onodeRow
		var base int64
		if err := rows.Scan(&r.Inode, &r.Type, &r.Mode, &r.UID, &r.GID, &r.MtimeNS,
			&r.CtimeNS, &r.Nlink, &r.Length, &r.Rdev, &r.Flags, &base); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		r.base = base != 0
		c.node[r.Inode] = r
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	// Sorted by name so a cached listing is in the same order the indexed
	// query returned, which is what makes the two paths interchangeable.
	rows, err = fs.q.Query(`SELECT parent, name, inode, type FROM oedge ORDER BY parent, name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var parent uint64
		var name []byte
		var e cachedEdge
		if err := rows.Scan(&parent, &name, &e.ino, &e.typ); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		e.name = string(name)
		c.edge[edgeKey{parent: parent, name: e.name}] = e
		c.edgeOf[parent] = append(c.edgeOf[parent], e)
		if e.ino != 0 {
			c.parents[e.ino] = append(c.parents[e.ino], parent)
		}
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode, name, value, tombstone FROM oxattr ORDER BY inode, name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ino uint64
		var name []byte
		var x cachedXattr
		var tomb int64
		if err := rows.Scan(&ino, &name, &x.value, &tomb); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		x.name, x.tomb = string(name), tomb != 0
		c.xattr[ino] = append(c.xattr[ino], x)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode, target FROM osymlink`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ino uint64
		var target []byte
		if err := rows.Scan(&ino, &target); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		c.symlink[ino] = string(target)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode FROM ocontent`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ino uint64
		if err := rows.Scan(&ino); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		c.content[ino] = struct{}{}
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode, parent, name FROM obase`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ino, parent uint64
		var name []byte
		if err := rows.Scan(&ino, &parent, &name); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		c.obase[ino] = provEdge{parent: parent, name: string(name)}
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return c, nil
}

// The cache-aware row readers. Each falls through to its query when no
// cache is armed — which includes every transactional caller, since a
// transaction drops the cache before it begins.
//
// The slice-returning ones hand back the cache's own slice rather than a
// copy, so callers read and never modify. Nothing else may: the rows are a
// frozen answer, and a caller that wanted to change one would be writing,
// which drops the cache anyway.

func (fs *FS) onodeLocked(q querier, ino uint64) (*onodeRow, error) {
	if fs.rows != nil {
		r, ok := fs.rows.node[ino]
		if !ok {
			return nil, nil
		}
		return &r, nil
	}
	return getONode(q, ino)
}

func (fs *FS) stagedLocked(q querier, ino uint64) (bool, error) {
	if fs.rows != nil {
		_, ok := fs.rows.content[ino]
		return ok, nil
	}
	return hasContent(q, ino)
}

func (fs *FS) oxattrLocked(q querier, ino uint64, name string) ([]byte, bool, bool, error) {
	if fs.rows != nil {
		for _, x := range fs.rows.xattr[ino] {
			if x.name == name {
				return x.value, x.tomb, true, nil
			}
		}
		return nil, false, false, nil
	}
	return getOXattr(q, ino, name)
}

// oxattrsOfLocked lists an inode's overlay xattr rows, tombstones included.
func (fs *FS) oxattrsOfLocked(ino uint64) ([]cachedXattr, error) {
	if fs.rows != nil {
		return fs.rows.xattr[ino], nil
	}
	rows, err := fs.q.Query(`SELECT name, tombstone FROM oxattr WHERE inode = ?`, int64(ino))
	if err != nil {
		return nil, err
	}
	var out []cachedXattr
	for rows.Next() {
		var name []byte
		var tomb int64
		if err := rows.Scan(&name, &tomb); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		out = append(out, cachedXattr{name: string(name), tomb: tomb != 0})
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return out, nil
}

// oedgeLocked resolves one overlay edge by name.
func (fs *FS) oedgeLocked(parent uint64, name string) (cachedEdge, bool, error) {
	if fs.rows != nil {
		e, ok := fs.rows.edge[edgeKey{parent: parent, name: name}]
		return e, ok, nil
	}
	var e cachedEdge
	err := fs.q.QueryRow(`SELECT inode, type FROM oedge WHERE parent = ? AND name = ?`,
		int64(parent), []byte(name)).Scan(&e.ino, &e.typ)
	if errors.Is(err, sql.ErrNoRows) {
		return cachedEdge{}, false, nil
	}
	if err != nil {
		return cachedEdge{}, false, err
	}
	e.name = name
	return e, true, nil
}

// oedgesOfLocked lists a directory's overlay edges, whiteouts included,
// sorted by name.
func (fs *FS) oedgesOfLocked(parent uint64) ([]cachedEdge, error) {
	if fs.rows != nil {
		return fs.rows.edgeOf[parent], nil
	}
	rows, err := fs.q.Query(`SELECT name, inode, type FROM oedge WHERE parent = ? ORDER BY name`, int64(parent))
	if err != nil {
		return nil, err
	}
	var out []cachedEdge
	for rows.Next() {
		var name []byte
		var e cachedEdge
		if err := rows.Scan(&name, &e.ino, &e.typ); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		e.name = string(name)
		out = append(out, e)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return out, nil
}

// osymlinkLocked returns an overlay symlink target, if the overlay holds one.
func (fs *FS) osymlinkLocked(ino uint64) (string, bool, error) {
	if fs.rows != nil {
		t, ok := fs.rows.symlink[ino]
		return t, ok, nil
	}
	var target []byte
	err := fs.q.QueryRow(`SELECT target FROM osymlink WHERE inode = ?`, int64(ino)).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(target), true, nil
}

// oedgeParentsLocked lists the directories whose overlay edges name ino.
func (fs *FS) oedgeParentsLocked(ino uint64) ([]uint64, error) {
	if fs.rows != nil {
		return fs.rows.parents[ino], nil
	}
	rows, err := fs.q.Query(`SELECT parent FROM oedge WHERE inode = ?`, int64(ino))
	if err != nil {
		return nil, err
	}
	var out []uint64
	for rows.Next() {
		var parent uint64
		if err := rows.Scan(&parent); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		out = append(out, parent)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return out, nil
}

// obaseLocked returns an inode's persisted original base edge.
func (fs *FS) obaseLocked(q querier, ino uint64) (provEdge, bool, error) {
	if fs.rows != nil {
		pe, ok := fs.rows.obase[ino]
		return pe, ok, nil
	}
	var parent int64
	var name []byte
	err := q.QueryRow(`SELECT parent, name FROM obase WHERE inode = ?`, int64(ino)).Scan(&parent, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return provEdge{}, false, nil
	}
	if err != nil {
		return provEdge{}, false, err
	}
	return provEdge{parent: uint64(parent), name: string(name)}, true, nil
}

// dirtyRowInodesLocked is rowDirtyLocked's answer — every inode with a row
// that makes it differ from the base generation — from the cache. ok is
// false when no cache is armed and the caller must run the six queries.
func (fs *FS) dirtyRowInodesLocked() (map[uint64]struct{}, bool) {
	if fs.rows == nil {
		return nil, false
	}
	set := make(map[uint64]struct{}, len(fs.rows.node))
	for ino := range fs.rows.node {
		set[ino] = struct{}{}
	}
	for ino := range fs.rows.content {
		set[ino] = struct{}{}
	}
	for ino := range fs.rows.xattr {
		set[ino] = struct{}{}
	}
	for ino := range fs.rows.symlink {
		set[ino] = struct{}{}
	}
	for parent, es := range fs.rows.edgeOf {
		set[parent] = struct{}{}
		for _, e := range es {
			if e.ino != 0 {
				set[e.ino] = struct{}{}
			}
		}
	}
	return set, true
}
