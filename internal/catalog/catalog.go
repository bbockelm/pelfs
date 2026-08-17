// Package catalog implements the v2 path-catalog format
// (docs/design-packfs.md, "Catalog schema (v2)"): a self-contained SQLite
// database covering one subtree of the namespace, packed and
// content-addressed by the layers above.
//
// Catalogs are write-once build artifacts — a Writer builds one with
// journaling and syncing disabled (crash safety is the publisher's problem;
// a half-built catalog is simply rebuilt), then the file is immutable
// forever. Readers open it read-only.
//
// Schema constraints carried from the design doc:
//   - node has NO atime column (scratch volumes run noatime; persisting
//     atime would dirty catalogs on read).
//   - chunkref stores no logical offsets; they are prefix sums of llen
//     computed at load. Holes in sparse files are rows with NULL identity
//     and llen = hole length.
//   - catalog_meta self-identifies the catalog (volume UUID, covered path,
//     generation, format version, identity algo) so rescue can reassemble
//     the tree from packs alone.
//   - Tables with natural keys are WITHOUT ROWID; the inode-keyed tables
//     use INTEGER PRIMARY KEY (the rowid), which SQLite handles better
//     than a WITHOUT ROWID integer key.
package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	_ "modernc.org/sqlite"
)

// FormatVersion is the catalog format this package reads and writes.
const FormatVersion = 1

// Node/edge types, shared by node.type and edge.type.
const (
	TypeFile     = 1
	TypeDir      = 2
	TypeSymlink  = 3
	TypeFIFO     = 4
	TypeBlockDev = 5
	TypeCharDev  = 6
	TypeSocket   = 7
)

// ErrNotExist is returned by lookups that find no matching row.
var ErrNotExist = errors.New("catalog: entry does not exist")

// catalog_meta keys.
const (
	metaVolumeUUID    = "volume_uuid"
	metaCoveredPath   = "covered_path"
	metaGeneration    = "generation"
	metaFormatVersion = "format_version"
	metaIdentityAlgo  = "identity_algo"
)

const schema = `
CREATE TABLE catalog_meta (
	key   TEXT PRIMARY KEY,
	value BLOB
) WITHOUT ROWID;
CREATE TABLE node (
	inode    INTEGER PRIMARY KEY,
	type     INTEGER NOT NULL,
	mode     INTEGER NOT NULL,
	uid      INTEGER NOT NULL,
	gid      INTEGER NOT NULL,
	mtime_ns INTEGER NOT NULL,
	ctime_ns INTEGER NOT NULL,
	nlink    INTEGER NOT NULL,
	length   INTEGER NOT NULL,
	rdev     INTEGER NOT NULL,
	keyid    INTEGER NOT NULL,
	flags    INTEGER NOT NULL
);
CREATE TABLE edge (
	parent INTEGER NOT NULL,
	name   BLOB NOT NULL,
	inode  INTEGER NOT NULL,
	type   INTEGER NOT NULL,
	PRIMARY KEY (parent, name)
) WITHOUT ROWID;
CREATE TABLE nested (
	parent           INTEGER NOT NULL,
	name             BLOB NOT NULL,
	catalog_identity BLOB NOT NULL,
	PRIMARY KEY (parent, name)
) WITHOUT ROWID;
CREATE TABLE chunkref (
	inode    INTEGER NOT NULL,
	idx      INTEGER NOT NULL,
	identity BLOB,
	llen     INTEGER NOT NULL,
	clen     INTEGER NOT NULL,
	alg      INTEGER NOT NULL,
	keyid    INTEGER NOT NULL,
	PRIMARY KEY (inode, idx)
) WITHOUT ROWID;
CREATE TABLE inline (
	inode INTEGER PRIMARY KEY,
	data  BLOB NOT NULL
);
CREATE TABLE xattr (
	inode INTEGER NOT NULL,
	name  BLOB NOT NULL,
	value BLOB NOT NULL,
	PRIMARY KEY (inode, name)
) WITHOUT ROWID;
CREATE TABLE symlink (
	inode  INTEGER PRIMARY KEY,
	target BLOB NOT NULL
);
`

// Meta is the self-identification a rescue scan needs to reassemble the
// catalog tree from packs alone (design doc, "Disaster recovery").
type Meta struct {
	VolumeUUID   string
	CoveredPath  string
	Generation   uint64
	IdentityAlgo string
}

// Node is one row of the node table. There is deliberately no Atime field.
type Node struct {
	Inode   int64
	Type    uint8
	Mode    uint32
	UID     uint32
	GID     uint32
	MtimeNS int64
	CtimeNS int64
	Nlink   uint32
	Length  int64
	Rdev    uint32
	KeyID   int64
	Flags   uint32
}

// Dirent is one row of the edge table.
type Dirent struct {
	Name  []byte
	Inode int64
	Type  uint8
}

// Nested is one transition-point row: the named child directory lives in
// the child catalog with the given identity.
type Nested struct {
	Name            []byte
	CatalogIdentity []byte
}

// ChunkRef is one extent of a file's chunk list. A nil Identity marks a
// hole of LLen bytes (CLen, Alg, KeyID are meaningless for holes).
// LogicalOffset is not stored; readers fill it in as the prefix sum of the
// preceding LLens.
type ChunkRef struct {
	Identity      []byte
	LLen          int64
	CLen          int64
	Alg           int64
	KeyID         int64
	LogicalOffset int64
}

// Xattr is one extended-attribute row.
type Xattr struct {
	Name  []byte
	Value []byte
}

// Writer builds a new catalog. It is not safe for concurrent use; all rows
// are written in one implicit transaction committed by Close.
type Writer struct {
	db *sql.DB
	tx *sql.Tx

	node    *sql.Stmt
	edge    *sql.Stmt
	nested  *sql.Stmt
	chunk   *sql.Stmt
	inline  *sql.Stmt
	xattr   *sql.Stmt
	symlink *sql.Stmt
}

// Create makes a new catalog file at path and stamps its catalog_meta.
// The path must not already exist: catalogs are write-once artifacts, never
// rewritten in place. Journaling and syncing are off for build speed; a
// crash mid-build leaves garbage the publisher discards and rebuilds.
func Create(path string, meta Meta) (*Writer, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("catalog: %s already exists (catalogs are write-once)", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// cache_size is negative = KiB, and 16 MiB is chosen against SMax: a
	// catalog is bounded at 8 MiB by construction, so the whole B-tree fits
	// in the pager and the build stops spilling. With the 2 MiB default,
	// a full-size catalog's pages are written out and read back in as the
	// WITHOUT ROWID indexes rebalance — profiling a whole-tree seal found
	// pwrite and pread the single largest cost in the pipeline, most of it
	// this churn rather than the one write the file actually needs.
	//
	// locking_mode=EXCLUSIVE for the same reason it is set on the write
	// overlay: a build file is private to the writer that created it (Create
	// refuses an existing path), so there is no one to coordinate with and
	// no reason to take and drop a POSIX lock per statement.
	db, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)"+
		"&_pragma=cache_size(-16384)&_pragma=locking_mode(EXCLUSIVE)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	w := &Writer{db: db}
	if err := w.init(meta); err != nil {
		db.Close()
		os.Remove(path)
		return nil, err
	}
	return w, nil
}

func (w *Writer) init(meta Meta) error {
	if _, err := w.db.Exec(schema); err != nil {
		return fmt.Errorf("catalog: create schema: %w", err)
	}
	tx, err := w.db.Begin()
	if err != nil {
		return err
	}
	w.tx = tx
	for _, kv := range []struct {
		key   string
		value []byte
	}{
		{metaVolumeUUID, []byte(meta.VolumeUUID)},
		{metaCoveredPath, []byte(meta.CoveredPath)},
		{metaGeneration, []byte(strconv.FormatUint(meta.Generation, 10))},
		{metaFormatVersion, []byte(strconv.Itoa(FormatVersion))},
		{metaIdentityAlgo, []byte(meta.IdentityAlgo)},
	} {
		if _, err := tx.Exec(`INSERT INTO catalog_meta (key, value) VALUES (?, ?)`, kv.key, kv.value); err != nil {
			return err
		}
	}
	for stmt, q := range map[**sql.Stmt]string{
		&w.node:    `INSERT INTO node (inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink, length, rdev, keyid, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		&w.edge:    `INSERT INTO edge (parent, name, inode, type) VALUES (?, ?, ?, ?)`,
		&w.nested:  `INSERT INTO nested (parent, name, catalog_identity) VALUES (?, ?, ?)`,
		&w.chunk:   `INSERT INTO chunkref (inode, idx, identity, llen, clen, alg, keyid) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		&w.inline:  `INSERT INTO inline (inode, data) VALUES (?, ?)`,
		&w.xattr:   `INSERT INTO xattr (inode, name, value) VALUES (?, ?, ?)`,
		&w.symlink: `INSERT INTO symlink (inode, target) VALUES (?, ?)`,
	} {
		s, err := tx.Prepare(q)
		if err != nil {
			return err
		}
		*stmt = s
	}
	return nil
}

// AddNode records one inode's attributes.
func (w *Writer) AddNode(n Node) error {
	_, err := w.node.Exec(n.Inode, n.Type, n.Mode, n.UID, n.GID,
		n.MtimeNS, n.CtimeNS, n.Nlink, n.Length, n.Rdev, n.KeyID, n.Flags)
	return err
}

// AddEdge records one directory entry.
func (w *Writer) AddEdge(parent int64, name []byte, inode int64, typ uint8) error {
	_, err := w.edge.Exec(parent, name, inode, typ)
	return err
}

// AddNested records a transition point: the named entry under parent is the
// root of the child catalog with the given identity.
func (w *Writer) AddNested(parent int64, name []byte, catalogIdentity []byte) error {
	_, err := w.nested.Exec(parent, name, catalogIdentity)
	return err
}

// AddChunks records a file's entire chunk list in one call; slice order is
// the logical order (idx). Hole entries carry a nil Identity and llen = the
// hole length. LogicalOffset fields are ignored — offsets are never stored.
func (w *Writer) AddChunks(inode int64, refs []ChunkRef) error {
	for i, r := range refs {
		var identity any
		if r.Identity != nil {
			identity = r.Identity
		}
		if _, err := w.chunk.Exec(inode, i, identity, r.LLen, r.CLen, r.Alg, r.KeyID); err != nil {
			return err
		}
	}
	return nil
}

// SetInline stores a small file's content directly in the catalog.
func (w *Writer) SetInline(inode int64, data []byte) error {
	_, err := w.inline.Exec(inode, data)
	return err
}

// AddXattr records one extended attribute.
func (w *Writer) AddXattr(inode int64, name, value []byte) error {
	_, err := w.xattr.Exec(inode, name, value)
	return err
}

// SetSymlink records a symlink's target.
func (w *Writer) SetSymlink(inode int64, target []byte) error {
	_, err := w.symlink.Exec(inode, target)
	return err
}

// Close commits everything and finalizes the catalog file. The Writer is
// unusable afterwards.
func (w *Writer) Close() error {
	if w.tx == nil {
		return errors.New("catalog: writer already closed")
	}
	for _, s := range []*sql.Stmt{w.node, w.edge, w.nested, w.chunk, w.inline, w.xattr, w.symlink} {
		s.Close()
	}
	err := w.tx.Commit()
	w.tx = nil
	if cerr := w.db.Close(); err == nil {
		err = cerr
	}
	return err
}

// Catalog reads a finished catalog. Safe for concurrent use.
//
// Read statements are prepared once and cached: profiling the phase-3
// lookup path showed SQL PARSING (sqlite3's yacc reduce) burning ~13% of
// CPU because database/sql re-prepares on every Query call with
// arguments. Catalogs are immutable and read hot, so the parse belongs at
// open time. The pool is sized for concurrent readers rather than left at
// the single-connection default the writer needs.
type Catalog struct {
	db   *sql.DB
	meta Meta

	stLookupEdge    *sql.Stmt
	stLookupNested  *sql.Stmt
	stReaddirEdges  *sql.Stmt
	stReaddirNested *sql.Stmt
	stReaddirPlus   *sql.Stmt
	stStat          *sql.Stmt
	stChunks        *sql.Stmt
	stInline        *sql.Stmt
	stXattrs        *sql.Stmt
	stSymlink       *sql.Stmt
}

// readerConns bounds prepared-statement replication across pooled
// connections (each connection holds its own compiled statement).
var readerConns = min(runtime.NumCPU(), 8)

// Open opens an existing catalog read-only and validates its format version.
func Open(path string) (*Catalog, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	// cache_size is negative = KiB: catalogs are bounded by SMax (8 MiB)
	// by construction, so the whole file fits in the pager and a cold
	// readdir stops pread-storming (87% of Readdir CPU was syscalls).
	//
	// immutable=1 is the other half of that story, and the bigger one. It
	// tells SQLite the file cannot change underneath it, so the pager
	// stops taking POSIX locks and stops re-stat'ing the file to detect
	// foreign writes. Profiling a seal over an 80k-inode tree found 65% of
	// the whole publish inside fcntl() and stat() from exactly that
	// bookkeeping — more than the catalog building it was there to serve.
	// A point lookup is ~4x cheaper without it.
	//
	// The precondition is structural, not a hope: a catalog is named by
	// the hash of its own bytes, Create refuses to open an existing path,
	// and the readers that materialize one (genfs's catalog spill) publish
	// it by rename and never rewrite it. There is no writer that could
	// change a catalog file under a reader.
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1&_pragma=query_only(1)&_pragma=cache_size(-16384)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(readerConns)
	db.SetMaxIdleConns(readerConns)
	c := &Catalog{db: db}
	if err := c.loadMeta(); err != nil {
		db.Close()
		return nil, err
	}
	if err := c.prepare(); err != nil {
		db.Close()
		return nil, err
	}
	return c, nil
}

// prepare compiles the read statements once. Failure is fatal to Open:
// a catalog whose schema does not match this reader is unusable.
func (c *Catalog) prepare() error {
	for _, p := range []struct {
		dst **sql.Stmt
		sql string
	}{
		{&c.stLookupEdge, `SELECT inode, type FROM edge WHERE parent = ? AND name = ?`},
		{&c.stLookupNested, `SELECT catalog_identity FROM nested WHERE parent = ? AND name = ?`},
		{&c.stReaddirEdges, `SELECT name, inode, type FROM edge WHERE parent = ? ORDER BY name`},
		{&c.stReaddirNested, `SELECT name, catalog_identity FROM nested WHERE parent = ? ORDER BY name`},
		{&c.stReaddirPlus, `SELECT e.name, n.inode, n.type, n.mode, n.uid, n.gid, n.mtime_ns, n.ctime_ns, n.nlink, n.length, n.rdev, n.keyid, n.flags FROM edge e JOIN node n ON n.inode = e.inode WHERE e.parent = ? ORDER BY e.name`},
		{&c.stStat, `SELECT inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink, length, rdev, keyid, flags FROM node WHERE inode = ?`},
		{&c.stChunks, `SELECT identity, llen, clen, alg, keyid FROM chunkref WHERE inode = ? ORDER BY idx`},
		{&c.stInline, `SELECT data FROM inline WHERE inode = ?`},
		{&c.stXattrs, `SELECT name, value FROM xattr WHERE inode = ? ORDER BY name`},
		{&c.stSymlink, `SELECT target FROM symlink WHERE inode = ?`},
	} {
		st, err := c.db.Prepare(p.sql)
		if err != nil {
			return fmt.Errorf("catalog: prepare %q: %w", p.sql, err)
		}
		*p.dst = st
	}
	return nil
}

func (c *Catalog) loadMeta() error {
	rows, err := c.db.Query(`SELECT key, value FROM catalog_meta`)
	if err != nil {
		return fmt.Errorf("catalog: read catalog_meta: %w", err)
	}
	defer rows.Close()
	version := -1
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return err
		}
		switch key {
		case metaVolumeUUID:
			c.meta.VolumeUUID = string(value)
		case metaCoveredPath:
			c.meta.CoveredPath = string(value)
		case metaGeneration:
			g, err := strconv.ParseUint(string(value), 10, 64)
			if err != nil {
				return fmt.Errorf("catalog: bad generation %q: %w", value, err)
			}
			c.meta.Generation = g
		case metaFormatVersion:
			v, err := strconv.Atoi(string(value))
			if err != nil {
				return fmt.Errorf("catalog: bad format_version %q: %w", value, err)
			}
			version = v
		case metaIdentityAlgo:
			c.meta.IdentityAlgo = string(value)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if version != FormatVersion {
		return fmt.Errorf("catalog: format version %d, want %d", version, FormatVersion)
	}
	return nil
}

// Meta returns the catalog's self-identification.
func (c *Catalog) Meta() Meta { return c.meta }

// LookupResult is the outcome of a name lookup. An ordinary entry sets
// only Dirent. A transition point sets BOTH: publish writes the child
// directory's dirent (and node row) into the parent catalog alongside the
// nested locator, so lookup and stat of the transition directory never
// fetch the child catalog — only descending into its entries does.
type LookupResult struct {
	Dirent         *Dirent
	NestedIdentity []byte
}

// Lookup resolves one name under parent. Returns ErrNotExist when the
// name has neither an edge row nor a nested row.
func (c *Catalog) Lookup(parent int64, name []byte) (LookupResult, error) {
	var res LookupResult
	var d Dirent
	err := c.stLookupEdge.QueryRow(parent, name).
		Scan(&d.Inode, &d.Type)
	switch {
	case err == nil:
		d.Name = append([]byte(nil), name...)
		res.Dirent = &d
	case !errors.Is(err, sql.ErrNoRows):
		return LookupResult{}, err
	}
	var identity []byte
	err = c.stLookupNested.QueryRow(parent, name).
		Scan(&identity)
	switch {
	case err == nil:
		res.NestedIdentity = identity
	case !errors.Is(err, sql.ErrNoRows):
		return LookupResult{}, err
	}
	if res.Dirent == nil && res.NestedIdentity == nil {
		return LookupResult{}, ErrNotExist
	}
	return res, nil
}

// Readdir lists a directory: its ordinary entries and its transition
// points, each sorted by name (the primary-key order).
func (c *Catalog) Readdir(parent int64) ([]Dirent, []Nested, error) {
	rows, err := c.stReaddirEdges.Query(parent)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var dirents []Dirent
	for rows.Next() {
		var d Dirent
		if err := rows.Scan(&d.Name, &d.Inode, &d.Type); err != nil {
			return nil, nil, err
		}
		dirents = append(dirents, d)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	nrows, err := c.stReaddirNested.Query(parent)
	if err != nil {
		return nil, nil, err
	}
	defer nrows.Close()
	var nesteds []Nested
	for nrows.Next() {
		var n Nested
		if err := nrows.Scan(&n.Name, &n.CatalogIdentity); err != nil {
			return nil, nil, err
		}
		nesteds = append(nesteds, n)
	}
	return dirents, nesteds, nrows.Err()
}

// Stat returns one inode's attributes; ErrNotExist if absent.
func (c *Catalog) Stat(inode int64) (Node, error) {
	var n Node
	err := c.stStat.QueryRow(inode).
		Scan(&n.Inode, &n.Type, &n.Mode, &n.UID, &n.GID,
			&n.MtimeNS, &n.CtimeNS, &n.Nlink, &n.Length, &n.Rdev, &n.KeyID, &n.Flags)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotExist
	}
	return n, err
}

// Chunks returns a file's chunk list in logical order with LogicalOffset
// filled in (prefix sum of llen — offsets are not stored). Hole rows come
// back with a nil Identity. When any chunk rows exist, the summed llen must
// equal node.length; a mismatch is corruption and returns an error.
func (c *Catalog) Chunks(inode int64) ([]ChunkRef, error) {
	rows, err := c.stChunks.Query(inode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refs []ChunkRef
	var offset int64
	for rows.Next() {
		var r ChunkRef
		if err := rows.Scan(&r.Identity, &r.LLen, &r.CLen, &r.Alg, &r.KeyID); err != nil {
			return nil, err
		}
		r.LogicalOffset = offset
		offset += r.LLen
		refs = append(refs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if refs == nil {
		return nil, nil
	}
	n, err := c.Stat(inode)
	if err != nil {
		return nil, fmt.Errorf("catalog: inode %d has chunks but no node row: %w", inode, err)
	}
	if offset != n.Length {
		return nil, fmt.Errorf("catalog: inode %d chunk lengths sum to %d, node length is %d", inode, offset, n.Length)
	}
	return refs, nil
}

// Inline returns a file's inline content, or (nil, nil) when the file has
// no inline row.
func (c *Catalog) Inline(inode int64) ([]byte, error) {
	var data []byte
	err := c.stInline.QueryRow(inode).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return data, err
}

// Xattrs returns an inode's extended attributes sorted by name; empty when
// there are none.
func (c *Catalog) Xattrs(inode int64) ([]Xattr, error) {
	rows, err := c.stXattrs.Query(inode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attrs []Xattr
	for rows.Next() {
		var x Xattr
		if err := rows.Scan(&x.Name, &x.Value); err != nil {
			return nil, err
		}
		attrs = append(attrs, x)
	}
	return attrs, rows.Err()
}

// Symlink returns a symlink's target; ErrNotExist if the inode has none.
func (c *Catalog) Symlink(inode int64) ([]byte, error) {
	var target []byte
	err := c.stSymlink.QueryRow(inode).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotExist
	}
	return target, err
}

// Close releases the underlying database.
func (c *Catalog) Close() error { return c.db.Close() }

// DirentNode pairs a directory entry with its full node row.
type DirentNode struct {
	Name []byte
	Node Node
}

// ReaddirPlus lists a directory's ordinary entries WITH their attributes
// in one query. The FUSE readdirplus path needs both, and issuing a
// per-entry Stat turned one directory read into 1+N pager round trips.
// Transition points are not included — Readdir's nested half still
// reports them (they resolve in the child catalog).
func (c *Catalog) ReaddirPlus(parent int64) ([]DirentNode, error) {
	rows, err := c.stReaddirPlus.Query(parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []DirentNode
	for rows.Next() {
		var e DirentNode
		if err := rows.Scan(&e.Name, &e.Node.Inode, &e.Node.Type, &e.Node.Mode,
			&e.Node.UID, &e.Node.GID, &e.Node.MtimeNS, &e.Node.CtimeNS,
			&e.Node.Nlink, &e.Node.Length, &e.Node.Rdev, &e.Node.KeyID, &e.Node.Flags); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
