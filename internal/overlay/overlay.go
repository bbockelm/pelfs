// Package overlay is the phase-3 write path: a crash-safe local shadow of
// dirty state over one immutable base generation served by genfs
// (docs/design-packfs.md, "Phase 3 VFS architecture": write path =
// overlay + seal). Writes never mutate the base; a later seal walks the
// overlay's dirty set (Dirty) into new catalogs and packs.
//
// State is one SQLite database in the overlay directory (WAL mode, one
// transaction per operation — the accumulate-mode crash contract:
// committed metadata survives any crash, and staged content bytes are
// synced before the row that publishes them commits) plus one staging
// file per dirty inode for file content.
//
// Content COW is file-granular: the first write or truncate of a base
// file copies its surviving content into staging before the mutation
// applies. The large-file-append cost (full copy on first dirty byte) is
// accepted for v0; chunk-granular COW is the listed later optimization.
//
// Resolution order: overlay wins. A whiteout row (oedge.inode = 0) hides
// a base name; an oedge for an existing base name replaces it (rename
// target / recreate); onode rows override base attributes. Inodes are
// stable and never renumber: new inodes come from the persisted
// next_inode counter seeded from the base superblock's NextInode, and
// renaming a base entry moves its inode, never its identity — subtree
// contents follow automatically because children resolve via the moved
// inode.
//
// Base residency: genfs serves an inode only after a Lookup descent, so
// the overlay pins base residency for the life of the handle (it never
// forwards Forget to the base, which must be exclusively owned by this
// overlay) and persists, per detached inode (renamed or linked away from
// its base path), the original base edge chain (obase). The base
// generation is immutable, so original paths are permanent facts; the
// chain is replayed to re-establish residency after reopen.
package overlay

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	_ "modernc.org/sqlite" // registers the "sqlite" driver for the overlay database

	"github.com/bbockelm/pelfs/internal/genfs"
)

// RootInode is the volume root, shared with the base generation.
const RootInode = genfs.RootInode

// Node and DirEntry mirror genfs so a raw-FUSE binding consumes one shape
// for clean and dirty inodes alike.
type (
	Node     = genfs.Node
	DirEntry = genfs.DirEntry
)

var (
	// ErrNotExist is genfs.ErrNotExist: merged-view absence (including
	// whiteouts) and base absence are indistinguishable to the binding.
	ErrNotExist = genfs.ErrNotExist
	// ErrStale is genfs.ErrStale: the kernel never looked the inode up.
	ErrStale = genfs.ErrStale
	// ErrExist is returned when a create-style operation hits an existing
	// merged-view name.
	ErrExist = errors.New("overlay: entry already exists")
	// ErrNotEmpty is returned by Rmdir/Rename when the merged view of the
	// directory still has entries.
	ErrNotEmpty = errors.New("overlay: directory not empty")
	// ErrNotDir is returned when a directory operand is not a directory.
	ErrNotDir = errors.New("overlay: not a directory")
	// ErrIsDir is returned when a non-directory operand is a directory.
	ErrIsDir = errors.New("overlay: is a directory")
	// ErrGeneration is returned by Open when the overlay directory was
	// created over a different base generation: an overlay over
	// generation N must never silently sit on generation N+1.
	ErrGeneration = errors.New("overlay: existing state belongs to a different base generation")
)

// Options configures Open. The base superblock's identity fields are
// re-carried here because genfs does not expose its superblock.
type Options struct {
	// NextInode seeds the persisted inode allocator (the base
	// superblock's NextInode). Required on first open of an overlay
	// directory; ignored on reopen (the stored counter is authoritative
	// — allocated inodes must never be reissued).
	NextInode uint64
	// BaseRoot is the base generation's root-catalog identity (the
	// superblock's RootCatalog). Stored on first open; a mismatch at
	// reopen is ErrGeneration. Required.
	BaseRoot [32]byte
	// BaseGeneration is the base superblock's generation counter, stored
	// for diagnostics.
	BaseGeneration uint64
}

// provEdge records how an inode was reached in the BASE namespace: one
// successful base.Lookup(parent, name). Base edges are immutable, so any
// recorded edge is a permanently valid descent step.
type provEdge struct {
	parent uint64
	name   string
}

// FS is one open overlay over one base generation.
type FS struct {
	base       *genfs.FS
	db         *sql.DB
	dir        string
	stagingDir string

	// mu serializes every operation: one writer, one transaction at a
	// time (v0 simplicity; SQLite serializes writes anyway).
	mu sync.Mutex
	// prov caches this session's base residency: prov[ino] present means
	// base.Lookup succeeded for ino via the recorded edge, and residency
	// is pinned (Forget is never forwarded to the base).
	prov map[uint64]provEdge
}

const (
	overlayDBName  = "overlay.db"
	stagingDirName = "staging"

	metaFormatVersion  = "format_version"
	metaNextInode      = "next_inode"
	metaBaseRoot       = "base_root"
	metaBaseGeneration = "base_generation"

	formatVersion = "1"
)

// One SQLite database holds all dirty metadata. Row presence IS the dirty
// marker: onode = attrs dirty or node new; oedge = namespace dirty
// (inode 0 is a whiteout hiding a base name); oxattr rows carry a
// tombstone flag because removal of a base xattr needs its own marker;
// ocontent presence = content lives in the staging file; obase is
// provenance (original base edges of detached inodes), not dirt.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS onode (
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
	flags    INTEGER NOT NULL,
	base     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oedge (
	parent INTEGER NOT NULL,
	name   BLOB NOT NULL,
	inode  INTEGER NOT NULL,
	type   INTEGER NOT NULL,
	PRIMARY KEY (parent, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS oedge_by_inode ON oedge (inode);
CREATE TABLE IF NOT EXISTS oxattr (
	inode     INTEGER NOT NULL,
	name      BLOB NOT NULL,
	value     BLOB,
	tombstone INTEGER NOT NULL,
	PRIMARY KEY (inode, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS osymlink (
	inode  INTEGER PRIMARY KEY,
	target BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ocontent (
	inode INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS obase (
	inode  INTEGER PRIMARY KEY,
	parent INTEGER NOT NULL,
	name   BLOB NOT NULL
);
`

// querier is the subset of database/sql shared by *sql.DB and *sql.Tx so
// row helpers work inside and outside transactions.
type querier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// Open opens (or creates) the overlay state in dir over base. Reopen
// verifies the stored base identity: the overlay's whiteouts, edges, and
// COW copies are meaningful only against the exact generation they were
// recorded over.
func Open(dir string, base *genfs.FS, opts Options) (*FS, error) {
	if base == nil {
		return nil, errors.New("overlay: base is required")
	}
	if opts.BaseRoot == ([32]byte{}) {
		return nil, errors.New("overlay: BaseRoot is required")
	}
	stagingDir := filepath.Join(dir, stagingDirName)
	for _, d := range []string{dir, stagingDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("overlay: state dir: %w", err)
		}
	}
	dsn := "file:" + filepath.Join(dir, overlayDBName) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("overlay: open db: %w", err)
	}
	// A single connection: every operation is one transaction on one
	// writer, and pragma state stays on the connection that set it.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("overlay: schema: %w", err)
	}
	wantRoot := hex.EncodeToString(opts.BaseRoot[:])
	tx, err := db.Begin()
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	storedRoot, ok, err := metaGet(tx, metaBaseRoot)
	if err == nil {
		if ok {
			if storedRoot != wantRoot {
				err = fmt.Errorf("%w: overlay recorded root %s, base is %s", ErrGeneration, storedRoot, wantRoot)
			}
		} else {
			if opts.NextInode == 0 {
				err = errors.New("overlay: NextInode is required on first open")
			} else {
				err = metaInit(tx, opts, wantRoot)
			}
		}
	}
	if err != nil {
		tx.Rollback() //nolint:errcheck
		db.Close()    //nolint:errcheck
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	return &FS{
		base:       base,
		db:         db,
		dir:        dir,
		stagingDir: stagingDir,
		prov:       make(map[uint64]provEdge),
	}, nil
}

// Close releases the database. Staging files and all dirty state persist
// for the next Open.
func (fs *FS) Close() error {
	return fs.db.Close()
}

// Forget is accepted for API symmetry with genfs and does nothing: all
// overlay state is persistent, and base residency stays pinned for the
// life of the handle (the overlay owns the base exclusively and never
// forwards Forget).
func (fs *FS) Forget(ino uint64, nlookup uint64) {}

func metaInit(tx querier, opts Options, rootHex string) error {
	for _, kv := range [][2]string{
		{metaFormatVersion, formatVersion},
		{metaNextInode, strconv.FormatUint(opts.NextInode, 10)},
		{metaBaseRoot, rootHex},
		{metaBaseGeneration, strconv.FormatUint(opts.BaseGeneration, 10)},
	} {
		if err := metaSet(tx, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

func metaGet(q querier, key string) (string, bool, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func metaSet(q querier, key, value string) error {
	_, err := q.Exec(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`, key, value)
	return err
}

// allocInodeLocked hands out the next inode inside the operation's
// transaction: a rolled-back operation burns nothing, a committed one can
// never reissue.
func (fs *FS) allocInodeLocked(tx querier) (uint64, error) {
	v, ok, err := metaGet(tx, metaNextInode)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, errors.New("overlay: next_inode missing from meta")
	}
	ino, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("overlay: corrupt next_inode %q: %w", v, err)
	}
	if err := metaSet(tx, metaNextInode, strconv.FormatUint(ino+1, 10)); err != nil {
		return 0, err
	}
	return ino, nil
}

// withTx runs fn in one transaction: the per-operation crash-safety unit.
func (fs *FS) withTx(fn func(tx *sql.Tx) error) error {
	tx, err := fs.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	return tx.Commit()
}

func (fs *FS) stagingPath(ino uint64) string {
	return filepath.Join(fs.stagingDir, strconv.FormatUint(ino, 10))
}

// baseLookupLocked resolves one BASE edge and records it as provenance:
// the recorded fact "base has edge parent->name->ino" never changes
// within the generation, and the successful Lookup pins residency.
func (fs *FS) baseLookupLocked(ctx context.Context, parent uint64, name string) (Node, error) {
	n, err := fs.base.Lookup(ctx, parent, name)
	if err != nil {
		return Node{}, err
	}
	fs.prov[n.Inode] = provEdge{parent: parent, name: name}
	return n, nil
}

// ensureBaseLocked re-establishes base residency for a detached inode by
// replaying its persisted original base edge chain. Inodes reached by
// pass-through lookups this session are already resident (prov hit).
// Inodes with neither provenance nor an obase row are left alone: either
// the caller's own descent made them resident, or the base correctly
// answers ErrStale (the kernel-contract violation, not ours). q is the
// caller's active handle: the transaction when inside one — the pool
// holds a single connection, so touching fs.db mid-transaction deadlocks.
func (fs *FS) ensureBaseLocked(ctx context.Context, q querier, ino uint64) error {
	if ino == RootInode {
		return nil
	}
	if _, ok := fs.prov[ino]; ok {
		return nil
	}
	var parent int64
	var name []byte
	err := q.QueryRow(`SELECT parent, name FROM obase WHERE inode = ?`, int64(ino)).Scan(&parent, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := fs.ensureBaseLocked(ctx, q, uint64(parent)); err != nil {
		return err
	}
	if _, err := fs.baseLookupLocked(ctx, uint64(parent), string(name)); err != nil {
		return fmt.Errorf("overlay: replay base edge %d/%q: %w", parent, name, err)
	}
	return nil
}

// persistChainLocked stores ino's original base edge chain up to the
// root (or an already-persisted ancestor — chains are always persisted
// whole, so an existing row implies a complete tail). Called whenever an
// inode detaches from its base path (rename, link): after that, the
// merged namespace no longer walks the base path that granted residency.
func (fs *FS) persistChainLocked(tx querier, ino uint64) error {
	for ino != RootInode {
		var one int64
		err := tx.QueryRow(`SELECT 1 FROM obase WHERE inode = ?`, int64(ino)).Scan(&one)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		pe, ok := fs.prov[ino]
		if !ok {
			// Unreachable under the kernel contract: detaching an inode
			// requires having looked it up, which records provenance.
			return fmt.Errorf("overlay: no base provenance for inode %d", ino)
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO obase (inode, parent, name) VALUES (?, ?, ?)`,
			int64(ino), int64(pe.parent), []byte(pe.name)); err != nil {
			return err
		}
		ino = pe.parent
	}
	return nil
}
