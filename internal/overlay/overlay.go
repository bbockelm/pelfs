// Package overlay is the write path: a crash-safe local shadow of
// dirty state over one immutable base generation served by genfs
// (docs/design-packfs.md, on the catalog-native mount: the write path is
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
// applies. Appending to a large file therefore copies the whole thing on
// the first dirty byte, which is accepted because the sessions this
// serves rewrite small files far more often than they extend huge ones;
// chunk-granular COW is the escape hatch if that stops being true.
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
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver for the overlay database

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
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
	// Memtable puts the BYTES of changed files in the write path's
	// memtable instead of in one staging file per dirty inode
	// (content_memtable.go). Nil keeps the staging directory.
	//
	// The two are held to the same contract (contentStore) and the same
	// tests; what differs is when content reaches the federation — at the
	// seal, or during the session — and what it costs to write one byte of
	// a file that came from the base.
	Memtable *memtable.Store
}

// provEdge records how an inode was reached in the BASE namespace: one
// successful base.Lookup(parent, name). Base edges are immutable, so any
// recorded edge is a permanently valid descent step.
type provEdge struct {
	parent uint64
	name   string
}

// opLock is the overlay's lock with an account of what waiting for it
// costs. Lock is on the path of every filesystem operation, so the two
// clock reads it adds are deliberate: an operation that reaches SQLite is
// already orders of magnitude more expensive, and knowing how long the
// mount was blocked is worth more than the nanoseconds.
//
// It measures WAITING rather than holding. A long hold nobody is waiting
// behind costs the user nothing; a short one that fifty operations queue
// behind is what a stall actually is.
type opLock struct {
	sync.Mutex
	waitNS  atomic.Int64
	worstNS atomic.Int64
	waits   atomic.Int64
}

func (l *opLock) Lock() {
	start := time.Now()
	l.Mutex.Lock()
	d := int64(time.Since(start))
	if d < int64(time.Millisecond) {
		// Uncontended, or near enough that nobody noticed. Counting these
		// would bury the ones that matter in millions of nanoseconds.
		return
	}
	l.waitNS.Add(d)
	l.waits.Add(1)
	for {
		worst := l.worstNS.Load()
		if d <= worst || l.worstNS.CompareAndSwap(worst, d) {
			return
		}
	}
}

// LockWait reports how long callers have waited for this overlay: the
// total, the longest single wait, and how many waits were long enough to
// count. Sample it either side of an operation to learn what that
// operation cost the mount.
func (fs *FS) LockWait() (total, worst time.Duration, waits int64) {
	return time.Duration(fs.mu.waitNS.Load()), time.Duration(fs.mu.worstNS.Load()), fs.mu.waits.Load()
}

// FS is one open overlay over one base generation.
type FS struct {
	base *genfs.FS
	db   *sql.DB
	// q is db behind a prepared-statement cache: every non-transactional
	// read goes through it (see stmtcache.go).
	q          *stmtCache
	dir        string
	stagingDir string
	// content is where the BYTES of changed files live (content.go).
	// Everything else about them — names, attributes, structure — is in
	// the database above.
	content contentStore

	// mu serializes every operation: one writer, one transaction at a
	// time. SQLite serializes writes anyway, so a finer lock would buy
	// concurrency the storage layer refuses to deliver.
	//
	// It counts what waiting for it costs, because EVERY filesystem
	// operation takes it: time spent waiting here is time the mount is
	// not answering, and until it was measured the only evidence of a
	// stall was an NFS client declaring the server dead.
	mu opLock
	// dirtySet is the in-memory answer to IsDirty (see accessors.go);
	// nil until first use, then maintained by every mutating path.
	dirtySet map[uint64]struct{}
	// prov caches this session's base residency: prov[ino] present means
	// base.Lookup succeeded for ino via the recorded edge, and residency
	// is pinned (Forget is never forwarded to the base).
	prov map[uint64]provEdge
	// rows is the dirty tables read as sets rather than queried per inode,
	// armed by PrepareSeal and dropped by every transaction (see bulk.go).
	// nil means read the tables.
	rows *rowCache

	// seq counts mutating operations; modSeq records, per inode, the seq
	// of its last modification. Snapshot names the seq it froze, and
	// Rebase drops exactly the state whose last modification is at or
	// below a sealed snapshot's seq (see snapshot.go).
	seq    uint64
	modSeq map[uint64]uint64
	// rebasedSeq is the highest seq already rebased away.
	rebasedSeq uint64
	// snapEdges holds, per snapshot seq, what that frozen instant left the
	// live overlay to reconcile against (see snapshotState).
	snapEdges map[uint64]*snapshotState
}

// edgeName is one name in one directory: the key a whiteout is written at.
type edgeName struct {
	parent uint64
	name   string
}

// snapshotState is what one frozen instant leaves behind for the LIVE
// overlay, which keeps serving while that instant is being published.
//
// byInode is the namespace Rebase replays against the sealed base: child
// inode -> the edge naming it. names is the same namespace keyed the other
// way, and it exists because the two questions are different ones. Rebase
// asks "where does this inode live", and one name per inode answers it. The
// write path asks "is this NAME about to appear underneath me", and for a
// hardlinked inode every one of its names has to answer yes, so the set has
// an entry per EDGE rather than per inode.
//
// Both are dropped together (retireSnapEdgesLocked, and Rebase once the
// sealed generation is the one being served), because they answer for the
// same instant and are wrong the moment it stops being pending.
type snapshotState struct {
	byInode map[uint64]provEdge
	names   map[edgeName]struct{}
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
	// cache_size is negative = KiB. Without it the pager re-reads pages
	// from the OS on nearly every query: profiling showed ~90% of a
	// metadata operation's CPU in read syscalls, which is why IsDirty —
	// the most frequent call in the FUSE TTL path — cost more than a
	// whole Lookup. Dirty state is small (it is a session's changes, not
	// a tree), so 32 MiB holds all of it.
	dsn := "file:" + filepath.Join(dir, overlayDBName) +
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=cache_size(-32768)&_pragma=temp_store(MEMORY)" +
		// locking_mode=EXCLUSIVE is the big one. Profiling found 60% of
		// every metadata operation in fcntl(): SQLite acquires and
		// releases POSIX file locks per query. An overlay belongs to
		// exactly one session — single-writer scratch is the whole
		// premise — so it can hold the lock for its lifetime instead of
		// re-taking it thousands of times a second. A second process
		// trying to open the same overlay now fails fast and loudly,
		// which is the honest outcome: two writers would corrupt it.
		"&_pragma=locking_mode(EXCLUSIVE)"
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
	// The staging directory is created either way — an overlay reopened
	// with a different backend must still find the previous one's files,
	// and an empty directory costs nothing.
	content := contentStore(newStagingContent(stagingDir))
	if opts.Memtable != nil {
		content = newMemtableContent(opts.Memtable)
		if err := applyRecoveredTruncations(db, opts.Memtable.RecoveredTruncations()); err != nil {
			db.Close() //nolint:errcheck
			return nil, err
		}
	}
	return &FS{
		base:       base,
		db:         db,
		q:          newStmtCache(db),
		dir:        dir,
		stagingDir: stagingDir,
		content:    content,
		prov:       make(map[uint64]provEdge),
		modSeq:     make(map[uint64]uint64),
		snapEdges:  make(map[uint64]*snapshotState),
	}, nil
}

// applyRecoveredTruncations brings the node lengths down to what a
// recovered content store can actually serve.
//
// A file's length lives in TWO places, and only one of them is what a
// reader sees. The content store holds the extent map; the node row holds
// the length, and that is what stat answers and what Read clamps to
// (read.go). They are written in one transaction on the live path, so they
// never disagree — until a crash, where the operation log that records the
// write is durable before the location record that says where the bytes
// went. Recovery cuts the extent map back to the first byte it cannot
// serve (memtable.Truncation); without the same cut here the node row
// still claims the old length, the read is clamped to it, and the range
// past the cut is answered out of an extent map that has nothing there —
// which is to say with ZEROS. The file would come back at its full size,
// wrong, and would seal that way.
//
// Only downward, and only for the inodes recovery named. A length that is
// already at or below the cut is left exactly as it is: this reconciles a
// crash, it does not police the invariant.
func applyRecoveredTruncations(db *sql.DB, cuts []memtable.Truncation) error {
	if len(cuts) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, c := range cuts {
		if _, err := tx.Exec(`UPDATE onode SET length = ? WHERE inode = ? AND length > ?`,
			c.Size, int64(c.Inode), c.Size); err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("overlay: cut inode %d back to %d bytes after a recovery: %w", c.Inode, c.Size, err)
		}
	}
	return tx.Commit()
}

// Close releases the database. Staging files and all dirty state persist
// for the next Open.
//
// It takes the operation lock, because closing is not exempt from the
// serialization every other method here runs under. Without it a teardown
// could land in the MIDDLE of an operation and pull the statement cache
// and the connection pool out from under a query already in flight — a
// session closing its overlay while a background checkpoint was inside
// Rebase, which is where this was found. Close now waits for the
// operation to finish, as any other operation would.
//
// Waiting is bounded by the operation ahead of it, and Rebase — the long
// one — releases the lock between batches by design, so a Close can still
// land mid-rebase. What it cannot do any more is land mid-QUERY: the
// batch after it finds the pool closed and returns an error, and a failed
// rebase costs performance, never correctness (see Rebase).
func (fs *FS) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.q != nil {
		fs.q.close()
	}
	return fs.db.Close()
}

// RootInode reports the inode a walk starts at. It exists so one
// interface accepts both an FS and a Snapshot (the seal walks either).
func (fs *FS) RootInode() uint64 { return RootInode }

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
//
// fn gets a querier, not the raw *sql.Tx, so its statements go through
// the same compile-once cache the read paths use (stmtcache.go). The warm
// call is why it can: compiling needs the pool's one connection, which
// the transaction is about to take, so any query a previous transaction
// met for the first time is compiled here — before Begin, never inside.
func (fs *FS) withTx(fn func(tx querier) error) error {
	// Every mutation runs through here, which makes it the one place the
	// set-oriented row cache has to be dropped: rows this transaction is
	// about to change must not be answered from a snapshot taken before it.
	// Re-arming needs the filesystem lock this caller is holding, so the
	// cache cannot come back mid-transaction either.
	fs.rows = nil
	fs.q.warm()
	tx, err := fs.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(newTxStmts(tx, fs.q)); err != nil {
		tx.Rollback() //nolint:errcheck
		return err
	}
	return tx.Commit()
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

// ensureBaseLocked re-establishes base residency for an inode this
// overlay needs to reach through the base generation. Inodes with neither
// provenance nor an obase row are left alone: either the caller's own
// descent made them resident, or the base correctly answers ErrStale (the
// kernel-contract violation, not ours). q is the caller's active handle:
// the transaction when inside one — the pool holds a single connection, so
// touching fs.db mid-transaction deadlocks.
//
// A prov hit used to be taken as proof of residency, on the grounds that
// this overlay owns the base exclusively and never forwards Forget. That
// was wrong in two ways, and a SEAL — which walks the whole tree — hit
// both: genfs evicts residency when MaxResident bounds it (the NFS backend
// sets it), and a generation swap rebuilds the table from what it could
// re-descend. Either leaves an inode this session resolved earlier
// unreachable, and every base-facing operation on it then fails with
// ErrStale — a whole volume that could no longer be published.
//
// So provenance is treated as what it actually is: a permanently valid
// DESCENT STEP (base edges are immutable within a generation), replayed
// whenever residency is missing rather than trusted to still be there. The
// cost at the residency bound is one catalog lookup per ancestor of an
// evicted inode, paid on the operation that needs it.
func (fs *FS) ensureBaseLocked(ctx context.Context, q querier, ino uint64) error {
	return fs.ensureBaseDepth(ctx, q, ino, 0)
}

// maxBaseChainDepth bounds the replay recursion. Real paths are nowhere
// near it; a chain longer than this means a cycle, and recursing forever
// on corrupt state is worse than reporting it.
const maxBaseChainDepth = 4096

func (fs *FS) ensureBaseDepth(ctx context.Context, q querier, ino uint64, depth int) error {
	if ino == RootInode {
		return nil
	}
	if depth > maxBaseChainDepth {
		return fmt.Errorf("overlay: base edge chain for inode %d is deeper than %d levels", ino, maxBaseChainDepth)
	}
	if fs.base.Resident(ino) {
		return nil
	}
	if pe, ok := fs.prov[ino]; ok {
		if err := fs.ensureBaseDepth(ctx, q, pe.parent, depth+1); err != nil {
			return err
		}
		if n, err := fs.baseLookupLocked(ctx, pe.parent, pe.name); err == nil && n.Inode == ino {
			return nil
		}
		// The recorded edge is gone or now names something else — a swap
		// moved the inode. The persisted chain below is then the authority.
	}
	chain, ok, err := fs.obaseLocked(q, ino)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if err := fs.ensureBaseDepth(ctx, q, chain.parent, depth+1); err != nil {
		return err
	}
	if _, err := fs.baseLookupLocked(ctx, chain.parent, chain.name); err != nil {
		return fmt.Errorf("overlay: replay base edge %d/%q: %w", chain.parent, chain.name, err)
	}
	return nil
}

// persistChainLocked stores ino's original base edge chain up to the
// root (or an already-persisted ancestor — chains are always persisted
// whole, so an existing row implies a complete tail). Called whenever an
// inode detaches from its base path (rename, link): after that, the
// merged namespace no longer walks the base path that granted residency.
//
// A step it cannot find in prov it asks the BASE for, because prov is a
// cache of the base's own answer and a cache whose miss is a hard error is
// not a cache. That used to be written the other way round — a miss was
// declared unreachable, "detaching an inode requires having looked it up,
// which records provenance" — and it was true of every caller but ONE.
// link(2) names its source by BARE INODE: the kernel sends
// LinkIn.Oldnodeid and internal/rawfuse passes it straight through, so a
// link resolves no name and records no provenance on the way in. It used
// not to matter, because nothing ever deleted from prov. Then the
// checkpoint's provenance sweep (rebase.go) started dropping the entry for
// every inode a published generation cleaned, to bound a map that was
// otherwise 6.6 GB at the hundred-million-object target — and turned an
// unreachable error into an ordinary one:
//
//	overlay: no base provenance for inode N
//
// on a plain `ln` after a checkpoint. The sweep's own test says a sweep
// that made a published inode unreachable would be trading an
// out-of-memory kill for an ESTALE; it checked reading and writing, and
// link is the reachability it missed.
//
// What a MOUNT has to do to reach it, since the link fails only when no
// LOOKUP intervenes: the kernel must answer from a dentry it still holds,
// and the plainest way there is a SECOND session over a file an earlier
// one published. A fresh mount's dirty set is empty, so its first lookup
// of that file is stamped CLEAN — ten years (rawfuse.validity) — and
// editing the file afterwards makes it dirty without un-caching the dentry
// the kernel already has. The checkpoint that publishes the edit then
// sweeps this map underneath it, and the `ln` arrives with a bare inode
// and nothing behind it. Inside ONE session the two conditions race
// rather than compose, because rawfuse's dirty mark is sticky and holds
// the TTL down to a second. Both are pinned, with the reasoning, in
// internal/overlay/linkprov_test.go.
//
// genfs.Edge is the source: genfs records (parent, name) for every
// resident inode, only a descent fills it, and base edges are immutable
// within a generation. The answer is not written back into prov — the row
// this loop is about to insert is the durable home for the fact, and
// refilling the map would re-grow precisely what the sweep bounds.
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
			parent, name, err := fs.base.Edge(ino)
			if err != nil {
				// Neither cache nor base can name it. For the inode the
				// operation NAMED this cannot happen: reaching here means
				// its attrs came back from the base, which needs the very
				// residency Edge reads. An ANCESTOR can, if MaxResident
				// evicted it — the FUSE backstop is far above any real
				// dcache, and where it does fire this is the same ESTALE
				// every other base-facing operation on that inode already
				// gets. Say which inode and why, so the next reader is not
				// left deducing it from a bare refusal.
				return fmt.Errorf("overlay: no base provenance for inode %d, and the base cannot name it either: %w", ino, err)
			}
			pe = provEdge{parent: parent, name: name}
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO obase (inode, parent, name) VALUES (?, ?, ?)`,
			int64(ino), int64(pe.parent), []byte(pe.name)); err != nil {
			return err
		}
		ino = pe.parent
	}
	return nil
}
