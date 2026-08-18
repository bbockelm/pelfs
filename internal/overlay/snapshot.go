package overlay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
)

// Snapshot freezes the overlay at one instant so a seal can walk a view
// no writer moves under it. Without it, a mid-session checkpoint is tar
// over a live directory: the published generation is self-consistent but
// corresponds to no instant, so nothing it published could be marked
// clean afterwards and every touched inode would keep paying the dirty
// TTL for the rest of the session. With it, the seal's input has a
// sequence number, and Rebase can drop the state that sequence
// published.
//
// Two halves, frozen differently:
//
//   - Metadata by VACUUM INTO: one consistent copy of the dirty tables,
//     taken under the lock and read afterwards through its own
//     connection.
//   - Content by RECORDING each staged file's length and nothing else.
//     The snapshot reads the LIVE staging file, which stays correct for
//     as long as the live side leaves the first recorded-length bytes
//     alone; before it stops doing that — a write below the length, a
//     truncate, an unlink, a rebase drop — it MOVES the old file into the
//     snapshot's scratch and takes itself a private copy back if it still
//     needs one.
//
// This used to freeze content eagerly, as one hardlink per staged file
// taken under the lock, and it was wrong twice over. It is not free per
// FILE — 362 µs each on APFS — so a session that unpacks a source tree
// paid 8.5 s of lock hold on a 28,184-file dirty set, which is a mount
// that has stopped answering: NFS calls the server unresponsive at five
// seconds and writes begin to fail. And it left staging files with two
// names, which is a property every other part of the overlay then has to
// keep in mind for no benefit it can name.
//
// Handing the file over by RENAME has neither problem. The freeze pays
// only the VACUUM and the edge map, both proportional to dirty METADATA;
// the moves are paid one at a time, off the lock's critical path, for the
// handful of files the mount actually disturbs while a seal runs; and no
// staging file is ever reachable by two names.

// Snapshot is a consistent read-only view of an overlay at one instant.
// It serves the same read API as FS, from its own database connection and
// its own staging copies, so reading it never contends with the mount.
//
// A Snapshot is valid only while the FS's base generation is the one it
// was taken over: it resolves clean inodes through that base. Close it
// before swapping the base (the seal-then-swap order does this anyway).
type Snapshot struct {
	owner *FS
	// frozen is the content view an append-only store handed over, closed
	// with the snapshot. Nil for a staging store, which protects its bytes
	// with pins instead (see snapPin).
	frozen frozenContentStore
	view   *FS
	seq    uint64
	dir    string
	pin    *snapPin
	cost   SnapshotCost

	closeOnce sync.Once
	closeErr  error
}

// SnapshotCost is where taking one snapshot went. Freezing runs with the
// overlay's lock held, so a slow one stalls the mount as well as the seal
// that asked for it. Every part of it is now proportional to dirty
// METADATA — recording the staged lengths is a map fill, not file work —
// and the breakdown is kept because that is the claim it has to keep
// proving: a Freeze that grows with the staged file count is the
// regression this design was built to remove.
type SnapshotCost struct {
	// Drain is content pushed to the federation before the instant could
	// be taken, WITHOUT the lock held. It is not part of the stall, and
	// counting it as freezing is how a slow uplink came to look like a
	// slow freeze.
	Drain  time.Duration
	Vacuum time.Duration // VACUUM INTO: the frozen copy of the dirty tables
	Freeze time.Duration // recording the staged lengths to pin
	Edges  time.Duration // reading the namespace map Rebase replays against
	Open   time.Duration // opening the frozen view
	Staged int           // staged files the snapshot pinned
}

// Total is the whole time the overlay lock was held. Drain is excluded
// on purpose: the mount kept serving through it.
func (c SnapshotCost) Total() time.Duration {
	return c.Vacuum + c.Freeze + c.Edges + c.Open
}

// Cost reports where taking this snapshot went.
func (s *Snapshot) Cost() SnapshotCost { return s.cost }

// Snapshot freezes the overlay into dir, which must be empty or absent
// and belongs to the snapshot until Close removes it.
func (fs *FS) Snapshot(ctx context.Context, dir string) (*Snapshot, error) {
	if dir == "" {
		return nil, errors.New("overlay: Snapshot requires a scratch directory")
	}
	// A content store may have expensive, network-touching work to do
	// before an instant can exist at all — the memtable flushes what is
	// still in its ring, because an extent with no location cannot be
	// named by a frozen view. It happens OUTSIDE the lock: the mount must
	// not stop answering for the length of an upload. Whatever arrives
	// during it is caught by the small second flush inside freeze.
	drain := time.Duration(0)
	if p, ok := fs.content.(contentSnapshotter); ok {
		start := time.Now()
		if err := p.prepareSnapshot(ctx); err != nil {
			return nil, err
		}
		drain = time.Since(start)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if filepath.Clean(dir) == filepath.Clean(fs.dir) {
		return nil, errors.New("overlay: a snapshot cannot be taken into the overlay's own directory")
	}
	// A content store that can do neither is one whose bytes a frozen
	// view could not reach. Saying so beats producing a view whose
	// metadata is consistent and whose content is absent — a seal that
	// publishes empty files.
	if !fs.contentCanFreeze() {
		return nil, errors.New("overlay: this content store cannot be frozen; " +
			"seal the live overlay instead of a snapshot")
	}
	stagingDir := filepath.Join(dir, stagingDirName)
	// The two entries below are the snapshot's by contract, so a reused
	// scratch directory starts clean rather than serving a stale link.
	if err := os.RemoveAll(stagingDir); err != nil {
		return nil, err
	}
	for _, d := range []string{dir, stagingDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return nil, fmt.Errorf("overlay: snapshot dir: %w", err)
		}
	}
	snap := &Snapshot{owner: fs, seq: fs.seq, dir: dir}
	snap.cost.Drain = drain
	if err := fs.freezeLocked(ctx, snap, dir, stagingDir); err != nil {
		os.RemoveAll(stagingDir)                     //nolint:errcheck
		os.Remove(filepath.Join(dir, overlayDBName)) //nolint:errcheck
		return nil, err
	}
	return snap, nil
}

// freezeLocked does the work Snapshot must not interleave: copy the
// tables, link the staged content, and record the merged namespace Rebase
// replays against the sealed base.
func (fs *FS) freezeLocked(ctx context.Context, snap *Snapshot, dir, stagingDir string) error {
	dbPath := filepath.Join(dir, overlayDBName)
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	start := time.Now()
	// VACUUM's destination is a literal, not a bindable parameter, and
	// the live connection is the only one that may read the live database
	// (locking_mode=EXCLUSIVE).
	if _, err := fs.db.Exec("VACUUM INTO '" + strings.ReplaceAll(dbPath, "'", "''") + "'"); err != nil {
		return fmt.Errorf("overlay: snapshot vacuum: %w", err)
	}
	snap.cost.Vacuum = time.Since(start)

	type staged struct {
		ino    uint64
		length int64
	}
	var content []staged
	rows, err := fs.q.Query(`SELECT c.inode, n.length FROM ocontent c
		JOIN onode n ON n.inode = c.inode ORDER BY c.inode`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var s staged
		if err := rows.Scan(&s.ino, &s.length); err != nil {
			rows.Close() //nolint:errcheck
			return err
		}
		content = append(content, s)
	}
	if err := closeRows(rows); err != nil {
		return err
	}
	start = time.Now()
	// The freeze is a map fill and nothing else, whichever store answers.
	// A staging store records the lengths it must protect; an append-only
	// one hands back a read-only view of itself and has nothing to
	// protect at all.
	viewContent := contentStore(&stagingContent{dir: stagingDir, fallback: fs.stagingDir})
	if f, ok := fs.content.(contentFreezer); ok {
		lens := make(map[uint64]int64, len(content))
		for _, st := range content {
			lens[st.ino] = st.length
		}
		snap.pin = f.freeze(stagingDir, lens)
	} else if sn, ok := fs.content.(contentSnapshotter); ok {
		frozen, err := sn.freezeContent(ctx)
		if err != nil {
			return err
		}
		viewContent = frozen
		snap.frozen = frozen
	}
	snap.cost.Staged = len(content)
	snap.cost.Freeze = time.Since(start)

	start = time.Now()
	edges, err := readEdgeMap(fs.q)
	if err != nil {
		return err
	}
	snap.cost.Edges = time.Since(start)

	start = time.Now()
	view, err := openSnapshotView(fs, dir, stagingDir, viewContent)
	if err != nil {
		return err
	}
	snap.cost.Open = time.Since(start)
	snap.view = view
	fs.snapEdges[snap.seq] = edges
	return nil
}

// readEdgeMap collects the overlay's live namespace as child -> the edge
// naming it. Whiteouts are not edges to an inode and are excluded; for a
// hardlinked inode any one of its names is a valid descent, so last wins.
func readEdgeMap(q querier) (map[uint64]provEdge, error) {
	rows, err := q.Query(`SELECT parent, name, inode FROM oedge WHERE inode != 0 ORDER BY parent, name`)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]provEdge)
	for rows.Next() {
		var parent, ino uint64
		var name []byte
		if err := rows.Scan(&parent, &name, &ino); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		out[ino] = provEdge{parent: parent, name: string(name)}
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return out, nil
}

// openSnapshotView builds the read-only FS over the frozen copy. It
// shares the base generation (genfs is safe for concurrent use) and
// inherits this session's base residency, but nothing else: its own lock,
// its own connection, its own staging files.
func openSnapshotView(fs *FS, dir, stagingDir string, content contentStore) (*FS, error) {
	// immutable=1: the frozen copy is written once, by the VACUUM INTO
	// above, and never touched again — so the pager can skip both the
	// POSIX locking and the change-detection stat it would otherwise pay
	// on every query. A seal queries this database several times per inode
	// in the tree, which is where that per-query overhead became seconds.
	dsn := "file:" + filepath.Join(dir, overlayDBName) +
		"?mode=ro&immutable=1&_pragma=busy_timeout(10000)&_pragma=query_only(1)" +
		"&_pragma=cache_size(-32768)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("overlay: open snapshot db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("overlay: open snapshot db: %w", err)
	}
	prov := make(map[uint64]provEdge, len(fs.prov))
	for ino, e := range fs.prov {
		prov[ino] = e
	}
	return &FS{
		base:       fs.base,
		db:         db,
		q:          newStmtCache(db),
		dir:        dir,
		stagingDir: stagingDir,
		content:    content,
		prov:       prov,
		modSeq:     make(map[uint64]uint64),
		snapEdges:  make(map[uint64]map[uint64]provEdge),
	}, nil
}

// Seq is the modification sequence the snapshot was taken at. Rebase
// takes it back after the snapshot has been sealed and published.
func (s *Snapshot) Seq() uint64 { return s.seq }

// Close releases the snapshot and deletes its scratch space. The FS may
// then modify staged files in place again without copying them out.
func (s *Snapshot) Close() error { return s.release(true) }

// Discard releases the snapshot exactly as Close does but LEAVES its
// scratch directory on disk, handing ownership of it to the caller.
//
// The scratch holds a file only for the inodes the mount disturbed while
// the seal ran, which is usually none of them — but a session that
// rewrites what it just wrote can leave a substantial set behind, and
// deleting those is an unlink apiece, paid wherever the release happens
// to fall. A caller that can move the directory aside and reclaim it when
// nobody is waiting should do that instead, and this is how it takes it
// over.
func (s *Snapshot) Discard() error { return s.release(false) }

func (s *Snapshot) release(deleteScratch bool) error {
	s.closeOnce.Do(func() {
		s.owner.mu.Lock()
		if f, ok := s.owner.content.(contentFreezer); ok && s.pin != nil {
			f.release(s.pin)
		}
		s.owner.mu.Unlock()
		if s.frozen != nil {
			s.frozen.releaseFrozen()
		}
		if s.view != nil {
			s.closeErr = s.view.Close()
		}
		if !deleteScratch {
			return
		}
		os.RemoveAll(filepath.Join(s.dir, stagingDirName)) //nolint:errcheck
		os.Remove(filepath.Join(s.dir, overlayDBName))     //nolint:errcheck
		os.Remove(s.dir)                                   //nolint:errcheck
	})
	return s.closeErr
}

// The frozen read API: the surface a seal walks, identical in shape to
// the live FS so one source implementation serves both.

// RootInode reports the inode a walk starts at.
func (s *Snapshot) RootInode() uint64 { return RootInode }

// NextInode is the allocator high-water mark as of the snapshot.
func (s *Snapshot) NextInode() (uint64, error) { return s.view.NextInode() }

// Lookup resolves name under parent in the frozen merged view.
func (s *Snapshot) Lookup(ctx context.Context, parent uint64, name string) (Node, error) {
	return s.view.Lookup(ctx, parent, name)
}

// GetAttr returns frozen merged attributes.
func (s *Snapshot) GetAttr(ctx context.Context, ino uint64) (Node, error) {
	return s.view.GetAttr(ctx, ino)
}

// Readdir lists the frozen merged view of a directory.
func (s *Snapshot) Readdir(ctx context.Context, ino uint64) ([]DirEntry, error) {
	return s.view.Readdir(ctx, ino)
}

// PrepareSeal arms the frozen view's set-oriented read of the dirty
// tables. A snapshot is never written, so nothing can invalidate it.
func (s *Snapshot) PrepareSeal() error { return s.view.PrepareSeal() }

// ReleaseSeal drops it, and its memory with it.
func (s *Snapshot) ReleaseSeal() { s.view.ReleaseSeal() }

// ReaddirRetain lists the frozen merged view of a directory and makes its
// base entries operable, which is what a seal walking this view needs.
func (s *Snapshot) ReaddirRetain(ctx context.Context, ino uint64) ([]DirEntry, error) {
	return s.view.ReaddirRetain(ctx, ino)
}

// Readlink returns a frozen symlink target.
func (s *Snapshot) Readlink(ctx context.Context, ino uint64) (string, error) {
	return s.view.Readlink(ctx, ino)
}

// GetXattr returns one frozen extended attribute.
func (s *Snapshot) GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error) {
	return s.view.GetXattr(ctx, ino, name)
}

// ListXattr returns the frozen extended attribute names.
func (s *Snapshot) ListXattr(ctx context.Context, ino uint64) ([]string, error) {
	return s.view.ListXattr(ctx, ino)
}

// AllXattrs returns every frozen extended attribute in one pass.
func (s *Snapshot) AllXattrs(ctx context.Context, ino uint64) (map[string][]byte, error) {
	return s.view.AllXattrs(ctx, ino)
}

// Read fills dst from the frozen content of ino at off.
func (s *Snapshot) Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	return s.view.Read(ctx, ino, off, dst)
}

// OpenFile streams an inode's frozen content.
func (s *Snapshot) OpenFile(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error) {
	return s.view.OpenFile(ctx, ino, length)
}

// BaseRootCatalog is the generation the frozen view resolves clean inodes
// through — the live base, which a snapshot may not outlive a swap of.
func (s *Snapshot) BaseRootCatalog() [32]byte { return s.view.BaseRootCatalog() }

// BaseContent answers from the FROZEN tables, so "unchanged" means
// unchanged as of the instant the snapshot was taken — which is exactly
// the tree being sealed, whatever the mount has done since.
func (s *Snapshot) BaseContent(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	return s.view.BaseContent(ctx, ino)
}

// Dirty enumerates the frozen changed set — what the seal must publish.
func (s *Snapshot) Dirty() (*DirtyReport, error) { return s.view.Dirty() }

// DirtyInodes reports the frozen touched set, so "unchanged since the
// base generation" means unchanged as of the instant that was frozen —
// the tree being sealed, not whatever the mount has done since.
func (s *Snapshot) DirtyInodes() (map[uint64]struct{}, error) { return s.view.DirtyInodes() }

// DirtyScope reports the frozen changed set placed in the namespace: the
// directories a seal of this snapshot must descend into.
func (s *Snapshot) DirtyScope() (map[uint64]struct{}, bool, error) { return s.view.DirtyScope() }

// sortedInodes orders a set for deterministic reports and replays.
func sortedInodes(set map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0, len(set))
	for ino := range set {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
