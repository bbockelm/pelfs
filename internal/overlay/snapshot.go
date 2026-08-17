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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
)

// Snapshot freezes the overlay at one instant so a seal can walk a view
// no writer moves under it. Without it, a mid-session checkpoint is tar
// over a live directory: the published generation is self-consistent but
// corresponds to no instant, and nothing may be marked clean afterwards
// (cmd/pelfs's checkpoint keeps every dirty row for exactly that reason).
// With it, the seal's input has a sequence number, and Rebase can drop
// the state that sequence published.
//
// Two halves, frozen differently:
//
//   - Metadata by VACUUM INTO, the CUT primitive already used for v1
//     publishes: one consistent copy of the dirty tables, read afterwards
//     through its own connection.
//   - Content by one hardlink per staging file plus the length the
//     snapshot recorded. A link is the cheap clone every POSIX filesystem
//     has (no reflink required) and costs no data movement; in exchange
//     the live side must copy a file out from under the link before it
//     disturbs any byte below the recorded length. Appends and extending
//     truncates land above it and never copy.
//
// Lock cost is therefore the VACUUM (proportional to dirty METADATA, not
// to the tree and not to staged bytes) plus one link syscall per staged
// file. No file content is copied while the lock is held.

// snapPin is one live snapshot's frozen staging lengths, registered with
// the owning FS. Identity is the pointer: Close removes exactly this one.
type snapPin struct {
	lens map[uint64]int64
}

// Snapshot is a consistent read-only view of an overlay at one instant.
// It serves the same read API as FS, from its own database connection and
// its own staging copies, so reading it never contends with the mount.
//
// A Snapshot is valid only while the FS's base generation is the one it
// was taken over: it resolves clean inodes through that base. Close it
// before swapping the base (the seal-then-swap order does this anyway).
type Snapshot struct {
	owner *FS
	view  *FS
	seq   uint64
	dir   string
	pin   *snapPin
	cost  SnapshotCost

	closeOnce sync.Once
	closeErr  error
}

// SnapshotCost is where taking one snapshot went. Freezing runs with the
// overlay's lock held, so a slow one stalls the mount as well as the seal
// that asked for it — and the two halves scale with completely different
// things (dirty metadata versus staged FILE COUNT), so a single duration
// cannot say which to go after.
type SnapshotCost struct {
	Vacuum time.Duration // VACUUM INTO: the frozen copy of the dirty tables
	Freeze time.Duration // pinning staged content
	Edges  time.Duration // reading the namespace map Rebase replays against
	Open   time.Duration // opening the frozen view
	Staged int           // staged files the snapshot pinned
}

// Total is the whole time the overlay lock was held.
func (c SnapshotCost) Total() time.Duration {
	return c.Vacuum + c.Freeze + c.Edges + c.Open
}

// Cost reports where taking this snapshot went.
func (s *Snapshot) Cost() SnapshotCost { return s.cost }

// Snapshot freezes the overlay into dir, which must be empty or absent
// and belongs to the snapshot until Close removes it.
func (fs *FS) Snapshot(dir string) (*Snapshot, error) {
	if dir == "" {
		return nil, errors.New("overlay: Snapshot requires a scratch directory")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if filepath.Clean(dir) == filepath.Clean(fs.dir) {
		return nil, errors.New("overlay: a snapshot cannot be taken into the overlay's own directory")
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
	snap := &Snapshot{owner: fs, seq: fs.seq, dir: dir, pin: &snapPin{lens: make(map[uint64]int64)}}
	if err := fs.freezeLocked(snap, dir, stagingDir); err != nil {
		os.RemoveAll(stagingDir)                     //nolint:errcheck
		os.Remove(filepath.Join(dir, overlayDBName)) //nolint:errcheck
		return nil, err
	}
	fs.snapPins = append(fs.snapPins, snap.pin)
	return snap, nil
}

// freezeLocked does the work Snapshot must not interleave: copy the
// tables, link the staged content, and record the merged namespace Rebase
// replays against the sealed base.
func (fs *FS) freezeLocked(snap *Snapshot, dir, stagingDir string) error {
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
	for _, s := range content {
		dst := filepath.Join(stagingDir, strconv.FormatUint(s.ino, 10))
		if err := linkOrCopy(fs.stagingPath(s.ino), dst); err != nil {
			return fmt.Errorf("overlay: snapshot staging inode %d: %w", s.ino, err)
		}
		snap.pin.lens[s.ino] = s.length
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
	view, err := openSnapshotView(fs, dir, stagingDir)
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
func openSnapshotView(fs *FS, dir, stagingDir string) (*FS, error) {
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
// The scratch holds one hardlink per staged inode, so deleting it is an
// unlink per file in the session's dirty set — measured in seconds for an
// unpacked source tree, and paid wherever the release happens to fall. A
// caller that can move the directory aside and reclaim it when nobody is
// waiting should do that instead, and this is how it takes it over.
func (s *Snapshot) Discard() error { return s.release(false) }

func (s *Snapshot) release(deleteScratch bool) error {
	s.closeOnce.Do(func() {
		s.owner.mu.Lock()
		for i, p := range s.owner.snapPins {
			if p == s.pin {
				s.owner.snapPins = append(s.owner.snapPins[:i], s.owner.snapPins[i+1:]...)
				break
			}
		}
		s.owner.mu.Unlock()
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

// breakSnapshotLinkLocked gives ino a private staging file when a live
// snapshot froze bytes at or above below. Snapshots hold hardlinks, so
// the copy replaces the LIVE name and every snapshot keeps the old inode;
// one copy therefore satisfies all of them, which is why the pin is
// dropped from every live snapshot afterwards.
func (fs *FS) breakSnapshotLinkLocked(ino uint64, below int64) error {
	pinned := false
	for _, p := range fs.snapPins {
		if l, ok := p.lens[ino]; ok && l > below {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil
	}
	live := fs.stagingPath(ino)
	// The suffix cannot collide with a staging path (those are decimal).
	tmp := live + ".cow"
	if err := copyFileSync(live, tmp); err != nil {
		return fmt.Errorf("overlay: snapshot copy-out inode %d: %w", ino, err)
	}
	if err := os.Rename(tmp, live); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	for _, p := range fs.snapPins {
		delete(p.lens, ino)
	}
	return nil
}

// linkOrCopy freezes src at dst by hardlink, falling back to a copy when
// the scratch is on another filesystem or links are unavailable.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFileSync(src, dst)
}

// copyFileSync writes a durable copy: the staging crash contract is that
// bytes are on disk before anything points at them.
func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		out.Close()    //nolint:errcheck
		os.Remove(dst) //nolint:errcheck
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	return out.Close()
}

// sortedInodes orders a set for deterministic reports and replays.
func sortedInodes(set map[uint64]struct{}) []uint64 {
	out := make([]uint64, 0, len(set))
	for ino := range set {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
