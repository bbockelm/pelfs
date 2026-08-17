package overlay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// onodeRow is one dirty attribute row. base records whether the inode
// exists in the base generation (modified) or is overlay-new — the flag
// Dirty exposes and node cleanup keys off.
type onodeRow struct {
	Node
	base bool
}

func getONode(q querier, ino uint64) (*onodeRow, error) {
	r := &onodeRow{}
	var base int64
	err := q.QueryRow(`SELECT inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink, length, rdev, flags, base
		FROM onode WHERE inode = ?`, int64(ino)).
		Scan(&r.Inode, &r.Type, &r.Mode, &r.UID, &r.GID, &r.MtimeNS, &r.CtimeNS,
			&r.Nlink, &r.Length, &r.Rdev, &r.Flags, &base)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.base = base != 0
	return r, nil
}

func putONode(q querier, r *onodeRow) error {
	base := int64(0)
	if r.base {
		base = 1
	}
	_, err := q.Exec(`INSERT OR REPLACE INTO onode
		(inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink, length, rdev, flags, base)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(r.Inode), r.Type, r.Mode, r.UID, r.GID, r.MtimeNS, r.CtimeNS,
		r.Nlink, r.Length, r.Rdev, r.Flags, base)
	return err
}

func putOEdge(q querier, parent uint64, name string, ino uint64, typ uint8) error {
	_, err := q.Exec(`INSERT OR REPLACE INTO oedge (parent, name, inode, type) VALUES (?, ?, ?, ?)`,
		int64(parent), []byte(name), int64(ino), typ)
	return err
}

// putWhiteout hides a base name: oedge with inode 0.
func putWhiteout(q querier, parent uint64, name string) error {
	return putOEdge(q, parent, name, 0, 0)
}

func deleteOEdge(q querier, parent uint64, name string) error {
	_, err := q.Exec(`DELETE FROM oedge WHERE parent = ? AND name = ?`, int64(parent), []byte(name))
	return err
}

func hasContent(q querier, ino uint64) (bool, error) {
	var one int64
	err := q.QueryRow(`SELECT 1 FROM ocontent WHERE inode = ?`, int64(ino)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// baseBackedLocked reports whether ino may have a base half: an inode
// with no onode row is only visible via base, so absence means base.
func (fs *FS) baseBackedLocked(q querier, ino uint64) (bool, error) {
	row, err := fs.onodeLocked(q, ino)
	if err != nil {
		return false, err
	}
	if row == nil {
		return true, nil
	}
	return row.base, nil
}

// resolved is one merged-view edge resolution.
type resolved struct {
	ino     uint64
	typ     uint8
	overlay bool  // resolved via an oedge row
	node    *Node // base attributes when resolution passed through base.Lookup
}

// resolveLocked resolves name under parent in the merged view: whiteout
// wins (ErrNotExist), then oedge, then base pass-through.
func (fs *FS) resolveLocked(ctx context.Context, parent uint64, name string) (resolved, error) {
	e, found, err := fs.oedgeLocked(parent, name)
	if err != nil {
		return resolved{}, err
	}
	if found {
		if e.ino == 0 {
			return resolved{}, ErrNotExist
		}
		return resolved{ino: e.ino, typ: e.typ, overlay: true}, nil
	}
	backed, err := fs.baseBackedLocked(fs.q, parent)
	if err != nil {
		return resolved{}, err
	}
	if !backed {
		return resolved{}, ErrNotExist
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, parent); err != nil {
		return resolved{}, err
	}
	n, err := fs.baseLookupLocked(ctx, parent, name)
	if err != nil {
		return resolved{}, err
	}
	return resolved{ino: n.Inode, typ: n.Type, node: &n}, nil
}

// attrsLocked returns an inode's merged attributes: onode row wins, then
// the hint from a just-done base lookup, then a base GetAttr (residency
// replayed for detached inodes).
func (fs *FS) attrsLocked(ctx context.Context, ino uint64, hint *Node) (Node, error) {
	row, err := fs.onodeLocked(fs.q, ino)
	if err != nil {
		return Node{}, err
	}
	if row != nil {
		return row.Node, nil
	}
	if hint != nil {
		return *hint, nil
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
		return Node{}, err
	}
	return fs.base.GetAttr(ctx, ino)
}

// Lookup resolves name under parent in the merged view.
func (fs *FS) Lookup(ctx context.Context, parent uint64, name string) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	r, err := fs.resolveLocked(ctx, parent, name)
	if err != nil {
		return Node{}, err
	}
	return fs.attrsLocked(ctx, r.ino, r.node)
}

// GetAttr returns merged attributes: the onode row wins, else base.
func (fs *FS) GetAttr(ctx context.Context, ino uint64) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.attrsLocked(ctx, ino, nil)
}

// Readdir lists the merged view: base entries minus whiteouts plus
// overlay edges (an oedge for an existing base name replaces it), sorted
// by name with no duplicates.
func (fs *FS) Readdir(ctx context.Context, ino uint64) ([]DirEntry, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.readdirLocked(ctx, ino, false)
}

// ReaddirRetain lists the merged view exactly as Readdir does and, for
// every entry that comes from the base, establishes base residency at the
// same time.
//
// It exists for the seal, which descends the whole tree with no kernel
// Lookup behind it. Readdir alone leaves base entries un-resident, so the
// seal used to re-resolve every name it had just been handed — three
// catalog queries and four overlay queries per entry, to learn nothing
// Readdir had not already returned. The base does the retaining in bulk
// (genfs.ReaddirRetain), which is where the equivalence lives: same
// inodes, same catalogs, same order as the per-entry loop.
func (fs *FS) ReaddirRetain(ctx context.Context, ino uint64) ([]DirEntry, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.readdirLocked(ctx, ino, true)
}

func (fs *FS) readdirLocked(ctx context.Context, ino uint64, retain bool) ([]DirEntry, error) {
	type oent struct {
		ino uint64
	}
	oes, err := fs.oedgesOfLocked(ino)
	if err != nil {
		return nil, err
	}
	over := make(map[string]oent, len(oes))
	for _, oe := range oes {
		over[oe.name] = oent{ino: oe.ino}
	}

	var out []DirEntry
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil {
		return nil, err
	}
	if backed {
		if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
			return nil, err
		}
		var bes []DirEntry
		if retain {
			bes, err = fs.base.ReaddirRetain(ctx, ino)
		} else {
			bes, err = fs.base.Readdir(ctx, ino)
		}
		if err != nil {
			return nil, err
		}
		for _, be := range bes {
			if _, shadowed := over[be.Name]; shadowed {
				continue // whiteout or replacing oedge
			}
			row, err := fs.onodeLocked(fs.q, be.Node.Inode)
			if err != nil {
				return nil, err
			}
			if row != nil {
				be.Node = row.Node
			}
			out = append(out, be)
		}
	}
	for name, oe := range over {
		if oe.ino == 0 {
			continue // whiteout
		}
		n, err := fs.attrsLocked(ctx, oe.ino, nil)
		if err != nil {
			return nil, fmt.Errorf("overlay: readdir %d: attrs for %q (inode %d): %w", ino, name, oe.ino, err)
		}
		out = append(out, DirEntry{Name: name, Node: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Readlink returns a symlink's target: overlay row wins, else base.
func (fs *FS) Readlink(ctx context.Context, ino uint64) (string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	target, found, err := fs.osymlinkLocked(ino)
	if err != nil {
		return "", err
	}
	if found {
		return target, nil
	}
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil {
		return "", err
	}
	if !backed {
		return "", ErrNotExist
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
		return "", err
	}
	return fs.base.Readlink(ctx, ino)
}

// getOXattr returns the overlay xattr row: (value, tombstoned, found).
func getOXattr(q querier, ino uint64, name string) ([]byte, bool, bool, error) {
	var value []byte
	var tomb int64
	err := q.QueryRow(`SELECT value, tombstone FROM oxattr WHERE inode = ? AND name = ?`,
		int64(ino), []byte(name)).Scan(&value, &tomb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	return value, tomb != 0, true, nil
}

// GetXattr returns one extended attribute in the merged view: an overlay
// row wins (a tombstone hides the base value), else base.
func (fs *FS) GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	value, tomb, found, err := fs.oxattrLocked(fs.q, ino, name)
	if err != nil {
		return nil, err
	}
	if found {
		if tomb {
			return nil, ErrNotExist
		}
		return value, nil
	}
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil {
		return nil, err
	}
	if !backed {
		return nil, ErrNotExist
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
		return nil, err
	}
	return fs.base.GetXattr(ctx, ino, name)
}

// ListXattr returns the merged attribute names, sorted: base names minus
// tombstones plus overlay names.
func (fs *FS) ListXattr(ctx context.Context, ino uint64) ([]string, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	names := make(map[string]bool) // name -> visible
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil {
		return nil, err
	}
	if backed {
		if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
			return nil, err
		}
		base, err := fs.base.ListXattr(ctx, ino)
		if err != nil {
			return nil, err
		}
		for _, n := range base {
			names[n] = true
		}
	}
	xs, err := fs.oxattrsOfLocked(ino)
	if err != nil {
		return nil, err
	}
	for _, x := range xs {
		names[x.name] = !x.tomb
	}
	out := make([]string, 0, len(names))
	for n, visible := range names {
		if visible {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Read fills dst from ino at off: dirty content is served from the
// staging file, clean content passes through to the base generation.
func (fs *FS) Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("overlay: negative read offset %d", off)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	staged, err := fs.stagedLocked(fs.q, ino)
	if err != nil {
		return 0, err
	}
	if !staged {
		if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
			return 0, err
		}
		return fs.base.Read(ctx, ino, off, dst)
	}
	row, err := fs.onodeLocked(fs.q, ino)
	if err != nil {
		return 0, err
	}
	if row == nil {
		return 0, fmt.Errorf("overlay: staged inode %d has no onode row", ino)
	}
	if off >= row.Length || len(dst) == 0 {
		return 0, nil
	}
	n := int64(len(dst))
	if off+n > row.Length {
		n = row.Length - off
	}
	f, err := os.Open(fs.stagingPath(ino))
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck
	// Staging file size tracks onode length (writes extend, truncate
	// sets), so a full ReadAt succeeds; EOF would mean a torn invariant.
	if _, err := io.ReadFull(io.NewSectionReader(f, off, n), dst[:n]); err != nil {
		return 0, fmt.Errorf("overlay: staging read inode %d at %d: %w", ino, off, err)
	}
	return int(n), nil
}

// typeName aids error text only.
func typeName(t uint8) string {
	switch t {
	case catalog.TypeFile:
		return "file"
	case catalog.TypeDir:
		return "dir"
	case catalog.TypeSymlink:
		return "symlink"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}
