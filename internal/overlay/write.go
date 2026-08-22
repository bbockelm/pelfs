package overlay

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// copyBufSize is the base->staging copy window for file-granular COW.
const copyBufSize = 1 << 20

func nowNS() int64 { return time.Now().UnixNano() }

// checkParentDirLocked verifies parent is a directory in the merged view.
func (fs *FS) checkParentDirLocked(ctx context.Context, parent uint64) error {
	n, err := fs.attrsLocked(ctx, parent, nil)
	if err != nil {
		return err
	}
	if n.Type != catalog.TypeDir {
		return ErrNotDir
	}
	return nil
}

// checkAbsentLocked verifies (parent, name) is free in the merged view.
func (fs *FS) checkAbsentLocked(ctx context.Context, parent uint64, name string) error {
	_, err := fs.resolveLocked(ctx, parent, name)
	if err == nil {
		return ErrExist
	}
	if !errors.Is(err, ErrNotExist) {
		return err
	}
	return nil
}

// createNodeLocked shares the Create/Mkdir/Symlink/Mknod skeleton: one
// transaction that allocates the inode, writes the onode row and edge,
// and runs the per-type extra rows.
func (fs *FS) createNodeLocked(ctx context.Context, parent uint64, name string, tmpl Node,
	extra func(tx querier, ino uint64) error) (Node, error) {
	if err := fs.checkParentDirLocked(ctx, parent); err != nil {
		return Node{}, err
	}
	if err := fs.checkAbsentLocked(ctx, parent, name); err != nil {
		return Node{}, err
	}
	var out Node
	err := fs.withTx(func(tx querier) error {
		ino, err := fs.allocInodeLocked(tx)
		if err != nil {
			return err
		}
		tmpl.Inode = ino
		if err := putONode(tx, &onodeRow{Node: tmpl, base: false}); err != nil {
			return err
		}
		// INSERT OR REPLACE: the new edge may replace a whiteout
		// (recreate after unlink) — the oedge shadows the base name
		// either way.
		if err := putOEdge(tx, parent, name, ino, tmpl.Type); err != nil {
			return err
		}
		if extra != nil {
			if err := extra(tx, ino); err != nil {
				return err
			}
		}
		out = tmpl
		return nil
	})
	if err != nil {
		return Node{}, err
	}
	fs.markDirtyLocked(parent, out.Inode)
	return out, nil
}

// Create makes a new empty regular file with a fresh stable inode.
func (fs *FS) Create(ctx context.Context, parent uint64, name string, mode, uid, gid uint32) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := nowNS()
	return fs.createNodeLocked(ctx, parent, name, Node{
		Type: catalog.TypeFile, Mode: mode, UID: uid, GID: gid,
		MtimeNS: now, CtimeNS: now, Nlink: 1,
	}, func(tx querier, ino uint64) error {
		if _, err := tx.Exec(`INSERT INTO ocontent (inode) VALUES (?)`, int64(ino)); err != nil {
			return err
		}
		// The body lands before commit; a crash leaves at worst an orphan
		// for a never-committed inode, truncated on the number's eventual
		// reuse (numbers themselves are never reissued after commit).
		return fs.content.Create(ino)
	})
}

// Mkdir makes a new directory. Parent link counts are not maintained in
// the overlay (seal recomputes directory nlink from surviving edges).
func (fs *FS) Mkdir(ctx context.Context, parent uint64, name string, mode, uid, gid uint32) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := nowNS()
	return fs.createNodeLocked(ctx, parent, name, Node{
		Type: catalog.TypeDir, Mode: mode, UID: uid, GID: gid,
		MtimeNS: now, CtimeNS: now, Nlink: 2,
	}, nil)
}

// Symlink makes a new symbolic link to target.
func (fs *FS) Symlink(ctx context.Context, parent uint64, name, target string, uid, gid uint32) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := nowNS()
	return fs.createNodeLocked(ctx, parent, name, Node{
		Type: catalog.TypeSymlink, Mode: 0777, UID: uid, GID: gid,
		MtimeNS: now, CtimeNS: now, Nlink: 1, Length: int64(len(target)),
	}, func(tx querier, ino uint64) error {
		_, err := tx.Exec(`INSERT INTO osymlink (inode, target) VALUES (?, ?)`, int64(ino), []byte(target))
		return err
	})
}

// Mknod makes a special file (fifo/dev/socket) with the catalog type
// constants; regular files should use Create.
func (fs *FS) Mknod(ctx context.Context, parent uint64, name string, typ uint8, mode, uid, gid, rdev uint32) (Node, error) {
	switch typ {
	case catalog.TypeFIFO, catalog.TypeBlockDev, catalog.TypeCharDev, catalog.TypeSocket:
	default:
		return Node{}, fmt.Errorf("overlay: mknod of %s", typeName(typ))
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := nowNS()
	return fs.createNodeLocked(ctx, parent, name, Node{
		Type: typ, Mode: mode, UID: uid, GID: gid,
		MtimeNS: now, CtimeNS: now, Nlink: 1, Rdev: rdev,
	}, nil)
}

// baseHasEdgeLocked reports whether the base UNDER THIS OVERLAY has, or is
// about to have, an edge at (parent, name) — the whiteout-needed test when
// an oedge goes away. q must be the caller's active handle
// (single-connection pool).
//
// "Is about to" is not a hedge: a frozen snapshot that has not been rebased
// yet is a generation already being published, and every name in it will be
// served by the base the moment the swap lands. Asking only about the
// generation currently mounted is what left rename sources, unlinked names
// and rmdir'd directories visible after a mid-session checkpoint
// (pendingBaseNameLocked, snapshot.go).
func (fs *FS) baseHasEdgeLocked(ctx context.Context, q querier, parent uint64, name string) (bool, error) {
	if fs.pendingBaseNameLocked(parent, name) {
		return true, nil
	}
	backed, err := fs.baseBackedLocked(q, parent)
	if err != nil || !backed {
		return false, err
	}
	if err := fs.ensureBaseLocked(ctx, q, parent); err != nil {
		return false, err
	}
	_, err = fs.baseLookupLocked(ctx, parent, name)
	if errors.Is(err, ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// dropNodeRefLocked decrements the link count after an edge to ino went
// away. At zero the inode's rows and staging file go (an overlay-new inode
// vanishes entirely; a base-backed one stays expressed by the whiteouts on
// its base edges).
//
// An inode with no onode row is one this session has not touched, so the
// count to decrement is the BASE generation's, and hint carries it when the
// caller resolved the name through base (Unlink and Rename both did, one
// query ago). It is decremented by MATERIALIZING the row — but only when
// there is something left to count. Two cases, and the difference between
// them is the whole of this function's cost on an `rm -rf`:
//
//   - nlink 1, the overwhelmingly common one: the name being removed is the
//     only one, the whiteout expresses the deletion completely, and no row
//     is written. A removal stays one whiteout, which is what makes
//     removing a published tree proportional to the tree.
//   - nlink > 1: names survive, and the count they publish has to shrink.
//     Nothing downstream will do it — the seal recomputes nlink from
//     surviving edges for DIRECTORIES only (publish.go, "A directory's link
//     count is a function of the namespace"); a file's count is a stored
//     attribute, and for a clean base-backed inode the stored attribute is
//     the base's stale one. So the row is materialized here, at one
//     decrement, and the row is also what puts the inode in the dirty set
//     (DirtyInodes reads the onode table) so that the seal descends to the
//     SURVIVING names and republishes them. Without the row the catalog
//     holding the survivor is not dirty, and a seal carries it forward
//     verbatim — stale count and all.
//
// The nlink-1 early return is not a hole in the same argument: an inode
// losing its last name is published by nobody, so no surviving catalog
// holds a count of it to correct.
func (fs *FS) dropNodeRefLocked(ctx context.Context, tx querier, ino uint64, hint *Node, removeStaging *uint64) error {
	row, err := getONode(tx, ino)
	if err != nil {
		return err
	}
	if row == nil {
		n := hint
		if n == nil {
			// Resolved through an oedge (a base inode this session renamed,
			// say), so nothing handed us the base attributes.
			if err := fs.ensureBaseLocked(ctx, tx, ino); err != nil {
				return err
			}
			bn, err := fs.base.GetAttr(ctx, ino)
			if err != nil {
				return err
			}
			n = &bn
		}
		if n.Nlink <= 1 {
			return nil
		}
		// No persistChainLocked here, unlike Link: the inode is losing a
		// name, not gaining one at a path the base does not have, so at
		// least one base name still walks to it and residency is still
		// reachable the way it always was.
		row = &onodeRow{Node: *n, base: true}
	}
	if row.Nlink > 1 {
		row.Nlink--
		row.CtimeNS = nowNS()
		return putONode(tx, row)
	}
	return fs.purgeNodeLocked(tx, ino, removeStaging)
}

// purgeNodeLocked removes every per-inode row; the staging path is
// reported for post-commit removal (files must not vanish before the
// transaction that stops referencing them commits).
func (fs *FS) purgeNodeLocked(tx querier, ino uint64, removeStaging *uint64) error {
	for _, q := range []string{
		`DELETE FROM onode WHERE inode = ?`,
		`DELETE FROM oxattr WHERE inode = ?`,
		`DELETE FROM osymlink WHERE inode = ?`,
	} {
		if _, err := tx.Exec(q, int64(ino)); err != nil {
			return err
		}
	}
	res, err := tx.Exec(`DELETE FROM ocontent WHERE inode = ?`, int64(ino))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 && removeStaging != nil {
		*removeStaging = ino
	}
	return nil
}

// Unlink removes a non-directory name from the merged view: a base
// target gets a whiteout, an overlay edge is deleted (plus a whiteout if
// it was shadowing a base name).
func (fs *FS) Unlink(ctx context.Context, parent uint64, name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(parent)
	r, err := fs.resolveLocked(ctx, parent, name)
	if err != nil {
		return err
	}
	if r.typ == catalog.TypeDir {
		return ErrIsDir
	}
	// The target's own rows change too (a surviving link's nlink, or a
	// purge), which the dirty set cannot express once they are gone.
	fs.bumpSeqLocked(r.ino)
	var removeStaging uint64
	err = fs.withTx(func(tx querier) error {
		if err := fs.removeEdgeLocked(ctx, tx, parent, name, r.overlay); err != nil {
			return err
		}
		return fs.dropNodeRefLocked(ctx, tx, r.ino, r.node, &removeStaging)
	})
	if err == nil && removeStaging != 0 {
		if drop := fs.content.Drop(removeStaging); drop != nil {
			drop()
		}
	}
	return err
}

// removeEdgeLocked makes (parent, name) resolve to nothing: delete the
// oedge if one exists, and leave a whiteout whenever base still has the
// name underneath.
func (fs *FS) removeEdgeLocked(ctx context.Context, tx querier, parent uint64, name string, overlayEdge bool) error {
	if overlayEdge {
		if err := deleteOEdge(tx, parent, name); err != nil {
			return err
		}
		shadow, err := fs.baseHasEdgeLocked(ctx, tx, parent, name)
		if err != nil {
			return err
		}
		if !shadow {
			return nil
		}
	}
	return putWhiteout(tx, parent, name)
}

// emptyDirLocked verifies the MERGED view of dir ino is empty: no live
// overlay edges, and every base entry covered by a whiteout.
func (fs *FS) emptyDirLocked(ctx context.Context, ino uint64) error {
	var live int64
	if err := fs.q.QueryRow(`SELECT count(*) FROM oedge WHERE parent = ? AND inode <> 0`,
		int64(ino)).Scan(&live); err != nil {
		return err
	}
	if live > 0 {
		return ErrNotEmpty
	}
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil || !backed {
		return err
	}
	if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
		return err
	}
	bes, err := fs.base.Readdir(ctx, ino)
	if err != nil {
		return err
	}
	for _, be := range bes {
		var eIno int64
		err := fs.q.QueryRow(`SELECT inode FROM oedge WHERE parent = ? AND name = ?`,
			int64(ino), []byte(be.Name)).Scan(&eIno)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotEmpty
		}
		if err != nil {
			return err
		}
		// Live edges were counted above; a hit here is a whiteout.
	}
	return nil
}

// removeDirLocked drops dir ino's rows once emptiness is verified: the
// spent whiteouts under it, its own attribute and xattr rows.
func (fs *FS) removeDirLocked(tx querier, ino uint64) error {
	if _, err := tx.Exec(`DELETE FROM oedge WHERE parent = ?`, int64(ino)); err != nil {
		return err
	}
	return fs.purgeNodeLocked(tx, ino, nil)
}

// Rmdir removes a directory that is empty in the MERGED view (base
// children must already be whiteouted, overlay children unlinked).
func (fs *FS) Rmdir(ctx context.Context, parent uint64, name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(parent)
	r, err := fs.resolveLocked(ctx, parent, name)
	if err != nil {
		return err
	}
	if r.typ != catalog.TypeDir {
		return ErrNotDir
	}
	if err := fs.emptyDirLocked(ctx, r.ino); err != nil {
		return err
	}
	fs.bumpSeqLocked(r.ino)
	return fs.withTx(func(tx querier) error {
		if err := fs.removeDirLocked(tx, r.ino); err != nil {
			return err
		}
		return fs.removeEdgeLocked(ctx, tx, parent, name, r.overlay)
	})
}

// Rename moves one edge in a single transaction. Renaming a BASE entry
// is a whiteout at the source plus an oedge at the destination pointing
// at the SAME inode — stable inodes make this free, and subtree contents
// follow because children resolve via the moved inode. An existing
// destination is replaced atomically (directories only when empty in the
// merged view). Loop prevention (moving a directory into its own
// subtree) is left to the binding, which is the layer that already walks
// ancestors and can answer it without a second descent here.
func (fs *FS) Rename(ctx context.Context, srcParent uint64, srcName string, dstParent uint64, dstName string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(srcParent, dstParent)
	src, err := fs.resolveLocked(ctx, srcParent, srcName)
	if err != nil {
		return err
	}
	// Same-name no-op only AFTER the source resolves: rename("x","x") on
	// a nonexistent x is ENOENT, not success (op-fuzzer finding).
	if srcParent == dstParent && srcName == dstName {
		return nil
	}
	// The moved inode is named by the destination oedge, which is exactly
	// what the table-derived dirty set reports for it.
	fs.markDirtyLocked(src.ino)
	dst, dstErr := fs.resolveLocked(ctx, dstParent, dstName)
	if dstErr != nil && !errors.Is(dstErr, ErrNotExist) {
		return dstErr
	}
	if dstErr == nil {
		if dst.ino == src.ino {
			return nil // hardlinks to the same inode: POSIX no-op
		}
		fs.bumpSeqLocked(dst.ino) // replaced: its rows go or lose a link
		srcDir := src.typ == catalog.TypeDir
		dstDir := dst.typ == catalog.TypeDir
		switch {
		case srcDir && !dstDir:
			return ErrNotDir
		case !srcDir && dstDir:
			return ErrIsDir
		case dstDir:
			if err := fs.emptyDirLocked(ctx, dst.ino); err != nil {
				return err
			}
		}
	}
	var removeStaging uint64
	err = fs.withTx(func(tx querier) error {
		if dstErr == nil {
			// Replace the destination. No whiteout at the destination
			// name: the incoming oedge shadows any base entry there.
			if dst.overlay {
				if err := deleteOEdge(tx, dstParent, dstName); err != nil {
					return err
				}
			}
			if dst.typ == catalog.TypeDir {
				if err := fs.removeDirLocked(tx, dst.ino); err != nil {
					return err
				}
			} else if err := fs.dropNodeRefLocked(ctx, tx, dst.ino, dst.node, &removeStaging); err != nil {
				return err
			}
		}
		if src.overlay {
			if err := fs.removeEdgeLocked(ctx, tx, srcParent, srcName, true); err != nil {
				return err
			}
		} else {
			// Detaching a base entry: its merged path no longer matches
			// its base path, so persist the original edge chain for
			// residency replay after reopen.
			if err := fs.persistChainLocked(tx, src.ino); err != nil {
				return err
			}
			if err := putWhiteout(tx, srcParent, srcName); err != nil {
				return err
			}
		}
		return putOEdge(tx, dstParent, dstName, src.ino, src.typ)
	})
	if err == nil && removeStaging != 0 {
		if drop := fs.content.Drop(removeStaging); drop != nil {
			drop()
		}
	}
	return err
}

// materializeAttrsLocked ensures ino has an onode row, seeding it from
// base attributes on first touch.
func (fs *FS) materializeAttrsLocked(ctx context.Context, tx querier, ino uint64) (*onodeRow, error) {
	row, err := getONode(tx, ino)
	if err != nil || row != nil {
		return row, err
	}
	if err := fs.ensureBaseLocked(ctx, tx, ino); err != nil {
		return nil, err
	}
	n, err := fs.base.GetAttr(ctx, ino)
	if err != nil {
		return nil, err
	}
	row = &onodeRow{Node: n, base: true}
	if err := putONode(tx, row); err != nil {
		return nil, err
	}
	return row, nil
}

// materializeContentLocked gives ino a writable body: file-granular COW.
// The first copyLen bytes of base content are copied in (callers pass the
// full length for writes, the surviving length for truncates), and only
// then does the publishing row join the transaction — a crash before
// commit leaves an invisible orphan.
//
// The copy is why the write path exists to replace this store: writing
// one byte of a clean file costs the whole file, and for a file that only
// the base generation holds, "the whole file" is a download.
func (fs *FS) materializeContentLocked(ctx context.Context, tx querier, row *onodeRow, copyLen int64) error {
	staged, err := hasContent(tx, row.Inode)
	if err != nil || staged {
		return err
	}
	if row.Type != catalog.TypeFile {
		return fmt.Errorf("overlay: content write on %s inode %d", typeName(row.Type), row.Inode)
	}
	if copyLen > row.Length {
		copyLen = row.Length
	}
	base := baseFile{ino: row.Inode}
	if copyLen > 0 {
		if err := fs.ensureBaseLocked(ctx, tx, row.Inode); err != nil {
			return err
		}
		base.body = &baseReader{ctx: ctx, fs: fs, ino: row.Inode}
	}
	if err := fs.content.Adopt(ctx, row.Inode, copyLen, base); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO ocontent (inode) VALUES (?)`, int64(row.Inode))
	return err
}

// baseReader streams one inode out of the base generation, which is what
// a content store adopting a clean file reads from.
type baseReader struct {
	ctx context.Context
	fs  *FS
	ino uint64
	off int64
}

func (r *baseReader) Read(p []byte) (int, error) {
	n, err := r.fs.base.Read(r.ctx, r.ino, r.off, p)
	r.off += int64(n)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return n, nil
}

// Write stores data at off, staging base content first (COW at file
// granularity). The byte count is always len(data) on success.
func (fs *FS) Write(ctx context.Context, ino uint64, off int64, data []byte) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("overlay: negative write offset %d", off)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(ino)
	err := fs.withTx(func(tx querier) error {
		row, err := fs.materializeAttrsLocked(ctx, tx, ino)
		if err != nil {
			return err
		}
		if row.Type != catalog.TypeFile {
			return fmt.Errorf("overlay: write on %s inode %d", typeName(row.Type), ino)
		}
		if err := fs.materializeContentLocked(ctx, tx, row, row.Length); err != nil {
			return err
		}
		if err := fs.content.WriteAt(ctx, ino, off, data); err != nil {
			return err
		}
		if end := off + int64(len(data)); end > row.Length {
			row.Length = end
		}
		now := nowNS()
		row.MtimeNS = now
		row.CtimeNS = now
		return putONode(tx, row)
	})
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// SetAttrIn selects which attributes SetAttr changes; nil fields are
// left alone. Size on a regular file is truncate (content COW applies).
type SetAttrIn struct {
	Mode    *uint32
	UID     *uint32
	GID     *uint32
	MtimeNS *int64
	Size    *int64
}

// SetAttr applies chmod/chown/utimens/truncate to the merged view,
// materializing the onode row (and, for truncate, content) on first
// touch of a base inode.
func (fs *FS) SetAttr(ctx context.Context, ino uint64, in SetAttrIn) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(ino)
	var out Node
	err := fs.withTx(func(tx querier) error {
		row, err := fs.materializeAttrsLocked(ctx, tx, ino)
		if err != nil {
			return err
		}
		now := nowNS()
		if in.Size != nil {
			if row.Type != catalog.TypeFile {
				return fmt.Errorf("overlay: truncate on %s inode %d", typeName(row.Type), ino)
			}
			if *in.Size < 0 {
				return fmt.Errorf("overlay: negative truncate length %d", *in.Size)
			}
			// Only the surviving prefix is copied; extension zero-fills
			// via ftruncate.
			if err := fs.materializeContentLocked(ctx, tx, row, *in.Size); err != nil {
				return err
			}
			if err := fs.content.Truncate(ctx, ino, *in.Size); err != nil {
				return err
			}
			row.Length = *in.Size
			row.MtimeNS = now
		}
		if in.Mode != nil {
			row.Mode = *in.Mode
		}
		if in.UID != nil {
			row.UID = *in.UID
		}
		if in.GID != nil {
			row.GID = *in.GID
		}
		if in.MtimeNS != nil {
			row.MtimeNS = *in.MtimeNS
		}
		row.CtimeNS = now
		if err := putONode(tx, row); err != nil {
			return err
		}
		out = row.Node
		return nil
	})
	if err != nil {
		return Node{}, err
	}
	return out, nil
}

// Link adds a hard link to a regular file, materializing the onode row
// for nlink bookkeeping (and the base edge chain, since the inode now
// lives at a path that is not its base path).
func (fs *FS) Link(ctx context.Context, ino uint64, parent uint64, name string) (Node, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(ino, parent)
	n, err := fs.attrsLocked(ctx, ino, nil)
	if err != nil {
		return Node{}, err
	}
	if n.Type == catalog.TypeDir {
		return Node{}, ErrIsDir
	}
	if err := fs.checkParentDirLocked(ctx, parent); err != nil {
		return Node{}, err
	}
	if err := fs.checkAbsentLocked(ctx, parent, name); err != nil {
		return Node{}, err
	}
	var out Node
	err = fs.withTx(func(tx querier) error {
		row, err := fs.materializeAttrsLocked(ctx, tx, ino)
		if err != nil {
			return err
		}
		if row.base {
			if err := fs.persistChainLocked(tx, ino); err != nil {
				return err
			}
		}
		row.Nlink++
		row.CtimeNS = nowNS()
		if err := putONode(tx, row); err != nil {
			return err
		}
		if err := putOEdge(tx, parent, name, ino, row.Type); err != nil {
			return err
		}
		out = row.Node
		return nil
	})
	if err != nil {
		return Node{}, err
	}
	return out, nil
}

// SetXattr sets one extended attribute (new or overwriting base).
func (fs *FS) SetXattr(ctx context.Context, ino uint64, name string, value []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(ino)
	if _, err := fs.attrsLocked(ctx, ino, nil); err != nil {
		return err
	}
	return fs.withTx(func(tx querier) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO oxattr (inode, name, value, tombstone) VALUES (?, ?, ?, 0)`,
			int64(ino), []byte(name), value)
		return err
	})
}

// RemoveXattr removes one extended attribute from the merged view: a
// base attribute gets a tombstone row (honored by Get and List), an
// overlay-only attribute's row is deleted.
func (fs *FS) RemoveXattr(ctx context.Context, ino uint64, name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.markDirtyLocked(ino)
	_, tomb, found, err := getOXattr(fs.q, ino, name)
	if err != nil {
		return err
	}
	if found && tomb {
		return ErrNotExist
	}
	baseHas := false
	backed, err := fs.baseBackedLocked(fs.q, ino)
	if err != nil {
		return err
	}
	if backed {
		if err := fs.ensureBaseLocked(ctx, fs.db, ino); err != nil {
			return err
		}
		_, err := fs.base.GetXattr(ctx, ino, name)
		if err == nil {
			baseHas = true
		} else if !errors.Is(err, ErrNotExist) {
			return err
		}
	}
	if !found && !baseHas {
		return ErrNotExist
	}
	return fs.withTx(func(tx querier) error {
		if baseHas {
			_, err := tx.Exec(`INSERT OR REPLACE INTO oxattr (inode, name, value, tombstone) VALUES (?, ?, NULL, 1)`,
				int64(ino), []byte(name))
			return err
		}
		_, err := tx.Exec(`DELETE FROM oxattr WHERE inode = ? AND name = ?`, int64(ino), []byte(name))
		return err
	})
}
