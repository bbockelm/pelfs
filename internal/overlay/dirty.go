package overlay

import (
	"os"
)

// DirtyNode is one changed inode: overlay-new (Base false) or a base
// inode with modified attributes/content (Base true).
type DirtyNode struct {
	Node Node
	Base bool
}

// DirtyEdge is one changed name: Inode 0 is a whiteout (the base name is
// deleted), anything else binds Name to Inode in the merged view
// (replacing any base entry of the same name).
type DirtyEdge struct {
	Parent uint64
	Name   string
	Inode  uint64
	Type   uint8
}

// DirtyXattr is one changed extended attribute; Removed marks a
// tombstone over a base attribute.
type DirtyXattr struct {
	Inode   uint64
	Name    string
	Value   []byte
	Removed bool
}

// DirtySymlink is one overlay-created symlink target.
type DirtySymlink struct {
	Inode  uint64
	Target string
}

// DirtyReport is the whole changed set in one value: everything the
// overlay changed relative to the base generation, in deterministic order
// (nodes, content, symlinks by inode; edges by parent then name; xattrs
// by inode then name).
type DirtyReport struct {
	Nodes    []DirtyNode
	Edges    []DirtyEdge
	Xattrs   []DirtyXattr
	Symlinks []DirtySymlink
	// Content lists inodes whose bytes live in staging files, ascending.
	Content []uint64
}

// Dirty enumerates the changed set. The overlay database rows ARE the
// dirty markers, so this is a straight ordered dump.
func (fs *FS) Dirty() (*DirtyReport, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rep := &DirtyReport{}

	rows, err := fs.q.Query(`SELECT inode, type, mode, uid, gid, mtime_ns, ctime_ns, nlink, length, rdev, flags, base
		FROM onode ORDER BY inode`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n Node
		var base int64
		if err := rows.Scan(&n.Inode, &n.Type, &n.Mode, &n.UID, &n.GID, &n.MtimeNS, &n.CtimeNS,
			&n.Nlink, &n.Length, &n.Rdev, &n.Flags, &base); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		rep.Nodes = append(rep.Nodes, DirtyNode{Node: n, Base: base != 0})
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT parent, name, inode, type FROM oedge ORDER BY parent, name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e DirtyEdge
		var name []byte
		if err := rows.Scan(&e.Parent, &name, &e.Inode, &e.Type); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		e.Name = string(name)
		rep.Edges = append(rep.Edges, e)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode, name, value, tombstone FROM oxattr ORDER BY inode, name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x DirtyXattr
		var name []byte
		var tomb int64
		if err := rows.Scan(&x.Inode, &name, &x.Value, &tomb); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		x.Name = string(name)
		x.Removed = tomb != 0
		rep.Xattrs = append(rep.Xattrs, x)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode, target FROM osymlink ORDER BY inode`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s DirtySymlink
		var target []byte
		if err := rows.Scan(&s.Inode, &target); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		s.Target = string(target)
		rep.Symlinks = append(rep.Symlinks, s)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}

	rows, err = fs.q.Query(`SELECT inode FROM ocontent ORDER BY inode`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ino uint64
		if err := rows.Scan(&ino); err != nil {
			rows.Close() //nolint:errcheck
			return nil, err
		}
		rep.Content = append(rep.Content, ino)
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	return rep, nil
}

// Stats is the writeback-cap plumbing's view of overlay pressure.
type Stats struct {
	// DirtyNodes counts onode rows (new or attribute-dirty inodes).
	DirtyNodes int
	// DirtyEdges counts oedge rows, whiteouts included.
	DirtyEdges int
	// StagedFiles counts inodes with staged content.
	StagedFiles int
	// StagedBytes sums the staging files' sizes.
	StagedBytes int64
}

// Stats reports dirty counts and staged bytes.
func (fs *FS) Stats() (Stats, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	var s Stats
	if err := fs.q.QueryRow(`SELECT count(*) FROM onode`).Scan(&s.DirtyNodes); err != nil {
		return Stats{}, err
	}
	if err := fs.q.QueryRow(`SELECT count(*) FROM oedge`).Scan(&s.DirtyEdges); err != nil {
		return Stats{}, err
	}
	rows, err := fs.q.Query(`SELECT inode FROM ocontent ORDER BY inode`)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close() //nolint:errcheck
	for rows.Next() {
		var ino uint64
		if err := rows.Scan(&ino); err != nil {
			return Stats{}, err
		}
		s.StagedFiles++
		if fi, err := os.Stat(fs.stagingPath(ino)); err == nil {
			s.StagedBytes += fi.Size()
		}
	}
	if err := rows.Err(); err != nil {
		return Stats{}, err
	}
	return s, nil
}

// closeRows finishes an iteration, preferring the iteration error.
func closeRows(rows interface {
	Err() error
	Close() error
}) error {
	if err := rows.Err(); err != nil {
		rows.Close() //nolint:errcheck
		return err
	}
	return rows.Close()
}
