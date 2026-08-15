package mountfs

import (
	"database/sql"
	"fmt"
	"os"
)

// squashOwnership normalizes every inode in the local metadata database to
// the given uid/gid, returning how many rows changed.
//
// A pelfs volume is single-user scratch space, but sessions run under
// whatever identity their backend dictates — the Docker fallback is root,
// native mounts are the invoking user — so files accumulate foreign uids.
// A FUSE mount enforces mode bits in the kernel (default_permissions)
// against the accessor's uid, silently rejecting writes to another
// session's files. Since the metadata is a local SQLite file (restored from
// the latest snapshot moments earlier), normalizing ownership is one UPDATE
// before the mount starts; the session's snapshots then carry the
// normalized ownership back to the federation.
func squashOwnership(metaPath string, uid, gid uint32) (int64, error) {
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		// Fresh volume: nothing to squash (and sql.Open must not create an
		// empty database file here).
		return 0, nil
	}
	db, err := sql.Open("sqlite3", metaPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	res, err := db.Exec("UPDATE jfs_node SET uid = ?, gid = ? WHERE uid <> ? OR gid <> ?",
		uid, gid, uid, gid)
	if err != nil {
		return 0, fmt.Errorf("squash ownership: %w", err)
	}
	return res.RowsAffected()
}
