package hydrate

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Slice kinds in the sidecar's slice_map.
const (
	sliceKindPack   = 0 // bytes live in a pack entry (range-read + decode)
	sliceKindInline = 1 // bytes live in the sidecar row itself
)

// sliceRow maps one synthetic slice id to where its decoded bytes come
// from. Pack rows carry the pack location of the stored entry plus the
// decode parameters from the chunkref (alg/keyid are per-chunk columns,
// never sniffed); inline rows carry the bytes outright.
type sliceRow struct {
	id       uint64
	kind     int
	identity []byte
	pack     string
	off      int64
	length   int64 // stored entry length in the pack (== clen)
	clen     int64
	alg      int64
	keyid    int64
	llen     int64 // decoded length; also the slice size
	inline   []byte
}

const sidecarSchema = `
CREATE TABLE sidecar_meta (
	key   TEXT PRIMARY KEY,
	value BLOB
) WITHOUT ROWID;
CREATE TABLE slice_map (
	slice_id INTEGER PRIMARY KEY,
	kind     INTEGER NOT NULL,
	identity BLOB,
	pack     TEXT,
	off      INTEGER,
	length   INTEGER,
	clen     INTEGER,
	alg      INTEGER,
	keyid    INTEGER,
	llen     INTEGER NOT NULL,
	inline   BLOB
);
`

const sidecarBlockSizeKey = "block_size"

// writeSidecar creates the sidecar database. blockSize is the rebuilt
// volume's block BYTE size (Format.BlockSize is KiB); NewBlob needs it to
// turn a block index into an offset within the decoded slice.
func writeSidecar(path string, blockSize int64, rows []sliceRow) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(OFF)&_pragma=synchronous(OFF)")
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sidecarSchema); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`INSERT INTO sidecar_meta (key, value) VALUES (?, ?)`,
		sidecarBlockSizeKey, []byte(strconv.FormatInt(blockSize, 10))); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO slice_map
		(slice_id, kind, identity, pack, off, length, clen, alg, keyid, llen, inline)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:errcheck
	for _, r := range rows {
		var identity, inline any
		if r.identity != nil {
			identity = r.identity
		}
		if r.inline != nil {
			inline = r.inline
		}
		if _, err := stmt.Exec(r.id, r.kind, identity, r.pack, r.off, r.length,
			r.clen, r.alg, r.keyid, r.llen, inline); err != nil {
			return fmt.Errorf("slice %d: %w", r.id, err)
		}
	}
	return tx.Commit()
}

// openSidecar opens an existing sidecar read-only and returns the handle
// plus the recorded block size.
func openSidecar(path string) (*sql.DB, int64, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, 0, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, 0, err
	}
	var raw []byte
	if err := db.QueryRow(`SELECT value FROM sidecar_meta WHERE key = ?`, sidecarBlockSizeKey).Scan(&raw); err != nil {
		db.Close() //nolint:errcheck
		return nil, 0, fmt.Errorf("sidecar %s: read %s: %w", path, sidecarBlockSizeKey, err)
	}
	blockSize, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || blockSize <= 0 {
		db.Close() //nolint:errcheck
		return nil, 0, fmt.Errorf("sidecar %s: bad %s %q", path, sidecarBlockSizeKey, raw)
	}
	return db, blockSize, nil
}
