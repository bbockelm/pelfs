package publish

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/bbockelm/pelfs/internal/chunkid"
	_ "modernc.org/sqlite"
)

// The dedup index is a LOCAL sidecar (volume state directory) mapping
// chunk identity -> (clen, alg, keyid) for every chunk stored by this
// branch's generations. Loading it lets TRANSFORM skip re-encoding and
// re-uploading content that already lives in a carried-forward pack.
//
// Correctness never depends on it: content addressing makes a re-upload
// a harmless duplicate, so a missing, stale, or foreign index only costs
// bandwidth. The index is USED only when its recorded head generation
// matches the generation being built on (Prev), because its entries are
// sound only while the pack set is append-only across the gap — a v2
// repack, when it lands, must rewrite the index with exactly the live
// set it computed (it walks catalogs for liveness anyway).

const dedupSchema = `
CREATE TABLE IF NOT EXISTS dedup_meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dedup_chunk (
  identity BLOB PRIMARY KEY,
  clen     INTEGER NOT NULL,
  alg      INTEGER NOT NULL,
  keyid    INTEGER NOT NULL
) WITHOUT ROWID;
`

// loadDedupIndex populates chunkSeen from the sidecar when it matches
// this volume, branch, and predecessor generation; any mismatch is
// silently ignored (the index is an optimization, never an authority).
func (p *pipeline) loadDedupIndex() error {
	if p.o.DedupIndexPath == "" || p.o.Prev == nil {
		return nil
	}
	if _, err := os.Stat(p.o.DedupIndexPath); err != nil {
		return nil // no index yet
	}
	db, err := sql.Open("sqlite", "file:"+p.o.DedupIndexPath+"?mode=ro")
	if err != nil {
		return nil
	}
	defer db.Close() //nolint:errcheck
	meta := make(map[string]string)
	rows, err := db.Query(`SELECT key, value FROM dedup_meta`)
	if err != nil {
		return nil // unreadable index = no index
	}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			meta[k] = v
		}
	}
	_ = rows.Close()
	if meta["volume"] != p.volUUID || meta["branch"] != p.o.Branch ||
		meta["generation"] != fmt.Sprint(p.o.Prev.Generation) {
		return nil
	}
	crows, err := db.Query(`SELECT identity, clen, alg, keyid FROM dedup_chunk`)
	if err != nil {
		return nil
	}
	defer crows.Close() //nolint:errcheck
	for crows.Next() {
		var idb []byte
		var info chunkInfo
		if err := crows.Scan(&idb, &info.clen, &info.alg, &info.keyID); err != nil || len(idb) != chunkid.IdentitySize {
			continue
		}
		p.chunkSeen[chunkid.Identity(idb)] = info
		p.stats.DedupIndexChunks++
	}
	return nil
}

// saveDedupIndex records the full post-publish chunk set stamped with the
// NEW generation. Best-effort: failure is reported to the caller's stderr
// path via the returned error but must never fail the publish (the flip
// already happened).
func (p *pipeline) saveDedupIndex(gen uint64) error {
	if p.o.DedupIndexPath == "" {
		return nil
	}
	tmp := p.o.DedupIndexPath + ".tmp"
	_ = os.Remove(tmp)
	db, err := sql.Open("sqlite", "file:"+tmp)
	if err != nil {
		return err
	}
	if _, err := db.Exec(dedupSchema); err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	for k, v := range map[string]string{
		"volume":     p.volUUID,
		"branch":     p.o.Branch,
		"generation": fmt.Sprint(gen),
	} {
		if _, err := tx.Exec(`INSERT INTO dedup_meta (key, value) VALUES (?, ?)`, k, v); err != nil {
			tx.Rollback() //nolint:errcheck
			db.Close()    //nolint:errcheck
			return err
		}
	}
	stmt, err := tx.Prepare(`INSERT INTO dedup_chunk (identity, clen, alg, keyid) VALUES (?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback() //nolint:errcheck
		db.Close()    //nolint:errcheck
		return err
	}
	for id, info := range p.chunkSeen {
		if _, err := stmt.Exec(id[:], info.clen, info.alg, info.keyID); err != nil {
			stmt.Close()  //nolint:errcheck
			tx.Rollback() //nolint:errcheck
			db.Close()    //nolint:errcheck
			return err
		}
	}
	stmt.Close() //nolint:errcheck
	if err := tx.Commit(); err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p.o.DedupIndexPath)
}
