package publish

import (
	"database/sql"
	"errors"
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
// sound only while the pack set is append-only across the gap. A repack
// breaks that gap in both directions — it publishes a generation, and it
// drops packs — so it carries the index across itself, keeping exactly
// the live set its sweep computed: RestampDedupIndex, below. Before that
// existed the sidecar was not merely stale after a repack, it was
// discarded, and the first seal after one re-uploaded everything the
// index would have spared it.

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
	return writeDedupIndex(p.o.DedupIndexPath, p.volUUID, p.o.Branch, gen,
		func(add func(id []byte, info chunkInfo) error) error {
			for id, info := range p.chunkSeen {
				if err := add(id[:], info); err != nil {
					return err
				}
			}
			return nil
		})
}

// writeDedupIndex writes a whole sidecar and moves it into place, which is
// the only way one is ever updated: a sidecar is READ as a set of promises
// that a chunk is already stored, so a half-applied edit is a file that
// promises something untrue. Rename makes the whole set land or none of it.
func writeDedupIndex(path, volUUID, branch string, gen uint64,
	rows func(add func(id []byte, info chunkInfo) error) error) error {

	tmp := path + ".tmp"
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
		"volume":     volUUID,
		"branch":     branch,
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
	if err := rows(func(id []byte, info chunkInfo) error {
		_, err := stmt.Exec(id, info.clen, info.alg, info.keyID)
		return err
	}); err != nil {
		stmt.Close()  //nolint:errcheck
		tx.Rollback() //nolint:errcheck
		db.Close()    //nolint:errcheck
		return err
	}
	stmt.Close() //nolint:errcheck
	if err := tx.Commit(); err != nil {
		db.Close() //nolint:errcheck
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RestampOptions describes the generation a repack published and how to
// ask whether a stored identity is still live.
type RestampOptions struct {
	// VolumeID and Branch are the volume and branch the sidecar must
	// already name; a sidecar naming anything else belongs to somebody
	// else and is left exactly as it is.
	VolumeID [16]byte
	Branch   string
	// PrevGen is the generation the sidecar must be stamped with — the
	// one the repack grew from — and NewGen is the one it published.
	PrevGen, NewGen uint64
	// Live reports whether an identity is still reachable. Required: a
	// restamp without one would promise that chunks a repack has just
	// dropped are still stored.
	Live func(identity []byte) bool
}

// Restamped is what RestampDedupIndex did.
type Restamped struct {
	// Rewritten is false when there was nothing to carry: no sidecar, or
	// one stamped for another volume, branch, or generation. It is not an
	// error — the index is an optimization, never an authority.
	Rewritten bool
	// Kept and Dropped count the rows carried and the rows discarded.
	Kept, Dropped int
}

// RestampDedupIndex carries a dedup sidecar across a repack: it keeps
// exactly the rows Live still reaches and stamps the result with the
// generation the repack published.
//
// This is the operation dedup.go's own comment asks for at the top of this
// file — "a v2 repack must rewrite the index with exactly the live set it
// computed" — and it lives here, next to the schema and the loader, so
// that the reader and the writer of this file cannot drift apart. What it
// must not do is ADD a row: the caller's liveness oracle speaks for the
// whole volume, including branches this sidecar has no business
// deduplicating against, while every row already present was written by a
// publish on this branch.
func RestampDedupIndex(path string, o RestampOptions) (Restamped, error) {
	var got Restamped
	if path == "" {
		return got, nil
	}
	if o.Live == nil {
		return got, errors.New("publish: RestampDedupIndex needs a liveness oracle")
	}
	if _, err := os.Stat(path); err != nil {
		return got, nil // no index yet, nothing to carry
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return got, err
	}
	defer db.Close() //nolint:errcheck
	volUUID := formatVolumeID(o.VolumeID)
	meta := make(map[string]string)
	mrows, err := db.Query(`SELECT key, value FROM dedup_meta`)
	if err != nil {
		return got, nil // unreadable index = no index
	}
	for mrows.Next() {
		var k, v string
		if mrows.Scan(&k, &v) == nil {
			meta[k] = v
		}
	}
	_ = mrows.Close()
	if meta["volume"] != volUUID || meta["branch"] != o.Branch ||
		meta["generation"] != fmt.Sprint(o.PrevGen) {
		// A sidecar the next seal would have ignored anyway. Left alone
		// rather than deleted: it costs one file, and whoever it does
		// belong to is the one entitled to overwrite it.
		return got, nil
	}

	// Read the whole surviving set into memory before writing, because the
	// destination is this same file: streaming from the reader into the
	// writer would leave the outcome depending on which one the rename
	// beat. The set is bounded by the volume's distinct chunk count and
	// each row is ~56 bytes, which is the same bound the loader already
	// accepts on every seal.
	type row struct {
		id   []byte
		info chunkInfo
	}
	var keep []row
	crows, err := db.Query(`SELECT identity, clen, alg, keyid FROM dedup_chunk`)
	if err != nil {
		return got, nil
	}
	for crows.Next() {
		var idb []byte
		var info chunkInfo
		if err := crows.Scan(&idb, &info.clen, &info.alg, &info.keyID); err != nil ||
			len(idb) != chunkid.IdentitySize {
			continue
		}
		if !o.Live(idb) {
			got.Dropped++
			continue
		}
		keep = append(keep, row{idb, info})
	}
	err = crows.Err()
	_ = crows.Close()
	if err != nil {
		return Restamped{}, err
	}
	if err := writeDedupIndex(path, volUUID, o.Branch, o.NewGen,
		func(add func(id []byte, info chunkInfo) error) error {
			for _, r := range keep {
				if err := add(r.id, r.info); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return Restamped{}, err
	}
	got.Rewritten, got.Kept = true, len(keep)
	return got, nil
}
