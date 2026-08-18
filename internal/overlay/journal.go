package overlay

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// contentJournal persists what a memtable content store must not lose to
// a crash: the operations that built each file's extent map, and the
// binding from extents to chunks to packs. It is memtable.Journal backed
// by SQLite.
//
// It is its OWN database file, on its own connection, and that is a
// decision rather than an accident. The overlay's database runs on a
// single connection with one transaction at a time, and a journal sharing
// it would deadlock: a writer inside a transaction blocks when the ring
// is full, the ring drains only when the flusher publishes, and the
// flusher's Located would be waiting for the connection that writer is
// holding. Separate files make that impossible to construct.
//
// What separate files cost is cross-file atomicity, and the reconciliation
// rule is what pays for it — in one direction only:
//
//   - The journal may hold entries for inodes the metadata never
//     committed. Replay produces a content map nothing in the namespace
//     names, which is garbage and is dropped.
//   - The metadata can never name content the journal lacks, because
//     content is written and journaled BEFORE the row that publishes it
//     commits. That is the same ordering the staging store has always
//     used, for the same reason.
type contentJournal struct {
	db *sql.DB
	// append is prepared once. It runs on every write in the session, and
	// re-parsing the same INSERT each time is pure overhead on the one
	// path where the overhead is visible: a streaming write is nothing
	// but this statement, repeated.
	append *sql.Stmt
}

const contentDBName = "content.db"

// The operation log is append-only and replayed in seq order; the other
// three tables are the location map, rewritten as flushes land.
const journalSchema = `
CREATE TABLE IF NOT EXISTS ojournal (
	seq     INTEGER PRIMARY KEY AUTOINCREMENT,
	op      INTEGER NOT NULL,
	inode   INTEGER NOT NULL,
	handle  INTEGER NOT NULL,
	fileoff INTEGER NOT NULL,
	length  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ohandle (
	handle INTEGER PRIMARY KEY,
	slices BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ochunk (
	identity TEXT PRIMARY KEY,
	pack     TEXT NOT NULL,
	off      INTEGER NOT NULL,
	stored   INTEGER NOT NULL,
	logical  INTEGER NOT NULL,
	alg      INTEGER NOT NULL,
	key_id   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS opack (
	name    TEXT PRIMARY KEY,
	trailer BLOB NOT NULL,
	size    INTEGER NOT NULL
);
`

func openContentJournal(dir string) (*contentJournal, error) {
	dsn := "file:" + filepath.Join(dir, contentDBName) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(10000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("overlay: open content journal: %w", err)
	}
	db.SetMaxOpenConns(1)
	// The journal describes one unsealed session and is retired with it,
	// so an older layout is scratch rather than history: start over rather
	// than half-read it. A recovery that finds nothing reports the loss,
	// which is the honest outcome for state this process cannot parse.
	if err := resetIfOldSchema(db); err != nil {
		db.Close() //nolint:errcheck
		return nil, err
	}
	if _, err := db.Exec(journalSchema); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("overlay: content journal schema: %w", err)
	}
	stmt, err := db.Prepare(`INSERT INTO ojournal (op, inode, handle, fileoff, length) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("overlay: content journal: %w", err)
	}
	return &contentJournal{db: db, append: stmt}, nil
}

// journalSchemaVersion is bumped whenever the tables change shape.
const journalSchemaVersion = 2

func resetIfOldSchema(db *sql.DB) error {
	var have int64
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&have); err != nil {
		return fmt.Errorf("overlay: content journal version: %w", err)
	}
	if have != journalSchemaVersion {
		for _, t := range []string{"ojournal", "ohandle", "ochunk", "opack"} {
			if _, err := db.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
				return fmt.Errorf("overlay: reset content journal: %w", err)
			}
		}
		if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, journalSchemaVersion)); err != nil {
			return fmt.Errorf("overlay: content journal version: %w", err)
		}
	}
	return nil
}

func (j *contentJournal) Close() error {
	err := j.append.Close()
	if cerr := j.db.Close(); err == nil {
		err = cerr
	}
	return err
}

func (j *contentJournal) Append(e memtable.JournalEntry) error {
	_, err := j.append.Exec(int64(e.Op), int64(e.Inode), int64(e.Handle), e.Off, e.Length)
	if err != nil {
		return fmt.Errorf("overlay: journal append: %w", err)
	}
	return nil
}

// Located records a flush's location map in one transaction: a partial
// record would name chunks whose packs are not listed, which is a
// generation nobody can read.
func (j *contentJournal) Located(l memtable.Location) error {
	tx, err := j.db.Begin()
	if err != nil {
		return err
	}
	fail := func(err error) error {
		tx.Rollback() //nolint:errcheck
		return fmt.Errorf("overlay: journal locations: %w", err)
	}
	for h, slices := range l.Handles {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO ohandle (handle, slices) VALUES (?, ?)`,
			int64(h), encodeSlices(slices)); err != nil {
			return fail(err)
		}
	}
	for id, loc := range l.Chunks {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO ochunk (identity, pack, off, stored, logical, alg, key_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, loc.Pack, loc.Off, loc.Stored, loc.Logical, int64(loc.Alg), loc.KeyID); err != nil {
			return fail(err)
		}
	}
	for _, p := range l.Packs {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO opack (name, trailer, size) VALUES (?, ?, ?)`,
			p.Name, p.TrailerHash[:], p.Size); err != nil {
			return fail(err)
		}
	}
	return tx.Commit()
}

// Load reads everything back as the durable state a store recovers from.
func (j *contentJournal) Load() (memtable.Durable, error) {
	var entries []memtable.JournalEntry
	rows, err := j.db.Query(`SELECT op, inode, handle, fileoff, length FROM ojournal ORDER BY seq`)
	if err != nil {
		return memtable.Durable{}, err
	}
	for rows.Next() {
		var e memtable.JournalEntry
		var op, ino, h int64
		if err := rows.Scan(&op, &ino, &h, &e.Off, &e.Length); err != nil {
			rows.Close() //nolint:errcheck
			return memtable.Durable{}, err
		}
		e.Op, e.Inode, e.Handle = memtable.JournalOp(op), uint64(ino), memtable.Handle(h)
		entries = append(entries, e)
	}
	if err := closeRows(rows); err != nil {
		return memtable.Durable{}, err
	}

	d := memtable.Durable{
		Handles: map[memtable.Handle][]memtable.ChunkSlice{},
		Chunks:  map[string]memtable.PackLoc{},
	}
	d.Rows, d.Adopted = memtable.ReplayJournal(entries)

	hrows, err := j.db.Query(`SELECT handle, slices FROM ohandle`)
	if err != nil {
		return memtable.Durable{}, err
	}
	for hrows.Next() {
		var h int64
		var blob []byte
		if err := hrows.Scan(&h, &blob); err != nil {
			hrows.Close() //nolint:errcheck
			return memtable.Durable{}, err
		}
		slices, err := decodeSlices(blob)
		if err != nil {
			hrows.Close() //nolint:errcheck
			return memtable.Durable{}, err
		}
		d.Handles[memtable.Handle(h)] = slices
	}
	if err := closeRows(hrows); err != nil {
		return memtable.Durable{}, err
	}

	crows, err := j.db.Query(`SELECT identity, pack, off, stored, logical, alg, key_id FROM ochunk`)
	if err != nil {
		return memtable.Durable{}, err
	}
	for crows.Next() {
		var id string
		var loc memtable.PackLoc
		var alg int64
		if err := crows.Scan(&id, &loc.Pack, &loc.Off, &loc.Stored, &loc.Logical, &alg, &loc.KeyID); err != nil {
			crows.Close() //nolint:errcheck
			return memtable.Durable{}, err
		}
		loc.Alg = uint8(alg)
		d.Chunks[id] = loc
	}
	if err := closeRows(crows); err != nil {
		return memtable.Durable{}, err
	}

	prows, err := j.db.Query(`SELECT name, trailer, size FROM opack ORDER BY name`)
	if err != nil {
		return memtable.Durable{}, err
	}
	for prows.Next() {
		var p packstore.SealedPack
		var trailer []byte
		if err := prows.Scan(&p.Name, &trailer, &p.Size); err != nil {
			prows.Close() //nolint:errcheck
			return memtable.Durable{}, err
		}
		if len(trailer) != len(p.TrailerHash) {
			prows.Close() //nolint:errcheck
			return memtable.Durable{}, fmt.Errorf("overlay: pack %s has a %d-byte trailer hash", p.Name, len(trailer))
		}
		copy(p.TrailerHash[:], trailer)
		d.Packs = append(d.Packs, p)
	}
	if err := closeRows(prows); err != nil {
		return memtable.Durable{}, err
	}
	return d, nil
}

// A chunk slice is fixed width, so the list is a plain array of records:
// 32 bytes of identity, then two 8-byte counts. Nothing here is read by
// anything but this file, and a fixed layout means a slice list costs one
// row rather than one row per slice.
const sliceRecordLen = 32 + 8 + 8

func encodeSlices(slices []memtable.ChunkSlice) []byte {
	out := make([]byte, len(slices)*sliceRecordLen)
	for i, s := range slices {
		rec := out[i*sliceRecordLen:]
		copy(rec[0:32], s.ID[:])
		binary.LittleEndian.PutUint64(rec[32:], uint64(s.ChunkOff))
		binary.LittleEndian.PutUint64(rec[40:], uint64(s.Length))
	}
	return out
}

func decodeSlices(b []byte) ([]memtable.ChunkSlice, error) {
	if len(b)%sliceRecordLen != 0 {
		return nil, fmt.Errorf("overlay: chunk slice blob is %d bytes, not a multiple of %d", len(b), sliceRecordLen)
	}
	out := make([]memtable.ChunkSlice, len(b)/sliceRecordLen)
	for i := range out {
		rec := b[i*sliceRecordLen:]
		copy(out[i].ID[:], rec[0:32])
		out[i].ChunkOff = int(binary.LittleEndian.Uint64(rec[32:]))
		out[i].Length = int(binary.LittleEndian.Uint64(rec[40:]))
	}
	return out, nil
}
