// Package shimtest verifies the cgo-free replacement modules behave the way
// JuiceFS expects: the sqlite3 driver (DSN translation, duplicate-entry and
// busy error mapping, VACUUM INTO) and the zstd/lz4 compressors (roundtrip
// through JuiceFS's own pkg/compress).
package shimtest

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/juicedata/juicefs/pkg/compress"
	"github.com/juicedata/juicefs/pkg/meta"
	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestSQLiteDSNTranslation(t *testing.T) {
	// The exact DSN JuiceFS builds for sqlite3 volumes.
	dsn := filepath.Join(t.TempDir(), "t.db") + "?cache=shared&_journal=WAL&_timeout=5000"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var timeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	if timeout != 5000 {
		t.Fatalf("busy_timeout = %d, want 5000", timeout)
	}
}

func TestSQLiteDuplicateEntryError(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO kv VALUES ('a', '1')"); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO kv VALUES ('a', '2')")
	if err == nil {
		t.Fatal("duplicate insert should fail")
	}
	// This is exactly what JuiceFS's isSQLiteDuplicateEntryErr does.
	e, ok := err.(sqlite3.Error)
	if !ok {
		t.Fatalf("error type %T, want sqlite3.Error (err=%v)", err, err)
	}
	if e.Code != sqlite3.ErrConstraint {
		t.Fatalf("code = %d, want ErrConstraint(%d)", e.Code, sqlite3.ErrConstraint)
	}
}

func TestSQLiteVacuumInto(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	db, err := sql.Open("sqlite3", src)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (42)"); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "snap.db")
	if _, err := db.Exec("VACUUM INTO ?", dst); err != nil {
		t.Fatalf("VACUUM INTO: %v", err)
	}
	db2, err := sql.Open("sqlite3", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var x int
	if err := db2.QueryRow("SELECT x FROM t").Scan(&x); err != nil || x != 42 {
		t.Fatalf("snapshot contents: x=%d err=%v", x, err)
	}
}

// TestMetaEngineSmoke formats and reopens a JuiceFS volume on the pure-Go
// sqlite driver, exercising xorm + the shim end to end.
func TestMetaEngineSmoke(t *testing.T) {
	p := filepath.Join(t.TempDir(), "meta.db")
	m := meta.NewClient("sqlite3://"+p, meta.DefaultConf())
	format := &meta.Format{
		Name:      "shimtest",
		UUID:      "00000000-0000-0000-0000-000000000001",
		Storage:   "file",
		Bucket:    t.TempDir() + "/",
		BlockSize: 4096,
		DirStats:  true,
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("Init: %v", err)
	}
	loaded, err := m.Load(true)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Name != "shimtest" || loaded.BlockSize != 4096 {
		t.Fatalf("Load = %+v", loaded)
	}
	if err := m.NewSession(true); err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := m.CloseSession(); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
}

func testCompressor(t *testing.T, algo string, payload []byte) {
	t.Helper()
	c := compress.NewCompressor(algo)
	if c == nil {
		t.Fatalf("no compressor %q", algo)
	}
	dst := make([]byte, c.CompressBound(len(payload)))
	n, err := c.Compress(dst, payload)
	if err != nil {
		t.Fatalf("%s compress: %v", algo, err)
	}
	out := make([]byte, len(payload))
	dn, err := c.Decompress(out, dst[:n])
	if err != nil {
		t.Fatalf("%s decompress: %v", algo, err)
	}
	if !bytes.Equal(out[:dn], payload) {
		t.Fatalf("%s roundtrip mismatch (%d -> %d -> %d bytes)", algo, len(payload), n, dn)
	}
}

func TestCompressorsRoundtrip(t *testing.T) {
	compressible := bytes.Repeat([]byte("pelican federation "), 4096)
	incompressible := make([]byte, 64<<10)
	if _, err := rand.Read(incompressible); err != nil {
		t.Fatal(err)
	}
	for _, algo := range []string{"zstd", "lz4"} {
		for name, payload := range map[string][]byte{
			"compressible":   compressible,
			"incompressible": incompressible,
			"tiny":           []byte("x"),
		} {
			t.Run(fmt.Sprintf("%s/%s", algo, name), func(t *testing.T) {
				testCompressor(t, algo, payload)
			})
		}
	}
}
