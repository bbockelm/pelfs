package mountfs

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3" // the pure-Go shim driver

	"github.com/juicedata/juicefs/pkg/meta"
)

func TestSquashOwnership(t *testing.T) {
	dir := t.TempDir()
	metaPath := filepath.Join(dir, "meta.db")

	m := meta.NewClient("sqlite3://"+metaPath, meta.DefaultConf())
	format := &meta.Format{
		Name:      "squashtest",
		UUID:      "00000000-0000-0000-0000-0000000000aa",
		Storage:   "file",
		Bucket:    dir + "/",
		BlockSize: 4096,
	}
	if err := m.Init(format, false); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Simulate a volume written by a root session: force foreign ownership
	// onto every inode (Init at least creates the root directory).
	db, err := sql.Open("sqlite3", metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE jfs_node SET uid = 0, gid = 0"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	n, err := squashOwnership(metaPath, 501, 20)
	if err != nil {
		t.Fatalf("squashOwnership: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least one squashed inode, got %d", n)
	}

	db, err = sql.Open("sqlite3", metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var foreign int
	if err := db.QueryRow("SELECT count(*) FROM jfs_node WHERE uid <> 501 OR gid <> 20").Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if foreign != 0 {
		t.Fatalf("%d inodes still foreign-owned", foreign)
	}

	// Idempotent: nothing left to change.
	if n, err := squashOwnership(metaPath, 501, 20); err != nil || n != 0 {
		t.Fatalf("second squash: n=%d err=%v", n, err)
	}
}

// TestSquashOwnershipFreshVolume: a missing metadata file must be a no-op
// and must NOT leave an empty database behind (that would break volume
// creation).
func TestSquashOwnershipFreshVolume(t *testing.T) {
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	n, err := squashOwnership(metaPath, 501, 20)
	if err != nil || n != 0 {
		t.Fatalf("fresh volume squash: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
		t.Fatal("squash created a spurious metadata file")
	}
}
