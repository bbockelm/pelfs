package snapshot

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // the pure-Go shim driver

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

func newStore(t *testing.T) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	s, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/ns"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "meta.db")
	db, err := sql.Open("sqlite3", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	return p, db
}

func TestSnapshotOverwriteAndConflict(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	metaPath, db := newDB(t)
	mgr := &Manager{MetaPath: metaPath, Store: store, Session: "sess-a"}

	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	ki1, err := store.StatKey(ctx, "meta/sess-a/current.db")
	if err != nil {
		t.Fatalf("StatKey: %v", err)
	}
	if ki1.ETag == "" {
		t.Fatal("expected an ETag from fakeorigin")
	}

	// A second snapshot overwrites the same key.
	if _, err := db.Exec("INSERT INTO t VALUES (2)"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // ensure a distinct mtime-based ETag
	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatalf("second snapshot (overwrite): %v", err)
	}
	ki2, err := store.StatKey(ctx, "meta/sess-a/current.db")
	if err != nil {
		t.Fatal(err)
	}
	if ki2.ETag == ki1.ETag {
		t.Fatal("overwrite did not change the ETag")
	}

	// A foreign write to our session object must be detected.
	time.Sleep(10 * time.Millisecond)
	if err := store.Put(ctx, "meta/sess-a/current.db", strings.NewReader("intruder")); err != nil {
		t.Fatal(err)
	}
	err = mgr.Snapshot(ctx, false)
	if err == nil || !strings.Contains(err.Error(), "another writer") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestFinalSnapshotAndRestore(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	// Session A: periodic snapshot only.
	pathA, _ := newDB(t)
	mgrA := &Manager{MetaPath: pathA, Store: store, Session: "sess-a"}
	if err := mgrA.Snapshot(ctx, false); err != nil {
		t.Fatal(err)
	}

	// Session B (later): writes a final snapshot with a recognizable row.
	time.Sleep(10 * time.Millisecond)
	pathB, dbB := newDB(t)
	if _, err := dbB.Exec("INSERT INTO t VALUES (42)"); err != nil {
		t.Fatal(err)
	}
	mgrB := &Manager{MetaPath: pathB, Store: store, Session: "sess-b"}
	if err := mgrB.Snapshot(ctx, true); err != nil {
		t.Fatal(err)
	}

	restored := filepath.Join(t.TempDir(), "restored.db")
	key, err := Restore(ctx, store, restored)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if key != "meta/sess-b/final.db" {
		t.Fatalf("restored from %q, want sess-b final", key)
	}
	db, err := sql.Open("sqlite3", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM t WHERE x = 42").Scan(&n); err != nil || n != 1 {
		t.Fatalf("restored contents wrong: n=%d err=%v", n, err)
	}
}

func TestRestoreEmptyPrefix(t *testing.T) {
	store := newStore(t)
	key, err := Restore(context.Background(), store, filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("Restore on empty prefix: %v", err)
	}
	if key != "" {
		t.Fatalf("expected no snapshot, got %q", key)
	}
}

// Guard against the tmp file lingering after snapshots.
func TestSnapshotCleansTemp(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	metaPath, _ := newDB(t)
	mgr := &Manager{MetaPath: metaPath, Store: store, Session: "s"}
	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(metaPath + ".snap"); !os.IsNotExist(err) {
		t.Fatalf("temp snapshot file left behind: %v", err)
	}
	// Restore's temp path should not exist either after a successful run.
	if _, err := os.Stat(metaPath + ".restore"); !os.IsNotExist(err) {
		t.Fatalf("restore temp file present: %v", err)
	}
}
