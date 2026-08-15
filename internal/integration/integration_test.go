//go:build integration

// Package integration exercises pelfs's federation transport against a real
// Pelican federation (director + registry + origin, usually launched by
// scripts/integration-pelican.sh). It covers the object CRUD surface, the
// origin's ETag-on-overwrite behavior, and a full metadata snapshot /
// restore cycle — everything except the FUSE mount itself.
//
// Required environment:
//
//	PELFS_TEST_PREFIX  e.g. pelican://localhost:8444/pelfs-test/it
//	PELFS_TEST_TOKEN   path to a bearer token with read+modify on the prefix
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // the pure-Go shim driver

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/snapshot"
)

func newStore(t *testing.T) pelicanobj.Store {
	t.Helper()
	prefix := os.Getenv("PELFS_TEST_PREFIX")
	if prefix == "" {
		t.Skip("PELFS_TEST_PREFIX not set; run via scripts/integration-pelican.sh")
	}
	s, err := pelicanobj.New(context.Background(), pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    os.Getenv("PELFS_TEST_TOKEN"),
		AcquireToken: false,
		Insecure:     true,
	})
	if err != nil {
		t.Fatalf("construct store for %s: %v", prefix, err)
	}
	return s
}

func TestFederationCRUD(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	payload := make([]byte, 3<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	key := "crud/blocks/0/1_0_3145728"
	if err := s.Put(ctx, key, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("Get read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("full read mismatch: %d vs %d bytes", len(got), len(payload))
	}

	rc, err = s.Get(ctx, key, 1<<20, 4096)
	if err != nil {
		t.Fatalf("ranged Get: %v", err)
	}
	got, _ = io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload[1<<20:(1<<20)+4096]) {
		t.Fatalf("ranged read mismatch (%d bytes)", len(got))
	}

	obj, err := s.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if obj.Size() != int64(len(payload)) {
		t.Fatalf("Head size = %d, want %d", obj.Size(), len(payload))
	}

	entries, err := s.ListDir(ctx, "crud/blocks/0")
	if err != nil {
		t.Fatalf("ListDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "1_0_3145728" {
		t.Fatalf("ListDir = %+v", entries)
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete (idempotent on missing): %v", err)
	}
	if _, err := s.Get(ctx, key, 0, -1); err == nil {
		t.Fatal("Get after Delete should fail")
	}
}

// TestOverwriteETag verifies the modern origin behavior pelfs's snapshot
// scheme depends on: overwriting an object in place succeeds, and the ETag
// changes with the content.
func TestOverwriteETag(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	key := "etag/current.db"

	if err := s.Put(ctx, key, strings.NewReader("generation one")); err != nil {
		t.Fatalf("initial Put: %v", err)
	}
	ki1, err := s.StatKey(ctx, key)
	if err != nil {
		t.Fatalf("StatKey: %v", err)
	}
	if ki1.ETag == "" {
		t.Fatal("origin returned no ETag; snapshot conflict detection would be inert")
	}

	time.Sleep(1100 * time.Millisecond) // outlast coarse mtime-based ETags
	if err := s.Put(ctx, key, strings.NewReader("generation two, longer")); err != nil {
		t.Fatalf("overwrite Put: %v", err)
	}
	ki2, err := s.StatKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if ki2.ETag == ki1.ETag {
		t.Fatalf("ETag unchanged across overwrite (%q)", ki1.ETag)
	}

	rc, err := s.Get(ctx, key, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "generation two, longer" {
		t.Fatalf("read after overwrite = %q", body)
	}
	_ = s.Delete(ctx, key)
}

// TestSnapshotCycle runs the real snapshot manager against the federation:
// periodic overwrite, conflict detection, final snapshot, restore.
func TestSnapshotCycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	metaPath := filepath.Join(t.TempDir(), "meta.db")
	db, err := sql.Open("sqlite3", metaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (7)"); err != nil {
		t.Fatal(err)
	}

	mgr := &snapshot.Manager{MetaPath: metaPath, Meta: s, Data: s, Session: snapshot.NewSessionID()}
	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatalf("periodic snapshot: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t VALUES (8)"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatalf("periodic snapshot (overwrite): %v", err)
	}
	if err := mgr.Snapshot(ctx, true); err != nil {
		t.Fatalf("final snapshot: %v", err)
	}

	restored := filepath.Join(t.TempDir(), "restored.db")
	key, err := snapshot.Restore(ctx, s, s, restored)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if key == "" {
		t.Fatal("Restore found no snapshot")
	}
	rdb, err := sql.Open("sqlite3", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	var n int
	if err := rdb.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil || n != 2 {
		t.Fatalf("restored db contents: n=%d err=%v (restored from %s)", n, err, key)
	}
}
