package snapshot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

func testRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// TestEncryptedSnapshotRoundtrip proves the metadata snapshot is protected:
// bytes at rest are not a SQLite database, and restore through the encrypted
// wrapper recovers the original.
func TestEncryptedSnapshotRoundtrip(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	data, err := pelicanobj.WrapEncrypted(store, testRSAKeyPEM(t))
	if err != nil {
		t.Fatalf("WrapEncrypted: %v", err)
	}

	metaPath, db := newDB(t)
	if _, err := db.Exec("INSERT INTO t VALUES (1234)"); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{MetaPath: metaPath, Meta: store, Data: data, Session: "enc-sess"}
	if err := mgr.Snapshot(ctx, true); err != nil {
		t.Fatalf("encrypted snapshot: %v", err)
	}

	// Raw bytes must not look like SQLite.
	rc, err := store.Get(ctx, "meta/enc-sess/final.db", 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	head, _ := io.ReadAll(rc)
	rc.Close()
	if strings.HasPrefix(string(head), "SQLite format 3") {
		t.Fatal("snapshot stored in plaintext despite encryption")
	}

	// Restore through the encrypted wrapper must yield a working database.
	restored := filepath.Join(t.TempDir(), "restored.db")
	key, err := Restore(ctx, store, data, restored)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if key != "meta/enc-sess/final.db" {
		t.Fatalf("restored from %q", key)
	}
	rdb, err := sql.Open("sqlite3", restored)
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	var n int
	if err := rdb.QueryRow("SELECT count(*) FROM t WHERE x = 1234").Scan(&n); err != nil || n != 1 {
		t.Fatalf("restored contents: n=%d err=%v", n, err)
	}
}

func TestPruneSessions(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	// Four old sessions plus the current one.
	for _, sess := range []string{"s1", "s2", "s3", "s4"} {
		p, _ := newDB(t)
		m := &Manager{MetaPath: p, Meta: store, Data: store, Session: sess}
		if err := m.Snapshot(ctx, true); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := newDB(t)
	cur := &Manager{MetaPath: p, Meta: store, Data: store, Session: "s5-current"}
	if err := cur.Snapshot(ctx, false); err != nil {
		t.Fatal(err)
	}

	// keep=3: current + two newest old sessions (s3, s4) survive.
	if err := cur.PruneSessions(ctx, 3); err != nil {
		t.Fatalf("PruneSessions: %v", err)
	}
	for sess, wantGone := range map[string]bool{"s1": true, "s2": true, "s3": false, "s4": false, "s5-current": false} {
		files, err := store.ListDir(ctx, MetaDir+"/"+sess)
		hasFiles := err == nil && len(files) > 0
		if wantGone && hasFiles {
			t.Fatalf("session %s should have been pruned, still has %v", sess, files)
		}
		if !wantGone && !hasFiles {
			t.Fatalf("session %s should have been kept", sess)
		}
	}
}

// TestFinalRemovesCurrent verifies the superseded periodic snapshot is
// cleaned up by the final one.
func TestFinalRemovesCurrent(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	p, _ := newDB(t)
	mgr := &Manager{MetaPath: p, Meta: store, Data: store, Session: "s"}
	if err := mgr.Snapshot(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Snapshot(ctx, true); err != nil {
		t.Fatal(err)
	}
	files, err := store.ListDir(ctx, MetaDir+"/s")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name != "final.db" {
		t.Fatalf("expected only final.db, got %+v", files)
	}
}
