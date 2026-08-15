//go:build integration

package integration

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/snapshot"
)

// TestManySessionDirs mirrors a long-lived prefix: many past session
// directories under meta/, which restore lists and prune deletes. Each
// listing used to build and tear down a transfer engine and ask the
// director again.
func TestManySessionDirs(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	for i := 0; i < 6; i++ {
		key := fmt.Sprintf("%s/sess-%02d/final.db", snapshot.MetaDir, i)
		if err := s.Put(ctx, key, strings.NewReader("snapshot-"+fmt.Sprint(i))); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	restored := filepath.Join(t.TempDir(), "meta.db")
	key, err := snapshot.Restore(ctx, s, s, restored)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if key == "" {
		t.Fatal("Restore found nothing")
	}

	mgr := &snapshot.Manager{MetaPath: restored, Meta: s, Data: s, Session: "sess-current"}
	if err := mgr.PruneSessions(ctx, 2); err != nil {
		t.Fatalf("PruneSessions: %v", err)
	}
	t.Logf("restored from %s and pruned", key)
}
