//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

// TestDirectorQueryReuse touches many objects under one namespace. The
// client caches director responses per namespace, flavor, and credential,
// so the number of director queries this provokes should stay flat rather
// than tracking the object count. Run the harness with -v and count
// "Will query director at" lines to see it.
func TestDirectorQueryReuse(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	const objects = 12
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("dircount/blocks/%d_0_1024", i)
		if err := s.Put(ctx, key, bytes.NewReader(make([]byte, 1024))); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	for i := 0; i < objects; i++ {
		key := fmt.Sprintf("dircount/blocks/%d_0_1024", i)
		rc, err := s.Get(ctx, key, 0, -1)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		rc.Close()
		if _, err := s.StatKey(ctx, key); err != nil {
			t.Fatalf("stat %d: %v", i, err)
		}
	}
}
