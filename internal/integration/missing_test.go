//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestStatMissingObject pins how the origin answers a stat for an object
// that is not there. It must be distinguishable from an authorization
// failure: pelfs (and the pelican client's own not-found handling) treat a
// 403 as "retry with a fresh credential", so an origin that returns 403 for
// a missing object turns every probe into three futile token acquisitions.
func TestStatMissingObject(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	_, err := s.StatKey(ctx, "packs/p-does-not-exist-0000")
	if err == nil {
		t.Fatal("stat of a missing object should fail")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat of a missing object did not map to not-exist: %v", err)
	}
	if strings.Contains(err.Error(), "403") || strings.Contains(strings.ToLower(err.Error()), "authoriz") {
		t.Fatalf("origin answered a missing object with an authorization failure: %v", err)
	}

	// An existing object under the same prefix must stat cleanly, so the
	// case above is really about absence and not about the prefix.
	if err := s.Put(ctx, "packs/p-real-0001", strings.NewReader("pack bytes")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := s.StatKey(ctx, "packs/p-real-0001"); err != nil {
		t.Fatalf("stat of an existing pack: %v", err)
	}
	_ = s.Delete(ctx, "packs/p-real-0001")
}
