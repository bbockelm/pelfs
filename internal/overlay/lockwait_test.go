package overlay_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
)

// The overlay's lock is the mount: a filesystem operation cannot proceed
// without it, so waiting for it IS a filesystem that does not answer.
// Until this was measured, the only evidence of a stall was an NFS client
// declaring the server dead — which says nothing about which phase did
// it, or for how long.
func TestLockWaitMeasuresWhatTheMountLost(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "b10cbeef-0001-4000-8000-000000000001")
	ov := openOverlay(t, fx, "")

	if total, _, waits := ov.LockWait(); total != 0 || waits != 0 {
		t.Fatalf("a fresh overlay reports %v across %d waits", total, waits)
	}

	// Enough dirty state that a freeze's VACUUM is comfortably longer than
	// the millisecond this counts from.
	for i := 0; i < 400; i++ {
		if _, err := ov.Create(ctx, rootIno, "seed"+strconv.Itoa(i), 0644, 0, 0); err != nil {
			t.Fatal(err)
		}
	}

	// A freeze holds the overlay's lock for its whole duration; ordinary
	// work arriving meanwhile is the mount being blocked. Both run at
	// once, which is the only arrangement that measures anything.
	done := make(chan struct{})
	go func() {
		defer close(done)
		snap, err := ov.Snapshot(ctx, filepath.Join(t.TempDir(), "snap"))
		if err != nil {
			t.Errorf("Snapshot: %v", err)
			return
		}
		snap.Close() //nolint:errcheck
	}()
	for i := 0; i < 400; i++ {
		if _, err := ov.Create(ctx, rootIno, "during"+strconv.Itoa(i), 0644, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	<-done

	total, worst, waits := ov.LockWait()
	if waits == 0 {
		t.Fatal("400 operations issued against a running freeze and none was recorded as blocked")
	}
	if worst > total {
		t.Errorf("incoherent accounting: worst %v exceeds total %v", worst, total)
	}
	t.Logf("mount blocked %v across %d operations (longest %v)", total, waits, worst)
}
