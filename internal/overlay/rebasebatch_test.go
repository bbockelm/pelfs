package overlay_test

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
)

// A rebase drops the overlay rows a published generation now covers, and
// it used to hold the mount's lock for every one of them — 7 to 11
// seconds on a source tree, which is long enough for an NFS client to
// give up. It is batched now, and the batching has one hazard worth a
// test: the lock is released between batches, so a writer can dirty an
// inode the loop was about to clean, and dropping its rows then would
// lose that write.
func TestRebaseKeepsWritesThatLandDuringIt(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5eba5eba-0001-4000-8000-000000000001")
	ov := openOverlay(t, fx, "")

	// A dirty set big enough to span several batches.
	const files = 2000
	for i := 0; i < files; i++ {
		n, err := ov.Create(ctx, rootIno, "f"+strconv.Itoa(i), 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, []byte("published "+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	snap := takeSnapshot(t, ov)
	res := sealAndSwap(t, fx, ov)

	// While the rebase runs, keep writing. Every one of these must
	// survive: they are newer than the generation being rebased away.
	late := map[string][]byte{}
	var mu sync.Mutex
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			name := "f" + strconv.Itoa(i%files)
			body := []byte("written during the rebase " + strconv.Itoa(i))
			n, err := ov.Lookup(ctx, rootIno, name)
			if err != nil {
				continue
			}
			if err := truncWrite(ctx, ov, n.Inode, body); err != nil {
				continue
			}
			mu.Lock()
			late[name] = body
			mu.Unlock()
		}
	})

	rep, err := ov.Rebase(ctx, snap.Seq(), overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	})
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	if len(rep.Clean) == 0 {
		t.Fatal("nothing was cleaned, so the batching was never exercised")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(late) == 0 {
		t.Fatal("no write landed during the rebase; this test proved nothing")
	}
	for name, body := range late {
		mustBody(t, ov, name, body)
	}
	t.Logf("%d inodes cleaned; %d files written during the rebase all survived", len(rep.Clean), len(late))
}
