package genfs

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"lukechampine.com/blake3"
)

func idOf(s string) string {
	h := blake3.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newCacheDir(t *testing.T) (string, *graftCache) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "packs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, newGraftCache(dir)
}

// TestGraftCacheIsOneFilePerBlobAndNotOnePerBlock pins the storage shape,
// because the failure it rules out is the one this repo already paid for
// once: 6,646 files where 1 would do (chunkarena.go).
func TestGraftCacheIsOneFilePerBlobAndNotOnePerBlock(t *testing.T) {
	dir, c := newCacheDir(t)
	const n = 500
	block := make([]byte, 4096)
	for i := 0; i < n; i++ {
		block[0] = byte(i)
		block[1] = byte(i >> 8)
		c.put(idOf(string(block[:2])), block, true)
	}
	c.flush()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("%d blocks produced %d files (%v); a blob holds many blocks", n, len(entries), names)
	}
	if got := c.stats().Blocks; got != n {
		t.Fatalf("the cache indexes %d of %d blocks", got, n)
	}
}

// TestGraftCacheRoundTripsAcrossAReopen: the blob is self-describing, so a
// new process finds what the last one cached without a sidecar index that
// eviction could have separated from its data.
func TestGraftCacheRoundTripsAcrossAReopen(t *testing.T) {
	dir, c := newCacheDir(t)
	want := map[string][]byte{}
	for i := 0; i < 20; i++ {
		buf := make([]byte, 1000+i)
		for j := range buf {
			buf[j] = byte(i*7 + j)
		}
		id := idOf(string(buf[:8]))
		want[id] = buf
		c.put(id, buf, false)
	}
	c.flush()

	c2 := newGraftCache(dir)
	for id, w := range want {
		got, ok := c2.get(id)
		if !ok {
			t.Fatalf("%s is not in the reopened cache", id[:12])
		}
		if string(got) != string(w) {
			t.Fatalf("%s came back wrong from the reopened cache", id[:12])
		}
	}
	if c2.stats().Blocks != len(want) {
		t.Fatalf("reopened cache holds %d of %d blocks", c2.stats().Blocks, len(want))
	}
}

// TestATornBlobIsDiscardedRatherThanServed. A process killed mid-prefetch
// leaves a payload with no footer; a rotted one has a footer that does not
// describe it. Either way the cache must not answer from it.
func TestATornBlobIsDiscardedRatherThanServed(t *testing.T) {
	dir, c := newCacheDir(t)
	buf := make([]byte, 4096)
	id := idOf("torn")
	c.put(id, buf, false)
	c.flush()
	names := c.blobNames()
	if len(names) != 1 {
		t.Fatalf("expected one blob, got %v", names)
	}
	path := filepath.Join(dir, names[0])
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cut the footer off, which is what a kill mid-finalize looks like.
	if err := os.Truncate(path, fi.Size()-8); err != nil {
		t.Fatal(err)
	}
	c2 := newGraftCache(dir)
	if _, ok := c2.get(id); ok {
		t.Fatal("a blob with no valid footer answered a lookup")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the unreadable blob was left on disk to be re-read forever")
	}
}

// TestPrefetchedBlobsAreEvictedLastAndTheLossIsRecorded is the eviction
// answer, and it is the subtle part of the whole feature.
//
// A prefetched graft block is re-fetchable, so it must be evictable —
// pinning it forever would let a graft larger than the disk wedge the
// cache. But plain LRU takes it FIRST, because when a prefetch finishes it
// is the oldest thing there. So: everything else goes first, and a
// prefetched blob yields only when the cache is still over its CAP
// afterwards — and when that happens it is COUNTED, because that is the
// moment a `--prefetch all` report stopped being true.
func TestPrefetchedBlobsAreEvictedLastAndTheLossIsRecorded(t *testing.T) {
	dir, c := newCacheDir(t)
	blob := make([]byte, 200<<10)
	pin := idOf("pinned")
	c.put(pin, blob, true)
	c.flush()
	pinnedName := c.blobNames()[0]

	// Something newer and unpinned, in the same directory the sweep walks.
	other := filepath.Join(dir, "p-0000000000000001-abcd")
	if err := os.WriteFile(other, make([]byte, 400<<10), 0o600); err != nil {
		t.Fatal(err)
	}

	// A budget that forces a sweep but that the pinned blob alone fits
	// inside: everything else must go and the pinned blob must stay.
	fs := &FS{cacheDir: filepath.Dir(dir), packDir: dir, cacheCap: 300 << 10, graftCache: c}
	fs.evictCache()
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("the unpinned file survived a sweep that had to free space")
	}
	if _, err := os.Stat(filepath.Join(dir, pinnedName)); err != nil {
		t.Fatalf("the PREFETCHED blob was evicted while an unpinned file was available: %v", err)
	}
	if got := c.stats().PinnedEvicted; got != 0 {
		t.Fatalf("PinnedEvicted moved to %d without a prefetched blob being taken", got)
	}
	if _, ok := c.get(pin); !ok {
		t.Fatal("the surviving blob stopped answering")
	}

	// Now a budget the pinned blob CANNOT fit inside. It has to go, and
	// the loss has to be recorded rather than leaving an earlier "fully
	// local" report quietly false.
	fs.cacheCap = 8 << 10
	fs.cache.scannedA.Store(0)
	fs.evictCache()
	if _, err := os.Stat(filepath.Join(dir, pinnedName)); !os.IsNotExist(err) {
		t.Fatal("a prefetched blob was kept even though the cache stayed over its cap")
	}
	if got := c.stats().PinnedEvicted; got == 0 {
		t.Fatal("a prefetched blob was evicted and PinnedEvicted stayed zero, so nothing records " +
			"that the prefetch promise was broken")
	}
	if _, ok := c.get(pin); ok {
		t.Fatal("the index still points at an evicted blob")
	}
	t.Logf("PinnedEvicted = %d bytes after the cap forced it", c.stats().PinnedEvicted)
}

// TestAnUnfinalizedBlobIsReadableWhileItIsBeingWritten: a long prefetch
// must serve what it has already fetched, not only what it has rolled.
func TestAnUnfinalizedBlobIsReadableWhileItIsBeingWritten(t *testing.T) {
	_, c := newCacheDir(t)
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = byte(i)
	}
	id := idOf("inflight")
	c.put(id, buf, true)
	got, ok := c.get(id)
	if !ok {
		t.Fatal("a block in the open blob is not readable")
	}
	if string(got) != string(buf) {
		t.Fatal("a block in the open blob came back wrong")
	}
	c.flush()
	if got, ok := c.get(id); !ok || string(got) != string(buf) {
		t.Fatal("the same block stopped being readable once its blob was finalized")
	}
}
