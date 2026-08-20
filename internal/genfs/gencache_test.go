package genfs_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The local cache used to have one bound over one of its four
// directories. These are the claims the single budget has to keep: it
// holds, it does not break a reader, and what it throws away comes back
// byte-for-byte.

// cacheFixture is a volume with enough distinct content that reading all
// of it cannot fit in a small cache.
type cacheFixture struct {
	inner *countingStore
	sb    *superblock.Superblock
	body  map[string][]byte
	names []string
	cache string
}

func newCacheFixture(t *testing.T, uuid string, files, size int) *cacheFixture {
	t.Helper()
	raw, _ := newInner(t)
	f := &cacheFixture{
		inner: &countingStore{Store: raw},
		body:  make(map[string][]byte),
		cache: t.TempDir(),
	}
	v := newTestVolume(t, f.inner, uuid)
	// A subdirectory, and SMax below the entry count, so the generation
	// splits into more than one catalog: an eviction pass has to make a
	// decision about a catalog spill file that is not the root's.
	dir := v.Mkdir(rootIno, "dir")
	for i := 0; i < files; i++ {
		name := fmt.Sprintf("f%03d.bin", i)
		f.body[name] = pseudorandom(size, int64(7000+i))
		parent := rootIno
		if i%2 == 1 {
			parent = dir
		}
		v.Write(v.Create(parent, name), f.body[name])
		f.names = append(f.names, name)
	}
	res := publishVolume(t, v, f.inner, publish.Options{SMax: 8, TargetPackSize: 2 << 20})
	if res.Stats.Catalogs < 2 {
		t.Fatalf("fixture did not split into catalogs: %d", res.Stats.Catalogs)
	}
	f.sb = res.Superblock
	return f
}

// path resolves a fixture file, which lives under /dir on odd indexes.
func (f *cacheFixture) path(i int) string {
	if i%2 == 1 {
		return "dir/" + f.names[i]
	}
	return f.names[i]
}

func (f *cacheFixture) open(t *testing.T, o genfs.Options) *genfs.FS {
	t.Helper()
	o.CacheDir = f.cache
	return openFS(t, f.inner, f.sb, o)
}

// readPath reads a whole file by slash-separated path and returns it.
func readPath(t *testing.T, fs *genfs.FS, p string, bufSize int) []byte {
	t.Helper()
	ctx := context.Background()
	n, err := fs.LookupPath(ctx, p)
	if err != nil {
		t.Fatalf("lookup %s: %v", p, err)
	}
	out := make([]byte, 0, n.Length)
	buf := make([]byte, bufSize)
	for off := int64(0); off < n.Length; {
		got, err := fs.Read(ctx, n.Inode, off, buf)
		if err != nil {
			t.Fatalf("read %s at %d: %v", p, off, err)
		}
		if got == 0 {
			t.Fatalf("read %s: short at %d of %d", p, off, n.Length)
		}
		out = append(out, buf[:got]...)
		off += int64(got)
	}
	return out
}

// TestCacheHoldsItsBudgetUnderChurn is the claim that matters to a user
// with a full disk: reading far more than the cache can hold leaves the
// cache the size it was told to be, not the size of what was read.
func TestCacheHoldsItsBudgetUnderChurn(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0001-4000-8000-000000000001", 24, 1<<20)
	const cap = 6 << 20
	fs := f.open(t, genfs.Options{CacheBytes: cap})

	total := 0
	for i := range f.names {
		got := readPath(t, fs, f.path(i), 256<<10)
		if !bytes.Equal(got, f.body[f.names[i]]) {
			t.Fatalf("%s did not read back byte-exact under eviction pressure", f.names[i])
		}
		total += len(got)
		// The budget is enforced continuously, not at the end: a cache
		// that swelled to the size of the whole read and then swept once
		// would still have filled the disk.
		if u := fs.CacheUsage(); u.Bytes > cap {
			t.Fatalf("after %d files (%d bytes read) the cache holds %d bytes, budget is %d",
				i+1, total, u.Bytes, cap)
		}
	}
	if total <= cap {
		t.Fatalf("the read (%d bytes) did not exceed the budget (%d); the test proves nothing", total, cap)
	}
	u := fs.CacheUsage()
	if u.EvictedFiles == 0 {
		t.Fatalf("nothing was ever evicted, yet %d bytes went through a %d-byte cache", total, cap)
	}
	if u.Bytes == 0 {
		t.Fatalf("the cache is empty; eviction is not an LRU, it is a purge")
	}
	// The report has to name the directories, or a full disk is still not
	// diagnosable.
	if len(u.Dirs) != 4 {
		t.Fatalf("usage reports %d directories, want 4: %+v", len(u.Dirs), u.Dirs)
	}
	t.Logf("read %d bytes through a %d-byte cache: %s (evicted %d files, %d bytes)",
		total, cap, u, u.EvictedFiles, u.EvictedBytes)
}

// TestEvictionKeepsOpenCatalogs is the one file under CacheDir that is
// NOT safe to unlink under a reader: a spilled catalog is opened by path,
// and by SQLite. Eviction must skip the ones the handle cache holds open,
// and reads through them must keep working while the pressure runs.
func TestEvictionKeepsOpenCatalogs(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0002-4000-8000-000000000002", 20, 1<<20)
	fs := f.open(t, genfs.Options{CacheBytes: 4 << 20, MaxOpenCatalogs: 8})
	ctx := context.Background()

	// Descend into the nested catalog so it is open in the handle cache,
	// then read enough to force many eviction passes.
	if _, err := fs.LookupPath(ctx, "dir"); err != nil {
		t.Fatal(err)
	}
	for i := range f.names {
		readPath(t, fs, f.path(i), 256<<10)
	}
	// Every catalog the handle cache still holds open must still have its
	// spill file: closing the handle later would otherwise find nothing.
	pinned, err := os.ReadDir(filepath.Join(f.cache, "catalogs"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned) == 0 {
		t.Fatal("eviction removed every catalog spill, including the ones held open")
	}
	// And the reads still work — through the open handles, and through
	// whatever has to be re-spilled.
	for i := range f.names {
		if got := readPath(t, fs, f.path(i), 1<<20); !bytes.Equal(got, f.body[f.names[i]]) {
			t.Fatalf("%s is wrong after eviction pressure", f.names[i])
		}
	}
}

// TestConcurrentReadsSurviveEviction runs the eviction path against
// readers in flight. A cache that answers a read with an error, or with
// the wrong bytes, is worse than no cache: correctness first.
func TestConcurrentReadsSurviveEviction(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0003-4000-8000-000000000003", 16, 1<<20)
	fs := f.open(t, genfs.Options{CacheBytes: 3 << 20})

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ctx := context.Background()
			for round := 0; round < 3; round++ {
				for i := range f.names {
					p := f.path(i)
					n, err := fs.LookupPath(ctx, p)
					if err != nil {
						errs <- fmt.Errorf("worker %d lookup %s: %w", w, p, err)
						return
					}
					buf := make([]byte, n.Length)
					read := 0
					for int64(read) < n.Length {
						got, err := fs.Read(ctx, n.Inode, int64(read), buf[read:])
						if err != nil {
							errs <- fmt.Errorf("worker %d read %s: %w", w, p, err)
							return
						}
						if got == 0 {
							errs <- fmt.Errorf("worker %d read %s: short at %d", w, p, read)
							return
						}
						read += got
					}
					if !bytes.Equal(buf, f.body[f.names[i]]) {
						errs <- fmt.Errorf("worker %d read %s: bytes differ", w, p)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if u := fs.CacheUsage(); u.EvictedFiles == 0 {
		t.Fatalf("no eviction happened during the concurrent read; the test proves nothing (%s)", u)
	}
}

// TestClearedCacheRefills is `pelfs cache clear` followed by a cold read:
// everything under CacheDir is re-derivable, so clearing it may cost time
// and must not cost bytes.
func TestClearedCacheRefills(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0004-4000-8000-000000000004", 8, 1<<20)
	fs := f.open(t, genfs.Options{})
	for i := range f.names {
		readPath(t, fs, f.path(i), 1<<20)
	}
	before, err := genfs.InspectCache(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if before.Bytes == 0 {
		t.Fatal("nothing was cached by reading the whole volume")
	}
	// Closed first: clearing under a live mount would unlink a catalog
	// SQLite has open, which is exactly what `pelfs cache clear` refuses
	// to do to a running session.
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	cleared, err := genfs.ClearCache(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Bytes != before.Bytes {
		t.Errorf("clear reported %d bytes, inspect had said %d", cleared.Bytes, before.Bytes)
	}
	after, err := genfs.InspectCache(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	if after.Bytes != 0 || after.Files != 0 {
		t.Fatalf("cache still holds %d bytes in %d files after clear", after.Bytes, after.Files)
	}

	// Cold: a new mount over the emptied cache, and every byte identical.
	cold := f.open(t, genfs.Options{})
	for i := range f.names {
		if got := readPath(t, cold, f.path(i), 1<<20); !bytes.Equal(got, f.body[f.names[i]]) {
			t.Fatalf("%s did not read back byte-exact from a cleared cache", f.names[i])
		}
	}
}

// TestCacheBudgetSurvivesRemount is the case a per-session bound would
// miss: the cache outlives the process, so a session that starts against
// a cache filled by a more generous one has to bring it back inside the
// budget rather than inherit it.
func TestCacheBudgetSurvivesRemount(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0005-4000-8000-000000000005", 16, 1<<20)
	big := f.open(t, genfs.Options{CacheBytes: 64 << 20})
	for i := range f.names {
		readPath(t, big, f.path(i), 1<<20)
	}
	filled := big.CacheUsage()
	if err := big.Close(); err != nil {
		t.Fatal(err)
	}
	const small = 4 << 20
	if filled.Bytes <= small {
		t.Fatalf("the first session cached only %d bytes; nothing for the second to reclaim", filled.Bytes)
	}
	tight := f.open(t, genfs.Options{CacheBytes: small})
	if u := tight.CacheUsage(); u.Bytes > small {
		t.Fatalf("a mount with a %d-byte budget opened onto %d bytes of cache and kept them", small, u.Bytes)
	}
	// And it still serves.
	if got := readPath(t, tight, f.path(0), 1<<20); !bytes.Equal(got, f.body[f.names[0]]) {
		t.Fatal("the first read after a budget-shrinking remount is wrong")
	}
}
