package genfs_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
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

// readInode reads a resolved inode end to end in bufSize windows. Unlike
// readPath it REPORTS failure rather than calling t.Fatalf, because the
// readers below run in goroutines.
func readInode(fs *genfs.FS, ino uint64, length int64, bufSize int) ([]byte, error) {
	ctx := context.Background()
	out := make([]byte, 0, length)
	buf := make([]byte, bufSize)
	for off := int64(0); off < length; {
		got, err := fs.Read(ctx, ino, off, buf)
		if err != nil {
			return nil, fmt.Errorf("read at %d of %d: %w", off, length, err)
		}
		if got == 0 {
			return nil, fmt.Errorf("short read at %d of %d", off, length)
		}
		out = append(out, buf[:got]...)
		off += int64(got)
	}
	return out, nil
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

// TestConcurrentReadsSurviveEviction runs the eviction path against a
// read in flight. A cache that answers a read with an error, or with the
// wrong bytes, is worse than no cache: correctness first.
//
// The interleaving is FORCED, not hoped for. The first version of this
// test ran six readers against a small budget and asserted afterwards
// that something had been evicted, which made the whole proof a matter of
// which goroutine the scheduler ran first; under -race on a loaded runner
// the luck ran out and the vacuity guard fired (v0.1.0). So one read is
// parked mid-fetch on a gate this test holds, eviction is DRIVEN past the
// budget while it sits there, and only then is the read released and
// checked byte-for-byte. The six readers stay, because reads racing a
// sweep is what the race detector is here for — but nothing is proven by
// their timing.
func TestConcurrentReadsSurviveEviction(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0003-4000-8000-000000000003", 16, 1<<20)
	const cap = 3 << 20
	ctx := context.Background()

	// The read that has to survive, on a session of its own with
	// whole-pack caching off. Both halves of that matter:
	//
	//   - Fills are serialised per cache key within ONE mount, and the
	//     parked read holds its key for as long as the test wants. A
	//     pressure read on the same mount that wanted the same pack would
	//     queue behind it, and the test would hang instead of evicting.
	//     A second session shares the cache DIRECTORY (which is the
	//     point) and nothing else, so its fills cannot queue behind this
	//     one — the cache outliving a process and being shared between
	//     sessions is what gencache.go is written for.
	//   - Ranged reads guarantee the fetch happens at all: a whole pack
	//     another session had already pulled down would be served off
	//     local disk, and a gate armed for a fetch that never comes is a
	//     test that hangs.
	park := newParkedStore(f.inner)
	reader := openFS(t, park, f.sb, genfs.Options{CacheDir: f.cache, CacheBytes: cap, PackCacheBytes: -1})
	target := f.path(0)
	n, err := reader.LookupPath(ctx, target)
	if err != nil {
		t.Fatalf("lookup %s: %v", target, err)
	}
	// Armed after the descent, so what parks is a fill this read needs
	// rather than the catalog it was going to open anyway.
	park.arm()
	var got []byte
	var reading sync.WaitGroup
	done := make(chan error, 1)
	reading.Add(1)
	go func() {
		defer reading.Done()
		var err error
		got, err = readInode(reader, n.Inode, n.Length, 256<<10)
		done <- err
	}()
	// However this test ends, the parked read is let go and joined before
	// the mount it is reading through is closed: cleanups run
	// last-registered-first, so this one precedes openFS's Close. Without
	// it a failed assertion below leaves a goroutine reading a closed
	// mount out of a deleted temp directory, and the failure that matters
	// is buried under what that produces.
	t.Cleanup(func() { park.letGo(); reading.Wait() })
	parked := park.waitForPark(t, done)

	// The pressure, from the second session. Its sweeps remove the very
	// files the parked read is working from, and every catalog this
	// session has open is one it holds open itself — it reads the whole
	// tree — so nothing here relies on cross-session pinning, which no
	// mount can do.
	driver := openFS(t, f.inner, f.sb, genfs.Options{CacheDir: f.cache, CacheBytes: cap})
	before := driver.CacheUsage()

	// Chorus. Not the proof: readers racing a sweep, for the detector and
	// for the bytes they check.
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
					n, err := driver.LookupPath(ctx, p)
					if err != nil {
						errs <- fmt.Errorf("worker %d lookup %s: %w", w, p, err)
						return
					}
					buf, err := readInode(driver, n.Inode, n.Length, 256<<10)
					if err != nil {
						errs <- fmt.Errorf("worker %d read %s: %w", w, p, err)
						return
					}
					if !bytes.Equal(buf, f.body[f.names[i]]) {
						errs <- fmt.Errorf("worker %d read %s: bytes differ", w, p)
						return
					}
				}
			}
		}(w)
	}
	t.Cleanup(wg.Wait) // likewise: the chorus is joined before its mount closes

	// The proof: this goroutine alone reads 16 MiB of distinct content
	// through a 3 MiB budget, so the sweep cannot fail to happen, and it
	// happens while the read above is demonstrably stopped between two of
	// its own bytes.
	total := 0
	for i := range f.names {
		b := readPath(t, driver, f.path(i), 256<<10)
		if !bytes.Equal(b, f.body[f.names[i]]) {
			t.Fatalf("%s is wrong under the eviction the parked read is waiting through", f.names[i])
		}
		total += len(b)
	}
	usage := driver.CacheUsage()
	swept := usage.EvictedFiles - before.EvictedFiles
	if swept <= 0 {
		t.Fatalf("%d bytes went through a %d-byte cache with a read parked in %s and nothing was evicted (%s)",
			total, cap, parked, usage)
	}
	t.Logf("evicted %d files (%d bytes) while the read of %s sat parked mid-fetch in %s",
		swept, usage.EvictedBytes-before.EvictedBytes, target, parked)

	// Released, and the claim the whole arrangement exists to make: a
	// read that was in flight across every one of those sweeps still
	// returns its file, byte for byte.
	park.letGo()
	if err := <-done; err != nil {
		t.Fatalf("the read parked across %d evictions failed: %v", swept, err)
	}
	if !bytes.Equal(got, f.body[f.names[0]]) {
		t.Fatalf("the read parked across %d evictions returned %d bytes of the wrong content for %s",
			swept, len(got), target)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// The guard that refused a vacuous pass, kept — and now impossible to
	// trip, since the assertion above establishes the same thing at a
	// point where eviction is guaranteed rather than likely.
	if u := driver.CacheUsage(); u.EvictedFiles == 0 {
		t.Fatalf("no eviction happened during the concurrent read; the test proves nothing (%s)", u)
	}
}

// parkedStore parks one pack fetch mid-stream, on a gate the test owns.
// It is what turns "eviction probably overlapped a read" into "eviction
// ran while this read was stopped between its first byte and its last":
// the fetch that goes through the arm below delivers a byte, blocks, and
// stays blocked inside FS.Read until the test lets it go.
type parkedStore struct {
	pelicanobj.Store
	armed   atomic.Bool
	parked  chan string
	release chan struct{}
	once    sync.Once
}

func newParkedStore(inner pelicanobj.Store) *parkedStore {
	return &parkedStore{Store: inner, parked: make(chan string, 1), release: make(chan struct{})}
}

// arm makes the next pack fetch the parked one.
func (p *parkedStore) arm() { p.armed.Store(true) }

// letGo releases the parked fetch, and may be called twice: once by the
// test at the point it means to, and once from a cleanup so that a failed
// assertion cannot leave a goroutine parked inside a mount being closed.
func (p *parkedStore) letGo() { p.once.Do(func() { close(p.release) }) }

// waitForPark blocks until the fetch is parked, and names the way it went
// wrong rather than hanging the suite when it never does: a read that
// finished instead is a gate that was armed too late, and a read that did
// neither never reached the store at all.
func (p *parkedStore) waitForPark(t *testing.T, done <-chan error) string {
	t.Helper()
	select {
	case key := <-p.parked:
		return key
	case err := <-done:
		t.Fatalf("the read finished (err=%v) without parking; nothing was holding it in flight", err)
	case <-time.After(time.Minute):
		t.Fatal("no pack fetch parked within a minute; the read never reached the store")
	}
	return ""
}

func (p *parkedStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	rc, err := p.Store.Get(ctx, key, off, limit)
	if err != nil || !strings.HasPrefix(key, packstore.PackDirKey+"/") || !p.armed.CompareAndSwap(true, false) {
		return rc, err
	}
	// Drained and closed BEFORE parking rather than held open across it.
	// The fetch stays parked for as long as the pressure pass takes, and
	// no transport owes anyone an open response body for that long; what
	// the parked read holds is its place inside FS.Read, which is the
	// thing being tested.
	body, rerr := io.ReadAll(rc)
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, cerr
	}
	if len(body) < 2 {
		p.armed.Store(true) // nothing to stop in the middle of; take the next one
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return &parkedBody{store: p, key: key, body: body}, nil
}

// parkedBody hands over one byte, then stops.
type parkedBody struct {
	store *parkedStore
	key   string
	body  []byte
	off   int
	held  bool
}

func (b *parkedBody) Read(p []byte) (int, error) {
	if b.off >= len(b.body) {
		return 0, io.EOF
	}
	if b.off > 0 && !b.held {
		b.held = true
		b.store.parked <- b.key
		<-b.store.release
	}
	n := len(b.body) - b.off
	if !b.held {
		n = 1
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, b.body[b.off:b.off+n])
	b.off += n
	return n, nil
}

func (b *parkedBody) Close() error { return nil }

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

// TestResidencyReportsItsBound is what makes a residency cap operable: a
// mount that never reaches its bound says so with a zero, and one that
// does say so with a number. On a FUSE mount that number is the
// explanation for an ESTALE, because there the kernel still believes it
// holds what the cap dropped — which is why the FUSE backstop is set
// twenty times higher than the NFS working bound (cmd/pelfs/mountgen.go).
func TestResidencyReportsItsBound(t *testing.T) {
	f := newCacheFixture(t, "cac1e000-0006-4000-8000-000000000006", 12, 4<<10)
	ctx := context.Background()

	// Unbounded: every descent stays resident and nothing is ever dropped.
	free := f.open(t, genfs.Options{})
	for i := range f.names {
		readPath(t, free, f.path(i), 4<<10)
	}
	resident, evicted := free.Residency()
	if resident == 0 {
		t.Fatal("an unbounded mount reports no resident inodes after reading every file")
	}
	if evicted != 0 {
		t.Errorf("an unbounded mount evicted %d residency entries", evicted)
	}
	_ = free.Close()

	// Bounded hard, the way the NFS frontend is: entries go, the count
	// says so, and — because a path frontend re-descends — reads are still
	// correct afterwards.
	tight := f.open(t, genfs.Options{MaxResident: 4})
	for i := range f.names {
		if got := readPath(t, tight, f.path(i), 4<<10); !bytes.Equal(got, f.body[f.names[i]]) {
			t.Fatalf("%s is wrong under residency eviction", f.names[i])
		}
	}
	resident, evicted = tight.Residency()
	if evicted == 0 {
		t.Fatalf("a 4-entry residency cap over %d files evicted nothing", len(f.names))
	}
	if resident > 4 {
		t.Errorf("residency holds %d entries against a cap of 4", resident)
	}
	// The stale inode is the documented consequence, and it has to be
	// exactly that rather than a wrong answer: an inode dropped by the cap
	// answers ErrStale until something descends to it again.
	n, err := tight.LookupPath(ctx, f.path(0))
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.names {
		readPath(t, tight, f.path(i), 4<<10) // push it back out
	}
	if _, err := tight.GetAttr(ctx, n.Inode); err != nil && !errors.Is(err, genfs.ErrStale) {
		t.Fatalf("an evicted inode answered %v, want ErrStale or a live answer", err)
	}
}
