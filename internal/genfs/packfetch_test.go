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
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// countingStore counts pack range reads and the bytes they carry. A chunk
// read used to be exactly one of these; on a wide-area link the count is
// the number of round trips, which is what actually bounds throughput.
type countingStore struct {
	pelicanobj.Store
	gets  atomic.Int64
	bytes atomic.Int64
}

func (c *countingStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	rc, err := c.Store.Get(ctx, key, off, limit)
	if err != nil || !strings.HasPrefix(key, packstore.PackDirKey+"/") {
		return rc, err
	}
	c.gets.Add(1)
	// Counted as delivered rather than as requested: a whole-pack fetch
	// asks for no limit at all, and that is the request whose size this
	// test file most needs to see.
	return &tallyReader{ReadCloser: rc, n: &c.bytes}, nil
}

type tallyReader struct {
	io.ReadCloser
	n *atomic.Int64
}

func (t *tallyReader) Read(p []byte) (int, error) {
	got, err := t.ReadCloser.Read(p)
	t.n.Add(int64(got))
	return got, err
}

func (c *countingStore) since(n int64) int64 { return c.gets.Load() - n }

// packFixture is a published volume with several chunked files, served
// through a counted transport.
type packFixture struct {
	inner *countingStore
	sb    *superblock.Superblock
	body  map[string][]byte
	cache string
}

func newPackFixture(t *testing.T, uuid string, target int64) *packFixture {
	t.Helper()
	raw, _ := newInner(t)
	f := &packFixture{
		inner: &countingStore{Store: raw},
		body:  make(map[string][]byte),
		cache: t.TempDir(),
	}
	v := newTestVolume(t, f.inner, uuid)
	// The shape of a real tree, and the reason both mechanisms exist. The
	// chunker averages 4 MiB, so the big files are several chunks each
	// (something to coalesce) while every small file is exactly one chunk
	// (nothing to coalesce, one round trip apiece — the 40,029-request
	// workload in miniature).
	for i, name := range []string{"a.bin", "b.bin", "c.bin"} {
		f.body[name] = pseudorandom(12<<20, int64(9100+i))
		v.Write(v.Create(rootIno, name), f.body[name])
	}
	for i := 0; i < smallFiles; i++ {
		name := fmt.Sprintf("s%03d.c", i)
		f.body[name] = pseudorandom(9<<10, int64(9200+i))
		v.Write(v.Create(rootIno, name), f.body[name])
	}
	f.sb = publishVolume(t, v, f.inner, publish.Options{TargetPackSize: target}).Superblock
	return f
}

// smallFiles is how many one-chunk files the fixture holds.
const smallFiles = 240

func (f *packFixture) open(t *testing.T, o genfs.Options) *genfs.FS {
	t.Helper()
	o.CacheDir = f.cache
	return openFS(t, f.inner, f.sb, o)
}

// readFile reads a whole file in bufSize windows, the way a kernel hands
// a sequential read down.
func readFile(t *testing.T, fs *genfs.FS, name string, bufSize int) []byte {
	t.Helper()
	ctx := context.Background()
	n, err := fs.Lookup(ctx, rootIno, name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	out := make([]byte, 0, n.Length)
	buf := make([]byte, bufSize)
	for off := int64(0); off < n.Length; {
		got, err := fs.Read(ctx, n.Inode, off, buf)
		if err != nil {
			t.Fatalf("read %s at %d: %v", name, off, err)
		}
		if got == 0 {
			t.Fatalf("read %s: short at %d of %d", name, off, n.Length)
		}
		out = append(out, buf[:got]...)
		off += int64(got)
	}
	return out
}

// chunkFiles counts the decoded chunks currently cached.
func chunkFiles(t *testing.T, cache string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(cache, "chunks"))
	if err != nil {
		return 0
	}
	return len(entries)
}

// dropChunks empties the decoded-chunk cache, so a re-read has to go back
// to whatever holds the stored bytes and prove where that was.
func dropChunks(t *testing.T, cache string) {
	t.Helper()
	dir := filepath.Join(cache, "chunks")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
}

func cachedPacks(t *testing.T, cache string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(cache, "packs"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !strings.Contains(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out
}

// A read spanning several chunks is one request, not one per chunk.
//
// Worth being precise about the reach of this. The chunker averages 4 MiB,
// so a kernel-sized read (128 KiB, or 1 MiB with big reads) never touches
// two chunks of one file — coalescing does nothing there, and nothing
// needs it, since one request per 4 MiB is already efficient. What it
// serves is the caller that asks for a lot at once: Prefetch, and any
// frontend passing a large buffer down.
func TestMultiChunkReadIsOneRequest(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0001-4002-8003-a0b0c0d0e0f0", 64<<20)
	// Whole-pack caching off, so this measures coalescing alone.
	fs := f.open(t, genfs.Options{PackCacheBytes: -1})

	// One throwaway pass, then drop the decoded chunks. The location layer
	// is resolved lazily now, so the FIRST read of a pack also pays a
	// trailer probe; counting that as a chunk read would measure the index,
	// not the coalescing this test is about.
	readFile(t, fs, "a.bin", 16<<20)
	dropChunks(t, f.cache)

	before := f.inner.gets.Load()
	got := readFile(t, fs, "a.bin", 16<<20)
	gets := f.inner.since(before)
	if !bytes.Equal(got, f.body["a.bin"]) {
		t.Fatalf("a.bin did not read back byte-exact")
	}
	chunks := chunkFiles(t, f.cache)
	if chunks < 3 {
		t.Fatalf("fixture produced %d cached chunks; the test needs a multi-chunk file", chunks)
	}
	if gets >= int64(chunks) {
		t.Errorf("%d pack reads for %d chunks: no coalescing happened", gets, chunks)
	}
	t.Logf("one 12 MiB read: %d pack read(s) for %d chunks", gets, chunks)
}

// The single-chunk-per-read case, which is what a FUSE mount actually
// issues: it must still cost one request per chunk and not one per read.
func TestKernelSizedSequentialReadCostsOnePerChunk(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0008-4002-8003-a0b0c0d0e0f0", 64<<20)
	fs := f.open(t, genfs.Options{PackCacheBytes: -1})

	// See TestMultiChunkReadIsOneRequest: the first pass resolves the
	// location layer, the measured one reads chunks.
	readFile(t, fs, "a.bin", 128<<10)
	dropChunks(t, f.cache)

	before := f.inner.gets.Load()
	got := readFile(t, fs, "a.bin", 128<<10)
	gets := f.inner.since(before)
	if !bytes.Equal(got, f.body["a.bin"]) {
		t.Fatalf("a.bin did not read back byte-exact")
	}
	chunks := int64(chunkFiles(t, f.cache))
	if gets > chunks {
		t.Errorf("%d pack reads for %d chunks over %d kernel-sized reads",
			gets, chunks, (12<<20)/(128<<10))
	}
	t.Logf("12 MiB in 128 KiB windows: %d pack reads for %d chunks", gets, chunks)
}

// The policy, stated as a test: the FIRST read of a pack fetches it whole.
// No evidence is gathered and none is waited for, so what one small read
// costs is a property of the generation — the publisher's cut size — and
// not of what this mount happened to read earlier.
//
// The scattered case is where that is at its most expensive, which is
// exactly why it is worth pinning: three reads in three different files
// pull three packs and nothing else, and pulling them is bounded, not
// open-ended.
func TestScatteredReadFetchesEachPackWholeAndOnce(t *testing.T) {
	const target = 4 << 20
	f := newPackFixture(t, "9ac0de01-0002-4002-8003-a0b0c0d0e0f0", target)
	fs := f.open(t, genfs.Options{})
	ctx := context.Background()

	before := f.inner.gets.Load()
	beforeBytes := f.inner.bytes.Load()
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		n, err := fs.Lookup(ctx, rootIno, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		buf := make([]byte, 4096)
		if _, err := fs.Read(ctx, n.Inode, n.Length/2, buf); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(buf, f.body[name][n.Length/2:n.Length/2+4096]) {
			t.Errorf("%s: scattered read returned the wrong bytes", name)
		}
	}
	packs := cachedPacks(t, f.cache)
	if len(packs) == 0 {
		t.Fatal("three scattered reads cached no pack at all")
	}
	// Three files' chunks, plus the pack holding the catalog they were
	// looked up through. Anything beyond that is a pack nobody asked for.
	if len(packs) > 4 {
		t.Errorf("three scattered reads pulled %d packs: %v", len(packs), packs)
	}
	t.Logf("3 scattered 4 KiB reads at a %d MiB cut size: %d pack request(s), %d bytes, %d pack(s) cached",
		target>>20, f.inner.since(before), f.inner.bytes.Load()-beforeBytes, len(packs))

	// A second read in the same files must not go out again: the pack it
	// needs is already whole on disk, decoded chunks or not.
	dropChunks(t, f.cache)
	before = f.inner.gets.Load()
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		n, err := fs.Lookup(ctx, rootIno, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		buf := make([]byte, 4096)
		if _, err := fs.Read(ctx, n.Inode, n.Length/2, buf); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
	}
	if again := f.inner.since(before); again != 0 {
		t.Errorf("re-reading out of packs already on disk made %d federation request(s)", again)
	}
}

// Walking a directory of one-chunk files is the case coalescing cannot
// help with: each file is one entry, and under a ranged-read policy one
// round trip apiece. Fetching the pack whole collapses the whole directory
// into one transfer, from the first file rather than from the sixteenth.
func TestManySmallReadsCostOneTransfer(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0003-4002-8003-a0b0c0d0e0f0", 4<<20)
	fs := f.open(t, genfs.Options{})

	// The first small file must already have pulled its pack; nothing is
	// waiting for a case to be made.
	name := fmt.Sprintf("s%03d.c", 0)
	if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, f.body[name]) {
		t.Fatalf("%s did not read back byte-exact", name)
	}
	if len(cachedPacks(t, f.cache)) == 0 {
		t.Fatal("the first read of a pack did not fetch it whole")
	}

	before := f.inner.gets.Load()
	for i := 1; i < smallFiles; i++ {
		name := fmt.Sprintf("s%03d.c", i)
		if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, f.body[name]) {
			t.Fatalf("%s did not read back byte-exact", name)
		}
	}
	rest := f.inner.since(before)
	t.Logf("first small file pulled its pack; the other %d cost %d request(s) across %d cached pack(s)",
		smallFiles-1, rest, len(cachedPacks(t, f.cache)))
	// Far fewer requests than files: whatever is left is the packs the
	// directory spills into, not one round trip per file.
	if rest >= int64(smallFiles-1) {
		t.Errorf("%d requests for %d small files: the directory is not being served from whole packs",
			rest, smallFiles-1)
	}
}

// Prefetch declares bulk intent by definition, and the cache it leaves
// behind must survive the process: remounting a volume the last session
// already pulled down should not go back to the federation.
func TestPrefetchCachesPacksAcrossOpens(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0004-4002-8003-a0b0c0d0e0f0", 4<<20)
	fs := f.open(t, genfs.Options{})

	rep, err := fs.Prefetch(context.Background(), 4)
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if rep.Failed != 0 {
		t.Fatalf("prefetch failed %d chunks: %v", rep.Failed, rep.Sample)
	}
	if len(cachedPacks(t, f.cache)) == 0 {
		t.Errorf("a bulk prefetch cached no packs whole")
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh FS over the same cache directory, with the decoded chunks
	// thrown away: the reopen must be served entirely from cached packs.
	if err := os.RemoveAll(filepath.Join(f.cache, "chunks")); err != nil {
		t.Fatal(err)
	}
	again := f.open(t, genfs.Options{})
	before := f.inner.gets.Load()
	for name, want := range f.body {
		if got := readFile(t, again, name, 1<<20); !bytes.Equal(got, want) {
			t.Errorf("%s did not read back byte-exact after reopen", name)
		}
	}
	t.Logf("reopen and re-read the whole volume: %d pack reads", f.inner.since(before))
	if got := f.inner.since(before); got != 0 {
		t.Errorf("reopening over a warm pack cache still made %d federation read(s)", got)
	}
}

// A cached pack that is short — a killed download, a truncated file — must
// never be served as if it were whole, and must not turn into a read
// error either.
func TestTruncatedCachedPackIsNotServed(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0005-4002-8003-a0b0c0d0e0f0", 4<<20)
	fs := f.open(t, genfs.Options{})
	if _, err := fs.Prefetch(context.Background(), 4); err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	packs := cachedPacks(t, f.cache)
	if len(packs) == 0 {
		t.Fatalf("no packs cached")
	}
	for _, name := range packs {
		fp := filepath.Join(f.cache, "packs", name)
		fi, err := os.Stat(fp)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(fp, fi.Size()/2); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(f.cache, "chunks")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	again := f.open(t, genfs.Options{})
	for name, want := range f.body {
		if got := readFile(t, again, name, 1<<20); !bytes.Equal(got, want) {
			t.Errorf("%s did not read back byte-exact over a truncated pack cache", name)
		}
	}
}

// The cache is bounded: past the cap, least recently used packs go.
//
// READS drive it, not a prefetch. A prefetch refuses a generation this
// much larger than the budget outright — that is what the budget check is
// for (TestPrefetchRefusesAGenerationLargerThanTheCache) — so the only way
// a cache this small ever overfills is the ordinary one, a read at a time.
func TestPackCacheEvicts(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0006-4002-8003-a0b0c0d0e0f0", 2<<20)
	// Room for a couple of packs out of the several the fixture produces.
	fs := f.open(t, genfs.Options{PackCacheBytes: 5 << 20})
	for name, want := range f.body {
		if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, want) {
			t.Fatalf("%s did not read back byte-exact", name)
		}
	}
	var total int64
	for _, name := range cachedPacks(t, f.cache) {
		fi, err := os.Stat(filepath.Join(f.cache, "packs", name))
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
	}
	if total > 5<<20 {
		t.Errorf("pack cache holds %d bytes, cap is %d", total, 5<<20)
	}
	// Evicting must not cost correctness: everything still reads.
	for name, want := range f.body {
		if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, want) {
			t.Errorf("%s did not read back byte-exact after eviction", name)
		}
	}
}

// PackCacheBytes negative means "coalesce, but never store a whole pack" —
// the setting for a client with less disk than bandwidth.
//
// A prefetch in that mode has nothing it is allowed to make local, so it
// says so instead of quietly doing nothing (or, as it once did, decoding
// the whole volume into chunk files that the pack policy had just been
// told not to spend disk on).
func TestPackCacheCanBeDisabled(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0007-4002-8003-a0b0c0d0e0f0", 4<<20)
	fs := f.open(t, genfs.Options{PackCacheBytes: -1})
	if _, err := fs.Prefetch(context.Background(), 4); !errors.Is(err, genfs.ErrPrefetchNeedsPackCache) {
		t.Fatalf("Prefetch with whole-pack caching off: %v, want ErrPrefetchNeedsPackCache", err)
	}
	if packs := cachedPacks(t, f.cache); len(packs) != 0 {
		t.Errorf("whole-pack caching is disabled but cached %v", packs)
	}
	for name, want := range f.body {
		if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, want) {
			t.Errorf("%s did not read back byte-exact", name)
		}
	}
}

// A generation that does not FIT in the local cache cannot be made local,
// and the honest answer is a refusal with both numbers in it. Fetching it
// anyway would evict the front of the pack set to make room for the back
// and leave the mount slower than it would have been with no prefetch at
// all — and, in strict mode, would report a warm cache that is not one.
func TestPrefetchRefusesAGenerationLargerThanTheCache(t *testing.T) {
	f := newPackFixture(t, "9ac0de01-0008-4002-8003-a0b0c0d0e0f0", 2<<20)
	fs := f.open(t, genfs.Options{CacheBytes: 5 << 20})
	// Open has already pulled the pack holding the root catalog; the
	// question is whether the REFUSED prefetch adds to that.
	wasCached := len(cachedPacks(t, f.cache))
	before := f.inner.gets.Load()
	rep, err := fs.Prefetch(context.Background(), 4)
	var budget *genfs.PrefetchBudgetError
	if !errors.As(err, &budget) {
		t.Fatalf("Prefetch of a ~36 MiB generation into a 5 MiB cache: %v (report %+v)", err, rep)
	}
	if budget.Need <= budget.Budget {
		t.Errorf("refused a set of %d bytes against a %d-byte budget", budget.Need, budget.Budget)
	}
	if budget.Packs == 0 {
		t.Error("the refusal did not say how many packs it was refusing")
	}
	// It refused BEFORE moving payload. Trailers are read to resolve the
	// locations the refusal is computed from; packs are not.
	if got := cachedPacks(t, f.cache); len(got) != wasCached {
		t.Errorf("a refused prefetch went from %d cached pack(s) to %d", wasCached, len(got))
	}
	t.Logf("refused %d bytes in %d packs against a %d-byte budget, after %d trailer request(s)",
		budget.Need, budget.Packs, budget.Budget, f.inner.since(before))

	// And the mount still WORKS: a refusal to prefetch is not a refusal to
	// read. Only --prefetch all turns it into a failure to start.
	for name, want := range f.body {
		if got := readFile(t, fs, name, 1<<20); !bytes.Equal(got, want) {
			t.Errorf("%s did not read back byte-exact after a refused prefetch", name)
		}
	}
}
