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

// arenaFixture is a published volume big enough that a small arena has to
// wrap several times to hold it.
type arenaFixture struct {
	inner *countingStore
	sb    *superblock.Superblock
	body  map[string][]byte
	names []string
	cache string
}

func newArenaFixture(t *testing.T, uuid string, files, size int) *arenaFixture {
	t.Helper()
	raw, _ := newInner(t)
	f := &arenaFixture{
		inner: &countingStore{Store: raw},
		body:  make(map[string][]byte),
		cache: t.TempDir(),
	}
	v := newTestVolume(t, f.inner, uuid)
	for i := 0; i < files; i++ {
		name := fmt.Sprintf("a%03d.bin", i)
		f.body[name] = pseudorandom(size, int64(3300+i))
		v.Write(v.Create(rootIno, name), f.body[name])
		f.names = append(f.names, name)
	}
	f.sb = publishVolume(t, v, f.inner, publish.Options{TargetPackSize: 2 << 20}).Superblock
	return f
}

func (f *arenaFixture) open(t *testing.T, o genfs.Options) *genfs.FS {
	t.Helper()
	o.CacheDir = f.cache
	return openFS(t, f.inner, f.sb, o)
}

// The tier is ONE file. That is the whole point of the change: the shape
// it replaced cost an inode and a flat directory entry per chunk anyone
// had ever read, on a volume with no upper bound on how many that is.
func TestDecodedChunksAreOneFile(t *testing.T) {
	f := newArenaFixture(t, "a4e4a000-0001-4000-8000-000000000001", 12, 512<<10)
	fs := f.open(t, genfs.Options{})
	for _, name := range f.names {
		if got := readFile(t, fs, name, 64<<10); !bytes.Equal(got, f.body[name]) {
			t.Fatalf("%s did not read back byte-exact", name)
		}
	}
	if n := fs.DecodedChunksResident(); n == 0 {
		t.Fatal("reading the whole volume put nothing in the decoded-chunk arena")
	}
	if _, err := os.Stat(filepath.Join(f.cache, "chunks")); err == nil {
		t.Error("a per-chunk directory came back")
	}
	ents, err := os.ReadDir(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	var arenaFiles int
	for _, e := range ents {
		if !e.IsDir() {
			arenaFiles++
			if e.Name() != "chunks.arena" {
				t.Errorf("unexpected loose file in the cache: %s", e.Name())
			}
		}
	}
	if arenaFiles != 1 {
		t.Errorf("the decoded-chunk tier is %d files, want exactly 1", arenaFiles)
	}
	// And it is charged against the one budget, under its own name.
	usage := fs.CacheUsage()
	var arena int64
	for _, d := range usage.Dirs {
		if d.Name == "arena" {
			arena = d.Bytes
		}
	}
	if arena <= 0 {
		t.Errorf("the arena is not reported in the cache usage: %s", usage)
	}
}

// The tier turned off is a supported configuration, not a broken one: a
// mount that reads a volume once has no use for a decode cache, and the
// reservation is better spent on packs.
func TestDecodedChunkArenaCanBeDisabled(t *testing.T) {
	f := newArenaFixture(t, "a4e4a000-0002-4000-8000-000000000002", 8, 256<<10)
	fs := f.open(t, genfs.Options{ChunkArenaBytes: -1})
	for _, name := range f.names {
		if got := readFile(t, fs, name, 64<<10); !bytes.Equal(got, f.body[name]) {
			t.Fatalf("%s did not read back byte-exact with no decode tier", name)
		}
	}
	if _, err := os.Stat(filepath.Join(f.cache, "chunks.arena")); err == nil {
		t.Error("the tier is off and an arena file was created anyway")
	}
	if st := fs.ChunkStats(); st.Hits != 0 {
		t.Errorf("%d chunk-cache hits with no chunk cache", st.Hits)
	}
}

// The correctness claim the arena has to earn: a reader copying bytes out
// of the mapping while the cursor is wrapping over them gets its own
// bytes, or a miss, and never somebody else's chunk.
//
// The pressure is real, not hoped for — the arena is a tenth of the
// volume, so the cursor laps it many times over during the run — and every
// read is compared against the source content, which is the only check
// that would catch a torn copy.
func TestArenaEvictionUnderConcurrentReaders(t *testing.T) {
	const files, size = 24, 512 << 10
	f := newArenaFixture(t, "a4e4a000-0003-4000-8000-000000000003", files, size)
	// Room for a couple of chunks at a time out of twelve megabytes.
	fs := f.open(t, genfs.Options{ChunkArenaBytes: 1 << 20})
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ctx := context.Background()
			buf := make([]byte, 32<<10)
			for round := 0; round < 6; round++ {
				for i, name := range f.names {
					n, err := fs.Lookup(ctx, rootIno, name)
					if err != nil {
						errs <- fmt.Errorf("worker %d lookup %s: %w", w, name, err)
						return
					}
					// A window that moves per worker and round, so readers
					// are inside different parts of the same chunks at once.
					off := int64((w*7+round*13+i)%(size/len(buf))) * int64(len(buf))
					got, err := fs.Read(ctx, n.Inode, off, buf)
					if err != nil {
						errs <- fmt.Errorf("worker %d read %s at %d: %w", w, name, off, err)
						return
					}
					want := f.body[name][off : off+int64(got)]
					if !bytes.Equal(buf[:got], want) {
						errs <- fmt.Errorf("worker %d read %s at %d: bytes differ (arena eviction tore a read)",
							w, name, off)
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
	st := fs.ChunkStats()
	if st.Hits == 0 {
		t.Error("no read was ever served out of the arena; the test proved nothing about eviction")
	}
	if st.Misses <= int64(files) {
		t.Errorf("only %d misses over %d reads: the arena never had to evict", st.Misses, files*8*6)
	}
	t.Logf("1 MiB arena over a %d MiB volume, 8 readers x 6 rounds: %d hits, %d misses, %s decoded",
		(files*size)>>20, st.Hits, st.Misses, bytesH(st.DecodedBytes))
}

// A v0.1.0 state directory has a populated flat chunks/ directory. It is a
// cache, so deleting it is always safe, and leaving it would be disk that
// nothing in this build reclaims and no budget covers.
func TestLegacyChunkDirectoryIsSweptOnce(t *testing.T) {
	f := newArenaFixture(t, "a4e4a000-0004-4000-8000-000000000004", 4, 64<<10)
	legacy := filepath.Join(f.cache, "chunks")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	const stale = 7
	for i := 0; i < stale; i++ {
		name := fmt.Sprintf("%064x", i)
		if err := os.WriteFile(filepath.Join(legacy, name), make([]byte, 4096), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fs := f.open(t, genfs.Options{})
	files, bytes := fs.LegacyChunksSwept()
	if files != stale || bytes != stale*4096 {
		t.Fatalf("swept %d files / %d bytes, want %d / %d", files, bytes, stale, stale*4096)
	}
	if _, err := os.Stat(legacy); err == nil {
		t.Error("the legacy chunk directory survived the sweep")
	}
	// And only once: a second mount over the same state directory has
	// nothing to say.
	again := f.open(t, genfs.Options{})
	if n, _ := again.LegacyChunksSwept(); n != 0 {
		t.Errorf("the second mount reported sweeping %d files", n)
	}
}

// The arena is a RESERVATION out of the one cache budget, so a mount must
// not be able to hand out disk it has already spent. A prefetch that
// ignored it would promise a pack set the sweep then has to eat into.
func TestArenaIsChargedAgainstTheCacheBudget(t *testing.T) {
	f := newArenaFixture(t, "a4e4a000-0005-4000-8000-000000000005", 8, 256<<10)
	const budget = 64 << 20
	fs := f.open(t, genfs.Options{CacheBytes: budget})
	u := fs.CacheUsage()
	var arena int64
	for _, d := range u.Dirs {
		if d.Name == "arena" {
			arena = d.Bytes
		}
	}
	if want := int64(budget) / 8; arena != want {
		t.Fatalf("a %d-byte budget produced a %d-byte arena, want %d", int64(budget), arena, want)
	}
	if u.Bytes < arena {
		t.Fatalf("the cache reports %d bytes, less than the %d-byte arena inside it", u.Bytes, arena)
	}
	// A cache too small to be worth an arena simply does not get one,
	// rather than getting a mapping that one chunk would evict.
	tiny := newArenaFixture(t, "a4e4a000-0006-4000-8000-000000000006", 4, 64<<10)
	small := tiny.open(t, genfs.Options{CacheBytes: 4 << 20})
	for _, d := range small.CacheUsage().Dirs {
		if d.Name == "arena" && d.Bytes != 0 {
			t.Errorf("a 4 MiB budget still reserved %d bytes of arena", d.Bytes)
		}
	}
}
