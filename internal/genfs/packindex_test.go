package genfs_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
)

// packGetStore counts requests against pack objects, which is what a mount
// pays before it can serve anything. all counts EVERY object read, so a
// change that trades pack requests for requests of some other kind — a
// multi-pack index, say — cannot look like a saving it is not. bytes is
// the third column, and the one the other two cannot stand in for: an
// index fetched WHOLE is one request and a gigabyte.
type packGetStore struct {
	pelicanobj.Store
	gets  atomic.Int64
	all   atomic.Int64
	bytes atomic.Int64
}

func (p *packGetStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	p.all.Add(1)
	if strings.HasPrefix(key, packstore.PackDirKey+"/") {
		p.gets.Add(1)
	}
	rc, err := p.Store.Get(ctx, key, off, limit)
	if err != nil {
		return nil, err
	}
	return &countingReadCloser{ReadCloser: rc, n: &p.bytes}, nil
}

// reset zeroes the counters between the halves of a comparison.
func (p *packGetStore) reset() {
	p.gets.Store(0)
	p.all.Store(0)
	p.bytes.Store(0)
}

// countingReadCloser charges bytes as they are consumed rather than as
// they are requested: a reader that asks for the rest of an object and
// stops after a header has not moved the object.
type countingReadCloser struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// A cold mount must not index the generation. Serving the first question
// takes the root catalog and the pack that holds it; the trailers of every
// other pack answer questions nobody has asked, and there is one of them
// per cut size however large the volume grows.
func TestColdMountDoesNotIndexEveryPack(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a3")
	dir := v.Mkdir(1, "d")
	for i := 0; i < 12; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	packs := len(packsOf(t, inner, res.Superblock))
	if packs < 8 {
		t.Fatalf("volume has %d packs; the test needs many", packs)
	}

	var volumeBytes int64
	for _, pe := range packsOf(t, inner, res.Superblock) {
		volumeBytes += pe.Size
	}

	inner.reset()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	if _, err := fs.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	got, all, bytes := inner.gets.Load(), inner.all.Load(), inner.bytes.Load()
	t.Logf("cold mount over %d packs: %d pack request(s), %d request(s) in all, %d bytes of a %d-byte volume",
		packs, got, all, bytes, volumeBytes)
	if got >= int64(packs) {
		t.Errorf("mounting a %d-pack generation cost %d pack request(s): the index is still being built up front",
			packs, got)
	}
	// The counter that exists for exactly this and had no assertion reading
	// it. Trading a trailer per pack for an index per pack, or for one
	// index fetched whole, is not a saving; only the total says so.
	if all >= int64(packs) {
		t.Errorf("mounting a %d-pack generation cost %d request(s) in all: the round trips moved to another "+
			"key space rather than going away", packs, all)
	}
	// And the third column, which neither of the other two can stand in
	// for: one request can be the whole multi-pack index.
	if bytes >= volumeBytes/4 {
		t.Errorf("mounting cost %d bytes of a %d-byte volume: a mount is meant to read a root catalog, "+
			"not a proportion of the generation", bytes, volumeBytes)
	}
}

// The location cache is a CACHE, and the test of a cache is that losing
// its contents costs time and not correctness. Driven at a cap of a
// handful of entries, so eviction happens between one read and the next
// and every location has to be re-derived.
func TestReadsAreByteExactUnderLocationEviction(t *testing.T) {
	defer genfs.SetHotPackLocationCap(8)()
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a5")
	dir := v.Mkdir(1, "d")
	want := map[string][]byte{}
	for i := 0; i < 12; i++ {
		name := string(rune('a'+i)) + ".bin"
		body := pseudorandom(600<<10, int64(i)+1)
		f := v.Create(dir, name)
		v.Write(f, body)
		want["d/"+name] = body
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	packs := len(packsOf(t, inner, res.Superblock))

	readAllFiles := func(fs *genfs.FS, when string) {
		t.Helper()
		for p, body := range want {
			n, err := fs.LookupPath(ctx, p)
			if err != nil {
				t.Fatalf("%s: lookup %s: %v", when, p, err)
			}
			got := readAll(t, fs, n.Inode, int(n.Length), 64<<10)
			if !bytes.Equal(got, body) {
				t.Fatalf("%s: %s read back %d bytes, want %d identical", when, p, len(got), len(body))
			}
		}
		if held := fs.HeldPackLocations(); held > 8 {
			t.Errorf("%s: the mount holds %d locations over a cap of 8", when, held)
		}
	}

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	readAllFiles(fs, "cold")
	// Again, against a cache whose every entry has been evicted since.
	readAllFiles(fs, "second pass")
	_ = fs.Close()

	// And on a cold remount, where the trailers are local but the map is
	// empty — the case a bounded map has to get right or a remount reads
	// the wrong bytes.
	fs2 := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	readAllFiles(fs2, "remount")
	t.Logf("%d packs read byte-exact three times over holding at most 8 locations", packs)
}

// Absence is the answer that must never come out of a cache. A generation
// genuinely holds an identity or it does not, and eviction cannot be
// allowed to turn the first into the second — the caller's response to
// "missing" is to re-upload content it has, or to refuse a seal.
func TestEvictionNeverTurnsIntoAbsence(t *testing.T) {
	defer genfs.SetHotPackLocationCap(4)()
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a6")
	dir := v.Mkdir(1, "d")
	var paths []string
	for i := 0; i < 10; i++ {
		name := string(rune('a'+i)) + ".bin"
		f := v.Create(dir, name)
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
		paths = append(paths, "d/"+name)
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})

	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	// ContentOf is the seal's carry-forward check: it asks for the whole
	// location map and then reports anything it cannot find as gone.
	for _, p := range paths {
		n, err := fs.LookupPath(ctx, p)
		if err != nil {
			t.Fatalf("lookup %s: %v", p, err)
		}
		if _, err := fs.ContentOf(ctx, n.Inode); err != nil {
			t.Fatalf("ContentOf %s: %v", p, err)
		}
	}
	// A caller that asked for every location holds every location: the cap
	// governs what a READ accumulates, not what an inventory asked for.
	if held, packs := fs.HeldPackLocations(), fs.IndexedPacks(); held <= 4 {
		t.Errorf("after a whole-map request the mount holds %d locations across %d packs; the cap was "+
			"applied to a caller that explicitly asked for all of them", held, packs)
	}
}

// mountCost is what a cold mount pays before it can answer its first
// question: every request, not only the ones against packs, and the bytes
// they moved.
type mountCost struct {
	packs    int
	requests int64
	bytes    int64
	// manifest is what the generation's own pack list weighs. It is the
	// one thing at mount that legitimately grows with pack count — the
	// signed list is what authorizes reading any pack at all, and the
	// mount holds it either way — so it is measured and subtracted rather
	// than asserted away.
	manifest int64
	// rootPack is the size of the pack holding the root catalog: the other
	// thing a mount legitimately reads, since the whole-pack policy takes
	// the pack the hint names entire.
	rootPack int64
	segments int
	wall     time.Duration
}

// coldMountBody is one staged file. Every file is the same size and every
// generation below holds the same files, so the NAMESPACE — and with it
// the root catalog a mount reads — is a constant and the pack count is
// the only variable.
const coldMountBody = 16 << 10

// measureColdMount publishes the same content cut at the given pack size
// and reports what mounting it costs from an empty cache. A cut below the
// body size gives one pack per file; a cut far above it gives a handful.
func measureColdMount(t *testing.T, files int, target int64) mountCost {
	t.Helper()
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, fmt.Sprintf("9efe7c40-0000-4000-8000-%012x", target))
	// A fan-out rather than a flat directory: a flat one puts every dirent
	// in a single catalog, which is not the shape whose cost is in
	// question.
	const perDir = 64
	dirs := map[string]uint64{}
	for i := 0; i < files; i++ {
		dirName := fmt.Sprintf("d%03d", i/perDir)
		dirIno, made := dirs[dirName]
		if !made {
			dirIno = v.Mkdir(1, dirName)
			dirs[dirName] = dirIno
		}
		f := v.Create(dirIno, fmt.Sprintf("f%05d.bin", i))
		v.Write(f, pseudorandom(coldMountBody, int64(i)+1))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: target, FirstPackSize: target})
	got := len(packsOf(t, inner, res.Superblock))

	inner.reset()
	start := time.Now()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	if _, err := fs.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	c := mountCost{
		packs: got, requests: inner.all.Load(), bytes: inner.bytes.Load(),
		segments: len(res.Superblock.Manifests), wall: time.Since(start),
	}
	for _, m := range res.Superblock.Manifests {
		c.manifest += m.Size
	}
	if h := res.Superblock.RootCatalogHint; h != nil {
		if pe, ok := packEntryNamed(packsOf(t, inner, res.Superblock), h.Pack); ok {
			c.rootPack = pe.Size
		}
	}
	if c.rootPack == 0 {
		t.Fatal("the generation records no usable root-catalog hint; the bound below has no floor")
	}
	_ = fs.Close()
	return c
}

// THE cold-mount bound: what a mount costs must not follow how many packs
// the generation is made of, beyond the generation's own pack list.
//
// Stated as a comparison between two pack counts rather than as an
// absolute, because that is the property and because it holds at any
// fixture size an ordinary test run can afford. Both regressions this
// guards against are linear in packs and so cannot hide inside it: a
// trailer per pack shows up in requests, and an index fetched whole shows
// up in bytes.
//
// The pack list is subtracted because it is not one of them. A mount is
// handed a signed list of the packs it may read and holds it — that is the
// authorization, not an optimization — so its bytes are the floor a mount
// cannot go under while the list lives in one object. At 72 bytes a pack
// that is ~28 MB at the 400,000-pack target, against the 1.6 GB the index
// used to be.
//
// PELFS_MOUNT_PACKS runs it at a real scale — `PELFS_MOUNT_PACKS=10000 go
// test ./internal/genfs -run MountCostDoesNotFollow -v -timeout 60m` — where
// the numbers are the ones the design claims rather than a proxy for them.
func TestMountCostDoesNotFollowPackCount(t *testing.T) {
	if testing.Short() {
		t.Skip("publishes several hundred packs")
	}
	files := 384
	if spec := os.Getenv("PELFS_MOUNT_PACKS"); spec != "" {
		n, err := strconv.Atoi(spec)
		if err != nil || n < 16 {
			t.Fatalf("PELFS_MOUNT_PACKS=%q", spec)
		}
		files = n
	}
	// The same files, cut two ways: a handful of packs, and one per file.
	a := measureColdMount(t, files, 8<<20)
	b := measureColdMount(t, files, coldMountBody/2)
	if b.packs < 8*a.packs {
		t.Fatalf("the two cuts produced %d and %d packs; the fixture no longer varies pack count",
			a.packs, b.packs)
	}
	for _, c := range []mountCost{a, b} {
		t.Logf("cold mount over %d packs: %d request(s), %d bytes (pack list %d in %d segment(s), "+
			"root's pack %d) in %v",
			c.packs, c.requests, c.bytes, c.manifest, c.segments, c.rootPack, c.wall.Round(time.Millisecond))

		// The bound, stated as what a mount is FOR: read the signed pack
		// list, read the pack holding the root catalog, answer. Anything
		// else showing up here is per-pack work — a trailer each, or an
		// index fetched whole — and both are what this exists to catch.
		if want := c.manifest + c.rootPack + 8192; c.bytes > want {
			t.Errorf("mounting %d packs moved %d bytes, over the %d it takes to read the pack list (%d) "+
				"and the root catalog's pack (%d)", c.packs, c.bytes, want, c.manifest, c.rootPack)
		}
		// One request per manifest segment, one for the root's pack, and
		// slack for a mount that has to range-read rather than take a pack
		// whole.
		if want := int64(c.segments) + 3; c.requests > want {
			t.Errorf("mounting %d packs cost %d request(s), over the %d it takes to read %d pack-list "+
				"segment(s) and one pack", c.packs, c.requests, want, c.segments)
		}
	}
	// And the same thing said as a comparison, which is the form that
	// survives a change to what a mount reads: eight times the packs must
	// not be eight times the requests.
	if b.requests > a.requests+int64(b.segments-a.segments)+2 {
		t.Errorf("mounting %d packs cost %d request(s) against %d for %d packs: the mount is doing work "+
			"per pack again", b.packs, b.requests, a.requests, a.packs)
	}
}

// Packs are immutable and the superblock signs each trailer's hash, so a
// trailer this mount has already authenticated is the same bytes forever.
// The second mount of a generation must not go back to the federation for
// anything it resolved in the first.
func TestPackIndexReusesCachedTrailers(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a1")
	dir := v.Mkdir(1, "d")
	// Several packs, so the index is worth building at all.
	for i := 0; i < 6; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	if len(packsOf(t, inner, res.Superblock)) < 2 {
		t.Fatalf("volume has %d packs; the test needs several", len(packsOf(t, inner, res.Superblock)))
	}

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	cold := inner.gets.Load()
	if cold == 0 {
		t.Fatal("the first mount fetched nothing at all")
	}
	if _, err := fs.LookupPath(ctx, "d/a.bin"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	_ = fs.Close()

	inner.gets.Store(0)
	fs2 := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	if warm := inner.gets.Load(); warm != 0 {
		t.Errorf("the second mount issued %d pack read(s) to index a generation it has already indexed", warm)
	}
	// And it still resolves: a cached trailer is a location map, not a hint.
	if _, err := fs2.LookupPath(ctx, "d/a.bin"); err != nil {
		t.Fatalf("lookup after warm open: %v", err)
	}
	n, err := fs2.LookupPath(ctx, "d/a.bin")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := readAll(t, fs2, n.Inode, int(n.Length), 64<<10); len(got) != int(n.Length) {
		t.Fatalf("read %d bytes of a %d-byte file", len(got), n.Length)
	}
}

// A damaged local trailer must cost a round trip, never a mount — and it
// must not survive being consulted, or every mount would re-reject it.
func TestPackIndexFallsBackOnCorruptCachedTrailer(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a2")
	f := v.Create(1, "one.bin")
	v.Write(f, pseudorandom(300<<10, 7))
	res := publishVolume(t, v, inner, publish.Options{})

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	// Prefetch asks for the whole location map, so every pack's trailer is
	// on disk to be corrupted.
	if _, err := fs.Prefetch(ctx, 2); err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	_ = fs.Close()

	trailers, err := os.ReadDir(filepath.Join(cache, "trailers"))
	if err != nil || len(trailers) == 0 {
		t.Fatalf("no trailers were cached: %v", err)
	}
	for _, e := range trailers {
		if err := os.WriteFile(filepath.Join(cache, "trailers", e.Name()), []byte("not a trailer"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	fs2 := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	if _, err := fs2.LookupPath(ctx, "one.bin"); err != nil {
		t.Fatalf("mount over corrupt cached trailers: %v", err)
	}
	if _, err := fs2.Prefetch(ctx, 2); err != nil {
		t.Fatalf("Prefetch over corrupt cached trailers: %v", err)
	}
	// And the bad copies are gone, not re-read forever.
	for _, e := range trailers {
		b, err := os.ReadFile(filepath.Join(cache, "trailers", e.Name()))
		if err == nil && string(b) == "not a trailer" {
			t.Errorf("the corrupt trailer for %s survived the mount that rejected it", e.Name())
		}
	}
}

// A trailer read out of a locally cached pack has to clear the same bar a
// fetched one does. The pack is a file in a cache directory: it can be
// truncated, swapped, or scribbled on, and a location map built from it
// would send every read to an arbitrary offset in an arbitrary object.
func TestTrailerFromCachedPackIsVerified(t *testing.T) {
	ctx := context.Background()
	base, volDir := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000a4")
	dir := v.Mkdir(1, "d")
	for i := 0; i < 6; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})

	cache := t.TempDir()
	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	if _, err := fs.Prefetch(ctx, 2); err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	_ = fs.Close()

	// Throw away the saved trailers so the next mount has to read them out
	// of the cached packs, then corrupt the packs' trailer regions.
	if err := os.RemoveAll(filepath.Join(cache, "trailers")); err != nil {
		t.Fatal(err)
	}
	packs := cachedPacks(t, cache)
	if len(packs) == 0 {
		t.Fatal("prefetch cached no packs")
	}
	for _, name := range packs {
		fp := filepath.Join(cache, "packs", name)
		fi, err := os.Stat(fp)
		if err != nil {
			t.Fatal(err)
		}
		pf, err := os.OpenFile(fp, os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		// Inside the trailer, past the footer: the length and magic still
		// parse, so nothing but the hash check can catch this.
		if _, err := pf.WriteAt([]byte("wrongwrongwrong!"), fi.Size()-64); err != nil {
			t.Fatal(err)
		}
		_ = pf.Close()
	}
	if err := os.RemoveAll(filepath.Join(cache, "chunks")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(cache, "catalogs")); err != nil {
		t.Fatal(err)
	}
	_ = volDir

	fs2 := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: cache})
	n, err := fs2.LookupPath(ctx, "d/a.bin")
	if err != nil {
		t.Fatalf("mount over packs with corrupt trailers: %v", err)
	}
	if got := readAll(t, fs2, n.Inode, int(n.Length), 64<<10); len(got) != int(n.Length) {
		t.Fatalf("read %d bytes of a %d-byte file", len(got), n.Length)
	}
}
