package genfs_test

import (
	"context"
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
)

// packGetStore counts requests against pack objects, which is what a mount
// pays before it can serve anything. all counts EVERY object read, so a
// change that trades pack requests for requests of some other kind — a
// multi-pack index, say — cannot look like a saving it is not.
type packGetStore struct {
	pelicanobj.Store
	gets atomic.Int64
	all  atomic.Int64
}

func (p *packGetStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	p.all.Add(1)
	if strings.HasPrefix(key, packstore.PackDirKey+"/") {
		p.gets.Add(1)
	}
	return p.Store.Get(ctx, key, off, limit)
}

// reset zeroes both counters between the halves of a comparison.
func (p *packGetStore) reset() {
	p.gets.Store(0)
	p.all.Store(0)
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

	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	if _, err := fs.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	got := inner.gets.Load()
	t.Logf("cold mount over %d packs: %d pack request(s) to first readdir", packs, got)
	if got >= int64(packs) {
		t.Errorf("mounting a %d-pack generation cost %d pack request(s): the index is still being built up front",
			packs, got)
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
