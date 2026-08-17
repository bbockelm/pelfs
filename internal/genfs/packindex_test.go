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

// packGetStore counts pack range reads, which is what a mount pays before
// it can serve anything: one per pack in the generation's pack list.
type packGetStore struct {
	pelicanobj.Store
	gets atomic.Int64
}

func (p *packGetStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if strings.HasPrefix(key, packstore.PackDirKey+"/") {
		p.gets.Add(1)
	}
	return p.Store.Get(ctx, key, off, limit)
}

// A mount indexes every pack trailer in the generation before it serves a
// byte. Packs are immutable and the superblock signs each trailer's hash,
// so the second mount of a generation must not go back to the federation
// for any of it — that cost was being paid on every single mount.
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
	if len(res.Superblock.PackList) < 2 {
		t.Fatalf("volume has %d packs; the test needs several", len(res.Superblock.PackList))
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

// A damaged local trailer must cost a round trip, never a mount.
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
	// And the bad copy is gone, not re-read forever.
	for _, e := range trailers {
		b, err := os.ReadFile(filepath.Join(cache, "trailers", e.Name()))
		if err == nil && string(b) == "not a trailer" {
			t.Errorf("the corrupt trailer for %s survived the mount that rejected it", e.Name())
		}
	}
}
