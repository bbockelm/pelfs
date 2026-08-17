package publish_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// TestCatalogOutputIsIndependentOfScheduling is the catalog counterpart of
// TestChunkIdentityDomainIsStable: it pins that what a seal PRODUCES is a
// function of its input alone, not of how many catalogs the machine
// happened to build at once.
//
// Catalogs are built concurrently and appended serially, and that split is
// the whole safety argument. A catalog's identity is the hash of its own
// bytes, so it cannot depend on scheduling. Pack MEMBERSHIP can: a pack is
// cut when the next append would overflow it, so the order of appends
// decides which entries share a pack. If that drifted with the core count,
// two machines sealing the same tree would lay out different packs —
// reproducibility gone, for nothing.
//
// One overlay is therefore sealed several times at different concurrency,
// each into its own store (the same tree twice is not the same input: node
// rows carry mtimes), and the catalog tree and the pack shapes must match.
func TestCatalogOutputIsIndependentOfScheduling(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x60, 0x0d, 0xde, 0x71})
	// A small SMax so a modest fixture splits into a TREE of catalogs, and
	// a small pack target so the appends actually cut; with one flat
	// catalog in one pack there is no order to get wrong.
	v.smax = 24 << 10
	for i := 0; i < 30; i++ {
		dir, err := v.ov.Mkdir(ctx, publishRootInode, fmt.Sprintf("d%02d", i), 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for j := 0; j < 24; j++ {
			v.create(dir.Inode, fmt.Sprintf("f%02d.txt", j),
				[]byte(fmt.Sprintf("body of %02d/%02d, long enough to weigh something at all", i, j)))
		}
	}

	seal := func(concurrency int) (*publish.Result, pelicanobj.Store) {
		t.Helper()
		// A fresh store per seal: the same overlay is published repeatedly,
		// and a ref that already moved would be read as a concurrent writer.
		inner := newInner(t)
		res, err := publish.Seal(ctx, publish.Options{
			Overlay: v.ov, Inner: inner, SpoolDir: t.TempDir(),
			SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
			TargetPackSize: 4 << 10, SMax: v.smax,
			CreatedUnixNano:    1,
			CatalogConcurrency: concurrency,
		})
		if err != nil {
			t.Fatalf("seal at concurrency %d: %v", concurrency, err)
		}
		return res, inner
	}

	serial, serialStore := seal(1)
	if serial.Stats.Catalogs < 3 {
		t.Fatalf("fixture produced %d catalogs; it must split to test anything", serial.Stats.Catalogs)
	}
	if len(serial.NewPacks) < 2 {
		t.Fatalf("fixture produced %d packs; it must cut to test pack membership", len(serial.NewPacks))
	}
	serialPacks := packLayout(t, serialStore, serial)
	for _, concurrency := range []int{2, 8} {
		parallel, parallelStore := seal(concurrency)
		if serial.Superblock.RootCatalog != parallel.Superblock.RootCatalog {
			t.Errorf("concurrency %d changed the root catalog: %x vs %x",
				concurrency, serial.Superblock.RootCatalog, parallel.Superblock.RootCatalog)
		}
		if got, want := catalogFingerprint(parallel.Superblock.Catalogs),
			catalogFingerprint(serial.Superblock.Catalogs); got != want {
			t.Errorf("concurrency %d changed the catalog tree:\n%s\nvs\n%s", concurrency, got, want)
		}
		if got, want := packLayout(t, parallelStore, parallel), serialPacks; got != want {
			t.Errorf("concurrency %d changed pack membership:\n%s\nvs\n%s", concurrency, got, want)
		}
	}
}

// packLayout renders which entries landed in which pack, in order. That is
// the part of a publish the append ORDER decides, and therefore the part
// concurrency could perturb. Pack names and sizes are not comparable
// across runs — a name is random and a trailer carries a build timestamp —
// so packs are identified by position and the superblock backup, whose key
// covers the pack names, by its type alone.
func packLayout(t *testing.T, inner pelicanobj.Store, res *publish.Result) string {
	t.Helper()
	out := ""
	for i, sp := range res.NewPacks {
		entries, err := packstore.FetchTrailer(context.Background(), inner, sp.Name, sp.Size)
		if err != nil {
			t.Fatalf("read pack %s: %v", sp.Name, err)
		}
		out += fmt.Sprintf("pack %d:\n", i)
		for _, e := range entries {
			key := e.Key
			if e.Type == packstore.EntrySuperblock {
				key = "<superblock backup>"
			}
			out += fmt.Sprintf("  %s %s %d\n", e.Type, key, e.Length)
		}
	}
	return out
}

// catalogFingerprint renders a superblock's catalog list as comparable
// text: one line per catalog, identity and all.
func catalogFingerprint(cats []superblock.CatalogEntry) string {
	out := ""
	for _, c := range cats {
		out += fmt.Sprintf("%s inode=%d weight=%d promoted=%d %s\n",
			c.Path, c.Inode, c.Weight, c.Promoted, hex.EncodeToString(c.Identity[:]))
	}
	return out
}
