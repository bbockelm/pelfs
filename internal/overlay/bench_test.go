package overlay_test

// Benchmarks for the write path. The kernel-level mount gate measured
// ~0.4 ms per stat through a writable mount; these isolate how much of
// that is the overlay itself (the FUSE round trip and the kernel are not
// in the picture here).
//
//	CGO_ENABLED=0 go test -bench . -benchmem ./internal/overlay/

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
)

func benchOverlay(b *testing.B, files int) (*overlay.FS, uint64, []string) {
	b.Helper()
	fx := newFixture(b, "b0000000-0000-4000-8000-00000000b001")
	ov := openOverlay(b, fx, b.TempDir())
	ctx := context.Background()
	dir, err := ov.Mkdir(ctx, 1, "bench", 0755, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	names := make([]string, files)
	for i := range names {
		names[i] = fmt.Sprintf("f%04d.txt", i)
		n, err := ov.Create(ctx, dir.Inode, names[i], 0644, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, []byte("content")); err != nil {
			b.Fatal(err)
		}
	}
	return ov, dir.Inode, names
}

// BenchmarkOverlayCreate is the untar shape with the kernel and FUSE
// removed: one create per iteration into a directory that keeps growing,
// so the reported ns/op is the overlay's own cost for the operation an
// unpack issues tens of thousands of times.
func BenchmarkOverlayCreate(b *testing.B) {
	fx := newFixture(b, "b0000000-0000-4000-8000-00000000b002")
	ov := openOverlay(b, fx, b.TempDir())
	ctx := context.Background()
	dir, err := ov.Mkdir(ctx, 1, "bench", 0755, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		if _, err := ov.Create(ctx, dir.Inode, fmt.Sprintf("f%07d", i), 0644, 0, 0); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// BenchmarkOverlayCreateWrite adds the content write and the attribute
// fixup an unpack performs per file (tar sets mode and mtime after
// writing the body), so one iteration is one whole extracted file.
func BenchmarkOverlayCreateWrite(b *testing.B) {
	fx := newFixture(b, "b0000000-0000-4000-8000-00000000b003")
	ov := openOverlay(b, fx, b.TempDir())
	ctx := context.Background()
	dir, err := ov.Mkdir(ctx, 1, "bench", 0755, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	body := make([]byte, 4096)
	mode := uint32(0644)
	mtime := int64(1700000000)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		n, err := ov.Create(ctx, dir.Inode, fmt.Sprintf("f%07d", i), 0644, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, body); err != nil {
			b.Fatal(err)
		}
		if _, err := ov.SetAttr(ctx, n.Inode, overlay.SetAttrIn{Mode: &mode, MtimeNS: &mtime}); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkOverlayLookup(b *testing.B) {
	ov, dir, names := benchOverlay(b, 256)
	ctx := context.Background()
	for _, par := range []int{1, 8} {
		b.Run(fmt.Sprintf("parallel-%d", par), func(b *testing.B) {
			b.SetParallelism(par)
			var i atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := ov.Lookup(ctx, dir, names[i.Add(1)%uint64(len(names))]); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkOverlayGetAttr(b *testing.B) {
	ov, dir, names := benchOverlay(b, 256)
	ctx := context.Background()
	inos := make([]uint64, len(names))
	for i, n := range names {
		node, err := ov.Lookup(ctx, dir, n)
		if err != nil {
			b.Fatal(err)
		}
		inos[i] = node.Inode
	}
	for _, par := range []int{1, 8} {
		b.Run(fmt.Sprintf("parallel-%d", par), func(b *testing.B) {
			b.SetParallelism(par)
			var i atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := ov.GetAttr(ctx, inos[i.Add(1)%uint64(len(inos))]); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkOverlayIsDirty(b *testing.B) {
	ov, dir, names := benchOverlay(b, 64)
	ctx := context.Background()
	node, err := ov.Lookup(ctx, dir, names[0])
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ov.IsDirty(node.Inode); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOverlayReaddir(b *testing.B) {
	ov, dir, _ := benchOverlay(b, 256)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ov.Readdir(ctx, dir); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOverlayUnlinkCleanFile is the `rm -rf` shape against a
// PUBLISHED tree: every name resolves through the base, every inode is
// clean, and nothing the removal touches was written by this session. It
// is the workload the release-week report was about (an rm -rf of a
// kernel-tarball-sized tree), and it is the one a fix that materializes an
// onode row per unlink would pay for.
//
// One iteration is one unlink. The pool is republished whenever it runs
// out, off the clock.
func BenchmarkOverlayUnlinkCleanFile(b *testing.B) {
	const pool = 2048
	ctx := context.Background()
	var ov *overlay.FS
	var dir uint64
	var names []string
	next := pool
	refill := func() {
		b.StopTimer()
		fx := newFixture(b, "b0000000-0000-4000-8000-00000000b010")
		v := openOverlay(b, fx, b.TempDir())
		d, err := v.Mkdir(ctx, rootIno, "rmrf", 0755, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		names = make([]string, pool)
		for i := range names {
			names[i] = fmt.Sprintf("f%05d.dat", i)
			n, err := v.Create(ctx, d.Inode, names[i], 0644, 0, 0)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := v.Write(ctx, n.Inode, 0, []byte("content")); err != nil {
				b.Fatal(err)
			}
		}
		// One whole checkpoint: the tree becomes the base generation's and
		// the overlay forgets every row it wrote.
		quietCheckpointB(b, fx, v)
		ov, dir, next = v, d.Inode, 0
		b.StartTimer()
	}
	b.ReportAllocs()
	for b.Loop() {
		if next == pool {
			refill()
		}
		if err := ov.Unlink(ctx, dir, names[next]); err != nil {
			b.Fatal(err)
		}
		next++
	}
}

// quietCheckpointB is quietCheckpoint (renameghost_test.go) for a
// benchmark, which gets a testing.TB rather than a *testing.T.
func quietCheckpointB(b *testing.B, fx *fixture, ov *overlay.FS) {
	b.Helper()
	ctx := context.Background()
	snap, err := ov.Snapshot(ctx, filepath.Join(b.TempDir(), "snap"))
	if err != nil {
		b.Fatalf("snapshot: %v", err)
	}
	defer snap.Close() //nolint:errcheck
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap,
		Inner:           fx.inner,
		SpoolDir:        b.TempDir(),
		SigningKey:      fx.key,
		Prev:            fx.head.Superblock,
		PrevRaw:         fx.head.Raw,
		TargetPackSize:  1 << 20,
	})
	if err != nil {
		b.Fatalf("seal: %v", err)
	}
	if _, err := fx.base.Swap(ctx, res.Superblock); err != nil {
		b.Fatalf("swap: %v", err)
	}
	fx.head = res
	if _, err := ov.Rebase(ctx, snap.Seq(), overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	}); err != nil {
		b.Fatalf("rebase: %v", err)
	}
}
