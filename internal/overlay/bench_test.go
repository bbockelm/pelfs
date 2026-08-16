package overlay_test

// Benchmarks for the write path. The kernel-level mount gate measured
// ~0.4 ms per stat through a writable mount; these isolate how much of
// that is the overlay itself (the FUSE round trip and the kernel are not
// in the picture here).
//
//	CGO_ENABLED=0 go test -tags nogspt,notikv -bench . -benchmem ./internal/overlay/

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/overlay"
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
