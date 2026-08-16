package genfs_test

// Microbenchmarks for the phase-3 read path: metadata operations under
// varying concurrency (the kernel issues Lookup/GetAttr storms during
// builds and git-status walks) and chunk reads from the warm cache.
//
//	CGO_ENABLED=0 go test -tags nogspt,notikv -bench . -benchmem ./internal/genfs/
//
// The fixture is a published generation over an in-process fakeorigin, so
// numbers include the full stack below the FUSE boundary — catalog SQLite
// queries, residency locking, cache lookups — but only loopback HTTP.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/publish"
)

// benchFS publishes a fixture tree once per benchmark binary: a directory
// of many small files (the stat-storm shape) plus one multi-MiB chunked
// file, resolved by genfs.
func benchFS(b *testing.B) (*genfs.FS, uint64, []string, uint64, int) {
	b.Helper()
	env := newBenchEnv(b, 512) // 512 inline files under /many + 8 MiB /big.bin
	return env.fs, env.manyIno, env.names, env.bigIno, env.bigLen
}

func BenchmarkLookup(b *testing.B) {
	fs, dirIno, names, _, _ := benchFS(b)
	ctx := context.Background()
	for _, par := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("parallel-%d", par), func(b *testing.B) {
			b.SetParallelism(par)
			var i atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					name := names[i.Add(1)%uint64(len(names))]
					if _, err := fs.Lookup(ctx, dirIno, name); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkGetAttr(b *testing.B) {
	fs, dirIno, names, _, _ := benchFS(b)
	ctx := context.Background()
	// Establish residency once (the kernel contract), then hammer stat.
	inos := make([]uint64, len(names))
	for i, n := range names {
		node, err := fs.Lookup(ctx, dirIno, n)
		if err != nil {
			b.Fatal(err)
		}
		inos[i] = node.Inode
	}
	for _, par := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("parallel-%d", par), func(b *testing.B) {
			b.SetParallelism(par)
			var i atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, err := fs.GetAttr(ctx, inos[i.Add(1)%uint64(len(inos))]); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkReaddir(b *testing.B) {
	fs, dirIno, _, _, _ := benchFS(b)
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		entries, err := fs.Readdir(ctx, dirIno)
		if err != nil {
			b.Fatal(err)
		}
		if len(entries) < 500 {
			b.Fatalf("short listing: %d", len(entries))
		}
	}
}

func BenchmarkReadWarm(b *testing.B) {
	fs, _, _, bigIno, bigLen := benchFS(b)
	ctx := context.Background()
	buf := make([]byte, 1<<20)
	// Warm the decoded-chunk cache.
	if _, err := fs.Read(ctx, bigIno, 0, buf); err != nil {
		b.Fatal(err)
	}
	for _, par := range []int{1, 8} {
		b.Run(fmt.Sprintf("1MiB-parallel-%d", par), func(b *testing.B) {
			b.SetParallelism(par)
			b.SetBytes(1 << 20)
			var i atomic.Uint64
			b.RunParallel(func(pb *testing.PB) {
				local := make([]byte, 1<<20)
				for pb.Next() {
					off := int64(i.Add(1)*(1<<20)) % int64(bigLen-(1<<20))
					if _, err := fs.Read(ctx, bigIno, off, local); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func BenchmarkInlineRead(b *testing.B) {
	fs, dirIno, names, _, _ := benchFS(b)
	ctx := context.Background()
	node, err := fs.Lookup(ctx, dirIno, names[0])
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 4096)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fs.Read(ctx, node.Inode, 0, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// benchEnv builds and publishes the benchmark fixture once per process.
type benchEnv struct {
	fs      *genfs.FS
	manyIno uint64
	names   []string
	bigIno  uint64
	bigLen  int
}

func newBenchEnv(b *testing.B, files int) *benchEnv {
	b.Helper()
	inner, _ := newInner(b)
	v := newTestVolume(b, "beefbeef-0000-4000-8000-000000000001")
	dir := v.mkdir(1, "many")
	names := make([]string, files)
	for i := range names {
		names[i] = fmt.Sprintf("f%04d.txt", i)
		ino := v.create(dir, names[i])
		v.write(ino, []byte(fmt.Sprintf("inline content %04d", i)))
	}
	bigContent := pseudorandom(8<<20, 7)
	big := v.create(1, "big.bin")
	v.write(big, bigContent)

	res := publishVolume(b, v, inner, publish.Options{})
	fs := openFS(b, inner, res.Superblock, genfs.Options{})
	node, err := fs.Lookup(context.Background(), genfs.RootInode, "many")
	if err != nil {
		b.Fatal(err)
	}
	bigNode, err := fs.Lookup(context.Background(), genfs.RootInode, "big.bin")
	if err != nil {
		b.Fatal(err)
	}
	return &benchEnv{fs: fs, manyIno: node.Inode, names: names, bigIno: bigNode.Inode, bigLen: len(bigContent)}
}
