package genfs_test

// What does the decoded-chunk tier actually buy?
//
// It is a cache of DECODE WORK: post-zstd, post-AES bytes of chunks that
// live, already local, in a pack. What it saves is one decode of a chunk
// read more than once; what it costs is disk and — in the shape this
// replaced, one plaintext file per chunk — an inode apiece. Nobody had
// measured the first number, so nobody could say whether the second was
// worth paying. This is the harness that measures it, and the numbers it
// produced are in chunkarena.go and docs/TODO.md.
//
// It is not part of the suite: it builds a ~166 MiB source-shaped tree and
// reads it several times over, so it runs only under
// PELFS_CHUNKCACHE_BENCH=1. Four workloads:
//
//	scan     — a cold read of every file, front to back. The `grep -r` that
//	           follows an untar: every chunk touched once, which is the case
//	           a decode cache is supposed not to help.
//	rescan   — the same read again, warm. The case it is FOR.
//	rescan2  — and again, because an admission policy that admits on
//	           evidence can look excellent on the pass after the one that
//	           filled the arena and then drift, as each pass's misses evict
//	           the residents that served the last one.
//	scatter  — one small window from a randomly chosen file, over and over.
//	           The interactive case, and the one where a whole chunk is
//	           decoded to serve four kilobytes of it.
//
// over four arms, which since there is an admission policy is the axis that
// decides everything: an arena LARGER than the working set, one a hair
// smaller, one a fifth the size, and no tier at all. Packs are made local
// first in every arm, so what is being compared is decode work and nothing
// else.

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// sourceTree is the corpus shape: a kernel/source checkout, which is what
// the workloads this cache is judged on actually read.
const (
	benchDirs      = 120
	benchPerDir    = 60
	benchScatterN  = 20000
	benchScatterSz = 4 << 10
)

// sourceText generates compressible, source-code-shaped bytes. It matters
// that this is not pseudorandom(): an incompressible corpus makes zstd's
// store-if-smaller policy skip compression entirely, and the decode cost
// under measurement would be a cost the shipped codec never pays.
func sourceText(n int, seed int64) []byte {
	words := []string{
		"static", "inline", "struct", "return", "const", "void", "int", "unsigned",
		"if", "else", "for", "while", "goto", "err", "buf", "len", "size", "offset",
		"spin_lock", "kmalloc", "GFP_KERNEL", "EINVAL", "ENOMEM", "printk",
		"/* the comment that every source file has too many of */",
	}
	r := rand.New(rand.NewSource(seed))
	out := make([]byte, 0, n+64)
	for len(out) < n {
		switch r.Intn(8) {
		case 0:
			out = append(out, '\n')
		case 1:
			out = append(out, '\t')
		default:
			out = append(out, words[r.Intn(len(words))]...)
			out = append(out, ' ')
		}
	}
	return out[:n]
}

// benchCorpus is a published source-shaped volume plus the paths in it.
type benchCorpus struct {
	sb    *superblock.Superblock
	inner *countingStore
	files []benchFile
	bytes int64
}

type benchFile struct {
	dir  string
	name string
	size int64
}

func buildBenchCorpus(t *testing.T, encrypted bool) *benchCorpus {
	t.Helper()
	raw, _ := newInner(t)
	c := &benchCorpus{inner: &countingStore{Store: raw}}
	opts := testvol.Options{VolumeID: testvol.ParseUUID(t, "cacc0de0-0001-4000-8000-000000000001")}
	if encrypted {
		opts.VolumeID = testvol.ParseUUID(t, "cacc0de0-0002-4000-8000-000000000002")
		opts.DEK = pseudorandom(32, 11)
		opts.IdentityKey = pseudorandom(32, 12)
		opts.KeyID = 7
		opts.KeyTable = []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		}
	}
	v := testvol.New(t, c.inner, opts)

	r := rand.New(rand.NewSource(4242))
	start := time.Now()
	for d := 0; d < benchDirs; d++ {
		dirName := fmt.Sprintf("d%03d", d)
		dirIno := v.Mkdir(rootIno, dirName)
		for f := 0; f < benchPerDir; f++ {
			// Source-tree size distribution: mostly a few kilobytes, a long
			// tail into the hundreds.
			size := 1<<10 + r.Intn(12<<10)
			if r.Intn(20) == 0 {
				size = 64<<10 + r.Intn(512<<10)
			}
			name := fmt.Sprintf("f%03d.c", f)
			v.WriteFile(dirIno, name, sourceText(size, int64(d*1000+f)))
			c.files = append(c.files, benchFile{dir: dirName, name: name, size: int64(size)})
			c.bytes += int64(size)
		}
	}
	t.Logf("corpus: %d files, %s, written in %s", len(c.files), bytesH(c.bytes), time.Since(start).Round(time.Millisecond))
	sealed := time.Now()
	c.sb = publishVolume(t, v, c.inner, publish.Options{}).Superblock
	t.Logf("corpus: sealed in %s", time.Since(sealed).Round(time.Millisecond))
	return c
}

func bytesH(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// phase is one measured workload run.
type phase struct {
	name  string
	wall  time.Duration
	read  int64
	stats genfs.ChunkStats
	gets  int64
	res   genfs.ArenaResidency
}

func (p phase) rate() float64 {
	total := p.stats.Hits + p.stats.Misses
	if total == 0 {
		return 0
	}
	return 100 * float64(p.stats.Hits) / float64(total)
}

func (p phase) String() string {
	total := p.stats.Hits + p.stats.Misses
	return fmt.Sprintf("%-8s %8s  read %9s  chunk hits %7d / %7d (%5.1f%%)  decoded %9s  gets %5d  %s",
		p.name, p.wall.Round(time.Millisecond), bytesH(p.read),
		p.stats.Hits, total, p.rate(), bytesH(p.stats.DecodedBytes), p.gets,
		residencyH(p.res))
}

// residencyH says what the arena is holding and how much of it anybody read
// again — the question an admission policy exists to change.
func residencyH(r genfs.ArenaResidency) string {
	if r.Slots == 0 {
		return "resident 0"
	}
	return fmt.Sprintf("resident %5d/%9s  served %4.0f%% reused %4.0f%%  fill %6d evict %6d promote %6d",
		r.Slots, bytesH(r.Bytes),
		100*float64(r.ServedBytes)/float64(r.Bytes),
		100*float64(r.ReusedBytes)/float64(r.Bytes),
		r.Fills, r.Evicted, r.Promoted)
}

// runArm runs the three workloads against one configuration and returns a
// phase per workload.
func runArm(t *testing.T, c *benchCorpus, o genfs.Options, encrypted bool) ([]phase, string) {
	t.Helper()
	ctx := context.Background()
	cache := t.TempDir()
	o.CacheDir = cache
	if encrypted {
		o.DEK = pseudorandom(32, 11)
	}
	fs := openFS(t, c.inner, c.sb, o)

	// Packs local first, in both arms: the question is decode cost, not
	// transfer cost, and a prefetch is exactly how a batch job asks for
	// that state.
	if _, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 8}); err != nil {
		t.Fatalf("Prefetch: %v", err)
	}

	base := fs.ChunkStats()
	baseGets := c.inner.gets.Load()
	measure := func(name string, body func() int64) phase {
		start := time.Now()
		read := body()
		p := phase{name: name, wall: time.Since(start), read: read}
		now := fs.ChunkStats()
		p.stats = genfs.ChunkStats{
			Hits:         now.Hits - base.Hits,
			Misses:       now.Misses - base.Misses,
			Decodes:      now.Decodes - base.Decodes,
			DecodedBytes: now.DecodedBytes - base.DecodedBytes,
		}
		p.gets = c.inner.gets.Load() - baseGets
		p.res = fs.ArenaResidency()
		base, baseGets = now, c.inner.gets.Load()
		return p
	}

	scan := func() int64 {
		var total int64
		buf := make([]byte, 128<<10)
		for _, f := range c.files {
			dirNode, err := fs.Lookup(ctx, rootIno, f.dir)
			if err != nil {
				t.Fatalf("lookup %s: %v", f.dir, err)
			}
			n, err := fs.Lookup(ctx, dirNode.Inode, f.name)
			if err != nil {
				t.Fatalf("lookup %s/%s: %v", f.dir, f.name, err)
			}
			for off := int64(0); off < n.Length; {
				got, err := fs.Read(ctx, n.Inode, off, buf)
				if err != nil {
					t.Fatalf("read %s/%s at %d: %v", f.dir, f.name, off, err)
				}
				if got == 0 {
					break
				}
				off += int64(got)
				total += int64(got)
			}
		}
		return total
	}

	// Two re-scans, not one. A policy that admits on evidence can look
	// excellent on the pass right after the one that filled the arena and
	// then drift, as each pass's misses evict the residents that served the
	// last one; the only way to see that is to run the pass again.
	out := []phase{measure("scan", scan), measure("rescan", scan), measure("rescan2", scan)}

	out = append(out, measure("scatter", func() int64 {
		r := rand.New(rand.NewSource(99))
		buf := make([]byte, benchScatterSz)
		var total int64
		for i := 0; i < benchScatterN; i++ {
			f := c.files[r.Intn(len(c.files))]
			dirNode, err := fs.Lookup(ctx, rootIno, f.dir)
			if err != nil {
				t.Fatalf("lookup %s: %v", f.dir, err)
			}
			n, err := fs.Lookup(ctx, dirNode.Inode, f.name)
			if err != nil {
				t.Fatalf("lookup %s/%s: %v", f.dir, f.name, err)
			}
			off := int64(0)
			if n.Length > int64(benchScatterSz) {
				off = r.Int63n(n.Length - int64(benchScatterSz))
			}
			got, err := fs.Read(ctx, n.Inode, off, buf)
			if err != nil {
				t.Fatalf("read %s/%s at %d: %v", f.dir, f.name, off, err)
			}
			total += int64(got)
		}
		return total
	}))

	return out, describeCache(t, cache)
}

// describeCache is the inode question, answered: how many files and how
// many bytes each directory of the cache is holding.
func describeCache(t *testing.T, dir string) string {
	t.Helper()
	out := ""
	for _, name := range []string{"chunks", "packs", "catalogs", "trailers"} {
		var files int
		var bytes int64
		ents, err := os.ReadDir(filepath.Join(dir, name))
		if err == nil {
			for _, e := range ents {
				if fi, err := e.Info(); err == nil && !e.IsDir() {
					files++
					bytes += fi.Size()
				}
			}
		}
		out += fmt.Sprintf("%s=%d files/%s  ", name, files, bytesH(bytes))
	}
	return out
}

// The SIZE arms, which are the interesting axis once there is an admission
// policy at all: the tier's behaviour is entirely decided by how the working
// set compares to the mapping.
//
//	fits   — the default arena, comfortably larger than the corpus. The
//	         shipped numbers, and the floor no policy may regress.
//	1.1x   — an arena a HAIR smaller than the working set. The adversarial
//	         case: a bare FIFO cursor evicts each chunk one access before it
//	         is wanted, so a re-scan hits nothing at all though nearly
//	         everything would fit.
//	32M    — an arena a fifth of the working set. The thrash case, where the
//	         honest ceiling for a cyclic re-read is the resident fraction.
func benchSizeArms(corpus int64) []struct {
	name  string
	arena int64
} {
	return []struct {
		name  string
		arena int64
	}{
		{"fits", 0},
		{"1.1x", int64(float64(corpus) / 1.1)},
		{"32M", 32 << 20},
	}
}

func TestChunkCacheWorkloads(t *testing.T) {
	if os.Getenv("PELFS_CHUNKCACHE_BENCH") != "1" {
		t.Skip("set PELFS_CHUNKCACHE_BENCH=1 to measure the decoded-chunk tier")
	}
	for _, encrypted := range []bool{false, true} {
		label := "plaintext"
		if encrypted {
			label = "encrypted"
		}
		t.Run(label, func(t *testing.T) {
			c := buildBenchCorpus(t, encrypted)
			t.Logf("== %s corpus: %d files, %s ==", label, len(c.files), bytesH(c.bytes))

			type row struct {
				arm string
				ps  []phase
			}
			var rows []row
			for _, size := range benchSizeArms(c.bytes) {
				ps, cache := runArm(t, c, genfs.Options{ChunkArenaBytes: size.arena}, encrypted)
				t.Logf("%s (arena %s)", size.name, bytesH(genfs.ArenaBytesFor(size.arena)))
				for _, p := range ps {
					t.Logf("  %s", p)
				}
				t.Logf("  cache: %s", cache)
				rows = append(rows, row{size.name, ps})
			}
			// No tier at all: the number every arm has to beat to be worth
			// the disk, and the one a thrashing arena was not beating.
			none, _ := runArm(t, c, genfs.Options{ChunkArenaBytes: -1}, encrypted)
			t.Logf("none (no decode tier)")
			for _, p := range none {
				t.Logf("  %s", p)
			}
			rows = append(rows, row{"none", none})

			t.Logf("== wall, and chunk hit rate ==")
			t.Logf("%-6s | %-15s %-15s %-15s %-15s", "arm", "scan", "rescan", "rescan2", "scatter")
			for _, r := range rows {
				line := fmt.Sprintf("%-6s |", r.arm)
				for _, p := range r.ps {
					line += fmt.Sprintf(" %8s %5.1f%% ", p.wall.Round(time.Millisecond), p.rate())
				}
				t.Logf("%s", line)
			}
		})
	}
}

// TestDecodeThroughput is the other half of the question: if a decode is
// free, a cache that saves one is worth nothing. Measured on the entry
// codec itself, at the shipped chunk sizes, both with and without the
// AES-GCM layer an encrypted volume adds.
func TestDecodeThroughput(t *testing.T) {
	if os.Getenv("PELFS_CHUNKCACHE_BENCH") != "1" {
		t.Skip("set PELFS_CHUNKCACHE_BENCH=1 to measure decode throughput")
	}
	key := pseudorandom(entrycodec.KeySize, 5)
	for _, size := range []int{4 << 10, 64 << 10, 1 << 20, 4 << 20} {
		plain := sourceText(size, 7)
		for _, enc := range []bool{false, true} {
			var k []byte
			if enc {
				k = key
			}
			stored, alg, err := entrycodec.Encode(plain, k)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			// Enough iterations that the timer is not the measurement.
			iters := max(20, (256<<20)/size)
			start := time.Now()
			for i := 0; i < iters; i++ {
				if _, err := entrycodec.Decode(stored, alg, k); err != nil {
					t.Fatalf("Decode: %v", err)
				}
			}
			d := time.Since(start)
			gbps := float64(size) * float64(iters) / d.Seconds() / (1 << 30)
			label := "zstd"
			if enc {
				label = "zstd+aesgcm"
			}
			t.Logf("%-12s %8s chunk: %6.2f GiB/s plaintext out (%6.1f ns/chunk, ratio %.2fx)",
				label, bytesH(int64(size)), gbps,
				float64(d.Nanoseconds())/float64(iters), float64(size)/float64(len(stored)))
		}
	}
}
