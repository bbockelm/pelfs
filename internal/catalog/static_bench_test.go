package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// The A/B this format exists to win. Both implementations get the same
// tree, built the same way, and answer the same queries. The shapes that
// matter are build cost (a seal writes catalogs), read cost under
// concurrency (a mount serves them), and stored size (a reader downloads
// them).

const benchDirs = 400
const benchPerDir = 40

// benchTree feeds one catalog's worth of a source-shaped tree into
// whichever writer it is given.
func benchTree(addNode func(Node), addEdge func(int64, []byte, int64, uint8), inline func(int64, []byte)) {
	ino := int64(1)
	addNode(Node{Inode: ino, Type: 2, Mode: 0755, Nlink: 2})
	root := ino
	for d := 0; d < benchDirs; d++ {
		ino++
		dirIno := ino
		addNode(Node{Inode: dirIno, Type: 2, Mode: 0755, Nlink: 2})
		addEdge(root, []byte(fmt.Sprintf("dir%04d", d)), dirIno, 2)
		for f := 0; f < benchPerDir; f++ {
			ino++
			addNode(Node{Inode: ino, Type: 1, Mode: 0644, Nlink: 1, Length: 512})
			addEdge(dirIno, []byte(fmt.Sprintf("source_file_%04d.c", f)), ino, 1)
			inline(ino, []byte(fmt.Sprintf("// file %d in dir %d\n", f, d)))
		}
	}
}

// benchDirInode maps a counter onto a real directory inode. The tree
// allocates one directory then its files, so directories are strided --
// probing "2 + n" lands on files, whose listings are empty, and times
// nothing at all.
func benchDirInode(n int) int64 {
	return int64(2 + (n%benchDirs)*(benchPerDir+1))
}

func buildStaticBench(tb testing.TB) []byte {
	w := NewStaticWriter(Meta{VolumeUUID: "u", CoveredPath: "/", IdentityAlgo: "blake3-256"}, 1, 2048)
	benchTree(w.AddNode, w.AddEdge, func(i int64, b []byte) { w.SetInline(i, b) })
	blob, err := w.Finish()
	if err != nil {
		tb.Fatal(err)
	}
	return blob
}

func buildSQLiteBench(tb testing.TB, path string) {
	w, err := Create(path, Meta{VolumeUUID: "u", CoveredPath: "/", IdentityAlgo: "blake3-256"})
	if err != nil {
		tb.Fatal(err)
	}
	var ferr error
	keep := func(err error) {
		if err != nil && ferr == nil {
			ferr = err
		}
	}
	benchTree(
		func(n Node) { keep(w.AddNode(n)) },
		func(p int64, name []byte, i int64, t uint8) { keep(w.AddEdge(p, name, i, t)) },
		func(i int64, b []byte) { keep(w.SetInline(i, b)) },
	)
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	if ferr != nil {
		tb.Fatal(ferr)
	}
}

func BenchmarkCatalogBuildStatic(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildStaticBench(b)
	}
}

func BenchmarkCatalogBuildSQLite(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildSQLiteBench(b, filepath.Join(b.TempDir(), fmt.Sprintf("c%d.db", i)))
	}
}

// TestCatalogStoredSize reports what a reader has to download. It is a
// test rather than a benchmark because the answer is a number, not a
// rate.
func TestCatalogStoredSize(t *testing.T) {
	static := buildStaticBench(t)
	path := filepath.Join(t.TempDir(), "c.db")
	buildSQLiteBench(t, path)
	sqlite, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A catalog is zstd'd into a pack, so the compressed size is what a
	// reader actually downloads. Fixed-width records pad with zeroes,
	// which is exactly what a compressor eats — the raw comparison
	// understates the format and the wire comparison is the honest one.
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zStatic := enc.EncodeAll(static, nil)
	zSQLite := enc.EncodeAll(sqlite, nil)

	entries := benchDirs*benchPerDir + benchDirs
	t.Logf("SIZE %d entries", entries)
	t.Logf("  raw:  static %7d (%.1f B/entry)  sqlite %7d (%.1f B/entry)  ratio %.2fx",
		len(static), float64(len(static))/float64(entries),
		len(sqlite), float64(len(sqlite))/float64(entries),
		float64(len(static))/float64(len(sqlite)))
	t.Logf("  zstd: static %7d (%.1f B/entry)  sqlite %7d (%.1f B/entry)  ratio %.2fx",
		len(zStatic), float64(len(zStatic))/float64(entries),
		len(zSQLite), float64(len(zSQLite))/float64(entries),
		float64(len(zStatic))/float64(len(zSQLite)))
}

// readAll drives the read mix a mount actually issues: a directory
// listing with attributes, then a lookup and a stat per entry.
func benchReadStatic(b *testing.B, parallel bool) {
	blob := buildStaticBench(b)
	s, err := OpenStatic(blob)
	if err != nil {
		b.Fatal(err)
	}
	run := func(pb func() bool, next func() int) {
		for pb() {
			dir := benchDirInode(next())
			ents, err := s.ReaddirPlus(dir)
			if err != nil {
				b.Fatal(err)
			}
			for _, e := range ents {
				if _, err := s.Lookup(dir, e.Name); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	b.ResetTimer()
	if parallel {
		var counter int
		b.RunParallel(func(pb *testing.PB) {
			n := 0
			run(pb.Next, func() int { n++; return n + counter })
		})
		return
	}
	i := 0
	run(func() bool { i++; return i <= b.N }, func() int { return i })
}

func BenchmarkCatalogReadStatic(b *testing.B)         { benchReadStatic(b, false) }
func BenchmarkCatalogReadStaticParallel(b *testing.B) { benchReadStatic(b, true) }

func benchReadSQLite(b *testing.B, parallel bool) {
	path := filepath.Join(b.TempDir(), "c.db")
	buildSQLiteBench(b, path)
	c, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	run := func(pb func() bool, next func() int) {
		for pb() {
			dir := benchDirInode(next())
			ents, err := c.ReaddirPlus(dir)
			if err != nil {
				b.Fatal(err)
			}
			for _, e := range ents {
				if _, err := c.Lookup(dir, e.Name); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	b.ResetTimer()
	if parallel {
		var counter int
		b.RunParallel(func(pb *testing.PB) {
			n := 0
			run(pb.Next, func() int { n++; return n + counter })
		})
		return
	}
	i := 0
	run(func() bool { i++; return i <= b.N }, func() int { return i })
}

func BenchmarkCatalogReadSQLite(b *testing.B)         { benchReadSQLite(b, false) }
func BenchmarkCatalogReadSQLiteParallel(b *testing.B) { benchReadSQLite(b, true) }
