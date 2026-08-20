// Package dedupbench measures what content-defined chunking actually buys
// this system, against fixed-size blocking and plain whole-file hashing.
//
// SCRATCH / MEASUREMENT ONLY. Not part of the build; nothing imports it.
//
// Run with a corpus:
//
//	PELFS_CORPUS_A=/path/linux-6.6 PELFS_CORPUS_B=/path/linux-6.6.1 \
//	  go test -tags nogspt,notikv ./internal/dedupbench/ -run TestDedup -v
package dedupbench

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
)

// inlineMax mirrors publish.DefaultInlineMax: at or below this, a file is
// stored verbatim in the catalog and never chunked or deduped at all.
const inlineMax = 4096

// fixedBlock is the fixed-size alternative. 4 MiB matches chunkid's
// DefaultAvgSize so the two schemes target the same size distribution.
const fixedBlock = 4 << 20

// ---------------------------------------------------------------------
// scheme accounting
// ---------------------------------------------------------------------

// store models the bytes a scheme would have to upload. Keys are content
// identities; a repeated identity is a dedup hit and costs nothing.
type store struct {
	seen map[[32]byte]struct{}

	logical  int64 // bytes presented
	inline   int64 // bytes below inlineMax: stored verbatim, never deduped
	uploaded int64 // unique chunk bytes actually written
	deduped  int64 // chunk bytes elided by a dedup hit
	units    int64 // chunks/files presented above inlineMax
	unique   int64 // distinct identities
}

func newStore() *store { return &store{seen: map[[32]byte]struct{}{}} }

func (s *store) add(b []byte) {
	id := blake3.Sum256(b)
	s.units++
	if _, ok := s.seen[id]; ok {
		s.deduped += int64(len(b))
		return
	}
	s.seen[id] = struct{}{}
	s.unique++
	s.uploaded += int64(len(b))
}

// dedupPct is the share of chunked bytes avoided by dedup.
func (s *store) dedupPct() float64 {
	tot := s.uploaded + s.deduped
	if tot == 0 {
		return 0
	}
	return 100 * float64(s.deduped) / float64(tot)
}

// total is what the volume costs: unique chunk bytes plus every inline
// byte (inline bytes are per-file catalog blobs, deduped by nothing).
func (s *store) total() int64 { return s.uploaded + s.inline }

// ---------------------------------------------------------------------
// the three schemes
// ---------------------------------------------------------------------

type scheme int

const (
	schemeCDC scheme = iota
	schemeFixed
	schemeWholeFile
)

func (sc scheme) String() string {
	switch sc {
	case schemeCDC:
		return "CDC(1/4/16MiB)"
	case schemeFixed:
		return "fixed(4MiB)"
	default:
		return "whole-file"
	}
}

// feed presents one file's bytes to a store under the given scheme,
// applying the same inline rule publish applies.
func (s *store) feed(sc scheme, data []byte) {
	s.logical += int64(len(data))
	if int64(len(data)) <= inlineMax {
		s.inline += int64(len(data))
		return
	}
	switch sc {
	case schemeWholeFile:
		s.add(data)
	case schemeFixed:
		for off := 0; off < len(data); off += fixedBlock {
			end := off + fixedBlock
			if end > len(data) {
				end = len(data)
			}
			s.add(data[off:end])
		}
	case schemeCDC:
		ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
		for {
			c, err := ck.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				panic(err)
			}
			s.add(c.Data)
		}
	}
}

// byteReader must not copy: a copy would charge the CDC path for work the
// other schemes do not do.
func byteReader(b []byte) io.Reader { return bytes.NewReader(b) }

// sealChunked is publish.chunkFile's per-file work: CDC, identity hash,
// entry encode. sealWhole is the same work with the chunker replaced by a
// single whole-file read. Both return the stored byte count so nothing is
// optimised away.
func sealChunked(data []byte) int {
	var n int
	ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
	for {
		c, err := ck.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
		_ = blake3.Sum256(c.Data)
		stored, _, err := entrycodec.Encode(c.Data, nil)
		if err != nil {
			panic(err)
		}
		n += len(stored)
	}
	return n
}

func sealWhole(data []byte) int {
	buf, err := io.ReadAll(byteReader(data))
	if err != nil {
		panic(err)
	}
	_ = blake3.Sum256(buf)
	stored, _, err := entrycodec.Encode(buf, nil)
	if err != nil {
		panic(err)
	}
	return len(stored)
}

// BenchmarkSealFileWork compares a seal's per-file CPU with and without
// the chunker, at sizes spanning the corpus.
func BenchmarkSealFileWork(b *testing.B) {
	src := make([]byte, 8<<20)
	if p := os.Getenv("PELFS_BIGFILE"); p != "" {
		f, err := os.Open(p)
		if err != nil {
			b.Skip(err)
		}
		if _, err := io.ReadFull(f, src); err != nil {
			b.Skip(err)
		}
		f.Close() //nolint:errcheck
	}
	for _, sz := range []int{8 << 10, 64 << 10, 256 << 10, 1 << 20, 8 << 20} {
		data := src[:sz]
		b.Run(fmt.Sprintf("%dKiB/chunked", sz>>10), func(b *testing.B) {
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sealChunked(data)
			}
		})
		b.Run(fmt.Sprintf("%dKiB/whole", sz>>10), func(b *testing.B) {
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sealWhole(data)
			}
		})
	}
}

// ---------------------------------------------------------------------
// corpus walking
// ---------------------------------------------------------------------

type fileInfo struct {
	path string
	size int64
}

func walkCorpus(t testing.TB, root string) []fileInfo {
	t.Helper()
	var out []fileInfo
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, fileInfo{path: p, size: fi.Size()})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

func corpusEnv(t testing.TB, name string) string {
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s not set", name)
	}
	return v
}

// ---------------------------------------------------------------------
// Test 1: size distribution of a kernel-shaped tree
// ---------------------------------------------------------------------

func TestSizeDistribution(t *testing.T) {
	root := corpusEnv(t, "PELFS_CORPUS_A")
	files := walkCorpus(t, root)

	var (
		nTotal, nInline, nSingle, nMulti int64
		bTotal, bInline, bSingle, bMulti int64
		maxSize                          int64
		nOverFixed, bOverFixed           int64
	)
	for _, f := range files {
		nTotal++
		bTotal += f.size
		if f.size > maxSize {
			maxSize = f.size
		}
		switch {
		case f.size <= inlineMax:
			nInline++
			bInline += f.size
		case f.size <= chunkid.DefaultMinSize:
			// Below MinSize the cut loop never runs: exactly one chunk,
			// byte-identical to a whole-file hash.
			nSingle++
			bSingle += f.size
		default:
			nMulti++
			bMulti += f.size
		}
		if f.size > fixedBlock {
			nOverFixed++
			bOverFixed += f.size
		}
	}
	pc := func(a, b int64) string {
		if b == 0 {
			return "0%"
		}
		return fmt.Sprintf("%.3f%%", 100*float64(a)/float64(b))
	}
	t.Logf("corpus %s", root)
	t.Logf("  files=%d  bytes=%s  largest=%s", nTotal, mib(bTotal), mib(maxSize))
	t.Logf("  inline (<=%dB, never chunked):        %d files (%s)  %s (%s of bytes)",
		inlineMax, nInline, pc(nInline, nTotal), mib(bInline), pc(bInline, bTotal))
	t.Logf("  chunked, single chunk (<=MinSize 1MiB): %d files (%s)  %s (%s of bytes)",
		nSingle, pc(nSingle, nTotal), mib(bSingle), pc(bSingle, bTotal))
	t.Logf("  chunked, MULTI-chunk possible (>1MiB):  %d files (%s)  %s (%s of bytes)  <-- only these can differ from whole-file",
		nMulti, pc(nMulti, nTotal), mib(bMulti), pc(bMulti, bTotal))
	t.Logf("  files above the 4MiB fixed block:      %d (%s)  %s", nOverFixed, pc(nOverFixed, nTotal), mib(bOverFixed))
}

// ---------------------------------------------------------------------
// Test 2: cold dedup on a whole tree, three schemes
// ---------------------------------------------------------------------

func TestColdTreeDedup(t *testing.T) {
	root := corpusEnv(t, "PELFS_CORPUS_A")
	files := walkCorpus(t, root)
	for _, sc := range []scheme{schemeCDC, schemeFixed, schemeWholeFile} {
		st := newStore()
		start := time.Now()
		for _, f := range files {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			st.feed(sc, data)
		}
		el := time.Since(start)
		t.Logf("%-16s logical=%s inline=%s chunked-units=%d unique=%d uploaded=%s deduped=%s (%.2f%% of chunked bytes) total-stored=%s  [%s]",
			sc, mib(st.logical), mib(st.inline), st.units, st.unique,
			mib(st.uploaded), mib(st.deduped), st.dedupPct(), mib(st.total()), el.Round(time.Millisecond))
	}
}

// ---------------------------------------------------------------------
// Test 3: cross-file dedup — whole-file duplicates vs sub-file chunks
// ---------------------------------------------------------------------

// TestDedupProvenance answers: is chunk-level dedup finding anything a
// whole-file hash would not? It reports, of all bytes CDC deduped, how
// many came from a file that is byte-identical to an earlier file (which
// whole-file hashing catches for free) versus a genuine sub-file match.
func TestDedupProvenance(t *testing.T) {
	root := corpusEnv(t, "PELFS_CORPUS_A")
	files := walkCorpus(t, root)

	wholeSeen := map[[32]byte]struct{}{}
	chunkSeen := map[[32]byte]struct{}{}
	var (
		dupFileBytes int64 // bytes in files identical to an earlier file
		dupFiles     int64
		subFileBytes int64 // chunk bytes deduped inside a NON-duplicate file
		subFileHits  int64
		chunkedFiles int64
	)
	for _, f := range files {
		data, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) <= inlineMax {
			continue
		}
		chunkedFiles++
		wid := blake3.Sum256(data)
		_, wholeDup := wholeSeen[wid]
		wholeSeen[wid] = struct{}{}

		ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
		for {
			c, err := ck.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			id := blake3.Sum256(c.Data)
			_, hit := chunkSeen[id]
			chunkSeen[id] = struct{}{}
			if !hit {
				continue
			}
			if wholeDup {
				continue // whole-file hashing would have caught this
			}
			subFileBytes += int64(len(c.Data))
			subFileHits++
		}
		if wholeDup {
			dupFiles++
			dupFileBytes += int64(len(data))
		}
	}
	t.Logf("chunked files=%d", chunkedFiles)
	t.Logf("  byte-identical duplicate files: %d  (%s)  <- whole-file hashing catches all of this", dupFiles, mib(dupFileBytes))
	t.Logf("  genuine SUB-FILE chunk matches: %d hits (%s) <- the part only chunking can find", subFileHits, mib(subFileBytes))
	if dupFileBytes+subFileBytes > 0 {
		t.Logf("  sub-file share of all dedup: %.4f%%",
			100*float64(subFileBytes)/float64(dupFileBytes+subFileBytes))
	}
}

// ---------------------------------------------------------------------
// Test 4: incremental re-seal of an edited tree (A -> B)
// ---------------------------------------------------------------------

// TestIncrementalTree seals corpus A, then seals corpus B against A's
// chunk set, and reports the bytes each scheme has to upload for B.
// Publish's mtime-based content reuse is NOT modelled: this is the
// content-addressing question alone (what a scheme would upload if it
// re-read every file).
func TestIncrementalTree(t *testing.T) {
	a := corpusEnv(t, "PELFS_CORPUS_A")
	b := corpusEnv(t, "PELFS_CORPUS_B")
	filesA, filesB := walkCorpus(t, a), walkCorpus(t, b)

	for _, sc := range []scheme{schemeCDC, schemeFixed, schemeWholeFile} {
		st := newStore()
		for _, f := range filesA {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			st.feed(sc, data)
		}
		gen1 := st.uploaded
		gen1Inline := st.inline
		st.uploaded, st.deduped, st.inline = 0, 0, 0
		for _, f := range filesB {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			st.feed(sc, data)
		}
		t.Logf("%-16s gen1 uploaded=%s (+inline %s)   gen2 NEW chunk bytes=%s  (inline re-stored %s)",
			sc, mib(gen1), mib(gen1Inline), mib(st.uploaded), mib(st.inline))
	}
}

// ---------------------------------------------------------------------
// Test 5: synthetic single-file workloads
// ---------------------------------------------------------------------

func TestSingleFileWorkloads(t *testing.T) {
	const big = 256 << 20
	base := randomBytes(big, 1)

	realPath := os.Getenv("PELFS_BIGFILE")
	var real []byte
	if realPath != "" {
		f, err := os.Open(realPath)
		if err != nil {
			t.Fatal(err)
		}
		real = make([]byte, big)
		if _, err := io.ReadFull(f, real); err != nil {
			t.Fatalf("read %s: %v", realPath, err)
		}
		f.Close() //nolint:errcheck
	}

	type variant struct {
		name string
		v1   []byte
		v2   []byte
	}
	mk := func(prefix string, src []byte) []variant {
		if src == nil {
			return nil
		}
		return []variant{
			{prefix + "/overwrite-1B-at-midpoint", src, editInPlace(src, len(src)/2, 1)},
			{prefix + "/overwrite-64KiB-at-midpoint", src, editInPlace(src, len(src)/2, 64<<10)},
			{prefix + "/INSERT-4KiB-at-midpoint", src, insertAt(src, len(src)/2, 4<<10)},
			{prefix + "/INSERT-1B-at-start", src, insertAt(src, 0, 1)},
			{prefix + "/truncate-head-1MiB", src, src[1<<20:]},
		}
	}
	variants := mk("random", base)
	variants = append(variants, mk("realdata", real)...)
	// Append-only log: 64 MiB grown by 4 MiB.
	logV1 := randomBytes(64<<20, 7)
	variants = append(variants, variant{"log/append-4MiB-to-64MiB", logV1, append(append([]byte(nil), logV1...), randomBytes(4<<20, 8)...)})

	for _, v := range variants {
		line := fmt.Sprintf("%-38s v1=%s v2=%s |", v.name, mib(int64(len(v.v1))), mib(int64(len(v.v2))))
		for _, sc := range []scheme{schemeCDC, schemeFixed, schemeWholeFile} {
			st := newStore()
			st.feed(sc, v.v1)
			first := st.uploaded
			st.uploaded, st.deduped = 0, 0
			st.feed(sc, v.v2)
			line += fmt.Sprintf("  %s: re-upload %s (of %s, %.1f%%)",
				sc, mib(st.uploaded), mib(int64(len(v.v2))),
				100*float64(st.uploaded)/float64(len(v.v2)))
			_ = first
		}
		t.Log(line)
	}
}

// TestRenameWorkload: files moved/renamed, contents untouched.
func TestRenameWorkload(t *testing.T) {
	root := corpusEnv(t, "PELFS_CORPUS_A")
	files := walkCorpus(t, root)
	if len(files) > 20000 {
		files = files[:20000] // enough to make the point; keeps the test quick
	}
	for _, sc := range []scheme{schemeCDC, schemeFixed, schemeWholeFile} {
		st := newStore()
		for _, f := range files {
			data, err := os.ReadFile(f.path)
			if err != nil {
				t.Fatal(err)
			}
			st.feed(sc, data)
		}
		st.uploaded, st.deduped = 0, 0
		// Re-seal the same bytes under different names (rename is a
		// catalog-only change; content identity is path-independent).
		for i := len(files) - 1; i >= 0; i-- {
			data, err := os.ReadFile(files[i].path)
			if err != nil {
				t.Fatal(err)
			}
			st.feed(sc, data)
		}
		t.Logf("%-16s re-upload after pure rename/move: %s", sc, mib(st.uploaded))
	}
}

// ---------------------------------------------------------------------
// CPU cost
// ---------------------------------------------------------------------

// TestCDCThroughput measures the gear-hash cut search in isolation, on
// data large enough that the cut loop actually runs.
func TestCDCThroughput(t *testing.T) {
	data := randomBytes(256<<20, 3)
	for _, n := range []int{1} {
		_ = n
		start := time.Now()
		var chunks, bytes int64
		ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
		for {
			c, err := ck.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			chunks++
			bytes += int64(len(c.Data))
		}
		el := time.Since(start)
		t.Logf("CDC over %s: %s, %.0f MiB/s, %d chunks, mean chunk %s",
			mib(bytes), el.Round(time.Millisecond),
			float64(bytes)/(1<<20)/el.Seconds(), chunks, mib(bytes/chunks))
	}
}

func BenchmarkCDCCut(b *testing.B) {
	data := randomBytes(64<<20, 5)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
		for {
			if _, err := ck.Next(); err == io.EOF {
				break
			} else if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkEntryEncode(b *testing.B) {
	// One 4 MiB chunk of realistic (compressible) data, the other of
	// incompressible data: the two ends of the seal's zstd cost.
	real := make([]byte, 4<<20)
	if p := os.Getenv("PELFS_BIGFILE"); p != "" {
		f, err := os.Open(p)
		if err != nil {
			b.Skip(err)
		}
		if _, err := io.ReadFull(f, real); err != nil {
			b.Skip(err)
		}
		f.Close() //nolint:errcheck
	}
	rnd := randomBytes(4<<20, 21)
	for _, tc := range []struct {
		name string
		data []byte
	}{{"compressible", real}, {"incompressible", rnd}} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			for i := 0; i < b.N; i++ {
				if _, _, err := entrycodec.Encode(tc.data, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBlake3(b *testing.B) {
	data := randomBytes(64<<20, 6)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake3.Sum256(data)
	}
}

// BenchmarkSmallFileChunker measures the per-file cost of running the
// chunker over a file too small ever to be cut: the cut loop does not
// execute, so whatever this costs is pure overhead.
func BenchmarkSmallFileChunker(b *testing.B) {
	for _, sz := range []int{8 << 10, 64 << 10, 256 << 10} {
		data := randomBytes(sz, 11)
		b.Run(fmt.Sprintf("%dKiB", sz>>10), func(b *testing.B) {
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
				for {
					if _, err := ck.Next(); err == io.EOF {
						break
					} else if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// BenchmarkSmallFileWholeHash is the alternative for the same file:
// read it and hash it.
func BenchmarkSmallFileWholeHash(b *testing.B) {
	for _, sz := range []int{8 << 10, 64 << 10, 256 << 10} {
		data := randomBytes(sz, 11)
		b.Run(fmt.Sprintf("%dKiB", sz>>10), func(b *testing.B) {
			b.SetBytes(int64(sz))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				blake3.Sum256(data)
			}
		})
	}
}

// TestSealCorpus does publish's per-file transform work over a real tree,
// single-threaded, with and without the chunker, and reports where the
// time went. Repeated so the variance is visible (macOS timings are
// noisy; only differences much larger than the spread mean anything).
func TestSealCorpus(t *testing.T) {
	root := corpusEnv(t, "PELFS_CORPUS_A")
	files := walkCorpus(t, root)
	// Warm the page cache so this measures CPU, not the SSD.
	for _, f := range files {
		if _, err := os.ReadFile(f.path); err != nil {
			t.Fatal(err)
		}
	}
	const reps = 3
	for rep := 0; rep < reps; rep++ {
		for _, mode := range []string{"chunked", "whole"} {
			var readT, workT time.Duration
			var inlineN, bodyN int64
			start := time.Now()
			for _, f := range files {
				r0 := time.Now()
				data, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				readT += time.Since(r0)
				if int64(len(data)) <= inlineMax {
					inlineN++
					continue
				}
				bodyN++
				w0 := time.Now()
				if mode == "chunked" {
					sealChunked(data)
				} else {
					sealWhole(data)
				}
				workT += time.Since(w0)
			}
			t.Logf("rep%d %-8s total=%-9s read=%-9s transform=%-9s (%d inline, %d chunked)",
				rep, mode, time.Since(start).Round(time.Millisecond),
				readT.Round(time.Millisecond), workT.Round(time.Millisecond), inlineN, bodyN)
		}
	}
}

// TestChunkerOverheadIsolated measures only what the chunker adds for a
// file that can never be cut: construct + drain, versus a plain read.
func TestChunkerOverheadIsolated(t *testing.T) {
	data := randomBytes(8<<10, 13)
	const iters = 3000
	for rep := 0; rep < 5; rep++ {
		s0 := time.Now()
		for i := 0; i < iters; i++ {
			ck := chunkid.NewChunker(byteReader(data), chunkid.Options{})
			for {
				if _, err := ck.Next(); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
			}
		}
		chunked := time.Since(s0)
		s1 := time.Now()
		for i := 0; i < iters; i++ {
			if _, err := io.ReadAll(byteReader(data)); err != nil {
				t.Fatal(err)
			}
		}
		plain := time.Since(s1)
		t.Logf("rep%d 8KiB file x%d: chunker %v (%.0f us/file), plain read %v (%.1f us/file)",
			rep, iters, chunked.Round(time.Millisecond),
			float64(chunked.Microseconds())/iters, plain.Round(time.Millisecond),
			float64(plain.Microseconds())/iters)
	}
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func randomBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i += 8 {
		v := r.Uint64()
		for j := 0; j < 8 && i+j < n; j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
	return b
}

func editInPlace(src []byte, off, n int) []byte {
	out := append([]byte(nil), src...)
	r := rand.New(rand.NewSource(99))
	for i := 0; i < n; i++ {
		out[off+i] = byte(r.Intn(256))
	}
	return out
}

func insertAt(src []byte, off, n int) []byte {
	ins := randomBytes(n, 42)
	out := make([]byte, 0, len(src)+n)
	out = append(out, src[:off]...)
	out = append(out, ins...)
	out = append(out, src[off:]...)
	return out
}

func mib(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2fGiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2fMiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
