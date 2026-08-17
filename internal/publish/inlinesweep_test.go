package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// TestInlineMaxSweep answers "should small files still be inlined?" with
// numbers instead of a guess. A file at or below InlineMax is stored
// verbatim in a catalog row; above it, it is chunked into a pack. Since a
// small file costs no inode either way, the question is where the bytes
// live — and a catalog carries its inline bytes into every generation
// that rewrites it, while a packed chunk is written once and referenced
// after.
//
// For each threshold it reports, on one real source tree:
//
//   - seal cost (wall, CPU) for the initial seal, a one-file change, and a
//     whole-tree reseal that stages no new content;
//   - what the seal put on the wire, split into catalog bytes (which can
//     only move at exit, because a catalog is not identified until the
//     tree is) and data-chunk bytes (which a memtable write path could
//     have flushed during the session);
//   - catalog count and size, and how many catalogs a one-file change
//     rewrites versus carries forward;
//   - cold and warm read latency for scattered small files, and for a
//     whole-directory walk, against a modelled round trip.
//
// The corpus is a real checkout — PELFS_INLINE_TREE names its root — so
// the compressibility of the bytes is the real thing: both catalog
// entries and data chunks are zstd-encoded on the way into a pack, and a
// fixture of random bytes would misreport both sides.
//
//	PELFS_INLINE_SWEEP=1 PELFS_INLINE_TREE=/scratch/linux-6.6 \
//	  go test ./internal/publish -run InlineMaxSweep -v -timeout 240m
//
// PELFS_INLINE_MAXES overrides the sweep (comma-separated bytes; 1 stands
// in for "never inline", since InlineMax<=0 selects the default and no
// real tree holds 1-byte files). PELFS_INLINE_RTT_MS sets the modelled
// round trip, PELFS_INLINE_SAMPLES the number of scattered small files
// read, and PELFS_INLINE_WALKDIR the subtree the directory walk covers.
func TestInlineMaxSweep(t *testing.T) {
	if os.Getenv("PELFS_INLINE_SWEEP") == "" {
		t.Skip("set PELFS_INLINE_SWEEP=1 to run the InlineMax sweep")
	}
	root := os.Getenv("PELFS_INLINE_TREE")
	if root == "" {
		t.Skip("set PELFS_INLINE_TREE to a source checkout to sweep against")
	}
	corpus := scanCorpus(t, root)
	t.Logf("corpus %s: %d files, %d dirs, %s logical", root, len(corpus.files), corpus.dirs, human(corpus.bytes))
	for _, thr := range []int64{256, 1024, 4096, 16384} {
		var n, b int64
		for _, f := range corpus.files {
			if f.size <= thr {
				n++
				b += f.size
			}
		}
		t.Logf("corpus: %d files (%.1f%%) and %s (%.1f%%) at or below %d",
			n, 100*float64(n)/float64(len(corpus.files)), human(b),
			100*float64(b)/float64(corpus.bytes), thr)
	}

	rtt := time.Duration(envInt("PELFS_INLINE_RTT_MS", 20)) * time.Millisecond
	samples := sampleSmallFiles(corpus, envInt("PELFS_INLINE_SAMPLES", 60))
	walkDir := os.Getenv("PELFS_INLINE_WALKDIR")

	for _, max := range inlineSweepValues() {
		t.Run(fmt.Sprintf("inline%d", max), func(t *testing.T) {
			runInlineSweep(t, corpus, max, rtt, samples, walkDir)
		})
	}
}

func inlineSweepValues() []int64 {
	spec := os.Getenv("PELFS_INLINE_MAXES")
	if spec == "" {
		return []int64{1, 256, 512, 1024, 4096, 16384}
	}
	var out []int64
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.ParseInt(strings.TrimSpace(f), 10, 64)
		if err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------------
// corpus
// ---------------------------------------------------------------------

type corpusFile struct {
	path string // slash-separated, relative to the tree root
	size int64
}

type corpus struct {
	root  string
	files []corpusFile
	dirs  int
	bytes int64
}

// scanCorpus records the tree's shape once. Only regular files are taken:
// a symlink or a device node stores no content, so it can neither be
// inlined nor chunked and contributes nothing either side of the question.
func scanCorpus(t *testing.T, root string) *corpus {
	t.Helper()
	c := &corpus{root: root}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			c.dirs++
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		c.files = append(c.files, corpusFile{path: filepath.ToSlash(rel), size: fi.Size()})
		c.bytes += fi.Size()
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	sort.Slice(c.files, func(i, j int) bool { return c.files[i].path < c.files[j].path })
	return c
}

// sampleSmallFiles picks the files whose STORAGE DECISION the sweep
// changes — non-empty and at or below the largest threshold swept — with a
// fixed seed, so every threshold is asked for the same paths and the read
// numbers compare directly.
func sampleSmallFiles(c *corpus, n int) []corpusFile {
	var pool []corpusFile
	for _, f := range c.files {
		if f.size > 0 && f.size <= 16<<10 {
			pool = append(pool, f)
		}
	}
	rng := mrand.New(mrand.NewSource(0x1e11e))
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if n > len(pool) {
		n = len(pool)
	}
	return pool[:n]
}

// ---------------------------------------------------------------------
// one threshold
// ---------------------------------------------------------------------

type sealCost struct {
	wall, cpu            time.Duration
	putBytes, putObjects int64
	catalogBytes         int64 // pack entries a seal can only write at exit
	dataBytes            int64 // pack entries a session could have flushed earlier
	catalogs, reused     int
	pruned               int
	catalogCount         int   // catalog entries written this generation
	catalogMax           int64 // largest catalog entry, stored bytes
}

func runInlineSweep(t *testing.T, c *corpus, inlineMax int64, rtt time.Duration,
	samples []corpusFile, walkDir string) {
	ctx := context.Background()
	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	index := filepath.Join(state, "dedup.db")
	opts := func(o publish.Options) publish.Options {
		o.Inner, o.SpoolDir, o.SigningKey = inner, t.TempDir(), priv
		o.InlineMax, o.DedupIndexPath = inlineMax, index
		return o
	}

	head, err := publish.InitVolume(ctx, opts(publish.Options{
		VolumeID: [16]byte{0x1e, 0x11, 0x5e, 0xed},
	}))
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	gfs, ov := openBigLayers(t, inner, head.Superblock, state, 1)
	start := time.Now()
	stageCorpus(t, ov, c)
	t.Logf("fixture: staged %d files in %s", len(c.files), time.Since(start).Round(time.Second))

	head, initial := sweepSeal(t, "initial", inner, ov, head, opts)

	// Reopen the way a fresh mount does, so the one-file seal pays the
	// real carry-forward path rather than reading a warm overlay.
	_ = ov.Close()
	_ = gfs.Close()
	gfs, ov = openBigLayers(t, inner, head.Superblock, state, 2)
	deep := deepestDir(c)
	dirIno := lookupOverlayPath(t, ov, deep)
	n, err := ov.Create(ctx, dirIno, "sweep-touch.c", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create in %s: %v", deep, err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte("/* one changed file */\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	beforeOneFile := head.Superblock
	head, oneFile := sweepSeal(t, "one-file", inner, ov, head, opts)
	touchedWeight, touchedCatalogs := rewrittenWeight(beforeOneFile, head.Superblock)
	_, totalWeight, maxWeight := catalogShape(head.Superblock)

	// Every inode dirty, no byte of content new: whatever this costs is
	// catalog construction, which is where inline bytes are paid for.
	_ = ov.Close()
	_ = gfs.Close()
	gfs, ov = openBigLayers(t, inner, head.Superblock, state, 3)
	dirtied := chmodTree(t, ov, 1)
	head, whole := sweepSeal(t, "whole-tree", inner, ov, head, opts)
	t.Logf("whole-tree reseal dirtied %d inodes", dirtied)
	_ = ov.Close()
	_ = gfs.Close()

	for _, p := range []struct {
		name string
		c    sealCost
	}{{"initial", initial}, {"one-file", oneFile}, {"whole-tree", whole}} {
		mean := int64(0)
		if p.c.catalogCount > 0 {
			mean = p.c.catalogBytes / int64(p.c.catalogCount)
		}
		t.Logf("SEAL[%d] %-10s %8s wall %8s CPU | wire %9s = %9s catalog + %9s data in %d PUT | catalogs: %d planned, %d reused, %d rewritten (%d subtrees pruned), stored mean %s max %s",
			inlineMax, p.name, p.c.wall.Round(time.Millisecond), p.c.cpu.Round(time.Millisecond),
			human(p.c.putBytes), human(p.c.catalogBytes), human(p.c.dataBytes), p.c.putObjects,
			p.c.catalogs, p.c.reused, p.c.catalogCount, p.c.pruned,
			human(mean), human(p.c.catalogMax))
	}
	t.Logf("SPLIT[%d] namespace weight %s across %d catalogs (largest %s); one changed file rebuilt %d of them, %s of namespace (%.1f%%)",
		inlineMax, human(totalWeight), len(head.Superblock.Catalogs), human(maxWeight),
		touchedCatalogs, human(touchedWeight), 100*float64(touchedWeight)/float64(totalWeight))

	// Reads run against the final generation with a modelled round trip.
	// The store's own delay is what makes the pack cache's promotion rule
	// visible: on a loopback origin an extra GET costs nothing.
	inner.delay = rtt
	defer func() { inner.delay = 0 }()

	mountWall, mountGets, mountBytes := measureMount(t, inner, head.Superblock, state, inlineMax)
	t.Logf("MOUNT[%d] open + first lookup %s (%d GET, %s), %d packs",
		inlineMax, mountWall.Round(time.Millisecond), mountGets, human(mountBytes),
		len(head.Superblock.PackList))

	cold, neigh, warm := measureScatteredReads(t, inner, head.Superblock, state, samples, inlineMax)
	t.Logf("READ[%d] scattered small files: cold %d files %s (%d GET, %s) | neighbours %d files %s (%d GET, %s) | warm %s (%d GET, %s)",
		inlineMax,
		cold.files, cold.wall.Round(time.Millisecond), cold.gets, human(cold.getBytes),
		neigh.files, neigh.wall.Round(time.Millisecond), neigh.gets, human(neigh.getBytes),
		warm.wall.Round(time.Millisecond), warm.gets, human(warm.getBytes))

	if walkDir == "" {
		walkDir = busiestDir(c)
	}
	wcold, wwarm := measureDirWalk(t, inner, head.Superblock, state, walkDir, inlineMax)
	t.Logf("READ[%d] walk %s (%d files): cold %s (%d GET, %s) | warm %s (%d GET, %s)",
		inlineMax, walkDir, wcold.files, wcold.wall.Round(time.Millisecond), wcold.gets, human(wcold.getBytes),
		wwarm.wall.Round(time.Millisecond), wwarm.gets, human(wwarm.getBytes))
}

func sweepSeal(t *testing.T, label string, inner *meterStore, ov *overlay.FS, prev *publish.Result,
	opts func(publish.Options) publish.Options) (*publish.Result, sealCost) {
	t.Helper()
	ctx := context.Background()
	mark := inner.snapshot()
	cpu0 := processCPU()
	start := time.Now()
	res, err := publish.Seal(ctx, opts(publish.Options{
		Overlay: ov, Prev: prev.Superblock, PrevRaw: prev.Raw,
	}))
	if err != nil {
		t.Fatalf("%s seal: %v", label, err)
	}
	c := sealCost{
		wall: time.Since(start), cpu: processCPU() - cpu0,
		putBytes: inner.putB.Load() - mark.putB, putObjects: inner.puts.Load() - mark.puts,
		catalogs: res.Stats.Catalogs, reused: res.Stats.CatalogsReused, pruned: res.Stats.SubtreesPruned,
	}
	// Split the wire bytes by entry kind. The trailers are fetched after
	// the meter has been read, so this accounting does not charge itself
	// to the seal it is describing.
	for _, sp := range res.NewPacks {
		entries, err := packstore.FetchTrailerVerified(ctx, inner, sp.Name, sp.Size, sp.TrailerHash)
		if err != nil {
			t.Fatalf("trailer %s: %v", sp.Name, err)
		}
		for _, e := range entries {
			switch e.Type {
			case packstore.EntryCatalog, packstore.EntryShard:
				c.catalogBytes += e.Length
				c.catalogCount++
				if e.Length > c.catalogMax {
					c.catalogMax = e.Length
				}
			default:
				c.dataBytes += e.Length
			}
		}
	}
	return res, c
}

// catalogShape reports how finely a generation divides its namespace, read
// off the superblock — which carries exactly this so the next publish can
// decide what not to walk.
func catalogShape(sb *superblock.Superblock) (n int, total, max int64) {
	for _, c := range sb.Catalogs {
		n++
		total += c.Weight
		if c.Weight > max {
			max = c.Weight
		}
	}
	return n, total, max
}

// rewrittenWeight is how much NAMESPACE a seal had to rebuild: the summed
// split weight of the catalogs whose identity changed.
//
// It is the number carry-forward is really about. The byte cost of
// rewriting one catalog is capped by SMax at every threshold, because
// inline bytes count toward the same weight the split bounds — so what
// InlineMax moves is how MANY catalogs a tree has, and therefore how much
// unrelated namespace one changed file drags along with it.
func rewrittenWeight(prev, cur *superblock.Superblock) (weight int64, n int) {
	was := make(map[[32]byte]bool, len(prev.Catalogs))
	for _, c := range prev.Catalogs {
		was[c.Identity] = true
	}
	for _, c := range cur.Catalogs {
		if !was[c.Identity] {
			weight += c.Weight
			n++
		}
	}
	return weight, n
}

// measureMount is what a fresh mount pays before it can answer anything.
// genfs.Open builds the identity index from every pack trailer in the
// generation, so every small file moved out of a catalog and into a pack
// adds one trailer entry, and this is where that shows up.
func measureMount(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state string, inlineMax int64) (wall time.Duration, gets, bytes int64) {
	t.Helper()
	ctx := context.Background()
	mark := inner.snapshot()
	start := time.Now()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb,
		CacheDir: filepath.Join(state, fmt.Sprintf("mountcache-%d", inlineMax)),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	if _, err := fs.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	wall = time.Since(start)
	_ = fs.Close()
	return wall, inner.gets.Load() - mark.gets, inner.getB.Load() - mark.getB
}

// ---------------------------------------------------------------------
// fixture staging
// ---------------------------------------------------------------------

func stageCorpus(t *testing.T, ov *overlay.FS, c *corpus) {
	t.Helper()
	ctx := context.Background()
	dirs := map[string]uint64{"": 1}
	var mkdirp func(p string) uint64
	mkdirp = func(p string) uint64 {
		if ino, ok := dirs[p]; ok {
			return ino
		}
		parent, name := splitLast(p)
		n, err := ov.Mkdir(ctx, mkdirp(parent), name, 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		dirs[p] = n.Inode
		return n.Inode
	}

	buf := make([]byte, 1<<20)
	for _, f := range c.files {
		parent, name := splitLast(f.path)
		n, err := ov.Create(ctx, mkdirp(parent), name, 0644, 0, 0)
		if err != nil {
			t.Fatalf("create %s: %v", f.path, err)
		}
		if f.size == 0 {
			continue
		}
		src, err := os.Open(filepath.Join(c.root, filepath.FromSlash(f.path)))
		if err != nil {
			t.Fatalf("open %s: %v", f.path, err)
		}
		var off int64
		for {
			got, rerr := src.Read(buf)
			if got > 0 {
				if _, err := ov.Write(ctx, n.Inode, off, buf[:got]); err != nil {
					t.Fatalf("write %s: %v", f.path, err)
				}
				off += int64(got)
			}
			if rerr != nil {
				break
			}
		}
		_ = src.Close()
	}
}

func splitLast(p string) (dir, name string) {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// deepestDir is where the one-file change lands: the deepest directory in
// the tree, so the seal pays a full chain of parent catalogs and not just
// the root's.
func deepestDir(c *corpus) string {
	best, depth := "", -1
	for _, f := range c.files {
		dir, _ := splitLast(f.path)
		if dir == "" {
			continue
		}
		if d := strings.Count(dir, "/"); d > depth {
			best, depth = dir, d
		}
	}
	return best
}

// busiestDir picks the subtree the grep -r-shaped walk covers: the one
// whose file count comes closest to walkTargetFiles. A single leaf
// directory is too small to say anything about pack locality and the
// whole tree is not a workload anyone runs interactively; a subsystem's
// worth of source is what `grep -r` is actually pointed at.
func busiestDir(c *corpus) string {
	const walkTargetFiles = 2000
	count := map[string]int{}
	for _, f := range c.files {
		dir, _ := splitLast(f.path)
		for {
			count[dir]++
			if dir == "" {
				break
			}
			dir, _ = splitLast(dir)
		}
	}
	best, diff := "", -1
	for d, k := range count {
		if d == "" {
			continue
		}
		if delta := abs(k - walkTargetFiles); diff < 0 || delta < diff || (delta == diff && d < best) {
			best, diff = d, delta
		}
	}
	return best
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func lookupOverlayPath(t *testing.T, ov *overlay.FS, p string) uint64 {
	t.Helper()
	ctx := context.Background()
	ino := uint64(1)
	for _, name := range strings.Split(p, "/") {
		n, err := ov.Lookup(ctx, ino, name)
		if err != nil {
			t.Fatalf("lookup %s (%s): %v", p, name, err)
		}
		ino = n.Inode
	}
	return ino
}

// ---------------------------------------------------------------------
// read measurements
// ---------------------------------------------------------------------

type readCost struct {
	wall     time.Duration
	gets     int64
	getBytes int64
	files    int
	bytes    int64
}

// measureScatteredReads is the interactive case: files picked at random
// across the whole tree, so consecutive reads rarely share a pack and the
// pack cache's promotion rule mostly refuses.
//
// Three passes, all on one mount over a fresh cache directory. COLD is
// the sample against empty caches. NEIGHBOURS then reads a DIFFERENT
// small file from each sampled file's directory — that is the pack
// cache's actual claim under test, since publish lays a directory's files
// down together, so a promoted pack should make the neighbour free while
// an inline neighbour was never going to cost anything. WARM repeats the
// cold sample, which by then is answered entirely from cache.
func measureScatteredReads(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state string, samples []corpusFile, inlineMax int64) (cold, neighbours, warm readCost) {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb,
		CacheDir: filepath.Join(state, fmt.Sprintf("readcache-%d", inlineMax)),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	defer fs.Close() //nolint:errcheck

	run := func(set []corpusFile) readCost {
		mark := inner.snapshot()
		start := time.Now()
		var rc readCost
		for _, f := range set {
			n, err := fs.LookupPath(ctx, f.path)
			if err != nil {
				t.Fatalf("lookup %s: %v", f.path, err)
			}
			readWhole(t, fs, n.Inode, n.Length)
			rc.files++
			rc.bytes += n.Length
		}
		rc.wall = time.Since(start)
		rc.gets = inner.gets.Load() - mark.gets
		rc.getBytes = inner.getB.Load() - mark.getB
		return rc
	}
	cold = run(samples)
	// Neighbours are named after the cold pass so the namespace lookups
	// that find them are not charged to it; they read catalogs the cold
	// pass already fetched and no pack bytes at all.
	neighbours = run(neighboursOf(t, fs, samples))
	warm = run(samples)
	return cold, neighbours, warm
}

// neighboursOf names one other small file in each sampled file's
// directory, read out of the sealed namespace rather than the corpus so
// the walk itself is what a reader would do.
func neighboursOf(t *testing.T, fs *genfs.FS, samples []corpusFile) []corpusFile {
	t.Helper()
	ctx := context.Background()
	var out []corpusFile
	seen := map[string]bool{}
	for _, f := range samples {
		dir, base := splitLast(f.path)
		if dir == "" {
			continue
		}
		d, err := fs.LookupPath(ctx, dir)
		if err != nil {
			t.Fatalf("lookup %s: %v", dir, err)
		}
		ents, err := fs.Readdir(ctx, d.Inode)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		for _, e := range ents {
			if e.Name == base {
				continue
			}
			p := dir + "/" + e.Name
			if seen[p] {
				continue
			}
			n, err := fs.Lookup(ctx, d.Inode, e.Name)
			if err != nil || n.Type == 2 || n.Length == 0 || n.Length > 16<<10 {
				continue
			}
			seen[p] = true
			out = append(out, corpusFile{path: p, size: n.Length})
			break
		}
	}
	return out
}

// measureDirWalk is the batch case: everything under one directory, read
// in namespace order, which is also the order publish laid the bytes down
// in. This is where whole-pack promotion should converge on one transfer
// and where inline should need none at all.
func measureDirWalk(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state string, dir string, inlineMax int64) (cold, warm readCost) {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb,
		CacheDir: filepath.Join(state, fmt.Sprintf("walkcache-%d", inlineMax)),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	defer fs.Close() //nolint:errcheck

	top, err := fs.LookupPath(ctx, dir)
	if err != nil {
		t.Fatalf("lookup %s: %v", dir, err)
	}
	run := func() readCost {
		mark := inner.snapshot()
		start := time.Now()
		var rc readCost
		var walk func(ino uint64)
		walk = func(ino uint64) {
			ents, err := fs.Readdir(ctx, ino)
			if err != nil {
				t.Fatalf("readdir: %v", err)
			}
			for _, e := range ents {
				n, err := fs.Lookup(ctx, ino, e.Name)
				if err != nil {
					t.Fatalf("lookup %s: %v", e.Name, err)
				}
				switch {
				case n.Type == 2:
					walk(n.Inode)
				case n.Length > 0:
					readWhole(t, fs, n.Inode, n.Length)
					rc.files++
					rc.bytes += n.Length
				default:
					rc.files++
				}
			}
		}
		walk(top.Inode)
		rc.wall = time.Since(start)
		rc.gets = inner.gets.Load() - mark.gets
		rc.getBytes = inner.getB.Load() - mark.getB
		return rc
	}
	return run(), run()
}
