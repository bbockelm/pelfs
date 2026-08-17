package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Pack size is the unit of transfer, and these two tests measure the two
// sides of the trade it makes.
//
// A pack is the only thing a reader can cache as a whole object, so the
// SMALLER it is, the less a reader pulls to serve one file. But every pack
// costs a row in the pack list of every superblock from now on — publish
// carries the previous generation's list forward unconditionally — plus one
// federation object and one trailer. So the question is not "which is
// faster" but where the reader's transfer saving stops paying for the
// generation-side bookkeeping.
//
// TestMountCostByPackCount isolates the bookkeeping side: identical content
// cut into 10, 100, and 1000 packs, measuring only what a mount pays before
// it can answer its first question.
//
// TestPackSizeSweep is the reader side against a real corpus.

// ---------------------------------------------------------------------
// mount cost as a function of pack count
// ---------------------------------------------------------------------

// TestMountCostByPackCount reports what a cold mount costs at several pack
// counts: wall time, federation GETs, and bytes moved before the mount can
// answer a readdir, and then before it can answer a read.
//
// The content is the same at every point — one file per pack, so the pack
// count is set by how many files are staged rather than by a cut size that
// would also change what shares a pack. Random bodies, because a pack that
// compresses away is not a pack.
//
//	PELFS_PACKCOUNT_SWEEP=1 go test ./internal/publish -run MountCostByPackCount -v -timeout 60m
//
// PELFS_PACKCOUNT_N overrides the pack counts, PELFS_PACKCOUNT_RTT_MS the
// modelled round trip.
func TestMountCostByPackCount(t *testing.T) {
	if os.Getenv("PELFS_PACKCOUNT_SWEEP") == "" {
		t.Skip("set PELFS_PACKCOUNT_SWEEP=1 to run the pack-count mount sweep")
	}
	rtt := time.Duration(envInt("PELFS_PACKCOUNT_RTT_MS", 20)) * time.Millisecond
	counts := envIntList("PELFS_PACKCOUNT_N", []int{10, 100, 1000})
	for _, n := range counts {
		t.Run(fmt.Sprintf("packs%d", n), func(t *testing.T) {
			measureMountAtPackCount(t, n, rtt)
		})
	}
}

// packSweepBodySize is one staged file, and therefore one pack. It has to
// exceed the trailer tail probe (128 KiB), or every "read the trailer"
// request would incidentally carry the whole object and the byte counts
// below would stop distinguishing a location probe from a transfer.
const packSweepBodySize = 512 << 10

func measureMountAtPackCount(t *testing.T, packs int, rtt time.Duration) {
	ctx := context.Background()
	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	opts := func(o publish.Options) publish.Options {
		o.Inner, o.SpoolDir, o.SigningKey = inner, t.TempDir(), priv
		// One entry per pack: cut below the body size so every append but
		// the first overflows the pack it would land in.
		o.TargetPackSize, o.FirstPackSize = packSweepBodySize/2, packSweepBodySize/2
		return o
	}
	head, err := publish.InitVolume(ctx, opts(publish.Options{
		VolumeID: [16]byte{0x9a, 0xc0, 0xde, byte(packs)},
	}))
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	gfs, ov := openBigLayers(t, inner, head.Superblock, state, 1)
	// A flat directory would put every dirent in one catalog; a fan-out
	// keeps the namespace shaped like a real tree, which is what decides
	// how many catalogs the descent has to fetch.
	const perDir = 64
	names := make([]string, 0, packs)
	for i := 0; i < packs; i++ {
		dirName := fmt.Sprintf("d%03d", i/perDir)
		dirIno := uint64(1)
		if n, err := ov.Lookup(ctx, 1, dirName); err == nil {
			dirIno = n.Inode
		} else {
			n, err := ov.Mkdir(ctx, 1, dirName, 0755, 0, 0)
			if err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			dirIno = n.Inode
		}
		name := fmt.Sprintf("f%04d.bin", i)
		n, err := ov.Create(ctx, dirIno, name, 0644, 0, 0)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, pseudorandom(packSweepBodySize, int64(i)+1)); err != nil {
			t.Fatalf("write: %v", err)
		}
		names = append(names, dirName+"/"+name)
	}
	res, err := publish.Seal(ctx, opts(publish.Options{
		Overlay: ov, Prev: head.Superblock, PrevRaw: head.Raw,
	}))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_ = ov.Close()
	_ = gfs.Close()
	sb := res.Superblock
	t.Logf("generation: %d packs, superblock %s (pack list %s)",
		len(sb.PackList), human(int64(len(res.Raw))), human(packListBytes(t, sb)))

	inner.delay = rtt
	defer func() { inner.delay = 0 }()

	// Cold: nothing local at all.
	cache := filepath.Join(state, "coldcache")
	mark := inner.snapshot()
	start := time.Now()
	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: sb, CacheDir: cache})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	if _, err := fs.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir: %v", err)
	}
	serveWall := time.Since(start)
	serveGets, serveBytes := inner.gets.Load()-mark.gets, inner.getB.Load()-mark.getB

	// The first read of content in a pack the mount has not touched.
	mark = inner.snapshot()
	start = time.Now()
	last := names[len(names)-1]
	n, err := fs.LookupPath(ctx, last)
	if err != nil {
		t.Fatalf("lookup %s: %v", last, err)
	}
	readWhole(t, fs, n.Inode, n.Length)
	readWall := time.Since(start)
	readGets, readBytes := inner.gets.Load()-mark.gets, inner.getB.Load()-mark.getB
	_ = fs.Close()

	// Warm: same cache directory, second mount. Whatever this still costs
	// is what the format forces onto every mount forever.
	mark = inner.snapshot()
	start = time.Now()
	fs2, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: sb, CacheDir: cache})
	if err != nil {
		t.Fatalf("genfs.Open (warm): %v", err)
	}
	if _, err := fs2.Readdir(ctx, 1); err != nil {
		t.Fatalf("root readdir (warm): %v", err)
	}
	warmWall := time.Since(start)
	warmGets, warmBytes := inner.gets.Load()-mark.gets, inner.getB.Load()-mark.getB
	_ = fs2.Close()

	t.Logf("MOUNT[%d packs] cold serve %s (%d GET, %s) | first read %s (%d GET, %s) | warm serve %s (%d GET, %s)",
		len(sb.PackList),
		serveWall.Round(time.Millisecond), serveGets, human(serveBytes),
		readWall.Round(time.Millisecond), readGets, human(readBytes),
		warmWall.Round(time.Millisecond), warmGets, human(warmBytes))
}

// packListBytes is what the pack list costs inside the signed superblock:
// the difference between encoding the generation with and without it.
func packListBytes(t *testing.T, sb *superblock.Superblock) int64 {
	t.Helper()
	with, err := sb.Encode()
	if err != nil {
		t.Fatalf("encode superblock: %v", err)
	}
	stripped := *sb
	stripped.PackList = nil
	without, err := stripped.Encode()
	if err != nil {
		t.Fatalf("encode superblock: %v", err)
	}
	return int64(len(with) - len(without))
}

// ---------------------------------------------------------------------
// pack size against a real corpus
// ---------------------------------------------------------------------

// TestPackSizeSweep answers "how big should a pack be?" against a real
// checkout. For each target size it reports what the generation costs to
// carry (pack count, pack-list bytes, trailer bytes, objects) and what a
// reader pays (mount, scattered reads, a directory walk).
//
//	PELFS_PACK_SWEEP=1 PELFS_PACK_TREE=/scratch/linux-6.6 \
//	  go test ./internal/publish -run PackSizeSweep -v -timeout 480m
//
// PELFS_PACK_SIZES overrides the sweep (comma-separated MiB),
// PELFS_PACK_RTT_MS the modelled round trip, PELFS_PACK_SAMPLES the number
// of scattered small files read, PELFS_PACK_WALKDIR the walked subtree,
// PELFS_PACK_INLINE the inline threshold (default: the shipped one).
func TestPackSizeSweep(t *testing.T) {
	if os.Getenv("PELFS_PACK_SWEEP") == "" {
		t.Skip("set PELFS_PACK_SWEEP=1 to run the pack size sweep")
	}
	root := os.Getenv("PELFS_PACK_TREE")
	if root == "" {
		t.Skip("set PELFS_PACK_TREE to a source checkout to sweep against")
	}
	c := scanCorpus(t, root)
	t.Logf("corpus %s: %d files, %d dirs, %s logical", root, len(c.files), c.dirs, human(c.bytes))

	rtt := time.Duration(envInt("PELFS_PACK_RTT_MS", 20)) * time.Millisecond
	samples := sampleSmallFiles(c, envInt("PELFS_PACK_SAMPLES", 100))
	walkDir := os.Getenv("PELFS_PACK_WALKDIR")
	if walkDir == "" {
		walkDir = busiestDir(c)
	}
	inlineMax := int64(envInt("PELFS_PACK_INLINE", publish.DefaultInlineMax))
	t.Logf("sweep: inline %d, %d scattered samples, walk %s, modelled RTT %s",
		inlineMax, len(samples), walkDir, rtt)

	for _, mib := range envIntList("PELFS_PACK_SIZES", []int{1, 2, 4, 8, 16, 32, 64}) {
		t.Run(fmt.Sprintf("pack%dMiB", mib), func(t *testing.T) {
			runPackSizeSweep(t, c, int64(mib)<<20, inlineMax, rtt, samples, walkDir)
		})
	}
}

func runPackSizeSweep(t *testing.T, c *corpus, target, inlineMax int64,
	rtt time.Duration, samples []corpusFile, walkDir string) {
	ctx := context.Background()
	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	opts := func(o publish.Options) publish.Options {
		o.Inner, o.SpoolDir, o.SigningKey = inner, t.TempDir(), priv
		o.InlineMax = inlineMax
		// The first-pack ramp exists to start the uplink early; here it
		// would mean the generation is not actually cut at one size, which
		// is the variable under test.
		o.TargetPackSize, o.FirstPackSize = target, target
		return o
	}
	head, err := publish.InitVolume(ctx, opts(publish.Options{
		VolumeID: [16]byte{0xac, 0x00, byte(target >> 20), byte(inlineMax)},
	}))
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	gfs, ov := openBigLayers(t, inner, head.Superblock, state, 1)
	start := time.Now()
	stageCorpus(t, ov, c)
	t.Logf("fixture: staged %d files in %s", len(c.files), time.Since(start).Round(time.Second))

	mark := inner.snapshot()
	cpu0 := processCPU()
	start = time.Now()
	res, err := publish.Seal(ctx, opts(publish.Options{
		Overlay: ov, Prev: head.Superblock, PrevRaw: head.Raw,
	}))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealWall, sealCPU := time.Since(start), processCPU()-cpu0
	putBytes, putObjects := inner.putB.Load()-mark.putB, inner.puts.Load()-mark.puts
	_ = ov.Close()
	_ = gfs.Close()
	sb := res.Superblock

	var packBytes int64
	for _, pe := range sb.PackList {
		packBytes += pe.Size
	}
	// What the containers cost beyond the entries they hold: trailer plus
	// footer, which is the per-pack overhead a smaller cut size multiplies.
	trailerBytes := packBytes - entryBytes(ctx, t, inner, sb)

	t.Logf("GEN[%s] %d packs, %s stored (%s trailer overhead, %.2f%%), superblock %s of which pack list %s | seal %s wall %s CPU, %d PUT (%s)",
		human(target), len(sb.PackList), human(packBytes), human(trailerBytes),
		100*float64(trailerBytes)/float64(packBytes),
		human(int64(len(res.Raw))), human(packListBytes(t, sb)),
		sealWall.Round(time.Millisecond), sealCPU.Round(time.Millisecond),
		putObjects, human(putBytes))

	inner.delay = rtt
	defer func() { inner.delay = 0 }()

	label := fmt.Sprintf("%d", target>>20)
	mountWall, mountGets, mountBytes := measurePackMount(t, inner, sb, state, label)
	t.Logf("MOUNT[%s] open + first lookup %s (%d GET, %s)",
		human(target), mountWall.Round(time.Millisecond), mountGets, human(mountBytes))

	first := measureFirstRead(t, inner, sb, state, label, samples)
	t.Logf("FIRSTREAD[%s] one file in a pack nothing has touched: %s (%d GET, %s)",
		human(target), first.wall.Round(time.Millisecond), first.gets, human(first.getBytes))

	cold, warm := measurePackScattered(t, inner, sb, state, label, samples)
	t.Logf("READ[%s] scattered %d files (%s wanted): cold %s (%d GET, %s) | warm %s (%d GET, %s)",
		human(target), cold.files, human(cold.bytes),
		cold.wall.Round(time.Millisecond), cold.gets, human(cold.getBytes),
		warm.wall.Round(time.Millisecond), warm.gets, human(warm.getBytes))

	wcold, wwarm := measureDirWalk(t, inner, sb, state, walkDir, target>>20)
	t.Logf("WALK[%s] %s (%d files, %s): cold %s (%d GET, %s) | warm %s (%d GET, %s)",
		human(target), walkDir, wcold.files, human(wcold.bytes),
		wcold.wall.Round(time.Millisecond), wcold.gets, human(wcold.getBytes),
		wwarm.wall.Round(time.Millisecond), wwarm.gets, human(wwarm.getBytes))
}

// entryBytes sums every pack entry the generation lists, so the difference
// against the objects' total size is the container overhead pack size
// controls.
func entryBytes(ctx context.Context, t *testing.T, inner *meterStore, sb *superblock.Superblock) int64 {
	t.Helper()
	var n int64
	for _, pe := range sb.PackList {
		entries, err := packstore.FetchTrailerVerified(ctx, inner, pe.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			t.Fatalf("trailer %s: %v", pe.Name, err)
		}
		for _, e := range entries {
			n += e.Length
		}
	}
	return n
}

func measurePackMount(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state, label string) (wall time.Duration, gets, bytes int64) {
	t.Helper()
	ctx := context.Background()
	mark := inner.snapshot()
	start := time.Now()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb, CacheDir: filepath.Join(state, "mount-"+label),
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

// measureFirstRead is the latency a user sees for the first byte of a file
// whose pack nothing has pulled yet — the cost the whole-pack policy pays
// up front and the one smaller packs are meant to bring down.
func measureFirstRead(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state, label string, samples []corpusFile) readCost {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb, CacheDir: filepath.Join(state, "first-"+label),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	defer fs.Close() //nolint:errcheck
	// A chunked file, so the read actually reaches a pack: an inlined one
	// is answered by the catalog the lookup already fetched.
	var pick corpusFile
	for _, f := range samples {
		if f.size > publish.DefaultInlineMax {
			pick = f
			break
		}
	}
	if pick.path == "" {
		pick = samples[len(samples)-1]
	}
	n, err := fs.LookupPath(ctx, pick.path)
	if err != nil {
		t.Fatalf("lookup %s: %v", pick.path, err)
	}
	mark := inner.snapshot()
	start := time.Now()
	buf := make([]byte, 4096)
	if _, err := fs.Read(ctx, n.Inode, 0, buf); err != nil {
		t.Fatalf("read %s: %v", pick.path, err)
	}
	return readCost{
		wall: time.Since(start), files: 1, bytes: n.Length,
		gets: inner.gets.Load() - mark.gets, getBytes: inner.getB.Load() - mark.getB,
	}
}

// measurePackScattered is the interactive case: files picked at random
// across the whole tree, so consecutive reads rarely share a pack. This is
// where a whole-pack policy is at its worst and where pack size decides how
// bad that is.
func measurePackScattered(t *testing.T, inner *meterStore, sb *superblock.Superblock,
	state, label string, samples []corpusFile) (cold, warm readCost) {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb, CacheDir: filepath.Join(state, "scatter-"+label),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	defer fs.Close() //nolint:errcheck
	run := func() readCost {
		mark := inner.snapshot()
		start := time.Now()
		var rc readCost
		for _, f := range samples {
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
	return run(), run()
}

func envIntList(name string, def []int) []int {
	spec := os.Getenv(name)
	if spec == "" {
		return def
	}
	var out []int
	for _, f := range strings.Split(spec, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
