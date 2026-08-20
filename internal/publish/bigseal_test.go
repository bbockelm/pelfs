package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// TestBigTreeSealCost is the gate for "a one-file change must not cost
// whole-tree work". It builds a tree shaped like a source checkout (tens
// of thousands of inodes, most files small enough to live inline in a
// catalog, which is what drives catalog COUNT), seals it, reopens over
// the sealed generation the way a fresh mount does, touches exactly one
// file, and seals again — reporting wall time, CPU, bytes moved, and
// catalogs written for each phase.
//
// It reports those numbers AND holds them to a bound. For a long time it
// only reported: it stated the claim in this comment and then t.Logf'd,
// so a regression that made every seal rewrite the whole namespace would
// have printed larger numbers and passed. Phase 5 exists to make the
// bound checkable — it dirties every inode without staging a byte, so
// what it costs IS whole-tree catalog construction, and the one-file
// phases are measured against it. See sealCostBounds below for the
// numbers and the headroom.
//
// It is skipped unless PELFS_BIGSEAL is set: the fixture alone is minutes
// of work, which does not belong in the ordinary test run.
//
//	PELFS_BIGSEAL=1 PELFS_BIGSEAL_FILES=80000 go test ./internal/publish -run BigTreeSealCost -v -timeout 60m
//	PELFS_BIGSEAL_CPUPROFILE=/tmp/seal.prof   # profile the one-file seal
func TestBigTreeSealCost(t *testing.T) {
	if os.Getenv("PELFS_BIGSEAL") == "" {
		t.Skip("set PELFS_BIGSEAL=1 to run the big-tree seal measurement")
	}
	ctx := context.Background()
	files := envInt("PELFS_BIGSEAL_FILES", 20000)
	perDir := envInt("PELFS_BIGSEAL_PERDIR", 16)

	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	index := filepath.Join(state, "dedup.db")

	head, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0xb1, 0x67, 0x5e, 0xa1}, DedupIndexPath: index,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	gfs, ov := openBigLayers(t, inner, head.Superblock, state, 1)

	start := time.Now()
	dirs := buildBigTree(t, ov, files, perDir)
	t.Logf("fixture: %d files in %d directories, built in %s",
		files, len(dirs), time.Since(start).Round(time.Millisecond))

	// What each phase cost, so the bound below compares measurements
	// rather than restating the claim.
	cost := map[string]publish.Stats{}
	head = timedSeal(t, "initial seal", inner, ov, head, priv, index, "")
	cost["initial"] = head.Stats

	for phase := 2; phase <= 5; phase++ {
		_ = ov.Close()
		_ = gfs.Close()
		// Reopen exactly as a fresh mount does: a new genfs over the
		// sealed generation, a fresh overlay directory on top of it.
		mountStart := time.Now()
		gm := inner.snapshot()
		gfs, ov = openBigLayers(t, inner, head.Superblock, state, phase)
		t.Logf("MOUNT %d: genfs.Open + overlay.Open %s, %s",
			phase, time.Since(mountStart).Round(time.Millisecond), inner.since(gm))
		// One lookup, so mount-to-serving is measured and not just Open.
		lStart := time.Now()
		if _, err := ov.Lookup(ctx, 1, "top000"); err != nil {
			t.Fatalf("first lookup: %v", err)
		}
		t.Logf("MOUNT %d: first lookup %s", phase, time.Since(lStart).Round(time.Millisecond))

		switch phase {
		case 2:
			head = timedSeal(t, "unchanged seal", inner, ov, head, priv, index, "")
			cost["unchanged"] = head.Stats
		case 3:
			if _, err := ov.Create(ctx, 1, "no.txt", 0644, 0, 0); err != nil {
				t.Fatalf("create no.txt: %v", err)
			}
			head = timedSeal(t, "one-file seal (root)", inner, ov, head, priv, index,
				os.Getenv("PELFS_BIGSEAL_CPUPROFILE"))
			cost["onefile-root"] = head.Stats
		case 4:
			// A change deep in the tree, which is the ordinary case: one
			// leaf directory's catalog plus the chain to the root.
			deep, err := ov.Lookup(ctx, 1, "top000")
			if err != nil {
				t.Fatalf("lookup top000: %v", err)
			}
			sub, err := ov.Lookup(ctx, deep.Inode, "sub000")
			if err != nil {
				t.Fatalf("lookup sub000: %v", err)
			}
			n, err := ov.Create(ctx, sub.Inode, "deep.txt", 0644, 0, 0)
			if err != nil {
				t.Fatalf("create deep.txt: %v", err)
			}
			if _, err := ov.Write(ctx, n.Inode, 0, []byte("hello")); err != nil {
				t.Fatalf("write deep.txt: %v", err)
			}
			head = timedSeal(t, "one-file seal (deep)", inner, ov, head, priv, index, "")
			cost["onefile-deep"] = head.Stats
		case 5:
			// The untar shape: every inode dirty, no byte of content new.
			// Whatever this seal costs is catalog construction and nothing
			// else, which is the only way to read the cost honestly — an
			// initial seal mixes in chunking, and a one-file seal measures
			// the reuse path instead.
			start := time.Now()
			n := chmodTree(t, ov, 1)
			t.Logf("dirtied %d inodes in %s", n, time.Since(start).Round(time.Millisecond))
			head = timedSeal(t, "whole-tree seal (no new content)", inner, ov, head, priv, index,
				os.Getenv("PELFS_BIGSEAL_WHOLETREE_CPUPROFILE"))
			cost["wholetree"] = head.Stats
		}
	}
	_ = ov.Close()
	_ = gfs.Close()

	sealCostBounds(t, cost)

	// The generation every phase built on must still read back whole.
	verifyBigTree(t, inner, head.Superblock, dirs)
}

// sealCostBounds holds the phases to the claim the test is named for.
//
// Measured 2026-08-19 at the default 20,000 files / 16 per directory
// (1,250 leaf directories, 12 catalogs in the sealed namespace):
//
//	phase             catalogs written  reused  dirs walked  subtrees pruned
//	initial                         12       0         1286                0
//	unchanged                        0      12          890               11
//	one-file (root)                  1      11          890               11
//	one-file (deep)                  2      10          926               10
//	whole-tree                      12       0         1286                0
//
// The bounds below sit at roughly 2x the measured values, which is loose
// enough to survive a catalog-splitting tweak and tight enough that
// losing reuse entirely — the regression worth catching, where a one-file
// seal rewrites all 12 — fails every one of them.
func sealCostBounds(t *testing.T, cost map[string]publish.Stats) {
	t.Helper()
	whole, ok := cost["wholetree"]
	if !ok {
		t.Fatal("no whole-tree seal was recorded; there is nothing to bound against")
	}

	// The comparison is only meaningful if the fixture actually splits
	// into several catalogs. Below about 8,000 files the whole namespace
	// is ONE catalog, every phase writes it, and every ratio below is
	// trivially 1 — a bound that cannot fail. Say so instead of passing:
	// a gate that silently stops discriminating is the failure mode this
	// assertion was added to end.
	if whole.Catalogs < 4 {
		t.Fatalf("fixture too small to bound anything: the whole-tree seal wrote %d catalogs, "+
			"so a one-file seal cannot write measurably fewer. Raise PELFS_BIGSEAL_FILES "+
			"(20000 splits into 12).", whole.Catalogs)
	}
	// And the whole-tree phase must really have done whole-tree work,
	// or it is the wrong yardstick.
	if whole.CatalogsReused != 0 || whole.SubtreesPruned != 0 {
		t.Fatalf("the whole-tree seal reused %d catalogs and pruned %d subtrees; "+
			"it did not do whole-tree work, so it cannot serve as the bound",
			whole.CatalogsReused, whole.SubtreesPruned)
	}

	// A seal over an unchanged tree must write no catalog at all. This is
	// the strongest of the three and needs no ratio.
	if unch, ok := cost["unchanged"]; ok {
		if unch.Catalogs != 0 {
			t.Errorf("a seal over an UNCHANGED tree wrote %d catalogs; it must reuse all %d",
				unch.Catalogs, whole.Catalogs)
		}
		if unch.CatalogsReused != whole.Catalogs {
			t.Errorf("a seal over an unchanged tree reused %d of %d catalogs",
				unch.CatalogsReused, whole.Catalogs)
		}
	}

	// The claim itself: one changed file costs a chain to the root, not
	// the namespace. Measured 1 and 2 catalogs of 12; the bound is a
	// third, and it does not scale with tree size — the fan-out is two
	// levels deep however many files hang off it, while the whole-tree
	// number grows.
	limit := whole.Catalogs / 3
	if limit < 1 {
		limit = 1
	}
	for _, phase := range []string{"onefile-root", "onefile-deep"} {
		one, ok := cost[phase]
		if !ok {
			t.Fatalf("no %q seal was recorded", phase)
		}
		if one.Catalogs > limit {
			t.Errorf("%s: wrote %d catalogs, want <= %d — a one-file change is costing "+
				"whole-tree work (the whole-tree seal writes %d)",
				phase, one.Catalogs, limit, whole.Catalogs)
		}
		// Reuse is the other half of the same fact, and it fails
		// differently: a seal could write few catalogs because it
		// DROPPED the rest rather than carrying them forward.
		if want := whole.Catalogs - limit; one.CatalogsReused < want {
			t.Errorf("%s: reused %d catalogs, want >= %d of %d",
				phase, one.CatalogsReused, want, whole.Catalogs)
		}
		// And the walk must stop at the subtrees it is carrying forward,
		// which is the difference between "did not rewrite the tree" and
		// "did not look at the tree".
		if one.SubtreesPruned == 0 {
			t.Errorf("%s: pruned no subtrees, so the seal read the whole namespace "+
				"even though it rewrote almost none of it", phase)
		}
	}
	t.Logf("seal cost bound: one-file writes %d/%d and %d/%d catalogs against a whole-tree %d",
		cost["onefile-root"].Catalogs, whole.Catalogs,
		cost["onefile-deep"].Catalogs, whole.Catalogs, whole.Catalogs)
}

// chmodTree touches the mode of every inode below root, which dirties the
// whole tree without staging a single byte — the state an untar leaves
// behind once its content has already been checkpointed.
func chmodTree(t *testing.T, ov *overlay.FS, root uint64) int {
	t.Helper()
	ctx := context.Background()
	n := 0
	var walk func(ino uint64)
	walk = func(ino uint64) {
		ents, err := ov.Readdir(ctx, ino)
		if err != nil {
			t.Fatalf("readdir %d: %v", ino, err)
		}
		for _, e := range ents {
			// Residency in the base is established by LOOKUP, not by
			// readdir, so a write addressed straight at a readdir'd inode is
			// rejected as stale — exactly as it would be for a kernel that
			// never looked the name up.
			node, err := ov.Lookup(ctx, ino, e.Name)
			if err != nil {
				t.Fatalf("lookup %d/%s: %v", ino, e.Name, err)
			}
			mode := uint32(0640)
			if node.Type == 2 {
				mode = 0750
			}
			if _, err := ov.SetAttr(ctx, node.Inode, overlay.SetAttrIn{Mode: &mode}); err != nil {
				t.Fatalf("setattr %d: %v", node.Inode, err)
			}
			n++
			if node.Type == 2 {
				walk(node.Inode)
			}
		}
	}
	walk(root)
	return n
}

// verifyBigTree walks the final generation through a COLD cache and reads
// every file, so a carried-forward reference that names bytes no longer
// reachable fails here rather than in production.
func verifyBigTree(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, dirs []uint64) {
	t.Helper()
	ctx := context.Background()
	fs := openGenfs(t, inner, sb, nil)
	var files, bytes int64
	var walk func(ino uint64)
	walk = func(ino uint64) {
		ents, err := fs.Readdir(ctx, ino)
		if err != nil {
			t.Fatalf("readdir %d: %v", ino, err)
		}
		for _, e := range ents {
			n, err := fs.Lookup(ctx, ino, e.Name)
			if err != nil {
				t.Fatalf("lookup %d/%s: %v", ino, e.Name, err)
			}
			if n.Type == 2 {
				walk(n.Inode)
				continue
			}
			if n.Length > 0 {
				readWhole(t, fs, n.Inode, n.Length)
				bytes += n.Length
			}
			files++
		}
	}
	start := time.Now()
	walk(1)
	t.Logf("cold read-back: %d files, %d bytes, %s", files, bytes, time.Since(start).Round(time.Millisecond))
}

func openBigLayers(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, state string, seq int) (*genfs.FS, *overlay.FS) {
	t.Helper()
	gfs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: sb, CacheDir: filepath.Join(state, "gencache"),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	ov, err := overlay.Open(filepath.Join(state, "overlay", strconv.Itoa(seq)), gfs, overlay.Options{
		NextInode:      gfs.NextInode(),
		BaseRoot:       gfs.RootCatalog(),
		BaseGeneration: gfs.Generation(),
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	return gfs, ov
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// buildBigTree writes a source-checkout-shaped tree: a two-level directory
// fan-out, most files small enough to inline (which is what makes catalogs
// big and therefore numerous), a minority chunked.
func buildBigTree(t *testing.T, ov *overlay.FS, files, perDir int) []uint64 {
	t.Helper()
	ctx := context.Background()
	rng := mrand.New(mrand.NewSource(20250815))
	buf := make([]byte, 256<<10)
	rng.Read(buf)

	var dirs []uint64
	nDirs := (files + perDir - 1) / perDir
	span := 1
	for span*span < nDirs {
		span++
	}
	for i := 0; i < span && len(dirs) < nDirs; i++ {
		top, err := ov.Mkdir(ctx, 1, fmt.Sprintf("top%03d", i), 0755, 0, 0)
		if err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for j := 0; j < span && len(dirs) < nDirs; j++ {
			sub, err := ov.Mkdir(ctx, top.Inode, fmt.Sprintf("sub%03d", j), 0755, 0, 0)
			if err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			dirs = append(dirs, sub.Inode)
		}
	}
	written := 0
	for _, d := range dirs {
		for k := 0; k < perDir && written < files; k++ {
			var size int
			switch r := rng.Intn(100); {
			case r < 70:
				size = 512 + rng.Intn(3500) // inline: lands in the catalog
			case r < 95:
				size = 5000 + rng.Intn(12000)
			default:
				size = 40000 + rng.Intn(50000)
			}
			n, err := ov.Create(ctx, d, fmt.Sprintf("f%04d.c", k), 0644, 0, 0)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			off := rng.Intn(len(buf) - size)
			if _, err := ov.Write(ctx, n.Inode, 0, buf[off:off+size]); err != nil {
				t.Fatalf("write: %v", err)
			}
			written++
		}
	}
	return dirs
}

// timedSeal runs one seal and reports what the seal cost line reports:
// wall, CPU, bytes moved, catalogs written.
func timedSeal(t *testing.T, label string, inner *meterStore, ov *overlay.FS, prev *publish.Result,
	priv ed25519.PrivateKey, index, cpuProfile string) *publish.Result {
	t.Helper()
	ctx := context.Background()
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			t.Fatal(err)
		}
		defer func() {
			pprof.StopCPUProfile()
			_ = f.Close()
			t.Logf("%s: cpu profile written to %s", label, cpuProfile)
		}()
	}
	mark := inner.snapshot()
	cpu0 := processCPU()
	start := time.Now()
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: inner, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: prev.Superblock, PrevRaw: prev.Raw,
		DedupIndexPath: index,
		// Catalog building is the one step that scales with cores, and how
		// far it is worth scaling is a measurement, not a guess: past some
		// width the pure-Go SQLite's own allocator becomes the contended
		// resource and the wall time stops improving while the CPU keeps
		// climbing.
		CatalogConcurrency: envInt("PELFS_BIGSEAL_CATCONC", 0),
		// PELFS_BIGSEAL_SQLITE=1 seals in the older SQLite encoding, so the
		// same measurement covers both on the same tree.
		SQLiteCatalogs: os.Getenv("PELFS_BIGSEAL_SQLITE") != "",
	})
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	wall := time.Since(start)
	t.Logf("SEAL %s: %s wall, %s CPU, %s, %d catalogs (%d reused), %d dirs walked, %d subtrees pruned, %d packs, %d chunks added",
		label, wall.Round(time.Millisecond), (processCPU() - cpu0).Round(time.Millisecond),
		inner.since(mark), res.Stats.Catalogs, res.Stats.CatalogsReused, res.Stats.Dirs,
		res.Stats.SubtreesPruned, len(res.NewPacks), res.Stats.ChunksAdded)
	return res
}

// processCPU is user+system CPU for the whole process, which is what the
// seal-cost line a session prints reports as its CPU number.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	return tv(ru.Utime) + tv(ru.Stime)
}

// meterStore counts the bytes and requests a phase moves in each
// direction; "22.5 MiB uploaded for one new file" is exactly this.
type meterStore struct {
	pelicanobj.Store
	gets, puts   atomic.Int64
	getB, putB   atomic.Int64
	listRequests atomic.Int64
	// delay models a federation round trip. A local fakeorigin answers in
	// microseconds, which hides the cost that actually dominates a mount:
	// the NUMBER of requests it makes before it can serve anything.
	delay time.Duration
}

type meterMark struct{ gets, puts, getB, putB, lists int64 }

func (m *meterStore) snapshot() meterMark {
	return meterMark{m.gets.Load(), m.puts.Load(), m.getB.Load(), m.putB.Load(), m.listRequests.Load()}
}

func (m *meterStore) since(k meterMark) string {
	return fmt.Sprintf("%d GET (%s), %d PUT (%s), %d LIST",
		m.gets.Load()-k.gets, human(m.getB.Load()-k.getB),
		m.puts.Load()-k.puts, human(m.putB.Load()-k.putB),
		m.listRequests.Load()-k.lists)
}

func human(n int64) string {
	switch {
	case n > 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n > 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func (m *meterStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	rc, err := m.Store.Get(ctx, key, off, limit)
	if err != nil {
		return nil, err
	}
	m.gets.Add(1)
	return &countingReader{rc: rc, n: &m.getB}, nil
}

func (m *meterStore) Put(ctx context.Context, key string, in io.Reader) error {
	m.puts.Add(1)
	return m.Store.Put(ctx, key, &countingReader{rd: in, n: &m.putB})
}

func (m *meterStore) ListDir(ctx context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	m.listRequests.Add(1)
	return m.Store.ListDir(ctx, dir)
}

type countingReader struct {
	rc io.ReadCloser
	rd io.Reader
	n  *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	r := c.rd
	if r == nil {
		r = c.rc
	}
	n, err := r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReader) Close() error {
	if c.rc != nil {
		return c.rc.Close()
	}
	return nil
}

// TestMountOpenCost measures what a mount pays before it can serve its
// first byte, against a store with a round-trip delay — because that is
// what the cost is made of. genfs.Open builds the identity index from
// every pack trailer in the generation's pack list, and a volume of any
// size has a lot of packs.
//
//	PELFS_BIGSEAL=1 PELFS_MOUNT_RTT_MS=20 go test ./internal/publish -run MountOpenCost -v -timeout 30m
func TestMountOpenCost(t *testing.T) {
	if os.Getenv("PELFS_BIGSEAL") == "" {
		t.Skip("set PELFS_BIGSEAL=1 to run the mount-cost measurement")
	}
	ctx := context.Background()
	files := envInt("PELFS_MOUNT_FILES", 20000)
	rtt := time.Duration(envInt("PELFS_MOUNT_RTT_MS", 20)) * time.Millisecond

	inner := &meterStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	head, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0x60, 0x0d, 0xca, 0xfe}, TargetPackSize: 4 << 20,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	gfs, ov := openBigLayers(t, inner, head.Superblock, state, 1)
	buildBigTree(t, ov, files, 16)
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: inner, SpoolDir: t.TempDir(), SigningKey: priv,
		Prev: head.Superblock, PrevRaw: head.Raw, TargetPackSize: 4 << 20,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	_ = ov.Close()
	_ = gfs.Close()
	t.Logf("volume: %d packs, %d catalogs", len(res.Superblock.PackList), res.Stats.Catalogs)

	inner.delay = rtt
	for _, phase := range []string{"cold cache", "warm cache"} {
		mark := inner.snapshot()
		start := time.Now()
		fs, err := genfs.Open(ctx, genfs.Options{
			Inner: inner, SB: res.Superblock, CacheDir: filepath.Join(state, "mountcache"),
		})
		if err != nil {
			t.Fatalf("genfs.Open: %v", err)
		}
		open := time.Since(start)
		lookStart := time.Now()
		if _, err := fs.LookupPath(ctx, "top000/sub000"); err != nil {
			t.Fatalf("first lookup: %v", err)
		}
		t.Logf("MOUNT (%s, %s RTT): genfs.Open %s, first lookup %s, %s",
			phase, rtt, open.Round(time.Millisecond),
			time.Since(lookStart).Round(time.Millisecond), inner.since(mark))
		_ = fs.Close()
	}
}
