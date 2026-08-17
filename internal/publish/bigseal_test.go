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

// TestBigTreeSealCost is the measurement rig for "a one-file change must
// not cost whole-tree work". It builds a tree shaped like a source
// checkout (tens of thousands of inodes, most files small enough to live
// inline in a catalog, which is what drives catalog COUNT), seals it,
// reopens over the sealed generation the way a fresh mount does, touches
// exactly one file, and seals again — reporting wall time, CPU, bytes
// moved, and catalogs written for each phase.
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

	head = timedSeal(t, "initial seal", inner, ov, head, priv, index, "")

	for phase := 2; phase <= 4; phase++ {
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
		case 3:
			if _, err := ov.Create(ctx, 1, "no.txt", 0644, 0, 0); err != nil {
				t.Fatalf("create no.txt: %v", err)
			}
			head = timedSeal(t, "one-file seal (root)", inner, ov, head, priv, index,
				os.Getenv("PELFS_BIGSEAL_CPUPROFILE"))
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
		}
	}
	_ = ov.Close()
	_ = gfs.Close()

	// The generation every phase built on must still read back whole.
	verifyBigTree(t, inner, head.Superblock, dirs)
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
	})
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	wall := time.Since(start)
	t.Logf("SEAL %s: %s wall, %s CPU, %s, %d catalogs (%d reused), %d shards, %d packs, %d chunks added, %d files reused",
		label, wall.Round(time.Millisecond), (processCPU() - cpu0).Round(time.Millisecond),
		inner.since(mark), res.Stats.Catalogs, catalogsReused(res.Stats), res.Stats.Shards,
		len(res.NewPacks), res.Stats.ChunksAdded, res.Stats.ReusedFiles)
	return res
}

func catalogsReused(s publish.Stats) int { return s.CatalogsReused }

// processCPU is user+system CPU for the whole process, which is what the
// owner's `20s CPU` number measures.
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
