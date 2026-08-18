package memtable

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// The measurement compares this write path against the one it would
// replace, on a session shaped like the kernel-tree extraction the design
// quotes: 85k files, most of them small, some rewritten. It is gated
// because it writes hundreds of megabytes and takes tens of seconds —
// exactly the cost it exists to measure.
//
//	PELFS_WRITEPATH_MEASURE=1 go test ./internal/memtable -run Measure -v
//
// PELFS_WRITEPATH_FILES overrides the file count; PELFS_WRITEPATH_LATENCY
// sets the modelled per-pack round trip in milliseconds. Latency is the
// point of the comparison, not a detail: with a free federation an upload
// costs nothing and "the flush overlapped the write phase" cannot be
// distinguished from "there was nothing to overlap".
const (
	defaultMeasureFiles   = 85000
	defaultMeasureLatency = 50 * time.Millisecond
)

type sessionSpec struct {
	files   int
	seed    uint64
	rewrite float64 // fraction of files written more than once
}

type fileSpec struct {
	ino      uint64
	size     int
	versions int
}

// plan draws a file-size distribution close to a kernel tree's: a heavy
// small-file mode with a long tail. The absolute shape matters less than
// that most files are single-chunk under the production CDC parameters,
// which is what the design's "99.89% of files are single-chunk" says.
func (sp sessionSpec) plan() []fileSpec {
	r := rand.New(rand.NewPCG(sp.seed, 0x5eed))
	out := make([]fileSpec, sp.files)
	for i := range out {
		var size int
		switch n := r.IntN(100); {
		case n < 60:
			size = 512 + r.IntN(6<<10)
		case n < 90:
			size = 6<<10 + r.IntN(24<<10)
		case n < 99:
			size = 30<<10 + r.IntN(100<<10)
		default:
			size = 130<<10 + r.IntN(900<<10)
		}
		versions := 1
		if r.Float64() < sp.rewrite {
			versions = 2 + r.IntN(2)
		}
		out[i] = fileSpec{ino: uint64(i + 1), size: size, versions: versions}
	}
	return out
}

func (sp sessionSpec) bytes(plan []fileSpec) (live, written int64) {
	for _, f := range plan {
		live += int64(f.size)
		written += int64(f.size) * int64(f.versions)
	}
	return
}

// scratchFor sizes the one reusable content buffer both measurements use.
func scratchFor(plan []fileSpec) []byte {
	n := 0
	for _, f := range plan {
		n = max(n, f.size)
	}
	return make([]byte, n)
}

// versionBytes fills buf deterministically. Content is generated rather
// than stored so a 900 MiB session does not need 900 MiB of test heap.
func versionBytes(buf []byte, ino uint64, version int) []byte {
	r := rand.New(rand.NewPCG(ino, uint64(version)+1))
	for i := 0; i < len(buf); i += 8 {
		v := r.Uint64()
		for j := 0; j < 8 && i+j < len(buf); j++ {
			buf[i+j] = byte(v >> (8 * j))
		}
	}
	return buf
}

type phase struct {
	name string
	dur  time.Duration
}

type result struct {
	phases     []phase
	uploaded   int64
	uploadedAt map[string]int64 // bytes uploaded during each phase
	packs      int
	extra      string
}

func (r result) total() time.Duration {
	var d time.Duration
	for _, p := range r.phases {
		d += p.dur
	}
	return d
}

func (r result) report(t *testing.T, label string) {
	t.Helper()
	t.Logf("--- %s ---", label)
	for _, p := range r.phases {
		t.Logf("  %-22s %8.2fs   uploaded during phase: %s", p.name, p.dur.Seconds(), mib(r.uploadedAt[p.name]))
	}
	t.Logf("  %-22s %8.2fs   uploaded total: %s in %d packs", "TOTAL", r.total().Seconds(), mib(r.uploaded), r.packs)
	if r.extra != "" {
		t.Logf("  %s", r.extra)
	}
}

func mib(n int64) string { return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20)) }

func TestMeasureWritePathAgainstStaging(t *testing.T) {
	if os.Getenv("PELFS_WRITEPATH_MEASURE") == "" {
		t.Skip("set PELFS_WRITEPATH_MEASURE=1 to run the write-path measurement")
	}
	files := defaultMeasureFiles
	if v := os.Getenv("PELFS_WRITEPATH_FILES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		files = n
	}
	latency := defaultMeasureLatency
	if v := os.Getenv("PELFS_WRITEPATH_LATENCY"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		latency = time.Duration(ms) * time.Millisecond
	}
	spec := sessionSpec{files: files, seed: 20260817, rewrite: 0.30}
	plan := spec.plan()
	live, written := spec.bytes(plan)
	t.Logf("session: %d files, %s written, %s live (%.1f%% of writes die before they settle), modelled pack round trip %s",
		files, mib(written), mib(live), 100*float64(written-live)/float64(written), latency)
	t.Logf("scratch: %s", t.TempDir())

	staging := measureStaging(t, plan, latency)
	staging.report(t, "staging file per inode (what exists today)")
	t.Logf("  peak local content footprint: %s (one file per inode, held for the session)", mib(live))

	mem := measureMemtable(t, plan, latency)
	mem.report(t, "memtable (this prototype)")
	t.Logf("  peak local content footprint: %s (two tables, whatever the session's size)", mib(2*DefaultTableSize))
}

// measureStaging reproduces today's shape: a local file per inode, a
// hardlink snapshot to freeze it, and all of the chunking, packing and
// uploading at the seal.
func measureStaging(t *testing.T, plan []fileSpec, latency time.Duration) result {
	ctx := context.Background()
	dir := t.TempDir()
	stage := filepath.Join(dir, "staging")
	snap := filepath.Join(dir, "snapshot")
	for _, d := range []string{stage, snap} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	obj := &countingStore{objs: map[string][]byte{}, discard: true, latency: latency}
	res := result{uploadedAt: map[string]int64{}}

	buf := scratchFor(plan)
	t0 := time.Now()
	for _, f := range plan {
		for v := range f.versions {
			// A rewrite of a staged file pays full local I/O for a version
			// nothing will ever read. That is the cost the memtable path
			// claims to avoid.
			fh, err := os.OpenFile(filepath.Join(stage, strconv.FormatUint(f.ino, 10)), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fh.Write(versionBytes(buf[:f.size], f.ino, v)); err != nil {
				t.Fatal(err)
			}
			if err := fh.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	res.phases = append(res.phases, phase{"write", time.Since(t0)})

	t1 := time.Now()
	for _, f := range plan {
		name := strconv.FormatUint(f.ino, 10)
		if err := os.Link(filepath.Join(stage, name), filepath.Join(snap, name)); err != nil {
			t.Fatal(err)
		}
	}
	linkDur := time.Since(t1)
	t2 := time.Now()
	for _, f := range plan {
		if err := os.Remove(filepath.Join(snap, strconv.FormatUint(f.ino, 10))); err != nil {
			t.Fatal(err)
		}
	}
	unlinkDur := time.Since(t2)
	res.phases = append(res.phases,
		phase{"freeze (link)", linkDur},
		phase{"freeze (unlink)", unlinkDur},
	)

	t3 := time.Now()
	pk := newFlushPacker(obj, dir, DefaultPackTarget, nil, nil, 0, nil)
	hasher := chunkid.Hasher{}
	for _, f := range plan {
		fh, err := os.Open(filepath.Join(stage, strconv.FormatUint(f.ino, 10)))
		if err != nil {
			t.Fatal(err)
		}
		ch := chunkid.NewChunker(fh, chunkid.Options{})
		for {
			c, err := ch.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := pk.add(ctx, hasher.Sum(c.Data), c.Data); err != nil {
				t.Fatal(err)
			}
		}
		fh.Close() //nolint:errcheck
	}
	if err := pk.finish(ctx); err != nil {
		t.Fatal(err)
	}
	sealDur := time.Since(t3)
	res.phases = append(res.phases, phase{"seal (chunk+upload)", sealDur})
	res.uploadedAt["seal (chunk+upload)"] = pk.bytes
	res.uploaded = pk.bytes
	res.packs = len(pk.sealed)
	return res
}

// measureMemtable runs the same session through the prototype. The seal
// is Flush: it moves at most one memtable, and only what is still live in
// it.
func measureMemtable(t *testing.T, plan []fileSpec, latency time.Duration) result {
	ctx := context.Background()
	dir := t.TempDir()
	obj := &countingStore{objs: map[string][]byte{}, discard: true, latency: latency}
	s, err := New(Options{Dir: dir, TableSize: DefaultTableSize, Obj: obj})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck
	res := result{uploadedAt: map[string]int64{}}

	buf := scratchFor(plan)
	t0 := time.Now()
	for _, f := range plan {
		for v := range f.versions {
			if err := s.Write(ctx, f.ino, 0, versionBytes(buf[:f.size], f.ino, v)); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeDur := time.Since(t0)
	duringWrite := s.Stats().UploadedBytes

	t1 := time.Now()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	sealDur := time.Since(t1)

	st := s.Stats()
	res.phases = []phase{
		{"write (flush overlaps)", writeDur},
		{"freeze", 0},
		{"seal (flush tail)", sealDur},
	}
	res.uploadedAt["write (flush overlaps)"] = duringWrite
	res.uploadedAt["seal (flush tail)"] = st.UploadedBytes - duringWrite
	res.uploaded = st.UploadedBytes
	res.packs = int(st.Packs)
	res.extra = fmt.Sprintf("%d extents written, %d died in memory (%s never sent); %d flushes, %d blocked writes",
		st.Extents, st.DeadExtents, mib(st.DeadBytes), st.Flushes, st.BlockedWrites)
	return res
}

// BenchmarkFreezeCost isolates the hardlink storm the design wants gone,
// so the 31.6s-per-85k-files figure can be checked on whatever filesystem
// the measurement is running on rather than taken on faith.
func BenchmarkFreezeCost(b *testing.B) {
	const files = 5000
	dir := b.TempDir()
	stage := filepath.Join(dir, "staging")
	if err := os.MkdirAll(stage, 0700); err != nil {
		b.Fatal(err)
	}
	for i := range files {
		if err := os.WriteFile(filepath.Join(stage, strconv.Itoa(i)), []byte("x"), 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for n := 0; b.Loop(); n++ {
		snap := filepath.Join(dir, "snap"+strconv.Itoa(n))
		if err := os.MkdirAll(snap, 0700); err != nil {
			b.Fatal(err)
		}
		for i := range files {
			if err := os.Link(filepath.Join(stage, strconv.Itoa(i)), filepath.Join(snap, strconv.Itoa(i))); err != nil {
				b.Fatal(err)
			}
		}
		for i := range files {
			if err := os.Remove(filepath.Join(snap, strconv.Itoa(i))); err != nil {
				b.Fatal(err)
			}
		}
		os.Remove(snap) //nolint:errcheck
	}
	b.ReportMetric(float64(files), "files/op")
}
