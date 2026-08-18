package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
)

// linkStore models the uplink a seal actually has to push through, which
// a loopback fakeorigin does not: a shared aggregate bandwidth, a
// round-trip cost per object, and a per-stream ceiling of window/RTT.
//
// The per-stream ceiling is what makes the model able to tell the two
// regimes apart. On a home uplink the aggregate is the binding
// constraint and a second stream only divides the same pipe; on a
// long-fat link one stream is window-limited and concurrency is the only
// way to fill the pipe. A model with aggregate bandwidth alone would
// declare concurrency pointless everywhere.
type linkStore struct {
	pelicanobj.Store
	bw     float64       // aggregate bytes/sec, shared by all streams
	rtt    time.Duration // per-object round trip before bytes flow
	window int64         // per-stream bytes in flight; rate ceiling is window/rtt

	mu       sync.Mutex
	inflight int
	lastAt   time.Time
	dwell    map[int]time.Duration // wall time spent with exactly N uploads in flight
	begunAt  time.Time
	endedAt  time.Time
	bytes    int64
	puts     int
	starts   []time.Duration // when each upload began, relative to begunAt
}

func newLinkStore(inner pelicanobj.Store, mbits float64, rtt time.Duration, window int64) *linkStore {
	return &linkStore{
		Store:  inner,
		bw:     mbits * 1e6 / 8,
		rtt:    rtt,
		window: window,
		dwell:  map[int]time.Duration{},
	}
}

// begin/end bracket the measured window so the idle time BEFORE the first
// upload counts. That leading gap is the whole complaint: the walk runs,
// and nothing leaves.
func (s *linkStore) begin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.begunAt, s.lastAt = now, now
}

func (s *linkStore) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(time.Now())
	s.endedAt = time.Now()
}

// advance charges the elapsed time to whatever depth was in flight.
func (s *linkStore) advance(now time.Time) {
	if !s.lastAt.IsZero() {
		s.dwell[s.inflight] += now.Sub(s.lastAt)
	}
	s.lastAt = now
}

func (s *linkStore) enter() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(time.Now())
	s.inflight++
	s.puts++
	s.starts = append(s.starts, time.Since(s.begunAt))
}

func (s *linkStore) leave() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advance(time.Now())
	s.inflight--
}

// share is the rate one stream gets right now: its fair slice of the
// aggregate, capped by what a single stream's window can keep in flight.
func (s *linkStore) share() float64 {
	s.mu.Lock()
	n := s.inflight
	s.mu.Unlock()
	if n < 1 {
		n = 1
	}
	fair := s.bw / float64(n)
	if s.rtt > 0 {
		if ceil := float64(s.window) / s.rtt.Seconds(); ceil < fair {
			return ceil
		}
	}
	return fair
}

func (s *linkStore) Put(ctx context.Context, key string, in io.Reader) error {
	if !strings.HasPrefix(key, "packs/") {
		return s.Store.Put(ctx, key, in)
	}
	s.enter()
	defer s.leave()
	time.Sleep(s.rtt)
	// Pack bodies are dropped rather than stored: the sweep seals the same
	// fixture a dozen times and nothing here ever reads a pack back, so
	// keeping them would cost gigabytes of scratch to prove nothing. The
	// wrapper hides io.Discard's ReaderFrom, which would otherwise pull in
	// 8 KiB reads and make the model pay a host sleep per 8 KiB.
	buf := make([]byte, 64<<10)
	_, err := io.CopyBuffer(struct{ io.Writer }{io.Discard},
		&pacedReader{link: s, r: in, next: time.Now()}, buf)
	time.Sleep(s.rtt)
	return err
}

type pacedReader struct {
	link *linkStore
	r    io.Reader
	next time.Time // when this stream is entitled to have sent what it has
}

// Read paces against a running deadline rather than sleeping per slice.
// Sleeping for each slice's computed cost charges the model the host's
// timer granularity thousands of times over, and the error compounds: the
// modelled link quietly lost ~20% of its own bandwidth. The deadline is
// never advanced to the wall clock, so an overshoot is repaid by the next
// slice instead of becoming the new baseline.
func (p *pacedReader) Read(b []byte) (int, error) {
	// Cap the slice so the fair share is re-sampled often enough to track
	// streams starting and finishing mid-transfer.
	if len(b) > 64<<10 {
		b = b[:64<<10]
	}
	n, err := p.r.Read(b)
	if n > 0 {
		p.next = p.next.Add(time.Duration(float64(n) / p.link.share() * float64(time.Second)))
		if d := time.Until(p.next); d > 0 {
			time.Sleep(d)
		}
		p.link.mu.Lock()
		p.link.bytes += int64(n)
		p.link.mu.Unlock()
	}
	return n, err
}

type linkReport struct {
	wall     time.Duration
	idle     time.Duration // wall time with nothing in flight
	dwell    map[int]time.Duration
	bytes    int64
	puts     int
	firstPut time.Duration
	lastPut  time.Duration
}

func (s *linkStore) report() linkReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := linkReport{
		wall:  s.endedAt.Sub(s.begunAt),
		idle:  s.dwell[0],
		dwell: map[int]time.Duration{},
		bytes: s.bytes,
		puts:  s.puts,
	}
	for k, v := range s.dwell {
		r.dwell[k] = v
	}
	if len(s.starts) > 0 {
		r.firstPut, r.lastPut = s.starts[0], s.starts[len(s.starts)-1]
	}
	return r
}

func (r linkReport) log(t *testing.T, label string, bw float64) {
	t.Helper()
	depths := make([]int, 0, len(r.dwell))
	for k := range r.dwell {
		depths = append(depths, k)
	}
	sort.Ints(depths)
	var parts []string
	for _, d := range depths {
		parts = append(parts, fmt.Sprintf("%d:%.0f%%", d, 100*r.dwell[d].Seconds()/r.wall.Seconds()))
	}
	// Utilization against the modelled aggregate is the honest headline:
	// "the pipe was busy" is not the same as "the pipe was full".
	util := 100 * float64(r.bytes) / (bw * r.wall.Seconds())
	t.Logf("%-28s wall %7.2fs  idle %5.1f%%  util %5.1f%%  first PUT at %6.2fs  last PUT at %6.2fs  %d packs, %s  depth %s",
		label, r.wall.Seconds(), 100*r.idle.Seconds()/r.wall.Seconds(), util,
		r.firstPut.Seconds(), r.lastPut.Seconds(), r.puts, human(r.bytes), strings.Join(parts, " "))
}

// linkProfile is one point in the bandwidth/latency space a seal has to
// survive: a slow home uplink, a decent residential link, and a long-fat
// data-centre path where a single stream cannot fill the pipe.
type linkProfile struct {
	name   string
	mbits  float64
	rtt    time.Duration
	window int64
}

var linkProfiles = []linkProfile{
	// "free" is not a link anyone has; it is the CPU-bound floor, so
	// "the seal is upload-bound" can be stated as a difference rather
	// than asserted.
	{"free-10Gb/1ms", 10000, time.Millisecond, 8 << 20},
	{"home-20Mb/30ms", 20, 30 * time.Millisecond, 512 << 10},
	{"resi-100Mb/30ms", 100, 30 * time.Millisecond, 512 << 10},
	{"wan-1Gb/80ms", 1000, 80 * time.Millisecond, 1 << 20},
}

// TestSealUploadPipeline measures where a seal's wall time goes against a
// modelled link and how full the upload pipe stays. It is gated because
// each profile pushes hundreds of megabytes through a deliberately slow
// model.
//
//	PELFS_UPLOADPIPE=1 go test ./internal/publish -run SealUploadPipeline -v -timeout 60m
//
// PELFS_UPLOADPIPE_FILES sizes the tree; PELFS_UPLOADPIPE_PROFILES selects
// profiles by name; PELFS_UPLOADPIPE_CONC and PELFS_UPLOADPIPE_RAMP sweep
// the knobs under test.
func TestSealUploadPipeline(t *testing.T) {
	if os.Getenv("PELFS_UPLOADPIPE") == "" {
		t.Skip("set PELFS_UPLOADPIPE=1 to run the upload-pipeline measurement")
	}
	files := envInt("PELFS_UPLOADPIPE_FILES", 12000)
	conc := envInts("PELFS_UPLOADPIPE_CONC", []int{0})
	ramps := envInts("PELFS_UPLOADPIPE_RAMP", []int{-1})
	want := os.Getenv("PELFS_UPLOADPIPE_PROFILES")

	// One fixture for the whole sweep. Every seal re-reads and re-chunks
	// the same tree from the same base generation, so the configurations
	// differ in nothing but the knobs — and building a 40k-file overlay
	// per configuration would cost more than the measurement.
	fx := newPipeFixture(t, files)

	for _, prof := range linkProfiles {
		if want != "" && !strings.Contains(want, prof.name) {
			continue
		}
		for _, c := range conc {
			for _, ramp := range ramps {
				fx.seal(t, prof, c, int64(ramp))
			}
		}
	}
}

type pipeFixture struct {
	base    pelicanobj.Store
	head    *publish.Result
	overlay *overlay.FS
	priv    ed25519.PrivateKey
	// Each configuration flips its own branch. The flip is a
	// compare-and-swap against the ref it read, so a second seal of the
	// same base generation onto the same branch is correctly refused as a
	// concurrent writer.
	runs int
}

func newPipeFixture(t *testing.T, files int) *pipeFixture {
	t.Helper()
	ctx := context.Background()
	base := newInner(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The volume is created through the raw store: its cost is not the
	// measurement, and it would otherwise pay the modelled round trips.
	head, err := publish.InitVolume(ctx, publish.Options{
		Inner: base, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0x0f, 0xf1, 0xce},
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	gfs, ov := openBigLayers(t, base, head.Superblock, t.TempDir(), 1)
	start := time.Now()
	buildBigTree(t, ov, files, 16)
	t.Logf("fixture: %d files built in %s", files, time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { _ = ov.Close(); _ = gfs.Close() })

	fx := &pipeFixture{base: base, head: head, priv: priv}
	fx.overlay = ov
	return fx
}

func (fx *pipeFixture) seal(t *testing.T, prof linkProfile, conc int, ramp int64) {
	t.Helper()
	ctx := context.Background()
	link := newLinkStore(fx.base, prof.mbits, prof.rtt, prof.window)

	fx.runs++
	opts := publish.Options{
		Overlay: fx.overlay, Inner: link, SpoolDir: t.TempDir(), SigningKey: fx.priv,
		Prev: fx.head.Superblock, PrevRaw: fx.head.Raw,
		Branch:            "run" + strconv.Itoa(fx.runs),
		UploadConcurrency: conc,
	}
	switch {
	case ramp == 0:
		// Cutting the first pack at the steady-state target IS the ramp
		// turned off; that is the shape being measured against.
		opts.FirstPackSize = publish.DefaultTargetPackSize
	case ramp > 0:
		opts.FirstPackSize = ramp << 20
	}
	link.begin()
	cpu0 := processCPU()
	start := time.Now()
	res, err := publish.Seal(ctx, opts)
	wall := time.Since(start)
	cpu := processCPU() - cpu0
	link.end()
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	label := fmt.Sprintf("%s conc=%s ramp=%s", prof.name, concLabel(conc), rampLabel(ramp))
	link.report().log(t, label, link.bw)
	t.Logf("%-28s seal %7.2fs  cpu %6.2fs  %d packs, %d chunks (%s of content), %d catalogs",
		"", wall.Seconds(), cpu.Seconds(), len(res.NewPacks), res.Stats.ChunksAdded,
		human(res.Stats.ChunkBytes), res.Stats.Catalogs)
}

func concLabel(c int) string {
	if c == 0 {
		return "default"
	}
	return strconv.Itoa(c)
}

func rampLabel(r int64) string {
	if r < 0 {
		return "default"
	}
	if r == 0 {
		return "off"
	}
	return human(r << 20)
}

func envInts(name string, def []int) []int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	var out []int
	for _, f := range strings.Split(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return def
	}
	return out
}
