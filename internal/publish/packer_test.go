package publish

import (
	"context"
	"io"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// gateStore counts concurrent Puts and blocks each one until it has seen
// `want` at once. If uploads were serialized the first Put would wait
// alone until its timeout, so this deadlock-with-a-deadline is what
// distinguishes real overlap from a test that merely passes.
type gateStore struct {
	pelicanobj.Store

	want    int
	mu      sync.Mutex
	inFlnow int
	maxSeen int
	opened  chan struct{}
	once    sync.Once
}

func newGateStore() *gateStore {
	return &gateStore{want: 2, opened: make(chan struct{})}
}

func (s *gateStore) Put(_ context.Context, _ string, in io.Reader) error {
	s.mu.Lock()
	s.inFlnow++
	if s.inFlnow > s.maxSeen {
		s.maxSeen = s.inFlnow
	}
	if s.inFlnow >= s.want {
		s.once.Do(func() { close(s.opened) })
	}
	s.mu.Unlock()

	select {
	case <-s.opened:
	case <-time.After(10 * time.Second):
	}

	s.mu.Lock()
	s.inFlnow--
	s.mu.Unlock()
	_, err := io.Copy(io.Discard, in)
	return err
}

func (s *gateStore) peak() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxSeen
}

// TestPackerUploadsOverlap pins that building the next pack does not wait
// on the previous one's upload. Sealing serialized every transfer behind
// the walk, which on a high-latency link cost ~25s per pack, paid one
// after another, entirely after the user had asked to unmount.
func TestPackerUploadsOverlap(t *testing.T) {
	ctx := context.Background()
	store := newGateStore()
	// A tiny target so each entry seals its own pack.
	p := newPacker(store, t.TempDir(), 1, 1, 0)

	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, key := range []string{"aa", "bb", "cc", "dd"} {
		if err := p.add(ctx, key, packstore.EntryData, payload); err != nil {
			t.Fatalf("add %s: %v", key, err)
		}
	}

	packs, err := p.finish(ctx)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	if len(packs) < 2 {
		t.Fatalf("expected the small target to cut several packs, got %d", len(packs))
	}
	if got := store.peak(); got < 2 {
		t.Errorf("peak concurrent uploads = %d; uploads are still serialized behind the walk", got)
	}
}

// TestPackerFinishReportsUploadFailure pins that a failed upload fails the
// publish. The ref flip happens after finish returns, so a swallowed
// error here would publish a generation naming a pack that never landed.
//
// It runs for ~17s because the store fails permanently and the upload
// path retries with backoff before giving up. That wait is the retry
// policy working, not a hang.
func TestPackerFinishReportsUploadFailure(t *testing.T) {
	ctx := context.Background()
	store := &failingStore{}
	p := newPacker(store, t.TempDir(), 1, 1, 0)

	payload := make([]byte, 256)
	for _, key := range []string{"aa", "bb"} {
		if err := p.add(ctx, key, packstore.EntryData, payload); err != nil {
			// A cut may surface the earlier upload's failure, which is
			// itself correct behavior.
			return
		}
	}
	if _, err := p.finish(ctx); err == nil {
		t.Fatal("finish reported success though every upload failed")
	}
}

type failingStore struct {
	pelicanobj.Store
}

func (s *failingStore) Put(_ context.Context, _ string, _ io.Reader) error {
	return io.ErrClosedPipe
}

// sizingStore records what each upload weighed, which is how the ramp is
// observable at all: the cut policy is otherwise invisible from outside.
type sizingStore struct {
	pelicanobj.Store
	mu    sync.Mutex
	sizes []int64
}

func (s *sizingStore) Put(_ context.Context, _ string, in io.Reader) error {
	n, err := io.Copy(io.Discard, in)
	s.mu.Lock()
	s.sizes = append(s.sizes, n)
	s.mu.Unlock()
	return err
}

func (s *sizingStore) sorted() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]int64(nil), s.sizes...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// fill feeds n entries of size each, then finishes.
func fill(t *testing.T, p *packer, n, size int) {
	t.Helper()
	ctx := context.Background()
	payload := make([]byte, size)
	for i := range n {
		if err := p.add(ctx, strconv.Itoa(i), packstore.EntryData, payload); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if _, err := p.finish(ctx); err != nil {
		t.Fatalf("finish: %v", err)
	}
}

// TestPackerRampCutsTheFirstPackSmall pins the ramp on both sides. It has
// to start small — nothing can be uploaded until a whole pack exists, so
// cutting only at the steady-state target leaves the uplink idle for the
// first target's worth of walking — and it has to STOP being small,
// because every extra pack is a trailer every future mount range-reads
// before it can serve a byte.
func TestPackerRampCutsTheFirstPackSmall(t *testing.T) {
	const (
		target = 64 << 10
		first  = 8 << 10
		entry  = 1 << 10
	)
	store := &sizingStore{}
	p := newPacker(store, t.TempDir(), target, first, 0)
	fill(t, p, 320, entry) // 320 KiB: past the ramp and well into steady state

	got := store.sorted()
	if len(got) < 5 {
		t.Fatalf("expected several packs, got %d", len(got))
	}
	if got[0] > first+(1<<10) {
		t.Errorf("first pack is %d bytes; the ramp did not cut below the %d target", got[0], target)
	}
	// 8 + 16 + 32 KiB of ramp is at most three packs under half the
	// target however much data follows; anything more is inflation the
	// pack list pays for on every mount, forever.
	small := 0
	for _, n := range got {
		if n < target/2 {
			small++
		}
	}
	if small > 3 {
		t.Errorf("%d packs under half the target; the ramp is inflating the pack list", small)
	}
	if last := got[len(got)-1]; last < target/2 {
		t.Errorf("largest pack is %d bytes; the ramp never reached the %d target", last, target)
	}
}

// TestPackerRampNeverExceedsTheTarget pins that FirstPackSize is a floor
// on the ramp, not an override: a caller that asks for packs larger than
// the target gets the target.
func TestPackerRampNeverExceedsTheTarget(t *testing.T) {
	const target = 16 << 10
	store := &sizingStore{}
	p := newPacker(store, t.TempDir(), target, 1<<20, 0)
	fill(t, p, 96, 1<<10)

	for _, n := range store.sorted() {
		if n > target+(2<<10) { // slack for the trailer
			t.Fatalf("pack of %d bytes exceeds the %d target", n, target)
		}
	}
}

// TestPackerHonorsUploadConcurrency pins the cap as a cap. The number is
// a link property the caller sets, so the packer must both reach it (a
// long-fat path needs every stream to fill the pipe) and never exceed it
// (the mount is still serving reads through the same uplink).
func TestPackerHonorsUploadConcurrency(t *testing.T) {
	const conc = 3
	ctx := context.Background()
	store := newGateStore()
	store.want = conc
	// A tiny target with the ramp disabled so each entry seals its own pack.
	p := newPacker(store, t.TempDir(), 1, 1, conc)

	payload := make([]byte, 512)
	for i := range 8 {
		if err := p.add(ctx, strconv.Itoa(i), packstore.EntryData, payload); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if _, err := p.finish(ctx); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if got := store.peak(); got != conc {
		t.Errorf("peak concurrent uploads = %d, want exactly %d", got, conc)
	}
}
