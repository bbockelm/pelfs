package publish

import (
	"context"
	"io"
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
	p := newPacker(store, t.TempDir(), 1, 0)

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
	p := newPacker(store, t.TempDir(), 1, 0)

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

// TestPackerHonorsUploadConcurrency pins the cap as a cap. The number is
// a link property the caller sets, so the packer must both reach it (a
// long-fat path needs every stream to fill the pipe) and never exceed it
// (the mount is still serving reads through the same uplink).
func TestPackerHonorsUploadConcurrency(t *testing.T) {
	const conc = 3
	ctx := context.Background()
	store := newGateStore()
	store.want = conc
	// A tiny target so each entry seals its own pack.
	p := newPacker(store, t.TempDir(), 1, conc)

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
