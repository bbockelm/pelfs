package manifest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// packName mirrors what packstore writes: p-<16 hex of unixnano>-<4 hex>,
// so lexical order is creation order.
func packName(n int) string {
	return fmt.Sprintf("p-%016x-%04x", 1_700_000_000_000_000_000+int64(n), n%0xffff)
}

func pack(n int) packstore.SealedPack {
	p := packstore.SealedPack{Name: packName(n), Size: int64(1000 + n)}
	p.TrailerHash = blake3.Sum256([]byte(p.Name))
	return p
}

func build(t *testing.T, from, to int) *Manifest {
	t.Helper()
	b := NewBuilder()
	for i := from; i < to; i++ {
		if err := b.Add(pack(i)); err != nil {
			t.Fatal(err)
		}
	}
	m, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLookupResolvesEveryPack(t *testing.T) {
	const n = 5000
	b := NewBuilder()
	for i := 0; i < n; i++ {
		if err := b.Add(pack(i)); err != nil {
			t.Fatal(err)
		}
	}
	raw := b.Encode()
	m, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Len() != n {
		t.Fatalf("%d packs, want %d", m.Len(), n)
	}
	for i := 0; i < n; i++ {
		want := pack(i)
		got, ok := m.Lookup(want.Name)
		if !ok {
			t.Fatalf("pack %s is missing", want.Name)
		}
		if got.Name != want.Name || got.Size != want.Size || got.TrailerHash != want.TrailerHash {
			t.Fatalf("pack %s = %+v, want %+v", want.Name, got, want)
		}
	}
	if _, ok := m.Lookup("p-not-a-pack"); ok {
		t.Error("a name that was never added resolved")
	}
	t.Logf("%d packs in %d bytes (%d per pack)", n, len(raw), len(raw)/n)
}

// Names begin with a zero-padded creation stamp, so sorted by name is
// sorted by age — the order retention already thinks in.
func TestEnumerationIsInCreationOrder(t *testing.T) {
	m := build(t, 0, 500)
	prev := ""
	for i := 0; i < m.Len(); i++ {
		p := m.At(i)
		if p.Name <= prev {
			t.Fatalf("pack %d (%s) does not follow %s", i, p.Name, prev)
		}
		prev = p.Name
	}
}

// A segment holds a generation's new packs; a set is the generation. The
// union is what retention walks.
func TestASetEnumeratesEverySegment(t *testing.T) {
	set := NewSet([]*Manifest{build(t, 0, 100), build(t, 100, 250)})
	all := set.All()
	if len(all) != 250 {
		t.Fatalf("%d packs across two segments, want 250", len(all))
	}
	prev := ""
	for _, p := range all {
		if p.Name <= prev {
			t.Fatalf("%s does not follow %s; the union is not in creation order", p.Name, prev)
		}
		prev = p.Name
	}
	if _, ok := set.Lookup(packName(150)); !ok {
		t.Error("a pack in the newer segment does not resolve through the set")
	}
	if _, ok := set.Lookup(packName(7)); !ok {
		t.Error("a pack in the older segment does not resolve through the set")
	}
}

// Merging is how segments become tiers without any of them being
// rewritten from the whole set.
func TestMergeStreamsSegmentsTogether(t *testing.T) {
	merged, err := Open(Merge([]*Manifest{build(t, 0, 300), build(t, 300, 700)}))
	if err != nil {
		t.Fatal(err)
	}
	if merged.Len() != 700 {
		t.Fatalf("merged manifest holds %d packs, want 700", merged.Len())
	}
	for _, i := range []int{0, 299, 300, 699} {
		want := pack(i)
		got, ok := merged.Lookup(want.Name)
		if !ok {
			t.Fatalf("pack %d is missing from the merge", i)
		}
		if got.TrailerHash != want.TrailerHash {
			t.Fatalf("pack %d lost its trailer hash in the merge", i)
		}
	}
}

// The in-memory merge is the spooling one over a buffer, so the two must
// produce the same bytes: a segment is content-addressed, and where its
// records were parked must not change its name.
func TestSpooledAndInMemoryMergesAgreeByteForByte(t *testing.T) {
	segments := []*Manifest{build(t, 0, 300), build(t, 250, 700)}
	spool, err := os.CreateTemp(t.TempDir(), "merge-*")
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close() //nolint:errcheck
	var streamed bytes.Buffer
	if err := MergeTo(&streamed, spool, segments); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(streamed.Bytes(), Merge(segments)) {
		t.Fatal("the spooled merge and the in-memory one produced different segments")
	}
	merged, err := Open(streamed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if merged.Len() != 700 {
		t.Fatalf("merged manifest holds %d packs, want 700", merged.Len())
	}
	for _, i := range []int{0, 249, 250, 299, 300, 699} {
		got, ok := merged.Lookup(packName(i))
		if !ok {
			t.Fatalf("pack %d is missing from the spooled merge", i)
		}
		if got.TrailerHash != pack(i).TrailerHash {
			t.Fatalf("pack %d lost its trailer hash in the merge", i)
		}
	}
}

// A name that does not fit the key is refused rather than truncated into
// a collision with whatever shares its prefix.
func TestAnOverlongPackNameIsRefused(t *testing.T) {
	b := NewBuilder()
	long := packstore.SealedPack{Name: string(make([]byte, keyLen+1))}
	if err := b.Add(long); err == nil {
		t.Fatal("a name longer than the key was accepted")
	}
}

func TestTruncatedManifestIsRefused(t *testing.T) {
	b := NewBuilder()
	for i := 0; i < 50; i++ {
		if err := b.Add(pack(i)); err != nil {
			t.Fatal(err)
		}
	}
	raw := b.Encode()
	for _, n := range []int{0, 7, headerLen - 1, headerLen, len(raw) - 1} {
		if _, err := Open(raw[:n]); err == nil {
			t.Errorf("a %d-byte prefix of a %d-byte manifest was accepted", n, len(raw))
		}
	}
}

type slowStore struct {
	pelicanobj.Store
	objs    map[string][]byte
	latency time.Duration
	peak    atomic.Int64
	inFlt   atomic.Int64
}

func (s *slowStore) Get(_ context.Context, key string, _, _ int64) (io.ReadCloser, error) {
	n := s.inFlt.Add(1)
	for {
		peak := s.peak.Load()
		if n <= peak || s.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	time.Sleep(s.latency)
	s.inFlt.Add(-1)
	b, ok := s.objs[key]
	if !ok {
		return nil, fmt.Errorf("no object %s", key)
	}
	return io.NopCloser(&sliceReader{b: b}), nil
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// Segments are fetched together, for the same reason index tiers are:
// otherwise tiering trades one round trip for several, paid in sequence.
func TestSegmentsAreFetchedInParallel(t *testing.T) {
	ctx := context.Background()
	store := &slowStore{objs: map[string][]byte{}, latency: 100 * time.Millisecond}
	var refs []superblock.ManifestRef
	for i := 0; i < 6; i++ {
		b := NewBuilder()
		if err := b.Add(pack(i)); err != nil {
			t.Fatal(err)
		}
		raw := b.Encode()
		name := "m-" + strconv.Itoa(i)
		store.objs[Dir+"/"+name] = raw
		refs = append(refs, superblock.ManifestRef{Name: name, Hash: blake3.Sum256(raw), Size: int64(len(raw)), Packs: 1})
	}
	start := time.Now()
	got, err := FetchAll(ctx, store, refs)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(refs) {
		t.Fatalf("fetched %d segments, want %d", len(got), len(refs))
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("fetching %d segments at %v each took %v; they were serialised",
			len(refs), store.latency, elapsed)
	}
	t.Logf("%d segments at %v each fetched in %v, peak concurrency %d",
		len(refs), store.latency, elapsed.Round(time.Millisecond), store.peak.Load())
}

// A manifest that does not verify is not survivable the way an index is:
// it is the only record of what a generation's packs are. The error must
// reach the caller alongside whatever did verify, so retention can refuse
// to sweep on a partial view.
func TestAnUnverifiableSegmentIsReported(t *testing.T) {
	ctx := context.Background()
	store := &slowStore{objs: map[string][]byte{}}
	b := NewBuilder()
	if err := b.Add(pack(1)); err != nil {
		t.Fatal(err)
	}
	raw := b.Encode()
	store.objs[Dir+"/ok"] = raw
	store.objs[Dir+"/bad"] = raw
	refs := []superblock.ManifestRef{
		{Name: "ok", Hash: blake3.Sum256(raw)},
		{Name: "bad", Hash: [32]byte{0xde, 0xad}},
	}
	got, err := FetchAll(ctx, store, refs)
	if err == nil {
		t.Error("a hash mismatch was not reported")
	}
	if len(got) != 1 {
		t.Fatalf("%d segments survived, want the one that verified", len(got))
	}
}
