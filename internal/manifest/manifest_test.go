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

func build(tb testing.TB, from, to int) *Manifest {
	tb.Helper()
	b := NewBuilder()
	for i := from; i < to; i++ {
		if err := b.Add(pack(i)); err != nil {
			tb.Fatal(err)
		}
	}
	m, err := Open(b.Encode())
	if err != nil {
		tb.Fatal(err)
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

// tieredSet builds a set shaped the way consolidate leaves one: a few
// segments, oldest first, each roughly half the size of the one before
// it, summing to n packs. Sizes descend towards the newest end because
// that is what geometric tiering produces — and because it is the shape
// that used to be worst for the union, every older segment's whole run
// sorting BELOW everything already placed.
func tieredSet(tb testing.TB, n int) *Set {
	tb.Helper()
	var segments []*Manifest
	at := 0
	for rest := n; rest > 0; {
		// Halving from the oldest end: geometric tiering leaves each
		// surviving segment at least as large as the sum of the newer ones.
		s := rest / 2
		if s < 1 {
			s = rest
		}
		segments = append(segments, build(tb, at, at+s))
		at += s
		rest -= s
	}
	return NewSet(segments)
}

// The union of a generation's segments is on the critical path of every
// cold mount — manifest.Packs calls it before the first question — so its
// cost is a mount-time cost and belongs under a bound.
//
// The bound is deliberately loose: what it has to separate is a pass
// (milliseconds at this size) from the quadratic sort this replaced, which
// over the same fixture spent tens of seconds moving each older segment's
// run past every newer one. Anything between those is a regression worth
// failing on, and no ordinary machine variation reaches it.
func TestUnioningSegmentsIsAPassNotASort(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 100,000-pack fixture")
	}
	const n = 100_000
	set := tieredSet(t, n)
	const budget = 3 * time.Second
	start := time.Now()
	all := set.All()
	elapsed := time.Since(start)
	if len(all) != n {
		t.Fatalf("the union holds %d packs, want %d", len(all), n)
	}
	prev := ""
	for _, p := range all {
		if p.Name <= prev {
			t.Fatalf("%s does not follow %s; the union is not in creation order", p.Name, prev)
		}
		prev = p.Name
	}
	if elapsed > budget {
		t.Errorf("unioning %d packs across %d segments took %v, over the %v budget: "+
			"the union is sorting its input again rather than merging it",
			n, len(set.segments), elapsed.Round(time.Millisecond), budget)
	}
	t.Logf("%d packs across %d segments unioned in %v", n, len(set.segments), elapsed.Round(time.Millisecond))
}

// The union must not depend on the shape of the segmentation: the same
// packs cut into one segment or a dozen are the same generation.
func TestUnionIsIndependentOfSegmentation(t *testing.T) {
	one := NewSet([]*Manifest{build(t, 0, 600)}).All()
	many := tieredSet(t, 600).All()
	if len(one) != len(many) {
		t.Fatalf("one segment yields %d packs, several yield %d", len(one), len(many))
	}
	for i := range one {
		if one[i] != many[i] {
			t.Fatalf("pack %d differs: %+v vs %+v", i, one[i], many[i])
		}
	}
}

// A pack rewritten into a newer segment — what a repack leaves behind —
// must resolve to the NEWER record, and appear once.
func TestTheNewestSegmentWinsInTheUnion(t *testing.T) {
	old := build(t, 0, 10)
	b := NewBuilder()
	rewritten := pack(5)
	rewritten.Size = 999_999
	rewritten.TrailerHash = blake3.Sum256([]byte("rewritten"))
	if err := b.Add(rewritten); err != nil {
		t.Fatal(err)
	}
	newer, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	all := NewSet([]*Manifest{old, newer}).All()
	if len(all) != 10 {
		t.Fatalf("the union holds %d packs, want 10: the rewritten pack was not deduped", len(all))
	}
	if all[5] != rewritten {
		t.Fatalf("pack 5 = %+v, want the newer segment's %+v", all[5], rewritten)
	}
}

func BenchmarkSetAll(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			set := tieredSet(b, n)
			b.ResetTimer()
			for b.Loop() {
				if got := len(set.All()); got != n {
					b.Fatalf("%d packs, want %d", got, n)
				}
			}
		})
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
	if _, err := MergeTo(&streamed, spool, segments); err != nil {
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
