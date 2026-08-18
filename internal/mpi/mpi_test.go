package mpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

func id(n uint64) [32]byte {
	var k [32]byte
	binary.BigEndian.PutUint64(k[:8], n*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(k[24:], n)
	return k
}

func buildIndex(t *testing.T, packs, perPack int) ([]byte, *Builder) {
	t.Helper()
	b := NewBuilder()
	n := uint64(0)
	for p := 0; p < packs; p++ {
		pack := "p-" + strconv.Itoa(p)
		for e := 0; e < perPack; e++ {
			if err := b.Add(id(n), pack, int64(e*100), 100, ""); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}
	return b.Encode(), b
}

func TestLookupResolvesToTheRightPack(t *testing.T) {
	raw, _ := buildIndex(t, 40, 50)
	ix, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 2000 {
		t.Fatalf("%d entries, want 2000", ix.Len())
	}
	if got := len(ix.Packs()); got != 40 {
		t.Fatalf("%d packs, want 40", got)
	}
	for n := uint64(0); n < 2000; n++ {
		loc, ok := ix.Lookup(id(n))
		if !ok {
			t.Fatalf("entry %d is missing", n)
		}
		wantPack := "p-" + strconv.Itoa(int(n)/50)
		if loc.Pack != wantPack {
			t.Fatalf("entry %d resolved to %s, want %s", n, loc.Pack, wantPack)
		}
		if want := int64(int(n) % 50 * 100); loc.Off != want {
			t.Fatalf("entry %d is at %d, want %d", n, loc.Off, want)
		}
	}
	if _, ok := ix.Lookup(id(999999)); ok {
		t.Fatal("an identity that was never added resolved")
	}
	t.Logf("2000 entries across 40 packs in %d bytes (%d per entry)", len(raw), len(raw)/2000)
}

func TestEntryTypesSurvive(t *testing.T) {
	b := NewBuilder()
	for i, typ := range []string{"", "catalog", "shard", "sb"} {
		if err := b.Add(id(uint64(i)), "p-0", int64(i), 1, typ); err != nil {
			t.Fatal(err)
		}
	}
	ix, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"", "catalog", "shard", "sb"} {
		loc, ok := ix.Lookup(id(uint64(i)))
		if !ok {
			t.Fatalf("entry %d missing", i)
		}
		if loc.Type != want {
			t.Errorf("entry %d has type %q, want %q", i, loc.Type, want)
		}
	}
}

// An index is bytes somebody fetched, so every truncation of it must be
// refused rather than indexed into.
func TestTruncatedIndexIsRefused(t *testing.T) {
	raw, _ := buildIndex(t, 4, 4)
	for _, n := range []int{0, 7, headerLen - 1, headerLen, headerLen + 4, len(raw) - 1} {
		if _, err := Open(raw[:n]); err == nil {
			t.Errorf("a %d-byte prefix of a %d-byte index was accepted", n, len(raw))
		}
	}
}

// A set is consulted newest-first: the same identity can sit in two packs
// after a re-upload, and the later index names the one more likely to
// still exist.
func TestASetPrefersTheNewestIndex(t *testing.T) {
	older := NewBuilder()
	if err := older.Add(id(1), "p-old", 0, 10, ""); err != nil {
		t.Fatal(err)
	}
	newer := NewBuilder()
	if err := newer.Add(id(1), "p-new", 0, 10, ""); err != nil {
		t.Fatal(err)
	}
	o, err := Open(older.Encode())
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(newer.Encode())
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet([]*Index{o, n})
	loc, ok := set.Lookup(id(1))
	if !ok {
		t.Fatal("missing")
	}
	if loc.Pack != "p-new" {
		t.Errorf("resolved to %s, want the newest index's p-new", loc.Pack)
	}
	if !set.Covers("p-old") || !set.Covers("p-new") {
		t.Error("the set does not report the packs it covers")
	}
	if set.Covers("p-elsewhere") {
		t.Error("the set claims a pack no index names")
	}
}

// slowStore charges a fixed latency per object, which is the only way to
// tell a parallel fetch from a serial one.
type slowStore struct {
	pelicanobj.Store
	objs    map[string][]byte
	latency time.Duration
	gets    atomic.Int64
	inFlt   atomic.Int64
	peak    atomic.Int64
}

func (s *slowStore) Get(_ context.Context, key string, _, _ int64) (io.ReadCloser, error) {
	s.gets.Add(1)
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
	return io.NopCloser(newReader(b)), nil
}

func newReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// The whole point of an index is to collapse round trips, so fetching a
// generation's indexes one after another would give most of the problem
// back. They are fetched at once, and this is the test that says so: with
// eight indexes at 100ms each, serial is 800ms and parallel is about one.
func TestIndexesAreFetchedInParallel(t *testing.T) {
	ctx := context.Background()
	store := &slowStore{objs: map[string][]byte{}, latency: 100 * time.Millisecond}
	var refs []Ref
	for i := 0; i < 8; i++ {
		b := NewBuilder()
		if err := b.Add(id(uint64(i)), "p-"+strconv.Itoa(i), 0, 10, ""); err != nil {
			t.Fatal(err)
		}
		raw := b.Encode()
		name := "mpi-" + strconv.Itoa(i)
		store.objs[Dir+"/"+name] = raw
		refs = append(refs, Ref{Name: name, Hash: blake3.Sum256(raw), Size: int64(len(raw))})
	}

	start := time.Now()
	set, err := FetchAll(ctx, store, refs)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != len(refs) {
		t.Fatalf("fetched %d indexes, want %d", len(set), len(refs))
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("fetching %d indexes at %v each took %v; they are not being fetched together",
			len(refs), store.latency, elapsed)
	}
	if peak := store.peak.Load(); peak < 2 {
		t.Errorf("peak concurrency was %d; the fetches were serialised", peak)
	}
	t.Logf("%d indexes at %v each fetched in %v, peak concurrency %d",
		len(refs), store.latency, elapsed.Round(time.Millisecond), store.peak.Load())
}

// An index that does not hash to what the generation says is not one this
// reader may trust — and losing it must cost speed, not the mount.
func TestACorruptIndexIsRejectedButNotFatal(t *testing.T) {
	ctx := context.Background()
	store := &slowStore{objs: map[string][]byte{}}
	good := NewBuilder()
	if err := good.Add(id(1), "p-0", 0, 10, ""); err != nil {
		t.Fatal(err)
	}
	raw := good.Encode()
	store.objs[Dir+"/ok"] = raw
	store.objs[Dir+"/bad"] = append([]byte(nil), raw...)

	refs := []Ref{
		{Name: "ok", Hash: blake3.Sum256(raw), Size: int64(len(raw))},
		{Name: "bad", Hash: [32]byte{0xde, 0xad}, Size: int64(len(raw))},
	}
	set, err := FetchAll(ctx, store, refs)
	if err == nil {
		t.Error("a hash mismatch was not reported")
	}
	if len(set) != 1 {
		t.Fatalf("%d indexes survived, want the one that verified", len(set))
	}
	if _, ok := set[0].Lookup(id(1)); !ok {
		t.Error("the index that verified does not answer")
	}
}
