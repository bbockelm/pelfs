package mpi

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// rangeStore honours off/limit, which the windowed reader is entirely
// about and which slowStore does not, and records what was actually asked
// for — the numbers under test here are requests and bytes, so a store
// that quietly served whole objects would make every assertion vacuous.
type rangeStore struct {
	pelicanobj.Store
	objs  map[string][]byte
	gets  atomic.Int64
	bytes atomic.Int64
	last  atomic.Int64 // length of the most recent request
}

func (s *rangeStore) Get(_ context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	b, ok := s.objs[key]
	if !ok {
		return nil, fmt.Errorf("no object %s", key)
	}
	if off < 0 || off > int64(len(b)) {
		return nil, fmt.Errorf("range %d past the end of %s", off, key)
	}
	b = b[off:]
	if limit >= 0 && limit < int64(len(b)) {
		b = b[:limit]
	}
	s.gets.Add(1)
	s.bytes.Add(int64(len(b)))
	s.last.Store(int64(len(b)))
	return io.NopCloser(newReader(b)), nil
}

func (s *rangeStore) reset() {
	s.gets.Store(0)
	s.bytes.Store(0)
}

// publishIndex puts an index in the store and returns the ref a superblock
// would carry for it.
func publishIndex(t testing.TB, s *rangeStore, name string, raw []byte, entries int) superblock.IndexRef {
	t.Helper()
	if s.objs == nil {
		s.objs = map[string][]byte{}
	}
	s.objs[Dir+"/"+name] = raw
	return superblock.IndexRef{
		Name: name, Hash: blake3.Sum256(raw),
		Size: int64(len(raw)), Entries: uint32(entries),
	}
}

// windowed forces the windowed path for the length of one test, so the
// fixtures below stay small enough to build in milliseconds.
func windowed(t *testing.T) {
	t.Helper()
	prev := wholeFetchMax
	wholeFetchMax = 1
	t.Cleanup(func() { wholeFetchMax = prev })
}

// The reader must answer exactly what the in-memory index answers, for
// every key, present and absent. A location map that is merely mostly
// right is a corrupt read waiting for the wrong file.
func TestWindowedReaderAgreesWithTheWholeIndex(t *testing.T) {
	windowed(t)
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	raw, _ := buildIndex(t, 60, 200) // 12,000 entries, several strides
	ix, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := OpenReader(store, publishIndex(t, store, "big", raw, ix.Len()))

	for n := uint64(0); n < 12_000; n++ {
		want, wantOK := ix.Lookup(id(n))
		got, gotOK := r.Lookup(ctx, id(n))
		if gotOK != wantOK {
			t.Fatalf("entry %d: windowed ok=%v, whole ok=%v", n, gotOK, wantOK)
		}
		if !equal(got, want) {
			t.Fatalf("entry %d: windowed %v, whole %v", n, got, want)
		}
	}
	for _, n := range []uint64{12_000, 999_999, 1 << 40} {
		if _, ok := r.Lookup(ctx, id(n)); ok {
			t.Fatalf("an identity that was never added resolved through the window at %d", n)
		}
	}
}

// The whole point: an index is consulted without being moved. One lookup
// costs the resident prefix once and a window thereafter — never the
// object.
func TestAWindowedLookupMovesAWindow(t *testing.T) {
	windowed(t)
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	raw, _ := buildIndex(t, 100, 400) // 40,000 entries, ten strides
	r := OpenReader(store, publishIndex(t, store, "big", raw, 40_000))

	// Nothing before the first question: a mount that never consults its
	// index must not pay for it.
	if store.gets.Load() != 0 {
		t.Fatalf("naming an index cost %d request(s)", store.gets.Load())
	}
	if _, ok := r.Lookup(ctx, id(20_000)); !ok {
		t.Fatal("a key in the index did not resolve")
	}
	loadGets, loadBytes := store.gets.Load(), store.bytes.Load()
	if loadGets > 3 {
		t.Errorf("the first lookup cost %d request(s); the prefix is meant to converge in at most two "+
			"plus the window", loadGets)
	}
	if loadBytes >= int64(len(raw)) {
		t.Errorf("the first lookup moved %d bytes of a %d-byte index: it is still being fetched whole",
			loadBytes, len(raw))
	}

	store.reset()
	for n := uint64(0); n < 200; n++ {
		r.Lookup(ctx, id(n*37))
	}
	window := int64(packidx.DefaultStride * (KeyLen + recordLen))
	if got := store.gets.Load(); got != 200 {
		t.Errorf("200 lookups cost %d request(s), want one window each", got)
	}
	if got := store.bytes.Load(); got > 200*window {
		t.Errorf("200 lookups moved %d bytes, over 200 windows of %d", got, window)
	}
	t.Logf("%d-byte index: prefix %d bytes in %d request(s), then %d bytes per lookup",
		len(raw), loadBytes, loadGets, store.bytes.Load()/200)
}

// A small index is still read whole, hash and all: below the threshold the
// windowed path would trade a check it can make for requests it does not
// need.
func TestASmallIndexIsStillReadWholeAndVerified(t *testing.T) {
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	raw, _ := buildIndex(t, 4, 10)
	ref := publishIndex(t, store, "small", raw, 40)

	r := OpenReader(store, ref)
	if _, ok := r.Lookup(ctx, id(0)); !ok {
		t.Fatal("a key in a small index did not resolve")
	}
	if got := store.gets.Load(); got != 1 {
		t.Errorf("a small index cost %d request(s), want one", got)
	}
	store.reset()
	for n := uint64(0); n < 40; n++ {
		if _, ok := r.Lookup(ctx, id(n)); !ok {
			t.Fatalf("entry %d is missing", n)
		}
	}
	if got := store.gets.Load(); got != 0 {
		t.Errorf("40 lookups against a resident index cost %d request(s)", got)
	}

	// And the whole-object check still applies where it can be made.
	bad := ref
	bad.Hash[0] ^= 0xff
	if _, ok := OpenReader(store, bad).Lookup(ctx, id(0)); ok {
		t.Error("an index that does not hash to what the generation says was consulted anyway")
	}
}

// The whole-object hash cannot be checked from a window, so what stops a
// hostile prefix is the SIGNED SIZE and nothing else. Every length off the
// wire is held against it before a byte is allocated — and a length that
// fails must be a miss, never an allocation and never a panic.
func TestAHostilePrefixIsBoundedByTheSignedSize(t *testing.T) {
	windowed(t)
	ctx := context.Background()
	raw, _ := buildIndex(t, 40, 100)
	blobLen := binary.LittleEndian.Uint32(raw[12:])
	tbl := int64(headerLen) + int64(blobLen)

	for _, tc := range []struct {
		name string
		bend func(b []byte)
	}{
		{"a strings blob longer than the object", func(b []byte) {
			binary.LittleEndian.PutUint32(b[12:], 0xffff_fff0)
		}},
		{"more samples than the object holds", func(b []byte) {
			binary.LittleEndian.PutUint32(b[tbl+20:], 0xffff_fff0)
		}},
		{"more entries than the object holds", func(b []byte) {
			binary.LittleEndian.PutUint32(b[tbl+12:], 0xffff_fff0)
		}},
		{"an absurd stride", func(b []byte) {
			binary.LittleEndian.PutUint32(b[tbl+16:], 0xffff_fff0)
		}},
		{"a version this build does not know", func(b []byte) {
			binary.LittleEndian.PutUint32(b[8:], 99)
		}},
		{"not an index at all", func(b []byte) { copy(b[0:8], "NOTANIDX") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &rangeStore{objs: map[string][]byte{}}
			bent := append([]byte(nil), raw...)
			tc.bend(bent)
			// The ref still carries the honest size: that is the field the
			// signature covers, and the only one a reader may lean on.
			ref := publishIndex(t, store, "bent", bent, 4000)
			ref.Size = int64(len(raw))
			r := OpenReader(store, ref)
			if _, ok := r.Lookup(ctx, id(1)); ok {
				t.Error("a bent index answered a lookup")
			}
			if got := store.bytes.Load(); got > int64(len(raw)) {
				t.Errorf("rejecting a bent index moved %d bytes of a %d-byte object", got, len(raw))
			}
		})
	}
}

// A ref with no size is refused rather than read: every bound the windowed
// path applies is relative to it, so trusting the object to describe
// itself would be trusting it about how much of it to allocate.
func TestASizelessRefIsRefused(t *testing.T) {
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	raw, _ := buildIndex(t, 4, 10)
	ref := publishIndex(t, store, "small", raw, 40)
	ref.Size = 0
	if _, ok := OpenReader(store, ref).Lookup(ctx, id(0)); ok {
		t.Error("an index with no stated size was read")
	}
	if store.gets.Load() != 0 {
		t.Errorf("a sizeless ref cost %d request(s)", store.gets.Load())
	}
}

// An index that will not load is an index this mount does without. It must
// not be re-fetched on every lookup — that turns a missing object into a
// request per read — and it must not fail anything.
func TestAnIndexThatWillNotLoadIsAskedOnce(t *testing.T) {
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	r := OpenReader(store, superblock.IndexRef{Name: "absent", Size: 1 << 30})
	for i := 0; i < 20; i++ {
		if _, ok := r.Lookup(ctx, id(1)); ok {
			t.Fatal("an index that is not there answered")
		}
	}
	if got := store.gets.Load(); got > 1 {
		t.Errorf("a missing index was fetched %d times", got)
	}
}

// Hints is the read path's Set: newest index first, and the pack names it
// may produce readable without touching a single record.
func TestHintsPreferTheNewestIndexAndReportTheirPacks(t *testing.T) {
	windowed(t)
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}

	older := NewBuilder()
	newer := NewBuilder()
	for i := uint64(0); i < 5000; i++ {
		older.Add(id(i), "p-old")
	}
	for i := uint64(2500); i < 7500; i++ {
		newer.Add(id(i), "p-new")
	}
	refs := []superblock.IndexRef{
		publishIndex(t, store, "older", older.Encode(), 5000),
		publishIndex(t, store, "newer", newer.Encode(), 5000),
	}
	h := NewHints(store, refs)
	for _, tc := range []struct {
		n    uint64
		want string
	}{{100, "p-old"}, {3000, "p-new"}, {7000, "p-new"}} {
		got, ok := h.Lookup(ctx, id(tc.n))
		if !ok {
			t.Fatalf("entry %d is missing", tc.n)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("entry %d resolved to %v, want [%s]", tc.n, got, tc.want)
		}
	}
	if _, ok := h.Lookup(ctx, id(99_999)); ok {
		t.Error("an identity in neither index resolved")
	}

	store.reset()
	names, ok := h.readers[0].PackNames(ctx)
	if !ok || len(names) != 1 || names[0] != "p-old" {
		t.Errorf("pack names = %v (ok=%v), want [p-old]", names, ok)
	}
	if got := store.gets.Load(); got != 0 {
		t.Errorf("reading the pack names cost %d request(s); it is meant to come off the blob", got)
	}
}

// The real shape, at a size where fetching whole is the thing being
// avoided: an index over the threshold, read through its header.
func TestALargeIndexIsNotFetchedWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a multi-megabyte index")
	}
	ctx := context.Background()
	store := &rangeStore{objs: map[string][]byte{}}
	const packs, perPack = 600, 500 // 300,000 entries, over wholeFetchMax
	b := NewBuilder()
	for p := 0; p < packs; p++ {
		name := "p-" + strconv.Itoa(p)
		for e := 0; e < perPack; e++ {
			b.Add(id(uint64(p*perPack+e)), name)
		}
	}
	raw := b.Encode()
	if int64(len(raw)) <= wholeFetchMax {
		t.Fatalf("the fixture is %d bytes, under the %d-byte threshold", len(raw), wholeFetchMax)
	}
	r := OpenReader(store, publishIndex(t, store, "large", raw, packs*perPack))

	if _, ok := r.Lookup(ctx, id(150_000)); !ok {
		t.Fatal("a key in the index did not resolve")
	}
	resident := int64(len(r.blob)) + r.hdr.SampleBytes()
	t.Logf("%d entries in %s: %d request(s), %s moved, %s resident (blob %s + samples %s)",
		packs*perPack, human(int64(len(raw))), store.gets.Load(), human(store.bytes.Load()),
		human(resident), human(int64(len(r.blob))), human(r.hdr.SampleBytes()))
	if store.bytes.Load() >= int64(len(raw))/2 {
		t.Errorf("resolving one key moved %d of %d bytes", store.bytes.Load(), len(raw))
	}
	if resident >= int64(len(raw))/2 {
		t.Errorf("%d bytes stayed resident out of a %d-byte index", resident, len(raw))
	}
	// Spot-check the whole key space against the truth.
	ix, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	for n := uint64(0); n < uint64(packs*perPack); n += 997 {
		want, wantOK := ix.Lookup(id(n))
		got, gotOK := r.Lookup(ctx, id(n))
		if gotOK != wantOK || !equal(got, want) {
			t.Fatalf("entry %d: windowed %v/%v, whole %v/%v", n, got, gotOK, want, wantOK)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return strconv.FormatInt(n, 10) + " B"
	}
}
