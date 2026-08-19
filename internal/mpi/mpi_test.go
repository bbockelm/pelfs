package mpi

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
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
			b.Add(id(n), pack)
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
		packs, ok := ix.Lookup(id(n))
		if !ok {
			t.Fatalf("entry %d is missing", n)
		}
		want := "p-" + strconv.Itoa(int(n)/50)
		if len(packs) != 1 || packs[0] != want {
			t.Fatalf("entry %d resolved to %v, want [%s]", n, packs, want)
		}
	}
	if _, ok := ix.Lookup(id(999999)); ok {
		t.Fatal("an identity that was never added resolved")
	}
	t.Logf("2000 entries across 40 packs in %d bytes (%d per entry)", len(raw), len(raw)/2000)
}

// A truncated key can only be a false positive, so a collision is
// RECORDED rather than resolved: both packs are named, and the caller
// looks in each until one's trailer confirms the full identity.
func TestATruncatedKeyCollisionNamesBothPacks(t *testing.T) {
	var a, bID [32]byte
	for i := 0; i < KeyLen; i++ {
		a[i], bID[i] = 0x11, 0x11
	}
	a[31], bID[31] = 1, 2 // same 12-byte prefix, different identities

	b := NewBuilder()
	b.Add(a, "p-first")
	b.Add(bID, "p-second")
	ix, err := Open(b.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if ix.Len() != 1 {
		t.Fatalf("%d entries for one shared prefix, want 1", ix.Len())
	}
	for _, want := range [][32]byte{a, bID} {
		packs, ok := ix.Lookup(want)
		if !ok {
			t.Fatal("the colliding prefix does not resolve")
		}
		if len(packs) != 2 || packs[0] != "p-first" || packs[1] != "p-second" {
			t.Fatalf("collision resolved to %v, want both packs", packs)
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
	older.Add(id(1), "p-old")
	newer := NewBuilder()
	newer.Add(id(1), "p-new")
	o, err := Open(older.Encode())
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(newer.Encode())
	if err != nil {
		t.Fatal(err)
	}
	set := NewSet([]*Index{o, n})
	packs, ok := set.Lookup(id(1))
	if !ok {
		t.Fatal("missing")
	}
	if len(packs) != 1 || packs[0] != "p-new" {
		t.Errorf("resolved to %v, want the newest index's p-new", packs)
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
	var refs []superblock.IndexRef
	for i := 0; i < 8; i++ {
		b := NewBuilder()
		b.Add(id(uint64(i)), "p-"+strconv.Itoa(i))
		raw := b.Encode()
		name := "mpi-" + strconv.Itoa(i)
		store.objs[Dir+"/"+name] = raw
		refs = append(refs, superblock.IndexRef{Name: name, Hash: blake3.Sum256(raw), Size: int64(len(raw))})
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
	good.Add(id(1), "p-0")
	raw := good.Encode()
	store.objs[Dir+"/ok"] = raw
	store.objs[Dir+"/bad"] = append([]byte(nil), raw...)

	refs := []superblock.IndexRef{
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

// Merging is how a large index gets built without one ever being held:
// a cursor per input, newest last. It is also what a consolidation does,
// so the property that matters is that the newest placement wins.
func TestMergeTakesTheNewestPlacement(t *testing.T) {
	older := NewBuilder()
	for i := uint64(0); i < 3000; i++ {
		older.Add(id(i), "p-old")
	}
	newer := NewBuilder()
	for i := uint64(1500); i < 4500; i++ {
		newer.Add(id(i), "p-new")
	}
	o, err := Open(older.Encode())
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(newer.Encode())
	if err != nil {
		t.Fatal(err)
	}
	merged, err := Open(Merge([]*Index{o, n}))
	if err != nil {
		t.Fatal(err)
	}
	if merged.Len() != 4500 {
		t.Fatalf("merged index holds %d entries, want 4500", merged.Len())
	}
	for i := uint64(0); i < 4500; i++ {
		packs, ok := merged.Lookup(id(i))
		if !ok {
			t.Fatalf("entry %d is missing from the merge", i)
		}
		want := "p-old"
		if i >= 1500 {
			want = "p-new"
		}
		if len(packs) != 1 || packs[0] != want {
			t.Fatalf("entry %d = %v, want [%s] (newest placement wins)", i, packs, want)
		}
	}
	t.Logf("two 3000-entry indexes merged to %d entries", merged.Len())
}

// The in-memory merge is the spooling one over a buffer, so the two must
// produce the same bytes — an index is content-addressed, and a merge
// that named the same content differently depending on where its records
// were parked would upload the same index twice.
func TestSpooledAndInMemoryMergesAgreeByteForByte(t *testing.T) {
	// Overlapping keys, colliding keys (two packs for one key), and packs
	// whose name lists repeat, so the strings blob has something to intern.
	older, newer := NewBuilder(), NewBuilder()
	for i := uint64(0); i < 4000; i++ {
		older.Add(id(i), "p-"+strconv.Itoa(int(i)/97))
		if i%13 == 0 {
			older.Add(id(i), "p-collide")
		}
	}
	for i := uint64(2000); i < 7000; i++ {
		newer.Add(id(i), "p-"+strconv.Itoa(int(i)/89))
	}
	o, err := Open(older.Encode())
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(newer.Encode())
	if err != nil {
		t.Fatal(err)
	}

	spool, err := os.CreateTemp(t.TempDir(), "merge-*")
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close() //nolint:errcheck
	var streamed bytes.Buffer
	if _, _, err := MergeTo(&streamed, spool, []*Index{o, n}); err != nil {
		t.Fatal(err)
	}
	inMemory := Merge([]*Index{o, n})
	if !bytes.Equal(streamed.Bytes(), inMemory) {
		t.Fatalf("the spooled merge is %d bytes and the in-memory one %d; they must be the same index",
			streamed.Len(), len(inMemory))
	}

	// And the bytes are an index that still answers, including for the
	// collision, which is the entry a merge is likeliest to lose.
	merged, err := Open(streamed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if packs, ok := merged.Lookup(id(13)); !ok || len(packs) != 2 {
		t.Fatalf("the colliding key resolved to %v, want both packs", packs)
	}
	for i := uint64(0); i < 7000; i++ {
		if _, ok := merged.Lookup(id(i)); !ok {
			t.Fatalf("entry %d is missing from the spooled merge", i)
		}
	}
}
