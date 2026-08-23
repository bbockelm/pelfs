package graft

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/superblock"

	"lukechampine.com/blake3"
)

// buildIndex is the shared fixture: n blocks spread over n/perObj source
// objects, encoded into a finished index object.
func buildIndex(t *testing.T, n, perObj int) ([]byte, map[string]Loc) {
	t.Helper()
	w, err := NewWriter(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close() //nolint:errcheck
	want := map[string]Loc{}
	batch := make([]Block, 0, 256)
	for i := 0; i < n; i++ {
		id := chunkid.Identity(blake3.Sum256([]byte(fmt.Sprintf("block-%d", i))))
		l := Loc{Key: fmt.Sprintf("data/dir%d/obj%d.bin", i/(perObj*8), i/perObj), Off: int64(i%perObj) << 20, Length: 1 << 20}
		batch = append(batch, Block{ID: id, Loc: l})
		want[id.Hex()] = l
		if len(batch) == cap(batch) {
			if err := w.Add(batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := w.Add(batch); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	blocks, err := w.Encode(&buf)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if blocks != n {
		t.Fatalf("encoded %d blocks, want %d", blocks, n)
	}
	return buf.Bytes(), want
}

// TestIndexRoundTrip is the format check: what a Writer encodes, Open
// decodes, and every block it recorded is found where it was put.
func TestIndexRoundTrip(t *testing.T) {
	raw, want := buildIndex(t, 500, 64)
	ix, err := Open(raw)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ix.Len() != 500 {
		t.Fatalf("decoded Len = %d, want 500", ix.Len())
	}
	if ix.Block() != 1<<20 {
		t.Fatalf("decoded Block = %d, want %d", ix.Block(), 1<<20)
	}
	for hex, w := range want {
		id, err := chunkid.ParseIdentity(hex)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ix.Lookup(id[:])
		if !ok {
			t.Fatalf("identity %s is not in the index", hex)
		}
		if got != w {
			t.Fatalf("identity %s: got %+v, want %+v", hex, got, w)
		}
	}
	// An identity nothing recorded must miss rather than resolve to
	// something adjacent: a graft that answered approximately would serve
	// the wrong bytes, which is the one outcome the whole design refuses.
	absent := chunkid.Identity(blake3.Sum256([]byte("nothing put this here")))
	if _, ok := ix.Lookup(absent[:]); ok {
		t.Fatal("an identity that was never added resolved")
	}
}

// TestDuplicateBlocksShareOneLocation pins the dedup-within-a-graft rule:
// the same bytes in two objects need one location, and adding the second
// is not an error.
func TestDuplicateBlocksShareOneLocation(t *testing.T) {
	w, err := NewWriter(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	id := chunkid.Identity(blake3.Sum256([]byte("the same block twice")))
	if err := w.Add([]Block{
		{ID: id, Loc: Loc{Key: "a.bin", Off: 0, Length: 100}},
		{ID: id, Loc: Loc{Key: "b.bin", Off: 4096, Length: 100}},
	}); err != nil {
		t.Fatalf("a repeated identity must not be an error: %v", err)
	}
	var buf bytes.Buffer
	n, err := w.Encode(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("encoded %d blocks, want 1: identical blocks share one location", n)
	}
	ix, err := Open(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ix.Lookup(id[:]); !ok {
		t.Fatal("the collapsed identity does not resolve")
	}
}

// TestIndexSizePerBlock measures what an index costs per block, because
// the honest answer to "how big can a graft be" is arithmetic on this
// number and the design doc quotes it.
func TestIndexSizePerBlock(t *testing.T) {
	const n = 20000
	raw, _ := buildIndex(t, n, 64)
	per := float64(len(raw)) / float64(n)
	t.Logf("%d blocks index to %d bytes: %.1f bytes per block", n, len(raw), per)
	// 32-byte identity + 16-byte record is the floor; the sampled index
	// and the object-key string table are the rest. A regression past 64
	// means something started storing per-block state it should not.
	if per > 64 {
		t.Fatalf("%.1f bytes per block is over the 64-byte ceiling", per)
	}
}

// TestOpenRejectsGarbage: an index that is not one must not decode into a
// resolver that answers confidently.
func TestOpenRejectsGarbage(t *testing.T) {
	v1 := make([]byte, 64)
	copy(v1, magic)
	v1[8] = 1
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", []byte("PELFSGR1")},
		{"wrong magic", append([]byte("NOTAGRFT"), make([]byte, 64)...)},
		{"version 1, whose string table no prefix can reach", v1},
	} {
		if _, err := Open(tc.in); err == nil {
			t.Fatalf("%s: Open accepted bytes that are not an index this build reads", tc.name)
		}
	}
}

// TestWindowedAndWholeReadersAgree is the claim the 10 TB case rests on:
// an index too large to hold answers exactly what the same index held
// whole answers, and it does so WITHOUT fetching itself.
func TestWindowedAndWholeReadersAgree(t *testing.T) {
	const n = 20000
	raw, want := buildIndex(t, n, 64)
	obj := newMemStore()
	sum := blake3.Sum256(raw)
	obj.put(IndexKey(sum), raw, time.Unix(0, 0))
	ent := superblock.GraftEntry{
		Path: "/ext", Source: "mem://ext", Index: sum,
		Size: int64(len(raw)), Block: 1 << 20, Blocks: uint64(n),
	}
	ctx := context.Background()

	// Whole, which is what a small index gets.
	whole := OpenReader(obj, ent)
	if err := whole.Load(ctx); err != nil {
		t.Fatalf("whole Load: %v", err)
	}
	if whole.Windowed() {
		t.Fatal("an index under the whole-fetch ceiling was windowed")
	}

	// Windowed, by moving the ceiling under this fixture rather than
	// building a 4 MiB one.
	old := wholeFetchMax
	wholeFetchMax = 1 << 10
	defer func() { wholeFetchMax = old }()
	obj.bytes.Store(0)
	win := OpenReader(obj, ent)
	if err := win.Load(ctx); err != nil {
		t.Fatalf("windowed Load: %v", err)
	}
	if !win.Windowed() {
		t.Fatal("an index over the ceiling was fetched whole")
	}
	resident := obj.bytes.Load()
	if resident >= int64(len(raw)) {
		t.Fatalf("the windowed reader moved %d bytes to load a %d-byte index; it fetched it whole",
			resident, len(raw))
	}
	t.Logf("a %d-byte index loaded from %d bytes of prefix (%.1f%%)",
		len(raw), resident, 100*float64(resident)/float64(len(raw)))

	for hex, wantLoc := range want {
		id, err := chunkid.ParseIdentity(hex)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := win.Lookup(ctx, id[:])
		if err != nil || !ok {
			t.Fatalf("windowed lookup of %s: ok=%v err=%v", hex, ok, err)
		}
		if got != wantLoc {
			t.Fatalf("windowed lookup of %s: got %+v, want %+v", hex, got, wantLoc)
		}
		gotWhole, okWhole, err := whole.Lookup(ctx, id[:])
		if err != nil || !okWhole || gotWhole != got {
			t.Fatalf("the two readers disagree about %s", hex)
		}
	}
	absent := chunkid.Identity(blake3.Sum256([]byte("nothing put this here")))
	if _, ok, err := win.Lookup(ctx, absent[:]); ok || err != nil {
		t.Fatalf("an absent identity must MISS rather than error or resolve: ok=%v err=%v", ok, err)
	}
	// The object list comes out of the string table, so it costs nothing
	// in either mode — which is what fsck's cheap mode needs.
	objs, err := win.Objects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := (n + 63) / 64; len(objs) != want {
		t.Fatalf("windowed Objects() returned %d objects, want %d", len(objs), (n+63)/64)
	}
}

// TestWindowedReaderRefusesAnIndexThatDoesNotFitItsOwnSize pins the bound
// that replaces the whole-object hash: every length off the wire is held
// against the SIGNED size before anything is allocated.
func TestWindowedReaderRefusesAnIndexThatDoesNotFitItsOwnSize(t *testing.T) {
	raw, _ := buildIndex(t, 5000, 64)
	obj := newMemStore()
	sum := blake3.Sum256(raw)
	obj.put(IndexKey(sum), raw, time.Unix(0, 0))
	old := wholeFetchMax
	wholeFetchMax = 1 << 10
	defer func() { wholeFetchMax = old }()
	// The generation says the object is far smaller than it is, so its
	// own header describes more than the signature covers.
	r := OpenReader(obj, superblock.GraftEntry{
		Path: "/ext", Index: sum, Size: 4096, Blocks: 5000,
	})
	if err := r.Load(context.Background()); err == nil {
		t.Fatal("a reader accepted an index whose header describes more than its signed size")
	}
}

// TestWholeFetchStillChecksTheHash: below the ceiling the check is free,
// so it is kept, and a corrupted index is one clear failure at mount
// rather than a confusing one per file.
func TestWholeFetchStillChecksTheHash(t *testing.T) {
	raw, _ := buildIndex(t, 100, 16)
	obj := newMemStore()
	sum := blake3.Sum256(raw)
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 0xff
	obj.put(IndexKey(sum), bad, time.Unix(0, 0))
	r := OpenReader(obj, superblock.GraftEntry{Path: "/ext", Index: sum, Size: int64(len(raw))})
	err := r.Load(context.Background())
	if err == nil {
		t.Fatal("a whole-fetched index that does not hash to what the superblock says was accepted")
	}
}
