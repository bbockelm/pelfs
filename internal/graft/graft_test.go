package graft

import (
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"

	"lukechampine.com/blake3"
)

// TestIndexRoundTrip is the format check: what a Builder encodes, Open
// decodes, and every block it recorded is found where it was put.
func TestIndexRoundTrip(t *testing.T) {
	b := NewBuilder(1 << 20)
	want := map[string]Loc{}
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("data/dir%d/file%d.bin", i%7, i)
		id := chunkid.Identity(blake3.Sum256([]byte(key)))
		l := Loc{Key: key, Off: int64(i) << 20, Length: 1 << 20}
		if err := b.Add(id, l); err != nil {
			t.Fatalf("Add: %v", err)
		}
		want[id.Hex()] = l
	}
	if b.Len() != 500 {
		t.Fatalf("Len = %d, want 500", b.Len())
	}
	ix, err := Open(b.Encode())
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
	b := NewBuilder(1 << 20)
	id := chunkid.Identity(blake3.Sum256([]byte("the same block twice")))
	if err := b.Add(id, Loc{Key: "a.bin", Off: 0, Length: 100}); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(id, Loc{Key: "b.bin", Off: 4096, Length: 100}); err != nil {
		t.Fatalf("a repeated identity must not be an error: %v", err)
	}
	if b.Len() != 1 {
		t.Fatalf("Len = %d, want 1: identical blocks share one location", b.Len())
	}
}

// TestIndexSizePerBlock measures what an index costs per block, because
// the honest answer to "how big can a graft be" is arithmetic on this
// number and the design doc quotes it.
func TestIndexSizePerBlock(t *testing.T) {
	const n = 20000
	b := NewBuilder(1 << 20)
	for i := 0; i < n; i++ {
		id := chunkid.Identity(blake3.Sum256([]byte(fmt.Sprintf("block-%d", i))))
		if err := b.Add(id, Loc{Key: fmt.Sprintf("obj%d.bin", i/64), Off: int64(i%64) << 20, Length: 1 << 20}); err != nil {
			t.Fatal(err)
		}
	}
	raw := b.Encode()
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
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", []byte("PELFSGR1")},
		{"wrong magic", append([]byte("NOTAGRFT"), make([]byte, 64)...)},
	} {
		if _, err := Open(tc.in); err == nil {
			t.Fatalf("%s: Open accepted bytes that are not an index", tc.name)
		}
	}
}
