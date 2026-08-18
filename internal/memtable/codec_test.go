package memtable

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// compressible is data zstd can do something with, so "the packer
// compresses" is a claim the bytes on the wire can settle.
func compressible(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + i%7)
	}
	return out
}

// A session that packs as it writes must produce the objects a seal would
// have produced, or it is not writing the same format. Compression is the
// visible half of that: without it every session upload is larger than
// the equivalent seal for no reason but which code path ran.
func TestPackedChunksAreCompressed(t *testing.T) {
	ctx := context.Background()
	s, obj := newTestStore(t, 1<<20, Hooks{})
	body := compressible(200000)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	_, sent := obj.stats()
	if sent >= int64(len(body)) {
		t.Errorf("uploaded %d bytes for %d bytes of compressible content; the packer is not compressing",
			sent, len(body))
	}
	t.Logf("%d bytes of compressible content uploaded as %d", len(body), sent)
	if got := readAll(t, s, 1); !bytes.Equal(got, body) {
		t.Fatal("compressed content does not read back byte-exact")
	}
}

// An encrypted volume is served by the same path, and the test is the one
// that matters for encryption: the plaintext must not be in the objects.
func TestEncryptedVolumeKeepsPlaintextOutOfPacks(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	dek := bytes.Repeat([]byte{0x5a}, 32)
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil), DEK: dek, KeyID: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	// Incompressible, so a plaintext store would leave these bytes
	// verbatim in a pack and the search below would find them.
	secret := fill(120000, 101)
	if err := s.Write(ctx, 1, 0, secret); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if obj.contains(secret[:2048]) {
		t.Fatal("plaintext reached the federation from an encrypted volume")
	}
	// And it still reads back, which is what says the key is actually
	// being applied in both directions rather than the bytes being lost.
	if got := readAll(t, s, 1); !bytes.Equal(got, secret) {
		t.Fatal("encrypted content does not read back byte-exact")
	}

	// The rows a seal writes have to name the key, or a reader has no way
	// to know what to do with the bytes.
	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	if len(refs) == 0 {
		t.Fatal("no rows rendered")
	}
	for i, r := range refs {
		if r.KeyID != 7 {
			t.Fatalf("row %d names key %d, want the volume's 7", i, r.KeyID)
		}
		if r.CLen == r.LLen && r.Alg != 0 {
			t.Fatalf("row %d claims algorithm %d but the same stored and logical length", i, r.Alg)
		}
	}
}

// A compressed chunk has no addressable interior, so a partial read has
// to fetch and decode the whole entry. The shapes here are the ones that
// would silently return the wrong bytes if the skip arithmetic moved from
// the pack offset to the decoded buffer incorrectly.
func TestPartialReadsOfCompressedChunks(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t, 1<<20, Hooks{})
	body := compressible(150000)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ off, n int64 }{
		{0, 1}, {1, 4095}, {5000, 7}, {12345, 20000}, {int64(len(body)) - 3, 3},
	} {
		got := make([]byte, r.n)
		n, err := s.Read(ctx, 1, r.off, got)
		if err != nil {
			t.Fatalf("read [%d,+%d): %v", r.off, r.n, err)
		}
		if int64(n) != r.n || !bytes.Equal(got[:n], body[r.off:r.off+r.n]) {
			t.Fatalf("read [%d,+%d) returned the wrong bytes", r.off, r.n)
		}
	}
}
