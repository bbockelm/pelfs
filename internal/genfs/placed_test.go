package genfs_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// newTestVolumeKeyed is newTestVolume with a key table, for the questions
// that are only questions on an encrypted volume.
func newTestVolumeKeyed(t testing.TB, inner pelicanobj.Store, uuid string,
	dek, idKey []byte, keyTable []superblock.KeyEntry) *testvol.Volume {
	t.Helper()
	return testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, uuid),
		DEK:         dek,
		IdentityKey: idKey,
		KeyID:       1,
		KeyTable:    keyTable,
	})
}

// FS.Placed is the cross-generation dedup lookup, and its whole reason for
// existing rather than reusing the read path's locate is COST: a miss must
// not turn into a sweep of every pack in the generation. On new content
// every lookup misses, so a miss that swept would make writing a volume of
// unique bytes quadratic in the number of packs.
func TestPlacedNeverSweepsTheGeneration(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000d1")
	dir := v.Mkdir(1, "d")
	for i := 0; i < 12; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	packs := len(packsOf(t, inner, res.Superblock))
	if packs < 8 {
		t.Fatalf("volume has %d packs; the test needs many", packs)
	}

	fs := openFS(t, inner, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	inner.reset()
	// Twenty identities the volume does not hold. Each one is a miss, which
	// is the case that has to stay cheap.
	const misses = 20
	for i := range misses {
		var id chunkid.Identity
		id[0], id[1] = byte(i), 0xfe
		if _, ok := fs.Placed(ctx, id); ok {
			t.Fatalf("the generation claims to hold a chunk nobody wrote")
		}
	}
	got := inner.gets.Load()
	t.Logf("%d misses over a %d-pack generation cost %d pack request(s), %d in all, %d bytes",
		misses, packs, got, inner.all.Load(), inner.bytes.Load())
	// The bound is one sweep, not one lookup: whatever a miss does, it must
	// not be proportional to the pack count per lookup. A sweep of every
	// pack for every miss is 240 requests here; the whole point is that a
	// miss answers out of what is already in hand.
	if got >= int64(packs) {
		t.Errorf("%d misses cost %d pack request(s) over %d packs: a miss is sweeping the generation",
			misses, got, packs)
	}
}

// And a hit is a hit: the identities the generation does hold are found,
// with the stored length its own trailer states — which is the number a
// reader will range-read, and the only one a borrowed chunkref may claim.
func TestPlacedFindsWhatTheGenerationHolds(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	v := newTestVolume(t, base, "9efe7c40-0000-4000-8000-0000000000d2")
	body := pseudorandom(3<<20, 7)
	v.WriteFile(1, "big.bin", body)
	res := publishVolume(t, v, base, publish.Options{TargetPackSize: 512 << 10})

	fs := openFS(t, base, res.Superblock, genfs.Options{CacheDir: t.TempDir()})
	node, err := fs.Lookup(ctx, 1, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	content, err := fs.ContentOf(ctx, node.Inode)
	if err != nil {
		t.Fatal(err)
	}
	if len(content.Refs) == 0 {
		t.Fatal("the file has no chunkrefs")
	}
	for _, r := range content.Refs {
		id := chunkid.Identity(r.Identity)
		pl, ok := fs.Placed(ctx, id)
		if !ok {
			t.Fatalf("chunk %s is in the generation and Placed did not find it", id)
		}
		if pl.Length != r.CLen {
			t.Errorf("chunk %s: Placed says %d stored bytes, the chunkref says %d", id, pl.Length, r.CLen)
		}
		if pl.Pack == "" {
			t.Errorf("chunk %s: Placed named no pack", id)
		}
	}
}

// A volume with more than one data-encryption key is one where an entry's
// key id is not derivable from the writer's own, so there is no
// cross-generation dedup on it rather than a row naming the wrong key.
//
// Nothing in the tree mints a second DEK today — `pelfs volume create`
// makes one and every generation carries the key table forward verbatim —
// which is exactly why this is checked rather than assumed: the assumption
// is load-bearing and lives three packages away from the code that would
// break it.
func TestPlacedRefusesAVolumeWithTwoDataKeys(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	dek := pseudorandom(32, 3)
	idKey := pseudorandom(32, 4)
	keyTable := []superblock.KeyEntry{
		{ID: 1, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
		{ID: 2, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-id")},
	}
	v := newTestVolumeKeyed(t, base, "9efe7c40-0000-4000-8000-0000000000d3", dek, idKey, keyTable)
	body := pseudorandom(3<<20, 9)
	v.WriteFile(1, "big.bin", body)
	res := publishVolume(t, v, base, publish.Options{TargetPackSize: 512 << 10})

	fs := openFS(t, base, res.Superblock, genfs.Options{CacheDir: t.TempDir(), DEK: dek})
	node, err := fs.Lookup(ctx, 1, "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	content, err := fs.ContentOf(ctx, node.Inode)
	if err != nil {
		t.Fatal(err)
	}
	id := chunkid.Identity(content.Refs[0].Identity)
	if _, ok := fs.Placed(ctx, id); !ok {
		t.Fatal("one DEK: Placed should answer")
	}

	// The same generation, with a second DEK bolted onto its key table.
	// The document is not re-signed, which does not matter: Placed reads
	// the table it was given, and what is under test is the refusal.
	sb2 := *res.Superblock
	sb2.KeyTable = append(append([]superblock.KeyEntry(nil), keyTable...),
		superblock.KeyEntry{ID: 3, Kind: superblock.KeyKindDEK,
			Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("second-dek")})
	fs2 := openFS(t, base, &sb2, genfs.Options{CacheDir: t.TempDir(), DEK: dek})
	if _, ok := fs2.Placed(ctx, id); ok {
		t.Error("two DEKs: Placed answered, so a borrowed row would name a key id nothing checked")
	}
	// Reading is unaffected: a reader takes the key id from the row it
	// follows, which is why only the WRITER's question is refused.
	node2, err := fs2.Lookup(ctx, 1, "big.bin")
	if err != nil {
		t.Fatalf("a second key in the table must not stop a lookup: %v", err)
	}
	got := make([]byte, node2.Length)
	if _, err := fs2.Read(ctx, node2.Inode, 0, got); err != nil {
		t.Errorf("a second key in the table must not stop a read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Error("the file does not read back byte-exact with a second key in the table")
	}
}
