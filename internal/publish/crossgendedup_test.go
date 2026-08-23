package publish_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// newTestVolumeEncrypted is newTestVolume with a key table, so that the
// dedup question can be asked of a volume where identity is keyed and
// entries are sealed.
func newTestVolumeEncrypted(t *testing.T, inner *countingObjStore, uuid string, dek, idKey []byte) *testvol.Volume {
	t.Helper()
	return testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, uuid),
		DEK:         dek,
		IdentityKey: idKey,
		KeyID:       1,
		KeyTable: []superblock.KeyEntry{
			{ID: 1, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 2, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})
}

// CROSS-GENERATION DEDUP ON THE DEFAULT WRITE PATH.
//
// The claim these tests exist for is a bandwidth claim, so they assert on
// BYTES PUT and not on a counter: a counter can say dedup happened while
// the bytes went out anyway, and the counter was the thing that was wrong
// (docs/design-apptainer.md, W2 — `write.deduped_chunks` read 0 for the
// path that was actually deduplicating).
//
// THE TRAP, recorded because it cost the previous attempt at this: a seal
// folds the chunkrefs it CARRIES FORWARD into its own dedup set
// (publish.rememberReusedChunks), so a test that writes a copy of a file
// beside the original proves nothing — the copy dedups against the walk,
// with or without the write path knowing anything. Every test here
// therefore leaves the original in a subtree the second generation does
// not touch, so catalog reuse prunes it and the walk never sees its rows,
// and each one asserts publish's own ChunksDeduped is ZERO. That is what
// makes the saving attributable to the write path.

// gen2 is a second generation written through a memtable over base: the
// default write path, which packs and uploads DURING the session.
type gen2 struct {
	store *memtable.Store
	ov    *overlay.FS
	base  *genfs.FS
}

func openGen2(t *testing.T, obj *countingObjStore, sb *superblock.Superblock, dek []byte,
	ring int, chunks chunkid.Options, idKey []byte, keyID int64) *gen2 {
	t.Helper()
	base := openGenfs(t, obj, sb, dek)
	store, err := memtable.New(memtable.Options{
		Dir: t.TempDir(), TableSize: ring, Obj: obj, Base: base,
		Chunk: chunks, Hasher: chunkid.NewHasher(idKey), DEK: dek, KeyID: keyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
		Memtable:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ov.Close() })
	return &gen2{store: store, ov: ov, base: base}
}

// write creates one file under the root and writes it whole.
func (g *gen2) write(t *testing.T, name string, body []byte) {
	t.Helper()
	ctx := context.Background()
	n, err := g.ov.Create(ctx, genfs.RootInode, name, 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.ov.Write(ctx, n.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
}

// readBack reads a file out of a published generation the way a mount
// does, which is the only proof that a row naming somebody else's pack is
// a row that works.
func readBack(t *testing.T, obj *countingObjStore, sb *superblock.Superblock, dek []byte, name string) []byte {
	t.Helper()
	ctx := context.Background()
	fs := openGenfs(t, obj, sb, dek)
	node, err := fs.Lookup(ctx, genfs.RootInode, name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	got := make([]byte, node.Length)
	if _, err := fs.Read(ctx, node.Inode, 0, got); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return got
}

// TestAByteIdenticalFileInALaterGenerationUploadsAlmostNothing is the
// headline. Production chunker parameters, because the threshold that
// governs whether the index is consulted at all is derived from the size
// of a lookup and a test-sized chunk would sit under it.
func TestAByteIdenticalFileInALaterGenerationUploadsAlmostNothing(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	v := newTestVolume(t, obj, "5ea15ea1-0007-4000-8000-000000000001")

	// Generation 1, in a subtree generation 2 will not touch.
	body := bytesPattern(6<<20, 0x5170)
	arch := v.Mkdir(genfs.RootInode, "archive")
	v.WriteFile(arch, "image.bin", body)
	head := v.Publish(publish.Options{})

	// Generation 2: the same bytes, under a different name, written
	// through the memtable.
	g := openGen2(t, obj, head.Superblock, nil, 12<<20, chunkid.Options{}, nil, 0)
	before := obj.putBytes.Load()
	g.write(t, "again.bin", body)
	if err := g.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: g.ov, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: v.SigningKey(), Prev: head.Superblock, PrevRaw: head.Raw,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	moved := obj.putBytes.Load() - before

	if res.Stats.ChunksDeduped != 0 {
		t.Fatalf("the SEAL deduped %d chunks, so this test is not measuring the write path",
			res.Stats.ChunksDeduped)
	}
	st := g.store.Stats()
	if st.BaseDedupedChunks == 0 {
		t.Errorf("no chunk was recognised as already stored (%+v)", st)
	}
	if st.BaseDedupedBytes != int64(len(body)) {
		t.Errorf("recognised %d bytes of the %d-byte file as already stored",
			st.BaseDedupedBytes, len(body))
	}
	// The ceiling is the user-visible claim: a 6 MiB re-push must cost the
	// generation's metadata and nothing else. Without cross-generation
	// dedup this is the whole 6 MiB.
	const ceiling = 256 << 10
	if moved > ceiling {
		t.Errorf("re-pushing a %d-byte file moved %d bytes; the ceiling is %d",
			len(body), moved, ceiling)
	}
	if got := readBack(t, obj, res.Superblock, nil, "again.bin"); !bytes.Equal(got, body) {
		t.Fatal("the deduplicated file does not read back byte-exact")
	}
}

// A file that only PARTLY repeats an earlier generation pays for the part
// that is new and nothing for the part that is not. The shared prefix
// starts at offset zero, so the chunker cuts the same boundaries over it
// as it did the first time — which is the property content-defined
// chunking exists for and the reason this is not just the whole-file case
// again.
func TestAPartlyRepeatedFilePaysOnlyForWhatIsNew(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	v := newTestVolume(t, obj, "5ea15ea1-0007-4000-8000-000000000002")

	// Production chunker parameters, so the two generations cut the same
	// boundaries — publish's own chunker is hardcoded to them — which
	// makes a fixture that says anything about the JOIN necessarily larger
	// than the 16 MiB maximum chunk.
	const overlap = 48 << 20
	shared := bytesPattern(overlap, 0x5171)
	arch := v.Mkdir(genfs.RootInode, "archive")
	v.WriteFile(arch, "image.bin", shared)
	head := v.Publish(publish.Options{})

	body := append(append([]byte(nil), shared...), bytesPattern(4<<20, 0x5172)...)
	g := openGen2(t, obj, head.Superblock, nil, 72<<20, chunkid.Options{}, nil, 0)
	before := obj.putBytes.Load()
	g.write(t, "derived.bin", body)
	if err := g.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: g.ov, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: v.SigningKey(), Prev: head.Superblock, PrevRaw: head.Raw,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	moved := obj.putBytes.Load() - before
	if res.Stats.ChunksDeduped != 0 {
		t.Fatalf("the SEAL deduped %d chunks, so this test is not measuring the write path",
			res.Stats.ChunksDeduped)
	}
	st := g.store.Stats()
	if st.BaseDedupedBytes == 0 {
		t.Fatalf("none of the shared prefix was recognised (%+v)", st)
	}
	// The bound is structural rather than typical. Boundaries re-converge
	// AFTER the join and not at it, so the one chunk straddling the end of
	// the shared prefix is genuinely new content and has to be stored;
	// nothing else in the overlap does. One chunk is at most MaxSize, so
	// everything past that must dedup, and a run that stores more than the
	// new content plus one chunk is the mechanism not working.
	const slack = chunkid.DefaultMaxSize
	if st.BaseDedupedBytes < overlap-slack {
		t.Errorf("recognised only %d bytes of a %d-byte overlap; one straddling chunk is %d at worst",
			st.BaseDedupedBytes, overlap, slack)
	}
	if moved > int64(len(body))-overlap+slack {
		t.Errorf("a %d-byte file with a %d-byte overlap moved %d bytes",
			len(body), overlap, moved)
	}
	if got := readBack(t, obj, res.Superblock, nil, "derived.bin"); !bytes.Equal(got, body) {
		t.Fatal("the partly-deduplicated file does not read back byte-exact")
	}
}

// An encrypted volume dedups too, and it has to: identity is keyed BLAKE3
// over the PLAINTEXT there (internal/chunkid), so the dedup domain is the
// volume and nothing about the encryption narrows it. What a reused entry
// carries with it is its own nonce and its own ciphertext, together, so
// nothing is encrypted twice under one nonce — the reuse encrypts nothing
// at all.
func TestAnEncryptedVolumeDedupsAcrossGenerations(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	dek := bytesPattern(32, 0x11)
	idKey := bytesPattern(32, 0x22)
	v := newTestVolumeEncrypted(t, obj, "5ea15ea1-0007-4000-8000-000000000003", dek, idKey)

	body := bytesPattern(6<<20, 0x5173)
	arch := v.Mkdir(genfs.RootInode, "archive")
	v.WriteFile(arch, "image.bin", body)
	head := v.Publish(publish.Options{})

	g := openGen2(t, obj, head.Superblock, dek, 12<<20, chunkid.Options{}, idKey, 1)
	before := obj.putBytes.Load()
	g.write(t, "again.bin", body)
	if err := g.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: g.ov, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: v.SigningKey(), Prev: head.Superblock, PrevRaw: head.Raw,
		DEK: dek, IdentityKey: idKey, KeyID: 1, KeyTable: head.Superblock.KeyTable,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	moved := obj.putBytes.Load() - before
	if st := g.store.Stats(); st.BaseDedupedBytes != int64(len(body)) {
		t.Errorf("encrypted volume recognised %d of %d bytes (%+v)", st.BaseDedupedBytes, len(body), st)
	}
	const ceiling = 256 << 10
	if moved > ceiling {
		t.Errorf("re-pushing a %d-byte file onto an encrypted volume moved %d bytes", len(body), moved)
	}
	// The proof that the reused entry is decodable with the alg and key id
	// the row claims: the alg was DERIVED here, not read anywhere.
	if got := readBack(t, obj, res.Superblock, dek, "again.bin"); !bytes.Equal(got, body) {
		t.Fatal("the deduplicated file does not read back byte-exact on an encrypted volume")
	}
}
