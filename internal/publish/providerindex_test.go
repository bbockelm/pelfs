package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/publish"
)

// A writable mount's content is packed by the MEMTABLE, not by the seal,
// so an index built from the seal's own packer alone would answer for
// catalogs and shards and miss nearly all the data — leaving a reader on
// the trailer fallback for exactly the lookups the index exists to
// answer. The source reports what it placed instead.
func TestTheIndexCoversContentTheSourcePacked(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gen0, err := publish.InitVolume(ctx, publish.Options{
		Inner: obj, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0x1d, 0xec},
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	src := newMemSource(t, obj)
	bodies := map[string][]byte{
		"a.bin": bytesPattern(150000, 21),
		"b.bin": bytesPattern(90000, 22),
	}
	for _, name := range []string{"a.bin", "b.bin"} {
		src.write(t, name, bodies[name])
	}
	if err := src.store.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	res, err := publish.Publish(ctx, publish.Options{
		Source: src, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: gen0.Superblock, PrevRaw: gen0.Raw,
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(res.Superblock.PackIndexes) == 0 {
		t.Fatal("the generation lists no index")
	}
	indexes, err := mpi.FetchAll(ctx, obj, res.Superblock.PackIndexes)
	if err != nil {
		t.Fatal(err)
	}
	set := mpi.NewSet(indexes)

	// Every chunk the memtable placed must resolve, and to the pack that
	// actually holds it.
	packs := map[string]struct{}{}
	for _, p := range src.store.Packs() {
		packs[p.Name] = struct{}{}
	}
	checked := 0
	src.store.EachPlacedChunk(func(idHex, pack string) {
		var id [32]byte
		raw, err := hex.DecodeString(idHex)
		if err != nil || len(raw) != len(id) {
			t.Fatalf("chunk key %q is not an identity", idHex)
		}
		copy(id[:], raw)
		got, ok := set.Lookup(id)
		if !ok {
			t.Fatalf("chunk %s is not in the generation's index", idHex[:16])
		}
		found := false
		for _, name := range got {
			if name == pack {
				found = true
			}
		}
		if !found {
			t.Fatalf("chunk %s resolved to %v, want the pack that holds it (%s)", idHex[:16], got, pack)
		}
		checked++
	})
	if checked == 0 {
		t.Fatal("the memtable placed no chunks, so this test proved nothing")
	}
	t.Logf("%d chunks placed by the source, all resolvable through the generation's index", checked)

	// And it still reads back, which is what says the index did not
	// replace correctness with speed.
	sealed := openGenfs(t, obj, res.Superblock, nil)
	for name, want := range bodies {
		n, err := sealed.Lookup(ctx, genfs.RootInode, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		got := make([]byte, n.Length)
		if _, err := sealed.Read(ctx, n.Inode, 0, got); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s does not read back byte-exact", name)
		}
	}
}
