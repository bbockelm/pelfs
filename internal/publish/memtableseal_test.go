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
)

// The whole write path through a real overlay: a mount whose bytes live
// in the memtable, sealed by publish, read back through genfs.
//
// This is the assertion the staging directory is judged against. The seal
// opens no file and chunks nothing — every byte was packed and uploaded
// while the writes were happening — and the generation it produces is an
// ordinary one, indistinguishable to a reader from one a staging overlay
// would have made.
func TestSealAnOverlayWhoseContentIsAMemtable(t *testing.T) {
	ctx := context.Background()
	obj := &countingObjStore{Store: newInner(t)}
	v := newTestVolume(t, obj, "5ea15ea1-0001-4000-8000-000000000001")
	baseBody := bytesPattern(120000, 3)
	v.WriteFile(genfs.RootInode, "inherited.bin", baseBody)
	v.WriteFile(genfs.RootInode, "untouched.txt", []byte("never written by the session"))
	head := v.Publish(publish.Options{})

	base := openGenfs(t, obj, head.Superblock, nil)
	store, err := memtable.New(memtable.Options{
		Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj, Base: base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck

	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
		Memtable:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ov.Close() //nolint:errcheck

	// A new file, and one byte into a file that came from the base — the
	// case that costs a staging overlay the whole file.
	want := map[string][]byte{}
	fresh := bytesPattern(90000, 4)
	n, err := ov.Create(ctx, genfs.RootInode, "written.bin", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, fresh); err != nil {
		t.Fatal(err)
	}
	want["written.bin"] = fresh

	inherited := lookupInode(t, ov, "inherited.bin")
	if _, err := ov.Write(ctx, inherited, 1000, []byte("PATCH")); err != nil {
		t.Fatal(err)
	}
	patched := append([]byte(nil), baseBody...)
	copy(patched[1000:], "PATCH")
	want["inherited.bin"] = patched
	want["untouched.txt"] = []byte("never written by the session")

	// Everything the session wrote reaches the federation here, not at the
	// seal. This is the checkpoint a mount would run under write pressure.
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	sessionPuts := obj.puts

	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: obj, SpoolDir: t.TempDir(),
		SigningKey: v.SigningKey(), Prev: head.Superblock, PrevRaw: head.Raw,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if res.Stats.ChunksAdded != 0 {
		t.Errorf("the seal chunked %d new chunks; the memtable had already packed the session", res.Stats.ChunksAdded)
	}
	if res.Stats.ProvidedFiles == 0 {
		t.Errorf("no file was provided by the overlay (%+v)", res.Stats)
	}

	// Every pack the session cut must be listed, or its chunkrefs name
	// bytes retention is entitled to delete.
	listed := map[string]bool{}
	for _, e := range res.Superblock.PackList {
		listed[e.Name] = true
	}
	for _, sp := range store.Packs() {
		if !listed[sp.Name] {
			t.Fatalf("pack %s holds session content and is not listed in the generation", sp.Name)
		}
	}

	sealed := openGenfs(t, obj, res.Superblock, nil)
	for name, body := range want {
		node, err := sealed.Lookup(ctx, genfs.RootInode, name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if node.Length != int64(len(body)) {
			t.Fatalf("%s: length %d, want %d", name, node.Length, len(body))
		}
		got := make([]byte, node.Length)
		if _, err := sealed.Read(ctx, node.Inode, 0, got); err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("%s does not read back byte-exact from the sealed generation", name)
		}
	}
	// What the patch cost. Adoption moved nothing, and the re-chunk is
	// bounded by the CHUNKS it straddled — never by the file — so the
	// bound is stated in terms of the base's own chunk sizes. Here the
	// base published this file as a single chunk, so straddling it costs
	// the whole thing: the bound is a property of the chunk size the base
	// chose, and this is what it looks like when that size is the file.
	st := store.Stats()
	if st.AdoptedBytes != int64(len(baseBody)) || st.AdoptedByReading != 0 {
		t.Errorf("adopted %d bytes (%d by reading), want %d taken by reference",
			st.AdoptedBytes, st.AdoptedByReading, len(baseBody))
	}
	content, err := base.ContentOf(ctx, inherited)
	if err != nil {
		t.Fatal(err)
	}
	var largest int64
	for _, r := range content.Refs {
		largest = max(largest, r.LLen)
	}
	if bound := int64(len("PATCH")) + 2*largest; st.RechunkedBytes > bound {
		t.Errorf("re-chunked %d bytes for a 5-byte patch; the bound is %d (patch + the two chunks it can straddle)",
			st.RechunkedBytes, bound)
	}
	t.Logf("session uploaded %d packs, the seal added %d; adopted %d files (%d bytes) by reference; "+
		"a 5-byte patch re-chunked %d bytes against a largest base chunk of %d",
		sessionPuts, obj.puts-sessionPuts, st.AdoptedFiles, st.AdoptedBytes, st.RechunkedBytes, largest)
}

func lookupInode(t *testing.T, ov *overlay.FS, name string) uint64 {
	t.Helper()
	n, err := ov.Lookup(context.Background(), genfs.RootInode, name)
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	return n.Inode
}
