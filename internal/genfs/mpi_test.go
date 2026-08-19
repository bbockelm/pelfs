package genfs_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"path"
	"testing"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// manyPackVolume publishes a generation of a few dozen packs — the shape
// the multi-pack index exists for, and small enough to run in a second.
// Each file is larger than the cut size, so it seals into packs of its
// own and the tree spreads across all of them.
func manyPackVolume(t *testing.T, uuid string) (*packGetStore, *superblock.Superblock, []string) {
	t.Helper()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, uuid)
	dir := v.Mkdir(rootIno, "d")
	var names []string
	for i := 0; i < 30; i++ {
		name := string(rune('a'+i/5)) + string(rune('a'+i%5)) + ".bin"
		f := v.Create(dir, name)
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
		names = append(names, path.Join("d", name))
	}
	res := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	if len(res.Superblock.PackList) < 24 {
		t.Fatalf("volume has %d packs; the test needs a few dozen", len(res.Superblock.PackList))
	}
	if len(res.Superblock.PackIndexes) == 0 {
		t.Fatal("publish listed no multi-pack index")
	}
	return inner, res.Superblock, names
}

// walkAndRead descends the whole tree and reads a handful of files whole —
// a mount doing what a mount does, so the request count below is the one a
// user waits through.
func walkAndRead(t *testing.T, fs *genfs.FS, files []string) []string {
	t.Helper()
	ctx := context.Background()
	tree := treeOf(t, fs)
	for _, p := range files {
		n, err := fs.LookupPath(ctx, p)
		if err != nil {
			t.Fatalf("lookup %s: %v", p, err)
		}
		if got := readAll(t, fs, n.Inode, int(n.Length), 64<<10); len(got) != int(n.Length) {
			t.Fatalf("read %d bytes of a %d-byte %s", len(got), n.Length, p)
		}
	}
	return tree
}

// The whole point of the index, in the only unit that matters: requests.
//
// Without one, the first identity a mount cannot guess its way to resolves
// the ENTIRE generation — one trailer per pack, whatever the question was
// — because "present in no listed pack" may only be said once every pack
// has been indexed. With one, a lookup names its pack and the mount fetches
// that trailer and no other.
//
// Both halves read the same tree and the same files from a cold cache, and
// the count is of every object read rather than only packs: an index that
// merely moved the round trips into a different key space would show up
// here as no saving at all.
func TestPackIndexCollapsesTheRoundTrips(t *testing.T) {
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000c1")
	packs := len(sb.PackList)
	read := files[:5]

	inner.reset()
	blind := openFS(t, inner, withoutPackIndexes(sb), genfs.Options{CacheDir: t.TempDir()})
	blindTree := walkAndRead(t, blind, read)
	without, withoutPacks := inner.all.Load(), inner.gets.Load()

	inner.reset()
	indexed := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	indexedTree := walkAndRead(t, indexed, read)
	with, withPacks := inner.all.Load(), inner.gets.Load()

	t.Logf("%d packs, mount + walk + %d file reads: %d request(s) with the index (%d against packs), "+
		"%d without (%d against packs)", packs, len(read), with, withPacks, without, withoutPacks)

	if !equalStrings(blindTree, indexedTree) {
		t.Error("the indexed mount and the trailer-only mount disagree about the tree")
	}
	// The fallback indexes every pack; the index must not.
	if without < int64(packs) {
		t.Errorf("the trailer-only mount cost %d request(s) over %d packs: the fixture no longer forces "+
			"the fallback, so the comparison measures nothing", without, packs)
	}
	if with >= int64(packs) {
		t.Errorf("an indexed mount cost %d request(s) over %d packs: it is still indexing the generation",
			with, packs)
	}
	if with*2 >= without {
		t.Errorf("the index saved little: %d request(s) with it, %d without", with, without)
	}
}

// The old shape of the format: a superblock written before indexes existed
// lists none, and must mount and serve exactly as it always did. This is
// the fallback the rest of the design leans on — every other failure here
// degrades to it.
func TestGenerationWithNoPackIndexStillServes(t *testing.T) {
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000c2")
	want := walkAndRead(t, openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()}), files[:3])
	old := openFS(t, inner, withoutPackIndexes(sb), genfs.Options{CacheDir: t.TempDir()})
	if got := walkAndRead(t, old, files[:3]); !equalStrings(got, want) {
		t.Errorf("a generation listing no index served a different tree: %v", got)
	}
}

// An index is fetched from the same federation as everything else and is
// not signed on its own — the superblock names its hash, and that check is
// the only thing standing between a reader and an arbitrary location map.
// A copy that fails it must be discarded, and discarding it must cost the
// fallback and nothing more: not a failed mount, and not a different tree.
func TestUnverifiablePackIndexStillMounts(t *testing.T) {
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000c3")
	want := walkAndRead(t, openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()}), files[:3])

	for _, tc := range []struct {
		name string
		ref  func(mpi.Ref) mpi.Ref
	}{
		{"a hash the index does not have", func(r mpi.Ref) mpi.Ref {
			r.Hash[0] ^= 0xff
			return r
		}},
		{"an index object that is not there", func(r mpi.Ref) mpi.Ref {
			r.Name = "0000000000000000000000000000000000000000000000000000000000000000"
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := *sb
			cp.PackIndexes = append([]mpi.Ref(nil), sb.PackIndexes...)
			for i := range cp.PackIndexes {
				cp.PackIndexes[i] = tc.ref(cp.PackIndexes[i])
			}
			fs := openFS(t, inner, &cp, genfs.Options{CacheDir: t.TempDir()})
			if got := walkAndRead(t, fs, files[:3]); !equalStrings(got, want) {
				t.Errorf("a mount over %s served a different tree: %v", tc.name, got)
			}
		})
	}
}

// An index that verifies can still be WRONG about where something is: a
// repack moves entries between packs without rewriting anything that names
// them by identity, and a 12-byte key can collide outright. Either way the
// reader is sent to a pack whose trailer does not confirm the identity, and
// the only acceptable outcome is the ordinary fallback.
//
// The fixture is the worst case rather than a plausible one — every entry
// attributed to the wrong pack — because the failure mode being ruled out
// is "believed the index", and that has to be ruled out for all of them.
func TestPackIndexNamingTheWrongPackFallsBack(t *testing.T) {
	ctx := context.Background()
	inner, sb, files := manyPackVolume(t, "9efe7c40-0000-4000-8000-0000000000c4")
	want := walkAndRead(t, openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()}), files[:3])

	// Read the real placement out of the trailers, then rotate it: every
	// key is claimed by the pack after the one that holds it.
	b := mpi.NewBuilder()
	entries := 0
	for i, pe := range sb.PackList {
		got, _, err := packstore.FetchTrailerStoredVerified(ctx, inner, pe.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			t.Fatalf("trailer of %s: %v", pe.Name, err)
		}
		wrong := sb.PackList[(i+1)%len(sb.PackList)].Name
		for _, e := range got {
			var id [32]byte
			if _, err := hex.Decode(id[:], []byte(e.Key)); err != nil {
				continue // not an identity key; the index skips those too
			}
			b.Add(id, wrong)
			entries++
		}
	}
	if entries == 0 {
		t.Fatal("the generation's trailers hold no identity-keyed entries")
	}
	raw := b.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := inner.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		t.Fatalf("upload the misleading index: %v", err)
	}

	cp := *sb
	cp.PackIndexes = []mpi.Ref{{
		Name: name, Hash: hash, Size: int64(len(raw)),
		Entries: uint32(b.Len()), Packs: uint32(b.Packs()),
	}}
	fs := openFS(t, inner, &cp, genfs.Options{CacheDir: t.TempDir()})
	if got := walkAndRead(t, fs, files[:3]); !equalStrings(got, want) {
		t.Errorf("a mount over an index that names the wrong pack for everything served a different tree: %v", got)
	}
}

// A generation swap resolves a root catalog it has never located and every
// read after it goes through the new generation's location layer, so the
// incoming indexes have to be picked up with the rest of it — otherwise a
// long-lived mount quietly loses them at the first checkpoint.
func TestSwapPicksUpTheNewGenerationsIndexes(t *testing.T) {
	ctx := context.Background()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, "9efe7c40-0000-4000-8000-0000000000c5")
	dir := v.Mkdir(rootIno, "d")
	writeSpread(t, v, dir, 0, 12)
	first := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})

	fs := openFS(t, inner, first.Superblock, genfs.Options{CacheDir: t.TempDir()})
	if _, err := fs.Readdir(ctx, rootIno); err != nil {
		t.Fatalf("root readdir: %v", err)
	}

	// The publish reopened the write layers, so the directory has to be
	// looked up again before anything can be created in it.
	dir = v.Lookup(rootIno, "d")
	writeSpread(t, v, dir, 12, 24)
	second := publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	// One ref or several: consolidation may have folded the first
	// generation's index into this one's. What the swap needs is that the
	// coverage is there to pick up.
	if len(second.Superblock.PackIndexes) == 0 {
		t.Fatal("the second generation lists no index; it should carry the first's coverage forward")
	}
	if _, err := fs.Swap(ctx, second.Superblock); err != nil {
		t.Fatalf("swap: %v", err)
	}

	packs := len(second.Superblock.PackList)
	inner.reset()
	// Everything the new generation added, read through the swapped mount.
	for i := 12; i < 24; i++ {
		p := path.Join("d", spreadName(i))
		n, err := fs.LookupPath(ctx, p)
		if err != nil {
			t.Fatalf("lookup %s after swap: %v", p, err)
		}
		if got := readAll(t, fs, n.Inode, int(n.Length), 64<<10); len(got) != int(n.Length) {
			t.Fatalf("read %d bytes of a %d-byte %s", len(got), n.Length, p)
		}
	}
	after := inner.all.Load()
	t.Logf("reading 12 files across a %d-pack generation after a swap: %d request(s)", packs, after)
	if after >= int64(packs)+12 {
		t.Errorf("a swapped mount cost %d request(s) over %d packs: it is indexing the generation, "+
			"so the incoming indexes were not picked up", after, packs)
	}
}

func spreadName(i int) string { return string(rune('a'+i/5)) + string(rune('a'+i%5)) + ".bin" }

// writeSpread writes files [from,to) of about a pack each into dir.
func writeSpread(t *testing.T, v *testvol.Volume, dir uint64, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		f := v.Create(dir, spreadName(i))
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
}
