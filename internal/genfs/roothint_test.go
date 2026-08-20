package genfs_test

import (
	"context"
	"fmt"
	"path"
	"sort"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// withHint returns a copy of sb serving the same generation with a
// different root-catalog hint (nil for none). A hint is not signed content
// as far as a mount is concerned — genfs is handed a superblock its caller
// has already verified — so a test can state exactly what a reader was
// told and watch what it does about it.
func withHint(sb *superblock.Superblock, h *superblock.RootHint) *superblock.Superblock {
	cp := *sb
	cp.RootCatalogHint = h
	return &cp
}

// withoutPackIndexes returns a copy of sb listing no multi-pack index, so
// a test can measure what locating something costs from PACK TRAILERS
// alone. Same standing as withHint: an index is a hint, and a mount is
// handed a superblock its caller already verified.
func withoutPackIndexes(sb *superblock.Superblock) *superblock.Superblock {
	cp := *sb
	cp.PackIndexes = nil
	return &cp
}

// hintedVolume publishes a generation whose root catalog is NOT in one of
// the newest packs, which is the case the hint is for.
//
// Getting there takes several publishes. The first writes the tree, ending
// with the root catalog in its last pack — where a newest-first probe finds
// it immediately, so a hint would buy nothing there. Every seal after it
// changes nothing: the catalogs are all carried forward by reference, the
// root among them, and the only pack such a generation adds holds its own
// superblock backup. That is the shape a mount that checkpoints on a timer
// reaches — the root catalog drifting further back down the pack list with
// every seal, and no way to tell from its identity which pack it is in.
func hintedVolume(t *testing.T, uuid string) (*packGetStore, *superblock.Superblock, *testvol.Volume) {
	t.Helper()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	v := newTestVolume(t, inner, uuid)
	dir := v.Mkdir(rootIno, "d")
	for i := 0; i < 12; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	var res *publish.Result
	for i := 0; i < 7; i++ {
		res = publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	}
	if len(packsOf(t, inner, res.Superblock)) < 8 {
		t.Fatalf("volume has %d packs; the test needs many", len(packsOf(t, inner, res.Superblock)))
	}
	if res.Superblock.RootCatalogHint == nil {
		t.Fatal("publish recorded no root-catalog hint")
	}
	return inner, res.Superblock, v
}

// treeOf renders the whole namespace as sorted "path type length" lines,
// so two mounts can be compared as trees rather than entry by entry.
func treeOf(t *testing.T, fs *genfs.FS) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	var walk func(ino uint64, at string)
	walk = func(ino uint64, at string) {
		es, err := fs.Readdir(ctx, ino)
		if err != nil {
			t.Fatalf("readdir %s: %v", at, err)
		}
		for _, e := range es {
			p := path.Join(at, e.Name)
			out = append(out, fmt.Sprintf("%s %d %d", p, e.Node.Type, e.Node.Length))
			if e.Node.Type == 2 { // catalog.TypeDir
				if _, err := fs.Lookup(ctx, ino, e.Name); err != nil {
					t.Fatalf("lookup %s: %v", p, err)
				}
				walk(e.Node.Inode, p)
			}
		}
	}
	walk(rootIno, "/")
	sort.Strings(out)
	return out
}

// The point of the hint is round trips. A generation whose root catalog is
// not in a recently written pack costs a request per pack to locate it —
// the whole location layer, built to answer one question — and that is what
// a mount waits through before it can serve anything at all.
//
// Measured with the multi-pack index taken away, deliberately. The index
// answers the same question for every pack at once, so where a generation
// lists one the fallback is a trailer fetch rather than a walk and this
// comparison would measure almost nothing (mpi_test.go measures that
// case). What is being pinned here is the hint against the walk, which is
// still what a generation without an index — an old one, or one whose
// index did not verify — pays.
func TestRootHintSkipsThePackIndex(t *testing.T) {
	ctx := context.Background()
	inner, hintedSB, _ := hintedVolume(t, "9efe7c40-0000-4000-8000-0000000000b1")
	sb := withoutPackIndexes(hintedSB)
	packs := len(packsOf(t, inner, sb))

	inner.gets.Store(0)
	hinted := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	withHintGets := inner.gets.Load()
	if _, err := hinted.Readdir(ctx, rootIno); err != nil {
		t.Fatalf("root readdir: %v", err)
	}

	inner.gets.Store(0)
	blind := openFS(t, inner, withHint(sb, nil), genfs.Options{CacheDir: t.TempDir()})
	noHintGets := inner.gets.Load()
	if _, err := blind.Readdir(ctx, rootIno); err != nil {
		t.Fatalf("root readdir without the hint: %v", err)
	}

	t.Logf("mounting a %d-pack generation: %d pack request(s) with the hint, %d without",
		packs, withHintGets, noHintGets)
	if withHintGets > 2 {
		t.Errorf("a hinted mount issued %d pack request(s); it should read the pack the hint names and stop",
			withHintGets)
	}
	if withHintGets >= noHintGets {
		t.Errorf("the hint saved nothing: %d request(s) with it, %d without", withHintGets, noHintGets)
	}
	if noHintGets < 4 {
		t.Errorf("locating the root without the hint cost %d request(s): the fixture stopped reproducing "+
			"a generation whose root catalog is not in a recently written pack, and the comparison above "+
			"no longer measures anything", noHintGets)
	}
	if !equalStrings(treeOf(t, hinted), treeOf(t, blind)) {
		t.Error("the hinted mount and the fallback mount disagree about the tree")
	}
}

// A hint is not authority: a repack moves entries between packs without
// touching anything that names them by identity, so a superblock published
// before one points somewhere the bytes no longer are. Every such hint has
// to cost a fallback and nothing more — never a wrong root, never a failed
// mount.
func TestWrongRootHintStillMounts(t *testing.T) {
	inner, sb, _ := hintedVolume(t, "9efe7c40-0000-4000-8000-0000000000b2")
	good := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()})
	want := treeOf(t, good)

	real := sb.RootCatalogHint
	other := ""
	for _, pe := range packsOf(t, inner, sb) {
		if pe.Name != real.Pack {
			other = pe.Name
			break
		}
	}
	if other == "" {
		t.Fatal("the generation has only one pack; there is no wrong pack to point at")
	}
	for _, tc := range []struct {
		name string
		hint *superblock.RootHint
	}{
		{"another pack", &superblock.RootHint{Pack: other, Off: 0, Length: real.Length}},
		{"the right pack at the wrong offset", &superblock.RootHint{Pack: real.Pack, Off: real.Off + 1, Length: real.Length}},
		{"a pack this generation does not list", &superblock.RootHint{Pack: "p-0000000000000000-deadbeef", Off: 0, Length: real.Length}},
		{"a length past the end of the pack", &superblock.RootHint{Pack: real.Pack, Off: real.Off, Length: 1 << 40}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := openFS(t, inner, withHint(sb, tc.hint), genfs.Options{CacheDir: t.TempDir()})
			if got := treeOf(t, fs); !equalStrings(got, want) {
				t.Errorf("a wrong hint (%s) served a different tree: %v", tc.name, got)
			}
		})
	}
}

// encryptedHintedVolume is hintedVolume over a volume whose identities are
// keyed — the case the hint used to be unavailable for.
func encryptedHintedVolume(t *testing.T, uuid string) (*packGetStore, *superblock.Superblock, []byte) {
	t.Helper()
	base, _ := newInner(t)
	inner := &packGetStore{Store: base}
	dek := pseudorandom(32, 91)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, uuid),
		DEK:         dek,
		IdentityKey: pseudorandom(32, 92),
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})
	dir := v.Mkdir(rootIno, "d")
	for i := 0; i < 12; i++ {
		f := v.Create(dir, string(rune('a'+i))+".bin")
		v.Write(f, pseudorandom(600<<10, int64(i)+1))
	}
	var res *publish.Result
	for i := 0; i < 7; i++ {
		res = publishVolume(t, v, inner, publish.Options{TargetPackSize: 512 << 10})
	}
	if res.Superblock.RootCatalogHint == nil {
		t.Fatal("publish recorded no root-catalog hint")
	}
	if len(packsOf(t, inner, res.Superblock)) < 8 {
		t.Fatalf("volume has %d packs; the test needs many", len(packsOf(t, inner, res.Superblock)))
	}
	return inner, res.Superblock, dek
}

// An encrypted volume cannot recompute identity, so it used to skip the
// hint and locate its root the long way — a trailer per pack, on every
// mount, for exactly the volumes that can least afford it. It now confirms
// the hint against the pack's own trailer, which the whole-pack policy has
// already brought down.
//
// Measured without the multi-pack index for the same reason
// TestRootHintSkipsThePackIndex is: the index answers the same question,
// and what is being pinned here is the hint against the walk.
func TestRootHintWorksOnAnEncryptedVolume(t *testing.T) {
	ctx := context.Background()
	inner, hintedSB, dek := encryptedHintedVolume(t, "9efe7c40-0000-4000-8000-0000000000b4")
	sb := withoutPackIndexes(hintedSB)
	packs := len(packsOf(t, inner, sb))

	inner.reset()
	hinted := openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir(), DEK: dek})
	withHintGets := inner.gets.Load()
	if _, err := hinted.Readdir(ctx, rootIno); err != nil {
		t.Fatalf("root readdir: %v", err)
	}

	inner.reset()
	blind := openFS(t, inner, withHint(sb, nil), genfs.Options{CacheDir: t.TempDir(), DEK: dek})
	noHintGets := inner.gets.Load()
	if _, err := blind.Readdir(ctx, rootIno); err != nil {
		t.Fatalf("root readdir without the hint: %v", err)
	}

	t.Logf("mounting a %d-pack ENCRYPTED generation: %d pack request(s) with the hint, %d without",
		packs, withHintGets, noHintGets)
	if withHintGets > 2 {
		t.Errorf("a hinted encrypted mount issued %d pack request(s); the pack the hint names carries the "+
			"trailer that confirms it, so one read should do", withHintGets)
	}
	if withHintGets >= noHintGets {
		t.Errorf("the hint saved nothing on an encrypted volume: %d request(s) with it, %d without",
			withHintGets, noHintGets)
	}
	if !equalStrings(treeOf(t, hinted), treeOf(t, blind)) {
		t.Error("the hinted encrypted mount and the fallback mount disagree about the tree")
	}
}

// The check that has to hold for the above to be safe. On an encrypted
// volume the GCM open proves only that the bytes were sealed under this
// volume's DEK — every catalog in the volume was — so a hint pointing at a
// DIFFERENT entry of the right pack decrypts perfectly and is not the
// root. Only the pack's authenticated trailer can tell them apart.
//
// Every other entry of the root's pack is tried as the hint, because the
// failure being ruled out is "believed the hint", and that has to be ruled
// out for all of them.
func TestAnEncryptedHintPointingAtAnotherEntryIsRejected(t *testing.T) {
	ctx := context.Background()
	inner, sb, dek := encryptedHintedVolume(t, "9efe7c40-0000-4000-8000-0000000000b5")
	want := treeOf(t, openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir(), DEK: dek}))

	real := sb.RootCatalogHint
	pe, ok := packEntryNamed(packsOf(t, inner, sb), real.Pack)
	if !ok {
		t.Fatalf("the hint names %s, which the generation does not list", real.Pack)
	}
	entries, _, err := packstore.FetchTrailerStoredVerified(ctx, inner, pe.Name, pe.Size, pe.TrailerHash)
	if err != nil {
		t.Fatalf("trailer of %s: %v", pe.Name, err)
	}
	tried := 0
	for _, e := range entries {
		if e.Off == real.Off && e.Length == real.Length {
			continue // the root itself
		}
		tried++
		hint := &superblock.RootHint{Pack: pe.Name, Off: e.Off, Length: e.Length}
		fs := openFS(t, inner, withHint(sb, hint), genfs.Options{CacheDir: t.TempDir(), DEK: dek})
		if got := treeOf(t, fs); !equalStrings(got, want) {
			t.Fatalf("a hint at entry %s of the root's own pack served a different tree: %v", e.Key, got)
		}
	}
	if tried == 0 {
		t.Fatal("the root's pack holds nothing but the root; there is no other entry to point at")
	}
	t.Logf("%d other entries of the root's pack rejected as the root", tried)
}

func packEntryNamed(packs []superblock.PackEntry, name string) (superblock.PackEntry, bool) {
	for _, pe := range packs {
		if pe.Name == name {
			return pe, true
		}
	}
	return superblock.PackEntry{}, false
}

// The old shape of the format: a superblock written before the hint
// existed carries none, and must mount exactly as it always did.
func TestNoRootHintStillMounts(t *testing.T) {
	inner, sb, _ := hintedVolume(t, "9efe7c40-0000-4000-8000-0000000000b3")
	want := treeOf(t, openFS(t, inner, sb, genfs.Options{CacheDir: t.TempDir()}))
	blind := openFS(t, inner, withHint(sb, nil), genfs.Options{CacheDir: t.TempDir()})
	if got := treeOf(t, blind); !equalStrings(got, want) {
		t.Errorf("a superblock with no hint served a different tree: %v", got)
	}
}
