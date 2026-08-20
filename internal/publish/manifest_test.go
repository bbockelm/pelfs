package publish_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// fabricatedPacks are pack rows shaped exactly like real ones — the name
// is what the manifest keys on and what the superblock spends most of its
// bytes on, so a fake short name would measure the wrong thing.
func fabricatedPacks(n int) []packstore.SealedPack {
	out := make([]packstore.SealedPack, n)
	for i := range out {
		out[i] = packstore.SealedPack{
			Name: fmt.Sprintf("p-%016x-%04x", 0x18cd000000000000+int64(i), i&0xffff),
			Size: 2 << 20,
		}
		out[i].TrailerHash[0] = byte(i)
		out[i].TrailerHash[31] = byte(i >> 8)
	}
	return out
}

// The number this whole change is for: what a generation's superblock
// costs as pack count grows, in the shape that inlines the pack list and
// in the shape that names a manifest.
//
// The bytes do not vanish — they move OUT of the object every mount reads
// and every seal rewrites, into one that is fetched when something needs
// to enumerate. That is the trade, so the manifest object is measured
// here too rather than quietly left out.
func TestSuperblockStopsGrowingWithPackCount(t *testing.T) {
	base := func() *superblock.Superblock {
		return &superblock.Superblock{
			FormatVersion:   superblock.FormatV2,
			Generation:      42,
			CreatedUnixNano: 1,
			RootCatalog:     [32]byte{0xab},
			Params:          superblock.Params{SMaxBytes: 4096, TGraceSeconds: 259200, RetainK: 8},
			KeyTable:        []superblock.KeyEntry{{ID: 1, Kind: superblock.KeyKindDEK, Alg: 1, Wrapped: bytes.Repeat([]byte{7}, 256)}},
		}
	}
	encode := func(sb *superblock.Superblock) int64 {
		raw, err := sb.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return int64(len(raw))
	}

	var manifestSizes []int64
	for _, n := range []int{1, 1_000, 10_000, 100_000} {
		packs := fabricatedPacks(n)

		inline := base()
		inline.PackList = manifest.Entries(packs)

		b := manifest.NewBuilder()
		for _, sp := range packs {
			if err := b.Add(sp); err != nil {
				t.Fatal(err)
			}
		}
		raw := b.Encode()
		hash := blake3.Sum256(raw)
		named := base()
		named.Manifests = []superblock.ManifestRef{{
			Name: hex.EncodeToString(hash[:]), Hash: hash, Size: int64(len(raw)), Packs: uint32(n),
		}}

		before, after := encode(inline), encode(named)
		manifestSizes = append(manifestSizes, after)
		t.Logf("%7d packs: superblock %9d B inline -> %4d B named (%.0fx smaller); the manifest object is %d B",
			n, before, after, float64(before)/float64(after), len(raw))

		if after >= before && n > 1 {
			t.Errorf("at %d packs the manifest shape (%d B) is no smaller than the inline one (%d B)", n, after, before)
		}
	}
	// The point is not "smaller", it is "does not depend on pack count".
	// One ref is one ref whether it covers a pack or a hundred thousand.
	first, last := manifestSizes[0], manifestSizes[len(manifestSizes)-1]
	if last-first > 8 {
		t.Errorf("the manifest-shaped superblock grew from %d B to %d B between 1 and 100,000 packs; "+
			"it is still carrying something per-pack", first, last)
	}
}

// A seal states its pack set ONE way, and the packs it names have to be
// exactly the packs it wrote plus the packs it inherited — that set is
// what retention will spare and what a reader may fetch, so a gap in it
// is data loss on the next sweep.
func TestASealNamesItsPacksThroughAManifest(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x11, 0x22, 0x33, 0x44})
	v.create(publishRootInode, "a.bin", pseudorandom(3<<20, 1))
	first := v.checkpoint()

	if !first.Superblock.PacksAreInManifests() {
		t.Fatal("a seal wrote no manifest refs")
	}
	if len(first.Superblock.PackList) != 0 {
		t.Errorf("the generation names a manifest AND inlines %d packs; it must do one or the other",
			len(first.Superblock.PackList))
	}
	firstPacks := packsOf(t, v.inner, first.Superblock)
	if len(firstPacks) < len(first.NewPacks) {
		t.Fatalf("the manifest names %d packs; this seal cut %d", len(firstPacks), len(first.NewPacks))
	}
	for _, sp := range first.NewPacks {
		if listedPack(t, v.inner, first.Superblock, sp.Name) == nil {
			t.Errorf("this seal cut pack %s and its manifest does not name it", sp.Name)
		}
	}

	// The second generation must carry the first's packs, which it does by
	// carrying its refs rather than by rewriting the list.
	v.create(publishRootInode, "b.bin", pseudorandom(3<<20, 2))
	second := v.checkpoint()
	secondPacks := packsOf(t, v.inner, second.Superblock)
	for _, pe := range firstPacks {
		if listedPack(t, v.inner, second.Superblock, pe.Name) == nil {
			t.Errorf("pack %s dropped out of the successor's pack set", pe.Name)
		}
	}
	for _, sp := range second.NewPacks {
		if listedPack(t, v.inner, second.Superblock, sp.Name) == nil {
			t.Errorf("new pack %s is in no manifest the successor names", sp.Name)
		}
	}
	t.Logf("gen %d: %d packs named by %d manifest ref(s), superblock %d B",
		second.Superblock.Generation, len(secondPacks), len(second.Superblock.Manifests), len(second.Raw))

	// The manifest objects are real objects, fetched and verified, not a
	// claim in the superblock: corrupt one and the generation must refuse
	// to resolve rather than resolve to fewer packs.
	ref := second.Superblock.Manifests[0]
	if err := v.inner.Put(ctx, manifest.Dir+"/"+ref.Name, bytes.NewReader([]byte("not a manifest"))); err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Packs(ctx, v.inner, second.Superblock); err == nil {
		t.Error("a corrupted manifest resolved anyway; a short pack set is how a sweep deletes live data")
	}
}

// The migration, which happens exactly once per volume: a generation
// built on a parent that still keeps its packs inline must fold that
// parent's packs into its own manifest. Carrying refs forward covers
// nothing when the parent has none, and a manifest holding only the new
// packs would drop every inherited pack out of the live set.
func TestAnInlineParentsPacksSurviveIntoTheManifest(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x55, 0x66, 0x77, 0x88})
	v.create(publishRootInode, "a.bin", pseudorandom(3<<20, 3))
	first := v.checkpoint()
	inherited := packsOf(t, v.inner, first.Superblock)
	if len(inherited) == 0 {
		t.Fatal("fixture: the first generation has no packs to inherit")
	}

	// Rewrite the head into the shape a pre-manifest writer produced: the
	// same packs, inline, no manifest refs. Signed by the same key, since
	// publish reads Prev as a verified document.
	old := *first.Superblock
	old.PackList = inherited
	old.Manifests = nil
	if err := old.Sign(v.priv); err != nil {
		t.Fatal(err)
	}
	oldRaw, err := old.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.inner.Put(ctx, "refs/main", bytes.NewReader(oldRaw)); err != nil {
		t.Fatal(err)
	}

	v.create(publishRootInode, "b.bin", pseudorandom(3<<20, 4))
	next := v.sealOnly(&publish.Result{Superblock: &old, Raw: oldRaw})
	if !next.Superblock.PacksAreInManifests() {
		t.Fatal("the successor of an inline generation did not write a manifest")
	}
	got := map[string]bool{}
	for _, pe := range packsOf(t, v.inner, next.Superblock) {
		got[pe.Name] = true
	}
	for _, pe := range inherited {
		if !got[pe.Name] {
			t.Errorf("inherited pack %s is named by neither the parent's inline list nor the new manifest; "+
				"the next sweep would delete it", pe.Name)
		}
	}
	for _, sp := range next.NewPacks {
		if !got[sp.Name] {
			t.Errorf("new pack %s is in no manifest", sp.Name)
		}
	}
}

// backupSuperblock digs the superblock backup out of the packs a seal
// wrote. It is stored raw — rescue has to read it before it holds any
// keys — so decoding it needs nothing but the bytes.
func backupSuperblock(t *testing.T, v *reuseVol, res *publish.Result) *superblock.Superblock {
	t.Helper()
	ctx := context.Background()
	for _, sp := range res.NewPacks {
		entries, err := packstore.FetchTrailer(ctx, v.inner, sp.Name, sp.Size)
		if err != nil {
			t.Fatalf("trailer of %s: %v", sp.Name, err)
		}
		for _, e := range entries {
			if e.Type != packstore.EntrySuperblock {
				continue
			}
			rc, err := v.inner.Get(ctx, packstore.PackDirKey+"/"+sp.Name, e.Off, e.Length)
			if err != nil {
				t.Fatalf("read the backup out of %s: %v", sp.Name, err)
			}
			raw, err := io.ReadAll(rc)
			rc.Close() //nolint:errcheck
			if err != nil {
				t.Fatalf("read the backup out of %s: %v", sp.Name, err)
			}
			sb, err := superblock.Decode(raw)
			if err != nil {
				t.Fatalf("decode the backup in %s: %v", sp.Name, err)
			}
			return sb
		}
	}
	t.Fatal("no superblock backup rode in any pack this seal wrote")
	return nil
}

// The backup's in-flight manifest segment is GONE (see backupPackList):
// the backup states its own packs inline, so there is no extra object per
// seal and no ledger entry keeping one alive. What replaced this test is
// the DR property itself, in backupsb_test.go.

// The ledger is a window, not a promise, and this is the mechanism that
// makes it one: an entry is carried forward until it is older than
// T_grace and then simply stops being written. Without the fall-off the
// ledger grows for the life of the volume — a consolidating seal condemns
// refs every time — and with it, a reader pinned to a generation older
// than the window is back to losing its index or its manifest. That is
// the limit, and it lives here as much as in the comments.
func TestCondemnedRefEntriesAgeOffTheSuperblock(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x22})
	v.create(publishRootInode, "a.bin", pseudorandom(2<<20, 42))
	first := v.checkpoint()

	now := time.Now()
	fresh := strings.Repeat("a", 64) // condemned an hour ago -> carried
	stale := strings.Repeat("b", 64) // condemned 200h ago -> dropped
	ledger := []superblock.CondemnedRef{
		{Name: fresh, CondemnedAtUnix: now.Add(-1 * time.Hour).Unix()},
		{Name: stale, CondemnedAtUnix: now.Add(-200 * time.Hour).Unix()},
	}
	prev := *first.Superblock
	prev.CondemnedIndexes = ledger
	prev.CondemnedManifests = ledger
	if err := prev.Sign(v.priv); err != nil {
		t.Fatal(err)
	}
	prevRaw, err := prev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.inner.Put(ctx, "refs/main", bytes.NewReader(prevRaw)); err != nil {
		t.Fatal(err)
	}

	v.create(publishRootInode, "b.bin", pseudorandom(2<<20, 43))
	next := v.sealOnly(&publish.Result{Superblock: &prev, Raw: prevRaw})

	for _, space := range []struct {
		what string
		got  []superblock.CondemnedRef
	}{
		{"index", next.Superblock.CondemnedIndexes},
		{"manifest", next.Superblock.CondemnedManifests},
	} {
		at := map[string]int64{}
		for _, c := range space.got {
			at[c.Name] = c.CondemnedAtUnix
		}
		if _, ok := at[stale]; ok {
			t.Errorf("a %s condemned 200h ago is still on the ledger; a %s ledger that never sheds "+
				"grows for the life of the volume", space.what, space.what)
		}
		when, ok := at[fresh]
		if !ok {
			t.Errorf("a %s condemned an hour ago fell off a 72h ledger; the object it names is now "+
				"one sweep from deletion", space.what)
			continue
		}
		// Carried, not re-stamped: refreshing the timestamp every seal
		// would keep an entry alive forever and the window would never end.
		if when != ledger[0].CondemnedAtUnix {
			t.Errorf("%s ledger entry re-stamped %d -> %d; the clock must not restart on carry-forward",
				space.what, ledger[0].CondemnedAtUnix, when)
		}
	}
}

// Maintenance state belongs to the BRANCH, not to a seal: a repack
// writes it and every ordinary publish afterwards must carry it forward
// untouched.
//
// Dropping it is not a cosmetic loss. It is the state the cheap
// auto-repack gate reads (repack.Worthwhile), so a seal that forgot it
// would make the volume look like one that had never been repacked — and
// the next quiescent moment would pay for a full reachability sweep that
// had just been paid for.
func TestMaintenanceStateSurvivesAnOrdinarySeal(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x33})
	v.create(publishRootInode, "a.bin", pseudorandom(2<<20, 42))
	first := v.checkpoint()
	if first.Superblock.Maint != nil {
		t.Fatal("an ordinary seal invented maintenance state")
	}

	want := superblock.Maint{RepackGeneration: 7, RepackPacks: 42, RepackUnixNano: 1700000000000000000}
	prev := *first.Superblock
	prev.Maint = &want
	if err := prev.Sign(v.priv); err != nil {
		t.Fatal(err)
	}
	prevRaw, err := prev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.inner.Put(ctx, "refs/main", bytes.NewReader(prevRaw)); err != nil {
		t.Fatal(err)
	}

	v.create(publishRootInode, "b.bin", pseudorandom(2<<20, 43))
	next := v.sealOnly(&publish.Result{Superblock: &prev, Raw: prevRaw})
	if next.Superblock.Maint == nil {
		t.Fatal("the seal dropped the maintenance state; the auto gate would re-sweep a volume just repacked")
	}
	if *next.Superblock.Maint != want {
		t.Fatalf("the seal changed the maintenance state: %+v, want %+v", *next.Superblock.Maint, want)
	}
}
