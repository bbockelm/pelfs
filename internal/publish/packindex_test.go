package publish_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// packEntryKeys reads one pack's trailer back out of the federation: the
// identities it actually holds, which is what an index claiming to describe
// it is checked against.
func packEntryKeys(t *testing.T, inner pelicanobj.Store, pe superblock.PackEntry) []string {
	t.Helper()
	entries, _, err := packstore.FetchTrailerStoredVerified(context.Background(), inner,
		pe.Name, pe.Size, pe.TrailerHash)
	if err != nil {
		t.Fatalf("trailer of %s: %v", pe.Name, err)
	}
	var keys []string
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	return keys
}

// fetchIndex fetches and verifies one listed index the way a mount does.
func fetchIndex(t *testing.T, inner pelicanobj.Store, ref mpi.Ref) *mpi.Index {
	t.Helper()
	ix, err := mpi.Fetch(context.Background(), inner, ref)
	if err != nil {
		t.Fatalf("fetch index %s: %v", ref.Name, err)
	}
	return ix
}

// A publish emits ONE index covering the packs it created, and it has to
// be right about all of them: an index is the reader's first answer to
// "which pack", and every entry it gets wrong is a fallback the reader
// pays for silently.
func TestPublishEmitsAnIndexOverItsOwnPacks(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x01})
	v.reuseTree(4)
	res := v.checkpoint()
	sb := res.Superblock

	// Generation 0 published one of its own, so this generation lists it
	// and the one this seal wrote.
	if len(sb.PackIndexes) < 1 {
		t.Fatal("a seal that cut packs listed no index")
	}
	ref := sb.PackIndexes[len(sb.PackIndexes)-1]
	if ref.Name == "" || ref.Entries == 0 || ref.Size == 0 {
		t.Fatalf("the index ref says nothing useful: %+v", ref)
	}
	if int(ref.Packs) != len(res.NewPacks) {
		t.Errorf("the index covers %d pack(s); this seal cut %d", ref.Packs, len(res.NewPacks))
	}

	ix := fetchIndex(t, v.inner, ref)
	if ix.Len() != int(ref.Entries) {
		t.Errorf("the index holds %d entries; the superblock says %d", ix.Len(), ref.Entries)
	}
	for _, sp := range res.NewPacks {
		pe := listedPack(sb, sp.Name)
		if pe == nil {
			t.Fatalf("this seal cut pack %s and the generation does not list it", sp.Name)
		}
		for _, key := range packEntryKeys(t, v.inner, *pe) {
			var id [32]byte
			if _, err := hex.Decode(id[:], []byte(key)); err != nil {
				continue // not identity-keyed; the index skips those
			}
			names, ok := ix.Lookup(id)
			if !ok {
				t.Fatalf("the index does not know %s, which pack %s holds", key[:16], sp.Name)
			}
			found := false
			for _, n := range names {
				if n == sp.Name {
					found = true
				}
			}
			if !found {
				// Not a collision: a collision NAMES both packs.
				t.Fatalf("the index sends %s to %v; pack %s holds it", key[:16], names, sp.Name)
			}
		}
	}
}

// Carrying the previous generation's refs forward is the same rule as the
// pack list, for the same reason: the packs a carried index covers are the
// packs this generation carried forward, so dropping the index would leave
// most of the volume unindexed — silently, and permanently, because
// nothing rebuilds an index that was merely forgotten.
func TestPublishCarriesPreviousIndexesForward(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x02})
	v.reuseTree(5)
	first := v.checkpoint()
	firstRefs := first.Superblock.PackIndexes
	if len(firstRefs) == 0 {
		t.Fatal("the first seal listed no index")
	}

	v.create(publishRootInode, "later.bin", pseudorandom(300<<10, 9))
	second := v.checkpoint()
	got := second.Superblock.PackIndexes
	if len(got) != len(firstRefs)+1 {
		t.Fatalf("the second generation lists %d index(es), the first listed %d: refs are being dropped or duplicated",
			len(got), len(firstRefs))
	}
	for i, want := range firstRefs {
		if got[i] != want {
			t.Errorf("carried ref %d came back as %+v, want %+v", i, got[i], want)
		}
	}
	// And every carried ref still names an object that fetches and
	// verifies — a ref pointing at nothing is worse than no ref, since a
	// reader pays a round trip to learn it.
	for _, ref := range got {
		fetchIndex(t, v.inner, ref)
	}

	// A seal that changes nothing still cuts one pack (its own superblock
	// backup), so it emits an index for it and carries the rest.
	third := v.checkpoint()
	if len(third.Superblock.PackIndexes) < len(got) {
		t.Errorf("a no-op seal lost indexes: %d, was %d", len(third.Superblock.PackIndexes), len(got))
	}
	for i, want := range got {
		if third.Superblock.PackIndexes[i] != want {
			t.Errorf("a no-op seal rewrote carried ref %d: %+v, want %+v",
				i, third.Superblock.PackIndexes[i], want)
		}
	}
}

// The index is derived: publish must be able to write it, but a generation
// without one is complete and readable. What must NOT happen is a seal
// that packed and uploaded everything failing at the last step over an
// optimization — so an index upload that fails is reported and the
// generation is published listing one fewer index.
func TestPublishSurvivesAnIndexUploadFailure(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x03})
	body, _ := v.reuseTree(6)
	before := len(v.head.Superblock.PackIndexes)
	v.inner.failPutPrefix(mpi.Dir + "/")
	res := v.checkpoint()
	v.inner.failPutPrefix("")

	// The seal published, and listed only what it could carry forward:
	// naming an index it failed to upload would cost every reader a round
	// trip to discover it is not there.
	if got := len(res.Superblock.PackIndexes); got != before {
		t.Errorf("the generation lists %d index(es); the seal could upload none, so it should list the %d it carried",
			got, before)
	}
	for _, ref := range res.Superblock.PackIndexes {
		if ref.Name == "" {
			t.Fatalf("the generation lists an unnamed index: %+v", ref)
		}
		fetchIndex(t, v.inner, ref)
	}
	// The generation is otherwise whole: it serves the tree it sealed.
	v.verifyBodies(res, body)
}
