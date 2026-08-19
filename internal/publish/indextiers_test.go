package publish_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// indexSet opens every index a generation lists, the way a mount does.
func indexSet(t *testing.T, inner pelicanobj.Store, refs []superblock.IndexRef) *mpi.Set {
	t.Helper()
	indexes, err := mpi.FetchAll(context.Background(), inner, refs)
	if err != nil {
		t.Fatalf("fetch the listed indexes: %v", err)
	}
	if len(indexes) != len(refs) {
		t.Fatalf("%d of %d listed indexes fetched", len(indexes), len(refs))
	}
	return mpi.NewSet(indexes)
}

// idOf rebuilds a lookup key from a table key. An index holds 12 bytes of
// identity and Lookup reads only those, so the rest may be anything.
func idOf(key []byte) [32]byte {
	var id [32]byte
	copy(id[:], key)
	return id
}

// One index per generation is one object a mount fetches per seal the
// volume has ever done, and a checkpointing mount seals every few minutes.
// Consolidation is what stops that list tracking the number of
// GENERATIONS: fifty small seals are worth one index, not fifty.
func TestIndexRefsStayBoundedAcrossGenerations(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x10})
	v.reuseTree(21)
	res := v.checkpoint()
	at := map[int]int{1: len(res.Superblock.PackIndexes)}
	for gen := 2; gen <= 50; gen++ {
		v.create(publishRootInode, fmt.Sprintf("g%02d.bin", gen), pseudorandom(8<<10, int64(gen)))
		res = v.checkpoint()
		at[gen] = len(res.Superblock.PackIndexes)
	}
	var bytes int64
	for _, ref := range res.Superblock.PackIndexes {
		bytes += ref.Size
	}
	t.Logf("index refs listed: 5 gens=%d, 20 gens=%d, 50 gens=%d (%d bytes at 50)",
		at[5], at[20], at[50], bytes)

	// The bound is in BYTES — a merged index stops growing at the target —
	// so what a generation count may not do is drive the ref count. These
	// fixtures are kilobytes, so the whole volume is one index's worth.
	if at[50] > at[5] {
		t.Errorf("50 generations list %d index refs and 5 listed %d: the list is tracking generations",
			at[50], at[5])
	}
	if at[50] > 4 {
		t.Errorf("50 small generations list %d index refs; they fit in one index", at[50])
	}
	for _, ref := range res.Superblock.PackIndexes {
		fetchIndex(t, v.inner, ref)
	}
}

// The test that matters for a merge: a consolidated index must answer for
// every identity its inputs did. A superseded ref is dropped from the list
// and nothing rebuilds it, so coverage lost here is lost permanently — the
// reader just silently pays the trailer fallback forever.
func TestConsolidationKeepsEveryIdentityItsInputsAnswered(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x11})
	body, _ := v.reuseTree(22)
	res := v.checkpoint()

	// Every ref this volume ever listed, whether it survived into the
	// current generation or was merged away.
	ever := map[string]superblock.IndexRef{}
	record := func(res *publish.Result) {
		for _, ref := range res.Superblock.PackIndexes {
			ever[ref.Name] = ref
		}
	}
	record(res)
	for gen := 2; gen <= 8; gen++ {
		v.create(publishRootInode, fmt.Sprintf("f%d.bin", gen), pseudorandom(200<<10, int64(gen)))
		res = v.checkpoint()
		record(res)
	}
	if len(ever) <= len(res.Superblock.PackIndexes) {
		t.Fatalf("%d refs listed of %d ever written: nothing was consolidated, so this proves nothing",
			len(res.Superblock.PackIndexes), len(ever))
	}

	set := indexSet(t, v.inner, res.Superblock.PackIndexes)
	for name, ref := range ever {
		fetchIndex(t, v.inner, ref).Each(func(key []byte, packs []string) {
			if _, ok := set.Lookup(idOf(key)); !ok {
				t.Fatalf("index %s answered %x -> %v; the generation's indexes no longer answer for it",
					name[:12], key, packs)
			}
		})
	}
	// And the volume still reads, which is what the index is for.
	v.verifyBodies(res, body)
}

// A merge needs its inputs, so it can fail the way any fetch can. The
// generation must publish anyway: consolidation is an optimization on top
// of a structure that is itself derived, so the unmerged refs still name
// objects that still answer.
func TestAFailedMergeStillPublishesAndStillResolves(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x12})
	body, _ := v.reuseTree(23)
	before := v.checkpoint()
	carried := len(before.Superblock.PackIndexes)

	v.create(publishRootInode, "after.bin", pseudorandom(300<<10, 31))
	v.inner.failGetPrefix(mpi.Dir + "/")
	res := v.checkpoint()
	v.inner.failGetPrefix("")

	// It listed what it could not merge, rather than listing a merge it
	// could not build or dropping refs into nothing.
	if got := len(res.Superblock.PackIndexes); got != carried+1 {
		t.Fatalf("a seal whose merge failed lists %d index(es); it carried %d and wrote one",
			got, carried)
	}
	set := indexSet(t, v.inner, res.Superblock.PackIndexes)
	for _, ref := range before.Superblock.PackIndexes {
		fetchIndex(t, v.inner, ref).Each(func(key []byte, _ []string) {
			if _, ok := set.Lookup(idOf(key)); !ok {
				t.Fatalf("%x resolved before the failed merge and does not after", key)
			}
		})
	}
	v.verifyBodies(res, body)

	// The next seal, with the store healthy again, tidies up what the
	// failed one left: a merge that failed is retried, not abandoned.
	v.create(publishRootInode, "later.bin", pseudorandom(4<<10, 32))
	next := v.checkpoint()
	if len(next.Superblock.PackIndexes) >= len(res.Superblock.PackIndexes) {
		t.Errorf("the seal after the failure lists %d index(es), the failed one listed %d: it did not consolidate",
			len(next.Superblock.PackIndexes), len(res.Superblock.PackIndexes))
	}
}
