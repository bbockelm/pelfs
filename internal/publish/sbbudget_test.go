package publish_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// THE BRICK. A superblock is read through a 1 MiB ceiling and, until the
// budget existed, was written through nothing at all: a seal that produced
// a larger one flipped it, and from that moment the volume could neither
// be mounted (every reader refuses the object) nor published again (the
// next seal cannot read the parent it must grow from). Nothing inside the
// tool recovers that.
//
// So the seal must refuse, and refusing must be harmless — which is the
// half of this that needs a test more than the refusal does. A failed seal
// has already uploaded packs; what it must not have done is touch the ref.
func TestASealOverTheSuperblockBudgetIsRefusedAndLeavesTheVolumeMountable(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x5b, 0x1d, 0x01})
	body := map[string][]byte{"a.bin": pseudorandom(2<<20, 91)}
	v.create(publishRootInode, "a.bin", body["a.bin"])
	head := v.checkpoint()
	v.verifyBodies(head, body)

	headRaw, err := pelicanobj.ReadMutable(ctx, v.inner, publish.RefPrefix+"main")
	if err != nil {
		t.Fatalf("read the branch head: %v", err)
	}

	// The key table is the one bulk field a caller supplies outright, so it
	// is how a test asks for an oversized superblock without building a
	// volume large enough to grow one. What is being tested is the guard,
	// not the arithmetic that gets a real volume there.
	var keys []superblock.KeyEntry
	for i := 0; i < 700; i++ {
		keys = append(keys, superblock.KeyEntry{
			ID: uint32(i + 1), Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256,
			Wrapped: pseudorandom(800, int64(i)),
		})
	}
	v.create(publishRootInode, "b.bin", pseudorandom(1<<20, 92))
	_, err = publish.Seal(ctx, publish.Options{
		Overlay: v.ov, Inner: v.inner, SpoolDir: t.TempDir(),
		SigningKey: v.priv, Prev: head.Superblock, PrevRaw: head.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index, KeyTable: keys,
	})
	if err == nil {
		t.Fatal("a seal that would have flipped an over-budget superblock succeeded; " +
			"that volume is now unmountable and unpublishable")
	}
	for _, want := range []string{"write budget", "key_table"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so a user cannot tell what grew: %v", want, err)
		}
	}

	// The ref is untouched, which is what makes the refusal cost nothing
	// but the uploads.
	nowRaw, err := pelicanobj.ReadMutable(ctx, v.inner, publish.RefPrefix+"main")
	if err != nil {
		t.Fatalf("read the branch head after the refused seal: %v", err)
	}
	if !bytes.Equal(headRaw, nowRaw) {
		t.Fatal("the refused seal changed the branch head")
	}
	// And the volume still reads, cold, out of the generation that was
	// already there.
	v.verifyBodies(head, body)
}

// A3 through the writer that actually fills a ledger. The growth is
// checkpoint-rate times grace window and has nothing to do with volume
// size, so a mount checkpointing every minute walks an EMPTY volume into
// the read cap in about three days. The cap is what stops that, and it has
// to hold on the seal path, not only in the rule's unit tests.
func TestASealCapsTheCondemnedLedgerAndKeepsTheNewestEntries(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x5b, 0x1d, 0x03})
	body := map[string][]byte{"a.bin": pseudorandom(2<<20, 51)}
	v.create(publishRootInode, "a.bin", body["a.bin"])
	head := v.checkpoint()

	// A parent whose ledger is already over the cap, entries stamped a
	// minute apart the way a fast-checkpointing mount stamps them. All are
	// inside the grace window, so nothing here falls off by age: what
	// bounds this ledger is the cap and only the cap.
	now := time.Now()
	over := superblock.MaxCondemnedEntries + 60
	var ledger []superblock.CondemnedRef
	for i := 0; i < over; i++ {
		ledger = append(ledger, superblock.CondemnedRef{
			Name:            fmt.Sprintf("%064d", i),
			CondemnedAtUnix: now.Add(-time.Duration(over-i) * time.Minute).Unix(),
		})
	}
	prev := *head.Superblock
	prev.CondemnedIndexes = ledger
	prev.CondemnedManifests = ledger
	if err := prev.Sign(v.priv); err != nil {
		t.Fatal(err)
	}
	prevRaw, err := prev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.inner.Put(ctx, publish.RefPrefix+"main", bytes.NewReader(prevRaw)); err != nil {
		t.Fatal(err)
	}

	body["b.bin"] = pseudorandom(1<<20, 52)
	v.create(publishRootInode, "b.bin", body["b.bin"])
	next := v.sealOnly(&publish.Result{Superblock: &prev, Raw: prevRaw})

	for _, space := range []struct {
		what string
		got  []superblock.CondemnedRef
	}{
		{"index", next.Superblock.CondemnedIndexes},
		{"manifest", next.Superblock.CondemnedManifests},
	} {
		if len(space.got) > superblock.MaxCondemnedEntries {
			t.Errorf("the %s ledger came out of the seal with %d entries against a cap of %d; "+
				"unbounded, this is what fills the read cap", space.what, len(space.got), superblock.MaxCondemnedEntries)
		}
		at := map[string]int64{}
		for _, c := range space.got {
			at[c.Name] = c.CondemnedAtUnix
		}
		// The OLDEST go: they are nearest to ageing off, so the cap only
		// shortens a window that was about to close anyway.
		if _, ok := at[fmt.Sprintf("%064d", 0)]; ok {
			t.Errorf("the oldest %s entry survived a full ledger; the cap must drop from the old end", space.what)
		}
		newest := fmt.Sprintf("%064d", over-1)
		if when, ok := at[newest]; !ok {
			t.Errorf("the newest %s entry was dropped by the cap", space.what)
		} else if when != ledger[over-1].CondemnedAtUnix {
			t.Errorf("%s entry re-stamped %d -> %d", space.what, ledger[over-1].CondemnedAtUnix, when)
		}
	}
	// A capped ledger is still a generation, and it still reads cold.
	v.verifyBodies(next, body)
}

// A2's other half: the guard's escape valve is dropping the catalog list,
// and that is only safe if a generation WITHOUT one still seals and still
// reads. The list is a publisher's optimisation — it says which subtrees
// need not be rebuilt — so its absence must cost time and nothing else.
//
// The fixture takes the head a normal seal produced, strips Catalogs, and
// re-signs it: that is exactly the document a trimmed seal writes, and
// building it this way keeps the test independent of how many catalog
// entries it takes to trip the budget.
func TestASealAfterAnOmittedCatalogListRebuildsAndReadsBackByteExact(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0x5b, 0x1d, 0x02})
	body, _ := v.reuseTree(7)
	head := v.checkpoint()
	if len(head.Superblock.Catalogs) == 0 {
		t.Fatal("fixture: the first seal listed no catalogs, so stripping them exercises nothing")
	}

	trimmed := *head.Superblock
	trimmed.Catalogs = nil
	if err := trimmed.Sign(v.priv); err != nil {
		t.Fatal(err)
	}
	trimmedRaw, err := trimmed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := v.inner.Put(ctx, publish.RefPrefix+"main", bytes.NewReader(trimmedRaw)); err != nil {
		t.Fatal(err)
	}

	body["c.bin"] = pseudorandom(1<<20, 8)
	v.create(publishRootInode, "c.bin", body["c.bin"])
	next := v.sealOnly(&publish.Result{Superblock: &trimmed, Raw: trimmedRaw})

	// The slow path really was taken: with no list to compare against,
	// nothing can be carried forward and no subtree can be skipped.
	if next.Stats.SubtreesPruned != 0 || next.Stats.CatalogsReused != 0 {
		t.Errorf("a seal over a generation with no catalog list pruned %d subtrees and reused %d catalogs; "+
			"it cannot know either is safe", next.Stats.SubtreesPruned, next.Stats.CatalogsReused)
	}
	// And it rebuilt the list, so the generation after this one is fast
	// again — the cost of a trim is one seal, not the rest of the volume's
	// life.
	if len(next.Superblock.Catalogs) == 0 {
		t.Error("the seal that rebuilt every catalog recorded no catalog list, so the next seal is slow too")
	}
	// Byte-exact through a COLD cache: every file, including the ones the
	// stripped generation carried, is reachable from what this superblock
	// names.
	v.verifyBodies(next, body)
}
