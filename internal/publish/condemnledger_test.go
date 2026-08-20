package publish_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// INVARIANT: an ordinary seal carries the condemned-PACK ledger forward.
//
// The pack ledger is the only thing standing between a repacked-away pack
// and the next sweep. Repack writes it; every seal after that has to carry
// it, exactly as it carries the two derived-ref ledgers, or the window
// collapses from the grace period to one checkpoint interval — and a mount
// still pinned to the pre-repack generation reads its packs LAZILY for the
// whole session, so it starts answering EIO for content that has not
// changed.
//
// The fixture is a head with a ledger on it, which is what a repack leaves
// behind, followed by an ordinary seal. Nothing here is about how the
// entries got there.
func TestASealCarriesTheCondemnedPackLedgerForward(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xc0, 0x11, 0x01})
	body := map[string][]byte{"a.bin": pseudorandom(2<<20, 71)}
	v.create(publishRootInode, "a.bin", body["a.bin"])
	head := v.checkpoint()

	// What a repack leaves: packs it rewrote and dropped from the list,
	// condemned a moment ago and so squarely inside the grace window.
	now := time.Now()
	condemned := []superblock.CondemnedPack{
		{Name: "p-0000000000000001-0001", CondemnedAtUnix: now.Add(-time.Minute).Unix()},
		{Name: "p-0000000000000002-0002", CondemnedAtUnix: now.Add(-2 * time.Minute).Unix()},
	}
	prev := *head.Superblock
	prev.Condemned = condemned
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

	body["b.bin"] = pseudorandom(1<<20, 72)
	v.create(publishRootInode, "b.bin", body["b.bin"])
	next := v.sealOnly(&publish.Result{Superblock: &prev, Raw: prevRaw})

	kept := map[string]int64{}
	for _, c := range next.Superblock.Condemned {
		kept[c.Name] = c.CondemnedAtUnix
	}
	for _, c := range condemned {
		when, ok := kept[c.Name]
		if !ok {
			t.Fatalf("the seal after a repack dropped %s from the condemned-pack ledger; that pack is named "+
				"by no live superblock and is old by its own name, so the next gc deletes it — the grace "+
				"window a repack promises is one checkpoint interval, not %v",
				c.Name, time.Duration(prev.Params.TGraceSeconds)*time.Second)
		}
		if when != c.CondemnedAtUnix {
			t.Errorf("%s was re-stamped %d -> %d; refreshing a ledger entry restarts its clock every seal "+
				"and it never ages off", c.Name, c.CondemnedAtUnix, when)
		}
	}
	v.verifyBodies(next, body)
}

// INVARIANT: a ledger row is only ever spent on an object some published
// generation named.
//
// The ledger buys an object protection from the moment it stops being
// named until the grace window closes. Retention already keeps every
// hash-named object for that same window from its own mtime, so a row is
// worth exactly the gap between those two instants — and for the segment a
// seal uploads and consolidation merges away within the same seal, that gap
// is zero: no generation ever named it, and nothing can be pinned to it.
//
// This is the growth rate that decides when the cap bites. Charging for the
// in-flight segment doubled it, which halved the time a fast-checkpointing
// mount took to reach the cap, in exchange for protecting nothing.
func TestASealSpendsALedgerRowOnlyOnObjectsAGenerationNamed(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xc0, 0x11, 0x02})
	const seals = 6

	// Every manifest name any head has ever listed. A ledger entry naming
	// anything outside this set is a row bought for an object no reader
	// could have been pinned to.
	everListed := map[string]bool{}
	for _, ref := range v.head.Superblock.Manifests {
		everListed[ref.Name] = true
	}

	var head = v.head
	for i := range seals {
		v.create(publishRootInode, fmt.Sprintf("f%d.bin", i), pseudorandom(256<<10, int64(i)))
		head = v.checkpoint()
		for _, c := range head.Superblock.CondemnedManifests {
			if !everListed[c.Name] {
				t.Errorf("seal %d condemned manifest %s, which no generation ever listed: the seal created "+
					"it and merged it away itself, so the row protects an object nothing can be pinned to "+
					"and only brings the ledger cap forward", i, c.Name[:12])
			}
		}
		for _, ref := range head.Superblock.Manifests {
			everListed[ref.Name] = true
		}
	}

	// And the rate that follows from it: at most one row per seal per key
	// space, because a seal stops listing only what its parent listed.
	if got := len(head.Superblock.CondemnedManifests); got > seals {
		t.Errorf("%d seals left %d rows on the condemned-manifest ledger; more than one per seal means the "+
			"ledger fills in half the time the cap was sized for", seals, got)
	}
}
