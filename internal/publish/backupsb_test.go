package publish_test

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// THE DR PROPERTY, read the way a rescue would read it. A rescue has the
// packs and nothing else: no ref, no manifest it did not find, no index.
// It digs the superblock backup out of a pack trailer and asks it what
// packs the generation had. The answer must include THIS generation's own
// packs — otherwise the backup is worth no more than the parent generation
// it carries refs to, and the tail is lost.
//
// The backup is built before the last pack is cut, so it names the
// generation minus its tail; that has always been the contract. What
// changed is how it says it. It used to publish a manifest segment of its
// own — an upload per seal, superseded the instant the seal finished, kept
// alive only by a condemned-ledger entry that also cost a superblock row
// per seal. Now it states those packs INLINE and carries its parent's refs
// for the rest, and its pack set is the union of the two.
func TestTheSuperblockBackupNamesThisGenerationsPacksWithoutAManifestOfItsOwn(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x31})
	// Big enough that the seal cuts several packs, so the backup rides in
	// a pack that is not the first and has a real tail to describe.
	v.create(publishRootInode, "a.bin", pseudorandom(6<<20, 41))
	parent := v.head.Superblock
	res := v.checkpoint()

	backup := backupSuperblock(t, v, res)
	if len(backup.PackList) == 0 {
		t.Fatal("the backup states no packs inline; a rescue from it recovers this generation's ancestors only")
	}

	// A rescue's view: the inline list plus whatever the carried refs name.
	rescued := map[string]bool{}
	for _, pe := range backup.PackList {
		rescued[pe.Name] = true
	}
	for _, pe := range packsOf(t, v.inner, &superblock.Superblock{
		Generation: backup.Generation, Manifests: backup.Manifests,
	}) {
		rescued[pe.Name] = true
	}

	// Every pack sealed BEFORE the backup was written is named. The last
	// one is not, by construction — it is the pack the backup is inside.
	named := 0
	for i, sp := range res.NewPacks {
		if rescued[sp.Name] {
			named++
			continue
		}
		if i != len(res.NewPacks)-1 {
			t.Errorf("pack %s was sealed before the backup was written and the backup does not name it",
				sp.Name)
		}
	}
	if named == 0 {
		t.Fatal("fixture: the seal cut one pack, so the backup had no tail to name and this proves nothing")
	}

	// AND IT BOUGHT NOTHING TO SAY IT. Every manifest ref the backup names
	// is one its PARENT named: the backup publishes no segment of its own,
	// so there is no object that only a superseded document names and
	// nothing extra to keep alive on the condemned ledger.
	//
	// Against the parent rather than against the new head, deliberately:
	// consolidation may fold the parent's refs into a merged one, so a
	// segment the new head does not list is an ordinary merge input, not
	// evidence of a backup segment.
	inherited := map[string]bool{}
	for _, ref := range parent.Manifests {
		inherited[ref.Name] = true
	}
	for _, ref := range backup.Manifests {
		if !inherited[ref.Name] {
			t.Errorf("the backup names manifest %s that its parent did not; the backup published a segment "+
				"of its own, which costs an upload per seal and a ledger entry to keep alive", ref.Name[:12])
		}
	}
	if len(parent.Manifests) > 0 && len(backup.Manifests) == 0 {
		t.Error("the backup carries none of its parent's manifest refs, so it cannot name the inherited packs")
	}
}

// The upload count, which is the other half of what A5 bought. A seal
// writes its own segment and, when consolidation fires, the merged result
// — two objects in this fixture. The backup's segment was a THIRD, on
// every seal, for a document superseded before the seal finished.
func TestASealUploadsNoManifestSegmentForItsBackup(t *testing.T) {
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x32})
	v.create(publishRootInode, "a.bin", pseudorandom(6<<20, 42))
	before := countManifestObjects(t, v)
	res := v.checkpoint()
	after := countManifestObjects(t, v)

	if got := after - before; got != 2 {
		t.Errorf("the seal left %d new manifest objects; this fixture's seal writes its own segment and "+
			"one consolidated merge of it with the parent's, and nothing else", got)
	}
	if len(res.Superblock.Manifests) == 0 {
		t.Fatal("fixture: this seal wrote no manifest at all")
	}
}

func countManifestObjects(t *testing.T, v *reuseVol) int {
	t.Helper()
	entries, err := v.inner.ListDir(context.Background(), manifest.Dir)
	if err != nil {
		t.Fatalf("list %s: %v", manifest.Dir, err)
	}
	return len(entries)
}

// THE BACKUP SAYS WHICH BRANCH SEALED IT.
//
// This is the field the retain window is built on, and the backup is the
// document that needs it: a head is fetched by name, so its branch is
// never in doubt, while a backup is dug out of a pack trailer by looking
// and has only what is written inside it to say whose generation it
// describes. A generation NUMBER counts steps along one lineage, so on a
// forked volume it names two documents; the branch turns that pair into
// two answers (internal/retention/lastk.go).
//
// Both halves are asserted, because a stamp that is not signed is a stamp
// anyone able to append to a pack can write, and the window would then be
// aimable: the backup must carry the branch AND still verify under the
// volume key with it there.
func TestTheSuperblockBackupCarriesTheBranchThatSealedIt(t *testing.T) {
	const branch = "release-2"
	v := newReuseVol(t, [16]byte{0x11, 0xd0, 0x33})
	v.create(publishRootInode, "a.bin", pseudorandom(3<<20, 43))

	res, err := publish.Seal(context.Background(), publish.Options{
		Overlay: v.ov, Inner: v.inner, SpoolDir: t.TempDir(),
		SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
		Branch: branch, TargetPackSize: 1 << 20, DedupIndexPath: v.index, SMax: v.smax,
		SQLiteCatalogs: v.sqlite,
	})
	if err != nil {
		t.Fatalf("seal onto %s: %v", branch, err)
	}
	if res.Superblock.Branch != branch {
		t.Errorf("the head sealed onto %s says it belongs to %q", branch, res.Superblock.Branch)
	}
	backup := backupSuperblock(t, v, res)
	if backup.Branch != branch {
		t.Fatalf("the disaster-recovery backup says it belongs to %q, not %q; a scavenged document with no "+
			"branch is one a forked volume cannot attribute, which is the whole hazard", backup.Branch, branch)
	}
	if err := backup.Verify(v.priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("the backup no longer verifies with the branch stamped on it: %v — an unsigned attribution "+
			"could be written by anyone who can append to a pack", err)
	}
	// A seal that states no branch defaults to main rather than to nothing,
	// so an EMPTY Branch is a v0.1.0 writer and only that. The distinction
	// is what lets the window scan tell "no attribution available" from "not
	// this branch".
	plain := v.checkpoint()
	if plain.Superblock.Branch != "main" {
		t.Errorf("a seal that named no branch produced a head claiming %q, so an empty stamp no longer "+
			"means what the window scan reads it as", plain.Superblock.Branch)
	}
}
