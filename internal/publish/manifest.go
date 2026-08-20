package publish

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The pack manifest a publish leaves behind (internal/manifest,
// docs/design-packfs.md "The pack list moves out of the superblock").
//
// ONE SEGMENT PER GENERATION, covering the packs that generation created,
// with the previous generation's refs carried forward beside it — the
// same shape as the pack index (packindex.go), for the same reason: a
// merge streams, so a large manifest is never built, only merged, and the
// write path stays proportional to what this publish wrote rather than to
// the volume. That is the whole point. The inline pack list was rewritten
// whole on every seal, so a volume with 200,000 packs paid 14 MB of
// superblock per checkpoint; a generation that adds three packs now
// writes about 216 bytes.
//
// WHAT IT IS NOT is a hint. A pack index is derived from a pack set the
// superblock states some other way, so a seal that fails to write one
// warns and carries on. This IS that statement, so the failure handling
// is the opposite: see sealManifests.

// prevManifests are the refs the previous generation listed, which is
// what this one carries forward.
func (p *pipeline) prevManifests() []superblock.ManifestRef {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.Manifests
}

// prevCondemnedManifests is the parent's ledger of dropped manifest refs,
// which this generation carries forward until the entries age out
// (condemnedrefs.go).
func (p *pipeline) prevCondemnedManifests() []superblock.CondemnedRef {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.CondemnedManifests
}

// manifestPacks is what this generation's own segment must cover: every
// pack it references that no CARRIED ref already names.
//
// That is the packs it created — its own and the source's — plus, exactly
// once in a volume's life, the packs it inherited from a predecessor that
// still kept them inline. A generation whose parent has no manifest refs
// has no carried coverage at all, so a segment holding only the new packs
// would silently drop every inherited pack out of the live set and let
// the next sweep delete data that is still referenced.
//
// That migration segment costs O(inherited packs) bytes, once — which is
// precisely what the OLD code paid on every seal, so the changeover seal
// is no more expensive than the steady state it replaces.
func (p *pipeline) manifestPacks(newPacks []packstore.SealedPack) []packstore.SealedPack {
	var packs []packstore.SealedPack
	if p.o.Prev != nil && !p.o.Prev.PacksAreInManifests() {
		packs = append(packs, manifest.Sealed(p.o.Prev.PackList)...)
	}
	packs = append(packs, newPacks...)
	packs = append(packs, p.providedPacks...)
	return packs
}

// publishManifest uploads one segment and returns the ref naming it, or a
// zero ref when there is nothing to cover.
//
// Content-addressed, like the index and like everything else that is not
// a ref: two publishes that produced the same segment write the same
// object, and an interrupted upload is retried rather than left
// half-named.
func (p *pipeline) publishManifest(ctx context.Context, packs []packstore.SealedPack) (superblock.ManifestRef, error) {
	if len(packs) == 0 {
		return superblock.ManifestRef{}, nil
	}
	b := manifest.NewBuilder()
	for _, sp := range packs {
		if err := b.Add(sp); err != nil {
			return superblock.ManifestRef{}, err
		}
	}
	raw := b.Encode()
	// Read back what is about to be uploaded, for the count and for the
	// check: the builder's own tally counts additions, the segment's
	// counts packs (the table collapses a name added twice), and a
	// generation must never name a manifest this build cannot open.
	m, err := manifest.Open(raw)
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	return p.putManifest(ctx, raw, uint32(m.Len()))
}

func (p *pipeline) putManifest(ctx context.Context, raw []byte, packs uint32) (superblock.ManifestRef, error) {
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, manifest.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.ManifestRef{}, fmt.Errorf("%s: %w", name, err)
	}
	return superblock.ManifestRef{Name: name, Hash: hash, Size: int64(len(raw)), Packs: packs}, nil
}

// sealManifests publishes this generation's segment and returns the refs
// the superblock records: the carried set plus this one, consolidated.
//
// FAILURE IS NOT SWALLOWED, and this is where the manifest parts company
// with the pack index. An empty result is not "no manifest, carry on" —
// it is an instruction to buildSuperblock to write the inline pack list
// instead, which is the shape every older generation already has and
// every reader still understands. The fallback is only available while
// this publish can state the whole pack set from what it holds:
//
//   - A parent that kept its packs inline (or no parent at all) can be
//     restated inline, so a failed upload degrades to the old shape and
//     the next seal tries again. Slow, complete, warned about.
//   - A parent that keeps its packs in a manifest cannot: publish does
//     not hold that list, and inlining it would mean fetching and
//     re-uploading the whole thing — the cost this change exists to
//     remove — while a generation that simply omitted it would be signed,
//     valid-looking, and missing most of its packs. So the seal FAILS.
//     A failed seal loses nothing: the ref never flips, and the packs
//     already uploaded are picked up by the retry.
func (p *pipeline) sealManifests(ctx context.Context, newPacks []packstore.SealedPack) ([]superblock.ManifestRef, error) {
	ref, err := p.publishManifest(ctx, p.manifestPacks(newPacks))
	if err != nil {
		if p.o.Prev != nil && p.o.Prev.PacksAreInManifests() {
			return nil, fmt.Errorf("publish: pack manifest not uploaded, and generation %d keeps its pack list in %s/ "+
				"so this generation cannot state its pack set without one: %w", p.o.Prev.Generation, manifest.Dir, err)
		}
		ui.Warn("publish: pack manifest not uploaded ({error}); this generation records its pack list inline instead",
			"error", err)
		return nil, nil
	}
	// What consolidation stops listing is condemned, not forgotten, and
	// the stake is higher here than for an index: a generation inside the
	// retain window names those segments, and a segment swept out from
	// under it leaves it unable to state its own pack set. See
	// condemnedrefs.go, including what the ledger still does not fix.
	prev := p.prevManifests()
	after := consolidate(ctx, carryForward(prev, ref), "pack manifest", p.mergeManifests)
	p.droppedManifests = append(p.droppedManifests, droppedRefs(prev, after)...)
	return after, nil
}

// sealedPackList is what the BRANCH HEAD states inline: nothing at all
// when this generation records manifest refs, the whole pack set
// otherwise.
//
// The rule is superblock.Manifests': one way or the other, never both.
// Writing both would keep every byte the manifest exists to remove and
// would hand a reader two lists that can disagree — superblock.Validate
// refuses a head shaped that way.
//
// In the inline shape the same three groups have to be named, because
// every one of them holds bytes something still references and retention
// deletes any pack no live superblock names:
//
//   - what the parent named, carried forward — TRANSFORM's content reuse
//     depends on it, since a carried chunkref points into one of the
//     parent's packs. Trimming dead packs is repack's job. In the manifest
//     shape this is the carried refs; if that ever grows a filter, reuse
//     must be gated on the surviving set in the same change.
//   - the packs this seal wrote.
//   - the packs the SOURCE uploaded, holding content it provided rather
//     than content this seal chunked.
func (p *pipeline) sealedPackList(newPacks []packstore.SealedPack, manifests []superblock.ManifestRef) []superblock.PackEntry {
	if len(manifests) > 0 {
		return nil
	}
	var out []superblock.PackEntry
	if p.o.Prev != nil {
		out = append(out, p.o.Prev.PackList...)
	}
	out = append(out, manifest.Entries(newPacks)...)
	out = append(out, manifest.Entries(p.providedPacks)...)
	return out
}

// backupPackList is what the DISASTER-RECOVERY BACKUP states inline: the
// packs this seal has cut so far, the source's, and an inline parent list
// if the parent kept one.
//
// THE BACKUP IS THE ONE DOCUMENT THAT STATES ITS PACK SET BOTH WAYS, and
// saying why is most of the reason this function exists. It rides in the
// last pack, so it is built before the seal has finished cutting packs and
// long before a manifest covering them could exist; what it carries from
// its parent (prevManifests) names the parent's packs and nothing this
// seal wrote. So a rescue reads its pack set as the UNION of the inline
// list and the carried refs. Nothing mounts a backup, and
// superblock.Validate — which refuses that shape for a branch head, where
// two lists can disagree about what is live — is a writer's check this
// document is deliberately not put through.
//
// WHAT IT REPLACED, because it was a whole mechanism and its absence
// should not read as an oversight: the backup used to publish a manifest
// segment of its own covering exactly these packs. That was an upload on
// every seal for an object the final superblock superseded the instant it
// landed, and since nothing addressable named it afterwards it also had to
// be CONDEMNED — one ledger entry per seal, on the ledger whose growth is
// already what fills a superblock. Both are gone. The DR property is not:
// the backup still names the tail generation's packs, it just says so
// inline instead of buying an object to say it in.
//
// The limit, unchanged: the backup describes the generation minus the pack
// that carries it, so a rescue from it is "the newest generation minus its
// tail".
func (p *pipeline) backupPackList() []superblock.PackEntry {
	var out []superblock.PackEntry
	// A parent that kept its packs inline has nothing else naming them —
	// its carried refs are empty — so the backup carries that list too.
	if p.o.Prev != nil && !p.o.Prev.PacksAreInManifests() {
		out = append(out, p.o.Prev.PackList...)
	}
	out = append(out, manifest.Entries(p.pk.sealedSoFar())...)
	out = append(out, manifest.Entries(p.providedPacks)...)
	return out
}

// mergeManifests fetches the given refs, merges them and uploads the
// result. It is mergeIndexes for the other key space, and the two are
// deliberately the same shape — the policy driving both is shared
// (consolidate.go), and only this part differs.
func (p *pipeline) mergeManifests(ctx context.Context, refs []superblock.ManifestRef) (superblock.ManifestRef, error) {
	segments, err := manifest.FetchAll(ctx, p.o.Inner, refs)
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	// ALL of them or none. For an index a partial merge would lose
	// coverage; here it would lose PACKS — the merged segment would
	// replace refs naming packs it does not name, and the next sweep would
	// delete them.
	if len(segments) != len(refs) {
		return superblock.ManifestRef{}, fmt.Errorf("%d of %d manifests fetched", len(segments), len(refs))
	}
	// Oldest first, which is the order the list is already in: the merge
	// lets later inputs win, and later here means newer. It streams to a
	// file and is hashed on the way, for the reason mergeIndexes gives.
	out, err := os.CreateTemp(p.tmpDir, "mergeman-*")
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	defer os.Remove(out.Name()) //nolint:errcheck
	defer out.Close()           //nolint:errcheck
	spool, err := os.CreateTemp(p.tmpDir, "mergespool-*")
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	defer os.Remove(spool.Name()) //nolint:errcheck
	defer spool.Close()           //nolint:errcheck

	h := blake3.New(32, nil)
	packs, err := manifest.MergeTo(io.MultiWriter(out, h), spool, segments)
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	if size > refTargetBytes {
		return superblock.ManifestRef{}, fmt.Errorf("merged manifest is %d bytes, past the %d-byte ceiling", size, refTargetBytes)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return superblock.ManifestRef{}, err
	}
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	name := hex.EncodeToString(hash[:])
	if err := p.o.Inner.Put(ctx, manifest.Dir+"/"+name, out); err != nil {
		return superblock.ManifestRef{}, fmt.Errorf("%s: %w", name, err)
	}
	return superblock.ManifestRef{Name: name, Hash: hash, Size: size, Packs: uint32(packs)}, nil
}
