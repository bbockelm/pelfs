package publish

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

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
	return consolidate(ctx, carryForward(p.prevManifests(), ref), "pack manifest", p.mergeManifests), nil
}

// backupManifests is sealManifests for the superblock backup that rides
// in the last pack — best effort, and deliberately so.
//
// The backup is built before the final pack is sealed, so it can only
// ever describe the generation minus its tail; that is the documented
// contract and is not new. What is new is that it must name its packs
// through a manifest of its own, since the refs it carries from its
// parent cover the parent's packs and nothing this seal wrote. A small
// extra object, then — and usually not even that: a seal whose content
// fits in one pack has sealed nothing yet at this point, so there is
// nothing to cover and nothing to upload.
//
// It does not consolidate. Merging is a tidy-up for the list a mount
// reads, and nothing mounts a backup; paying a download and an upload to
// shorten a list inside a disaster-recovery artifact would be spending
// the seal's time on the wrong document.
//
// A failure here warns rather than failing the seal: a backup missing
// this generation's own packs is worth less than a complete one and far
// more than a seal that did not happen.
//
// The limit to admit: the final superblock lists a segment covering ALL
// of this generation's packs, so the one written here is superseded the
// moment the seal completes and nothing addressable names it. Retention
// sweeps it once it ages past the grace window — the same gap the design
// already records for a consolidated-away index — after which a rescue
// from this backup recovers the ancestors and not the tail generation.
// Closing it wants the ledger of dropped refs that does not exist yet.
func (p *pipeline) backupManifests(ctx context.Context) []superblock.ManifestRef {
	ref, err := p.publishManifest(ctx, p.manifestPacks(p.pk.sealedSoFar()))
	if err != nil {
		ui.Warn("publish: superblock backup's pack manifest not uploaded ({error}); "+
			"a rescue from it recovers this generation's ancestors only", "error", err)
		return p.prevManifests()
	}
	return carryForward(p.prevManifests(), ref)
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
	// Oldest first, which is the order the list is already in:
	// manifest.Merge lets later inputs win, and later here means newer.
	raw := manifest.Merge(segments)
	if len(raw) > refTargetBytes {
		return superblock.ManifestRef{}, fmt.Errorf("merged manifest is %d bytes, past the %d-byte target", len(raw), refTargetBytes)
	}
	m, err := manifest.Open(raw)
	if err != nil {
		return superblock.ManifestRef{}, err
	}
	return p.putManifest(ctx, raw, uint32(m.Len()))
}
