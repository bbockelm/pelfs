package manifest

import (
	"context"
	"fmt"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Packs is the one place that answers "which packs does this generation
// name", from whichever of the two shapes the generation uses.
//
// It exists as a shared helper rather than as five call sites because the
// fallback rule is a FORMAT rule (superblock.Manifests): prefer the
// manifest, fall back to the inline list only when there are no manifest
// refs. Five copies of that is five chances to get the precedence
// backwards, and getting it backwards on a generation that carries both
// would mean reading a stale pack set as the current one.
//
// It never returns a partial answer. manifest.FetchAll hands back what
// verified alongside the error, which is right for a reader chasing one
// object and wrong here: every caller of this — a mount deciding what it
// may read, a sweep deciding what may be deleted, an fsck deciding what
// is missing — reads a short list as a statement about the volume. A
// generation whose manifest cannot be read has an UNKNOWN pack set, and
// saying so is the only safe answer.
//
// The result is in pack-name order, which (names beginning with a
// zero-padded creation stamp) is creation order, oldest first — the same
// order the inline list was carried in, so callers that bet on recency by
// walking it backwards keep the bet they had.
func Packs(ctx context.Context, obj pelicanobj.Store, sb *superblock.Superblock) ([]superblock.PackEntry, error) {
	if !sb.PacksAreInManifests() {
		return sb.PackList, nil
	}
	segments, err := FetchAll(ctx, obj, sb.Manifests)
	if err != nil {
		return nil, fmt.Errorf("manifest: generation %d lists %d manifest segment(s) and one could not be read, "+
			"so its pack set is unknown (this generation keeps its pack list in %s/, not in the superblock): %w",
			sb.Generation, len(sb.Manifests), Dir, err)
	}
	if len(segments) != len(sb.Manifests) {
		// FetchAll only returns a short list with an error, so this is
		// unreachable — and it is checked anyway, because the failure it
		// guards against is an empty pack set that looks authoritative.
		return nil, fmt.Errorf("manifest: generation %d resolved %d of %d manifest segments",
			sb.Generation, len(segments), len(sb.Manifests))
	}
	all := NewSet(segments).All()
	out := make([]superblock.PackEntry, len(all))
	for i, p := range all {
		out[i] = superblock.PackEntry{Name: p.Name, TrailerHash: p.TrailerHash, Size: p.Size}
	}
	return out, nil
}

// Entries converts sealed packs to the pack-list rows the rest of the
// tree passes around. The two structs are the same three fields; the
// conversion exists so that publish, which holds SealedPacks, and every
// reader, which holds PackEntries, meet in one place.
func Entries(packs []packstore.SealedPack) []superblock.PackEntry {
	out := make([]superblock.PackEntry, len(packs))
	for i, p := range packs {
		out[i] = superblock.PackEntry{Name: p.Name, TrailerHash: p.TrailerHash, Size: p.Size}
	}
	return out
}

// Sealed is Entries in reverse, for the builder, which is keyed by the
// sealed-pack shape.
func Sealed(entries []superblock.PackEntry) []packstore.SealedPack {
	out := make([]packstore.SealedPack, len(entries))
	for i, e := range entries {
		out[i] = packstore.SealedPack{Name: e.Name, TrailerHash: e.TrailerHash, Size: e.Size}
	}
	return out
}
