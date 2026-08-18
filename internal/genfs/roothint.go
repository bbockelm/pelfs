package genfs

import (
	"context"
	"os"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
)

// The root-catalog hint: the one shortcut through the location layer.
//
// Every other entry a mount reads is found the same way — identity into a
// pack trailer, trailer into an offset — and that indirection is what lets
// a repack move bytes between packs without rewriting the catalogs and
// chunkrefs that name them. The root catalog is the entry that has to be
// found before any of that machinery can be used at all, so the superblock
// records where the publisher put it (superblock.RootHint) and a mount
// tries there first.
//
// It is a hint, so it is checked rather than believed: the bytes it points
// at must hash to the root identity the superblock already records, and
// anything else — a short read, a pack that is no longer listed, an entry
// that has been repacked away, a decode that fails — falls back to
// resolving the root through pack trailers. That fallback is the cost of a
// stale hint, and it is the only cost: nothing here can produce a wrong
// root, and nothing here can fail a mount that would otherwise have
// worked.
//
// The limit worth naming: an ENCRYPTED volume's identities are keyed
// BLAKE3 under a key genfs does not hold (see the package comment), so
// this check cannot pass there and those mounts always take the fallback.
// Publish still records the hint — it is true, and rescue tooling reads
// it — but making it usable would mean authenticating the location some
// other way, which is one pack trailer, which is what the hint exists to
// avoid.

// spillRootFromHint materializes the root catalog straight from the
// superblock's location hint, returning the spill path and whether the
// hint worked. Callers fall back to the ordinary resolution when it did
// not; no error is reported, because there is nothing here a caller could
// act on that the fallback does not handle.
func (fs *FS) spillRootFromHint(ctx context.Context, rootHex string) (string, bool) {
	h := fs.sb.RootCatalogHint
	if h == nil || h.Pack == "" || h.Off < 0 || h.Length <= 0 {
		return "", false
	}
	// The signed pack list is the only thing this extent can be checked
	// against before anything is read, so check it against all of it: a
	// pack that is not listed is stale past use (nothing authorizes reading
	// that object, and its size is unknown), and an extent that does not
	// fit inside the one that IS listed cannot be an entry of it. The
	// length matters more than it looks — it is a buffer size on the
	// whole-pack path, so a hint that survived a truncated pack list or a
	// bad edit would otherwise be an allocation request.
	size := fs.packIndex.size(h.Pack)
	if size <= 0 || h.Off+h.Length > size {
		return "", false
	}
	fp := filepath.Join(fs.catDir, rootHex+".db")
	if _, err := os.Stat(fp); err == nil {
		return fp, true
	}
	unlock := fs.lockFill("cat:" + rootHex)
	defer unlock()
	if _, err := os.Stat(fp); err == nil {
		return fp, true
	}
	loc := packLoc{pack: h.Pack, off: h.Off, length: h.Length}
	stored, err := fs.packRead(ctx, fs.packIndex, rootHex, loc)
	if err != nil {
		return "", false
	}
	plain, err := entrycodec.Decode(stored, entrycodec.AlgZstd, fs.catalogDEK())
	if err != nil {
		return "", false
	}
	// The check that makes following a hint safe. Identity is the truth
	// about which bytes these are; the hint only ever proposed where to
	// look, and a proposal that does not hash to the root the superblock
	// signs is one this mount ignores.
	if chunkid.NewHasher(nil).Sum(plain) != chunkid.Identity(fs.sb.RootCatalog) {
		return "", false
	}
	if err := writeAtomic(fp, plain); err != nil {
		return "", false
	}
	return fp, true
}
