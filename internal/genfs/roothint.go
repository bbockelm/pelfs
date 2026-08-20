package genfs

import (
	"context"
	"os"
	"path/filepath"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/superblock"
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
// AN ENCRYPTED VOLUME cannot make that check: its identities are keyed
// BLAKE3 under a key genfs does not hold (see the package comment), so
// the hint used to be skipped outright there and every encrypted mount
// took the fallback — which for the root catalog means fetching pack
// trailers until one claims it, and with nothing to narrow the search
// that is a request per pack of the generation. The one shortcut through
// the location layer was unavailable to exactly the mounts that could
// least afford to do without it.
//
// So those mounts confirm the hint a different way, and the way is the
// same one the fallback would have used — the pack's own TRAILER, whose
// hash the signed pack list records, which is the only record in the
// format that binds an identity to an extent. Note what the GCM open does
// NOT establish: it proves the bytes were sealed under this volume's DEK,
// which any other catalog in the volume also was, so "it decrypted" is not
// "it is the root".
//
// That confirmation is free where it matters. Following the hint reads the
// pack, the whole-pack policy caches it entire, and a pack carries its own
// trailer — so the check is a local read and zero requests. A mount that
// has turned whole-pack caching off pays one trailer range read, against
// one per pack for the fallback it replaces.

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
	pe, listed := fs.packIndex.entry(h.Pack)
	if !listed || pe.Size <= 0 || h.Off+h.Length > pe.Size {
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
	if !fs.hintHolds(ctx, pe, rootHex, loc, plain) {
		return "", false
	}
	if err := writeAtomic(fp, plain); err != nil {
		return "", false
	}
	return fp, true
}

// hintHolds is the check that makes following a hint safe, in the two
// forms a volume can offer it.
//
// Identity first, because it is both the strongest answer and the cheapest
// one: it is the truth about which bytes these are, it needs no request,
// and the hint only ever proposed where to look. A plaintext volume ends
// here in both directions — a proposal that does not hash to the root the
// superblock signs is one this mount ignores.
//
// A keyed-identity volume cannot compute it, so the question moves to the
// authenticated trailer: does the pack itself say this extent is the root
// identity? Same guarantee, one local read (see the note above).
func (fs *FS) hintHolds(ctx context.Context, pe superblock.PackEntry, rootHex string, loc packLoc, plain []byte) bool {
	if chunkid.NewHasher(nil).Sum(plain) == chunkid.Identity(fs.sb.RootCatalog) {
		return true
	}
	if len(fs.catalogDEK()) == 0 {
		return false
	}
	return fs.packIndex.confirms(ctx, pe, rootHex, loc)
}
