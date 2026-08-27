package importvol

import (
	"crypto/rsa"
	"crypto/subtle"
	"fmt"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// Custody is the answer to "may these two volumes' bytes be moved without
// being read".
//
// # The whole of the encryption story, in one place
//
// A copy carries entries STORED — already compressed, already encrypted —
// which is what makes it need no data key and unable to corrupt what it
// cannot read. The price is that the bytes stay in the encryption domain
// they were written in, and TWO THINGS have to line up for that to be
// legal in the destination:
//
//   - THE DATA KEY. A stored entry decrypts under the DEK that encrypted
//     it and no other. If the destination's DEK is a different key, the
//     copied bytes are unreadable there, and the only repair is to
//     decrypt and re-encrypt — a real repack, which needs the source's
//     DEK and reads every byte.
//   - THE IDENTITY KEY. On an encrypted volume a chunk's identity is
//     keyed BLAKE3 over its plaintext (superblock.KeyKindIdentity), so
//     identity means something DIFFERENT under a different key. Carrying
//     an identity across that boundary would put an entry in our packs
//     whose name nothing on this side can recompute — dedup would be
//     wrong in the direction that loses data, and `pelfs fsck` could
//     never confirm a chunk.
//
// So an import is allowed exactly when the two volumes are in ONE domain:
// both plaintext, or both encrypted under the same DEK and the same
// identity key. Everything else is refused by name, and the refusal says
// what it would take.
//
// # What is NOT required to match
//
// The KEY ID. A key id is an index into one volume's own key table, so
// the same key can be id 1 on one volume and id 3 on another. Chunkrefs
// carry the id, and an import is rebuilding the catalogs anyway, so the
// ids are TRANSLATED on the way through (KeyIDs). Getting this wrong
// would be silent: merge's sameRef deliberately ignores CLen, Alg and
// KeyID, so any path that compared refs across a key boundary would call
// a plaintext ref and an encrypted ref equal.
type Custody struct {
	// KeyIDs maps a source key id to this volume's id for the same key.
	// Empty when both volumes are plaintext, in which case every ref
	// carries key id 0 and there is nothing to translate.
	KeyIDs map[int64]int64
	// Encrypted reports that both sides are, for a caller that wants to
	// say so.
	Encrypted bool
}

// Translate returns the destination key id for a chunkref's recorded one.
// An id the source's key table does not name is refused rather than
// passed through: a ref pointing at a key nobody has is a file that never
// opens, and it would be signed before anyone found out.
func (c *Custody) Translate(srcKeyID int64) (int64, error) {
	if srcKeyID == 0 {
		// Plaintext, on either kind of volume. Key id 0 is reserved to
		// mean exactly that and never appears in a key table.
		return 0, nil
	}
	if id, ok := c.KeyIDs[srcKeyID]; ok {
		return id, nil
	}
	return 0, fmt.Errorf("%w: a chunk record names source key id %d, which this volume's key "+
		"table has no equivalent for", ErrForeignCustody, srcKeyID)
}

// CheckCustody decides whether the source's stored bytes may be carried
// into the destination untouched, and how key ids translate if so.
//
// kek is the user key-encryption key, needed only when either side is
// encrypted — it is the only thing that can prove two wrapped keys are
// the same key, since RSA-OAEP is randomized and the wrapped bytes of one
// key differ every time it is wrapped.
func CheckCustody(src, dst *superblock.Superblock, kek *rsa.PrivateKey) (*Custody, error) {
	srcEnc, dstEnc := isEncrypted(src), isEncrypted(dst)
	switch {
	case !srcEnc && !dstEnc:
		return &Custody{}, nil
	case srcEnc && !dstEnc:
		return nil, fmt.Errorf("%w: the source volume is encrypted and this one is not. Its pack "+
			"entries are ciphertext and its chunk identities are keyed, so copying them here would "+
			"produce a volume whose own readers cannot verify or decrypt what it holds. Importing "+
			"across that boundary means decrypting and re-chunking every byte — a real repack, "+
			"which needs the source's data key — and is not implemented", ErrForeignCustody)
	case !srcEnc && dstEnc:
		return nil, fmt.Errorf("%w: this volume is encrypted and the source is not. A stored copy "+
			"would put plaintext entries under unkeyed identities into an encrypted volume, where "+
			"every other chunk is ciphertext under a keyed identity. Importing across that boundary "+
			"means chunking and encrypting every byte — a real repack — and is not implemented",
			ErrForeignCustody)
	}
	if kek == nil {
		return nil, fmt.Errorf("%w: both volumes are encrypted, and only the key-encryption key can "+
			"tell whether they are encrypted under the SAME data key — the wrapped bytes differ "+
			"every time a key is wrapped. Pass --encrypt-key", ErrForeignCustody)
	}
	srcKeys, err := unwrapTable(kek, src, "the source volume")
	if err != nil {
		return nil, err
	}
	dstKeys, err := unwrapTable(kek, dst, "this volume")
	if err != nil {
		return nil, err
	}
	if !sameKey(srcKeys[superblock.KeyKindIdentity], dstKeys[superblock.KeyKindIdentity]) {
		return nil, fmt.Errorf("%w: the two volumes use different chunk-identity keys, so an "+
			"identity means a different thing on each. Copying entries across would name bytes "+
			"this volume cannot recompute the identity of; only re-chunking every byte under this "+
			"volume's identity key would fix it, and that is a real repack", ErrForeignCustody)
	}
	if !sameKey(srcKeys[superblock.KeyKindDEK], dstKeys[superblock.KeyKindDEK]) {
		return nil, fmt.Errorf("%w: the two volumes use different data-encryption keys. The copied "+
			"entries would be ciphertext this volume's readers hold no key for; decrypting and "+
			"re-encrypting them is a real repack and is not implemented", ErrForeignCustody)
	}
	// Same custody. The ids may still differ, because an id is an index
	// into one volume's own table.
	ids := map[int64]int64{}
	for _, se := range src.KeyTable {
		key, err := superblock.UnwrapKey(kek, se.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("%w: unwrap the source key %d: %v", ErrForeignCustody, se.ID, err)
		}
		for _, de := range dst.KeyTable {
			dk, err := superblock.UnwrapKey(kek, de.Wrapped)
			if err != nil {
				continue
			}
			if de.Kind == se.Kind && sameKey(key, dk) {
				ids[int64(se.ID)] = int64(de.ID)
				break
			}
		}
	}
	return &Custody{KeyIDs: ids, Encrypted: true}, nil
}

// isEncrypted reports whether a generation writes ciphertext. The key
// table is the statement: a volume that has one wraps a DEK, and one that
// does not writes plaintext with key id 0 everywhere.
func isEncrypted(sb *superblock.Superblock) bool {
	if sb == nil {
		return false
	}
	for _, k := range sb.KeyTable {
		if k.Kind == superblock.KeyKindDEK {
			return true
		}
	}
	return sb.CatalogKeyID != 0
}

func unwrapTable(kek *rsa.PrivateKey, sb *superblock.Superblock, who string) (map[superblock.KeyKind][]byte, error) {
	out := map[superblock.KeyKind][]byte{}
	for _, k := range sb.KeyTable {
		key, err := superblock.UnwrapKey(kek, k.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("%w: --encrypt-key does not unwrap %s's key %d (%v). Both "+
				"volumes have to be under one key-encryption key for their contents to be "+
				"comparable at all", ErrForeignCustody, who, k.ID, err)
		}
		out[k.Kind] = key
	}
	return out, nil
}

// sameKey compares in constant time, which costs nothing and keeps a
// secret comparison from being a timing oracle by habit.
func sameKey(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
