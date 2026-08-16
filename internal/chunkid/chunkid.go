// Package chunkid implements chunk identity for the v2 format
// (docs/design-packfs.md): content-defined chunking via FastCDC and
// keyed content addressing via BLAKE3-256.
//
// Chunking is FastCDC (Xia et al., USENIX ATC 2016): a gear rolling hash
// with normalized chunking — a stricter mask before the average size and
// a looser one after, pulling the size distribution toward the average
// without losing boundary-shift resistance. Cut points depend only on
// the input bytes and the (Min, Avg, Max) parameters, never on process
// state, so the same stream always chunks identically — the property
// dedup and publish-what-changed rest on. The gear table is generated
// from a seed constant baked into the source; there is no runtime
// randomness anywhere in the cut decision.
//
// Identity is BLAKE3-256 of the chunk plaintext. Unencrypted volumes
// hash unkeyed (anyone can verify the Merkle path); encrypted volumes
// hash in keyed mode with a per-volume identity key, which preserves
// dedup inside the volume and across its forks while making
// content-confirmation attacks impossible without the key. The identity
// key is separate from the data-encryption keys by design.
package chunkid

import (
	"encoding/hex"
	"fmt"

	"lukechampine.com/blake3"
)

// IdentitySize is the digest length in bytes (BLAKE3-256 in both the
// keyed and unkeyed modes).
const IdentitySize = 32

// Identity is the content address of a chunk.
type Identity [IdentitySize]byte

// Hex returns the lowercase hex encoding of the identity.
func (id Identity) Hex() string {
	return hex.EncodeToString(id[:])
}

// String implements fmt.Stringer.
func (id Identity) String() string {
	return id.Hex()
}

// ParseIdentity decodes the hex form produced by Hex/String.
func ParseIdentity(s string) (Identity, error) {
	var id Identity
	if len(s) != hex.EncodedLen(IdentitySize) {
		return id, fmt.Errorf("chunkid: identity must be %d hex characters, got %d", hex.EncodedLen(IdentitySize), len(s))
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, fmt.Errorf("chunkid: invalid identity %q: %w", s, err)
	}
	return id, nil
}

// Hasher computes chunk identities. The zero value hashes unkeyed;
// use NewHasher to select the mode explicitly. A Hasher is immutable
// and safe for concurrent use.
type Hasher struct {
	key []byte // nil for unkeyed; exactly 32 bytes for keyed
}

// NewHasher returns a Hasher for the given identity key. A nil or empty
// key selects plain BLAKE3-256 (unencrypted volumes); a 32-byte key
// selects keyed BLAKE3 (encrypted volumes). Any other length is a
// programming error and panics — a truncated key must never silently
// degrade to a different identity domain.
func NewHasher(key []byte) Hasher {
	if len(key) == 0 {
		return Hasher{}
	}
	if len(key) != IdentitySize {
		panic(fmt.Sprintf("chunkid: identity key must be nil or %d bytes, got %d", IdentitySize, len(key)))
	}
	// Copy so a caller mutating its key slice cannot change identities
	// out from under the Hasher.
	k := make([]byte, IdentitySize)
	copy(k, key)
	return Hasher{key: k}
}

// Sum returns the identity of data under the Hasher's mode.
func (h Hasher) Sum(data []byte) Identity {
	if h.key == nil {
		return Identity(blake3.Sum256(data))
	}
	d := blake3.New(IdentitySize, h.key)
	d.Write(data) // never errors
	var id Identity
	copy(id[:], d.Sum(nil))
	return id
}
