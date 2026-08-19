package superblock

import (
	"crypto/ed25519"
	"testing"
)

// The superblock is fetched from mutable, attacker-writable federation
// storage BEFORE any trust is established (verification needs the decoded
// document). Decode must never panic, and nothing that fails Verify may
// be mistaken for trusted.
//
//	go test -fuzz FuzzDecodeVerify ./internal/superblock/
func FuzzDecodeVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sb := &Superblock{
		FormatVersion:   FormatV2,
		Generation:      7,
		CreatedUnixNano: 1234,
		PackList:        []PackEntry{{Name: "p-1-aa", Size: 10}},
		KeyTable:        []KeyEntry{{ID: 1, Kind: KeyKindDEK, Alg: KeyAlgRSAOAEPSHA256, Wrapped: []byte("xx")}},
		Condemned:       []CondemnedPack{{Name: "p-0-zz", CondemnedAtUnix: 99}},
		// A ref names an object this reader will fetch on the strength of
		// the superblock alone, so the seed carries one.
		PackIndexes: []IndexRef{{Name: "ix", Hash: [32]byte{0x5a}, Size: 64, Entries: 2, Packs: 1}},
		Manifests:   []ManifestRef{{Name: "mf", Hash: [32]byte{0xa5}, Size: 88, Packs: 1}},
	}
	if err := sb.Sign(priv); err != nil {
		f.Fatal(err)
	}
	valid, err := sb.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{0xa0})       // empty CBOR map
	f.Add([]byte{0xff, 0xff}) // garbage
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dec, err := Decode(data)
		if err != nil {
			return
		}
		// Anything that decodes but is not byte-derived from the signed
		// document must fail verification under the real key.
		if err := dec.Verify(pub); err == nil {
			reenc, encErr := dec.Encode()
			if encErr != nil || string(reenc) != string(valid) {
				t.Fatalf("mutated superblock verified under the trusted key (len %d)", len(data))
			}
		}
		// Chain verification must also never panic on arbitrary prevRaw.
		_ = VerifyChain(data, sb, pub)
	})
}
