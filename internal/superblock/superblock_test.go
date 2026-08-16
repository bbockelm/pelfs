package superblock

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testSuperblock populates every field so round-trip tests exercise the
// whole format, not just the scalar spine.
func testSuperblock() *Superblock {
	sb := &Superblock{
		FormatVersion:   FormatV2,
		Generation:      7,
		CreatedUnixNano: 1755200000123456789,
		NextInode:       1 << 20,
		Params: Params{
			SMaxBytes:     8 << 20,
			SMinBytes:     1 << 20,
			InlineMax:     4 << 10,
			TGraceSeconds: 72 * 3600,
			RetainK:       8,
		},
		PackList: []PackEntry{
			{Name: "p-0001-aa", Size: 64 << 20},
			{Name: "p-0002-bb", Size: 12345},
		},
		Shards: []ShardEntry{
			{FirstInode: 1, LastInode: 999},
			{FirstInode: 1000, LastInode: 1 << 40},
		},
		KeyTable: []KeyEntry{
			{ID: 1, Kind: KeyKindDEK, Alg: KeyAlgRSAOAEPSHA256, Wrapped: bytes.Repeat([]byte{0xd0}, 256)},
			{ID: 2, Kind: KeyKindIdentity, Alg: KeyAlgRSAOAEPSHA256, Wrapped: bytes.Repeat([]byte{0x1d}, 256)},
		},
	}
	copy(sb.VolumeID[:], "0123456789abcdef")
	for i := range sb.PrevHash {
		sb.PrevHash[i] = byte(i)
	}
	for i := range sb.RootCatalog {
		sb.RootCatalog[i] = byte(0xc0 + i%16)
	}
	sb.PackList[0].TrailerHash[0] = 0xaa
	sb.PackList[1].TrailerHash[0] = 0xbb
	sb.Shards[0].Identity[31] = 0x01
	sb.Shards[1].Identity[31] = 0x02
	return sb
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

func TestDeterministicRoundTrip(t *testing.T) {
	sb := testSuperblock()
	_, priv := genKey(t)
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	enc1, err := sb.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := Decode(enc1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	enc2, err := dec.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(enc1, enc2) {
		t.Fatalf("Encode->Decode->Encode not byte-identical:\n  %x\n  %x", enc1, enc2)
	}
	// Encoding twice from the same struct must also be stable.
	enc3, err := sb.Encode()
	if err != nil {
		t.Fatalf("Encode again: %v", err)
	}
	if !bytes.Equal(enc1, enc3) {
		t.Fatal("two encodings of the same struct differ")
	}
}

func TestRoundTripPreservesTables(t *testing.T) {
	sb := testSuperblock()
	nextPub, _ := genKey(t)
	sb.NextPub = new([32]byte)
	copy(sb.NextPub[:], nextPub)

	enc, err := sb.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(dec.PackList) != 2 || dec.PackList[0] != sb.PackList[0] || dec.PackList[1] != sb.PackList[1] {
		t.Errorf("PackList mismatch: %+v", dec.PackList)
	}
	if len(dec.Shards) != 2 || dec.Shards[0] != sb.Shards[0] || dec.Shards[1] != sb.Shards[1] {
		t.Errorf("Shards mismatch: %+v", dec.Shards)
	}
	if len(dec.KeyTable) != 2 {
		t.Fatalf("KeyTable length %d, want 2", len(dec.KeyTable))
	}
	for i := range sb.KeyTable {
		want, got := sb.KeyTable[i], dec.KeyTable[i]
		if got.ID != want.ID || got.Kind != want.Kind || got.Alg != want.Alg || !bytes.Equal(got.Wrapped, want.Wrapped) {
			t.Errorf("KeyTable[%d] mismatch: %+v", i, got)
		}
	}
	if dec.Params != sb.Params {
		t.Errorf("Params mismatch: %+v", dec.Params)
	}
	if dec.NextPub == nil || *dec.NextPub != *sb.NextPub {
		t.Errorf("NextPub mismatch: %v", dec.NextPub)
	}
	if dec.VolumeID != sb.VolumeID || dec.Generation != sb.Generation ||
		dec.CreatedUnixNano != sb.CreatedUnixNano || dec.NextInode != sb.NextInode ||
		dec.RootCatalog != sb.RootCatalog || dec.PrevHash != sb.PrevHash {
		t.Error("scalar field mismatch after round trip")
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	pub, priv := genKey(t)
	sb := testSuperblock()
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("Verify freshly signed: %v", err)
	}

	enc, err := sb.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Any single-byte flip must be caught: either the CBOR no longer
	// parses, or the canonical re-encoding no longer verifies.
	for i := range enc {
		tampered := bytes.Clone(enc)
		tampered[i] ^= 0x01
		dec, err := Decode(tampered)
		if err != nil {
			continue
		}
		if err := dec.Verify(pub); err == nil {
			t.Fatalf("flip at byte %d of %d went undetected", i, len(enc))
		}
	}
}

func TestVerifyUsesTrustedKeyNotEmbedded(t *testing.T) {
	trustedPub, _ := genKey(t)
	attackerPub, attackerPriv := genKey(t)

	forged := testSuperblock()
	if err := forged.Sign(attackerPriv); err != nil {
		t.Fatalf("Sign with attacker key: %v", err)
	}
	// Sign embedded the attacker's public key; a verifier that trusted
	// the embedded key would accept this.
	if !bytes.Equal(forged.SigningPub[:], attackerPub) {
		t.Fatal("Sign did not embed the signing public key")
	}
	if err := forged.Verify(attackerPub); err != nil {
		t.Fatalf("sanity: signature invalid even under attacker key: %v", err)
	}
	if err := forged.Verify(trustedPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged superblock verified against the trusted key: %v", err)
	}
}

// successor builds and signs the generation after prev, wired up with the
// correct lineage hash and generation number before mutate/sign.
func successor(t *testing.T, prev *Superblock, priv ed25519.PrivateKey, mutate func(*Superblock)) *Superblock {
	t.Helper()
	prevEnc, err := prev.Encode()
	if err != nil {
		t.Fatalf("encode predecessor: %v", err)
	}
	cur := testSuperblock()
	cur.Generation = prev.Generation + 1
	cur.PrevHash = Hash(prevEnc)
	cur.NextPub = nil
	if mutate != nil {
		mutate(cur)
	}
	if err := cur.Sign(priv); err != nil {
		t.Fatalf("sign successor: %v", err)
	}
	return cur
}

func TestVerifyChain(t *testing.T) {
	trustedPub, trustedPriv := genKey(t)
	nextPub, nextPriv := genKey(t)
	strangerPub, strangerPriv := genKey(t)
	_ = strangerPub

	prev := testSuperblock()
	if err := prev.Sign(trustedPriv); err != nil {
		t.Fatalf("sign prev: %v", err)
	}

	t.Run("normal succession", func(t *testing.T) {
		cur := successor(t, prev, trustedPriv, nil)
		if err := VerifyChain(mustEncode(t, prev), cur, trustedPub); err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
	})

	// A predecessor that announces nextPub as its successor.
	rotating := testSuperblock()
	rotating.NextPub = new([32]byte)
	copy(rotating.NextPub[:], nextPub)
	if err := rotating.Sign(trustedPriv); err != nil {
		t.Fatalf("sign rotating prev: %v", err)
	}

	t.Run("announced rotation succeeds", func(t *testing.T) {
		cur := successor(t, rotating, nextPriv, nil)
		if err := VerifyChain(mustEncode(t, rotating), cur, trustedPub); err != nil {
			t.Fatalf("VerifyChain with announced successor: %v", err)
		}
	})

	t.Run("unannounced rotation fails", func(t *testing.T) {
		cur := successor(t, prev, nextPriv, nil)
		if err := VerifyChain(mustEncode(t, prev), cur, trustedPub); err == nil {
			t.Fatal("rotation without a NextPub announcement was accepted")
		}
	})

	t.Run("stranger key fails even when announced key exists", func(t *testing.T) {
		cur := successor(t, rotating, strangerPriv, nil)
		if err := VerifyChain(mustEncode(t, rotating), cur, trustedPub); err == nil {
			t.Fatal("successor signed by an unrelated key was accepted")
		}
	})

	t.Run("generation skip fails", func(t *testing.T) {
		cur := successor(t, prev, trustedPriv, func(sb *Superblock) {
			sb.Generation = prev.Generation + 2
		})
		if err := VerifyChain(mustEncode(t, prev), cur, trustedPub); err == nil {
			t.Fatal("generation skip was accepted")
		}
	})

	t.Run("prev-hash mismatch fails", func(t *testing.T) {
		cur := successor(t, prev, trustedPriv, func(sb *Superblock) {
			sb.PrevHash[0] ^= 0xff
		})
		if err := VerifyChain(mustEncode(t, prev), cur, trustedPub); err == nil {
			t.Fatal("lineage hash mismatch was accepted")
		}
	})

	t.Run("untrusted predecessor fails", func(t *testing.T) {
		forgedPrev := testSuperblock()
		if err := forgedPrev.Sign(strangerPriv); err != nil {
			t.Fatalf("sign forged prev: %v", err)
		}
		cur := successor(t, forgedPrev, strangerPriv, nil)
		if err := VerifyChain(mustEncode(t, forgedPrev), cur, trustedPub); err == nil {
			t.Fatal("chain rooted at an untrusted predecessor was accepted")
		}
	})
}

// mustEncode returns the wire bytes VerifyChain hashes for lineage.
func mustEncode(t *testing.T, sb *Superblock) []byte {
	t.Helper()
	enc, err := sb.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return enc
}

// A document carrying a field this version does not know must be
// rejected at Verify: the re-encoding cannot reproduce the signed bytes,
// and accepting while silently dropping signed content would be worse.
// (Newer fields readers SHOULD understand are added omitempty — see the
// Superblock evolution rule.)
func TestUnknownFieldDocIsRejected(t *testing.T) {
	pub, priv := genKey(t)
	sb := testSuperblock()
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc, err := sb.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Splice an unknown field in as a future writer would: decode to a
	// generic map, add, re-encode canonically, re-sign with the same key
	// (the future writer signs its own full encoding).
	var m map[string]any
	if err := cbor.Unmarshal(enc, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	m["zz_future_field"] = "from-a-newer-writer"
	m["signature"] = make([]byte, 64)
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := em.Marshal(m)
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}
	m["signature"] = ed25519.Sign(priv, msg)
	wire, err := em.Marshal(m)
	if err != nil {
		t.Fatalf("marshal signed map: %v", err)
	}

	dec, err := Decode(wire)
	if err != nil {
		t.Fatalf("decode with unknown field: %v", err)
	}
	if err := dec.Verify(pub); err == nil {
		t.Fatal("document with an unknown signed field verified; signed content was silently dropped")
	}
}
