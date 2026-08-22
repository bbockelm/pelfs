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

// The root-catalog hint is optional in both directions, which is the whole
// of its compatibility story: a superblock written before it existed
// decodes with none and verifies, and one carrying it round-trips and
// verifies too. Being a nilable, omitempty field is what makes both true —
// an absent hint contributes nothing to the encoding, so it cannot change
// the bytes an older generation was signed over.
func TestRootHintIsOptionalInBothDirections(t *testing.T) {
	pub, priv := genKey(t)

	old := testSuperblock()
	if err := old.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, old)
	if bytes.Contains(enc, []byte("root_catalog_hint")) {
		t.Fatal("a superblock with no hint still wrote the key")
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode hintless superblock: %v", err)
	}
	if dec.RootCatalogHint != nil {
		t.Fatalf("decoded a hint out of a superblock that has none: %+v", dec.RootCatalogHint)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("a superblock written before the hint existed no longer verifies: %v", err)
	}

	hinted := testSuperblock()
	hinted.RootCatalogHint = &RootHint{Pack: "p-0002-bb", Off: 4096, Length: 1234}
	if err := hinted.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dec, err = Decode(mustEncode(t, hinted))
	if err != nil {
		t.Fatalf("decode hinted superblock: %v", err)
	}
	if dec.RootCatalogHint == nil || *dec.RootCatalogHint != *hinted.RootCatalogHint {
		t.Fatalf("hint round-tripped as %+v, want %+v", dec.RootCatalogHint, hinted.RootCatalogHint)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("verify hinted superblock: %v", err)
	}
}

// A reader that does not know the field must still be able to READ the
// document — the hint is a shortcut, not content anything depends on. What
// such a reader must not do is claim the document verified, which is the
// standing rule for any dropped signed field (TestUnknownFieldDocIsRejected)
// and is why the hint is worth nothing to a reader that cannot see it.
func TestHintedSuperblockDecodesForAReaderThatIgnoresIt(t *testing.T) {
	_, priv := genKey(t)
	sb := testSuperblock()
	sb.RootCatalogHint = &RootHint{Pack: "p-0001-aa", Off: 64, Length: 900}
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// The struct as it was before the field existed, decoded from bytes
	// written after.
	var older struct {
		Generation  uint64      `cbor:"generation"`
		RootCatalog [32]byte    `cbor:"root_catalog"`
		PackList    []PackEntry `cbor:"pack_list"`
	}
	if err := cbor.Unmarshal(mustEncode(t, sb), &older); err != nil {
		t.Fatalf("a reader that ignores the hint could not decode: %v", err)
	}
	if older.Generation != sb.Generation || older.RootCatalog != sb.RootCatalog ||
		len(older.PackList) != len(sb.PackList) {
		t.Fatalf("the fields such a reader does know came back wrong: %+v", older)
	}
}

// The multi-pack index list is optional in both directions, the same
// compatibility story as the root-catalog hint and for the same reason: a
// superblock written before indexes existed must still verify, and a
// reader that ignores the field must still be able to read the document.
// A nilable, omitempty field is what makes both true — an absent list
// contributes nothing to the encoding, so it cannot change the bytes an
// older generation was signed over.
func TestPackIndexesAreOptionalInBothDirections(t *testing.T) {
	pub, priv := genKey(t)

	old := testSuperblock()
	if err := old.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, old)
	if bytes.Contains(enc, []byte("pack_indexes")) {
		t.Fatal("a superblock listing no index still wrote the key")
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode index-less superblock: %v", err)
	}
	if dec.PackIndexes != nil {
		t.Fatalf("decoded indexes out of a superblock that lists none: %+v", dec.PackIndexes)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("a superblock written before indexes existed no longer verifies: %v", err)
	}

	indexed := testSuperblock()
	indexed.PackIndexes = []IndexRef{
		{Name: "aa11", Hash: [32]byte{0xaa, 0x11}, Size: 4096, Entries: 128, Packs: 3},
		{Name: "bb22", Hash: [32]byte{0xbb, 0x22}, Size: 1 << 20, Entries: 65536, Packs: 200},
	}
	if err := indexed.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dec, err = Decode(mustEncode(t, indexed))
	if err != nil {
		t.Fatalf("decode indexed superblock: %v", err)
	}
	if len(dec.PackIndexes) != len(indexed.PackIndexes) {
		t.Fatalf("index list round-tripped as %+v", dec.PackIndexes)
	}
	for i, want := range indexed.PackIndexes {
		if dec.PackIndexes[i] != want {
			t.Errorf("index ref %d round-tripped as %+v, want %+v", i, dec.PackIndexes[i], want)
		}
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("verify indexed superblock: %v", err)
	}

	// A reader that does not know the field must still READ the document.
	// It must not claim it verified — that is the standing rule for any
	// dropped signed field — but the index list is a shortcut, and nothing
	// a reader needs depends on seeing it.
	var older struct {
		Generation  uint64      `cbor:"generation"`
		RootCatalog [32]byte    `cbor:"root_catalog"`
		PackList    []PackEntry `cbor:"pack_list"`
	}
	if err := cbor.Unmarshal(mustEncode(t, indexed), &older); err != nil {
		t.Fatalf("a reader that ignores the index list could not decode: %v", err)
	}
	if older.Generation != indexed.Generation || len(older.PackList) != len(indexed.PackList) {
		t.Fatalf("the fields such a reader does know came back wrong: %+v", older)
	}
}

// The manifest field is the one addition that is NOT optional in both
// directions, and the compatibility story is the opposite of the index
// list's: a generation that names manifests has no inline pack list, so a
// reader that drops the field would mount a volume that looks empty. It
// does not get the chance. Decoding drops unknown keys and Verify
// re-encodes what it decoded, so an old binary's re-encoding is missing
// signed content and the signature fails — a refusal at the trust
// boundary rather than an empty tree.
//
// This test stands in for that old binary by dropping the field itself.
func TestAManifestOnlyGenerationIsRefusedByAReaderThatDropsTheField(t *testing.T) {
	pub, priv := genKey(t)

	sb := testSuperblock()
	sb.PackList = nil
	sb.Manifests = []ManifestRef{
		{Name: "aa11", Hash: [32]byte{0xaa, 0x11}, Size: 8192, Packs: 113},
		{Name: "bb22", Hash: [32]byte{0xbb, 0x22}, Size: 1 << 20, Packs: 14000},
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, sb)
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("a reader that knows the field could not verify: %v", err)
	}
	if len(dec.Manifests) != len(sb.Manifests) || !dec.PacksAreInManifests() {
		t.Fatalf("manifest refs round-tripped as %+v", dec.Manifests)
	}
	for i, want := range sb.Manifests {
		if dec.Manifests[i] != want {
			t.Errorf("manifest ref %d round-tripped as %+v, want %+v", i, dec.Manifests[i], want)
		}
	}

	dropped := *dec
	dropped.Manifests = nil
	if err := dropped.Verify(pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a reader that dropped the manifest list verified anyway (%v); it would serve an empty volume", err)
	}
}

// The condemned-ref ledgers are additive, which is the whole basis for
// adding them to a signed document: a superblock written before they
// existed must still encode without the keys, decode with empty ledgers,
// and verify. Get that wrong and every generation on disk stops
// verifying, because Verify re-encodes what it decoded.
func TestCondemnedRefLedgersAreAdditive(t *testing.T) {
	pub, priv := genKey(t)

	old := testSuperblock()
	if err := old.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, old)
	for _, key := range []string{"condemned_indexes", "condemned_manifests"} {
		if bytes.Contains(enc, []byte(key)) {
			t.Fatalf("a superblock condemning nothing still wrote %q", key)
		}
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode ledger-less superblock: %v", err)
	}
	if dec.CondemnedIndexes != nil || dec.CondemnedManifests != nil {
		t.Fatalf("decoded ledgers out of a superblock that has none: %+v / %+v",
			dec.CondemnedIndexes, dec.CondemnedManifests)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("a superblock written before the ledgers existed no longer verifies: %v", err)
	}

	ledgered := testSuperblock()
	ledgered.CondemnedIndexes = []CondemnedRef{
		{Name: "aa11", CondemnedAtUnix: 1755200000},
		{Name: "bb22", CondemnedAtUnix: 1755300000},
	}
	ledgered.CondemnedManifests = []CondemnedRef{{Name: "cc33", CondemnedAtUnix: 1755400000}}
	if err := ledgered.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	dec, err = Decode(mustEncode(t, ledgered))
	if err != nil {
		t.Fatalf("decode ledgered superblock: %v", err)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("verify ledgered superblock: %v", err)
	}
	for i, want := range ledgered.CondemnedIndexes {
		if dec.CondemnedIndexes[i] != want {
			t.Errorf("condemned index %d round-tripped as %+v, want %+v", i, dec.CondemnedIndexes[i], want)
		}
	}
	for i, want := range ledgered.CondemnedManifests {
		if dec.CondemnedManifests[i] != want {
			t.Errorf("condemned manifest %d round-tripped as %+v, want %+v", i, dec.CondemnedManifests[i], want)
		}
	}
}

// Every inode a lineage can produce has to fit in a SIGNED 64-bit
// integer, because the catalog and the overlay are SQLite and its
// integers are signed. A lineage with the top bit set makes inodes that
// round-trip as negative and fail to scan back.
func TestEveryLineageProducesInodesThatFitInInt64(t *testing.T) {
	for _, l := range []uint32{0, 1, 1 << 10, MaxLineage} {
		first := FirstInode(l)
		if first > 1<<63-1 {
			t.Errorf("lineage %d starts at %d, past the signed 64-bit range", l, first)
		}
		if int64(first) < 0 {
			t.Errorf("lineage %d starts at a value that is negative as int64", l)
		}
		if got := LineageOf(first); got != l {
			t.Errorf("lineage %d round-trips as %d", l, got)
		}
	}
	// And the last inode a lineage can allocate is still positive.
	last := FirstInode(MaxLineage) + (1<<InodeLineageShift - 3)
	if int64(last) < 0 {
		t.Errorf("the last inode of the last lineage (%d) is negative as int64", last)
	}
}
