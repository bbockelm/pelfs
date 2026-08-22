package superblock

// THE EVOLUTION RULE, EXERCISED BY THE FIELD MOST LIKELY TO BREAK IT.
//
// Verify re-encodes the decoded struct, so a non-omitempty addition changes
// the canonical form of every document already on disk and invalidates
// every signature ever made. Branch is exactly the shape of addition that
// tempts someone to write `Branch string \`cbor:"branch"\`` — one scalar,
// almost always set by current writers — and the cost of getting it wrong
// is not a failed test but a volume nobody can mount or publish to again.
//
// So the evidence here is not a round trip through the current encoder,
// which would prove nothing (the current encoder is what is on trial). It
// is WIRE BYTES CAPTURED FROM THE v0.1.0 ENCODER, checked in under
// testdata/, decoded and verified by the code as it stands now.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// v010Golden is one v0.1.0 superblock: bytes produced by the encoder as it
// stood before the Branch field existed, over a struct with every optional
// field populated (maint, catalogs, root hint, both condemned-ref ledgers,
// next_pub), signed by the fixed key in the companion file.
func v010Golden(t *testing.T) ([]byte, []byte) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return b
	}
	return read("v010-superblock.hex"), read("v010-signing-pub.hex")
}

// A SUPERBLOCK WRITTEN BEFORE THE FIELD EXISTED STILL VERIFIES.
//
// Three claims, and the third is the one that actually pins the rule: the
// old bytes decode, they verify under the key that signed them, and
// re-encoding what was decoded reproduces those bytes EXACTLY. The third
// is what a non-omitempty tag would break — Verify's signing message is a
// re-encoding, so a struct that insists on writing `branch: ""` signs a
// different message than the one the v0.1.0 writer signed, and every
// document in every volume fails at the trust boundary at once.
func TestAV010SuperblockStillVerifies(t *testing.T) {
	golden, pub := v010Golden(t)

	if bytes.Contains(golden, []byte("branch")) {
		t.Fatal("the captured v0.1.0 bytes already contain a branch key; the fixture is not v0.1.0")
	}
	sb, err := Decode(golden)
	if err != nil {
		t.Fatalf("a v0.1.0 superblock no longer decodes: %v", err)
	}
	if sb.Branch != "" {
		t.Errorf("a v0.1.0 superblock decoded with Branch=%q; it states none", sb.Branch)
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("a v0.1.0 superblock no longer verifies under the key that signed it: %v — every generation "+
			"in every existing volume is now unreadable, which is what omitempty on Branch exists to prevent", err)
	}
	again, err := sb.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(again, golden) {
		t.Fatalf("re-encoding a decoded v0.1.0 superblock produced %d bytes, not the %d it came from; "+
			"Verify signs over exactly this re-encoding, so the two can never differ", len(again), len(golden))
	}
	// And the lineage hash, which is defined over wire bytes rather than
	// over a re-encoding, is unmoved either way — the successor generation
	// that names this one by PrevHash still names it.
	if Hash(again) != Hash(golden) {
		t.Fatal("the lineage hash of a v0.1.0 superblock moved")
	}
}

// A BRANCH-STAMPED SUPERBLOCK IS REFUSED BY A READER THAT DROPS THE FIELD,
// AND THAT IS THE ACCEPTED DIRECTION.
//
// The old binary's decoder tolerates unknown keys, so it parses a v0.2
// document happily; Verify then re-encodes what it parsed, the branch key
// is gone from the message, and the signature fails. A v0.1.0 `pelfs` will
// therefore refuse a generation a v0.2 writer sealed.
//
// WHY THAT IS ACCEPTABLE, and it is a decision rather than a shrug:
//
//   - It is a REFUSAL, not a misread. ErrBadSignature at the trust boundary
//     is the same failure the manifest-only change already accepted, and it
//     is the safe direction the package comment argues for: an old reader
//     that silently ignored signed content would be mounting a document it
//     does not understand.
//   - NOBODY RE-SIGNS A BACKUP. A reader has no signing key, so there is no
//     path where the field is laundered away and the result still verifies
//     — the only outcome of an old reader meeting a new document is the
//     refusal above. The field cannot be stripped into a document that
//     passes.
//   - The alternative was WORSE, and it is worth writing down because it
//     looks tidier: stamping only the BACKUP and leaving heads in the
//     v0.1.0 shape would keep old mounts working, and would leave an old
//     `pelfs gc` able to read the volume while failing to verify the new
//     backups — reading them as absent, reporting a short window, and
//     collecting what those generations alone named. That trades a loud
//     refusal for a quiet deletion. Stamping every document a v0.2 writer
//     produces means an old binary fails closed on the head, before it can
//     sweep anything.
//   - The format is pre-release, and this is the same one-way door
//     Manifests already went through.
func TestABranchStampedSuperblockIsRefusedByAReaderThatDropsTheField(t *testing.T) {
	pub, priv := genKey(t)

	sb := testSuperblock()
	sb.Branch = "dev"
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, sb)
	if !bytes.Contains(enc, []byte("branch")) {
		t.Fatal("a superblock stamped with a branch wrote no branch key")
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Branch != "dev" {
		t.Fatalf("branch round-tripped as %q", dec.Branch)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("a reader that knows the field could not verify: %v", err)
	}

	// The old binary, stood in for by dropping the field it does not have.
	dropped := *dec
	dropped.Branch = ""
	if err := dropped.Verify(pub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a reader that dropped the branch verified anyway (%v); the field would then be "+
			"strippable, and attribution rests on it being signed", err)
	}
}

// AND THE FIELD COSTS AN UNSTAMPED DOCUMENT NOTHING. A writer that states
// no branch must produce the same bytes it always did — this is the half
// that keeps hand-built and pre-Params superblocks (and every fixture in
// this tree) verifying without a migration.
func TestAnUnstampedSuperblockWritesNoBranchKey(t *testing.T) {
	pub, priv := genKey(t)

	sb := testSuperblock()
	if sb.Branch != "" {
		t.Fatal("fixture already states a branch")
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, sb)
	if bytes.Contains(enc, []byte("branch")) {
		t.Fatal("a superblock stating no branch still wrote the key")
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
