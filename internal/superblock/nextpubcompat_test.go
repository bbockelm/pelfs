package superblock

// THE ANNOUNCEMENT'S WIRE FORM, PINNED AGAINST CAPTURED v0.1.0 BYTES.
//
// `pelfs rotate` publishes a generation whose only distinguishing content is
// NextPub, and the two generations of a rotation are separated in time — by
// seconds normally, and deliberately by hours or days when an operator uses
// --announce-only to let polling readers record the announcement first. So
// an announcement can outlive a binary upgrade, and the question "does a
// promise made by the old writer still read as the same promise" is a real
// one rather than a hypothetical.
//
// It is answered here against BYTES CAPTURED FROM THE v0.1.0 ENCODER, not a
// round trip through today's one: a round trip would be the current encoder
// grading its own work, which proves nothing about the documents actually
// sitting in volumes. The captured fixture happens to carry a populated
// next_pub, which is what makes it usable for this.
//
// WHAT IS NOT PROVEN HERE, said plainly so nobody reads more into it: the
// fixture's announced key is a placeholder with no private half, so this
// cannot sign a successor under it and cannot exercise VerifyChain's
// rotation branch from these bytes. That half is tested in
// internal/rotate/compat_test.go, over a legacy-shaped chain whose keys the
// test holds.

import (
	"bytes"
	"testing"
)

// TestAV010AnnouncementIsStillTheSameAnnouncement.
//
// Three claims, and the second is the load-bearing one. The bytes decode;
// re-encoding what was decoded reproduces them EXACTLY (so Verify's signing
// message is unchanged and the document still verifies, which is what any
// drift in NextPub's tag or omitempty behaviour would break); and the
// announced key reads back bit-for-bit, so a reader today would follow the
// same successor the v0.1.0 writer named.
func TestAV010AnnouncementIsStillTheSameAnnouncement(t *testing.T) {
	golden, pub := v010Golden(t)

	if !bytes.Contains(golden, []byte("next_pub")) {
		t.Fatal("the captured v0.1.0 fixture announces no successor, so it cannot pin this")
	}
	sb, err := Decode(golden)
	if err != nil {
		t.Fatalf("a v0.1.0 announcement no longer decodes: %v", err)
	}
	if sb.NextPub == nil {
		t.Fatal("a v0.1.0 announcement decoded with NextPub==nil: an in-flight rotation would silently " +
			"evaporate across an upgrade, and the next seal would be signed by a key no reader expects")
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("a v0.1.0 announcement no longer verifies: %v", err)
	}
	again, err := sb.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(again, golden) {
		t.Fatalf("re-encoding a decoded v0.1.0 announcement produced %d bytes, not the %d it came from; "+
			"VerifyChain hashes the WIRE bytes for lineage and Verify signs the re-encoding, so a successor "+
			"generation published against the old bytes would stop chaining", len(again), len(golden))
	}
	// The announced key itself, byte for byte: a rotation names ONE
	// successor, and a reader that followed a different one would be
	// following whatever re-encoding drift produced.
	want := golden[bytes.Index(golden, []byte("next_pub"))+len("next_pub")+2:][:32]
	if !bytes.Equal(sb.NextPub[:], want) {
		t.Errorf("the announced successor decoded as %x, but the wire bytes say %x", sb.NextPub[:8], want[:8])
	}
}

// TestAnnouncingCostsAnUnannouncedDocumentNothing is the omitempty half. A
// rotation's SECOND generation announces nothing, and it must therefore
// encode exactly as any ordinary generation does — otherwise every
// non-rotating writer in the tree would be paying for a field it never
// sets, and (much worse) a NextPub that serialized as 32 zero bytes when
// unset would read to a reader as an announcement of the all-zero key.
func TestAnnouncingCostsAnUnannouncedDocumentNothing(t *testing.T) {
	pub, priv := genKey(t)

	sb := testSuperblock()
	sb.NextPub = nil
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	enc := mustEncode(t, sb)
	if bytes.Contains(enc, []byte("next_pub")) {
		t.Fatal("a generation announcing no successor still wrote the key; a reader would take the zero " +
			"value for an announcement and accept a rotation to a key nobody holds")
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.NextPub != nil {
		t.Errorf("NextPub round-tripped as %x, want nil", dec.NextPub[:8])
	}
	if err := dec.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
