package superblock

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestUnsignedIsTheAbsenceOfTheCredential: the marker is that there is no
// signature, not a field claiming there is none. A signed document must
// never read as unsigned, and an unsigned one must verify under no key at
// all — which is what makes the reader's refusal automatic.
func TestUnsignedIsTheAbsenceOfTheCredential(t *testing.T) {
	priv := testKey(t)
	sb := &Superblock{FormatVersion: FormatV2, Generation: 1}
	if !sb.IsUnsigned() {
		t.Fatal("a zero superblock must read as unsigned")
	}
	if err := sb.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if sb.IsUnsigned() {
		t.Fatal("a signed superblock read as unsigned")
	}
	sb.Unsign()
	if !sb.IsUnsigned() {
		t.Fatal("Unsign left something behind")
	}
	// And it verifies under nothing — including under the key that signed
	// it a moment ago. Every existing reader refuses it with no change.
	if err := sb.Verify(priv.Public().(ed25519.PublicKey)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an unsigned superblock verified: %v", err)
	}
	other := testKey(t)
	if err := sb.Verify(other.Public().(ed25519.PublicKey)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("an unsigned superblock verified under a stranger's key: %v", err)
	}
}

// TestUnsignClearsTheAnnouncement: NextPub is worth exactly the signature
// over it, so an unsigned document may not carry one — and a writer that
// sets it afterwards is caught by Validate rather than shipping a promise
// anyone could have written.
func TestUnsignClearsTheAnnouncement(t *testing.T) {
	sb := &Superblock{FormatVersion: FormatV2, Generation: 1}
	sb.NextPub = new([32]byte)
	sb.NextPub[0] = 9
	sb.Unsign()
	if sb.NextPub != nil {
		t.Fatal("Unsign kept a successor announcement")
	}
	sb.NextPub = new([32]byte)
	if err := sb.Validate(); err == nil {
		t.Fatal("an unsigned superblock announcing a successor validated")
	}
}

// TestSignAsCannotChangeTheMode is the invariant that keeps every ordinary
// writer — seal, checkpoint, repack, merge, rescue — out of this decision.
func TestSignAsCannotChangeTheMode(t *testing.T) {
	priv := testKey(t)
	signedParent := &Superblock{FormatVersion: FormatV2, Generation: 1}
	if err := signedParent.Sign(priv); err != nil {
		t.Fatal(err)
	}
	unsignedParent := &Superblock{FormatVersion: FormatV2, Generation: 1}
	unsignedParent.Unsign()

	// Signed parent, key: signed child.
	child := &Superblock{FormatVersion: FormatV2, Generation: 2}
	if err := child.SignAs(signedParent, priv); err != nil {
		t.Fatal(err)
	}
	if child.IsUnsigned() {
		t.Fatal("a successor of a signed generation came out unsigned")
	}

	// Signed parent, no key: an error, NOT a quiet downgrade. This is the
	// one that would otherwise be silent — a writer that lost its key
	// publishing a volume with no integrity root.
	child = &Superblock{FormatVersion: FormatV2, Generation: 2}
	if err := child.SignAs(signedParent, nil); err == nil {
		t.Fatal("a nil key on a signed volume produced a generation instead of an error")
	}

	// Unsigned parent, no key: unsigned child.
	child = &Superblock{FormatVersion: FormatV2, Generation: 2}
	if err := child.SignAs(unsignedParent, nil); err != nil {
		t.Fatal(err)
	}
	if !child.IsUnsigned() {
		t.Fatal("a successor of an unsigned generation came out signed")
	}

	// Unsigned parent, key: refused, and namedly so. A repack or a merge
	// that happened to have a key lying about must not sign a volume every
	// reader has pinned as unsigned.
	child = &Superblock{FormatVersion: FormatV2, Generation: 2}
	err := child.SignAs(unsignedParent, priv)
	if !errors.Is(err, ErrSigningChange) {
		t.Fatalf("signing a successor of an unsigned generation: err=%v, want ErrSigningChange", err)
	}
}
