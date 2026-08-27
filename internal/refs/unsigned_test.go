package refs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// unsignedGen builds generation n with NO signature — what
// `pelfs init --unsigned` publishes and what a forgery against a signed
// volume looks like, which is the point: they are the same document.
func unsignedGen(t *testing.T, n uint64, prevRaw []byte, mutate func(*superblock.Superblock)) []byte {
	t.Helper()
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      n,
		CreatedUnixNano: int64(1000 + n),
	}
	if prevRaw != nil {
		sb.PrevHash = superblock.Hash(prevRaw)
	}
	if mutate != nil {
		mutate(sb)
	}
	sb.Unsign()
	raw, err := sb.Encode()
	if err != nil {
		t.Fatalf("encode gen %d: %v", n, err)
	}
	return raw
}

// TestUnsignedRefusedWithoutConsent is the rule the whole feature rests
// on: an unsigned volume never trust-on-first-uses. A reader that expected
// a signed volume and met an unsigned one must stop, not pin.
func TestUnsignedRefusedWithoutConsent(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	dir := t.TempDir()
	s, err := New(inner, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flip(ctx, "main", unsignedGen(t, 0, nil, nil), ""); err != nil {
		t.Fatal(err)
	}
	_, err = s.Fetch(ctx, "main")
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("fetch of an unsigned head without consent: err=%v, want ErrUnsigned", err)
	}
	if !strings.Contains(err.Error(), "--allow-unsigned") {
		t.Fatalf("the refusal must name the flag that lifts it; got %v", err)
	}
	// AND IT MUST NOT HAVE PINNED ANYTHING. A refusal that left a pin
	// behind would make the second attempt succeed, which is the bug this
	// test exists to catch.
	if _, err := os.Stat(s.pinPath()); !os.IsNotExist(err) {
		t.Fatalf("a refused fetch wrote a pin at %s", s.pinPath())
	}
}

// TestUnsignedAcceptedWithConsentThenPinned: the opt-in is given once and
// recorded, so later commands need no flag — the volume announces itself
// on the reporting surfaces instead.
func TestUnsignedAcceptedWithConsentThenPinned(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	dir := t.TempDir()
	allow, err := NewWithPolicy(inner, dir, Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := allow.Flip(ctx, "main", unsignedGen(t, 0, nil, nil), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := allow.Fetch(ctx, "main"); err != nil {
		t.Fatalf("fetch with --allow-unsigned: %v", err)
	}
	b, err := os.ReadFile(allow.pinPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != unsignedPin {
		t.Fatalf("pin file holds %q, want %q", strings.TrimSpace(string(b)), unsignedPin)
	}
	// A second store over the same state directory, WITHOUT the flag.
	plain, err := New(inner, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Fetch(ctx, "main"); err != nil {
		t.Fatalf("fetch on a pinned-unsigned volume without the flag: %v", err)
	}
}

// TestPinnedReaderRefusesDowngrade is the security case the design turns
// on. A volume signed yesterday, unsigned today, against a reader holding a
// key pin: refused, and refused EVEN WITH --allow-unsigned, because a
// deliberate downgrade and a forgery are the same document.
func TestPinnedReaderRefusesDowngrade(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	dir := t.TempDir()
	_, priv := genKey(t)

	s, err := New(inner, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("TOFU on the signed volume: %v", err)
	}

	// The downgrade lands.
	if err := s.Flip(ctx, "main", unsignedGen(t, 1, raw0, nil), f.ETag); err != nil {
		t.Fatal(err)
	}
	_, err = s.Fetch(ctx, "main")
	if !errors.Is(err, ErrSignatureDropped) {
		t.Fatalf("pinned reader on a downgraded volume: err=%v, want ErrSignatureDropped", err)
	}
	if !strings.Contains(err.Error(), s.pinPath()) {
		t.Fatalf("the refusal must name the pin file to delete; got %v", err)
	}

	// THE FLAG DOES NOT LIFT IT. This is the assertion that keeps
	// --allow-unsigned from becoming a habit that swallows an attack.
	lax, err := NewWithPolicy(inner, dir, Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lax.Fetch(ctx, "main"); !errors.Is(err, ErrSignatureDropped) {
		t.Fatalf("--allow-unsigned lifted a downgrade refusal: err=%v", err)
	}

	// Nor does an explicit key: there is no signature for it to check.
	pinned, err := New(inner, dir, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.Fetch(ctx, "main"); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("--volume-pubkey against an unsigned head: err=%v, want ErrUnsigned", err)
	}

	// The documented remedy, and nothing less than it: delete the pin.
	if err := os.Remove(s.pinPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := lax.Fetch(ctx, "main"); err != nil {
		t.Fatalf("after clearing the pin, --allow-unsigned must work: %v", err)
	}
}

// TestUnsignedPinRefusesASignatureAppearing is the mirror, and it is not
// symmetry for its own sake: adopting a key that turned up on an unsigned
// volume would hand the pin to whoever published it.
func TestUnsignedPinRefusesASignatureAppearing(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	dir := t.TempDir()
	s, err := NewWithPolicy(inner, dir, Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	raw0 := unsignedGen(t, 0, nil, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	_, evil := genKey(t)
	if err := s.Flip(ctx, "main", gen(t, 1, raw0, evil, nil), f.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrSignatureAppeared) {
		t.Fatalf("a key appearing on an unsigned volume: err=%v, want ErrSignatureAppeared", err)
	}
}

// TestUnsignedNeverArrivesThroughTheChain: NextPub announces a KEY and
// never "no key". A predecessor that announced a successor must not be a
// route by which an unsigned generation is accepted.
func TestUnsignedNeverArrivesThroughTheChain(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	dir := t.TempDir()
	_, priv := genKey(t)
	nextPub, _ := genKey(t)

	s, err := New(inner, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw0 := gen(t, 0, nil, priv, func(sb *superblock.Superblock) {
		sb.NextPub = new([32]byte)
		copy(sb.NextPub[:], nextPub)
	})
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	// The successor the announcement invited — except unsigned.
	if err := s.Flip(ctx, "main", unsignedGen(t, 1, raw0, nil), f.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrSignatureDropped) {
		t.Fatalf("an announcement must not admit an unsigned successor: err=%v", err)
	}
	// And the format refuses to build the other half of that idea: an
	// unsigned generation cannot announce anything.
	sb := &superblock.Superblock{FormatVersion: superblock.FormatV2, Generation: 2}
	sb.NextPub = new([32]byte)
	copy(sb.NextPub[:], nextPub)
	if err := sb.Validate(); err == nil {
		t.Fatal("an unsigned superblock announcing a successor must not validate")
	}
}

// TestTagAndScavengedBackupNeverEstablishUnsigned: consent is given by
// reading a BRANCH. A tag and a superblock dug out of a pack are chosen by
// anyone who can write the key space, so neither may be the thing that
// decides what a volume IS.
func TestTagAndScavengedBackupNeverEstablishUnsigned(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	s, err := NewWithPolicy(inner, t.TempDir(), Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := unsignedGen(t, 3, nil, nil)
	if err := s.Tag(ctx, "v1", raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FetchTag(ctx, "v1"); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("an unsigned tag must not establish trust: err=%v", err)
	}
	if _, err := s.Verify(raw); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("a scavenged unsigned backup must not establish trust: err=%v", err)
	}
	// Once the volume IS established as unsigned, both read.
	if err := s.AcceptUnsigned(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FetchTag(ctx, "v1"); err != nil {
		t.Fatalf("tag on a pinned-unsigned volume: %v", err)
	}
	if _, err := s.Verify(raw); err != nil {
		t.Fatalf("scavenged backup on a pinned-unsigned volume: %v", err)
	}
}
