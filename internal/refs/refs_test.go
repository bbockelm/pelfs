package refs

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

func newInner(t *testing.T) pelicanobj.Store {
	t.Helper()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner
}

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// gen builds and signs generation n; prevRaw wires the lineage hash.
func gen(t *testing.T, n uint64, prevRaw []byte, priv ed25519.PrivateKey, mutate func(*superblock.Superblock)) []byte {
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
	if err := sb.Sign(priv); err != nil {
		t.Fatalf("sign gen %d: %v", n, err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatalf("encode gen %d: %v", n, err)
	}
	return raw
}

func TestTOFUPinsAndEnforces(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	_, evilPriv := genKey(t)

	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// First generation: flip with no prior ETag, fetch pins via TOFU.
	raw0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatalf("first flip: %v", err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("TOFU fetch: %v", err)
	}
	if f.Superblock.Generation != 0 {
		t.Fatalf("generation %d, want 0", f.Superblock.Generation)
	}

	// An attacker replacing the ref with their own key must be rejected.
	evil := gen(t, 1, raw0, evilPriv, nil)
	if err := s.Flip(ctx, "main", evil, f.ETag); err != nil {
		t.Fatalf("attacker flip (transport-level, allowed): %v", err)
	}
	if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("fetch of attacker superblock: err=%v, want ErrUntrusted", err)
	}
}

func TestRotationAdvancesPin(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	nextPub, nextPriv := genKey(t)

	s, err := New(inner, t.TempDir(), nil)
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
	f0, err := s.Fetch(ctx, "main") // pins the original key, records raw0
	if err != nil {
		t.Fatal(err)
	}

	raw1 := gen(t, 1, raw0, nextPriv, nil)
	if err := s.Flip(ctx, "main", raw1, f0.ETag); err != nil {
		t.Fatal(err)
	}
	f1, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch after announced rotation: %v", err)
	}
	if f1.Superblock.Generation != 1 {
		t.Fatalf("generation %d, want 1", f1.Superblock.Generation)
	}

	// The pin advanced: a THIRD generation signed by the old key must fail.
	raw2 := gen(t, 2, raw1, priv, nil)
	if err := s.Flip(ctx, "main", raw2, f1.ETag); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("old-key generation after rotation: err=%v, want ErrUntrusted", err)
	}
}

func TestExplicitKeyDisablesTOFU(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	trustedPub, _ := genKey(t)
	_, otherPriv := genKey(t)

	s, err := New(inner, t.TempDir(), trustedPub)
	if err != nil {
		t.Fatal(err)
	}
	raw0 := gen(t, 0, nil, otherPriv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err == nil {
		// Flip persists only on decode success; the write itself is fine.
		// The trust check is on the read side:
		if _, err := s.Fetch(ctx, "main"); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("explicit key accepted a foreign superblock: %v", err)
		}
	}
}

func TestFlipDetectsRace(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)

	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatal(err)
	}
	f, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}

	// A competing writer advances the ref...
	rawTheirs := gen(t, 1, raw0, priv, nil)
	if err := s.Flip(ctx, "main", rawTheirs, f.ETag); err != nil {
		t.Fatal(err)
	}
	// ...so our flip built on the stale fetch must fail.
	rawOurs := gen(t, 1, raw0, priv, func(sb *superblock.Superblock) { sb.NextInode = 42 })
	if err := s.Flip(ctx, "main", rawOurs, f.ETag); !errors.Is(err, ErrStaleFlip) {
		t.Fatalf("stale flip: err=%v, want ErrStaleFlip", err)
	}
	// First-generation flip against an existing ref also fails.
	if err := s.Flip(ctx, "main", raw0, ""); !errors.Is(err, ErrStaleFlip) {
		t.Fatalf("create-flip over existing ref: err=%v, want ErrStaleFlip", err)
	}
}

func TestTagsAreImmutableAndVerified(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)

	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fetch(ctx, "main"); err != nil { // establish the pin
		t.Fatal(err)
	}

	if err := s.Tag(ctx, "v1.0", raw0); err != nil {
		t.Fatalf("tag: %v", err)
	}
	if err := s.Tag(ctx, "v1.0", raw0); err == nil {
		t.Fatal("re-tagging an existing name succeeded")
	}
	sb, _, err := s.FetchTag(ctx, "v1.0")
	if err != nil {
		t.Fatalf("fetch tag: %v", err)
	}
	if sb.Generation != 0 {
		t.Fatalf("tag generation %d, want 0", sb.Generation)
	}

	// A tag signed by a stranger is rejected against the pins on file.
	_, evilPriv := genKey(t)
	evil := gen(t, 5, nil, evilPriv, nil)
	if err := s.Tag(ctx, "evil", evil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.FetchTag(ctx, "evil"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("foreign tag: err=%v, want ErrUntrusted", err)
	}
}

// TestFetchRefusesARolledBackHead pins the guard against an origin that
// answers an overwritten key with a superseded body -- observed on a real
// deployment, where refs/main returned an older generation than the one
// already published. The stale bytes are perfectly signed, because they
// were genuine once, so signature verification cannot catch this; only
// the client's own record of how far the branch has come can.
func TestFetchRefusesARolledBackHead(t *testing.T) {
	inner := newInner(t)
	ctx := context.Background()
	_, priv := genKey(t)
	s, err := New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	raw0 := gen(t, 0, nil, priv, nil)
	if err := s.Flip(ctx, "main", raw0, ""); err != nil {
		t.Fatalf("first flip: %v", err)
	}
	f0, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch generation 0: %v", err)
	}
	raw1 := gen(t, 1, raw0, priv, nil)
	if err := s.Flip(ctx, "main", raw1, f0.ETag); err != nil {
		t.Fatalf("second flip: %v", err)
	}
	if _, err := s.Fetch(ctx, "main"); err != nil {
		t.Fatalf("fetch generation 1: %v", err)
	}

	// The origin now answers with the superseded generation 0 body.
	f1, err := s.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("re-fetch: %v", err)
	}
	if err := s.Flip(ctx, "main", raw0, f1.ETag); err != nil {
		t.Fatalf("staging the stale body: %v", err)
	}
	_, err = s.Fetch(ctx, "main")
	if !errors.Is(err, ErrRollback) {
		t.Fatalf("fetch of a superseded head: err=%v, want ErrRollback", err)
	}

	// The same generation re-read is NOT a rollback: an unchanged branch
	// is the common case and must keep working.
	if err := s.Flip(ctx, "main", raw1, ""); err != nil {
		// Re-publishing over the stale head needs the current ETag.
		ki, serr := inner.StatKey(ctx, "refs/main")
		if serr != nil {
			t.Fatal(serr)
		}
		if err := s.Flip(ctx, "main", raw1, ki.ETag); err != nil {
			t.Fatalf("restoring generation 1: %v", err)
		}
	}
	if _, err := s.Fetch(ctx, "main"); err != nil {
		t.Fatalf("re-reading the current generation must succeed: %v", err)
	}
}
