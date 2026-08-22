package rotate

// MIXED VERSIONS: A LEGACY VOLUME, ROTATED BY TODAY'S WRITER.
//
// The rotation code is new; the code that FOLLOWS a rotation is not — it
// shipped in v0.1.0 (superblock.VerifyChain, and refs.Store.Fetch's rotation
// path). So the mixed-version question is not "does the reader know how",
// it is whether a rotation published today is still the shape that reader
// recognizes when the volume it is published onto predates the fields
// today's writer stamps.
//
// The concrete asymmetry, and the whole reason this file exists: a v0.1.0
// generation carries no `branch` key, and every document `pelfs rotate`
// writes carries one (rotate.Successor sets it, because the field means "the
// ref this generation was sealed onto" and a rotation is a seal). So a
// legacy volume's rotation is a chain whose PREDECESSOR is v0.1.0-shaped and
// whose successor is not, on both steps. That crossing is what is tested,
// through the real refs.Store, with the pin advancing or not advancing for
// real.
//
// The predecessor's v0.1.0 shape is established the way the format's own
// evolution rule guarantees it — Branch empty writes no branch key, pinned
// against captured v0.1.0 bytes by
// superblock.TestAnUnstampedSuperblockWritesNoBranchKey — and asserted here
// on the bytes rather than assumed.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// legacyVolume publishes a v0.1.0-SHAPED generation 0 by hand: no branch
// key, no manifests, an inline pack list. It goes onto the ref directly
// rather than through internal/publish, because publish is today's writer
// and would stamp today's fields — which is the very thing being crossed.
func legacyVolume(t *testing.T) (pelicanobj.Store, string, ed25519.PrivateKey, *superblock.Superblock, []byte) {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDir, "v2-signing.key"),
		[]byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sb := &superblock.Superblock{
		FormatVersion:   superblock.FormatV2,
		Generation:      0,
		CreatedUnixNano: time.Now().UnixNano(),
		NextInode:       2,
		// The v0.1.0 shape: packs stated INLINE, no manifest refs. A rotation
		// must carry this forward untouched, and superblock.Validate must
		// keep accepting it (it refuses only a document stating BOTH).
		PackList: []superblock.PackEntry{{Name: "p-00000000000000000000-aaaa", Size: 1024}},
		Params:   superblock.Params{TGraceSeconds: 3600, RetainK: 4},
	}
	if _, err := rand.Read(sb.VolumeID[:]); err != nil {
		t.Fatal(err)
	}
	if err := sb.Sign(key); err != nil {
		t.Fatal(err)
	}
	raw, err := sb.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("branch")) {
		t.Fatal("the legacy fixture wrote a branch key; it is not v0.1.0-shaped")
	}
	rstore, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rstore.Flip(ctx, "main", raw, ""); err != nil {
		t.Fatal(err)
	}
	return inner, stateDir, key, sb, raw
}

// TestALegacyVolumeRotatesAndItsReaderFollows is the mixed-version claim, end
// to end: a volume whose head predates the branch field is rotated by today's
// writer, and a reader that watched it move its pin through the chain.
func TestALegacyVolumeRotatesAndItsReaderFollows(t *testing.T) {
	ctx := context.Background()
	inner, stateDir, oldKey, legacy, legacyRaw := legacyVolume(t)

	writer, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Fetch(ctx, "main"); err != nil {
		t.Fatalf("writer's own fetch of the legacy head: %v", err)
	}
	// A reader pinned to the legacy key, with the legacy generation on
	// record — which is what makes the one chain step available to it.
	readerDir := t.TempDir()
	reader, err := refs.New(inner, readerDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	oldPin := readPin(t, readerDir)
	if oldPin != hex.EncodeToString(legacy.SigningPub[:]) {
		t.Fatalf("pin is %s, want the legacy key", oldPin[:16])
	}

	opts := Options{
		Refs: writer, Branches: []string{"main"},
		KeyPath: filepath.Join(stateDir, "v2-signing.key"),
		Now:     time.Now().UnixNano(), AnnounceOnly: true,
	}
	if _, err := Execute(ctx, opts); err != nil {
		t.Fatalf("announce on a legacy volume: %v", err)
	}
	// THE CROSSING: the announcement is a v0.2-shaped document whose
	// predecessor is v0.1.0-shaped. Its lineage hash is over the legacy WIRE
	// bytes, which is the part a re-encoding would break.
	ann, err := reader.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("reader on the announcement over a legacy parent: %v", err)
	}
	if ann.Superblock.PrevHash != superblock.Hash(legacyRaw) {
		t.Error("the announcement's lineage hash is not over the legacy head's wire bytes")
	}
	if ann.Superblock.Branch != "main" {
		t.Errorf("the announcement records branch %q; today's writer stamps one", ann.Superblock.Branch)
	}
	if !bytes.Contains(ann.Raw, []byte("branch")) {
		t.Error("the announcement wrote no branch key, so this is not the mixed-shape case it claims to be")
	}
	// The legacy inline pack list survived, and the document is still valid
	// under the one-shape rule.
	if len(ann.Superblock.PackList) != 1 || len(ann.Superblock.Manifests) != 0 {
		t.Errorf("the legacy inline pack list was not carried verbatim: %d inline, %d manifests",
			len(ann.Superblock.PackList), len(ann.Superblock.Manifests))
	}
	if err := ann.Superblock.Validate(); err != nil {
		t.Errorf("the rotated legacy document is not a valid head: %v", err)
	}
	if readPin(t, readerDir) != oldPin {
		t.Error("the pin moved on the announcement")
	}

	// Finish, and the pin advances — the v0.1.0 code path doing its job over
	// documents it has never seen the shape of.
	opts.AnnounceOnly = false
	opts.Now = time.Now().UnixNano()
	res, err := Execute(ctx, opts)
	if err != nil {
		t.Fatalf("execute on a legacy volume: %v", err)
	}
	after, err := reader.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("reader following a legacy volume's rotation: %v", err)
	}
	newPin := readPin(t, readerDir)
	if newPin == oldPin {
		t.Fatal("the pin did not advance")
	}
	if newPin != res.NewPub {
		t.Errorf("pin is %s, want %s", newPin[:16], res.NewPub[:16])
	}
	if hex.EncodeToString(after.Superblock.SigningPub[:]) == hex.EncodeToString(oldKey.Public().(ed25519.PublicKey)) {
		t.Error("the head is still signed by the old key")
	}
	if after.Superblock.Generation != legacy.Generation+2 {
		t.Errorf("head generation %d, want %d", after.Superblock.Generation, legacy.Generation+2)
	}
}

// ============================== MUTATIONS ==============================
//
// The three refusals that make custody a chain rather than a suggestion,
// each driven by breaking the thing it rests on. These are here rather than
// in internal/superblock because what is being checked is that a document
// shaped like the ones THIS PACKAGE writes cannot be forged into the chain —
// the unit tests over VerifyChain check the function, and these check the
// output of rotate.Successor against it.

// TestAnUnannouncedKeyChangeIsRefused: strip the announcement and the
// successor generation stops being reachable. This is the mutation that
// matters most — without it, any holder of any keypair could publish a
// generation and have readers adopt it.
func TestAnUnannouncedKeyChangeIsRefused(t *testing.T) {
	_, _, oldKey, legacy, legacyRaw := legacyVolume(t)
	_, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trusted := oldKey.Public().(ed25519.PublicKey)

	// The honest chain first, so the test is known to have teeth: prev
	// announces, cur is signed by the announced key, VerifyChain accepts.
	var next [32]byte
	copy(next[:], newKey.Public().(ed25519.PublicKey))
	ann, annRaw, err := Successor(legacy, legacyRaw, "main", time.Now().UnixNano(), oldKey, &next)
	if err != nil {
		t.Fatal(err)
	}
	cur, _, err := Successor(ann, annRaw, "main", time.Now().UnixNano(), newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := superblock.VerifyChain(annRaw, cur, trusted); err != nil {
		t.Fatalf("the honest rotation does not verify, so this test proves nothing: %v", err)
	}

	// THE MUTATION: the same successor, against a predecessor that announced
	// nothing. Everything else is identical — generation, lineage, signer.
	plain, plainRaw, err := Successor(legacy, legacyRaw, "main", ann.CreatedUnixNano, oldKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain.NextPub != nil {
		t.Fatal("the unannounced predecessor announces something")
	}
	forged, _, err := Successor(plain, plainRaw, "main", cur.CreatedUnixNano, newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = superblock.VerifyChain(plainRaw, forged, trusted)
	if err == nil {
		t.Fatal("a key change nobody announced was accepted: custody would flow to anyone who can write a ref")
	}
	if !errors.Is(err, superblock.ErrBadSignature) {
		t.Errorf("error is %v, want ErrBadSignature", err)
	}
	if !strings.Contains(err.Error(), "no successor was announced") {
		t.Errorf("error %q does not say the announcement was missing", err)
	}
}

// TestASuccessorMustBeTheAnnouncedKey: announce one key, sign with another.
// Both are keys the writer holds, so this is the insider case — a
// compromised writer trying to hand custody somewhere the signed
// announcement does not point.
func TestASuccessorMustBeTheAnnouncedKey(t *testing.T) {
	_, _, oldKey, legacy, legacyRaw := legacyVolume(t)
	_, announced, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	trusted := oldKey.Public().(ed25519.PublicKey)

	var next [32]byte
	copy(next[:], announced.Public().(ed25519.PublicKey))
	ann, annRaw, err := Successor(legacy, legacyRaw, "main", time.Now().UnixNano(), oldKey, &next)
	if err != nil {
		t.Fatal(err)
	}
	_ = ann
	cur, _, err := Successor(ann, annRaw, "main", time.Now().UnixNano(), other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := superblock.VerifyChain(annRaw, cur, trusted); err == nil {
		t.Fatal("a generation signed by a key the announcement did not name was accepted")
	}
}

// TestALineageHashMustCoverTheRealPredecessor: the announcement is genuine
// and the successor is signed by the announced key, but the lineage hash
// points at a different document. Without this check an attacker holding one
// announced-successor generation could splice it onto any other head.
func TestALineageHashMustCoverTheRealPredecessor(t *testing.T) {
	_, _, oldKey, legacy, legacyRaw := legacyVolume(t)
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	trusted := oldKey.Public().(ed25519.PublicKey)

	var next [32]byte
	copy(next[:], newKey.Public().(ed25519.PublicKey))
	ann, annRaw, err := Successor(legacy, legacyRaw, "main", time.Now().UnixNano(), oldKey, &next)
	if err != nil {
		t.Fatal(err)
	}
	cur, _, err := Successor(ann, annRaw, "main", time.Now().UnixNano(), newKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A second, equally genuine announcement, differing only in its stamp —
	// so the successor's lineage hash names the wrong one of two documents
	// that both announce the same key.
	other, otherRaw, err := Successor(legacy, legacyRaw, "main", ann.CreatedUnixNano+1, oldKey, &next)
	if err != nil {
		t.Fatal(err)
	}
	if other.Generation != ann.Generation {
		t.Fatal("the two announcements are not at the same generation")
	}
	err = superblock.VerifyChain(otherRaw, cur, trusted)
	if err == nil {
		t.Fatal("a successor was spliced onto a predecessor it does not name")
	}
	if !strings.Contains(err.Error(), "lineage hash mismatch") {
		t.Errorf("error %q does not name the lineage mismatch", err)
	}
}
