package rotate

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE CRASH MATRIX.
//
// A rotation is four steps and can be interrupted between any two of them.
// The claim this file exists to check is a single sentence with no
// exceptions in it:
//
//	A rotation interrupted anywhere is either resumable or abortable, and
//	never leaves a volume whose next seal cannot be signed.
//
// The four interruption points, and what each must leave behind:
//
//	C1  after minting the successor, before the announcement
//	    -> head unchanged, live key still the head's key. Resume publishes
//	       the announcement with the SAME successor (never a second one);
//	       abort deletes it and the volume never knew.
//	C2  after the announcement, before the executing generation
//	    -> head announces, still signed by the live key. An ordinary seal
//	       works (the live key is still the head's). Resume finishes;
//	       abort supersedes the announcement with an ordinary generation.
//	C3  after the executing generation, before the local promotion
//	    -> THE DANGEROUS ONE on paper: the head is signed by a key that is
//	       sitting in a file called `.next`. Resume promotes and publishes
//	       nothing; Reconcile does the same from inside an ordinary seal, so
//	       a mount recovers without anyone running a command.
//	C4  mid-promotion, after the archive and before the rename
//	    -> both keys present, pending still pending. Promote is idempotent.
//
// Each case drives the real state machine to the point in question and then
// asserts the recovery, rather than constructing the intermediate state by
// hand: a hand-built state directory proves the recovery works on the state
// the test imagined, which is not the same claim.

// TestC1CrashAfterMintingIsResumableWithTheSameSuccessor also pins the
// property that makes resumption safe at all: a second run must ADOPT the
// pending key. Minting a second one while the first had already been
// announced would leave the volume carrying a signed promise about a key
// this machine had just replaced — the one state nothing recovers from.
func TestC1CrashAfterMintingIsResumableWithTheSameSuccessor(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.seal(t, "a.txt", "hello").Generation

	keys := Keys{Path: f.keyPath()}
	minted, err := keys.MintPending()
	if err != nil {
		t.Fatal(err)
	}
	// The volume is untouched and still signable: this is the invariant that
	// makes C1 boring.
	if f.head(t, "main").Generation != base {
		t.Fatal("minting a key published something")
	}
	if live, _ := keys.Live(); !matches(live, f.head(t, "main").SigningPub) {
		t.Fatal("the live key stopped matching the head")
	}

	res, err := Execute(ctx, f.opts("main"))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.NewPub != PublicOf(minted) {
		t.Fatalf("the resumed run rotated to %s, but %s had already been minted — a second successor "+
			"orphans the first", res.NewPub[:16], PublicOf(minted)[:16])
	}
	if res.Plans[0].Found != PhaseFresh {
		t.Errorf("found %s, want fresh: nothing had been published yet", res.Plans[0].Found)
	}
}

// TestC1AbortLeavesNoTrace: nothing was published, so aborting is local.
func TestC1AbortLeavesNoTrace(t *testing.T) {
	f := newFixture(t)
	base := f.seal(t, "a.txt", "hello").Generation
	keys := Keys{Path: f.keyPath()}
	if _, err := keys.MintPending(); err != nil {
		t.Fatal(err)
	}
	if _, err := Abort(context.Background(), f.opts("main")); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if p, _ := keys.Pending(); p != nil {
		t.Error("the pending key survived the abort")
	}
	if f.head(t, "main").Generation != base {
		t.Error("aborting a rotation that had published nothing published something")
	}
}

// TestC2AnnouncedButNotExecutedIsStillSignable is the point of the ordering:
// while a rotation is announced, the live key is still the head's key, so
// every other writer on the volume carries on unaware.
func TestC2AnnouncedButNotExecutedIsStillSignable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.seal(t, "a.txt", "hello").Generation

	o := f.opts("main")
	o.AnnounceOnly = true
	if _, err := Execute(ctx, o); err != nil {
		t.Fatalf("announce: %v", err)
	}
	head := f.head(t, "main")
	if head.Generation != base+1 || head.NextPub == nil {
		t.Fatalf("head is generation %d with NextPub==nil? %v", head.Generation, head.NextPub == nil)
	}
	keys := Keys{Path: f.keyPath()}
	live, err := keys.Live()
	if err != nil {
		t.Fatal(err)
	}
	if !matches(live, head.SigningPub) {
		t.Fatal("the announcing generation is not signed by the live key, so an ordinary seal would refuse")
	}
	// Reconcile must do NOTHING here. Promoting on an announcement would
	// hand the volume a key its own head has not used, and the next seal
	// would publish a generation no reader could chain to.
	promoted, err := Reconcile(f.keyPath(), head)
	if err != nil {
		t.Fatal(err)
	}
	if promoted {
		t.Fatal("Reconcile promoted on an ANNOUNCEMENT; the successor has not been used yet")
	}

	// And resumption finishes exactly the outstanding half.
	res, err := Execute(ctx, f.opts("main"))
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.Plans[0].Found != PhaseAnnounced {
		t.Errorf("found %s, want announced", res.Plans[0].Found)
	}
	if res.Plans[0].Announce != 0 {
		t.Errorf("the resumed run announced again at generation %d", res.Plans[0].Announce)
	}
	if res.Plans[0].Execute != base+2 {
		t.Errorf("executed at generation %d, want %d", res.Plans[0].Execute, base+2)
	}
}

// TestC2AbortSupersedesTheAnnouncement: a published announcement cannot be
// unpublished, so it is buried under an ordinary generation signed by the
// still-live key. The volume ends up on the key it started on.
func TestC2AbortSupersedesTheAnnouncement(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.seal(t, "a.txt", "hello").Generation
	startPub := hex.EncodeToString(f.head(t, "main").SigningPub[:])

	o := f.opts("main")
	o.AnnounceOnly = true
	if _, err := Execute(ctx, o); err != nil {
		t.Fatal(err)
	}
	if _, err := Abort(ctx, f.opts("main")); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	head := f.head(t, "main")
	if head.Generation != base+2 {
		t.Fatalf("head generation %d, want %d (the retraction is a generation)", head.Generation, base+2)
	}
	if head.NextPub != nil {
		t.Error("the retraction still announces a successor")
	}
	if hex.EncodeToString(head.SigningPub[:]) != startPub {
		t.Error("the abort changed the volume's key")
	}
	if p, _ := (Keys{Path: f.keyPath()}).Pending(); p != nil {
		t.Error("the pending key survived the abort")
	}
	// A reader that saw the announcement must be fine with the retraction:
	// VerifyChain checks the trusted key FIRST and only consults an
	// announcement when that fails, so an ordinary successor is ordinary.
	reader, err := refsNew(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Errorf("a fresh reader cannot read the retracted head: %v", err)
	}
}

// TestC3ExecutedButNotPromotedIsRecoveredByReconcile is the case the whole
// design turns on. The head is signed by a key sitting in `.next`, so
// without Reconcile every seal on this machine would refuse — a volume
// bricked for writing by a crash in a one-instruction window.
func TestC3ExecutedButNotPromotedIsRecoveredByReconcile(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")

	// Drive to exactly C3: publish both generations, then undo the local
	// promotion the way a crash would — the archived copy goes back to being
	// the live key and the successor returns to `.next`.
	res, err := Execute(ctx, f.opts("main"))
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{Path: f.keyPath()}
	newKey, err := keys.Live()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.pendingPath(), []byte(hex.EncodeToString(newKey)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	retired, err := os.ReadFile(res.RetiredPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.Path, retired, 0600); err != nil {
		t.Fatal(err)
	}
	head := f.head(t, "main")

	// The state is genuinely broken for a writer before the fix: the live
	// key is not the head's key.
	if live, _ := keys.Live(); matches(live, head.SigningPub) {
		t.Fatal("the fixture failed to reproduce C3")
	}

	promoted, err := Reconcile(keys.Path, head)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !promoted {
		t.Fatal("Reconcile did not promote; every seal on this machine would now be refused")
	}
	live, err := keys.Live()
	if err != nil {
		t.Fatal(err)
	}
	if !matches(live, head.SigningPub) {
		t.Fatal("after Reconcile the live key still does not match the head")
	}
	// C3 IS A PURELY LOCAL REPAIR: it publishes nothing. The remote half of
	// the rotation had already landed, so a fix that flipped anything would
	// be adding a generation to paper over a file rename.
	if f.head(t, "main").Generation != head.Generation {
		t.Error("the C3 repair published a generation")
	}
	// AND THE CLAIM THIS WHOLE FILE IS ABOUT: the next seal can be signed.
	// Checked the way a seal checks it — build the successor with the key
	// the state directory now holds, and see the volume's own reader accept
	// it — rather than by re-comparing the bytes Reconcile just moved.
	f.clock = f.clock.Add(time.Minute)
	sb, raw, err := Successor(head, mustRaw(t, f, "main"), "main", f.clock.UnixNano(), live, nil)
	if err != nil {
		t.Fatalf("signing the next generation after the repair: %v", err)
	}
	if err := f.rstore.Flip(ctx, "main", raw, mustETag(t, f, "main")); err != nil {
		t.Fatalf("flipping the next generation after the repair: %v", err)
	}
	got := f.head(t, "main")
	if got.Generation != sb.Generation {
		t.Errorf("head generation %d, want %d", got.Generation, sb.Generation)
	}
}

func mustRaw(t *testing.T, f *fixture, branch string) []byte {
	t.Helper()
	got, err := f.rstore.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatal(err)
	}
	return got.Raw
}

func mustETag(t *testing.T, f *fixture, branch string) string {
	t.Helper()
	got, err := f.rstore.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatal(err)
	}
	return got.ETag
}

// TestReconcileRefusesAKeyTheHeadDoesNotName is the mutation-shaped half of
// Reconcile: it promotes on EVIDENCE (the pending key is the head's key) and
// on nothing else. A wrong state directory must keep getting the refusal it
// deserves rather than having a stray `.next` adopted for it.
func TestReconcileRefusesAKeyTheHeadDoesNotName(t *testing.T) {
	f := newFixture(t)
	f.seal(t, "a.txt", "hello")
	keys := Keys{Path: f.keyPath()}
	// A pending key that has nothing to do with anything.
	if _, err := keys.MintPending(); err != nil {
		t.Fatal(err)
	}
	// And a live key that is not the head's either, which is what a wrong
	// state directory looks like.
	_, stranger, err := ed25519.GenerateKey(nil2Reader{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys.Path, []byte(hex.EncodeToString(stranger)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	promoted, err := Reconcile(keys.Path, f.head(t, "main"))
	if err != nil {
		t.Fatal(err)
	}
	if promoted {
		t.Fatal("Reconcile adopted a key the head does not name")
	}
}

// TestC4PromoteIsIdempotent: a crash between the archive and the rename
// leaves the state Promote was called in, so calling it again finishes.
func TestC4PromoteIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.seal(t, "a.txt", "hello")
	keys := Keys{Path: f.keyPath()}
	old, err := keys.Live()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := keys.MintPending()
	if err != nil {
		t.Fatal(err)
	}
	// The first half of Promote, by hand: the archive exists and the rename
	// has not happened.
	archive := keys.retiredPath(old.Public().(ed25519.PublicKey))
	if err := writeFileMode(archive, []byte(hex.EncodeToString(old)+"\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := keys.Promote(); err != nil {
		t.Fatalf("Promote over an existing archive: %v", err)
	}
	live, err := keys.Live()
	if err != nil {
		t.Fatal(err)
	}
	if PublicOf(live) != PublicOf(pending) {
		t.Error("Promote did not install the pending key")
	}
	// The archive is still the old key: re-archiving must not overwrite it
	// with the key that just became live, or the abort path loses its input.
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != hex.EncodeToString(old) {
		t.Error("the archived key was overwritten")
	}
}

// TestAForeignAnnouncementIsRefusedRatherThanGuessed: a head announcing a
// successor this machine does not hold cannot be finished here, and the
// error has to say which of the two recoveries applies. Silently minting a
// new successor and announcing it again would leave two announcements in
// the lineage and a reader following the wrong one.
func TestAForeignAnnouncementIsRefusedRatherThanGuessed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")
	o := f.opts("main")
	o.AnnounceOnly = true
	if _, err := Execute(ctx, o); err != nil {
		t.Fatal(err)
	}
	// The pending key goes missing — the shape of "a different machine
	// started this rotation".
	if err := os.Remove(filepath.Join(f.stateDir, "v2-signing.key"+pendingSuffix)); err != nil {
		t.Fatal(err)
	}
	_, err := Execute(ctx, f.opts("main"))
	if err == nil {
		t.Fatal("a rotation continued past an announcement it cannot honour")
	}
	if !errors.Is(err, ErrForeignAnnouncement) {
		t.Fatalf("error is %v, want ErrForeignAnnouncement", err)
	}
}

// TestAbortRefusesAnExecutedRotation: once the head is signed by the new
// key, readers have moved or will move, and "abort" would be a second
// rotation wearing the wrong name.
func TestAbortRefusesAnExecutedRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")
	if _, err := Execute(ctx, f.opts("main")); err != nil {
		t.Fatal(err)
	}
	// Put the volume back in the executed-not-promoted shape so Abort has a
	// pending key to be asked about.
	keys := Keys{Path: f.keyPath()}
	live, _ := keys.Live()
	if err := os.WriteFile(keys.pendingPath(), []byte(hex.EncodeToString(live)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Abort(ctx, f.opts("main"))
	if err == nil {
		t.Fatal("Abort accepted a completed rotation")
	}
	if !strings.Contains(err.Error(), "already signed by the successor") {
		t.Errorf("error %q does not explain that the rotation is done", err)
	}
}

// nil2Reader is a deterministic key source for the one test that needs a
// key it will never use again.
type nil2Reader struct{}

func (nil2Reader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i * 7)
	}
	return len(p), nil
}
