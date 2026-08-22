package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/rotate"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// cliVol is a volume plus the state directory the commands will find, set up
// the way a user's would be: the signing key on disk at the default path, and
// the volume pin established by an ordinary fetch.
type cliVol struct {
	prefix   string
	stateDir string
	inner    pelicanobj.Store
	tv       *testvol.Volume
	rstore   *refs.Store
	key      ed25519.PrivateKey
	root     string
	clock    time.Time
}

func newCLIVol(t *testing.T) *cliVol {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
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
	c := &cliVol{
		prefix: prefix, stateDir: stateDir, inner: inner, key: key,
		root: filepath.Join(root, "vol"), clock: time.Now(),
		tv: testvol.New(t, inner, testvol.Options{SigningKey: key}),
	}
	if c.rstore, err = refs.New(inner, stateDir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.rstore.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *cliVol) seal(t *testing.T, name, body string) {
	t.Helper()
	c.tv.WriteFile(testvol.RootInode, name, []byte(body))
	c.clock = c.clock.Add(time.Hour)
	c.tv.Publish(publish.Options{SMax: 1000, CreatedUnixNano: c.clock.UnixNano()})
}

// args prefixes the flags every command in these tests needs: the state
// directory the key lives in, and --no-lease, because a lease wants a
// direct-read store the fake origin does not have to model for these checks.
func (c *cliVol) args(rest ...string) []string {
	return append([]string{"--state-dir", c.stateDir, "--no-lease"}, append(rest, c.prefix)...)
}

// argsWith is args for the commands that take a second positional (a branch
// or tag name), which has to come AFTER the prefix.
func (c *cliVol) argsWith(name string, rest ...string) []string {
	return append(append([]string{"--state-dir", c.stateDir, "--no-lease"}, rest...), c.prefix, name)
}

// ============================ ROTATE, AT THE CLI =======================

// TestRotateReportsBeforeItActs. The default is a description, and the
// description has to contain the two things a user cannot deduce: that the
// pin is volume-wide, and that a reader too far behind cannot follow.
func TestRotateReportsBeforeItActs(t *testing.T) {
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	before := head(t, c, "main").Generation

	out, code := captureLog(t, func() int { return cmdRotate(c.args()) })
	if code != 0 {
		t.Fatalf("report-only exited %d: %s", code, out)
	}
	if head(t, c, "main").Generation != before {
		t.Fatal("the default form published a generation")
	}
	// And no key was created: a report is readable by anyone who can read the
	// volume, so leaving private key material behind would make "report
	// only" a lie.
	if _, err := os.Stat(filepath.Join(c.stateDir, "v2-signing.key.next")); !os.IsNotExist(err) {
		t.Error("the report minted a successor key")
	}
	if !strings.Contains(out, "ONE lineage step") {
		t.Errorf("the report does not warn about the reader window:\n%s", out)
	}
}

// TestRotateRefusesToStrandSiblingsWithoutTheFlag is the confirmation gate.
// The refusal is the feature: rotating one branch of a multi-branch volume
// leaves the others unverifiable for any reader whose pin advances, and that
// has to be typed out rather than discovered.
func TestRotateRefusesToStrandSiblingsWithoutTheFlag(t *testing.T) {
	ctx := context.Background()
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	h, err := c.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.rstore.Flip(ctx, "dev", h.Raw, ""); err != nil {
		t.Fatal(err)
	}
	before := head(t, c, "main").Generation

	out, code := captureLog(t, func() int {
		return cmdRotate(c.args("--apply", "--branch", "main"))
	})
	if code == 0 {
		t.Fatalf("rotating one branch of a two-branch volume was allowed:\n%s", out)
	}
	if head(t, c, "main").Generation != before {
		t.Fatal("the refused run published anyway")
	}
	if !strings.Contains(out, "--break-siblings") {
		t.Errorf("the refusal does not name the flag that overrides it:\n%s", out)
	}
	if !strings.Contains(out, "dev") {
		t.Errorf("the refusal does not name the branch being stranded:\n%s", out)
	}

	// With the flag it proceeds — and rotating BOTH needs no flag at all,
	// which is the shape the default steers to.
	if _, code := captureLog(t, func() int {
		return cmdRotate(c.args("--apply", "--branch", "main", "--break-siblings"))
	}); code != 0 {
		t.Error("--break-siblings did not override the refusal")
	}
}

// TestRotatingEveryBranchNeedsNoConfirmation: the safe form is the default
// form. A volume with several branches and no tags rotates cleanly.
func TestRotatingEveryBranchNeedsNoConfirmation(t *testing.T) {
	ctx := context.Background()
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	h, err := c.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.rstore.Flip(ctx, "dev", h.Raw, ""); err != nil {
		t.Fatal(err)
	}
	out, code := captureLog(t, func() int { return cmdRotate(c.args("--apply")) })
	if code != 0 {
		t.Fatalf("rotating the whole volume was refused:\n%s", out)
	}
	m, d := head(t, c, "main"), head(t, c, "dev")
	if m.SigningPub != d.SigningPub {
		t.Fatal("the branches ended up on different keys")
	}
	if strings.Contains(out, "--break-siblings") {
		t.Errorf("the safe form still demanded the confirmation flag:\n%s", out)
	}
}

// TestATagMakesRotationRequireConfirmation. A tag is immutable and is
// verified against the pinned key with no chain step, so every tag stops
// verifying for a reader whose pin advances — permanently, with no
// republishing possible. That is the second thing --break-siblings confirms.
func TestATagMakesRotationRequireConfirmation(t *testing.T) {
	ctx := context.Background()
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	h, err := c.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.rstore.Tag(ctx, "v1.0", h.Raw); err != nil {
		t.Fatal(err)
	}
	out, code := captureLog(t, func() int { return cmdRotate(c.args("--apply")) })
	if code == 0 {
		t.Fatalf("a volume with a tag rotated without confirmation:\n%s", out)
	}
	if !strings.Contains(out, "v1.0") {
		t.Errorf("the refusal does not name the tag it would strand:\n%s", out)
	}
	if !strings.Contains(out, "--volume-pubkey") {
		t.Errorf("the refusal does not say how an old tag can still be read:\n%s", out)
	}

	// And after rotating anyway, the tag really is unreadable to a reader on
	// the new pin — the documented consequence, executed rather than claimed.
	if _, code := captureLog(t, func() int {
		return cmdRotate(c.args("--apply", "--break-siblings"))
	}); code != 0 {
		t.Fatal("the confirmed rotation failed")
	}
	reader, err := refs.New(c.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.FetchTag(ctx, "v1.0"); err == nil {
		t.Fatal("the tag still verified under the rotated pin")
	}
	// The escape: the retired key, which is why it is archived rather than
	// deleted.
	retired := findRetired(t, c.stateDir)
	old, err := os.ReadFile(retired)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(old)))
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := refs.New(c.inner, t.TempDir(),
		ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := explicit.FetchTag(ctx, "v1.0"); err != nil {
		t.Errorf("the archived key does not read the tag it was archived for: %v", err)
	}
}

// TestASealAfterARotationUsesTheNewKey closes the loop through the resolver
// every writer shares: once a rotation has promoted, loadOrCreateSigningKey
// hands out the successor and does not complain about the head.
func TestASealAfterARotationUsesTheNewKey(t *testing.T) {
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	if _, code := captureLog(t, func() int { return cmdRotate(c.args("--apply")) }); code != 0 {
		t.Fatal("rotate failed")
	}
	h := head(t, c, "main")
	got, err := loadOrCreateSigningKey(filepath.Join(c.stateDir, "v2-signing.key"), h)
	if err != nil {
		t.Fatalf("the shared key resolver refuses the rotated volume: %v", err)
	}
	if hex.EncodeToString(got.Public().(ed25519.PublicKey)) != hex.EncodeToString(h.SigningPub[:]) {
		t.Error("the resolver handed out a key the head does not name")
	}
}

// TestAnInterruptedRotationIsRepairedByTheNextSeal is C3 through the CLI's
// own resolver, which is the only path a mount takes. Without it a crash in
// a one-instruction window would refuse every seal on the machine.
func TestAnInterruptedRotationIsRepairedByTheNextSeal(t *testing.T) {
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	if _, code := captureLog(t, func() int { return cmdRotate(c.args("--apply")) }); code != 0 {
		t.Fatal("rotate failed")
	}
	keyPath := filepath.Join(c.stateDir, "v2-signing.key")
	// Undo the local promotion the way a crash between the flip and the
	// rename would.
	newKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	retired := findRetired(t, c.stateDir)
	old, err := os.ReadFile(retired)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".next", newKey, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, old, 0600); err != nil {
		t.Fatal(err)
	}

	h := head(t, c, "main")
	out, err := captureErr(t, func() error {
		_, e := loadOrCreateSigningKey(keyPath, h)
		return e
	})
	if err != nil {
		t.Fatalf("a seal after an interrupted rotation was refused: %v", err)
	}
	if !strings.Contains(out, "interrupted key rotation") {
		t.Errorf("the repair was silent; an operator has no way to know it happened:\n%s", out)
	}
	// And it is durable: the file, not just the return value.
	got, err := (rotate.Keys{Path: keyPath}).Live()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.Public().(ed25519.PublicKey)) != hex.EncodeToString(h.SigningPub[:]) {
		t.Error("the live key file was not repaired on disk")
	}
}

// ============================ RESCUE, AT THE CLI =======================

// TestRescueReportsBeforeItWrites, and the report is the deliverable: it
// needs no signing key, because an operator with read access must be able to
// find out what is recoverable.
func TestRescueReportsBeforeItWrites(t *testing.T) {
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	c.seal(t, "b.txt", "world")
	if err := os.RemoveAll(filepath.Join(c.root, "refs")); err != nil {
		t.Fatal(err)
	}
	// The key is moved out of the way, so a report that needed it would fail.
	keyPath := filepath.Join(c.stateDir, "v2-signing.key")
	if err := os.Rename(keyPath, keyPath+".elsewhere"); err != nil {
		t.Fatal(err)
	}

	out, code := captureLog(t, func() int { return cmdRescue(c.args()) })
	if code != 0 {
		t.Fatalf("the report exited %d with no signing key present:\n%s", code, out)
	}
	if _, err := c.rstore.Fetch(context.Background(), "main"); err == nil {
		t.Fatal("the report re-pointed the ref")
	}
}

// TestRescueApplyRestoresAVolumeFromTheCLI is the operator's path end to end:
// the refs are gone, one command brings them back, and the result verifies
// through the ordinary trust path.
func TestRescueApplyRestoresAVolumeFromTheCLI(t *testing.T) {
	ctx := context.Background()
	c := newCLIVol(t)
	c.seal(t, "a.txt", "hello")
	c.seal(t, "b.txt", "world")
	if err := os.RemoveAll(filepath.Join(c.root, "refs")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.rstore.Fetch(ctx, "main"); err == nil {
		t.Fatal("refs/main survived deletion")
	}
	out, code := captureLog(t, func() int { return cmdRescue(c.args("--apply")) })
	if code != 0 {
		t.Fatalf("rescue --apply exited %d:\n%s", code, out)
	}
	got, err := c.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("the rescued ref does not verify: %v", err)
	}
	if err := got.Superblock.Validate(); err != nil {
		t.Errorf("the rescued head is not a valid head: %v", err)
	}
	// The command has to say the thing an operator will otherwise be
	// blindsided by on their other machines.
	if !strings.Contains(out, "stale read") {
		t.Errorf("the output does not warn about clients that accepted a higher generation:\n%s", out)
	}
}

// head fetches a branch head through the trust path.
func head(t *testing.T, c *cliVol, branch string) *superblock.Superblock {
	t.Helper()
	got, err := c.rstore.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	return got.Superblock
}

// findRetired locates the archived key a rotation left behind.
func findRetired(t *testing.T, stateDir string) string {
	t.Helper()
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".retired-") {
			return filepath.Join(stateDir, e.Name())
		}
	}
	t.Fatal("no retired key was archived")
	return ""
}

// captureErr runs fn with the ui logger redirected, returning both what pelfs
// said and what fn returned — for the paths where the interesting output is a
// warning beside a successful return.
func captureErr(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	var got error
	out, _ := captureLog(t, func() int {
		got = fn()
		return 0
	})
	return out, got
}

// ============ THE ROTATION x MERGE INTERACTION ============
//
// Found by reading `pelfs merge` after it landed beside this work, and it is
// the sharpest edge either feature has: a rotation makes a PENDING MERGE
// impossible, permanently, and neither feature's own documentation would
// have told you.
//
// The chain of facts, each of which is fine on its own:
//   - `pelfs branch` records where it was cut from and pins that base with a
//     tag (superblock.Fork.Tag, forkTagName). The pin is load-bearing: the
//     base stops being any branch's head as soon as the source seals again,
//     and a generation is addressable only through a ref or a tag.
//   - `pelfs merge` reads its base with refs.Store.FetchTag, which verifies
//     against the PINNED key and takes no custody-chain step.
//   - A rotation retires the pin volume-wide.
//
// So after a rotation the fork tag no longer verifies, the base is no longer
// readable, and the merge fails. There is no repair: `pelfs tag` freezes a
// branch HEAD, so a fork point cannot be re-pinned once unreadable.
//
// This test asserts the mechanism (the fork tag becomes unreadable) and that
// `pelfs rotate` says MERGE FIRST before doing it.
func TestRotationMakesAPendingMergeBaseUnreadable(t *testing.T) {
	ctx := context.Background()
	c := newCLIVol(t)
	c.seal(t, "base.txt", "shared")

	// A branch, created through the command, so the Fork record and its
	// pinning tag are the real ones rather than a fixture's idea of them.
	if code := cmdBranch(c.argsWith("dev", "--from", "main")); code != 0 {
		t.Fatal("pelfs branch failed")
	}
	h, err := c.rstore.Fetch(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	fork := h.Superblock.Fork
	if fork == nil || fork.Tag == "" {
		t.Skip("this release's `pelfs branch` does not pin the fork point, so there is no interaction yet")
	}
	// The base is readable now, which is the baseline the rotation destroys.
	if _, _, err := c.rstore.FetchTag(ctx, fork.Tag); err != nil {
		t.Fatalf("the fork tag is not readable before the rotation: %v", err)
	}

	// THE WARNING, before anything is written.
	out, _ := captureLog(t, func() int { return cmdRotate(c.args()) })
	if !strings.Contains(out, "MERGE THESE BRANCHES FIRST") {
		t.Errorf("rotate does not warn that a pending merge base will be lost:\n%s", out)
	}
	if !strings.Contains(out, fork.Tag) {
		t.Errorf("the warning does not name the fork tag %s:\n%s", fork.Tag, out)
	}

	// And the consequence itself, for a reader whose pin has advanced.
	if _, code := captureLog(t, func() int {
		return cmdRotate(c.args("--apply", "--break-siblings"))
	}); code != 0 {
		t.Fatal("the confirmed rotation failed")
	}
	reader, err := refs.New(c.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reader.FetchTag(ctx, fork.Tag); err == nil {
		t.Fatal("the fork tag still verified under the rotated pin; the interaction has been fixed " +
			"elsewhere and this warning should be removed")
	}
}

// ============ RESCUING A MERGED GENERATION ============
//
// A merge changes what a generation's pack set MEANS, so rescue's union rule
// had to be checked against one rather than assumed to hold.
//
// WHY IT COULD HAVE BROKEN. A merge reads no content: both sides' files are
// already chunked, so the merged tree is handed to publish as a
// ContentProvider and the chunkrefs point into THEIRS' packs. Those packs
// belong to a generation on another branch — nothing in ours' lineage names
// them — so if the merged generation did not name them itself, a rescue
// rebuilding from a backup would produce a head missing half its data.
//
// WHY IT DOES NOT. publish folds a provider's packs into the generation's
// own pack set (manifestPacks and sealedPackList both include
// providedPacks), and so does the disaster-recovery backup
// (backupPackList). So the union rescue already computes covers both sides,
// and nothing in internal/rescue needed to change for merge.
//
// WHAT DID NOT NEED HANDLING EITHER: two parents. A merged generation has
// ONE PrevHash — ours' head — and records the fork base in superblock.Fork
// rather than as a second parent. Rescue never walks PrevHash at all (it
// scans packs and groups candidates by (branch, generation)), so a
// merge's lineage shape is invisible to it in both directions.
//
// This is the test that says all of that is true rather than reasoned.
func TestRescuingAMergedGenerationServesBothSides(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 91)
	b.write(t, "shared.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}
	b.onBranch(t, "dev")
	theirFile := b.write(t, "theirs.bin")
	b.seal(t)
	b.onBranch(t, "main")
	ourFile := b.write(t, "ours.bin")
	b.seal(t)

	if out, code := captureMerge(t, "--state-dir", b.stateDir, "--apply", b.prefix, "dev"); code != 0 {
		t.Fatalf("merge --apply exited %d:\n%s", code, out)
	}
	merged := mustFetch(t, b.rstore, "main")
	// Re-seat the fixture on what the merge published, exactly as a mount
	// does when it notices the branch has moved: the merge flipped the ref
	// from outside this harness, so the next seal must grow from it.
	b.onBranch(t, "main")
	// One more seal, so the merged generation is what a BACKUP describes:
	// a backup rides in the last pack of the seal that wrote it.
	b.write(t, "after.bin")
	b.seal(t)

	// THE DISASTER: the ref, gone the way a stray write token would take it.
	if err := b.inner.Delete(ctx, refs.RefDirKey+"/main"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.rstore.Fetch(ctx, "main"); err == nil {
		t.Fatal("refs/main survived deletion")
	}

	out, code := captureLog(t, func() int {
		return cmdRescue([]string{"--state-dir", b.stateDir, "--no-lease", "--apply", b.prefix})
	})
	if code != 0 {
		t.Fatalf("rescue --apply on a merged volume exited %d:\n%s", code, out)
	}
	after := mustFetch(t, b.rstore, "main")
	if after.Generation < merged.Generation {
		t.Fatalf("rescued generation %d is older than the merge at %d", after.Generation, merged.Generation)
	}
	// BOTH SIDES, read cold from the rescued head. This is the assertion the
	// whole test exists for: theirs.bin lives in packs dev cut, which only
	// the merged generation's own pack set names.
	if err := coldRead(t, b.inner, after, map[string][]byte{
		"ours.bin": ourFile, "theirs.bin": theirFile,
	}); err != nil {
		t.Fatalf("the rescued merged head does not serve both sides: %v", err)
	}
	// And the fork record survived the rescue's copy, which is what a LATER
	// merge on this volume would need.
	if merged.Fork != nil && after.Fork == nil {
		t.Error("the rescue dropped the fork record, so a future merge could not find its base")
	}
}
