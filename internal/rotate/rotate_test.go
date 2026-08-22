package rotate

import (
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
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// fixture is a real volume on a real (fake) origin, with the writer's state
// directory holding a real signing key file — which is the thing under test
// as much as the superblocks are.
type fixture struct {
	t        *testing.T
	prefix   string
	inner    pelicanobj.Store
	vol      *testvol.Volume
	stateDir string
	rstore   *refs.Store
	key      ed25519.PrivateKey
	clock    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	srv := httptest.NewServer(fakeorigin.Handler(t.TempDir()))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	// The key on disk, hex, exactly as `pelfs init` leaves it: the rotation
	// reads and rewrites these files, so a fixture that held the key only in
	// memory would test half the operation.
	if err := os.WriteFile(filepath.Join(stateDir, "v2-signing.key"),
		[]byte(hex.EncodeToString(key)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		t: t, prefix: prefix, inner: inner, stateDir: stateDir, key: key,
		vol:   testvol.New(t, inner, testvol.Options{SigningKey: key}),
		clock: time.Now(),
	}
	if f.rstore, err = refs.New(inner, stateDir, nil); err != nil {
		t.Fatal(err)
	}
	// The writer's own pin, established the way every client's is.
	if _, err := f.rstore.Fetch(ctx, "main"); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}
	return f
}

func (f *fixture) keyPath() string { return filepath.Join(f.stateDir, "v2-signing.key") }

// seal publishes content, so a rotation has real generations under it.
func (f *fixture) seal(t *testing.T, name, body string) *superblock.Superblock {
	t.Helper()
	f.vol.WriteFile(testvol.RootInode, name, []byte(body))
	f.clock = f.clock.Add(time.Hour)
	res := f.vol.Publish(publish.Options{SMax: 1000, CreatedUnixNano: f.clock.UnixNano()})
	return res.Superblock
}

func (f *fixture) opts(branches ...string) Options {
	f.clock = f.clock.Add(time.Minute)
	return Options{Refs: f.rstore, Branches: branches, KeyPath: f.keyPath(), Now: f.clock.UnixNano()}
}

func (f *fixture) head(t *testing.T, branch string) *superblock.Superblock {
	t.Helper()
	got, err := f.rstore.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	return got.Superblock
}

// TestARotationPublishesAnAnnouncementThenUsesTheKey is the shape of the
// whole feature: two generations, the first announcing and still signed by
// the old key, the second signed by the new one and announcing nothing.
func TestARotationPublishesAnAnnouncementThenUsesTheKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	base := f.seal(t, "a.txt", "hello").Generation

	res, err := Execute(ctx, f.opts("main"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res.Plans) != 1 || res.Plans[0].Found != PhaseFresh {
		t.Fatalf("plans = %+v, want one fresh branch", res.Plans)
	}
	if res.Plans[0].Announce != base+1 || res.Plans[0].Execute != base+2 {
		t.Fatalf("announce/execute = %d/%d, want %d/%d",
			res.Plans[0].Announce, res.Plans[0].Execute, base+1, base+2)
	}
	head := f.head(t, "main")
	if head.Generation != base+2 {
		t.Fatalf("head generation %d, want %d", head.Generation, base+2)
	}
	if head.NextPub != nil {
		t.Error("the executing generation still announces a successor; a rotation that never ends")
	}
	if hex.EncodeToString(head.SigningPub[:]) != res.NewPub {
		t.Errorf("head signed by %x, want the successor %s", head.SigningPub[:8], res.NewPub[:16])
	}
	// And the local half: the successor is now the live key and the old one
	// is archived read-only.
	live, err := Keys{Path: f.keyPath()}.Live()
	if err != nil {
		t.Fatal(err)
	}
	if PublicOf(live) != res.NewPub {
		t.Error("the live key file was not promoted; the next seal would be refused")
	}
	st, err := os.Stat(res.RetiredPath)
	if err != nil {
		t.Fatalf("the retired key was not archived: %v", err)
	}
	if st.Mode().Perm() != 0400 {
		t.Errorf("retired key mode %v, want 0400", st.Mode().Perm())
	}
	if _, err := os.Stat(f.keyPath() + pendingSuffix); !os.IsNotExist(err) {
		t.Error("the pending key file survived promotion")
	}
}

// TestARotationIsContentNeutral pins the property that makes copying the
// head safe: the rotated generations name exactly the objects their parent
// named, so nothing a sweep walks changes and no data can be lost by
// rotating.
func TestARotationIsContentNeutral(t *testing.T) {
	f := newFixture(t)
	f.seal(t, "a.txt", "hello")
	f.seal(t, "b.txt", "world")
	before := f.head(t, "main")

	if _, err := Execute(context.Background(), f.opts("main")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	after := f.head(t, "main")

	if after.RootCatalog != before.RootCatalog {
		t.Error("the root catalog moved; a rotation must not change what the volume contains")
	}
	if len(after.Manifests) != len(before.Manifests) {
		t.Fatalf("manifest refs %d, want %d", len(after.Manifests), len(before.Manifests))
	}
	for i := range after.Manifests {
		if after.Manifests[i] != before.Manifests[i] {
			t.Errorf("manifest ref %d changed", i)
		}
	}
	if len(after.PackList) != len(before.PackList) {
		t.Errorf("inline pack list length %d, want %d", len(after.PackList), len(before.PackList))
	}
	if after.NextInode != before.NextInode {
		t.Error("the inode allocator counter moved")
	}
	if after.Params != before.Params {
		t.Error("the volume's parameters changed")
	}
	// The field this package has never heard of. Fork exists because a merge
	// needs to know where a branch was cut from, and a rotation that dropped
	// it would break that from a direction nobody would look in. The copy
	// carries it; this asserts the copy, not the field.
	if (after.Fork == nil) != (before.Fork == nil) {
		t.Error("the fork record was not carried forward")
	}
}

// TestAReaderThatSawTheAnnouncementFollowsTheRotation is the reader half,
// through the real refs.Store — the shipped VerifyChain path, not a
// re-implementation of it.
func TestAReaderThatSawTheAnnouncementFollowsTheRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")

	// A separate client with its own state directory, pinned to the old key
	// by an ordinary fetch.
	readerDir := t.TempDir()
	reader, err := refs.New(f.inner, readerDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatalf("reader's first fetch: %v", err)
	}
	oldPin := readPin(t, readerDir)

	// Announce, and let the reader see it — which is what makes the chain
	// step available. The wait an operator would do with --announce-only is
	// this fetch.
	o := f.opts("main")
	o.AnnounceOnly = true
	if _, err := Execute(ctx, o); err != nil {
		t.Fatalf("announce: %v", err)
	}
	got, err := reader.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("reader fetching the announcement: %v", err)
	}
	if got.Superblock.NextPub == nil {
		t.Fatal("the announcing generation carries no NextPub")
	}
	if readPin(t, readerDir) != oldPin {
		t.Error("the pin moved on the ANNOUNCEMENT; it must only move when the successor is used")
	}

	// Finish it, and the reader follows.
	if _, err := Execute(ctx, f.opts("main")); err != nil {
		t.Fatalf("execute: %v", err)
	}
	after, err := reader.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("reader following the rotation: %v", err)
	}
	newPin := readPin(t, readerDir)
	if newPin == oldPin {
		t.Fatal("the reader's pin did not advance; the rotation was invisible to it")
	}
	if newPin != hex.EncodeToString(after.Superblock.SigningPub[:]) {
		t.Errorf("pin is %s, want the successor %x", newPin[:16], after.Superblock.SigningPub[:8])
	}
}

// TestAReaderThatMissedTheAnnouncementCannotFollow is the LIMIT, tested
// because it is real and undocumented rather than because it is desirable.
//
// VerifyChain advances a pin by exactly one lineage step (cur.Generation ==
// prev.Generation+1). A rotation is two generations, so a client that looks
// only after both have landed has a record at N and a head at N+2 and no
// way between them. That is the whole reason --announce-only exists, and it
// is what `pelfs rotate` warns about before acting.
func TestAReaderThatMissedTheAnnouncementCannotFollow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")

	readerDir := t.TempDir()
	reader, err := refs.New(f.inner, readerDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatal(err)
	}
	// The whole rotation, with no fetch in between.
	if _, err := Execute(ctx, f.opts("main")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, err = reader.Fetch(ctx, "main")
	if err == nil {
		t.Fatal("a reader two steps behind followed the chain; VerifyChain is supposed to be one step")
	}
	if !errors.Is(err, refs.ErrUntrusted) {
		t.Fatalf("error is %v, want ErrUntrusted", err)
	}
	if !strings.Contains(err.Error(), "does not succeed") {
		t.Errorf("error %q does not name the generation gap, so a user cannot tell this from a forgery", err)
	}

	// AND THE DOCUMENTED ESCAPE WORKS: an explicit key verifies directly and
	// never consults the chain, so out-of-band re-pinning recovers such a
	// client. This is the sentence in the rotate warning, executed.
	head := f.head(t, "main")
	explicit, err := refs.New(f.inner, t.TempDir(), ed25519.PublicKey(head.SigningPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := explicit.Fetch(ctx, "main"); err != nil {
		t.Errorf("--volume-pubkey with the new key still failed: %v", err)
	}
}

// TestRotatingEveryBranchUsesOneSuccessorKey is why the default is the
// whole volume: the pin is per volume, so two branches on two different
// successors is a volume that cannot be read.
func TestRotatingEveryBranchUsesOneSuccessorKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")
	// A second branch, created the way `pelfs branch` creates one: the
	// verified head's bytes under a second name.
	head, err := f.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rstore.Flip(ctx, "dev", head.Raw, ""); err != nil {
		t.Fatal(err)
	}

	res, err := Execute(ctx, f.opts("main", "dev"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res.Plans) != 2 {
		t.Fatalf("plans = %d, want 2", len(res.Plans))
	}
	mainHead, devHead := f.head(t, "main"), f.head(t, "dev")
	if mainHead.SigningPub != devHead.SigningPub {
		t.Fatalf("main is on %x and dev on %x: one pin cannot serve two keys",
			mainHead.SigningPub[:8], devHead.SigningPub[:8])
	}
	if hex.EncodeToString(mainHead.SigningPub[:]) != res.NewPub {
		t.Error("the branches rotated to something other than the reported successor")
	}
	// A reader that follows main's lineage then reads dev must succeed,
	// which is the property "one successor key" is FOR.
	readerDir := t.TempDir()
	reader, err := refs.New(f.inner, readerDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatalf("fresh reader on the rotated main: %v", err)
	}
	if _, err := reader.Fetch(ctx, "dev"); err != nil {
		t.Errorf("dev unreadable after rotating both branches: %v", err)
	}
	// And dev's generations say dev sealed them, not main: the field the
	// retain window attributes by.
	if devHead.Branch != "dev" {
		t.Errorf("dev's head records branch %q, want \"dev\"", devHead.Branch)
	}
}

// TestASiblingLeftBehindBreaksForAReaderThatFollowedTheRotation is the
// documented consequence, asserted rather than asserted-about. This is the
// failure `--break-siblings` makes a user acknowledge.
func TestASiblingLeftBehindBreaksForAReaderThatFollowedTheRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.seal(t, "a.txt", "hello")
	head, err := f.rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rstore.Flip(ctx, "dev", head.Raw, ""); err != nil {
		t.Fatal(err)
	}

	// Only main. dev keeps the old key.
	if _, err := Execute(ctx, f.opts("main")); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// A fresh reader pins the new key from main, then cannot read dev: no
	// prior generation on record for dev's lineage, so there is not even a
	// chain step to try.
	reader, err := refs.New(f.inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Fetch(ctx, "main"); err != nil {
		t.Fatalf("reader on rotated main: %v", err)
	}
	_, err = reader.Fetch(ctx, "dev")
	if err == nil {
		t.Fatal("dev still verified under the rotated pin; the volume-wide pin is not volume-wide")
	}
	if !errors.Is(err, refs.ErrUntrusted) {
		t.Errorf("error is %v, want ErrUntrusted", err)
	}
}

func readPin(t *testing.T, stateDir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, "refs", "volume.pub"))
	if err != nil {
		t.Fatalf("read pin: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// refsNew builds a reader with a fresh state directory, for tests that need
// a client with no history on the volume.
func refsNew(t *testing.T, f *fixture) (*refs.Store, error) {
	t.Helper()
	return refs.New(f.inner, t.TempDir(), nil)
}
