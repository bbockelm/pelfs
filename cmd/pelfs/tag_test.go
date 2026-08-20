package main

import (
	"bytes"
	"context"
	mrand "math/rand"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
	"github.com/bbockelm/pelfs/internal/ui"
)

// tagPublishOpts keeps packs small enough that a handful of writes produce
// several of them, which is what gives the repack and the sweep something
// to be wrong about.
var tagPublishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

// captureLog runs fn with the ui logger redirected and returns what pelfs
// said. Everything the command reports about a refusal goes through ui, so
// this is where the advice is checked.
func captureLog(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	var buf bytes.Buffer
	restore := ui.SetOutput(&buf, ui.Plain)
	defer restore()
	code := fn()
	return buf.String(), code
}

// THE END-TO-END GUARANTEE BEHIND `pelfs tag`.
//
// The retention design's every stated limit ends in "a workflow that needs
// a longer pin must TAG the generation": past the grace window, an
// untagged older generation loses the refs only IT named, and a sweep can
// enumerate exactly two things — branch heads and tags. So the promise the
// verb makes is not that a tag object exists. It is that a generation the
// CLI froze is still mountable, byte for byte, after the branch has moved
// well past it and an adversarial sweep has run.
//
// So this drives the whole arc through the command a user actually types:
// write, seal, `pelfs tag`, keep writing and sealing, repack (which
// RETIRES the generation it grew from — the tagged one is no longer any
// branch's ancestor by name), then gc --delete on a FAR-FUTURE clock,
// where every age guard has expired and every condemned-ledger row has
// aged out. Nothing is left protecting the tagged generation's objects
// except the tag itself. Then mount it cold, with an empty cache, and
// compare every byte.
func TestTaggedGenerationSurvivesAnAdversarialSweep(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	prefix := srv.URL + "/vol"
	inner, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: prefix})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	stateDir := t.TempDir()
	v := testvol.New(t, inner, testvol.Options{})
	rng := mrand.New(mrand.NewSource(7))
	clock := time.Now()

	// A tree worth pinning, sealed.
	want := map[string][]byte{}
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		body := make([]byte, 200<<10+rng.Intn(200<<10))
		rng.Read(body)
		v.WriteFile(testvol.RootInode, name, body)
		want[name] = body
	}
	o := tagPublishOpts
	o.CreatedUnixNano = clock.UnixNano()
	tagged := v.Publish(o).Superblock

	// THE VERB, exactly as a user runs it.
	if _, code := captureLog(t, func() int {
		return cmdTag([]string{"--state-dir", stateDir, prefix, "v1.0"})
	}); code != 0 {
		t.Fatalf("pelfs tag exited %d", code)
	}

	// It must have frozen the generation that was the head, not some
	// re-derived approximation of it. Read through the state directory the
	// command used: `pelfs tag` fetches the head on the way in, so the
	// volume key is pinned there — which is also the reason a tag can be
	// verified at all (FetchTag never pins, it only checks).
	rstore, err := refs.New(inner, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	pinned, _, err := rstore.FetchTag(ctx, "v1.0")
	if err != nil {
		t.Fatalf("the tag the command wrote does not verify: %v", err)
	}
	if pinned.Generation != tagged.Generation {
		t.Fatalf("tag names generation %d, but the branch head was %d", pinned.Generation, tagged.Generation)
	}

	// The branch moves on, well past the tag: rewriting the same files is
	// what turns the tagged generation's chunks into garbage as far as the
	// head is concerned.
	for range 4 {
		for _, name := range []string{"a.bin", "b.bin"} {
			body := make([]byte, 200<<10+rng.Intn(200<<10))
			rng.Read(body)
			v.Write(v.Lookup(testvol.RootInode, name), body)
		}
		clock = clock.Add(time.Hour)
		o := tagPublishOpts
		o.CreatedUnixNano = clock.UnixNano()
		v.Publish(o)
	}

	// A repack, so the head's manifest is rewritten wholesale and the
	// generation the tag names is retired rather than merely old.
	head, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	aged := 400 * time.Hour
	if _, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head.Superblock, pinned},
			Head: head.Superblock, CacheDir: t.TempDir(), Workers: 4, Now: clock.Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("repack: %v", err)
	}

	// THE ADVERSARIAL SWEEP. A far-future clock expires every pack's
	// name-age guard, every derived object's mtime guard, and every
	// condemned-ledger row. The gc CLI has no clock flag — deliberately, it
	// is not a knob a user should have — so this drives the sweep directly
	// at the time no real run can reach.
	rep, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Delete: true, Now: clock.Add(2 * aged),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if rep.Tags != 1 {
		t.Fatalf("the sweep counted %d tags as roots; the tag is not in the live set", rep.Tags)
	}
	if rep.Deleted+rep.Indexes.Deleted+rep.Manifests.Deleted == 0 {
		t.Fatal("the far-future sweep deleted nothing, so it cannot have threatened the tag; " +
			"this test would pass on a volume with no garbage at all")
	}
	t.Logf("swept %d packs, %d indexes, %d manifests", rep.Deleted, rep.Indexes.Deleted, rep.Manifests.Deleted)

	// COLD MOUNT of the tag: a fresh genfs with an empty cache, resolving
	// every identity from what the tagged superblock names and nothing else.
	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: pinned, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("the tagged generation will not mount after the sweep: %v", err)
	}
	defer fs.Close() //nolint:errcheck
	for name, body := range want {
		n, err := fs.Lookup(ctx, testvol.RootInode, name)
		if err != nil {
			t.Fatalf("the tagged generation cannot resolve %s: %v", name, err)
		}
		got := make([]byte, len(body))
		read, err := fs.Read(ctx, n.Inode, 0, got)
		if err != nil {
			t.Fatalf("the tagged generation cannot read %s: %v", name, err)
		}
		if read != len(body) || !bytes.Equal(got, body) {
			t.Fatalf("the tagged generation serves %s differently than when it was tagged "+
				"(%d of %d bytes read)", name, read, len(body))
		}
	}
}

// A tag is immutable, and the refusal has to be the kind a user can act
// on: which generation already holds the name, and that no flag will
// override it. A "force" here would silently unpin whatever a reader — or
// the sweep — was holding through the old one.
func TestTagRefusesToMoveAnExistingTag(t *testing.T) {
	prefix, _, _, _ := planVolume(t)
	stateDir := t.TempDir()
	if _, code := captureLog(t, func() int {
		return cmdTag([]string{"--state-dir", stateDir, prefix, "v1"})
	}); code != 0 {
		t.Fatalf("first tag exited %d", code)
	}
	out, code := captureLog(t, func() int {
		return cmdTag([]string{"--state-dir", stateDir, prefix, "v1"})
	})
	if code == 0 {
		t.Fatal("tagging over an existing tag succeeded")
	}
	for _, wantText := range []string{"already names generation", "immutable", "choose another name"} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the refusal does not say %q:\n%s", wantText, out)
		}
	}
}

// The name rules are the key space's, not taste — and the one that matters
// is the .tmp suffix, which every ref listing skips. Such a tag would
// exist, verify and mount, and be invisible to the sweep that is supposed
// to retain it: the packs it alone pinned would be collected out from
// under it. It has to be refused at creation, since nothing downstream can
// see it to complain.
func TestTagRefusesNamesTheSweepCannotSee(t *testing.T) {
	prefix, _, _, _ := planVolume(t)
	for _, name := range []string{"v1.tmp", "a/b", "..", ""} {
		out, code := captureLog(t, func() int {
			return cmdTag([]string{"--state-dir", t.TempDir(), prefix, name})
		})
		if code == 0 {
			t.Errorf("tag %q was accepted", name)
		}
		if !strings.Contains(out, "pelfs:") {
			t.Errorf("tag %q failed without saying why: %q", name, out)
		}
	}
}

// --list answers "what is pinned here", including on a volume where
// nothing is: an empty tags key space does not exist at all, and reporting
// that as an error would make the healthy case look broken.
func TestTagListReportsWhatIsPinned(t *testing.T) {
	prefix, _, _, _ := planVolume(t)
	stateDir := t.TempDir()
	out, code := capture(t, func() int {
		return cmdTag([]string{"--list", "--state-dir", stateDir, prefix})
	})
	if code != 0 || !strings.Contains(out, "no tags") {
		t.Fatalf("--list on an untagged volume: exit %d, output %q", code, out)
	}
	for _, name := range []string{"v2", "v1"} {
		if _, code := captureLog(t, func() int {
			return cmdTag([]string{"--state-dir", stateDir, prefix, name})
		}); code != 0 {
			t.Fatalf("tag %s exited %d", name, code)
		}
	}
	out, code = capture(t, func() int {
		return cmdTag([]string{"--list", "--state-dir", stateDir, prefix})
	})
	if code != 0 {
		t.Fatalf("--list exited %d", code)
	}
	if out != "v1\nv2\n" {
		t.Fatalf("--list printed %q, want the tags one per line in a stable order", out)
	}
}
