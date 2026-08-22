package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// branchPublishOpts keeps packs small, so a handful of writes cut several
// of them: a repack and a sweep need something to be wrong about.
var branchPublishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

// branchVolume is the fixture every test here starts from: a real volume
// on a real (fake) origin, one generation of content on main.
type branchVolume struct {
	prefix   string
	inner    pelicanobj.Store
	v        *testvol.Volume
	rstore   *refs.Store
	stateDir string
	clock    time.Time
	rng      *mrand.Rand
	want     map[string][]byte
}

func newBranchVolume(t *testing.T, seed int64) *branchVolume {
	t.Helper()
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
	b := &branchVolume{
		prefix: prefix, inner: inner, stateDir: stateDir,
		v:     testvol.New(t, inner, testvol.Options{}),
		clock: time.Now(), rng: mrand.New(mrand.NewSource(seed)),
		want: map[string][]byte{},
	}
	if b.rstore, err = refs.New(inner, stateDir, nil); err != nil {
		t.Fatal(err)
	}
	return b
}

// body is a fresh incompressible blob, big enough that writing one cuts a
// pack of its own.
func (b *branchVolume) body() []byte {
	buf := make([]byte, 200<<10+b.rng.Intn(200<<10))
	b.rng.Read(buf)
	return buf
}

// seal publishes what has been written, advancing the injected clock so
// generations are distinguishable in time.
func (b *branchVolume) seal(t *testing.T) *publish.Result {
	t.Helper()
	b.clock = b.clock.Add(time.Hour)
	o := branchPublishOpts
	o.CreatedUnixNano = b.clock.UnixNano()
	return b.v.Publish(o)
}

// onBranch re-seats the fixture on one branch's head and points the next
// seal at that ref — both halves, because publishing onto a branch means
// building on its head AND flipping its name.
func (b *branchVolume) onBranch(t *testing.T, name string) *superblock.Superblock {
	t.Helper()
	f, err := b.rstore.Fetch(context.Background(), name)
	if err != nil {
		t.Fatalf("fetch branch %s: %v", name, err)
	}
	b.v.SetBranch(name)
	b.v.Adopt(f.Superblock, f.Raw)
	return f.Superblock
}

// write puts a file and remembers what it should read back as.
func (b *branchVolume) write(t *testing.T, name string) []byte {
	t.Helper()
	body := b.body()
	if _, ok := b.want[name]; ok {
		b.v.Write(b.v.Lookup(testvol.RootInode, name), body)
	} else {
		b.v.WriteFile(testvol.RootInode, name, body)
	}
	return body
}

// THE SHIP TEST: a branch is a second line of history, and everything that
// makes it one has to be true at once.
//
// A branch is not a feature of the format — no field names one, and a
// generation is a document — so "branching works" is not a claim about an
// object. It is four claims about behaviour, and this drives all four
// through the verbs a user types:
//
//   - CREATED at a head, so the new branch starts life mounting exactly
//     what the old one does;
//   - INDEPENDENT, so a seal on one is invisible to the other. This is the
//     claim the whole feature rests on and the one nothing else tests: the
//     two refs share every pack they inherited, so "did dev's write reach
//     main" is a real question with a wrong answer available;
//   - DELETABLE, and the deletion releases what only that branch named —
//     the same guarantee `pelfs tag --rm` makes, arrived at from the ref
//     side;
//   - AND THE TAG SURVIVES IT. A tag taken on a branch outlives the branch,
//     because a tag is a root in its own right. Without that, deleting a
//     branch would silently unpin every release cut from it.
//
// The sweep runs at --retain-k 1 for the reason tag_test.go states: the
// last-K window is an independent root set that covers this whole young
// volume, so leaving it in would answer "still retained" to every question
// here. What the window itself does across branches is
// internal/retention's business (branches_test.go there).
func TestABranchIsAnIndependentLineOfHistory(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 7)

	// Generation 1 on main: the content both branches inherit.
	shared := map[string][]byte{}
	for _, name := range []string{"a.bin", "b.bin"} {
		shared[name] = b.write(t, name)
		b.want[name] = shared[name]
	}
	mainGen1 := b.seal(t).Superblock

	// THE VERB.
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatalf("pelfs branch exited %d", code)
	}
	listed, code := capture(t, func() int {
		return cmdBranch([]string{"--list", "--state-dir", b.stateDir, b.prefix})
	})
	if code != 0 || listed != "dev\nmain\n" {
		t.Fatalf("--list printed %q (exit %d), want both branches one per line", listed, code)
	}

	// It must start at the head it was told to, and it must be the VERIFIED
	// head: `pelfs branch` fetches through the ordinary trust path, so what
	// lands under the new name is bytes this client checked.
	devHead, err := b.rstore.Fetch(ctx, "dev")
	if err != nil {
		t.Fatalf("the branch the command wrote does not verify: %v", err)
	}
	if devHead.Superblock.Generation != mainGen1.Generation ||
		devHead.Superblock.RootCatalog != mainGen1.RootCatalog {
		t.Fatalf("branch dev starts at generation %d/%x, but main's head was %d/%x",
			devHead.Superblock.Generation, devHead.Superblock.RootCatalog[:4],
			mainGen1.Generation, mainGen1.RootCatalog[:4])
	}

	// DIVERGENT WORK ON DEV, sealed. This is the generation the tag will
	// pin.
	b.onBranch(t, "dev")
	devOnly := b.write(t, "dev-only.bin")
	devTagged := b.seal(t).Superblock

	// DIVERGENT WORK ON MAIN, sealed, from main's own head.
	b.onBranch(t, "main")
	mainOnly := b.write(t, "main-only.bin")
	mainGen2 := b.seal(t).Superblock

	// INDEPENDENCE, both ways. Each branch sees its own file and not the
	// other's, and both still serve everything they inherited.
	if err := coldRead(t, b.inner, mainGen2, map[string][]byte{
		"a.bin": shared["a.bin"], "b.bin": shared["b.bin"], "main-only.bin": mainOnly,
	}); err != nil {
		t.Fatalf("main does not serve its own generation: %v", err)
	}
	if err := coldRead(t, b.inner, mainGen2, map[string][]byte{"dev-only.bin": devOnly}); err == nil {
		t.Fatal("main can see a file that was only ever written on dev; the branches are not independent")
	}
	if err := coldRead(t, b.inner, devTagged, map[string][]byte{
		"a.bin": shared["a.bin"], "b.bin": shared["b.bin"], "dev-only.bin": devOnly,
	}); err != nil {
		t.Fatalf("dev does not serve its own generation: %v", err)
	}
	if err := coldRead(t, b.inner, devTagged, map[string][]byte{"main-only.bin": mainOnly}); err == nil {
		t.Fatal("dev can see a file that was only ever written on main; the branches are not independent")
	}

	// A TAG ON DEV, then dev seals PAST it. What the tag pins and what the
	// branch alone holds are now different generations, which is what makes
	// the sweep below able to tell them apart.
	if _, code := captureLog(t, func() int {
		return cmdTag([]string{"--branch", "dev", "--state-dir", b.stateDir, b.prefix, "dev-1.0"})
	}); code != 0 {
		t.Fatalf("pelfs tag --branch dev exited %d", code)
	}
	b.onBranch(t, "dev")
	abandoned := b.write(t, "abandoned.bin")
	devGen3 := b.seal(t).Superblock

	// DELETE THE BRANCH. It must name the generation being let go and say
	// that nothing is reclaimed yet — a user who checks the volume's size
	// next has otherwise been handed a mystery.
	out, code := captureLog(t, func() int {
		return cmdBranch([]string{"--rm", "--state-dir", b.stateDir, b.prefix, "dev"})
	})
	if code != 0 {
		t.Fatalf("pelfs branch --rm exited %d: %s", code, out)
	}
	for _, wantText := range []string{
		fmt.Sprintf("generation %d", devGen3.Generation), "gc", "grace window",
	} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the confirmation does not say %q:\n%s", wantText, out)
		}
	}
	listed, code = capture(t, func() int {
		return cmdBranch([]string{"--list", "--state-dir", b.stateDir, b.prefix})
	})
	if code != 0 || listed != "main\n" {
		t.Fatalf("--list after --rm printed %q (exit %d), want main alone", listed, code)
	}

	// THE ADVERSARIAL SWEEP: a far-future clock expires every pack's
	// name-age guard, every derived object's mtime guard and every
	// condemned-ledger row, so the only thing left protecting anything is
	// membership of the root set.
	aged := 400 * time.Hour
	rep, err := retention.GC(ctx, retention.Options{
		Inner: b.inner, Refs: b.rstore, Delete: true, RetainK: 1, Now: b.clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if rep.Branches != 1 || rep.Tags != 1 {
		t.Fatalf("the sweep saw %d branches and %d tags; want main and dev-1.0 alone",
			rep.Branches, rep.Tags)
	}
	if rep.Deleted+rep.Indexes.Deleted+rep.Manifests.Deleted == 0 {
		t.Fatal("the sweep collected nothing, so it never threatened anything and this test proves nothing")
	}
	t.Logf("after --rm, the sweep collected %d packs, %d indexes, %d manifests",
		rep.Deleted, rep.Indexes.Deleted, rep.Manifests.Deleted)

	// WHAT THE DELETION RELEASED: the generation only the deleted branch
	// named is gone.
	if err := coldRead(t, b.inner, devGen3, map[string][]byte{"abandoned.bin": abandoned}); err == nil {
		t.Fatal("the generation only the deleted branch named is still fully readable after the sweep; " +
			"deleting a branch released nothing at all")
	}

	// WHAT IT DID NOT TOUCH: main, and the tag cut from the branch that is
	// gone. Byte for byte, cold, with an empty cache.
	if err := coldRead(t, b.inner, mainGen2, map[string][]byte{
		"a.bin": shared["a.bin"], "b.bin": shared["b.bin"], "main-only.bin": mainOnly,
	}); err != nil {
		t.Fatalf("main did not survive the deletion of a sibling branch: %v", err)
	}
	tagged, _, err := b.rstore.FetchTag(ctx, "dev-1.0")
	if err != nil {
		t.Fatalf("the tag cut on the deleted branch no longer verifies: %v", err)
	}
	if err := coldRead(t, b.inner, tagged, map[string][]byte{
		"a.bin": shared["a.bin"], "b.bin": shared["b.bin"], "dev-only.bin": devOnly,
	}); err != nil {
		t.Fatalf("the tag cut on the deleted branch is no longer readable: %v", err)
	}
}

// DANGER 1: REPACK LIVENESS IS A QUESTION ABOUT THE WHOLE VOLUME.
//
// A repack decides what to condemn by measuring how much of each pack some
// LIVE generation still references, and it is the caller that says which
// generations those are (liveGenerations, repackplan.go). While a volume
// had one branch, "the branch I am repacking" and "every branch" were the
// same set and nothing could tell them apart. With two they are different
// sets, and picking the wrong one is not a mistake that shows up as an
// error: the packs a sibling branch alone references measure as dead, get
// condemned, and are deleted by the next sweep past the grace window. The
// sibling then gets EIO on content it never changed.
//
// So this repacks main hard enough to condemn packs, sweeps with every age
// guard expired, and then reads dev — which nothing has touched since it
// was created — byte for byte from a cold cache.
//
// It drives liveGenerations, the CLI's own enumeration, rather than
// building a live set by hand: the enumeration IS what is under test.
// Making it return only the named branch's head fails this test at the
// cold read (checked; see the branch commit message).
func TestARepackOnOneBranchDoesNotCondemnAnothersPacks(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 11)

	shared := map[string][]byte{}
	for _, name := range []string{"a.bin", "b.bin"} {
		shared[name] = b.write(t, name)
		b.want[name] = shared[name]
	}
	b.seal(t)

	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatalf("pelfs branch exited %d", code)
	}

	// Content that lives ONLY on dev, in packs main will never name.
	b.onBranch(t, "dev")
	devWant := map[string][]byte{"a.bin": shared["a.bin"], "b.bin": shared["b.bin"]}
	devWant["dev-only.bin"] = b.write(t, "dev-only.bin")
	devHead := b.seal(t).Superblock

	// Main churns: rewriting the same files over and over is what turns its
	// own older chunks into garbage, which is what gives the repack
	// something to condemn.
	b.onBranch(t, "main")
	mainWant := map[string][]byte{"a.bin": shared["a.bin"], "b.bin": shared["b.bin"]}
	for range 4 {
		for _, name := range []string{"a.bin", "b.bin"} {
			mainWant[name] = b.write(t, name)
		}
		b.seal(t)
	}

	// THE ENUMERATION UNDER TEST, called exactly as `pelfs repack` calls it.
	live, head, err := liveGenerations(ctx, b.inner, b.rstore, "main")
	if err != nil {
		t.Fatalf("liveGenerations: %v", err)
	}
	if len(live) < 2 {
		t.Fatalf("the live set holds %d generations; a two-branch volume has at least two heads", len(live))
	}
	aged := 400 * time.Hour
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: b.inner, Live: live, Head: head, CacheDir: t.TempDir(),
			Workers: 4, Now: b.clock.Add(aged),
		},
		Refs: b.rstore, Branch: "main", SigningKey: b.v.SigningKey(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repack: %v", err)
	}
	if len(res.CondemnedPacks) == 0 {
		t.Fatal("the repack condemned no packs, so it never had the chance to condemn the wrong ones; " +
			"this test would pass on a volume with no garbage at all")
	}
	t.Logf("repack on main condemned %d packs into %d", len(res.CondemnedPacks), len(res.NewPacks))

	// The sweep that acts on it, with every guard expired.
	rep, err := retention.GC(ctx, retention.Options{
		Inner: b.inner, Refs: b.rstore, Delete: true, RetainK: 1, Now: b.clock.Add(2 * aged),
	})
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if rep.Deleted == 0 {
		t.Fatal("the sweep deleted no packs, so the condemned ones are still there and the cold read below " +
			"would pass whatever the repack decided")
	}

	// DEV, UNTOUCHED SINCE IT WAS CREATED, READ COLD.
	if err := coldRead(t, b.inner, devHead, devWant); err != nil {
		t.Fatalf("a repack on main destroyed content only dev referenced: %v", err)
	}
	// And main is still itself, so the repack did its job rather than
	// declining to do anything.
	if err := coldRead(t, b.inner, mustFetch(t, b.rstore, "main"), mainWant); err != nil {
		t.Fatalf("main is not readable after its own repack: %v", err)
	}
}

func mustFetch(t *testing.T, rstore *refs.Store, branch string) *superblock.Superblock {
	t.Helper()
	f, err := rstore.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	return f.Superblock
}

// Creating a branch over one that exists is refused, and the refusal has to
// name the generation that holds the name.
//
// This is not tidiness. `pelfs branch` writes with an empty expect-ETag, so
// the store refuses an existing ref; if it did not, a second `pelfs branch
// dev` would REPOINT a branch somebody is publishing onto — their next seal
// would fail its own CAS check having already uploaded everything, and the
// work built on the old head would be reparented under a generation that
// never contained it. Moving a branch is what publishing does, and it goes
// through the guard.
func TestBranchRefusesToMoveAnExistingBranch(t *testing.T) {
	b := newBranchVolume(t, 13)
	b.write(t, "f.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("first branch failed")
	}
	// Move main on, so a successful second create would be visibly wrong.
	b.onBranch(t, "main")
	b.write(t, "g.bin")
	moved := b.seal(t).Superblock

	out, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	})
	if code == 0 {
		t.Fatal("creating a branch over an existing one succeeded")
	}
	for _, wantText := range []string{"already names generation", "never moved", "pick another name"} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the refusal does not say %q:\n%s", wantText, out)
		}
	}
	// And it really did not move.
	if got := mustFetch(t, b.rstore, "dev"); got.Generation == moved.Generation {
		t.Fatal("the refused create moved the branch anyway")
	}
}

// THE ONE DELETION THAT IS NOT A DELETION.
//
// Every other object in a volume is reachable from a ref: a branch starts
// at a branch head or a tag, a mount opens one, and the retention sweep
// refuses outright to run on a volume with no refs ("refusing to treat
// every pack as garbage"). So removing the last branch leaves every pack in
// place with nothing able to name them and no CLI path back. That is
// destroying the volume with a verb whose name says otherwise, and it is
// refused — with the way out in the message, because a user who meant it
// still needs to know what to type.
func TestBranchRefusesToDeleteTheLastBranch(t *testing.T) {
	b := newBranchVolume(t, 17)
	b.write(t, "f.bin")
	b.seal(t)

	out, code := captureLog(t, func() int {
		return cmdBranch([]string{"--rm", "--state-dir", b.stateDir, b.prefix, "main"})
	})
	if code == 0 {
		t.Fatal("deleting the volume's only branch succeeded")
	}
	for _, wantText := range []string{"only branch", "no head to mount", "pelfs branch"} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the refusal does not say %q:\n%s", wantText, out)
		}
	}
	if _, err := b.rstore.Fetch(context.Background(), "main"); err != nil {
		t.Fatalf("the refused deletion removed the branch anyway: %v", err)
	}

	// With a second branch there, the same command goes through: the rule
	// is about the LAST branch, not about the name `main`. A project that
	// renames its trunk has done nothing wrong.
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "trunk"})
	}); code != 0 {
		t.Fatal("could not create a second branch")
	}
	out, code = captureLog(t, func() int {
		return cmdBranch([]string{"--rm", "--state-dir", b.stateDir, b.prefix, "main"})
	})
	if code != 0 {
		t.Fatalf("deleting main with a sibling present exited %d: %s", code, out)
	}
	// And it says what a user now has to type, since every --branch flag
	// defaults to the name that just went away.
	for _, wantText := range []string{"main is gone", "--branch", "trunk"} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the confirmation does not say %q:\n%s", wantText, out)
		}
	}
}

// Deleting something that is not there is a typo, not a no-op: the store's
// Delete treats a missing key as success, so "deleted dev" for a name that
// never existed would send someone looking for space that was never held.
func TestBranchRmRefusesANameThatIsNotThere(t *testing.T) {
	b := newBranchVolume(t, 19)
	b.write(t, "f.bin")
	b.seal(t)
	out, code := captureLog(t, func() int {
		return cmdBranch([]string{"--rm", "--state-dir", b.stateDir, b.prefix, "never-existed"})
	})
	if code == 0 {
		t.Fatal("deleting a branch that does not exist succeeded")
	}
	for _, wantText := range []string{"no branch named", "never-existed", "--list"} {
		if !strings.Contains(out, wantText) {
			t.Errorf("the refusal does not say %q:\n%s", wantText, out)
		}
	}
}

// The name rules are the key space's, and the `.tmp` one is the same silent
// hazard it is for a tag: every listing of refs/ skips such a name, so the
// branch would mount and be invisible to the retention sweep — which
// enumerates refs/ to build its root set. The packs it alone named would be
// collected out from under it. Refused at creation, since nothing
// downstream can see it to complain.
func TestBranchRefusesNamesTheSweepCannotSee(t *testing.T) {
	b := newBranchVolume(t, 23)
	b.write(t, "f.bin")
	b.seal(t)
	for _, name := range []string{"dev.tmp", "a/b", "..", ""} {
		out, code := captureLog(t, func() int {
			return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, name})
		})
		if code == 0 {
			t.Errorf("branch %q was accepted", name)
		}
		if !strings.Contains(out, "pelfs:") {
			t.Errorf("branch %q failed without saying why: %q", name, out)
		}
	}
}

// `--from-tag` starts a branch at a PINNED generation rather than at
// whatever a branch happens to hold now, and the point is that it then
// SEALS FORWARD like any other branch.
//
// It is the maintenance-line case: a release was tagged, the trunk has
// moved on, and a fix has to go on top of what shipped. Without it the only
// way to get a writable ref at an old generation would be to move a branch
// backwards, which is the operation `pelfs branch` refuses for good reason.
func TestBranchFromATagSealsForward(t *testing.T) {
	b := newBranchVolume(t, 29)

	released := map[string][]byte{}
	for _, name := range []string{"a.bin", "b.bin"} {
		released[name] = b.write(t, name)
		b.want[name] = released[name]
	}
	pinned := b.seal(t).Superblock
	if _, code := captureLog(t, func() int {
		return cmdTag([]string{"--state-dir", b.stateDir, b.prefix, "v1.0"})
	}); code != 0 {
		t.Fatal("tag failed")
	}

	// The trunk moves well past it.
	b.onBranch(t, "main")
	for range 3 {
		b.write(t, "a.bin")
		b.seal(t)
	}

	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--from-tag", "v1.0", "--state-dir", b.stateDir, b.prefix, "v1-fixes"})
	}); code != 0 {
		t.Fatal("branch --from-tag failed")
	}
	started := mustFetch(t, b.rstore, "v1-fixes")
	if started.Generation != pinned.Generation || started.RootCatalog != pinned.RootCatalog {
		t.Fatalf("branch --from-tag started at generation %d, not the tagged %d",
			started.Generation, pinned.Generation)
	}

	// And it publishes: a fix on top of what shipped.
	b.onBranch(t, "v1-fixes")
	fix := b.write(t, "fix.bin")
	fixed := b.seal(t).Superblock
	if fixed.Generation != pinned.Generation+1 {
		t.Fatalf("the maintenance branch sealed generation %d on top of %d",
			fixed.Generation, pinned.Generation)
	}
	want := map[string][]byte{"a.bin": released["a.bin"], "b.bin": released["b.bin"], "fix.bin": fix}
	if err := coldRead(t, b.inner, fixed, want); err != nil {
		t.Fatalf("the maintenance branch does not serve the release plus its fix: %v", err)
	}
	// The trunk is untouched by any of it.
	if err := coldRead(t, b.inner, mustFetch(t, b.rstore, "main"), map[string][]byte{"fix.bin": fix}); err == nil {
		t.Fatal("main can see a fix that was only ever written on the maintenance branch")
	}
}

// DANGER 5: A BRANCH MUST NOT BE A FRESH TRUST-ON-FIRST-USE.
//
// The volume pin is deliberately volume-level and not per-branch
// (refs.Store.pinPath says why: a per-branch pin would hand an attacker a
// fresh TOFU for every branch name they can invent). Creating a branch has
// to go through the same door — and it does, structurally, because creation
// FETCHES the source through the ordinary verified path and writes those
// exact bytes.
//
// What this pins is the consequence a reader sees: a branch created from a
// head signed by the pinned key verifies immediately, under an explicitly
// supplied key, with no new pin file and no warning.
func TestABranchInheritsTheVolumePinRatherThanEarningItsOwn(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 31)
	b.write(t, "f.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}

	// A reader that has never seen this volume, told exactly which key to
	// trust: no pin, no TOFU, no rotation shortcut. A fresh state directory,
	// so nothing local can be doing the work.
	fresh := t.TempDir()
	strict, err := refs.New(b.inner, fresh, b.v.SigningKey().Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Fetch(ctx, "dev"); err != nil {
		t.Fatalf("a branch created from a head signed by the volume key does not verify under it: %v", err)
	}
	// And nothing pinned a key for the new NAME: the pin is the volume's,
	// which is what stops an invented branch name from being a fresh
	// trust-on-first-use.
	if _, err := os.Stat(filepath.Join(fresh, "refs", "dev.pub")); !os.IsNotExist(err) {
		t.Fatal("fetching a branch wrote a per-branch key pin; the pin is volume-level by design")
	}
}

// DANGER 4 (WAS): THE WRITE LEASE IS THE VOLUME'S, NOT THE BRANCH'S.
//
// It was, in v0.1.0. meta/lease.json was one object per prefix, so two
// writable mounts on DIFFERENT branches excluded each other though they
// would never touch the same ref, and TestBranchesShareOneWriteLease
// pinned that — deliberately, because while the limit lasted what mattered
// was that it be a clean refusal rather than a corruption.
//
// The key is meta/lease-<branch>.json now, and this pins the inverse: two
// writers on different branches both hold, at once, each on its own
// object. The lease remains ADVISORY DETECTION rather than mutual
// exclusion — the real guard against two writers on ONE branch is the
// seal's refusal to publish over a ref that moved — so what the per-branch
// key buys is exactly the removal of a false exclusion, and no safety that
// was not already there.
func TestBranchesDoNotShareAWriteLease(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 37)
	b.write(t, "f.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}

	o := &cmdOpts{stateDir: b.stateDir}
	onMain, err := maintenanceLease(ctx, o, b.prefix, "main", "writer-on-main")
	if err != nil {
		t.Fatalf("the first writer could not take the lease: %v", err)
	}
	defer releaseLease(ctx, onMain)

	onDev, err := maintenanceLease(ctx, o, b.prefix, "dev", "writer-on-dev")
	if err != nil {
		t.Fatalf("a writer on another branch was refused; that false exclusion is what this key space "+
			"exists to remove: %v", err)
	}
	defer releaseLease(ctx, onDev)

	if onMain.Key() == onDev.Key() {
		t.Fatalf("both branches took %q; the lease is not per branch", onMain.Key())
	}
	// Neither displaced the other. "Both succeeded" that was really "the
	// second overwrote the first" would leave the first renewing an object
	// it no longer owns — the corruption the volume-wide refusal used to
	// prevent by refusing everything.
	if onMain.Conflicted() || onDev.Conflicted() {
		t.Fatal("one writer overwrote the other's lease; the two branches are sharing an object after all")
	}
}

// TestASecondWriterOnTheSameBranchIsStillRefused: narrowing the lease must
// not weaken it. Same branch means the same object, and the refusal still
// has to name the holder — a user told only "another client holds this"
// cannot act on it.
func TestASecondWriterOnTheSameBranchIsStillRefused(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 41)
	b.write(t, "f.bin")
	b.seal(t)

	o := &cmdOpts{stateDir: b.stateDir}
	held, err := maintenanceLease(ctx, o, b.prefix, "main", "writer-on-main")
	if err != nil {
		t.Fatalf("the first writer could not take the lease: %v", err)
	}
	defer releaseLease(ctx, held)

	_, err = maintenanceLease(ctx, o, b.prefix, "main", "writer-on-main-too")
	if err == nil {
		t.Fatal("two writers took one branch's lease at once; the advisory lease detects nothing")
	}
	if !errors.Is(err, lease.ErrHeld) {
		t.Fatalf("the refusal is not the lease one: %v", err)
	}
	if !strings.Contains(err.Error(), "writer-on-main") {
		t.Errorf("the refusal does not name the holder, so a user cannot act on it: %v", err)
	}
	if held.Conflicted() {
		t.Fatal("the refused second writer took the lease out from under the holder; the refusal is not " +
			"the whole of what happened")
	}
}

// TestAV010WriterStillExcludesEveryBranch is the mixed-version rule seen
// from the CLI. A pelfs v0.1.0 client holds meta/lease.json and its record
// says nothing about which branch it is writing, so it must exclude EVERY
// branch here; assuming otherwise would be guessing that a client we
// cannot see is somewhere else.
//
// --steal-lease must not be what clears it. That flag is about the branch
// the user is looking at, and this object is about a client they cannot
// see, so the two decisions get two flags.
//
// The v0.1.0 holder is simulated by writing the old key directly. There is
// no other way: this release has no code path that writes it, which is
// itself the rule under test (writing both objects would make two v0.2
// writers on different branches deadlock through the legacy one).
func TestAV010WriterStillExcludesEveryBranch(t *testing.T) {
	ctx := context.Background()
	b := newBranchVolume(t, 43)
	b.write(t, "f.bin")
	b.seal(t)
	if _, code := captureLog(t, func() int {
		return cmdBranch([]string{"--state-dir", b.stateDir, b.prefix, "dev"})
	}); code != 0 {
		t.Fatal("branch failed")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	record := fmt.Sprintf(`{"session":"v010-writer","hostname":"elsewhere","pid":4242,`+
		`"acquired":%q,"renewed":%q,"ttl_seconds":600}`, now, now)
	if err := b.inner.Put(ctx, lease.VolumeKey, strings.NewReader(record)); err != nil {
		t.Fatal(err)
	}

	o := &cmdOpts{stateDir: b.stateDir}
	for _, branch := range []string{"main", "dev"} {
		_, err := maintenanceLease(ctx, o, b.prefix, branch, "writer-"+branch)
		if !errors.Is(err, lease.ErrHeld) {
			t.Fatalf("branch %s: a live v0.1.0 volume lease did not exclude it: %v", branch, err)
		}
		if !strings.Contains(err.Error(), "elsewhere") {
			t.Errorf("branch %s: the refusal does not name the holder: %v", branch, err)
		}
	}

	stealing := &cmdOpts{stateDir: b.stateDir, stealLease: true}
	if _, err := maintenanceLease(ctx, stealing, b.prefix, "main", "thief"); !errors.Is(err, lease.ErrHeld) {
		t.Fatalf("--steal-lease walked past the v0.1.0 volume lease: %v", err)
	}

	ignoring := &cmdOpts{stateDir: b.stateDir, ignoreVolumeLease: true}
	l, err := maintenanceLease(ctx, ignoring, b.prefix, "main", "informed-writer")
	if err != nil {
		t.Fatalf("--ignore-volume-lease: %v", err)
	}
	defer releaseLease(ctx, l)
	if l.Key() == lease.VolumeKey {
		t.Fatal("the writer claimed the legacy object; two writers on different branches would then " +
			"exclude each other through it")
	}
	// Ignoring is not stealing: the legacy record is left exactly where it
	// was, so a v0.1.0 client that is slow rather than dead still holds
	// what it believes it holds, and the next writer here is refused again
	// unless it too says so out loud.
	if _, err := b.inner.StatKey(ctx, lease.VolumeKey); err != nil {
		t.Fatalf("the v0.1.0 lease was disturbed: %v", err)
	}
}
