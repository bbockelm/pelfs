package retention

// WHAT A SECOND BRANCH DOES TO THE RETAIN WINDOW.
//
// The window is per-branch by construction — its K comes from that
// branch's own head, and its roots are meant to be that branch's own
// chain. What it is RESOLVED from is not per-branch at all: a retired
// generation has no address, so lastk.go scavenges the disaster-recovery
// superblock backups out of packs and matches them by the generation
// number inside them.
//
// A generation number counts steps along one lineage. Branch a volume and
// both children seal N+1; both write a backup; both are signed by the
// volume key and both carry the VolumeID. Every test the scan applied
// passed for either of them.
//
// v0.1.0 answered by keeping EVERY candidate for a wanted number, which
// turned a silent loss into over-retention and cost the early stop on any
// forked volume. The backups now say which branch sealed them
// (superblock.Branch), so these tests are about three things: that no
// branch's window loses its own chain (unchanged, and still the point),
// that an attributed window stops keeping the sibling's documents, and
// that the generations attribution cannot cover — the span below a fork,
// and anything written before the field existed — still get the
// conservative rule.

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// forkedVolume is a volume whose branches have each moved on.
type forkedVolume struct {
	t     *testing.T
	inner pelicanobj.Store
	v     *testvol.Volume
	rs    *refs.Store
	clock time.Time
	// byBranch holds each branch's published generations, oldest first,
	// with the tree each must still show; raws is the wire bytes of every
	// generation this fixture published, keyed by root catalog, so a branch
	// can be started at an old one.
	byBranch map[string][]generation
	raws     map[[32]byte][]byte
	// want is the tree as the currently seated overlay sees it.
	want map[string][]byte
	// n counts writes, so no two generations hold the same bytes.
	n int
}

// fork builds a volume that sealed `shared` generations on main, branched
// `other` off the head, and then sealed `each` more generations on BOTH
// branches — so the two chains hold the same generation NUMBERS over
// different content, which is the whole hazard.
func fork(t *testing.T, shared, each int, other string) *forkedVolume {
	t.Helper()
	ctx := context.Background()
	inner, _ := newInner(t)
	f := &forkedVolume{
		t: t, inner: inner, v: testvol.New(t, inner, testvol.Options{}),
		clock: time.Now(), byBranch: map[string][]generation{},
		raws: map[[32]byte][]byte{}, want: map[string][]byte{},
	}
	var err error
	if f.rs, err = refs.New(inner, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	for range shared {
		f.write("main")
		f.seal("main")
	}
	// THE FORK, done exactly as `pelfs branch` does it: the verified head's
	// bytes, written under a second name.
	head, err := f.rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.rs.Flip(ctx, other, head.Raw, ""); err != nil {
		t.Fatalf("create branch %s: %v", other, err)
	}
	// Both branches inherit everything sealed so far: those generations are
	// genuinely on both chains.
	f.byBranch[other] = append([]generation(nil), f.byBranch["main"]...)

	// INTERLEAVED, so neither branch's backups are systematically newer.
	// The scan walks packs newest-first, and a fixture where one branch
	// always sealed last would let a first-wins scan be accidentally right
	// on the branch that mattered.
	for range each {
		for _, branch := range []string{"main", other} {
			f.sealOn(t, branch, 1)
		}
	}
	return f
}

// rawOf is the wire bytes of a generation this fixture published — what a
// branch is created FROM.
func (f *forkedVolume) rawOf(t *testing.T, g generation) []byte {
	t.Helper()
	raw, ok := f.raws[g.sb.RootCatalog]
	if !ok {
		t.Fatalf("fixture: no wire bytes recorded for generation %d", g.sb.Generation)
	}
	return raw
}

// seatOn re-seats the overlay on a branch's head and points the next seal
// at that ref — both halves, as publishing onto a branch requires.
func (f *forkedVolume) seatOn(t *testing.T, branch string) {
	t.Helper()
	g, err := f.rs.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	f.v.SetBranch(branch)
	f.v.Adopt(g.Superblock, g.Raw)
	// The overlay was just reopened over that branch's head, so the
	// remembered tree has to follow it.
	last := f.byBranch[branch][len(f.byBranch[branch])-1]
	f.want = make(map[string][]byte, len(last.want))
	for k, val := range last.want {
		f.want[k] = val
	}
}

// sealOn seats on a branch and publishes n more generations onto it.
func (f *forkedVolume) sealOn(t *testing.T, branch string, n int) {
	t.Helper()
	for range n {
		f.seatOn(t, branch)
		f.write(branch)
		f.seal(branch)
	}
}

// write rewrites the same files, which is what turns each generation's
// chunks into garbage as far as the next one is concerned. The branch name
// and a running counter go into the bytes, so no two generations of the two
// chains ever hold the same content.
func (f *forkedVolume) write(branch string) {
	f.t.Helper()
	f.n++
	for _, name := range []string{"a.bin", "b.bin"} {
		body := make([]byte, 0, 120<<10)
		for len(body) < 120<<10 {
			body = append(body, byte(f.n), byte(f.n*7), branch[0], name[0])
		}
		if _, ok := f.want[name]; ok {
			f.v.Write(f.v.Lookup(testvol.RootInode, name), body)
		} else {
			f.v.WriteFile(testvol.RootInode, name, body)
		}
		f.want[name] = body
	}
}

func (f *forkedVolume) seal(branch string) {
	f.t.Helper()
	// A LONG STEP BETWEEN SEALS, and it is load-bearing rather than
	// cosmetic. The condemned ledgers are what speak for the refs a
	// generation's successor stopped listing, and publish carries a row
	// only until it ages past the grace window — so with seals a minute
	// apart, every row in this fixture's history is still there and the
	// ledger, not the retain window, is what keeps the old generations
	// readable. A test built that way passes whatever the window does.
	// Stepping past T_grace between seals retires the rows, and then the
	// window is the only thing left.
	f.clock = f.clock.Add(40 * time.Hour)
	o := windowPublishOpts
	o.CreatedUnixNano = f.clock.UnixNano()
	res := f.v.Publish(o)
	snap := make(map[string][]byte, len(f.want))
	for k, val := range f.want {
		snap[k] = val
	}
	f.byBranch[branch] = append(f.byBranch[branch], generation{sb: res.Superblock, want: snap})
	f.raws[res.Superblock.RootCatalog] = res.Raw
}

// THE TEST THE VERB WAITED ON.
//
// Both branches keep the window their own head asks for. The failure this
// catches is silent by construction: with the branches' backups
// indistinguishable by generation number, a scan that took the first one
// it found filled ONE branch's window with the OTHER's documents, and the
// loser's retired generations dropped out of the root set — after which a
// far-future sweep collected what only they named. Nothing errors; the
// report even says the window is full. The generation simply stops
// mounting.
//
// So the assertion is the one lastk_test.go uses: every generation inside
// each branch's window must still READ, cold and byte-exact, after a sweep
// with every age guard expired. Run against the first-wins scan this fails
// on the branch whose backups the walk reached second (checked; the
// mutation is in the branch commit message).
func TestEachBranchKeepsItsOwnRetainWindow(t *testing.T) {
	f := fork(t, 2, 3, "dev")

	rep, err := GC(context.Background(), Options{
		Inner: f.inner, Refs: f.rs, Delete: true, Now: f.clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Branches != 2 {
		t.Fatalf("the sweep saw %d branches; the fixture has two", rep.Branches)
	}
	if len(rep.Windows) != 2 {
		t.Fatalf("the sweep reported %d retain windows, want one per branch", len(rep.Windows))
	}
	for _, w := range rep.Windows {
		gens := f.byBranch[w.Branch]
		if w.Generations < len(gens) {
			t.Errorf("branch %s established %d of its %d generations (K=%d, unresolved %v); a branch's "+
				"window has to be resolvable from its own chain",
				w.Branch, w.Generations, len(gens), w.K, w.Unresolved)
		}
	}
	for branch, gens := range f.byBranch {
		for _, g := range gens {
			if err := mounts(t, f.inner, g); err != nil {
				t.Errorf("branch %s: generation %d is inside that branch's retain window and does not "+
					"read after the sweep: %v", branch, g.sb.Generation, err)
			}
		}
	}

	// THE MIRROR, so this is not a test about a volume with nothing to
	// lose: narrow both windows to the head alone and the retired
	// generations must go.
	if _, err := GC(context.Background(), Options{
		Inner: f.inner, Refs: f.rs, Delete: true, RetainK: 1, Now: f.clock.Add(2 * aged),
	}); err != nil {
		t.Fatalf("GC at retain-k 1: %v", err)
	}
	lost := 0
	for branch, gens := range f.byBranch {
		head := gens[len(gens)-1]
		if err := mounts(t, f.inner, head); err != nil {
			t.Fatalf("branch %s stopped reading its own HEAD after a sweep, which is a bug in the sweep "+
				"and not in the window: %v", branch, err)
		}
		for _, g := range gens[:len(gens)-1] {
			if mounts(t, f.inner, g) != nil {
				lost++
			}
		}
	}
	if lost == 0 {
		t.Fatal("every retired generation on both branches still read after a head-only sweep, so the " +
			"windows were not what kept them alive and this test proves nothing")
	}
	t.Logf("both windows held; retain-1 then left %d retired generations unreadable", lost)
}

// THE ROOT SET HOLDS EVERY BRANCH'S OWN CHAIN — asked of the set itself,
// which is the only place the answer is unambiguous.
//
// The test above reads the CONSEQUENCE (does it still mount), and that is
// the guarantee a user cares about. But the consequence is cushioned: a
// generation whose window root went missing is often still readable,
// because the condemned-ledger floor speaks for the refs its successor
// stopped listing, and because a head names every pack its branch ever
// cut. Those cushions are real, and they are why this collision was
// survivable in practice rather than why it was correct. They run out —
// the ledgers are bounded in bytes and drop their oldest rows, and a
// repack takes packs out of a head's list for good.
//
// So this asks the root set directly: for every generation inside every
// branch's window, is that generation's OWN manifest and index set live?
// Under the first-wins scan the answer is no for whichever branch the
// newest-first walk reached second, and it is no SILENTLY — the report
// still says the window is full, because it counts generation NUMBERS
// resolved and every number was resolved by somebody.
func TestTheRootSetHoldsEveryBranchsOwnChain(t *testing.T) {
	ctx := context.Background()
	f := fork(t, 2, 3, "dev")

	live, _, err := retainedSet(ctx, Options{Inner: f.inner, Refs: f.rs, Now: f.clock.Add(aged)},
		&Report{}, newWindowCache())
	if err != nil {
		t.Fatalf("retainedSet: %v", err)
	}

	checked := 0
	for branch, gens := range f.byBranch {
		head := gens[len(gens)-1].sb
		k := head.Params.RetainK
		if k == 0 {
			k = DefaultRetainK
		}
		for _, g := range gens {
			// Only what the window actually promises. Generations below it
			// are entitled to be collected, and asserting on those would be
			// asserting the opposite of the rule.
			if g.sb.Generation+uint64(k) <= head.Generation {
				continue
			}
			checked++
			for _, mf := range g.sb.Manifests {
				if _, ok := live.manifests[mf.Name]; !ok {
					t.Errorf("branch %s, generation %d: its manifest segment %s is not in the sweep's "+
						"live set, so this sweep would delete it and leave that generation unreadable",
						branch, g.sb.Generation, mf.Name[:12])
				}
			}
			for _, ix := range g.sb.PackIndexes {
				if _, ok := live.indexes[ix.Name]; !ok {
					t.Errorf("branch %s, generation %d: its pack index %s is not in the sweep's live set",
						branch, g.sb.Generation, ix.Name[:12])
				}
			}
		}
	}
	if checked < 2*len(f.byBranch) {
		t.Fatalf("only %d generations were inside any window; this fixture proves nothing about a window",
			checked)
	}
	t.Logf("checked %d generations across %d branches against the live set", checked, len(f.byBranch))
}

// A BRANCH IS AS DEEP AS ITS OWN CHAIN, NOT AS DEEP AS THE TRUNK.
//
// A branch started at an OLD generation — the maintenance-line case, which
// `pelfs branch --from-tag` makes ordinary — is where a per-branch window
// and a volume-wide scan come apart hardest. dev's head sits at generation
// 3 while main is at 7, both ask for K=8, and the numbers dev wants are
// numbers the trunk also has documents for. What dev must retain is its
// OWN generations at those numbers; what it must not do is answer the
// question out of main's chain and leave its own unprotected.
func TestABranchStartedInThePastKeepsItsOwnChain(t *testing.T) {
	ctx := context.Background()
	f := fork(t, 3, 0, "unused")

	// dev starts at main's SECOND generation, not at its head, and then
	// seals twice of its own.
	old := f.byBranch["main"][1]
	if err := f.rs.Flip(ctx, "dev", f.rawOf(t, old), ""); err != nil {
		t.Fatalf("create branch dev at an old generation: %v", err)
	}
	f.byBranch["dev"] = append([]generation(nil), f.byBranch["main"][:2]...)
	f.sealOn(t, "dev", 2)

	// Main moves on past it, so the two chains hold different content at
	// the same generation numbers.
	f.sealOn(t, "main", 2)

	rep, err := GC(ctx, Options{
		Inner: f.inner, Refs: f.rs, Delete: true, Now: f.clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, w := range rep.Windows {
		head := f.byBranch[w.Branch][len(f.byBranch[w.Branch])-1].sb
		if w.K < uint32(head.Generation)+1 {
			t.Fatalf("fixture: branch %s asks for K=%d at generation %d, so its window covers its whole "+
				"chain and the edge is never tested", w.Branch, w.K, head.Generation)
		}
		// A window can be SHORT (an unresolvable backup is reported, never
		// guessed) and it can hold extra roots (retention is a union, so
		// extra roots only keep more). What it can never do is claim
		// coverage of more generations than the branch has: generation
		// numbers run 0..head, so that is the bound.
		if w.Generations > int(head.Generation)+1 {
			t.Errorf("branch %s is at generation %d — %d generations deep — but its window claims %d",
				w.Branch, head.Generation, head.Generation+1, w.Generations)
		}
	}
	for branch, gens := range f.byBranch {
		for _, g := range gens {
			if err := mounts(t, f.inner, g); err != nil {
				t.Errorf("branch %s: generation %d is inside that branch's window and does not read "+
					"after the sweep: %v", branch, g.sb.Generation, err)
			}
		}
	}
}

// THE SINGLE-BRANCH STOP IS UNCHANGED, INCLUDING FOR A VOLUME WHOSE
// BACKUPS CARRY NO BRANCH AT ALL.
//
// Attribution gives the scan a complete answer to stop on, but it must not
// be the ONLY thing that does: a v0.1.0-era volume's backups say nothing
// about a branch, and with one branch a generation number IS an identity
// — the first document found for a number is the only one there can be.
// That stop is kept, and this pins it, because the alternative is a sweep
// that walks the whole pack space on every volume in the world: at target
// scale that is hundreds of thousands of trailer reads where a handful
// were needed.
//
// K=3 against a twelve-generation volume is the shape that shows it: only
// the three newest backups are wanted, and everything older must go unread.
func TestOneBranchStillStopsScanningEarly(t *testing.T) {
	inner, _, rs, _, clock := churn(t, 12)
	one, err := GC(context.Background(), Options{
		Inner: inner, Refs: rs, RetainK: 3, Now: clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(one.Windows) != 1 {
		t.Fatalf("one branch, %d windows", len(one.Windows))
	}
	packs, err := inner.ListDir(context.Background(), packstore.PackDirKey)
	if err != nil {
		t.Fatal(err)
	}
	// The window wants three backups, each riding in the pack its seal cut
	// last. Newest-first, that is three packs and a little slack for the
	// packs a seal cut after the one holding its backup; nothing like the
	// whole volume.
	if got, limit := one.Windows[0].TrailersRead, len(packs)/2; got > limit {
		t.Errorf("a retain-3 window on a %d-pack volume read %d trailers (over half); the early stop is "+
			"gone, and every sweep on every single-branch volume now walks the pack space",
			len(packs), got)
	}
	t.Logf("retain-3 resolved %d generations from %d of %d pack trailers",
		one.Windows[0].Generations, one.Windows[0].TrailersRead, len(packs))
}

// ================= ATTRIBUTION =================

// windowWant is the generations whose BACKUPS a branch's window looks for
// — backup_G describes generation G-1, so this is head..head-K+2 floored
// at 1, exactly as windowRoots computes it.
//
// The arithmetic is repeated here rather than reached for, because these
// tests are measuring what that arithmetic feeds: a helper that called
// windowRoots would be asking the rule under test to describe itself.
func windowWant(head *superblock.Superblock, k uint32) map[uint64]bool {
	oldest := uint64(1)
	if head.Generation+2 > uint64(k) {
		oldest = head.Generation - uint64(k) + 2
	}
	want := make(map[uint64]bool, head.Generation-oldest+1)
	for g := oldest; g <= head.Generation; g++ {
		want[g] = true
	}
	return want
}

// discardedByAttribution is every backup the OLD rule would have put in
// this branch's window and the new one leaves out: the candidates for a
// generation that also has a document of this branch's own.
//
// It is the exact difference between the two rules. Where a generation has
// no attributed candidate the new rule keeps everything the old one did,
// so nothing is discarded there; where it has one, the siblings go. Which
// makes "the v0.1.0 retained set" computable from the current one without
// a second implementation of the sweep: it is this set unioned in.
func discardedByAttribution(t *testing.T, o Options, branch string, branches int) []*superblock.Superblock {
	t.Helper()
	f, err := o.Refs.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	k := f.Superblock.Params.RetainK
	if k == 0 {
		k = DefaultRetainK
	}
	if o.RetainK != 0 {
		k = o.RetainK
	}
	rep := LastKReport{K: k}
	want := windowWant(f.Superblock, k)
	// An IMPOSSIBLE generation number, so the scan cannot reach a complete
	// attributed answer and runs the whole pack space. Without it the early
	// stop — the thing this change adds — hides candidates from the
	// measurement, and the v0.1.0 set would be understated by exactly the
	// documents the new rule never had to look at.
	want[f.Superblock.Generation+1000] = true
	found, err := scavengeBackups(context.Background(), o, branch, f.Superblock, want, &rep, branches)
	if err != nil {
		t.Fatalf("scavenge %s: %v", branch, err)
	}
	var out []*superblock.Superblock
	for _, set := range found {
		if len(set.mine) > 0 {
			out = append(out, set.others...)
		}
	}
	return out
}

// objectsOf is every object a set of superblocks names — packs, manifest
// segments, pack indexes — as one name set, which is what "the retained
// set" means to a sweep.
func objectsOf(t *testing.T, o Options, sbs []*superblock.Superblock) map[string]struct{} {
	t.Helper()
	out := make(map[string]struct{})
	for _, sb := range sbs {
		packs, err := manifest.Packs(context.Background(), o.Inner, sb)
		if err != nil {
			t.Fatalf("resolve generation %d's pack set: %v", sb.Generation, err)
		}
		for _, pe := range packs {
			out["pack/"+pe.Name] = struct{}{}
		}
		for _, mf := range sb.Manifests {
			out["manifest/"+mf.Name] = struct{}{}
		}
		for _, ix := range sb.PackIndexes {
			out["index/"+ix.Name] = struct{}{}
		}
	}
	return out
}

// THE OVER-RETENTION IS GONE, MEASURED.
//
// v0.1.0's rule was correct and expensive: with the branches' backups
// indistinguishable, every candidate for a wanted generation number went
// into every branch's window, so main's window carried dev's manifests,
// indexes and packs and dev's carried main's. Nothing was lost and nothing
// could be freed — the objects a retired generation on the OTHER branch
// alone named stayed live for as long as this branch's window ran.
//
// The measurement is the difference between the two rules over one
// fixture, taken from the same scan, so it cannot drift from what the
// sweep actually does: the v0.1.0 retained set is the current one plus the
// objects of the candidates attribution discarded.
//
// THE FIXTURE HAS TO HAVE BRANCHES AT DIFFERENT DEPTHS, and that is worth
// saying because the obvious fixture measures nothing. The live set is a
// UNION over every branch, so on two chains of equal length each branch's
// window wants the same generation numbers and the sibling's documents are
// retained by the sibling anyway — v0.1.0's extra roots cost nothing there
// because somebody needed every one of them. The cost appears when a
// window reaches for a number the OTHER branch has long since retired past:
// main nine generations deep and dev five, at K=3, means dev's window
// wanted main's generations 3 and 4, which main's own window stopped
// covering four seals ago.
func TestAttributionShrinksTheRetainedSetOnAForkedVolume(t *testing.T) {
	ctx := context.Background()
	f := fork(t, 2, 3, "dev")
	f.sealOn(t, "main", 4)
	o := Options{Inner: f.inner, Refs: f.rs, RetainK: 3, Now: f.clock.Add(aged)}

	live, _, err := retainedSet(ctx, o, &Report{}, newWindowCache())
	if err != nil {
		t.Fatalf("retainedSet: %v", err)
	}
	after := make(map[string]struct{}, len(live.packs)+len(live.manifests)+len(live.indexes))
	for n := range live.packs {
		after["pack/"+n] = struct{}{}
	}
	for n := range live.manifests {
		after["manifest/"+n] = struct{}{}
	}
	for n := range live.indexes {
		after["index/"+n] = struct{}{}
	}

	var discarded []*superblock.Superblock
	for _, branch := range []string{"main", "dev"} {
		discarded = append(discarded, discardedByAttribution(t, o, branch, 2)...)
	}
	if len(discarded) == 0 {
		t.Fatal("attribution discarded no candidate on a two-branch fixture, so the two rules agree here " +
			"and this measures nothing; the fixture is not forked the way it thinks it is")
	}
	before := make(map[string]struct{}, len(after))
	for n := range after {
		before[n] = struct{}{}
	}
	for n := range objectsOf(t, o, discarded) {
		before[n] = struct{}{}
	}

	if len(before) <= len(after) {
		t.Fatalf("the v0.1.0 rule retained %d objects and attribution retains %d; the over-retention this "+
			"change exists to remove is not there", len(before), len(after))
	}
	t.Logf("two branches, %d discarded sibling candidates: retained set %d objects -> %d (%.0f%% smaller)",
		len(discarded), len(before), len(after),
		100*float64(len(before)-len(after))/float64(len(before)))

	// AND IT IS STILL A UNION OVER EVERY BRANCH'S OWN CHAIN. The shrink is
	// only worth having if nothing a branch needs left with it, which is
	// what the two tests above assert on the same fixture — this one adds
	// the sharpest version: each branch's OWN generations, by their own
	// manifests, must be in the set that just got smaller.
	for branch, gens := range f.byBranch {
		head := gens[len(gens)-1].sb
		for _, g := range gens {
			// The window in force is the OVERRIDE this sweep ran with, not
			// the head's own K. Generations below it are entitled to be
			// collected, and asserting on those would be asserting the
			// opposite of the rule.
			if g.sb.Generation+uint64(o.RetainK) <= head.Generation {
				continue
			}
			for _, mf := range g.sb.Manifests {
				if _, ok := after["manifest/"+mf.Name]; !ok {
					t.Errorf("branch %s, generation %d: attribution dropped its manifest segment %s out of "+
						"the retained set — the window is now tight and WRONG", branch, g.sb.Generation, mf.Name[:12])
				}
			}
		}
	}
}

// THE EARLY STOP COMES BACK, AND FOR FORKED VOLUMES TOO.
//
// This is the cost half of the same change. Keeping every candidate meant
// the scan could never stop at "every generation has one", so every sweep
// of a forked volume walked the pack space to its end or to the budget —
// at target scale, hundreds of thousands of trailer reads to establish a
// window of eight. With (branch, generation) an identity, a generation
// with an attributed candidate is FINISHED, and a window whose generations
// are all attributed is a complete answer no later pack can improve on.
//
// K=3 over a nine-generation fork is the shape that shows it: both
// branches sealed every generation the window wants, so both windows are
// fully attributed, and the backups they want are in the newest packs.
func TestAForkedVolumeStopsScanningEarlyOnceAttributed(t *testing.T) {
	f := fork(t, 2, 6, "dev")
	packs, err := f.inner.ListDir(context.Background(), packstore.PackDirKey)
	if err != nil {
		t.Fatal(err)
	}

	rep, err := GC(context.Background(), Options{
		Inner: f.inner, Refs: f.rs, RetainK: 3, Now: f.clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(rep.Windows) != 2 {
		t.Fatalf("the sweep reported %d windows, want one per branch", len(rep.Windows))
	}
	for _, w := range rep.Windows {
		// Both branches sealed every generation a retain-3 window wants, so
		// both windows are attributable in full. Anything else means the
		// scan resolved one of them out of the SIBLING's documents and
		// stopped before reaching the branch's own — which is the silent
		// loss this whole rule exists to prevent, wearing a report line.
		if w.ScanMode() != "attributed" {
			t.Fatalf("branch %s's retain-3 window reports %q: a generation it sealed itself was resolved "+
				"from somebody else's backup", w.Branch, w.ScanMode())
		}
		if w.Generations != 3 {
			t.Errorf("branch %s established %d of a retain-3 window (unresolved %v)",
				w.Branch, w.Generations, w.Unresolved)
		}
		// The window wants two backups, each in the pack its seal cut last.
		// Under the keep-every-candidate rule this was len(packs) every
		// time; half the pack space is a bound loose enough to survive the
		// packs a seal cuts after the one holding its backup, and tight
		// enough that a scan running to the end fails it.
		if limit := len(packs) / 2; w.TrailersRead > limit {
			t.Errorf("branch %s's retain-3 window read %d of %d pack trailers (over half); the early stop "+
				"is not firing on a forked volume, which is the cost this change was supposed to remove",
				w.Branch, w.TrailersRead, len(packs))
		}
		t.Logf("branch %s: %s, %d generations from %d of %d pack trailers",
			w.Branch, w.ScanMode(), w.Generations, w.TrailersRead, len(packs))
	}
}

// A BRANCH'S WINDOW REACHES BACK PAST ITS OWN FORK, AND THOSE GENERATIONS
// ARE NOT ITS OWN TO CLAIM.
//
// dev inherits main's generations 1..N, and their backups say "main"
// because main is what sealed them. They are dev's history all the same,
// so an attribution rule that simply required a matching name would
// declare them unresolved and drop them out of dev's root set — which is
// the very failure this change exists to remove, arrived at from the other
// side.
//
// So the fallback is per generation and it is conservative, and this asks
// for it directly: dev's window must report legacy candidates for exactly
// the generations below the fork, and its shared ancestry must still read.
func TestABranchsPreForkGenerationsUseTheConservativeRule(t *testing.T) {
	ctx := context.Background()
	f := fork(t, 3, 3, "dev")

	rep, err := GC(ctx, Options{Inner: f.inner, Refs: f.rs, Delete: true, Now: f.clock.Add(aged)})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	byBranch := map[string]LastKReport{}
	for _, w := range rep.Windows {
		byBranch[w.Branch] = w
	}
	// main sealed every generation in its own window, so it is entirely
	// attributed and pays nothing for dev existing.
	if got := byBranch["main"]; got.ScanMode() != "attributed" || got.Legacy != 0 {
		t.Errorf("main sealed its whole chain and its window reports %q (%d legacy generations)",
			got.ScanMode(), got.Legacy)
	}
	// dev sealed generations 4..6 and inherited 1..3. Its window wants the
	// backups of 1..6; three of those are its own and three are main's.
	dev := byBranch["dev"]
	if dev.Attributed == 0 || dev.Legacy == 0 {
		t.Fatalf("dev's window reports %d attributed and %d legacy generations; a branch forked mid-history "+
			"has both, and a fixture with only one kind tests neither rule", dev.Attributed, dev.Legacy)
	}
	if dev.Attributed+dev.Legacy != dev.Generations-1 {
		t.Errorf("dev's window: %d attributed + %d legacy != %d generations - the head",
			dev.Attributed, dev.Legacy, dev.Generations)
	}
	if dev.LegacyCandidates < dev.Legacy {
		t.Errorf("dev kept %d candidates across %d legacy generations; each needs at least one",
			dev.LegacyCandidates, dev.Legacy)
	}
	t.Logf("dev: %s (%d attributed, %d legacy generations); main: %s",
		dev.ScanMode(), dev.Attributed, dev.Legacy, byBranch["main"].ScanMode())

	// The consequence, which is the only thing a user sees: every
	// generation on both chains — inherited ones included — still reads
	// cold after a sweep with every age guard expired.
	for branch, gens := range f.byBranch {
		for _, g := range gens {
			if err := mounts(t, f.inner, g); err != nil {
				t.Errorf("branch %s: generation %d is inside that branch's window and does not read after "+
					"the sweep: %v", branch, g.sb.Generation, err)
			}
		}
	}
}

// A MIXED-ERA VOLUME: THE TIGHT RULE FOR NEW HISTORY, THE CONSERVATIVE ONE
// ONLY ACROSS THE LEGACY SPAN.
//
// An existing volume does not get its old backups rewritten — they are
// inside packs, signed, and nothing re-signs them — so for K seals after
// an upgrade a window straddles the two eras. The rule has to be per
// generation for that reason alone: applied per BRANCH it would be either
// wrong (attributed, dropping the legacy generations) or pointless
// (conservative, until every backup in the window is new).
//
// The fixture writes genuine v0.1.0-shaped backups — Branch empty, signed
// by the volume's own key, buried in a pack exactly as a seal buries one —
// for generations the head wants and nothing else describes. One of them
// gets TWO distinct legacy documents, which is the case the conservative
// rule exists for: nothing can tell them apart, so both are kept.
func TestAMixedEraWindowUsesBothRules(t *testing.T) {
	ctx := context.Background()
	inner, v, rs, gens, clock := churn(t, 5)

	// The head jumps forward, which is the cheap way to ask for backups
	// that do not exist: generations 6 and 7 have never been sealed, so
	// nothing but the fixture below describes them.
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	head := *f.Superblock
	head.Generation = 7
	if err := head.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := head.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(ctx, "main", raw, f.ETag); err != nil {
		t.Fatal(err)
	}

	// Two v0.1.0-shaped backups for generation 7 and one for 6, built from
	// a real generation so they resolve to real objects, stripped of the
	// branch and re-signed. Distinct CreatedUnixNano makes the pair at
	// generation 7 two distinct DOCUMENTS rather than one seen twice, which
	// is what the scan dedups on.
	pw, err := packstore.NewPackWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacy := []struct {
		gen     uint64
		created int64
	}{{7, clock.UnixNano()}, {7, clock.Add(time.Second).UnixNano()}, {6, clock.UnixNano()}}
	for _, l := range legacy {
		sb := *gens[len(gens)-1].sb
		sb.Generation, sb.Branch, sb.CreatedUnixNano = l.gen, "", l.created
		if err := sb.Sign(v.SigningKey()); err != nil {
			t.Fatal(err)
		}
		enc, err := sb.Encode()
		if err != nil {
			t.Fatal(err)
		}
		h := superblock.Hash(enc)
		if err := pw.Add(hex.EncodeToString(h[:]), packstore.EntrySuperblock, enc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pw.Seal(ctx, inner); err != nil {
		t.Fatalf("seal the legacy-backup pack: %v", err)
	}

	// Report only: the synthetic pack is named by no live superblock, so a
	// deleting sweep would collect it and the second half of this test
	// would be measuring a volume it had just changed.
	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Now: clock.Add(aged)})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	w := rep.Windows[0]
	// Generations 2..5 are described by real, branch-stamped backups; 6 and
	// 7 by the legacy documents above; the head is itself.
	if w.Attributed == 0 {
		t.Fatalf("no generation in a mixed window was attributed (%s); the new history is being resolved "+
			"by the conservative rule too, which is the whole cost this change removes", w.ScanMode())
	}
	if w.Legacy != 2 {
		t.Errorf("the window resolved %d generations from unattributed backups, want the 2 the fixture "+
			"wrote (mode %q, unresolved %v)", w.Legacy, w.ScanMode(), w.Unresolved)
	}
	if w.LegacyCandidates != 3 {
		t.Errorf("the window kept %d legacy candidates, want 3: generation 7 has two documents nothing can "+
			"tell apart, and the conservative rule keeps both", w.LegacyCandidates)
	}
	if mode := w.ScanMode(); mode == "attributed" {
		t.Errorf("a window holding %d legacy candidates reported itself as %q; the report is what tells a "+
			"user why a sweep on their volume is still retaining more than K generations' worth",
			w.LegacyCandidates, mode)
	}
	t.Logf("mixed window: %d generations, %d attributed, %s", w.Generations, w.Attributed, w.ScanMode())

	// And the real generations still read: a mixed window is not an excuse
	// for the half of it that IS attributable to be short.
	for _, g := range gens[len(gens)-3:] {
		if err := mounts(t, inner, g); err != nil {
			t.Errorf("generation %d is inside the window and does not read after the sweep: %v",
				g.sb.Generation, err)
		}
	}
}

// A WINDOW ROOT NAMES ITS OWN BRANCH, ASKED OF THE ROOTS THEMSELVES.
//
// The tests above read consequences — does it still mount, is the object
// in the live set, how big is the set — and consequences are cushioned. A
// head names every pack its branch ever cut, the condemned ledgers speak
// for refs a successor stopped listing, and both make a window that picked
// the wrong document survivable for a while. Those cushions are why the
// original collision went unnoticed, not why it was safe.
//
// So this asks the root set the unambiguous question: after the fork,
// every document standing for a generation of THIS branch must be one this
// branch sealed. Below the fork they are the parent's and must not be — a
// branch does not seal its inherited history, and demanding otherwise is
// the strict rule that would lose it.
func TestAWindowRootNamesItsOwnBranch(t *testing.T) {
	ctx := context.Background()
	const shared = 2
	f := fork(t, shared, 3, "dev")
	o := Options{Inner: f.inner, Refs: f.rs, Now: f.clock.Add(aged)}

	win := newWindowCache()
	checked := 0
	for _, branch := range []string{"main", "dev"} {
		head, err := f.rs.Fetch(ctx, branch)
		if err != nil {
			t.Fatalf("fetch %s: %v", branch, err)
		}
		w, err := win.get(ctx, o, branch, head.Superblock, 2)
		if err != nil {
			t.Fatalf("window for %s: %v", branch, err)
		}
		for _, sb := range w.roots {
			// A root DESCRIBES ITS PARENT: the backup at generation G stands
			// for generation G-1, so the generation at stake is one below.
			if sb.Generation-1 <= shared {
				continue // inherited history; the parent branch sealed it
			}
			checked++
			if sb.Branch != branch {
				t.Errorf("branch %s's window stands generation %d up on a backup branch %q sealed; that "+
					"branch's own generation %d is then described by nothing in the root set",
					branch, sb.Generation-1, sb.Branch, sb.Generation-1)
			}
		}
	}
	// Three seals per branch after the fork, and the head is described by no
	// backup — there is no backup_6 — so the roots cover post-fork
	// generations 3 and 4 on each of the two chains.
	if want := 2 * 2; checked < want {
		t.Fatalf("only %d post-fork window roots were examined, want %d; this proves nothing about either "+
			"branch", checked, want)
	}
}
