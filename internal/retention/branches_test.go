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
// These tests are about what that costs and what now prevents it.

import (
	"context"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
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

// THE COST OF THE RULE IS UNCHANGED FOR THE VOLUME THAT HAS IT TODAY.
//
// Keeping every candidate means the scan cannot stop at "every generation
// has one" — but only where a generation number fails to identify a
// generation, which is to say on a volume with siblings. With one branch
// the number IS the identity, the first document found is the only one
// there can be, and the scan still stops. This pins that, because the
// alternative is a sweep that walks the whole pack space on every volume
// in the world: at target scale that is hundreds of thousands of trailer
// reads where a handful were needed.
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
