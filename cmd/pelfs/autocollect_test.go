package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/stats"
)

// Automatic COLLECTION, from the mount that hosts it.
//
// A repack condemns and never deletes; retention's sweep is what frees
// bytes, and until this existed the only thing that ran it was a person
// typing `pelfs gc --delete`. So a volume could repack itself faithfully
// forever and still grow forever.
//
// What these check is the pairing and the reporting, not the sweep: the
// sweep is retention.GC, tested in its own package, and the whole design
// of this feature is that there is no second deletion path here to test.

// INVARIANT: a background repack is followed by a sweep that actually
// reclaims what it condemned, once the windows have passed.
func TestAutoCollectReclaimsWhatTheRepackCondemned(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()

	// Content that mostly dies: four megabyte files, three of them
	// rewritten, so the first generation's packs are largely garbage.
	for i := range 4 {
		writeFile(t, g.ov, fmt.Sprintf("f%d.bin", i), string(incompressible(1<<20, int64(i))))
	}
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("first checkpoint: %v", err)
	}
	for i := 1; i < 4; i++ {
		n, err := g.ov.Lookup(ctx, overlay.RootInode, fmt.Sprintf("f%d.bin", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.ov.Write(ctx, n.Inode, 0, incompressible(1<<20, int64(100+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("second checkpoint: %v", err)
	}

	// The clock every step runs on. Past the grace window, which no real
	// deployment can arrange and every test must.
	future := time.Now().Add(400 * time.Hour)
	policy := repack.AutoPolicy{Packs: 1, Now: future}

	before := packNames(t, g)
	repacked, err := g.autoRepackOnce(ctx, policy)
	if err != nil {
		t.Fatalf("autoRepackOnce: %v", err)
	}
	if !repacked {
		t.Fatal("the fixture did not repack, so there is nothing condemned for a sweep to collect")
	}
	// What the repack condemned: present in the key space beforehand, named
	// by nothing the new head lists. Comparing raw pack COUNTS would prove
	// nothing here — the seals below add packs of their own — and these are
	// the objects the whole feature is about.
	named := map[string]bool{}
	for _, pe := range headPacks(t, g) {
		named[pe] = true
	}
	var condemned []string
	for _, name := range before {
		if !named[name] {
			condemned = append(condemned, name)
		}
	}
	if len(condemned) == 0 {
		t.Fatal("the repack published and condemned no pack; there is nothing for a sweep to collect")
	}

	// Retain-K holds the pre-repack generations in the root set, so a sweep
	// now must NOT free them — the windows are retention's and automating
	// the sweep does not get to shorten them.
	if err := g.autoCollectOnce(ctx, policy); err != nil {
		t.Fatalf("autoCollectOnce: %v", err)
	}
	for _, name := range condemned {
		if !hasPack(packNames(t, g), name) {
			t.Fatalf("%s was collected while the generation that names it is still inside the retain "+
				"window; a background sweep must honour every window the command does", name)
		}
	}

	// Then the branch is sealed forward, which is what a volume does on its
	// own, and swept again. This is the pairing the feature exists for: a
	// mount that repacks and then collects, with nobody typing anything.
	for i := range 8 {
		writeFile(t, g.ov, fmt.Sprintf("filler%d.txt", i), "seal the branch forward")
		if _, err := g.checkpoint(ctx); err != nil {
			t.Fatalf("checkpoint: %v", err)
		}
	}
	if err := g.autoCollectOnce(ctx, policy); err != nil {
		t.Fatalf("autoCollectOnce: %v", err)
	}
	after := packNames(t, g)

	// WHAT THIS TEST DOES NOT PROVE, said here rather than left to be
	// inferred from an assertion that is not present: that those particular
	// PACKS come back. Their ledger rows are stamped by the repack from the
	// wall clock and every generation in this fixture is created within the
	// same second, so the retain window's floor still covers them however
	// far forward the sweep's clock is moved — real separation is the one
	// thing a test cannot fake here. The end-to-end "condemned, then
	// collected" property is driven on an explicit clock in
	// internal/repack/lifecycle_test.go, whose auto-collect interleaving is
	// this path's op sequence.
	//
	// What IS proved here is the wiring: a real retention.GC ran with
	// Delete, it honoured the windows above, it deleted unreferenced
	// objects, and it reported what it freed.

	// And it is reported: an operator has to be able to see WHEN the volume
	// last collected without reading a log that has rotated away.
	var m *stats.MaintenanceStats
	g.stats.Update(func(sum *stats.Summary) { m = sum.Maintenance })
	if m == nil {
		t.Fatal("the statistics document says nothing about maintenance after a repack and two sweeps")
	}
	if m.Collections < 2 || m.LastCollectAt.IsZero() {
		t.Fatalf("collections=%d last_gc_at=%v", m.Collections, m.LastCollectAt)
	}
	if m.ReclaimedObjects == 0 || m.ReclaimedBytes == 0 {
		t.Fatalf("two background sweeps reclaimed %d objects / %d bytes; a sweep that never deletes "+
			"anything is the state this whole path was built to end",
			m.ReclaimedObjects, m.ReclaimedBytes)
	}
	if m.Repacks != 1 || m.LastRepackAt.IsZero() {
		t.Fatalf("repacks=%d last_repack_at=%v", m.Repacks, m.LastRepackAt)
	}
	if m.GraceSeconds == 0 {
		t.Error("the sweep did not record the grace window it applied; 'nothing was reclaimed' and " +
			"'nothing was old enough' are different answers")
	}
	t.Logf("%d packs condemned and still inside the window; key space %d -> %d, %d objects / %d bytes "+
		"reclaimed in %d sweeps", len(condemned), len(before), len(after), m.ReclaimedObjects,
		m.ReclaimedBytes, m.Collections)
}

// INVARIANT: the sweep FAILS CLOSED and says so. An unverifiable ref means
// the retained set is unknown, retention deletes nothing at all, and the
// mount records the failure — because a failing sweep is otherwise
// indistinguishable from a volume with nothing to collect.
func TestAutoCollectRecordsAFailedSweep(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "a.txt", "content")
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	before := packNames(t, g)

	// Corrupt the branch head: a ref that will not verify is exactly the
	// case the fail-closed rule exists for.
	if err := g.inner.Put(ctx, "refs/main", strings.NewReader("not a superblock")); err != nil {
		t.Fatal(err)
	}
	err := g.autoCollectOnce(ctx, repack.AutoPolicy{Now: time.Now().Add(400 * time.Hour)})
	if err == nil {
		t.Fatal("a sweep over an unverifiable branch head returned success; the retained set is unknown " +
			"there, and anything it deleted would be a guess")
	}
	if got := packNames(t, g); len(got) != len(before) {
		t.Fatalf("the failed sweep deleted %d packs; failing closed means deleting NOTHING",
			len(before)-len(got))
	}
	var m *stats.MaintenanceStats
	g.stats.Update(func(sum *stats.Summary) { m = sum.Maintenance })
	if m == nil || m.CollectionFailures != 1 || m.LastCollectionError == "" {
		t.Fatalf("a failed sweep was not recorded: %+v", m)
	}
	if m.Collections != 0 {
		t.Errorf("a failed sweep counted as a collection (%d)", m.Collections)
	}
}

// INVARIANT: the floor is honoured. A sweep lists the whole pack key space
// and every ref, so a mount that swept an hour ago must not sweep again
// just because it went idle again.
func TestAutoCollectRespectsItsFloor(t *testing.T) {
	g := newGenSession(t, true)
	now := time.Now()
	if !g.collectDue(repack.AutoPolicy{Now: now}) {
		t.Fatal("a session that has never collected is not due; a mount starting up is the best evidence " +
			"available that nobody has swept this volume lately")
	}
	g.mu.Lock()
	g.lastCollect = now
	g.mu.Unlock()
	if g.collectDue(repack.AutoPolicy{Now: now.Add(autoCollectInterval - time.Minute)}) {
		t.Fatal("a sweep a minute inside the floor was declared due")
	}
	if !g.collectDue(repack.AutoPolicy{Now: now.Add(autoCollectInterval + time.Minute)}) {
		t.Fatal("a sweep past the floor was not declared due")
	}
}

// INVARIANT: the loop's decision is the three things it should be — the
// operator's switch, a repack that has just made work, and the floor — and
// `--no-auto-gc` wins over all of it.
//
// Tested as a function rather than through the ticker for the obvious
// reason, and stated as a table because every row is a real deployment: a
// site that repacks but does not want background deletions, a volume that
// has just repacked and should not wait six hours to act on its own work,
// and an idle mount that must not re-sweep every time it goes quiet.
func TestTheCollectionDecision(t *testing.T) {
	g := newGenSession(t, true)
	now := time.Now()
	g.mu.Lock()
	g.lastCollect = now
	g.mu.Unlock()
	inside := repack.AutoPolicy{Now: now.Add(time.Minute)}
	past := repack.AutoPolicy{Now: now.Add(autoCollectInterval + time.Minute)}

	for _, tc := range []struct {
		name              string
		collect, repacked bool
		policy            repack.AutoPolicy
		want              bool
	}{
		{"--no-auto-gc beats a repack", false, true, past, false},
		{"--no-auto-gc beats the floor", false, false, past, false},
		{"a repack beats the floor", true, true, inside, true},
		{"inside the floor, no repack", true, false, inside, false},
		{"past the floor", true, false, past, true},
	} {
		if got := g.shouldCollect(tc.collect, tc.repacked, tc.policy); got != tc.want {
			t.Errorf("%s: shouldCollect(collect=%v, repacked=%v) = %v, want %v",
				tc.name, tc.collect, tc.repacked, got, tc.want)
		}
	}
}

// The mount's status has to answer "when did this volume last collect",
// because that is the question asked months later by someone who was not
// watching the logs.
func TestStatusReportsTheLastCollection(t *testing.T) {
	g := newGenSession(t, true)
	ctx := context.Background()
	writeFile(t, g.ov, "a.txt", "content")
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.autoCollectOnce(ctx, repack.AutoPolicy{Now: time.Now()}); err != nil {
		t.Fatalf("autoCollectOnce: %v", err)
	}
	c := serve(t, g)
	body, err := c.Do(ctx, "GET", "/v1/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if _, ok := st["last_gc_at"]; !ok {
		t.Fatalf("status says nothing about the last collection: %v", st)
	}
	if _, ok := st["reclaimed_bytes"]; !ok {
		t.Errorf("status reports no reclaimed_bytes: %v", st)
	}
}

// headPacks is the pack set the session's head names, resolved the way the
// sweep resolves it.
func headPacks(t *testing.T, g *genSession) []string {
	t.Helper()
	f, err := g.refs.Fetch(context.Background(), g.branch)
	if err != nil {
		t.Fatalf("fetch head: %v", err)
	}
	packs, err := manifest.Packs(context.Background(), g.inner, f.Superblock)
	if err != nil {
		t.Fatalf("resolve the head's pack set: %v", err)
	}
	out := make([]string, 0, len(packs))
	for _, pe := range packs {
		out = append(out, pe.Name)
	}
	return out
}

func hasPack(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// packNames is what the volume actually holds, read from the key space
// rather than from any superblock: the point of a sweep is the objects, and
// a list is exactly what it does not prove.
func packNames(t *testing.T, g *genSession) []string {
	t.Helper()
	entries, err := g.inner.ListDir(context.Background(), packstore.PackDirKey)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("list packs: %v", err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir {
			out = append(out, e.Name)
		}
	}
	return out
}
