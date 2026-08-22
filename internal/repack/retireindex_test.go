package repack_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// Retiring an index whose packs are mostly gone.
//
// The planner has measured this for two releases and the executor ignored
// it: a segment written for packs a later repack condemned goes on being
// listed, fetched and windowed through forever, spending its bytes on
// entries that resolve to nothing. It is the narrowest of the three
// retirement rules and the only one that is pure fetch cost — an index is
// DERIVED, so a generation missing one still mounts and serves.
//
// Which is exactly why the rule has to be careful about the OTHER half.
// The entries a stale segment still answers for are the ones for its
// surviving packs, and dropping the object without re-emitting them would
// send every lookup of those identities down the trailer-walk fallback: a
// cleanup that makes cold reads slower. The design says "drops it and
// re-emits its live entries", and both halves are checked below.

// staleIndexVolume builds a volume whose oldest index segments name packs
// a repack is about to condemn: four files rewritten whole, four times, so
// each generation's packs die with the next generation.
func staleIndexVolume(t *testing.T, uuid string) (pelicanobj.Store, *testvol.Volume, *superblock.Superblock, map[string][]byte) {
	t.Helper()
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	want := map[string][]byte{}
	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		body := pseudorandom(2<<20, int64(700+i))
		v.WriteFile(rootIno, names[i], body)
		want[names[i]] = body
	}
	v.Publish(publishOpts)
	var head *superblock.Superblock
	for round := range 4 {
		for i := range files {
			body := pseudorandom(2<<20, int64(800+100*round+i))
			v.Write(v.Lookup(rootIno, names[i]), body)
			want[names[i]] = body
		}
		head = v.Publish(publishOpts).Superblock
	}
	if len(head.PackIndexes) == 0 {
		t.Fatal("the fixture lists no index segments; there is nothing to retire and the test would " +
			"prove nothing")
	}
	return inner, v, head, want
}

// indexCoverage is every (entry, pack) pair a set of segments answers for,
// restricted to packs in keep. It is what "the coverage did not shrink"
// means, stated as data rather than as a lookup that could be answered by
// a fallback the test cannot see.
func indexCoverage(t *testing.T, inner pelicanobj.Store, refs []superblock.IndexRef, keep map[string]bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, ref := range refs {
		ix, err := mpi.Fetch(context.Background(), inner, ref)
		if err != nil {
			t.Fatalf("fetch index %s: %v", ref.Name, err)
		}
		ix.Each(func(key []byte, packs []string) {
			for _, p := range packs {
				if keep == nil || keep[p] {
					out[fmt.Sprintf("%x@%s", key, p)] = true
				}
			}
		})
	}
	return out
}

// INVARIANT: a repack retires the index segments whose live-pack coverage
// has fallen below the threshold, re-emits everything they still answered
// for, and condemns them through the ledger rather than dropping them.
func TestARepackRetiresAStaleIndexAndKeepsItsLiveEntries(t *testing.T) {
	ctx := context.Background()
	inner, v, head, want := staleIndexVolume(t, "beefbeef-1111-2222-3333-444444444444")
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]superblock.IndexRef{}, head.PackIndexes...)

	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Plan.Refused() || res.Plan.Empty() {
		t.Fatalf("the fixture produced no work: %s", res.Plan.Refusal)
	}
	var proposed int
	for _, c := range res.Plan.Refs {
		if c.Kind == repack.RefIndex {
			proposed++
		}
	}
	if proposed == 0 {
		t.Fatalf("the plan proposed no index for retirement (%d ref candidates, %d packs condemned); "+
			"the fixture is not producing the case this test is about", len(res.Plan.Refs), len(res.Plan.Packs))
	}

	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	sb := f.Superblock
	listed := map[string]bool{}
	for _, ref := range sb.PackIndexes {
		listed[ref.Name] = true
	}
	condemned := map[string]bool{}
	for _, c := range sb.CondemnedIndexes {
		condemned[c.Name] = true
	}
	retired := 0
	for _, ref := range before {
		if listed[ref.Name] {
			continue
		}
		retired++
		if !condemned[ref.Name] {
			t.Errorf("index %s was dropped from the list and is not on the condemned-index ledger; it is "+
				"hash-named, so the sweep's mtime guard expired long ago and the ledger row is the only "+
				"thing keeping it while a retired generation still names it", ref.Name)
		}
	}
	if retired == 0 {
		t.Fatal("the plan proposed retiring an index and the published generation still lists all of them")
	}

	// The coverage that must survive: every entry the retired segments
	// answered for whose pack this generation still LISTS.
	live := map[string]bool{}
	for _, pe := range packsOf(t, inner, sb) {
		live[pe.Name] = true
	}
	var retiredRefs []superblock.IndexRef
	for _, ref := range before {
		if !listed[ref.Name] {
			retiredRefs = append(retiredRefs, ref)
		}
	}
	owed := indexCoverage(t, inner, retiredRefs, live)
	got := indexCoverage(t, inner, sb.PackIndexes, live)
	for pair := range owed {
		if !got[pair] {
			t.Fatalf("entry %s was answered by a segment this repack retired and is answered by nothing it "+
				"lists; retiring an index without re-emitting its live entries turns a cleanup into a "+
				"cold-read regression — every lookup of it now walks pack trailers", pair)
		}
	}
	if len(owed) == 0 {
		t.Fatal("fixture: the retired segments named no surviving pack, so the re-emit half of the rule " +
			"was never exercised")
	}
	t.Logf("retired %d of %d index segments, carrying %d entries for packs that survived",
		retired, len(before), len(owed))

	// And the volume still reads, which is the property none of the
	// bookkeeping above is worth anything without.
	readsBack(t, inner, sb, want, "after retiring an index")
}

// INVARIANT: a retired index is kept by the ledger for the grace window
// and collected after it — the same lifecycle a condemned pack has, since
// it is the same ledger discipline.
func TestASweepHonoursTheLedgerForARetiredIndex(t *testing.T) {
	ctx := context.Background()
	inner, v, head, _ := staleIndexVolume(t, "beefbeef-5555-6666-7777-888888888888")
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]superblock.IndexRef{}, head.PackIndexes...)
	now := time.Now().Add(aged)
	if _, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: now,
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, ref := range f.Superblock.PackIndexes {
		listed[ref.Name] = true
	}
	var retired string
	for _, ref := range before {
		if !listed[ref.Name] {
			retired = ref.Name
			break
		}
	}
	if retired == "" {
		t.Skip("no index was retired on this fixture; the ledger property has nothing to observe")
	}

	// RetainK 1 on both sweeps, which is what makes this a property about
	// the LEDGER: with the default window the last K generations are roots
	// too, and their backups name the retired index, so it would survive
	// whatever the ledger said and the assertion below would be vacuous.
	//
	// Inside the window: the ledger speaks for it even though no enumerable
	// superblock names it.
	if _, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Delete: true, Now: time.Now(), RetainK: 1,
	}); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if !objectAlive(t, inner, mpi.Dir+"/"+retired) {
		t.Fatal("a sweep inside the grace window deleted an index the ledger had just condemned; a reader " +
			"pinned to the pre-repack generation loses its index the moment the repack lands")
	}

	// Past it, with the ledger rows aged off, it is ordinary garbage.
	if _, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Delete: true, Now: time.Now().Add(2 * aged), RetainK: 1,
	}); err != nil {
		t.Fatalf("gc: %v", err)
	}
	if objectAlive(t, inner, mpi.Dir+"/"+retired) {
		t.Error("past the window the retired index is still here; retirement that never reclaims anything " +
			"is a list edit, not a cleanup")
	}
}

func objectAlive(t *testing.T, inner pelicanobj.Store, key string) bool {
	t.Helper()
	_, err := inner.StatKey(context.Background(), key)
	return err == nil
}
