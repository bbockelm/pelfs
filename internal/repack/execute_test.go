package repack_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// rewrittenVolume builds the fixture the whole feature exists for: four
// files published, three of them rewritten with fresh incompressible
// content, so the first generation's chunks become dead entries inside
// immutable packs that nothing reclaims today.
//
// It returns the store, the volume, the head, and the file contents as
// they must read back afterwards.
func rewrittenVolume(t *testing.T, uuid string) (pelicanobj.Store, *testvol.Volume, *superblock.Superblock, map[string][]byte) {
	t.Helper()
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})

	want := map[string][]byte{}
	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		body := pseudorandom(2<<20, int64(100+i))
		v.WriteFile(rootIno, names[i], body)
		want[names[i]] = body
	}
	v.Publish(publishOpts)
	for i := 1; i < files; i++ {
		body := pseudorandom(2<<20, int64(200+i))
		v.Write(v.Lookup(rootIno, names[i]), body)
		want[names[i]] = body
	}
	res := v.Publish(publishOpts)
	return inner, v, res.Superblock, want
}

// readsBack asserts every file in want reads byte-exact through a
// generation.
func readsBack(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, want map[string][]byte, label string) {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: inner, SB: sb, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("%s: open generation %d: %v", label, sb.Generation, err)
	}
	defer fs.Close() //nolint:errcheck
	for name, body := range want {
		n, err := fs.Lookup(ctx, rootIno, name)
		if err != nil {
			t.Fatalf("%s: %s is gone: %v", label, name, err)
		}
		got := make([]byte, len(body))
		read, err := fs.Read(ctx, n.Inode, 0, got)
		if err != nil {
			t.Fatalf("%s: read %s: %v", label, name, err)
		}
		if read != len(body) {
			t.Fatalf("%s: %s read %d bytes, want %d", label, name, read, len(body))
		}
		for i := range body {
			if got[i] != body[i] {
				t.Fatalf("%s: %s differs at byte %d after the repack", label, name, i)
			}
		}
	}
}

// The whole point, end to end: a repack rewrites the packs that are
// mostly garbage, and EVERY FILE STILL READS BYTE-EXACT through the
// generation it publishes.
//
// That works because chunkrefs name identities rather than places. The
// catalogs are not rewritten, not even touched — so this test is also the
// assertion that they did not need to be.
func TestRepackRewritesPacksAndEveryFileStillReads(t *testing.T) {
	inner, v, head, want := rewrittenVolume(t, "aaaa1111-2222-3333-4444-555555555555")
	ctx := context.Background()
	readsBack(t, inner, head, want, "before")

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(),
		SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Plan.Refused() {
		t.Fatalf("a clean sweep produced a refusal: %s", res.Plan.Refusal)
	}
	if len(res.CondemnedPacks) == 0 {
		t.Fatal("three of four files were rewritten and nothing was condemned")
	}
	if res.Generation != head.Generation+1 {
		t.Fatalf("published generation %d, want %d", res.Generation, head.Generation+1)
	}
	t.Logf("condemned %d packs, wrote %d, moved %d entries / %d bytes, reclaimed %d",
		len(res.CondemnedPacks), len(res.NewPacks), res.MovedEntries, res.MovedBytes, res.ReclaimedBytes)

	// The published generation, fetched the way a mount would.
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatalf("fetch the repacked head: %v", err)
	}
	if f.Superblock.Generation != res.Generation {
		t.Fatalf("the branch is at generation %d, the repack published %d",
			f.Superblock.Generation, res.Generation)
	}
	readsBack(t, inner, f.Superblock, want, "after")

	// Stronger than reading the files: fsck walks the whole generation and
	// checks every chunkref resolves in a listed pack at the recorded
	// stored length. A repack that moved bytes and mis-recorded where they
	// went passes a read of the files it happened to relocate correctly
	// and fails here.
	rep, err := fsck.Check(ctx, fsck.Options{
		Inner: inner, SB: f.Superblock, CacheDir: t.TempDir(), Deep: true, Workers: 4,
	})
	if err != nil {
		t.Fatalf("fsck the repacked generation: %v", err)
	}
	if !rep.Clean() {
		for _, pr := range rep.Problems {
			t.Errorf("fsck: %s %s: %s", pr.Kind, pr.Path, pr.Detail)
		}
		t.Fatalf("the repacked generation does not verify (%d problems)", len(rep.Problems))
	}
	t.Logf("fsck deep: %d chunks verified across %d packs", rep.ChunksVerified, rep.Packs)

	// The namespace is IDENTICAL — a repack moves bytes and must not
	// republish the tree. Same root, same catalogs, same shards.
	if f.Superblock.RootCatalog != head.RootCatalog {
		t.Error("the repack changed the root catalog; it must not touch the namespace")
	}
	if len(f.Superblock.Catalogs) != len(head.Catalogs) {
		t.Errorf("the repack changed the catalog list: %d entries, was %d",
			len(f.Superblock.Catalogs), len(head.Catalogs))
	}

	// Every condemned pack is in the ledger, which is what keeps a reader
	// pinned to the parent generation alive through the grace window.
	ledger := map[string]bool{}
	for _, c := range f.Superblock.Condemned {
		ledger[c.Name] = true
		if c.CondemnedAtUnix == 0 {
			t.Errorf("condemned pack %s carries no timestamp; the grace window cannot be applied", c.Name)
		}
	}
	for _, name := range res.CondemnedPacks {
		if !ledger[name] {
			t.Errorf("pack %s was dropped but not condemned; GC would delete it out from under a live reader", name)
		}
	}

	// And the manifest no longer names them, which is what lets GC take
	// them once the window passes.
	for _, pe := range packsOf(t, inner, f.Superblock) {
		for _, name := range res.CondemnedPacks {
			if pe.Name == name {
				t.Errorf("condemned pack %s is still in the repacked generation's pack set", name)
			}
		}
	}
}

// A dry run must decide everything and change nothing.
func TestADryRunWritesNothing(t *testing.T) {
	inner, _, head, want := rewrittenVolume(t, "bbbb1111-2222-3333-4444-555555555555")
	ctx := context.Background()

	before := packsOf(t, inner, head)
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.DryRun {
		t.Error("a dry run's result does not say so; a caller could report a rehearsal as a change")
	}
	if res.Generation != 0 || len(res.NewPacks) != 0 || len(res.CondemnedPacks) != 0 {
		t.Fatalf("a dry run wrote something: generation %d, %d new packs, %d condemned",
			res.Generation, len(res.NewPacks), len(res.CondemnedPacks))
	}
	if res.Plan.Empty() {
		t.Fatal("the dry run planned nothing on a volume that was mostly rewritten")
	}
	if got := packsOf(t, inner, head); len(got) != len(before) {
		t.Fatalf("the pack set changed under a dry run: %d packs, was %d", len(got), len(before))
	}
	readsBack(t, inner, head, want, "after a dry run")

	// A dry run needs no key and no ref store, which is what makes it
	// runnable by someone who only has read access.
	t.Logf("dry run: %d packs proposed, %d bytes reclaimable", len(res.Plan.Packs), res.Plan.Reclaim())
}

// Superblock backups are live for as long as their generation is, and
// nothing references them BY IDENTITY — so the reachable set cannot speak
// for them and a repack that trusted it alone would silently drop the
// disaster-recovery copy.
func TestSuperblockBackupsSurviveARepack(t *testing.T) {
	inner, v, head, _ := rewrittenVolume(t, "cccc1111-2222-3333-4444-555555555555")
	ctx := context.Background()

	backupsIn := func(sb *superblock.Superblock) int {
		n := 0
		for _, pe := range packsOf(t, inner, sb) {
			entries, err := packstore.FetchTrailerVerified(ctx, inner, pe.Name, pe.Size, pe.TrailerHash)
			if err != nil {
				t.Fatalf("read trailer of %s: %v", pe.Name, err)
			}
			for _, e := range entries {
				if e.Type == packstore.EntrySuperblock {
					n++
				}
			}
		}
		return n
	}
	was := backupsIn(head)
	if was == 0 {
		// Not a skip. The whole test is "a repack must not drop the
		// disaster-recovery copy", and with no backup in the fixture there
		// is nothing to drop — so the skip made the test vacate ITSELF the
		// moment the fixture stopped publishing backups, which is exactly
		// when this coverage would be needed and exactly when nobody would
		// notice it was gone. If the fixture legitimately changes, this
		// test needs a new one, and the failure is how that gets decided.
		t.Fatalf("the fixture published no superblock backups, so this test would "+
			"verify nothing: rewrittenVolume must produce at least one %v entry",
			packstore.EntrySuperblock)
	}

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
			CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
		},
		Refs: rstore, Branch: "main", SigningKey: v.SigningKey(), SpoolDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	if now := backupsIn(f.Superblock); now < was {
		t.Fatalf("%d superblock backups before the repack, %d after; rescue lost a copy", was, now)
	}
}

// The point of the whole feature, stated as a measurement: after a
// repack, GC can finally take the bytes back.
//
// Before this existed, a pack whose contents were ENTIRELY dead stayed
// named by every later generation — publish carries pack lists forward
// and consolidation is a union — so gc --delete would never touch it and
// a volume grew monotonically with rewrites. This asserts the loop is
// closed: repack condemns, the grace window passes, GC deletes, and the
// files still read.
func TestGCReclaimsWhatARepackCondemned(t *testing.T) {
	inner, v, head, want := rewrittenVolume(t, "dddd1111-2222-3333-4444-555555555555")
	ctx := context.Background()
	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// GC before the repack: the dead packs are still named, so nothing
	// goes. This is the "before" half of the claim.
	pre, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Now: time.Now().Add(aged),
	})
	if err != nil {
		t.Fatalf("GC before the repack: %v", err)
	}
	if pre.Candidates != 0 {
		t.Fatalf("GC found %d deletable packs before any repack; the fixture is not the case this feature is for", pre.Candidates)
	}

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

	// Immediately after: the condemned ledger holds them, so GC must NOT
	// take them yet. A reader still pinned to the parent generation is
	// reading those packs right now.
	held, err := retention.GC(ctx, retention.Options{Inner: inner, Refs: rstore, Now: time.Now()})
	if err != nil {
		t.Fatalf("GC inside the grace window: %v", err)
	}
	for _, name := range held.CandidateNames {
		for _, c := range res.CondemnedPacks {
			if name == c {
				t.Errorf("GC proposed condemned pack %s while it is still inside the grace window", name)
			}
		}
	}

	// Past the grace window they STILL do not go, and that is the retain
	// window rather than a bug: this volume is four generations old, so
	// every generation the repack retired is inside Params.RetainK and each
	// of them names the condemned packs. Reclamation waits for the window
	// to move past the repack, which is exactly what the sweep promises
	// when it says it keeps the last K generations
	// (internal/retention/lastk.go).
	windowed, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Delete: true, Now: time.Now().Add(aged),
	})
	if err != nil {
		t.Fatalf("GC past the grace window: %v", err)
	}
	if windowed.Deleted != 0 {
		t.Errorf("GC deleted %d objects while every generation the repack retired is still inside the "+
			"retain-%d window; those generations name the condemned packs and must keep them",
			windowed.Deleted, windowed.Windows[0].K)
	}

	// With the window narrowed to the head alone — the sweep's behaviour
	// before RetainK was enforced, and what an operator states when no
	// reader is pinned to a retired generation — the loop closes.
	after, err := retention.GC(ctx, retention.Options{
		Inner: inner, Refs: rstore, Delete: true, RetainK: 1, Now: time.Now().Add(aged),
	})
	if err != nil {
		t.Fatalf("GC past the grace window: %v", err)
	}
	if after.Deleted == 0 {
		t.Fatal("GC deleted nothing after a repack condemned packs; the reclamation loop is still open")
	}
	t.Logf("repack condemned %d packs (%d bytes reclaimable); GC then deleted %d objects, %d bytes",
		len(res.CondemnedPacks), res.ReclaimedBytes, after.Deleted, after.CandidateBytes)

	// And the tree still reads, from the head GC just swept around.
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	readsBack(t, inner, f.Superblock, want, "after gc")
}

// A pack that is PARTLY live is the case that exercises the copy: its
// surviving entries have to be read out, written into a new pack, and
// found again afterwards. A fixture of whole-pack-sized files never
// reaches that path — every candidate is 0% live and the rewrite moves
// nothing — so this one packs many small files together and rewrites most
// of them.
func TestPartlyLivePacksHaveTheirSurvivorsCarried(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "eeee1111-2222-3333-4444-555555555555")})
	ctx := context.Background()

	// Sixteen files of 256 KiB share a handful of 2 MiB packs.
	const files = 16
	want := map[string][]byte{}
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("s%02d.bin", i)
		body := pseudorandom(256<<10, int64(400+i))
		v.WriteFile(rootIno, names[i], body)
		want[names[i]] = body
	}
	v.Publish(publishOpts)
	// Rewrite twelve of the sixteen: every pack keeps a survivor or two
	// and loses the rest.
	for i := range files {
		if i%4 == 0 {
			continue
		}
		body := pseudorandom(256<<10, int64(500+i))
		v.Write(v.Lookup(rootIno, names[i]), body)
		want[names[i]] = body
	}
	head := v.Publish(publishOpts).Superblock
	readsBack(t, inner, head, want, "before")

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
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
	if len(res.CondemnedPacks) == 0 {
		t.Fatal("nothing was condemned on a volume where three quarters of the content was rewritten")
	}
	// The point of this fixture: entries actually moved.
	if res.MovedEntries == 0 {
		t.Fatalf("condemned %d packs and moved nothing; this fixture is meant to have survivors to carry",
			len(res.CondemnedPacks))
	}
	if len(res.NewPacks) == 0 {
		t.Fatal("entries moved but no pack was written to hold them")
	}
	t.Logf("condemned %d packs, wrote %d, carried %d entries (%d bytes), reclaimed %d",
		len(res.CondemnedPacks), len(res.NewPacks), res.MovedEntries, res.MovedBytes, res.ReclaimedBytes)

	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	// Every file, including the survivors whose bytes physically moved.
	readsBack(t, inner, f.Superblock, want, "after")

	rep, err := fsck.Check(ctx, fsck.Options{
		Inner: inner, SB: f.Superblock, CacheDir: t.TempDir(), Deep: true, Workers: 4,
	})
	if err != nil {
		t.Fatalf("fsck: %v", err)
	}
	if !rep.Clean() {
		for _, pr := range rep.Problems {
			t.Errorf("fsck: %s %s: %s", pr.Kind, pr.Path, pr.Detail)
		}
		t.Fatal("the repacked generation does not verify")
	}

	// The moved entries must resolve through the INDEX, not by falling
	// back to trailers: the new segment is listed last so it wins over the
	// stale entries the older segments still carry for the deleted packs.
	if len(f.Superblock.PackIndexes) <= len(head.PackIndexes) {
		t.Errorf("the repack published no index segment for what it moved: %d refs, was %d",
			len(f.Superblock.PackIndexes), len(head.PackIndexes))
	}
	t.Logf("fsck deep: %d chunks verified; %d index refs (was %d)",
		rep.ChunksVerified, len(f.Superblock.PackIndexes), len(head.PackIndexes))
}

// The cheap gate is only cheap because the state it reads is maintained.
// A repack must stamp it, and every ordinary publish afterwards must
// carry it forward — a seal that dropped it would make the volume look
// like one that had never been repacked, and it would sweep again on the
// next tick.
func TestARepackStampsMaintenanceStateAndSealsCarryIt(t *testing.T) {
	inner, v, head, _ := rewrittenVolume(t, "ffff1111-2222-3333-4444-555555555555")
	ctx := context.Background()
	if head.Maint != nil {
		t.Fatal("an ordinary seal invented maintenance state")
	}

	rstore, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
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
	f, err := rstore.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	m := f.Superblock.Maint
	if m == nil {
		t.Fatal("the repack published no maintenance state; the auto gate would sweep again immediately")
	}
	if m.RepackGeneration != res.Generation {
		t.Errorf("maintenance state names generation %d, the repack published %d", m.RepackGeneration, res.Generation)
	}
	if m.RepackUnixNano == 0 {
		t.Error("maintenance state carries no timestamp; the interval floor cannot be applied")
	}
	if int(m.RepackPacks) != len(packsOf(t, inner, f.Superblock)) {
		t.Errorf("maintenance state records %d packs, the generation holds %d",
			m.RepackPacks, len(packsOf(t, inner, f.Superblock)))
	}
	// And the gate now says so, from the head alone.
	if worth, why := repack.Worthwhile(f.Superblock, repack.AutoPolicy{}); worth {
		t.Errorf("a volume repacked a moment ago is still worth sweeping: %s", why)
	}

	// That an ordinary seal carries this forward is asserted in
	// internal/publish, where a two-generation fixture already exists:
	// this volume handle is pinned to the generation the repack
	// superseded, so it cannot publish on top of it.
}
