package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The sleep scenario, end to end on a real session.
//
// THE QUESTION THESE TESTS ANSWER is the one an owner asked of the write
// lease: if a mount accidentally goes to sleep for a long time, will it
// realize it has lost the lock? The answer used to be "partly, and it would
// publish anyway". A renewal loop notices a takeover only while it is
// RUNNING and only while the usurper is still holding; a suspended process
// runs no loop; and nothing on the seal path consulted the result either way
// — Conflicted() had one consumer and it was a status field.
//
// The sleep is deterministic in all of this, and not a sleep. A lease whose
// TTL is one nanosecond is already past it by the time anything can ask, and
// the gate's arithmetic — the gap since the last landed renewal, against the
// TTL — is the same at 1ns as at two minutes. Nothing here waits on a timer,
// so nothing here can flake on a loaded machine (internal/lease paid for
// timing-driven tests once already: 7de6f69, df54b95).

// asleep gives the session a lease that is already past its TTL and that
// will never renew itself: the state a laptop that closed its lid comes back
// in. The renewal interval is an hour so no tick fires inside a test — the
// suspended process ran no ticks either, which is the whole difficulty.
func asleep(t *testing.T, g *genSession) *lease.Lease {
	t.Helper()
	return attachLease(t, g, time.Nanosecond)
}

func attachLease(t *testing.T, g *genSession, ttl time.Duration) *lease.Lease {
	t.Helper()
	ctx := context.Background()
	store, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: g.prefix, DirectRead: true})
	if err != nil {
		t.Fatal(err)
	}
	l, err := lease.Acquire(ctx, lease.Options{
		Store: store, Session: g.sessionID, Branch: g.branch,
		TTL: ttl, RenewInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("acquire lease: %v", err)
	}
	g.lease = l
	g.stats.Update(func(sum *stats.Summary) {
		sum.LeaseHeld = true
		sum.LeaseKey = l.Key()
	})
	t.Cleanup(func() { _ = l.Release(context.Background()) })
	return l
}

// otherWriter is a second client on the same branch: it takes the lease
// (which it is entitled to, the incumbent's having expired) and optionally
// publishes a generation over the head before letting go.
//
// Publishing is done by writing a signed successor to refs/<branch>
// directly, which is what any other writer's flip leaves behind and is
// exactly what the fence's head comparison reads. Driving a whole second
// mount to produce the same two hundred bytes would test the seal pipeline,
// not the fence.
func otherWriter(t *testing.T, g *genSession, session string, publishOver, release bool) {
	t.Helper()
	ctx := context.Background()
	store, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: g.prefix, DirectRead: true})
	if err != nil {
		t.Fatal(err)
	}
	l, err := lease.Acquire(ctx, lease.Options{
		Store: store, Session: session, Branch: g.branch,
		TTL: time.Hour, RenewInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("the second writer could not take an EXPIRED lease, so this test is not testing the "+
			"scenario it claims: %v", err)
	}
	if publishOver {
		key, err := loadOrCreateSigningKey(g.signingKeyFile(), g.sb)
		if err != nil {
			t.Fatal(err)
		}
		next := *g.sb
		next.Generation = g.sb.Generation + 1
		next.PrevHash = superblock.Hash(g.prevRaw)
		next.CreatedUnixNano = g.sb.CreatedUnixNano + 1
		if err := next.Sign(key); err != nil {
			t.Fatal(err)
		}
		raw, err := next.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(ctx, publish.RefPrefix+g.branch, strings.NewReader(string(raw))); err != nil {
			t.Fatal(err)
		}
	}
	if release {
		if err := l.Release(ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Cleanup(func() { _ = l.Release(context.Background()) })
}

// dirtyState is what a refused seal must leave behind: the work, all of it.
func dirtyState(t *testing.T, g *genSession) (nodes int, gen uint64) {
	t.Helper()
	st, err := g.ov.Stats()
	if err != nil {
		t.Fatalf("overlay stats: %v", err)
	}
	return st.DirtyNodes, g.sb.Generation
}

// TestSleepingMountRefusesToCheckpointOverAUsurper is the headline case, and
// the one a mutation must break.
//
// A writes, sleeps past its TTL, and while it is out B takes the branch. B
// has published NOTHING yet — which is what makes this the dangerous
// interleaving rather than a merely unlucky one: the branch head is still
// exactly what A's seal is anchored on, so the flip's compare-then-put is
// satisfied and A's checkpoint sails through it, publishing a generation
// under a lease it does not hold. B then publishes over A, or A over B, and
// one of the two generations is gone with its packs.
//
// MUTATION TEST, kept here because it is the only thing that shows this test
// has teeth: delete the `g.fenceSeal(ctx)` call at the top of sealLocked and
// this test does not fail with a different message — it fails by SILENT
// SUCCESS. The checkpoint returns "generation 1", the ref moves, and nothing
// anywhere reports that the branch had been taken. That is what the code did
// before the fence, and it is why "the ETag guard is the real protection"
// was not the whole answer: the ETag guard is a guard on the head, and the
// head had not moved yet.
func TestSleepingMountRefusesToCheckpointOverAUsurper(t *testing.T) {
	ctx := context.Background()
	g := newGenSession(t, true)
	asleep(t, g)
	writeFile(t, g.ov, "work.txt", "an hour of unsealed work")
	nodesBefore, genBefore := dirtyState(t, g)

	otherWriter(t, g, "sess-awake", false, false)

	_, err := g.checkpoint(ctx)
	if err == nil {
		t.Fatal("the checkpoint SUCCEEDED after another client took the branch.\n" +
			"this is the silent-clobber case: the head has not moved yet, so the flip's " +
			"compare-then-put is satisfied and the seal publishes under a lease this session " +
			"no longer holds. the fence in sealLocked is what refuses it.")
	}
	if !errors.Is(err, lease.ErrLost) {
		t.Fatalf("checkpoint refusal: err = %v, want lease.ErrLost", err)
	}
	// The message has to name what happened and where the work is, because
	// the only correct action is a remount and the user must know that
	// publishing nothing cost them nothing.
	for _, want := range []string{"sess-awake", g.overlayDir, "intact", "remount"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%v", want, err)
		}
	}
	// Overlay untouched, branch untouched.
	if nodes, gen := dirtyState(t, g); nodes != nodesBefore || gen != genBefore {
		t.Errorf("a refused checkpoint changed the session: dirty %d->%d, generation %d->%d",
			nodesBefore, nodes, genBefore, gen)
	}
	head, err := pelicanobj.ReadMutable(ctx, g.inner, publish.RefPrefix+g.branch)
	if err != nil {
		t.Fatal(err)
	}
	if string(head) != string(g.prevRaw) {
		t.Error("a refused checkpoint moved the branch head")
	}
}

// TestSleepingMountRefusesWhenAWriterCameAndWent is the come-and-gone hole:
// B takes the expired lease, seals, and RELEASES — and release DELETES the
// lease object, so the only trace of the episode is that A's lease is not
// there any more.
//
// renewOnce read that absence as "someone deleted our lease; reclaim it
// below" and did exactly that, silently. The refusal here comes from
// comparing the branch head against what this session's seal is anchored on,
// which is the only evidence that survives.
func TestSleepingMountRefusesWhenAWriterCameAndWent(t *testing.T) {
	ctx := context.Background()
	g := newGenSession(t, true)
	asleep(t, g)
	writeFile(t, g.ov, "work.txt", "an hour of unsealed work")
	nodesBefore, genBefore := dirtyState(t, g)

	otherWriter(t, g, "sess-came-and-went", true, true)

	_, err := g.checkpoint(ctx)
	if !errors.Is(err, lease.ErrLost) {
		t.Fatalf("checkpoint after a writer came and went: err = %v, want lease.ErrLost", err)
	}
	for _, want := range []string{"ADVANCED", "superseded", g.overlayDir, "remount"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q:\n%v", want, err)
		}
	}
	if nodes, gen := dirtyState(t, g); nodes != nodesBefore || gen != genBefore {
		t.Errorf("a refused checkpoint changed the session: dirty %d->%d, generation %d->%d",
			nodesBefore, nodes, genBefore, gen)
	}
	// Refused BEFORE the work, which is the difference between this and
	// being caught by the flip: no generation was built, so nothing was
	// packed and nothing was uploaded for the branch to refuse.
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	if sum.Seals != 0 || sum.SealedPacks != 0 {
		t.Errorf("the refused checkpoint still did publish work: %d seals, %d packs",
			sum.Seals, sum.SealedPacks)
	}
	if !g.lease.State().WasInterrupted {
		t.Error("the vanished lease left no latched trace for the stats file")
	}
}

// TestAdminDeletedLeaseIsReclaimedAndTheSealProceeds is the harmless half of
// the same absence, and the reason the resolution is a head comparison
// rather than "any deletion is fatal".
//
// An operator clearing what looks like a stale lease by hand is a normal
// thing to do, and it publishes nothing. The object is equally missing in
// both cases; the head is what distinguishes them, so a session in this
// state re-takes its lease, says so, and goes on to seal.
func TestAdminDeletedLeaseIsReclaimedAndTheSealProceeds(t *testing.T) {
	ctx := context.Background()
	g := newGenSession(t, true)
	l := asleep(t, g)
	writeFile(t, g.ov, "work.txt", "work that must still be publishable")

	store, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: g.prefix, DirectRead: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, l.Key()); err != nil {
		t.Fatal(err)
	}

	summary, err := g.checkpoint(ctx)
	if err != nil {
		t.Fatalf("a hand-deleted lease must not cost a session its seal: %v", err)
	}
	if !strings.Contains(summary, "generation 1") {
		t.Fatalf("checkpoint summary = %q, want generation 1", summary)
	}
	// Re-taken, and re-taken as OURS: the object is back with this session's
	// record on it, so the lease is genuinely held again.
	if _, err := store.StatKey(ctx, l.Key()); err != nil {
		t.Fatalf("the lease was not re-taken: %v", err)
	}
	st := l.State()
	if st.Interrupted || st.Conflicted {
		t.Errorf("state after a clean reclaim = %+v, want neither interrupted nor lost", st)
	}
	if !st.WasInterrupted || st.RevalidatedAt.IsZero() {
		t.Error("a reclaim that happened silently is the bug this replaced; it must leave a trace")
	}
	// And the trace reaches the statistics file, which is where a question
	// asked days later gets answered.
	g.refresh()
	var sum stats.Summary
	g.stats.Update(func(s *stats.Summary) { sum = *s })
	if !sum.LeaseInterrupted || sum.LeaseRevalidatedAt.IsZero() {
		t.Errorf("stats did not record the episode: interrupted=%v revalidated=%v",
			sum.LeaseInterrupted, sum.LeaseRevalidatedAt)
	}
}

// TestFreshLeaseSealsWithoutRevalidating: the gate must be invisible on the
// path every healthy session takes. A lease inside its TTL is answered from
// memory, so a checkpointing mount pays nothing for any of this.
func TestFreshLeaseSealsWithoutRevalidating(t *testing.T) {
	ctx := context.Background()
	g := newGenSession(t, true)
	l := attachLease(t, g, 2*time.Minute)
	writeFile(t, g.ov, "work.txt", "ordinary work")

	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("checkpoint under a fresh lease: %v", err)
	}
	if st := l.State(); st.Name() != "held" || !st.RevalidatedAt.IsZero() {
		t.Fatalf("a fresh lease was revalidated anyway: %+v", st)
	}
}

// TestNoLeaseSessionSealsExactlyAsBefore: --no-lease is unchanged, and the
// test says what "unchanged" means rather than only that it still works.
//
// Such a session has nothing to fence with, so it publishes on the strength
// of the flip's compare-then-put alone: it sails past a usurper that has not
// published (there is nothing for the compare to catch) and is stopped by
// one that has, at the end, after the whole publish has been paid for. Both
// halves are asserted, because the first is the capability the flag gives up
// and the flag's help now says so.
func TestNoLeaseSessionSealsExactlyAsBefore(t *testing.T) {
	ctx := context.Background()

	// No lease, another writer holding, nothing published: the seal goes
	// through, exactly as it always did.
	g := newGenSession(t, true)
	if g.lease != nil {
		t.Fatal("the harness took a lease")
	}
	writeFile(t, g.ov, "work.txt", "one")
	otherWriter(t, g, "sess-holder", false, false)
	if _, err := g.checkpoint(ctx); err != nil {
		t.Fatalf("--no-lease checkpoint was refused; this flag's behaviour is deliberately "+
			"unchanged: %v", err)
	}

	// No lease, and the head HAS moved: the flip's compare is the only
	// guard, and it still holds.
	h := newGenSession(t, true)
	writeFile(t, h.ov, "work.txt", "one")
	otherWriter(t, h, "sess-publisher", true, true)
	_, err := h.checkpoint(ctx)
	if err == nil {
		t.Fatal("--no-lease checkpoint published over a moved head")
	}
	if errors.Is(err, lease.ErrLost) {
		t.Fatalf("a --no-lease session was refused by the FENCE, which it has no lease for: %v", err)
	}
	if !strings.Contains(err.Error(), "changed since the previous generation was read") {
		t.Errorf("the refusal did not come from the flip's compare-and-swap: %v", err)
	}
}

// TestLostLeaseStopsTheCheckpointTicker: enforcement, not just reporting.
//
// Every seal from a lost lease is refused, so a periodic checkpointer that
// kept ticking would freeze the overlay, walk the dirty set and upload packs
// on its interval, forever, to be told each time what it was told the first
// time. That was the shape of the one broken-CAS report in this repo's
// history: the same warning every fifteen seconds, indefinitely.
func TestLostLeaseStopsTheCheckpointTicker(t *testing.T) {
	ctx := context.Background()
	g := newGenSession(t, true)
	asleep(t, g)
	writeFile(t, g.ov, "work.txt", "work")

	// A checkpointer with an interval long enough that it will never fire on
	// its own: what is under test is that the refusal STOPS it, not that a
	// tick happens to be missed.
	g.startCheckpointer(context.Background(), time.Hour)
	otherWriter(t, g, "sess-awake", false, false)
	if _, err := g.checkpoint(ctx); !errors.Is(err, lease.ErrLost) {
		t.Fatalf("checkpoint: err = %v, want lease.ErrLost", err)
	}

	done := make(chan struct{})
	go func() { g.checkpointWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the periodic checkpointer is still running after the lease was lost; every seal it " +
			"starts from here spends a freeze, a walk and an upload to be refused")
	}
}
