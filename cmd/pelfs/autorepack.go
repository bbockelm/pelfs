package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/stats"
	"github.com/bbockelm/pelfs/internal/ui"
)

// Automatic repacking: `git gc --auto`, for a mount.
//
// The shape of the problem is git's. Deciding whether a repack is worth
// running TRUTHFULLY costs a reachability sweep — every catalog, every
// trailer — which is far too much to pay on a timer. So a cheap counter
// decides whether to pay for the real analysis (repack.Worthwhile, read
// from the head alone), and the real analysis decides what to do.
//
// Two things make a mount the right place to run it, rather than the cron
// job that would otherwise be the obvious answer:
//
//   - IT ALREADY HOLDS THE LEASE. A repack from a separate process has to
//     take it, and will lose to any live mount. Here there is nothing to
//     contend with.
//   - IT KNOWS WHEN THE VOLUME IS IDLE. A scheduler does not. Running
//     this while someone is extracting a kernel tree is exactly the sort
//     of background work that turns into a stall complaint.
//
// And one thing makes it SAFE, which is the property the whole design
// leans on: a repack does not change the namespace. Same root catalog,
// same catalog list, same inodes. So a mount that follows one has no
// tree to rebase, no inodes to invalidate, and nothing to tell the
// kernel — it only has to learn which generation it is now building on.
// The packs it was reading are still there for the grace window, so even
// its open reads are undisturbed.

// AND THE COLLECTION, which is the half that was missing.
//
// A repack CONDEMNS; it never deletes. Retention's sweep is what removes
// the objects, and until now the only thing that ran it was a person typing
// `pelfs gc --delete`. So the volume that repacked itself faithfully every
// six hours still grew forever, and "a volume nobody runs gc on grows
// without bound" stayed true for exactly the half that frees bytes.
//
// The sweep belongs in the same idle machinery for the same two reasons the
// repack does — the mount is holding the lease and knows when the volume is
// quiet — plus a third: a repack is precisely the event that CREATES work
// for a sweep, so the two want to run in that order, and only one of them
// knows when the other finished.
//
// What makes it safe to automate is that nothing about the sweep changes.
// It is retention.GC, the same call the command makes, with the same
// windows (grace, retain-K, the condemned ledgers) and the same fail-closed
// rule: a ref that will not verify aborts the whole run and deletes
// nothing. There is no second deletion path in this file to keep in
// agreement with the first.

const (
	// autoRepackCheck is how often the cheap gate is consulted. It reads
	// the head this session already holds, so the cost is a comparison.
	autoRepackCheck = 2 * time.Minute
	// autoRepackQuiet is how long the write path must have been idle
	// before a repack is allowed to start. A repack is minutes of reading
	// and uploading; starting one during a pause between two files would
	// be the background work users learn to disable.
	autoRepackQuiet = 5 * time.Minute
	// autoCollectInterval is the floor between sweeps that no repack asked
	// for.
	//
	// A sweep has no cheap gate the way a repack does (repack.Worthwhile
	// reads the head; "is there garbage" is a listing of the whole pack key
	// space plus every ref, every tag and the retain window's backups), so
	// the floor IS the policy. Six hours matches the repack floor, which is
	// the cadence the pair was reasoned about together: a volume that is
	// quiet enough to sweep is quiet enough to have been swept recently.
	autoCollectInterval = 6 * time.Hour
)

// maintainPeriodically repacks when the mount is quiet and the branch has
// drifted far enough to be worth sweeping, and collects what earlier
// repacks condemned.
//
// collect is `--no-auto-gc` inverted. It is separate from the repack half
// because the two have different failure modes — a repack that does not run
// costs storage, a sweep that runs wrongly costs data — and an operator who
// wants the second one off should not have to turn the first one off too.
//
// Failures are logged and dropped, exactly as a periodic checkpoint's are.
// Nothing here is load-bearing: maintenance that does not happen costs
// storage, and storage is what this is trying to save. Tearing down a mount
// over it would be a strictly worse trade.
func (g *genSession) maintainPeriodically(ctx context.Context, policy repack.AutoPolicy, collect bool) {
	if !g.rw {
		// Writable mounts only, and it is the lease that decides it rather
		// than tidiness: this deletes objects, and the session that holds
		// the branch's write lease is the one that knows no other writer is
		// mid-publish. A read-only mount is also, usually, one of MANY on a
		// volume — a sweep per reader would be the same work N times.
		return
	}
	t := time.NewTicker(autoRepackCheck)
	defer t.Stop()
	var lastWritten int64 = -1
	quietSince := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Quiescence, measured from the write path itself rather than
		// from a lock or a queue: bytes accepted since the last look. A
		// mount serving reads all day is quiet for this purpose, which is
		// right — reads are undisturbed by a repack.
		written := g.writtenBytes()
		if written != lastWritten {
			lastWritten, quietSince = written, time.Now()
			continue
		}
		if time.Since(quietSince) < autoRepackQuiet {
			continue
		}
		repacked, err := g.autoRepackOnce(ctx, policy)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			ui.Warn("automatic repack did not run ({error}); it will be tried again", "error", err)
		}
		// The sweep follows a repack that published — that repack is what
		// created the work — and otherwise runs on its own floor, because a
		// volume also accumulates garbage no repack was involved in: an
		// aborted publish's packs, a deleted tag's closure, the previous
		// repack's condemnations now past their window.
		if g.shouldCollect(collect, repacked, policy) {
			if err := g.autoCollectOnce(ctx, policy); err != nil {
				if ctx.Err() != nil {
					return
				}
				ui.Warn("automatic collection did not run ({error}); nothing was deleted, and it will be "+
					"tried again", "error", err)
			}
		}
		// Whether it ran, refused or failed, the volume has been looked
		// at: start the quiet window over so a failure cannot spin.
		quietSince = time.Now()
	}
}

// shouldCollect is the loop's decision, and it is a function rather than an
// expression inside the loop so that it can be checked without driving a
// ticker for six hours. The three inputs are the three reasons a sweep runs
// or does not: the operator's switch, a repack that has just created work,
// and the floor.
func (g *genSession) shouldCollect(collect, repacked bool, policy repack.AutoPolicy) bool {
	if !collect {
		// --no-auto-gc, and it wins over everything including a repack that
		// just condemned: an operator who turned the deletions off did not
		// ask for them back the moment maintenance found something.
		return false
	}
	// A repack that published overrides the floor. It is the event that
	// CREATED the collectable objects, and making the volume wait six hours
	// to act on its own work would be a floor protecting nothing — the
	// expensive part (the sweep behind the repack) has just been paid.
	return repacked || g.collectDue(policy)
}

// collectDue reports whether the sweep floor has passed. The first check of
// a session is due: a mount that has just started is the best evidence
// available that nobody has swept this volume lately, since the sweep is
// something only a mount does.
func (g *genSession) collectDue(policy repack.AutoPolicy) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastCollect.IsZero() {
		return true
	}
	return maintNow(policy).Sub(g.lastCollect) >= autoCollectInterval
}

// maintNow is the clock the maintenance paths run on. It is the repack
// policy's, so that a test driving one of these forward drives both and
// cannot end up with a repack in the future and a sweep in the present.
func maintNow(policy repack.AutoPolicy) time.Time {
	if policy.Now.IsZero() {
		return time.Now()
	}
	return policy.Now
}

// autoCollectOnce runs ONE sweep, with deletion, and says what it freed.
//
// It is deliberately a thin wrapper. Every window is retention's — the
// grace window the volume RECORDS, the retain-K generations reconstructed
// from superblock backups, the three condemned ledgers — and every guard is
// retention's too, including the one that matters most: a ref or tag that
// cannot be fetched and verified aborts the run and deletes NOTHING. This
// function adds no policy of its own, and that is the point. The most
// dangerous code in the repo should have exactly one implementation, and
// automating it must not become a second.
func (g *genSession) autoCollectOnce(ctx context.Context, policy repack.AutoPolicy) error {
	// One clock for the run: the sweep's windows and the timestamp this
	// records have to be the same instant, or a test that moves the clock
	// gets a sweep in the future recorded in the present.
	now := maintNow(policy)
	// The counted transport, so what a background sweep deletes appears in
	// the session's object-store statistics like everything else.
	rep, err := retention.GC(ctx, retention.Options{
		Inner:  g.inner,
		Refs:   g.refs,
		Delete: true,
		Now:    now,
	})
	if err != nil {
		g.recordCollect(now, nil, err)
		return err
	}
	freedObjects := int64(rep.Deleted + rep.Indexes.Deleted + rep.Manifests.Deleted)
	g.recordCollect(now, rep, nil)
	if freedObjects == 0 {
		// Said at debug rather than info: on a healthy volume this is the
		// answer most of the time, and a line every six hours saying
		// nothing happened is a line people filter out.
		ui.Debug("automatic collection found nothing to reclaim ({packs} packs scanned, grace window {grace})",
			"packs", rep.ScannedPacks, "grace", rep.Grace)
		return nil
	}
	ui.Info("collected {objects} unreferenced object(s), reclaiming {bytes} ({packs} packs, {indexes} "+
		"indexes, {manifests} manifests; grace window {grace})",
		"objects", freedObjects, "bytes", ui.ByteCount(reclaimedBytes(rep)),
		"packs", rep.Deleted, "indexes", rep.Indexes.Deleted, "manifests", rep.Manifests.Deleted,
		"grace", rep.Grace)
	return nil
}

// reclaimedBytes is what a completed sweep freed. The candidate bytes ARE
// the deleted bytes on a run that finished: finish() counts a candidate and
// then deletes it, and a failure returns the error this only reads past.
func reclaimedBytes(rep *retention.Report) int64 {
	return rep.CandidateBytes + rep.Indexes.CandidateBytes + rep.Manifests.CandidateBytes
}

// recordCollect publishes the outcome where an operator can see it: when
// the volume last collected, and what it got back.
//
// This is the F5/F6 shape — a timestamp and a counter rather than a log
// line — because the question it answers is asked LONG after the event ("is
// this volume being maintained at all?"), and a log line that has rotated
// away cannot answer it. A failure is recorded too, with its message: a
// sweep that fails closed every time is a volume quietly growing, and it
// would otherwise look identical to a volume with nothing to collect.
func (g *genSession) recordCollect(at time.Time, rep *retention.Report, err error) {
	g.mu.Lock()
	g.lastCollect = at
	g.mu.Unlock()
	g.stats.Update(func(sum *stats.Summary) {
		if sum.Maintenance == nil {
			sum.Maintenance = &stats.MaintenanceStats{}
		}
		m := sum.Maintenance
		if err != nil {
			m.CollectionFailures++
			m.LastCollectionError = err.Error()
			return
		}
		m.Collections++
		m.LastCollectAt = at
		m.ReclaimedObjects += int64(rep.Deleted + rep.Indexes.Deleted + rep.Manifests.Deleted)
		m.ReclaimedBytes += reclaimedBytes(rep)
		m.GraceSeconds = int64(rep.Grace / time.Second)
	})
}

// autoRepackOnce consults the cheap gate and, if it passes, runs one
// repack. It reports whether a repack actually PUBLISHED, which is what
// tells the caller a sweep now has something to collect: a run that was
// gated out, refused, or found nothing has created no work.
func (g *genSession) autoRepackOnce(ctx context.Context, policy repack.AutoPolicy) (bool, error) {
	g.mu.Lock()
	head := g.sb
	anchor := g.prevRaw
	busy := g.spent || g.ov == nil
	g.mu.Unlock()
	if busy {
		return false, nil
	}
	if worth, _ := repack.Worthwhile(head, policy); !worth {
		return false, nil
	}
	// A repack ends in a flip, so it is fenced like any other publish — and
	// it has the most to lose by not being: it sweeps the volume and rewrites
	// gigabytes BEFORE it flips, so a session that has already lost the
	// branch spends all of that to be refused, and leaves orphan packs for
	// the sweep to find.
	//
	// Fenced here, before the work, rather than next to the flip: minutes
	// pass between the two, and the flip's own compare-and-swap is what
	// covers that interval. This covers the decision to start.
	if err := g.lease.Fence(ctx, func(ctx context.Context) (bool, error) {
		return g.headIs(ctx, anchor)
	}); err != nil {
		return false, err
	}
	// Claimed for the length of the operation so the periodic checkpoint
	// stands aside (checkpointPeriodically). Deliberately a FLAG and not a
	// held lock: a repack runs for minutes, and holding mu across it would
	// block reads, writes and the seal at unmount — the things this is
	// supposed to be invisible to.
	g.mu.Lock()
	if g.repacking {
		g.mu.Unlock()
		return false, nil
	}
	g.repacking = true
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.repacking = false
		g.mu.Unlock()
	}()

	// The live set has to be every branch head and every tag, not just
	// this session's branch: a pack only a tag references is live, and a
	// repack that swept on this branch alone would condemn it.
	live, _, err := liveGenerations(ctx, g.inner, g.refs, g.branch)
	if err != nil {
		return false, err
	}
	key, err := loadOrCreateSigningKey(g.signingKeyFile(), head)
	if err != nil {
		return false, err
	}
	ui.Info("repacking in the background: the mount has been idle and the branch has drifted since the last one")
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner:    g.inner,
			Live:     live,
			Head:     head,
			DEK:      g.dek,
			CacheDir: filepath.Join(g.stateDir, "gencache"),
			Now:      policy.Now,
		},
		Refs:       g.refs,
		Branch:     g.branch,
		SigningKey: key,
		// The state directory itself: Execute makes its own per-run
		// subdirectory under it and removes it on the way out, and the
		// mount's scratch sweep collects one a crash strands. This is the
		// path that made a leak automatic — an idle mount repacks itself.
		SpoolDir: g.stateDir,
		// The same sidecar the seal path writes, so that the seal after
		// this repack still deduplicates against it.
		DedupIndexPath: filepath.Join(g.stateDir, dedupIndexName),
	})
	if err != nil {
		return false, err
	}
	if res.Plan.Refused() {
		ui.Warn("automatic repack could not measure the volume: {reason}", "reason", res.Plan.Refusal)
		return false, nil
	}
	if res.Plan.Empty() {
		ui.Info("automatic repack found nothing worth rewriting; {packs} packs, {live} live",
			"packs", res.Plan.ScannedPacks, "live", ui.Percent(liveFraction(res.Plan.LiveBytes, res.Plan.Bytes)))
		return false, nil
	}
	ui.Info("repacked {condemned} packs into {written}, reclaiming {bytes} at generation {generation}",
		"condemned", len(res.CondemnedPacks), "written", len(res.NewPacks),
		"bytes", ui.ByteCount(res.ReclaimedBytes), "generation", res.Generation)
	g.recordRepack(maintNow(policy), res.ReclaimedBytes)
	return true, g.followRepack(ctx)
}

// recordRepack is recordCollect for the other half: when this volume last
// repacked, and what that repack condemned. The two together are what an
// operator reads to answer "is this volume maintaining itself" without
// having to already know which of the two steps stopped.
//
// Reclaimed bytes here are what the repack CONDEMNED less what it wrote —
// bytes that become free once the sweep collects them, not bytes that are
// free now. The statistics document names the two fields differently for
// that reason.
func (g *genSession) recordRepack(at time.Time, condemnedBytes int64) {
	g.stats.Update(func(sum *stats.Summary) {
		if sum.Maintenance == nil {
			sum.Maintenance = &stats.MaintenanceStats{}
		}
		sum.Maintenance.Repacks++
		sum.Maintenance.LastRepackAt = at
		sum.Maintenance.CondemnedBytes += condemnedBytes
	})
}

// followRepack moves this session onto the generation the repack
// published.
//
// It is a head swap and nothing else, which is the whole reason this can
// run under a live mount. A repack preserves the root catalog and the
// catalog list byte for byte, so the tree the kernel is looking at is
// still exactly right; what changed is which packs hold the bytes, and
// the old ones survive the grace window. What MUST be updated is the
// generation the next seal builds on — otherwise its flip is compared
// against a head that moved, and the session's work is refused at
// unmount, which is the one outcome worth avoiding.
func (g *genSession) followRepack(ctx context.Context) error {
	f, err := g.refs.Fetch(ctx, g.branch)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sb != nil && f.Superblock.RootCatalog != g.sb.RootCatalog {
		// A repack does not touch the namespace, so a changed root means
		// something else published. Leaving the session where it is makes
		// its seal fail loudly at unmount rather than build on a tree it
		// never saw.
		ui.Warn("the branch moved to a different tree during the repack; this session keeps its own base")
		return nil
	}
	g.sb, g.prevRaw = f.Superblock, f.Raw
	return nil
}

// writtenBytes is how much the write path has accepted this session, or
// -1 when there is no content store to ask.
func (g *genSession) writtenBytes() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.content == nil {
		return -1
	}
	return g.content.Stats().WrittenBytes
}

// repackInFlight reports whether a background repack is between its sweep
// and its flip.
func (g *genSession) repackInFlight() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.repacking
}
