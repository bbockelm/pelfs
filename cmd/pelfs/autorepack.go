package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/bbockelm/pelfs/internal/repack"
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

const (
	// autoRepackCheck is how often the cheap gate is consulted. It reads
	// the head this session already holds, so the cost is a comparison.
	autoRepackCheck = 2 * time.Minute
	// autoRepackQuiet is how long the write path must have been idle
	// before a repack is allowed to start. A repack is minutes of reading
	// and uploading; starting one during a pause between two files would
	// be the background work users learn to disable.
	autoRepackQuiet = 5 * time.Minute
)

// autoRepackPeriodically repacks when the mount is quiet and the branch
// has drifted far enough to be worth sweeping.
//
// Failures are logged and dropped, exactly as a periodic checkpoint's
// are. Nothing here is load-bearing: a repack that does not happen costs
// storage, and storage is the thing this is trying to save. Tearing down
// a mount over it would be a strictly worse trade.
func (g *genSession) autoRepackPeriodically(ctx context.Context, policy repack.AutoPolicy) {
	if !g.rw {
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
		if err := g.autoRepackOnce(ctx, policy); err != nil {
			if ctx.Err() != nil {
				return
			}
			ui.Warn("automatic repack did not run ({error}); it will be tried again", "error", err)
		}
		// Whether it ran, refused or failed, the volume has been looked
		// at: start the quiet window over so a failure cannot spin.
		quietSince = time.Now()
	}
}

// autoRepackOnce consults the cheap gate and, if it passes, runs one
// repack.
func (g *genSession) autoRepackOnce(ctx context.Context, policy repack.AutoPolicy) error {
	g.mu.Lock()
	head := g.sb
	busy := g.spent || g.ov == nil
	g.mu.Unlock()
	if busy {
		return nil
	}
	if worth, _ := repack.Worthwhile(head, policy); !worth {
		return nil
	}
	// Claimed for the length of the operation so the periodic checkpoint
	// stands aside (checkpointPeriodically). Deliberately a FLAG and not a
	// held lock: a repack runs for minutes, and holding mu across it would
	// block reads, writes and the seal at unmount — the things this is
	// supposed to be invisible to.
	g.mu.Lock()
	if g.repacking {
		g.mu.Unlock()
		return nil
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
		return err
	}
	key, err := loadOrCreateSigningKey(g.signingKeyFile(), head)
	if err != nil {
		return err
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
		SpoolDir:   filepath.Join(g.stateDir, "repack"),
	})
	if err != nil {
		return err
	}
	if res.Plan.Refused() {
		ui.Warn("automatic repack could not measure the volume: {reason}", "reason", res.Plan.Refusal)
		return nil
	}
	if res.Plan.Empty() {
		ui.Info("automatic repack found nothing worth rewriting; {packs} packs, {live} live",
			"packs", res.Plan.ScannedPacks, "live", ui.Percent(liveFraction(res.Plan.LiveBytes, res.Plan.Bytes)))
		return nil
	}
	ui.Info("repacked {condemned} packs into {written}, reclaiming {bytes} at generation {generation}",
		"condemned", len(res.CondemnedPacks), "written", len(res.NewPacks),
		"bytes", ui.ByteCount(res.ReclaimedBytes), "generation", res.Generation)
	return g.followRepack(ctx)
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
