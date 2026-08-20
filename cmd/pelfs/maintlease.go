package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbockelm/pelfs/internal/lease"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/ui"
)

// maintenanceLease takes the advisory lease for a command that PUBLISHES
// a generation.
//
// A repack is safe against a concurrent writer without this: the age
// guard keeps it off packs young enough to be a live writer's, and the
// ref flip is CAS-guarded, so the worst outcome is a refused flip rather
// than a clobbered branch. What it is not is CHEAP to lose. A repack
// sweeps the whole volume, rewrites gigabytes and uploads new packs
// before it flips, so losing the race there throws all of that away and
// leaves orphan packs for GC to find.
//
// That was tolerable while a human ran it and knew whether a mount was
// up. It stops being tolerable the moment it runs on a schedule, where
// overlapping a mount is a matter of when rather than whether.
//
// Read-only maintenance does NOT take it. `gc` deletes only what is older
// than the grace window and `fsck` writes nothing; making them wait on a
// mount would trade a real capability — inspecting a volume someone is
// using — for a race neither of them can lose.
func maintenanceLease(ctx context.Context, o *cmdOpts, prefix, session string) (*lease.Lease, error) {
	if o.noLease {
		ui.Warn("--no-lease: publishing without the advisory lease; " +
			"a concurrent mount will make one of the two flips fail")
		return nil, nil
	}
	// A direct-read store, for the reason the mount uses one: the lease is
	// mutable, and a cached copy either hides a live holder or resurrects
	// a dead one.
	metaStore, err := pelicanobj.New(ctx, pelicanobj.Config{
		PrefixURL:    prefix,
		TokenPath:    o.token,
		Insecure:     o.insecure,
		AcquireToken: !o.noAcquireToken,
		DirectRead:   true,
	})
	if err != nil {
		return nil, err
	}
	l, err := lease.Acquire(ctx, lease.Options{
		Store:   metaStore,
		Session: session,
		Steal:   o.stealLease,
		OnConflict: func(holder *lease.Info) {
			ui.Warn("another client took this prefix mid-operation: {holder}\n"+
				"this run keeps going, but its publish will be refused if that client advanced the branch",
				"holder", holder.Describe())
		},
	})
	if err != nil {
		if errors.Is(err, lease.ErrHeld) {
			// Named rather than generic: the fix is to stop the other
			// client or wait for it, and the message has to say which.
			return nil, fmt.Errorf("%w\nrepacking would rewrite packs and then lose the publish to that client; "+
				"stop it first, or pass --no-lease to proceed anyway", err)
		}
		return nil, err
	}
	return l, nil
}

// releaseLease drops a lease that may be nil (--no-lease), reporting a
// failure without turning it into the command's exit status: the work is
// already published, and a stuck lease object expires on its own TTL.
func releaseLease(ctx context.Context, l *lease.Lease) {
	if l == nil {
		return
	}
	if err := l.Release(ctx); err != nil {
		ui.Warn("could not release the lease ({error}); it expires on its own", "error", err)
	}
}
