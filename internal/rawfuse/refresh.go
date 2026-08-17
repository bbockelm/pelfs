package rawfuse

import (
	"context"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// Live generation refresh for read-only mounts (docs/design-packfs.md,
// "Read-only mounts and update propagation"): poll the branch head, swap
// the served generation, and push the resulting invalidation set into the
// kernel.
//
// The propagation problem CVMFS spent years on does not arise here. Their
// pain was (a) manifest freshness behind TTL'd caches with no bypass, and
// (b) inode renumbering on catalog reload, which broke open files. Here
// the freshness signal is one small mutable object read with ?directread,
// and inodes are stable across generations — so a swap invalidates only
// what actually changed, and everything else stays valid in the kernel's
// caches.

// Fetcher returns the current head of the branch being followed. It must
// verify signature and lineage; refs.Store.Fetch does both.
type Fetcher func(ctx context.Context) (*superblock.Superblock, error)

// Refresher polls a branch and keeps a mounted generation current.
type Refresher struct {
	fs    *genfs.FS
	srv   *fuse.Server
	fetch Fetcher
	every time.Duration
	// logger takes a ui message and its attributes; the seam exists so a
	// test can watch what a swap reported without reading stderr.
	logger func(msg string, attrs ...any)
}

// NewRefresher wires a poller to a mounted filesystem. Interval zero
// disables polling (the mount stays pinned to the generation it started
// with, which is what a reproducible batch job wants).
func NewRefresher(fs *genfs.FS, srv *fuse.Server, fetch Fetcher, every time.Duration) *Refresher {
	return &Refresher{fs: fs, srv: srv, fetch: fetch, every: every, logger: ui.Info}
}

// Run polls until ctx ends. Fetch failures are logged and retried at the
// next tick: a federation hiccup must never take down a mount that is
// serving a perfectly good generation.
func (r *Refresher) Run(ctx context.Context) {
	if r.every <= 0 {
		return
	}
	tick := time.NewTicker(r.every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := r.Refresh(ctx); err != nil {
				r.logger("refresh: {error} (still serving generation {generation})",
					"error", err, "generation", r.fs.Generation())
			}
		}
	}
}

// Refresh performs one poll-and-swap. It is safe to call directly (tests,
// or a control-socket verb).
func (r *Refresher) Refresh(ctx context.Context) error {
	sb, err := r.fetch(ctx)
	if err != nil {
		return err
	}
	if sb.Generation == r.fs.Generation() {
		return nil
	}
	rep, err := r.fs.Swap(ctx, sb)
	if err != nil {
		return err
	}
	if len(rep.Changes) == 0 && len(rep.Entries) == 0 {
		r.logger("generation {from} -> {to}: nothing this mount holds changed",
			"from", rep.From, "to", rep.To)
		return nil
	}
	r.notify(rep)
	r.logger("generation {from} -> {to}: invalidated {inodes} and {names} of {resident} resident",
		"from", rep.From, "to", rep.To,
		"inodes", ui.Count(len(rep.Changes), "inode"),
		"names", ui.Count(len(rep.Entries), "name"),
		"resident", rep.Resident)
	return nil
}

// notify pushes the invalidation set to the kernel. Order matters:
// entries first, so a name the kernel is about to re-resolve cannot be
// answered from a dentry that the inode invalidation just made stale.
//
// Notification failures are not errors: ENOENT means the kernel never
// cached that inode or name in the first place, which is exactly the
// state the notification was trying to produce.
func (r *Refresher) notify(rep *genfs.SwapReport) {
	if r.srv == nil {
		return
	}
	for _, e := range rep.Entries {
		r.srv.EntryNotify(e.Parent, e.Name) //nolint:errcheck
	}
	for _, c := range rep.Changes {
		if c.Gone {
			// The inode is no longer reachable at its edge; the entry
			// notification above already removed the name, and dropping
			// its pages here keeps a still-open handle from serving stale
			// bytes after the last reference goes.
			r.srv.InodeNotify(c.Inode, 0, -1) //nolint:errcheck
			continue
		}
		if c.Content {
			// Offset 0, length -1: invalidate the whole page cache for
			// this inode.
			r.srv.InodeNotify(c.Inode, 0, -1) //nolint:errcheck
		} else if c.Attr {
			// Attributes only: a zero-length invalidation refreshes the
			// kernel's cached attrs without dropping page cache.
			r.srv.InodeNotify(c.Inode, 0, 0) //nolint:errcheck
		}
	}
}
