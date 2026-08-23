package nfsmount

import (
	"context"
	"path/filepath"
	"time"
)

// The kernel's mount table, and one thing pelfs needs from it: whether the
// mount this session attached is still attached.
//
// The FUSE frontend never had to ask. go-fuse's Server.Wait returns when
// the mount goes away, so a `fusermount -u` from another terminal ends the
// session and the seal runs (mountgen.go says so where it calls Wait).
// The loopback-NFS frontend has no such edge: our process is the SERVER,
// not the client, and a client that unmounts simply stops sending RPCs. A
// session whose mount was detached from outside therefore sits in the
// signal wait forever, holding an unsealed overlay that the user believes
// they have finished with.
//
// On macOS that is not a corner case: a browsable volume (see MountOptions
// in nfsmount.go) has an eject button in the Finder sidebar, and pressing
// it is how a Mac user says "I'm done with this". Eject detaches the mount
// and tells nobody. Polling the mount table is what turns that gesture
// back into the teardown it means.

// Entry is one row of the kernel's mount table: what is mounted, where,
// and by which filesystem.
type Entry struct {
	From string // f_mntfromname, e.g. "127.0.0.1:/pelfs"
	On   string // f_mntonname, the mount point
	Type string // f_fstypename, e.g. "nfs"
}

// Mounted reports whether path is currently a mount point.
//
// An error means the question could not be answered — NOT that the answer
// is no. Every caller here treats "unknown" as "still mounted", because
// the action taken on a no (seal and exit, or skip the unmount) is one
// that must not be taken on a guess.
func Mounted(path string) (bool, error) {
	entries, err := Entries()
	if err != nil {
		return false, err
	}
	return isMounted(entries, path), nil
}

// isMounted is the comparison, split out so it can be tested against
// captured mount tables on either platform.
//
// Paths are compared cleaned but NOT symlink-resolved. The kernel records
// the resolved path it mounted on, so a caller that hands us a path
// through a symlink gets a false negative; every caller here passes the
// path it just mounted, which is the same string mount(2) recorded.
func isMounted(entries []Entry, path string) bool {
	want := filepath.Clean(path)
	for _, e := range entries {
		if filepath.Clean(e.On) == want {
			return true
		}
	}
	return false
}

// FindFrom returns the mount point of the first entry mounted from the
// given source, or "" when there is none.
//
// This is the discovery half: it answers "where did this land" for a mount
// somebody else placed. pelfs chooses its own mount point today, so the
// only caller is the test that proves the table can be read at all — but
// it is the shape any route that lets the SYSTEM choose the mount point
// (Finder's own "Connect to Server", which mounts into /Volumes under a
// name it derives) would have to use to find the result.
func FindFrom(entries []Entry, from string) string {
	for _, e := range entries {
		if e.From == from {
			return e.On
		}
	}
	return ""
}

// unmountPollInterval is how often a live session re-reads the mount
// table. Reading it is a single syscall over a table with a handful of
// rows, so the cost is noise; the interval is set by how long a user
// should wait between pressing eject and seeing the session seal.
const unmountPollInterval = 2 * time.Second

// WatchUnmount closes the returned channel once mountPoint is no longer
// mounted. It stops watching when ctx is cancelled, and never closes the
// channel in that case: a cancelled watch is a session ending for its own
// reasons, and the difference matters to the caller, which reports WHY it
// is tearing down.
//
// THIS IS NOT A SEALING TRIGGER. It reports one fact — the mount is gone —
// to the single place that decides a mount session is over (awaitMountEnd
// in cmd/pelfs/mountgen.go), which then runs the same teardown a signal
// runs. The reason that distinction is written down here is that pelfs has
// a second, genuinely different automatic-publish trigger (idle sealing,
// cmd/pelfs/idleseal.go) and the two must not be confused: that one
// CHECKPOINTS a session that keeps running, this one ENDS one. See the
// "Eject and idle sealing" section of docs/finder.md.
func WatchUnmount(ctx context.Context, mountPoint string) <-chan struct{} {
	t := time.NewTicker(unmountPollInterval)
	go func() {
		<-ctx.Done()
		t.Stop()
	}()
	gone, _ := watchUnmount(ctx, func() (bool, error) { return Mounted(mountPoint) }, t.C)
	return gone
}

// watchUnmount is the state machine, with the clock and the mount table
// injected so a test can drive both. The second channel closes when the
// watch has stopped, which is what lets a test assert that a cancelled
// watch reported NOTHING rather than waiting a while and hoping.
//
// Three states and one transition: while the probe says mounted, nothing
// happens; while the probe FAILS, nothing happens either (the table could
// not be read, which is not evidence of an unmount); the first successful
// probe that does not find the mount closes the channel and ends the
// watch. There is no debounce, because the probe reads a kernel table
// rather than the network: it does not flap, and a mount that is absent
// from it is absent.
func watchUnmount(ctx context.Context, probe func() (bool, error), tick <-chan time.Time) (<-chan struct{}, <-chan struct{}) {
	gone, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-ctx.Done():
				return
			case _, ok := <-tick:
				if !ok {
					return
				}
				// Cancellation wins over a tick that arrived with it. A
				// select with both cases ready picks at random, and the
				// two answers are not equivalent: "you were ejected" makes
				// the caller report an eject and seal, while a cancelled
				// context means the session is already ending for its own
				// reasons and has its own account of why. idleSealer.run
				// and checkpointPeriodically make the same re-check for
				// the same reason.
				if ctx.Err() != nil {
					return
				}
				mounted, err := probe()
				if err != nil || mounted {
					continue
				}
				close(gone)
				return
			}
		}
	}()
	return gone, stopped
}
