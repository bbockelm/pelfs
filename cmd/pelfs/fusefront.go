package main

import (
	"context"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The FUSE frontend, as narrow an interface as a mount session actually
// needs of it — because on Windows there is no FUSE frontend at all.
//
// internal/rawfuse is built on github.com/hanwen/go-fuse, which is
// Unix-only and not portable in principle: its whole surface is
// syscall.Stat_t, iovecs and a device fd. So the Windows build does not
// contain it, and cannot. What it contains instead is
// fusefront_windows.go, whose every entry point refuses with a sentence.
//
// WHY AN INTERFACE RATHER THAN #ifdef AT EVERY CALL SITE. runMountGen is
// one function with the whole session lifecycle in it — lease, overlay,
// mount, checkpointer, seal — and forking it per platform would mean
// maintaining two copies of the part that has nothing to do with FUSE.
// Three method signatures is the entire coupling, and this is it.
type fuseServer interface {
	// Unmount detaches the mount. It is refused for a passed descriptor,
	// whose mountpoint belongs to whoever opened it.
	Unmount() error
	// Wait blocks until the serve loop ends — because the mount was
	// detached, or because the connection went away.
	Wait()
	// NewRefresher builds the live-refresh poller for this mount: it
	// re-reads the branch head and swaps the served generation, pushing
	// the invalidations the kernel needs to drop what it cached.
	NewRefresher(fs *genfs.FS, fetch fuseFetcher, every time.Duration) fuseRefresher
}

// fuseFetcher re-reads the branch head. It matches rawfuse.Fetcher.
type fuseFetcher func(ctx context.Context) (*superblock.Superblock, error)

// fuseRefresher is one poll of the branch, applied. genSession.follow
// drives it on its own ticker so that it can count the swaps.
type fuseRefresher interface {
	Refresh(ctx context.Context) error
}

// THE REST OF THE SPLIT, in fusefront_unix.go and fusefront_windows.go
// because the Windows half has no rawfuse to call:
//
//   - fuseMount serves a generation read-only, fuseMountRW serves a write
//     overlay over one.
//   - fusePassedFD reports whether the "mountpoint" is really a /dev/fuse
//     descriptor a parent opened (the apptainer --fusemount convention).
//   - fuseBuilt says whether this binary has a FUSE frontend at all, and
//     fuseUnsupported says why not when it does not. fuseUsable in main.go
//     consults them FIRST, so "can this mount with FUSE" is answered by
//     what was compiled and not by a string compare on runtime.GOOS.
