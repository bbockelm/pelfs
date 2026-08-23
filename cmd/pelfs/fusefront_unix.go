//go:build !windows

package main

import (
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/rawfuse"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// fuseBuilt: this binary has a FUSE frontend. Whether the HOST will let it
// mount is a separate question, and the one fuseUsable goes on to ask.
const fuseBuilt = true

// fuseUnsupported is empty here because FUSE is supported here. It exists
// so that fuseUsable can read the same two names on every platform.
const fuseUnsupported = ""

// fuseSrv is go-fuse's server behind the interface the mount session uses.
// Unmount and Wait are go-fuse's own, promoted; NewRefresher is the one
// method that needs the concrete type, which is exactly why the wrapper is
// here rather than an interface assertion at the call site.
type fuseSrv struct{ *fuse.Server }

func (s fuseSrv) NewRefresher(fs *genfs.FS, fetch fuseFetcher, every time.Duration) fuseRefresher {
	return rawfuse.NewRefresher(fs, s.Server, rawfuse.Fetcher(fetch), every)
}

// fuseMount serves fs at mountpoint read-only.
func fuseMount(mountpoint string, fs *genfs.FS, debug bool) (fuseServer, error) {
	srv, err := rawfuse.Mount(mountpoint, fs, debug)
	if err != nil {
		// Returned as an untyped nil, deliberately: a fuseSrv wrapping a
		// nil *fuse.Server would be a non-nil interface, and the caller's
		// `srv != nil` would then be true for a mount that never happened.
		return nil, err
	}
	return fuseSrv{srv}, nil
}

// fuseMountRW serves the write overlay ov at mountpoint.
func fuseMountRW(mountpoint string, ov *overlay.FS, debug bool) (fuseServer, error) {
	srv, err := rawfuse.MountRW(mountpoint, ov, debug)
	if err != nil {
		return nil, err
	}
	return fuseSrv{srv}, nil
}

// fusePassedFD reports whether mountpoint is a /dev/fuse descriptor a
// parent opened and mounted rather than a directory to mount on.
func fusePassedFD(mountpoint string) bool { return rawfuse.PassedFD(mountpoint) }
