package main

import (
	"errors"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// There is no FUSE frontend in a Windows build, and this file is what
// says so rather than what fakes it.
//
// internal/rawfuse is not compiled here at all (its files carry
// `//go:build !windows`), because github.com/hanwen/go-fuse cannot be
// ported: its types ARE the Unix kernel protocol — syscall.Stat_t,
// iovecs, a /dev/fuse descriptor. A stub that returned a working-looking
// server would be worse than nothing, since the failure would surface
// later, somewhere else, as a nil dereference in the middle of a session.
//
// So every entry point below refuses immediately and says why. The
// refusal a user actually meets is earlier still: fuseUsable consults
// fuseBuilt before anything opens a device, so `pelfs mount --backend
// fuse` on Windows fails during argument handling with errNoFUSE's
// sentence, before a lease is taken or a byte is fetched.
const fuseBuilt = false

// fuseUnsupported is what fuseUsable reports as the reason. It names the
// dependency rather than the platform, because "Windows has no FUSE" is
// not quite true — WinFsp exists — and the honest statement is that
// pelfs's frontend is written against a library that has no Windows
// backend.
const fuseUnsupported = "this build has no FUSE frontend: pelfs mounts through go-fuse, which is Unix-only. " +
	"A Windows frontend is a separate thing and not this binary"

var errNoFUSE = errors.New(fuseUnsupported)

func fuseMount(string, *genfs.FS, bool) (fuseServer, error) { return nil, errNoFUSE }

func fuseMountRW(string, *overlay.FS, bool) (fuseServer, error) { return nil, errNoFUSE }

// fusePassedFD is always false. `/dev/fd/N` is a Unix convention for
// handing a mounted FUSE device to a child (apptainer --fusemount) and
// there is no Windows spelling of it, so a mountpoint that happens to
// look like one is treated as the ordinary path it is.
func fusePassedFD(string) bool { return false }
