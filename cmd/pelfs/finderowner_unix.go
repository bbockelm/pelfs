//go:build !windows

package main

import (
	"os"
	"syscall"
)

// Who owns a candidate mount point, which is the check that catches a
// half-done recipe: `sudo mkdir /Volumes/Data` without the chown leaves a
// root-owned directory, and the kernel refuses an unprivileged mount(2) on
// a directory owned by anybody else. Asking first turns that into a
// sentence with two commands in it instead of a mount error.

// ownerOf is the uid that owns fi, or -1 when the platform did not say.
func ownerOf(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

func ownedByUs(fi os.FileInfo) bool {
	owner := ownerOf(fi)
	return owner >= 0 && owner == os.Getuid()
}
