//go:build !windows

package main

import (
	"os"
	"syscall"
)

// ownerOf is the uid that owns fi, or -1 when the platform did not say.
//
// The assertion can fail even here — os.FileInfo.Sys() is documented as
// returning the underlying data source and nothing more — so a -1 is
// reported rather than assumed away, and ownedByUs (finder.go) treats it
// as "not ours", which is the conservative answer: the mount is attempted
// somewhere the process certainly owns instead of on a directory it may
// not.
func ownerOf(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
