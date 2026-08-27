//go:build !darwin && !linux

package nfsmount

import (
	"errors"
	"runtime"
)

// Entries on a platform whose mount table pelfs has no reader for.
//
// Windows is the platform that reaches this, and it reaches it only as a
// COMPILED thing: `Mount` refuses there (nfsmount.go), so nothing this
// package attached can be in a mount table to find. The file exists
// because mounttable.go is platform-independent and calls Entries, and a
// build tag is the only way to say "not here" in a language that resolves
// this at link time.
//
// It returns an error rather than an empty table, which is the difference
// that matters: mounttable.go's contract is that an error means the
// question could not be answered and NOT that the answer is no, and every
// caller treats it that way. An empty table would be a positive claim that
// nothing is mounted anywhere — which would make Mounted answer false for
// a path that may well be a mount point, WatchUnmount fire immediately on
// a mount it cannot see, and Unmount's "already gone" shortcut skip a
// teardown. Reporting "unknown" leaves every one of those on the
// conservative branch it was written for.
//
// The reader Windows would need, the day something here can mount there,
// is GetLogicalDriveStrings plus QueryDosDevice, or FindFirstVolume /
// FindFirstVolumeMountPoint — a different shape from a table of rows,
// because a Windows mount is a drive letter or a reparse point rather than
// a directory a filesystem was attached to. docs/TODO.md, macosmerge-agent.
func Entries() ([]Entry, error) {
	return nil, errors.New("pelfs cannot read the mount table on " + runtime.GOOS +
		": it has no reader for this platform, and the NFS backend cannot mount here either")
}
