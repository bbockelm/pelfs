//go:build !darwin && !linux

package nfsmount

import (
	"errors"
	"runtime"
)

// Entries has no implementation on a platform where this backend cannot
// attach a mount in the first place (Server.Mount refuses Windows by
// name). It returns an ERROR rather than an empty table, which is the
// whole reason it exists: Mounted's contract is that an error means the
// question could not be answered, and every caller treats that as "still
// mounted". An empty table would instead be read as "nothing is mounted
// anywhere", which is the one answer that makes a session seal and exit.
func Entries() ([]Entry, error) {
	return nil, errors.New("the kernel's mount table is not read on " + runtime.GOOS +
		": the NFS backend cannot attach a mount there, so there is none of ours to find")
}
