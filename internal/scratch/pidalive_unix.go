//go:build !windows

package scratch

import (
	"errors"
	"syscall"
)

// PIDAlive reports whether a process is still running. See the contract
// in scratch.go: only a positive "no such process" answers false.
//
// EPERM counts as alive: the signal was refused because the process
// exists and belongs to somebody else, and "somebody else's process" is a
// reason to leave its directory alone, not to delete it.
func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return true
	}
	// ESRCH is the only "it is gone" there is. Anything else — and
	// signal(0) has no other documented failure — is not a reason to
	// delete a directory.
	return !errors.Is(err, syscall.ESRCH)
}
