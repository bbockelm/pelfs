//go:build !windows

package main

import (
	"fmt"
	"syscall"
	"time"
)

// The OS-specific half of how pelfs treats processes: is one alive, how
// is the background mount daemon detached, how is it asked to stop, and
// how much CPU has this one used. The Windows half is procplat_windows.go.

// pidAlive reports whether a mount daemon THIS user started is still up.
//
// Stricter than scratch.PIDAlive on purpose, and the difference is EPERM.
// scratch is deciding whether to delete somebody's spool directory, so a
// process it may not signal counts as alive. Here the pid came out of
// this user's own mount registry, so a pid that now belongs to another
// user is a RECYCLED pid and the record behind it is stale — reporting it
// alive would leave a dead mount listed forever with no way to clear it.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// daemonSysProcAttr detaches the spawned mount daemon from this process's
// session, so closing the terminal that started it does not take the
// mount down with it.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// signalStop asks a mount daemon to unmount and seal. SIGTERM, because
// that is what runMountGen waits for: the seal happens on the way out,
// so this must never be a kill that skips it.
func signalStop(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal pid %d: %w", pid, err)
	}
	return nil
}

// processCPU is this process's user+system time. Seals are mostly
// chunking and SQLite, so CPU well below wall time points at the network
// and CPU near wall time points at us.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	return tv(ru.Utime) + tv(ru.Stime)
}
