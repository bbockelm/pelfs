//go:build !windows

package publish_test

import (
	"syscall"
	"time"
)

// processCPU is user+system CPU for the whole process, which is what the
// seal-cost line a session prints reports as its CPU number. It is used
// only by the PELFS_BIGSEAL measurement harness in bigseal_test.go.
//
// Per-OS because there is no portable way to ask: Getrusage does not
// exist on Windows. cmd/pelfs/procplat_*.go carries the production copy
// of the same split, for the same reason.
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
