package publish_test

import (
	"syscall"
	"time"
)

// processCPU is user+system CPU for the whole process. GetProcessTimes
// rather than Getrusage, which Windows does not have; Filetime counts
// 100-nanosecond ticks, so this is the same quantity the Unix half
// reports and not an approximation of it. See procpu_unix_test.go.
func processCPU() time.Duration {
	var creation, exit, kernel, user syscall.Filetime
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0
	}
	return time.Duration(kernel.Nanoseconds() + user.Nanoseconds())
}
