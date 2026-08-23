package main

import (
	"errors"
	"syscall"
	"time"

	"github.com/bbockelm/pelfs/internal/scratch"
)

// The OS-specific half of how pelfs treats processes on Windows. The
// Unix half, and what each of these is for, is in procplat_unix.go.

// pidAlive reports whether a mount daemon this user started is still up.
//
// The hard part — Windows has no kill(pid, 0), os.FindProcess cannot
// fail, and a handle outlives the process it names — is solved once, in
// internal/scratch, with the reasoning written out there
// (pidalive_windows.go). This is the same question with one extra
// consideration, so it defers.
//
// The one difference from Unix is deliberate. scratch.PIDAlive reports a
// process it may not query as ALIVE, because it is deciding whether to
// delete a directory. The Unix pidAlive here is stricter — a pid that now
// belongs to another user is a recycled pid and the mount record behind
// it is stale — but on Windows there is nothing to gain from being
// stricter: the registry this pid came from is under the user's own state
// directory, "access denied" is far more common than on Unix (integrity
// levels, not just uids), and calling a live process dead here would let
// `pelfs mount` start a second mount over a running one. So Windows takes
// the conservative answer, and a genuinely stale record is cleared by
// `pelfs umount`, which removes it by name.
func pidAlive(pid int) bool { return scratch.PIDAlive(pid) }

// daemonSysProcAttr detaches the spawned mount daemon.
//
// DETACHED_PROCESS is the closest thing Windows has to setsid: the child
// gets no console, so it does not die when the console that started it
// closes, and CREATE_NEW_PROCESS_GROUP keeps a Ctrl+C in the parent's
// console from reaching it.
//
// UNEXERCISED, and honestly so: nothing on Windows can mount yet, so
// resolveBackend refuses `pelfs mount` before this is ever reached. It is
// written to be right rather than left as a nil, so that the day a
// Windows frontend exists this is a thing to verify and not a thing to
// discover.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}

// detachedProcess is DETACHED_PROCESS. syscall names CREATE_NEW_PROCESS_GROUP
// and not this one.
const detachedProcess = 0x00000008

// signalStop asks a mount daemon to unmount and seal — and REFUSES to,
// on Windows, rather than doing something that looks similar.
//
// The Unix path sends SIGTERM because runMountGen's exit path seals the
// overlay into the next generation on the way out. Windows has no
// SIGTERM: os/signal delivers Ctrl+C and Ctrl+Break to a process that
// shares a console, and this daemon deliberately has none
// (daemonSysProcAttr detaches it), so there is no channel to ask it
// politely.
//
// What is available is TerminateProcess, which os.Process.Kill calls, and
// that is `kill -9`: it stops the process wherever it is, with an
// unsealed overlay on disk and an unfinished upload on the wire. The
// overlay survives and a later mount can resume it, but a user who typed
// `pelfs umount` and got that would reasonably believe their session had
// been sealed. Refusing says the true thing instead.
func signalStop(pid int) error {
	return errors.New("stopping a background mount is not implemented on Windows: " +
		"a graceful stop needs a signal, and the only thing Windows offers a detached process " +
		"is TerminateProcess, which would strand the session's overlay unsealed instead of publishing it")
}

// processCPU is this process's user+system time.
//
// GetProcessTimes rather than Getrusage, which Windows does not have.
// Filetime counts 100-nanosecond ticks and Nanoseconds() converts, so
// this is the same quantity the Unix path reports and not an approximation
// of it.
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
