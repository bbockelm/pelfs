package scratch

import (
	"errors"

	"golang.org/x/sys/windows"
)

// stillActive is STILL_ACTIVE, the exit code GetExitCodeProcess reports
// for a process that has not exited. Neither syscall nor
// golang.org/x/sys/windows defines it, so it is named here rather than
// left as a bare 259 at the comparison.
const stillActive = 259

// PIDAlive reports whether a process is still running. See the contract
// in scratch.go: only a positive "no such process" answers false, and
// this function DELETES DIRECTORIES when it is wrong about that.
//
// WHY NOT os.FindProcess. On Windows it opens a real handle and can
// fail, but Go's implementation falls back to a synthetic Process value
// whenever it cannot, so it effectively always succeeds and can never
// answer this question. Signal(syscall.Signal(0)) is no better: Windows
// has no signals, so Go implements it as a liveness probe on the handle
// FindProcess may not have — and on a pid that never existed the pair
// reports a live process. Asking the kernel directly is the only way to
// get an answer that means anything.
//
// TWO CALLS, BECAUSE A HANDLE OUTLIVES A PROCESS. Unix reaps a process
// and its pid stops answering. Windows keeps the process OBJECT alive as
// long as anybody holds a handle to it — a parent that has not called
// CloseHandle, a debugger, Task Manager with the row selected — and
// OpenProcess on such a pid SUCCEEDS long after the process exited. That
// is the Windows shape of a zombie, and it is the case that would strand
// gigabytes forever if the open were taken as proof of life. So the open
// only gets us a handle; GetExitCodeProcess is what answers the
// question, and STILL_ACTIVE is the only value that means running.
//
// THE THREE FAILURE MODES, and why each lands where it does:
//
//   - ERROR_INVALID_PARAMETER (87) is what OpenProcess returns for a pid
//     that names nothing. It is the ESRCH of this API — Windows does not
//     have a "no such process" error and reuses the argument-validation
//     one — and it is the ONLY path in this function that reports dead.
//   - ERROR_ACCESS_DENIED (5) means the process is there and this token
//     may not look at it: another user's session, or a higher integrity
//     level. That is Unix's EPERM, and it reports ALIVE for the same
//     reason — somebody else's process is a reason to leave its directory
//     alone, not to delete it. PROCESS_QUERY_LIMITED_INFORMATION is
//     requested precisely to make this rare: it is the weakest right that
//     answers, and it is granted across integrity levels where
//     PROCESS_QUERY_INFORMATION is not.
//   - Anything else, including a GetExitCodeProcess that fails on a
//     handle we hold, reports ALIVE. An unrecognized error is not
//     evidence of death.
//
// ON PID REUSE, which is worse here than on Unix. Windows pids are
// indices into a kernel handle table, handed out in small multiples of
// four and recycled promptly; a boot can hand the same number out within
// minutes, where Linux walks a large counter before it wraps. So the
// case Owner's pid guard cannot see — a stranded directory whose number
// now belongs to some unrelated long-lived service — is not a curiosity
// on Windows, it is expected. That is what DefaultReuseAge exists for,
// and it is why this function does not try to be clever about it: it
// answers "is something running under that number", the age guard
// answers "and has it touched this directory in a week".
//
// One deliberate imprecision: a process that exits with code 259 is
// indistinguishable from one that is still running. That errs toward
// alive, which is the safe direction, and 259 is not a code anything in
// pelfs returns.
func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h) //nolint:errcheck
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code == stillActive
}
