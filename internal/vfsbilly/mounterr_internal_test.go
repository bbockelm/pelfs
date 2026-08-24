package vfsbilly

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/mounterr"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// The NFS half of the same rule as rawfuse's errStatus: an error this
// adapter has a sentinel for is an answer it MEANT, and only the
// fall-through -- what go-nfs turns into NFS3ERR_IO -- is the mount
// telling the payload that it broke.
func TestOnlyUntranslatedErrorsLatch(t *testing.T) {
	kept := []struct {
		name string
		err  error
	}{
		{"not exist", genfs.ErrNotExist},
		{"stale", genfs.ErrStale},
		{"exists", overlay.ErrExist},
		{"not empty", overlay.ErrNotEmpty},
		{"not dir", overlay.ErrNotDir},
		{"is dir", overlay.ErrIsDir},
		// Chosen by this package: a permission refusal, an invalid
		// operand, a symlink loop. All of them are the filesystem
		// answering correctly.
		{"eacces", syscall.EACCES},
		{"eperm", syscall.EPERM},
		{"einval", syscall.EINVAL},
		{"eloop", syscall.ELOOP},
		{"estale", syscall.ESTALE},
		// go-nfs answers NFS3ERR_NOSPC for this, so the payload gets a
		// specific, catchable error rather than "the mount broke".
		{"enospc", syscall.ENOSPC},
		{"wrapped enospc", fmt.Errorf("stage write: %w", &os.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC})},
	}
	for _, c := range kept {
		t.Run(c.name, func(t *testing.T) {
			mounterr.Rearm()
			t.Cleanup(mounterr.Rearm)
			_ = sentinel(c.err)
			if ev, ok := mounterr.Fired(); ok {
				t.Fatalf("a deliberate answer latched a mount failure: %v", ev.Err)
			}
		})
	}

	untranslated := []struct {
		name string
		err  error
	}{
		{"bare", errors.New("pack 3 trailer is truncated")},
		{"wrapped", fmt.Errorf("read chunk: %w", errors.New("checksum mismatch"))},
		{"federation", fmt.Errorf("GET meta/ref: %w", errors.New("503 Service Unavailable"))},
	}
	for _, c := range untranslated {
		t.Run(c.name, func(t *testing.T) {
			mounterr.Rearm()
			t.Cleanup(mounterr.Rearm)
			if got := sentinel(c.err); got != c.err {
				t.Fatalf("sentinel rewrote an untranslated error to %v", got)
			}
			ev, ok := mounterr.Fired()
			if !ok {
				t.Fatal("an error that becomes NFS3ERR_IO did not latch")
			}
			if !errors.Is(ev.Err, c.err) {
				t.Errorf("latched %v", ev.Err)
			}
			if ev.Frontend != mounterr.FrontendNFS {
				t.Errorf("frontend %q", ev.Frontend)
			}
		})
	}
}

// pe is the only caller, and a read or a write is the operation that
// matters most: those are the calls a payload does not check.
func TestReadErrorsReachTheLatchThroughPathError(t *testing.T) {
	mounterr.Rearm()
	t.Cleanup(mounterr.Rearm)
	err := pe("read", "/data/x", errors.New("pack is unreadable"))
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("pe returned %T", err)
	}
	if _, ok := mounterr.Fired(); !ok {
		t.Fatal("a failing read did not latch")
	}
}

// Latched failures are free, for the same reason they are on the FUSE
// side: one bad file answers every read a tar issues.
func TestLatchedSentinelIsFree(t *testing.T) {
	mounterr.Rearm()
	t.Cleanup(mounterr.Rearm)
	err := errors.New("still broken")
	_ = sentinel(err)
	if n := testing.AllocsPerRun(200, func() { _ = sentinel(err) }); n != 0 {
		t.Errorf("a suppressed failure allocates %v times per call", n)
	}
}
