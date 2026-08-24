//go:build !windows

package rawfuse

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/mounterr"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The instant that matters to a job supervisor is the one where an error
// the binding could not translate becomes the payload's EIO. Every
// translated status is an answer the filesystem MEANT, and reporting one
// of those as a mount failure would hold jobs for looking up a file that
// is not there.
func TestOnlyUntranslatableErrorsLatch(t *testing.T) {
	translated := []struct {
		name string
		err  error
		want fuse.Status
	}{
		{"not exist", genfs.ErrNotExist, fuse.ENOENT},
		{"stale", genfs.ErrStale, errStale},
		{"exists", overlay.ErrExist, errExist},
		{"not empty", overlay.ErrNotEmpty, errNotEmpty},
		{"not dir", overlay.ErrNotDir, fuse.ENOTDIR},
		{"is dir", overlay.ErrIsDir, fuse.EISDIR},
		{"cancelled", context.Canceled, fuse.EINTR},
	}
	for _, c := range translated {
		t.Run(c.name, func(t *testing.T) {
			mounterr.Rearm()
			t.Cleanup(mounterr.Rearm)
			if got := errStatus(c.err); got != c.want {
				t.Fatalf("errStatus = %v, want %v", got, c.want)
			}
			if ev, ok := mounterr.Fired(); ok {
				t.Fatalf("a translated status latched a mount failure: %v", ev.Err)
			}
		})
	}

	t.Run("untranslatable", func(t *testing.T) {
		mounterr.Rearm()
		t.Cleanup(mounterr.Rearm)
		var out bytes.Buffer
		defer ui.SetOutput(&out, ui.Plain)()
		eioReportedAt.Store(0)
		eioSuppressed.Store(0)

		boom := errors.New("pack 3 trailer is truncated")
		if got := errStatus(boom); got != fuse.EIO {
			t.Fatalf("errStatus = %v, want EIO", got)
		}
		ev, ok := mounterr.Fired()
		if !ok {
			t.Fatal("an EIO answered to the payload did not latch")
		}
		if !errors.Is(ev.Err, boom) {
			t.Errorf("latched %v", ev.Err)
		}
		if ev.Frontend != mounterr.FrontendFUSE {
			t.Errorf("frontend %q", ev.Frontend)
		}
	})
}

// The latch is on a per-operation path. Once it has fired -- which is
// exactly the situation where a workload is producing them in bulk -- it
// must cost one atomic load, the same discipline the EIO log line
// already follows.
func TestLatchedErrStatusIsFree(t *testing.T) {
	mounterr.Rearm()
	t.Cleanup(mounterr.Rearm)
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()

	err := errors.New("still broken")
	errStatus(err) // fire the latch and the first log line
	eioReportedAt.Store(time.Now().UnixNano())
	eioSuppressed.Store(0)

	if n := testing.AllocsPerRun(200, func() { _ = errStatus(err) }); n != 0 {
		t.Errorf("a suppressed EIO allocates %v times per call", n)
	}
}

// A late subscriber -- a session that finishes wiring itself up after
// the mount has already served a failing read -- still learns.
func TestSessionSubscribingLateStillSeesTheFailure(t *testing.T) {
	mounterr.Rearm()
	t.Cleanup(mounterr.Rearm)
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()
	eioReportedAt.Store(0)

	errStatus(errors.New("early failure"))
	got := make(chan mounterr.Event, 1)
	mounterr.OnFirst(func(ev mounterr.Event) { got <- ev })
	select {
	case ev := <-got:
		if ev.Err.Error() != "early failure" {
			t.Fatalf("got %v", ev.Err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the late subscriber was never told")
	}
}
