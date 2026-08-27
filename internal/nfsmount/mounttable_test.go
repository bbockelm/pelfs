package nfsmount

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A mount table in the shapes macOS actually produces: the system volumes
// and autofs maps a Mac carries, an NFS source with the port nowhere in it
// (mount_nfs records only host:/export, which is why a session identifies
// its mount by the mount POINT), and a mountpoint with a space in it,
// because a volume named for a dataset usually has one.
func fixture() []Entry {
	return []Entry{
		{From: "/dev/disk3s1s1", On: "/", Type: "apfs"},
		{From: "devfs", On: "/dev", Type: "devfs"},
		{From: "/dev/disk3s5", On: "/System/Volumes/Data", Type: "apfs"},
		{From: "map auto_home", On: "/System/Volumes/Data/home", Type: "autofs"},
		{From: "127.0.0.1:/Survey Data", On: "/Users/x/Volumes/Survey Data", Type: "nfs"},
		{From: "127.0.0.1:/", On: "/Users/x/.local/state/pelfs/vol-abc/mnt", Type: "nfs"},
	}
}

func TestIsMounted(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/Users/x/Volumes/Survey Data", true},
		// Cleaned, not resolved: a trailing slash or a doubled separator
		// is the same mountpoint, and callers build these paths with Join.
		{"/Users/x/Volumes/Survey Data/", true},
		{"/Users/x/Volumes//Survey Data", true},
		{"/", true},
		// A path INSIDE a mount is not the mountpoint. This is the
		// distinction the eject watch depends on: after an eject the
		// directory is still there, and still inside "/".
		{"/Users/x/Volumes/Survey Data/sub", false},
		{"/Users/x/Volumes/Other", false},
		{"", false},
	} {
		if got := isMounted(fixture(), tc.path); got != tc.want {
			t.Errorf("isMounted(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestFindFrom(t *testing.T) {
	if got := FindFrom(fixture(), "127.0.0.1:/Survey Data"); got != "/Users/x/Volumes/Survey Data" {
		t.Errorf("FindFrom = %q", got)
	}
	if got := FindFrom(fixture(), "127.0.0.1:/nothing"); got != "" {
		t.Errorf("FindFrom of an absent source = %q, want empty", got)
	}
}

// The eject state machine. It has one job -- notice, exactly once, that
// the mount is gone -- and one way to be dangerous: firing when it should
// not, because what the caller does next is seal the session and exit.
func TestWatchUnmountFiresWhenTheMountIsGone(t *testing.T) {
	tick := make(chan time.Time)
	probed := make(chan struct{})
	mounted := true
	gone, _ := watchUnmount(context.Background(), func() (bool, error) {
		defer func() { probed <- struct{}{} }()
		return mounted, nil
	}, tick)

	// Two ticks while it is mounted: nothing happens, and the proof is
	// that the probe ran (so the tick was consumed) and the channel is
	// still open afterwards.
	for i := 0; i < 2; i++ {
		tick <- time.Now()
		<-probed
		select {
		case <-gone:
			t.Fatal("reported an unmount while the mount was still there")
		default:
		}
	}

	mounted = false
	tick <- time.Now()
	<-probed
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("did not report the unmount")
	}
}

// A mount table that cannot be READ is not a mount that is gone. This is
// the difference between a watch that is safe to attach to a writable
// session and one that seals it on a transient error.
func TestWatchUnmountIgnoresProbeErrors(t *testing.T) {
	tick := make(chan time.Time)
	probed := make(chan struct{})
	gone, _ := watchUnmount(context.Background(), func() (bool, error) {
		defer func() { probed <- struct{}{} }()
		return false, errors.New("getfsstat: interrupted")
	}, tick)

	for i := 0; i < 3; i++ {
		tick <- time.Now()
		<-probed
		select {
		case <-gone:
			t.Fatal("treated an unreadable mount table as an unmount")
		default:
		}
	}
}

// A cancelled watch reports nothing: the session is ending for its own
// reasons, and the caller distinguishes "you were ejected" from "you were
// signalled" by which channel woke it.
func TestWatchUnmountStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Buffered, and a probe that would report an unmount if it ran: the
	// tick and the cancellation are deliberately both ready, which is the
	// race a select decides at random.
	tick := make(chan time.Time, 1)
	gone, stopped := watchUnmount(ctx, func() (bool, error) { return false, nil }, tick)
	cancel()
	tick <- time.Now()
	<-stopped
	select {
	case <-gone:
		t.Fatal("a cancelled watch reported an unmount")
	default:
	}
}
