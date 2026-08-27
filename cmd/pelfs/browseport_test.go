package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// TestBrowseListenProbesUpwardFrom8443 is the whole contract of the port,
// and it is the owner's sentence turned into assertions: "try probing
// starting at 8443 and going up. If not found in 100 ports, use the kernel
// localhost:0 binding."
//
// Every subtest here sits on ports itself rather than mocking the bind,
// because "is this port free" is a question only the kernel answers and a
// probe that agreed with a fake would tell us nothing.
func TestBrowseListenProbesUpwardFrom8443(t *testing.T) {
	t.Run("prefersTheWellKnownPort", func(t *testing.T) {
		ln, probed, err := browseListen(0)
		if err != nil {
			t.Fatalf("browseListen: %v", err)
		}
		defer ln.Close() //nolint:errcheck
		if !probed {
			t.Fatal("the probe reported that it did not get a port from its window")
		}
		got := ln.Addr().(*net.TCPAddr).Port
		// Not asserted as exactly 8443: this test runs on developer
		// machines and CI hosts where something may legitimately have it,
		// which is the ordinary case the probe exists for. What IS asserted
		// is that it is in the window and that the probe says so.
		if got < browsePortFirst || got >= browsePortFirst+browsePortProbe {
			t.Errorf("bound %d, outside the probe window %d-%d",
				got, browsePortFirst, browsePortFirst+browsePortProbe-1)
		}
	})

	t.Run("stepsOverWhatIsTaken", func(t *testing.T) {
		// Sit on the first two, which is exactly what two other browse
		// sessions do, and the third must be what comes back.
		var held []net.Listener
		defer func() {
			for _, l := range held {
				l.Close() //nolint:errcheck
			}
		}()
		for p := browsePortFirst; p < browsePortFirst+2; p++ {
			l, err := listenLoopback(p)
			if err != nil {
				t.Skipf("cannot hold port %d on this host: %v", p, err)
			}
			held = append(held, l)
		}
		ln, probed, err := browseListen(0)
		if err != nil {
			t.Fatalf("browseListen: %v", err)
		}
		defer ln.Close() //nolint:errcheck
		if !probed {
			t.Fatal("fell out of the probe window with ports still free in it")
		}
		if got := ln.Addr().(*net.TCPAddr).Port; got < browsePortFirst+2 {
			t.Errorf("bound %d, which is one of the ports being held", got)
		}
	})

	t.Run("theWindowIsAHundredPortsAndTheyAreAllNavigable", func(t *testing.T) {
		if browsePortProbe != 100 {
			t.Errorf("the probe window is %d ports, and the request was 100", browsePortProbe)
		}
		if browsePortFirst != 8443 {
			t.Errorf("the probe starts at %d, and the request was 8443", browsePortFirst)
		}
		// Chromium refuses to navigate to a list of ports, and a browse
		// session on one would be unusable with no error anybody could act
		// on. None of these is on it; the two that come closest are 6000
		// (X11) and 10080, both outside the window.
		last := browsePortFirst + browsePortProbe - 1
		for _, blocked := range []int{6000, 6665, 6666, 6667, 6668, 6669, 6697, 10080} {
			if blocked >= browsePortFirst && blocked <= last {
				t.Errorf("port %d is on Chromium's blocked list and inside the window", blocked)
			}
		}
	})

	t.Run("fallsBackToTheKernelWhenTheWholeWindowIsGone", func(t *testing.T) {
		// A hundred binds is a slow way to say this and the only honest
		// one: the fallback has to be reachable, and the only way in is an
		// exhausted window.
		var held []net.Listener
		defer func() {
			for _, l := range held {
				l.Close() //nolint:errcheck
			}
		}()
		for p := browsePortFirst; p < browsePortFirst+browsePortProbe; p++ {
			l, err := listenLoopback(p)
			if err != nil {
				// Something else on this host has one of them. That IS the
				// exhausted case as far as the probe is concerned, so the
				// test simply keeps going: what matters is that no port in
				// the window is left free.
				continue
			}
			held = append(held, l)
		}
		if len(held) == 0 {
			t.Skip("cannot hold any port in the probe window on this host")
		}
		ln, probed, err := browseListen(0)
		if err != nil {
			t.Fatalf("browseListen refused to start at all: %v", err)
		}
		defer ln.Close() //nolint:errcheck
		got := ln.Addr().(*net.TCPAddr).Port
		if got >= browsePortFirst && got < browsePortFirst+browsePortProbe {
			t.Fatalf("bound %d, which is inside a window this test is holding", got)
		}
		// FALLING BACK rather than refusing, and SAYING SO: the caller
		// warns off `probed`, because a session on an unexpected port hands
		// out connection files nobody's bookmark will match.
		if probed {
			t.Error("probed = true on a kernel-chosen port; the caller has nothing to warn about")
		}
	})

	t.Run("explicitPortIsExact", func(t *testing.T) {
		// --port N means N. Serving something else instead would break the
		// very bookmark the flag was passed to protect, so a busy port here
		// is an ERROR and not a fallback.
		probe, err := listenLoopback(0)
		if err != nil {
			t.Fatal(err)
		}
		busy := probe.Addr().(*net.TCPAddr).Port
		defer probe.Close() //nolint:errcheck

		if _, _, err := browseListen(busy); err == nil {
			t.Error("--port on a taken port started anyway")
		} else if !strings.Contains(err.Error(), fmt.Sprint(browsePortFirst)) {
			t.Errorf("the error does not point at the default probe: %v", err)
		}
		if _, _, err := browseListen(70000); err == nil {
			t.Error("--port 70000 was accepted")
		}
	})

	t.Run("negativeMeansEphemeral", func(t *testing.T) {
		// The opt-out, for somebody who wants no preference at all.
		ln, probed, err := browseListen(-1)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close() //nolint:errcheck
		if probed {
			t.Error("probed = true on an explicitly ephemeral bind")
		}
	})
}
