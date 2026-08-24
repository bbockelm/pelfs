package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// TestBrowsePortIsStableAndPerVolume is the whole contract of the derivation,
// and every assertion in it is a property a saved Cyberduck bookmark depends
// on. The report that prompted it: "can we try to have a stable port so the
// CyberDuck bookmark is not one-time-use?"
func TestBrowsePortIsStableAndPerVolume(t *testing.T) {
	const a = "pelican://osg-htc.org/user/bbockelman"
	const b = "pelican://osg-htc.org/user/bbockelman/other"

	// 1. STABLE. The same prefix, twice, is the same port — this is the
	// property the bookmark rests on, and the one an OS-chosen port did not
	// have.
	if browsePort(a) != browsePort(a) {
		t.Fatal("browsePort is not deterministic")
	}

	// 2. PER VOLUME. Two volumes must not collide, or the second `pelfs
	// browse` a user starts silently takes the first one's port and its
	// profile's Vendor with it.
	if browsePort(a) == browsePort(b) {
		t.Errorf("two volumes derive the same port %d", browsePort(a))
	}

	// 3. IN THE WINDOW, for every input rather than for the two above. The
	// range is the point (see the file comment on why 61000-65535), and a
	// modulo that could land below the base or above 65535 would produce a
	// port the OS hands out to outbound connections or no port at all.
	for i := 0; i < 20000; i++ {
		prefix := fmt.Sprintf("pelican://example.org/vol/%d", i)
		p := browsePort(prefix)
		if p < portBase || p > 65535 {
			t.Fatalf("browsePort(%q) = %d, outside %d-65535", prefix, p, portBase)
		}
	}

	// 4. PINNED. A change to the salt or the hash input moves every user's
	// port and breaks every bookmark they saved, so it has to be a change
	// somebody makes on purpose and not a side effect. If this fails and you
	// meant it, bump portSalt and say so in the CHANGELOG.
	if got, want := browsePort(a), 61767; got != want {
		t.Errorf("browsePort(%q) = %d, want %d — the derivation moved, and with "+
			"it every saved Cyberduck bookmark. Bump portSalt deliberately or "+
			"put the input back.", a, got, want)
	}
}

// TestBrowseListen covers the three ways a port gets chosen and, for each,
// what happens when it is already taken — which is the case the report calls
// "a stale session, or another tool" and the one that has to say something
// useful rather than fail obscurely.
func TestBrowseListen(t *testing.T) {
	const prefix = "pelican://example.org/user/someone"

	t.Run("stablePortWhenFree", func(t *testing.T) {
		ln, taken, err := browseListen(prefix, 0)
		if err != nil {
			t.Skipf("cannot bind this volume's stable port on this host: %v", err)
		}
		defer ln.Close() //nolint:errcheck
		if taken != 0 {
			t.Errorf("fell back from port %d on a free port", taken)
		}
		if got := ln.Addr().(*net.TCPAddr).Port; got != browsePort(prefix) {
			t.Errorf("bound %d, want the derived %d", got, browsePort(prefix))
		}
	})

	t.Run("fallsBackAndSaysSoWhenTheStablePortIsTaken", func(t *testing.T) {
		// Sit on it, which is exactly what a stale `pelfs browse` does.
		squatter, err := listenLoopback(browsePort(prefix))
		if err != nil {
			t.Skipf("cannot bind this volume's stable port on this host: %v", err)
		}
		defer squatter.Close() //nolint:errcheck

		ln, taken, err := browseListen(prefix, 0)
		if err != nil {
			t.Fatalf("browseListen refused to start at all: %v", err)
		}
		defer ln.Close() //nolint:errcheck
		// FALLING BACK rather than refusing: a `pelfs browse` that will not
		// start is worse than one whose bookmark needs regenerating. The
		// caller is what warns, and `taken` is how it knows to.
		if taken != browsePort(prefix) {
			t.Errorf("taken = %d, want %d — the caller has nothing to warn about",
				taken, browsePort(prefix))
		}
		if got := ln.Addr().(*net.TCPAddr).Port; got == browsePort(prefix) {
			t.Errorf("bound the taken port %d", got)
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

		if _, _, err := browseListen(prefix, busy); err == nil {
			t.Error("--port on a taken port started anyway")
		} else if !strings.Contains(err.Error(), fmt.Sprint(browsePort(prefix))) {
			t.Errorf("the error does not offer the volume's own stable port: %v", err)
		}
		if _, _, err := browseListen(prefix, 70000); err == nil {
			t.Error("--port 70000 was accepted")
		}
	})

	t.Run("negativeMeansEphemeral", func(t *testing.T) {
		// The opt-out, for somebody who wants the old behaviour: no derived
		// port, nothing to report.
		ln, taken, err := browseListen(prefix, -1)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close() //nolint:errcheck
		if taken != 0 {
			t.Errorf("taken = %d on an explicitly ephemeral bind", taken)
		}
		if got := ln.Addr().(*net.TCPAddr).Port; got == browsePort(prefix) {
			t.Errorf("--port -1 bound the derived port %d anyway", got)
		}
	})
}
