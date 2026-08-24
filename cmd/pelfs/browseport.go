package main

// THE PORT `pelfs browse` LISTENS ON.
//
// It is the first free port at or above 8443, and if all hundred of them
// are busy it is whatever the kernel hands out. That is what was asked
// for, in as many words: "I asked you to preferentially bind to a known
// port, such as 8443. Instead of using the kernel by binding to :0, try
// probing starting at 8443 and going up. If not found in 100 ports, use
// the kernel localhost:0 binding."
//
// # Why the port is not just where the browser goes
//
// It is baked into everything a session hands out (internal/davprofile):
//
//	Default Port          the .cyberduckprofile's port
//	Port, Hostname        the .duck bookmark's own connection details
//	OAuth Authorization
//	  Url / Token Url     http://127.0.0.1:<port>/oauth/{authorize,token}
//
// so an OS-chosen port made every generated profile and saved bookmark
// single-use, which is the report this replaced: "can we try to have a
// stable port so the CyberDuck bookmark is not one-time-use?"
//
// # What a PROBE gives, and what it takes away, which has to be said
//
// It gives a port a human can predict and type, and one that is the same
// on every machine. What it takes away is the thing a hash gave for free:
// a port that identified the VOLUME. `pelfs browse` on two volumes now
// lands on 8443 and 8444 in whatever order they started, so tomorrow's
// 8443 may be a different volume from today's — and a saved Cyberduck
// bookmark names a PORT.
//
// That is a real regression in a feature asked for last round, and it is
// handled rather than accepted, one layer up:
//
//   - THE PROFILE'S IDENTITY IS THE VOLUME, NOT THE PORT.
//     davprofile.Params.vendor() keys the `Vendor` (which is what a
//     bookmark's `Provider` names) on a digest of the volume URL. Two
//     volumes therefore install as two profiles, and volume A's bookmark
//     keeps resolving to volume A's profile — carrying volume A's
//     client_id — however the ports fell.
//   - SO THE MISMATCH BECOMES A REFUSAL, AND A LEGIBLE ONE. That client_id
//     names nothing in a session serving another volume, so
//     /oauth/authorize answers its "this is not an authorization request
//     pelfs issued" page — which now NAMES THE VOLUME THIS LISTENER IS
//     SERVING, because "wrong volume on a shared port" is otherwise
//     indistinguishable from "corrupt profile".
//
// The remaining cost is honest and unavoidable: a profile is only good
// while its volume keeps getting the same port. Start volume B first
// tomorrow and volume A's profile has to be downloaded again. It is
// recorded in docs/known-issues.md.
//
// # Why 8443, given that a developer may well be using it
//
// Because it was asked for, and because the probe makes the objection
// cheap: 8443 is the well-known alternate-HTTPS port, so something else
// having it is ORDINARY rather than exceptional, and the answer is 8444.
// The probe is a real bind on 127.0.0.1 (not a connect test, which races
// and answers a different question), IPv4, and the loser of a probe is
// closed immediately rather than left open.
//
// None of 8443-8542 is on Chromium's blocked-port list, so every port the
// probe can return is navigable. That had to be checked: a port a browser
// refuses to open would make the whole verb unusable, silently, on one
// platform.
//
// # A WELL-KNOWN PORT AND THE THREAT MODEL
//
// docs/design-webui.md's threat model says "a random port is not a secret
// … the random port is friction, not a control, and nothing in this design
// may rely on it". That claim was audited against the code again for a
// port that is not merely guessable but PUBLISHED, and it holds: the Host
// allowlist, CrossOriginProtection, the exact-Origin match, the provenance
// rule, the header-borne session token and the single-use tickets are all
// computed from or checked against the port the listener ACTUALLY got, and
// not one of them is weaker for the port being known in advance. Nothing
// anywhere hashes, seeds or salts anything with it. See that document's "A
// well-known port" note for the audit.
//
// What genuinely changes is squatting, and it changes in DEGREE rather
// than in kind: a local process could always guess the old derived port,
// and can now simply take 8443 before pelfs starts. A user's saved
// bookmark would then reach the squatter. That is not a new capability — a
// process running as the user can already read the volume, the state
// directory and the tokens — and pelfs does not silently cooperate with
// it: the bind fails, the probe moves on, and the session says which port
// it got.

import (
	"fmt"
	"net"
	"strconv"

	"github.com/bbockelm/pelfs/internal/ui"
)

const (
	// browsePortFirst is the port to prefer. Well-known, alternate-HTTPS,
	// and the one that was asked for by number.
	browsePortFirst = 8443

	// browsePortProbe is how many consecutive ports the probe tries before
	// giving up and letting the kernel choose. A hundred is enough that a
	// machine would need a hundred concurrent browse sessions (or a hundred
	// unrelated servers in that window) to exhaust it, and small enough
	// that exhausting it takes a hundred failed binds and no noticeable
	// time.
	browsePortProbe = 100
)

const browsePortUsage = "TCP port for the browse listener on 127.0.0.1: 0 (the default) takes the " +
	"first free port at or above 8443, so the URL and a saved Cyberduck profile keep working; " +
	"-1 takes any free port from the OS"

// browseListen binds the listener and says how the port was chosen.
//
// The three cases, and the difference between them is who chose:
//
//	want == 0   the probe: 8443, 8444, ... up to browsePortProbe ports. If
//	            every one of them is taken this falls back to an OS-chosen
//	            port with probed=false, because a `pelfs browse` that will
//	            not start is worse than one whose URL is unfamiliar — and
//	            the caller says so, since a silent fallback is the class of
//	            bug this file exists to avoid.
//	want < 0    an OS-chosen port, explicitly asked for. probed is false
//	            and there is nothing to report: nothing was preferred.
//	want > 0    an exact port the user named. A failure here is an ERROR,
//	            not a fallback: somebody who typed --port 9000 wants 9000,
//	            and quietly serving 54021 instead would break the bookmark
//	            they passed the flag to protect.
func browseListen(want int) (ln net.Listener, probed bool, err error) {
	switch {
	case want < 0:
		ln, err = listenLoopback(0)
		if err != nil {
			return nil, false, fmt.Errorf("browse listen: %w", err)
		}
		return ln, false, nil
	case want > 0:
		if want > 65535 {
			return nil, false, fmt.Errorf("--port %d is not a port", want)
		}
		ln, err = listenLoopback(want)
		if err != nil {
			return nil, false, fmt.Errorf("browse listen on 127.0.0.1:%d: %w — "+
				"something already has that port. Stop it, or leave --port off and pelfs "+
				"will take the first free port at or above %d",
				want, err, browsePortFirst)
		}
		return ln, false, nil
	}
	for p := browsePortFirst; p < browsePortFirst+browsePortProbe && p <= 65535; p++ {
		if ln, err = listenLoopback(p); err == nil {
			return ln, true, nil
		}
	}
	ln, err = listenLoopback(0)
	if err != nil {
		return nil, false, fmt.Errorf("browse listen: %w", err)
	}
	return ln, false, nil
}

// sayBrowsePort reports the port and, when the probe did not get one, that
// it did not. The port is on stdout already inside the launch URL; this is
// the line that says WHICH MECHANISM chose it, which is the difference
// between "8444, because 8443 was busy" and "54021, because a hundred
// ports were".
func sayBrowsePort(port, want int, probed bool) {
	switch {
	case want > 0:
		ui.Info("browse listener on 127.0.0.1:{port} (--port)", "port", port)
	case want < 0:
		ui.Info("browse listener on 127.0.0.1:{port} (--port -1: chosen by the OS)", "port", port)
	case probed && port == browsePortFirst:
		ui.Info("browse listener on 127.0.0.1:{port}", "port", port)
	case probed:
		ui.Info("browse listener on 127.0.0.1:{port}: {first} was taken, so this is the first "+
			"free port above it. A Cyberduck profile downloaded from an earlier session on a "+
			"different port names that port and will not reach this one — download a fresh one.",
			"port", port, "first", browsePortFirst)
	default:
		ui.Warn("ports {first}-{last} are all in use, so this session is on {port}, which the OS "+
			"chose. Every connection file this session generates names {port}, so a Cyberduck "+
			"profile or bookmark kept from an earlier session will not match it.",
			"first", browsePortFirst, "last", browsePortFirst+browsePortProbe-1, "port", port)
	}
}

// listenLoopback is the one bind, in one place. tcp4 explicitly and
// 127.0.0.1 rather than 0.0.0.0: internal/nfsmount.Serve's comment applies
// word for word ("a hostname like 'localhost' can resolve to ::1 where
// nothing listens"), and binding the wildcard address would put this UI on
// the machine's LAN address — a mistake that turns a local threat model into
// a network one.
func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
}
