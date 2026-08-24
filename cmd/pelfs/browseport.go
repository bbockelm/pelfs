package main

// THE PORT `pelfs browse` LISTENS ON, AND WHY IT IS NOT `:0` ANY MORE.
//
// It used to be. `net.Listen("tcp4", "127.0.0.1:0")`, an OS-chosen ephemeral
// port, once per session — which is right for a listener nobody has to name
// twice and wrong for this one, because the port is not just where the
// browser goes. It is baked into everything `pelfs browse` hands out:
//
//	Default Port      the .cyberduckprofile's port
//	Vendor            org.pelicanplatform.pelfs.local.<port>, which is the
//	                  string a .duck bookmark's Provider names to bind
//	                  itself to that profile
//	Port, Hostname    the .duck bookmark's own connection details
//	OAuth Authorization Url / Token Url
//	                  http://127.0.0.1:<port>/oauth/{authorize,token}
//
// (internal/davprofile). So a fresh port per session meant every generated
// profile and every saved bookmark was dead the moment the session that
// made it exited. The report that prompted this said it exactly: "can we
// try to have a stable port so the CyberDuck bookmark is not one-time-use?"
//
// # The scheme
//
// The port is DERIVED FROM THE VOLUME, so it is stable across sessions and
// different for different volumes, and it is the same derivation the state
// directory uses (cmd/pelfs/daemon.go's volDirIn): SHA-256 of the prefix
// URL. Same prefix, same port, on this machine and any other, for as long
// as portSalt does not change.
//
//	port = portBase + (sha256(portSalt || prefix) mod portSpan)
//
// portSalt is there so that this mapping can be changed deliberately — bump
// the salt, every volume moves — rather than by accident when somebody
// edits the hash input for an unrelated reason.
//
// # Why THIS range
//
// 61000–65535, which is 4536 ports, and the choice is about what else on
// the machine hands out ports:
//
//   - It is inside IANA's Dynamic/Private range (49152–65535), so it
//     collides with no registered service.
//   - It is ABOVE Linux's default ephemeral range. `net.ipv4.ip_local_port_range`
//     ships as 32768 60999, so an outbound connection on a Linux box is
//     never given a port in this window and cannot be sitting on ours.
//     macOS's ephemeral range is 49152–65535 and DOES overlap, which is
//     what the collision path below is for rather than something to solve
//     by picking a different window (every window overlaps something).
//   - No port in it is on Chromium's blocked-port list, so the URL is
//     navigable. A port that a browser refuses to open would make the whole
//     verb unusable, silently, on one platform.
//
// # Why a predictable port costs nothing, which had to be checked
//
// docs/design-webui.md's threat model already says it in as many words:
// "a random port is not a secret … the random port is friction, not a
// control, and nothing in this design may rely on it". That claim was
// audited against the code before this change landed, control by control,
// and it holds — see the "Threat model" section's F-notes and A2, and
// docs/design-webui.md's "A stable port" note for the audit itself. The
// short version: the Host allowlist, CrossOriginProtection, the exact-Origin
// match, the provenance rule, the header-borne session token and the
// single-use tickets are all computed from or checked against the port the
// listener ACTUALLY got, and not one of them is weaker for the port being
// guessable. Nothing anywhere hashes, seeds or salts anything with it.
//
// The one thing that genuinely changes is worth stating rather than
// glossing: a local process could now SQUAT the port before pelfs starts,
// and a user's saved bookmark would then reach the squatter instead. That
// is not a new capability — a process running as the user can already read
// the volume, the state directory and the tokens — and pelfs does not
// silently cooperate with it: the bind fails, and browseListen says so and
// falls back rather than pretending. It is recorded in
// docs/known-issues.md.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

const (
	// portBase and portSpan are the window; see the file comment for why
	// this one.
	portBase = 61000
	portSpan = 65536 - portBase

	// portSalt versions the mapping. Change it only on purpose: every
	// volume's port moves, and every bookmark a user saved stops
	// resolving.
	portSalt = "pelfs-browse-port-v1\x00"
)

const browsePortUsage = "TCP port for the browse listener on 127.0.0.1: 0 (the default) " +
	"derives a stable port from the volume, so a saved Cyberduck bookmark keeps working; " +
	"-1 takes any free port from the OS"

// browsePort is the stable port for a volume. Deterministic, and the ONLY
// input is the prefix URL, so two pelfs installs and two pelfs versions
// agree.
func browsePort(prefix string) int {
	sum := sha256.Sum256([]byte(portSalt + prefix))
	// The low 8 bytes, as an integer, modulo the span. A modulo bias over
	// 4536 values out of 2^64 is not a property anything here depends on;
	// the requirement is "the same answer every time", not uniformity.
	return portBase + int(binary.BigEndian.Uint64(sum[:8])%uint64(portSpan))
}

// browseListen binds the listener and reports which port it wanted but did
// not get.
//
// The three cases, and the difference between them is who chose the port:
//
//	want == 0   the volume's stable port, and if it is taken this FALLS
//	            BACK to an OS-chosen one with taken set. Falling back
//	            rather than refusing, because a `pelfs browse` that will
//	            not start is worse than one whose bookmark needs
//	            regenerating — but the caller warns, because a silent
//	            fallback is the bug this whole file exists to fix, one
//	            level down.
//	want < 0    an OS-chosen port, explicitly asked for. No fallback to
//	            report because nothing was preferred.
//	want > 0    an exact port the user named. A failure here is an ERROR,
//	            not a fallback: somebody who typed --port 61234 wants 61234,
//	            and quietly serving 54021 instead would break the bookmark
//	            they passed the flag to protect.
func browseListen(prefix string, want int) (ln net.Listener, taken int, err error) {
	switch {
	case want < 0:
		ln, err = listenLoopback(0)
		if err != nil {
			return nil, 0, fmt.Errorf("browse listen: %w", err)
		}
		return ln, 0, nil
	case want > 0:
		if want > 65535 {
			return nil, 0, fmt.Errorf("--port %d is not a port", want)
		}
		ln, err = listenLoopback(want)
		if err != nil {
			return nil, 0, fmt.Errorf("browse listen on 127.0.0.1:%d: %w — "+
				"something already has that port. Stop it, or leave --port off "+
				"and pelfs will use this volume's own stable port (%d)",
				want, err, browsePort(prefix))
		}
		return ln, 0, nil
	}
	stable := browsePort(prefix)
	if ln, err = listenLoopback(stable); err == nil {
		return ln, 0, nil
	}
	ln, err = listenLoopback(0)
	if err != nil {
		return nil, 0, fmt.Errorf("browse listen: %w", err)
	}
	return ln, stable, nil
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
