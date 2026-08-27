package pelcred

import (
	"context"
	"net/url"
	"os"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// Interactive SSO, and the one thing missing to make it comfortable.
//
// When no usable token is in the wallet, the Pelican client runs the OAuth2
// device flow: it prints a URL and a code to stderr and polls until the user
// has approved the request in a browser. On a laptop that means reading a
// URL off a terminal and getting it into a browser by hand, which on macOS
// is what /usr/bin/open exists to avoid.
//
// oauth2.AcquireToken does the printing with fmt.Fprintln and offers no
// callback, so today there is nothing for an embedder to hook. The pieces
// that would let pelfs run the flow itself ARE public — Config.AuthDevice,
// Config.Poll, and DeviceAuth's URL and code fields — but everything
// AROUND the flow is not: the scope path is computed by the unexported
// trimPath against the director's MaxScopeDepth, the anonymous OAuth client
// is registered by the unexported registerClient, and whether a token is
// good enough to use is decided by the unexported tokenIsAcceptable. Running
// our own flow means reimplementing all three, and the failure mode when our
// copy drifts from Pelican's is that Pelican judges our token unacceptable
// and starts its OWN device flow — so the user approves twice, which is the
// exact annoyance the feature set out to remove.
//
// So the browser opener lives here, complete and tested, and the wiring is
// one line the moment Pelican exposes a hook:
//
//	oauth2.SetVerificationURLHandler(pelcred.ShowVerificationURL)
//
// See docs/TODO.md ("keychain-agent") for the upstream patch that adds it.

// ShowVerificationURL must keep the exact shape of the hook it is written
// to be installed as (oauth2.VerificationURLHandler in the patch below), so
// that "add the replace and wire it up" stays a one-line change and a drift
// in the signature is a build failure here rather than a surprise later.
var _ func(url, userCode string) = ShowVerificationURL

// browserTimeout bounds the `open` call. Launching a browser is fire and
// forget as far as this process is concerned — the device flow is already
// polling — so all this bounds is how long a wedged LaunchServices can hold
// the goroutine.
const browserTimeout = 15 * time.Second

// ShowVerificationURL brings a device-flow verification URL to the user's
// browser. It has the signature of the Pelican hook it is meant to be
// installed as: verifyURL is the address to visit, and userCode is the code
// the user must type there, empty when the URL already carries it.
//
// It never reports failure, because failure is not a problem: Pelican has
// already printed the URL and the code to stderr by the time this runs, so
// a user whose browser did not open is in exactly the position they were in
// before this function existed. That is also why nothing here re-prints
// them — that would show every headless user the same URL twice.
func ShowVerificationURL(verifyURL, userCode string) {
	if !ShouldOpenBrowser(verifyURL) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), browserTimeout)
	defer cancel()
	if err := openBrowser(ctx, verifyURL); err != nil {
		ui.Debug("could not open a browser for the approval URL ({err}); the URL above is still good", "err", err)
		return
	}
	if userCode != "" {
		ui.Info("opened your browser at the approval page; the code to enter there is {code}", "code", userCode)
	} else {
		ui.Info("opened your browser at the approval page")
	}
}

// ShouldOpenBrowser decides whether opening a browser is the right thing to
// do for this URL, in this process.
//
// Every clause is a case where opening one is useless or wrong:
//
//   - PELFS_NO_BROWSER, the explicit opt-out.
//   - No person at the terminal (see Interactive): a background mount, a
//     daemon, a CI job, a container, root.
//   - An SSH session: the window would open on the machine at the far end
//     of the connection, where nobody is sitting.
//   - A URL that is not http(s): the verification URL comes off the wire
//     from an issuer, and handing an arbitrary scheme to `open` lets a
//     malicious or compromised issuer name a local application or a file
//     instead of a web page.
func ShouldOpenBrowser(verifyURL string) bool {
	if !browserSupported {
		return false
	}
	switch os.Getenv("PELFS_NO_BROWSER") {
	case "1", "true", "yes":
		return false
	}
	if !Interactive() || remoteSession() {
		return false
	}
	return httpURL(verifyURL)
}

// httpURL reports whether s is an absolute http or https URL with a host.
func httpURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
