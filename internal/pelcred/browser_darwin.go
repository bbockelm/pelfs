//go:build darwin

package pelcred

import (
	"context"
	"os/exec"
)

// openBinary is /usr/bin/open, macOS's "hand this to whatever handles it".
// Named by absolute path for the same reason as /usr/bin/security: the
// argument comes off the network, so what runs must not be decided by PATH.
const openBinary = "/usr/bin/open"

const browserSupported = true

// openBrowser hands the URL to the user's default browser.
//
// The URL is passed after "--" so that a URL beginning with a dash cannot
// be read as an option to open, and `open` is given no other arguments: no
// -a to name an application (the user's default is the right choice) and no
// --background (the user has to act on this page, so it should come
// forward).
func openBrowser(ctx context.Context, verifyURL string) error {
	return exec.CommandContext(ctx, openBinary, "--", verifyURL).Run()
}
