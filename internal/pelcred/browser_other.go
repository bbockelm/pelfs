//go:build !darwin

package pelcred

import (
	"context"
	"errors"
)

// This package's browser opener is macOS-only on purpose. Linux's
// equivalent is xdg-open, which is not part of a base install, is absent
// from every container pelfs runs in, and reaches a browser only when a
// desktop session is there to receive it — so the honest Linux behaviour is
// the one that was there before: print the URL, which Pelican already does.
const browserSupported = false

func openBrowser(context.Context, string) error {
	return errors.New("opening a browser is only implemented on macOS")
}
