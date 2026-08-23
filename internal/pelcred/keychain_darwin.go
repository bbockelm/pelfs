//go:build darwin

package pelcred

import "os"

// securityBinary is /usr/bin/security, part of every macOS install. It is
// named by absolute path deliberately: this call decides whether a stored
// secret is handed over, so it must not be satisfiable by anything a
// modified PATH points at.
const securityBinary = "/usr/bin/security"

// defaultKeychain returns the macOS Keychain, or nil if /usr/bin/security
// is not there — which would mean a macOS install missing part of itself,
// but a missing tool is a reason to do nothing rather than to fail a mount.
func defaultKeychain() keychain {
	if _, err := os.Stat(securityBinary); err != nil {
		return nil
	}
	return securityKeychain{run: execRunner(securityBinary)}
}
