//go:build !darwin

package pelcred

// defaultKeychain reports that there is no Keychain here.
//
// Linux gets nothing new from this package and loses nothing: on
// linux/amd64 Pelican already caches the wallet password in the kernel
// session keyring, which is the same comfort by another route. Everywhere
// else the behaviour is exactly what it was before this package existed —
// Pelican asks, and remembers for the life of the process.
func defaultKeychain() keychain { return nil }
