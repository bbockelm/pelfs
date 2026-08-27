package pelcred

import (
	"errors"

	"github.com/pelicanplatform/pelican/config"
)

// pelicanWallet is the real credential wallet: a thin naming layer over the
// public Pelican config API, so the rest of this package can be tested
// without one.
//
// Every function it calls is exported by Pelican today. That is the whole
// reason this feature needs no fork.
type pelicanWallet struct{}

var _ wallet = pelicanWallet{}

func (pelicanWallet) Path() (string, error) { return config.GetEncryptedConfigName() }

// Encrypted is HasEncryptedPassword, which answers false both for "no
// wallet" and for "a wallet whose private key is stored unprotected".
// Neither has a password worth keeping.
func (pelicanWallet) Encrypted() (bool, error) { return config.HasEncryptedPassword() }

func (pelicanWallet) Cached() ([]byte, error) { return config.TryGetPassword() }

// Seed hands the password to Pelican's password cache, which on macOS is a
// process-lifetime variable. Pelican retains the SLICE, so the caller loses
// ownership of the bytes here.
func (pelicanWallet) Seed(password []byte) error { return config.SavePassword(password) }

// Forget clears the cache; Pelican zeroes the bytes it was holding on the
// way out, which is what disposes of a password seeded from the Keychain.
func (pelicanWallet) Forget() { config.ForgetPassword() }

// Open reads the wallet, which is the operation that actually tests the
// password: GetCredentialConfigContents consults TryGetPassword first and
// prompts the user only when nothing is cached.
//
// The contents are deliberately dropped. This package is not interested in
// the credentials, only in whether the password opened them.
func (pelicanWallet) Open() error {
	_, err := config.GetCredentialConfigContents()
	return err
}

func (pelicanWallet) WrongPassword(err error) bool {
	return errors.Is(err, config.ErrIncorrectPassword)
}
