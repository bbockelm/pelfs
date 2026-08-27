// Package pelcred keeps the Pelican credential wallet's password in the
// macOS Keychain, so a mount stops asking for it.
//
// # What the password is, and why it is asked for at all
//
// The Pelican client keeps its OAuth2 refresh tokens and client secrets in
// one file — the "credential wallet" — whose private key is encrypted with
// a password the user chose. Every operation that needs a federation token
// has to open that wallet, and Pelican's own cache for the password is a
// process-lifetime variable on every platform except linux/amd64, where it
// is the kernel session keyring. macOS therefore gets the weakest version:
// the password is remembered until the process exits and not one moment
// longer, so every `pelfs shell`, every `pelfs mount`, every `pelfs gc`
// asks again.
//
// The macOS Keychain is exactly the store Pelican is missing, and reaching
// it needs no library: /usr/bin/security ships with the OS, which matters
// because pelfs is built CGO_ENABLED=0 and a Keychain binding is cgo.
//
// # The seam, and why there is no Pelican patch here
//
// config.GetCredentialConfigContents asks config.TryGetPassword FIRST and
// only falls back to the interactive terminal prompt when that comes back
// empty. config.SavePassword is public. So pre-seeding the cache from the
// Keychain is enough: Pelican finds a password already there and never
// prompts. Nothing in Pelican has to change.
//
// # What this package will not do
//
// It never makes UNENCRYPTED storage easier to reach. Pelican has two ways
// to skip the password entirely — config.SetEmptyPassword and the
// PELICAN_CLIENT_NOPASSWORD environment variable — and both write refresh
// tokens and client secrets to disk in the clear (Pelican warns when they
// are used). This package is the opposite trade: keep the wallet encrypted
// and put the key somewhere the OS guards. When the wallet on disk is
// already unencrypted, everything here turns itself off — there is no
// password to remember, and offering to store an empty one in the Keychain
// would be theatre.
//
// # Opt-out, not opt-in
//
// Reading is on by default. An absent Keychain item is not an error and
// costs one failed lookup, so a user who has never used this feature sees
// no change at all; a user who has one gets what they asked for without
// having to remember a flag. Writing is never silent: it is offered, once,
// at the moment the user has just typed a password, and only at a terminal.
// PELFS_NO_KEYCHAIN=1 turns both halves off, and is the answer to "stop
// asking me".
package pelcred

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"os"

	"github.com/bbockelm/pelfs/internal/ui"
)

// Disabled reports whether the user has switched the Keychain integration
// off. It is checked on every entry point rather than cached so that a test
// (or a subshell) can set it without restarting the process.
func Disabled() bool {
	switch os.Getenv("PELFS_NO_KEYCHAIN") {
	case "1", "true", "yes":
		return true
	}
	return false
}

// wallet is the slice of Pelican's credential-wallet API this package
// drives. It is an interface for one reason: so the tests can drive the
// whole state machine — stale password, wrong password, first use — without
// a Pelican config, a real wallet file, or a real Keychain. The production
// implementation (pelicanWallet, in wallet.go) is three lines per method.
type wallet interface {
	// Path is the credential file's absolute path. It is the Keychain
	// item's account name, so two wallets never share one item.
	Path() (string, error)
	// Encrypted reports whether a wallet exists AND is password-protected.
	// False means there is nothing for this package to do.
	Encrypted() (bool, error)
	// Cached returns the password Pelican currently has in memory, empty
	// if none. The slice is Pelican's, not ours: never zero it.
	Cached() ([]byte, error)
	// Seed puts a password into Pelican's cache. Pelican keeps the slice
	// by reference, so the caller must not zero or reuse it afterwards.
	Seed([]byte) error
	// Forget drops (and zeroes) the cached password.
	Forget()
	// Open reads the wallet with whatever password is cached, prompting
	// the user when none is. The contents are discarded; only the error
	// matters here.
	Open() error
	// WrongPassword reports whether an Open error was specifically "that
	// password does not decrypt this wallet".
	WrongPassword(error) bool
}

// keychain is the Keychain operations this package needs, injected for the
// same reason as wallet.
type keychain interface {
	// Lookup returns the stored password for account, or nil when there is
	// no such item. A denied authorization prompt is an error, not nil.
	Lookup(ctx context.Context, account string) ([]byte, error)
	// Save writes password for account, replacing any existing item.
	Save(ctx context.Context, account string, password []byte) error
	// Describe names the item the way a user would find it in Keychain
	// Access, for messages that tell them what to go and revoke.
	Describe(account string) string
}

// asker asks the user a yes/no question. It returns false for "no" and for
// "nobody is there to answer".
type asker interface {
	Confirm(prompt string) bool
}

// Unlock seeds the Pelican credential wallet's password from the macOS
// Keychain, and returns a function to call once the caller has finished
// with Pelican — which offers to remember a password the user typed.
//
// The returned function is never nil, so the call reads:
//
//	remember := pelcred.Unlock(ctx)
//	primeCredential(ctx, prefix)
//	remember()
//
// Both halves are best-effort and neither ever fails the caller: the worst
// outcome of everything here going wrong is the password prompt the user
// was getting anyway.
func Unlock(ctx context.Context) (remember func()) {
	kc := defaultKeychain()
	if kc == nil || Disabled() {
		return func() {}
	}
	return unlock(ctx, pelicanWallet{}, kc, terminalAsker{})
}

// unlock is Unlock with its three collaborators supplied, which is the form
// the tests drive.
func unlock(ctx context.Context, w wallet, kc keychain, ask asker) (remember func()) {
	noop := func() {}

	encrypted, err := w.Encrypted()
	if err != nil {
		ui.Debug("cannot tell whether the Pelican credential wallet is encrypted; leaving the Keychain alone ({err})", "err", err)
		return noop
	}
	account, err := w.Path()
	if err != nil || account == "" {
		ui.Debug("cannot locate the Pelican credential wallet; leaving the Keychain alone ({err})", "err", err)
		return noop
	}

	// No wallet yet, or an unencrypted one. There is nothing to unlock.
	// Pelican may still CREATE an encrypted wallet during the work that
	// follows (a first-ever token acquisition asks the user to choose a
	// password), so the second half still runs: it re-checks the state it
	// is offering to remember.
	if !encrypted {
		return func() { offerToRemember(ctx, w, kc, ask, account, nil) }
	}

	if cached, err := w.Cached(); err == nil && len(cached) > 0 {
		// Something in this process already knows the password. Reading
		// the Keychain could only overwrite a working password with a
		// stale one, and would spend an authorization prompt to do it.
		ui.Debug("the wallet password is already cached in this process; not consulting the Keychain")
		return noop
	}

	// One lookup per process, ever. If the item's access control does not
	// already trust /usr/bin/security, this raises a GUI authorization
	// prompt, and a program that retries turns one prompt into a barrage.
	stored, err := kc.Lookup(ctx, account)
	if err != nil {
		// Includes the user denying the prompt. Say so once, at debug
		// level: the visible consequence is Pelican's own password
		// prompt, which explains itself.
		ui.Debug("no wallet password from the Keychain ({err}); Pelican will ask for it", "err", err)
		return func() { offerToRemember(ctx, w, kc, ask, account, nil) }
	}
	if len(stored) == 0 {
		ui.Debug("no Keychain item holds this wallet's password yet ({item})", "item", kc.Describe(account))
		return func() { offerToRemember(ctx, w, kc, ask, account, nil) }
	}

	// Fingerprint rather than keep the plaintext: the only thing this
	// package ever needs to know later is "is the password Pelican has now
	// the one I supplied", and a hash answers that without a second copy
	// of the secret living in our own memory for the life of the mount.
	seeded := fingerprint(stored)

	// From here on the slice belongs to Pelican (SavePassword keeps it by
	// reference), so it is not ours to zero. w.Forget() is what zeroes it.
	if err := w.Seed(stored); err != nil {
		ui.Debug("could not seed the wallet password from the Keychain ({err})", "err", err)
		return func() { offerToRemember(ctx, w, kc, ask, account, nil) }
	}

	// Prove the password before handing the process off. Doing it here,
	// once, is what makes a stale Keychain item a single clear warning
	// instead of an authorization failure surfacing later as a token error
	// in the middle of filesystem I/O.
	if err := w.Open(); err == nil {
		ui.Debug("unlocked the Pelican credential wallet from the Keychain ({item})", "item", kc.Describe(account))
		return noop
	} else if !w.WrongPassword(err) {
		// The wallet is unreadable for some other reason (corrupt file,
		// unreadable path). Not our problem to diagnose, and NOT a reason
		// to throw away a password that may well be correct.
		ui.Debug("could not read the credential wallet ({err})", "err", err)
		return noop
	}

	// The Keychain item is stale — the user changed the wallet password, or
	// replaced the wallet. Drop it (Forget zeroes the bytes we handed over)
	// and let Pelican ask. Retrying the same stored password would fail
	// identically every time, so it is dropped, not retried.
	w.Forget()
	ui.Warn("the wallet password in your Keychain no longer opens {wallet}; you will be asked for the current one. "+
		"The stale item is {item} — remove it in Keychain Access if you would rather it were gone",
		"wallet", account, "item", kc.Describe(account))

	if err := w.Open(); err != nil {
		// Pelican asked and did not get a working password (wrong again,
		// or no terminal to ask at). Nothing to remember.
		ui.Debug("the wallet is still locked after prompting ({err})", "err", err)
		return noop
	}
	// Pelican's own success path caches whatever the user typed, so the
	// offer below will find it and can update the stale item in place.
	return func() { offerToRemember(ctx, w, kc, ask, account, seeded) }
}

// offerToRemember asks whether to put the password the user just typed into
// the Keychain. seeded is the fingerprint of the password this package
// supplied, or nil if it supplied none; a cached password matching it was
// not typed by anyone and is already stored.
func offerToRemember(ctx context.Context, w wallet, kc keychain, ask asker, account string, seeded []byte) {
	if Disabled() {
		return
	}
	// Only ever offer to store the key to a wallet that is actually
	// locked. An unencrypted wallet has no password worth keeping, and
	// storing the empty string would make the Keychain claim to hold a
	// secret that is not one.
	if encrypted, err := w.Encrypted(); err != nil || !encrypted {
		return
	}
	cached, err := w.Cached()
	if err != nil || len(cached) == 0 {
		return
	}
	if seeded != nil && subtle.ConstantTimeCompare(seeded, fingerprint(cached)) == 1 {
		// This is our own seed coming back. Already in the Keychain.
		return
	}

	verb, updating := "Save", false
	if seeded != nil {
		verb, updating = "Update", true
	}
	if !ask.Confirm(verb + " this password in your macOS Keychain so pelfs can open the wallet without asking? " +
		"[y/N] (set PELFS_NO_KEYCHAIN=1 to stop being asked) ") {
		return
	}
	if err := kc.Save(ctx, account, cached); err != nil {
		ui.Warn("could not write the wallet password to your Keychain ({err})", "err", err)
		return
	}
	if updating {
		ui.Info("updated the wallet password in your Keychain ({item})", "item", kc.Describe(account))
	} else {
		ui.Info("saved the wallet password to your Keychain ({item}); remove that item to revoke it",
			"item", kc.Describe(account))
	}
}

// fingerprint is a comparison handle for a password: enough to answer "is
// this the same secret" and useless for anything else.
func fingerprint(password []byte) []byte {
	sum := sha256.Sum256(password)
	return sum[:]
}
