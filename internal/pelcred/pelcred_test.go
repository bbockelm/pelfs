package pelcred

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// errWrongPassword stands in for config.ErrIncorrectPassword.
var errWrongPassword = errors.New("incorrect password")

// fakeWallet is a credential wallet whose password is known to the test.
type fakeWallet struct {
	real      []byte // the password that actually opens it; nil means unencrypted
	cached    []byte // what Pelican has in memory
	typed     []byte // what the user types when prompted; nil means "no terminal"
	opens     int    // how many times Open was called
	forgotten int
}

func (w *fakeWallet) Path() (string, error)      { return "/wallet/client-credentials.pem", nil }
func (w *fakeWallet) Encrypted() (bool, error)   { return w.real != nil, nil }
func (w *fakeWallet) Cached() ([]byte, error)    { return w.cached, nil }
func (w *fakeWallet) Seed(p []byte) error        { w.cached = p; return nil }
func (w *fakeWallet) WrongPassword(e error) bool { return errors.Is(e, errWrongPassword) }

func (w *fakeWallet) Forget() {
	// Pelican zeroes the bytes it was holding; so does this, because the
	// production code relies on it to dispose of a seed it handed over.
	for i := range w.cached {
		w.cached[i] = 0
	}
	w.cached = nil
	w.forgotten++
}

// Open mirrors GetCredentialConfigContents: it uses the cached password if
// there is one, otherwise it prompts, and it caches a password the user
// typed successfully.
func (w *fakeWallet) Open() error {
	w.opens++
	if w.real == nil {
		return nil
	}
	if len(w.cached) > 0 {
		if bytes.Equal(w.cached, w.real) {
			return nil
		}
		return errWrongPassword
	}
	if w.typed == nil {
		return errors.New("not connected to a terminal")
	}
	if !bytes.Equal(w.typed, w.real) {
		return errWrongPassword
	}
	w.cached = append([]byte(nil), w.typed...)
	return nil
}

// fakeKeychain records what was stored and what was asked for.
type fakeKeychain struct {
	items   map[string][]byte
	lookups int
	saves   int
	saved   []byte
	lookErr error
}

func newFakeKeychain() *fakeKeychain { return &fakeKeychain{items: map[string][]byte{}} }

func (k *fakeKeychain) Lookup(_ context.Context, account string) ([]byte, error) {
	k.lookups++
	if k.lookErr != nil {
		return nil, k.lookErr
	}
	if v, ok := k.items[account]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, nil
}

func (k *fakeKeychain) Save(_ context.Context, account string, password []byte) error {
	k.saves++
	k.saved = append([]byte(nil), password...)
	k.items[account] = k.saved
	return nil
}

func (k *fakeKeychain) Describe(account string) string { return "item(" + account + ")" }

// fakeAsker answers every question the same way and counts them.
type fakeAsker struct {
	yes   bool
	asked int
}

func (a *fakeAsker) Confirm(string) bool { a.asked++; return a.yes }

func TestKeychainPasswordMeansPelicanNeverPrompts(t *testing.T) {
	w := &fakeWallet{real: []byte("hunter2")}
	kc := newFakeKeychain()
	kc.items["/wallet/client-credentials.pem"] = []byte("hunter2")
	ask := &fakeAsker{yes: true}

	unlock(context.Background(), w, kc, ask)()

	if !bytes.Equal(w.cached, []byte("hunter2")) {
		t.Fatalf("wallet password was not seeded from the Keychain; cached=%q", w.cached)
	}
	if w.forgotten != 0 {
		t.Errorf("a working Keychain password was thrown away")
	}
	// The whole point: nothing was asked of the user, and nothing was
	// written back to a Keychain that already holds the right value.
	if ask.asked != 0 {
		t.Errorf("asked the user %d questions with a working stored password", ask.asked)
	}
	if kc.saves != 0 {
		t.Errorf("rewrote a Keychain item that was already correct")
	}
}

func TestStalePasswordIsDroppedAndOfferedForUpdate(t *testing.T) {
	w := &fakeWallet{real: []byte("current"), typed: []byte("current")}
	kc := newFakeKeychain()
	kc.items["/wallet/client-credentials.pem"] = []byte("old")
	ask := &fakeAsker{yes: true}

	unlock(context.Background(), w, kc, ask)()

	if w.forgotten == 0 {
		t.Errorf("the stale password was left in Pelican's cache")
	}
	if !bytes.Equal(kc.saved, []byte("current")) {
		t.Errorf("the Keychain was not updated to the password that works; saved=%q", kc.saved)
	}
	if kc.saves != 1 {
		t.Errorf("saved %d times, want exactly one update", kc.saves)
	}
	// The stale password must be tried once and never again: a retry loop
	// on a password that cannot work is what makes this feature a
	// liability rather than a comfort.
	if kc.lookups != 1 {
		t.Errorf("consulted the Keychain %d times, want 1", kc.lookups)
	}
	if w.opens != 2 {
		t.Errorf("opened the wallet %d times, want 2 (stale attempt, then the prompt)", w.opens)
	}
}

func TestStalePasswordWithNoTerminalDoesNotLoop(t *testing.T) {
	// typed == nil: nobody is there to answer Pelican's prompt.
	w := &fakeWallet{real: []byte("current")}
	kc := newFakeKeychain()
	kc.items["/wallet/client-credentials.pem"] = []byte("old")
	ask := &fakeAsker{yes: true}

	unlock(context.Background(), w, kc, ask)()

	if w.opens != 2 {
		t.Errorf("opened the wallet %d times, want 2", w.opens)
	}
	if kc.saves != 0 {
		t.Errorf("stored something after never learning a working password")
	}
	if ask.asked != 0 {
		t.Errorf("asked to store a password it does not have")
	}
}

func TestTypedPasswordIsOfferedToTheKeychainOnce(t *testing.T) {
	w := &fakeWallet{real: []byte("hunter2"), typed: []byte("hunter2")}
	kc := newFakeKeychain()
	ask := &fakeAsker{yes: true}

	remember := unlock(context.Background(), w, kc, ask)
	// Stand in for the Pelican work between the two halves: it prompts the
	// user, who types the right password, and Pelican caches it.
	if err := w.Open(); err != nil {
		t.Fatalf("wallet did not open after prompting: %v", err)
	}
	remember()

	if ask.asked != 1 {
		t.Fatalf("asked %d times, want exactly one offer", ask.asked)
	}
	if !bytes.Equal(kc.saved, []byte("hunter2")) {
		t.Errorf("saved %q, want the password the user typed", kc.saved)
	}
}

func TestDecliningStoresNothing(t *testing.T) {
	w := &fakeWallet{real: []byte("hunter2"), typed: []byte("hunter2")}
	kc := newFakeKeychain()
	ask := &fakeAsker{yes: false}

	remember := unlock(context.Background(), w, kc, ask)
	_ = w.Open()
	remember()

	if ask.asked != 1 {
		t.Errorf("asked %d times, want one", ask.asked)
	}
	if kc.saves != 0 {
		t.Errorf("stored a password after the user said no")
	}
}

func TestUnencryptedWalletIsLeftAlone(t *testing.T) {
	// real == nil: the wallet's key is on disk unprotected, which is what
	// PELICAN_CLIENT_NOPASSWORD produces. There is no password to keep,
	// and offering to store the empty one would put a Keychain item there
	// that claims to hold a secret.
	w := &fakeWallet{}
	kc := newFakeKeychain()
	ask := &fakeAsker{yes: true}

	unlock(context.Background(), w, kc, ask)()

	if kc.lookups != 0 || kc.saves != 0 {
		t.Errorf("touched the Keychain for an unencrypted wallet (%d lookups, %d saves)", kc.lookups, kc.saves)
	}
	if ask.asked != 0 {
		t.Errorf("asked the user about a wallet with no password")
	}
}

func TestAlreadyCachedPasswordSkipsTheKeychain(t *testing.T) {
	// Some earlier step in this process already knows the password. A
	// lookup here could only replace a working password with a stale one,
	// and would spend a GUI authorization prompt to do it.
	w := &fakeWallet{real: []byte("hunter2"), cached: []byte("hunter2")}
	kc := newFakeKeychain()
	kc.items["/wallet/client-credentials.pem"] = []byte("stale")
	ask := &fakeAsker{yes: true}

	unlock(context.Background(), w, kc, ask)()

	if kc.lookups != 0 {
		t.Errorf("consulted the Keychain with a password already cached")
	}
	if !bytes.Equal(w.cached, []byte("hunter2")) {
		t.Errorf("clobbered the cached password with %q", w.cached)
	}
}

func TestDeniedKeychainPromptFallsBackToAsking(t *testing.T) {
	// The user clicked Deny on the macOS authorization dialog. That is a
	// refusal, not a missing item, and it must not be retried.
	w := &fakeWallet{real: []byte("hunter2"), typed: []byte("hunter2")}
	kc := newFakeKeychain()
	kc.items["/wallet/client-credentials.pem"] = []byte("hunter2")
	kc.lookErr = errors.New("User canceled the operation")
	ask := &fakeAsker{yes: false}

	remember := unlock(context.Background(), w, kc, ask)
	_ = w.Open()
	remember()

	if kc.lookups != 1 {
		t.Errorf("looked up %d times after a denial, want 1", kc.lookups)
	}
	if kc.saves != 0 {
		t.Errorf("wrote to a Keychain the user just refused access to")
	}
}

func TestDisabledTurnsBothHalvesOff(t *testing.T) {
	t.Setenv("PELFS_NO_KEYCHAIN", "1")
	if !Disabled() {
		t.Fatal("PELFS_NO_KEYCHAIN=1 did not disable the integration")
	}
	// Unlock is the exported entry point and must not reach a Keychain at
	// all; the inner offer must refuse too, so that a caller holding an
	// already-obtained remember() cannot write after the switch flips.
	w := &fakeWallet{real: []byte("hunter2"), typed: []byte("hunter2")}
	kc := newFakeKeychain()
	ask := &fakeAsker{yes: true}
	_ = w.Open()
	offerToRemember(context.Background(), w, kc, ask, "/wallet/client-credentials.pem", nil)
	if ask.asked != 0 || kc.saves != 0 {
		t.Errorf("stored or asked while disabled (%d asks, %d saves)", ask.asked, kc.saves)
	}
	if remember := Unlock(context.Background()); remember == nil {
		t.Error("Unlock returned a nil remember function")
	} else {
		remember()
	}
}

func TestParseSecurityPassword(t *testing.T) {
	// Both forms are security's, verified against /usr/bin/security on
	// macOS 15. The hex form is what it emits for anything it cannot print
	// literally: high bytes, control characters, and (surprisingly)
	// backslashes. The quoted form does NOT escape quotes, so a password
	// containing them is recovered by taking everything between the first
	// and last quote rather than by unquoting.
	for _, tc := range []struct {
		name   string
		stderr string
		want   string
		ok     bool
	}{
		{"plain", "password: \"hunter2\"\n", "hunter2", true},
		{"spaces", "password: \"has space\"\n", "has space", true},
		{"embedded quote", "password: \"a\"b\"\n", `a"b`, true},
		{"two quotes", "password: \"a\"b\"c\"\n", `a"b"c`, true},
		{"only a quote", "password: \"\"\"\n", `"`, true},
		{"empty", "password: \"\"\n", "", true},
		{"high bytes as hex", "password: 0x70C3A47373  \"p\\303\\244ss\"\n", "p\xc3\xa4ss", true},
		{"tab as hex", "password: 0x74616209696E73696465  \"tab\\011inside\"\n", "tab\tinside", true},
		{"backslash as hex", "password: 0x6261636B5C736C617368  \"back\\134slash\"\n", `back\slash`, true},
		// A password that is itself a hex string must survive verbatim.
		// This is the case `security -w` cannot express, and the reason
		// this package uses -g.
		{"literal hex string", "password: \"70c3a47373\"\n", "70c3a47373", true},
		// Real output has the password line among others.
		{"among other lines", "keychain: \"/x\"\npassword: \"hunter2\"\n", "hunter2", true},
		{"not found", "security: SecKeychainSearchCopyNext: The specified item could not be found.\n", "", false},
		{"no output", "", "", false},
		{"malformed hex", "password: 0xZZ  \"?\"\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSecurityPassword([]byte(tc.stderr))
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v (got %q)", ok, tc.ok, got)
			}
			if ok && string(got) != tc.want {
				t.Errorf("password %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLookupAndSaveArguments(t *testing.T) {
	// The invocations this package makes, checked for the properties that
	// are not obvious from reading them:
	//   - the password never appears in argv (it goes in on stdin);
	//   - -w is the FINAL argument, which is what makes security prompt
	//     for the password rather than take it from the command line;
	//   - -U is present, so a save replaces a stale item in one step;
	//   - the account is the wallet path, so two wallets cannot collide;
	//   - a save reads the value back before reporting success.
	type call struct {
		args  []string
		stdin []byte
	}
	var calls []call
	kc := securityKeychain{run: func(_ context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
		calls = append(calls, call{args: args, stdin: append([]byte(nil), stdin...)})
		return nil, []byte("password: \"hunter2\"\n"), 0, nil
	}}

	got, err := kc.Lookup(context.Background(), "/wallet/a.pem")
	if err != nil || string(got) != "hunter2" {
		t.Fatalf("Lookup = %q, %v", got, err)
	}
	if len(calls) != 1 {
		t.Fatalf("Lookup ran %d commands, want 1", len(calls))
	}
	look := calls[0].args
	if look[0] != "find-generic-password" || !contains(look, "-g") {
		t.Errorf("lookup args %v do not use find-generic-password -g", look)
	}
	if !hasPair(look, "-a", "/wallet/a.pem") {
		t.Errorf("lookup args %v do not key the item on the wallet path", look)
	}
	if !hasPair(look, "-s", keychainService) {
		t.Errorf("lookup args %v do not name the service", look)
	}

	calls = nil
	if err := kc.Save(context.Background(), "/wallet/a.pem", []byte("hunter2")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("Save ran %d commands, want 2 (the add, then the read-back)", len(calls))
	}
	add, back := calls[0], calls[1]
	if back.args[0] != "find-generic-password" {
		t.Errorf("Save did not read the value back; second command was %v", back.args)
	}
	if add.args[0] != "add-generic-password" || !contains(add.args, "-U") {
		t.Errorf("save args %v are not an updating add", add.args)
	}
	if last := add.args[len(add.args)-1]; last != "-w" {
		t.Errorf("save args end in %q; -w must be last so security prompts", last)
	}
	for _, a := range add.args {
		if a == "hunter2" {
			t.Fatal("the password was passed in argv, where every process the user owns can read it")
		}
	}
	if string(add.stdin) != "hunter2\nhunter2\n" {
		t.Errorf("stdin %q; security prompts twice and wants the answer twice", add.stdin)
	}
	if !hasPair(add.args, "-l", keychainLabel) {
		t.Errorf("save args %v do not label the item for Keychain Access", add.args)
	}
	for _, a := range add.args {
		for _, b := range []byte(a) {
			if b > 127 {
				t.Fatalf("argument %q is not ASCII; security silently drops a non-ASCII -l", a)
			}
		}
	}
}

func TestSaveRemovesAnItemItCouldNotVerify(t *testing.T) {
	// security exits 0 for a write it mangled — the 128-byte prompt limit
	// is one such case. A stored password that does not open the wallet is
	// worse than none: it costs an authorization prompt and a warning on
	// every later mount to arrive at the same "type it in" it started
	// from. So a save that does not read back is undone.
	var ran []string
	kc := securityKeychain{run: func(_ context.Context, args []string, _ []byte) ([]byte, []byte, int, error) {
		ran = append(ran, args[0])
		return nil, []byte("password: \"something else\"\n"), 0, nil
	}}
	if err := kc.Save(context.Background(), "/wallet/a.pem", []byte("hunter2")); err == nil {
		t.Error("Save reported success for a value that did not read back")
	}
	if len(ran) != 3 || ran[2] != "delete-generic-password" {
		t.Errorf("commands run were %v; want the add, the read-back, then the delete", ran)
	}
}

func TestSaveRefusesAPasswordTooLongForThePrompt(t *testing.T) {
	kc := securityKeychain{run: func(context.Context, []string, []byte) ([]byte, []byte, int, error) {
		t.Fatal("ran security with a password it would silently truncate")
		return nil, nil, 0, nil
	}}
	long := make([]byte, maxPromptedPassword+1)
	for i := range long {
		long[i] = 'x'
	}
	if err := kc.Save(context.Background(), "/wallet/a.pem", long); err == nil {
		t.Error("stored a password longer than security's prompt accepts")
	}
}

func TestMissingItemIsNotAnError(t *testing.T) {
	kc := securityKeychain{run: func(context.Context, []string, []byte) ([]byte, []byte, int, error) {
		return nil, []byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n"),
			securityMissingItem, nil
	}}
	got, err := kc.Lookup(context.Background(), "/wallet/a.pem")
	if err != nil {
		t.Fatalf("a missing item was reported as an error: %v", err)
	}
	if got != nil {
		t.Errorf("got %q for a missing item", got)
	}
}

func TestSaveRefusesAPasswordItCannotRoundTrip(t *testing.T) {
	kc := securityKeychain{run: func(context.Context, []string, []byte) ([]byte, []byte, int, error) {
		t.Fatal("ran security with a password that cannot survive the round trip")
		return nil, nil, 0, nil
	}}
	if err := kc.Save(context.Background(), "/wallet/a.pem", []byte("two\nlines")); err == nil {
		t.Error("stored a password containing a newline")
	}
}

func TestBrowserRulesRefuseEveryHeadlessCase(t *testing.T) {
	const good = "https://issuer.example/device?code=ABCD"

	// A terminal with a person at it, so the refusals below are each
	// attributable to their own clause rather than to the test binary's
	// stdin never being a tty.
	present := func(t *testing.T) {
		t.Helper()
		saveTTY, saveEuid := isTerminal, geteuid
		isTerminal = func(*os.File) bool { return true }
		geteuid = func() int { return 501 }
		t.Cleanup(func() { isTerminal, geteuid = saveTTY, saveEuid })
		for _, k := range []string{"CI", "GITHUB_ACTIONS", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER",
			"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "PELFS_NO_BROWSER"} {
			t.Setenv(k, "")
		}
	}

	if browserSupported {
		t.Run("a person at a terminal", func(t *testing.T) {
			present(t)
			if !ShouldOpenBrowser(good) {
				t.Error("refused to open a browser for a person at a terminal")
			}
		})
	}

	for _, tc := range []struct {
		name string
		set  func(t *testing.T)
	}{
		{"opted out", func(t *testing.T) { t.Setenv("PELFS_NO_BROWSER", "1") }},
		{"no terminal", func(t *testing.T) {
			save := isTerminal
			isTerminal = func(*os.File) bool { return false }
			t.Cleanup(func() { isTerminal = save })
		}},
		{"only stdin is a terminal", func(t *testing.T) {
			save := isTerminal
			isTerminal = func(f *os.File) bool { return f == os.Stdin }
			t.Cleanup(func() { isTerminal = save })
		}},
		{"root", func(t *testing.T) {
			save := geteuid
			geteuid = func() int { return 0 }
			t.Cleanup(func() { geteuid = save })
		}},
		{"CI", func(t *testing.T) { t.Setenv("CI", "true") }},
		{"GitHub Actions", func(t *testing.T) { t.Setenv("GITHUB_ACTIONS", "true") }},
		{"over SSH", func(t *testing.T) { t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present(t)
			tc.set(t)
			if ShouldOpenBrowser(good) {
				t.Errorf("would open a browser with %s", tc.name)
			}
		})
	}

	// The URL arrives from an issuer over the network. Handing an
	// arbitrary scheme to /usr/bin/open would let it name a local
	// application or a file instead of a web page.
	for _, bad := range []string{
		"", "not a url", "file:///etc/passwd", "javascript:alert(1)",
		"ftp://issuer.example/x", "https://", "/relative/path",
		"x-apple-something://open",
	} {
		t.Run("refuses "+bad, func(t *testing.T) {
			present(t)
			if ShouldOpenBrowser(bad) {
				t.Errorf("would hand %q to open", bad)
			}
		})
	}
}

func TestShowVerificationURLIsHarmlessWhenHeadless(t *testing.T) {
	// The Pelican hook must be safe to install unconditionally: in a
	// daemon or a CI job it has to do nothing at all, and it must never
	// report a failure back into the device flow.
	save := isTerminal
	isTerminal = func(*os.File) bool { return false }
	t.Cleanup(func() { isTerminal = save })
	ShowVerificationURL("https://issuer.example/device", "ABCD-1234")
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
