package pelcred

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/ui"
)

// How the item is named, and why.
//
// A user has to be able to find this thing in Keychain Access and delete it,
// which is the only way to revoke it. So:
//
//	Name (label, -l)   pelfs (Pelican credential wallet)
//	Kind (-D)          pelfs credential-wallet password
//	Account (-a)       /Users/you/.config/pelican/credentials/client-credentials.pem
//	Where (service, -s) pelfs.pelican-credential-wallet
//
// The ACCOUNT is the wallet file's absolute path, not a username. It is the
// one attribute that distinguishes two items that would otherwise collide:
// Pelican's credential file location moves with Client.CredentialFile and
// with the preferred prefix (pelican vs. osdf), so a user with both has two
// wallets, two passwords, and needs two items. Using the path also makes the
// item self-explanatory in Keychain Access — the "Account" column says
// exactly which file this password opens.
//
// The label is deliberately plain ASCII. /usr/bin/security silently ignores
// a -l argument containing non-ASCII bytes and falls back to using the
// service name as the label, so a prettier label with an em dash in it
// produced an item named "pelfs.pelican-credential-wallet".
const (
	keychainService = "pelfs.pelican-credential-wallet"
	keychainLabel   = "pelfs (Pelican credential wallet)"
	keychainKind    = "pelfs credential-wallet password"
	keychainComment = "Password for the Pelican client's credential wallet, saved by pelfs. " +
		"Delete this item to make pelfs ask for the password again."
)

// securityTimeout bounds each /usr/bin/security call. A lookup can raise a
// GUI authorization prompt, and a user reading it is not a hang — but an
// unattended run against a wedged keychain daemon is, and it must not park
// a mount forever. Generous enough to read a dialog, short enough that a
// stuck one is not the rest of your afternoon.
const securityTimeout = 2 * time.Minute

// securityMissingItem is /usr/bin/security's exit status for
// errSecItemNotFound. It is the one failure that means "nothing is wrong,
// there is simply no such item".
const securityMissingItem = 44

// maxPromptedPassword is how many bytes security's password PROMPT accepts.
// Measured on macOS 15: 128 bytes go in and come back out, 129 come back as
// the first 128, with no error and exit status 0. A silently truncated
// password is the worst possible outcome for this feature — it stores a
// secret that does not work and then reports the user's own Keychain as
// stale on every subsequent mount — so anything longer is refused here, and
// every write is read back and compared besides.
const maxPromptedPassword = 128

// ErrNoItem reports that the Keychain holds no password for this wallet.
var ErrNoItem = errors.New("no such Keychain item")

// runner runs one /usr/bin/security invocation. It exists so the tests can
// exercise the argument construction and the output parsing on any platform
// without a Keychain — the parsing in particular has enough shape to it
// (see parseSecurityPassword) to deserve tests that run in the Linux CI lane
// as well as the macOS one.
type runner func(ctx context.Context, args []string, stdin []byte) (stdout, stderr []byte, exitCode int, err error)

// securityKeychain is the Keychain reached through /usr/bin/security.
//
// Shelling out rather than binding the Security framework is a deliberate
// trade: pelfs is built CGO_ENABLED=0 (it cross-compiles to four targets
// from one machine and ships a static binary), and every Go Keychain
// binding is cgo. /usr/bin/security ships with every macOS, so this costs
// no dependency at all.
type securityKeychain struct{ run runner }

var _ keychain = securityKeychain{}

func (k securityKeychain) Describe(account string) string {
	return fmt.Sprintf("%q / %q in Keychain Access", keychainLabel, account)
}

// Lookup reads the stored password.
//
// -g rather than -w. Both print the password, but -w prints raw bytes when
// they look printable and a bare hex string when they do not, with nothing
// to tell the two apart: a password of literally "70c3a47373" and a password
// of "päss" both come back as the nine characters 70c3a47373. -g is explicit
// — `password: "text"` or `password: 0xHEX  "escaped"` — so it can always be
// decoded exactly. It writes the password to stderr and the item's other
// attributes to stdout, which is why only stderr is parsed.
func (k securityKeychain) Lookup(ctx context.Context, account string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()

	_, stderr, code, err := k.run(ctx, []string{
		"find-generic-password", "-g",
		"-s", keychainService,
		"-a", account,
	}, nil)
	defer zero(stderr)
	if code == securityMissingItem {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if code != 0 {
		// Includes the user denying the authorization prompt. security's
		// own message is the useful part; it never contains the password
		// on a failure, so it is safe to pass on.
		return nil, fmt.Errorf("security exited %d: %s", code, firstLine(stderr))
	}
	password, ok := parseSecurityPassword(stderr)
	if !ok {
		return nil, errors.New("could not parse the password out of security's output")
	}
	if len(password) == 0 {
		// An item holding an empty password is indistinguishable from no
		// password at all, and seeding an empty one would send Pelican
		// down its "must have non-empty password" path.
		return nil, nil
	}
	return password, nil
}

// Save writes the password, replacing any item already there.
//
// -U ("update if it already exists") is unconditional rather than a
// fallback. Without it, security refuses a duplicate with exit 45, so the
// no--U form would need a delete-then-add — two operations, with a window
// in which the user has no stored password at all if the second fails. And
// every write this package makes is meant to replace what is there: the
// only reason it writes at all is that the stored value was absent or
// stale.
//
// The password goes in on STDIN, not on argv. `security -w <password>`
// would put the wallet password in the process table for every process the
// user owns to read; passing -w as the final argument makes security prompt
// for it instead, and it reads that prompt from stdin. security asks twice
// (it wants a confirmation), hence the doubled line. The trade is that the
// prompt form cannot also name a keychain, so this always writes to the
// user's default keychain — which is the login keychain, and is where a
// user looking for this item would look.
func (k securityKeychain) Save(ctx context.Context, account string, password []byte) error {
	if bytes.ContainsAny(password, "\r\n") {
		// security reads the password from a line of stdin, so a password
		// containing a newline cannot be round-tripped. Pelican's own
		// prompt is term.ReadPassword, which stops at the newline, so this
		// is unreachable through the normal path — but a password that
		// silently stored as its first line would be far worse than a
		// refusal.
		return errors.New("a password containing a newline cannot be stored in the Keychain")
	}
	if len(password) > maxPromptedPassword {
		return fmt.Errorf("this password is %d bytes and /usr/bin/security's prompt accepts %d, "+
			"silently keeping only the first %d; pelfs will not store a password it knows would be wrong",
			len(password), maxPromptedPassword, maxPromptedPassword)
	}
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()

	// security prompts twice; feed it the same answer twice.
	stdin := make([]byte, 0, 2*len(password)+2)
	stdin = append(append(stdin, password...), '\n')
	stdin = append(append(stdin, password...), '\n')
	defer zero(stdin)

	_, stderr, code, err := k.run(ctx, []string{
		"add-generic-password", "-U",
		"-s", keychainService,
		"-a", account,
		"-l", keychainLabel,
		"-D", keychainKind,
		"-j", keychainComment,
		// -w LAST, with no value: that is what makes security prompt
		// rather than take the secret from argv. Nothing may follow it.
		"-w",
	}, stdin)
	defer zero(stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("security exited %d: %s", code, firstLine(stderr))
	}

	// Read it back and compare. security reports success for a write it
	// mangled (the length limit above is one such case, found only because
	// this check existed), and the cost of being wrong is asymmetric: a
	// wrong stored password is worse than no stored password, because it
	// spends an authorization prompt and a warning on every later mount to
	// arrive at the same "you will have to type it" it started from. The
	// item was just created by /usr/bin/security, so its access control
	// already trusts the reader and this raises no second prompt.
	stored, err := k.Lookup(ctx, account)
	defer zero(stored)
	if err != nil {
		return fmt.Errorf("stored the password but could not read it back: %w", err)
	}
	if !bytes.Equal(stored, password) {
		// Do not leave it there. An item holding the wrong password is
		// what produces the "no longer opens" warning on every mount.
		k.forget(ctx, account)
		return errors.New("the Keychain did not store the password unchanged; the item has been removed")
	}
	return nil
}

// forget deletes the item, best-effort. It is only ever called to undo a
// write this package has just discovered was wrong.
func (k securityKeychain) forget(ctx context.Context, account string) {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()
	if _, _, code, err := k.run(ctx, []string{
		"delete-generic-password", "-s", keychainService, "-a", account,
	}, nil); err != nil || (code != 0 && code != securityMissingItem) {
		ui.Warn("could not remove the Keychain item {item}; delete it in Keychain Access",
			"item", k.Describe(account))
	}
}

// passwordPrefix is what security's -g output puts in front of the value.
const passwordPrefix = "password: "

// parseSecurityPassword pulls the password out of `security -g`'s stderr.
//
// Two forms, and the distinction is security's, not ours:
//
//	password: "hunter2"                       printable, verbatim in quotes
//	password: 0x70C3A47373  "p\303\244ss"     anything else, hex first
//
// The hex form is authoritative when present. The quoted form is taken as
// everything between the FIRST and LAST quote on the line, which is exact
// even for a password containing quotes: security does not escape them (it
// switches to the hex form for anything that would need escaping — control
// characters, high bytes, backslashes), so `a"b` prints as `"a"b"` and
// trimming one quote from each end recovers it.
func parseSecurityPassword(stderr []byte) ([]byte, bool) {
	for _, raw := range strings.Split(string(stderr), "\n") {
		line := strings.TrimRight(raw, "\r")
		if !strings.HasPrefix(line, passwordPrefix) {
			continue
		}
		value := line[len(passwordPrefix):]
		if hexDigits, ok := strings.CutPrefix(value, "0x"); ok {
			// "0xHEX  \"escaped\"" — the hex runs to the first space.
			if i := strings.IndexAny(hexDigits, " \t"); i >= 0 {
				hexDigits = hexDigits[:i]
			}
			decoded, err := hex.DecodeString(hexDigits)
			if err != nil {
				return nil, false
			}
			return decoded, true
		}
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			return []byte(value[1 : len(value)-1]), true
		}
		return nil, false
	}
	return nil, false
}

// execRunner is the production runner: it runs /usr/bin/security by
// absolute path so nothing on PATH can stand in for it.
func execRunner(securityPath string) runner {
	return func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
		cmd := exec.CommandContext(ctx, securityPath, args...)
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return out.Bytes(), errOut.Bytes(), 0, nil
		case errors.As(err, &exitErr):
			// A non-zero status is data, not a failure to report: 44 means
			// "no such item", and the caller decides what the rest mean.
			return out.Bytes(), errOut.Bytes(), exitErr.ExitCode(), nil
		default:
			ui.Debug("could not run {path} ({err})", "path", securityPath, "err", err)
			return nil, nil, -1, err
		}
	}
}

// zero overwrites a buffer that held, or may have held, a password. The
// buffers that reach it are ours: the pipe we wrote to security's stdin and
// the stderr we parsed out of. The password Pelican holds is never zeroed
// here — Pelican owns that slice, and clearing it would lock the wallet
// out from under the running process.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
