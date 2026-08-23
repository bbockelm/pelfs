//go:build darwin

package pelcred

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The round trip against the real /usr/bin/security. This is the assertion
// no fake can make: that the arguments this package builds and the output it
// parses agree with the tool as macOS ships it. It runs in the macOS unit
// lane, so a future macOS that changes the -g output format is reported by
// CI rather than by a user whose password stopped working.
//
// IT NEVER TOUCHES THE USER'S LOGIN KEYCHAIN, and that is a rule with a
// history: an earlier draft mis-placed `-w` so it swallowed the positional
// after it, and the write landed in a real login keychain (found and
// deleted). The Security framework resolves both the default keychain and
// the search list through $HOME, so the test redirects HOME to a scratch
// directory and creates a keychain there; `security` inherits the redirected
// environment, sandboxKeychain ASSERTS the sandbox is the default before
// anything writes, and the login keychain is not reachable from inside the
// test.
func TestSecurityRoundTrip(t *testing.T) {
	if _, err := os.Stat(securityBinary); err != nil {
		t.Skipf("%s is not present: %v", securityBinary, err)
	}
	kcPath := sandboxKeychain(t)

	kc := securityKeychain{run: execRunner(securityBinary)}
	ctx := context.Background()
	const account = "/wallet/client-credentials.pem"

	// An absent item is not an error. This also proves the redirected
	// search list really is empty — if HOME redirection had failed and the
	// login keychain were in play, a previous run's item could answer here.
	if got, err := kc.Lookup(ctx, account); err != nil || got != nil {
		t.Fatalf("Lookup of a missing item = %q, %v; want nil, nil", got, err)
	}

	// Every shape the parser has a branch for, plus the two only the real
	// tool can settle: a password that is itself a hex string must come
	// back verbatim rather than hex-decoded, and a backslash takes
	// security's hex path even though it is printable ASCII.
	for _, password := range []string{
		"hunter2",
		"has space",
		`quote"inside`,
		`back\slash`,
		"tab\tinside",
		"pässwörd",
		"70c3a47373",
		"~!@#$%^&*()_+-=[]{}|;:,.<>?",
		// A leading dash, which is what the -w-swallows-a-positional
		// incident was really about: nothing this package passes may be
		// mistaken for a flag.
		"-w",
		// Exactly at security's prompt limit, which is where truncation
		// starts one byte later.
		strings.Repeat("p", maxPromptedPassword),
	} {
		if err := kc.Save(ctx, account, []byte(password)); err != nil {
			t.Fatalf("Save(%q): %v", password, err)
		}
		got, err := kc.Lookup(ctx, account)
		if err != nil {
			t.Fatalf("Lookup after Save(%q): %v", password, err)
		}
		if string(got) != password {
			t.Errorf("round trip of %q came back as %q", password, got)
		}
	}

	// One byte past the limit. security exits 0 having kept only the first
	// 128 bytes, so Save has to catch it: storing a truncated password
	// would report the user's own Keychain as stale on every later mount.
	tooLong := []byte(strings.Repeat("q", maxPromptedPassword+1))
	if err := kc.Save(ctx, account, tooLong); err == nil {
		t.Error("stored a password longer than security's prompt accepts")
	}
	// And the refusal left the previous, working item alone.
	if got, err := kc.Lookup(ctx, account); err != nil || string(got) != strings.Repeat("p", maxPromptedPassword) {
		t.Errorf("a refused save disturbed the stored password: %q, %v", got, err)
	}

	// -U in action: every save above went to the same service and account
	// and left ONE item, updated in place. Without -U the second would
	// have failed as a duplicate (security exits 45), and a
	// delete-then-add would leave a window with no stored password at all.
	out, err := exec.Command(securityBinary, "dump-keychain", kcPath).CombinedOutput()
	if err != nil {
		t.Fatalf("dump-keychain: %v\n%s", err, out)
	}
	if n := strings.Count(string(out), account); n != 1 {
		t.Errorf("the keychain holds %d items for %s; -U should leave exactly one", n, account)
	}
	// The label is what a user reads in Keychain Access's Name column, and
	// it is how they find the item to revoke it.
	if !strings.Contains(string(out), keychainLabel) {
		t.Errorf("the item is not labelled %q:\n%s", keychainLabel, out)
	}
}

// TestSecuritySaveIsVerified proves the read-back check, by letting the
// write succeed and the stored value differ. It uses the real tool for the
// write and a wrapper that corrupts what comes back, because the property
// under test is Save's reaction, not security's behaviour.
func TestSecuritySaveIsVerified(t *testing.T) {
	if _, err := os.Stat(securityBinary); err != nil {
		t.Skipf("%s is not present: %v", securityBinary, err)
	}
	kcPath := sandboxKeychain(t)

	real := execRunner(securityBinary)
	var deleted bool
	kc := securityKeychain{run: func(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, int, error) {
		if args[0] == "delete-generic-password" {
			deleted = true
		}
		out, errOut, code, err := real(ctx, args, stdin)
		if args[0] == "find-generic-password" && code == 0 {
			errOut = []byte("password: \"something else\"\n")
		}
		return out, errOut, code, err
	}}

	if err := kc.Save(context.Background(), "/wallet/a.pem", []byte("hunter2")); err == nil {
		t.Error("Save reported success for a password that did not read back")
	}
	if !deleted {
		t.Error("Save left an item behind that it knew held the wrong password")
	}
	// And it really is gone from the keychain, not merely attempted.
	out, _ := exec.Command(securityBinary, "dump-keychain", kcPath).CombinedOutput()
	if strings.Contains(string(out), "/wallet/a.pem") {
		t.Errorf("the bad item is still in the keychain:\n%s", out)
	}
}

// sandboxKeychain builds a keychain in a temp HOME, makes it the default
// (which is where Save writes, since the form that keeps the password off
// argv cannot also name a keychain), and returns its path.
//
// Every `security` invocation here names the keychain by path. The one
// operation that cannot — the add, because -w-as-a-prompt and -k are
// mutually exclusive — is the reason the default-keychain assertion at the
// bottom is a hard t.Fatalf and not a log line.
func sandboxKeychain(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	// BOTH directories are required. Without Library/Preferences,
	// `security default-keychain -s` exits 0 and silently changes nothing;
	// the subsequent add-generic-password then has no default keychain to
	// write to and BLOCKS. Getting that wrong would send the write at the
	// user's real login keychain, so the check below is not decoration.
	for _, dir := range []string{"Library/Keychains", "Library/Preferences"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)

	kcPath := filepath.Join(home, "Library", "Keychains", "pelfs-test.keychain-db")
	// Not a secret: this keychain lives for one test and is deleted below.
	const kcPassword = "pelfs-test-keychain"
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(securityBinary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("security %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("create-keychain", "-p", kcPassword, kcPath)
	t.Cleanup(func() {
		// Removes it from the (redirected) search list as well as from
		// disk, so nothing is left pointing into a deleted temp dir.
		_ = exec.Command(securityBinary, "delete-keychain", kcPath).Run()
	})
	run("default-keychain", "-s", kcPath)
	run("unlock-keychain", "-p", kcPassword, kcPath)

	// Fail loudly rather than write to the user's login keychain.
	got := run("default-keychain")
	if !strings.Contains(got, kcPath) {
		t.Fatalf("the sandbox keychain is not the default (HOME redirection did not take); default is %s", got)
	}
	// And say what the login keychain is NOT: if $HOME redirection had
	// failed, this would name the user's own login.keychain-db and the
	// assertion above would already have fired. Belt and braces, because
	// the cost of being wrong here is an item in somebody's real keychain.
	if strings.Contains(got, "login.keychain") {
		t.Fatalf("the default keychain is a login keychain (%s); refusing to run", got)
	}
	return kcPath
}
