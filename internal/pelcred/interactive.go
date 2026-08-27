package pelcred

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/term"
)

// Interactive reports whether there is a person at this process's terminal
// who can be asked a question or shown a browser window.
//
// It is one predicate, shared by the Keychain prompt and the browser
// opener, because the two need the same answer and getting it wrong has
// the same shape both ways: a background mount that stops to ask a question
// nobody sees hangs forever, and a CI job that opens a browser window is a
// mystery in a log.
//
// The rules, and why each one is here:
//
//   - stdin and stderr must both be terminals. stderr is where the question
//     and the URL are written; stdin is where the answer has to come from.
//     `pelfs mount` re-executes itself detached with both redirected, so
//     this single check already excludes the daemon.
//   - not root. `sudo pelfs ...` runs as a user with no GUI session, and
//     `open` from root either fails or opens a window in a session the
//     person in front of the machine does not own.
//   - not CI. A runner can have a pseudo-terminal, so the tty test alone
//     does not exclude it, and the CI variables are the only signal there
//     is.
//   - not a container. Same reasoning; /.dockerenv is the conventional
//     marker, and pelfs's own Docker fallback runs a Linux binary in one.
//   - not an SSH session without a local display. A browser opened by the
//     far end appears on the far end's screen, where nobody is looking.
//
// PELFS_NO_KEYCHAIN and PELFS_NO_BROWSER are checked by their own callers,
// not here: they are per-feature opt-outs, and this is the question of
// whether anyone is home.
func Interactive() bool {
	if !isTerminal(os.Stdin) || !isTerminal(os.Stderr) {
		return false
	}
	if geteuid() == 0 {
		return false
	}
	for _, name := range []string{"CI", "GITHUB_ACTIONS", "CONTINUOUS_INTEGRATION", "BUILD_NUMBER"} {
		if os.Getenv(name) != "" {
			return false
		}
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return false
	}
	return true
}

// isTerminal and geteuid are indirected so that the interactivity rules can
// be tested for what they DO as well as what they refuse. Without them a
// test binary — whose stdin is never a terminal — can only ever observe the
// negative answer, which would leave every positive clause unchecked.
var (
	isTerminal = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
	geteuid    = os.Geteuid
)

// remoteSession reports whether this process is being driven over SSH. It
// is a separate predicate from Interactive because the two features want
// different things from it: a password question over SSH is perfectly
// answerable, while a browser window opened at the far end is not.
func remoteSession() bool {
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// terminalAsker puts a yes/no question on stderr and reads the answer from
// stdin.
//
// Anything other than an explicit yes is a no, including end-of-file and a
// terminal that is not there. That default is the important part: this
// question is only ever asked about writing a secret somewhere new, and the
// safe answer to "shall I store your password" is no.
type terminalAsker struct{}

var _ asker = terminalAsker{}

func (terminalAsker) Confirm(prompt string) bool {
	if !Interactive() {
		return false
	}
	if _, err := os.Stderr.WriteString("pelfs: " + prompt); err != nil {
		return false
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}
