package pelcred

import (
	"bufio"
	"os"
	"strings"

	"golang.org/x/term"
)

// interactive reports whether there is a person at this process's terminal
// who can be asked a question.
//
// The only question this package ever asks is "shall I put your wallet
// password in the Keychain", and it is asked at most once per process. It
// is worth a predicate of its own rather than a bare term.IsTerminal
// because getting it wrong is not a cosmetic failure: a background mount
// that stops to ask a question nobody sees does not fall back, it hangs,
// with a filesystem half-attached behind it.
//
// The rules, and why each one is here:
//
//   - stdin and stderr must both be terminals. stderr is where the question
//     is written; stdin is where the answer has to come from. `pelfs mount`
//     re-executes itself detached with both redirected, so this single
//     check already excludes the daemon.
//   - not root. `sudo pelfs ...` runs as a user whose Keychain is not the
//     one the person in front of the machine owns, so a password stored
//     there would be stored for the wrong user and found by nobody.
//   - not CI. A runner can have a pseudo-terminal, so the tty test alone
//     does not exclude it, and the CI variables are the only signal there
//     is.
//   - not a container. Same reasoning; /.dockerenv is the conventional
//     marker, and pelfs's own Docker fallback runs a Linux binary in one.
//
// An SSH session is deliberately NOT excluded: a password question over
// SSH is perfectly answerable, and the remote machine's Keychain is the
// one the remote pelfs will read next time. A feature that opened a WINDOW
// rather than asking a question would need the opposite answer — the
// window appears at the far end, where nobody is sitting — so a second
// caller of this predicate is a sign it wants a predicate of its own, not
// another clause in this one.
//
// PELFS_NO_KEYCHAIN is checked by Disabled, not here: it is the feature's
// opt-out, and this is the question of whether anyone is home.
func interactive() bool {
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
	return !inContainer()
}

// isTerminal, geteuid and inContainer are indirected so that the
// interactivity rules can be tested for what they DO as well as what they
// refuse. Without them a test binary — whose stdin is never a terminal, and
// which in the Linux lane may itself be inside a container — can only ever
// observe the negative answer, which would leave every positive clause
// unchecked.
var (
	isTerminal  = func(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
	geteuid     = os.Geteuid
	inContainer = func() bool {
		_, err := os.Stat("/.dockerenv")
		return err == nil
	}
)

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
	if !interactive() {
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
