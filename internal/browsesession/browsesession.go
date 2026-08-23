// Package browsesession is the credential lifecycle of one `pelfs browse`
// process: the bootstrap token that arrives in the launch URL's fragment,
// the session token the page holds afterwards, and the single-use tickets
// that authorize a download the page's own credential cannot.
//
// Nothing here persists. Every secret is minted from crypto/rand into
// memory and dies with the process, which makes exiting `pelfs browse` a
// complete revocation of everything it ever issued. That property is worth
// more than surviving a restart, and it is why there is no file, no state
// directory entry, and no key derivation in this package.
//
// # Three credentials, three lifetimes, three places they live
//
//	bootstrap   32 bytes, ONE use, 120 s   in the launch URL's FRAGMENT,
//	                                       then in the browser's history —
//	                                       which is why it is single-use
//	                                       and short-lived rather than the
//	                                       credential itself
//	session     32 bytes, process life     in the page's sessionStorage,
//	                                       sent as X-Pelfs-Session; NEVER a
//	                                       cookie, because a cookie for
//	                                       127.0.0.1 has no port isolation
//	                                       and reaches every other local
//	                                       service the browser talks to
//	ticket      32 bytes, ONE use, 30 s    in a URL PATH, /d/<ticket>,
//	                                       because an <a href> download
//	                                       cannot carry a request header
//
// # Why the bootstrap token is in the fragment
//
// A fragment is never sent in a request line, so it is in no access log,
// and it is in no Referer under any policy. What it IS in is the browser's
// history and session-restore data, the opener process's argv
// (/proc/<pid>/cmdline on Linux), and the user's shell if they pasted it.
// The design answer to all three is the same: make the value stale before
// anyone can read it. One use, 120 seconds — long enough for a cold
// browser start on a loaded laptop, short enough that a leaked argv is
// worthless — and constant-time comparison so a guess cannot be steered.
//
// # Why downloads need a ticket at all
//
// The session token is a custom request header, which is exactly what
// forces a CORS preflight and makes a cross-origin page unable to reach
// the API. An <a href> or a window.location cannot set a header, so a
// download authorized by the session would have to be authorized by an
// AMBIENT credential on a GET — which is the one hole DNS rebinding
// exploits (CVE-2018-5702, where a custom header WAS the CSRF defence).
// So the page asks an authenticated API route for a ticket, navigates to
// /d/<ticket>, and that route accepts no session credential at all: 256
// bits to guess, one use, and the URL that lands in the download history
// is already spent by the time it is written.
package browsesession

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/httpguard"
)

// TokenBytes is the size of every secret this package mints. 32 bytes
// from crypto/rand: the same width as the ticket, the session token and
// the bootstrap token, so that a length never distinguishes them.
const TokenBytes = 32

// BootstrapTTL is how long the launch URL works. See the package comment
// for the reasoning; 120 s is the design's number.
const BootstrapTTL = 120 * time.Second

// TicketTTL is how long a download ticket is redeemable. It only has to
// survive the round trip from "the page got a ticket" to "the browser
// started the navigation", so it is short on purpose.
const TicketTTL = 30 * time.Second

// Errors every refusal wraps. Callers must not distinguish them in a
// RESPONSE — every one of them is a 401 (or a 404 for a ticket) with no
// detail, because telling an attacker which of "wrong", "expired" and
// "already used" they hit is telling them how to iterate. They are
// distinguished here so that a test, and a log line, can say which
// happened.
var (
	// ErrBootstrap is any refusal of a bootstrap exchange.
	ErrBootstrap = errors.New("bootstrap token refused")
	// ErrTicket is any refusal of a download ticket.
	ErrTicket = errors.New("download ticket refused")
)

// Manager holds one process's credentials. Safe for concurrent use.
type Manager struct {
	// now is time.Now except in tests, which drive the clock rather than
	// waiting on it: a TTL test that sleeps is a test that flakes on a
	// loaded machine.
	now func() time.Time

	mu sync.Mutex
	// bootstrap is the launch token, and "" once it has been exchanged.
	// The zero value after exchange is what makes single-use structural:
	// there is nothing left to compare against.
	bootstrap   string
	bootstrapAt time.Time
	// sessions is a slice rather than a map so that lookup can be
	// constant-time in the token (see ValidSession). One browser session
	// per process is the norm — the bootstrap is single-use — so the slice
	// holds one element in practice.
	sessions []string
	tickets  []ticket
}

type ticket struct {
	token  string
	path   string
	issued time.Time
}

// Ticket is a redeemed download authorization: what the API minted it for.
type Ticket struct {
	// Path is the volume path the ticket authorizes. M1 mints no
	// path-bearing tickets (there is no file surface yet); U11 does, and
	// the download handler must treat this as the ONLY thing the request
	// says about what to serve — never a path from the query string.
	Path string
	// Issued is when the API minted it.
	Issued time.Time
}

// New mints a manager and its bootstrap token.
func New() (*Manager, error) { return NewAt(time.Now) }

// NewAt is New with a clock, for tests.
func NewAt(now func() time.Time) (*Manager, error) {
	tok, err := mint()
	if err != nil {
		return nil, err
	}
	return &Manager{now: now, bootstrap: tok, bootstrapAt: now()}, nil
}

// mint is the only place a secret is created.
func mint() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	// RawURLEncoding: no padding, so no '=' to be escaped, re-encoded or
	// eaten by a platform opener between here and the browser's address
	// bar. Every one of these values travels through a URL.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Bootstrap is the launch token, or "" once it has been spent. Callers
// print the URL that carries it; nothing else should read it.
func (m *Manager) Bootstrap() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bootstrap
}

// LaunchURL is the URL the terminal prints and the opener opens: the app
// shell, with the bootstrap token in the FRAGMENT.
//
// origin must be the exact origin the listener serves (httpguard.Guard's
// Origin), so that the URL a user pastes matches the Host allowlist.
func (m *Manager) LaunchURL(origin string) string {
	return origin + "/#bt=" + url.PathEscape(m.Bootstrap())
}

// Exchange trades the bootstrap token for a session token. It succeeds at
// most once per process.
func (m *Manager) Exchange(candidate string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bootstrap == "" {
		return "", fmt.Errorf("%w: already exchanged", ErrBootstrap)
	}
	if m.now().Sub(m.bootstrapAt) > BootstrapTTL {
		// Cleared on the way out, so a late arrival cannot be followed by
		// a lucky guess against a token that is still sitting here.
		m.bootstrap = ""
		return "", fmt.Errorf("%w: expired (%s)", ErrBootstrap, BootstrapTTL)
	}
	if !httpguard.ConstantTimeEqual(candidate, m.bootstrap) {
		// NOT cleared: a wrong guess must not be able to invalidate the
		// real user's launch URL, or any page that can reach this route
		// could deny the session by racing the browser to it.
		return "", fmt.Errorf("%w: no match", ErrBootstrap)
	}
	tok, err := mint()
	if err != nil {
		return "", err
	}
	m.bootstrap = ""
	m.sessions = append(m.sessions, tok)
	return tok, nil
}

// ValidSession implements httpguard.SessionVerifier.
//
// The comparison is constant-time against every live session rather than a
// map lookup. The slice holds one element in practice, so the cost is a
// single 32-byte compare, and it removes the question of whether a hash
// table's probe sequence says anything about a secret.
func (m *Manager) ValidSession(token string) bool {
	if token == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ok := false
	for _, s := range m.sessions {
		if httpguard.ConstantTimeEqual(token, s) {
			ok = true
		}
	}
	return ok
}

// Revoke drops one session token: the "sign out" of a design with no
// cookie to clear.
func (m *Manager) Revoke(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.sessions[:0]
	for _, s := range m.sessions {
		if !httpguard.ConstantTimeEqual(token, s) {
			kept = append(kept, s)
		}
	}
	m.sessions = kept
}

// Sessions is how many live session tokens there are, for a status line.
func (m *Manager) Sessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// MintTicket authorizes one download of path. The caller must already have
// checked that the session may read it: a ticket is an authorization
// RESULT, not a request, and the /d/ route that redeems it has no
// principal with which to re-decide.
func (m *Manager) MintTicket(path string) (string, error) {
	tok, err := mint()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepTickets()
	m.tickets = append(m.tickets, ticket{token: tok, path: path, issued: m.now()})
	return tok, nil
}

// RedeemTicket burns a ticket and reports what it authorized. A second
// redemption of the same token fails, which is the property that makes the
// spent URL in the browser's download history harmless.
func (m *Manager) RedeemTicket(token string) (Ticket, error) {
	if token == "" {
		return Ticket{}, fmt.Errorf("%w: empty", ErrTicket)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepTickets()
	for i, t := range m.tickets {
		if !httpguard.ConstantTimeEqual(token, t.token) {
			continue
		}
		m.tickets = append(m.tickets[:i], m.tickets[i+1:]...)
		return Ticket{Path: t.path, Issued: t.issued}, nil
	}
	return Ticket{}, fmt.Errorf("%w: unknown, spent or expired", ErrTicket)
}

// sweepTickets drops the expired ones. Called under mu on every ticket
// operation, which is often enough: the set is small and short-lived, and
// a background sweeper would be a goroutine to shut down for no gain.
func (m *Manager) sweepTickets() {
	now := m.now()
	kept := m.tickets[:0]
	for _, t := range m.tickets {
		if now.Sub(t.issued) <= TicketTTL {
			kept = append(kept, t)
		}
	}
	m.tickets = kept
}

// Tickets is how many tickets are outstanding, for a status line and for
// the test that asserts a redemption really removed one.
func (m *Manager) Tickets() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepTickets()
	return len(m.tickets)
}
