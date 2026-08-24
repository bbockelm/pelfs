// Package localoauth is the authorization server `pelfs browse` runs for
// external WebDAV clients: `GET /oauth/authorize`, `POST /oauth/token`,
// authorization-code with PKCE `S256`, and the token verifier
// internal/vfsdav's Bearer seam calls. It is work item U7 of
// docs/design-webui.md, and A7 of that document's threat model is the
// specification it is written against rather than a list of suggestions.
//
// It is the WHOLE of what a client may present at /dav/*: one scheme,
// Bearer, minted here, listed here and revoked here. THERE IS NO PASSWORD
// PATH ANY MORE. Per-client HTTP Basic used to live here as U8's
// contingency; it was removed because a credential that authenticates in
// one hop with no gesture in front of it is a second, weaker door on the
// same room, and the owner's instruction was the short version of that:
// "if we're going to use OAuth2, we don't need to show the password-based
// bookmarking. Passwords are bad." internal/vfsdav.Basic still exists as a
// library primitive and is used by internal/vfsdav's own client-gate
// server; nothing a user runs offers it.
//
// # Why this is the most attackable code in `pelfs browse`
//
// docs/design-webui.md, A7, in one sentence: "/oauth/authorize turns an
// authenticated browser session into a bearer token and hands it to a URL
// supplied in the request. Every other route in this design gives an
// attacker one action; this one gives them a credential."
//
// The attack is a page the user visits navigating their browser to
// http://127.0.0.1:PORT/oauth/authorize?...&redirect_uri=http://attacker/.
// Nothing in the browser platform stops the navigation — a top-level
// navigation needs no preflight, and it is the one thing Chromium's Local
// Network Access does NOT gate — so nothing about being on loopback helps.
// What stops it is this package refusing to mint anything without (a) a
// client_id the attacker cannot know, (b) a redirect_uri that matches, byte
// for byte, the one URL pelfs itself wrote into a profile, and (c) a POST
// carrying a ticket that only ever existed inside the body of a consent
// page rendered in the user's own browser, submitted from a document on
// which script cannot run.
//
// # The seven A7 controls, and where each one lives
//
//  1. Host allowlist + CSRF guard first  internal/httpguard, in front of
//     every route here; this package
//     never sees an unguarded request
//  2. a live browser session required    Config.Sessions, checked on every
//     /authorize (see SessionPresence
//     for why it is per-PROCESS and not
//     per-request, which is a real
//     limitation and is stated there)
//  3. exact-string redirect_uri          Client.RedirectURI, one entry, one
//     byte-for-byte comparison, and no
//     redirect of any kind on failure
//  4. client_id comes only from a        32 bytes, stored as an HMAC and
//     profile pelfs generated             compared in constant time:
//     crypto/rand, or derived from the state directory's key when one is
//     configured (identity.go)
//  5. PKCE S256 REQUIRED                 not accepted-if-offered: an
//     /authorize with no S256 challenge
//     is refused (and `plain` with it)
//  6. one real user gesture              the consent ticket plus a page
//     whose CSP is `script-src 'none'`;
//     see "The consent gesture" below
//  7. no custom-header rule here         SAID OUT LOUD at AuthorizeHandler,
//     because the instinct of a later
//     maintainer is to make this look
//     like the JSON API, and the
//     consistent version cannot work
//
// # The consent gesture, which is structural and not advisory
//
// The requirement is that a code cannot be minted without a human acting on
// a screen that says what is being authorized. Four properties make that a
// property of the code rather than of a comment:
//
//   - GET /oauth/authorize CANNOT REDIRECT. It has no path that writes a
//     Location header; the only caller of the code minter is the POST
//     handler. A silent drive of /authorize therefore ends at a page,
//     which is the outcome the attack cannot use.
//   - The POST requires a consent ticket: 32 bytes of crypto/rand that
//     exist in exactly one place, the HTML of the consent page. A
//     cross-origin page cannot read that body — no Access-Control-Allow-*
//     is emitted by anything on this listener — so it cannot forge the POST.
//   - The consent page cannot be framed (`frame-ancestors 'none'` plus the
//     guard's X-Frame-Options: DENY), so it cannot be rendered invisibly
//     inside an attacker's document to be clicked through.
//   - The consent page RUNS NO SCRIPT: its CSP is `script-src 'none'` and
//     it contains none. There is no form.submit() available on that
//     document to anybody, including us, so the only thing that can submit
//     the form is a user activating the button. That is what makes the
//     gesture structural: not "we did not write an auto-submit", but "an
//     auto-submit cannot execute here".
//
// One deliberate divergence from docs/design-webui.md, verification 2e,
// which says to remember consent per client_id for the life of the process
// so a reconnect does not re-prompt. Remembering it AT /authorize would
// reinstate exactly the primitive control 6 exists to remove: after one
// click, a navigation could mint codes again. So the gesture is required on
// every authorization, and the no-re-prompt property is delivered where the
// client actually needs it — the refresh token, which never touches
// /authorize at all (OAuth2RequestInterceptor refreshes before the request
// goes out and never revisits /authorize while a refresh works).
//
// THAT IS ALSO THE ANSWER TO "why do I have to redo this every session".
// Two different things were being conflated under "persist the OAuth
// connection", and only one of them is the attack:
//
//   - persisting CONSENT — auto-approving /authorize for a client that was
//     approved before — is the primitive control 6 removes, because a page
//     the user merely visits could then drive the endpoint to a code with
//     no human in the loop. It is refused, permanently, and no
//     configuration turns it on.
//   - persisting the ISSUED GRANT — the refresh token a consent gesture
//     already bought — does not touch /authorize in any way. A client
//     holding one calls POST /oauth/token directly, so there is no
//     authorization request for anybody to drive silently, and the
//     credential it renews is the one a human already approved.
//
// So the grant persists (grants.go, when Config.Grants is set) and consent
// does not. A saved Cyberduck bookmark reconnects across a restart of
// `pelfs browse` with NO CLICK AT ALL; only a client that has never been
// authorized, or one whose grant was revoked or expired, meets the consent
// screen.
//
// # What persists and what does not, and that is the revocation story
//
// Every secret this package issues is still crypto/rand, and no table holds
// a secret — only HMACs of secrets. Two files in the volume's state
// directory outlive the process, and neither of them contains a credential:
//
//   - browse-identity.key (identity.go): the per-volume key a client_id is
//     DERIVED from, so the `.cyberduckprofile` a user installed last week
//     is still a profile this session recognises.
//   - browse-grants.key (grants.go): one row per issued grant, holding an
//     HMAC of its refresh token — never the token — plus the scope, the
//     issue time and the expiry. It is a VERIFIER, not a credential: it
//     lets this process keep honouring a refresh token the client already
//     holds. Reading the file yields nothing that can be presented
//     anywhere. What it costs is stated plainly in grants.go's own comment
//     and in docs/design-webui.md: the standing WebDAV access a grant
//     represents now survives a restart, so a restart is no longer a
//     revocation.
//
// The ACCESS token is still per-process and unsaved (Server.key is
// crypto/rand at New, so an access token from a previous `pelfs browse`
// does not validate against a new one even on the same port), no password
// exists at all any more, and Revoke and RevokeGrant reach the disk — a
// revoked grant is dead after a restart, which is the property that makes
// persisting one defensible.
package localoauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/vfsdav"
)

// The two scopes, and there are only two. A DAV token names the filesystem
// and nothing else: there is no scope for publishing (a checkpoint stays a
// human decision, docs/design-webui.md A7), none for minting credentials,
// and none that reaches /api/v1 or /oauth — those refuse an Authorization
// header outright, in internal/httpguard, one layer above this package.
const (
	// ScopeRead reads /dav/*.
	ScopeRead = "pelfs.read"
	// ScopeWrite additionally allows the mutating WebDAV verbs. It is
	// refusable at three points: the client may not be allowed it, the
	// authorization request may not ask for it, and the request-time check
	// clamps it to the session's mode anyway.
	ScopeWrite = "pelfs.write"
)

// Lifetimes. Each is short for a reason stated where it is used.
const (
	// CodeTTL bounds an authorization code. 60 seconds is the design's
	// number: the code's whole life is one redirect and one back-channel
	// POST, both on this machine.
	CodeTTL = 60 * time.Second

	// AccessTTL is the access token's lifetime, and it is what `expires_in`
	// reports. It MUST be reported: Cyberduck treats a token with no
	// expiry as one that never expires and will never refresh it, so an
	// omitted expires_in turns our own expiry into 401s the client cannot
	// recover from (docs/design-webui.md, verification 2d).
	AccessTTL = time.Hour

	// ConsentTTL is how long a rendered consent page stays submittable. It
	// is a human's dwell time on a screen they did not expect, not a
	// protocol round trip.
	ConsentTTL = 5 * time.Minute
)

// maxPending caps rendered-but-unanswered consent pages. Each GET
// /authorize allocates one, the route is unauthenticated by necessity
// (control 7), and an unbounded table behind an unauthenticated GET is a
// way for a page the user visited to spend our memory. The oldest is
// dropped, so a flood costs the user a stale consent page rather than the
// server.
const maxPending = 16

// tokenBytes is the width of every secret minted here: client_id, code,
// access token, refresh token, consent ticket. The same width for all of
// them so that a length never says which is which.
const tokenBytes = 32

// Errors. A CALLER MUST NOT TURN THESE INTO DISTINCT RESPONSES. The token
// endpoint answers every refusal with the same `invalid_grant`, because
// telling a caller which of "unknown", "expired", "replayed", "wrong
// client" and "wrong verifier" they hit is telling them how to iterate.
// They are distinguished here so a test, a counter and a log line can say
// which happened.
var (
	// ErrRefused is any refusal of a code, a token or a credential.
	ErrRefused = errors.New("localoauth: refused")
	// ErrConfig is a caller error at construction or client registration —
	// a redirect URI with no port, a writable client on a read-only
	// session. It is never the answer to a network request.
	ErrConfig = errors.New("localoauth: configuration")
)

// SessionPresence reports whether this process has a live browser session.
// *internal/browsesession.Manager satisfies it as it stands.
//
// WHY THIS IS A PROCESS FACT AND NOT A REQUEST FACT, stated because the
// weaker check is easy to mistake for the stronger one. A7 control 2 asks
// for "an authenticated browser session". /oauth/authorize is reached by a
// NAVIGATION Cyberduck opens, so the request cannot carry X-Pelfs-Session
// (control 7) — and the session token lives in sessionStorage, which is
// scoped to the tab that minted it, so the new tab Cyberduck opens could
// not read it even with script, and this package's consent page runs no
// script by design. There is therefore no request-level session binding
// available on this route, and any design that claims one on a loopback
// origin is claiming it from a cookie, which on 127.0.0.1 is shared with
// every other local service the browser talks to (RFC 6265bis §8.5, and
// internal/httpguard's package comment).
//
// What is left is a two-part answer, and it is stronger than it first
// looks:
//
//   - this check: a process nobody has opened the app on mints nothing, and
//     the page a driven navigation reaches says "open pelfs from your
//     terminal first";
//   - control 4, which does the real work: a client_id exists only because
//     an authenticated session asked for a profile download and got 32
//     random bytes back in a file. An attacker who was never handed a
//     profile cannot name a client, so they never get past the first check
//     in AuthorizeHandler whether a session is live or not.
type SessionPresence interface {
	// Sessions is how many live browser session tokens this process holds.
	Sessions() int
}

// Config is what the authorization server needs to know about the session
// it serves.
type Config struct {
	// Writable is the `pelfs browse` session's own mode. It is the ceiling
	// on every grant: a read-only session may never mint a writable DAV
	// token, and that is checked at client registration, at grant time and
	// again at request time (Verify) — three places, because the session's
	// mode cannot change mid-life today but a future version might let it,
	// and the check that survives that change is the one at request time.
	Writable bool

	// Volume is what the consent screen names, e.g.
	// "pelican://osg-htc.org/user/bbockelman". A user who is driven to a
	// consent page they did not ask for can only act on what the page tells
	// them, so the page names the volume, the client, the scope and the
	// redirect target.
	Volume string

	// Sessions gates /oauth/authorize on a live browser session. A nil
	// verifier refuses every authorization, which is the right failure for
	// a misconfigured server.
	Sessions SessionPresence

	// Now is time.Now except in tests, which drive the clock rather than
	// sleeping on it.
	Now func() time.Time

	// Identity makes the CLIENT IDENTITY persistent: client ids are derived
	// from a per-volume key in the state directory instead of minted per
	// download, so a generated profile is byte-identical across restarts and
	// the one a user installed keeps working. See identity.go for the whole
	// of what that does and does not persist — no token, no password, and
	// not consent.
	//
	// nil is the ephemeral server this package started as: every client id
	// is crypto/rand and dies with the process. That is what every test
	// that does not care about persistence gets, and it is still the right
	// answer for a caller with no state directory.
	Identity *Identity

	// Grants makes the ISSUED GRANT persistent: a refresh token a consent
	// gesture bought keeps working after `pelfs browse` restarts, so a
	// saved bookmark reconnects with no click at all. grants.go is the
	// whole of what that stores (an HMAC of the refresh token, never the
	// token) and what it costs.
	//
	// It is only honoured together with Identity: a grant is bound to a
	// client identity tuple, and a client id that is crypto/rand per
	// process cannot be re-bound after a restart. A Grants with no Identity
	// is a configuration error rather than a silent no-op.
	//
	// nil is the ephemeral server: every grant dies with the process, which
	// is what every test that is not about persistence gets.
	Grants *GrantStore
}

// Server is one process's authorization server and credential registry.
// Safe for concurrent use; holds no goroutines.
type Server struct {
	cfg Config
	// key is the per-process HMAC key. Every secret this package accepts is
	// looked up by HMAC(key, secret) rather than by the secret, so the
	// tables hold no usable credential and a token minted by a previous
	// process cannot validate here even if the port was reused.
	key [32]byte

	mu      sync.Mutex
	clients []*client
	codes   []*code
	grants  []*grant
	pending []*pending
	counts  Counts
}

// refreshMac is the lookup key for a REFRESH token, and it is deliberately
// not s.mac.
//
// An access token is per-process by design, so s.key (crypto/rand at New)
// is the right key for it. A refresh token has to be recognisable to the
// NEXT process as well, so when there is a grant store its rows are keyed
// under the store's own persistent key — one scheme for adopted and
// freshly minted grants alike, so nothing has to remember which kind of
// grant it is holding. With no store the two are the same thing.
func (s *Server) refreshMac(secret string) [32]byte {
	if s.cfg.Grants != nil {
		return s.cfg.Grants.mac(secret)
	}
	return s.mac(secret)
}

// Counts is what the server refused, for a status line and for the tests
// that assert a refusal HAPPENED rather than merely that a response was a
// 400. Every field counts a thing that is either a bug or an attack.
type Counts struct {
	// CodeReplays is authorization codes presented a second time BY A
	// CALLER THAT COULD NOT PROVE IT WAS THE CLIENT THE CODE WAS ISSUED TO
	// — i.e. with no valid PKCE verifier. A replay also revokes the grant
	// the first presentation created, so a non-zero value means somebody
	// lost a token as well as that somebody tried.
	CodeReplays int
	// CodeRetries is a used code presented again WITH a code_verifier that
	// hashes to the challenge it was bound to. The verifier never leaves
	// the client, so this is the client that asked for the code asking
	// again — a retried POST, not a stolen code. It is still refused (the
	// code is single use) but nothing is revoked. See exchangeCode.
	CodeRetries int
	// RedirectMismatches is redirect_uri values that did not match a
	// registered client's, byte for byte. None of them was redirected to.
	RedirectMismatches int
	// UnknownClients is client_id values that named no registered client.
	UnknownClients int
	// MissingPKCE is /authorize requests with no S256 challenge.
	MissingPKCE int
	// VerifierMismatches is code exchanges whose code_verifier did not hash
	// to the challenge.
	VerifierMismatches int
	// ConsentDenied is consent screens a human answered with Deny.
	ConsentDenied int
	// ConsentTicketsRefused is consent POSTs whose ticket matches NOTHING
	// this server minted and still remembers: an expired page or a forged
	// one. A re-press of a page we did mint is ConsentRepeats, not this.
	ConsentTicketsRefused int
	// ConsentRepeats is a consent page answered a second time — the user
	// pressing Authorize twice, or reloading the page the first press
	// produced. Nothing is minted for it; the answer is a page saying what
	// the first press already did. It is a usability number, not a
	// security one.
	ConsentRepeats int
	// NoSession is /authorize requests refused for control 2.
	NoSession int
	// ScopeClamped is credentials whose write scope was removed at request
	// time because the session is read-only. It should never be non-zero;
	// if it is, grant-time enforcement has a hole and this is the net that
	// caught it.
	ScopeClamped int
}

// New builds a server. It fails rather than defaulting when something
// security-relevant is missing.
//
// When Config.Identity is set it ADOPTS the clients already on disk, before
// serving anything. That is what makes a saved bookmark work with no
// interaction: the user's Cyberduck reconnects to a client this process has
// never issued a profile for, and the registry has to know the name already
// or the flow ends on "This is not an authorization request pelfs issued".
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Grants != nil && cfg.Identity == nil {
		// A grant row names its client by the identity tuple, which is the
		// only handle that survives a restart. Without an identity there is
		// nothing to re-bind it to, and adopting a grant onto a client id
		// that was crypto/rand this morning would be adopting it onto
		// nobody.
		return nil, fmt.Errorf("%w: Config.Grants needs Config.Identity — a persisted "+
			"grant is bound to a persistent client identity", ErrConfig)
	}
	s := &Server{cfg: cfg}
	if _, err := rand.Read(s.key[:]); err != nil {
		return nil, fmt.Errorf("localoauth: per-process key: %w", err)
	}
	if err := s.adoptPersistentClients(); err != nil {
		return nil, err
	}
	if err := s.adoptPersistentGrants(); err != nil {
		return nil, err
	}
	return s, nil
}

// adoptPersistentClients registers the identities the state directory
// already holds. Called once, from New, before the server can serve.
//
// ONE THING IT DELIBERATELY DOES NOT DO:
//
//   - It does not drop or downgrade a write:true identity on a read-only
//     session. Keeping it is what turns Cyberduck's reconnect into "That
//     scope is wider than this profile … restart it with --rw", which is
//     the true answer, instead of "this is not an authorization request
//     pelfs issued", which is not. NewClient still refuses to CREATE a
//     writable client on a read-only session, and parseScopes still refuses
//     to grant the scope; adoption is not creation.
func (s *Server) adoptPersistentClients() error {
	if s.cfg.Identity == nil {
		return nil
	}
	for _, e := range s.cfg.Identity.clients() {
		id, err := s.cfg.Identity.derive(e)
		if err != nil {
			return err
		}
		ref, err := mintRef()
		if err != nil {
			return err
		}
		s.clients = append(s.clients, &client{
			ref: ref, label: e.Label, macID: s.mac(id), redirect: e.Redirect,
			write: e.Write, created: e.Created, persistent: true,
		})
	}
	return nil
}

// adoptPersistentGrants re-arms the grants the state directory already
// holds. Called once, from New, after the clients they belong to exist.
//
// THIS IS THE WHOLE OF THE "no click after a restart" FEATURE: a grant that
// is in this table is one the token endpoint will renew, so a Cyberduck
// that saved its refresh token last session gets an access token out of
// POST /oauth/token and never opens a browser.
//
// Three things it does on the way in, all of which are refusals rather than
// repairs:
//
//   - it drops a row whose client tuple is not in the identity roster. That
//     is a grant for a client the user revoked (Revoke deletes the identity
//     and the grants together, but a half-written state directory, or one
//     edited by hand, must not resurrect either half).
//   - it drops an EXPIRED row. RefreshTTL is a bound on a standing
//     credential, checked here as well as at refresh time so an expired row
//     never even becomes a live grant.
//   - it CLAMPS the scope to this session's mode. A write grant adopted
//     into a read-only `pelfs browse` becomes a read grant, here, once —
//     rather than being clamped on every request, which would make
//     Counts.ScopeClamped (a "this should never happen" number) fire
//     routinely and stop meaning anything.
//
// It does not rewrite the file for any of that: an expired row is pruned by
// the store's own save path, and a scope clamped for a read-only session
// must come back if the user restarts with --rw.
func (s *Server) adoptPersistentGrants() error {
	if s.cfg.Grants == nil {
		return nil
	}
	now := s.cfg.Now()
	for _, rec := range s.cfg.Grants.records() {
		if !rec.Expires.IsZero() && now.After(rec.Expires) {
			continue
		}
		c := s.findClientByTuple(rec.Label, rec.Redirect, rec.Write)
		if c == nil {
			continue
		}
		mac, ok := rec.refreshMAC()
		if !ok {
			continue
		}
		write := rec.Write && s.cfg.Writable
		scopes := []string{ScopeRead}
		if write {
			scopes = append(scopes, ScopeWrite)
		}
		s.grants = append(s.grants, &grant{
			ref: rec.Ref, clientRef: c.ref, label: c.label,
			// NO access token: macAccess stays zero, which no presented
			// token can HMAC to, so an adopted grant authenticates nothing
			// at /dav/* until the client refreshes. That is the point —
			// the access token is per-process and this is not one.
			macRefresh: mac, write: write, scopes: scopes,
			issued: rec.Issued, expires: time.Time{}, lastUsed: rec.LastUsed,
			refreshExpires: rec.Expires, persistent: true,
		})
	}
	return nil
}

// findClientByTuple is the restart-time binding: a persisted grant names its
// client by the same (label, redirect, write) tuple the identity file uses,
// because that is the only handle both files can agree on across a process.
// Called from New, before anything can race.
func (s *Server) findClientByTuple(label, redirect string, write bool) *client {
	for _, c := range s.clients {
		if c.label == label && c.redirect == redirect && c.write == write {
			return c
		}
	}
	return nil
}

// Writable reports the session's mode: the ceiling on every grant.
func (s *Server) Writable() bool { return s.cfg.Writable }

// Counts is a snapshot of the refusal counters.
func (s *Server) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts
}

// hasSession is A7 control 2. A nil SessionPresence refuses.
func (s *Server) hasSession() bool {
	return s.cfg.Sessions != nil && s.cfg.Sessions.Sessions() > 0
}

// ---------------------------------------------------------------- clients

// client is a registered external client. The client_id is held as an HMAC:
// the registry can verify one and cannot leak one.
type client struct {
	ref      string // public handle, for the UI's list and Revoke
	label    string
	macID    [32]byte
	redirect string
	write    bool
	created  time.Time
	lastUsed time.Time
	// consented records that a human has authorized this client at least
	// once, for the UI's list. IT IS NOT A PERMISSION: nothing reads it to
	// decide anything, because a remembered consent at /authorize is the
	// primitive control 6 removes. See the package comment.
	consented bool
	// persistent says this client's IDENTITY is in the state directory, so
	// the profile the user installed survives a restart and revoking it has
	// to reach the disk. Also for the UI's list, and also not a permission.
	persistent bool
}

// ClientRequest registers one external client — in practice, one profile
// download.
type ClientRequest struct {
	// Label is what the consent screen and the credential list call this
	// client: "Cyberduck", "rclone on this laptop". It is rendered as text
	// into an HTML page, so it is escaped there, and it is length-capped
	// here.
	Label string

	// RedirectURI is the loopback callback pelfs itself wrote into the
	// generated profile — the WHOLE allowlist for this client, matched byte
	// for byte. It must name a loopback host with an EXPLICIT non-zero
	// port: Cyberduck's LoopbackOAuth2AuthorizationCodeProvider substitutes
	// port 0 when the URI has none, and then the redirect_uri it sends
	// disagrees with the port it is listening on. Use
	// davprofile.RedirectURI to build it.
	RedirectURI string

	// Write asks for a client that may be granted pelfs.write. Refused on a
	// read-only session — the earliest of the three places the session's
	// mode is the ceiling.
	Write bool
}

// Client is what a profile download needs. ITS ONE SECRET IS RETURNED
// ONCE: the server keeps only an HMAC of the id, so a caller that loses ID
// must register a new client. There is no second credential in here any
// more — Basic is gone (see the package comment).
type Client struct {
	// ID is the OAuth client_id. A SECRET, and the thing that makes control
	// 4 work: possessing the generated profile is what identifies the
	// client, so an attacker who was never handed one cannot name a valid
	// client_id. Never log it and never render it into a page.
	ID string
	// Ref is the non-secret handle: what the UI lists and what Revoke
	// takes. A revoke button that needed the secret would be a UI holding
	// the secret.
	Ref      string
	Label    string
	Redirect string
	Write    bool
	Created  time.Time
}

// NewClient registers a client and mints its credentials.
//
// WITH Config.Identity SET IT IS IDEMPOTENT ON (label, redirect, write), and
// that is forced by the derivation rather than chosen for convenience: the
// client id is HMAC(key, tuple), so a second registration of the same tuple
// cannot produce a different id, and a second ROW for it would be one
// profile with two revoke buttons. So the same tuple is the same client,
// re-generating its download hands back a byte-identical profile — and now
// that there is no password to roll, nothing at all is re-issued: asking
// again for a program you already have is a no-op that hands back the same
// file, and any live grant it holds keeps working.
func (s *Server) NewClient(req ClientRequest) (*Client, error) {
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "WebDAV client"
	}
	if len(label) > 64 {
		label = label[:64]
	}
	if req.Write && !s.cfg.Writable {
		// The earliest of the three ceiling checks: a read-only `pelfs
		// browse` cannot even register a client that could ask.
		return nil, fmt.Errorf("%w: this session is read-only, so no client may be granted %s",
			ErrConfig, ScopeWrite)
	}
	if err := CheckRedirectURI(req.RedirectURI); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	// The identity: derived and recorded when there is a state directory to
	// record it in, 32 fresh random bytes otherwise. This is the whole of
	// the difference between a profile that survives a restart and one that
	// does not.
	var (
		id      string
		created = now
		err     error
	)
	if s.cfg.Identity != nil {
		id, created, err = s.cfg.Identity.register(label, req.RedirectURI, req.Write, now)
	} else {
		id, err = mint()
	}
	if err != nil {
		return nil, err
	}
	ref, err := mintRef()
	if err != nil {
		return nil, err
	}
	// ONE critical section for find-or-append, not two: two concurrent
	// downloads of the same label would otherwise both miss and both append,
	// and one derived id on two rows is one profile with two revoke buttons.
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-registering an identity this process already knows — either adopted
	// from disk at startup or downloaded earlier in this session — reuses
	// the ROW, so the ref the UI lists and the Basic username stay put and
	// the password is the only thing that rolls.
	if c := s.findClient(id); c != nil {
		return &Client{
			ID: id, Ref: c.ref, Label: c.label, Redirect: c.redirect,
			Write: c.write, Created: c.created,
		}, nil
	}
	c := &client{
		ref:        ref,
		label:      label,
		macID:      s.mac(id),
		redirect:   req.RedirectURI,
		write:      req.Write,
		created:    created,
		persistent: s.cfg.Identity != nil,
	}
	s.clients = append(s.clients, c)
	return &Client{
		ID: id, Ref: ref, Label: label, Redirect: req.RedirectURI,
		Write: req.Write, Created: created,
	}, nil
}

// CheckRedirectURI is the "loopback, explicit port, no substitution
// hazards" rule, exported because the profile generator and the client
// registry must agree on it and because it is the one rule whose violation
// fails with nothing useful in any UI.
//
// It refuses:
//
//   - any scheme but http, and any host but a loopback literal. Cyberduck's
//     BrowserOAuth2AuthorizationCodeProvider dispatches on the URI's shape:
//     the custom-scheme provider (`…:oauth`) needs an OS-registered handler
//     and the prompt provider makes the user paste a code, so the loopback
//     provider is the only one of the three that needs nothing installed.
//   - a MISSING OR ZERO PORT. See ClientRequest.RedirectURI.
//   - a query or a fragment, because the code and state are appended as a
//     query and a second one is an invitation to a parser disagreement.
//   - a '$' anywhere. Every string in a Cyberduck profile passes through a
//     StringSubstitutor, so a '$' in a value pelfs generated is a value
//     Cyberduck may rewrite before it ever sends it — and then the
//     byte-for-byte comparison in control 3 fails on our own URL.
func CheckRedirectURI(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: no redirect_uri", ErrConfig)
	}
	if strings.ContainsRune(raw, '$') {
		return fmt.Errorf("%w: redirect_uri contains '$', which Cyberduck's "+
			"StringSubstitutor may rewrite: %q", ErrConfig, raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: redirect_uri: %v", ErrConfig, err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("%w: redirect_uri must be http on loopback, got scheme %q",
			ErrConfig, u.Scheme)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%w: redirect_uri must have no query and no fragment", ErrConfig)
	}
	if u.User != nil {
		return fmt.Errorf("%w: redirect_uri must have no userinfo", ErrConfig)
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1":
	default:
		return fmt.Errorf("%w: redirect_uri host must be a loopback literal, got %q",
			ErrConfig, u.Hostname())
	}
	port := u.Port()
	if port == "" || port == "0" {
		return fmt.Errorf("%w: redirect_uri needs an EXPLICIT non-zero port — "+
			"Cyberduck's loopback provider substitutes 0 when the URI has none "+
			"and then sends a redirect_uri that disagrees with the port it "+
			"listens on: %q", ErrConfig, raw)
	}
	if !strings.HasPrefix(u.Path, "/") {
		return fmt.Errorf("%w: redirect_uri needs a path, which is what "+
			"Cyberduck registers its listener's context at: %q", ErrConfig, raw)
	}
	// AND IT HAS TO BE SAFE TO PUT IN A HEADER, because it goes in one: the
	// consent page's `form-action` names this exact URL (see consentCSP for
	// why it must). A space, a `;`, a `,` or a quote in it would either
	// truncate the policy or split the header, and a mangled CSP is a
	// silently weaker one. Checked here rather than at the header, so a
	// redirect URI that could do it never becomes a registered client.
	for _, r := range raw {
		if r <= ' ' || r > '~' || r == ';' || r == ',' || r == '\'' || r == '"' {
			return fmt.Errorf("%w: redirect_uri may only use printable "+
				"URL characters (no space, `;`, `,` or quote): %q", ErrConfig, raw)
		}
	}
	return nil
}

// ClientInfo is one row of the UI's credential list. A credential the user
// cannot see is a credential the user cannot revoke (docs/design-webui.md,
// A6), so this carries everything the list shows and no secret at all.
type ClientInfo struct {
	Ref      string
	Label    string
	Redirect string
	Write    bool
	Created  time.Time
	// Consented is whether a human has authorized this client on a consent
	// screen at least once.
	Consented bool
	// Persistent is whether this client's IDENTITY is in the state
	// directory. It is what distinguishes "this profile still works next
	// session" from "this profile dies with this process", and it is what
	// makes Revoke's promise different between the two: revoking a
	// persistent client kills the installed profile for good.
	Persistent bool
	// Grants is how many live OAuth grants this client holds.
	Grants int
	// LastUsed is the most recent time any of this client's credentials
	// authenticated a /dav/* request; zero if never.
	LastUsed time.Time
}

// Clients lists the registry for the UI.
func (s *Server) Clients() []ClientInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ClientInfo, 0, len(s.clients))
	for _, c := range s.clients {
		info := ClientInfo{
			Ref: c.ref, Label: c.label,
			Redirect: c.redirect, Write: c.write, Created: c.created,
			Consented: c.consented, LastUsed: c.lastUsed,
			Persistent: c.persistent,
		}
		for _, g := range s.grants {
			if g.clientRef == c.ref {
				info.Grants++
			}
		}
		out = append(out, info)
	}
	return out
}

// Revoke drops one client: every grant it holds, and every code and consent
// page outstanding for it. Immediate, and the first return says whether
// there was anything to revoke.
//
// WHAT IT MEANS FOR A PERSISTENT CLIENT, which is the whole reason this
// returns an error. With Config.Identity set, revoking a client also DELETES
// ITS IDENTITY FROM THE STATE DIRECTORY, so the derived client_id names
// nothing in this session and in every session after it: the profile the
// user installed in Cyberduck is permanently dead and they have to download
// a new one. That is the honest meaning of the button, and it is stronger
// than the old one, which outlived nothing.
//
// It is therefore the one revocation that can FAIL. If the file cannot be
// rewritten, the credential is dead in this session and alive in the next,
// and a caller that reported plain success would be lying about the only
// part of it that is durable. The in-memory half is done either way — the
// error says the durable half is not — so a caller must surface it rather
// than retrying on the user's behalf.
//
// The key is not rotated: see Identity.forget for why revoking one profile
// must not kill the others.
func (s *Server) Revoke(ref string) (bool, error) {
	s.mu.Lock()
	found := false
	var gone *client
	kept := s.clients[:0]
	for _, c := range s.clients {
		if c.ref == ref {
			found, gone = true, c
			continue
		}
		kept = append(kept, c)
	}
	s.clients = kept
	if found {
		s.grants = filterGrants(s.grants, func(g *grant) bool { return g.clientRef != ref })
		s.codes = filterCodes(s.codes, func(c *code) bool { return c.clientRef != ref })
		s.pending = filterPending(s.pending, func(p *pending) bool { return p.clientRef != ref })
	}
	s.mu.Unlock()
	if !found {
		return false, nil
	}
	// Outside the lock: these write files, and no /dav/* request may wait on
	// a disk to answer.
	//
	// THE GRANTS GO FIRST, and the order is load-bearing. A persisted grant
	// is the thing that lets a client reconnect with no click; the identity
	// only lets it name itself. If exactly one of these two writes can
	// happen, the one that must happen is the one that takes the standing
	// access away.
	if s.cfg.Grants != nil {
		if err := s.cfg.Grants.forgetClient(gone.label, gone.redirect, gone.write); err != nil {
			return true, fmt.Errorf("localoauth: %q is revoked in this session but its saved "+
				"connection is still on disk, so it would reconnect after a restart with no "+
				"consent screen: %w", gone.label, err)
		}
	}
	if s.cfg.Identity != nil && gone.persistent {
		if _, err := s.cfg.Identity.forget(gone.label, gone.redirect, gone.write); err != nil {
			return true, fmt.Errorf("localoauth: %q is revoked in this session but its identity "+
				"is still on disk, so the profile would work again after a restart: %w",
				gone.label, err)
		}
	}
	return true, nil
}

// RevokeGrant drops one issued grant — one client connection's access and
// refresh token — leaving the client able to authorize again. This is the
// individual revocation A7 asks for.
//
// AND IT NOW REACHES THE DISK, which is why it reports an error the way
// Revoke does. A grant is persisted so a bookmark reconnects with no click;
// a revocation that only cleared memory would come back at the next
// restart, which would make the button on the page a lie about the only
// part of it a user cares about. The in-memory half is done either way —
// the error says the durable half is not.
func (s *Server) RevokeGrant(ref string) (bool, error) {
	s.mu.Lock()
	before := len(s.grants)
	var gone *grant
	for _, g := range s.grants {
		if g.ref == ref {
			gone = g
		}
	}
	s.grants = filterGrants(s.grants, func(g *grant) bool { return g.ref != ref })
	found := len(s.grants) != before
	s.mu.Unlock()
	if !found {
		return false, nil
	}
	if s.cfg.Grants != nil && gone != nil && gone.persistent {
		if err := s.cfg.Grants.forget(ref); err != nil {
			return true, fmt.Errorf("localoauth: grant %s is revoked in this session but is "+
				"still on disk, so the client would reconnect after a restart with no consent "+
				"screen: %w", ref, err)
		}
	}
	return true, nil
}

// findClient looks a presented client_id up in constant time and returns
// the client it names, or nil. Called under mu.
//
// EVERY candidate is compared and none returns early, so the time this
// takes says how many clients exist and nothing about which one matched.
func (s *Server) findClient(id string) *client {
	if id == "" {
		return nil
	}
	mac := s.mac(id)
	var found *client
	for _, c := range s.clients {
		if subtle.ConstantTimeCompare(mac[:], c.macID[:]) == 1 {
			found = c
		}
	}
	return found
}

// ----------------------------------------------------------------- grants

// grant is one issued authorization: an access token, a refresh token and
// the scope they carry. Both tokens are held as HMACs.
type grant struct {
	ref        string
	clientRef  string
	label      string
	macAccess  [32]byte
	macRefresh [32]byte
	write      bool
	scopes     []string
	issued     time.Time
	// expires is the ACCESS token's expiry. refreshExpires is the whole
	// grant's, and it is the bound on a standing credential: zero for an
	// ephemeral server (the process is the bound), RefreshTTL out for a
	// persisted one.
	expires        time.Time
	refreshExpires time.Time
	lastUsed       time.Time
	// persistent says this grant has a row in the state directory, so
	// revoking it has to reach the disk and the UI should say that
	// revoking it is what takes the standing access away.
	persistent bool
}

// GrantInfo is one row of the issued-token list in the UI.
type GrantInfo struct {
	Ref       string
	ClientRef string
	Label     string
	Scopes    []string
	Write     bool
	Issued    time.Time
	Expires   time.Time
	LastUsed  time.Time
	// Persistent is whether this grant is in the state directory — i.e.
	// whether the program holding it reconnects after a restart with no
	// consent screen. A credential the user cannot see is a credential the
	// user cannot revoke (A6), and a credential that outlives the process
	// is the one that most needs seeing.
	Persistent bool
	// RefreshExpires is when the whole grant dies whatever happens; zero on
	// an ephemeral server, where the process is the bound.
	RefreshExpires time.Time
}

// Grants lists the live grants for the UI.
func (s *Server) Grants() []GrantInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]GrantInfo, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, GrantInfo{
			Ref: g.ref, ClientRef: g.clientRef, Label: g.label,
			Scopes: append([]string(nil), g.scopes...), Write: g.write,
			Issued: g.issued, Expires: g.expires, LastUsed: g.lastUsed,
			Persistent: g.persistent, RefreshExpires: g.refreshExpires,
		})
	}
	return out
}

// Grant is what one accepted credential may do, as this package sees it.
// DAVAuth maps it onto vfsdav.Grant; nothing else should need it.
type Grant struct {
	// Ref is the grant's (or the client's) non-secret handle, for a log
	// line.
	Ref string
	// Label is the client's label.
	Label string
	// Scopes is what was granted.
	Scopes []string
	// Write allows the mutating WebDAV verbs.
	Write bool
}

// Verify authenticates an access token. It is the whole of what /dav/* knows
// about this package.
//
// Three things it does that are worth naming: the lookup is over an HMAC of
// the presented token, so no comparison touches a stored secret; the expiry
// is checked here rather than by a sweeper, so an expired token is dead the
// instant it expires whether or not anything swept; and the write scope is
// CLAMPED to the session's mode, which is A7's request-time half of "a
// read-only session may never grant a writable token".
func (s *Server) Verify(token string) (Grant, bool) {
	if token == "" {
		return Grant{}, false
	}
	mac := s.mac(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	var found *grant
	for _, g := range s.grants {
		if subtle.ConstantTimeCompare(mac[:], g.macAccess[:]) == 1 {
			found = g
		}
	}
	if found == nil || now.After(found.expires) {
		return Grant{}, false
	}
	found.lastUsed = now
	s.touchClient(found.clientRef, now)
	return Grant{Ref: found.ref, Label: found.label,
		Scopes: append([]string(nil), found.scopes...),
		Write:  s.clampWrite(found.write)}, true
}

// clampWrite is the request-time half of the ceiling. Called under mu.
func (s *Server) clampWrite(write bool) bool {
	if write && !s.cfg.Writable {
		s.counts.ScopeClamped++
		return false
	}
	return write
}

// touchClient records last-used on the owning client. Called under mu.
func (s *Server) touchClient(ref string, now time.Time) {
	for _, c := range s.clients {
		if c.ref == ref {
			c.lastUsed = now
		}
	}
}

// DAVAuth is the credential check to hand internal/vfsdav: this session's
// OAuth Bearer tokens, and NOTHING ELSE. It is one line at the mount site:
//
//	dav, err := vfsdav.New(vfsdav.Config{FS: fs, Prefix: "/dav",
//		Auth: oauth.DAVAuth("pelfs")})
//
// ONE SCHEME, WHICH IS THE POINT. This used to be
// AnyOf(Bearer, per-client Basic), with a long comment about the order the
// challenges are offered in. The password half is gone: a credential that
// authenticates at /dav/* in one hop, preemptively, with no gesture in
// front of it and no expiry behind it was the weakest thing on this
// listener, and its only job was to be a contingency for a flow that now
// works in a real browser and a real Cyberduck on every gate we run. What
// the removal buys is that an anonymous request is answered with exactly
// one challenge — Bearer — so no client can be talked into a password
// prompt for a profile that has no password field (docs/design-webui.md,
// verification 2d(iii)), and there is no second door to revoke.
func (s *Server) DAVAuth(realm string) vfsdav.Auth {
	return vfsdav.Bearer(realm, func(tok string) (vfsdav.Grant, bool) {
		g, ok := s.Verify(tok)
		if !ok {
			return vfsdav.Grant{}, false
		}
		return vfsdav.Grant{Subject: "oauth:" + g.Ref + " (" + g.Label + ")",
			Write: g.Write}, true
	})
}

// ------------------------------------------------------------- primitives

// mint is the only place a secret is created.
func mint() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("localoauth: mint: %w", err)
	}
	// RawURLEncoding: no padding, so no '=' for a URL, a plist or a
	// StringSubstitutor to argue about — and no '$', which a Cyberduck
	// profile value may not contain.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mintRef is a short NON-SECRET handle. 8 bytes is plenty for a list the
// user is looking at, and it is deliberately narrower than a secret so a
// ref can never be mistaken for one.
func mintRef() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("localoauth: mint ref: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mac is the per-process lookup key for a secret. HMAC rather than a bare
// hash so that the table is useless without the key, and the key never
// leaves this process.
func (s *Server) mac(secret string) [32]byte {
	h := hmac.New(sha256.New, s.key[:])
	h.Write([]byte(secret))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func filterGrants(in []*grant, keep func(*grant) bool) []*grant {
	out := in[:0]
	for _, g := range in {
		if keep(g) {
			out = append(out, g)
		}
	}
	return out
}

func filterCodes(in []*code, keep func(*code) bool) []*code {
	out := in[:0]
	for _, c := range in {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}

func filterPending(in []*pending, keep func(*pending) bool) []*pending {
	out := in[:0]
	for _, p := range in {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}
