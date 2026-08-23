package main

// The federation SSO card: work item U13 of docs/design-webui.md.
//
// A physicist runs `pelfs browse`, a browser opens, and their institution
// wants them to approve access. Today that conversation happens in the
// terminal they were just told they would not need. This is the registry
// that puts it on the page instead.
//
// # The hook, and the three properties of it that shape everything here
//
// pelican's oauth2.SetVerificationURLHandler installs a
// func(verificationURL, userCode string) that AcquireToken calls when a
// device flow starts. Reading it (oauth2/oauth2.go in the pinned fork):
//
//  1. IT IS PROCESS-WIDE — an atomic.Pointer, one handler per process —
//     because the TokenGenerationOpts that AcquireToken receives is built
//     inside client and cmd, so an embedder has nothing to put a per-call
//     field on. Consequence: there is exactly ONE place in pelfs allowed to
//     install it, and that place is runBrowse. Not internal/pelicanobj, and
//     not an init(): `pelfs mount` and `pelfs get` in the same binary must
//     keep the terminal behaviour, and a package both verbs import would
//     change it for both.
//  2. IT RUNS ON THE GOROUTINE DRIVING THE FLOW AND BLOCKS IT. The hook's
//     own doc comment says so: "a handler that blocks delays the user's own
//     approval". So Add does one map insert under one mutex and returns.
//     It never writes to a network connection — a half-closed SSE client
//     would otherwise delay the user's own login — and it never waits on a
//     lock a slow reader could be holding, which is why the fan-out to the
//     streams happens on a goroutine of the registry's own.
//  3. IT IS ONE-WAY. The handler learns that a flow STARTED. Nothing tells
//     it the flow finished, failed, or expired. Everything the card says is
//     shaped by that: it says "waiting for you to approve at your
//     institution", it is dismissible by hand, it greys out on a TTL of our
//     own choosing (the issuer's expires_in is not exposed to the handler),
//     and it NEVER says "authorization complete", because this code cannot
//     know that. The real completion signal is that the operation which was
//     waiting succeeded — the volume opens and the page shows the file
//     view.
//
// A fourth property is worth stating because it removes an obligation: the
// hook fires AFTER pelican's unconditional write to stderr, never instead
// of it. A headless `pelfs browse` on a login node still tells the user in
// the terminal, and this registry failing silently costs nothing. So
// nothing here re-prints the URL.
//
// # Concurrent prompts, and why this is a set rather than a slot
//
// client.AcquireToken has no global serialization around the device flow —
// no mutex, no singleflight — so two goroutines needing tokens for two
// namespaces can each open one. Since the handler is process-wide, both
// arrive HERE, on different goroutines, possibly at the same instant. Three
// consequences, all of them decisions:
//
//   - The registry is a SET, keyed by a hash of the URL and code, so a
//     retried flow that produces the same prompt appears once. Two flows
//     with genuinely different codes are two cards.
//   - The UI is a LIST OF CARDS, not a modal. A modal would have to pick
//     one of two prompts to show and hide the other, and the user needs to
//     complete both.
//   - Order is arrival order and it is stable, because the cards carry
//     codes a person is typing from and a list that reorders under them is
//     hostile.
//
// # The prompt that arrives before any browser has connected
//
// This is the failure the design names, and it is the ordering, not the
// registry, that prevents it: runBrowse binds the listener, prints the URL,
// starts serving and installs this handler BEFORE it opens the volume, so
// the page is loadable before anything can prompt. The registry's job is
// the remaining half — a prompt raised in the second between the browser
// launching and the page's stream attaching must not be lost. It is not,
// because the registry is the state and /events carries SNAPSHOTS: the
// first frame a stream ever receives contains every live prompt, and so
// does GET /api/v1/info. Nothing is delivered only on the edge.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pelicanplatform/pelican/oauth2"
)

// installPromptHandler points pelican's process-wide device-flow hook at
// this session's registry, and returns the removal.
//
// ONE CALLER, EVER: runBrowse. The hook is an atomic.Pointer with one slot
// for the whole process, so a second installer would silently replace the
// first, and an installer in a package that `pelfs mount` also imports
// would change that verb's behaviour too — its user is at a terminal that
// already gets the URL.
//
// The handler it installs does one map insert and returns; see Add.
func installPromptHandler(b *browseServer) func() {
	h := promptHandler(b)
	// Kept so a test can fire what was actually installed. pelican's
	// dispatcher (announceVerification) is unexported, so this is the
	// closest observable point on this side of the module boundary; the
	// dispatch half — that AcquireToken calls the stored pointer, after
	// writing to stderr and before polling — is covered by that module's
	// own oauth2 tests.
	installedPromptHandler.Store(&h)
	oauth2.SetVerificationURLHandler(h)
	return func() {
		installedPromptHandler.Store(nil)
		oauth2.SetVerificationURLHandler(nil)
	}
}

// promptHandler is the function pelican calls. It is separate from the
// installation so that what runs on the device flow's goroutine is one
// named thing rather than a closure buried in a startup sequence.
func promptHandler(b *browseServer) oauth2.VerificationURLHandler {
	return func(verificationURL, userCode string) {
		b.prompts.Add(verificationURL, userCode)
	}
}

// installedPromptHandler mirrors what installPromptHandler last stored.
var installedPromptHandler atomic.Pointer[oauth2.VerificationURLHandler]

// fireVerificationHandler calls whatever is installed, the way pelican's
// announceVerification does. Nothing in a real run calls it; it exists so a
// test can drive the installed handler rather than a copy of it.
func fireVerificationHandler(verificationURL, userCode string) {
	if h := installedPromptHandler.Load(); h != nil {
		(*h)(verificationURL, userCode)
	}
}

// ssoPromptTTL is how long a card is presented as live.
//
// It is OURS TO PICK, and that is not laziness: RFC 8628 device codes
// typically expire in minutes, but the issuer's expires_in is not exposed
// to the handler, so there is nothing to inherit. Ten minutes is longer
// than any device code this will see, which is the right direction to err —
// a card that outlives its code says "expired" a little late, while a card
// that vanishes early leaves a user staring at a code they cannot use.
const ssoPromptTTL = 10 * time.Minute

// ssoPromptGrace is how long an expired card lingers, greyed out, before it
// is forgotten. docs/design-webui.md asks for the greying rather than the
// vanishing, and the reason is that a card disappearing from under someone
// mid-typing is indistinguishable from a bug.
const ssoPromptGrace = 10 * time.Minute

// ssoPromptMax bounds the registry. The hook is called by code we do not
// control on goroutines we do not count, so the one thing this must not be
// is unbounded. Eight is far past the plausible case (one flow per
// namespace, primed once per session) and small enough that the whole set
// fits on the page.
const ssoPromptMax = 8

// ssoPrompt is one card. It carries what the user must DO and nothing else.
//
// THERE IS NO TOKEN FIELD, and that is the point: the handler is not given
// one — it receives a verification URL and a user code, never a credential
// — and this struct is serialized straight into the state document that
// /events pushes to the browser. A federation token on that document would
// be a credential in a page's memory, in a browser's memory, and in
// whatever the browser's process does with its memory. The absence is
// asserted by a test rather than left to reading.
type ssoPrompt struct {
	// ID is a hash of the prompt's contents, so it is stable across
	// repeats and carries nothing secret. It is what the dismiss route
	// names.
	ID string `json:"id"`
	// URL is where the user must go. When the issuer supplied a
	// verification_uri_complete it already carries the code and Code is
	// empty; otherwise it is the plain verification_uri and Code is what
	// they must type there. The hook normalizes the two RFC 8628 shapes, so
	// this code does not have to know which it got.
	URL  string `json:"url"`
	Code string `json:"code,omitempty"`
	// At is when the flow started, so the page can count.
	At time.Time `json:"at"`
	// AgeS is At in seconds, computed at sample time. The page gets a
	// number rather than doing clock arithmetic against a server it cannot
	// assume shares its clock.
	AgeS int64 `json:"age_s"`
	// Expired is the TTL having passed: the card greys out and says the
	// code is probably no longer accepted, which is the honest thing this
	// can say without the flow telling it anything.
	Expired bool `json:"expired,omitempty"`
}

// promptRegistry is the in-memory set of live prompts.
//
// Small, self-contained and clock-injected, so the TTL is testable without
// waiting ten minutes: the whole reason it is not a channel to a connection
// is properties 2 and 3 of the hook (see the file comment).
type promptRegistry struct {
	now    func() time.Time
	notify func()

	mu sync.Mutex
	// live is arrival-ordered. A slice rather than a map because it is
	// bounded at ssoPromptMax and order is part of the contract; the
	// dedupe scan is over at most eight entries.
	live []*ssoPrompt
}

func newPromptRegistry(now func() time.Time, notify func()) *promptRegistry {
	if now == nil {
		now = time.Now
	}
	return &promptRegistry{now: now, notify: notify}
}

// Add is the handler body: the single thing the device flow's goroutine
// does here before it goes back to polling the issuer.
//
// It is deliberately dull. One lock, one append, one goroutine spawned to
// tell the streams, and no I/O of any kind. Everything interesting about
// the card — expiry, ordering, what the page shows — is decided in Cards,
// which runs on a request's goroutine where blocking costs nobody their
// login.
func (r *promptRegistry) Add(rawURL, code string) {
	if !approvalURL(rawURL) {
		// Nothing showable. The hook is only called when the issuer named
		// a URL at all, so the empty case is defence — but the SCHEME
		// check is not: this string comes from an issuer's device-flow
		// response, it becomes an href on the page, and `javascript:` in
		// an href is script execution in this origin. The CSP would not
		// stop it (a javascript: URL a user clicks is a navigation, not a
		// script-src fetch), so it is refused here, where the refusal is
		// testable.
		return
	}
	now := r.now()
	sum := sha256.Sum256([]byte(rawURL + "\x00" + code))
	id := hex.EncodeToString(sum[:6])
	r.mu.Lock()
	found := false
	for _, p := range r.live {
		if p.ID != id {
			continue
		}
		// The same prompt again: a retried flow, or a second namespace
		// whose issuer produced the same URL and code. Refresh the clock
		// rather than adding a duplicate — the user still has to do it,
		// and now they have the full TTL to.
		p.At, found = now, true
		break
	}
	if !found {
		r.live = append(r.live, &ssoPrompt{ID: id, URL: rawURL, Code: code, At: now})
		// Bounded, oldest first. A prompt this drops is one the user has
		// had ssoPromptMax newer ones on top of.
		if len(r.live) > ssoPromptMax {
			r.live = r.live[len(r.live)-ssoPromptMax:]
		}
	}
	r.mu.Unlock()
	// OFF this goroutine, always. The fan-out takes browseServer's mutex,
	// which a state() sample holds while it reads the overlay, and this
	// goroutine is the one the user's own approval is waiting on.
	if r.notify != nil {
		go r.notify()
	}
}

// approvalURL reports whether a string is something a user can safely be
// invited to open: an absolute http or https URL with a host.
//
// Nothing else qualifies. A relative reference cannot be an issuer's
// verification endpoint, and every other scheme is either useless here or
// dangerous in an href (`javascript:`, `data:`).
func approvalURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// Cards is what the state document carries: copies, ordered by arrival,
// with the TTL applied and the dead ones forgotten.
func (r *promptRegistry) Cards() []ssoPrompt {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	keep := r.live[:0]
	out := make([]ssoPrompt, 0, len(r.live))
	for _, p := range r.live {
		age := now.Sub(p.At)
		if age > ssoPromptTTL+ssoPromptGrace {
			continue // forgotten; the code expired long ago
		}
		keep = append(keep, p)
		card := *p
		card.AgeS = int64(age.Seconds())
		card.Expired = age > ssoPromptTTL
		out = append(out, card)
	}
	r.live = keep
	if len(out) == 0 {
		// nil rather than an empty slice, so the state document omits the
		// field entirely and an unchanged snapshot stays byte-identical
		// (serveEvents suppresses frames that did not change).
		return nil
	}
	return out
}

// Dismiss removes one card and reports whether it was there.
//
// Dismissal is a USER action because the hook is one-way: nothing tells
// this process that a flow finished, failed or was abandoned, so there is
// no event that could retire a card on the user's behalf. What retires it
// implicitly is the thing the user actually cares about — the volume
// opening — and that is a different part of the page.
func (r *promptRegistry) Dismiss(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.live {
		if p.ID == id {
			r.live = append(r.live[:i], r.live[i+1:]...)
			return true
		}
	}
	return false
}
