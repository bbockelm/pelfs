package localoauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ConsentTicketField is the form field the consent page carries its ticket
// in. Exported only so a test can name it without duplicating the string.
const ConsentTicketField = "consent_ticket"

// ConsentDecisionField is the form field the Allow and Deny buttons set.
// Exactly "allow" authorizes; every other value, including a missing one,
// is a refusal.
const ConsentDecisionField = "decision"

// consentBodyLimit caps the consent POST. internal/httpguard's navigation
// surface sets no body limit — it is the surface for a route a browser
// reaches by navigation, and a navigation has no body — so this route caps
// its own. The form is four short fields.
const consentBodyLimit = 64 << 10

// AuthorizeHandler serves BOTH halves of /oauth/authorize: the GET that
// renders a consent screen and the POST that a human's click on it submits.
// Mount both on internal/httpguard's SurfaceNavigation:
//
//	r.Handle(httpguard.SurfaceNavigation, "GET /oauth/authorize", oauth.AuthorizeHandler())
//	r.Handle(httpguard.SurfaceNavigation, "POST /oauth/authorize", oauth.AuthorizeHandler())
//
// # THE X-PELFS-SESSION RULE DOES NOT APPLY HERE AND CANNOT
//
// A7 control 7, and it is written out because the natural instinct of a
// later maintainer is to make this route look like the JSON API routes, and
// the consistent version does not work. This endpoint is reached by a
// NAVIGATION that Cyberduck triggers in the user's browser — `duck` and
// Cyberduck open a URL, they do not fetch() it — so it cannot require a
// custom request header, and it cannot require a token from sessionStorage
// either, because sessionStorage belongs to the tab that minted it and this
// is a new tab. There is no header to check and no place to check it.
//
// The controls that carry the weight instead, all in this file: a client_id
// that only a profile download carries (findClient, constant time); a redirect_uri
// matched byte for byte against the one URL pelfs itself wrote into that
// client's profile; PKCE S256 required rather than accepted; and one real
// user gesture on a consent screen that cannot be framed and on which no
// script may run. If you are about to add a header requirement here, the
// thing to change is not this handler — it is Cyberduck.
//
// # NO ERROR IS EVER A REDIRECT
//
// RFC 6749 §4.1.2.1 lets an authorization server report some errors by
// redirecting to the client's redirect_uri with `error=`. This server never
// does, for any error, even one where the redirect_uri validated: A7
// control 3's whole point is that redirecting to a URI supplied in the
// request is the vulnerability, and a code path that redirects on failure is
// a code path an attacker will look for a way into. Every refusal is an
// HTML page on pelfs's own origin. The cost is real and is worth naming: a
// Cyberduck whose request is refused sits waiting on its loopback listener
// until the user cancels, because nothing arrives to tell it otherwise. The
// page in front of the user says what went wrong, which is the half of the
// exchange that can act on the information.
func (s *Server) AuthorizeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			s.authorizeGET(w, r)
		case http.MethodPost:
			s.authorizePOST(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			s.page(w, r, http.StatusMethodNotAllowed, pageData{
				Heading: "That is not how this endpoint works",
				Detail:  "GET renders the authorization screen; POST is the button on it.",
			})
		}
	})
}

// authorizeRequest is one validated authorization request. Nothing reaches
// this shape without every control having passed, which is why the consent
// page and the code minter can both take it and neither has to re-check.
type authorizeRequest struct {
	client    *client
	redirect  string
	challenge string
	state     string
	scopes    []string
	write     bool
}

// authorizeGET validates and then RENDERS. It has no path that writes a
// Location header, and that is deliberate: see the package comment on the
// consent gesture. The only caller of the code minter is authorizePOST.
func (s *Server) authorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Control 4 first, because it is the control an attacker cannot get
	// past at all: a client_id exists only inside a profile pelfs generated
	// and an authenticated session downloaded.
	s.mu.Lock()
	c := s.findClient(q.Get("client_id"))
	if c == nil {
		s.counts.UnknownClients++
		s.mu.Unlock()
		// No echo of the client_id, and the same page whether it was
		// absent, malformed or simply wrong.
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "This is not an authorization request pelfs issued",
			Detail: "The client identifier does not name a client this pelfs session " +
				"knows. A client identifier only exists inside a connection profile " +
				"that this page generated and you downloaded.",
			Hint: "If you meant to connect a WebDAV client, download a fresh profile " +
				"from the pelfs page and open that.",
		})
		return
	}
	// Control 3: exact string, one entry, no parsing, no prefix match, no
	// "is it loopback". The allowlist IS the URL pelfs wrote into this
	// client's profile.
	redirect := q.Get("redirect_uri")
	if subtle.ConstantTimeCompare([]byte(redirect), []byte(c.redirect)) != 1 {
		s.counts.RedirectMismatches++
		want := c.redirect
		s.mu.Unlock()
		// THE DETAIL IS TWO PORT NUMBERS AND NOTHING ELSE.
		//
		// No string from the request is echoed — a page that repeats an
		// attacker's string back to the user is a page that can be made to
		// say anything — but a user who is told only "that address is not
		// the one in this profile" has no next step, which is what the
		// person who reported this was left with. So: the port pelfs wrote
		// into the profile (ours, a constant of this process) and the port
		// the request asked for, PARSED TO AN INTEGER AND REFORMATTED. An
		// int that survived strconv.Atoi is not a string an attacker
		// controls the shape of; it can only be 1..65535.
		detail := "pelfs will only send an authorization back to the exact address " +
			"it wrote into the profile it generated, and this request named a " +
			"different one. Nothing has been authorized and nothing was sent " +
			"anywhere."
		if wantPort, ok := loopbackPort(want); ok {
			if gotPort, ok := loopbackPort(redirect); ok && gotPort != wantPort {
				detail = "This profile expects the client's callback on port " +
					strconv.Itoa(wantPort) + "; the client asked for port " +
					strconv.Itoa(gotPort) + " instead. That usually means port " +
					strconv.Itoa(wantPort) + " was already in use on this machine, so " +
					"the client took one of its own. Nothing has been authorized and " +
					"nothing was sent anywhere."
			} else {
				detail += " The profile's callback is on port " + strconv.Itoa(wantPort) + "."
			}
		}
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "That callback address is not the one in this profile",
			Detail:  detail,
			Hint: "Close the client, then generate a fresh profile from the pelfs " +
				"connection page: it will pick a callback port that is free right now " +
				"and write it into both the profile and this allowlist. Nobody has to " +
				"edit a plist.",
		})
		return
	}
	s.mu.Unlock()

	// Control 2. See SessionPresence for what this check is and is not.
	if !s.hasSession() {
		s.mu.Lock()
		s.counts.NoSession++
		s.mu.Unlock()
		s.page(w, r, http.StatusForbidden, pageData{
			Heading: "Open pelfs from your terminal first",
			Detail: "This pelfs process has no browser session, so there is nobody " +
				"here to authorize anything. Nothing has been issued.",
			Hint: "Run `pelfs browse` and open the link it prints, then try your " +
				"WebDAV client again.",
		})
		return
	}

	if rt := q.Get("response_type"); rt != "code" {
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "Only the authorization-code flow is supported",
			Detail: "pelfs issues authorization codes and exchanges them at its token " +
				"endpoint. There is no implicit flow and no password grant.",
		})
		return
	}

	// Control 5: PKCE S256 REQUIRED, not merely accepted. Cyberduck sends it
	// by default (AbstractProtocol.isOAuthPKCE() returns true and DAVProtocol
	// does not override it), so requiring it costs the primary client
	// nothing — and it means a code that leaks is useless without the
	// verifier that never left the client.
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if method != "S256" || !validChallenge(challenge) {
		s.mu.Lock()
		s.counts.MissingPKCE++
		s.mu.Unlock()
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "This authorization request has no PKCE challenge",
			Detail: "pelfs requires proof-of-possession (PKCE, method S256) on every " +
				"authorization. A request without it is refused rather than " +
				"downgraded, and `plain` is not accepted.",
			Hint: "Cyberduck and Mountain Duck send S256 by default; a client that " +
				"cannot is one to use the password credential with instead.",
		})
		return
	}

	scopes, write, ok := s.parseScopes(q.Get("scope"), c)
	if !ok {
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "That scope is wider than this profile",
			Detail: "A WebDAV credential from pelfs reaches the files and nothing " +
				"else — it can never publish and can never be wider than the " +
				"browse session that minted it. This request asked for more than " +
				"the profile allows.",
			Hint: "A read-only `pelfs browse` cannot hand out a writable credential. " +
				"Restart it with --rw if that is what you want.",
		})
		return
	}

	state := q.Get("state")
	if len(state) > 512 {
		// A client's own CSRF value, echoed back verbatim. Bounded because
		// it is held in memory here between two requests.
		state = state[:512]
	}

	req := authorizeRequest{
		client: c, redirect: redirect, challenge: challenge,
		state: state, scopes: scopes, write: write,
	}
	ticket, err := s.addPending(req)
	if err != nil {
		s.page(w, r, http.StatusInternalServerError, pageData{
			Heading: "pelfs could not prepare this authorization",
			Detail:  "Nothing has been issued. Try again.",
		})
		return
	}
	s.consentPage(w, r, req, ticket)
}

// authorizePOST is the ONLY caller of the code minter. It requires the
// consent ticket, which existed in exactly one place — the body of a page
// rendered in the user's own browser — and consumes it whichever button was
// pressed.
func (s *Server) authorizePOST(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, consentBodyLimit)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		// A form post from our own page sends exactly this. Requiring it
		// keeps anything else from being parsed as a decision.
		s.page(w, r, http.StatusUnsupportedMediaType, pageData{
			Heading: "That is not the consent form",
			Detail:  "This endpoint accepts the form on the pelfs authorization screen.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "That is not the consent form",
			Detail:  "pelfs could not read the submitted form.",
		})
		return
	}
	req, ok := s.takePending(r.PostFormValue(ConsentTicketField))
	if !ok {
		s.mu.Lock()
		s.counts.ConsentTicketsRefused++
		s.mu.Unlock()
		// An expired page, a page already answered, or a forged POST: one
		// answer for all three.
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "This authorization screen is no longer live",
			Detail: "Nothing was authorized. An authorization screen can be answered " +
				"once, and it expires a few minutes after it is shown.",
			Hint: "Ask your WebDAV client to connect again and a fresh screen will " +
				"appear.",
		})
		return
	}
	if r.PostFormValue(ConsentDecisionField) != "allow" {
		s.mu.Lock()
		s.counts.ConsentDenied++
		s.mu.Unlock()
		s.page(w, r, http.StatusOK, pageData{
			Heading: "Not authorized",
			Detail: "Nothing was issued and nothing was sent to the client. You can " +
				"close this tab.",
			Hint: "If you did not ask any program to connect to pelfs, this is the " +
				"outcome you want — and it is worth knowing that something tried.",
		})
		return
	}

	code, err := s.mintCode(req)
	if err != nil {
		s.page(w, r, http.StatusInternalServerError, pageData{
			Heading: "pelfs could not issue this authorization",
			Detail:  "Nothing has been issued. Ask the client to connect again.",
		})
		return
	}

	// The one redirect in this file, to the one URL that matched control 3
	// byte for byte. 303 rather than 302 so the browser turns the POST into
	// a GET, which is what Cyberduck's loopback listener answers.
	target, err := url.Parse(req.redirect)
	if err != nil {
		// Unreachable: the URI was parsed at registration. Fail closed.
		s.page(w, r, http.StatusInternalServerError, pageData{
			Heading: "pelfs could not issue this authorization",
			Detail:  "Nothing has been issued.",
		})
		return
	}
	q := url.Values{}
	q.Set("code", code)
	if req.state != "" {
		q.Set("state", req.state)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// parseScopes reads the space-delimited scope parameter. An empty scope is
// read-only; an unknown scope is a refusal rather than something to ignore,
// because a scope this server does not understand is a scope it cannot
// bound. Called without mu (it only reads the client's fixed fields).
func (s *Server) parseScopes(raw string, c *client) (scopes []string, write, ok bool) {
	if strings.TrimSpace(raw) == "" {
		return []string{ScopeRead}, false, true
	}
	seenRead := false
	for _, f := range strings.Fields(raw) {
		switch f {
		case ScopeRead:
			seenRead = true
		case ScopeWrite:
			write = true
		default:
			return nil, false, false
		}
	}
	// Write implies read: there is no write-only WebDAV client.
	_ = seenRead
	if write && (!c.write || !s.cfg.Writable) {
		// Grant-time enforcement of the ceiling, and the reason the answer
		// is a refusal rather than a silent downgrade: a client that
		// believes it has write access and does not will fail its first PUT
		// with a 403 the user cannot explain, while a refusal here is a
		// sentence on a screen.
		return nil, false, false
	}
	scopes = []string{ScopeRead}
	if write {
		scopes = append(scopes, ScopeWrite)
	}
	return scopes, write, true
}

// loopbackPort is the port of a loopback callback URL, as an INTEGER.
//
// It exists so that a refusal page can say "port 52001, not 61033" without
// echoing one byte of a caller's string: the only thing that escapes here is
// a number that survived strconv.Atoi and is in range, and the caller
// reformats it with strconv.Itoa rather than passing the original text
// through. It reports false for anything it cannot read that way, and the
// page then says less rather than guessing.
func loopbackPort(raw string) (int, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(u.Port())
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

// validChallenge is the S256 challenge's shape: base64url, no padding, of a
// SHA-256 digest, which is exactly 43 characters. Checking the shape here
// means the comparison at exchange time is against something well-formed.
func validChallenge(v string) bool {
	if len(v) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil
}

// ---------------------------------------------------------------- pending

// pending is one rendered consent page: a validated authorization request
// plus the ticket that submitting it requires. THE TICKET IS THE GESTURE:
// it is 32 bytes of crypto/rand that exist in one HTML body and nowhere
// else, so a POST carrying one is a POST that came from a page the user's
// browser rendered from this origin.
type pending struct {
	macTicket [32]byte
	clientRef string
	req       authorizeRequest
	created   time.Time
}

func (s *Server) addPending(req authorizeRequest) (string, error) {
	ticket, err := mint()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepPending()
	if len(s.pending) >= maxPending {
		// Drop the oldest rather than refuse the newest: a flood of
		// /authorize navigations must not be able to stop the user's own
		// client from connecting.
		s.pending = s.pending[1:]
	}
	s.pending = append(s.pending, &pending{
		macTicket: s.mac(ticket), clientRef: req.client.ref,
		req: req, created: s.cfg.Now(),
	})
	return ticket, nil
}

// takePending consumes a ticket. Single use, whichever button was pressed,
// so a consent page cannot be replayed into a second code.
func (s *Server) takePending(ticket string) (authorizeRequest, bool) {
	if ticket == "" {
		return authorizeRequest{}, false
	}
	mac := s.mac(ticket)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepPending()
	for i, p := range s.pending {
		if subtle.ConstantTimeCompare(mac[:], p.macTicket[:]) != 1 {
			continue
		}
		s.pending = append(s.pending[:i], s.pending[i+1:]...)
		// The client may have been revoked between the screen and the
		// click, in which case there is nothing to authorize.
		if s.findClientByRef(p.req.client.ref) == nil {
			return authorizeRequest{}, false
		}
		return p.req, true
	}
	return authorizeRequest{}, false
}

func (s *Server) findClientByRef(ref string) *client {
	for _, c := range s.clients {
		if c.ref == ref {
			return c
		}
	}
	return nil
}

// sweepPending drops expired consent pages. Called under mu on every
// pending operation, which is often enough: the set is capped at maxPending
// and a background sweeper would be a goroutine to shut down for no gain.
func (s *Server) sweepPending() {
	now := s.cfg.Now()
	s.pending = filterPending(s.pending, func(p *pending) bool {
		return now.Sub(p.created) <= ConsentTTL
	})
}

// ------------------------------------------------------------------ codes

// code is one authorization code: single use, 60-second TTL, bound to the
// client, the exact redirect_uri and the PKCE challenge. It is held as an
// HMAC, like every other secret here.
//
// A USED CODE IS KEPT until its TTL expires, rather than deleted, which is
// what makes a replay DETECTABLE instead of merely unsuccessful — and a
// replay is either a bug or an attack, so it is counted, and the grant the
// first exchange produced is revoked (RFC 6819 §5.2.1.1: a replayed code
// means the code leaked, and the token it bought is the thing at risk).
type code struct {
	macCode   [32]byte
	clientRef string
	redirect  string
	challenge string
	scopes    []string
	write     bool
	issued    time.Time
	used      bool
	// grantRef is what the first exchange produced, so a replay knows what
	// to revoke.
	grantRef string
}

func (s *Server) mintCode(req authorizeRequest) (string, error) {
	c, err := mint()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepCodes()
	if cl := s.findClientByRef(req.client.ref); cl != nil {
		// Recorded for the UI's list only. Nothing reads it to decide
		// anything; see client.consented.
		cl.consented = true
	}
	s.codes = append(s.codes, &code{
		macCode: s.mac(c), clientRef: req.client.ref, redirect: req.redirect,
		challenge: req.challenge, scopes: req.scopes, write: req.write,
		issued: s.cfg.Now(),
	})
	return c, nil
}

func (s *Server) sweepCodes() {
	now := s.cfg.Now()
	s.codes = filterCodes(s.codes, func(c *code) bool {
		return now.Sub(c.issued) <= CodeTTL
	})
}

// ------------------------------------------------------------------ pages

// pageData is the text of one served page. Everything in it is written by
// this package: no field is ever filled from the request, because a page
// that repeats an attacker's string back to the user is a page that can be
// made to say anything.
type pageData struct {
	Heading string
	Detail  string
	Hint    string
}

// consentData is the consent screen. Client and Redirect DO come from the
// request in the sense that the client chose them — but Client is the label
// an authenticated session typed when it generated the profile, and
// Redirect is the URL pelfs itself wrote into that profile and has just
// compared byte for byte, so neither is attacker-supplied text. Both are
// escaped anyway, by html/template, because that is not a judgement call to
// make per field.
type consentData struct {
	Client   string
	Volume   string
	Scope    string
	Redirect string
	Write    bool
	Ticket   string
	Action   string
	Nonce    string
	Field    string
	Decision string
}

// consentCSP is the consent page's own policy, and it REPLACES
// internal/httpguard's default (which sets `form-action 'none'`, so the
// form would not submit under it). `%s` is the style nonce and `%r` is the
// client's callback URL; both are substituted by cspFor.
//
// The three clauses that are load-bearing rather than tidy:
//
//   - `script-src 'none'`: this is the structural half of "one real user
//     gesture". No script may execute on this document, so no script can
//     call form.submit(), so the only thing that can submit the consent
//     form is a person activating the button. The page contains no script
//     either, but the header is what makes it impossible rather than merely
//     absent.
//
//   - `form-action 'self'`: the form may post to this origin, so an
//     injected form cannot exfiltrate the ticket even in a world where
//     injection were possible on a page with no script.
//
//   - AND THE CLIENT'S CALLBACK URL, EXACTLY, WITHOUT WHICH THE FLOW
//     CANNOT COMPLETE IN CHROMIUM. `form-action` is enforced on the
//     REDIRECTS of a form submission, not only on its first hop, and the
//     one thing a successful authorization does is 303 the POST to the
//     client's own loopback listener — a different origin. So `'self'`
//     alone blocked the last step of every real-browser flow:
//
//     Sending form data to 'http://127.0.0.1:PORT/oauth/authorize'
//     violates the following Content Security Policy directive:
//     "form-action 'self'". The request has been blocked.
//
//     with the code minted, the consent recorded, the browser sitting on
//     the consent page, and Cyberduck waiting on a callback that never
//     arrives. No curl-driven gate could see it: curl does not implement
//     CSP. See scripts/oauth-browser-docker.sh, which does.
//
//     The value is safe because it is not a value from the request: it is
//     the URL pelfs itself wrote into this client's profile, which control
//     3 has just compared byte for byte, and which CheckRedirectURI has
//     already confined to a loopback literal with an explicit port and no
//     character that could break a header. CSP source matching ignores the
//     query, so the `?code=…&state=…` the redirect appends is covered by
//     naming the path alone — and naming the path rather than the origin
//     means a form on this page could not be redirected to any OTHER
//     resource on the client's port either.
//
// The style nonce is there so the page can have a stylesheet without
// 'unsafe-inline' anywhere on this listener.
const consentCSP = "default-src 'none'; script-src 'none'; style-src 'nonce-%s'; " +
	"img-src 'none'; connect-src 'none'; form-action 'self' %r; base-uri 'none'; " +
	"frame-ancestors 'none'"

// pageCSP is consentCSP for a page with NO form: every refusal and every
// acknowledgement this package serves. `form-action 'none'` rather than
// 'self' because none of these pages has anything to submit, and a page
// that cannot submit anywhere is one fewer thing to reason about.
const pageCSP = "default-src 'none'; script-src 'none'; style-src 'nonce-%s'; " +
	"img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; " +
	"frame-ancestors 'none'"

// cspFor substitutes the nonce and, for the consent page, the one callback
// URL the form may be redirected to.
func cspFor(policy, nonce, redirect string) string {
	p := strings.Replace(policy, "%s", nonce, 1)
	return strings.Replace(p, "%r", redirect, 1)
}

func (s *Server) consentPage(w http.ResponseWriter, r *http.Request, req authorizeRequest, ticket string) {
	nonce, err := mintRef()
	if err != nil {
		s.page(w, r, http.StatusInternalServerError, pageData{
			Heading: "pelfs could not prepare this authorization",
			Detail:  "Nothing has been issued.",
		})
		return
	}
	scope := "read only — list and download"
	if req.write {
		scope = "read AND WRITE — list, download, upload, rename and delete"
	}
	data := consentData{
		Client: req.client.label, Volume: s.cfg.Volume, Scope: scope,
		Redirect: req.redirect, Write: req.write, Ticket: ticket,
		Action: r.URL.EscapedPath(), Nonce: nonce,
		Field: ConsentTicketField, Decision: ConsentDecisionField,
	}
	w.Header().Set("Content-Security-Policy", cspFor(consentCSP, nonce, req.redirect))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_ = consentTmpl.Execute(w, data)
}

// page serves one of this package's own refusals or acknowledgements. Same
// strict CSP as the consent screen, minus the form (pageCSP).
func (s *Server) page(w http.ResponseWriter, r *http.Request, status int, data pageData) {
	nonce, err := mintRef()
	if err != nil {
		http.Error(w, data.Heading, status)
		return
	}
	w.Header().Set("Content-Security-Policy", cspFor(pageCSP, nonce, ""))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = pageTmpl.Execute(w, struct {
		pageData
		Nonce string
	}{data, nonce})
}

// The two templates. html/template, so every value is escaped in its
// context; and no script, no image, no external anything, so the page
// renders identically with the CSP above.
var (
	pageStyle = `
<style nonce="{{.Nonce}}">
 body { font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, sans-serif;
        max-width: 40rem; margin: 3rem auto; padding: 0 1.25rem; color: #1a1a1a; }
 h1 { font-size: 1.35rem; margin: 0 0 .75rem; }
 dl { margin: 1.25rem 0; display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }
 dt { color: #555; }
 dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
 .rw { color: #a2431c; }
 .why { color: #555; font-size: .92rem; border-top: 1px solid #e3e3e3;
        margin-top: 1.75rem; padding-top: .9rem; }
 form { margin: 1.5rem 0 0; display: flex; gap: .75rem; }
 button { font: inherit; padding: .55rem 1.1rem; border-radius: .35rem;
          border: 1px solid #bbb; background: #f6f6f6; cursor: pointer; }
 button.go { border-color: #0f6ecd; background: #0f6ecd; color: #fff; font-weight: 600; }
</style>`

	consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize a WebDAV client — pelfs</title>` + pageStyle + `</head><body>
<h1>Authorize a WebDAV client?</h1>
<p>A program is asking pelfs for a credential it can use to reach this
volume's files.</p>
<dl>
 <dt>program</dt><dd>{{.Client}}</dd>
 <dt>volume</dt><dd>{{.Volume}}</dd>
 <dt>access</dt><dd{{if .Write}} class="rw"{{end}}>{{.Scope}}</dd>
 <dt>sends the authorization to</dt><dd>{{.Redirect}}</dd>
</dl>
<form method="post" action="{{.Action}}">
 <input type="hidden" name="{{.Field}}" value="{{.Ticket}}">
 <button class="go" type="submit" name="{{.Decision}}" value="allow">Authorize</button>
 <button type="submit" name="{{.Decision}}" value="deny">Do not authorize</button>
</form>
<p class="why">If you did not just ask a program to connect to pelfs,
choose <em>Do not authorize</em>. This screen is the one thing standing
between a page you happened to visit and a credential for your files, and
nothing is issued until you press a button on it. The credential reaches
this volume's files only: it can never publish, and it dies when
<code>pelfs browse</code> exits.</p>
</body></html>
`))

	pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Heading}} — pelfs</title>` + pageStyle + `</head><body>
<h1>{{.Heading}}</h1>
<p>{{.Detail}}</p>
{{if .Hint}}<p class="why">{{.Hint}}</p>{{end}}
</body></html>
`))
)

// s256 is the PKCE transform, here rather than inline so the exchange and
// any test agree on it: base64url(sha256(verifier)), unpadded.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
