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
// # NOTHING HERE IS EVER A REDIRECT — NOT AN ERROR, AND NOT A SUCCESS
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
//
// THE SUCCESS PATH STOPPED REDIRECTING TOO, and for a usability reason
// rather than a security one: a 303 to the client's callback left the user
// staring at a dead tab, because Cyberduck's loopback listener answers by
// closing the connection. connectedPage is the replacement — a real page on
// pelfs's own origin, with the authorization delivered from a hidden frame —
// and its comment is the whole argument. So this file now writes NO Location
// header anywhere, on any path, which is a stronger version of the property
// control 6 already had.
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
		//
		// IT NAMES THE VOLUME THIS LISTENER IS SERVING, and that is not
		// decoration: `pelfs browse` probes upward from 8443
		// (cmd/pelfs/browseport.go), so the port no longer identifies the
		// volume, and the ordinary way an honest user reaches this page is
		// now a saved bookmark for volume A meeting a session serving
		// volume B on the port A had yesterday. Without the volume on the
		// page that is indistinguishable from a corrupt profile, and the
		// user's next move is to re-download the profile that was never
		// wrong. The volume is this process's own configuration, not a
		// string from the request, so echoing it tells an attacker nothing
		// they did not have to know to send the request.
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "This is not an authorization request pelfs issued",
			Detail: "The client identifier does not name a client this pelfs session " +
				"knows. A client identifier only exists inside a connection profile " +
				"that this page generated and you downloaded. This listener is serving " +
				volumeName(s.cfg.Volume) + ".",
			Hint: "If this profile was made for a different volume, that is the whole " +
				"problem: pelfs sessions share a small range of ports, so a saved " +
				"bookmark can reach the wrong one. Open the pelfs page for the volume " +
				"you want and download a fresh profile from it.",
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
	entry, answer := s.takePending(r.PostFormValue(ConsentTicketField))
	switch answer {
	case ticketUnknown:
		s.mu.Lock()
		s.counts.ConsentTicketsRefused++
		s.mu.Unlock()
		// An expired page or a forged POST: one answer for both. A page we
		// DID mint and the user pressed twice no longer lands here — see
		// ticketSpent below, and pending's comment for how the two are told
		// apart.
		s.page(w, r, http.StatusBadRequest, pageData{
			Heading: "This authorization screen is no longer live",
			Detail: "Nothing was authorized. An authorization screen expires a few " +
				"minutes after it is shown.",
			Hint: "Ask your WebDAV client to connect again and a fresh screen will " +
				"appear.",
		})
		return
	case ticketSpent:
		// THE SECOND PRESS. Nothing is minted, nothing is re-sent, and the
		// page says what the first press already did.
		s.mu.Lock()
		s.counts.ConsentRepeats++
		denied := entry.denied
		alive := s.authorizationAlive(entry)
		label := entry.req.client.label
		s.mu.Unlock()
		switch {
		case denied:
			s.page(w, r, http.StatusOK, pageData{
				Heading: "Not authorized",
				Detail:  "That was already refused. Nothing has been issued.",
			})
		case alive:
			s.page(w, r, http.StatusOK, pageData{
				Heading: "Already connected",
				Detail: label + " is already authorized from this screen. Pressing " +
					"Authorize again does not issue a second credential. You can close " +
					"this tab.",
			})
		default:
			s.page(w, r, http.StatusOK, pageData{
				Heading: "That authorization has already been used",
				Detail: "Nothing further has been issued. If " + label + " is not " +
					"connected, ask it to connect again and a fresh screen will appear.",
			})
		}
		return
	}
	req := entry.req

	if r.PostFormValue(ConsentDecisionField) != "allow" {
		s.mu.Lock()
		s.counts.ConsentDenied++
		entry.denied = true
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

	code, rec, err := s.mintCode(req)
	if err != nil {
		s.page(w, r, http.StatusInternalServerError, pageData{
			Heading: "pelfs could not issue this authorization",
			Detail:  "Nothing has been issued. Ask the client to connect again.",
		})
		return
	}
	s.mu.Lock()
	entry.code = rec
	s.mu.Unlock()

	// The one URL this file will send an authorization to: the one that
	// matched control 3 byte for byte.
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
	s.connectedPage(w, r, req, target.String())
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

	// WHAT A SPENT TICKET REMEMBERS, AND WHY IT IS KEPT RATHER THAN
	// DELETED.
	//
	// The ticket used to be removed the moment it was answered, so a second
	// press of Authorize — the user double-clicking, or reloading the page
	// the first press produced — was indistinguishable from a forged POST
	// and got the forged POST's page: "This authorization screen is no
	// longer live", which tells a person who just successfully connected a
	// program that something went wrong. That was the reported bug.
	//
	// Keeping the entry, marked spent, is what tells the two apart, and it
	// tells them apart on evidence rather than on a guess: the ticket is 32
	// bytes of crypto/rand that existed in exactly one place, the body of a
	// page this server rendered into the user's own browser. A caller who
	// can produce it HAS BEEN SHOWN THAT PAGE. A forger who never saw it
	// cannot, and still lands on the refusal.
	//
	// NOTHING IS RELAXED BY THIS. A spent ticket mints nothing: the second
	// press does not call the code minter, does not re-issue anything, and
	// does not re-deliver the code. It is answered with a page describing
	// what the FIRST press already did. The single-use rule is exactly
	// where it was.
	spent  bool
	denied bool
	// code is what the first press minted, kept as a pointer so this entry
	// can see it get exchanged (and revoked, and expire) without holding a
	// second copy of anything. nil when the answer was Deny.
	code *code
}

// authorizationAlive reports whether what the first press of a consent
// screen bought is still worth anything: an unexchanged code inside its
// 60-second window, or the grant that exchanging it produced. Called under
// mu.
//
// It is what makes the second press say "already connected" rather than
// "already tried": if the user revoked the grant from the page between the
// two presses, or the code aged out unexchanged, the honest answer is that
// there is nothing there and the client should connect again.
func (s *Server) authorizationAlive(p *pending) bool {
	if p.code == nil {
		return false
	}
	if !p.code.used {
		return s.cfg.Now().Sub(p.code.issued) <= CodeTTL
	}
	for _, g := range s.grants {
		if g.ref == p.code.grantRef {
			return true
		}
	}
	return false
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

// ticketAnswer is what a consent POST's ticket resolved to.
type ticketAnswer int

const (
	// ticketUnknown: no entry matched. An expired page, or a forged POST.
	// One answer for both, as before.
	ticketUnknown ticketAnswer = iota
	// ticketFresh: the entry is ours and has not been answered. This is the
	// only value that lets a code be minted.
	ticketFresh
	// ticketSpent: the entry is ours and was answered already — a second
	// press. Nothing is minted for it.
	ticketSpent
)

// takePending resolves a ticket and, for a fresh one, marks it spent.
//
// SINGLE USE IS UNCHANGED: exactly one call can ever come back ticketFresh
// for a given ticket, because the first one flips the flag under the same
// lock. What changed is that the entry survives its own use, so a second
// press is answered as a second press instead of as a forgery. See
// pending's own comment for why that is evidence and not a guess.
func (s *Server) takePending(ticket string) (*pending, ticketAnswer) {
	if ticket == "" {
		return nil, ticketUnknown
	}
	mac := s.mac(ticket)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepPending()
	var found *pending
	for _, p := range s.pending {
		// No early return: which entry matched must not be timeable.
		if subtle.ConstantTimeCompare(mac[:], p.macTicket[:]) == 1 {
			found = p
		}
	}
	if found == nil {
		return nil, ticketUnknown
	}
	if found.spent {
		return found, ticketSpent
	}
	// The client may have been revoked between the screen and the click, in
	// which case there is nothing to authorize — and the entry goes with
	// it, because a ticket for a client that no longer exists must not
	// start answering "already connected".
	if s.findClientByRef(found.req.client.ref) == nil {
		s.pending = filterPending(s.pending, func(p *pending) bool { return p != found })
		return nil, ticketUnknown
	}
	found.spent = true
	return found, ticketFresh
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

// mintCode mints one authorization code and hands back both the secret and
// the record, so the consent entry that produced it can watch what becomes
// of it (authorizationAlive).
func (s *Server) mintCode(req authorizeRequest) (string, *code, error) {
	c, err := mint()
	if err != nil {
		return "", nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepCodes()
	if cl := s.findClientByRef(req.client.ref); cl != nil {
		// Recorded for the UI's list only. Nothing reads it to decide
		// anything; see client.consented.
		cl.consented = true
	}
	rec := &code{
		macCode: s.mac(c), clientRef: req.client.ref, redirect: req.redirect,
		challenge: req.challenge, scopes: req.scopes, write: req.write,
		issued: s.cfg.Now(),
	}
	s.codes = append(s.codes, rec)
	return c, rec, nil
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

// consentData is the consent screen, and it is now exactly three facts and
// the form.
//
// WHAT IT DELIBERATELY NO LONGER CARRIES is the callback URL — the row that
// read "sends the authorization to http://127.0.0.1:52001/pelfs/oauth/
// callback". It was on the screen because A7's list of what a consent page
// must name includes the redirect target, and the owner's verdict on it is
// the better one: it is useless. A loopback URL with a port in it is not
// information a person can act on; it tells them nothing about whether to
// press the button, and the security work it looks like it is doing is done
// elsewhere and unconditionally — the URL is matched byte for byte against
// the one pelfs itself wrote into this client's profile (control 3), and no
// authorization goes anywhere else whatever the screen says.
//
// What remains is what makes the click meaningful: WHICH PROGRAM, WHICH
// VOLUME, WHAT ACCESS. Client is the label an authenticated session typed
// when it generated the profile, not attacker text; it is escaped anyway,
// by html/template, because that is not a judgement call to make per field.
type consentData struct {
	Client   string
	Volume   string
	Scope    string
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
//   - `form-action 'self'`, AND ONLY 'self'. The form may post to this
//     origin, so an injected form cannot exfiltrate the ticket even in a
//     world where injection were possible on a page with no script.
//
//     This clause used to also name the client's callback URL, because
//     `form-action` is enforced on the REDIRECTS of a form submission and
//     the POST used to answer 303 to the client's loopback listener — a
//     different origin. `'self'` alone blocked the last step of every
//     real-browser flow:
//
//     Sending form data to 'http://127.0.0.1:PORT/oauth/authorize'
//     violates the following Content Security Policy directive:
//     "form-action 'self'". The request has been blocked.
//
//     with the code minted, the browser sitting on the consent page, and
//     Cyberduck waiting on a callback that never arrived. No curl-driven
//     gate could see it — curl does not implement CSP — and
//     scripts/oauth-browser-docker.sh exists because of it.
//
//     THE POST NO LONGER REDIRECTS AT ALL (connectedPage), so the extra
//     source is not merely unnecessary now, it is a cross-origin form
//     target that nothing uses, and those rot. The callback URL moved to
//     the one directive that still needs it: `frame-src` on the SUCCESS
//     page, connectedCSP. If a later change puts a 303 back here, the
//     browser gate goes red on the console message above, which is the
//     outcome we want.
//
// The style nonce is there so the page can have a stylesheet without
// 'unsafe-inline' anywhere on this listener.
const consentCSP = "default-src 'none'; script-src 'none'; style-src 'nonce-%s'; " +
	"img-src 'none'; connect-src 'none'; form-action 'self'; base-uri 'none'; " +
	"frame-ancestors 'none'"

// pageCSP is consentCSP for a page with NO form: every refusal and every
// acknowledgement this package serves. `form-action 'none'` rather than
// 'self' because none of these pages has anything to submit, and a page
// that cannot submit anywhere is one fewer thing to reason about.
const pageCSP = "default-src 'none'; script-src 'none'; style-src 'nonce-%s'; " +
	"img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; " +
	"frame-ancestors 'none'"

// connectedCSP is the success page's, and the ONE `frame-src` on this
// listener. `%r` is the client's registered callback URL — see connectedPage
// for why the delivery is a frame rather than a redirect. Naming the exact
// URL rather than an origin means nothing else on the client's port can be
// framed either.
//
// IT IS THE URL WITHOUT THE QUERY, and that is not a simplification. A CSP
// source expression may not carry a query: Chromium parses one and reports
//
//	The source list for Content Security Policy directive 'frame-src'
//	contains a source with an invalid path: '/pelfs/oauth/callback?code=…'.
//	The query component, including the '?', will be ignored.
//
// which it then does — so the policy still works and a console error is
// emitted on every successful authorization, which is exactly the class of
// silent-but-wrong that scripts/oauth-browser-docker.sh exists to catch (it
// caught this one). Source matching ignores the query anyway, so naming the
// path alone is both correct and the only spellable version.
const connectedCSP = "default-src 'none'; script-src 'none'; style-src 'nonce-%s'; " +
	"img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'; " +
	"frame-ancestors 'none'; frame-src %r"

// cspFor substitutes the nonce and, for the success page, the one callback
// URL a frame may be pointed at.
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
		Write: req.write, Ticket: ticket,
		Action: r.URL.EscapedPath(), Nonce: nonce,
		Field: ConsentTicketField, Decision: ConsentDecisionField,
	}
	w.Header().Set("Content-Security-Policy", cspFor(consentCSP, nonce, ""))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_ = consentTmpl.Execute(w, data)
}

// connectedPage is what a user sees after pressing Authorize, and it is a
// PAGE rather than a redirect for the reason the whole of item 1 exists.
//
// # The bug it fixes
//
// "When I click Authorize, nothing happens in the browser. I'd expect a
// 'success' type page." The POST used to answer 303 straight to the client's
// loopback callback, and Cyberduck's LoopbackOAuth2AuthorizationCodeProvider
// answers a captured authorization by CLOSING THE CONNECTION rather than by
// writing a response. So the browser's last act in the flow was to land on a
// dead tab — ERR_EMPTY_RESPONSE, or a blank page, depending on the browser —
// at the exact moment everything had in fact worked. The user could not tell
// success from failure, which for a screen whose whole job is informed
// consent is the worst possible ending.
//
// # How the authorization still reaches the client
//
// The code has to arrive at the client's own listener; that is the protocol,
// and nothing about the user's tab changes it. So the success page carries
// ONE HIDDEN FRAME whose src is exactly the URL the 303 used to name — same
// origin, same path, same `?code=…&state=…`. The browser issues the same GET
// it issued before, Cyberduck's HttpServer reads the query off it and
// captures the code, and the fact that it then answers with nothing is now
// invisible: it happens inside a frame nobody looks at, while the top-level
// document stays on pelfs's own page saying the program is connected.
//
// The frame is what the redirect was, minus the part where the user has to
// look at the result. Everything the redirect had, it has: the URL is the
// one that matched control 3 byte for byte, it is the only source
// `frame-src` allows (connectedCSP), and `Referrer-Policy: same-origin`
// means the request carries no Referer to a cross-origin callback, so
// nothing about the authorization URL travels with it.
//
// # Why the page does not offer to do it again
//
// There is no "retry" link and there must not be: a second delivery of the
// same code is a code presented twice, and a token endpoint that sees that
// without a PKCE verifier revokes the grant (token.go). The re-press path in
// authorizePOST is what handles a user who presses again, and it
// deliberately re-sends nothing.
func (s *Server) connectedPage(w http.ResponseWriter, r *http.Request, req authorizeRequest, deliver string) {
	nonce, err := mintRef()
	if err != nil {
		// The code is minted and the client is waiting; a page with a
		// weaker policy is not on the table, so say what happened plainly.
		http.Error(w, "connected", http.StatusOK)
		return
	}
	// req.redirect and NOT deliver: the policy names the path, the frame
	// carries the query. See connectedCSP.
	w.Header().Set("Content-Security-Policy", cspFor(connectedCSP, nonce, req.redirect))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_ = connectedTmpl.Execute(w, struct {
		Client  string
		Volume  string
		Deliver string
		Nonce   string
	}{req.client.label, s.cfg.Volume, deliver, nonce})
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
 /* The delivery frame on the success page. NOT display:none — a frame
    that is not rendered is a frame a browser may decline to fetch, and
    fetching it IS the delivery. Zero-sized and out of the flow instead. */
 iframe.deliver { position: absolute; width: 0; height: 0; border: 0; visibility: hidden; }
</style>`

	consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize a WebDAV client — pelfs</title>` + pageStyle + `</head><body>
<h1>Authorize a WebDAV client?</h1>
<dl>
 <dt>program</dt><dd>{{.Client}}</dd>
 <dt>volume</dt><dd>{{.Volume}}</dd>
 <dt>access</dt><dd{{if .Write}} class="rw"{{end}}>{{.Scope}}</dd>
</dl>
<form method="post" action="{{.Action}}">
 <input type="hidden" name="{{.Field}}" value="{{.Ticket}}">
 <button class="go" type="submit" name="{{.Decision}}" value="allow">Authorize</button>
 <button type="submit" name="{{.Decision}}" value="deny">Do not authorize</button>
</form>
</body></html>
`))

	// connectedTmpl is the success page. The frame is the delivery (see
	// connectedPage); everything visible is a heading, the two facts that
	// say which program reached which volume, and one instruction.
	connectedTmpl = template.Must(template.New("connected").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected — pelfs</title>` + pageStyle + `</head><body>
<h1>Connected</h1>
<dl>
 <dt>program</dt><dd>{{.Client}}</dd>
 <dt>volume</dt><dd>{{.Volume}}</dd>
</dl>
<p>You can close this tab.</p>
<iframe class="deliver" src="{{.Deliver}}" title="handing the authorization to the program"></iframe>
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

// volumeName is the volume as a page says it, and "this session's volume"
// when there is none to name — a browse server built without one (the
// tests, and nothing a user runs) must not render an empty sentence.
func volumeName(v string) string {
	if v == "" {
		return "this session's volume"
	}
	return v
}
