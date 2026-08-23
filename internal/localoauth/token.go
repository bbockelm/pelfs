package localoauth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// tokenBodyLimit caps the token endpoint's body. Every legitimate request is
// five short form fields.
const tokenBodyLimit = 64 << 10

// TokenHandler serves POST /oauth/token: `grant_type=authorization_code`
// and `grant_type=refresh_token`.
//
// # THE SURFACE THIS MOUNTS ON, AND WHY IT IS NOT SurfaceExchange
//
//	r.Handle(httpguard.SurfaceToken, "POST /oauth/token", oauth.TokenHandler())
//
// docs/design-webui.md and cmd/pelfs/browse.go's route-table comment both
// pencil this route in on httpguard.SurfaceExchange ("the API surface minus
// the session requirement"). THAT SURFACE CANNOT SERVE THIS ROUTE, and the
// reason is worth stating so it is not re-tried: SurfaceExchange requires a
// same-origin provenance signal and `Content-Type: application/json`, and
// the caller here is not a browser and is not our page. Cyberduck's token
// request comes from google-oauth-client through Apache HttpClient with no
// Origin and no Sec-Fetch-Site — so the provenance check answers 403 — and
// its body is `application/x-www-form-urlencoded`, which RFC 6749 §4.1.3
// mandates and which the JSON rule answers 415. A profile pointed at a
// SurfaceExchange token endpoint fails every exchange, which is why
// internal/httpguard grew SurfaceToken.
//
// What SurfaceToken keeps is everything that still applies to a non-browser
// POST: the Host allowlist (so a rebound Host never reaches here),
// net/http.CrossOriginProtection (so a form POST from a page on another
// loopback port is refused — an unsafe method with `Sec-Fetch-Site:
// same-site` is rejected, and by F3 another loopback port is same-SITE), the
// exact-Origin match if an Origin is present at all, no cookie, no
// Set-Cookie, and no Access-Control-Allow-*. What it drops is the
// provenance requirement, which is a browser-only signal, and the JSON
// content type.
//
// # ONE ERROR FOR EVERY REFUSAL
//
// Every failure is `400 {"error":"invalid_grant"}` with no detail. Which of
// "unknown code", "expired code", "replayed code", "wrong client", "wrong
// redirect_uri" and "wrong verifier" was hit is exactly what an attacker
// iterating would want to know; the counters (Server.Counts) are where that
// information goes instead.
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			tokenError(w, http.StatusMethodNotAllowed, "invalid_request")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, tokenBodyLimit)
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			// RFC 6749 §4.1.3: the token endpoint takes a form-encoded
			// body. Anything else is refused rather than sniffed.
			tokenError(w, http.StatusUnsupportedMediaType, "invalid_request")
			return
		}
		if err := r.ParseForm(); err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		switch r.PostFormValue("grant_type") {
		case "authorization_code":
			s.exchangeCode(w, r)
		case "refresh_token":
			s.refresh(w, r)
		default:
			// No implicit flow, no password grant, no client_credentials:
			// this server has exactly one way to mint a token and it goes
			// through a human on a consent screen.
			tokenError(w, http.StatusBadRequest, "unsupported_grant_type")
		}
	})
}

// tokenResponse is RFC 6749 §5.1, and `expires_in` is NOT OPTIONAL here:
// Cyberduck's OAuth2RequestInterceptor refreshes when
// `tokens.isExpired()`, and a token with no expiry is never expired, so
// omitting the field turns pelfs's own AccessTTL into 401s the client will
// not recover from (docs/design-webui.md, verification 2d).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func writeToken(w http.ResponseWriter, resp tokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	// Cache-Control: no-store is already set by internal/httpguard on every
	// response from this listener; RFC 6749 §5.1 requires it here, so it is
	// asserted by a test rather than repeated.
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// exchangeCode is `grant_type=authorization_code`.
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request) {
	presented := r.PostFormValue("code")
	verifier := r.PostFormValue("code_verifier")
	redirect := r.PostFormValue("redirect_uri")
	clientID := r.PostFormValue("client_id")

	if presented == "" || !validVerifier(verifier) {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepCodes()

	mac := s.mac(presented)
	var found *code
	for _, c := range s.codes {
		// No early return: which code matched must not be timeable.
		if subtle.ConstantTimeCompare(mac[:], c.macCode[:]) == 1 {
			found = c
		}
	}
	if found == nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if found.used {
		// A REPLAY. Either a bug or an attack, and both deserve a number
		// (A7's "a replayed code is a hard failure and is counted"). The
		// code leaked, so the token the first exchange bought is the thing
		// at risk: revoke it (RFC 6819 §5.2.1.1).
		s.counts.CodeReplays++
		s.grants = filterGrants(s.grants, func(g *grant) bool { return g.ref != found.grantRef })
		s.codes = filterCodes(s.codes, func(c *code) bool { return c != found })
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// The client that presents the code must be the client it was issued
	// to. The client_id is a secret, so it is looked up in constant time;
	// the refs it resolves to are not secrets and compare plainly.
	c := s.findClient(clientID)
	if c == nil || c.ref != found.clientRef {
		s.counts.UnknownClients++
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// The redirect_uri again, at exchange time, byte for byte against the
	// one the code was bound to (RFC 6749 §4.1.3). A code minted for one
	// callback cannot be redeemed by naming another.
	if subtle.ConstantTimeCompare([]byte(redirect), []byte(found.redirect)) != 1 {
		s.counts.RedirectMismatches++
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// PKCE. The verifier never left the client, so this is what makes a
	// leaked code worthless.
	if subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(found.challenge)) != 1 {
		s.counts.VerifierMismatches++
		// The code dies with the failure: there is no legitimate retry with
		// a different verifier, so a second attempt is either a bug or a
		// search, and neither should get another go at a live code.
		s.codes = filterCodes(s.codes, func(x *code) bool { return x != found })
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	g, access, refresh, err := s.newGrantLocked(c, found.scopes, found.write)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	// Single use, and kept (not deleted) until its TTL so a replay is
	// detectable rather than merely unsuccessful.
	found.used = true
	found.grantRef = g.ref

	writeToken(w, tokenResponse{
		AccessToken: access, TokenType: "Bearer",
		ExpiresIn: int(AccessTTL.Seconds()), RefreshToken: refresh,
		Scope: strings.Join(g.scopes, " "),
	})
}

// refresh is `grant_type=refresh_token`.
//
// THE REFRESH TOKEN IS NOT ROTATED, deliberately. Rotation's benefit is
// detecting the theft of a persisted refresh token, and nothing here is
// persisted: the token dies with the process either way. Its cost is real —
// a client that does not store the rotated value loses access, and
// Cyberduck's handling of a rotated token on the WebDAV path is in
// docs/design-webui.md's "could not be verified" list — so the stable token
// is the safe half of the trade. This is also where the no-re-prompt
// property of verification 2e lives: a client that holds a refresh token
// reconnects for the life of the process without another consent screen.
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	presented := r.PostFormValue("refresh_token")
	clientID := r.PostFormValue("client_id")
	if presented == "" {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	mac := s.mac(presented)
	var found *grant
	for _, g := range s.grants {
		if subtle.ConstantTimeCompare(mac[:], g.macRefresh[:]) == 1 {
			found = g
		}
	}
	if found == nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	c := s.findClient(clientID)
	if c == nil || c.ref != found.clientRef {
		s.counts.UnknownClients++
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	access, err := mint()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	now := s.cfg.Now()
	found.macAccess = s.mac(access)
	found.expires = now.Add(AccessTTL)
	found.lastUsed = now
	writeToken(w, tokenResponse{
		AccessToken: access, TokenType: "Bearer",
		ExpiresIn: int(AccessTTL.Seconds()), RefreshToken: presented,
		Scope: strings.Join(found.scopes, " "),
	})
}

// newGrantLocked mints a grant and its two tokens. Called under mu.
func (s *Server) newGrantLocked(c *client, scopes []string, write bool) (*grant, string, string, error) {
	ref, err := mintRef()
	if err != nil {
		return nil, "", "", err
	}
	access, err := mint()
	if err != nil {
		return nil, "", "", err
	}
	refresh, err := mint()
	if err != nil {
		return nil, "", "", err
	}
	now := s.cfg.Now()
	g := &grant{
		ref: ref, clientRef: c.ref, label: c.label,
		macAccess: s.mac(access), macRefresh: s.mac(refresh),
		// The ceiling, for the third time: even a code that somehow carries
		// write on a read-only session produces a read-only grant.
		write:  write && s.cfg.Writable,
		scopes: append([]string(nil), scopes...),
		issued: now, expires: now.Add(AccessTTL),
	}
	if write && !s.cfg.Writable {
		s.counts.ScopeClamped++
		g.scopes = []string{ScopeRead}
	}
	s.grants = append(s.grants, g)
	return g, access, refresh, nil
}

// validVerifier is RFC 7636 §4.1: 43 to 128 characters of the unreserved
// set. Checking the shape means the SHA-256 comparison is against something
// a conforming client could have sent.
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
