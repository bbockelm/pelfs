package localoauth

import (
	"crypto/subtle"
	"encoding/base64"
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
	// The client that presents the code must be the client it was issued
	// to. The client_id is a secret, so it is looked up in constant time;
	// the refs it resolves to are not secrets and compare plainly. Resolved
	// HERE, before the single-use check, because the used-code branch needs
	// it to tell a retry from a replay.
	c := s.findClient(clientID)
	if found.used {
		// A CODE PRESENTED TWICE, AND THE TWO REASONS IT HAPPENS ARE NOT
		// THE SAME EVENT.
		//
		// RFC 6819 §5.2.1.1's rule — a replayed code means the code leaked,
		// so revoke what the first exchange bought — is the right answer to
		// a caller who has the CODE. It is the wrong answer to the client
		// that asked for the code retrying its own POST after a lost
		// response, and that is a real thing an HTTP client does: the user
		// loses a working connection because their laptop's wifi dropped a
		// packet.
		//
		// PKCE tells the two apart, and it is the only thing on this
		// endpoint that can. The code_verifier NEVER LEAVES THE CLIENT: it
		// is not in the authorization request, not in the redirect, not in
		// the callback URL, not in any log. A caller who presents the used
		// code together with a verifier that hashes to the challenge the
		// code was bound to — and the right client_id, and the right
		// redirect_uri — is in possession of the secret that defines this
		// client. That is the client retrying. A caller who has the code
		// and not the verifier is exactly the attacker §5.2.1.1 describes.
		// Nothing is conceded by the distinction: an attacker who held the
		// verifier as well could simply have made the FIRST exchange.
		//
		// EITHER WAY THE CODE IS STILL SINGLE USE: neither branch mints a
		// token. What differs is whether the grant the first exchange
		// bought is destroyed, and whether this is counted as an attack.
		retry := c != nil && c.ref == found.clientRef &&
			subtle.ConstantTimeCompare([]byte(redirect), []byte(found.redirect)) == 1 &&
			subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(found.challenge)) == 1
		if retry {
			s.counts.CodeRetries++
		} else {
			s.counts.CodeReplays++
			s.grants = filterGrants(s.grants, func(g *grant) bool { return g.ref != found.grantRef })
			s.codes = filterCodes(s.codes, func(x *code) bool { return x != found })
		}
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
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

// refresh is `grant_type=refresh_token`, and it is THE WHOLE OF THE
// no-click reconnect.
//
// A client that holds a refresh token never revisits /oauth/authorize —
// Cyberduck's OAuth2RequestInterceptor refreshes before a request goes out
// and only falls back to an authorization when the refresh fails. With
// Config.Grants set the grant survives the process, so this endpoint answers
// a Cyberduck that saved its token last week and there is no consent screen
// in the path at all. That is the feature, and grants.go says why it is not
// the thing the consent gesture exists to stop.
//
// TWO THINGS IT CHECKS THAT AN EPHEMERAL SERVER DID NOT NEED:
//
//   - the lookup is under refreshMac, i.e. the STORE's key when there is a
//     store, so a token minted by a previous process is recognisable. Access
//     tokens keep the per-process key and are not recognisable, which is
//     why an adopted grant serves nothing at /dav/* until it is refreshed.
//   - refreshExpires. A persisted grant has a hard ceiling (RefreshTTL) and
//     it is enforced here as well as at load time, because a process that
//     has been up for weeks would otherwise go on renewing a row nothing has
//     re-read.
//
// THE REFRESH TOKEN IS NOT ROTATED, deliberately, and the argument changed
// with persistence rather than survived it. Rotation detects the theft of a
// stored refresh token — which now matters, where before the token died with
// the process. What it costs is a client that fails to store the rotated
// value losing access silently, and Cyberduck's handling of a rotated token
// on the WebDAV path is in docs/design-webui.md's "could not be verified"
// list: it is the one behaviour we could not confirm, on the one client this
// path exists for. Shipping rotation we cannot verify would trade a theft we
// can already bound (RefreshTTL, a visible row, a revoke button that reaches
// the disk) for a breakage we cannot. Revisit it when a real Cyberduck has
// been measured against a rotating server.
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	presented := r.PostFormValue("refresh_token")
	clientID := r.PostFormValue("client_id")
	if presented == "" {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	mac := s.refreshMac(presented)
	s.mu.Lock()
	now := s.cfg.Now()
	var found *grant
	for _, g := range s.grants {
		if subtle.ConstantTimeCompare(mac[:], g.macRefresh[:]) == 1 {
			found = g
		}
	}
	if found == nil {
		s.mu.Unlock()
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !found.refreshExpires.IsZero() && now.After(found.refreshExpires) {
		// Aged out. Drop it rather than leaving a row that answers this the
		// same way forever; the client's next move is the consent screen,
		// which is the right one.
		s.grants = filterGrants(s.grants, func(g *grant) bool { return g != found })
		s.mu.Unlock()
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	c := s.findClient(clientID)
	if c == nil || c.ref != found.clientRef {
		s.counts.UnknownClients++
		s.mu.Unlock()
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	access, err := mint()
	if err != nil {
		s.mu.Unlock()
		tokenError(w, http.StatusInternalServerError, "server_error")
		return
	}
	found.macAccess = s.mac(access)
	found.expires = now.Add(AccessTTL)
	found.lastUsed = now
	scopes := strings.Join(found.scopes, " ")
	ref, persistent := found.ref, found.persistent
	s.mu.Unlock()
	// Outside the lock, and best effort: recording when a grant was last
	// used is what lets a user judge a row on the page, and it is not worth
	// failing a refresh the client is entitled to because a disk was busy.
	if persistent && s.cfg.Grants != nil {
		_ = s.cfg.Grants.touch(ref, now)
	}
	writeToken(w, tokenResponse{
		AccessToken: access, TokenType: "Bearer",
		ExpiresIn: int(AccessTTL.Seconds()), RefreshToken: presented,
		Scope: scopes,
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
		macAccess: s.mac(access), macRefresh: s.refreshMac(refresh),
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
	// THE DURABLE HALF, and it is written BEFORE the grant is live in
	// memory.
	//
	// This is the ONE place in this package that touches a disk while
	// holding s.mu, and it is deliberate rather than overlooked: Revoke goes
	// out of its way to write outside the lock because a /dav/* request must
	// never wait on a disk, and the same argument does not reach here. This
	// runs once per grant, on the exchange that follows a human pressing
	// Authorize, and the thing it is protecting is the atomicity of "the
	// code is spent AND the grant exists AND the grant is durable". A grant that serves requests but is not on disk is one that
	// silently stops working at the next restart, which is the bug this
	// feature exists to fix arriving from the other side; a grant on disk
	// that this process forgot is harmless — nothing can present it until
	// something adopts it. So a failed write fails the exchange.
	if s.cfg.Grants != nil {
		g.refreshExpires = now.Add(RefreshTTL)
		g.persistent = true
		if err := s.cfg.Grants.save(grantRecord{
			Ref: ref, Label: c.label, Redirect: c.redirect, Write: g.write,
			Scopes:  append([]string(nil), g.scopes...),
			Refresh: base64.RawURLEncoding.EncodeToString(g.macRefresh[:]),
			Issued:  now.UTC(), Expires: g.refreshExpires.UTC(),
		}); err != nil {
			return nil, "", "", err
		}
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
