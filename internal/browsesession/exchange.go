package browsesession

import (
	"encoding/json"
	"net/http"

	"github.com/bbockelm/pelfs/internal/httpguard"
)

// ExchangeRequest is the body of POST /api/v1/session: the bootstrap token
// the page read out of its own location.hash.
type ExchangeRequest struct {
	Bootstrap string `json:"bootstrap"`
}

// ExchangeResponse is what the page stores in sessionStorage.
type ExchangeResponse struct {
	// Session is the token for the X-Pelfs-Session header.
	Session string `json:"session"`
	// Header names the header to send it in, so the page has one fewer
	// constant to keep in sync with the server.
	Header string `json:"header"`
	// Scope says where the token is valid: this process, this tab. It is
	// informational and it is what the page shows when it explains why a
	// new tab has no session.
	Scope string `json:"scope"`
}

// ExchangeHandler serves the bootstrap-for-session exchange.
//
// It is mounted on httpguard.SurfaceExchange, which is the API surface
// minus the session requirement — this is the route that mints the
// session, so it cannot require one. Everything else still applies: a
// same-origin provenance signal, `Content-Type: application/json`, no
// Authorization header, and a capped body.
//
// Every refusal is the same 401 with the same body. Distinguishing "wrong"
// from "expired" from "already used" would tell a caller which of the
// three walls they hit, and the only caller who benefits from that is one
// iterating.
func ExchangeHandler(m *Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ExchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "expected a JSON body", http.StatusBadRequest)
			return
		}
		tok, err := m.Exchange(req.Bootstrap)
		if err != nil {
			// No detail, and no hint in the status either: 401 for all
			// three refusals.
			http.Error(w, "this launch link is not valid any more; "+
				"start pelfs browse again to get a new one", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ExchangeResponse{
			Session: tok,
			Header:  httpguard.SessionHeader,
			Scope:   "this pelfs process, this browser tab",
		})
	})
}
