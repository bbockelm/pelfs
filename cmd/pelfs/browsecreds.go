package main

// The credential surface the page drives: hand another program a working
// connection to this session's volume, list what has been handed out, and
// take it back.
//
// It is work items U7 and U8 of docs/design-webui.md meeting the browser.
// internal/localoauth mints and revokes, internal/davprofile turns one
// client into the files a WebDAV client can actually open, and everything
// here is three thin routes on the session-authenticated API surface plus
// the one refusal that is a security property rather than a validation.
//
// # Why the profile comes back in a JSON body rather than from a GET
//
// The obvious shape is a download link. It cannot exist: a link is an
// <a href>, an <a href> cannot set X-Pelfs-Session, and a credential-bearing
// GET authorized by anything ambient is the exact hole DNS rebinding
// exploits (internal/httpguard, CVE-2018-5702). The other mechanism this
// listener has for that problem — a single-use ticket — is the DOWNLOAD
// path's, and its Source is the volume; a profile is not in the volume.
//
// So the page POSTs, gets the bytes in a JSON field, and saves them with a
// Blob and an <a download>. The secret never touches a URL, never enters
// the browser's history, and never reaches an access log.
//
// # What is returned once, and what is returned again
//
// The BASIC PASSWORD is once. internal/localoauth keeps an HMAC of it, so a
// page that loses it has to ask for the program again — which re-issues the
// password and invalidates the one before it, and is why the response says
// so in one sentence the page must show.
//
// THE PROFILE IS NOT ONCE ANY MORE, and that is the point of this session's
// work. With a persistent identity (internal/localoauth's identity.go) the
// client id is derived from a per-volume key in the state directory rather
// than minted per download, so asking for the same program again hands back
// a BYTE-IDENTICAL .cyberduckprofile: the user installs it once, and their
// saved Cyberduck bookmark keeps working next session without a
// reinstall. What has NOT changed is the consent gesture — a human clicks
// Authorize on every /oauth/authorize, once per session — and no surface
// here may imply otherwise.
//
// The client id is still never echoed as a field of its own: it is inside
// the generated profile, and one carrier is enough (A7 control 4).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bbockelm/pelfs/internal/davprofile"
	"github.com/bbockelm/pelfs/internal/localoauth"
)

// davRealm is the WWW-Authenticate realm. One word, and it is what a
// password dialog in a client that falls back to Basic will show.
const davRealm = "pelfs"

// credentialFile is one generated connection file, ready to be saved.
type credentialFile struct {
	// Name is the download's filename; Kind is what the page labels the
	// button with.
	Name string `json:"name"`
	Kind string `json:"kind"`
	Type string `json:"content_type"`
	// Content is the file, verbatim. Every generator here emits UTF-8 XML,
	// so it is a string rather than base64 — a profile a user can read is a
	// profile a user can debug, and this one is generated from their own
	// session.
	Content string `json:"content"`
}

// credentialResponse is what a registration hands back. It is the only
// response on this listener that contains a secret, and it contains two.
type credentialResponse struct {
	Ref     string    `json:"ref"`
	Label   string    `json:"label"`
	Write   bool      `json:"write"`
	Created time.Time `json:"created"`
	// The connection facts a client with no profile format needs.
	DAVURL        string `json:"dav_url"`
	RedirectURI   string `json:"redirect_uri"`
	BasicUser     string `json:"basic_user"`
	BasicPassword string `json:"basic_password"`
	// Preemptive is Details().Preemptive: the Basic credential must be sent
	// without waiting for a challenge, which is what Cyberduck, rclone and
	// curl all do by default.
	Preemptive bool             `json:"basic_preemptive"`
	Files      []credentialFile `json:"files"`
	// Notice is the one sentence the page must show beside the password,
	// worded here so no surface has to re-word it.
	Notice string `json:"notice"`
}

// credentialList is the revocable inventory: every credential this session
// has issued, and no secret at all.
//
// The rows are re-declared here rather than marshalling localoauth's own
// structs, which carry no JSON tags: their Go field names would become the
// wire contract, and a rename in that package would then silently rename a
// field the page selects on.
type credentialList struct {
	Writable bool        `json:"writable"`
	DAVURL   string      `json:"dav_url"`
	Clients  []clientRow `json:"clients"`
	Grants   []grantRow  `json:"grants"`
}

// clientRow is one program that was handed a profile.
type clientRow struct {
	Ref       string    `json:"ref"`
	Label     string    `json:"label"`
	BasicUser string    `json:"basic_user"`
	Write     bool      `json:"write"`
	Created   time.Time `json:"created"`
	// Consented is whether a human has authorized this client on a consent
	// screen at least once; Grants is how many live OAuth grants it holds.
	// Both are what distinguishes "downloaded a profile and never used it"
	// from "is connected right now", which is the distinction a revoke
	// decision turns on.
	Consented bool      `json:"consented"`
	Grants    int       `json:"grants"`
	LastUsed  time.Time `json:"last_used,omitzero"`
	// Persistent is whether this program's identity is in the state
	// directory — i.e. whether the profile the user installed will still
	// work after `pelfs browse` restarts, and therefore whether revoking
	// this row kills an installed profile for good or only for this
	// session. The two answers deserve different words on the page.
	Persistent bool `json:"persistent"`
}

// grantRow is one live connection: an access and refresh token pair.
type grantRow struct {
	Ref       string    `json:"ref"`
	ClientRef string    `json:"client_ref"`
	Label     string    `json:"label"`
	Scopes    []string  `json:"scopes"`
	Write     bool      `json:"write"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
	LastUsed  time.Time `json:"last_used,omitzero"`
}

// serveListCredentials answers the "Connect another program" panel.
//
// A credential the user cannot see is a credential the user cannot revoke
// (docs/design-webui.md, A6), so BOTH lists are here: the clients (one per
// profile download, each with its Basic credential) and the grants (one per
// connection a client has actually made). They revoke differently and the
// difference is user-visible — revoking a grant makes Cyberduck ask for
// consent again, revoking a client makes its profile permanently dead, in
// this session AND every later one, because the identity is deleted from
// the state directory — so the page shows them separately rather than
// merging them into one row.
func (b *browseServer) serveListCredentials(w http.ResponseWriter, _ *http.Request) {
	// Never nil: the page iterates these, and a JSON null would be one more
	// case for it to carry.
	out := credentialList{
		Writable: b.oauth.Writable(),
		DAVURL:   davprofile.DAVURL(b.port),
		Clients:  []clientRow{},
		Grants:   []grantRow{},
	}
	for _, c := range b.oauth.Clients() {
		out.Clients = append(out.Clients, clientRow{
			Ref: c.Ref, Label: c.Label, BasicUser: c.BasicUser, Write: c.Write,
			Created: c.Created, Consented: c.Consented, Grants: c.Grants,
			LastUsed: c.LastUsed, Persistent: c.Persistent,
		})
	}
	for _, g := range b.oauth.Grants() {
		out.Grants = append(out.Grants, grantRow{
			Ref: g.Ref, ClientRef: g.ClientRef, Label: g.Label, Scopes: g.Scopes,
			Write: g.Write, Issued: g.Issued, Expires: g.Expires, LastUsed: g.LastUsed,
		})
	}
	writeBrowseJSON(w, http.StatusOK, out)
}

// serveNewCredential registers one client and generates its files.
//
// THE REDIRECT URI IS OURS, NOT THE CALLER'S. It is
// davprofile.RedirectURI(davprofile.DefaultCallbackPort) — the loopback
// callback pelfs itself writes into the profile — and it is the whole
// allowlist for this client, compared byte for byte at /oauth/authorize
// (A7 control 3). A request body that could name it would be a request
// body that could point the authorization code at somebody else's
// listener, which is the single most dangerous thing this listener could
// be asked to do. There is therefore no field for it.
func (b *browseServer) serveNewCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label string `json:"label"`
		Write bool   `json:"write"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	redirect := davprofile.RedirectURI(davprofile.DefaultCallbackPort)
	// Before the registration, so that a generation failure below can tell
	// a client this request CREATED from one it merely re-derived. See the
	// rollback comment there: with a persistent identity those are the
	// difference between cleaning up after ourselves and deleting a profile
	// the user has installed and is using.
	start := b.nowTime()
	c, err := b.oauth.NewClient(localoauth.ClientRequest{
		Label: req.Label, RedirectURI: redirect, Write: req.Write,
	})
	if err != nil {
		// A writable client on a read-only session is a refusal the user
		// asked for by starting `pelfs browse` without --rw, so it says
		// what to do about it. Everything else ErrConfig covers is a
		// wiring bug and reads as one.
		if errors.Is(err, localoauth.ErrConfig) {
			writeBrowseJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeBrowseJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	p := davprofile.Params{
		Port: b.port, Volume: b.prefix, ClientID: c.ID, RedirectURI: c.Redirect,
		Write: c.Write, BasicUser: c.BasicUser, Label: c.Label,
	}
	files := make([]credentialFile, 0, 3)
	for _, gen := range []struct {
		kind, ext, ctype string
		fn               func(davprofile.Params) ([]byte, error)
	}{
		{"Cyberduck / Mountain Duck profile", "cyberduckprofile",
			"application/x-cyberduckprofile+xml", davprofile.Profile},
		{"Cyberduck bookmark", "duck", "application/x-cyberduck+xml", davprofile.Bookmark},
		{"Bookmark for the password path", "basic.duck", "application/x-cyberduck+xml",
			davprofile.BasicBookmark},
	} {
		body, err := gen.fn(p)
		if err != nil {
			// A generation failure here is davprofile refusing a value it
			// would have to mangle (a `$` in the volume name, say), which
			// is a refusal worth showing verbatim.
			//
			// THE ROLLBACK IS CONDITIONAL, and the condition is load-bearing
			// now that an identity is durable. A client this request created
			// is revoked, so a credential nobody was handed is not left
			// behind. A client that ALREADY EXISTED — the user asking again
			// for a program whose profile is installed and working — is left
			// exactly where it was, because revoking it would delete that
			// profile's identity from the state directory and kill a
			// connection the user did not ask us to touch. `Created` is the
			// FIRST registration time, from the state directory, so it is
			// the fact that tells the two apart.
			if !c.Created.Before(start) {
				// Best effort, and the error is deliberately dropped: the
				// caller is already being told the generation failed, and a
				// second failure to un-register a client nobody was handed
				// is not a second thing for them to act on.
				_, _ = b.oauth.Revoke(c.Ref)
			}
			writeBrowseJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		files = append(files, credentialFile{
			Name: davprofile.FileName(p, gen.ext), Kind: gen.kind,
			Type: gen.ctype, Content: string(body),
		})
	}
	d := p.Details()
	writeBrowseJSON(w, http.StatusOK, credentialResponse{
		Ref: c.Ref, Label: c.Label, Write: c.Write, Created: c.Created,
		DAVURL: d.URL, RedirectURI: c.Redirect,
		BasicUser: c.BasicUser, BasicPassword: c.BasicPassword,
		Preemptive: d.Preemptive, Files: files,
		Notice: "this password is shown once and is not stored anywhere pelfs can " +
			"read it back; asking for this program again issues a new one and " +
			"retires this. The Cyberduck profile beside it is the same file every " +
			"time, so install it once — you will still click Authorize once per " +
			"pelfs browse session.",
	})
}

// serveRevokeCredential drops one client or one grant.
//
// Two refs and not one, because they are different revocations and the user
// means different things by them: a grant is one connection's access and
// refresh token (the client can consent again), a client is the profile
// itself and everything it ever held. internal/localoauth's Revoke and
// RevokeGrant are both immediate — a token stops working mid-connection,
// which internal/localoauth's own suite asserts end to end.
//
// AND ONE OF THEM IS NOW DURABLE. Revoking a client deletes its identity
// from the state directory, so the .cyberduckprofile the user installed
// stops naming a client this volume knows — for good, not for this process.
// That is the only revocation on this listener that can half-succeed, and
// the 500 below is what says so rather than reporting a durable act that
// did not happen.
func (b *browseServer) serveRevokeCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Client string `json:"client"`
		Grant  string `json:"grant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{"error": "expected a JSON body"})
		return
	}
	switch {
	case req.Client != "" && req.Grant != "":
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{
			"error": "name a client or a grant, not both"})
	case req.Client != "":
		// The one revocation that can half-succeed. With a persistent
		// identity, revoking a client deletes it from the state directory so
		// the profile the user installed is dead for good — and if that
		// write fails, the credential is gone from this session and would
		// come back in the next one. Reporting that as `{"revoked":true}`
		// would be the page telling the user something durable happened when
		// it did not, so it is a 500 with the reason.
		revoked, err := b.oauth.Revoke(req.Client)
		if err != nil {
			writeBrowseJSON(w, http.StatusInternalServerError, map[string]any{
				"revoked": revoked, "error": err.Error()})
			return
		}
		writeBrowseJSON(w, http.StatusOK, map[string]bool{"revoked": revoked})
	case req.Grant != "":
		writeBrowseJSON(w, http.StatusOK, map[string]bool{"revoked": b.oauth.RevokeGrant(req.Grant)})
	default:
		writeBrowseJSON(w, http.StatusBadRequest, map[string]string{
			"error": "name a client or a grant to revoke"})
	}
}
