package vfsdav

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/go-git/go-billy/v5"
	"golang.org/x/net/webdav"
)

// Config is everything the WebDAV surface needs. Zero optional fields are
// fine; FS and Auth are not optional.
type Config struct {
	// FS is the volume, as internal/vfsbilly presents it. It MUST have been
	// built with vfsbilly.OpenAnsweredHere — WebDAV has a real open, so the
	// mode check in that layer is the only open check there is. See the FS
	// comment for what the NFS binding would do here.
	FS billy.Filesystem

	// Prefix is the URL prefix this handler is mounted under, WITHOUT a
	// trailing slash: "/dav" for a router that does
	// mux.Handle("/dav/", h). A trailing slash is trimmed rather than
	// rejected, because "/dav/" is the obvious thing to write and getting it
	// wrong turns every path into a 404 with nothing to see in the log.
	Prefix string

	// Auth is the credential check. There is no default and no zero value:
	// an unauthenticated WebDAV endpoint on a loopback port is writable by
	// every process on the machine, including a page's fetch() (for the
	// three verbs a browser can send without a preflight).
	Auth Auth

	// Logger, if set, is called once per request with the error x/net's
	// handler produced, nil on success. It is x/net's own hook.
	Logger func(*http.Request, error)

	// LockSystem overrides webdav.NewMemLS(). Only tests should set it.
	LockSystem webdav.LockSystem
}

// Handler is the WebDAV surface: authentication, then x/net's handler over
// the adapter. It is an http.Handler and holds no goroutines, so a router
// mounts it and forgets it:
//
//	h, err := vfsdav.New(vfsdav.Config{
//		FS:     vfsbilly.NewFor(ov, vfsbilly.ProcessCred(), vfsbilly.OpenAnsweredHere),
//		Prefix: "/dav",
//		Auth:   vfsdav.Basic("pelfs", user, password, vfsdav.Grant{Write: rw}),
//	})
//	mux.Handle("/dav/", h)
//
// It emits no Access-Control-Allow-* header on any response, ever — see the
// package comment for why that is the load-bearing part.
type Handler struct {
	dav  *webdav.Handler
	fs   *FS
	auth Auth
}

var _ http.Handler = (*Handler)(nil)

// New builds the handler. It fails rather than defaulting when something
// security-relevant is missing.
func New(cfg Config) (*Handler, error) {
	if cfg.FS == nil {
		return nil, errors.New("vfsdav: no filesystem")
	}
	if cfg.Auth == nil {
		return nil, errors.New("vfsdav: no Auth — a WebDAV endpoint with no " +
			"credential is reachable by every process on this machine")
	}
	ls := cfg.LockSystem
	if ls == nil {
		// Exclusive locks only, which is memLS's whole implementation. The
		// two litmus `locks` failures that follow from it are the upstream
		// baseline (scripts/webdav-litmus-docker.sh), and neither is on any
		// client path this design needs: the Windows redirector takes an
		// exclusive write lock, and Cyberduck does not lock at all
		// (docs/design-guiclients.md).
		ls = webdav.NewMemLS()
	}
	fs := NewFS(cfg.FS)
	return &Handler{
		fs:   fs,
		auth: cfg.Auth,
		dav: &webdav.Handler{
			Prefix:     strings.TrimSuffix(cfg.Prefix, "/"),
			FileSystem: fs,
			LockSystem: ls,
			Logger:     cfg.Logger,
		},
	}, nil
}

// Counts reports what the adapter hid from clients; see Counts.
func (h *Handler) Counts() Counts { return h.fs.Counts() }

// writeMethods are the verbs a read-only grant is refused. POST is not one
// of them: x/net serves GET, HEAD and POST through the same read-only
// handler. UNLOCK is not one either — releasing a lock is cleanup, and a
// grant that could not release what it took would leak the lock until the
// process exited.
var writeMethods = map[string]bool{
	"PUT": true, "DELETE": true, "MKCOL": true, "MOVE": true,
	"COPY": true, "PROPPATCH": true, "LOCK": true,
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	grant, ok := h.auth.Check(r)
	if !ok {
		for _, c := range h.auth.Challenge() {
			w.Header().Add("WWW-Authenticate", c)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !grant.Write && writeMethods[r.Method] {
		// A credential that is real but not allowed to write: 403, not 401.
		// A 401 would send the client back to ask for the password again,
		// which is the wrong instruction and the wrong dialog.
		http.Error(w, "read-only credential", http.StatusForbidden)
		return
	}
	h.dav.ServeHTTP(w, r)
}

// Grant is what one accepted credential may do. It is the scope seam: U7's
// `pelfs.read` token becomes Grant{Write: false}, and a read-only `pelfs
// browse` session cannot mint anything else.
type Grant struct {
	// Subject names the credential for a log line. It is never sent to a
	// client.
	Subject string
	// Write allows the mutating verbs (writeMethods).
	Write bool
}

// Auth decides whether one request carries a credential this endpoint
// accepts, and what it may do.
//
// THE SESSION TOKEN IS NOT A CREDENTIAL HERE. Nothing in this package reads
// X-Pelfs-Session, and no implementation of this interface should: the
// browser session and the WebDAV credential are separate principals with
// separate lifetimes (docs/design-webui.md, "The two-surface design"), and
// an implementation that accepted both would make every WebDAV verb
// reachable with a token the SPA holds in sessionStorage.
type Auth interface {
	// Challenge is the WWW-Authenticate header value (or values) a 401
	// carries. One line per scheme offered.
	Challenge() []string
	// Check reports whether the request is authenticated, and as what. It
	// must be constant-time in the secret.
	Check(r *http.Request) (Grant, bool)
}

// Basic is HTTP Basic, which is the path every client that is not Cyberduck
// uses — WinSCP, rclone, `mount_webdav`, the Windows redirector — and
// Cyberduck's own contingency (docs/design-webui.md, verification 2g). The
// password is a per-client secret minted by the caller, not the user's
// anything.
//
// Comparison is over SHA-256 digests, so neither the length nor a prefix of
// the real credential leaks through timing.
func Basic(realm, username, password string, grant Grant) Auth {
	return &basicAuth{
		realm: realm,
		user:  sha256.Sum256([]byte(username)),
		pass:  sha256.Sum256([]byte(password)),
		grant: grant,
	}
}

type basicAuth struct {
	realm string
	user  [32]byte
	pass  [32]byte
	grant Grant
}

func (a *basicAuth) Challenge() []string {
	return []string{`Basic realm="` + a.realm + `", charset="UTF-8"`}
}

func (a *basicAuth) Check(r *http.Request) (Grant, bool) {
	u, p, ok := r.BasicAuth()
	if !ok {
		return Grant{}, false
	}
	gotUser, gotPass := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
	// Both comparisons always run: an early return on the username would
	// make "is this a real user" measurable.
	okUser := subtle.ConstantTimeCompare(gotUser[:], a.user[:])
	okPass := subtle.ConstantTimeCompare(gotPass[:], a.pass[:])
	if okUser&okPass != 1 {
		return Grant{}, false
	}
	return a.grant, true
}

// Bearer is the seam for U7 and the whole of pelfs's involvement in OAuth
// at this layer: it accepts `Authorization: Bearer <token>` for tokens
// verify accepts, and knows nothing about how they were issued.
// internal/localoauth supplies verify; this package does not grow an
// authorization server, a grant table or a key.
//
// verify MUST be constant-time in the token and must return the scope as
// Grant.Write — a `pelfs.read` token returns Grant{Write: false} and the
// handler answers 403 on PUT without verify having to know the verb.
func Bearer(realm string, verify func(token string) (Grant, bool)) Auth {
	return &bearerAuth{realm: realm, verify: verify}
}

type bearerAuth struct {
	realm  string
	verify func(string) (Grant, bool)
}

func (a *bearerAuth) Challenge() []string {
	return []string{`Bearer realm="` + a.realm + `"`}
}

func (a *bearerAuth) Check(r *http.Request) (Grant, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return Grant{}, false
	}
	if a.verify == nil {
		return Grant{}, false
	}
	return a.verify(strings.TrimSpace(h[len(prefix):]))
}

// AnyOf accepts a request that any of auths accepts, and offers every
// scheme in its 401. This is how the two client paths coexist on one
// endpoint: AnyOf(Bearer(...), Basic(...)) is what U7 mounts, and the order
// is the order the challenges are offered in.
func AnyOf(auths ...Auth) Auth { return anyOf(auths) }

type anyOf []Auth

func (a anyOf) Challenge() []string {
	out := make([]string, 0, len(a))
	for _, one := range a {
		out = append(out, one.Challenge()...)
	}
	return out
}

func (a anyOf) Check(r *http.Request) (Grant, bool) {
	for _, one := range a {
		if g, ok := one.Check(r); ok {
			return g, true
		}
	}
	return Grant{}, false
}
