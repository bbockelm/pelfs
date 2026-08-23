// Package davprofile generates the connection files a WebDAV client
// downloads from `pelfs browse`: a Cyberduck/Mountain Duck
// `.cyberduckprofile`, a `.duck` bookmark, and the plain connection details
// every other client needs. It is work item U8 of docs/design-webui.md, and
// verification 2 of that document — read out of Cyberduck's own source,
// because its documentation does not cover this path — is what the rules
// here come from.
//
// # Nothing in here is a guess about Cyberduck, and five things are traps
//
// Each of these is enforced by this package rather than left to whoever
// fills in the struct, because each one fails as "it just will not connect"
// with nothing useful in any UI:
//
//  1. A NON-BLANK `OAuth Client ID` IS THE SWITCH. AbstractProtocol:
//     `isOAuthConfigurable()` is `isNotBlank(getOAuthClientId())` and
//     `isPasswordConfigurable()` is `isBlank(getOAuthClientId())`. So one
//     key turns OAuth on and password auth off in the same move; there is
//     no vendor protocol class and no compiled Java involved. Profile
//     refuses to emit a profile with a blank client id, because a blank one
//     silently produces a password-only profile — which is the single
//     documented case of somebody trying WebDAV+OAuth and seeing no dialog
//     at all.
//  2. `Authorization` MUST BE OMITTED. For an S3 profile that key names the
//     signature version, and that is the only meaning Cyberduck's
//     documentation gives it. For a `dav` profile, DAVSession feeds it
//     straight into `OAuth2AuthorizationService.FlowType.valueOf(...)`,
//     whose only constants are `AuthorizationCode` and `PasswordGrant` —
//     so anything else is an IllegalArgumentException inside session setup,
//     surfacing as an unexplained connection failure. This package has no
//     field for it and never writes it.
//  3. `Scopes` IS A PLIST `<array>`, read by `list(SCOPES_KEY)`. A single
//     space-delimited string does not produce a one-element list.
//  4. EVERY VALUE PASSES THROUGH A `StringSubstitutor`
//     (`substitutor.replace(dict.stringForKey(key))`), which is how
//     `${oauth.handler.scheme}` resolves in Cyberduck's published profiles
//     — and which means a literal `$` in a value pelfs generated may be
//     rewritten before the client ever uses it. So NO VALUE MAY CONTAIN
//     `$`, and every writer here checks (see checkValue). A rewritten
//     redirect URL is the worst case: it would no longer match the
//     exact-string allowlist in internal/localoauth, which is A7 control 3,
//     and the flow would fail on pelfs's own security check.
//  5. THE LOOPBACK REDIRECT NEEDS AN EXPLICIT PORT.
//     BrowserOAuth2AuthorizationCodeProvider picks the loopback provider by
//     testing `InetAddress.getByName(uri.getHost()).isLoopbackAddress()`,
//     and that provider takes the port from the URI, substituting 0
//     (OS-chosen) when there is none — at which point the `redirect_uri` it
//     SENDS disagrees with the port it is LISTENING on. RedirectURI always
//     writes a port, and DefaultCallbackPort is the one pelfs picks.
//
// # What a profile cannot carry, and what follows from it
//
// A PASSWORD. `HostDictionary.java`'s key set has `Protocol`, `Provider`,
// `Hostname`, `Port`, `Path`, `Username`, `Nickname` and friends, and no
// `Password` key at all — so neither a `.cyberduckprofile` nor a `.duck`
// bookmark can carry the HTTP Basic secret. That is exactly why the OAuth
// path is worth building (it is the only way a downloaded file becomes a
// working connection with no typing) and why the Basic credential is
// nonetheless generated for every client: it is the contingency if the
// OAuth flow will not run, and it is the path every non-Cyberduck client
// uses — WinSCP, rclone, macOS `mount_webdav`, the Windows redirector. The
// contingency costs the user one paste, and BasicBookmark is what makes it
// only one.
package davprofile

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// DefaultCallbackPort is the loopback port pelfs writes into a generated
// profile for Cyberduck's own OAuth listener.
//
// THE PORT IS THE CLIENT'S, NOT PELFS'S, and pelfs has to know it in
// advance to put it on the redirect_uri allowlist — so pelfs picks it. A
// fixed high port, written into both the profile and the allowlist. If it
// is already in use on the user's machine the flow fails, which is why the
// UI should offer "regenerate with a different callback port" rather than
// asking anybody to edit a plist.
const DefaultCallbackPort = 52001

// CallbackPath is the path component of the loopback redirect.
// LoopbackOAuth2AuthorizationCodeProvider registers its HttpServer context
// at the redirect URI's PATH, so this is the path Cyberduck will answer on.
const CallbackPath = "/pelfs/oauth/callback"

// DAVPath is where the WebDAV surface is mounted. Cyberduck's `Default
// Path` wants the trailing slash.
const DAVPath = "/dav/"

// VendorPrefix is the profile identity's stem. The full Vendor includes the
// listener's port (see Params.vendor) because the profile's Vendor must be
// unique and two concurrent `pelfs browse` sessions are two different
// servers.
const VendorPrefix = "org.pelicanplatform.pelfs.local"

// Params is one generated download: one client, one session, one set of
// files. Every string in it is checked for the `$` that a StringSubstitutor
// would eat.
type Params struct {
	// Port is the port `pelfs browse`'s listener actually got. It is the
	// profile's `Default Port` and the host part of every URL in it.
	Port int

	// Volume is what the bookmark and the description name, e.g.
	// "pelican://osg-htc.org/user/bbockelman". It is what the user reads in
	// a list of bookmarks, so it is the volume rather than a UUID.
	Volume string

	// ClientID is the OAuth client_id from internal/localoauth: a
	// per-download secret, and the key that turns OAuth on. A blank one is
	// an error rather than a default, per trap 1.
	ClientID string

	// RedirectURI is the loopback callback, with an explicit port. Build it
	// with RedirectURI; it must be the same string
	// internal/localoauth.NewClient was given, because that comparison is
	// byte for byte.
	RedirectURI string

	// Write asks for the `pelfs.write` scope in addition to `pelfs.read`.
	// A read-only browse session must not set it (internal/localoauth
	// refuses the client registration, which is where that is enforced).
	Write bool

	// BasicUser is the per-client HTTP Basic username, used by
	// BasicBookmark and by Details. Optional for Profile, which offers no
	// password field at all.
	BasicUser string

	// Label names the client in a bookmark's nickname: "Cyberduck". Falls
	// back to "pelfs".
	Label string
}

// RedirectURI is the loopback callback URL for a Cyberduck listening on
// port. ALWAYS with an explicit port; see trap 5.
func RedirectURI(port int) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + CallbackPath
}

// AuthorizeURL and TokenURL are pelfs's own endpoints, as the profile names
// them.
func AuthorizeURL(port int) string { return origin(port) + "/oauth/authorize" }

// TokenURL is pelfs's token endpoint.
func TokenURL(port int) string { return origin(port) + "/oauth/token" }

// DAVURL is what a client that is not Cyberduck is pointed at: rclone's
// `--webdav-url`, WinSCP's host and path, `mount_webdav`'s argument.
func DAVURL(port int) string { return origin(port) + DAVPath }

func origin(port int) string {
	// The literal 127.0.0.1, never "localhost": the name is the weaker case
	// (a resolver may answer ::1, where this tcp4 listener is not), and the
	// URL the terminal prints is the literal too.
	return "http://127.0.0.1:" + strconv.Itoa(port)
}

// Scopes is what the profile requests, in the order it writes them.
func (p Params) Scopes() []string {
	if p.Write {
		return []string{"pelfs.read", "pelfs.write"}
	}
	return []string{"pelfs.read"}
}

func (p Params) vendor() string {
	return VendorPrefix + "." + strconv.Itoa(p.Port)
}

func (p Params) description() string {
	v := p.Volume
	if v == "" {
		v = "this session"
	}
	mode := "read-only"
	if p.Write {
		mode = "read-write"
	}
	// No em dash, no smart quotes: this string lands in a plist that a Java
	// StringSubstitutor and an XML parser both read, and plain ASCII is one
	// fewer thing to go wrong.
	return "pelfs " + v + " (" + mode + ", this session only)"
}

func (p Params) nickname() string {
	label := p.Label
	if label == "" {
		label = "pelfs"
	}
	return label + " - pelfs " + p.Volume
}

// Profile is the `.cyberduckprofile`: a plist that installs by double-click
// or through Preferences -> Profiles, and that serves Mountain Duck
// identically because the loopback redirect sidesteps the handler-scheme
// difference between them.
//
// What is NOT in the output, deliberately, and each omission is a decision:
//
//	Authorization    trap 2 — omitted so DAVSession takes the default
//	                 authorization-code flow instead of throwing
//	OAuth PKCE       omitted so the parent's default (true) applies; PKCE is
//	                 REQUIRED by internal/localoauth, not merely accepted
//	Password         impossible — no such key exists (see the package
//	                 comment)
//	any secret but the client id, which is minted per download, so
//	possessing the profile is the whole of what identifies the client
func Profile(p Params) ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return nil, fmt.Errorf("davprofile: OAuth Client ID must be non-blank — " +
			"a blank one makes isOAuthConfigurable() false and silently yields a " +
			"password-only profile")
	}
	if p.RedirectURI == "" {
		return nil, fmt.Errorf("davprofile: no redirect URI (use RedirectURI(port))")
	}
	w := newPlist()
	// `dav` is plain HTTP; `davs` would be TLS, and this listener has none.
	w.str("Protocol", "dav")
	w.str("Vendor", p.vendor())
	w.str("Description", p.description())
	w.str("Default Hostname", "127.0.0.1")
	w.integer("Default Port", p.Port)
	w.str("Default Path", DAVPath)
	// Explicit, though `isOAuthConfigurable()` would infer it from the
	// non-blank client id. Saying it costs one line and makes the profile
	// readable by a person deciding whether to trust it.
	w.boolean("OAuth Configurable", true)
	w.str("OAuth Client ID", p.ClientID)
	// Blank: a PUBLIC client, sending client_id as a parameter
	// (ClientParametersAuthentication) rather than HTTP Basic. A profile is
	// a downloadable file, so it cannot hold a client secret that means
	// anything; PKCE is what stands in for one, and internal/localoauth
	// requires it.
	w.str("OAuth Client Secret", "")
	w.str("OAuth Authorization Url", AuthorizeURL(p.Port))
	w.str("OAuth Token Url", TokenURL(p.Port))
	w.str("OAuth Redirect Url", p.RedirectURI)
	w.array("Scopes", p.Scopes())
	// No password field and no username field: there is nothing for a user
	// to type, and a prompt with an empty box is worse than no prompt.
	w.boolean("Password Configurable", false)
	w.boolean("Username Configurable", false)
	return w.bytes()
}

// Bookmark is the `.duck` that opens the connection once the profile is
// installed. `Provider` is what binds it to the profile: it names the
// profile's Vendor, so Cyberduck resolves this bookmark to the OAuth-
// configured protocol rather than to its built-in WebDAV.
//
// It carries no Username, because the profile sets `Username Configurable`
// false, and it CANNOT carry a password (see the package comment).
func Bookmark(p Params) ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	w := newPlist()
	w.str("Protocol", "dav")
	w.str("Provider", p.vendor())
	w.str("Hostname", "127.0.0.1")
	w.str("Port", strconv.Itoa(p.Port))
	w.str("Path", DAVPath)
	w.str("Nickname", p.nickname())
	w.str("Comment", p.description())
	return w.bytes()
}

// BasicBookmark is the contingency, and the path every client that is not
// Cyberduck or Mountain Duck takes: the built-in WebDAV protocol, this
// listener, and the per-client Basic username filled in. The PASSWORD IS
// NOT IN IT and cannot be — HostDictionary has no such key — so this costs
// the user exactly one paste, which is the price docs/design-webui.md's
// verification 2g quotes.
//
// It deliberately does NOT name the profile's Provider: this bookmark must
// work whether or not the profile is installed, because its whole reason to
// exist is the case where the OAuth path is not working.
func BasicBookmark(p Params) ([]byte, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	if p.BasicUser == "" {
		return nil, fmt.Errorf("davprofile: BasicBookmark needs the per-client Basic username")
	}
	w := newPlist()
	w.str("Protocol", "dav")
	w.str("Hostname", "127.0.0.1")
	w.str("Port", strconv.Itoa(p.Port))
	w.str("Path", DAVPath)
	w.str("Username", p.BasicUser)
	w.str("Nickname", p.nickname()+" (password)")
	w.str("Comment", p.description()+" - paste the password pelfs showed you")
	return w.bytes()
}

// FileName is the download's filename, with no `/` and no space, for one of
// "cyberduckprofile", "duck" or "basic.duck".
func FileName(p Params, ext string) string {
	base := "pelfs-" + strconv.Itoa(p.Port)
	return base + "." + ext
}

// Details is the plain connection information for a client with no profile
// format at all: rclone, WinSCP, `mount_webdav`, curl. It is what the UI
// shows beside the download buttons.
type Details struct {
	URL      string
	Username string
	Writable bool
	// Preemptive says the Basic credential must be sent without waiting for
	// a challenge, which is what Cyberduck does
	// (`webdav.basic.preemptive=true`, docs/design-guiclients.md) and what
	// rclone and curl do by default.
	Preemptive bool
}

// Details returns the plain connection information. The password is not in
// it: the caller has it once, from internal/localoauth, and shows it once.
func (p Params) Details() Details {
	return Details{URL: DAVURL(p.Port), Username: p.BasicUser,
		Writable: p.Write, Preemptive: true}
}

// check is trap 4 plus the ordinary sanity: no `$` anywhere, no control
// characters, a real port.
func (p Params) check() error {
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("davprofile: port %d is not a port", p.Port)
	}
	for _, v := range []string{p.Volume, p.ClientID, p.RedirectURI, p.BasicUser, p.Label} {
		if err := checkValue(v); err != nil {
			return err
		}
	}
	return nil
}

// checkValue refuses what Cyberduck's StringSubstitutor or a plist parser
// would mangle. It is a REFUSAL rather than an escape or a strip, because
// the values here are a client id and a URL that both have to survive
// unchanged, and a silently-altered credential is worse than a failed
// download.
func checkValue(v string) error {
	if strings.ContainsRune(v, '$') {
		return fmt.Errorf("davprofile: %q contains '$', which Cyberduck's "+
			"StringSubstitutor may rewrite before the client uses it", v)
	}
	for _, r := range v {
		if r == '\n' || r == '\r' || r == '\t' || (unicode.IsControl(r) && r != ' ') {
			return fmt.Errorf("davprofile: %q contains a control character", v)
		}
	}
	return nil
}

// ------------------------------------------------------------------ plist

// plistWriter writes an Apple property list with the keys in the order they
// were added, because a generated file that is stable byte for byte is a
// generated file a golden test can pin and a human can diff.
//
// A hand-rolled writer rather than a dependency: the whole grammar used
// here is four value types, the escaping is encoding/xml's, and a plist
// library would be a module in go.mod for 60 lines.
type plistWriter struct {
	buf bytes.Buffer
	err error
}

func newPlist() *plistWriter {
	w := &plistWriter{}
	w.buf.WriteString(xml.Header)
	w.buf.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	w.buf.WriteString("<plist version=\"1.0\">\n<dict>\n")
	return w
}

func (w *plistWriter) key(k string) {
	w.buf.WriteString("\t<key>")
	w.escape(k)
	w.buf.WriteString("</key>\n")
}

func (w *plistWriter) str(k, v string) {
	if err := checkValue(v); err != nil && w.err == nil {
		w.err = err
	}
	w.key(k)
	w.buf.WriteString("\t<string>")
	w.escape(v)
	w.buf.WriteString("</string>\n")
}

func (w *plistWriter) integer(k string, v int) {
	w.key(k)
	fmt.Fprintf(&w.buf, "\t<integer>%d</integer>\n", v)
}

func (w *plistWriter) boolean(k string, v bool) {
	w.key(k)
	if v {
		w.buf.WriteString("\t<true/>\n")
		return
	}
	w.buf.WriteString("\t<false/>\n")
}

// array writes a plist <array> of strings, which is trap 3: `Scopes` is
// read by `list(SCOPES_KEY)` and a single string is not a one-element list.
func (w *plistWriter) array(k string, vs []string) {
	w.key(k)
	w.buf.WriteString("\t<array>\n")
	for _, v := range vs {
		if err := checkValue(v); err != nil && w.err == nil {
			w.err = err
		}
		w.buf.WriteString("\t\t<string>")
		w.escape(v)
		w.buf.WriteString("</string>\n")
	}
	w.buf.WriteString("\t</array>\n")
}

func (w *plistWriter) escape(v string) {
	if err := xml.EscapeText(&w.buf, []byte(v)); err != nil && w.err == nil {
		w.err = err
	}
}

func (w *plistWriter) bytes() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	w.buf.WriteString("</dict>\n</plist>\n")
	return w.buf.Bytes(), nil
}
