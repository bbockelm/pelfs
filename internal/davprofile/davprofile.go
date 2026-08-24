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
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

// VendorPrefix is the profile identity's stem. The full Vendor names the
// VOLUME (see Params.vendor), because that is what a profile is a profile
// for and it is no longer implied by anything else in the file.
//
// It used to name the listener's PORT, which worked only while the port
// identified the volume: the port was derived from the prefix URL by a
// hash, so one volume meant one port meant one Vendor. `pelfs browse` now
// probes upward from 8443 (cmd/pelfs/browseport.go), so two volumes take
// 8443 and 8444 in whatever order they happened to start, and tomorrow's
// 8443 may be a different volume from today's. A port-keyed Vendor under
// that rule is a COLLISION: installing volume B's profile would replace
// volume A's, and volume A's saved bookmark — which resolves to a profile
// by this string — would carry volume B's OAuth client into whatever is
// on the port. That is "a bookmark quietly opening another volume's
// files", which must not be reachable by accident.
//
// Keyed on the volume it cannot happen: two volumes are two profiles, A's
// bookmark keeps resolving to A's profile and therefore keeps presenting
// A's client_id, and a session serving another volume answers
// internal/localoauth's refusal page — which names the volume it IS
// serving, so the user can see what happened.
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

	// ClientID is the OAuth client_id from internal/localoauth: a secret
	// only a profile download carries, and the key that turns OAuth on. A
	// blank one is an error rather than a default, per trap 1.
	//
	// IT IS USUALLY THE SAME STRING EVERY SESSION — internal/localoauth
	// derives it from a per-volume key in the state directory — which is what
	// makes this package's determinism load-bearing rather than tidy: a
	// profile a user installed once has to keep matching the one pelfs would
	// generate today, byte for byte. Nothing here may grow a timestamp, a
	// nonce or a map iteration.
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
	return VendorPrefix + "." + VolumeTag(p.Volume)
}

// VolumeTag is a volume's identity inside a profile identifier: a short,
// stable, filename-safe digest of the volume URL.
//
// SHA-256 truncated to six bytes, which is a collision every 2^24 volumes
// by the birthday bound and is not a security boundary in either
// direction: it decides which PROFILE a bookmark resolves to, and every
// credential behind that profile is checked by internal/localoauth against
// the client roster of the session actually answering. Two volumes that
// collided here would produce one profile identity, which is exactly the
// behaviour of the port-keyed Vendor this replaced — no worse, and
// vanishingly rarer.
//
// The leading "v" is so the component is not a bare number: this string
// goes into a reverse-DNS-shaped identifier, and a segment starting with a
// digit is the kind of thing a parser somewhere decides to have an opinion
// about.
//
// DETERMINISM IS LOAD-BEARING, as everywhere in this package: a profile a
// user installed once has to keep matching the one pelfs would generate
// today, byte for byte.
func VolumeTag(volume string) string {
	sum := sha256.Sum256([]byte(volume))
	return "v" + hex.EncodeToString(sum[:6])
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
	//
	// IT USED TO SAY "this session only", which was true of the profile when
	// the client id was minted per download and is not true now: the id is
	// derived from a per-volume key in the state directory, so this file is
	// the same file next session and installing it again is unnecessary
	// (internal/localoauth's identity.go). What IS still per session is the
	// authorization — a human clicks Authorize on every /oauth/authorize, and
	// this string is one of the few places a user reads about the profile
	// with no page in front of them, so it says both halves.
	return "pelfs " + v + " (" + mode + "; install once, authorize once per session)"
}

// nickname is the ONE STRING A USER READS IN A LIST OF BOOKMARKS, and
// getting it wrong is what "each time I click on it, it just says
// '127.0.0.1 - WebDAV (HTTP)'; no clue which each is" was.
//
// That string is Cyberduck's own fallback, and it is worth writing out
// where it comes from because it names the two keys this package has to
// set and the two it must not confuse them with. BookmarkNameProvider.java:
//
//	if(StringUtils.isEmpty(bookmark.getNickname())) {
//	    if(StringUtils.isNotBlank(bookmark.getProtocol().getDefaultNickname())) {
//	        return bookmark.getProtocol().getDefaultNickname();
//	    }
//	    final String hostname = toHostname(bookmark, username);
//	    ...
//	    return hostname + StringUtils.SPACE + '\u2013' + StringUtils.SPACE
//	        + bookmark.getProtocol().getName();
//	}
//	return bookmark.getNickname();
//
// So there are exactly three places a name can come from, in order:
//
//  1. the BOOKMARK's `Nickname` — HostDictionary.java reads that key
//     (`bookmark.setNickname(...)`), so it belongs in the `.duck`;
//  2. the PROTOCOL's `Default Nickname` — Profile.java's
//     DEFAULT_NICKNAME_KEY, so it belongs in the `.cyberduckprofile`, and
//     it is the one that names every bookmark a user creates from the
//     profile HIMSELF rather than by opening our `.duck`;
//  3. hostname + en dash + the PROTOCOL's `Name` — Profile.java's
//     NAME_KEY, which falls through to `parent.getName()` when absent, and
//     the built-in `dav` parent's name is the literal string "WebDAV
//     (HTTP)".
//
// The old code set (1) and neither (2) nor (3), which is why a bookmark the
// user made from the installed profile — and any UI that shows the protocol
// name rather than the bookmark name — read "127.0.0.1 – WebDAV (HTTP)".
// Note also that `Description` is NOT in that list at all: it is
// DESCRIPTION_KEY and it shows in the profile chooser, never in the
// bookmark list. Setting it was not setting a name.
//
// The shape is "pelfs: <volume> (<label>)": the volume first, because it is
// what distinguishes two of these from each other, and the label — what
// the user typed on the connection page when generating the download — in
// parentheses, because it is what distinguishes two clients on the same
// volume.
func (p Params) nickname() string {
	label := p.Label
	if label == "" {
		label = "pelfs"
	}
	v := shortVolume(p.Volume)
	if v == "" {
		return "pelfs (" + label + ")"
	}
	return "pelfs: " + v + " (" + label + ")"
}

// basicNickname distinguishes the contingency bookmark from the OAuth one
// in the same list, and says which one needs the paste. Both end up in the
// user's bookmarks and "no clue which each is" applies to two of ours as
// much as to two of anybody's.
func (p Params) basicNickname() string {
	label := p.Label
	if label == "" {
		label = "pelfs"
	}
	if v := shortVolume(p.Volume); v != "" {
		return "pelfs: " + v + " (" + label + ", password)"
	}
	return "pelfs (" + label + ", password)"
}

// protocolName is the profile's `Name`: what Cyberduck shows wherever it
// names the PROTOCOL rather than the bookmark — the New Bookmark dropdown,
// and the tail of the fallback in nickname's quotation. Without it that is
// "WebDAV (HTTP)" for every pelfs profile a user has installed, which is
// true and useless.
func (p Params) protocolName() string {
	if v := shortVolume(p.Volume); v != "" {
		return "pelfs " + v
	}
	return "pelfs"
}

// shortVolume is the volume as a person recognises it: the scheme dropped,
// because every pelfs volume has the same one and it is the widest column
// in the name.
//
// "pelican://osg-htc.org/user/bbockelman" becomes
// "osg-htc.org/user/bbockelman". A long one is truncated from the FRONT,
// keeping the tail, because the tail is the part that differs between two
// volumes in the same federation and the head is the part that does not.
func shortVolume(volume string) string {
	v := strings.TrimSpace(volume)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+len("://"):]
	}
	v = strings.Trim(v, "/")
	const max = 48
	if len(v) > max {
		// A rune boundary rather than a byte one: a truncated multi-byte
		// character in a plist string is a parse error in the client, not
		// a cosmetic problem.
		cut := v[len(v)-max:]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[1:]
		}
		v = "..." + cut
	}
	return v
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
//	any secret but the client id, which only a profile download carries, so
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
	w.str("Name", p.protocolName())
	w.str("Description", p.description())
	// `Default Nickname` (Profile.java's DEFAULT_NICKNAME_KEY), not
	// `Nickname`: a Profile has no such key, and BookmarkNameProvider
	// consults this one for any bookmark whose own Nickname is empty. See
	// Params.nickname for the three-way precedence this is the middle of.
	w.str("Default Nickname", p.nickname())
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
	w.str("Nickname", p.basicNickname())
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
