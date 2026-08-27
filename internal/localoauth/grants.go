package localoauth

// THE SECOND THING THAT SURVIVES THE PROCESS, AND THE ONLY ONE THAT IS A
// CAPABILITY RATHER THAN A NAME.
//
// identity.go persists who a profile SAYS IT IS. This file persists what a
// human already AUTHORIZED it to do: one row per issued grant, so a client
// that holds a refresh token reconnects across a restart of `pelfs browse`
// with no click at all.
//
// # Why this is not the thing the consent gesture exists to stop
//
// The instinct — and this package's own comment used to hold the line this
// way — is that "persisting the OAuth connection" reinstates the attack A7
// control 6 removes. It does not, and the distinction is exact:
//
//   - Persisting CONSENT would mean /oauth/authorize approving a request
//     without a human. That IS the attack: a page the user merely visits can
//     navigate their browser to /authorize, and if the endpoint remembers
//     "this client was approved before" it mints a code with nobody in the
//     loop. That is refused here permanently and no configuration turns it
//     on. GET /oauth/authorize still has no code path that writes a Location
//     header, the POST still needs a ticket that only ever existed in the
//     body of a page rendered in the user's browser, and that page still
//     runs no script.
//   - Persisting the GRANT touches /oauth/authorize not at all. A client
//     holding a refresh token calls POST /oauth/token, presents the token
//     and its client_id, and gets an access token. There is no authorization
//     request in that exchange for anybody to drive silently, and the thing
//     being renewed is the credential a human already approved on a screen
//     naming the volume, the program and the scope.
//
// So the click is required to CREATE a grant, and not to keep one. The
// user-visible result is the one that was asked for twice: a saved Cyberduck
// bookmark connects after a restart with no browser interaction, and only a
// first-time setup — or a grant that was revoked or expired — meets the
// consent screen.
//
// # What is in the file, and what is deliberately not
//
// Per row: the client's identity tuple (label, redirect, write — the same
// handle identity.go uses, because it is the only one both files can agree
// on across a process), the grant's non-secret ref, its scope, when it was
// issued, when it was last used, when it expires, and
//
//	HMAC-SHA256(file key, refresh token)
//
// and NOT the refresh token. That is the whole difference between a file
// that is a credential and a file that is a verifier: this one lets the
// process RECOGNISE a token the client already holds, and yields nothing
// that can be presented anywhere. There is no access token in it either —
// access tokens stay per-process, keyed under Server.key, which is
// crypto/rand at New.
//
// # The trade, stated plainly, because it is a real one
//
// Before this file, exiting `pelfs browse` was a complete revocation of
// every credential it had ever issued. It is not any more. A refresh token
// stolen from the client's own credential store keeps working across
// restarts, for up to RefreshTTL, until the user revokes that row. That is
// the cost, and it is the price of the feature: "reconnect with no click"
// and "a restart revokes everything" are the same statement with opposite
// signs.
//
// What bounds the cost:
//
//   - The scope is unchanged: this volume's /dav/* only, clamped at every
//     request to the session's own mode, and there has never been a publish
//     scope on any DAV grant (/api/v1/publish refuses an Authorization
//     header a layer up, in internal/httpguard).
//   - RefreshTTL is a hard ceiling, recorded per row and checked both when
//     the file is read and when a refresh is presented.
//   - Every row is INDIVIDUALLY LISTED on the page (GrantInfo.Persistent)
//     and INDIVIDUALLY REVOCABLE, and RevokeGrant deletes the row before it
//     reports success — so a revoked grant is dead after a restart, which is
//     the property that makes persisting one defensible at all.
//   - A grant is worth nothing without the client_id, which is in the
//     installed profile.
//
// # Threat model for the file itself
//
// Mode 0600, in the state directory, which is 0700 — the same discipline,
// the same atomic write and the same directory as browse-identity.key and
// v2-signing.key. Created LAZILY: a session that issues no grant writes no
// new file.
//
// What an attacker who READS IT gets: the labels of the programs that have
// connected, their scopes and their timestamps. No token. They cannot
// present a row at /oauth/token, because the row is an HMAC and the token it
// verifies is in Cyberduck's keychain, not here.
//
// Compare the two neighbours it is judged against:
//
//   - v2-signing.key, in the same directory, unencrypted: the volume's
//     Ed25519 signing key, which can publish a generation every reader in
//     the federation will accept. This file is strictly weaker — it cannot
//     write a byte, and reading it yields no credential at all — and
//     docs/design-webui.md's A8 already declines to defend against a
//     malicious process running as the user, which is the only attacker who
//     can read either.
//   - the HTTP Basic password, which this session removed and which we had
//     refused to persist for exactly the reason this file has to answer. It
//     is a different proposition, and here is the difference rather than an
//     assertion of it: a password authenticated at /dav/* directly, in one
//     hop, preemptively, with no expiry, no recorded scope beyond the
//     client's, no issue time, no last-used time, and one live value per
//     client that rolled silently whenever the user re-downloaded. A refresh
//     token authenticates NOTHING on its own: it must be exchanged at
//     /oauth/token, against a client_id only the installed profile carries,
//     for an access token that dies in an hour — and the grant behind it is
//     one row the user can see, with a scope, an age, a last-used time and
//     its own revoke button that reaches the disk. That is what "scoped,
//     revocable, individually listed" buys, and it is why the answer here is
//     yes where the answer for a password was no.
//
// (On Windows the 0600 is advisory, as it is for every other secret pelfs
// writes.)

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GrantFileName is the file, in the volume's state directory, beside
// browse-identity.key. A `.key` extension on a file whose body is JSON, for
// the reason IdentityFileName gives: the extension is what tells a human
// reading a directory listing that the contents are not to be shared.
const GrantFileName = "browse-grants.key"

// grantVersion is the on-disk format. An unknown version is refused rather
// than guessed at.
const grantVersion = 1

// RefreshTTL is how long a persisted grant lives whatever else happens.
//
// It is the bound that makes a standing credential a bounded one. 30 days is
// chosen against the thing it protects: a user who connected a program once
// and forgot about it should not still be handing it their files a year
// later, and a user who uses the program weekly should never see the consent
// screen again. An expired row is pruned when the file is written and
// refused when it is read, so it does not depend on anything sweeping.
const RefreshTTL = 30 * 24 * time.Hour

// maxGrants caps the roster. Grants are created by a human pressing
// Authorize, so this is not an attack surface the way maxPending is — it is
// a bound on a file that would otherwise grow by a row every time a program
// reconnected after its grant was revoked. The OLDEST is dropped.
const maxGrants = 64

// grantNote is written into the file so a person who finds it knows what it
// is without having to find this package.
const grantNote = "pelfs browse: the OAuth grants a human authorized for this volume, so a " +
	"saved WebDAV bookmark reconnects without another consent screen. SECRET, mode 0600. " +
	"Each row holds an HMAC of a refresh token, NEVER the token, and no access token and no " +
	"password is stored here at all. Deleting this file makes every connected program ask " +
	"for consent once more; it breaks nothing else."

// GrantStore is the persistent grant roster for ONE volume — in practice for
// one state directory, which is the same thing in every default
// configuration.
//
// Safe for concurrent use. Holds no goroutines and does no IO until a grant
// actually needs saving.
type GrantStore struct {
	path string

	mu sync.Mutex
	// key is the HMAC key the rows are written under. present is false
	// until the file has been read (and it had one) or written (and we
	// minted one) — the laziness is what keeps a session that issues no
	// grant from leaving a new secret on disk.
	key     [32]byte
	present bool
	recs    []grantRecord
}

// grantRecord is one persisted grant.
//
// NO TOKEN IS IN HERE. Refresh is an HMAC of the refresh token under the
// file's key; the access token is not persisted at all.
type grantRecord struct {
	Ref string `json:"ref"`
	// The identity tuple, which is how a row finds its client after a
	// restart. It is the same tuple identity.go stores, deliberately: two
	// files that name a client two ways is two files that can disagree.
	Label    string `json:"label"`
	Redirect string `json:"redirect"`
	Write    bool   `json:"write"`

	Scopes   []string  `json:"scopes"`
	Refresh  string    `json:"refresh_mac"`
	Issued   time.Time `json:"issued"`
	LastUsed time.Time `json:"last_used,omitzero"`
	Expires  time.Time `json:"expires"`
}

// refreshMAC decodes the stored HMAC. A row whose MAC is not 32 base64url
// bytes is dropped rather than repaired: it can only have come from a
// hand-edited file, and a grant adopted from garbage is a grant nothing can
// present and nothing can revoke.
func (r grantRecord) refreshMAC() ([32]byte, bool) {
	var out [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(r.Refresh)
	if err != nil || len(raw) != len(out) {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// grantFile is the on-disk document.
type grantFile struct {
	Version int           `json:"version"`
	Note    string        `json:"note"`
	Key     string        `json:"key"`
	Grants  []grantRecord `json:"grants"`
}

// OpenGrants reads the grant roster in dir, or prepares an empty one.
//
// IT DOES NOT CREATE THE FILE. A missing file is the ordinary case — the
// first `pelfs browse` on a volume, or one that nobody has connected a
// program to — and is not an error. What IS an error is a file that exists
// and cannot be understood: the alternative is silently forgetting every
// grant, which looks to the user exactly like the bug this file was added to
// fix, and doing it quietly.
func OpenGrants(dir string) (*GrantStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: OpenGrants needs a state directory", ErrConfig)
	}
	g := &GrantStore{path: filepath.Join(dir, GrantFileName)}
	b, err := os.ReadFile(g.path)
	if err != nil {
		if os.IsNotExist(err) {
			return g, nil
		}
		return nil, fmt.Errorf("localoauth: read %s: %w", g.path, err)
	}
	var f grantFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("localoauth: %s is not a pelfs browse grant file: %w", g.path, err)
	}
	if f.Version != grantVersion {
		return nil, fmt.Errorf("localoauth: %s is version %d and this pelfs understands %d",
			g.path, f.Version, grantVersion)
	}
	raw, err := base64.RawURLEncoding.DecodeString(f.Key)
	if err != nil || len(raw) != len(g.key) {
		return nil, fmt.Errorf("localoauth: %s has no usable key (want %d base64url bytes)",
			g.path, len(g.key))
	}
	copy(g.key[:], raw)
	g.present = true
	g.recs = f.Grants
	return g, nil
}

// Path is where the roster lives, for a message that has to name it.
func (g *GrantStore) Path() string { return g.path }

// records is the roster, oldest first. A copy: the caller iterates it
// outside the lock.
func (g *GrantStore) records() []grantRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]grantRecord(nil), g.recs...)
}

// mac is the lookup key for a refresh token: HMAC under the FILE's key
// rather than the process's, which is the whole of what makes a token
// recognisable to the next process. It mints the key on first use, so the
// first grant of a volume's life is what creates it — and a failure of the
// RNG yields a zero MAC that nothing can match, rather than a panic on a
// path a /dav/* request can reach. save() is where an error surfaces.
func (g *GrantStore) mac(secret string) [32]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.present {
		if _, err := rand.Read(g.key[:]); err != nil {
			return [32]byte{}
		}
		g.present = true
	}
	h := hmac.New(sha256.New, g.key[:])
	h.Write([]byte(secret))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// save records one grant, replacing any row with the same ref.
//
// The roster is only mutated for as long as the write holds: if the file
// cannot be written, the in-memory copy must not go on claiming a durable
// grant the next process will not find.
func (g *GrantStore) save(rec grantRecord) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := g.recs
	kept := make([]grantRecord, 0, len(g.recs)+1)
	for _, r := range g.recs {
		if r.Ref != rec.Ref {
			kept = append(kept, r)
		}
	}
	kept = append(kept, rec)
	if len(kept) > maxGrants {
		kept = kept[len(kept)-maxGrants:]
	}
	g.recs = kept
	if err := g.saveLocked(); err != nil {
		g.recs = before
		return err
	}
	return nil
}

// touch records a refresh against an existing row: a new expiry is NOT
// granted (RefreshTTL runs from the issue, not from the last use, so a
// program that reconnects daily does not hold a credential forever), but the
// last-used time is, because a row the user cannot date is a row they cannot
// judge.
//
// A missing row is not an error: an ephemeral grant on a server that also
// has a store is a legitimate thing to refresh.
func (g *GrantStore) touch(ref string, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := append([]grantRecord(nil), g.recs...)
	found := false
	for i := range g.recs {
		if g.recs[i].Ref == ref {
			g.recs[i].LastUsed = now.UTC()
			found = true
		}
	}
	if !found {
		return nil
	}
	if err := g.saveLocked(); err != nil {
		g.recs = before
		return err
	}
	return nil
}

// forget deletes one grant row. This is what makes RevokeGrant durable: the
// refresh token the client holds stops being recognisable in this session
// AND in every session after it.
func (g *GrantStore) forget(ref string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := g.recs
	kept := make([]grantRecord, 0, len(g.recs))
	found := false
	for _, r := range g.recs {
		if r.Ref == ref {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return nil
	}
	g.recs = kept
	if err := g.saveLocked(); err != nil {
		g.recs = before
		return err
	}
	return nil
}

// forgetClient deletes every grant row for one client identity. Revoking a
// client has to take its saved connections with it, or the profile would be
// dead and the standing access it bought would not.
func (g *GrantStore) forgetClient(label, redirect string, write bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	before := g.recs
	kept := make([]grantRecord, 0, len(g.recs))
	found := false
	for _, r := range g.recs {
		if r.Label == label && r.Redirect == redirect && r.Write == write {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return nil
	}
	g.recs = kept
	if err := g.saveLocked(); err != nil {
		g.recs = before
		return err
	}
	return nil
}

// saveLocked writes the file atomically: a temp file in the SAME directory
// (so the rename cannot cross a filesystem), 0600 from the moment it exists,
// fsynced before the rename. The same discipline as identity.go's, and for
// the same reason — this file's whole purpose is surviving a restart,
// including the restart that follows a crash.
//
// EXPIRED ROWS ARE PRUNED HERE, which is why nothing sweeps: every write
// drops what has aged out, and every read refuses what a write has not
// caught yet.
func (g *GrantStore) saveLocked() error {
	if !g.present {
		if _, err := rand.Read(g.key[:]); err != nil {
			return fmt.Errorf("localoauth: grant key: %w", err)
		}
		g.present = true
	}
	now := time.Now()
	live := make([]grantRecord, 0, len(g.recs))
	for _, r := range g.recs {
		if !r.Expires.IsZero() && now.After(r.Expires) {
			continue
		}
		live = append(live, r)
	}
	g.recs = live
	body, err := json.MarshalIndent(grantFile{
		Version: grantVersion, Note: grantNote,
		Key:    base64.RawURLEncoding.EncodeToString(g.key[:]),
		Grants: g.recs,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("localoauth: grants: %w", err)
	}
	body = append(body, '\n')
	dir := filepath.Dir(g.path)
	tmp, err := os.CreateTemp(dir, GrantFileName+".*")
	if err != nil {
		return fmt.Errorf("localoauth: grants: %w", err)
	}
	name := tmp.Name()
	// CreateTemp is already 0600, but this file's mode is a documented
	// property rather than an inherited one, so it is set rather than
	// assumed. Windows has no chmod worth the name, and the state
	// directory's own 0700 is the boundary there.
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: write %s: %w", g.path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: sync %s: %w", g.path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: close %s: %w", g.path, err)
	}
	if err := os.Rename(name, g.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: replace %s: %w", g.path, err)
	}
	return nil
}
