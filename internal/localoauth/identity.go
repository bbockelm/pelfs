package localoauth

// THE ONE THING IN THIS PACKAGE THAT SURVIVES THE PROCESS, AND THE EXACT
// SHAPE OF WHAT IT BUYS.
//
// The rest of internal/localoauth persists nothing on purpose, and its
// package comment says so at length ("Nothing persists, and that is the
// revocation story"). This file is the deliberate exception, and it is
// narrow: it persists the CLIENT IDENTITY — who a profile says it is — and
// no credential of any kind.
//
// # Why it had to exist
//
// `pelfs browse` now listens on a port derived from the volume
// (cmd/pelfs/browseport.go), so the `.duck` bookmark a user saved keeps
// resolving next session: same host, same port, same Provider string. The
// report that asked for it ("can we try to have a stable port so the
// CyberDuck bookmark is not one-time-use?") was answered one step short of
// the user's actual problem, and docs/known-issues.md carried the residue
// as KL-17: the `.cyberduckprofile`'s `OAuth Client ID` was 32 bytes of
// crypto/rand minted per download and held in memory only, so a saved
// bookmark reached the right port and then failed at /oauth/authorize with
// "This is not an authorization request pelfs issued". The profile had to
// be regenerated and reinstalled every session — which is the one-time-use
// problem, moved one step later.
//
// So the client id is now DERIVED rather than minted:
//
//	client_id = base64url( HMAC-SHA256(key, "pelfs-browse-client-v1\0"
//	                          || label || redirect || write || epoch) )
//
// with `key` 32 bytes of crypto/rand held in the volume's state directory
// and `epoch` 8 more, recorded beside the tuple the first time it is
// registered. The derivation's only inputs are things this file holds, so
// the generated profile for a given (volume, program label, write flag) is
// byte-identical across restarts — which is the property that makes
// reinstalling unnecessary, and it is asserted in identity_test.go and again
// in scripts/browse-gate.sh with real `duck` across a real restart.
//
// THE EPOCH IS WHAT MAKES REVOCATION FINAL, and it is the one part of this
// scheme that is not obvious. Without it the derivation would be a pure
// function of the tuple, so a user who revoked "Cyberduck" and later added
// "Cyberduck" again would re-derive the id they revoked — re-arming the
// profile on the laptop they revoked it for. With it, forgetting an entry
// destroys the only copy of its epoch, and the next registration of the same
// label is a different client that the old profile cannot name.
//
// # WHAT THIS DOES NOT PERSIST, and each omission is the point
//
//   - NOT the access or refresh token. Grants live in Server.grants, in
//     memory, keyed by an HMAC under a PER-PROCESS key, and they die with
//     the process exactly as before. Exiting `pelfs browse` is still a
//     complete revocation of every token it ever issued.
//   - NOT consent. A human still clicks Authorize on every /oauth/authorize,
//     because remembering consent per client_id reinstates the exact
//     primitive A7 control 6 exists to remove (docs/design-webui.md says
//     "do not reinstate that" in as many words). The bookmark stops being
//     one-time-use; the click does not go away. The user-visible trade is
//     one click per session instead of a download, an install and a click
//     per session.
//   - NOT the HTTP Basic password. It is a credential that authenticates
//     directly at /dav/* with no gesture in front of it, so it stays
//     crypto/rand into memory and dies with the process. That is what makes
//     the paragraph below true: this file cannot be turned into a read of
//     the volume without a human clicking Authorize.
//   - NOT the volume, the tokens, the overlay, or anything about the data.
//
// # Threat model for the file, which is a long-lived secret on disk
//
// Mode 0600, in the state directory, which is created 0700 — the same
// discipline and the same directory as `v2-signing.key` (cmd/pelfs/volume.go)
// and the control socket. It is created LAZILY: a `pelfs browse` session
// that never generates a connection profile writes no new secret.
//
// What an attacker who READS it can do: derive the client ids for the
// clients listed in it, and therefore name a valid client at
// /oauth/authorize. That is all. To get a credential out of that they must
// also (a) have a `pelfs browse` running, (b) get the user to click
// Authorize on a consent page naming the volume, the client and the scope,
// and (c) be listening on 127.0.0.1:52001 to catch the code — i.e. already
// be running as the user on this machine. What they CANNOT do with it:
// read a byte of the volume, mint a token, publish anything (no DAV grant
// has ever carried a publish scope, and /api/v1/publish refuses an
// Authorization header one layer up in internal/httpguard), or use it
// against any other volume — the key is per-state-directory, so it is
// per-volume in every default configuration.
//
// Compare that with what is ALREADY in the same directory and unencrypted:
// `v2-signing.key`, the volume's Ed25519 signing key, which can publish a
// generation every reader will accept. This file is strictly weaker than
// its neighbour, and docs/design-webui.md's A8 already declines to defend
// against a malicious process running as the user for exactly that reason.
// It is therefore NOT encrypted: a passphrase-wrapped client identity in a
// directory that holds an unwrapped signing key would be ceremony, and the
// key it would have to be wrapped under would have to live somewhere a
// non-interactive `pelfs browse` could read.
//
// (On Windows the 0600 is advisory — Go maps it onto nothing meaningful for
// ACLs — which is true of every other secret pelfs writes and is worth
// stating rather than implying.)
//
// # What revoking one of these means now
//
// Deleting the entry, which is durable: the identity is gone from the file,
// so the derived client id names nothing in this session AND in every
// session after it. The installed profile is permanently dead and the user
// has to download a new one. That is a stronger promise than the old
// Revoke, which only outlived nothing at all, and it is why Revoke reports
// an error rather than a bool alone: a revocation that could not be written
// to disk is a revocation that comes back next session, and the page must
// not say "revoked" about it.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// IdentityFileName is the file, in the volume's state directory.
//
// A `.key` extension on a file whose body is JSON, deliberately: the
// extension is what tells a human reading a directory listing that the
// contents are a secret, and the key is in there with the roster. One file
// so there is one mode bit, one atomic write and one thing to delete.
const IdentityFileName = "browse-identity.key"

// identityVersion is the on-disk format. An unknown version is refused
// rather than guessed at, because guessing at a credential file's layout is
// how a client id gets derived from garbage and every installed profile
// silently stops working.
const identityVersion = 1

// clientIDDomain separates this HMAC's inputs from every other use of the
// same key. There is only one use today; the domain tag is what keeps that
// true when there is a second.
const clientIDDomain = "pelfs-browse-client-v1\x00"

// maxIdentityClients caps the roster. The route that grows it
// (POST /api/v1/credentials) is session-authenticated rather than
// unauthenticated, so this is not an attack surface the way maxPending is —
// it is a bound on a file that would otherwise grow by one entry every time
// a user typed a new label into the connection page. The OLDEST is dropped,
// which is the entry whose profile is least likely to still be installed.
const maxIdentityClients = 32

// identityNote is written into the file so that a person who finds it knows
// what it is and what losing it costs, without having to find this package.
const identityNote = "pelfs browse: the per-volume key that derives the OAuth client ids " +
	"in generated Cyberduck profiles, plus the clients derived from it. SECRET, mode 0600. " +
	"No access token, no refresh token and no password is stored here. Deleting this file " +
	"invalidates every profile pelfs generated for this volume."

// Identity is the persistent client identity for ONE volume — in practice
// for one state directory, which is the same thing in every default
// configuration (cmd/pelfs/daemon.go's volDirIn derives the directory from
// the prefix URL). Two --state-dir values for one volume are two
// identities, exactly as they are two signing keys.
//
// Safe for concurrent use. Holds no goroutines and does no IO until
// something actually needs a client id.
type Identity struct {
	path string

	mu sync.Mutex
	// key is the derivation key. present is false until the file has been
	// read (and it had one) or written (and we minted one) — the laziness
	// is what keeps a browse session that generates no profile from
	// leaving a new secret on disk.
	key     [32]byte
	present bool
	ents    []identityEntry
}

// identityEntry is one client identity: the whole of what the derivation
// takes, plus when it was first registered so a list can be sorted and the
// cap can drop the oldest.
//
// NO CREDENTIAL IS IN HERE. The client id is not stored, it is derived; the
// epoch is a nonce and is worth nothing without the key. Epoch may be empty
// in a hand-written file, which derives perfectly well — it only costs that
// file the revoke-is-final property.
type identityEntry struct {
	Label    string    `json:"label"`
	Redirect string    `json:"redirect"`
	Write    bool      `json:"write"`
	Epoch    string    `json:"epoch"`
	Created  time.Time `json:"created"`
}

// identityFile is the on-disk document.
type identityFile struct {
	Version int             `json:"version"`
	Note    string          `json:"note"`
	Key     string          `json:"key"`
	Clients []identityEntry `json:"clients"`
}

// OpenIdentity reads the identity in dir, or prepares an empty one.
//
// IT DOES NOT CREATE THE FILE. A missing file is the ordinary case — the
// first `pelfs browse` on a volume — and is not an error; the file appears
// the first time a client is registered. What IS an error is a file that
// exists and cannot be understood, because the alternative is deriving
// client ids from a key we invented and telling the user their installed
// profile is not one pelfs issued.
func OpenIdentity(dir string) (*Identity, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: OpenIdentity needs a state directory", ErrConfig)
	}
	id := &Identity{path: filepath.Join(dir, IdentityFileName)}
	b, err := os.ReadFile(id.path)
	if err != nil {
		if os.IsNotExist(err) {
			return id, nil
		}
		return nil, fmt.Errorf("localoauth: read %s: %w", id.path, err)
	}
	var f identityFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("localoauth: %s is not a pelfs browse identity file: %w", id.path, err)
	}
	if f.Version != identityVersion {
		return nil, fmt.Errorf("localoauth: %s is version %d and this pelfs understands %d",
			id.path, f.Version, identityVersion)
	}
	raw, err := base64.RawURLEncoding.DecodeString(f.Key)
	if err != nil || len(raw) != len(id.key) {
		return nil, fmt.Errorf("localoauth: %s has no usable key (want %d base64url bytes)",
			id.path, len(id.key))
	}
	copy(id.key[:], raw)
	id.present = true
	id.ents = f.Clients
	return id, nil
}

// clients is the roster, oldest first. A copy: the caller iterates it
// outside the lock.
func (i *Identity) clients() []identityEntry {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]identityEntry(nil), i.ents...)
}

// derive is the client id for one roster entry — the entries this identity
// already holds, which is all adoption needs.
func (i *Identity) derive(e identityEntry) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.ensureKeyLocked(); err != nil {
		return "", err
	}
	return i.deriveLocked(e), nil
}

// register records an identity tuple and returns its client id and the time
// it was FIRST registered.
//
// IDEMPOTENT, and that is forced rather than convenient: an existing tuple
// is derived from ITS OWN recorded epoch, so a second registration cannot
// produce a different id — and a second ROW for it would be a second revoke
// button for one profile. So the same (label, redirect, write) is one
// client, and re-generating a download for it hands back a byte-identical
// profile. A tuple that is NOT here yet gets a fresh epoch, which is what
// makes a re-added label a different client from the one that was revoked.
func (i *Identity) register(label, redirect string, write bool, now time.Time) (string, time.Time, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.ensureKeyLocked(); err != nil {
		return "", time.Time{}, err
	}
	for _, e := range i.ents {
		if e.Label == label && e.Redirect == redirect && e.Write == write {
			return i.deriveLocked(e), e.Created, nil
		}
	}
	epoch := make([]byte, 8)
	if _, err := rand.Read(epoch); err != nil {
		return "", time.Time{}, fmt.Errorf("localoauth: identity epoch: %w", err)
	}
	fresh := identityEntry{
		Label: label, Redirect: redirect, Write: write,
		Epoch: base64.RawURLEncoding.EncodeToString(epoch), Created: now.UTC(),
	}
	id := i.deriveLocked(fresh)
	// The roster is only mutated for as long as the write holds: if the file
	// cannot be written, the in-memory copy must not go on claiming an
	// identity the next process will not find.
	before := i.ents
	i.ents = append(append([]identityEntry(nil), i.ents...), fresh)
	if len(i.ents) > maxIdentityClients {
		sort.SliceStable(i.ents, func(a, b int) bool { return i.ents[a].Created.Before(i.ents[b].Created) })
		i.ents = i.ents[len(i.ents)-maxIdentityClients:]
	}
	if err := i.saveLocked(); err != nil {
		i.ents = before
		return "", time.Time{}, err
	}
	return id, now.UTC(), nil
}

// forget deletes one identity tuple, which is what makes revoking a
// persistent client mean something: the derived id names nothing in this
// session and in every session after it, so the profile the user installed
// is permanently dead.
//
// The key is deliberately NOT rotated on a forget: rotating it would kill
// every OTHER installed profile for this volume as a side effect of revoking
// one, which is not what a per-row Revoke button says it does. What makes
// this row's revocation final instead is the epoch, which goes with it — see
// the file comment.
func (i *Identity) forget(label, redirect string, write bool) (bool, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	kept := make([]identityEntry, 0, len(i.ents))
	found := false
	for _, e := range i.ents {
		if e.Label == label && e.Redirect == redirect && e.Write == write {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return false, nil
	}
	before := i.ents
	i.ents = kept
	if err := i.saveLocked(); err != nil {
		i.ents = before
		return false, err
	}
	return true, nil
}

// deriveLocked is the derivation. Called under mu, with the key present.
//
// EVERY FIELD IS LENGTH-PREFIXED rather than separated by a byte, because
// the label is a string the user typed on the connection page: any
// separator it could contain is a separator that lets two different tuples
// hash the same, and a client id collision is two profiles that are one
// credential.
func (i *Identity) deriveLocked(e identityEntry) string {
	h := hmac.New(sha256.New, i.key[:])
	h.Write([]byte(clientIDDomain))
	for _, s := range []string{e.Label, e.Redirect, e.Epoch} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	if e.Write {
		h.Write([]byte{'w'})
	} else {
		h.Write([]byte{'r'})
	}
	// The same width as mint(): 32 bytes, RawURLEncoding, so a client id's
	// length never says which kind of secret it is — and no '=' and no '$'
	// for a plist, a URL or Cyberduck's StringSubstitutor to argue about.
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// ensureKeyLocked mints the key on first use. Called under mu.
func (i *Identity) ensureKeyLocked() error {
	if i.present {
		return nil
	}
	if _, err := rand.Read(i.key[:]); err != nil {
		return fmt.Errorf("localoauth: identity key: %w", err)
	}
	i.present = true
	if err := i.saveLocked(); err != nil {
		i.present = false
		return err
	}
	return nil
}

// saveLocked writes the file atomically: a temp file in the SAME directory
// (so the rename cannot cross a filesystem), 0600 from the moment it
// exists, fsynced before the rename.
//
// The fsync is here and not at the signing key's precedent, because this
// file's whole reason to exist is surviving a restart — including the
// restart that follows a crash. A rename over a file whose bytes never
// reached the disk would leave a key that derives client ids nobody's
// installed profile carries, which is the failure this file exists to
// prevent, arriving by a different road.
func (i *Identity) saveLocked() error {
	body, err := json.MarshalIndent(identityFile{
		Version: identityVersion, Note: identityNote,
		Key:     base64.RawURLEncoding.EncodeToString(i.key[:]),
		Clients: i.ents,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("localoauth: identity: %w", err)
	}
	body = append(body, '\n')
	dir := filepath.Dir(i.path)
	tmp, err := os.CreateTemp(dir, IdentityFileName+".*")
	if err != nil {
		return fmt.Errorf("localoauth: identity: %w", err)
	}
	name := tmp.Name()
	// CreateTemp is already 0600, but this file's mode is a documented
	// property rather than an inherited one, so it is set rather than
	// assumed.
	if err := tmp.Chmod(0o600); err != nil && !os.IsNotExist(err) {
		// Windows has no chmod worth the name; a failure here is not a
		// reason to refuse to write the file, and the state directory's
		// own 0700 is the boundary that matters there.
		_ = err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: write %s: %w", i.path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: sync %s: %w", i.path, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: close %s: %w", i.path, err)
	}
	if err := os.Rename(name, i.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("localoauth: replace %s: %w", i.path, err)
	}
	return nil
}
