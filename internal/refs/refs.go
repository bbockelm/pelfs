// Package refs manages the mutable edge of a v2 volume: the named
// superblocks under refs/<branch> and tags/<name>
// (docs/design-packfs.md, "Federation namespace layout" and "Signing and
// key management").
//
// It owns two responsibilities the rest of the stack must never
// reimplement:
//
//   - Trust. Every fetched superblock is verified against the key the
//     READER trusts — an explicitly supplied public key, or one pinned in
//     local state on first use (TOFU, the SSH model). Custody-chain
//     rotation advances the pin only through a verified lineage step
//     (superblock.VerifyChain); any other key change is a loud error.
//
//   - The flip. Publishing a generation overwrites refs/<branch> guarded
//     by the ETag observed at fetch time: writers detect a lost race
//     instead of silently clobbering. The transports expose stat-ETags
//     but not conditional PUT, so the guard is check-then-put with a
//     narrow window, and the advisory lease keeps concurrent writers out
//     of even that window. True If-Match lands when the transport grows
//     it.
package refs

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// RefDirKey and TagDirKey are the key-space directories for branches and
// tags, relative to the volume prefix.
const (
	RefDirKey = "refs"
	TagDirKey = "tags"
)

// ErrStaleFlip reports that refs/<branch> changed between Fetch and Flip:
// another writer published first and this generation must be rebuilt on
// top of theirs.
var ErrStaleFlip = errors.New("ref changed since fetch (concurrent publish)")

// ErrUntrusted reports a superblock that does not verify under the pinned
// (or supplied) key and cannot be reached by a custody-chain step from
// the last accepted generation.
var ErrUntrusted = errors.New("superblock not signed by the trusted key")

// ErrRollback reports a branch head OLDER than the newest generation this
// client already accepted on it.
//
// Generations only ever move forward, so this means the read did not
// return the current object: an origin or cache answering an overwritten
// key with a superseded body. Refusing is not pedantry. A stale head
// silently mounts an old tree, and anything published on top of it is
// built on the wrong parent -- the CAS guard would then reject the flip,
// stranding the session's work after the fact instead of at the read that
// caused it.
var ErrRollback = errors.New("branch head went backwards (stale read)")

// Store reads and writes refs with trust enforcement and local pinning.
type Store struct {
	inner pelicanobj.Store
	// stateDir persists, per branch, the pinned public key and the last
	// accepted superblock (wire bytes, for custody-chain verification).
	stateDir string
	// trusted, when non-nil, is an explicitly supplied key: it is
	// authoritative and TOFU never runs.
	trusted ed25519.PublicKey
}

// New builds a ref store. stateDir is the volume's local state directory;
// trusted is an optional explicit public key (--volume-pubkey).
func New(inner pelicanobj.Store, stateDir string, trusted ed25519.PublicKey) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(stateDir, "refs"), 0700); err != nil {
		return nil, err
	}
	// Refs and tags are the volume's MUTABLE objects, and every one of
	// them is overwritten in place. Reading them through a federation
	// cache breaks read-after-write, and against a cache that
	// mis-reports object length it returns a truncated body — which
	// surfaces as a checksum mismatch, not as anything recognizably
	// cache-shaped. That is why it is enforced here instead of at each
	// call site: the symptom points nowhere near the cause, so a caller
	// that forgets has no way to learn it. Unwrap decorators to find the
	// transport: a stats counter or the pack layer embeds the Store
	// interface and hides this capability, which would leave the rule
	// silently inert on the mount path.
	if d, ok := pelicanobj.AsDirectReader(inner); ok {
		inner = d.DirectVariant()
	}
	return &Store{inner: inner, stateDir: stateDir, trusted: trusted}, nil
}

// Fetched is the result of one Fetch: the verified superblock, its wire
// bytes, and the ETag guarding the next Flip.
type Fetched struct {
	Superblock *superblock.Superblock
	Raw        []byte
	ETag       string
}

func refKey(branch string) string { return RefDirKey + "/" + branch }

// The pin is VOLUME-level, not per-branch: every branch and tag of a
// volume is signed by the one volume identity. A per-branch pin would
// hand an attacker a fresh TOFU on every branch name they invent.
func (s *Store) pinPath() string {
	return filepath.Join(s.stateDir, "refs", "volume.pub")
}

// lastPath is per-branch: custody-chain rotation is verified against the
// last superblock this client accepted on that branch's lineage.
func (s *Store) lastPath(branch string) string {
	return filepath.Join(s.stateDir, "refs", branch+".sb")
}

// Fetch reads refs/<branch>, verifies it, and returns it with its ETag.
// Verification policy, in order:
//
//  1. An explicitly supplied key must verify directly — no TOFU, no
//     rotation shortcut (an explicit key is a statement of intent).
//  2. The pinned volume key verifies directly, or via one custody-chain
//     step from the last accepted superblock of this branch — which
//     REPLACES the pin: the old key is retired, and sibling branches
//     still signed by it fail until republished with the new key.
//  3. No pin yet: trust-on-first-use — pin the embedded key, loudly.
func (s *Store) Fetch(ctx context.Context, branch string) (*Fetched, error) {
	if strings.ContainsAny(branch, "/\\") {
		return nil, fmt.Errorf("invalid branch name %q", branch)
	}
	raw, etag, err := s.read(ctx, refKey(branch))
	if err != nil {
		return nil, err
	}
	sb, err := superblock.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("ref %s: %w", branch, err)
	}
	if err := s.checkMonotonic(branch, sb); err != nil {
		return nil, err
	}

	if s.trusted != nil {
		if err := sb.Verify(s.trusted); err != nil {
			return nil, fmt.Errorf("ref %s: %w: %w", branch, ErrUntrusted, err)
		}
		return &Fetched{Superblock: sb, Raw: raw, ETag: etag}, nil
	}

	pinned, err := s.readPin()
	if err != nil {
		return nil, err
	}
	if pinned == nil {
		// TOFU: nothing pinned yet. Loud, because this is the one moment
		// an active attacker could substitute a key undetected.
		ui.Warn("pinning volume key {key} on first use; verify the fingerprint out of band "+
			"if this volume is shared", "key", hex.EncodeToString(sb.SigningPub[:]))
		if err := sb.Verify(ed25519.PublicKey(sb.SigningPub[:])); err != nil {
			return nil, fmt.Errorf("ref %s: %w", branch, err)
		}
		if err := s.persist(branch, sb.SigningPub[:], raw); err != nil {
			return nil, err
		}
		return &Fetched{Superblock: sb, Raw: raw, ETag: etag}, nil
	}

	if err := sb.Verify(pinned); err == nil {
		if err := s.persist(branch, pinned, raw); err != nil {
			return nil, err
		}
		return &Fetched{Superblock: sb, Raw: raw, ETag: etag}, nil
	}
	// Direct verification failed: accept only a custody-chain step from
	// the last superblock this client accepted on this branch.
	prevRaw, err := os.ReadFile(s.lastPath(branch))
	if err != nil {
		return nil, fmt.Errorf("ref %s: %w (no prior generation on record to rotate from)", branch, ErrUntrusted)
	}
	if err := superblock.VerifyChain(prevRaw, sb, pinned); err != nil {
		return nil, fmt.Errorf("ref %s: %w: %w", branch, ErrUntrusted, err)
	}
	ui.Warn("volume signing key rotated to {key} (announced by branch {branch}'s previous generation)",
		"key", hex.EncodeToString(sb.SigningPub[:]), "branch", branch)
	if err := s.persist(branch, sb.SigningPub[:], raw); err != nil {
		return nil, err
	}
	return &Fetched{Superblock: sb, Raw: raw, ETag: etag}, nil
}

// Flip publishes raw (an encoded, signed superblock) to refs/<branch>.
// expectETag is the ETag from the Fetch this generation was built on (""
// for the first generation, when the ref must not exist yet). Flip never
// touches the local trust state: pinning belongs to Fetch's verification
// path alone, or a compromised writer could re-pin its own key by
// publishing (the writer's next Fetch validates — and records — what it
// published like any other reader).
func (s *Store) Flip(ctx context.Context, branch string, raw []byte, expectETag string) error {
	key := refKey(branch)
	ki, err := s.inner.StatKey(ctx, key)
	switch {
	case err == nil && expectETag == "":
		return fmt.Errorf("%w: ref %s already exists", ErrStaleFlip, branch)
	case err == nil && ki.ETag != "" && ki.ETag != expectETag:
		return fmt.Errorf("%w: ref %s", ErrStaleFlip, branch)
	case err != nil && expectETag != "":
		return fmt.Errorf("%w: ref %s vanished", ErrStaleFlip, branch)
	}
	if err := s.inner.Put(ctx, key, strings.NewReader(string(raw))); err != nil {
		return fmt.Errorf("flip ref %s: %w", branch, err)
	}
	return nil
}

// ErrTagExists reports an attempt to write a tag that is already there.
//
// It is a sentinel rather than a bare error because refusing is the
// FEATURE: a tag is what a workflow pins a generation with when it needs
// to outlive the grace window, so a tag that could be repointed would
// silently unpin whatever a reader — or the retention sweep, which counts
// tags as roots — was relying on. Callers surface it as advice ("pick
// another name"), never as something to retry through.
var ErrTagExists = errors.New("tag already exists")

// ValidateName checks a ref or tag name against the rules both key spaces
// share. It is exported so a command can refuse a bad name before it
// spends a round trip on the head it was about to freeze.
//
// The rules are about what the KEY SPACE can represent, not taste:
//
//   - A separator would nest the object one level down, where the flat
//     listing that enumerates branches and tags never sees it.
//   - "." and ".." address the directory itself, or its parent.
//   - A ".tmp" suffix is skipped by every listing that enumerates refs and
//     tags (they are how a partial write announces itself), so such a tag
//     would exist, verify, and mount — and be invisible to the retention
//     sweep, which would then collect the packs it alone was pinning. That
//     is the one rule here whose absence is silent data loss rather than a
//     confusing error.
//   - A control character in a name reaches a log line, a terminal, and an
//     HTTP request line.
func ValidateName(name string) error {
	switch {
	case name == "":
		return errors.New("empty name")
	case strings.ContainsAny(name, "/\\"):
		return fmt.Errorf("invalid name %q: a ref or tag name cannot contain a path separator", name)
	case name == "." || name == "..":
		return fmt.Errorf("invalid name %q: that names a directory, not a ref", name)
	case strings.HasSuffix(name, ".tmp"):
		return fmt.Errorf("invalid name %q: a .tmp suffix marks a partial write, so listings skip it — "+
			"a tag named this way would be invisible to the retention sweep and would pin nothing", name)
	case len(name) > 255:
		return fmt.Errorf("invalid name (%d bytes): a ref or tag name must fit in 255", len(name))
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid name %q: it contains a control character", name)
		}
	}
	return nil
}

// Tag freezes raw under tags/<name>. Tags are immutable: an existing tag
// is never overwritten (ErrTagExists).
func (s *Store) Tag(ctx context.Context, name string, raw []byte) error {
	if err := ValidateName(name); err != nil {
		return fmt.Errorf("tag: %w", err)
	}
	key := TagDirKey + "/" + name
	if _, err := s.inner.StatKey(ctx, key); err == nil {
		return fmt.Errorf("%w: %s", ErrTagExists, name)
	}
	if err := s.inner.Put(ctx, key, strings.NewReader(string(raw))); err != nil {
		return fmt.Errorf("create tag %s: %w", name, err)
	}
	return nil
}

// ErrNoSuchTag reports a tag operation naming something that is not there.
//
// It is a sentinel because deletion has to tell two situations apart that
// a bare "delete failed" would blur: a name that was never a tag (a typo,
// or a script's assumption about what this volume pins) and a name whose
// object could not be removed. The store's Delete treats a missing key as
// success — correct for an idempotent sweep, wrong for a verb a user typed
// — so absence is checked before the removal rather than inferred from it.
var ErrNoSuchTag = errors.New("no such tag")

// DeleteTag removes tags/<name>.
//
// THIS IS THE VERB THAT MAKES A TAG'S PIN REVERSIBLE, and it is the only
// one: a tag is immutable, so until it existed every retention limit ended
// in "TAG the generation" with nothing on the other side — a pin, once
// taken, held its generation's packs against every sweep for the life of
// the volume.
//
// It is deliberately unguarded. There is no in-use check because there is
// nothing a tag can be in use BY: it names a frozen generation, no object
// refers to a tag, and a reader mounting one is holding the superblock it
// already fetched, which no deletion here can reach. And it takes no
// signature and needs none — see docs/design-packfs.md, "Threat model":
// removing an object is available to anyone with write access to the
// volume's key space, who could equally overwrite the ref it hangs off.
// Requiring a signature would only mean that the one tag most worth
// removing — the one a compromised or rotated key left behind, which no
// longer verifies — could never be removed at all.
//
// WHAT DELETION IS NOT is a reclaim. Removing the object takes the
// generation out of the sweep's ROOT SET; the objects it was pinning are
// released by the next retention sweep, subject to the same age guard as
// everything else. Callers must say so out loud: a user who deletes a tag,
// looks at the volume's size and sees no change has either been told the
// truth in advance or has been left to guess at a bug.
func (s *Store) DeleteTag(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return fmt.Errorf("delete tag: %w", err)
	}
	key := TagDirKey + "/" + name
	if _, err := s.inner.StatKey(ctx, key); err != nil {
		return fmt.Errorf("%w: %s", ErrNoSuchTag, name)
	}
	if err := s.inner.Delete(ctx, key); err != nil {
		return fmt.Errorf("delete tag %s: %w", name, err)
	}
	return nil
}

// Verify decodes and verifies a superblock the caller got from somewhere
// that is neither a ref nor a tag — in practice a disaster-recovery backup
// scavenged out of a pack, which is the only record a RETIRED generation
// leaves behind (internal/retention's last-K window).
//
// It never pins and never rotates. TOFU exists so a reader can start
// trusting a volume from its branch head, a mutable object the writer
// chose to publish; a document dug out of a pack was chosen by whoever
// could append a pack, so letting one establish trust would hand the pin
// to anyone who can write. A caller with no key yet gets an error, not a
// new pin.
func (s *Store) Verify(raw []byte) (*superblock.Superblock, error) {
	sb, err := superblock.Decode(raw)
	if err != nil {
		return nil, err
	}
	key := s.trusted
	if key == nil {
		pinned, err := s.readPin()
		if err != nil {
			return nil, err
		}
		if pinned == nil {
			return nil, fmt.Errorf("%w (no volume key pinned; fetch a branch first or supply --volume-pubkey)", ErrUntrusted)
		}
		key = pinned
	}
	if err := sb.Verify(key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	return sb, nil
}

// FetchTag reads and verifies tags/<name> under the same trust policy as
// branches, except that a tag never advances a pin (it is a frozen
// generation of some branch whose key the reader already trusts).
func (s *Store) FetchTag(ctx context.Context, name string) (*superblock.Superblock, []byte, error) {
	raw, _, err := s.read(ctx, TagDirKey+"/"+name)
	if err != nil {
		return nil, nil, err
	}
	sb, err := superblock.Decode(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("tag %s: %w", name, err)
	}
	key := s.trusted
	if key == nil {
		pinned, err := s.readPin()
		if err != nil {
			return nil, nil, err
		}
		if pinned == nil {
			return nil, nil, fmt.Errorf("tag %s: %w (no volume key pinned; fetch a branch first or supply --volume-pubkey)", name, ErrUntrusted)
		}
		key = pinned
	}
	if err := sb.Verify(key); err != nil {
		return nil, nil, fmt.Errorf("tag %s: %w: %w", name, ErrUntrusted, err)
	}
	return sb, raw, nil
}

func (s *Store) read(ctx context.Context, key string) ([]byte, string, error) {
	var etag string
	if ki, err := s.inner.StatKey(ctx, key); err == nil {
		etag = ki.ETag
	}
	// ReadMutable, not a plain Get: refs are overwritten in place, and an
	// origin that answers one with a mismatched digest would otherwise
	// make the volume unreadable. What makes accepting such a body safe
	// is the signature check and the rollback check the caller applies to
	// it, neither of which a transport md5 improves on.
	raw, err := pelicanobj.ReadMutable(ctx, s.inner, key)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", key, err)
	}
	return raw, etag, nil
}

// checkMonotonic refuses a branch head older than the newest generation
// this client has already accepted on that branch.
//
// The comparison is against local state, so it catches a stale read even
// when the stale bytes are perfectly signed -- they were genuine once.
// It cannot catch a client's FIRST read of a branch, which has nothing to
// compare against; that is the unavoidable limit of a purely local check.
//
// A missing or unreadable record is not an error: a fresh client, or one
// whose state was cleared, simply has nothing to check.
func (s *Store) checkMonotonic(branch string, sb *superblock.Superblock) error {
	prevRaw, err := os.ReadFile(s.lastPath(branch))
	if err != nil {
		return nil
	}
	prev, err := superblock.Decode(prevRaw)
	if err != nil {
		return nil
	}
	if sb.Generation < prev.Generation {
		return fmt.Errorf("ref %s: %w: served generation %d, but this client already accepted %d "+
			"(the origin answered with a superseded copy; retrying may clear it)",
			branch, ErrRollback, sb.Generation, prev.Generation)
	}
	return nil
}

func (s *Store) readPin() (ed25519.PublicKey, error) {
	k, err := readKeyFile(s.pinPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	return k, err
}

func readKeyFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("corrupt key pin %s", path)
	}
	return k, nil
}

// persist atomically records the volume pin and the branch's last
// accepted superblock.
func (s *Store) persist(branch string, pub []byte, raw []byte) error {
	if err := writeAtomic(s.pinPath(), []byte(hex.EncodeToString(pub)+"\n")); err != nil {
		return err
	}
	return writeAtomic(s.lastPath(branch), raw)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
