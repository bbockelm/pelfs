package rotate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// ============================ THE LOCAL KEY LIFECYCLE ======================
//
// A volume has ONE signing key at a time and rotation needs TWO, so for the
// span of a rotation the state directory holds both. Which file is which has
// to be answerable after a crash, from the filesystem alone, because the
// thing that decides it — "has the announcing generation been published
// yet?" — lives in the federation and the answer arrives too late to matter
// if the local half has already thrown a key away.
//
// THREE NAMES, derived from the live key's path so an explicit
// --signing-key keeps its siblings beside it rather than in a state
// directory the user chose not to use:
//
//	v2-signing.key                  THE LIVE KEY. What every seal signs with.
//	v2-signing.key.next             THE PENDING SUCCESSOR. Minted by rotate,
//	                                promoted to live once every branch this
//	                                run rotates has a generation signed by it.
//	v2-signing.key.retired-<pub8>   A FORMER LIVE KEY, mode 0400.
//
// WHY THE OLD KEY IS ARCHIVED AND NOT DELETED. Deleting a private key is
// the one step in this operation that cannot be retried, and it would be
// the LAST step of a multi-step operation that can be interrupted between
// any two of them — so a crash in the wrong microsecond would leave a
// volume whose head is signed by a key nothing on this machine holds. That
// is precisely the failure this whole file exists to make impossible.
//
// What the archived key is still GOOD for is narrow and worth stating
// exactly, because it is smaller than it looks: aborting a rotation that
// has announced but not executed (the retraction is signed by the old key),
// and reading the volume's own history — a tag frozen before the rotation
// verifies under it and under nothing else. What it is NOT good for is
// repairing the siblings this rotation broke: their repair is to be
// REPUBLISHED under the NEW key, because the reader's pin has moved. So the
// archive is a safety net and an audit trail, not a recovery path, and once
// the volume is healthy the file is safe to delete by hand. It is 0400 so
// that saying so does not make it easy to do by accident.
//
// WHY NOT A SINGLE FILE HOLDING BOTH. Because the interesting question is
// not "which keys exist" but "which one does the head expect", and that is
// a comparison against a document in the federation. Two files let
// Reconcile answer it with two hex reads and no parsing of a format that
// would then need its own evolution rule.

const (
	// pendingSuffix names the successor key while a rotation is in flight.
	pendingSuffix = ".next"
	// retiredPrefix, plus the first eight hex digits of its public half,
	// names a key that used to be live. The public half is in the name so
	// an operator staring at three files can match one to the generation
	// that last used it without loading any of them.
	retiredPrefix = ".retired-"
)

// Keys is the volume's local signing material, addressed by the path of
// the LIVE key. Every other path is derived, so the three files always
// travel together.
type Keys struct{ Path string }

func (k Keys) pendingPath() string { return k.Path + pendingSuffix }

func (k Keys) retiredPath(pub ed25519.PublicKey) string {
	return k.Path + retiredPrefix + hex.EncodeToString(pub[:4])
}

// ErrNoKey reports that the live signing key is not there. It is a
// sentinel because "this machine cannot write to this volume" and "this
// rotation is half-finished" need different advice, and only the caller
// knows which question it was asking.
var ErrNoKey = errors.New("no volume signing key")

// Live reads the key every seal signs with.
func (k Keys) Live() (ed25519.PrivateKey, error) { return readKey(k.Path) }

// Pending reads the successor key a rotation has minted, or (nil, nil)
// when no rotation is in flight. Absence is not an error: it is the state
// of every volume that is not mid-rotation, which is almost all of them.
func (k Keys) Pending() (ed25519.PrivateKey, error) {
	priv, err := readKey(k.pendingPath())
	if errors.Is(err, ErrNoKey) {
		return nil, nil
	}
	return priv, err
}

// MintPending generates the successor key, or returns the one an earlier
// interrupted run already generated.
//
// IDEMPOTENCE IS THE WHOLE POINT and it is not a convenience. A second run
// that minted a SECOND successor would orphan the first — and if the first
// had already been announced, the volume would be carrying a signed promise
// about a key this machine had just replaced, which is the one state from
// which no amount of re-running recovers. So the file is created
// exclusively and an existing one is adopted, never overwritten.
func (k Keys) MintPending() (ed25519.PrivateKey, error) {
	if priv, err := k.Pending(); err != nil {
		return nil, err
	} else if priv != nil {
		return priv, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// O_EXCL: two rotations racing on one state directory must not both
	// think they minted the successor. The loser adopts the winner's key on
	// its retry, which is the same path a crash takes.
	f, err := os.OpenFile(k.pendingPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return k.Pending()
		}
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(priv) + "\n"); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	// The directory entry too: the pending key's EXISTENCE is what a
	// resumed run reads to decide it must not mint another, and a name that
	// survived only in the page cache would let a crash between the mint
	// and the announcement produce a second successor.
	return priv, syncDir(filepath.Dir(k.pendingPath()))
}

// Promote makes the pending key live: the old live key is archived
// read-only FIRST, then the pending file takes its place.
//
// THE ORDER IS THE SAFETY. Archive-then-replace means a crash between the
// two steps leaves the old key present twice and the pending key still
// pending — the state Promote was called in, so calling it again finishes
// the job. Replace-then-archive would have a window in which the only copy
// of the old key had been overwritten, and the abort path needs that key.
func (k Keys) Promote() error {
	pending, err := k.Pending()
	if err != nil {
		return err
	}
	if pending == nil {
		return fmt.Errorf("promote: no pending key at %s", k.pendingPath())
	}
	live, err := k.Live()
	switch {
	case errors.Is(err, ErrNoKey):
		// No live key to archive. A rotation cannot get here — it read the
		// live key to sign the announcement — but a hand-repaired state
		// directory can, and there is nothing to protect.
	case err != nil:
		return err
	default:
		archive := k.retiredPath(live.Public().(ed25519.PublicKey))
		if err := writeFileMode(archive, []byte(hex.EncodeToString(live)+"\n"), 0400); err != nil {
			return fmt.Errorf("archive the retired signing key: %w", err)
		}
	}
	if err := os.Rename(k.pendingPath(), k.Path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(k.Path))
}

// DiscardPending removes the successor key, which is what aborting a
// rotation comes down to locally. Missing is success: abort is a verb a
// user may type twice.
func (k Keys) DiscardPending() error {
	if err := os.Remove(k.pendingPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(filepath.Dir(k.pendingPath()))
}

// Reconcile finishes the LOCAL half of a rotation whose remote half
// already landed, and it is the reason "a rotation interrupted anywhere
// leaves a volume whose next seal can still be signed" is a property
// rather than a hope.
//
// THE WINDOW IT CLOSES. Between the flip of the generation signed by the
// successor and the local promotion, the head expects a key that is
// sitting in a file called `.next` — so an ordinary seal would load the
// live key, compare it against the head, and refuse. Every writer resolves
// its key through one function (cmd/pelfs' loadOrCreateSigningKey), so this
// is called from there: the mount that finds the volume in that state
// promotes and carries on, instead of demanding that the user re-run a
// command they may not know exists.
//
// IT ONLY EVER MOVES FORWARD, and only on evidence. The promotion happens
// exactly when the pending key's public half is the one the head is signed
// with — which is a statement the volume's own signature makes, not
// something inferred from file timestamps. Any other mismatch is left
// alone for the caller to report: a live key that matches nothing and a
// pending key that matches nothing is a wrong state directory, not a
// half-finished rotation, and quietly adopting a key would be the worst
// possible answer to it.
//
// head may be nil (a brand-new volume), in which case there is nothing to
// reconcile against.
func Reconcile(path string, head *superblock.Superblock) (bool, error) {
	if head == nil {
		return false, nil
	}
	k := Keys{Path: path}
	// The ordinary case first and cheaply: the live key is the head's key,
	// so nothing is in flight. This runs on every seal of every volume.
	if live, err := k.Live(); err == nil {
		if matches(live, head.SigningPub) {
			return false, nil
		}
	} else if !errors.Is(err, ErrNoKey) {
		return false, err
	}
	pending, err := k.Pending()
	if err != nil || pending == nil {
		return false, err
	}
	if !matches(pending, head.SigningPub) {
		return false, nil
	}
	if err := k.Promote(); err != nil {
		return false, fmt.Errorf("completing an interrupted key rotation: %w", err)
	}
	return true, nil
}

// matches reports whether priv is the key that signed a superblock
// claiming pub. SigningPub is informational — never trusted for
// verification — but it is exactly the right thing to compare a local
// private key against, since the question is "would signing with this
// produce that document" and not "is that document authentic".
func matches(priv ed25519.PrivateKey, pub [32]byte) bool {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey)) == hex.EncodeToString(pub[:])
}

// PublicOf is the hex public half of a private key, for the many places a
// rotation has to name a key in a sentence.
func PublicOf(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w at %s", ErrNoKey, path)
		}
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("corrupt signing key %s", path)
	}
	return ed25519.PrivateKey(k), nil
}

// writeFileMode writes through a temp file so an interrupted archive
// leaves either the whole key or no file, never half of one. The mode is
// applied to the temp file, so the final name never exists writable.
func writeFileMode(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir flushes a directory entry. A rotation's crash-safety is about
// which FILES EXIST, so the names have to be durable and not merely the
// contents; a missing sync would let a crash lose the pending key's name
// while keeping its bytes, which reads as "no rotation in flight".
//
// Best effort by design: some filesystems refuse to open a directory for
// sync, and failing a rotation over it would trade a small durability gap
// for a total inability to rotate.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil //nolint:nilerr // see the comment above
	}
	defer d.Close() //nolint:errcheck
	d.Sync()        //nolint:errcheck
	return nil
}
