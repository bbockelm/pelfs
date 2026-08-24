package rotate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ============ ROTATING BETWEEN SIGNED AND UNSIGNED ====================
//
// A volume is either signed or it is not, and that is a property of the
// VOLUME rather than of any one generation: every ordinary writer inherits
// it (superblock.SignAs), so a seal, a checkpoint, a repack, a merge and a
// rescue cannot move a volume between the two modes even by accident. This
// file is the one thing that can, and it is reached only by typing
// `pelfs rotate --to-unsigned` or `--to-signed`.
//
// ================= ONE GENERATION, NOT TWO ============================
//
// A KEY rotation needs two (announce, then execute) because the reader's
// pin has to be carried across a gap, and only a signed announcement can
// carry it. A MODE change carries nothing: there is no chain step for a
// reader to follow in either direction, by design. So it is one
// content-neutral successor per branch, and the second generation a key
// rotation needs would be two documents saying the same thing.
//
// ================= THE CHAIN DOES NOT CARRY IT ========================
//
// This is the decision the rest of the design hangs off, so it is written
// where the code that could have done otherwise lives. `NextPub` could
// have been given a sentinel meaning "the next generation is unsigned",
// and `VerifyChain` could then have walked a reader's pin from a key to
// nothing, automatically, on the strength of one signed announcement. It
// is not done, and the reason is not cryptographic — the announcement
// would be perfectly authentic. It is that a WRITER WOULD BE DECIDING
// WHAT A READER'S MOUNT ACCEPTS. The volume's owner may stop signing
// whenever they like; they may not thereby turn off integrity checking on
// somebody else's machine, silently, at the next poll. A server does not
// get to announce "from now on, plaintext".
//
// So every OTHER reader refuses after a downgrade (refs.ErrSignatureDropped)
// and a human clears the pin. The one machine that does not have to is the
// one that ran the command — it knows the downgrade was deliberate because
// it performed it — and re-pinning itself is the last local step here,
// exactly as promoting the successor key is the last local step of a key
// rotation.
//
// ================= WHAT THE OLD KEY IS STILL FOR ======================
//
// A downgrade ARCHIVES the live key rather than deleting it, for a reason
// sharper than a key rotation's. After a key rotation the archived key is a
// safety net; after a downgrade it is the volume's only surviving identity,
// and the only way to read a tag frozen before it (`--volume-pubkey`, which
// is the same escape a key rotation leaves for tags). Deleting it would make
// every pre-downgrade tag permanently unverifiable.

// ModeResult is a completed mode change.
type ModeResult struct {
	// Branches are the refs that moved, with the generation each landed on.
	Branches []BranchPlan
	// AlreadyThere names the branches that were in the target mode
	// already: a resumed or repeated run, which must be reported rather
	// than counted as work.
	AlreadyThere []string
	// NewPub is the key a --to-signed run signed with, hex; empty for a
	// downgrade.
	NewPub string
	// RetiredPath is where a downgrade archived the old signing key.
	RetiredPath string
	// Tags are the volume's tags, which a mode change in either direction
	// makes unverifiable under the new pin. Reported, never touched.
	Tags []string
}

// ErrAlreadyInMode reports a volume that is already the way the run asked
// for. It is a sentinel because a caller that is scripting this wants to
// tell "nothing to do" from "could not do it".
var ErrAlreadyInMode = errors.New("the volume is already in that mode")

// ToUnsigned publishes one unsigned, content-neutral successor per branch,
// then archives the local signing key and re-pins this client.
//
// IT DOES NOT REQUIRE THE SIGNING KEY, and that is deliberate rather than
// an oversight. Publishing an unsigned superblock takes no key by
// definition, and anyone who can write this prefix could write one without
// this command; demanding a key would only make the downgrade impossible in
// the case where it is most wanted — a volume whose key has been lost — and
// would buy nothing against an attacker. What it DOES check is that a key
// present on this machine is the one the head is signed with, so that a
// wrong state directory cannot downgrade a volume its owner is still
// signing.
func ToUnsigned(ctx context.Context, o Options) (*ModeResult, error) {
	if len(o.Branches) == 0 {
		return nil, errors.New("rotate --to-unsigned: no branches to rotate")
	}
	keys := Keys{Path: o.KeyPath}
	live, err := keys.Live()
	if err != nil && !errors.Is(err, ErrNoKey) {
		return nil, err
	}
	res := &ModeResult{}
	var flipped bool
	for _, branch := range o.Branches {
		f, ferr := o.Refs.Fetch(ctx, branch)
		if ferr != nil {
			return nil, fmt.Errorf("rotate --to-unsigned %s: %w", branch, ferr)
		}
		if f.Superblock.IsUnsigned() {
			res.AlreadyThere = append(res.AlreadyThere, branch)
			continue
		}
		if live != nil && !matches(live, f.Superblock.SigningPub) {
			return nil, fmt.Errorf("rotate --to-unsigned %s: %w: the head of generation %d is signed by %x "+
				"and this state directory holds %s. Downgrading from here would be a downgrade of somebody "+
				"else's volume", branch, ErrKeyMismatch, f.Superblock.Generation,
				f.Superblock.SigningPub[:8], PublicOf(live)[:16])
		}
		plan := BranchPlan{Branch: branch, Found: PhaseFresh, Head: f.Superblock.Generation}
		if o.DryRun {
			plan.Execute = f.Superblock.Generation + 1
			res.Branches = append(res.Branches, plan)
			continue
		}
		sb, perr := publishStep(ctx, o, f, branch, nil, nil)
		if perr != nil {
			return nil, fmt.Errorf("rotate --to-unsigned %s: %w", branch, perr)
		}
		plan.Execute = sb.Generation
		res.Branches = append(res.Branches, plan)
		flipped = true
	}
	if o.DryRun || !flipped {
		if !o.DryRun && len(res.Branches) == 0 {
			return res, fmt.Errorf("rotate --to-unsigned: %w (every branch is already unsigned)", ErrAlreadyInMode)
		}
		return res, nil
	}
	// AFTER the flips, never before. A crash here leaves this client
	// pinned to a key on a volume that no longer has one, which is
	// refs.ErrSignatureDropped and says exactly what to delete; re-pinning
	// first would leave the opposite state, which reads as a takeover.
	if err := o.Refs.AcceptUnsigned(); err != nil {
		return nil, fmt.Errorf("rotate --to-unsigned: the volume is downgraded but this client's pin was "+
			"not updated (%w); delete the pin file and re-read with --allow-unsigned", err)
	}
	if live != nil {
		if err := keys.Retire(); err != nil {
			return nil, fmt.Errorf("rotate --to-unsigned: archive the retired signing key: %w", err)
		}
		res.RetiredPath = keys.retiredPath(live.Public().(ed25519.PublicKey))
	}
	return res, nil
}

// ToSigned gives an unsigned volume a signing key: one content-neutral
// successor per branch, signed, and this client re-pinned to the new key.
//
// WHAT IT DOES NOT DO IS MAKE THE PAST TRUSTWORTHY. The signature attests
// to the volume AS IT STANDS — the pack set, the root catalog, every
// identity below it — which is a real and useful root going forward. It
// says nothing about how the volume got there: while it was unsigned,
// anyone who could write the prefix could change it, and this signs
// whatever they left. The caller says so out loud, because the one way to
// misread this command is as a repair.
func ToSigned(ctx context.Context, o Options) (*ModeResult, error) {
	if len(o.Branches) == 0 {
		return nil, errors.New("rotate --to-signed: no branches to rotate")
	}
	keys := Keys{Path: o.KeyPath}
	var signer ed25519.PrivateKey
	live, err := keys.Live()
	switch {
	case err == nil:
		// A key already beside an unsigned volume is the ordinary case
		// after a --to-unsigned that archived nothing, or a state
		// directory shared with another volume. Adopt it rather than
		// minting a second identity.
		signer = live
	case errors.Is(err, ErrNoKey):
	default:
		return nil, err
	}
	res := &ModeResult{}
	var flipped bool
	for _, branch := range o.Branches {
		f, ferr := o.Refs.Fetch(ctx, branch)
		if ferr != nil {
			return nil, fmt.Errorf("rotate --to-signed %s: %w", branch, ferr)
		}
		if !f.Superblock.IsUnsigned() {
			res.AlreadyThere = append(res.AlreadyThere, branch)
			continue
		}
		plan := BranchPlan{Branch: branch, Found: PhaseFresh, Head: f.Superblock.Generation}
		if o.DryRun {
			plan.Execute = f.Superblock.Generation + 1
			res.Branches = append(res.Branches, plan)
			continue
		}
		if signer == nil {
			// Minted on the first branch that needs it and reused for every
			// branch after, for the reason Execute mints once: one volume,
			// one identity, or the volume-wide pin has several answers.
			if signer, err = keys.Mint(); err != nil {
				return nil, err
			}
		}
		sb, perr := publishStep(ctx, o, f, branch, signer, nil)
		if perr != nil {
			return nil, fmt.Errorf("rotate --to-signed %s: %w", branch, perr)
		}
		plan.Execute = sb.Generation
		res.Branches = append(res.Branches, plan)
		flipped = true
	}
	if signer != nil {
		res.NewPub = PublicOf(signer)
	}
	if o.DryRun || !flipped {
		if !o.DryRun && len(res.Branches) == 0 {
			return res, fmt.Errorf("rotate --to-signed: %w (every branch is already signed)", ErrAlreadyInMode)
		}
		return res, nil
	}
	if err := o.Refs.AcceptSigned(signer.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("rotate --to-signed: the volume is signed but this client's pin was not "+
			"updated (%w); delete the pin file and re-read", err)
	}
	return res, nil
}

// Mint writes a fresh live signing key, refusing to overwrite one.
//
// It is Keys' only creator of a LIVE key — MintPending creates the pending
// one — and it exists here rather than in cmd/pelfs because a volume that
// is gaining an identity should get it from the same file layout, with the
// same exclusive create, as every other key this package writes.
func (k Keys) Mint() (ed25519.PrivateKey, error) {
	if _, err := k.Live(); err == nil {
		return nil, fmt.Errorf("mint: a signing key already exists at %s", k.Path)
	} else if !errors.Is(err, ErrNoKey) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writeFileMode(k.Path, []byte(hex.EncodeToString(priv)+"\n"), 0600); err != nil {
		return nil, err
	}
	return priv, nil
}

// Retire archives the live key read-only and removes it as the live one.
//
// It is Promote's other half: Promote replaces the live key with a
// successor, and this one leaves no successor behind because a downgraded
// volume has no next key. The archive is written BEFORE the live file goes,
// so a crash between them leaves the key present twice rather than not at
// all — the same ordering, for the same reason.
func (k Keys) Retire() error {
	live, err := k.Live()
	if errors.Is(err, ErrNoKey) {
		return nil
	} else if err != nil {
		return err
	}
	archive := k.retiredPath(live.Public().(ed25519.PublicKey))
	if err := writeFileMode(archive, []byte(hex.EncodeToString(live)+"\n"), 0400); err != nil {
		return err
	}
	if err := os.Remove(k.Path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(filepath.Dir(k.Path))
}
