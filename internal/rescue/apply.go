package rescue

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// ================= WHY A RESCUE RE-SIGNS =============================
//
// The obvious implementation flips the backup's bytes onto refs/<branch>
// and stops. It does not work, and the reason is the union rule
// (resolvePacks): a backup states its pack set BOTH ways, and every reader
// in the tree resolves a head's pack set through manifest.Packs, which
// prefers the manifest refs and IGNORES the inline list. So a
// flipped-verbatim backup would mount with its parent's pack set — missing
// the tail packs that hold the very root catalog the document names. It
// would verify perfectly and fail to mount, which is the worst of the
// available failures.
//
// So the rescued head STATES THE UNION ONE WAY, which makes it a new
// document, which means it has to be signed. Three consequences, all of
// them stated to the operator before anything is written:
//
//  1. --apply NEEDS THE VOLUME'S SIGNING KEY. Report-only does not. That is
//     the same split repack has (repack-plan reads, repack signs), and it
//     is the right one: an operator with read access can find out what is
//     recoverable without holding the key that could rewrite history.
//  2. THE KEY THAT VERIFIES AND THE KEY THAT SIGNS MAY DIFFER. Rescuing a
//     pre-rotation backup means verifying under the retired key
//     (--volume-pubkey) and signing under the live one. That is legitimate
//     and it is also re-issuing old history under a new identity, so it is
//     warned about by the caller rather than silently allowed.
//  3. THE GENERATION NUMBER IS THE BACKUP'S OWN. A rescued head claims the
//     generation the document claims, not a fresh one on top. It is the
//     truthful answer — this IS that generation, restored — and it is the
//     one that keeps a later publish's lineage arithmetic working. The cost
//     is that a client which had already accepted a HIGHER generation on
//     this branch refuses the rescued head as a stale read
//     (refs.ErrRollback, which compares against purely local state). There
//     is no way around that from here and it is not a bug: the check exists
//     precisely so that a head going backwards is noticed, and after a
//     disaster the head HAS gone backwards. The escape is local — that
//     client's own record — and the caller says so.
//
// WHAT A RESCUE NEVER DOES IS DELETE. Not a pack, not a manifest, not the
// ref it replaces (a flip is a PUT). The state a rescue runs in is one where
// nobody yet knows what is really missing, and deleting on that evidence is
// how a recoverable volume becomes an unrecoverable one.

// ApplyOptions is what turns an offer into a head.
type ApplyOptions struct {
	Options
	// SigningKey signs the rescued head. Required.
	SigningKey ed25519.PrivateKey
	// Now stamps CreatedUnixNano. Injected rather than read from a clock,
	// as everywhere else that builds a superblock.
	Now int64
}

// Applied reports one branch's restoration.
type Applied struct {
	Branch string
	// Generation is the generation the rescued head claims.
	Generation uint64
	// Packs is how many packs it names.
	Packs int
	// Shape says how it states them: "inline" or "manifest".
	Shape string
	// ManifestObject names the segment written, when one was.
	ManifestObject string
	// Replaced reports that a ref was overwritten rather than created,
	// which is the difference between "the refs were deleted" and "the refs
	// were corrupt" and is worth a different line of output.
	Replaced bool
	// SignedBy is the hex public half of the key the head is signed with.
	SignedBy string
}

// Apply writes the rescued head for one branch plan.
//
// It refuses everything the report refused: no chosen candidate, an
// ambiguous head, or a root catalog that could not be located. The last one
// is the interesting refusal — the document verifies, so nothing about
// TRUST objects to it, and flipping it would produce a head that cannot
// serve its own root directory. An operator who wants it anyway has to say
// so (Force), because there is a real case for it: the packs may be
// restorable from somewhere else afterwards, and a ref is how you find out
// what to look for.
func Apply(ctx context.Context, o ApplyOptions, plan *BranchPlan, force bool) (*Applied, error) {
	if len(o.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("rescue --apply: a rescued head is a new signed document, so it needs the " +
			"volume's signing key")
	}
	switch {
	case len(plan.Ambiguous) > 0:
		return nil, fmt.Errorf("rescue %s: %d verifiable candidates for generation %d (%s); a rescue does not "+
			"choose between them — re-run with --pick <id>", plan.Branch, len(plan.Ambiguous),
			plan.Ambiguous[0].SB.Generation, ids(plan.Ambiguous))
	case plan.Chosen == nil:
		return nil, fmt.Errorf("rescue %s: nothing recoverable (no candidate's pack set could be resolved)", plan.Branch)
	case !plan.Root.Located && !force:
		return nil, fmt.Errorf("rescue %s: %s. Flipping this would publish a head that cannot serve its own "+
			"root directory; --force does it anyway, which is sometimes what you want (a ref names what to go "+
			"looking for)", plan.Branch, plan.Root.Note)
	}

	sb, raw, mref, err := head(ctx, o, plan)
	if err != nil {
		return nil, err
	}
	// The ETag from the read that established Current: an absent ref is
	// created with an empty expect-ETag (which refs.Flip turns into
	// create-if-absent), and a present one is replaced under the ETag it had
	// when we looked. A concurrent writer that flipped in between loses this
	// flip rather than having its own silently clobbered, which is the same
	// guard every other publisher gets.
	if err := o.Refs.Flip(ctx, plan.Branch, raw, plan.Current.ETag); err != nil {
		return nil, fmt.Errorf("rescue %s: %w", plan.Branch, err)
	}
	out := &Applied{
		Branch: plan.Branch, Generation: sb.Generation, Packs: len(plan.Packs),
		Replaced: plan.Current.Present, Shape: "inline",
		SignedBy: hex.EncodeToString(o.SigningKey.Public().(ed25519.PublicKey)),
	}
	if mref != "" {
		out.Shape, out.ManifestObject = "manifest", mref
	}
	return out, nil
}

// head builds the rescued superblock: the chosen backup, restated so that a
// reader resolves the whole union.
//
// INLINE FIRST, MANIFEST IF IT DOES NOT FIT. Inline is self-contained —
// the head names every pack in its own bytes, so a rescued volume depends
// on nothing but its packs, which is the property you want on the day the
// derived objects are the thing that went missing. It is also the shape
// every reader has understood since the first release. But an inline list
// is ~100 bytes per pack and the write budget is half of the 1 MiB cap on
// reading a mutable object, so past a few thousand packs it does not fit;
// then a segment is written and the head names it, which is the ordinary
// modern shape. The order of preference is deliberate and the fallback is
// automatic, because "your volume is too big to rescue" would be an absurd
// thing for this command to say.
func head(ctx context.Context, o ApplyOptions, plan *BranchPlan) (*superblock.Superblock, []byte, string, error) {
	// A copy, for the reason rotate.Successor copies: every field this
	// package has never heard of belongs to the generation being restored,
	// and a hand-written constructor is a list that silently drops whatever
	// was added after it was written.
	sb := *plan.Chosen.SB
	sb.CreatedUnixNano = o.Now
	sb.Branch = plan.Branch
	// A rescued head announces nothing. Carrying a predecessor's NextPub
	// would re-open a rotation window that whatever came after the disaster
	// may already have closed, and a rescue is in no position to make a
	// statement about future keys.
	sb.NextPub = nil
	sb.PackList = plan.Packs
	sb.Manifests = nil
	sb.Signature = [64]byte{}

	if raw, err := sign(&sb, o.SigningKey); err == nil {
		if err := sb.Validate(); err != nil {
			return nil, nil, "", err
		}
		if serr := sb.CheckSize(len(raw)); serr == nil {
			return &sb, raw, "", nil
		}
	} else {
		return nil, nil, "", err
	}

	// Too big inline. One segment covering the whole union — not the
	// segmented, size-tiered arrangement a seal builds, because there is no
	// history to carry forward here and a single segment is the simplest
	// object that states the same thing.
	b := manifest.NewBuilder()
	for _, p := range plan.Packs {
		if err := b.Add(manifest.Sealed([]superblock.PackEntry{p})[0]); err != nil {
			return nil, nil, "", err
		}
	}
	segRaw := b.Encode()
	m, err := manifest.Open(segRaw)
	if err != nil {
		return nil, nil, "", fmt.Errorf("rescue: the manifest segment just built will not open: %w", err)
	}
	hash := blake3.Sum256(segRaw)
	name := hex.EncodeToString(hash[:])
	if err := o.Inner.Put(ctx, manifest.Dir+"/"+name, bytes.NewReader(segRaw)); err != nil {
		return nil, nil, "", fmt.Errorf("rescue: upload manifest segment: %w", err)
	}
	sb.PackList = nil
	sb.Manifests = []superblock.ManifestRef{{
		Name: name, Hash: hash, Size: int64(len(segRaw)), Packs: uint32(m.Len()),
	}}
	sb.Signature = [64]byte{}
	raw, err := sign(&sb, o.SigningKey)
	if err != nil {
		return nil, nil, "", err
	}
	if err := sb.Validate(); err != nil {
		return nil, nil, "", err
	}
	if err := sb.CheckSize(len(raw)); err != nil {
		return nil, nil, "", err
	}
	return &sb, raw, name, nil
}

func sign(sb *superblock.Superblock, key ed25519.PrivateKey) ([]byte, error) {
	if err := sb.Sign(key); err != nil {
		return nil, err
	}
	return sb.Encode()
}

func ids(cands []*Candidate) string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.ID()
	}
	return joinComma(out)
}

func joinComma(in []string) string {
	s := ""
	for i, x := range in {
		if i > 0 {
			s += ", "
		}
		s += x
	}
	return s
}

// Pick narrows an ambiguous plan to one candidate named by an ID prefix,
// which is the only way a rescue ever resolves ambiguity: by being told.
//
// A prefix that matches more than one candidate is an error rather than a
// first-match, because the whole point of the operation is that the
// operator has decided WHICH document, and a prefix that does not identify
// one has not expressed a decision.
func Pick(plan *BranchPlan, id string) error {
	if len(plan.Ambiguous) == 0 {
		return fmt.Errorf("rescue %s: nothing to pick between", plan.Branch)
	}
	var hit *Candidate
	for _, c := range plan.Ambiguous {
		if len(id) > 0 && len(c.ID()) >= len(id) && c.ID()[:len(id)] == id {
			if hit != nil {
				return fmt.Errorf("rescue %s: --pick %s matches %s; use more characters",
					plan.Branch, id, ids(plan.Ambiguous))
			}
			hit = c
		}
	}
	if hit == nil {
		return fmt.Errorf("rescue %s: --pick %s matches none of %s", plan.Branch, id, ids(plan.Ambiguous))
	}
	plan.Chosen, plan.Ambiguous = hit, nil
	return nil
}

// Resolve finishes a picked plan: the pack set and the root check that
// planBranch would have done had the generation not been ambiguous.
func Resolve(ctx context.Context, o Options, plan *BranchPlan) error {
	if plan.Chosen == nil {
		return fmt.Errorf("rescue %s: no candidate chosen", plan.Branch)
	}
	packs, err := resolvePacks(ctx, o, plan.Chosen)
	if err != nil {
		return fmt.Errorf("rescue %s: generation %d's pack set is unresolvable: %w",
			plan.Branch, plan.Chosen.SB.Generation, err)
	}
	plan.Packs = packs
	plan.Root = locateRoot(ctx, o, plan.Chosen.SB, packs)
	return nil
}
