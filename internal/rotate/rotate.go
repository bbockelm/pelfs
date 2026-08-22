// Package rotate turns the format's custody-chain verification into an
// operation a user can run.
//
// The format has always carried `superblock.NextPub` — a signed
// announcement that the NEXT generation may be signed by a different key —
// and `superblock.VerifyChain` has always followed it, advancing a reader's
// pin through one verified lineage step. Nothing wrote it. So the volume
// could describe a key rotation and no tool could start one, which made
// `loadOrCreateSigningKey`'s advice ("import the key that signed this
// volume") the only advice there was.
//
// ================= WHAT A ROTATION IS, IN GENERATIONS =================
//
// Two, per branch, and it cannot be fewer. VerifyChain admits a successor
// key only when the PREDECESSOR announced it, so the announcement and the
// use of the announced key are necessarily different documents:
//
//	generation N      the head as it stands, signed by K_old
//	generation N+1    ANNOUNCE: NextPub = pub(K_new), still signed by K_old
//	generation N+2    EXECUTE:  no NextPub, signed by K_new
//
// A reader holding N+1 verifies N+2 through VerifyChain and moves its pin
// to K_new. A reader that has never seen this volume TOFUs onto K_new at
// N+2 and never learns there was a rotation, which is correct — the pin is
// about the key, not about its history.
//
// BOTH GENERATIONS ARE CONTENT-NEUTRAL. Neither writes a pack, a catalog,
// a shard, a manifest or an index: the successor superblock is the head's
// own struct with the lineage fields advanced and the signature replaced.
// That is not a shortcut, it is the only shape that is obviously correct —
// a rotation must not be able to change what a volume CONTAINS, and copying
// the document wholesale means every field this package has never heard of
// (a Fork record, a maintenance stamp, a condemned ledger, whatever lands
// next) is carried forward by construction rather than by a list someone
// has to remember to extend.
//
// WHAT CONTENT-NEUTRALITY COSTS, stated because it shows up in a report. A
// generation that cuts no pack writes no disaster-recovery backup, so the
// retain window (internal/retention/lastk.go) finds no backup for the two
// generations a rotation adds and lists the two below them as unresolved.
// Nothing is at risk: those generations named exactly what the new head
// names, since the pack set was copied verbatim, so a sweep that drops them
// from its root set drops nothing the head is not already protecting. It is
// a cosmetic gap in a report and it is the honest reason to say so here
// rather than to buy two packs to close it.
//
// ================= WHY IT IS ONE OPERATION, NOT TWO ==================
//
// The announcement is only good for ONE STEP: nothing carries NextPub
// forward, so if some other writer seals generation N+2 with K_old and no
// announcement, the promise evaporates and the rotation has to start over.
// Leaving "and now the next seal will use the new key" to whoever seals
// next is therefore a race with every mount on the volume, and losing it is
// silent. So `pelfs rotate` publishes BOTH generations itself, under the
// branch's write lease, and the window in which the announcement must
// survive is the inside of one command.
//
// ================= THE PIN IS VOLUME-WIDE ============================
//
// This is the consequence that makes rotation a decision rather than a
// chore, and it is not fixed here because it cannot be: a reader pins ONE
// key per volume (refs.Store.pinPath — a per-branch pin would hand an
// attacker a fresh trust-on-first-use for every branch name they invent).
// So the instant any reader's pin advances through one branch's lineage:
//
//   - every OTHER branch still signed by K_old fails for that reader, until
//     it too has a generation signed by K_new. Which is why this package
//     rotates EVERY branch of the volume by default, with one successor
//     key, and why narrowing it to a subset is the thing the CLI makes you
//     confirm.
//   - every TAG fails, permanently. A tag is immutable and frozen; there is
//     no republishing it and no chain to follow (FetchTag verifies against
//     the pinned key and does not rotate). A reader who wants an old tag
//     after a rotation must be handed K_old explicitly, with
//     --volume-pubkey. Nothing in this package can improve on that, so it
//     says so instead.
package rotate

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Options configures one rotation run.
type Options struct {
	// Refs is the trust-enforcing ref store: every head this run builds on
	// is fetched through it, so a rotation is never rooted in whatever the
	// origin happened to serve.
	Refs *refs.Store
	// Branches are the refs to rotate, in order. Each gets an announce and
	// an execute generation.
	Branches []string
	// KeyPath is the LIVE signing key; the pending and retired files are
	// derived from it (see Keys).
	KeyPath string
	// Now stamps CreatedUnixNano on the generations this run publishes.
	// Injected rather than read from a clock so a superblock stays a pure
	// function of its inputs, exactly as publish does it.
	Now int64
	// DryRun plans and reports without publishing or touching a key file.
	DryRun bool
	// AnnounceOnly stops after the announcing generation, leaving the
	// pending key on disk and the rotation resumable.
	//
	// THIS IS THE ANSWER TO A REAL LIMIT OF THE READER, and it is the
	// reason the flag exists at all. VerifyChain advances a pin by exactly
	// ONE lineage step: it requires cur.Generation == prev.Generation+1,
	// where prev is the last superblock the client accepted on that branch.
	// A rotation is two generations, so a client whose record is generation
	// N and which next looks after both have landed sees head N+2, cannot
	// chain from N, and refuses — correctly, by its own rules. The pin only
	// advances for a client that OBSERVED the announcement.
	//
	// So a rotation on a volume with polling readers is run in two steps
	// with a wait between them: announce, wait longer than the readers'
	// poll interval so their records advance to the announcing generation,
	// then finish. Both halves are the same command and the second one
	// resumes from what the first left (PhaseAnnounced), which is the same
	// machinery a crash recovery uses.
	//
	// Clients that miss the window are not broken beyond repair: an
	// explicit --volume-pubkey with the new key verifies directly and skips
	// the chain entirely, and a client with no record at all pins the new
	// key on first use. What they cannot do is discover the new key by
	// themselves, which is exactly what the wait buys.
	AnnounceOnly bool
}

// Phase is how far one branch has got. It is a report of what was FOUND,
// so a resumed run can say which steps it skipped rather than silently
// doing less than the command name implies.
type Phase string

const (
	// PhaseFresh: the head is signed by the live key and announces nothing.
	PhaseFresh Phase = "fresh"
	// PhaseAnnounced: the head announces the pending key and is still
	// signed by the live one. An earlier run got this far.
	PhaseAnnounced Phase = "announced"
	// PhaseExecuted: the head is signed by the pending key. Only the local
	// promotion is left.
	PhaseExecuted Phase = "executed"
)

// BranchPlan is what this run will do, or did, to one branch.
type BranchPlan struct {
	Branch string
	// Found is the phase the branch was in when this run looked.
	Found Phase
	// Head is the generation the branch was on.
	Head uint64
	// Announce and Execute are the generation numbers this run publishes,
	// zero for a step an earlier run already completed.
	Announce, Execute uint64
}

// Result is a completed rotation.
type Result struct {
	Plans []BranchPlan
	// OldPub and NewPub are the keys rotated from and to, hex.
	OldPub, NewPub string
	// Promoted reports that the local live key was replaced this run.
	Promoted bool
	// RetiredPath is where the old key was archived, empty on a dry run.
	RetiredPath string
	// Tags are the volume's tags, which this rotation makes unverifiable
	// under the new pin. Reported, never touched.
	Tags []string
}

// ErrKeyMismatch reports a state directory whose keys do not correspond to
// the branch head at all — not a half-finished rotation, a wrong or
// missing key. It is a sentinel because the advice differs completely from
// the advice for an interrupted run, and only the caller writes advice.
var ErrKeyMismatch = errors.New("local signing key does not match the branch head")

// ErrForeignAnnouncement reports a head announcing a successor this
// machine does not hold. Rotation cannot continue (nothing here can sign
// the executing generation) and cannot be aborted silently (the
// announcement is signed and published), so it is its own error with its
// own advice.
var ErrForeignAnnouncement = errors.New("the head announces a successor key this state directory does not hold")

// Execute performs the rotation: for every branch, publish whatever of the
// announce/execute pair is still outstanding, then promote the local key
// once — after ALL of them, never between two, because promoting early
// would leave the remaining branches to be signed by a key their own heads
// have not announced.
func Execute(ctx context.Context, o Options) (*Result, error) {
	if len(o.Branches) == 0 {
		return nil, errors.New("rotate: no branches to rotate")
	}
	keys := Keys{Path: o.KeyPath}
	live, err := keys.Live()
	if err != nil {
		return nil, err
	}
	// Minted before the first branch is touched, and adopted rather than
	// re-minted if an earlier run already made one, so every branch in this
	// run rotates to the SAME key. A per-branch key would leave a
	// multi-branch volume with several successors and one pin, which is the
	// broken state this whole package is trying to avoid.
	var pending ed25519.PrivateKey
	if o.DryRun {
		// A dry run must not create key material: the report is readable by
		// anyone who can read the volume, and a plan that left a private
		// key behind would make "report only" a lie. An existing pending
		// key is still adopted, so a dry run after an interrupted rotation
		// describes the real remaining work.
		if pending, err = keys.Pending(); err != nil {
			return nil, err
		}
	} else if pending, err = keys.MintPending(); err != nil {
		return nil, err
	}

	res := &Result{OldPub: PublicOf(live)}
	if pending != nil {
		res.NewPub = PublicOf(pending)
	}
	for _, branch := range o.Branches {
		plan, err := rotateBranch(ctx, o, keys, live, pending, branch)
		if err != nil {
			return nil, err
		}
		res.Plans = append(res.Plans, *plan)
	}
	if o.DryRun || o.AnnounceOnly {
		// NOT promoted, and that is the whole point of announce-only: the
		// live key is still the key every head is signed by, so a seal from
		// any other mount on the volume keeps working while the operator
		// waits for readers to catch up.
		return res, nil
	}
	// Every branch now has a head signed by the pending key, so the pending
	// key is the volume's key and the live file must say so. This is the
	// only step that destroys nothing and can be repeated: Promote archives
	// before it replaces, and Reconcile runs it again on the next seal if a
	// crash lands here.
	if err := keys.Promote(); err != nil {
		return nil, err
	}
	res.Promoted = true
	res.RetiredPath = keys.retiredPath(live.Public().(ed25519.PublicKey))
	return res, nil
}

// rotateBranch drives one branch through the phases it has left.
func rotateBranch(ctx context.Context, o Options, keys Keys, live, pending ed25519.PrivateKey,
	branch string) (*BranchPlan, error) {

	f, err := o.Refs.Fetch(ctx, branch)
	if err != nil {
		return nil, fmt.Errorf("rotate %s: %w", branch, err)
	}
	phase, err := phaseOf(f.Superblock, live, pending, branch)
	if err != nil {
		return nil, err
	}
	plan := &BranchPlan{Branch: branch, Found: phase, Head: f.Superblock.Generation}

	if phase == PhaseFresh {
		if pending == nil {
			// Dry run with nothing minted: report the shape without
			// inventing generation numbers that depend on a key that does
			// not exist yet.
			plan.Announce = f.Superblock.Generation + 1
			plan.Execute = f.Superblock.Generation + 2
			return plan, nil
		}
		var next [32]byte
		copy(next[:], pending.Public().(ed25519.PublicKey))
		sb, err := publishStep(ctx, o, f, branch, live, &next)
		if err != nil {
			return nil, fmt.Errorf("rotate %s: announcing the successor key: %w", branch, err)
		}
		plan.Announce = sb.Generation
		// Re-fetch rather than reuse: the executing generation's PrevHash is
		// over the WIRE BYTES of the announcement, and the flip's ETag is
		// what the next flip is guarded by. Going back through Fetch also
		// runs the trust path over what we just published, which is how the
		// writer learns its own generation verifies.
		if f, err = o.Refs.Fetch(ctx, branch); err != nil {
			return nil, fmt.Errorf("rotate %s: re-reading the announcement: %w", branch, err)
		}
		phase = PhaseAnnounced
		if o.AnnounceOnly {
			// Stop here with the pending key on disk. The head is signed by
			// the still-live key, so every writer carries on as before and
			// nothing is in a state that needs finishing urgently — the
			// announcement is simply a promise no generation has kept yet.
			return plan, nil
		}
	}

	if phase == PhaseAnnounced {
		if pending == nil {
			plan.Execute = f.Superblock.Generation + 1
			return plan, nil
		}
		if o.DryRun {
			plan.Execute = f.Superblock.Generation + 1
			return plan, nil
		}
		sb, err := publishStep(ctx, o, f, branch, pending, nil)
		if err != nil {
			return nil, fmt.Errorf("rotate %s: publishing under the successor key: %w", branch, err)
		}
		plan.Execute = sb.Generation
	}
	return plan, nil
}

// phaseOf works out how far a branch has already got, from the head and
// the two local keys.
//
// The order of the tests is the order of the operation, so a state that
// could be read two ways is read as the LATER one — which is the safe
// direction: treating an executed rotation as announced would publish a
// third generation for nothing, while treating an announced one as fresh
// would publish a second announcement of the same key and leave the
// lineage carrying a promise no generation kept.
func phaseOf(head *superblock.Superblock, live, pending ed25519.PrivateKey, branch string) (Phase, error) {
	if pending != nil && matches(pending, head.SigningPub) {
		return PhaseExecuted, nil
	}
	if !matches(live, head.SigningPub) {
		return "", fmt.Errorf("rotate %s: %w: the head of generation %d is signed by %x and this state "+
			"directory holds %s", branch, ErrKeyMismatch, head.Generation, head.SigningPub[:8], PublicOf(live)[:16])
	}
	if head.NextPub == nil {
		return PhaseFresh, nil
	}
	if pending == nil || !matches(pending, *head.NextPub) {
		return "", fmt.Errorf("rotate %s: %w: generation %d announces %x. Publishing the executing "+
			"generation needs that private key; `pelfs rotate --abort` retracts the announcement with the "+
			"key that made it", branch, ErrForeignAnnouncement, head.Generation, head.NextPub[:8])
	}
	return PhaseAnnounced, nil
}

// publishStep builds and flips one content-neutral successor generation.
//
// signer is the key that signs it and nextPub the announcement it carries,
// which between them are the only difference between the two steps of a
// rotation — so there is one function and the caller says which step it is
// asking for.
func publishStep(ctx context.Context, o Options, f *refs.Fetched, branch string,
	signer ed25519.PrivateKey, nextPub *[32]byte) (*superblock.Superblock, error) {

	sb, raw, err := Successor(f.Superblock, f.Raw, branch, o.Now, signer, nextPub)
	if err != nil {
		return nil, err
	}
	if err := o.Refs.Flip(ctx, branch, raw, f.ETag); err != nil {
		return nil, err
	}
	return sb, nil
}

// Successor builds the content-neutral next generation of prev: the same
// struct, with lineage advanced, an optional successor announcement, and a
// fresh signature.
//
// EXPORTED because it is the whole trust-relevant core of a rotation and a
// test has to be able to build a malformed one — a generation that skips a
// number, that announces a key it then signs with, that carries a stale
// PrevHash — without going through a CLI. Nothing else in the tree should
// call it; a generation with CONTENT goes through internal/publish.
//
// COPY, DON'T CONSTRUCT. `sb := *prev` takes every field, including the
// ones this package has never heard of. The alternative — naming the fields
// to carry — is a list that silently loses whatever was added since it was
// written, and the fields most likely to be added are exactly the ones a
// rotation must not drop: lineage records, ledgers, key tables. The shared
// slices are never written through here, and the document is encoded and
// then discarded, so aliasing prev's backing arrays is safe.
func Successor(prev *superblock.Superblock, prevRaw []byte, branch string, now int64,
	signer ed25519.PrivateKey, nextPub *[32]byte) (*superblock.Superblock, []byte, error) {

	sb := *prev
	sb.Generation = prev.Generation + 1
	sb.PrevHash = superblock.Hash(prevRaw)
	sb.CreatedUnixNano = now
	// The ref this generation is being sealed onto, which is what the field
	// means (superblock.Branch) — and not necessarily what the head says: a
	// branch created by copying main's head holds a document that truthfully
	// says "main", and a rotation on that branch is the first thing to seal
	// onto the new name.
	sb.Branch = branch
	sb.NextPub = nextPub
	sb.Signature = [64]byte{}
	if err := sb.Sign(signer); err != nil {
		return nil, nil, err
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, err
	}
	// Both writer checks, on a document that is about to become a branch
	// head. Validate cannot fail on a copy of a valid head — the pack-set
	// fields are untouched — and it is called anyway, because "cannot fail"
	// is an argument about today's fields and this function deliberately
	// copies tomorrow's too. CheckSize can fail for real: NextPub adds 34
	// bytes, and a head already at the budget edge would tip over it, which
	// must be a refusal here rather than a volume that flips and can never
	// be read again.
	if err := sb.Validate(); err != nil {
		return nil, nil, err
	}
	if err := sb.CheckSize(len(raw)); err != nil {
		return nil, nil, err
	}
	return &sb, raw, nil
}

// Abort retracts a rotation, and what that means depends entirely on how
// far it got.
//
// NOTHING PUBLISHED YET — the pending key is deleted and no generation is
// written. The volume never knew.
//
// ANNOUNCED, NOT EXECUTED — the announcement is signed and published, so it
// cannot be unpublished; it is SUPERSEDED. Abort publishes one more
// content-neutral generation, signed by the still-live key and announcing
// nothing, which is a perfectly ordinary successor (VerifyChain checks the
// trusted key first and only consults an announcement when that fails). The
// promise is then behind the head and no reader will ever act on it, and the
// pending key is deleted.
//
// ALREADY EXECUTED — there is nothing to abort. The head is signed by the
// new key; readers have moved or will move. Abort refuses and says to
// finish, because the only "undo" would be a second rotation back to the
// old key, which is a rotation and should be typed as one.
func Abort(ctx context.Context, o Options) (*Result, error) {
	keys := Keys{Path: o.KeyPath}
	live, err := keys.Live()
	if err != nil {
		return nil, err
	}
	pending, err := keys.Pending()
	if err != nil {
		return nil, err
	}
	res := &Result{OldPub: PublicOf(live)}
	if pending != nil {
		res.NewPub = PublicOf(pending)
	}
	for _, branch := range o.Branches {
		f, err := o.Refs.Fetch(ctx, branch)
		if err != nil {
			return nil, fmt.Errorf("rotate --abort %s: %w", branch, err)
		}
		phase, err := phaseOf(f.Superblock, live, pending, branch)
		if err != nil {
			return nil, err
		}
		plan := BranchPlan{Branch: branch, Found: phase, Head: f.Superblock.Generation}
		switch phase {
		case PhaseExecuted:
			return nil, fmt.Errorf("rotate --abort %s: generation %d is already signed by the successor key, "+
				"so this rotation has completed on this branch and there is nothing to retract. Re-run "+
				"`pelfs rotate` to finish the remaining branches and retire the old key locally; rotating "+
				"BACK is a new rotation, not an abort", branch, f.Superblock.Generation)
		case PhaseAnnounced:
			if o.DryRun {
				plan.Announce = f.Superblock.Generation + 1
				break
			}
			sb, err := publishStep(ctx, o, f, branch, live, nil)
			if err != nil {
				return nil, fmt.Errorf("rotate --abort %s: retracting the announcement: %w", branch, err)
			}
			plan.Announce = sb.Generation
		}
		res.Plans = append(res.Plans, plan)
	}
	if o.DryRun {
		return res, nil
	}
	return res, keys.DiscardPending()
}
