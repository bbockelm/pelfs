package merge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Carrying out the one merge that needs no tree built.
//
// When the branch being merged INTO has not moved since the fork, the
// other branch's tree is already the answer whole: there is nothing to
// three-way, nothing to conflict, and no catalog to write. git calls this
// a fast-forward and moves the ref.
//
// This does not move the ref. It PUBLISHES A GENERATION carrying the other
// side's tree, because two of the superblock's fields are load-bearing
// statements about the branch rather than about the bytes:
//
//   - Branch names the ref a generation was sealed onto, and retention
//     reads it to keep a per-branch window (internal/retention/lastk.go).
//     A head on `main` claiming it was sealed onto `dev` would make that
//     accounting wrong.
//   - Fork says where this branch came from. Adopting the other branch's
//     record would have main claiming it was forked from main.
//
// The cost is one superblock and one signature. Nothing else: the
// generation names the same root, the same catalogs and the same packs the
// other side named, so not a byte of content moves.
//
// THE INODE MARK STAYS OURS, which is worth stating because it looks like
// it should be the maximum of the two. It should not. Lineages are
// disjoint, so the two branches were never drawing from the same range:
// this branch keeps allocating from its own, the incoming tree keeps the
// numbers it has, and nothing can collide. Taking a maximum would only
// burn numbers.

// FastForward publishes the incoming branch's tree onto the branch being
// merged into, and returns the generation it published.
//
// It refuses anything that is not a fast-forward. Deciding that is
// Compute's job, and a caller that skipped it would be asking this to
// merge two diverged trees by taking one of them — which is not a merge,
// it is a discard.
func FastForward(ctx context.Context, o ApplyOptions) (*superblock.Superblock, error) {
	if o.Plan == nil || !o.Plan.FastForward {
		return nil, errors.New("merge: not a fast-forward; a diverged branch needs its tree merged, not replaced")
	}
	if o.Refs == nil || o.Branch == "" {
		return nil, errors.New("merge: Refs and Branch are required to publish")
	}
	if len(o.SigningKey) == 0 {
		return nil, errors.New("merge: a signing key is required to publish")
	}
	if o.Plan.Direction == "ours" || o.Plan.Direction == "already equal" {
		// Nothing to do, and saying so is not the same as doing it: the
		// caller gets no generation because none was published.
		return nil, nil
	}

	// Re-read the head, and refuse if it moved. The plan was computed
	// against a generation; publishing onto a different one would fast-
	// forward past work that arrived in between, which is the one way this
	// operation can lose something.
	head, err := o.Refs.Fetch(ctx, o.Branch)
	if err != nil {
		return nil, fmt.Errorf("merge: read %s: %w", o.Branch, err)
	}
	if head.Superblock.Generation != o.Ours.Generation ||
		head.Superblock.RootCatalog != o.Ours.RootCatalog {
		return nil, fmt.Errorf("merge: %w: %s moved to generation %d while this merge was planned",
			refs.ErrStaleFlip, o.Branch, head.Superblock.Generation)
	}

	sb := *o.Theirs
	// The tree is theirs; the identity is ours.
	sb.Branch = o.Branch
	sb.Generation = max(o.Ours.Generation, o.Theirs.Generation) + 1
	sb.CreatedUnixNano = time.Now().UnixNano()
	sb.PrevHash = superblock.Hash(head.Raw)
	sb.NextInode = o.Ours.NextInode
	if o.Ours.Fork != nil {
		f := *o.Ours.Fork
		sb.Fork = &f
	} else {
		sb.Fork = nil
	}
	if o.Ours.Maint != nil {
		m := *o.Ours.Maint
		sb.Maint = &m
	} else {
		sb.Maint = nil
	}
	sb.Signature = [64]byte{}
	if err := sb.Sign(o.SigningKey); err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, fmt.Errorf("merge: encode superblock: %w", err)
	}
	if err := o.Refs.Flip(ctx, o.Branch, raw, head.ETag); err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	return &sb, nil
}

// ApplyOptions is what carrying a plan out needs beyond computing it.
type ApplyOptions struct {
	// Inner, Base, DEK, CacheDir, SpoolDir, IdentityKey and KeyID are
	// needed only by Apply, which reads the three trees and publishes a
	// merged one. FastForward needs none of them: it writes a superblock.
	Inner       pelicanobj.Store
	Base        *superblock.Superblock
	DEK         []byte
	IdentityKey []byte
	KeyID       int64
	CacheDir    string
	SpoolDir    string

	// Plan is what Compute produced, and it is required: this package
	// never decides and acts in one call, because the decision is the part
	// a human has to see.
	Plan *Plan
	// Ours and Theirs are the two heads the plan was computed from.
	Ours, Theirs *superblock.Superblock

	// Refs and Branch name the head being moved, and SigningKey signs the
	// generation.
	Refs       *refs.Store
	Branch     string
	SigningKey ed25519.PrivateKey
}
