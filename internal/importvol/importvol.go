// Package importvol copies another pelfs volume's data into this one, so
// that the result depends on nobody.
//
// # Where it sits between graft and reference
//
// A GRAFT points at a foreign HTTP tree and stores none of its bytes; a
// REFERENCE would point at a foreign pelfs volume and store none of its
// bytes. Both trade self-containment for setup cost, and both leave the
// volume's availability multiplied by somebody else's. An IMPORT buys the
// opposite: every byte is copied under this volume's own prefix and
// re-signed under this volume's key, so afterwards nothing in the tree
// resolves anywhere else. It is the only one of the three that survives
// the source owner's `gc`, that `pelfs rescue` can rebuild from our packs
// alone, and that `pelfs fsck` can be conclusive about.
//
// # It is repack's shape, not merge's
//
// `merge` refuses cross-volume outright (merge.checkInputs) and could not
// help anyway: a merge is a three-way walk and across volumes there is no
// base. What an import does share with a merge is the HANDOVER — a
// publish.Source that never reads a byte of file content and hands the
// seal chunkrefs it already has.
//
// The copying half is repack's. repack.rewritePacks reads STORED entries
// out of packs and writes them into new packs, keeping identity, clen,
// alg and keyid untouched and needing no data-encryption key at all: "the
// bytes are copied STORED — already compressed, already encrypted — so a
// repack needs no data-encryption key and cannot corrupt content it
// cannot read". Copy is that loop with three changes: the source packs
// come from a FOREIGN store, the identity set comes from the imported
// tree's chunkrefs instead of a reachability report, and the catalogs are
// REBUILT for our namespace instead of carried.
//
// # The three things that do not survive the trip
//
//   - CATALOG DEDUP. Chunk identities are over bytes, so content dedup
//     survives an import exactly. Catalogs contain INODE NUMBERS, and an
//     import must renumber them, so the same subtree imported into two
//     volumes produces two distinct catalog objects. That is a property
//     of the format and not a defect here.
//   - PACK NAMES. `p-<unixnano>-<rand>` is time-ordered, not
//     content-derived (packstore.newPackName), so two volumes can mint
//     the same name and pack objects cannot simply be copied across
//     wholesale. New packs are cut on this side, which is also what stops
//     an import over-copying: a source pack holds entries from all over
//     the source tree, so copying pack OBJECTS would drag in bytes nobody
//     asked for.
//   - THE SOURCE'S SIGNATURE. It is verified on the way in — to confirm
//     we imported what they published — and then has nothing left to sign
//     in our document. See Verify.
//
// # What it refuses, and why each refusal is loud
//
//   - A SOURCE THAT SERVES GRAFTS. A grafted file's bytes were never in a
//     pack, so there is nothing to copy; importing one would produce a
//     chunkref this volume's packs cannot answer, in a generation that
//     signs and mounts. Refused by name, with the graft's path.
//   - A SOURCE IN A DIFFERENT ENCRYPTION DOMAIN. See CheckCustody.
//   - AN IDENTITY THE SOURCE'S PACKS DO NOT HOLD. Refused at the end of
//     the copy rather than discovered by a reader, because a signed
//     generation with a dangling chunkref is the one outcome worse than
//     a failed import.
package importvol

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrSourceGrafted is a source that serves grafted subtrees. Their bytes
// are not in any pack, so there is nothing for a copy to carry.
var ErrSourceGrafted = errors.New("importvol: the source volume serves grafted subtrees")

// ErrForeignCustody is a source encrypted under keys this volume does not
// hold, or a plaintext/encrypted mismatch in either direction.
var ErrForeignCustody = errors.New("importvol: the source is in a different encryption domain")

// ErrMissingBytes is a chunk identity the imported tree names that no
// pack of the source generation holds.
var ErrMissingBytes = errors.New("importvol: the source generation names bytes its own packs do not hold")

// Progress is what a long phase reports on a timer. An import reads and
// writes every byte of the source once, which at TB scale is hours, so
// the phases that take that long say where they are rather than going
// quiet.
type Progress struct {
	// Phase is "scanning" or "copying".
	Phase string
	// Done and Total are in the phase's own unit: inodes while scanning,
	// bytes while copying. Total is 0 when the phase cannot know it yet.
	Done, Total int64
	// Packs and PacksTotal count the copy's progress through the source's
	// pack set.
	Packs, PacksTotal int
	Elapsed           time.Duration
}

// Rate is the phase's unit per second, 0 before any elapsed time.
func (p Progress) Rate() float64 {
	if p.Elapsed <= 0 {
		return 0
	}
	return float64(p.Done) / p.Elapsed.Seconds()
}

// ETA is how much longer the phase has at its current rate, 0 when it
// cannot say.
func (p Progress) ETA() time.Duration {
	r := p.Rate()
	if r <= 0 || p.Total <= p.Done {
		return 0
	}
	return time.Duration(float64(p.Total-p.Done)/r) * time.Second
}

// ticker calls fn no more often than every d, and always once at the end.
// A progress line per object is unusable on a tree of a hundred million
// and invisible on a tree of one enormous file, which is why every long
// phase here is on a timer instead.
type ticker struct {
	every time.Duration
	last  time.Time
	fn    func(Progress)
	start time.Time
}

func newTicker(fn func(Progress), every time.Duration) *ticker {
	return &ticker{every: every, fn: fn, start: time.Now(), last: time.Now()}
}

func (t *ticker) tick(p Progress, force bool) {
	if t == nil || t.fn == nil {
		return
	}
	now := time.Now()
	if !force && now.Sub(t.last) < t.every {
		return
	}
	t.last = now
	p.Elapsed = now.Sub(t.start)
	t.fn(p)
}

// checkCtx turns a cancelled context into an error at the top of a loop
// body, which is where every long loop here checks it.
func checkCtx(ctx context.Context, what string) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("importvol: %s: %w", what, ctx.Err())
	default:
		return nil
	}
}
