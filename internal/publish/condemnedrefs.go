package publish

import (
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// The ledger of DROPPED derived refs, applied to both key spaces — the
// same split as consolidate.go, which decides which refs get dropped, for
// the same reason: nothing about the bookkeeping depends on whether the
// ref names an index or a manifest.
//
// THE BUG THIS EXISTS FOR. Consolidation merges several refs into one and
// stops listing the inputs. Retention's live set is head-plus-tags,
// because a retired generation is addressable only by hash and so cannot
// be enumerated — so once a dropped object ages past the grace window the
// sweep deletes it, even though a generation still inside the retain
// window names it. For an INDEX that is slow-not-broken (the reader falls
// back to pack trailers). For a MANIFEST that generation can no longer
// state its pack set, so it becomes unreadable and the packs it alone
// named go on the next sweep.
//
// Packs already solved this (superblock.CondemnedPack). This is the same
// answer for refs, and deliberately not a cleverer one.
//
// THE RULE ITSELF LIVES IN superblock.CarryCondemnedRefs, with repack's
// pack ledger, because a ledger written by two writers under two rules is
// a ledger with no rule. What is left here is the part that is publish's:
// turning "what did this seal stop listing" into the diff the rule reads.

// droppedRefs are the refs `before` listed that `after` does not, by
// name. Diffing the two lists is how this stays out of consolidate.go: a
// caller does not have to be told what a merge consumed, it can see what
// stopped being listed, which is the property that actually matters to
// retention.
func droppedRefs[T sizedRef](before, after []T) []string {
	if len(before) == 0 {
		return nil
	}
	kept := make(map[string]struct{}, len(after))
	for _, r := range after {
		kept[r.RefName()] = struct{}{}
	}
	var out []string
	for _, r := range before {
		if _, ok := kept[r.RefName()]; !ok {
			out = append(out, r.RefName())
		}
	}
	return out
}

// condemnLedger is the shared rule with this seal's still-listed refs
// reduced to the names it reads. The generic parameter exists only so one
// call site can pass index refs and the other manifest refs.
//
// The overflow warning is the only signal a user gets that their
// checkpoint interval is short enough for the cap to bite
// (superblock.MaxCondemnedEntries), and it is worth one line per seal
// because the alternative — silently shortening the grace window objects
// are kept for — is invisible until something a pinned reader wanted is
// already gone.
func condemnLedger[T sizedRef](prev []superblock.CondemnedRef, dropped []string, listed []T,
	now time.Time, grace time.Duration, what string) []superblock.CondemnedRef {
	names := make([]string, 0, len(listed))
	for _, r := range listed {
		names = append(names, r.RefName())
	}
	out, overflow := superblock.CarryCondemnedRefs(prev, dropped, names, now, grace)
	if overflow > 0 {
		ui.Warn("publish: the condemned-{what} ledger is full at {cap} entries, so this generation dropped "+
			"the {n} oldest; they are objects only a retired generation names, and they may now be swept "+
			"before the {grace} grace window ends — checkpoint less often to keep the full window",
			"what", what, "cap", superblock.MaxCondemnedEntries, "n", overflow, "grace", grace)
	}
	return out
}
