package publish

import (
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
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
//
// `before` IS THE PARENT'S LIST, not the parent's plus this seal's own new
// ref, and the difference is a ledger row per seal. A ledger entry buys an
// object protection from the moment it stops being named until the grace
// window closes; retention's age guard already keeps every hash-named
// object for that same window from the moment it was WRITTEN
// (retention.scanHashNamed). So an entry is worth exactly the gap between
// those two instants, and for the segment a seal both uploads and
// immediately merges away that gap is zero: no published generation ever
// named it, and its own mtime protects it for longer than the entry would.
// Charging the ledger for it halved the time a fast-checkpointing mount
// took to reach the cap, in exchange for nothing.
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

// prevCondemnedPacks is the parent's pack ledger, which this generation
// carries forward until the entries age out.
func (p *pipeline) prevCondemnedPacks() []superblock.CondemnedPack {
	if p.o.Prev == nil {
		return nil
	}
	return p.o.Prev.Condemned
}

// addedPackNames names the packs a document lists that its parent did not:
// the only input the pack ledger's listed-wins rule needs from a seal.
func addedPackNames(groups ...[]packstore.SealedPack) []string {
	var out []string
	for _, g := range groups {
		for _, sp := range g {
			out = append(out, sp.Name)
		}
	}
	return out
}

// condemnPackLedger carries the condemned-PACK ledger forward. Publish
// never ADDS to it — only a repack drops a pack from the pack list — so
// every entry here came from a repack, and this seal's whole job is not to
// lose them.
//
// IT USED TO LOSE ALL OF THEM. buildSuperblock assembled a fresh
// superblock and simply never mentioned Condemned, so the first ordinary
// checkpoint after a repack published a generation with an empty ledger.
// The effect is not a tidiness bug: those packs are named by no live
// superblock and are old by their own name, which is the exact pair of
// conditions retention deletes on. The 72-hour window a repack promises a
// pinned reader lasted until the next checkpoint — five minutes at the
// default interval — and a mount still on the pre-repack generation reads
// its packs LAZILY for the whole session, so the loss surfaces as EIO on
// content nobody changed.
//
// `listed` is only the packs this generation ADDED, which is enough for
// listed-wins: this generation's set is its parent's plus those, and the
// parent applied the same rule, so nothing already on the ledger can be in
// the carried part.
//
// Overflow cannot happen here and is reported rather than assumed away:
// this call adds nothing, and repack paces a plan to what the ledger will
// carry (repack.trimToLedger), so a ledger arriving over the cap means one
// of those two statements has stopped being true.
func condemnPackLedger(prev []superblock.CondemnedPack, listed []string,
	now time.Time, grace time.Duration) []superblock.CondemnedPack {
	out, overflow := superblock.CarryCondemnedPacks(prev, nil, listed, now, grace)
	if overflow > 0 {
		ui.Warn("publish: the condemned-pack ledger arrived over its {cap}-byte share of the superblock "+
			"and this generation dropped the {n} oldest rows; a seal adds nothing to this ledger, so it "+
			"was already over — those packs may now be swept before the {grace} grace window ends",
			"cap", int64(superblock.CondemnedBudgetBytes), "n", overflow, "grace", grace)
	}
	return out
}

// condemnLedger is the shared rule with this seal's still-listed refs
// reduced to the names it reads. The generic parameter exists only so one
// call site can pass index refs and the other manifest refs.
//
// The overflow warning is the only signal a user gets that their
// checkpoint interval is short enough for the cap to bite
// (superblock.CondemnedBudgetBytes), and it is worth one line per seal
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
		ui.Warn("publish: the condemned-{what} ledger has filled its {cap}-byte share of the superblock, "+
			"so this generation dropped the {n} oldest rows; they are objects only a retired generation "+
			"names, and they may now be swept before the {grace} grace window ends — checkpoint less "+
			"often to keep the full window",
			"what", what, "cap", int64(superblock.CondemnedBudgetBytes), "n", overflow, "grace", grace)
	}
	return out
}
