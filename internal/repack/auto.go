package repack

import (
	"fmt"
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// The cheap gate in front of the expensive question.
//
// "Should this volume be repacked" is answered truthfully only by a
// reachability sweep: every catalog read, every trailer fetched, the
// whole namespace walked. That is minutes on a large volume and it is far
// too much to pay on a schedule just to be told there is nothing to do.
//
// So the shape is git's `gc --auto`. A COUNT that accumulates decides
// whether to pay for the real analysis; the real analysis decides what to
// do. git counts loose objects and packs; this counts PACKS ADDED SINCE
// THE LAST REPACK, which is the same kind of number: readable from the
// head at zero cost, monotone, and knowable exactly.
//
// It is deliberately a proxy for CHURN rather than for garbage. A volume
// that only ever appends will trip it and the sweep will find nothing —
// which costs one sweep and then resets the counter, so it happens once
// per threshold rather than repeatedly. The opposite error, missing real
// garbage, is bounded by the same counter: enough rewriting to produce
// garbage is enough writing to add packs.

const (
	// DefaultAutoPacks is how many packs a branch may gain since its last
	// repack before a sweep is worth paying for.
	//
	// At the 2 MiB target a seal writes, this is a few hundred megabytes
	// of new content — small enough that a churny volume is looked at
	// often, large enough that an idle one is never swept and a busy one
	// is not swept every checkpoint.
	DefaultAutoPacks = 200
	// DefaultAutoInterval is the floor between sweeps whatever the count
	// says. It stops a volume whose writes arrive in bursts from sweeping
	// once per burst, and it is well under the grace window, so nothing a
	// repack could act on ages out while waiting.
	DefaultAutoInterval = 6 * time.Hour
)

// AutoPolicy is when an automatic repack is worth attempting. The zero
// value takes the defaults above.
type AutoPolicy struct {
	// Packs is how many packs may accumulate since the last repack.
	Packs int
	// Interval is the minimum time between automatic sweeps.
	Interval time.Duration
	// Now is an injectable clock.
	Now time.Time
}

func (a AutoPolicy) withDefaults() AutoPolicy {
	if a.Packs <= 0 {
		a.Packs = DefaultAutoPacks
	}
	if a.Interval <= 0 {
		a.Interval = DefaultAutoInterval
	}
	if a.Now.IsZero() {
		a.Now = time.Now()
	}
	return a
}

// Worthwhile reports whether a volume has changed enough since its last
// repack to be worth sweeping, and says why either way.
//
// It reads the HEAD ONLY — no manifest fetch, no trailer, no catalog — so
// a mount can ask it as often as it likes. The reason is returned in both
// directions because this decides whether a background job runs, and a
// job that silently does nothing is indistinguishable from one that is
// broken.
func Worthwhile(head *superblock.Superblock, a AutoPolicy) (bool, string) {
	if head == nil {
		return false, "no head to judge"
	}
	a = a.withDefaults()
	packs := packCount(head)
	m := head.Maint
	if m == nil {
		// Never repacked. Judge it on absolute size rather than treating
		// the missing record as "just repacked": a volume that has been
		// written for months before this feature existed should be looked
		// at once, not exempted forever.
		if packs < a.Packs {
			return false, fmt.Sprintf("never repacked, and %d packs is under the %d that would justify a sweep",
				packs, a.Packs)
		}
		return true, fmt.Sprintf("never repacked, and the branch holds %d packs", packs)
	}
	if since := a.Now.Sub(time.Unix(0, m.RepackUnixNano)); since < a.Interval {
		return false, fmt.Sprintf("repacked %s ago, inside the %s floor", since.Round(time.Minute), a.Interval)
	}
	// The count can go DOWN — a repack removes packs — so this is written
	// as a difference rather than a subtraction that could wrap.
	added := packs - int(m.RepackPacks)
	if added < a.Packs {
		return false, fmt.Sprintf("%d packs added since generation %d, under the %d that would justify a sweep",
			added, m.RepackGeneration, a.Packs)
	}
	return true, fmt.Sprintf("%d packs added since the repack at generation %d", added, m.RepackGeneration)
}

// packCount is how many packs the head names, from the head alone.
//
// The manifest refs carry the count precisely so that a policy can be
// read without fetching what they name — the same role Entries plays for
// an index.
func packCount(sb *superblock.Superblock) int {
	if len(sb.Manifests) > 0 {
		n := 0
		for _, m := range sb.Manifests {
			n += int(m.Packs)
		}
		return n
	}
	return len(sb.PackList)
}
