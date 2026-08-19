package publish

import (
	"time"

	"github.com/bbockelm/pelfs/internal/superblock"
)

// The ledger of DROPPED derived refs, written once and applied to both
// key spaces — the same split as consolidate.go, which decides which refs
// get dropped, for the same reason: nothing about the bookkeeping depends
// on whether the ref names an index or a manifest.
//
// THE BUG THIS EXISTS FOR. Consolidation merges several refs into one and
// stops listing the inputs. Retention's live set is head-plus-tags,
// because a retired generation is addressable only by hash and so cannot
// be enumerated — so once a dropped object ages past the grace window the
// sweep deletes it, even though a generation still inside the retain
// window names it. For an INDEX that is slow-not-broken (the reader falls
// back to pack trailers). For a MANIFEST that generation can no longer
// state its pack set, so it becomes unreadable and the packs it alone
// named go on the next sweep. The superblock backup's in-flight manifest
// segment falls in the same gap: it is superseded the instant the seal
// completes, and a rescue from an aged backup is exactly what would have
// needed it.
//
// Packs already solved this (superblock.CondemnedPack). This is the same
// answer for refs, and deliberately not a cleverer one.
//
// WHAT IT DOES NOT FIX, said here as well as on superblock.CondemnedRef,
// because this is the file someone edits when they want it to: the window
// is T_grace, not forever. An entry ages off, and after that a reader
// pinned to the generation that named the object is back to the behaviour
// above. Ledgers cannot fix that — only being addressable can, which
// means tagging.

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

// condemnLedger is the ledger one generation records for one key space:
// the parent's entries that are still inside the grace window, plus the
// refs this seal stopped listing, minus anything the generation still
// names.
//
// The three rules, and why each is the way round it is:
//
//   - LISTED WINS. A name the generation still lists is not condemned,
//     whatever the parent said. These objects are content-addressed, so a
//     name that reappears is the same bytes — and the backup's in-flight
//     segment relies on this directly: the backup superblock is built from
//     the very refs it just condemned, and only the FINAL superblock, which
//     does not list that segment, carries the entry.
//   - FIRST TIMESTAMP WINS. An entry already in the ledger keeps its
//     original condemned-at. Refreshing it would restart the clock every
//     seal and the entry would never age off.
//   - AGED ENTRIES FALL OFF. Past the grace window an entry stops being
//     carried, which is what bounds the ledger. Retention has already
//     stopped honouring it by then, so carrying it further would cost
//     bytes and buy nothing.
func condemnLedger[T sizedRef](prev []superblock.CondemnedRef, dropped []string, listed []T,
	now time.Time, grace time.Duration) []superblock.CondemnedRef {
	if len(prev) == 0 && len(dropped) == 0 {
		return nil
	}
	names := make(map[string]struct{}, len(listed)+len(prev))
	for _, r := range listed {
		names[r.RefName()] = struct{}{}
	}
	var out []superblock.CondemnedRef
	for _, c := range prev {
		if _, ok := names[c.Name]; ok {
			continue
		}
		if now.Sub(time.Unix(c.CondemnedAtUnix, 0)) >= grace {
			continue
		}
		names[c.Name] = struct{}{}
		out = append(out, c)
	}
	for _, name := range dropped {
		if name == "" {
			continue
		}
		if _, ok := names[name]; ok {
			continue
		}
		names[name] = struct{}{}
		out = append(out, superblock.CondemnedRef{Name: name, CondemnedAtUnix: now.Unix()})
	}
	return out
}
