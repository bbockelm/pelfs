package superblock

import (
	"sort"
	"time"
)

// The condemned ledgers, in ONE implementation.
//
// A ledger entry says "this generation stopped naming this object at this
// time", and retention reads it as "keep the object anyway, for the grace
// window". It is what speaks for an object no ENUMERABLE generation names:
// a retired generation is addressable only by hash, so once a head stops
// listing something, nothing a sweep can walk knows it is still needed.
//
// There were two implementations. Publish's carried the parent's entries
// forward, refused to condemn a name the generation still listed, kept the
// first timestamp for a name already on the ledger, and dropped aged
// entries. Repack's dropped aged entries and appended, and that was all —
// so a repack that rebuilt a manifest into the same bytes (same content,
// same hash, same name) condemned the very segment its own superblock was
// listing, and a name condemned twice appeared twice. Same field, same
// reader, two rules. This is that field's one rule, and both writers call
// it.
//
// THE FOUR RULES, and why each is the way round it is:
//
//   - LISTED WINS. A name the generation still lists is not condemned,
//     whatever the parent said and whatever the caller passes as dropped.
//     These objects are content-addressed, so a name that reappears is the
//     same bytes.
//   - FIRST TIMESTAMP WINS. An entry already on the ledger keeps its
//     original condemned-at. Refreshing it would restart the clock every
//     seal and the entry would never age off.
//   - AGED ENTRIES FALL OFF. Past the grace window an entry stops being
//     carried. Retention has already stopped honouring it by then.
//   - THE LEDGER IS CAPPED (MaxCondemnedEntries).
type ledgerRow struct {
	name string
	at   int64
}

// MaxCondemnedEntries bounds ONE ledger, and it is a brick guard rather
// than a tidiness rule.
//
// THE ARITHMETIC. Ledger growth is checkpoint-rate times grace window and
// is INDEPENDENT OF VOLUME SIZE: a consolidating seal condemns about one
// ref per key space every time, whether the volume holds ten files or a
// hundred million. An entry is a 64-character content hash plus a
// timestamp, ~96 bytes encoded. At the defaults — a checkpoint every five
// minutes, a 72-hour grace window — that is 864 entries and ~82 KB per key
// space, which is why an EMPTY volume was measured at 39% of the
// superblock budget. Halve the interval and it doubles; at
// `--snapshot-interval 1m` it is 4,320 entries per space and the volume
// passes the 1 MiB read cap — bricked, unmountable and unpublishable — in
// about three days of ordinary operation. T_grace is hardcoded, so a user
// has no lever at all.
//
// 512 entries is ~49 KB per ledger and ~147 KB for the three of them,
// under a third of the write budget, leaving the catalog list and the pack
// list room to be the reason a seal refuses.
//
// WHAT THE CAP COSTS, stated plainly because it is a real cost: at the
// default interval a ledger reaches 512 entries after about 43 hours, so
// the OLDEST entries are dropped while the 72-hour window they promise is
// still running. Dropping one does not corrupt anything and cannot affect
// anything a sweep can enumerate — a branch head and every tag name their
// own packs, indexes and manifests directly, so their objects are live
// whatever this ledger says. What it affects is the objects only a RETIRED
// generation names: those may now be swept earlier than the grace window
// says, which for an index costs a reader pinned there its speed (it falls
// back to pack trailers) and for a manifest costs that pinned reader the
// generation. That is the same limit the ledger already documents — it is
// a window, not a promise, and a workflow that needs a pin outliving it
// must TAG — narrowed from 72 hours to whatever 512 checkpoints comes to.
// Set against a volume that cannot be read at all, it is not a close call.
//
// OLDEST FIRST is which end to drop from for the same reason: those
// entries are nearest to ageing off anyway, so the cap only ever shortens
// a window that was about to close.
const MaxCondemnedEntries = 512

// CarryCondemnedPacks is the ledger rule for the pack key space:
// superblock.Condemned, written by repack when it drops packs from the
// pack list. overflow is how many entries the cap dropped, so a caller can
// say so.
func CarryCondemnedPacks(prev []CondemnedPack, dropped, listed []string,
	now time.Time, grace time.Duration) (out []CondemnedPack, overflow int) {
	rows := make([]ledgerRow, 0, len(prev))
	for _, c := range prev {
		rows = append(rows, ledgerRow{c.Name, c.CondemnedAtUnix})
	}
	kept, over := carryCondemned(rows, dropped, listed, now, grace)
	if len(kept) == 0 {
		return nil, over
	}
	out = make([]CondemnedPack, len(kept))
	for i, r := range kept {
		out[i] = CondemnedPack{Name: r.name, CondemnedAtUnix: r.at}
	}
	return out, over
}

// CarryCondemnedRefs is the same rule for the DERIVED key spaces:
// CondemnedIndexes and CondemnedManifests. Both writers call it, once per
// key space.
func CarryCondemnedRefs(prev []CondemnedRef, dropped, listed []string,
	now time.Time, grace time.Duration) (out []CondemnedRef, overflow int) {
	rows := make([]ledgerRow, 0, len(prev))
	for _, c := range prev {
		rows = append(rows, ledgerRow{c.Name, c.CondemnedAtUnix})
	}
	kept, over := carryCondemned(rows, dropped, listed, now, grace)
	if len(kept) == 0 {
		return nil, over
	}
	out = make([]CondemnedRef, len(kept))
	for i, r := range kept {
		out[i] = CondemnedRef{Name: r.name, CondemnedAtUnix: r.at}
	}
	return out, over
}

// carryCondemned is the rule itself: the parent's entries still inside the
// window, plus the names this generation stopped listing, minus anything
// it still lists, capped.
func carryCondemned(prev []ledgerRow, dropped, listed []string,
	now time.Time, grace time.Duration) ([]ledgerRow, int) {
	if len(prev) == 0 && len(dropped) == 0 {
		return nil, 0
	}
	seen := make(map[string]struct{}, len(listed)+len(prev)+len(dropped))
	for _, name := range listed {
		seen[name] = struct{}{}
	}
	out := make([]ledgerRow, 0, len(prev)+len(dropped))
	for _, c := range prev {
		if _, ok := seen[c.name]; ok {
			continue
		}
		if now.Sub(time.Unix(c.at, 0)) >= grace {
			continue
		}
		seen[c.name] = struct{}{}
		out = append(out, c)
	}
	for _, name := range dropped {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, ledgerRow{name, now.Unix()})
	}
	return capOldestFirst(out)
}

// capOldestFirst keeps the newest MaxCondemnedEntries rows and reports how
// many it dropped.
//
// The surviving rows stay in the order they were carried in, not in
// timestamp order: a superblock must be a pure function of its inputs, and
// re-ordering a ledger on the seal where it happens to overflow would
// change the encoding of entries nothing happened to.
func capOldestFirst(rows []ledgerRow) ([]ledgerRow, int) {
	if len(rows) <= MaxCondemnedEntries {
		return rows, 0
	}
	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	// Newest first; ties by name, so two entries stamped in the same second
	// — which is every entry a single seal adds — are dropped in an order
	// that does not depend on how the slice was built.
	sort.Slice(idx, func(a, b int) bool {
		ra, rb := rows[idx[a]], rows[idx[b]]
		if ra.at != rb.at {
			return ra.at > rb.at
		}
		return ra.name < rb.name
	})
	keep := make(map[int]struct{}, MaxCondemnedEntries)
	for _, i := range idx[:MaxCondemnedEntries] {
		keep[i] = struct{}{}
	}
	out := make([]ledgerRow, 0, MaxCondemnedEntries)
	for i, r := range rows {
		if _, ok := keep[i]; ok {
			out = append(out, r)
		}
	}
	return out, len(rows) - MaxCondemnedEntries
}
