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
//   - THE LEDGER IS CAPPED, in BYTES (CondemnedBudgetBytes, whose share
//     of the superblock's write budget is argued in size.go).
type ledgerRow struct {
	name string
	at   int64
}

// THE CAP IS A BRICK GUARD rather than a tidiness rule, and the number is
// in size.go because it is a SHARE of the superblock's write budget
// (CondemnedBudgetBytes, 48 KiB per ledger, 144 KiB for the three).
//
// THE ARITHMETIC IT ANSWERS. Ledger growth is checkpoint-rate times grace
// window and is INDEPENDENT OF VOLUME SIZE: a consolidating seal condemns
// about one ref per key space every time, whether the volume holds ten
// files or a hundred million. At the defaults — a checkpoint every five
// minutes, a 72-hour grace window — that is 864 rows per key space, which
// at 95 bytes a hash-named row is ~82 KB and is why an EMPTY volume was
// measured at 39% of the superblock budget. Halve the interval and it
// doubles; at `--snapshot-interval 1m` it is 4,320 rows per space and the
// volume passes the 1 MiB read cap — bricked, unmountable and
// unpublishable — in about three days of ordinary operation. T_grace is
// hardcoded, so a user has no lever at all.
//
// WHAT THE CAP COSTS, stated plainly because it is a real cost: 48 KiB is
// about 517 hash-named rows, which a default-interval mount reaches in
// about 43 hours, so the OLDEST rows are dropped while the 72-hour window
// they promise is still running. Dropping one does not corrupt anything
// and cannot affect anything a sweep can enumerate — a branch head and
// every tag name their own packs, indexes and manifests directly, so their
// objects are live whatever this ledger says. What it affects is the
// objects only a RETIRED generation names: those may now be swept earlier
// than the grace window says, which for an index costs a reader pinned
// there its speed (it falls back to pack trailers) and for a manifest
// costs that pinned reader the generation. That is the same limit the
// ledger already documents — it is a window, not a promise, and a workflow
// that needs a pin outliving it must TAG — narrowed from 72 hours to
// whatever the last 48 KiB of rows comes to. Set against a volume that
// cannot be read at all, it is not a close call.
//
// OLDEST FIRST is which end to drop from for the same reason: those rows
// are nearest to ageing off anyway, so the cap only ever shortens a window
// that was about to close.
//
// BYTES ARE THE UNIT because the ledgers do not agree on what a row costs
// — 53 bytes for a pack name, 95 for a content hash — so a row count
// charges the pack ledger 1.8x the price for the same protection. The cost
// of that landed on repack, which paces a plan to the room the ledger has
// (repack.trimToLedger): under rows a volume held packs back for a whole
// extra run to stay inside a share it was never spending.

// ledgerHeaderBytes is the CBOR array header, charged at the maximum a
// ledger this size can reach (three bytes covers 65,535 rows; the budget
// admits at most a couple of thousand).
//
// Charged FLAT rather than measured so that the weight of a ledger is
// monotone in its rows: a header that grew from two bytes to three on the
// row that crossed 255 would make a caller who planned to the budget
// (repack) and the cap that enforces it disagree by a byte, on exactly the
// seal where being wrong means a refused repack.
const ledgerHeaderBytes = 3

// rowBytes is the measured marginal cost of one ledger row: what appending
// it adds to the encoded array.
//
// MEASURED, NOT DERIVED. EncodedLen is the same machinery size.go weighs
// every other contributor with, so a ledger that fits this budget and the
// Contributors() line that reports its weight can never disagree about
// what a row costs.
//
// One measurement serves both ledgers: CondemnedPack and CondemnedRef are
// the same two columns under the same CBOR keys and encode identically.
// What differs is the NAME, which is the whole point of budgeting in
// bytes.
func rowBytes(name string, at int64) int64 {
	return EncodedLen(CondemnedPack{Name: name, CondemnedAtUnix: at})
}

// CondemnedRowBytes is rowBytes for a caller that has to plan against the
// budget before it writes anything: repack sizes a plan by summing this
// over the packs it proposes to condemn.
func CondemnedRowBytes(name string, at time.Time) int64 {
	return rowBytes(name, at.Unix())
}

// CondemnedPackRoom is how many bytes of one ledger's budget the rows
// already carried leave for new ones. Negative is impossible by
// construction (the rows came through the cap) but is clamped anyway,
// because the caller's next move is to divide it among candidates.
//
// It is stated as ROOM rather than as weight so that the array header is
// accounted in exactly one place. A caller that fills this room exactly
// produces a ledger of exactly CondemnedBudgetBytes.
func CondemnedPackRoom(carried []CondemnedPack) int64 {
	n := int64(ledgerHeaderBytes)
	for _, c := range carried {
		n += rowBytes(c.Name, c.CondemnedAtUnix)
	}
	if room := int64(CondemnedBudgetBytes) - n; room > 0 {
		return room
	}
	return 0
}

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

// capOldestFirst keeps the newest rows that fit CondemnedBudgetBytes and
// reports how many it dropped.
//
// The surviving rows stay in the order they were carried in, not in
// timestamp order: a superblock must be a pure function of its inputs, and
// re-ordering a ledger on the seal where it happens to overflow would
// change the encoding of entries nothing happened to.
func capOldestFirst(rows []ledgerRow) ([]ledgerRow, int) {
	cost := make([]int64, len(rows))
	total := int64(ledgerHeaderBytes)
	for i, r := range rows {
		cost[i] = rowBytes(r.name, r.at)
		total += cost[i]
	}
	if total <= CondemnedBudgetBytes {
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
	keep := make(map[int]struct{}, len(idx))
	used := int64(ledgerHeaderBytes)
	for _, i := range idx {
		// STOP at the first row that does not fit, rather than skipping it
		// to squeeze in a smaller one behind it. Skipping would drop a
		// NEWER row to keep an OLDER one, which is the one thing this rule
		// promises not to do; the few bytes it leaves unspent are the price
		// of "oldest first" meaning what it says.
		if used+cost[i] > CondemnedBudgetBytes {
			break
		}
		used += cost[i]
		keep[i] = struct{}{}
	}
	out := make([]ledgerRow, 0, len(keep))
	for i, r := range rows {
		if _, ok := keep[i]; ok {
			out = append(out, r)
		}
	}
	return out, len(rows) - len(out)
}
