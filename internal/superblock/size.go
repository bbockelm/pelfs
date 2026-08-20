package superblock

import (
	"fmt"
	"sort"
)

// THE HAZARD THIS FILE EXISTS FOR. A superblock is read through a hard
// ceiling — pelicanobj.MaxMutableObject, 1 MiB, enforced on every
// unverified read of a mutable object — and until this file existed
// nothing checked the size on the way OUT. A seal that flipped a
// superblock past the ceiling succeeded, and the volume was then
// permanently unmountable AND unpublishable: every reader refuses the
// object, and the next publish cannot read the parent it must grow from.
// There is no recovery from inside the tool.
//
// So the writers spend their budget before they spend the cap.

const (
	// MaxEncodedBytes is the WRITE budget: half of the 1 MiB read ceiling.
	//
	// Half, not 90%, because the ceiling is not the thing being avoided —
	// the CLIFF is. A superblock grows monotonically in the things a
	// volume accumulates (packs, catalogs, condemned refs), so a volume
	// that reaches 90% is one ordinary seal from being unrecoverable,
	// while a volume that reaches 50% has, at the growth rates measured
	// here, days of warning. The budget is what a seal refuses at, and a
	// refused seal loses nothing: the ref never flips, the volume stays
	// mountable, and the operator has a message naming what grew.
	//
	// It is stated here rather than derived from pelicanobj because this
	// package encodes bytes and must not depend on the object store (see
	// the package comment). TestTheWriteBudgetIsHalfTheReadCap pins the
	// two together.
	MaxEncodedBytes = 512 << 10

	// CatalogBudgetBytes is what the OPTIONAL catalog list may take of
	// that budget before a writer drops it instead.
	//
	// Catalogs is the one large field a writer may simply not write: both
	// consumers handle its absence (publish rebuilds every catalog rather
	// than carrying subtrees forward, reach walks the tree instead of
	// seeding from the list). So it is the field that turns "this volume
	// can no longer be sealed" into "this seal is slower", and a quarter
	// of the read cap is where that trade is worth taking — it leaves the
	// pack list, the key table and the ledgers room to be the reason a
	// seal fails, which are the growths a user can actually act on.
	CatalogBudgetBytes = 256 << 10
)

// EncodedLen is how many bytes v adds to an encoding, near enough to
// decide on. It encodes v alone, so it counts the value and not the map
// key naming it — a few bytes per field, which is noise against a budget
// measured in hundreds of kilobytes. A value that cannot be encoded
// reports 0: the caller is about to encode the whole superblock and will
// get the real error there.
func EncodedLen(v any) int64 {
	b, err := encMode.Marshal(v)
	if err != nil {
		return 0
	}
	return int64(len(b))
}

// TrimCatalogs drops the catalog list when it would take more than its
// share of the budget, and reports the bytes it dropped (0 when it kept
// them, so a caller warns on exactly the seals that paid for this).
//
// WHY THIS IS SAFE, once, here, because it is the property the whole idea
// rests on: Catalogs is optional in the format and both consumers already
// handle its absence. A publisher that finds it missing rebuilds every
// catalog instead of carrying unchanged subtrees forward, and a
// reachability sweep walks the tree from the root instead of seeding its
// frontier from the list. Neither reads a WRONG answer; both do more
// work. A dropped list therefore costs the next seal time proportional to
// the volume rather than to the change — real, and worth it against a
// superblock nobody can read.
//
// Callers trim BEFORE signing. There is no such thing as trimming a
// signed superblock.
func (sb *Superblock) TrimCatalogs() int64 {
	n := EncodedLen(sb.Catalogs)
	if n <= CatalogBudgetBytes {
		return 0
	}
	sb.Catalogs = nil
	return n
}

// Contributor is one variable-length field's share of an encoded
// superblock: what it is called on the wire, what it weighs, and how many
// rows it holds.
type Contributor struct {
	Field   string
	Bytes   int64
	Entries int
}

// Contributors reports the variable-length fields, heaviest first. It is
// the diagnosis half of the guard: "the superblock is too big" is not
// actionable, and "the superblock is too big and 80% of it is the
// condemned-manifest ledger" says to lengthen the checkpoint interval,
// while the same sentence ending in "the pack list" says to repack.
func (sb *Superblock) Contributors() []Contributor {
	out := []Contributor{
		{"pack_list", EncodedLen(sb.PackList), len(sb.PackList)},
		{"catalogs", EncodedLen(sb.Catalogs), len(sb.Catalogs)},
		{"shards", EncodedLen(sb.Shards), len(sb.Shards)},
		{"key_table", EncodedLen(sb.KeyTable), len(sb.KeyTable)},
		{"manifests", EncodedLen(sb.Manifests), len(sb.Manifests)},
		{"pack_indexes", EncodedLen(sb.PackIndexes), len(sb.PackIndexes)},
		{"condemned", EncodedLen(sb.Condemned), len(sb.Condemned)},
		{"condemned_indexes", EncodedLen(sb.CondemnedIndexes), len(sb.CondemnedIndexes)},
		{"condemned_manifests", EncodedLen(sb.CondemnedManifests), len(sb.CondemnedManifests)},
	}
	// Heaviest first, ties broken by name so the message a user reports is
	// reproducible.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Field < out[j].Field
	})
	return out
}

// CheckSize refuses an encoding that has eaten its budget, naming what ate
// it. encoded is the length of what Encode returned.
//
// WHICH DOCUMENTS IT GOVERNS, because getting this wrong costs seals that
// were never in danger. The budget exists because a MUTABLE object is read
// through pelicanobj.ReadMutable's 1 MiB ceiling, and exactly two kinds of
// object are read that way: refs/<branch> and tags/<name>. So every writer
// calls this on the document it is about to FLIP, and on nothing else.
//
// The disaster-recovery backup is the document this does NOT govern, and
// the reason is not leniency. It is an entry inside a pack, reached by a
// whole-pack fetch through a trailer, with no cap anywhere on that path.
// It also has a different SHAPE from the head it accompanies: the backup
// states its packs inline (publish.backupPackList) while the head states
// them through manifest refs, so the backup grows with pack count and the
// head does not. Checking it refused seals whose head was under a kilobyte
// — a first ingest past about 6,000 packs, which at the default cut is any
// tree over ~12 GB. "A backup over budget is a head over budget one step
// later" was true while both documents carried the list inline, and stopped
// being true when the backup started carrying it alone.
func (sb *Superblock) CheckSize(encoded int) error {
	if int64(encoded) <= MaxEncodedBytes {
		return nil
	}
	var worst Contributor
	if c := sb.Contributors(); len(c) > 0 {
		worst = c[0]
	}
	return fmt.Errorf("superblock: generation %d encodes to %d bytes, past the %d-byte write budget "+
		"(half the %d-byte limit on reading a mutable object, past which this volume could be neither "+
		"mounted nor published again); largest contributor is %s at %d bytes in %d entries%s",
		sb.Generation, encoded, int64(MaxEncodedBytes), int64(2*MaxEncodedBytes),
		worst.Field, worst.Bytes, worst.Entries, remedy(worst.Field))
}

// remedy turns the largest contributor into the thing to go and do. Each
// of these is a different problem wearing the same symptom, and the
// message is the only place a user finds out which one they have.
func remedy(field string) string {
	switch field {
	case "pack_list":
		return "; this volume still keeps its pack list inline — a repack rewrites it into " +
			"the manifest form the superblock stops growing with"
	case "catalogs":
		return "; the catalog list is a hint a writer may drop, so this means the rest of the " +
			"superblock has grown into its share too"
	case "condemned", "condemned_indexes", "condemned_manifests":
		return "; the condemned ledgers grow with the CHECKPOINT RATE times the grace window, " +
			"not with the volume — a longer --snapshot-interval is the lever"
	case "shards":
		return "; shards grow with the hard-linked file count"
	default:
		return ""
	}
}
