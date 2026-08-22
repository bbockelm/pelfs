package repack

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/reach"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// Executing a plan.
//
// The whole operation rests on one property of the format, and it is
// worth saying before the code: CHUNKREFS NAME IDENTITIES, NOT PLACES. A
// catalog says "this file is chunks a, b, c"; it never says which pack
// they sit in. So moving bytes between packs rewrites NOTHING in the
// namespace — not a catalog, not a shard, not the root. What has to
// change is only the structures that answer "where does identity X live":
// the pack manifest, and the multi-pack index.
//
// That is why a repack can be a small, self-contained generation rather
// than a republish of the tree. It is also why it is safe to interrupt:
// until the ref flips, everything written is unreferenced garbage that
// GC collects on its own schedule.
//
// # What it does, in order
//
//  1. Sweep, refusing to continue unless the sweep was clean. The
//     reachable set it produces decides which entries are worth carrying.
//  2. Copy each condemned pack's live entries into new packs. The bytes
//     are copied STORED — already compressed, already encrypted — so a
//     repack needs no data-encryption key and cannot corrupt content it
//     cannot read.
//  3. Write a new manifest naming the surviving packs plus the new ones.
//  4. Write one multi-pack index segment for the moved identities AND for
//     the live entries of any index this run retires, listed LAST so it
//     wins over the stale entries in older segments.
//  5. Publish a superblock that condemns the old packs and the retired
//     indexes, and flip the ref.
//
// # What it does not do
//
// It does not retire MANIFEST objects on their own account (Plan.Refs with
// Kind RefManifest). Replacing the manifest wholesale already drops every
// superseded segment, so there is nothing left for a rule to decide.
//
// It does not touch catalogs, shards, or the namespace in any way. A
// repacked generation has the same tree as its parent, byte for byte, and
// a test asserts exactly that.

// ExecOptions configures Execute. The sweep half mirrors Options, because
// executing a plan means computing one first — from a sweep this call
// runs itself, for the reason Compute does.
type ExecOptions struct {
	Options

	// Refs and Branch name the mutable head this publishes onto, and
	// SigningKey signs the generation. A repack produces a signed
	// superblock like any other publisher, and is refused without a key
	// rather than producing an unsigned one.
	Refs       *refs.Store
	Branch     string
	SigningKey ed25519.PrivateKey

	// SpoolDir holds packs being built. Empty takes a temporary directory
	// removed on return.
	SpoolDir string

	// TargetPackSize cuts the rewritten packs. Zero takes the same target
	// a seal uses.
	TargetPackSize int64

	// DryRun computes and reports without writing anything. It is the
	// default for the command, and it is here rather than in the caller so
	// that "what would happen" and "what happened" come from one code
	// path.
	DryRun bool
}

// Result is what an execution did.
type Result struct {
	// Plan is what was decided. On a dry run it is the whole answer.
	Plan *Plan
	// NewPacks are the packs written, CondemnedPacks the names dropped.
	NewPacks       []packstore.SealedPack
	CondemnedPacks []string
	// MovedEntries and MovedBytes are what was actually carried, which
	// may be under the plan's estimate: an identity placed in two
	// condemned packs is carried once.
	MovedEntries, MovedBytes int64
	// ReclaimedBytes is the size of the condemned objects less what the
	// new packs cost, so it is the real figure rather than the estimate.
	ReclaimedBytes int64
	// Generation is the generation published, zero on a dry run.
	Generation uint64
	// DryRun echoes the option, so a caller reporting a Result cannot
	// present a rehearsal as a change.
	DryRun bool
}

// Execute computes a plan and carries it out.
//
// A refused plan — an incomplete sweep — is returned with no error and
// nothing done, exactly as Compute reports it: the caller decides whether
// "nothing could be decided" is worth an exit code, and this must not
// look like success at the API level by silently doing nothing.
func Execute(ctx context.Context, o ExecOptions) (*Result, error) {
	if o.Inner == nil {
		return nil, errors.New("repack: Inner is required")
	}
	if !o.DryRun {
		if o.Refs == nil || o.Branch == "" {
			return nil, errors.New("repack: Refs and Branch are required to publish")
		}
		if len(o.SigningKey) == 0 {
			return nil, errors.New("repack: a signing key is required to publish")
		}
	}
	// CollectReachable is what makes this different from a plan: the
	// executor needs the identity set, not only the counts.
	sweepOpts := o.Options
	sweepOpts.collectReachable = true
	plan, rep, err := compute(ctx, sweepOpts)
	if err != nil {
		return nil, err
	}
	defer rep.Close() //nolint:errcheck
	res := &Result{Plan: plan, DryRun: o.DryRun}
	if plan.Refused() || plan.Empty() || o.DryRun {
		return res, nil
	}
	if rep == nil || rep.Reachable == nil {
		// Unreachable: a non-refused plan came from a clean sweep, and a
		// clean sweep asked for the set produces one. Refusing rather than
		// carrying on, because the alternative is deciding what to keep
		// with no idea what is live.
		return nil, errors.New("repack: the sweep produced no reachable set; refusing to rewrite anything")
	}
	return res, execute(ctx, o, res, rep)
}

// execute is the writing half, separated so that everything above it is
// decisions and everything below it is consequences.
func execute(ctx context.Context, o ExecOptions, res *Result, rep *reach.Report) error {
	spool := o.SpoolDir
	if spool == "" {
		tmp, err := os.MkdirTemp("", "pelfs-repack-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp) //nolint:errcheck
		spool = tmp
	}

	head, err := o.Refs.Fetch(ctx, o.Branch)
	if err != nil {
		return fmt.Errorf("repack: read the branch head: %w", err)
	}
	// The plan was computed against a live set the caller supplied. If the
	// head moved since, the plan describes a volume that no longer exists
	// and its liveness numbers are stale — a pack it calls dead may be one
	// the new head references. Refused rather than rebased: rebasing means
	// re-sweeping, which is the whole operation.
	if !headMatches(o.Head, head.Superblock) {
		return fmt.Errorf("repack: %w: the branch moved to generation %d while this plan was computed",
			refs.ErrStaleFlip, head.Superblock.Generation)
	}

	// The pack set of every live generation, unioned, because a candidate
	// may be one only an older generation names. The trailer hash comes
	// from here so that what is read is verified against a SIGNED
	// statement rather than trusted — the same rule the sweep follows.
	known, err := livePacks(ctx, o.Inner, o.Live)
	if err != nil {
		return err
	}
	// What this run may condemn is bounded by what the ledger will carry,
	// and the bound is applied HERE — before a byte is rewritten — because
	// the alternative is discovering it after the expensive part.
	if held := trimToLedger(res.Plan, head.Superblock.Condemned, o.Now, graceOf(head.Superblock)); held > 0 {
		ui.Warn("repack: this plan proposed condemning {planned} packs and the condemned ledger has "+
			"{cap} bytes of the superblock to protect them in; {held} of them are held back for a later "+
			"run, least-reclaim-first, so that every pack this run does condemn keeps the full {grace} "+
			"window",
			"planned", len(res.Plan.Packs)+held, "cap", int64(superblock.CondemnedBudgetBytes), "held", held,
			"grace", graceOf(head.Superblock))
	}
	if res.Plan.Empty() {
		// Everything was held back: the ledger is already full of entries
		// still inside their window, so there is no room to protect anything
		// else. Doing nothing is the answer, and the note says why.
		return nil
	}
	condemn := make(map[string]bool, len(res.Plan.Packs))
	for _, c := range res.Plan.Packs {
		condemn[c.Name] = true
	}
	moved, err := rewritePacks(ctx, o, spool, rep, condemn, known, res)
	if err != nil {
		return err
	}
	sb, raw, err := repackedSuperblock(ctx, o, head.Superblock, head.Raw, condemn, moved, res)
	if err != nil {
		return err
	}
	if err := o.Refs.Flip(ctx, o.Branch, raw, head.ETag); err != nil {
		return fmt.Errorf("repack: %w", err)
	}
	res.Generation = sb.Generation
	return nil
}

// trimToLedger holds back the candidates the condemned-pack ledger has no
// room for, and reports how many. It mutates the plan, so what the Result
// reports is what was actually done.
//
// WHY A REPACK IS PACED RATHER THAN TRUNCATED. The ledger is the only
// thing that keeps a repacked-away pack alive: the new generation does not
// name it, and it is old by its own name, which is exactly the pair of
// conditions retention deletes on — the age guard that protects a young
// pack cannot help here, because a repack only ever touches old ones. So an
// entry that does not fit is not a lost row in a log, it is a pack a reader
// pinned to the pre-repack generation loses while it is still reading it.
//
// The ledger's budget cannot simply be raised to fit: the superblock has a
// hard write budget (superblock.MaxEncodedBytes) and this ledger shares it
// with two others whose growth is set by the CHECKPOINT RATE and is
// unbounded in time. What can move is the size of one run. Repack is
// resumable by construction — every run re-sweeps and re-plans — so a plan
// larger than the ledger is not a failure to report, it is two runs: this
// one takes what fits, the grace window passes, `pelfs gc` reclaims, the
// entries age off, and the next run takes the rest.
//
// PACED IN THE LEDGER'S OWN UNITS, WHICH ARE BYTES. The ledger's bound is
// a share of the superblock (superblock.CondemnedBudgetBytes), so what a
// candidate consumes is what its ROW costs — 53 bytes for a pack name,
// against the 95 a hash-named ref row costs on the other two ledgers.
// Pacing in rows meant pacing to the smaller of those two prices: a volume
// held packs back, and bought itself a second full sweep and rewrite, to
// stay inside a share it was never spending.
//
// Held back LEAST-RECLAIM-FIRST (so the largest reclaims are what is kept)
// for two reasons. The bytes come back sooner, and the packs left for the
// next run are the ones with the least to give — so a repack that is
// interrupted forever still converges on the garbage that matters.
func trimToLedger(plan *Plan, prev []superblock.CondemnedPack, now time.Time, grace time.Duration) int {
	if now.IsZero() {
		now = time.Now()
	}
	// The room is what the budget leaves after the rows this generation
	// must carry: the parent's, less the ones that have aged out. Asked
	// through the ledger rule itself rather than recounted here, so the
	// arithmetic cannot drift from the rule that enforces it.
	//
	// `listed` is nil, which is exact rather than conservative: a ledger
	// entry names a pack its generation stopped listing, and a repack
	// cannot re-create that name (pack names carry a creation stamp and a
	// random suffix), so nothing on the carried ledger can be re-listed.
	// That also means no candidate here is already on the ledger, so every
	// one of them really does cost a row.
	carried, _ := superblock.CarryCondemnedPacks(prev, nil, nil, now, grace)
	room := superblock.CondemnedPackRoom(carried)
	var need int64
	for _, c := range plan.Packs {
		need += superblock.CondemnedRowBytes(c.Name, now)
	}
	// Asked before the sort, so a plan that fits keeps the order its
	// planner chose.
	if need <= room {
		return 0
	}
	sort.SliceStable(plan.Packs, func(i, j int) bool {
		if plan.Packs[i].Reclaim != plan.Packs[j].Reclaim {
			return plan.Packs[i].Reclaim > plan.Packs[j].Reclaim
		}
		return plan.Packs[i].Name < plan.Packs[j].Name
	})
	// Fill the room in that order and stop at the first candidate that does
	// not fit, matching the ledger rule's own stop-do-not-skip behaviour:
	// squeezing a shorter name in past a longer one would keep a worse
	// candidate over a better one for a handful of bytes.
	fits, used := 0, int64(0)
	for _, c := range plan.Packs {
		n := superblock.CondemnedRowBytes(c.Name, now)
		if used+n > room {
			break
		}
		used += n
		fits++
	}
	held := len(plan.Packs) - fits
	for _, c := range plan.Packs[fits:] {
		if len(plan.Notes) >= maxNames {
			break
		}
		plan.Notes = append(plan.Notes, Note{Object: c.Name,
			Detail: "held back: the condemned-pack ledger has no room; a later run takes it"})
	}
	plan.Packs = plan.Packs[:fits]
	// The estimate has to follow, or the report promises bytes this run
	// will not move.
	var move int64
	for _, c := range plan.Packs {
		move += c.Move
	}
	if move > 0 && plan.IntoPacks > 0 {
		plan.IntoPacks = int((move + defaultTargetPackSize - 1) / defaultTargetPackSize)
	} else if move == 0 {
		plan.IntoPacks = 0
	}
	return held
}

// retiredIndexes is which index refs this run drops from the list, paced
// to what the condemned-index ledger can carry.
//
// THE CASE IT ANSWERS is the narrow one the design states: an index whose
// packs are mostly gone spends its bytes on entries that resolve to
// nothing, and a mount pays for those bytes on every lookup it windows
// through the object, forever. The planner measures it (RefCandidate,
// live packs over packs, against RefLive) and this acts on it.
//
// IT IS FETCH COST AND NOTHING ELSE, which is what makes it the lowest-risk
// of the three retirement rules. An index is DERIVED: a generation whose
// index is missing still mounts and still serves, it just falls back to
// pack trailers (genfs.packIndex.locate). Nothing here can lose data even
// if every judgement in it is wrong — the worst case is a reader paying the
// fallback for entries that used to be indexed, which is why the live
// entries are re-emitted rather than dropped (carryIndexEntries).
//
// PACED THROUGH THE SAME LEDGER DISCIPLINE AS PACKS, for a weaker reason
// that still holds. A retired index is hash-named, so retention ages it by
// its mtime — which expired long ago for an index worth retiring — and the
// ledger row is then the only thing that keeps it while a retired
// generation still names it. Truncating that ledger silently is what this
// avoids: what does not fit is simply not retired this run, and the next
// run sees it again. A repack is resumable by construction.
//
// ONE APPROXIMATION, ADMITTED. The plan's liveness fractions were measured
// against the packs the plan proposed to condemn, and trimToLedger may
// since have held some of those back. An index judged against a pack that
// is no longer being condemned is judged slightly too dead. The cost is
// re-emitting a few live entries a run early; it cannot make a wrong
// location, because every entry re-emitted names a pack this generation
// LISTS.
func retiredIndexes(plan *Plan, prev *superblock.Superblock, now time.Time) map[string]bool {
	listed := make(map[string]bool, len(prev.PackIndexes))
	for _, ref := range prev.PackIndexes {
		listed[ref.Name] = true
	}
	// The room the ledger has after the rows this generation must carry.
	// Asked through the ledger rule itself, exactly as trimToLedger does, so
	// the arithmetic cannot drift from the rule that enforces it.
	carried, _ := superblock.CarryCondemnedRefs(prev.CondemnedIndexes, nil, nil, now, graceOf(prev))
	room := superblock.CondemnedPackRoom(condemnedAsPacks(carried))
	out := make(map[string]bool)
	var used int64
	held := 0
	for _, c := range plan.Refs {
		if c.Kind != RefIndex || !listed[c.Name] {
			// A manifest candidate (handled by rewriting the manifest whole)
			// or a ref the head no longer lists.
			continue
		}
		n := superblock.CondemnedRowBytes(c.Name, now)
		if used+n > room {
			held++
			continue
		}
		used += n
		out[c.Name] = true
	}
	if held > 0 {
		ui.Info("repack: {held} index segment(s) are worth retiring and the condemned-index ledger has no "+
			"room for their rows; they are left listed for a later run rather than dropped without one",
			"held", held)
	}
	return out
}

// condemnedAsPacks re-shapes ref rows as pack rows so that one room
// calculation serves both ledgers. The two row types encode identically —
// same two columns, same CBOR keys — and what differs is the NAME, which is
// carried across unchanged. Stated here rather than by adding a second
// Room function to the format package, where one rule for one row shape is
// the point.
func condemnedAsPacks(rows []superblock.CondemnedRef) []superblock.CondemnedPack {
	out := make([]superblock.CondemnedPack, len(rows))
	for i, r := range rows {
		out[i] = superblock.CondemnedPack{Name: r.Name, CondemnedAtUnix: r.CondemnedAtUnix}
	}
	return out
}

// carryIndexEntries re-emits the entries of every retired index that still
// name a pack this generation LISTS, and reports how many it carried.
//
// This is the "re-emits its live entries" half of the design's retirement
// rule, and without it retirement would be a speed regression wearing the
// costume of a cleanup: the entries an index still answers for are exactly
// the ones for its surviving packs, and dropping the object would send
// every lookup of them down the trailer-walk fallback. Re-emitting keeps
// the coverage and drops only the dead share, which is the trade the
// planner measured (RefCandidate.Move/Reclaim).
//
// A key is copied at its stored width (mpi.Builder.AddKey): an entry is
// twelve bytes of identity by design, and re-emitting one needs no more
// than the index already holds.
func carryIndexEntries(ctx context.Context, obj pelicanobj.Store, refs []superblock.IndexRef,
	retire map[string]bool, listedPacks []string, into *mpi.Builder) (int, error) {

	if len(retire) == 0 {
		return 0, nil
	}
	listed := make(map[string]bool, len(listedPacks))
	for _, name := range listedPacks {
		listed[name] = true
	}
	carried := 0
	for _, ref := range refs {
		if !retire[ref.Name] {
			continue
		}
		ix, err := mpi.Fetch(ctx, obj, ref)
		if err != nil {
			// Refused rather than skipped. Retiring an index whose entries
			// could not be read would drop coverage this run promised to
			// carry, and a repack that stops has cost only its rewriting —
			// the ref never flips, and what was written is unreferenced
			// garbage the sweep collects.
			return 0, fmt.Errorf("repack: read index %s to carry its live entries: %w", ref.Name, err)
		}
		var addErr error
		ix.Each(func(key []byte, packs []string) {
			if addErr != nil {
				return
			}
			for _, pn := range packs {
				if !listed[pn] {
					continue
				}
				if err := into.AddKey(key, pn); err != nil {
					addErr = fmt.Errorf("repack: carry an entry of index %s: %w", ref.Name, err)
					return
				}
				carried++
			}
		})
		if addErr != nil {
			return 0, addErr
		}
	}
	return carried, nil
}

// retiredNames is the retired refs in LIST ORDER, which is what the ledger
// rule wants: a deterministic order for the rows a generation adds.
func retiredNames(refs []superblock.IndexRef, retire map[string]bool) []string {
	out := make([]string, 0, len(retire))
	for _, ref := range refs {
		if retire[ref.Name] {
			out = append(out, ref.Name)
		}
	}
	return out
}

// indexNames is what a generation LISTS, for listed-wins: an index this
// generation still names is never condemned, whatever this run dropped.
func indexNames(refs []superblock.IndexRef) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ref.Name)
	}
	return out
}

// headMatches reports whether the branch head is still the generation this
// plan was computed against.
//
// IT COMPARES AGAINST o.Head, NOT AGAINST THE LIVE SET, and on a volume
// with two branches that is the difference between a guard and a
// formality. It used to scan Live for any generation with the same number
// and volume id — which was sound while a volume had one branch, because
// then a matching number could only be the branch itself. It is not sound
// with two: generation numbers are per-lineage, so both children of
// generation N seal N+1, and a SIBLING branch sitting at the same number
// would answer for a head that had moved. The stale-plan check would pass,
// and the repack would go on to condemn packs the new head references,
// using liveness numbers measured before it existed.
//
// So the question is asked of the one generation whose answer means
// anything: the head the plan was built from. Identity is (volume,
// generation, root catalog, lineage) rather than a number — PrevHash pins
// the exact parent and RootCatalog the exact content, so two documents
// agreeing on all four are the same generation whatever ref names them,
// which is precisely the case where proceeding is safe (a branch created
// as a copy of another head is byte-identical to it).
func headMatches(planned *superblock.Superblock, head *superblock.Superblock) bool {
	return planned != nil && sameGeneration(planned, head)
}

// sameGeneration reports whether two superblocks describe one generation.
// The generation NUMBER alone never does: it counts steps along a lineage,
// and two branches of a volume count independently.
func sameGeneration(a, b *superblock.Superblock) bool {
	return a.VolumeID == b.VolumeID &&
		a.Generation == b.Generation &&
		a.RootCatalog == b.RootCatalog &&
		a.PrevHash == b.PrevHash
}

// placement is where a moved identity ended up.
type placement struct {
	pack        string
	off, length int64
}

// rewritePacks copies the live entries of every condemned pack into new
// packs, and returns where each identity landed.
//
// Bytes are copied STORED, which is the property that makes this safe:
// the entry is compressed and encrypted exactly as it was, so a repack
// needs no data key, cannot mis-encode, and cannot silently change what a
// chunkref resolves to. Its identity still names its plaintext, and
// nothing that references it by identity has to be touched.
func rewritePacks(ctx context.Context, o ExecOptions, spool string, rep *reach.Report,
	condemn map[string]bool, known map[string]superblock.PackEntry, res *Result) (map[[32]byte]placement, error) {

	target := o.TargetPackSize
	if target <= 0 {
		target = defaultTargetPackSize
	}
	moved := make(map[[32]byte]placement)

	var w *packstore.PackWriter
	// pending holds the identities in the open pack, whose placements are
	// only known once it is sealed and named.
	var pending []struct {
		id  [32]byte
		off int64
		n   int64
	}
	closeOut := func() error {
		if w == nil {
			return nil
		}
		sp, err := w.Seal(ctx, o.Inner)
		w = nil
		if err != nil {
			return err
		}
		for _, p := range pending {
			moved[p.id] = placement{pack: sp.Name, off: p.off, length: p.n}
		}
		pending = pending[:0]
		res.NewPacks = append(res.NewPacks, sp)
		res.ReclaimedBytes -= sp.Size
		return nil
	}
	defer func() {
		if w != nil {
			w.Abort()
		}
	}()

	for _, c := range res.Plan.Packs {
		pe, ok := known[c.Name]
		if !ok {
			// A candidate no live generation names cannot be verified, and
			// an unverified trailer is a location map nothing vouches for.
			return nil, fmt.Errorf("repack: %s is a candidate but no live generation names it", c.Name)
		}
		entries, err := packstore.FetchTrailerVerified(ctx, o.Inner, c.Name, pe.Size, pe.TrailerHash)
		if err != nil {
			return nil, fmt.Errorf("repack: read %s: %w", c.Name, err)
		}
		for _, e := range entries {
			id, err := parseIdentity(e.Key)
			if err != nil {
				// The sweep already refused a trailer key that is not an
				// identity, so reaching this means the pack changed under
				// us. Stop rather than drop an entry nobody can name.
				return nil, fmt.Errorf("repack: %s entry %q: %w", c.Name, e.Key, err)
			}
			if !worthCarrying(rep, id, e.Type) {
				continue
			}
			if _, dup := moved[id]; dup {
				// The same bytes in two condemned packs collapse to one
				// copy. Nothing is lost: identity IS the content.
				continue
			}
			stored, err := readEntry(ctx, o.Inner, c.Name, e.Off, e.Length)
			if err != nil {
				return nil, fmt.Errorf("repack: read %s entry %s: %w", c.Name, e.Key, err)
			}
			if w != nil && w.Size() > 0 && w.Size()+int64(len(stored)) > target {
				if err := closeOut(); err != nil {
					return nil, fmt.Errorf("repack: seal a rewritten pack: %w", err)
				}
			}
			if w == nil {
				if w, err = packstore.NewPackWriter(spool); err != nil {
					return nil, err
				}
			}
			off := w.Size()
			if err := w.Add(e.Key, e.Type, stored); err != nil {
				return nil, fmt.Errorf("repack: write %s: %w", e.Key, err)
			}
			pending = append(pending, struct {
				id  [32]byte
				off int64
				n   int64
			}{id, off, int64(len(stored))})
			res.MovedEntries++
			res.MovedBytes += int64(len(stored))
		}
		res.CondemnedPacks = append(res.CondemnedPacks, c.Name)
		res.ReclaimedBytes += c.Size
	}
	if err := closeOut(); err != nil {
		return nil, fmt.Errorf("repack: seal a rewritten pack: %w", err)
	}
	return moved, nil
}

// worthCarrying decides whether one entry survives the rewrite.
//
// Two kinds do. Anything the sweep reached is referenced by a live
// generation. And a SUPERBLOCK BACKUP is live for as long as its
// generation is, while being reachable only by scavenging — nothing names
// it by identity, so the reachable set cannot speak for it, and dropping
// it would quietly remove the disaster-recovery copy this pack was
// carrying.
func worthCarrying(rep *reach.Report, id [32]byte, typ string) bool {
	if typ == packstore.EntrySuperblock {
		return true
	}
	rec, _, _ := rep.Reachable.Lookup(id[:])
	return rec != nil
}

func parseIdentity(key string) ([32]byte, error) {
	var id [32]byte
	if len(key) != 2*len(id) {
		return id, fmt.Errorf("is %d chars, want %d hex", len(key), 2*len(id))
	}
	if _, err := hex.Decode(id[:], []byte(key)); err != nil {
		return id, err
	}
	return id, nil
}

// livePacks unions the pack sets of every live generation, resolved the
// way the sweep resolves them — through the manifest when there is one
// and the inline list otherwise.
func livePacks(ctx context.Context, obj pelicanobj.Store, live []*superblock.Superblock) (map[string]superblock.PackEntry, error) {
	out := make(map[string]superblock.PackEntry)
	for _, sb := range live {
		packs, err := manifest.Packs(ctx, obj, sb)
		if err != nil {
			return nil, fmt.Errorf("repack: resolve generation %d's pack set: %w", sb.Generation, err)
		}
		for _, pe := range packs {
			out[pe.Name] = pe
		}
	}
	return out, nil
}

func readEntry(ctx context.Context, obj pelicanobj.Store, pack string, off, length int64) ([]byte, error) {
	rc, err := obj.Get(ctx, packstore.PackDirKey+"/"+pack, off, length)
	if err != nil {
		return nil, err
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, length))
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	// Transfer-engine transports may report failure only at Close (the
	// packstore lesson); never swallow it.
	if cerr != nil {
		return nil, cerr
	}
	if int64(len(buf)) != length {
		return nil, fmt.Errorf("short read: %d of %d bytes", len(buf), length)
	}
	return buf, nil
}

// repackedSuperblock builds and signs the generation this repack
// publishes: the parent's namespace exactly, with new location structures
// and the dropped packs condemned.
func repackedSuperblock(ctx context.Context, o ExecOptions, prev *superblock.Superblock, prevRaw []byte,
	condemn map[string]bool, moved map[[32]byte]placement, res *Result) (*superblock.Superblock, []byte, error) {

	now := time.Now()
	sb := *prev
	sb.Generation = prev.Generation + 1
	sb.CreatedUnixNano = now.UnixNano()
	sb.PrevHash = superblock.Hash(prevRaw)
	sb.Signature = [64]byte{}
	// The branch this repack publishes ONTO, which is not always the one the
	// parent recorded: `pelfs branch dev` copies main's head verbatim, so a
	// repack can be the first writer a branch ever has and would otherwise
	// inherit "main" from the copy and go on re-stating it.
	//
	// A REPACK WRITES NO SUPERBLOCK BACKUP — it carries the parent's forward,
	// it does not add one — so this stamp attributes nothing to the window
	// scan by itself. What it does is keep a head's own statement true, so
	// that the seal after it, and anything that reads a head to ask which
	// line of history it is on, get the same answer. The generation a repack
	// grows FROM is the one no backup will ever describe, and that hole is
	// covered by the condemned-ledger floor rather than by attribution
	// (retention.retainedSet, lastk.windowFloor).
	sb.Branch = o.Branch

	// The pack set: everything the parent named that is not condemned,
	// plus what this wrote.
	prevPacks, err := manifest.Packs(ctx, o.Inner, prev)
	if err != nil {
		return nil, nil, fmt.Errorf("repack: resolve the parent's pack set: %w", err)
	}
	mb := manifest.NewBuilder()
	kept := 0
	// listedPacks is what the new generation NAMES, which the ledger rule
	// needs: a name still listed is never condemned, whatever this run
	// thinks it dropped.
	listedPacks := make([]string, 0, len(prevPacks)+len(res.NewPacks))
	for _, pe := range prevPacks {
		if condemn[pe.Name] {
			continue
		}
		if err := mb.Add(packstore.SealedPack{Name: pe.Name, TrailerHash: pe.TrailerHash, Size: pe.Size}); err != nil {
			return nil, nil, err
		}
		listedPacks = append(listedPacks, pe.Name)
		kept++
	}
	for _, sp := range res.NewPacks {
		if err := mb.Add(sp); err != nil {
			return nil, nil, err
		}
		listedPacks = append(listedPacks, sp.Name)
	}
	mref, err := putManifest(ctx, o.Inner, mb)
	if err != nil {
		return nil, nil, err
	}
	// One segment replaces every previous one, so all of them are
	// condemned together (see the ledger note below). A repack is rare and
	// the manifest is the authority on what exists: rewriting it whole is
	// the version that cannot leave a stale entry naming a pack this very
	// change deleted.
	sb.PackList = nil
	sb.Manifests = []superblock.ManifestRef{mref}
	// The ledger rule is the superblock's, not this file's: publish and
	// repack write the same field and a reader cannot tell which of them
	// wrote it (superblock.CarryCondemnedRefs). Passing the segment this
	// generation LISTS matters here in particular — a repack that rebuilt
	// the manifest into the same bytes produces the same content hash, and
	// the old rule condemned the very segment sb.Manifests names.
	sb.CondemnedManifests = condemnRefs(prev.CondemnedManifests, refNames(prev.Manifests),
		[]string{mref.Name}, now, graceOf(prev), "manifest")

	// The index refs this run RETIRES: the ones whose live-pack coverage
	// has fallen under the threshold, paced to the room their ledger has.
	// Chosen before the segment is built because their surviving entries go
	// into it.
	retire := retiredIndexes(res.Plan, prev, now)
	ib := mpi.NewBuilder()
	for id, p := range moved {
		ib.Add(id, p.pack)
	}
	carried, err := carryIndexEntries(ctx, o.Inner, prev.PackIndexes, retire, listedPacks, ib)
	if err != nil {
		return nil, nil, err
	}

	// One index segment for what moved and for what a retired index still
	// answered for, listed LAST so it wins: a Set asks the newest index
	// first, and the older segments still name the packs this change
	// deleted.
	keptIndexes := make([]superblock.IndexRef, 0, len(prev.PackIndexes))
	for _, ref := range prev.PackIndexes {
		if !retire[ref.Name] {
			keptIndexes = append(keptIndexes, ref)
		}
	}
	sb.PackIndexes = keptIndexes
	if ib.Len() > 0 {
		iref, err := putIndex(ctx, o.Inner, ib)
		if err != nil {
			return nil, nil, err
		}
		sb.PackIndexes = append(keptIndexes, iref)
	}
	if len(retire) > 0 {
		// Same ledger rule, same field publish writes when consolidation
		// merges a ref away (superblock.CarryCondemnedRefs). It is what
		// speaks for these objects while a retired generation still names
		// them: they are hash-named, so the sweep's mtime guard expired long
		// ago, and nothing a sweep can enumerate lists them any more.
		sb.CondemnedIndexes = condemnRefs(prev.CondemnedIndexes, retiredNames(prev.PackIndexes, retire),
			indexNames(sb.PackIndexes), now, graceOf(prev), "index")
		ui.Info("repack: retired {n} index segment(s) whose packs are mostly gone, re-emitting {carried} "+
			"live entries; a reader pinned to an older generation keeps them for the {grace} window",
			"n", len(retire), "carried", carried, "grace", graceOf(prev))
	}

	// What this run did, so the next one can decide whether to bother
	// without paying for a sweep (auto.go). Written here and nowhere
	// else: an ordinary publish carries it forward untouched.
	sb.Maint = &superblock.Maint{
		RepackGeneration: sb.Generation,
		RepackPacks:      uint32(mref.Packs),
		RepackUnixNano:   now.UnixNano(),
	}

	// The condemned ledger for the packs themselves. This is the entry
	// retention reads to keep a pack alive through the grace window for
	// readers still pinned to a generation that names it.
	sb.Condemned, err = condemnPacks(prev.Condemned, res.CondemnedPacks, listedPacks, now, graceOf(prev))
	if err != nil {
		return nil, nil, err
	}

	// The root-catalog hint is a hint, verified against the identity and
	// falling back to the index — but a hint pointing into a pack this
	// change deletes is a guaranteed wasted round trip, so it is either
	// moved with the bytes or dropped.
	sb.RootCatalogHint = movedRootHint(prev, condemn, moved)

	// Same budget as a seal's, and the same order: spend the optional
	// catalog list before failing (superblock.TrimCatalogs). A repack is
	// what a user is told to run when the pack list has grown too big, so
	// it is the one writer that must not refuse for a reason it could have
	// fixed itself.
	if n := sb.TrimCatalogs(); n > 0 {
		ui.Warn("repack: the parent's catalog list is {bytes} bytes, past its {budget}-byte share of the "+
			"superblock budget, so the repacked generation omits it; the next seal rebuilds every catalog",
			"bytes", n, "budget", int64(superblock.CatalogBudgetBytes))
	}

	// A repack rewrites the pack list wholesale, so it is the writer most
	// able to leave a generation stating its pack set two ways (it starts
	// from a copy of the parent, which may be the inline shape). Asked
	// before signing, so an invalid document is never signed at all.
	if err := sb.Validate(); err != nil {
		return nil, nil, fmt.Errorf("repack: %w", err)
	}
	if err := sb.Sign(o.SigningKey); err != nil {
		return nil, nil, fmt.Errorf("repack: %w", err)
	}
	raw, err := sb.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("repack: encode superblock: %w", err)
	}
	// A repack SHRINKS the pack list, so this should be the writer that
	// never trips — and it is checked precisely because of that: the
	// failure it guards is a flip past the mutable-object read cap, after
	// which nothing can read the volume, this tool included.
	if err := sb.CheckSize(len(raw)); err != nil {
		return nil, nil, fmt.Errorf("repack: %w", err)
	}
	return &sb, raw, nil
}

// graceOf is the window a document RECORDS — the one the ledgers it
// carries were promised, and the one this generation's rows inherit
// (a repack copies its parent's Params).
func graceOf(sb *superblock.Superblock) time.Duration {
	return sb.Params.Grace()
}

func refNames(refs []superblock.ManifestRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name)
	}
	return out
}

// condemnPacks and condemnRefs are this writer's calls into the ONE
// ledger rule (superblock.CarryCondemnedPacks / CarryCondemnedRefs).
//
// THE PACK LEDGER REFUSES; THE REF LEDGERS WARN, and the asymmetry is not
// an oversight. A dropped REF entry costs at most the gap between when the
// object was written and when it stopped being named, because retention
// keeps every hash-named object for the grace window from its own mtime —
// one checkpoint interval, in the steady state. A dropped PACK entry costs
// the whole window: a repack only condemns packs already older than the
// grace window, so the age guard has nothing left to give and the ledger is
// the only thing between that pack and the next sweep.
//
// trimToLedger makes this unreachable by pacing the plan before anything
// is rewritten. It is checked again here because the cost of being wrong is
// deleted data, and a refused repack costs only the rewriting: the ref
// never flips, and what was written is unreferenced garbage GC collects.
func condemnPacks(prev []superblock.CondemnedPack, dropped, listed []string,
	now time.Time, grace time.Duration) ([]superblock.CondemnedPack, error) {
	out, overflow := superblock.CarryCondemnedPacks(prev, dropped, listed, now, grace)
	if overflow > 0 {
		return nil, fmt.Errorf("repack: this generation would condemn %d packs more than the condemned "+
			"ledger's %d-byte share of the superblock can carry, and a dropped row is a pack the next gc "+
			"deletes while readers pinned to the generation before this one are still reading it; refusing "+
			"(the plan should have been paced to fit — see trimToLedger)",
			overflow, int64(superblock.CondemnedBudgetBytes))
	}
	return out, nil
}

func condemnRefs(prev []superblock.CondemnedRef, dropped, listed []string,
	now time.Time, grace time.Duration, what string) []superblock.CondemnedRef {
	out, overflow := superblock.CarryCondemnedRefs(prev, dropped, listed, now, grace)
	warnLedgerOverflow(what, overflow, grace)
	return out
}

func warnLedgerOverflow(what string, overflow int, grace time.Duration) {
	if overflow == 0 {
		return
	}
	ui.Warn("repack: the condemned-{what} ledger has filled its {cap}-byte share of the superblock, so "+
		"this generation dropped the {n} oldest rows; they are objects only a retired generation names, "+
		"and they may now be swept before the {grace} grace window ends",
		"what", what, "cap", int64(superblock.CondemnedBudgetBytes), "n", overflow, "grace", grace)
}

// movedRootHint follows the root catalog if this change moved it.
func movedRootHint(prev *superblock.Superblock, condemn map[string]bool, moved map[[32]byte]placement) *superblock.RootHint {
	h := prev.RootCatalogHint
	if h == nil || !condemn[h.Pack] {
		return h
	}
	if p, ok := moved[prev.RootCatalog]; ok {
		return &superblock.RootHint{Pack: p.pack, Off: p.off, Length: p.length}
	}
	return nil
}

func putManifest(ctx context.Context, obj pelicanobj.Store, b *manifest.Builder) (superblock.ManifestRef, error) {
	raw := b.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := obj.Put(ctx, manifest.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.ManifestRef{}, fmt.Errorf("repack: upload manifest: %w", err)
	}
	return superblock.ManifestRef{Name: name, Hash: hash, Size: int64(len(raw)), Packs: uint32(b.Len())}, nil
}

// putIndex uploads the segment this generation adds. It takes a BUILDER
// rather than the moved map because the segment has two sources now — the
// identities this run moved, and the live entries of any index it retired
// — and both are filled in before anything is written.
func putIndex(ctx context.Context, obj pelicanobj.Store, ib *mpi.Builder) (superblock.IndexRef, error) {
	raw := ib.Encode()
	hash := blake3.Sum256(raw)
	name := hex.EncodeToString(hash[:])
	if err := obj.Put(ctx, mpi.Dir+"/"+name, bytes.NewReader(raw)); err != nil {
		return superblock.IndexRef{}, fmt.Errorf("repack: upload index: %w", err)
	}
	return superblock.IndexRef{
		Name: name, Hash: hash, Size: int64(len(raw)),
		Entries: uint32(ib.Len()), Packs: uint32(ib.Packs()),
	}, nil
}
