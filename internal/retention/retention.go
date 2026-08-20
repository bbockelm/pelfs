// Package retention implements the v2 sweep (docs/design-packfs.md,
// "Retention and GC"): pure set arithmetic over verified superblocks.
//
// Retained packs are the union, over every branch head and every tag, of
// the generation's pack set — inline, or resolved through its manifest
// segments (manifest.Packs) — plus its condemned-ledger entries still
// inside the grace window. A pack is deleted only when it is (a) absent
// from that union AND (b) older than the grace window by the timestamp in
// its own name. Guard (b) is what makes the sweep safe to run against
// live writers with no coordination: a writer's new packs are always
// young, and a mid-sweep fork's closure is already retained.
//
// The DERIVED key spaces sweep under the same two rules. Multi-pack
// indexes (internal/mpi, named by a superblock's PackIndexes) and pack
// manifests (internal/manifest) are hash-named objects that no generation
// removes on its own: an aborted publish leaves an index nothing names,
// and consolidation will leave superseded ones behind. Both are listed
// alongside packs and swept from the same live set, so an object any live
// superblock names — head or tag — survives whatever its age.
//
// Guard (b) needs a different clock for them. A pack carries its creation
// time in its NAME; an index or manifest name is a content hash and
// carries no time at all, so the age comes from the object's mtime. That
// guard is doing real work here, not bookkeeping: publish uploads its
// index BEFORE it flips the ref, so there is a window in which a live
// index exists that no live superblock has named yet. An object whose
// time cannot be established is KEPT — keeping garbage costs bytes,
// deleting a live index costs a mount.
//
// "Live" means named by a branch HEAD, by a tag, or by one of the last
// Params.RetainK generations of a branch. The first two a sweep can
// enumerate; the third it cannot, because a retired generation is not
// addressable, only hashed — so lastk.go reconstructs those generations
// from the disaster-recovery superblock every seal buries in a pack, and
// that file is where the whole of that argument lives, including which
// failures fail closed and which are reported.
//
// Even with the window, an index or manifest that only an older
// generation still names — one consolidation merged away and the head
// therefore stopped listing — needs something to speak for it. The
// CONDEMNED LEDGERS do: publish records the refs it stopped listing, with
// the time it stopped (superblock.CondemnedRef), and this sweep counts a
// ledger entry as live when it is younger than the grace window OR when
// it was stamped inside the retain window — exactly as it does for a
// condemned pack. The second half of that test is what covers the one
// generation the backups cannot describe, the parent of a repack.
//
// THE LIMIT TO ADMIT, and it is a window rather than a fix: T_grace, not
// forever. Publish drops an entry once it ages out, so a reader pinned to
// a generation whose refs were condemned longer ago than that loses them
// after all. For an index the cost is bounded and known — it is DERIVED,
// so that reader falls back to pack trailers and is slow rather than
// broken. FOR A MANIFEST IT IS NOT: the manifest is that generation's
// pack list, so sweeping one leaves the generation unreadable and the
// packs it alone named go on the sweep after. Nothing addressable is ever
// harmed (the head, every tag and every generation inside the retain
// window name their own), and a workflow that needs a pin outliving both
// windows must TAG, which pins exactly for as long as the tag exists.
//
// The sweep fails closed: if any ref or tag cannot be fetched and
// verified, nothing is deleted — an unreadable superblock means the
// retained set is unknown, and guessing destroys data. An unreadable
// MANIFEST counts as an unreadable superblock, for the same reason: a
// generation whose pack set cannot be resolved retains nothing, and
// acting on that would delete a volume.
package retention

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// DefaultGrace is the T_grace fallback when no superblock states one.
const DefaultGrace = 72 * time.Hour

// Options configures GC.
type Options struct {
	Inner pelicanobj.Store // raw transport (listings, deletes)
	Refs  *refs.Store      // verified superblock access
	// Grace overrides the grace window; zero derives it from the largest
	// Params.TGraceSeconds across verified superblocks (DefaultGrace floor
	// — the window may only ever widen, never narrow, from options).
	Grace time.Duration
	// RetainK overrides how many generations of each branch stay in the
	// root set; zero takes each branch's own head's Params.RetainK. Unlike
	// Grace this may narrow as well as widen — lastk.go argues why the two
	// are not the same kind of window.
	RetainK uint32
	Delete  bool      // false = report only
	Now     time.Time // injectable clock (zero = time.Now())
}

// SpaceReport summarizes the sweep of one key space.
type SpaceReport struct {
	Retained       int
	Scanned        int
	SkippedYoung   int
	Candidates     int
	CandidateBytes int64
	Deleted        int
	CandidateNames []string // capped sample
}

// Report summarizes one sweep. The pack counters stay flat for the
// callers that already print them; the derived key spaces report through
// SpaceReport.
type Report struct {
	Branches       int
	Tags           int
	RetainedPacks  int
	ScannedPacks   int
	SkippedYoung   int
	Candidates     int
	CandidateBytes int64
	Deleted        int
	CandidateNames []string // capped sample

	// Indexes and Manifests cover the derived key spaces: multi-pack
	// indexes (mpi.Dir) and pack manifests (manifest.Dir). Their
	// SkippedYoung counts objects kept by the mtime guard, including any
	// whose time could not be read at all.
	Indexes   SpaceReport
	Manifests SpaceReport

	// Windows reports the last-K root set, one entry per branch: how many
	// generations Params.RetainK asked for and how many the sweep could
	// actually establish (lastk.go). A short window is the one outcome a
	// successful-looking report would otherwise hide.
	Windows []LastKReport
}

// candidate is one object the sweep may delete.
type candidate struct {
	name string
	size int64
}

// liveSet is what the verified superblocks name, per key space. Names are
// kept apart by space rather than pooled: they are different namespaces
// (a timestamped pack name, a hex content hash), and pooling them would
// let a name in one space retain an unrelated object in another.
type liveSet struct {
	packs     map[string]struct{}
	indexes   map[string]struct{}
	manifests map[string]struct{}
}

// GC computes (and with o.Delete, removes) unreferenced packs, indexes
// and manifests.
func GC(ctx context.Context, o Options) (*Report, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	rep := &Report{}
	// The last-K window costs pack-trailer reads, so it is resolved once
	// and shared with the pre-delete recompute below. Reusing it there is
	// safe in the only direction that matters: if the branch moved while
	// this sweep was scanning, the window this holds is the OLDER one,
	// which names at least as much as the new one does — and the
	// recompute exists to shrink the candidate list, never to grow it.
	win := newWindowCache()
	live, grace, err := retainedSet(ctx, o, rep, win)
	if err != nil {
		return nil, err
	}
	if o.Grace > grace {
		grace = o.Grace
	}
	rep.RetainedPacks = len(live.packs)
	rep.Indexes.Retained = len(live.indexes)
	rep.Manifests.Retained = len(live.manifests)
	cutoff := o.Now.Add(-grace)

	// Packs report through the flat fields callers already print. Copying
	// on the way out (rather than at the end) keeps the counts honest on
	// the error paths too, where a delete may have half finished.
	var packRep SpaceReport
	defer func() {
		rep.ScannedPacks, rep.SkippedYoung = packRep.Scanned, packRep.SkippedYoung
		rep.Candidates, rep.CandidateBytes = packRep.Candidates, packRep.CandidateBytes
		rep.Deleted, rep.CandidateNames = packRep.Deleted, packRep.CandidateNames
	}()

	packCands, err := scanPacks(ctx, o, live.packs, cutoff, &packRep)
	if err != nil {
		return rep, err
	}
	idxCands, err := scanHashNamed(ctx, o, mpi.Dir, live.indexes, cutoff, &rep.Indexes)
	if err != nil {
		return rep, err
	}
	manCands, err := scanHashNamed(ctx, o, manifest.Dir, live.manifests, cutoff, &rep.Manifests)
	if err != nil {
		return rep, err
	}

	// Narrow the race window: a fork or publish that landed while we were
	// scanning could have retained a candidate. Recompute against fresh
	// heads immediately before acting. (Not needed for correctness — the
	// age guard already covers coordination-free safety for young objects,
	// and fork sources are ref-reachable — but it is cheap.) One recompute
	// covers all three spaces, so the extra key spaces cost no extra ref
	// fetches.
	if len(packCands)+len(idxCands)+len(manCands) > 0 {
		fresh, _, err := retainedSet(ctx, o, &Report{}, win)
		if err != nil {
			return rep, fmt.Errorf("re-list before delete: %w", err)
		}
		packCands = dropRetained(packCands, fresh.packs)
		idxCands = dropRetained(idxCands, fresh.indexes)
		manCands = dropRetained(manCands, fresh.manifests)
	}

	if err := finish(ctx, o, packstore.PackDirKey, packCands, &packRep); err != nil {
		return rep, err
	}
	if err := finish(ctx, o, mpi.Dir, idxCands, &rep.Indexes); err != nil {
		return rep, err
	}
	if err := finish(ctx, o, manifest.Dir, manCands, &rep.Manifests); err != nil {
		return rep, err
	}
	return rep, nil
}

// scanPacks selects packs no live superblock names and whose own name
// dates them past the cutoff.
func scanPacks(ctx context.Context, o Options, live map[string]struct{}, cutoff time.Time, sp *SpaceReport) ([]candidate, error) {
	// An absent pack directory is an empty one, as for the derived spaces:
	// a volume can hold a signed generation and no packs, and a listing
	// that shows nothing can only make the sweep delete less.
	packs, err := listDir(ctx, o.Inner, packstore.PackDirKey)
	if err != nil {
		return nil, fmt.Errorf("list packs: %w", err)
	}
	var cands []candidate
	for _, p := range packs {
		if p.IsDir || !strings.HasPrefix(p.Name, "p-") {
			continue
		}
		sp.Scanned++
		if _, ok := live[p.Name]; ok {
			continue
		}
		created, ok := packstore.PackNameTime(p.Name)
		if !ok || created.After(cutoff) {
			// Unparseable names are treated as young forever: a pack we
			// cannot age is a pack we do not delete.
			sp.SkippedYoung++
			continue
		}
		cands = append(cands, candidate{name: p.Name, size: p.Size})
	}
	return cands, nil
}

// scanHashNamed selects objects in a hash-named key space (indexes,
// manifests) that no live superblock names and that are older than the
// cutoff by their mtime. A missing directory is an empty one: neither
// space exists until something writes to it.
func scanHashNamed(ctx context.Context, o Options, dir string, live map[string]struct{}, cutoff time.Time, sp *SpaceReport) ([]candidate, error) {
	entries, err := listDir(ctx, o.Inner, dir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var cands []candidate
	for _, e := range entries {
		if e.IsDir || !isHashName(e.Name) {
			// Only content-hash names are ours to delete. A future naming
			// scheme (tiers, say) lands here as an unrecognized name and
			// is kept, which is the safe direction to be wrong in.
			continue
		}
		sp.Scanned++
		if _, ok := live[e.Name]; ok {
			continue
		}
		written, ok := objectTime(ctx, o.Inner, dir+"/"+e.Name, e.Mtime)
		if !ok || written.After(cutoff) {
			// No time, or too young: keep. The window between "publish
			// uploaded its index" and "publish flipped the ref" is exactly
			// a live object no superblock names yet, and it is only the
			// age guard that saves it.
			sp.SkippedYoung++
			continue
		}
		cands = append(cands, candidate{name: e.Name, size: e.Size})
	}
	return cands, nil
}

// objectTime reports when an object was written. It prefers a HEAD to the
// listing's mtime because a listing may omit the property entirely (the
// PROPFIND response is the server's choice, not ours) and because a HEAD
// answers about the object rather than about a directory listing that may
// be cached; it falls back to the listing when the HEAD gives nothing.
// The bool is false when neither yields a usable time, which the callers
// read as "keep it".
//
// The round trip is only spent on objects no live superblock names, so it
// scales with garbage rather than with volume size — which is why the age
// guard can afford to be per-object here while packs read theirs out of a
// name.
func objectTime(ctx context.Context, inner pelicanobj.Store, key string, listed time.Time) (time.Time, bool) {
	if ki, err := inner.StatKey(ctx, key); err == nil && !ki.Mtime.IsZero() {
		return ki.Mtime, true
	}
	if !listed.IsZero() {
		return listed, true
	}
	return time.Time{}, false
}

// isHashName reports whether a name is a hex content hash, which is how
// publish names index and manifest objects.
func isHashName(name string) bool {
	if len(name) < 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// dropRetained removes candidates a freshly read superblock now names.
func dropRetained(cands []candidate, live map[string]struct{}) []candidate {
	kept := cands[:0]
	for _, c := range cands {
		if _, ok := live[c.name]; !ok {
			kept = append(kept, c)
		}
	}
	return kept
}

// finish tallies the surviving candidates and, with o.Delete, removes
// them.
func finish(ctx context.Context, o Options, dir string, cands []candidate, sp *SpaceReport) error {
	sp.Candidates = len(cands)
	for _, c := range cands {
		sp.CandidateBytes += c.size
	}
	for _, c := range cands {
		if len(sp.CandidateNames) < 20 {
			sp.CandidateNames = append(sp.CandidateNames, c.name)
		}
		if o.Delete {
			if err := o.Inner.Delete(ctx, dir+"/"+c.name); err != nil {
				return fmt.Errorf("delete %s/%s: %w", dir, c.name, err)
			}
			sp.Deleted++
		}
	}
	return nil
}

// retainedSet unions pack lists, grace-young condemned entries and index
// refs across every verified branch head and tag, returning the live set
// and the largest stated grace window. Any unverifiable superblock is a
// hard error.
func retainedSet(ctx context.Context, o Options, rep *Report, win *windowCache) (*liveSet, time.Duration, error) {
	live := &liveSet{
		packs:     make(map[string]struct{}),
		indexes:   make(map[string]struct{}),
		manifests: make(map[string]struct{}),
	}
	grace := DefaultGrace

	// absorb unions one generation's objects into the live set.
	//
	// sinceUnixNano is the retain window's floor: a condemned-ledger row
	// stamped at or after it was dropped by a generation INSIDE the window,
	// so a generation still in the window names the object and it stays
	// live whatever its age. Zero disables it, which is what a tag gets —
	// a tag is one frozen generation, not a window, so its rows follow the
	// grace rule alone.
	//
	// This is the half of the rule the backups cannot supply, and it is
	// what makes a REPACK's parent readable. A repack writes no superblock
	// backup, so nothing describes the generation it grew from; what does
	// exist is the repack's own ledger, which names every manifest, index
	// and pack it stopped listing. Retaining those rows for as long as the
	// window covers the generation that named them is the same statement
	// the backups make, arrived at from the other side.
	absorb := func(sb *superblock.Superblock, sinceUnixNano int64) error {
		// The packs a generation names, from whichever shape it uses. A
		// manifest that will not read is a hard error, not an empty pack
		// set: this sweep DELETES on the strength of this answer, so an
		// unreadable manifest has exactly the standing of an unverifiable
		// superblock — the retained set is unknown, and guessing destroys
		// data.
		packs, err := manifest.Packs(ctx, o.Inner, sb)
		if err != nil {
			return err
		}
		for _, pe := range packs {
			live.packs[pe.Name] = struct{}{}
		}
		// Every generation still reachable — the head AND every tag —
		// keeps its indexes, so an index the head has consolidated past
		// stays alive as long as something still names it.
		for _, ix := range sb.PackIndexes {
			live.indexes[ix.Name] = struct{}{}
		}
		// And its manifests, for a stronger reason than an index's. An
		// index is derived, so sweeping a live one costs speed; a manifest
		// IS the generation's pack list, so sweeping one a live generation
		// names would leave that generation unreadable and its packs
		// unenumerable — every pack it alone referenced would go on the
		// next sweep.
		for _, mf := range sb.Manifests {
			live.manifests[mf.Name] = struct{}{}
		}
		if g := time.Duration(sb.Params.TGraceSeconds) * time.Second; g > grace {
			grace = g
		}
		inWindow := func(condemnedAtUnix int64) bool {
			if o.Now.Sub(time.Unix(condemnedAtUnix, 0)) < grace {
				return true
			}
			return sinceUnixNano != 0 && condemnedAtUnix >= sinceUnixNano/int64(time.Second)
		}
		for _, c := range sb.Condemned {
			if inWindow(c.CondemnedAtUnix) {
				live.packs[c.Name] = struct{}{}
			}
		}
		// And the same ledger for the derived key spaces. A condemned ref
		// is LIVE inside the window even though no live superblock lists it:
		// consolidation merged it away, and the generation that still names
		// it is retired and therefore not enumerable, so this entry is the
		// only thing that speaks for the object. Publish carries entries
		// forward until they age past the window and then drops them, so an
		// aged-out ref simply stops appearing here and sweeps normally.
		//
		// A condemned MANIFEST needs no matching rescue of the packs it
		// names, and that is a property of consolidation rather than luck:
		// a merge is a union, so every pack a superseded segment named is
		// named by the segment that replaced it, which a live superblock
		// lists. If a future repack ever TRIMS a segment instead of merging
		// it, the trimmed packs must go into sb.Condemned in the same
		// change.
		for _, c := range sb.CondemnedIndexes {
			if inWindow(c.CondemnedAtUnix) {
				live.indexes[c.Name] = struct{}{}
			}
		}
		for _, c := range sb.CondemnedManifests {
			if inWindow(c.CondemnedAtUnix) {
				live.manifests[c.Name] = struct{}{}
			}
		}
		return nil
	}

	branches, err := listNames(ctx, o.Inner, refs.RefDirKey)
	if err != nil {
		return nil, 0, fmt.Errorf("list refs: %w", err)
	}
	for _, b := range branches {
		f, err := o.Refs.Fetch(ctx, b)
		if err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): branch %s: %w", b, err)
		}
		// The K-1 generations below the head (lastk.go) are resolved FIRST,
		// because the oldest of them dates the window — and the head's own
		// ledger has to be read against that date, not only against the
		// grace window.
		w, err := win.get(ctx, o, b, f.Superblock)
		if err != nil {
			return nil, 0, err
		}
		since := windowFloor(w.roots)
		if err := absorb(f.Superblock, since); err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): branch %s: %w", b, err)
		}
		rep.Branches++

		// And the generations themselves, as roots exactly as the head is —
		// the same absorb, so a retired generation inside the window keeps
		// its packs, its manifests and its indexes on identical terms. The
		// only differences are where the document came from and what an
		// unreadable one means.
		lk := w.rep.clone(b)
		for _, sb := range w.roots {
			// A window root DESCRIBES ITS PARENT (lastk.go), so the
			// generation at stake is one below the document's own.
			gen := sb.Generation - 1
			if err := absorb(sb, since); err != nil {
				if isAbsent(err) {
					// Its manifest is gone, so that generation was already
					// unreadable before this sweep started. Failing closed
					// would protect nothing and would stop the volume
					// reclaiming anything for as long as the generation sat
					// inside the window.
					lk.Generations--
					lk.Unresolved = append(lk.Unresolved, gen)
					continue
				}
				return nil, 0, fmt.Errorf("gc aborted (fail closed): branch %s, generation %d inside the "+
					"retain-%d window: %w", b, gen, lk.K, err)
			}
		}
		sort.Slice(lk.Unresolved, func(i, j int) bool { return lk.Unresolved[i] > lk.Unresolved[j] })
		warnUnresolved(b, &lk)
		rep.Windows = append(rep.Windows, lk)
	}
	tags, err := listNames(ctx, o.Inner, refs.TagDirKey)
	if err != nil {
		return nil, 0, fmt.Errorf("list tags: %w", err)
	}
	for _, tname := range tags {
		sb, _, err := o.Refs.FetchTag(ctx, tname)
		if err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): tag %s: %w", tname, err)
		}
		// Zero floor: a tag is one frozen generation, not a window, so its
		// ledger rows follow the grace rule and nothing else.
		if err := absorb(sb, 0); err != nil {
			return nil, 0, fmt.Errorf("gc aborted (fail closed): tag %s: %w", tname, err)
		}
		rep.Tags++
	}
	if rep.Branches+rep.Tags == 0 {
		return nil, 0, fmt.Errorf("gc aborted: no refs or tags found (a v2 volume always has at least one branch; refusing to treat every pack as garbage)")
	}
	return live, grace, nil
}

// listDir lists a key-space directory, treating an absent one as empty:
// the derived key spaces do not exist until something writes to them.
func listDir(ctx context.Context, inner pelicanobj.Store, dir string) ([]pelicanobj.DirEntry, error) {
	entries, err := inner.ListDir(ctx, dir)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not exist") {
			return nil, nil
		}
		return nil, err
	}
	return entries, nil
}

func listNames(ctx context.Context, inner pelicanobj.Store, dir string) ([]string, error) {
	entries, err := listDir(ctx, inner, dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir || strings.HasSuffix(e.Name, ".tmp") {
			continue
		}
		names = append(names, e.Name)
	}
	return names, nil
}
