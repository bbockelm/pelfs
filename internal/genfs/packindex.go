package genfs

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The location layer, resolved on demand.
//
// A catalog names an entry's IDENTITY; a pack trailer maps that identity to
// an offset and a length inside one pack. The two are not duplicates, but
// the trailer's job is narrow: under the whole-pack policy (packfetch.go)
// the offset is always read out of a local copy of the pack, so the only
// question a trailer answers across the network is WHICH pack — and once
// that pack is local, its trailer came down with it.
//
// So a mount does not need the generation's trailers. It needs the root
// catalog, which lives in exactly one of them. Indexing every pack at Open
// was one round trip per pack before the mount could answer anything, and
// a generation has one pack per cut size however large it grows — the cost
// scaled with the volume rather than with the question.
//
// Probing runs NEWEST PACK FIRST. Publish appends this generation's packs
// after the ones it carried forward and writes the root catalog last, so
// the pack a cold mount is looking for is normally the final entry of the
// list and the first one probed.
//
// One rule is not negotiable: "present in no listed pack" may only be
// returned once EVERY listed pack has been indexed. That answer fails a
// read, and a caller like fsck or a seal's carry-forward check would read
// it as "this content is gone" — an incomplete map must never be able to
// say it.
//
// Ahead of the probing sits the generation's MULTI-PACK INDEX (hints,
// below), which answers "which pack" for many packs at once and turns the
// bet into a fact for everything it covers.
type packIndex struct {
	fs    *FS
	packs []superblock.PackEntry

	// hints is the generation's multi-pack index set — nil when the
	// superblock lists none, or when this build has not been given one.
	// Read-only once set, which is before the FS is handed to anyone; the
	// index objects behind it are fetched lazily and never whole (mpi's
	// Reader), so naming them costs nothing.
	//
	// It is a HINT in the same sense as the root-catalog hint: an index is
	// derived and may be stale, so a name it produces is followed to a
	// pack TRAILER, which is what actually confirms the identity. A wrong
	// or unverifiable answer costs the ordinary fallback below and can
	// never cost a wrong read or a failed mount.
	hints *mpi.Hints
	// warmed loads every tier's header at once on the first consult, so a
	// generation with several indexes costs one round trip of latency
	// rather than one per tier.
	warmed sync.Once

	// loadMu serializes the trailer work, so concurrent misses index a
	// pack once between them rather than once each. localMerged is under
	// it: that sweep is worth doing once, and a read for content that
	// genuinely is not here would otherwise re-walk every local trailer to
	// rediscover that on every attempt.
	loadMu      sync.Mutex
	localMerged bool

	mu    sync.Mutex
	byKey map[string]packLoc
	// keysOf records which keys each pack contributed to byKey, and its
	// key set IS the set of packs folded in — the old separate `indexed`
	// map said the same thing twice and could disagree with the map after
	// an eviction.
	keysOf map[string][]string
	// order is the packs in the order they were folded in, oldest first:
	// the eviction queue.
	order  []string
	listed map[string]superblock.PackEntry
	// unbounded is set by the callers that ask for the WHOLE location map
	// and by nobody else. See hotCapEntries.
	unbounded bool
}

// hotCapEntries bounds byKey, and the unit of both insertion and eviction
// is a PACK rather than a key.
//
// The map was unbounded, and its size is set by what a mount happens to
// read: one trailer's worth of locations per pack touched, forever. At a
// hundred million objects a mount that resolved everything held 13.4 GB of
// it — the largest resident structure in the tree, holding a fact (which
// pack) that is re-derivable from a local file in microseconds.
//
// So it is a CACHE now, and the things that made it not one are gone.
// Nothing answers "absent" out of it: every absence comes from a sweep
// that examined trailer entries directly, so an evicted key costs a
// re-derivation and never a wrong answer. And evicting a whole pack at a
// time keeps the map's accounting exact — keysOf names the packs folded
// in, so dropping one drops its claim to be folded in with it.
//
// 131,072 locations is about 20 MB, and at the shipped cut size that is
// the entries of roughly 250 packs: far more than the working set of any
// sequential read, which is what the whole-pack policy makes the common
// case.
//
// FIFO, not LRU. The whole-pack policy means locations arrive in bursts
// and are consumed in bursts, so recency at the KEY level says almost
// nothing; the pack a mount finished with is the right victim, and
// tracking per-key recency would cost more than the eviction saves.
//
// A var only so that tests can drive eviction without a fixture the size
// of the cap. Nothing in the tree writes it.
var hotCapEntries = 1 << 17

// newPackIndex builds the empty index for a generation's RESOLVED pack
// list — the rows the generation names, whether it stated them inline or
// through a manifest (manifest.Packs). It makes no requests: the rows
// alone give every pack's signed size, which is all the whole-pack cache
// needs to hold a local copy to account.
func newPackIndex(fs *FS, packs []superblock.PackEntry) *packIndex {
	x := &packIndex{
		fs:     fs,
		packs:  packs,
		byKey:  make(map[string]packLoc),
		keysOf: make(map[string][]string),
		listed: make(map[string]superblock.PackEntry, len(packs)),
	}
	for _, pe := range packs {
		x.listed[pe.Name] = pe
	}
	return x
}

// size reports a pack's SIGNED length — the only whole-object check a
// cached copy can be held to.
func (x *packIndex) bytes() int64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	var total int64
	for _, pe := range x.packs {
		total += pe.Size
	}
	return total
}

func (x *packIndex) size(pack string) int64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.listed[pack].Size
}

// entry returns the signed pack-list row for a pack name, and whether this
// generation lists it at all. Anything naming a pack from OUTSIDE the
// signed list — an index, a hint, a cache directory — has to come through
// here: the row carries the trailer hash and the size every later check is
// made against, and a name with no row is a name nothing authorizes
// reading.
func (x *packIndex) entry(pack string) (superblock.PackEntry, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	pe, ok := x.listed[pack]
	return pe, ok
}

// lookup answers out of the hot cache alone. A miss here means "not
// cached", never "not present" — the two were the same answer while the
// map held everything, and telling them apart is what lets it stop.
func (x *packIndex) lookup(key string) (packLoc, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	loc, ok := x.byKey[key]
	return loc, ok
}

// merge folds one pack's trailer into the map and reports where `want`
// sits IF this pack holds it — from the entries themselves, not from the
// map, so an answer cannot be lost to the eviction the merge may trigger.
// A want of "" asks nothing.
//
// Identical content dedups at publish, so a key appearing in several packs
// names the same bytes and either copy is a correct read. Which one wins
// is decided by the pack NAME, which begins with a zero-padded creation
// stamp: the newest placement, the one a retention sweep is least likely
// to have taken. That used to be a property of the ORDER callers merged
// in, which meant a concurrent sweep had to collect every trailer before
// merging any — len(packs) parsed trailers resident at once, which is
// gigabytes at target scale. Deciding it by name instead lets each worker
// merge and drop its trailer as it goes.
func (x *packIndex) merge(pe superblock.PackEntry, entries []packstore.PackEntry, want string) (packLoc, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	var (
		found packLoc
		hit   bool
	)
	_, folded := x.keysOf[pe.Name]
	if !folded {
		x.keysOf[pe.Name] = nil
		x.order = append(x.order, pe.Name)
	}
	for _, e := range entries {
		loc := packLoc{pack: pe.Name, off: e.Off, length: e.Length}
		if want != "" && e.Key == want {
			found, hit = loc, true
		}
		if folded {
			continue
		}
		if cur, dup := x.byKey[e.Key]; dup && cur.pack >= pe.Name {
			continue
		}
		x.byKey[e.Key] = loc
		// Recorded against this pack even when it took the key from
		// another: eviction deletes a key only when the entry still names
		// the pack being evicted, so both claims are safe and neither
		// stranded.
		x.keysOf[pe.Name] = append(x.keysOf[pe.Name], e.Key)
	}
	x.evictLocked()
	return found, hit
}

// evictLocked drops whole packs, oldest folded first, until the map is
// back within its cap. Callers hold mu.
//
// One pack is always kept however large its trailer: a cap that could
// empty the map would make the merge that just ran pointless, and the
// caller has the location it came for either way.
func (x *packIndex) evictLocked() {
	if x.unbounded {
		return
	}
	for len(x.byKey) > hotCapEntries && len(x.order) > 1 {
		victim := x.order[0]
		copy(x.order, x.order[1:])
		x.order = x.order[:len(x.order)-1]
		for _, k := range x.keysOf[victim] {
			// Only if the entry still belongs to the victim: a later pack
			// may have taken the key, and that pack records its own claim.
			if loc, ok := x.byKey[k]; ok && loc.pack == victim {
				delete(x.byKey, k)
			}
		}
		delete(x.keysOf, victim)
	}
}

// isIndexed reports whether a pack's trailer is folded into the map right
// now. It can go back to false: that is the point of the cap.
func (x *packIndex) isIndexed(pack string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	_, ok := x.keysOf[pack]
	return ok
}

// indexedAll reports whether every listed pack is folded in — the one
// condition under which a miss in the map means the generation genuinely
// does not hold the key.
//
// It is derived rather than remembered. A `complete` flag was true until
// something set it false, and nothing did when a pack was evicted; asking
// the map is exact by construction and cannot drift.
func (x *packIndex) indexedAll() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.keysOf) == len(x.listed)
}

// holdEverything lifts the cap for the callers that have asked for the
// WHOLE location map (all, below). It is one-way: a caller that needed the
// generation's every location once will need it again, and re-fetching
// every trailer to rebuild what was just dropped is the cost the cap
// exists to avoid, not one to introduce.
func (x *packIndex) holdEverything() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.unbounded = true
}

// lazyProbeBudget is how many packs a miss probes one at a time before it
// gives up on guessing and resolves the rest at once.
//
// Probing newest-first is a bet on recency, and it is a good bet for the
// entries a mount asks for first — the root catalog, and anything the last
// publish wrote. It is a bad bet for a chunk in an old pack, where a
// serial walk backwards would cost a round trip per pack it passes. The
// budget is what keeps the bet cheap when it is wrong: past it, the whole
// map is resolved CONCURRENTLY, which is the same bytes the old eager
// index moved and eight times less waiting than continuing to walk.
const lazyProbeBudget = 4

// locate resolves one entry identity, indexing packs on demand until it
// finds one that holds it.
//
// The order is by cost, and each step answers out of the ENTRIES it just
// examined rather than out of the map, so nothing here can be lost to an
// eviction that the same step's merge triggered:
//
//  1. the hot cache;
//  2. trailers already on disk, which cost no requests;
//  3. the multi-pack index, which names the pack outright — one trailer
//     fetch, and the step this whole structure exists for;
//  4. a short backwards walk of the pack list, betting on recency;
//  5. every listed pack, which is the answer of last resort and the only
//     thing that may say "not present".
//
// A trailer that will not load is remembered as an ERROR, not as an
// absence: reporting "not present" for a pack that could not be read would
// confuse a transport failure with missing content, and only one of those
// means anything is actually gone.
func (x *packIndex) locate(ctx context.Context, key string) (packLoc, error) {
	if loc, ok := x.lookup(key); ok {
		return loc, nil
	}
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	if loc, ok := x.lookup(key); ok {
		return loc, nil
	}
	// Trailers already on disk cost nothing to fold in, and a mount that
	// has read this volume before has most of them. Doing it first means a
	// remount resolves out of local state instead of guessing its way
	// backwards through the pack list over the network.
	if loc, ok := x.mergeLocal(key); ok {
		return loc, nil
	}
	// The multi-pack index, before any guessing: it names the pack outright
	// for everything it covers, which is one trailer fetch instead of a
	// walk backwards through the pack list and, past the budget, instead of
	// the whole generation.
	if loc, ok := x.probeHints(ctx, key); ok {
		return loc, nil
	}
	var failed error
	for i, budget := len(x.packs)-1, lazyProbeBudget; i >= 0 && budget > 0; i-- {
		pe := x.packs[i]
		if x.isIndexed(pe.Name) {
			continue
		}
		budget--
		entries, err := x.fs.trailerEntries(ctx, pe)
		if err != nil {
			if failed == nil {
				failed = fmt.Errorf("genfs: index pack %s: %w", pe.Name, err)
			}
			continue
		}
		if loc, ok := x.merge(pe, entries, key); ok {
			return loc, nil
		}
	}
	loc, ok, err := x.indexAll(ctx, key)
	if ok {
		return loc, nil
	}
	if err != nil {
		return packLoc{}, err
	}
	if failed != nil {
		return packLoc{}, failed
	}
	return packLoc{}, fmt.Errorf("genfs: %s not present in any listed pack", key)
}

// locatePlaced is locate with the two expensive steps removed: the
// backwards walk of the pack list and the sweep of every trailer.
//
// It exists for the caller that is asking a DIFFERENT question. locate
// asks "where are the bytes I am about to read", and for that question a
// wrong answer is a failed read, so it is worth any number of round trips
// to be sure — including the sweep, which is the only step entitled to say
// "present in no listed pack". This asks "would storing these bytes again
// be a waste", and for THAT question a miss costs one duplicate upload and
// nothing else. Paying a trailer fetch per pack to avoid one is the wrong
// trade by orders of magnitude, and at the hundred-million-object target it
// is the difference between a lookup and a whole-generation sweep.
//
// So the answer is three-valued and only two of the values are returned: a
// location, or "not cheaply". It never means "absent", and no caller may
// read it that way.
func (x *packIndex) locatePlaced(ctx context.Context, key string) (packLoc, bool) {
	if loc, ok := x.lookup(key); ok {
		return loc, true
	}
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	if loc, ok := x.lookup(key); ok {
		return loc, true
	}
	// Trailers already on disk, which cost no requests. For a session
	// publishing into a volume it has read or written before this is the
	// whole answer: the packs of the generation being built on are in the
	// local pack cache, so the identities of everything they hold are one
	// local read away and the index is never consulted at all.
	if loc, ok := x.mergeLocal(key); ok {
		return loc, true
	}
	return x.probeHints(ctx, key)
}

// holds answers PRESENCE — is key in some pack this generation lists —
// without resolving where, and it is the third question this file
// answers. locate asks "where are the bytes I am about to read", which
// must be exact and is worth a sweep. locatePlaced asks "would storing
// these bytes again be a waste", which may answer "not cheaply". This one
// must never say "absent" about content that is there, exactly like
// locate, but has no use for the extent — so it is entitled to accept
// evidence that names a pack without opening it.
//
// The caller is ContentOf, the seal's carry-forward check, and getting
// this question wrong was the headline cost of a metadata-only seal: it
// used to ask for the WHOLE location map, one trailer fetch per pack in
// the volume, so renaming a file downloaded tens of megabytes of trailers
// that nothing then read. The map is a means, not the question.
//
// The steps, cheapest first, and each of them is a sound YES:
//
//   - the hot cache, where a location was already resolved and verified;
//   - trailers already on disk, which cost no requests;
//   - the multi-pack index, which names the pack outright.
//
// The index step is where this differs from locate, and the difference is
// deliberate — and it is the one part of this worth arguing with, so the
// argument is written out.
//
// locate fetches the named pack's trailer, because it needs the extent
// and only the trailer carries it. Presence does not, so this stops at
// the name. The name is trustworthy: the index is fetched under the hash
// the SIGNED superblock records (mpi.Fetch), and the name it produces is
// held against the SIGNED pack list (entry), so what an index hit means
// is "the generation's own record of what it packed says this identity
// went into a pack this generation still lists".
//
// WHAT IS GIVEN UP is the trailer's confirmation of the FULL identity. An
// mpi entry keys on 12 bytes, not 32, on the stated reasoning that a
// truncated key can only produce a false positive because the caller
// checks what it finds (internal/mpi) — and this caller, uniquely, does
// not go and look. So a 96-bit prefix collision reads as presence here
// where every other consumer would catch it. Two things make that the
// right trade rather than a hole:
//
//   - A false positive is only reachable on a volume that is ALREADY
//     damaged. If the identity is genuinely stored, the answer was right
//     whatever route produced it; the collision only matters when the real
//     chunk is missing, and then it needs a ~10^-13 event on top.
//   - The alternative is a trailer fetch per pack the reused content
//     touches, which for a volume of a few large files in one catalog is
//     every pack in the volume — the exact cost being removed. A check
//     whose price is the volume is not a check anyone can afford to keep
//     turned on.
//
// And the chunk is verified against its identity when it is READ, which
// is where a missing chunk surfaces in any case. This is a standing
// consistency check on the base generation, not the thing that makes the
// format sound.
//
// The other failure this must not have — a pack retention has SWEPT
// reading as live — is not affected, because it is settled by the pack
// list rather than by the key: hintsName ignores any name the generation
// no longer lists, and an identity with no listed name falls through to
// the sweep. TestContentOfStillReportsASweptPackAsAbsent pins it.
//
// Filed as KL-21 in docs/known-issues.md.
//
// Only when nothing cheap can confirm it does this fall through to the
// sweep — because a NO is the answer that costs a re-upload or a refused
// seal, and no cache is entitled to produce one. So the expensive path
// survives for the case it was built for (a volume with no index, or one
// whose index missed a generation) and stops being the price of every
// seal on a healthy one.
func (x *packIndex) holds(ctx context.Context, key string) (bool, error) {
	if _, ok := x.lookup(key); ok {
		return true, nil
	}
	if x.holdsCheaply(ctx, key) {
		return true, nil
	}
	// Nothing that costs a round trip or less could confirm it, and only a
	// sweep may say "absent".
	if err := x.all(ctx); err != nil {
		return false, err
	}
	_, ok := x.lookup(key)
	return ok, nil
}

// holdsCheaply is holds without the sweep: a YES, or "could not say".
// Split out so the sweep runs with loadMu free, which all() takes itself.
func (x *packIndex) holdsCheaply(ctx context.Context, key string) bool {
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	if _, ok := x.lookup(key); ok {
		return true
	}
	if _, ok := x.mergeLocal(key); ok {
		return true
	}
	return x.hintsName(ctx, key)
}

// hintsName reports whether the generation's multi-pack index places key
// in a pack this generation still lists. It is probeHints with the
// trailer fetch removed, for the caller that wants the pack's NAME rather
// than the extent inside it — and therefore, unlike probeHints, it
// answers on the index's 12-byte key without confirming the full 32. See
// holds for why that is the trade taken; nothing else may use this.
func (x *packIndex) hintsName(ctx context.Context, key string) bool {
	if x.hints == nil {
		return false
	}
	var id [32]byte
	if len(key) != 2*len(id) {
		return false
	}
	if _, err := hex.Decode(id[:], []byte(key)); err != nil {
		return false
	}
	x.warmed.Do(func() { x.hints.Warm(ctx) })
	names, ok := x.hints.Lookup(ctx, id)
	if !ok {
		return false
	}
	for _, name := range names {
		// A name with no row in the signed pack list is a name nothing
		// authorizes reading, and a pack retention has already swept is
		// exactly what this check exists to catch.
		if _, listed := x.entry(name); listed {
			return true
		}
	}
	return false
}

// Placement is where a chunk this generation already holds is stored: the
// pack, the extent inside it, and nothing about how to decode it. Alg and
// key id are not here because a pack trailer does not record them — they
// live in the chunkref that names the chunk, and a writer reusing an entry
// has to supply them itself (see memtable's reuse, and dedupSound below).
type Placement struct {
	Pack   string
	Off    int64
	Length int64 // the STORED length: what a reader will range-read
}

// Placed reports where a chunk this generation already holds is stored,
// and nothing about a chunk it does not.
//
// It is the cross-generation dedup lookup, and every property that makes
// it safe comes from machinery the read path already has. The name a
// multi-pack index produces is held against the SIGNED pack list
// (packIndex.entry), so a stale or hostile index cannot name a pack this
// generation does not list; the full 32-byte identity is then confirmed
// against that pack's own trailer, whose hash the pack list signs, so a
// truncated-key collision cannot produce a hit. A hit therefore means
// exactly: this identity is stored, in a pack THIS generation lists, and
// the pack's own signed-for trailer says so.
//
// The stored length is the trailer's, which is the authority: it is what a
// reader will range-read, and a chunkref claiming any other number sends a
// reader to read an extent that is not the one that is there.
//
// A miss is never "absent". See locatePlaced.
func (fs *FS) Placed(ctx context.Context, id chunkid.Identity) (Placement, bool) {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	if !fs.dedupSound() {
		return Placement{}, false
	}
	loc, ok := fs.packIndex.locatePlaced(ctx, id.Hex())
	if !ok || loc.length <= 0 || loc.pack == "" {
		return Placement{}, false
	}
	return Placement{Pack: loc.pack, Off: loc.off, Length: loc.length}, true
}

// dedupSound reports whether reusing an entry this generation already
// stores is sound for a WRITER, which is a stronger question than whether
// reading it is.
//
// A reader takes a chunkref's alg and key id from the row it is following.
// A writer reusing an existing entry has to SUPPLY those, and the only
// key id it can supply is the one it is itself writing under. That is
// correct because a volume has exactly one data-encryption key for its
// lifetime — `pelfs volume create` mints it (cmd/pelfs/volume.go) and every
// generation carries the key table forward verbatim; nothing in the tree
// adds a second DEK. Rather than trust that from a distance, this checks
// it: a key table naming more than one DEK is a volume where an entry's
// key id is not derivable from the writer's own, and on such a volume
// there is no cross-generation dedup rather than a wrong row.
//
// Confidentiality is not at issue. Identity is keyed BLAKE3 over the
// PLAINTEXT on an encrypted volume (chunkid), so a hit means the writer
// already holds the identity key and the plaintext; it learns nothing it
// did not bring. Nor is the nonce: reusing an entry reuses the ciphertext
// and the nonce TOGETHER, which is not nonce reuse — nothing is encrypted
// a second time.
func (fs *FS) dedupSound() bool {
	deks := 0
	for _, ke := range fs.sb.KeyTable {
		if ke.Kind == superblock.KeyKindDEK {
			deks++
		}
	}
	return deks <= 1
}

// loadHints attaches the indexes a generation lists. It must be called
// before the index is shared, and it is the only writer of x.hints.
//
// IT MAKES NO REQUESTS, which is the whole change. It used to fetch every
// listed index whole and hold it: 1.6 GB moved and 1.6 GB resident at a
// hundred million objects, before the mount answered anything, for a
// structure the ordinary mount then never consults — the superblock's
// root-catalog hint resolves the first question, and everything after it
// comes out of the trailer of a pack the mount has already pulled.
//
// So the indexes are named here and read when something asks (mpi.Reader):
// the header and samples once, a ~64 KB window per lookup, and nothing at
// all for the mount that never has a miss the trailers cannot answer.
//
// A failure remains invisible on purpose. An index is derived, the
// trailers still answer every question it would have, so a generation
// whose index is missing, truncated, or hashes wrong mounts and serves —
// it just pays the fallback.
func (x *packIndex) loadHints(refs []superblock.IndexRef) {
	x.hints = mpi.NewHints(x.fs.inner, refs)
}

// probeHints asks the multi-pack index which pack holds key and indexes
// the packs it names. Callers hold loadMu.
//
// An answer is a CANDIDATE LIST, not an answer: more than one name is a
// truncated-key collision (12 bytes of identity, so a false positive is
// possible and a false negative is not), so each is tried until the pack's
// own trailer confirms the full identity. Three ways it can be wrong, all
// of which fall through to the ordinary probing:
//
//   - a pack this generation does not list, which the signed pack list
//     rejects before anything is fetched;
//   - a listed pack that turns out not to hold the identity, which is
//     either the collision case or an index a repack outdated;
//   - a trailer that will not load, which is a transport failure and is
//     the caller's problem to report, not this function's to hide.
//
// The trailers merged along the way are kept either way: they were fetched
// and verified, so a wrong hint at least leaves the map larger than it
// found it.
//
// A pack already folded in is probed AGAIN rather than skipped. That looks
// wasteful and is the opposite: the map is a bounded cache now, so
// "already folded in" and "still holds this key" are different statements,
// and the trailer that answers the second one is a local file this mount
// wrote the first time round. Skipping it would mean an evicted key fell
// through to the pack-list walk and then to the sweep — the exact cost
// this step exists to remove.
func (x *packIndex) probeHints(ctx context.Context, key string) (packLoc, bool) {
	if x.hints == nil {
		return packLoc{}, false
	}
	var id [32]byte
	if len(key) != 2*len(id) {
		return packLoc{}, false
	}
	if _, err := hex.Decode(id[:], []byte(key)); err != nil {
		return packLoc{}, false
	}
	// Every tier's header at once, on the first consult: a lookup that may
	// have to ask several indexes should cost one round trip of latency,
	// not one per tier.
	x.warmed.Do(func() { x.hints.Warm(ctx) })
	names, ok := x.hints.Lookup(ctx, id)
	if !ok {
		return packLoc{}, false
	}
	for _, name := range names {
		pe, listed := x.entry(name)
		if !listed {
			continue
		}
		entries, err := x.fs.trailerEntries(ctx, pe)
		if err != nil {
			continue
		}
		if loc, ok := x.merge(pe, entries, key); ok {
			return loc, true
		}
	}
	return packLoc{}, false
}

// confirms checks a location proposed from OUTSIDE the trailers against
// the pack's own trailer, which is the record the signed pack list
// authenticates and therefore the only thing that binds an identity to an
// extent. It folds the trailer in while it is here, since it has it.
//
// The one caller is the root-catalog hint on an encrypted volume, where
// identity cannot be recomputed from the bytes (roothint.go).
func (x *packIndex) confirms(ctx context.Context, pe superblock.PackEntry, key string, loc packLoc) bool {
	entries, err := x.fs.trailerEntries(ctx, pe)
	if err != nil {
		return false
	}
	got, ok := x.merge(pe, entries, key)
	return ok && got.off == loc.off && got.length == loc.length
}

// mergeLocal folds in every pack whose trailer this mount can read without
// a request — a saved copy, or a pack already cached whole — and reports
// where key sits if one of them holds it. Callers hold loadMu.
//
// It runs once per generation because it is O(local trailers): worth
// paying to turn a remount into local work, not worth repeating on every
// miss. What makes running it once safe under a bounded map is that it
// answers for key out of the entries it reads, so a location it found and
// then evicted is still the location it returns.
func (x *packIndex) mergeLocal(key string) (packLoc, bool) {
	if x.localMerged {
		return packLoc{}, false
	}
	x.localMerged = true
	var (
		found packLoc
		hit   bool
	)
	// Newest-first, like every other merge here, so a key in several packs
	// resolves the same way whichever path found it.
	for i := len(x.packs) - 1; i >= 0; i-- {
		pe := x.packs[i]
		if x.isIndexed(pe.Name) {
			continue
		}
		if entries, ok := x.fs.localTrailerEntries(pe); ok {
			if loc, got := x.merge(pe, entries, key); got && !hit {
				found, hit = loc, true
			}
		}
	}
	return found, hit
}

// LoadPackIndex resolves the location of every entry the generation holds,
// fetching whatever pack trailers are not already local.
//
// Reads never need this: they resolve the pack they are about to fetch and
// nothing else, which is why mounting no longer costs a round trip per
// pack. It is for the callers that reason about content they are NOT about
// to read — a check for absence, an inventory, a warm-up — and for a
// caller that would simply rather pay the cost somewhere it has chosen.
// Answering "not present" from a partially resolved map would be a lie
// with consequences: a failed read, a re-upload, or deleted live data.
func (fs *FS) LoadPackIndex(ctx context.Context) error {
	fs.swapMu.RLock()
	defer fs.swapMu.RUnlock()
	return fs.packIndex.all(ctx)
}

// indexWorkers bounds concurrent trailer fetches when a caller asks for the
// whole map. The packs are independent, so the only reason to do them one
// at a time is politeness to the federation.
const indexWorkers = 8

// all populates the index from every listed pack.
//
// It exists for the callers that need to reason about content they are not
// about to read, and there are two left: a prefetch that wants the volume
// local, and holds when nothing cheaper could confirm an identity. (fsck
// used to be named here and is not a caller at all — internal/fsck builds
// its own external-sorted, mmap'd index and never touches this one.)
// Those callers must ask for it — no read path builds it, and one that
// consulted a partial map would answer "missing" for content that is
// merely un-probed.
//
// The seal's carry-forward check was the third, and its departure is why
// a metadata-only checkpoint stopped costing one trailer fetch per pack in
// the volume: it wanted PRESENCE, which the generation's own multi-pack
// index answers, and only a presence it cannot confirm reaches here (see
// holds).
//
// They are also the only callers that ask for the cap to be lifted, and
// asking is the point: a caller that wants every location has asked for
// the memory every location takes, out loud, in one place, instead of a
// read path accumulating it silently. What would let this be bounded too
// is spilling the map to a local packidx table and searching THAT — the
// structure exists (fixed width, sorted, windowed) and this is the caller
// that wants it.
func (x *packIndex) all(ctx context.Context) error {
	x.loadMu.Lock()
	defer x.loadMu.Unlock()
	x.holdEverything()
	_, _, err := x.indexAll(ctx, "")
	return err
}

// indexAll folds in every listed pack not already accounted for, and
// reports where want sits if one of them holds it. Callers hold loadMu.
//
// This is the answer of last resort and the ONLY thing entitled to say a
// key is present in no listed pack — the rule at the top of this file,
// which is not negotiable because a false absence fails a read, re-uploads
// content that exists, or deletes live data.
//
// Two things about it changed with the cap. It merges each trailer as its
// fetch completes instead of collecting them all first: the collected form
// was len(packs) parsed trailers resident at once, ~11 GB in transit at
// target scale, and the only reason for it was to control which pack won a
// duplicate key — which merge now decides by name (see merge). And it
// reports `want` out of the entries rather than leaving the caller to look
// in a map that a later merge may have evicted from.
func (x *packIndex) indexAll(ctx context.Context, want string) (packLoc, bool, error) {
	if x.indexedAll() {
		// Every listed pack is folded in and nothing has been dropped, so
		// the map is the whole truth and a miss in it is an absence.
		loc, ok := x.lookup(want)
		return loc, ok, nil
	}
	if loc, ok := x.mergeLocal(want); ok {
		return loc, true, nil
	}
	var (
		mu       sync.Mutex
		found    packLoc
		hit      bool
		firstErr error
	)
	sem := make(chan struct{}, indexWorkers)
	var wg sync.WaitGroup
	for _, pe := range x.packs {
		if x.isIndexed(pe.Name) {
			continue
		}
		wg.Add(1)
		go func(pe superblock.PackEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			entries, err := x.fs.trailerEntries(ctx, pe)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("genfs: index pack %s: %w", pe.Name, err)
				}
				mu.Unlock()
				return
			}
			loc, ok := x.merge(pe, entries, want)
			if !ok {
				return
			}
			mu.Lock()
			if !hit {
				found, hit = loc, true
			}
			mu.Unlock()
		}(pe)
	}
	wg.Wait()
	if hit {
		// A located key is a better answer than a report that some other
		// pack's trailer would not load: the caller asked where this one
		// is, and now it knows.
		return found, true, nil
	}
	return packLoc{}, false, firstErr
}

// trailerEntries returns one pack's entries, from whatever local copy the
// mount already has and from the federation otherwise. Every source is held
// to the same standard — the stored bytes must hash to the TrailerHash the
// signed pack list records — so a corrupt, truncated, or substituted local
// file is not a hazard, only a wasted read that falls through.
//
// The order is by cost. A saved trailer is a few kilobytes. A whole pack in
// the cache already contains its trailer, so reading it there is free and,
// under the whole-pack policy, is the common case after the first touch. A
// federation range read is last.
func (fs *FS) trailerEntries(ctx context.Context, pe superblock.PackEntry) ([]packstore.PackEntry, error) {
	if entries, ok := fs.localTrailerEntries(pe); ok {
		return entries, nil
	}
	entries, stored, err := packstore.FetchTrailerStoredVerified(ctx, fs.inner, pe.Name, pe.Size, pe.TrailerHash)
	if err != nil {
		return nil, err
	}
	// Best effort: a mount that cannot write its cache still mounts.
	_ = writeAtomic(filepath.Join(fs.trailerDir, pe.Name), stored)
	return entries, nil
}

// localTrailerEntries is trailerEntries without the federation: the two
// sources this mount can read for free. Split out because folding in every
// trailer that is ALREADY local is worth doing before guessing which
// remote one to fetch — it costs no requests and often answers the
// question outright.
func (fs *FS) localTrailerEntries(pe superblock.PackEntry) ([]packstore.PackEntry, bool) {
	fp := filepath.Join(fs.trailerDir, pe.Name)
	if stored, err := os.ReadFile(fp); err == nil {
		if entries, ok := verifiedTrailer(stored, pe.TrailerHash); ok {
			return entries, true
		}
		os.Remove(fp) //nolint:errcheck
	}
	if entries, stored, ok := fs.trailerFromCachedPack(pe); ok {
		_ = writeAtomic(fp, stored)
		return entries, true
	}
	return nil, false
}

// trailerFromCachedPack reads a pack's trailer out of the local whole-pack
// cache. Reports false for anything at all wrong, so the caller goes to the
// federation — a cache must never turn into a mount failure.
func (fs *FS) trailerFromCachedPack(pe superblock.PackEntry) ([]packstore.PackEntry, []byte, bool) {
	if fs.packCacheCap <= 0 || !fs.packCachedLocally(pe.Name, pe.Size) {
		return nil, nil, false
	}
	f, err := os.Open(fs.packPath(pe.Name))
	if err != nil {
		return nil, nil, false
	}
	defer f.Close() //nolint:errcheck
	stored, err := packstore.StoredTrailerFrom(f, pe.Size)
	if err != nil {
		return nil, nil, false
	}
	entries, ok := verifiedTrailer(stored, pe.TrailerHash)
	return entries, stored, ok
}

// verifiedTrailer authenticates stored trailer bytes against the signed
// pack list and parses them. It is the single gate every trailer source
// passes through, so no source can drift into being trusted more.
func verifiedTrailer(stored []byte, want [32]byte) ([]packstore.PackEntry, bool) {
	if blake3.Sum256(stored) != want {
		return nil, false
	}
	entries, err := packstore.ParseStoredTrailer(stored)
	if err != nil {
		return nil, false
	}
	return entries, true
}
