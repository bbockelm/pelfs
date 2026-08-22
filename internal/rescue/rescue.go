// Package rescue reconstructs a mountable volume from PACKS ALONE, for the
// day the refs are gone or unreadable.
//
// It is the operation docs/design-packfs.md ("Disaster recovery") has
// specified since before any of the format existed, and the three
// provisions it depends on were all built FIRST, deliberately, because
// retrofitting them would have left early volumes unrescuable:
//
//  1. TYPED PACK ENTRIES. A trailer entry says whether it is a data chunk,
//     a catalog, an inode shard or a superblock BACKUP ("sb"), so an
//     inventory can find the documents it needs without sniffing container
//     magic — which encryption makes impossible anyway.
//  2. SELF-IDENTIFYING CATALOGS. Volume UUID, covered subtree, identity
//     algorithm, and child identities inline, so the namespace tree is
//     self-assembling.
//  3. SUPERBLOCK BACKUPS RIDE IN PACKS. Every seal writes its superblock
//     into the last pack it cuts, stored raw. Losing the mutable ref then
//     costs only the generations since the last publish.
//
// ================= WHAT A BACKUP ACTUALLY SAYS =====================
//
// The one thing that makes this harder than "restore the newest backup" is
// that a backup is built BEFORE its seal has finished. It rides in the last
// pack, so at the moment it is written the seal has cut packs that no
// manifest covers yet. It therefore states its pack set BOTH WAYS — the
// tail inline in PackList, everything older through the manifest refs it
// carries from its PARENT — and it is the only document in the format
// allowed to (superblock.Validate refuses that shape for a branch head, and
// internal/publish/manifest.go's backupPackList explains why the backup is
// exempt).
//
// SO A RESCUE READS THE PACK SET AS THE UNION OF THE TWO. Everything else
// in the tree reads it through manifest.Packs, which prefers the manifest
// and ignores the inline list — correct for a head, and for a backup it
// would silently drop the newest packs, which are the ones holding the
// generation's own root catalog. That is the difference this package exists
// to get right, and it is why `pelfs rescue` cannot simply flip the backup
// bytes onto the ref: a MOUNT resolves through manifest.Packs, so the
// document that becomes the head has to state the union ONE way. Rescue
// therefore re-signs (see apply.go), which is the honest cost and the
// reason --apply needs the volume's signing key.
//
// ================= THE TRUST BOUNDARY =============================
//
// A backup is found by LOOKING. Its offset comes from a trailer that
// nothing signed, nothing points at it, and a pack is appendable by anyone
// with write access to the volume's key space. A rescue that trusted a
// planted backup would be the attack — it would hand an attacker the
// contents of the volume, chosen by them, blessed by a recovery tool the
// operator ran on purpose. So:
//
//   - Every candidate is VERIFIED against the pinned key, or a key the
//     operator supplies explicitly (--volume-pubkey). A document that does
//     not verify is not a candidate; it is reported as rejected, because
//     "there are unsigned superblocks in your packs" is worth knowing.
//   - TOFU IS NOT AVAILABLE HERE, and refs.Store.Verify is what enforces
//     that: trust-on-first-use exists so a reader can start trusting a
//     volume from a MUTABLE object the writer chose to publish. A document
//     dug out of a pack was chosen by whoever could append a pack. A
//     rescue with no key yet gets an error, not a new pin.
//   - AMBIGUITY IS PRESENTED, NEVER RESOLVED. Two distinct verified
//     documents for one (branch, generation) is a real and legitimate state
//     — a publish that uploaded its last pack and then died leaves a backup
//     for a generation its retry sealed again — and it is also what a
//     rollback attack by a key-holder looks like. Nothing here can tell
//     them apart, so nothing here picks.
//
// ================= REPORT FIRST ===================================
//
// Scanning is read-only and needs no key beyond the one it verifies with.
// Writing happens only under --apply, and even then only ever as a PUT: a
// rescue never deletes an object, because the state it runs in is one where
// nobody knows yet what is really missing.
package rescue

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// DefaultTrailerBudget caps how many pack trailers one inventory reads.
//
// Unlike the retain window's budget (internal/retention, scanBudget), which
// exists so a healthy sweep stays cheap, this one is about a scan that
// genuinely wants to see EVERYTHING: a rescue has no index and no ref, and
// the whole point is to find the newest backup wherever it is. So the
// number is large, exhausting it is reported rather than fatal, and the
// report says the answer may not be the newest one — a truncated inventory
// that claimed completeness would be how a rescue silently restores an old
// generation.
const DefaultTrailerBudget = 100_000

// Options configures an inventory.
type Options struct {
	// Inner is the object store. A DIRECT-READ store is not required: packs
	// are immutable and content-verified, so a federation cache serving one
	// is serving the right bytes or bytes that fail their trailer hash.
	Inner pelicanobj.Store
	// Refs verifies candidates (pinned key, or the explicit one it was
	// built with) and, under --apply, performs the flip.
	Refs *refs.Store
	// Branch names the ref that UNATTRIBUTED candidates belong to. Backups
	// written before superblock.Branch existed (v0.1.0) say nothing about
	// which ref sealed them, and a rescue has no other source for it, so the
	// operator states it. Defaults to "main".
	Branch string
	// TrailerBudget caps trailer reads; zero takes DefaultTrailerBudget.
	TrailerBudget int
}

// Candidate is one verified superblock backup scavenged out of a pack.
type Candidate struct {
	// SB and Raw are the document and its wire bytes. Raw is kept because a
	// scavenged document's only exact identity is its bytes: two branches'
	// backups can agree on generation, volume and parent, and the same
	// backup is reachable through several packs once a repack has copied it.
	SB  *superblock.Superblock
	Raw []byte
	// Hash is superblock.Hash(Raw) — what --pick names a candidate by.
	Hash [32]byte
	// Pack is where it was found, and PackSize how big that object is.
	//
	// THIS IS NOT ONLY FOR THE REPORT. The pack a backup rides in is the one
	// pack the backup CANNOT name: it is built and added before the seal
	// finishes, so the carrier is still an unnamed open spool file at that
	// moment (internal/publish/manifest.go, backupPackList — "the newest
	// generation minus its tail"). And the carrier is exactly where the
	// generation's own root catalog usually is, since catalogs are written
	// immediately before the backup.
	//
	// So the rescuer supplies what the document could not: it KNOWS which
	// pack it read the backup out of. That is the whole difference between
	// restoring "the newest generation minus its tail" — which does not
	// mount, because its root catalog is in the tail — and restoring the
	// generation (see resolvePacks).
	Pack     string
	PackSize int64
	// Attributed reports that the document names a branch (v0.2 and later).
	// An unattributed one is assigned to Options.Branch, and the report says
	// so, because that assignment is an assumption and not a finding.
	Attributed bool
}

// ID is the short hash an operator types to disambiguate.
func (c *Candidate) ID() string { return fmt.Sprintf("%x", c.Hash[:6]) }

// Rejection is a superblock-shaped pack entry that did not verify. It is
// reported rather than dropped: on a healthy volume the count is zero, and
// anything else is either a second volume sharing the pack space or someone
// planting documents.
type Rejection struct {
	Pack   string
	Offset int64
	Reason string
}

// Skip records a candidate that was passed OVER in favour of an older one,
// and why. This is the spec's "falls back a generation when a closure has
// holes", made legible: a rescue that silently offered generation 40 when
// 43 existed would be indistinguishable from a rescue that could not see 43.
type Skip struct {
	Generation uint64
	ID         string
	Reason     string
}

// Current is what refs/<branch> holds right now, when it can be read at
// all. A rescue runs precisely when this is missing or broken, so all three
// outcomes are represented and none of them is an error.
type Current struct {
	// Present reports that the object exists.
	Present bool
	// Generation and Verified describe it when it decoded and verified.
	Generation uint64
	Verified   bool
	// Problem is why it is unusable: absent, undecodable, unverifiable.
	Problem string
	// ETag guards the flip that replaces it.
	ETag string
}

// BranchPlan is the offer for one branch.
type BranchPlan struct {
	Branch  string
	Current Current
	// Chosen is the candidate this rescue offers, nil when none was usable.
	Chosen *Candidate
	// Ambiguous holds every candidate tied with Chosen at the same
	// generation. Non-empty means nothing is chosen and --pick is required:
	// two verifiable candidates for one head is presented, never auto-picked.
	Ambiguous []*Candidate
	// Skipped names the newer candidates that were passed over, newest first.
	Skipped []Skip
	// Packs is the resolved pack set of Chosen — the UNION of its inline
	// list and its carried manifest refs.
	Packs []superblock.PackEntry
	// Root says whether the generation's root catalog could actually be
	// located in that pack set, which is the difference between a document
	// that verifies and a generation that mounts.
	Root RootStatus
}

// RootStatus is what could be established about the root catalog.
type RootStatus struct {
	// Pack names where it was found, empty when it was not.
	Pack string
	// Located reports a positive finding. NOT located is not the same as
	// absent: see Note.
	Located bool
	// Note explains a negative or unproven answer — the hint was stale, the
	// scan ran out of budget, the pack is gone. An operator deciding whether
	// to --apply needs to know which.
	Note string
}

// Report is one inventory plus the offers it produced.
type Report struct {
	Branches []*BranchPlan
	Rejected []Rejection
	// PacksSeen and TrailersRead are the cost, and TrailersFailed the
	// blindness: a pack whose trailer would not read may have held the
	// newest backup, and an operator reading "generation 40 is the newest I
	// found" deserves to know the scan was partly blind.
	PacksSeen      int
	TrailersRead   int
	TrailersFailed int
	// Truncated reports that the budget ran out with packs unread, so the
	// newest backup may not have been seen at all.
	Truncated bool
	// Unattributed counts candidates that named no branch and were assigned
	// to Options.Branch.
	Unattributed int
}

// ErrNoCandidates reports an inventory that found nothing usable: no
// verified superblock backup anywhere in the pack space. It is a sentinel
// because the two causes need opposite advice — the packs are gone, or the
// key is wrong — and only the caller knows which the operator was betting
// on.
var ErrNoCandidates = errors.New("no verified superblock backup found in any pack")

// Inventory scans the pack space and plans a rescue. It writes nothing.
func Inventory(ctx context.Context, o Options) (*Report, error) {
	if o.Branch == "" {
		o.Branch = "main"
	}
	if o.TrailerBudget <= 0 {
		o.TrailerBudget = DefaultTrailerBudget
	}
	rep := &Report{}
	cands, err := scan(ctx, o, rep)
	if err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return rep, ErrNoCandidates
	}
	for _, branch := range sortedKeys(cands) {
		plan, err := planBranch(ctx, o, branch, cands[branch])
		if err != nil {
			return nil, err
		}
		rep.Branches = append(rep.Branches, plan)
	}
	return rep, nil
}

// scan reads every pack trailer it is allowed to and returns the verified
// backups, grouped by the branch they belong to.
//
// NEWEST-PACK-FIRST, like the retain window's scan, and for a weaker reason
// here: a rescue wants the whole pack space, so the order only decides what
// it sees before a budget runs out. It matters exactly then, which is the
// case the order is for.
func scan(ctx context.Context, o Options, rep *Report) (map[string][]*Candidate, error) {
	entries, err := o.Inner.ListDir(ctx, packstore.PackDirKey)
	if err != nil {
		if isAbsent(err) {
			// No packs directory at all. This is not "nothing to rescue" —
			// it is "there is nothing here", and the two deserve different
			// words, because an operator who has just typed the wrong prefix
			// will read the first as bad news about their volume.
			return nil, fmt.Errorf("%s/ does not exist: this prefix holds no packs, so there is nothing to "+
				"rescue from (check the prefix)", packstore.PackDirKey)
		}
		return nil, fmt.Errorf("list %s: %w", packstore.PackDirKey, err)
	}
	packs := make([]pelicanobj.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir && strings.HasPrefix(e.Name, "p-") {
			packs = append(packs, e)
		}
	}
	sort.SliceStable(packs, func(i, j int) bool {
		ti, oki := packstore.PackNameTime(packs[i].Name)
		tj, okj := packstore.PackNameTime(packs[j].Name)
		if oki != okj {
			return oki
		}
		return ti.After(tj)
	})
	rep.PacksSeen = len(packs)

	out := map[string][]*Candidate{}
	// Keyed on wire hash: a repack copies backups into the packs it writes
	// (repack's worthCarrying keeps every EntrySuperblock whatever the
	// reachability sweep says), so the same document is reachable through
	// several packs and would otherwise be offered as its own alternative —
	// which would read as exactly the ambiguity this package refuses to
	// resolve.
	seen := map[[32]byte]bool{}
	for _, p := range packs {
		if rep.TrailersRead >= o.TrailerBudget {
			rep.Truncated = true
			break
		}
		rep.TrailersRead++
		tr, err := packstore.FetchTrailer(ctx, o.Inner, p.Name, p.Size)
		if err != nil {
			if isAbsent(err) || isNotAPack(err) {
				// Gone under us, or never a pack. No backup will ever come
				// out of it, so this is absence and not blindness.
				continue
			}
			rep.TrailersFailed++
			continue
		}
		for _, e := range tr {
			if e.Type != packstore.EntrySuperblock {
				continue
			}
			raw, err := readEntry(ctx, o.Inner, p.Name, e)
			if err != nil {
				rep.TrailersFailed++
				continue
			}
			// THE TRUST BOUNDARY. Refs.Verify checks the pinned or supplied
			// key and never pins: a document from a pack may not become the
			// reason a client trusts a volume.
			sb, err := o.Refs.Verify(raw)
			if err != nil {
				rep.Rejected = append(rep.Rejected, Rejection{
					Pack: p.Name, Offset: e.Off, Reason: err.Error(),
				})
				continue
			}
			h := superblock.Hash(raw)
			if seen[h] {
				continue
			}
			seen[h] = true
			c := &Candidate{SB: sb, Raw: raw, Hash: h, Pack: p.Name, PackSize: p.Size,
				Attributed: sb.Branch != ""}
			branch := sb.Branch
			if branch == "" {
				branch = o.Branch
				rep.Unattributed++
			}
			out[branch] = append(out[branch], c)
		}
	}
	return out, nil
}

// planBranch turns one branch's candidates into an offer.
//
// THE FALLBACK IS THE ALGORITHM. Newest generation first; a candidate whose
// pack set cannot be RESOLVED is skipped with a reason and the next-older
// one is tried. That is the spec's "recovery falls back a generation when a
// closure has holes", and it is the shape a crash mid-publish legitimately
// produces: packs upload before the ref flips, so the newest thing in the
// pack space is routinely a generation that never became a head.
func planBranch(ctx context.Context, o Options, branch string, cands []*Candidate) (*BranchPlan, error) {
	plan := &BranchPlan{Branch: branch}
	plan.Current = currentRef(ctx, o, branch)

	// Group by generation, newest first.
	byGen := map[uint64][]*Candidate{}
	for _, c := range cands {
		byGen[c.SB.Generation] = append(byGen[c.SB.Generation], c)
	}
	gens := make([]uint64, 0, len(byGen))
	for g := range byGen {
		gens = append(gens, g)
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i] > gens[j] })

	for _, g := range gens {
		set := byGen[g]
		if len(set) > 1 {
			// AMBIGUOUS, and this is where the walk STOPS rather than
			// continuing to an older generation. Falling through would
			// answer a question nobody asked: the operator's newest
			// recoverable head is right here, and which of these two it is
			// is a decision only they can make. Offering generation 40
			// because 43 was ambiguous would bury the ambiguity under a
			// successful-looking rescue.
			sort.Slice(set, func(i, j int) bool { return set[i].ID() < set[j].ID() })
			plan.Ambiguous = set
			return plan, nil
		}
		c := set[0]
		packs, err := resolvePacks(ctx, o, c)
		if err != nil {
			plan.Skipped = append(plan.Skipped, Skip{
				Generation: g, ID: c.ID(),
				Reason: fmt.Sprintf("pack set unresolvable: %v", err),
			})
			continue
		}
		plan.Chosen, plan.Packs = c, packs
		plan.Root = locateRoot(ctx, o, c.SB, packs)
		return plan, nil
	}
	return plan, nil
}

// resolvePacks is the UNION rule, and the one place it lives.
//
// THREE SOURCES, and the third one is the one the spec did not have.
//
//  1. THE INLINE LIST. The packs the seal had cut when the backup was built.
//  2. THE CARRIED MANIFEST REFS. Everything the PARENT generation named.
//  3. THE PACK THE BACKUP WAS FOUND IN. The one pack no backup can ever
//     name, because at the moment it is written that pack is still an open
//     spool file with no name — and, because catalogs are packed immediately
//     before the backup is added, the one most likely to hold the
//     generation's own ROOT CATALOG.
//
// Sources 1 and 2 are what docs/design-packfs.md means by "a rescue reads
// its pack set as the union of the two", and they are not enough: a head
// built from them alone verifies, states a root catalog, and cannot serve
// it. That is not a hypothesis — it is what the end-to-end test found on the
// first run, on every fixture. Source 3 closes it, and the rescuer is the
// only party that can: the DOCUMENT cannot name its carrier, but whoever
// read the document knows which object it came out of.
//
// (The carrier is one pack, not several: the backup is added last and the
// packer seals immediately after, so anything cut between the catalogs and
// the backup is already in source 1.)
//
// WHY THIS IS NOT A SEPARATE FUNCTION FROM THE HEAD RULE'S. manifest.Packs
// — which every other reader in the tree uses — implements the FORMAT rule
// for a HEAD: prefer the manifest, ignore the inline list. Applied to a
// backup that would drop sources 1 and 3 together. The two rules look like
// the same question and are not, which is why this lives here and says so
// at length.
//
// The manifest half is all-or-nothing. A segment that will not read leaves
// the pack set UNKNOWN, and an unknown pack set is what makes a candidate
// skippable — never something to paper over with a partial answer, since a
// partial answer here becomes a head naming fewer packs than the generation
// needs, and then a sweep acts on it.
func resolvePacks(ctx context.Context, o Options, c *Candidate) ([]superblock.PackEntry, error) {
	sb := c.SB
	byName := map[string]superblock.PackEntry{}
	for _, p := range sb.PackList {
		byName[p.Name] = p
	}
	if len(sb.Manifests) > 0 {
		segments, err := manifest.FetchAll(ctx, o.Inner, sb.Manifests)
		if err != nil {
			return nil, err
		}
		if len(segments) != len(sb.Manifests) {
			return nil, fmt.Errorf("resolved %d of %d manifest segment(s)", len(segments), len(sb.Manifests))
		}
		for _, p := range manifest.NewSet(segments).All() {
			// The inline row wins on a collision, and it never matters: a
			// pack's name, trailer hash and size are fixed at the moment it
			// is sealed, so two rows for one name are the same row. Stated
			// rather than left to the map, because "whichever the loop saw
			// last" is not a rule.
			if _, dup := byName[p.Name]; !dup {
				byName[p.Name] = superblock.PackEntry{Name: p.Name, TrailerHash: p.TrailerHash, Size: p.Size}
			}
		}
	}
	// SOURCE 3: the carrier. Its trailer hash is not recorded anywhere this
	// rescue can read — the signed list that would have carried it is the
	// very thing being reconstructed — so it is computed from the object,
	// which is sound for a pack: packs are immutable and content-verified
	// end to end by chunk identity, and the trailer hash a head records is
	// there to authenticate a LOCATION MAP against a signature. A rescued
	// head therefore states the hash of what is actually in the store, and
	// says so out loud (Applied.CarrierPack).
	if c.Pack != "" {
		if _, dup := byName[c.Pack]; !dup {
			h, size, err := carrierTrailer(ctx, o, c)
			if err != nil {
				return nil, fmt.Errorf("the pack carrying this backup (%s) could not be read, and it is "+
					"the one pack the backup cannot name — usually where the generation's root catalog "+
					"is: %w", c.Pack, err)
			}
			byName[c.Pack] = superblock.PackEntry{Name: c.Pack, TrailerHash: h, Size: size}
		}
	}
	if len(byName) == 0 {
		return nil, errors.New("names no packs at all")
	}
	out := make([]superblock.PackEntry, 0, len(byName))
	for _, p := range byName {
		out = append(out, p)
	}
	// Pack-name order, which is creation order: the order every other pack
	// list in the format is carried in, so a caller that bets on recency by
	// walking backwards keeps the bet it had.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// carrierTrailer computes the BLAKE3 of a pack's stored trailer bytes, plus
// its size, for the one pack a rescue has to describe itself.
//
// Two range requests, not a whole-pack fetch: the footer says how long the
// trailer is and where it starts, which is the same two-step probe every
// reader uses. remoteAt is what lets packstore's local-file reader do it
// over an object store.
func carrierTrailer(ctx context.Context, o Options, c *Candidate) ([32]byte, int64, error) {
	size := c.PackSize
	if size <= 0 {
		ki, err := o.Inner.StatKey(ctx, packstore.PackDirKey+"/"+c.Pack)
		if err != nil {
			return [32]byte{}, 0, err
		}
		size = ki.Size
	}
	stored, err := packstore.StoredTrailerFrom(&remoteAt{ctx: ctx, inner: o.Inner, key: packstore.PackDirKey + "/" + c.Pack}, size)
	if err != nil {
		return [32]byte{}, 0, err
	}
	return blake3.Sum256(stored), size, nil
}

// remoteAt adapts an object store to io.ReaderAt so packstore's
// already-written tail parser can be used against a remote pack. It is
// deliberately dumb — two short reads, no caching — because it runs once per
// candidate offered, on a recovery path.
type remoteAt struct {
	ctx   context.Context
	inner pelicanobj.Store
	key   string
}

func (r *remoteAt) ReadAt(p []byte, off int64) (int, error) {
	rc, err := r.inner.Get(r.ctx, r.key, off, int64(len(p)))
	if err != nil {
		return 0, err
	}
	defer rc.Close() //nolint:errcheck
	return io.ReadFull(rc, p)
}

// locateRoot establishes whether the generation's root catalog is actually
// reachable in the pack set — the difference between a document that
// verifies and a generation that mounts.
//
// THE HINT FIRST, which is what the hint is for: RootCatalogHint names the
// pack, offset and length directly, so a healthy generation costs one
// trailer read to confirm. A hint is only ever a HINT (a repack moves
// entries and does not rewrite old superblocks), so a miss falls through
// rather than failing.
//
// AND THE ANSWER IS THREE-VALUED, not two. "Found", "looked everywhere and
// it is not there", and "did not finish looking" are different facts, and
// the third is the one that must not masquerade as either: an operator
// deciding whether to --apply on a partly-scanned pack set is making a
// different bet from one whose root catalog is provably gone.
func locateRoot(ctx context.Context, o Options, sb *superblock.Superblock, packs []superblock.PackEntry) RootStatus {
	want := fmt.Sprintf("%x", sb.RootCatalog)
	if h := sb.RootCatalogHint; h != nil {
		if found, err := packHolds(ctx, o, h.Pack, packs, want); err == nil && found {
			return RootStatus{Pack: h.Pack, Located: true}
		}
	}
	// The budget is the pack count of ONE generation, which is bounded by
	// what that generation references rather than by the volume, so this is
	// not the unbounded walk the inventory's budget guards against. It is
	// still capped, because a generation naming two hundred thousand packs
	// would otherwise turn a report into an afternoon.
	//
	// Defaulted HERE and not only in Inventory, because Resolve reaches this
	// with the caller's Options after a --pick: a zero that fell through
	// reported "not found in the first 0 packs" on a perfectly healthy
	// generation, which is a refusal to apply a rescue that would have
	// worked. Found by the ambiguity test.
	budget := o.TrailerBudget
	if budget <= 0 {
		budget = DefaultTrailerBudget
	}
	for i, p := range packs {
		if i >= budget {
			return RootStatus{Note: fmt.Sprintf("not found in the first %d of %d packs (scan budget); "+
				"absence is not established", budget, len(packs))}
		}
		found, err := packHolds(ctx, o, p.Name, packs, want)
		if err != nil {
			continue
		}
		if found {
			return RootStatus{Pack: p.Name, Located: true}
		}
	}
	return RootStatus{Note: fmt.Sprintf("root catalog %s is in none of this generation's %d pack(s): the "+
		"document verifies but the tree it names is not there", want[:16], len(packs))}
}

// packHolds reports whether one pack's trailer lists the given entry key.
func packHolds(ctx context.Context, o Options, name string, packs []superblock.PackEntry, key string) (bool, error) {
	var size int64
	for _, p := range packs {
		if p.Name == name {
			size = p.Size
		}
	}
	if size == 0 {
		return false, fmt.Errorf("pack %s is not in this generation's pack set", name)
	}
	tr, err := packstore.FetchTrailer(ctx, o.Inner, name, size)
	if err != nil {
		return false, err
	}
	for _, e := range tr {
		if e.Key == key {
			return true, nil
		}
	}
	return false, nil
}

// currentRef reports what refs/<branch> holds, treating every outcome as
// information rather than as an error. A rescue runs when this is broken;
// refusing to proceed because it is broken would be a tool that only works
// when it is not needed.
func currentRef(ctx context.Context, o Options, branch string) Current {
	f, err := o.Refs.Fetch(ctx, branch)
	if err == nil {
		return Current{Present: true, Generation: f.Superblock.Generation, Verified: true, ETag: f.ETag}
	}
	cur := Current{Problem: err.Error()}
	// Absent and unverifiable are different states with different flips: an
	// absent ref is created (empty expect-ETag) and a present one is
	// overwritten under its ETag, so the distinction is load-bearing and not
	// just reporting.
	if ki, serr := o.Inner.StatKey(ctx, refs.RefDirKey+"/"+branch); serr == nil {
		cur.Present, cur.ETag = true, ki.ETag
	}
	return cur
}

func readEntry(ctx context.Context, inner pelicanobj.Store, pack string, e packstore.PackEntry) ([]byte, error) {
	rc, err := inner.Get(ctx, packstore.PackDirKey+"/"+pack, e.Off, e.Length)
	if err != nil {
		return nil, err
	}
	defer rc.Close() //nolint:errcheck
	return io.ReadAll(rc)
}

func sortedKeys(m map[string][]*Candidate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isAbsent and isNotAPack are the same string tests internal/retention
// applies, for the same reason: the transports and the pack reader do not
// model these as types. The failure direction if a message is ever reworded
// is that a rescue becomes MORE cautious (an absence reads as blindness and
// is counted in TrailersFailed, which the report surfaces), which is the
// safe way round for a tool whose output a human acts on.
func isAbsent(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "no such file")
}

func isNotAPack(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "bad pack magic") ||
		strings.Contains(msg, "pack too small") ||
		strings.Contains(msg, "bad index length") ||
		strings.Contains(msg, "unsupported pack version")
}
