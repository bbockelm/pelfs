package retention

// Params.RetainK, enforced: the sweep's root set is the last K generations
// of every branch, not only the head.
//
// ================= THE PROBLEM, AND WHY IT IS HARD =================
//
// Retaining a generation means keeping every object it names, which means
// having its SUPERBLOCK. A sweep can enumerate exactly two things —
// refs/<branch> and tags/<name> — and a retired generation is neither: its
// ref was overwritten by its successor and nothing archives what was
// there. So "the last K generations" is a question about K documents that
// no longer have an address.
//
// Three sources were on the table, and only one of them exists in the
// store:
//
//   - THE LINEAGE CHAIN. Every superblock carries PrevHash, the BLAKE3 of
//     its parent's wire bytes. That authenticates a parent but does not
//     produce one: walking the chain needs the parent's bytes at each
//     step, from somewhere, and the hash is only how you would check them.
//     It is a verifier, not a source.
//   - LOCAL STATE. refs keeps the last superblock it accepted per branch
//     (Store.lastPath), which is one generation, on one client, and only
//     if that client ever fetched. It is worse than it sounds: the write
//     path does not go through this package at all — publish flips
//     refs/<branch> itself — so a mount that checkpoints every five
//     minutes records none of its own generations. A rule resting on this
//     would be enforced on whichever machine happened to have watched.
//   - THE DISASTER-RECOVERY BACKUPS. Every seal writes a signed superblock
//     into the last pack it cuts (publish.go, packstore.EntrySuperblock).
//     It is the rescue path's input, and it is the only durable record a
//     retired generation leaves anywhere in the volume.
//
// THIS FILE USES THE BACKUPS, and the awkward part is what a backup
// actually says. It is built BEFORE the seal finishes, so it does not
// describe its own generation: it states the packs cut so far inline and
// carries its PARENT's manifest and index refs (publish's backupPackList
// — "the newest generation minus its tail"). Read as a description of
// generation G it is incomplete, which is exactly why rescue calls itself
// a fall-back-a-step.
//
// Read as a description of generation G-1 it is COMPLETE, and that is the
// hinge this whole rule turns on:
//
//	packs(G-1)     = resolve(backup_G.Manifests)   [or its inline list, pre-manifest]
//	manifests(G-1) = backup_G.Manifests
//	indexes(G-1)   = backup_G.PackIndexes
//
// because a backup carries its parent's refs verbatim and publishes no
// segment of its own (internal/publish/manifest.go, backupPackList; the
// property is pinned by publish's backupsb_test.go). Everything else in a
// backup — the packs it cut before it was written — is a SUPERSET of
// nothing we need, and retaining it costs nothing, since generation G's
// own head names those packs too.
//
// So to retain generations H-1 .. H-K+1 the sweep reads the backups of
// generations H .. H-K+2, and the head covers H itself. K generations, K-1
// scavenged documents, and each one is used to say what the generation
// BELOW it named.
//
// ================= WHAT CAN GO WRONG, AND WHICH WAY IT FAILS ==========
//
// A missing link must never quietly shrink the live set, so the three
// failure modes are separated by what they actually prove:
//
//   - THE BACKUP IS NOT THERE. Its pack was condemned by a repack and
//     swept, or the generation predates something. The generation cannot
//     be described by anything, and no sweep will ever be able to describe
//     it: this is reported (Report.LastK.Unresolved, plus a warning) and
//     that generation falls out of the root set. Failing the sweep instead
//     would protect nothing — the record is gone either way — and would
//     leave the volume unable to reclaim a byte for as long as the
//     generation stayed inside the window.
//   - THE BACKUP IS THERE AND WILL NOT RESOLVE. Its manifest segments do
//     not read. If they are ABSENT the generation was already lost before
//     this sweep started, so it is reported like the case above. Any OTHER
//     error — a transport failure, a decode failure, a hash mismatch — is
//     UNKNOWN STATE, and the sweep fails closed exactly as it does for a
//     head or a tag it cannot read: nothing is deleted.
//   - THE SCAN GAVE UP. The scan is bounded (scanBudget) because it reads
//     one trailer per pack and a volume can hold hundreds of thousands.
//     Exhausting the budget with generations still outstanding is NOT
//     evidence of absence — it is evidence that we stopped looking — so it
//     is a hard error naming the budget and the escape.
//
// The escape is `pelfs gc --retain-k`, and it is the one knob here that
// can NARROW a window, which deserves its reason. --grace may only widen,
// because the grace window is what makes a coordination-free sweep safe
// against a writer that is running right now; narrowing it races live
// uploads. K is not that. It is a policy about readers pinned to RETIRED
// generations, which no sweep can detect and no widening can protect
// beyond what the volume still stores, so stating a smaller K is an
// operator's assertion about their own readers rather than a bet on a
// race. It is printed loudly when it narrows.
//
// ================= THE HONEST LIMIT =================
//
// This rule is only as good as the backups, and a backup lives inside a
// pack. Repack carries them (repack's worthCarrying keeps every
// EntrySuperblock, whatever the reachability sweep says), so ordinary
// maintenance does not lose them; a pack deleted by a sweep run before
// this rule existed takes its backup with it, and those generations show
// up as unresolved once and then age out of the window. K=1 is the old
// behaviour exactly — head and tags — and costs not a single request,
// which is what makes it the safe thing to fall back to.
//
// And WHICH BRANCH a scavenged backup belongs to is the second question,
// answered by superblock.Branch and argued at length over scavengeBackups.
// The short version: a generation number counts steps along one lineage,
// so on a forked volume it names two documents; the branch the seal
// recorded turns (branch, generation) into an identity, which is what
// makes a window tight and lets the scan stop early again. Generations
// with no document of their own — the span below a branch's fork point,
// and anything sealed before the field existed — keep the conservative
// keep-every-candidate rule, and only those generations do.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/ui"
)

// DefaultRetainK is the window used when a head states none. It matches
// publish's defaultRetainK; a superblock written by any current writer
// carries the number, so this covers hand-built and pre-Params documents.
const DefaultRetainK = 8

// scanBudget caps how many pack trailers one sweep reads looking for
// backups. Each is a small range request, and the scan runs newest-pack
// first, so a healthy volume spends about as many as the window's seals
// cut packs — a handful to a few dozen. The cap exists for the unhealthy
// case: without it, one missing backup would turn every sweep into a full
// trailer read of the whole pack space, which at target scale is hours.
//
// A var rather than a const only so a test can reach the give-up path
// without building a thousand packs to walk past. Nothing in production
// writes it.
var scanBudget = 1024

// LastKReport says what the window rule managed to establish, for one
// branch. It is part of the sweep's report rather than a log line because
// "which generations did this sweep actually protect" is the question a
// user has after reading that something was deleted.
type LastKReport struct {
	// Branch is whose window this is; K the window in force (that branch's
	// head's Params.RetainK, or the override); Generations how many of them
	// were resolved, the head included.
	Branch      string
	K           uint32
	Generations int
	// Unresolved names the generations inside the window whose backup
	// could not be found or read, in descending order. A non-empty list
	// means the sweep did NOT retain those generations: anything only they
	// named is a deletion candidate.
	Unresolved []uint64
	// TrailersRead is how many pack trailers the scan cost.
	TrailersRead int

	// HOW each generation was established, which is a different question
	// from how many were. Attributed counts the generations resolved from a
	// backup THIS BRANCH sealed — an exact answer, one document. Legacy
	// counts the generations that had no such backup and fell back to the
	// keep-every-candidate rule, and LegacyCandidates how many documents
	// that kept for them.
	//
	// The two are worth separating in a report because they have different
	// costs and different meanings. A window that is entirely attributed is
	// tight and was cheap to establish. A window with legacy generations is
	// retaining more than that branch strictly needs — the fork prefix a
	// sibling sealed, or backups from before the field existed — and it is
	// why the scan could not stop early. Neither is an error; a user
	// wondering why a sweep freed nothing deserves to be told which.
	//
	// The head is in neither: Generations counts it, and it was fetched by
	// name rather than scavenged, so Attributed+Legacy is Generations-1.
	Attributed       int
	Legacy           int
	LegacyCandidates int
}

// ScanMode is the one-phrase answer to "how was this window established",
// for the sweep's report.
func (r LastKReport) ScanMode() string {
	switch {
	case r.Legacy == 0:
		return "attributed"
	case r.Attributed == 0:
		return fmt.Sprintf("%d legacy candidates kept", r.LegacyCandidates)
	default:
		return fmt.Sprintf("attributed, %d legacy candidates kept for %d generation(s)",
			r.LegacyCandidates, r.Legacy)
	}
}

// clone copies a report for one branch's use, so the caller's appends to
// Unresolved cannot reach back into the cached original — the pre-delete
// recompute runs the same window a second time.
func (r LastKReport) clone(branch string) LastKReport {
	out := r
	out.Branch = branch
	out.Unresolved = append([]uint64(nil), r.Unresolved...)
	return out
}

// windowCache resolves each branch's window ONCE per sweep. The scan reads
// pack trailers, and GC computes the retained set twice — once to find
// candidates and once against fresh heads before deleting — so without
// this the window would be scavenged twice for an answer that can only
// have grown.
type windowCache struct {
	byBranch map[string]*cachedWindow
}

type cachedWindow struct {
	roots []*superblock.Superblock
	rep   LastKReport
}

func newWindowCache() *windowCache {
	return &windowCache{byBranch: make(map[string]*cachedWindow, 1)}
}

func (c *windowCache) get(ctx context.Context, o Options, branch string,
	head *superblock.Superblock, branches int) (*cachedWindow, error) {
	if w, ok := c.byBranch[branch]; ok {
		return w, nil
	}
	w := &cachedWindow{}
	roots, err := windowRoots(ctx, o, branch, head, &w.rep, branches)
	if err != nil {
		return nil, err
	}
	w.roots = roots
	c.byBranch[branch] = w
	return w, nil
}

// windowRoots returns the superblocks standing for the K-1 generations
// below head, and records what could not be established.
//
// The returned superblocks are DESCRIPTIONS OF THEIR PARENTS (see the file
// comment): the backup of generation G stands for generation G-1. Callers
// absorb them into the live set exactly as they absorb a head, which is
// the point — a generation is a generation, whatever produced the document
// that describes it.
func windowRoots(ctx context.Context, o Options, branch string, head *superblock.Superblock, rep *LastKReport,
	branches int) ([]*superblock.Superblock, error) {
	// K comes from THIS BRANCH's own head, which is what makes the window
	// per-branch rather than volume-wide: a branch created yesterday and a
	// trunk with a thousand generations behind it each get the window their
	// own Params.RetainK asks for, and a branch two generations old with
	// K=8 retains its whole two-generation chain rather than eight of
	// somebody else's.
	k := head.Params.RetainK
	if k == 0 {
		k = DefaultRetainK
	}
	if o.RetainK != 0 {
		k = o.RetainK
	}
	rep.K, rep.Generations = k, 1 // the head itself
	if k <= 1 || head.Generation == 0 {
		// K=1 is head-and-tags, which is what the sweep did before this
		// rule existed, and it must cost nothing: no listing, no trailer,
		// no round trip. Generation 0 has no ancestors to want.
		return nil, nil
	}
	// The backups to look for. backup_G describes generation G-1, so
	// covering generations head-1 .. head-K+1 means reading the backups of
	// generations head .. head-K+2, floored at 1 (generation 0 is
	// described by backup_1, and has no backup that describes anything).
	oldest := uint64(1)
	if head.Generation+2 > uint64(k) {
		oldest = head.Generation - uint64(k) + 2
	}
	want := make(map[uint64]bool, head.Generation-oldest+1)
	for g := oldest; g <= head.Generation; g++ {
		want[g] = true
	}
	found, err := scavengeBackups(ctx, o, branch, head, want, rep, branches)
	if err != nil {
		return nil, err
	}
	// Descending, counted rather than compared: oldest can be 1 and these
	// are unsigned, so `g--` past the end wraps to a very large number
	// instead of ending the loop.
	var roots []*superblock.Superblock
	for i := uint64(0); i <= head.Generation-oldest; i++ {
		g := head.Generation - i
		set, ok := found[g]
		if !ok {
			// The generation this backup would have described.
			rep.Unresolved = append(rep.Unresolved, g-1)
			continue
		}
		switch {
		case len(set.mine) > 0:
			// ATTRIBUTED. A backup this branch sealed says which generation
			// of WHICH LINEAGE it describes, so the sibling documents at the
			// same number are not candidates for this window at all and are
			// left out of it. This is where the over-retention goes.
			//
			// All of them rather than the first, and they are almost always
			// one: a publish that uploaded its last pack and then failed
			// before the flip leaves a backup for a generation the retry
			// seals again, so two documents can honestly carry this branch's
			// name at one number. Keeping both is the union rule doing what
			// it always did, over a set this rule has already made small.
			roots = append(roots, set.mine...)
			rep.Attributed++
		case len(set.others) > 0:
			// LEGACY, and confined to the generations that need it. Nothing
			// on this branch claims the number: either the generation
			// predates the Branch field, or it predates the fork and the
			// PARENT branch sealed it. Both are this branch's history and
			// neither can be told from a sibling's document, so the old rule
			// applies here and only here — keep every distinct candidate and
			// let the union sort it out.
			roots = append(roots, set.others...)
			rep.Legacy++
			rep.LegacyCandidates += len(set.others)
		default:
			rep.Unresolved = append(rep.Unresolved, g-1)
			continue
		}
		rep.Generations++
	}
	return roots, nil
}

// backupSet is what the scan found for one generation NUMBER, split by
// whether the document says this branch sealed it.
//
// The split is the whole point of keeping a struct here rather than a
// slice: mine is an exact answer and others is a conservative one, and the
// caller must be able to tell which it is holding — a window resolved from
// `others` is retaining more than the branch needs and could not stop
// scanning early, and a user reading a sweep that freed nothing is owed
// that distinction.
type backupSet struct {
	// mine carries this branch's name. Normally one; a publish that
	// uploaded its last pack and then failed before the flip leaves a
	// second at the generation its retry sealed again.
	mine []*superblock.Superblock
	// others is everything else claiming the number: a v0.1.0 backup that
	// names no branch, a sibling's, and — the case that must never be
	// discarded — the PARENT branch's, for the generations below this
	// branch's fork point, which are this branch's history too.
	others []*superblock.Superblock
}

// scavengeBackups reads pack trailers newest-first, pulling out every
// superblock backup for a generation in want.
//
// Newest-first is what makes the cost proportional to the WINDOW rather
// than to the volume: a seal's backup rides in the last pack it cut, so
// the window's backups are in the volume's newest packs. (A repack breaks
// the correspondence between a backup's generation and its pack's name-age
// by copying old backups into new packs, which only ever moves one EARLIER
// in this order — never later — so nothing is missed by it.)
//
// ================= A GENERATION NUMBER IS NOT AN IDENTITY =============
//
// A backup is found by LOOKING, not by being pointed at, so what says
// which generation it describes is what is written inside it. A number
// alone will not do: it counts steps along ONE lineage, so branch a volume
// at generation N and both children seal N+1, both write a backup, and
// both are signed by the volume key over the same VolumeID. Every test
// this scan could apply passed for either of them.
//
// The consequence was never over-retention, which would be harmless. It is
// that the OTHER branch's generation silently leaves the root set: branch
// dev's window fills with main's documents, and anything only dev's
// retired generations named — a pack a repack on dev condemned, whose only
// protection past the grace window is being named by a generation inside
// the window — becomes a deletion candidate. A reader pinned to that
// generation loses it. v0.1.0 answered by keeping EVERY candidate for a
// wanted number, which converted that loss into bytes, and paid for it by
// giving up the early stop on any volume with siblings.
//
// SO THE BACKUP SAYS WHICH BRANCH SEALED IT (superblock.Branch), and the
// pair (branch, generation) is the identity a number could not be. It is a
// signed field, because the trailer that led us here is not authenticated
// and attribution decides which window a document may FILL — the direction
// that loses data. What it is NOT is a lineage chain: a head's PrevHash
// names its parent's wire bytes and a backup's names its own parent's, so
// nothing links backup_G to backup_{G-1}, and this file still cannot walk
// a chain. It matches a label.
//
// THREE RULES COME OUT OF THAT, and the second is the one that keeps this
// safe rather than merely tight:
//
//   - ATTRIBUTED. A generation with at least one candidate carrying THIS
//     branch's name is resolved from those alone. The siblings at that
//     number are not candidates and are dropped from the window.
//   - LEGACY, PER GENERATION. A generation with none keeps the v0.1.0 rule
//     — every distinct candidate, whoever sealed it. This is not only for
//     backups written before the field existed. A branch's window reaches
//     back PAST ITS OWN FORK POINT, and dev's generations 1..N were sealed
//     by main and say so; they are dev's history all the same. Refusing
//     them because the label does not match would be exactly the
//     under-retention this change exists to remove, so the fallback is
//     conservative and it is confined to the generations that need it. A
//     mixed volume gets the tight rule for its new history and the
//     conservative one only across the legacy span.
//   - THE EARLY STOP RETURNS, for every volume rather than only for
//     single-branch ones. The scan stops once every wanted generation has
//     an ATTRIBUTED candidate, which is a complete answer that no later
//     pack can improve on. It cannot stop while a generation is still on
//     the legacy rule, because "one candidate" is not "every candidate"
//     and the sibling's may be in the next pack — so a volume whose window
//     spans a fork prefix still walks the pack space for that span. The
//     single-branch stop (a number IS an identity there) is kept as it
//     was, for the v0.1.0-era volume whose backups carry no branch at all.
//
// THE RESIDUAL, written down rather than papered over: a branch NAME is
// not a lineage. Delete dev, recreate dev from an older generation, and
// seal the same numbers again, and the two incarnations' backups are
// indistinguishable exactly as two branches' were — the newest-first walk
// favours the live one, since the current incarnation's seals are the most
// recent, but a repack that copied an old backup into a new pack can
// defeat that. The exposure is one branch name reused for a different line
// of history, and the answer is the one that was always exact: TAG the
// generation, which pins it by name.
func scavengeBackups(ctx context.Context, o Options, branch string, head *superblock.Superblock,
	want map[uint64]bool, rep *LastKReport, branches int) (map[uint64]*backupSet, error) {

	entries, err := listDir(ctx, o.Inner, packstore.PackDirKey)
	if err != nil {
		return nil, fmt.Errorf("list packs for the retain-%d window: %w", rep.K, err)
	}
	packs := make([]pelicanobj.DirEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir && strings.HasPrefix(e.Name, "p-") {
			packs = append(packs, e)
		}
	}
	// Newest first by the timestamp in the name — the same clock the age
	// guard reads, and the only one a pack has. A name that will not parse
	// sorts last rather than being skipped: it is still a pack, and a
	// backup inside one would otherwise be invisible.
	sort.SliceStable(packs, func(i, j int) bool {
		ti, oki := packstore.PackNameTime(packs[i].Name)
		tj, okj := packstore.PackNameTime(packs[j].Name)
		if oki != okj {
			return oki
		}
		return ti.After(tj)
	})

	found := make(map[uint64]*backupSet, len(want))
	// attributed counts the generations that have at least one candidate
	// carrying this branch's name — the early stop's condition, kept as a
	// counter so the stop is a comparison rather than a walk of the map on
	// every pack.
	attributed := 0
	// seen dedups by DOCUMENT, not by generation: a repack copies backups
	// into the packs it writes, so the same bytes are reachable from
	// several packs, and counting one twice would put one generation in the
	// root set twice for nothing. Keyed on the wire hash because that is
	// the only exact answer — two branches can agree on generation, parent
	// and root catalog and still name different packs, since a pack's name
	// carries the time it was cut.
	seen := make(map[[32]byte]struct{}, len(want))
	unread := 0
	for _, p := range packs {
		// THE COMPLETE ANSWER: every wanted generation has a document this
		// branch sealed, and (branch, generation) is an identity, so no
		// later pack can hold a candidate that belongs in this window and
		// is not already in it.
		if attributed == len(want) {
			break
		}
		// The older stop, for the volume whose backups carry no branch at
		// all: with one branch a generation number IS an identity, so the
		// first document found for a number is the only one there can be.
		// It is what keeps a v0.1.0-era single-branch volume costing a
		// handful of trailer reads instead of a walk of its pack space.
		if branches <= 1 && len(found) == len(want) {
			break
		}
		if rep.TrailersRead >= scanBudget {
			return nil, fmt.Errorf("gc aborted (fail closed): the retain-%d window still needs the "+
				"superblock backups for generation(s) %s after reading %d pack trailers (the scan budget); "+
				"stopping early is not evidence they are absent, and acting on it could delete objects "+
				"those generations still name. Re-run with --retain-k to state a window this volume can "+
				"establish", rep.K, missingList(want, found), scanBudget)
		}
		rep.TrailersRead++
		tr, err := packstore.FetchTrailer(ctx, o.Inner, p.Name, p.Size)
		if err != nil {
			if isAbsent(err) || isNotAPack(err) {
				// Gone, or never a pack. Either way no backup will ever come
				// out of it, so this is absence rather than blindness: the
				// pack went away under us (a concurrent sweep), or the key
				// space holds an object that is not a pack at all, which the
				// sweep itself already tolerates elsewhere.
				continue
			}
			// Anything else is unknown state. Note it: if a generation ends
			// up unresolved, "we could not read some trailers" is the
			// difference between absence and blindness.
			unread++
			continue
		}
		for _, e := range tr {
			if e.Type != packstore.EntrySuperblock {
				continue
			}
			sb, raw, err := readBackup(ctx, o, p.Name, e)
			if err != nil {
				if isAbsent(err) {
					continue
				}
				unread++
				continue
			}
			// A backup is a statement by the volume's own signing key about
			// one generation of one volume. Both halves are checked: a
			// signed document from a DIFFERENT volume that happened to
			// share a pack space would otherwise contribute its pack names
			// to this volume's live set.
			if sb.VolumeID != head.VolumeID || !want[sb.Generation] {
				continue
			}
			h := superblock.Hash(raw)
			if _, dup := seen[h]; dup {
				continue
			}
			seen[h] = struct{}{}
			set := found[sb.Generation]
			if set == nil {
				set = &backupSet{}
				found[sb.Generation] = set
			}
			// The whole of the attribution: a name the volume's own key
			// signed, compared with the ref being swept. Everything else —
			// a v0.1.0 backup that states no branch, and a backup the
			// PARENT branch sealed before the fork — goes in the other pile
			// and is used only where nothing better exists.
			if sb.Branch == branch {
				if len(set.mine) == 0 {
					attributed++
				}
				set.mine = append(set.mine, sb)
				continue
			}
			set.others = append(set.others, sb)
		}
	}
	if len(found) < len(want) && unread > 0 {
		return nil, fmt.Errorf("gc aborted (fail closed): the retain-%d window is missing generation(s) %s "+
			"and %d pack trailer(s) or backup entries could not be read; a generation that is unreadable "+
			"rather than absent is unknown state, and a sweep does not guess", rep.K, missingList(want, found), unread)
	}
	return found, nil
}

// readBackup fetches and verifies one superblock backup out of a pack.
//
// Verification is the volume key, through the ref store, and it is the
// whole of what makes a scavenged document usable: nothing names this
// entry, its offset came from an unauthenticated trailer, and it was found
// by looking rather than by being pointed at. What the signature buys is
// that the bytes are a superblock the volume's own writer produced — after
// which a wrong one can only cost retention, never a wrong read, since the
// sweep's only use for it is to keep MORE.
// The wire bytes come back with it because they are the only exact
// identity a scavenged document has: the scan has to tell "the same backup
// reached through two packs" (a repack copied it) from "two branches'
// backups at the same generation number", and only the bytes distinguish
// those.
func readBackup(ctx context.Context, o Options, pack string, e packstore.PackEntry) (*superblock.Superblock, []byte, error) {
	rc, err := o.Inner.Get(ctx, packstore.PackDirKey+"/"+pack, e.Off, e.Length)
	if err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(rc)
	rc.Close() //nolint:errcheck
	if err != nil {
		return nil, nil, err
	}
	sb, err := o.Refs.Verify(raw)
	if err != nil {
		// Not the volume's own statement, so it says nothing about any
		// generation of it. Treated as absent rather than as a failure: a
		// pack is appendable by anyone who can write to the volume, so a
		// planted entry that ABORTED every sweep would be a way to stop a
		// volume ever reclaiming space.
		return nil, nil, fmt.Errorf("%w: %w", errNotOurs, err)
	}
	return sb, raw, nil
}

// errNotOurs marks a scavenged document that is not this volume's, which
// callers read as absence.
var errNotOurs = errors.New("not a superblock this volume signed")

// isAbsent reports an error that means "the object is not there", as
// opposed to "the answer is unknown". The distinction decides whether the
// sweep continues or fails closed, and it is the same string test the rest
// of this package uses on the transports, which do not model it as a type.
func isAbsent(err error) bool {
	if errors.Is(err, errNotOurs) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "not exist") ||
		strings.Contains(msg, "no such file")
}

// isNotAPack reports a trailer error that is a property of the BYTES
// rather than of this attempt to read them: no footer, no magic, an index
// length the object cannot hold. Retrying never changes the answer, so
// there is no backup in there to be blind to, and treating one as unknown
// state would let a single object in packs/ that is not a pack — a stray
// upload, a half-written file some other tool left — stop the volume ever
// reclaiming a byte.
//
// It is a string test because the transports and the pack reader do not
// model these as types; the same idiom carries the 404 test below and the
// missing-directory test in retention.go. The failure direction if a
// message is ever reworded is that the sweep becomes MORE conservative
// (the error reads as blindness and the window fails closed), which is the
// safe way round.
func isNotAPack(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "bad pack magic") ||
		strings.Contains(msg, "pack too small") ||
		strings.Contains(msg, "bad index length") ||
		strings.Contains(msg, "unsupported pack version")
}

// missingList renders the generations still wanted, for an error a user
// has to act on.
func missingList(want map[uint64]bool, found map[uint64]*backupSet) string {
	var gens []uint64
	for g := range want {
		if _, ok := found[g]; !ok {
			gens = append(gens, g-1) // the generation the backup describes
		}
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i] > gens[j] })
	parts := make([]string, len(gens))
	for i, g := range gens {
		parts[i] = fmt.Sprintf("%d", g)
	}
	return strings.Join(parts, ", ")
}

// warnUnresolved says out loud that the window is short. It is a warning
// rather than a report line alone because the consequence is silent
// otherwise: the sweep proceeds, deletes what those generations alone
// named, and the report shows a successful run.
func warnUnresolved(branch string, rep *LastKReport) {
	if len(rep.Unresolved) == 0 {
		return
	}
	parts := make([]string, len(rep.Unresolved))
	for i, g := range rep.Unresolved {
		parts[i] = fmt.Sprintf("%d", g)
	}
	ui.Warn("gc: branch {branch} retains {have} of the {k} generations its superblock asks for — "+
		"generation(s) {gens} left no readable superblock backup, so anything only they named is a "+
		"deletion candidate. Tag a generation to pin it exactly",
		"branch", branch, "have", rep.Generations, "k", rep.K, "gens", strings.Join(parts, ", "))
}

// windowFloor dates the retain window: the creation time of the OLDEST
// generation the window resolved, in Unix nanoseconds, or zero when there
// is no window at all.
//
// It is what a condemned-ledger row is judged against. A row's timestamp
// is the seal that dropped the object, so a row at or after this floor was
// dropped by a generation inside the window — which means a generation
// inside the window still names the object, and it stays live however old
// it is. Rows older than the floor were dropped before the window opened
// and have only the grace window to stand on, exactly as before.
//
// Taking the OLDEST resolved root rather than the arithmetic bottom of the
// window is what makes a short window consistent with itself: if the
// oldest generations could not be established, the floor rises with them
// and the ledger is read for the generations that WERE established. It
// never claims a coverage the roots do not have.
func windowFloor(roots []*superblock.Superblock) int64 {
	var floor int64
	for _, sb := range roots {
		if floor == 0 || sb.CreatedUnixNano < floor {
			floor = sb.CreatedUnixNano
		}
	}
	return floor
}
