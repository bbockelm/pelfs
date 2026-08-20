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
	head *superblock.Superblock) (*cachedWindow, error) {
	if w, ok := c.byBranch[branch]; ok {
		return w, nil
	}
	w := &cachedWindow{}
	roots, err := windowRoots(ctx, o, head, &w.rep)
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
func windowRoots(ctx context.Context, o Options, head *superblock.Superblock, rep *LastKReport) ([]*superblock.Superblock, error) {
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
	found, err := scavengeBackups(ctx, o, head, want, rep)
	if err != nil {
		return nil, err
	}
	// Descending, counted rather than compared: oldest can be 1 and these
	// are unsigned, so `g--` past the end wraps to a very large number
	// instead of ending the loop.
	var roots []*superblock.Superblock
	for i := uint64(0); i <= head.Generation-oldest; i++ {
		g := head.Generation - i
		sb, ok := found[g]
		if !ok {
			// The generation this backup would have described.
			rep.Unresolved = append(rep.Unresolved, g-1)
			continue
		}
		roots = append(roots, sb)
		rep.Generations++
	}
	return roots, nil
}

// scavengeBackups reads pack trailers newest-first, pulling out every
// superblock backup for a generation in want, and stops as soon as the set
// is complete.
//
// Newest-first is what makes the cost proportional to the WINDOW rather
// than to the volume: a seal's backup rides in the last pack it cut, so
// the window's backups are in the volume's newest packs. (A repack breaks
// the correspondence between a backup's generation and its pack's name-age
// by copying old backups into new packs, which only ever moves one EARLIER
// in this order — never later — so nothing is missed by it.)
func scavengeBackups(ctx context.Context, o Options, head *superblock.Superblock,
	want map[uint64]bool, rep *LastKReport) (map[uint64]*superblock.Superblock, error) {

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

	found := make(map[uint64]*superblock.Superblock, len(want))
	unread := 0
	for _, p := range packs {
		if len(found) == len(want) {
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
			sb, err := readBackup(ctx, o, p.Name, e)
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
			if _, dup := found[sb.Generation]; !dup {
				found[sb.Generation] = sb
			}
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
func readBackup(ctx context.Context, o Options, pack string, e packstore.PackEntry) (*superblock.Superblock, error) {
	rc, err := o.Inner.Get(ctx, packstore.PackDirKey+"/"+pack, e.Off, e.Length)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(rc)
	rc.Close() //nolint:errcheck
	if err != nil {
		return nil, err
	}
	sb, err := o.Refs.Verify(raw)
	if err != nil {
		// Not the volume's own statement, so it says nothing about any
		// generation of it. Treated as absent rather than as a failure: a
		// pack is appendable by anyone who can write to the volume, so a
		// planted entry that ABORTED every sweep would be a way to stop a
		// volume ever reclaiming space.
		return nil, fmt.Errorf("%w: %w", errNotOurs, err)
	}
	return sb, nil
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
func missingList(want map[uint64]bool, found map[uint64]*superblock.Superblock) string {
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
