// Package repack decides what a repack WOULD rewrite. It decides only:
// nothing in here writes an object, deletes one, or publishes a
// generation.
//
// Three rules are written down in docs/design-packfs.md and none of them
// is implemented: repack a pack that is mostly garbage ("Overwrite
// churn"), retire an index whose packs are under half live ("Tiers,
// merging and retiring"), rewrite a manifest segment that is mostly dead
// ("The pack list moves out of the superblock"). Each one is a question
// about LIVENESS, which internal/reach now answers, and none of them is a
// question about how to move bytes. What was missing between the two is
// the layer that reads the numbers and says which objects are worth the
// work. That is this package, and it stops there: executing a plan means
// publishing a new generation, which is internal/publish's business.
//
// # The number an operator actually needs
//
// "This pack is 4% live" is not a reason to do anything by itself. A plan
// that reclaims a megabyte by moving five hundred is one an operator
// should refuse, so every candidate here carries BOTH numbers — the bytes
// the rewrite reclaims and the bytes it must move to reclaim them — and
// so does the plan as a whole. For packs the two are related by the
// threshold: a pack under half live always reclaims at least what it
// moves, which is most of why the design states the rule in live
// fractions. For an index or manifest ref it is the other way round and
// the plan says so plainly: retiring one moves the whole object to
// reclaim only its dead share, and it is worth doing because the move is
// paid once while the dead bytes are fetched on every mount.
//
// # Safety, which is the whole shape of the API
//
// reach.Sweep hands back a *Report only when it read everything it
// needed; on any failure the report is nil and the error is an
// *Incomplete carrying a report that marks every pack fully live. A
// planner built on that conservative report would propose deleting live
// data, so this package is arranged so that it cannot see one:
//
//   - Options has NO field through which a caller can supply a report.
//     Compute runs the sweep itself. There is no "plan from this report"
//     entry point to call with the wrong report.
//   - Everything that can put a candidate into a plan takes the
//     unexported `swept` type, whose only constructor is the branch of
//     Compute that got a non-nil report back from reach.Sweep. An
//     *Incomplete returns before that value exists.
//
// So "an incomplete sweep produces an empty plan" is not a check that
// could be forgotten; it is the only path the types allow. A refused plan
// carries the reason and NO numbers at all — not even the conservative
// report's totals — because a number in the same field a measurement
// would have used is a number someone will read as one.
//
// # What it does not do
//
// It does not choose the live generation set (reach's reason: retention
// policy lives in the ref layer, and a planner that recomputed it could
// disagree with the GC acting on its answer). It does not delete the
// packs it condemns — a repack rewrites live entries and drops packs from
// the list, and retention's sweep is what removes the objects afterwards.
// And it plans one pass: the ref part is measured against the volume as
// it would be AFTER the pack part is applied, because those happen in one
// publish or not at all.
//
// It does not BUDGET either. Every candidate that passes the threshold
// and the age guard is listed, oldest first, however many that is; there
// is no "the best 64 MiB of work in this volume" here. Choosing that
// wants an executor with an opinion about what one pass may cost, and
// there is no executor yet.
package repack

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/reach"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// DefaultLiveFraction is the design's threshold, stated once for packs
// and refs alike: "under 50% live" retires an index, and a pack under
// half live is one whose rewrite reclaims at least the bytes it moves.
const DefaultLiveFraction = 0.5

// defaultTargetPackSize is the cut a rewrite would use, and it is only
// ever used to answer "how few packs would the moved bytes land in".
//
// It duplicates publish.DefaultTargetPackSize rather than importing it,
// so that a planner — which by design cannot execute anything — does not
// drag in the write path for one integer. The cost of the duplication is
// that a plan's pack-count estimate goes stale if that constant moves;
// the estimate is advisory, and Options.TargetPackSize overrides it.
const defaultTargetPackSize = 2 << 20

// maxNames caps the name samples a plan carries for things it did NOT
// choose, as retention's report does: a volume with 400,000 young packs
// should not produce a 400,000-string explanation. The candidate lists
// themselves are not capped — they ARE the plan.
const maxNames = 20

// Options configures Compute.
type Options struct {
	// Inner is the raw transport.
	Inner pelicanobj.Store
	// Live is the generation set whose references keep bytes alive: every
	// branch head, every tag, and every generation still inside the retain
	// window. The caller decides it, exactly as for reach.Sweep — and the
	// stakes are the same, since a generation left out of this set has its
	// packs reported dead.
	Live []*superblock.Superblock
	// Head is the generation whose index and manifest refs are considered
	// for retirement. It must also appear in Live: a head outside the live
	// set would have its own packs swept as unreferenced, and every ref it
	// names would then look entirely dead.
	Head *superblock.Superblock
	// DEK unwraps catalog objects on an encrypted volume; nil otherwise.
	DEK []byte
	// CacheDir holds the sweep's catalog spills (empty: a temp dir).
	CacheDir string
	// Workers bounds concurrent fetches during the sweep.
	Workers int

	// collectReachable asks the sweep to keep the identity set, which only
	// the executor needs. Unexported: a caller asking for a PLAN has no
	// use for it and would pay a materialized copy of the references for
	// nothing.
	collectReachable bool

	// Now is an injectable clock for the age guard (zero: time.Now()).
	Now time.Time
	// Grace widens the age guard past what the superblocks state. It may
	// only widen it: the window is a safety property, and an option that
	// could narrow it would be an option to delete a concurrent writer's
	// packs.
	Grace time.Duration

	// PackLive and RefLive are the liveness thresholds (default
	// DefaultLiveFraction each). A pack at or above PackLive is left
	// alone; a ref at or above RefLive is left listed.
	PackLive, RefLive float64
	// TargetPackSize is the cut a rewrite would use (default
	// defaultTargetPackSize), for the "into how few packs" estimate only.
	TargetPackSize int64
}

// PackCandidate is one pack worth rewriting: what it holds, how much of
// that is still referenced, and the trade.
type PackCandidate struct {
	Name string
	// Size is the whole object, trailer included — what deleting it frees.
	Size                 int64
	Entries, LiveEntries int64
	Bytes, LiveBytes     int64
	// LiveFraction is LiveBytes/Bytes, the number the threshold is in.
	LiveFraction float64
	// Move is the stored bytes a rewrite must read and write again: the
	// live ones. Reclaim is what the volume gets back, the whole object
	// less what was moved out of it.
	//
	// Reclaim is very slightly optimistic and stays that way on purpose:
	// the moved entries land in a new pack that has a trailer of its own,
	// and that trailer's bytes are not modelled here. It is tens of bytes
	// per entry against a pack of megabytes, and modelling it would mean
	// this package predicting the writer's framing.
	Move, Reclaim int64
	// Age is how old the pack's name says it is, which is what the grace
	// guard tests.
	Age time.Duration
}

// RefKind distinguishes the two derived key spaces a plan can retire.
type RefKind string

const (
	RefIndex    RefKind = "index"
	RefManifest RefKind = "manifest"
)

// RefCandidate is one index or manifest ref worth retiring — which means
// rewriting it, so it carries the same trade a pack does.
type RefCandidate struct {
	Kind RefKind
	Name string
	Size int64
	// Packs is how many packs the object names; LivePacks how many of
	// those still hold live bytes and would survive this plan; GonePacks
	// how many no live generation names at all (already swept, or swept
	// as soon as GC next runs); CondemnedPacks how many are packs THIS
	// plan proposes to condemn.
	Packs, LivePacks, GonePacks, CondemnedPacks int
	// LiveFraction is LivePacks/Packs.
	//
	// Measured in packs rather than in entries, which is exact for a
	// manifest — one fixed-width record per pack — and an approximation
	// for an index, where a pack contributes as many entries as it holds
	// objects. The design states the rule in packs ("an index whose packs
	// are mostly deleted"), the threshold is a coarse one half, and the
	// alternative is fetching every pack's entry count to weight a
	// decision about a few megabytes. Where it errs: an index naming one
	// enormous dead pack and nine tiny live ones is reported 90% live and
	// is not proposed.
	LiveFraction float64
	// Move is the whole object — retiring a ref means reading it and
	// writing its live entries out again. Reclaim is its dead share.
	// Unlike a pack, this trade is always unfavourable in one pass; what
	// makes it worth doing is that the move is paid once while a mount
	// fetches the dead bytes every time.
	Move, Reclaim int64
}

// Note is something the planner declined to judge, or held back, with the
// reason. Object names what it is about so a plan can be triaged without
// parsing prose — the shape reach.Failure uses.
type Note struct {
	Object string
	Detail string
}

func (n Note) String() string { return n.Object + ": " + n.Detail }

// Plan is what Compute produces. An empty plan is the expected answer on
// a healthy volume, and a planner that always finds work would be worse
// than none.
type Plan struct {
	// Refusal is non-empty when nothing could be planned safely. It is the
	// only field a refused plan fills apart from Notes: the sweep behind
	// it measured nothing, so there are no numbers to report.
	Refusal string

	// Generations is how many live generations were swept, ScannedPacks
	// how many packs they name between them, and Bytes/LiveBytes what
	// those packs hold. These are the denominator every candidate below is
	// a fraction of.
	Generations  int
	ScannedPacks int
	Bytes        int64
	LiveBytes    int64
	// Grace is the age guard actually applied.
	Grace time.Duration

	// Packs and Refs are the plan proper.
	Packs []PackCandidate
	Refs  []RefCandidate
	// IntoPacks estimates how few packs the moved bytes would land in — a
	// floor, since entries do not split across packs.
	IntoPacks int

	// SkippedYoung counts candidates the age guard held back, with a
	// sample of their names. They are not failures: a young pack is one a
	// concurrent writer may be about to reference, and the next run will
	// see it again.
	SkippedYoung      int
	SkippedYoungNames []string

	// Notes are refs that could not be judged, and anything else worth
	// saying about what is NOT in the plan.
	Notes []Note
}

// Refused reports whether the plan is a refusal rather than a
// measurement. A refused plan is always empty.
func (p *Plan) Refused() bool { return p.Refusal != "" }

// Empty reports whether there is nothing worth doing.
func (p *Plan) Empty() bool { return len(p.Packs) == 0 && len(p.Refs) == 0 }

// Move is the stored bytes the whole plan would read and write again.
func (p *Plan) Move() int64 {
	var n int64
	for _, c := range p.Packs {
		n += c.Move
	}
	for _, c := range p.Refs {
		n += c.Move
	}
	return n
}

// Reclaim is what the whole plan would give back.
func (p *Plan) Reclaim() int64 {
	var n int64
	for _, c := range p.Packs {
		n += c.Reclaim
	}
	for _, c := range p.Refs {
		n += c.Reclaim
	}
	return n
}

// swept is a reach report that came back from a COMPLETE sweep.
//
// This type is the mechanism described in the package comment. It is
// unexported, its field is unexported, and the one place that constructs
// it is Compute, on the branch where reach.Sweep returned a report rather
// than an *Incomplete. Every function that can append a candidate to a
// plan takes one of these, so a conservative report cannot reach the
// decisions even by a mistake made inside this package — there is no
// value of this type that an incomplete sweep can produce.
type swept struct{ rep *reach.Report }

// Compute sweeps the live generations and returns the plan.
//
// A refused plan (Plan.Refused) is returned with a nil error: it is a
// complete, correct answer to "what should be rewritten" — nothing,
// because the volume could not be measured. A non-nil error means the
// request itself was bad (no store, no live set, a head outside it), and
// then there is no plan at all.
func Compute(ctx context.Context, o Options) (*Plan, error) {
	plan, rep, err := compute(ctx, o)
	rep.Close() //nolint:errcheck
	return plan, err
}

// compute is Compute plus the sweep's report, for the executor, which
// needs the reachable set the report carries. The report is nil for a
// refused plan and for a bad request, and Report.Close is safe on nil, so
// every caller can defer it unconditionally.
//
// This is deliberately not "Compute with an out-parameter": the swept
// value that authorizes building a plan is still constructed at exactly
// one site below, on the branch where Sweep returned a report.
func compute(ctx context.Context, o Options) (*Plan, *reach.Report, error) {
	if o.Inner == nil {
		return nil, nil, errors.New("repack: Inner is required")
	}
	if o.Head == nil {
		return nil, nil, errors.New("repack: Head is required")
	}
	if len(o.Live) == 0 {
		// Deliberately not "then plan nothing": an empty live set means
		// every pack looks dead, and answering that would be answering the
		// most dangerous question with the most dangerous answer.
		return nil, nil, errors.New("repack: no live generations were supplied")
	}
	if !inLiveSet(o.Head, o.Live) {
		return nil, nil, fmt.Errorf("repack: head generation %d is not in the live set, so its own packs would sweep as unreferenced", o.Head.Generation)
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.PackLive <= 0 {
		o.PackLive = DefaultLiveFraction
	}
	if o.RefLive <= 0 {
		o.RefLive = DefaultLiveFraction
	}
	// A threshold above 1 proposes rewriting objects that are entirely
	// live, which is pure cost. Refused rather than clamped: a caller that
	// passed 50 meaning 50% should hear about it.
	if o.PackLive > 1 || o.RefLive > 1 {
		return nil, nil, fmt.Errorf("repack: liveness thresholds are fractions in (0, 1], got %g and %g", o.PackLive, o.RefLive)
	}
	if o.TargetPackSize <= 0 {
		o.TargetPackSize = defaultTargetPackSize
	}

	rep, err := reach.Sweep(ctx, reach.Options{
		Inner:            o.Inner,
		Live:             o.Live,
		DEK:              o.DEK,
		CacheDir:         o.CacheDir,
		Workers:          o.Workers,
		CollectReachable: o.collectReachable,
	})
	var inc *reach.Incomplete
	if errors.As(err, &inc) {
		return refused(inc), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return build(ctx, o, swept{rep}), rep, nil
}

// refused turns an incomplete sweep into the only plan it entitles anyone
// to: an empty one, and the reasons. The conservative report the error
// carries is deliberately NOT copied into the plan's counters — it says
// every pack is fully live, which is a floor on what must be kept and not
// a description of the volume, and a caller reading it out of a
// Plan.Bytes field would be reading it as one.
func refused(inc *reach.Incomplete) *Plan {
	p := &Plan{Refusal: inc.Error()}
	for i, f := range inc.Failures {
		if i == maxNames {
			p.Notes = append(p.Notes, Note{Object: "sweep", Detail: fmt.Sprintf("and %d more failure(s)", len(inc.Failures)-i)})
			break
		}
		p.Notes = append(p.Notes, Note{Object: f.Object, Detail: f.Detail})
	}
	return p
}

// build is the plan proper. Taking a swept value rather than a
// *reach.Report is the point (see the type).
func build(ctx context.Context, o Options, s swept) *Plan {
	rep := s.rep
	grace := graceWindow(o)
	p := &Plan{
		Generations:  rep.Generations,
		ScannedPacks: len(rep.Packs),
		Bytes:        rep.Bytes,
		LiveBytes:    rep.LiveBytes,
		Grace:        grace,
	}
	condemned := planPacks(o, s, o.Now.Add(-grace), p)
	planRefs(ctx, o, s, o.Now.Add(-grace), condemned, p)
	return p
}

// graceWindow mirrors retention's: the widest window any live generation
// RECORDS, the format's default when none records one, and Options may
// only widen it further. The two must agree — a planner proposing to
// condemn a pack the GC would refuse to delete plans work that reclaims
// nothing, and a planner using a wider window than the sweep would condemn
// packs the sweep then deletes early.
//
// The default is not a floor, which is what changed when T_grace became a
// per-volume parameter: a volume created with `--grace 12h` plans against
// twelve hours, exactly as its sweep does.
func graceWindow(o Options) time.Duration {
	var stated time.Duration
	for _, sb := range o.Live {
		if g := sb.Params.Grace(); g > stated {
			stated = g
		}
	}
	grace := retention.DefaultGrace
	if stated > 0 {
		grace = stated
	}
	if o.Grace > grace {
		grace = o.Grace
	}
	return grace
}

// planPacks selects the packs worth rewriting and returns the set it
// proposes to condemn, which the ref pass needs: a manifest segment's
// entries for those packs are about to become stale, and an index's
// entries into them about to resolve to nothing.
func planPacks(o Options, s swept, cutoff time.Time, p *Plan) map[string]bool {
	condemned := make(map[string]bool)
	var move int64
	for _, pk := range s.rep.Packs {
		// A clean sweep indexes every pack it lists — an unreadable trailer
		// is a failure and a failure is an *Incomplete — so this cannot fire
		// on a swept report. It is here because "unindexed" means Bytes is
		// zero, and a zero-byte pack reads as 100% dead to any arithmetic
		// that forgets to ask.
		if !pk.Indexed {
			p.Notes = append(p.Notes, Note{Object: pk.Name, Detail: "trailer was not read; not a candidate"})
			continue
		}
		if pk.LiveFraction() >= o.PackLive {
			continue
		}
		created, ok := packstore.PackNameTime(pk.Name)
		if !ok || created.After(cutoff) {
			// The age guard, and it is not an optimization: a pack younger
			// than the window may be one a concurrent writer is about to
			// reference from a generation this sweep never saw. A name that
			// will not parse is treated as young forever, exactly as
			// retention treats it — a pack we cannot age is a pack we do not
			// touch.
			p.SkippedYoung++
			if len(p.SkippedYoungNames) < maxNames {
				p.SkippedYoungNames = append(p.SkippedYoungNames, pk.Name)
			}
			continue
		}
		c := PackCandidate{
			Name:         pk.Name,
			Size:         pk.Size,
			Entries:      pk.Entries,
			LiveEntries:  pk.LiveEntries,
			Bytes:        pk.Bytes,
			LiveBytes:    pk.LiveBytes,
			LiveFraction: pk.LiveFraction(),
			Move:         pk.LiveBytes,
			Reclaim:      pk.Size - pk.LiveBytes,
			Age:          o.Now.Sub(created),
		}
		p.Packs = append(p.Packs, c)
		condemned[pk.Name] = true
		move += c.Move
	}
	if move > 0 {
		// A floor: entries do not split across packs, so a rewrite may need
		// one more than the division says.
		p.IntoPacks = int((move + o.TargetPackSize - 1) / o.TargetPackSize)
	}
	return condemned
}

// planRefs selects the index and manifest refs worth retiring.
//
// Both are judged the same way and against the volume AFTER the pack part
// of this plan: a ref is dead in proportion to the packs it names that no
// live generation names any more, PLUS the packs this plan proposes to
// condemn. Measuring against the volume as it stands today would report
// every ref fully live until a repack had already run — no pack has ever
// been condemned, so nothing is ever stale — and would make the rule
// unreachable rather than conservative. The two halves belong to one
// publish anyway: a repack that drops packs from the list is exactly the
// event that makes a segment worth rewriting.
func planRefs(ctx context.Context, o Options, s swept, cutoff time.Time, condemned map[string]bool, p *Plan) {
	byName := make(map[string]reach.Pack, len(s.rep.Packs))
	for _, pk := range s.rep.Packs {
		byName[pk.Name] = pk
	}

	judge := func(kind RefKind, dir, name string, size int64, packs []string) {
		if len(packs) == 0 {
			// A ref naming no packs is either empty or something this build
			// does not understand. Either way there is no fraction to take
			// and nothing to propose.
			p.Notes = append(p.Notes, Note{Object: string(kind) + " " + name, Detail: "names no packs; not a candidate"})
			return
		}
		c := RefCandidate{Kind: kind, Name: name, Size: size, Packs: len(packs)}
		for _, pn := range packs {
			pk, listed := byName[pn]
			switch {
			case !listed:
				// No live generation names it: already swept, or on the next
				// sweep. Its entry here resolves to nothing.
				c.GonePacks++
			case condemned[pn]:
				c.CondemnedPacks++
			case pk.LiveBytes > 0:
				c.LivePacks++
			default:
				// Fully dead but held back by the age guard, so it stays in
				// the pack list and this ref must go on naming it.
				c.LivePacks++
			}
		}
		c.LiveFraction = float64(c.LivePacks) / float64(c.Packs)
		if c.LiveFraction >= o.RefLive {
			return
		}
		// The age guard again, on a different clock. A hash-named object
		// carries no time in its name (retention's observation), so the age
		// comes from its mtime, and an object whose time cannot be
		// established is left alone — publish uploads a ref before it flips
		// the ref that names it, so "young and unnamed" is a real state.
		written, ok := objectTime(ctx, o.Inner, dir+"/"+name)
		if !ok || written.After(cutoff) {
			p.SkippedYoung++
			if len(p.SkippedYoungNames) < maxNames {
				p.SkippedYoungNames = append(p.SkippedYoungNames, name)
			}
			return
		}
		c.Move = size
		c.Reclaim = int64(float64(size) * (1 - c.LiveFraction))
		p.Refs = append(p.Refs, c)
	}

	// Fetching each ref is what makes this decidable: a ref's size and
	// pack COUNT are on the superblock, but which packs it names is only
	// in the object. The cost is bounded by consolidation's ceiling (64
	// MiB per ref) and paid once per plan, against a decision to move
	// megabytes.
	for _, ref := range o.Head.Manifests {
		m, err := manifest.Fetch(ctx, o.Inner, ref)
		if err != nil {
			// Not a refusal. The sweep already resolved this generation's
			// pack set through these same segments, so a failure here is
			// transient rather than structural; and a ref that cannot be read
			// is one this plan simply does not mention. Declining to propose
			// work is always safe.
			p.Notes = append(p.Notes, Note{Object: "manifest " + ref.Name, Detail: "not read, so not judged: " + err.Error()})
			continue
		}
		names := make([]string, 0, m.Len())
		for i := 0; i < m.Len(); i++ {
			names = append(names, m.At(i).Name)
		}
		judge(RefManifest, manifest.Dir, ref.Name, ref.Size, names)
	}
	for _, ref := range o.Head.PackIndexes {
		ix, err := mpi.Fetch(ctx, o.Inner, ref)
		if err != nil {
			p.Notes = append(p.Notes, Note{Object: "index " + ref.Name, Detail: "not read, so not judged: " + err.Error()})
			continue
		}
		judge(RefIndex, mpi.Dir, ref.Name, ref.Size, ix.Packs())
	}
}

// objectTime reports when a hash-named object was written. Only a HEAD:
// this asks about a handful of refs the plan already wants to touch, so
// there is nothing to amortize a listing over.
func objectTime(ctx context.Context, inner pelicanobj.Store, key string) (time.Time, bool) {
	ki, err := inner.StatKey(ctx, key)
	if err != nil || ki == nil || ki.Mtime.IsZero() {
		return time.Time{}, false
	}
	return ki.Mtime, true
}

// inLiveSet reports whether the head is one of the live generations. The
// pointer case is the ordinary one; the value comparison catches a caller
// that fetched the head twice, which is what a CLI listing branches and
// then naming one does.
//
// The value comparison is by IDENTITY and not by generation number
// (sameGeneration, execute.go). A number identifies a generation only
// within one lineage — two branches of a volume both seal N+1 on top of
// their own N — so on a multi-branch volume a number match would let a
// SIBLING branch's head vouch for a head that is genuinely missing from
// the live set, and the sweep would then report this branch's own packs as
// unreferenced. That is the exact failure this check exists to prevent.
func inLiveSet(head *superblock.Superblock, live []*superblock.Superblock) bool {
	for _, sb := range live {
		if sb == nil {
			continue
		}
		if sb == head || sameGeneration(sb, head) {
			return true
		}
	}
	return false
}
