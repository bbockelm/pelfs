package repack_test

// The invariants that make CONDEMN-THEN-COLLECT safe, driven by randomized
// interleavings of the operations that can race: seal, repack, gc, tag,
// crash-and-remount.
//
// Every other test in this tree fixes an order and asserts a consequence of
// it. These fix a SEED and let the order vary, because the failures this
// design can have are ordering failures: a sweep that ran between an upload
// and a flip, a consolidation that landed while a seal was reading the list
// it was consolidating, a ledger entry that aged out one cycle before the
// reader that needed it stopped reading.
//
// Each test states its invariant as a sentence, drives a random sequence,
// and on failure dumps the sequence — which is the only thing that makes a
// randomized failure actionable. Seeds are fixed so a failure reproduces;
// PELFS_LIFECYCLE_SEEDS raises the count for a longer run.

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/mpi"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"

	mrand "math/rand"
)

// seeds is how many independent sequences each property runs. Two keeps
// the suite inside its CI budget; PELFS_LIFECYCLE_SEEDS=20 is the longer
// mode, which is where a rare interleaving actually gets found.
func seeds(t *testing.T) []int64 {
	n := 2
	if s := os.Getenv("PELFS_LIFECYCLE_SEEDS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			t.Fatalf("PELFS_LIFECYCLE_SEEDS=%q is not a positive count", s)
		}
		n = v
	}
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(0x5eed0000 + i)
	}
	return out
}

// world is one volume under a random sequence, plus everything needed to
// check it afterwards: what the tree should contain, what has been tagged,
// and the op log that makes a failure reproducible.
type world struct {
	t     *testing.T
	rng   *mrand.Rand
	inner pelicanobj.Store
	v     *testvol.Volume
	rs    *refs.Store

	ops   []string
	want  map[string][]byte
	files []string
	// pinned are the generations a reader may still be holding: every tag,
	// plus the head. Only these are RETAINED — retention's live set is
	// head-plus-tags, because a retired generation is addressable only by
	// hash and a sweep cannot enumerate it.
	pinned []pin
	// clock is the seal clock, advanced explicitly so ledger ageing can be
	// driven rather than waited for.
	clock time.Time

	// did counts the operations that actually ran. Every property asserts a
	// floor on it: a randomized sequence that happened to seal once and
	// sweep never is a test that cannot fail, which is worse than no test
	// because it reads like coverage.
	did map[string]int
}

// ran reports how many of an operation the sequence performed.
func (w *world) ran(kind string) int { return w.did[kind] }

// mustHaveRun fails when the sequence did not reach the states the property
// is about.
func (w *world) mustHaveRun(min map[string]int) {
	w.t.Helper()
	for kind, n := range min {
		if w.did[kind] < n {
			w.fatalf("fixture: the sequence ran %d %s operations, and this property needs at least %d; "+
				"it proved nothing", w.did[kind], kind, n)
		}
	}
}

// pin is a generation something is still reading, and the tree it must
// still show.
type pin struct {
	label string
	sb    *superblock.Superblock
	want  map[string][]byte
}

func newWorld(t *testing.T, seed int64, uuid string) *world {
	t.Helper()
	inner, _ := newInner(t)
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{
		t:     t,
		rng:   mrand.New(mrand.NewSource(seed)),
		inner: inner,
		v:     testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)}),
		rs:    rs,
		want:  map[string][]byte{},
		clock: time.Now(),
		did:   map[string]int{},
	}
	return w
}

func (w *world) logf(format string, args ...any) {
	w.ops = append(w.ops, fmt.Sprintf(format, args...))
}

func (w *world) count(kind string) { w.did[kind]++ }

// fatalf fails with the op sequence attached. A randomized failure without
// the sequence is a bug report nobody can act on.
func (w *world) fatalf(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("%s\n\nOP SEQUENCE (%d ops):\n  %s", fmt.Sprintf(format, args...),
		len(w.ops), strings.Join(w.ops, "\n  "))
}

func (w *world) errorf(format string, args ...any) {
	w.t.Helper()
	w.t.Errorf("%s\n\nOP SEQUENCE (%d ops):\n  %s", fmt.Sprintf(format, args...),
		len(w.ops), strings.Join(w.ops, "\n  "))
}

// ---- operations ----

// write creates a new file or rewrites an existing one. Rewriting is what
// produces garbage: the old chunks stay in their packs, referenced by
// nothing the new generation names, which is what a repack is for.
func (w *world) write() {
	if len(w.files) > 0 && w.rng.Intn(3) > 0 {
		name := w.files[w.rng.Intn(len(w.files))]
		body := pseudorandom(64<<10+w.rng.Intn(192<<10), w.rng.Int63())
		w.v.Write(w.v.Lookup(rootIno, name), body)
		w.want[name] = body
		w.count("write")
		w.logf("rewrite %s (%d bytes)", name, len(body))
		return
	}
	name := fmt.Sprintf("f%02d.bin", len(w.files))
	body := pseudorandom(64<<10+w.rng.Intn(192<<10), w.rng.Int63())
	w.v.WriteFile(rootIno, name, body)
	w.files = append(w.files, name)
	w.want[name] = body
	w.count("write")
	w.logf("create %s (%d bytes)", name, len(body))
}

// seal publishes a generation at the world's clock.
func (w *world) seal() *publish.Result {
	o := publishOpts
	o.CreatedUnixNano = w.clock.UnixNano()
	res := w.v.Publish(o)
	w.count("seal")
	w.logf("seal -> generation %d (%d manifest refs, %d condemned-manifest rows, %d condemned packs)",
		res.Superblock.Generation, len(res.Superblock.Manifests),
		len(res.Superblock.CondemnedManifests), len(res.Superblock.Condemned))
	return res
}

// advance moves the seal clock, which is how a ledger is aged without the
// test sleeping.
func (w *world) advance(d time.Duration) {
	w.clock = w.clock.Add(d)
	w.logf("clock += %v", d)
}

// repack rewrites the mostly-dead packs and re-seats the volume on what it
// published, as a mount does when it sees the branch move.
func (w *world) repack() *repack.Result {
	ctx := context.Background()
	head := w.head()
	res, err := repack.Execute(ctx, repack.ExecOptions{
		Options: repack.Options{
			Inner: w.inner, Live: []*superblock.Superblock{head.Superblock}, Head: head.Superblock,
			CacheDir: w.t.TempDir(), Workers: 4, Now: w.clock.Add(aged),
		},
		Refs: w.rs, Branch: "main", SigningKey: w.v.SigningKey(), SpoolDir: w.t.TempDir(),
	})
	if err != nil {
		w.fatalf("repack: %v", err)
	}
	after := w.head()
	w.v.Adopt(after.Superblock, after.Raw)
	w.count("repack")
	if len(res.CondemnedPacks) > 0 {
		w.count("repack-condemned")
	}
	w.logf("repack -> generation %d (condemned %d packs, %d rows on the ledger)",
		after.Superblock.Generation, len(res.CondemnedPacks), len(after.Superblock.Condemned))
	return res
}

// gc sweeps at the given clock. A FAR-FUTURE clock is the adversarial
// setting: every age guard has expired and every ledger entry has aged out,
// so the only thing left protecting an object is a live superblock naming
// it.
func (w *world) gc(at time.Time, del bool) *retention.Report {
	rep, err := retention.GC(context.Background(), retention.Options{
		Inner: w.inner, Refs: w.rs, Delete: del, Now: at,
	})
	if err != nil {
		w.fatalf("gc: %v", err)
	}
	w.count("gc")
	if del {
		w.count("gc-delete")
	}
	if rep.Deleted+rep.Indexes.Deleted+rep.Manifests.Deleted > 0 {
		w.count("gc-collected")
	}
	w.logf("gc(delete=%v, clock+%v) -> deleted %d packs, %d indexes, %d manifests",
		del, at.Sub(w.clock).Round(time.Hour), rep.Deleted, rep.Indexes.Deleted, rep.Manifests.Deleted)
	return rep
}

// tag freezes the current head under a name, which is the one way a
// workflow pins a generation past the grace window.
func (w *world) tag(name string) {
	head := w.head()
	if err := w.rs.Tag(context.Background(), name, head.Raw); err != nil {
		w.fatalf("tag %s: %v", name, err)
	}
	snapshot := make(map[string][]byte, len(w.want))
	for k, v := range w.want {
		snapshot[k] = v
	}
	w.pinned = append(w.pinned, pin{label: "tag " + name, sb: head.Superblock, want: snapshot})
	w.count("tag")
	w.logf("tag %s at generation %d", name, head.Superblock.Generation)
}

func (w *world) head() *refs.Fetched {
	f, err := w.rs.Fetch(context.Background(), "main")
	if err != nil {
		w.fatalf("read the branch head: %v", err)
	}
	return f
}

// reads asserts a generation is COLD-readable and byte-exact: a fresh
// genfs with an empty cache, resolving every identity from what the
// superblock names and nothing else.
func (w *world) reads(sb *superblock.Superblock, want map[string][]byte, label string) {
	w.t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{Inner: w.inner, SB: sb, CacheDir: w.t.TempDir()})
	if err != nil {
		w.fatalf("%s: generation %d will not mount: %v", label, sb.Generation, err)
	}
	defer fs.Close() //nolint:errcheck
	for name, body := range want {
		n, err := fs.Lookup(ctx, rootIno, name)
		if err != nil {
			w.fatalf("%s: generation %d cannot resolve %s: %v", label, sb.Generation, name, err)
		}
		got := make([]byte, len(body))
		read, err := fs.Read(ctx, n.Inode, 0, got)
		if err != nil {
			w.fatalf("%s: generation %d cannot read %s: %v", label, sb.Generation, name, err)
		}
		if read != len(body) {
			w.fatalf("%s: generation %d read %d of %d bytes of %s", label, sb.Generation, read, len(body), name)
		}
		for i := range body {
			if got[i] != body[i] {
				w.fatalf("%s: generation %d serves %s wrong at byte %d", label, sb.Generation, name, i)
			}
		}
	}
}

// packSet is the pack names a generation resolves to, through whichever
// shape it uses.
func (w *world) packSet(sb *superblock.Superblock) map[string]bool {
	packs, err := manifest.Packs(context.Background(), w.inner, sb)
	if err != nil {
		w.fatalf("generation %d cannot state its pack set: %v", sb.Generation, err)
	}
	out := make(map[string]bool, len(packs))
	for _, p := range packs {
		out[p.Name] = true
	}
	return out
}

// step drives one random operation from the set that can race. Weighted so
// that seals dominate — that is what a mount does — with repacks and
// sweeps landing between them at arbitrary points.
func (w *world) step() {
	switch n := w.rng.Intn(100); {
	case n < 45:
		w.write()
	case n < 80:
		w.seal()
	case n < 88:
		// A sweep that cannot delete still exercises the read side: it
		// resolves every manifest of every ref and tag, which is the thing
		// that breaks when a segment is swept out from under a generation.
		w.gc(w.clock, false)
	case n < 96:
		w.seal()
		w.repack()
	default:
		w.gc(w.clock.Add(aged), true)
	}
}

// ---------------------------------------------------------------------
// INVARIANT 1
// ---------------------------------------------------------------------

// INVARIANT: no object a RETAINED generation references is ever condemned
// and then collected.
//
// Retained means what a sweep can enumerate — the branch head and every tag
// — because a retired generation is addressable only by its hash. The gc
// here runs on a FAR-FUTURE clock, which is the adversarial setting: every
// pack's name-age guard has expired, every derived object's mtime guard has
// expired, and every condemned-ledger row has aged out. Nothing is left
// protecting an object except a live superblock naming it. If the pack
// list, the manifest refs, or the arithmetic that maintains them is wrong
// anywhere, the sweep deletes something the head still needs and the head
// stops reading.
func TestNoRetainedGenerationLosesAnObjectToTheSweep(t *testing.T) {
	for _, seed := range seeds(t) {
		t.Run(fmt.Sprintf("seed-%x", seed), func(t *testing.T) {
			w := newWorld(t, seed, "11111111-0000-0000-0000-000000000001")
			// A tag early, so a generation that is NOT the head is retained
			// for the whole run and the sweep has to keep two closures apart.
			w.write()
			w.seal()
			w.tag("pinned")

			for range 24 {
				w.step()
			}
			// Land on a sealed state so the head is what the writes produced.
			w.write()
			w.seal()
			// A repack somewhere in the sequence, so the pack ledger and the
			// wholesale manifest rewrite are both in play rather than left to
			// the dice. Before the head is pinned, because a repack RETIRES
			// the generation it grew from, and an untagged retired generation
			// is not retained — asserting otherwise would be asserting a
			// promise this format deliberately does not make.
			if w.ran("repack") == 0 {
				w.repack()
			}
			w.mustHaveRun(map[string]int{"seal": 4, "repack": 1, "tag": 1, "write": 6})
			head := w.head()
			w.pinned = append(w.pinned, pin{label: "head", sb: head.Superblock, want: w.want})

			// The adversarial sweep: delete everything not named by a live
			// superblock, with every window long expired.
			w.gc(w.clock.Add(aged), true)

			for _, p := range w.pinned {
				w.reads(p.sb, p.want, p.label+" after the far-future sweep")
			}
			// And a second sweep finds nothing new: the first one was
			// complete, so the volume is at its floor.
			second := w.gc(w.clock.Add(2*aged), true)
			if second.Deleted != 0 {
				w.errorf("a second far-future sweep deleted %d more objects; the first left garbage the "+
					"live set could not account for", second.Deleted)
			}
		})
	}
}

// ---------------------------------------------------------------------
// INVARIANT 2
// ---------------------------------------------------------------------

// INVARIANT: consolidation never loses a pack.
//
// A seal merges manifest segments into one and stops listing the inputs; a
// repack rewrites the whole manifest. Both change how the pack set is
// NAMED, and neither may change what it IS. The check is the strongest
// available: resolve the generation's whole pack set before and after every
// transition, and require the merged set to be exactly the old set, plus
// what the writer added, minus what it condemned. A merge that dropped a
// segment's run would show up here as missing packs, and those packs are
// precisely what the next sweep deletes.
func TestConsolidationNeverLosesAPack(t *testing.T) {
	for _, seed := range seeds(t) {
		t.Run(fmt.Sprintf("seed-%x", seed), func(t *testing.T) {
			w := newWorld(t, seed, "22222222-0000-0000-0000-000000000002")
			w.write()
			prev := w.seal()
			before := w.packSet(prev.Superblock)

			for range 26 {
				// Writes make packs; seals consolidate; repacks rewrite the
				// manifest wholesale. Only the three matter here.
				switch n := w.rng.Intn(100); {
				case n < 50:
					w.write()
					continue
				case n < 90:
					res := w.seal()
					added := map[string]bool{}
					for _, p := range res.NewPacks {
						added[p.Name] = true
					}
					after := w.packSet(res.Superblock)
					checkPackSet(w, before, added, nil, after, "seal", res.Superblock)
					before = after
				default:
					w.seal()
					before = w.packSet(w.head().Superblock)
					res := w.repack()
					condemned := map[string]bool{}
					for _, name := range res.CondemnedPacks {
						condemned[name] = true
					}
					added := map[string]bool{}
					for _, p := range res.NewPacks {
						added[p.Name] = true
					}
					sb := w.head().Superblock
					after := w.packSet(sb)
					checkPackSet(w, before, added, condemned, after, "repack", sb)
					before = after
				}
			}
			// The tier transitions are what this is about; a run that never
			// merged, or never rewrote a manifest wholesale, proves nothing.
			if w.ran("repack") == 0 {
				before = w.packSet(w.head().Superblock)
				res := w.repack()
				condemned := map[string]bool{}
				for _, name := range res.CondemnedPacks {
					condemned[name] = true
				}
				added := map[string]bool{}
				for _, p := range res.NewPacks {
					added[p.Name] = true
				}
				sb := w.head().Superblock
				checkPackSet(w, before, added, condemned, w.packSet(sb), "repack", sb)
			}
			w.mustHaveRun(map[string]int{"seal": 5, "repack": 1, "write": 8})
		})
	}
}

// checkPackSet is the set equation, both directions. Both directions
// matter: a lost pack is data gone, and an INVENTED one is a name the
// signature vouches for that no writer wrote.
func checkPackSet(w *world, before, added, condemned map[string]bool, after map[string]bool,
	what string, sb *superblock.Superblock) {
	w.t.Helper()
	want := map[string]bool{}
	for name := range before {
		if !condemned[name] {
			want[name] = true
		}
	}
	for name := range added {
		want[name] = true
	}
	for name := range want {
		if !after[name] {
			w.errorf("after a %s, generation %d no longer names pack %s; it was in the parent's set, was "+
				"not condemned, and the next sweep deletes it", what, sb.Generation, name)
		}
	}
	for name := range after {
		if !want[name] {
			w.errorf("after a %s, generation %d names pack %s that neither its parent nor this writer "+
				"produced", what, sb.Generation, name)
		}
	}
}

// ---------------------------------------------------------------------
// INVARIANT 3
// ---------------------------------------------------------------------

// INVARIANT: the ledgers converge — every condemned object is eventually
// collected or re-listed, nothing lingers past the grace window plus one
// cycle, and the ledger returns to its baseline once churn stops.
//
// This is the property that makes the ledgers BOUNDED rather than merely
// capped. A row that never aged off would grow the superblock until it
// passed the read cap, which is a volume that can be neither mounted nor
// published; a row that aged off while its object was still needed is the
// hole the cap discussion is about. So: churn hard, stop, advance the clock
// past the window, and require the ledger back at baseline AND every object
// it once named either still listed or actually gone.
func TestTheCondemnedLedgersConverge(t *testing.T) {
	for _, seed := range seeds(t) {
		t.Run(fmt.Sprintf("seed-%x", seed), func(t *testing.T) {
			w := newWorld(t, seed, "33333333-0000-0000-0000-000000000003")
			grace := retention.DefaultGrace

			// Churn: every seal condemns the segment it merged away.
			everCondemned := map[string]bool{}
			for range 12 {
				w.write()
				res := w.seal()
				w.advance(time.Minute)
				for _, c := range res.Superblock.CondemnedManifests {
					everCondemned[c.Name] = true
				}
			}
			peak := len(w.head().Superblock.CondemnedManifests)
			if peak == 0 {
				t.Fatal("fixture: no seal condemned a manifest segment, so there is no ledger to converge")
			}

			// Churn stops. Time passes: one seal past the grace window is
			// all it takes, because carrying forward is what ages rows off.
			w.advance(grace + time.Hour)
			w.write()
			w.seal()

			head := w.head().Superblock
			if got := len(head.CondemnedManifests); got > 1 {
				w.errorf("%d rows are still on the condemned-manifest ledger a full grace window after churn "+
					"stopped (peak was %d); rows that do not age off grow the superblock until it passes "+
					"the read cap", got, peak)
			}
			// A seal past the window carries nothing forward, so the pack
			// ledger has to be empty too — no repack ran in this sequence.
			if got := len(head.Condemned); got != 0 {
				w.errorf("%d rows on the condemned-pack ledger with no repack in the sequence", got)
			}

			// And the objects those rows named are settled: still listed, or
			// actually deleted. Nothing lingers unreferenced and unswept.
			w.gc(w.clock.Add(grace+time.Hour), true)
			listed := map[string]bool{}
			for _, ref := range w.head().Superblock.Manifests {
				listed[ref.Name] = true
			}
			for name := range everCondemned {
				if listed[name] {
					continue
				}
				if objectExists(w, manifest.Dir+"/"+name) {
					w.errorf("manifest %s was condemned, has aged out of every ledger, is named by no live "+
						"generation, and is still in the store after a sweep past the window", name[:12])
				}
			}
			// Convergence has to be a floor, not a trend: sweeping again
			// changes nothing.
			if again := w.gc(w.clock.Add(2*grace), true); again.Manifests.Deleted != 0 {
				w.errorf("a second sweep deleted %d more manifests", again.Manifests.Deleted)
			}
			w.mustHaveRun(map[string]int{"seal": 13, "gc-delete": 1, "gc-collected": 1, "write": 13})
		})
	}
}

func objectExists(w *world, key string) bool {
	_, err := w.inner.StatKey(context.Background(), key)
	return err == nil
}

// ---------------------------------------------------------------------
// INVARIANT 4
// ---------------------------------------------------------------------

// INVARIANT: a cold reader at ANY retained generation resolves every
// identity that generation can name.
//
// "Cold" is load-bearing: a fresh cache, so every catalog, every pack and
// every location comes out of the federation through what the superblock
// names — the manifest for the pack set, the index or the trailers for the
// locations. A tag is the only pin that survives arbitrary time, so the
// sequence takes several, at different points, and reads all of them back
// byte-exact after everything else has happened to the volume.
//
// The half that would otherwise go untested is the OLD tags: their pack
// sets overlap the head's, a repack moves bytes out from under them, and
// nothing rewrites what they name. They read because identity is not
// location.
func TestEveryRetainedGenerationStillResolvesEverythingItNames(t *testing.T) {
	for _, seed := range seeds(t) {
		t.Run(fmt.Sprintf("seed-%x", seed), func(t *testing.T) {
			w := newWorld(t, seed, "44444444-0000-0000-0000-000000000004")
			for i := range 4 {
				for range 2 + w.rng.Intn(3) {
					w.write()
				}
				w.seal()
				w.tag(fmt.Sprintf("t%d", i))
				// Between tags, anything: more writes, a repack that moves
				// the tagged generation's bytes into different packs, a
				// sweep that is allowed to delete.
				for range 3 {
					w.step()
				}
			}
			w.write()
			w.seal()

			// A repack after the last tag, so at least one tagged generation
			// is certainly reading through packs that no longer hold its
			// bytes where its hint says they are.
			w.repack()
			w.gc(w.clock.Add(aged), true)

			// The head pin is taken HERE, after everything that can retire a
			// generation has happened. An untagged generation that a repack
			// superseded is not retained and the design does not claim it is
			// — pinning one earlier would be asserting a promise this format
			// deliberately does not make.
			head := w.head()
			w.pinned = append(w.pinned, pin{label: "head", sb: head.Superblock, want: w.want})

			for _, p := range w.pinned {
				w.reads(p.sb, p.want, p.label)
			}
			if len(w.pinned) < 5 {
				t.Fatalf("fixture: only %d generations were pinned", len(w.pinned))
			}
		})
	}
}

// ---------------------------------------------------------------------
// INVARIANT 5
// ---------------------------------------------------------------------

// INVARIANT: a crash leaves the volume mountable at a WHOLE generation,
// with orphans and never dangling references — and the orphans are exactly
// what a sweep past the grace window collects.
//
// The three windows a publish has, in the order it passes through them:
// after the derived objects are uploaded and before the ref flips; after
// the flip; and inside consolidation, which uploads a merged object and
// then re-points the list at it. Every one of them can be interrupted, and
// the design's claim is that none of them can produce a head that names
// something absent. A crash before the flip leaves objects nothing names —
// garbage, collectable. A crash after it leaves a complete new generation.
// There is no third outcome, and that is what "flip last" buys.
func TestACrashLeavesOrphansAndNeverADanglingReference(t *testing.T) {
	for _, seed := range seeds(t) {
		t.Run(fmt.Sprintf("seed-%x", seed), func(t *testing.T) {
			w := newWorld(t, seed, "55555555-0000-0000-0000-000000000005")
			for range 2 + w.rng.Intn(3) {
				w.write()
			}
			w.seal()
			for range 6 {
				w.step()
			}
			w.write()
			w.seal()

			survivor := w.head()
			before := objectNames(w)

			// THE CRASH. The failing key space is chosen by the seed: a
			// manifest upload is the one that cannot be survived by falling
			// back, an index upload is the one that can, and a ref flip is
			// the window between "everything is uploaded" and "anyone can
			// see it".
			var failing string
			switch w.rng.Intn(3) {
			case 0:
				failing = manifest.Dir
			case 1:
				failing = mpi.Dir
			default:
				failing = publish.RefPrefix
			}
			w.logf("CRASH: every write under %s fails from here", failing)
			crashed := &faultStore{Store: w.inner, failPrefix: failing}

			// A seal through the broken store. It may fail (the manifest and
			// the ref flip are not survivable) or succeed with a warning (an
			// index is a hint) — what is NOT allowed is a head that names
			// something that is not there.
			//
			// The tree as of the last COMPLETE seal, which is what the old
			// head must still show if the interrupted one does not land. The
			// write below is only in the volume if the seal finished.
			settled := make(map[string][]byte, len(w.want))
			for k, v := range w.want {
				settled[k] = v
			}
			w.write()
			o := publishOpts
			o.CreatedUnixNano = w.clock.UnixNano()
			o.Overlay = w.v.Overlay()
			o.Inner = crashed
			o.SpoolDir = t.TempDir()
			o.Branch = "main"
			o.SigningKey = w.v.SigningKey()
			o.Prev, o.PrevRaw = survivor.Superblock, survivor.Raw
			res, err := publish.Seal(context.Background(), o)
			w.logf("interrupted seal -> err=%v", err)

			// WHATEVER HAPPENED, the branch head is a whole generation and it
			// mounts cold.
			after := w.head()
			// live is the tree the surviving head must show — the settled one
			// if the seal did not land, the new one if it did. There is no
			// third answer, and that is the whole claim: a generation is
			// whole or it is not there.
			live := settled
			if err != nil {
				if after.Superblock.Generation != survivor.Superblock.Generation {
					w.fatalf("the seal failed with %v but the branch moved from generation %d to %d; a "+
						"failed publish must not flip", err, survivor.Superblock.Generation,
						after.Superblock.Generation)
				}
				w.reads(after.Superblock, settled, "the old head after an interrupted seal")
			} else {
				if res.Superblock.Generation != survivor.Superblock.Generation+1 {
					w.fatalf("a seal that succeeded published generation %d over %d",
						res.Superblock.Generation, survivor.Superblock.Generation)
				}
				live = w.want
				w.reads(after.Superblock, live, "the new head after a survivable interruption")
			}

			// And the debris is ORPHANS, never dangling references: every
			// object the head names is present, and everything the crash left
			// behind that it does not name is collected by a sweep past the
			// window.
			assertNoDanglingRefs(w, after.Superblock)
			w.gc(w.clock.Add(aged), true)
			assertNoDanglingRefs(w, w.head().Superblock)
			w.reads(w.head().Superblock, live, "the head after the debris was swept")

			w.mustHaveRun(map[string]int{"seal": 2, "gc-delete": 1, "write": 3})

			left := objectNames(w)
			for name := range left {
				if !before[name] && !namedByHead(w, name) {
					w.errorf("the crash left %s behind, no live generation names it, and a sweep past the "+
						"grace window did not collect it", name)
				}
			}
		})
	}
}

// assertNoDanglingRefs fetches everything the superblock names. A missing
// object here is the failure mode the whole flip-last ordering exists to
// make impossible.
func assertNoDanglingRefs(w *world, sb *superblock.Superblock) {
	w.t.Helper()
	ctx := context.Background()
	for _, ref := range sb.Manifests {
		if _, err := manifest.Fetch(ctx, w.inner, ref); err != nil {
			w.fatalf("generation %d names manifest %s and it does not resolve: %v",
				sb.Generation, ref.Name[:12], err)
		}
	}
	packs := w.packSet(sb)
	for name := range packs {
		if !objectExists(w, packstore.PackDirKey+"/"+name) {
			w.fatalf("generation %d names pack %s and it is not in the store", sb.Generation, name)
		}
	}
}

// objectNames lists every object in the three key spaces a publish writes.
func objectNames(w *world) map[string]bool {
	out := map[string]bool{}
	for _, dir := range []string{packstore.PackDirKey, manifest.Dir, mpi.Dir} {
		entries, err := w.inner.ListDir(context.Background(), dir)
		if err != nil {
			continue // a key space nothing has written to yet
		}
		for _, e := range entries {
			if !e.IsDir {
				out[dir+"/"+e.Name] = true
			}
		}
	}
	return out
}

func namedByHead(w *world, key string) bool {
	sb := w.head().Superblock
	name := key[strings.LastIndex(key, "/")+1:]
	for _, ref := range sb.Manifests {
		if ref.Name == name {
			return true
		}
	}
	for _, ref := range sb.PackIndexes {
		if ref.Name == name {
			return true
		}
	}
	return w.packSet(sb)[name]
}

// faultStore fails every write under one key space, which is how a crash
// is staged in process: the objects written before it are on the origin,
// the ones after are not, and the publish finds out at exactly the point a
// killed process would have stopped.
type faultStore struct {
	pelicanobj.Store
	failPrefix string
}

func (s *faultStore) Put(ctx context.Context, key string, in io.Reader) error {
	if strings.HasPrefix(key, s.failPrefix) {
		return fmt.Errorf("fault injected: %s", key)
	}
	return s.Store.Put(ctx, key, in)
}
