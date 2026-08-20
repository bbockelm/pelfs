package retention

// What Params.RetainK now MEANS, driven against real volumes: real packs,
// real superblock backups buried in them, real manifest segments that
// consolidation stops naming.
//
// The mirror is the point of nearly every test here. A generation is
// retained if it still MOUNTS COLD after an adversarial sweep — a fresh
// cache, every identity resolved out of the store — and the same assertion
// run at --retain-k 1 must show it NOT mounting. Without that half these
// would pass on a volume with no garbage at all.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// aged is comfortably past every grace window and mtime guard, which is
// the setting these tests need: with the age guards expired, the only
// thing left protecting an object is a superblock in the root set.
const aged = 400 * time.Hour

// windowPublishOpts keeps catalogs and packs small, so a handful of writes
// produce several packs and several catalog segments — enough for a seal
// to consolidate, which is what makes an older generation's manifest refs
// stop being named by the head.
var windowPublishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

// generation is one published state and the tree it must still show.
type generation struct {
	sb   *superblock.Superblock
	want map[string][]byte
}

// churn builds a volume of n generations past the empty one, rewriting the
// same files so that every seal leaves the previous generation's chunks
// referenced by nothing the head cares about.
func churn(t *testing.T, n int) (pelicanobj.Store, *testvol.Volume, *refs.Store, []generation, time.Time) {
	t.Helper()
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{})
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	want := map[string][]byte{}
	gens := []generation{{sb: v.Superblock(), want: map[string][]byte{}}}
	for i := range n {
		for _, name := range []string{"a.bin", "b.bin"} {
			body := bytes.Repeat([]byte{byte(i), byte(i * 7), 'x'}, 40<<10)
			if _, ok := want[name]; ok {
				v.Write(v.Lookup(testvol.RootInode, name), body)
			} else {
				v.WriteFile(testvol.RootInode, name, body)
			}
			want[name] = body
		}
		clock = clock.Add(time.Minute)
		o := windowPublishOpts
		o.CreatedUnixNano = clock.UnixNano()
		res := v.Publish(o)
		snapshot := make(map[string][]byte, len(want))
		for k, val := range want {
			snapshot[k] = val
		}
		gens = append(gens, generation{sb: res.Superblock, want: snapshot})
	}
	return inner, v, rs, gens, clock
}

// mounts reports whether a generation is cold-readable and byte-exact.
// Nothing is cached: every catalog, pack and location comes out of the
// store through what this superblock names.
func mounts(t *testing.T, inner pelicanobj.Store, g generation) error {
	t.Helper()
	ctx := context.Background()
	fs, err := genfs.Open(ctx, genfs.Options{Inner: inner, SB: g.sb, CacheDir: t.TempDir()})
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer fs.Close() //nolint:errcheck
	for name, body := range g.want {
		n, err := fs.Lookup(ctx, testvol.RootInode, name)
		if err != nil {
			return fmt.Errorf("lookup %s: %w", name, err)
		}
		got := make([]byte, len(body))
		read, err := fs.Read(ctx, n.Inode, 0, got)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if read != len(body) || !bytes.Equal(got, body) {
			return fmt.Errorf("%s came back different (%d of %d bytes)", name, read, len(body))
		}
	}
	return nil
}

// THE RULE. The sweep's root set is the last K generations of the branch,
// K counted on the branch's own chain WITH THE HEAD AS ONE OF THEM, and
// each of those generations stays fully readable after a sweep that has
// every age guard expired.
//
// The mirror at the bottom is what stops this being a test about a volume
// with no garbage: the same sweep at --retain-k 1 — the behaviour before
// this rule existed — must leave those same generations unmountable.
func TestTheSweepRetainsTheLastKGenerations(t *testing.T) {
	inner, _, rs, gens, clock := churn(t, 6)
	head := gens[len(gens)-1]
	if k := head.sb.Params.RetainK; k < uint32(len(gens)) {
		t.Fatalf("fixture: the head asks for %d generations and the volume only has %d, so the window "+
			"covers everything and its edge is never tested", k, len(gens))
	}

	rep, err := GC(context.Background(), Options{
		Inner: inner, Refs: rs, Delete: true, Now: clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(rep.Windows) != 1 {
		t.Fatalf("the sweep reported %d retain windows, want one per branch", len(rep.Windows))
	}
	if got, want := rep.Windows[0].Generations, len(gens); got != want {
		t.Fatalf("the sweep established %d generations of the window; this volume has %d and all of them "+
			"should be in it (unresolved: %v)", got, want, rep.Windows[0].Unresolved)
	}
	for _, g := range gens {
		if err := mounts(t, inner, g); err != nil {
			t.Errorf("generation %d is inside the retain-%d window and does not read after the sweep: %v",
				g.sb.Generation, rep.Windows[0].K, err)
		}
	}

	// THE MIRROR. Narrow the window to the head alone and sweep again: the
	// generations above must now go, or the test above was measuring a
	// volume with nothing to lose.
	if _, err := GC(context.Background(), Options{
		Inner: inner, Refs: rs, Delete: true, RetainK: 1, Now: clock.Add(2 * aged),
	}); err != nil {
		t.Fatalf("GC at retain-k 1: %v", err)
	}
	if err := mounts(t, inner, head); err != nil {
		t.Fatalf("the HEAD stopped reading after a sweep, which is a bug in the sweep and not in the "+
			"window: %v", err)
	}
	lost := 0
	for _, g := range gens[:len(gens)-1] {
		if mounts(t, inner, g) != nil {
			lost++
		}
	}
	if lost == 0 {
		t.Fatal("every retired generation still read after a head-only sweep, so the window was not what " +
			"kept them alive and this test proves nothing")
	}
	t.Logf("retain-%d kept %d generations; retain-1 left %d of %d retired generations unreadable",
		rep.Windows[0].K, rep.Windows[0].Generations, lost, len(gens)-1)
}

// K comes from the HEAD's Params, not from a constant in the sweep: a
// volume that states a different number gets that number, and the
// generation one step past the edge is not retained.
func TestTheWindowIsTheHeadsOwnParams(t *testing.T) {
	inner, v, rs, gens, clock := churn(t, 6)
	ctx := context.Background()

	// Re-publish the head with a smaller K, signed by the volume's own key
	// so it is the same document in every other respect. This is the only
	// way to state the parameter: publish hardcodes the default.
	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	narrowed := *f.Superblock
	narrowed.Params.RetainK = 3
	if err := narrowed.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := narrowed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(ctx, "main", raw, f.ETag); err != nil {
		t.Fatal(err)
	}
	gens[len(gens)-1].sb = &narrowed

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: clock.Add(aged)})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Windows[0].K != 3 || rep.Windows[0].Generations != 3 {
		t.Fatalf("the head states RetainK=3 and the sweep used K=%d over %d generations",
			rep.Windows[0].K, rep.Windows[0].Generations)
	}
	// Inside: the head and the two below it.
	for _, g := range gens[len(gens)-3:] {
		if err := mounts(t, inner, g); err != nil {
			t.Errorf("generation %d is inside the retain-3 window and does not read: %v", g.sb.Generation, err)
		}
	}
	// And the edge is real: one step further back is not retained, or "K"
	// would mean nothing.
	edge := gens[len(gens)-4]
	if mounts(t, inner, edge) == nil {
		t.Errorf("generation %d is one step outside the retain-3 window and still reads; the window is "+
			"not bounded by K at all", edge.sb.Generation)
	}
}

// K=1 is the sweep as it was before this rule, and it must cost nothing to
// say so: no listing of the pack space, no trailer read, no round trip.
// The window is the expensive part of a sweep, and a volume that does not
// want one should not pay for it.
func TestRetainKOfOneReadsNoTrailers(t *testing.T) {
	inner, _, rs, _, clock := churn(t, 3)
	rep, err := GC(context.Background(), Options{
		Inner: inner, Refs: rs, RetainK: 1, Now: clock.Add(aged),
	})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if rep.Windows[0].TrailersRead != 0 {
		t.Errorf("a retain-1 sweep read %d pack trailers; the head-only root set needs none",
			rep.Windows[0].TrailersRead)
	}
	if rep.Windows[0].Generations != 1 {
		t.Errorf("a retain-1 sweep established %d generations, want the head alone", rep.Windows[0].Generations)
	}
}

// A generation whose backup cannot be found is REPORTED, not guessed at
// and not fatal. The record of a retired generation lives in a pack, and a
// pack can be gone — swept by a run made before this rule existed, say. A
// sweep that refused to run would protect nothing (the record is gone
// either way) and would leave the volume unable to reclaim a byte for as
// long as the generation sat inside the window.
//
// The head here claims a generation number far past anything the volume
// has ever sealed, which is the cheapest way to ask for backups that
// cannot exist.
func TestAGenerationWithNoBackupIsReportedNotGuessed(t *testing.T) {
	inner, v, rs, gens, clock := churn(t, 3)
	ctx := context.Background()

	f, err := rs.Fetch(ctx, "main")
	if err != nil {
		t.Fatal(err)
	}
	jumped := *f.Superblock
	jumped.Generation = 500
	if err := jumped.Sign(v.SigningKey()); err != nil {
		t.Fatal(err)
	}
	raw, err := jumped.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Flip(ctx, "main", raw, f.ETag); err != nil {
		t.Fatal(err)
	}

	rep, err := GC(ctx, Options{Inner: inner, Refs: rs, Delete: true, Now: clock.Add(aged)})
	if err != nil {
		t.Fatalf("GC refused to run because a retired generation left no backup; that protects nothing "+
			"and stops the volume reclaiming anything: %v", err)
	}
	w := rep.Windows[0]
	if w.Generations != 1 {
		t.Errorf("the sweep established %d generations of the window; none of the backups it wanted exist", w.Generations)
	}
	if len(w.Unresolved) != int(w.K)-1 {
		t.Errorf("the sweep reported %d unresolved generations out of a window of %d; a short window that "+
			"is not reported is a silent loss", len(w.Unresolved), w.K)
	}
	// And the head is untouched by all of it.
	head := generation{sb: &jumped, want: gens[len(gens)-1].want}
	if err := mounts(t, inner, head); err != nil {
		t.Fatalf("the head does not read after a sweep with an unresolvable window: %v", err)
	}
}

// FAIL CLOSED. A backup that cannot be READ is not a backup that is
// absent: the first is unknown state and the second is a fact. A sweep
// that treated a transport failure as absence would quietly shrink the
// root set to whatever the network happened to answer, and delete the
// difference.
func TestTheWindowFailsClosedWhenAPackWillNotRead(t *testing.T) {
	inner, _, rs, _, clock := churn(t, 4)
	blind := &unreadablePacks{Store: inner}

	_, err := GC(context.Background(), Options{
		Inner: blind, Refs: rs, Delete: true, Now: clock.Add(aged),
	})
	if err == nil {
		t.Fatal("a sweep whose pack reads all failed with a transport error deleted things anyway")
	}
	for _, want := range []string{"fail closed", "unknown state"} {
		if !contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// And the same rule for giving up early: exhausting the scan budget is
// evidence that we stopped looking, never evidence of absence, so it is a
// hard error rather than a short window.
func TestTheWindowFailsClosedWhenTheScanGivesUp(t *testing.T) {
	inner, _, rs, _, clock := churn(t, 4)
	restore := scanBudget
	scanBudget = 1
	defer func() { scanBudget = restore }()

	_, err := GC(context.Background(), Options{
		Inner: inner, Refs: rs, Delete: true, Now: clock.Add(aged),
	})
	if err == nil {
		t.Fatal("the scan gave up with generations outstanding and the sweep deleted anyway")
	}
	for _, want := range []string{"fail closed", "scan budget", "--retain-k"} {
		if !contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// unreadablePacks answers a read of an ENTRY inside a pack with a
// transport error — not a 404, which would be a statement about the object
// rather than about the connection, and which the sweep is entitled to
// read as absence.
//
// It leaves trailer reads alone (they are the tail of the object, so they
// are told apart by the range) for a practical reason: the trailer path
// retries with capped exponential backoff, so faulting it would spend half
// a minute per pack proving something this proves in one request. The
// blindness it produces is the same either way — a backup the sweep knows
// is there and cannot read.
type unreadablePacks struct {
	pelicanobj.Store
}

func (s *unreadablePacks) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if strings.HasPrefix(key, packstore.PackDirKey+"/") && off > 0 && limit > 0 {
		if ki, err := s.Store.StatKey(ctx, key); err == nil && off+limit < ki.Size-64 {
			return nil, fmt.Errorf("read %s: connection reset by peer", key)
		}
	}
	return s.Store.Get(ctx, key, off, limit)
}
