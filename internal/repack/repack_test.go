package repack_test

import (
	"context"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/repack"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

const rootIno uint64 = 1

// aged is how far past the grace window the tests place their clock.
// Everything these fixtures write is seconds old, so without moving the
// clock the age guard alone would empty every plan — which is what
// TestGraceWindowHoldsBackYoungPacks asserts on purpose.
const aged = 200 * time.Hour

var publishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

// newInner starts a fakeorigin-backed store rooted at /vol (the reach and
// fsck test pattern) and returns the on-disk volume directory so a test
// can damage an object.
func newInner(t testing.TB) (pelicanobj.Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner, filepath.Join(root, "vol")
}

// pseudorandom returns deterministic incompressible content, so stored
// bytes track logical bytes and the plan's numbers can be reasoned about.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

func compute(t *testing.T, o repack.Options) *repack.Plan {
	t.Helper()
	p, err := repack.Compute(context.Background(), o)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	return p
}

func dump(t *testing.T, p *repack.Plan) {
	t.Helper()
	if p.Refused() {
		t.Logf("refused: %s", p.Refusal)
	}
	t.Logf("%d generations, %d packs, %d/%d bytes live, grace %s; plan: %d packs + %d refs, move %d, reclaim %d, into %d pack(s), %d held back",
		p.Generations, p.ScannedPacks, p.LiveBytes, p.Bytes, p.Grace,
		len(p.Packs), len(p.Refs), p.Move(), p.Reclaim(), p.IntoPacks, p.SkippedYoung)
	for _, c := range p.Packs {
		t.Logf("  pack %s: %d/%d bytes live (%.4f), move %d, reclaim %d, age %s",
			c.Name, c.LiveBytes, c.Bytes, c.LiveFraction, c.Move, c.Reclaim, c.Age.Round(time.Second))
	}
	for _, c := range p.Refs {
		t.Logf("  %s %s: %d/%d packs live (%.4f), %d condemned, %d gone, move %d, reclaim %d",
			c.Kind, c.Name, c.LivePacks, c.Packs, c.LiveFraction, c.CondemnedPacks, c.GonePacks, c.Move, c.Reclaim)
	}
	for _, n := range p.Notes {
		t.Logf("  note: %s", n)
	}
}

// A volume whose generations are all retained has nothing to reclaim, and
// the plan must say so — with the clock moved well past the grace window,
// so that the emptiness is a statement about liveness rather than about
// age.
func TestHealthyVolumePlansNothing(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "11111111-1111-1111-1111-111111111111")})
	gen0 := v.Superblock()

	dir := v.Mkdir(rootIno, "dir")
	v.WriteFile(dir, "small.txt", []byte("inline body, well under the threshold"))
	v.WriteFile(rootIno, "big.bin", pseudorandom(4<<20, 42))
	v.WriteFile(dir, "mid.bin", pseudorandom(2<<20, 43))
	res := v.Publish(publishOpts)
	head := res.Superblock

	p := compute(t, repack.Options{
		Inner: inner, Live: []*superblock.Superblock{gen0, head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
	})
	dump(t, p)
	if p.Refused() {
		t.Fatalf("a clean sweep produced a refusal: %s", p.Refusal)
	}
	if !p.Empty() {
		t.Fatalf("a fully live volume produced %d pack and %d ref candidates", len(p.Packs), len(p.Refs))
	}
	if p.Move() != 0 || p.Reclaim() != 0 || p.IntoPacks != 0 {
		t.Fatalf("an empty plan moves %d and reclaims %d bytes into %d packs", p.Move(), p.Reclaim(), p.IntoPacks)
	}
	if p.ScannedPacks == 0 || p.Bytes == 0 || p.LiveBytes != p.Bytes {
		t.Fatalf("the plan describes the volume as %d packs, %d/%d bytes live", p.ScannedPacks, p.LiveBytes, p.Bytes)
	}
}

// Rewriting most of a volume is the case the whole feature exists for:
// the superseded chunks are dead entries inside immutable packs, nothing
// reclaims them today, and the plan must name the packs and show a trade
// worth taking.
func TestRewrittenVolumePlansTheDeadPacks(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "22222222-2222-2222-2222-222222222222")})

	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(2<<20, int64(100+i)))
	}
	first := v.Publish(publishOpts)

	// The packs the first generation created, which the rewrite condemns.
	mine := map[string]bool{}
	for _, pe := range packsOf(t, inner, first.Superblock) {
		mine[pe.Name] = true
	}

	// Three of four files rewritten with fresh incompressible content:
	// nothing dedups, so those chunks are garbage the moment the second
	// generation lands.
	for i := 1; i < files; i++ {
		v.Write(v.Lookup(rootIno, names[i]), pseudorandom(2<<20, int64(200+i)))
	}
	second := v.Publish(publishOpts)
	head := second.Superblock

	p := compute(t, repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
	})
	dump(t, p)
	if p.Refused() {
		t.Fatalf("a clean sweep produced a refusal: %s", p.Refusal)
	}
	if len(p.Packs) < 3 {
		t.Fatalf("three of four files were rewritten but the plan names %d packs", len(p.Packs))
	}
	var reclaim, move int64
	for _, c := range p.Packs {
		if c.LiveFraction >= 0.5 {
			t.Fatalf("pack %s is %.4f live and was proposed anyway", c.Name, c.LiveFraction)
		}
		if !mine[c.Name] {
			t.Logf("pack %s was not one the first generation created; that is allowed, but note it", c.Name)
		}
		if c.Move != c.LiveBytes || c.Reclaim != c.Size-c.LiveBytes {
			t.Fatalf("pack %s: move %d / reclaim %d does not match %d live of %d stored (%d on disk)",
				c.Name, c.Move, c.Reclaim, c.LiveBytes, c.Bytes, c.Size)
		}
		if c.Age < p.Grace {
			t.Fatalf("pack %s is %s old, inside the %s grace window", c.Name, c.Age, p.Grace)
		}
		reclaim += c.Reclaim
		move += c.Move
	}
	// Three rewritten 2 MiB files: about 6 MiB of dead stored bytes, and
	// almost nothing to move, since the packs holding them are dead whole.
	if reclaim < 5<<20 {
		t.Fatalf("the plan reclaims %d bytes; three rewritten 2 MiB files should be worth about 6 MiB", reclaim)
	}
	if move > reclaim {
		t.Fatalf("the plan moves %d bytes to reclaim %d — a trade an operator should refuse", move, reclaim)
	}
	// The threshold is what guarantees that: under half live, a pack gives
	// back at least what it costs to move.
	if p.Reclaim() < p.Move() {
		t.Fatalf("plan totals: move %d, reclaim %d", p.Move(), p.Reclaim())
	}
	if p.IntoPacks > len(p.Packs) {
		t.Fatalf("the plan rewrites %d packs into %d, which is not fewer", len(p.Packs), p.IntoPacks)
	}
	// Whatever refs it proposes must be justified by the packs it condemns
	// and must be honest about the one-pass trade being unfavourable.
	for _, c := range p.Refs {
		if c.LiveFraction >= 0.5 {
			t.Fatalf("%s %s is %.4f live and was proposed anyway", c.Kind, c.Name, c.LiveFraction)
		}
		if c.CondemnedPacks+c.GonePacks == 0 {
			t.Fatalf("%s %s was proposed with no dead packs behind it", c.Kind, c.Name)
		}
		if c.Move != c.Size || c.Reclaim > c.Size {
			t.Fatalf("%s %s: move %d / reclaim %d against a %d-byte object", c.Kind, c.Name, c.Move, c.Reclaim, c.Size)
		}
	}
}

// The safety property, and the reason the API is shaped the way it is: an
// incomplete sweep reports every pack fully live, so a planner handed one
// must plan NOTHING and say why — never a plan built on partial
// reachability, which would condemn packs whose references were simply
// not read.
func TestIncompleteSweepPlansNothing(t *testing.T) {
	inner, volDir := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "33333333-3333-3333-3333-333333333333")})

	// A volume with real garbage in it, so the empty plan below is a
	// refusal rather than a healthy answer.
	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(2<<20, int64(300+i)))
	}
	v.Mkdir(rootIno, "dir")
	v.WriteFile(v.Lookup(rootIno, "dir"), "nested.bin", pseudorandom(2<<20, 350))
	v.Publish(publishOpts)
	for i := 1; i < files; i++ {
		v.Write(v.Lookup(rootIno, names[i]), pseudorandom(2<<20, int64(400+i)))
	}
	head := v.Publish(publishOpts).Superblock

	opts := repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
	}
	before := compute(t, opts)
	if before.Empty() {
		t.Fatal("the fixture plans nothing even when readable; the test would prove nothing")
	}

	// Scribble over a catalog the LIVE generation still names: the trailer
	// is untouched, so the pack still indexes and the entry is still
	// there, but nothing can decode it — the sweep can see the entry and
	// cannot learn what it references.
	victimPack, victim := packHolding(t, inner, head, func(e packstore.PackEntry) bool {
		return e.Key == hex.EncodeToString(head.RootCatalog[:])
	})
	scribble(t, filepath.Join(volDir, packstore.PackDirKey, victimPack.Name), victim.Off, victim.Length)

	p := compute(t, opts)
	dump(t, p)
	if !p.Refused() {
		t.Fatal("a sweep that could not read a catalog produced a plan rather than a refusal")
	}
	if !p.Empty() {
		t.Fatalf("a refused plan names %d packs and %d refs", len(p.Packs), len(p.Refs))
	}
	if p.Move() != 0 || p.Reclaim() != 0 {
		t.Fatalf("a refused plan moves %d and reclaims %d bytes", p.Move(), p.Reclaim())
	}
	// A refusal carries no measurements at all: the conservative report
	// behind it says every pack is fully live, which is a floor on what
	// must be kept and not a description of the volume.
	if p.Bytes != 0 || p.LiveBytes != 0 || p.ScannedPacks != 0 || p.Generations != 0 {
		t.Fatalf("a refused plan reports numbers: %d packs, %d/%d bytes, %d generations",
			p.ScannedPacks, p.LiveBytes, p.Bytes, p.Generations)
	}
	if len(p.Notes) == 0 {
		t.Fatal("a refused plan explains nothing")
	}
}

// The age guard: a pack inside the grace window is not a candidate no
// matter how dead it looks, because a concurrent writer may be about to
// reference it from a generation this sweep never saw. Same fixture as
// the plan above, only the clock differs.
func TestGraceWindowHoldsBackYoungPacks(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "44444444-4444-4444-4444-444444444444")})

	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(2<<20, int64(500+i)))
	}
	v.Publish(publishOpts)
	for i := 1; i < files; i++ {
		v.Write(v.Lookup(rootIno, names[i]), pseudorandom(2<<20, int64(600+i)))
	}
	head := v.Publish(publishOpts).Superblock

	opts := repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4,
	}
	// Now inside the window (the packs are seconds old).
	opts.Now = time.Now()
	young := compute(t, opts)
	dump(t, young)
	if !young.Empty() {
		t.Fatalf("packs seconds old were proposed: %d packs, %d refs", len(young.Packs), len(young.Refs))
	}
	if young.SkippedYoung == 0 || len(young.SkippedYoungNames) == 0 {
		t.Fatal("nothing was reported as held back, so the empty plan is unexplained")
	}

	// The same volume past the window: the candidates the guard was hiding
	// appear, and they are the ones it named.
	opts.Now = time.Now().Add(aged)
	old := compute(t, opts)
	dump(t, old)
	if old.Empty() {
		t.Fatal("nothing was proposed even past the grace window; the guard was not what held it back")
	}
	proposed := map[string]bool{}
	for _, c := range old.Packs {
		proposed[c.Name] = true
	}
	for _, n := range young.SkippedYoungNames {
		if !proposed[n] {
			t.Errorf("%s was held back as young but is not a candidate once aged", n)
		}
	}
	// The guard widens with the window the superblocks state, and Options
	// may only widen it further.
	opts.Grace = 2 * aged
	if wide := compute(t, opts); !wide.Empty() {
		t.Fatalf("--grace %s did not widen the guard: %d packs proposed", opts.Grace, len(wide.Packs))
	}
}

// A ref whose packs are mostly condemned is worth rewriting, and the plan
// must say so with the same trade — which for a ref is always
// unfavourable in one pass, since the whole object moves to reclaim only
// its dead share. Three generations, each rewriting everything, leave two
// generations' worth of packs dead against one live.
func TestMostlyStaleRefsAreProposedForRetirement(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "66666666-6666-6666-6666-666666666666")})

	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(2<<20, int64(700+i)))
	}
	v.Publish(publishOpts)
	var head *superblock.Superblock
	for round := range 4 {
		for i := range files {
			v.Write(v.Lookup(rootIno, names[i]), pseudorandom(2<<20, int64(800+100*round+i)))
		}
		head = v.Publish(publishOpts).Superblock
	}
	if len(head.Manifests) == 0 {
		t.Fatal("the fixture names no manifest segments; the test would prove nothing")
	}

	p := compute(t, repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4, Now: time.Now().Add(aged),
	})
	dump(t, p)
	if len(p.Refs) == 0 {
		t.Fatalf("two of three generations were rewritten away (%d of %d packs condemned) and no ref is stale enough to retire",
			len(p.Packs), p.ScannedPacks)
	}
	var sawManifest bool
	for _, c := range p.Refs {
		sawManifest = sawManifest || c.Kind == repack.RefManifest
		if c.LiveFraction >= 0.5 || c.LivePacks+c.CondemnedPacks+c.GonePacks != c.Packs {
			t.Fatalf("%s %s: %d live + %d condemned + %d gone of %d packs (%.4f live)",
				c.Kind, c.Name, c.LivePacks, c.CondemnedPacks, c.GonePacks, c.Packs, c.LiveFraction)
		}
		if c.Move != c.Size {
			t.Fatalf("%s %s moves %d bytes of a %d-byte object", c.Kind, c.Name, c.Move, c.Size)
		}
		if c.Reclaim >= c.Move {
			t.Fatalf("%s %s claims to reclaim %d by moving %d; a ref rewrite cannot come out ahead in one pass",
				c.Kind, c.Name, c.Reclaim, c.Move)
		}
	}
	if !sawManifest {
		t.Errorf("no manifest segment was proposed; only %+v", p.Refs)
	}
	// Nothing about a ref candidate depends on the packs being young or
	// old EXCEPT the guard, so a plan inside the window proposes neither.
	if young := compute(t, repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: head,
		CacheDir: t.TempDir(), Workers: 4, Now: time.Now(),
	}); !young.Empty() {
		t.Fatalf("inside the grace window the plan still proposes %d packs and %d refs", len(young.Packs), len(young.Refs))
	}
}

func TestComputeRefusesBadInput(t *testing.T) {
	inner, _ := newInner(t)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "55555555-5555-5555-5555-555555555555")})
	v.WriteFile(rootIno, "f.bin", pseudorandom(1<<20, 7))
	head := v.Publish(publishOpts).Superblock
	ctx := context.Background()

	cases := []struct {
		name string
		o    repack.Options
	}{
		{"no store", repack.Options{Live: []*superblock.Superblock{head}, Head: head}},
		{"no head", repack.Options{Inner: inner, Live: []*superblock.Superblock{head}}},
		{"no live set", repack.Options{Inner: inner, Head: head}},
		// 50 meaning 50%: a threshold above 1 proposes rewriting objects
		// that are entirely live.
		{"threshold out of range", repack.Options{Inner: inner, Live: []*superblock.Superblock{head}, Head: head, PackLive: 50}},
	}
	for _, c := range cases {
		if p, err := repack.Compute(ctx, c.o); err == nil {
			t.Errorf("%s: Compute succeeded (%+v)", c.name, p)
		}
	}

	// A head outside the live set is the dangerous one: the sweep would
	// report the head's own packs as unreferenced, and every ref it names
	// would look entirely dead.
	other := *head
	other.Generation = head.Generation + 1
	if p, err := repack.Compute(ctx, repack.Options{
		Inner: inner, Live: []*superblock.Superblock{head}, Head: &other, CacheDir: t.TempDir(),
	}); err == nil {
		t.Errorf("a head outside the live set was planned for (%+v)", p)
	}
}

// ---- helpers ----

// packsOf resolves a generation's pack set the way the sweep does.
func packsOf(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock) []superblock.PackEntry {
	t.Helper()
	packs, err := manifest.Packs(context.Background(), inner, sb)
	if err != nil {
		t.Fatalf("resolve pack set: %v", err)
	}
	return packs
}

// packHolding returns the first pack containing an entry the predicate
// accepts, and that entry.
func packHolding(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock,
	want func(packstore.PackEntry) bool) (superblock.PackEntry, packstore.PackEntry) {
	t.Helper()
	for _, pe := range packsOf(t, inner, sb) {
		entries, err := packstore.FetchTrailer(context.Background(), inner, pe.Name, pe.Size)
		if err != nil {
			t.Fatalf("fetch trailer of %s: %v", pe.Name, err)
		}
		for _, e := range entries {
			if want(e) {
				return pe, e
			}
		}
	}
	t.Fatal("no pack holds a matching entry")
	return superblock.PackEntry{}, packstore.PackEntry{}
}

// scribble replaces one entry's stored bytes with noise, leaving the
// pack's length and trailer intact.
func scribble(t *testing.T, packPath string, off, length int64) {
	t.Helper()
	f, err := os.OpenFile(packPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.WriteAt(pseudorandom(int(length), 7), off); err != nil {
		t.Fatal(err)
	}
}
