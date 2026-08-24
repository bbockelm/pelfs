package genfs_test

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// A grafted volume, end to end, in the ordinary test lane.
//
// The spike proved the read through a Linux kernel mount, which is the
// only honest place to prove a MOUNT. Everything below the mount — the
// spider, the index, the resolver, prefetch's arithmetic — is ordinary Go
// and belongs where it can run on every push.

// graftFixture publishes a volume whose whole tree is grafted from a
// second prefix on the same origin, and hands back both stores.
type graftFixture struct {
	innerStore pelicanobj.Store
	srcStore   pelicanobj.Store
	// srcServer serves ONLY the graft source prefix, so a test can take
	// the third party offline without touching the volume's own storage.
	// That separation is the whole point of the offline test: a graft's
	// availability is the intersection of two storage systems, and the
	// question is what happens when the one you do not own goes away.
	srcServer *httptest.Server
	srcDir    string
	sb        *superblock.Superblock
	entry     superblock.GraftEntry
	files     map[string][]byte
}

// offline stops the graft source. The volume's own prefix keeps working.
func (f *graftFixture) offline() { f.srcServer.Close() }

func newGraftFixture(t *testing.T, policy graft.BlockPolicy) *graftFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	volSrv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(volSrv.Close)
	srcSrv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srcSrv.Close)

	newStore := func(base, prefix string) pelicanobj.Store {
		s, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: base + "/" + prefix})
		if err != nil {
			t.Fatalf("pelicanobj.New: %v", err)
		}
		return s
	}
	f := &graftFixture{
		innerStore: newStore(volSrv.URL, "vol"),
		srcStore:   newStore(srcSrv.URL, "ext"),
		srcServer:  srcSrv,
		srcDir:     filepath.Join(root, "ext"),
		files:      map[string][]byte{},
	}
	// A deliberate size spread: under the inline threshold, one block,
	// several blocks, and one large enough for the ladder to climb.
	for name, n := range map[string]int{
		"data/small.txt":      40,     // under InlineKeep: copied, not grafted
		"data/one.bin":        70000,  // one block at the ladder's ceiling
		"data/multi.bin":      200000, // several blocks
		"data/nested/big.bin": 500000,
	} {
		b := pseudorandom(n, int64(len(name)))
		p := filepath.Join(f.srcDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		f.files[name] = b
	}

	spool := t.TempDir()
	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var vid [16]byte
	if _, err := crand.Read(vid[:]); err != nil {
		t.Fatal(err)
	}
	init, err := publish.InitVolume(ctx, publish.Options{
		Inner: f.innerStore, SpoolDir: spool, Branch: "main", SigningKey: key, VolumeID: vid,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	w, err := graft.NewWriter(t.TempDir(), policy.Block)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	res, err := graft.Spider(ctx, graft.SpiderOptions{
		Src: f.srcStore, Index: w, Policy: policy, Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("Spider: %v", err)
	}
	entry, err := w.Publish(ctx, f.innerStore, graft.PublishOptions{
		Mount: "/ext", Source: srcSrv.URL + "/ext", Policy: policy,
		Bytes: res.Bytes, Files: len(res.Files) - res.Inlined,
	})
	if err != nil {
		t.Fatalf("publish index: %v", err)
	}
	gsrc, err := publish.NewGraftSource(publish.GraftSourceOptions{Mount: "/ext", Result: res})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publish.Publish(ctx, publish.Options{
		Source: gsrc, Inner: f.innerStore, SpoolDir: t.TempDir(), Branch: "main",
		SigningKey: key, Prev: init.Superblock, PrevRaw: init.Raw,
		Grafts: []superblock.GraftEntry{entry},
	})
	if err != nil {
		t.Fatalf("publish generation: %v", err)
	}
	f.sb, f.entry = pub.Superblock, entry
	return f
}

func (f *graftFixture) opener() func(context.Context, string) (pelicanobj.Store, error) {
	return func(context.Context, string) (pelicanobj.Store, error) { return f.srcStore, nil }
}

// lookupPath walks a genfs to one path and returns the inode.
func lookupPath(t *testing.T, fs *genfs.FS, p string) uint64 {
	t.Helper()
	ino := uint64(genfs.RootInode)
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		n, err := fs.Lookup(context.Background(), ino, part)
		if err != nil {
			t.Fatalf("lookup %s in %s: %v", part, p, err)
		}
		ino = n.Inode
	}
	return ino
}

// TestAGraftedTreeReadsBackByteForByte, without a single byte of it
// having been copied under the volume's own prefix.
func TestAGraftedTreeReadsBackByteForByte(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	for name, want := range f.files {
		ino := lookupPath(t, fs, "/ext/"+name)
		got := make([]byte, len(want))
		n, err := fs.Read(ctx, ino, 0, got)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n != len(want) || string(got[:n]) != string(want) {
			t.Fatalf("%s: read %d bytes, they do not match the source", name, n)
		}
	}
	// A read that straddles a block boundary is the property a
	// whole-object digest could not have verified.
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	want := f.files["data/multi.bin"][16000:18000]
	got := make([]byte, 2000)
	if _, err := fs.Read(ctx, ino, 16000, got); err != nil {
		t.Fatalf("straddling read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("a read across a block boundary returned the wrong bytes")
	}
	st := fs.GraftStats()
	if st.Grafts != 1 || st.Resolved == 0 {
		t.Fatalf("graft stats say %+v", st)
	}
	if st.Mismatch != 0 || st.Failures != 0 {
		t.Fatalf("a healthy graft reported %d failures and %d mismatches", st.Failures, st.Mismatch)
	}
}

// TestAChangedSourceFailsClosed. The source is the one thing in the
// system with no obligation to this volume, and a changed byte must
// produce an error naming it rather than a wrong read.
func TestAChangedSourceFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	// One byte in the SECOND block, with the length unchanged: nothing
	// about the namespace looks wrong.
	p := filepath.Join(f.srcDir, "data", "multi.bin")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[20000] ^= 0xff
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	buf := make([]byte, 2000)
	_, err = fs.Read(ctx, ino, 19000, buf)
	if err == nil {
		t.Fatal("a read of a mutated source SUCCEEDED; unverified third-party bytes were served")
	}
	for _, want := range []string{"graft /ext", "the graft source has changed", "--refresh"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not say %q: %v", want, err)
		}
	}
	// Per BLOCK, not per tree: the first block of the same file still
	// reads, and so do its siblings.
	first := make([]byte, 1000)
	if _, err := fs.Read(ctx, ino, 0, first); err != nil {
		t.Fatalf("an untouched block of the same file failed: %v", err)
	}
	sib := lookupPath(t, fs, "/ext/data/one.bin")
	if _, err := fs.Read(ctx, sib, 0, make([]byte, 4096)); err != nil {
		t.Fatalf("an untouched sibling failed: %v", err)
	}
	if st := fs.GraftStats(); st.Mismatch == 0 {
		t.Fatal("the mismatch counter did not move")
	}
}

// TestAMountWithNoOpenerRefusesEveryGraft: nil is the correct default for
// a caller that has not thought about which third parties its users'
// clients may be pointed at.
func TestAMountWithNoOpenerRefusesEveryGraft(t *testing.T) {
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	_, err := genfs.Open(context.Background(), genfs.Options{
		Inner: f.innerStore, SB: f.sb, CacheDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("a mount with no graft opener served a grafted generation")
	}
	if !strings.Contains(err.Error(), "no graft opener") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// TestPrefetchCountsGraftedBytesInsteadOfFailingThem is the fix for the
// spike's measured breakage: --prefetch all refused to mount, reporting
// every grafted chunk as "present in no listed pack" — the sentence that
// means DAMAGE everywhere else in this system.
//
// What must be true now: the pass succeeds, reports zero failures, counts
// the grafted chunks and their bytes separately, names the graft they
// belong to, and — the load-bearing one — does NOT claim the volume is
// fully local.
func TestPrefetchCountsGraftedBytesInsteadOfFailingThem(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	rep, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 4})
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if rep.Failed != 0 {
		t.Fatalf("prefetch reported %d failures on a healthy grafted volume: %v", rep.Failed, rep.Sample)
	}
	if rep.Grafted == 0 {
		t.Fatal("prefetch counted no grafted chunks on a volume that is entirely grafted")
	}
	if rep.FullyLocal() {
		t.Fatal("prefetch claimed a volume with grafted bytes is fully local, which is the one " +
			"thing --prefetch must never say")
	}
	if len(rep.GraftRoots) != 1 || rep.GraftRoots[0].Path != "/ext" {
		t.Fatalf("prefetch did not name the graft it could not satisfy: %+v", rep.GraftRoots)
	}
	// The bytes it could not make local are the grafted content, not the
	// inlined small file (which IS local, in a catalog, in a pack).
	// A file at or under graft.InlineKeep was COPIED into the catalog and
	// is not grafted at all, so it is local and must not be counted here.
	var grafted int64
	for _, b := range f.files {
		if len(b) > graft.InlineKeep {
			grafted += int64(len(b))
		}
	}
	if grafted == 0 {
		t.Fatal("the fixture grafted nothing")
	}
	if rep.GraftedBytes != grafted {
		t.Fatalf("prefetch counted %d grafted bytes, the tree holds %d outside the inline threshold",
			rep.GraftedBytes, grafted)
	}
	// The packed part really was made local: catalogs and the inlined
	// file came down, and there were packs to come down.
	if rep.Packs+rep.Cached == 0 {
		t.Fatal("prefetch made no packs local; the catalogs live in packs and had to move")
	}
	t.Logf("prefetch: %d packs, %d grafted chunks (%d bytes), fully local %v",
		rep.Packs+rep.Cached, rep.Grafted, rep.GraftedBytes, rep.FullyLocal())
}

// TestABigIndexIsReadByWindowRatherThanFetched: the same volume, with the
// whole-fetch ceiling below its index, must still read correctly — which
// is what makes a 10 TB graft mountable at all.
func TestABigIndexIsReadByWindowRatherThanFetched(t *testing.T) {
	ctx := context.Background()
	// A 512-byte block over a ~105 KB tree is ~200 blocks, whose index is
	// comfortably over the 1 KB ceiling this sets.
	f := newGraftFixture(t, graft.BlockPolicy{Block: 512, Max: 512, PerObject: 1 << 30})
	defer graft.SetWholeFetchMaxForTest(1 << 10)()
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener()})
	want := f.files["data/nested/big.bin"]
	ino := lookupPath(t, fs, "/ext/data/nested/big.bin")
	got := make([]byte, len(want))
	if _, err := fs.Read(ctx, ino, 0, got); err != nil {
		t.Fatalf("reading through a windowed index: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("a windowed index resolved to the wrong bytes")
	}
}

// TestPrefetchAllMakesGraftedBlocksLocalAndReadsThemOffline is the real
// test of a prefetch, and it is the one that was missing: prefetch the
// graft, take the SOURCE away, and read.
//
// The volume's own prefix stays up throughout, so a failure here cannot be
// confused for a broken volume — what is being removed is exactly the
// third party a graft depends on.
func TestPrefetchAllMakesGraftedBlocksLocalAndReadsThemOffline(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	cache := t.TempDir()
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener(), CacheDir: cache})

	rep, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 4, Grafts: true})
	if err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	if rep.Failed != 0 {
		t.Fatalf("prefetch reported %d failures: %v", rep.Failed, rep.Sample)
	}
	if rep.Grafted == 0 {
		t.Fatal("the fixture grafted nothing, so this proves nothing")
	}
	if rep.GraftLocal != rep.Grafted {
		t.Fatalf("prefetch made %d of %d grafted blocks local", rep.GraftLocal, rep.Grafted)
	}
	if !rep.FullyLocal() {
		t.Fatal("every pack and every grafted block is local and the report still says it is not")
	}
	if rep.GraftFetched != rep.GraftedBytes {
		t.Fatalf("prefetch transferred %d bytes for %d bytes of grafted content",
			rep.GraftFetched, rep.GraftedBytes)
	}
	before := fs.GraftStats()
	t.Logf("prefetch: %d grafted blocks, %s local, cache holds %d blocks in %s",
		rep.GraftLocal, ui(rep.GraftLocalBytes), before.Cache.Blocks, ui(before.Cache.Bytes))

	// THE SOURCE GOES AWAY. Nothing under /ext can be fetched any more.
	f.offline()

	for name, want := range f.files {
		if len(want) <= graft.InlineKeep {
			continue // copied into the catalog, not grafted: not the test
		}
		ino := lookupPath(t, fs, "/ext/"+name)
		got := make([]byte, len(want))
		if _, err := fs.Read(ctx, ino, 0, got); err != nil {
			t.Fatalf("%s: reading a PREFETCHED grafted file with the source offline: %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s: the offline read returned the wrong bytes", name)
		}
	}
	// A read straddling a block boundary, offline, because that is the
	// shape a whole-object digest could never have verified.
	ino := lookupPath(t, fs, "/ext/data/multi.bin")
	want := f.files["data/multi.bin"][16000:18000]
	got := make([]byte, 2000)
	if _, err := fs.Read(ctx, ino, 16000, got); err != nil {
		t.Fatalf("straddling offline read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("the straddling offline read returned the wrong bytes")
	}

	after := fs.GraftStats()
	if after.Failures != before.Failures {
		t.Fatalf("%d graft fetches were attempted after the source went away; the reads did not "+
			"come from the local cache", after.Failures-before.Failures)
	}
	if after.Cached <= before.Cached {
		t.Fatal("no read was served from the local graft cache")
	}
	t.Logf("offline reads: %d served from the local cache, %d source fetches attempted",
		after.Cached-before.Cached, after.Failures-before.Failures)
}

// TestAPrefetchedGraftSurvivesARemount: the cache outlives the process,
// exactly as the pack cache does, because re-fetching is somebody else's
// bandwidth as well as yours.
func TestAPrefetchedGraftSurvivesARemount(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	cache := t.TempDir()
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener(), CacheDir: cache})
	rep, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 4, Grafts: true})
	if err != nil || rep.GraftLocal != rep.Grafted {
		t.Fatalf("Prefetch: %v (%d/%d local)", err, rep.GraftLocal, rep.Grafted)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A second mount over the SAME cache directory, with the source dead.
	f.offline()
	fs2 := openFS(t, f.innerStore, f.sb, genfs.Options{GraftOpener: f.opener(), CacheDir: cache})
	ino := lookupPath(t, fs2, "/ext/data/nested/big.bin")
	want := f.files["data/nested/big.bin"]
	got := make([]byte, len(want))
	if _, err := fs2.Read(ctx, ino, 0, got); err != nil {
		t.Fatalf("reading a grafted file on a REMOUNT with the source offline: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("the remounted read returned the wrong bytes")
	}
}

// TestPrefetchRefusesAGraftThatCannotFitTheCache. This is where the honest
// refusal belongs -- not "grafts cannot be prefetched", which is untrue,
// but "this graft is larger than your cache", with both numbers.
func TestPrefetchRefusesAGraftThatCannotFitTheCache(t *testing.T) {
	ctx := context.Background()
	f := newGraftFixture(t, graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2})
	// A cache far too small for the ~770 KB of grafted content.
	fs := openFS(t, f.innerStore, f.sb, genfs.Options{
		GraftOpener: f.opener(), CacheDir: t.TempDir(), CacheBytes: 64 << 10,
	})
	_, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 2, Grafts: true})
	var budget *genfs.PrefetchBudgetError
	if !errors.As(err, &budget) {
		t.Fatalf("a graft larger than the cache was accepted: %v", err)
	}
	if budget.GraftBytes == 0 {
		t.Fatal("the refusal does not say how much of the need is grafted")
	}
	if len(budget.GraftRoots) == 0 || budget.GraftRoots[0].Path != "/ext" {
		t.Fatalf("the refusal does not name the graft: %+v", budget.GraftRoots)
	}
	for _, want := range []string{"grafted from", "/ext", "--prefetch packs"} {
		if !strings.Contains(budget.Error(), want) {
			t.Fatalf("the refusal does not mention %q: %v", want, budget)
		}
	}
	t.Logf("refused: %v", budget)

	// And the packs-only mode still works on the same volume, which is the
	// whole point of having the refusal name it.
	rep, err := fs.Prefetch(ctx, genfs.PrefetchOptions{Workers: 2})
	if err != nil {
		t.Fatalf("--prefetch packs on a volume whose graft does not fit: %v", err)
	}
	if rep.FullyLocal() {
		t.Fatal("packs-only prefetch claimed a grafted volume is fully local")
	}
	if rep.Grafted == 0 || rep.GraftLocal != 0 {
		t.Fatalf("packs-only prefetch fetched %d grafted blocks; it must fetch none", rep.GraftLocal)
	}
}

// ui is a byte count for a log line, kept local so the test does not
// depend on the CLI's formatter.
func ui(n int64) string {
	switch {
	case n >= 1<<20:
		return fmtSize(n>>20, "MiB")
	case n >= 1<<10:
		return fmtSize(n>>10, "KiB")
	}
	return fmtSize(n, "B")
}

func fmtSize(n int64, unit string) string { return strconv.FormatInt(n, 10) + " " + unit }
