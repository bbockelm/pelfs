package reach_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/reach"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

const rootIno uint64 = 1

// countingStore counts reads by exact range, so a test can assert that an
// object carried by several generations was fetched ONCE.
type countingStore struct {
	pelicanobj.Store
	mu   sync.Mutex
	gets map[string]int
}

func counted(inner pelicanobj.Store) *countingStore {
	return &countingStore{Store: inner, gets: map[string]int{}}
}

func rangeKey(key string, off, length int64) string {
	return fmt.Sprintf("%s@%d+%d", key, off, length)
}

func (c *countingStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	c.mu.Lock()
	c.gets[rangeKey(key, off, limit)]++
	c.mu.Unlock()
	return c.Store.Get(ctx, key, off, limit)
}

func (c *countingStore) Unwrap() pelicanobj.Store { return c.Store }

func (c *countingStore) count(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets[k]
}

func (c *countingStore) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets = map[string]int{}
}

// newInner starts a fakeorigin-backed store rooted at /vol (the fsck test
// pattern) and returns the on-disk volume directory so tests can damage
// pack objects.
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
// bytes track logical bytes and the liveness numbers can be reasoned about.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

var publishOpts = publish.Options{SMax: 1000, TargetPackSize: 2 << 20}

// treeFixture publishes a tree exercising every structure the sweep
// touches: a nested catalog (SMax forces the split), inline and chunked
// files, a symlink, and a hardlink whose content lives in an inode shard.
// It returns the store, the volume dir, generation 0, and generation 1.
func treeFixture(t *testing.T, uuid string) (*countingStore, string, *superblock.Superblock, *publish.Result, *testvol.Volume) {
	t.Helper()
	raw, volDir := newInner(t)
	inner := counted(raw)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, uuid)})
	gen0 := v.Superblock()

	dir := v.Mkdir(rootIno, "dir")
	v.WriteFile(dir, "small.txt", []byte("inline body, well under the threshold"))
	v.Symlink(dir, "link", "small.txt")
	v.WriteFile(rootIno, "big.bin", pseudorandom(6<<20, 42))
	v.WriteFile(dir, "mid.bin", pseudorandom(2<<20, 43))
	hard := v.WriteFile(rootIno, "hard1", pseudorandom(3<<20, 44))
	v.Link(hard, dir, "hard2")

	res := v.Publish(publishOpts)
	if res.Stats.Catalogs < 2 || res.Stats.Shards < 1 || len(packsOf(t, inner, res.Superblock)) < 2 {
		t.Fatalf("fixture is not representative: %d catalogs, %d shards, %d packs",
			res.Stats.Catalogs, res.Stats.Shards, len(packsOf(t, inner, res.Superblock)))
	}
	return inner, volDir, gen0, res, v
}

// packsOf resolves a generation's pack set the way the sweep does:
// through its manifest segments, or through the inline list when it has
// none (manifest.Packs).
func packsOf(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock) []superblock.PackEntry {
	t.Helper()
	packs, err := manifest.Packs(context.Background(), inner, sb)
	if err != nil {
		t.Fatalf("resolve pack set: %v", err)
	}
	return packs
}

func sweep(t *testing.T, inner pelicanobj.Store, live ...*superblock.Superblock) *reach.Report {
	t.Helper()
	rep, err := reach.Sweep(context.Background(), reach.Options{
		Inner: inner, Live: live, CacheDir: t.TempDir(), Workers: 4,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	return rep
}

func dump(t *testing.T, rep *reach.Report) {
	t.Helper()
	t.Logf("%d generations, %d packs, %d/%d entries live, %d/%d bytes live (%.4f), fetched %d (%d trailers, %d objects)",
		rep.Generations, len(rep.Packs), rep.LiveEntries, rep.Entries, rep.LiveBytes, rep.Bytes,
		rep.LiveFraction(), rep.Fetched, rep.Trailers, rep.Objects)
	for _, p := range rep.Packs {
		t.Logf("  %s: %d/%d entries, %d/%d bytes, live %.4f", p.Name, p.LiveEntries, p.Entries, p.LiveBytes, p.Bytes, p.LiveFraction())
	}
}

// A generation just published references essentially everything in its
// packs; the only garbage is what its PREDECESSOR left behind, and adding
// that predecessor to the live set brings it back.
func TestFreshGenerationIsLive(t *testing.T) {
	inner, _, gen0, res, _ := treeFixture(t, "11111111-2222-3333-4444-555555555555")

	head := sweep(t, inner, res.Superblock)
	dump(t, head)
	if head.Generations != 1 || len(head.Packs) != len(packsOf(t, inner, res.Superblock)) {
		t.Fatalf("swept %d generations / %d packs, want 1 / %d", head.Generations, len(head.Packs), len(packsOf(t, inner, res.Superblock)))
	}
	for _, p := range head.Packs {
		if !p.Indexed {
			t.Fatalf("pack %s was not indexed by a clean sweep", p.Name)
		}
	}
	if head.LiveFraction() < 0.99 {
		t.Fatalf("a freshly published generation is only %.4f live", head.LiveFraction())
	}
	if head.Unresolved != 0 {
		t.Fatalf("%d referenced identities resolve in no pack", head.Unresolved)
	}
	// The dead bytes are generation 0's superseded root catalog, and
	// nothing else: it is one entry, in the pack InitVolume wrote.
	if dead := head.Entries - head.LiveEntries; dead != 1 {
		t.Fatalf("%d dead entries in a fresh generation, want exactly the superseded root catalog", dead)
	}

	// Retaining generation 0 keeps that catalog alive — the property the
	// whole sweep exists for: liveness is a question about a SET.
	both := sweep(t, inner, gen0, res.Superblock)
	dump(t, both)
	if both.LiveEntries != both.Entries || both.LiveBytes != both.Bytes {
		t.Fatalf("with generation 0 retained: %d/%d entries, %d/%d bytes live",
			both.LiveEntries, both.Entries, both.LiveBytes, both.Bytes)
	}
	if both.Bytes != head.Bytes {
		t.Fatalf("the pack universe changed with the live set: %d bytes vs %d", both.Bytes, head.Bytes)
	}
}

// Rewriting most of a volume turns most of the previous generation's
// packs into garbage, and the sweep says which — the number a repack
// policy needs and no pack list can produce.
func TestGarbageAfterRewrite(t *testing.T) {
	raw, _ := newInner(t)
	inner := counted(raw)
	v := testvol.New(t, inner, testvol.Options{VolumeID: testvol.ParseUUID(t, "22222222-3333-4444-5555-666666666666")})

	gen0 := v.Superblock()
	const files = 4
	names := make([]string, files)
	for i := range files {
		names[i] = fmt.Sprintf("f%d.bin", i)
		v.WriteFile(rootIno, names[i], pseudorandom(2<<20, int64(100+i)))
	}
	first := v.Publish(publishOpts)

	// The packs this generation CREATED, as opposed to the ones it
	// inherited from the empty generation 0: those are the ones the
	// rewrite condemns.
	mine := map[string]bool{}
	for _, pe := range packsOf(t, inner, first.Superblock) {
		mine[pe.Name] = true
	}
	for _, pe := range packsOf(t, inner, gen0) {
		delete(mine, pe.Name)
	}

	// Rewrite three of the four files with fresh incompressible content:
	// nothing dedups, so the old chunks are garbage the moment the new
	// generation lands. The lookup is what a kernel does on the way down,
	// and what the fresh overlay needs before it will take a write.
	for i := 1; i < files; i++ {
		v.Write(v.Lookup(rootIno, names[i]), pseudorandom(2<<20, int64(200+i)))
	}
	second := v.Publish(publishOpts)

	head := sweep(t, inner, second.Superblock)
	dump(t, head)

	var oldBytes, oldLive int64
	var dead, live int
	for _, p := range head.Packs {
		if !mine[p.Name] {
			continue
		}
		oldBytes += p.Bytes
		oldLive += p.LiveBytes
		switch {
		case p.LiveBytes == 0:
			dead++
		case p.LiveFraction() > 0.9:
			live++
		}
	}
	frac := float64(oldLive) / float64(oldBytes)
	t.Logf("the first generation's packs: %.4f live (%d bytes of %d), %d fully dead, %d still fully live", frac, oldLive, oldBytes, dead, live)
	// One file of four survives, so roughly a quarter of the old bytes do.
	if frac < 0.15 || frac > 0.45 {
		t.Fatalf("old-generation liveness is %.4f, want about a quarter", frac)
	}
	if dead < 2 {
		t.Fatalf("only %d of the first generation's packs are fully dead; three of four files were rewritten", dead)
	}
	if live < 1 {
		t.Fatal("no pack of the first generation is still fully live; one file was left alone")
	}
	if got := len(head.Below(0.5)); got < dead {
		t.Fatalf("Below(0.5) named %d packs, but %d are entirely dead", got, dead)
	}

	// Retaining the first generation makes its packs live again, whole.
	both := sweep(t, inner, first.Superblock, second.Superblock)
	dump(t, both)
	for _, p := range both.Packs {
		if !mine[p.Name] {
			continue
		}
		if p.LiveBytes != p.Bytes {
			t.Fatalf("with the first generation retained, pack %s is %d/%d bytes live", p.Name, p.LiveBytes, p.Bytes)
		}
	}
	if both.LiveBytes <= head.LiveBytes {
		t.Fatalf("retaining a generation did not raise live bytes: %d vs %d", both.LiveBytes, head.LiveBytes)
	}
}

// The safety property, asserted in numbers rather than in flags: a
// catalog that cannot be decoded makes the sweep return NO report, and
// the conservative one carried by the error reports every pack fully
// live.
func TestUndecodableCatalogIsFullyLive(t *testing.T) {
	inner, volDir, _, res, _ := treeFixture(t, "33333333-4444-5555-6666-777777777777")
	sb := res.Superblock

	// A clean sweep first, so the assertions below are not vacuous: this
	// volume genuinely has dead bytes to lose track of.
	clean := sweep(t, inner, sb)
	if clean.LiveBytes >= clean.Bytes {
		t.Fatalf("the fixture has no dead bytes (%d/%d); the test would prove nothing", clean.LiveBytes, clean.Bytes)
	}

	// Scribble over the nested catalog's stored bytes — one the LIVE
	// generation still names, not a superseded one, which would change
	// nothing. The trailer is untouched, so its hash still verifies and
	// the pack still indexes; what fails is the decode, which is the
	// interesting failure: the sweep can see the entry but cannot learn
	// what it references.
	nested := nestedIdentity(t, sb)
	victimPack, victim := packHolding(t, inner, sb, func(e packstore.PackEntry) bool { return e.Key == nested })
	scribble(t, filepath.Join(volDir, packstore.PackDirKey, victimPack.Name), victim.Off, victim.Length)

	rep, err := reach.Sweep(context.Background(), reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, CacheDir: t.TempDir(), Workers: 4,
	})
	if rep != nil {
		t.Fatalf("an incomplete sweep returned a report: %+v", rep)
	}
	var inc *reach.Incomplete
	if !errors.As(err, &inc) {
		t.Fatalf("Sweep error = %v, want *reach.Incomplete", err)
	}
	if len(inc.Failures) == 0 || !strings.Contains(inc.Failures[0].Object, victim.Key) {
		t.Fatalf("failures do not name the damaged catalog %s: %+v", victim.Key, inc.Failures)
	}
	dump(t, inc.Conservative)

	c := inc.Conservative
	if len(c.Packs) != len(clean.Packs) || c.Bytes != clean.Bytes || c.Entries != clean.Entries {
		t.Fatalf("the conservative report describes a different volume: %d packs / %d bytes / %d entries, clean saw %d / %d / %d",
			len(c.Packs), c.Bytes, c.Entries, len(clean.Packs), clean.Bytes, clean.Entries)
	}
	if c.LiveEntries != c.Entries || c.LiveBytes != c.Bytes {
		t.Fatalf("the conservative report is not fully live: %d/%d entries, %d/%d bytes",
			c.LiveEntries, c.Entries, c.LiveBytes, c.Bytes)
	}
	for _, p := range c.Packs {
		if p.LiveEntries != p.Entries || p.LiveBytes != p.Bytes || p.LiveFraction() != 1 {
			t.Fatalf("pack %s is not fully live in the conservative report: %d/%d entries, %d/%d bytes",
				p.Name, p.LiveEntries, p.Entries, p.LiveBytes, p.Bytes)
		}
	}
	if len(c.Below(0.5)) != 0 {
		t.Fatalf("the conservative report offers %d packs for retirement", len(c.Below(0.5)))
	}
}

// A pack that cannot be read at all is the same story with less to
// report: fully live, unindexed, and the sweep says so.
func TestUnreadablePackIsFullyLive(t *testing.T) {
	inner, volDir, _, res, _ := treeFixture(t, "44444444-5555-6666-7777-888888888888")
	sb := res.Superblock
	victim, _ := packHolding(t, inner, sb, func(e packstore.PackEntry) bool { return e.Type == "" || e.Type == "data" })
	if err := os.Remove(filepath.Join(volDir, packstore.PackDirKey, victim.Name)); err != nil {
		t.Fatal(err)
	}

	rep, err := reach.Sweep(context.Background(), reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, CacheDir: t.TempDir(), Workers: 4,
	})
	if rep != nil {
		t.Fatalf("an incomplete sweep returned a report: %+v", rep)
	}
	var inc *reach.Incomplete
	if !errors.As(err, &inc) {
		t.Fatalf("Sweep error = %v, want *reach.Incomplete", err)
	}
	for _, p := range inc.Conservative.Packs {
		if p.LiveEntries != p.Entries || p.LiveBytes != p.Bytes {
			t.Fatalf("pack %s is not fully live: %d/%d entries, %d/%d bytes", p.Name, p.LiveEntries, p.Entries, p.LiveBytes, p.Bytes)
		}
		if p.Name == victim.Name && p.Indexed {
			t.Fatalf("the deleted pack %s is reported as indexed", p.Name)
		}
	}
}

// Catalog reuse carries the same catalog through generation after
// generation. The sweep must read it once however many name it — that
// deduplication is the difference between a sweep that costs one volume
// and one that costs a volume per retained generation.
func TestCarriedCatalogFetchedOnce(t *testing.T) {
	inner, _, _, first, v := treeFixture(t, "55555555-6666-7777-8888-999999999999")

	// One new file at the root: the root catalog is rebuilt, /dir's is
	// carried forward out of the first generation's packs.
	v.WriteFile(rootIno, "late.txt", []byte("one new file in a whole volume"))
	second := v.Publish(publishOpts)
	if second.Stats.CatalogsReused == 0 {
		t.Fatal("nothing was carried forward; the test would prove nothing")
	}

	live := []*superblock.Superblock{first.Superblock, second.Superblock}
	distinct := map[string]bool{}
	total := 0
	for _, sb := range live {
		for _, id := range objectIdentities(sb) {
			distinct[id] = true
			total++
		}
	}
	if total <= len(distinct) {
		t.Fatalf("the two generations share no catalog (%d identities, %d distinct)", total, len(distinct))
	}

	// Where the carried catalog's bytes physically sit, so the count is of
	// reads of THOSE bytes rather than of any object.
	carried := carriedIdentity(t, first.Superblock, second.Superblock)
	pack, entry := packHolding(t, inner, second.Superblock, func(e packstore.PackEntry) bool { return e.Key == carried })
	inner.reset()

	rep := sweep(t, inner, live...)
	dump(t, rep)
	if rep.Objects != len(distinct) {
		t.Fatalf("fetched %d catalog-class objects, %d are distinct across the two generations", rep.Objects, len(distinct))
	}
	if rep.Trailers != len(rep.Packs) || rep.Fetched != rep.Trailers+rep.Objects {
		t.Fatalf("fetch accounting: %d trailers for %d packs, %d fetched in total", rep.Trailers, len(rep.Packs), rep.Fetched)
	}
	if n := inner.count(rangeKey(packstore.PackDirKey+"/"+pack.Name, entry.Off, entry.Length)); n != 1 {
		t.Fatalf("the carried catalog's bytes were read %d times, want 1", n)
	}
	// Both generations are retained, so the only garbage in the whole
	// volume is generation 0's superseded root catalog — the one object no
	// live generation names.
	if dead := rep.Entries - rep.LiveEntries; dead != 1 {
		t.Fatalf("%d dead entries with both generations retained, want exactly generation 0's root catalog", dead)
	}
}

// The Catalogs list is optional in the format — a writer that does not
// maintain it publishes a generation with only a root catalog named — so
// the sweep must find the rest by their nested locators and reach the
// same answer. Reporting the subtrees below an unlisted catalog as dead
// would be the worst bug this package could have.
func TestCatalogListIsOptional(t *testing.T) {
	inner, _, _, res, _ := treeFixture(t, "77777777-8888-9999-aaaa-bbbbbbbbbbbb")
	listed := sweep(t, inner, res.Superblock)

	bare := *res.Superblock
	if len(bare.Catalogs) < 2 {
		t.Fatalf("the fixture names %d catalogs; the test needs a nested one", len(bare.Catalogs))
	}
	bare.Catalogs = nil
	descended := sweep(t, inner, &bare)
	dump(t, descended)

	if descended.LiveEntries != listed.LiveEntries || descended.LiveBytes != listed.LiveBytes {
		t.Fatalf("descending found %d entries / %d bytes live, the catalog list found %d / %d",
			descended.LiveEntries, descended.LiveBytes, listed.LiveEntries, listed.LiveBytes)
	}
	if descended.Objects != listed.Objects {
		t.Fatalf("descending fetched %d objects, the catalog list %d", descended.Objects, listed.Objects)
	}
}

// An encrypted volume decodes its catalogs under the DEK, and the failure
// mode that matters is the wrong key: it must report nothing dead.
func TestEncryptedVolume(t *testing.T) {
	raw, _ := newInner(t)
	inner := counted(raw)
	dek := pseudorandom(32, 1)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, "88888888-9999-aaaa-bbbb-cccccccccccc"),
		DEK:         dek,
		IdentityKey: pseudorandom(32, 2),
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})
	dir := v.Mkdir(rootIno, "dir")
	v.WriteFile(dir, "mid.bin", pseudorandom(2<<20, 43))
	v.WriteFile(rootIno, "big.bin", pseudorandom(3<<20, 44))
	res := v.Publish(publishOpts)
	sb := res.Superblock
	if sb.CatalogKeyID == 0 {
		t.Fatal("the fixture volume is not encrypted")
	}
	ctx := context.Background()

	rep, err := reach.Sweep(ctx, reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, DEK: dek, CacheDir: t.TempDir(), Workers: 4,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	dump(t, rep)
	if rep.LiveFraction() < 0.99 {
		t.Fatalf("a freshly published encrypted generation is only %.4f live", rep.LiveFraction())
	}

	// The wrong DEK opens nothing, so it must claim everything is live.
	bad, err := reach.Sweep(ctx, reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, DEK: pseudorandom(32, 99), CacheDir: t.TempDir(), Workers: 4,
	})
	if bad != nil {
		t.Fatalf("a sweep with the wrong DEK returned a report: %+v", bad)
	}
	var inc *reach.Incomplete
	if !errors.As(err, &inc) {
		t.Fatalf("Sweep with the wrong DEK = %v, want *reach.Incomplete", err)
	}
	if inc.Conservative.LiveBytes != inc.Conservative.Bytes || inc.Conservative.LiveBytes != rep.Bytes {
		t.Fatalf("the wrong DEK reported %d of %d bytes live", inc.Conservative.LiveBytes, inc.Conservative.Bytes)
	}
	// No DEK at all is a bad request, refused before anything is fetched.
	if _, err := reach.Sweep(ctx, reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, CacheDir: t.TempDir(),
	}); err == nil || errors.As(err, &inc) {
		t.Fatalf("a sweep of an encrypted volume without a DEK = %v", err)
	}
}

func TestSweepRefusesBadInput(t *testing.T) {
	inner, _, _, res, _ := treeFixture(t, "66666666-7777-8888-9999-aaaaaaaaaaaa")
	ctx := context.Background()

	// An empty live set is the one answer that must never be produced by
	// accident, so it is refused rather than answered.
	if _, err := reach.Sweep(ctx, reach.Options{Inner: inner}); err == nil {
		t.Fatal("a sweep with no live generations succeeded")
	}
	if _, err := reach.Sweep(ctx, reach.Options{Live: []*superblock.Superblock{res.Superblock}}); err == nil {
		t.Fatal("a sweep with no store succeeded")
	}
	other := *res.Superblock
	other.VolumeID = testvol.ParseUUID(t, "99999999-9999-9999-9999-999999999999")
	if _, err := reach.Sweep(ctx, reach.Options{Inner: inner, Live: []*superblock.Superblock{res.Superblock, &other}}); err == nil {
		t.Fatal("a sweep mixing volumes succeeded")
	}
	// A bad request is not an incomplete sweep: the caller has nothing to
	// be conservative about.
	_, err := reach.Sweep(ctx, reach.Options{Inner: inner})
	var inc *reach.Incomplete
	if errors.As(err, &inc) {
		t.Fatalf("a bad request came back as an incomplete sweep: %v", err)
	}
}

// ---- helpers ----

// objectIdentities is every catalog-class object a generation names: its
// root catalog, its catalog list, and its inode shards.
func objectIdentities(sb *superblock.Superblock) []string {
	seen := map[string]bool{}
	var out []string
	add := func(id [32]byte) {
		h := hex.EncodeToString(id[:])
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	add(sb.RootCatalog)
	for _, ce := range sb.Catalogs {
		add(ce.Identity)
	}
	for _, sh := range sb.Shards {
		add(sh.Identity)
	}
	return out
}

// nestedIdentity returns a catalog this generation names that is not its
// root: the one whose loss costs the sweep a subtree.
func nestedIdentity(t *testing.T, sb *superblock.Superblock) string {
	t.Helper()
	root := hex.EncodeToString(sb.RootCatalog[:])
	for _, ce := range sb.Catalogs {
		if id := hex.EncodeToString(ce.Identity[:]); id != root {
			return id
		}
	}
	t.Fatal("the generation names no catalog below its root")
	return ""
}

// carriedIdentity returns an identity both generations name — the catalog
// reuse carried forward.
func carriedIdentity(t *testing.T, a, b *superblock.Superblock) string {
	t.Helper()
	in := map[string]bool{}
	for _, id := range objectIdentities(a) {
		in[id] = true
	}
	for _, id := range objectIdentities(b) {
		if in[id] {
			return id
		}
	}
	t.Fatal("the two generations share no catalog-class object")
	return ""
}

func packEntries(t *testing.T, inner pelicanobj.Store, pe superblock.PackEntry) []packstore.PackEntry {
	t.Helper()
	entries, err := packstore.FetchTrailer(context.Background(), inner, pe.Name, pe.Size)
	if err != nil {
		t.Fatalf("fetch trailer of %s: %v", pe.Name, err)
	}
	return entries
}

// packHolding returns the first pack containing an entry the predicate
// accepts, and that entry.
func packHolding(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock,
	want func(packstore.PackEntry) bool) (superblock.PackEntry, packstore.PackEntry) {
	t.Helper()
	for _, pe := range packsOf(t, inner, sb) {
		for _, e := range packEntries(t, inner, pe) {
			if want(e) {
				return pe, e
			}
		}
	}
	t.Fatal("no pack holds a matching entry")
	return superblock.PackEntry{}, packstore.PackEntry{}
}

// scribble replaces one entry's stored bytes with noise, leaving the
// pack's length and trailer intact: the location map still verifies and
// the entry is still there, but nothing can decode it.
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

// Liveness is a property of the packs and the references into them, not
// of how a superblock happens to name them. The two shapes must produce
// the same numbers, or the retirement thresholds the design states in
// live fractions would mean different things for different generations.
func TestLivenessIsTheSameThroughAManifestAndAnInlineList(t *testing.T) {
	inner, _, _, res, _ := treeFixture(t, "aaaa1111-2222-3333-4444-555555555555")
	sb := res.Superblock
	if !sb.PacksAreInManifests() {
		t.Fatal("fixture: publish did not name its packs through a manifest")
	}

	named := sweep(t, inner, sb)

	// The same generation as a pre-manifest writer would have written it.
	old := *sb
	old.PackList = packsOf(t, inner, sb)
	old.Manifests = nil
	inline := sweep(t, inner, &old)

	if len(named.Packs) != len(inline.Packs) {
		t.Fatalf("swept %d packs through the manifest, %d through the inline list",
			len(named.Packs), len(inline.Packs))
	}
	if named.Entries != inline.Entries || named.LiveEntries != inline.LiveEntries ||
		named.Bytes != inline.Bytes || named.LiveBytes != inline.LiveBytes {
		t.Fatalf("the two shapes disagree: manifest %d/%d entries %d/%d bytes, inline %d/%d entries %d/%d bytes",
			named.LiveEntries, named.Entries, named.LiveBytes, named.Bytes,
			inline.LiveEntries, inline.Entries, inline.LiveBytes, inline.Bytes)
	}
	for i := range named.Packs {
		if named.Packs[i] != inline.Packs[i] {
			t.Errorf("pack %d differs: %+v vs %+v", i, named.Packs[i], inline.Packs[i])
		}
	}
	t.Logf("%d packs, %.4f live, identical through both shapes", len(named.Packs), named.LiveFraction())
}

// A sweep that cannot read a generation's manifest does not know that
// generation's packs. It must report the sweep incomplete rather than
// quietly leave those packs out — a pack missing from the report is a
// pack a caller acting on the report may delete.
func TestASweepRefusesAGenerationWhoseManifestIsUnreadable(t *testing.T) {
	inner, volDir, _, res, _ := treeFixture(t, "bbbb1111-2222-3333-4444-555555555555")
	sb := res.Superblock
	for _, ref := range sb.Manifests {
		if err := os.Remove(filepath.Join(volDir, manifest.Dir, ref.Name)); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := reach.Sweep(context.Background(), reach.Options{
		Inner: inner, Live: []*superblock.Superblock{sb}, CacheDir: t.TempDir(), Workers: 4,
	})
	if rep != nil || err == nil {
		t.Fatalf("a sweep over an unresolvable pack set returned a report: %+v", rep)
	}
	var inc *reach.Incomplete
	if !errors.As(err, &inc) {
		t.Fatalf("want an *Incomplete, got %T: %v", err, err)
	}
	t.Logf("refused, with: %v", inc.Failures)
}
