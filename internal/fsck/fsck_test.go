package fsck_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

const rootIno uint64 = 1

// newInner starts a fakeorigin-backed store rooted at /vol (the genfs test
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

// pseudorandom returns deterministic incompressible content.
func pseudorandom(n int, seed int64) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// healthyFixture publishes a tree exercising every structure fsck knows
// about: a nested catalog (SMax forces a split), inline and chunked files,
// a symlink, and a hardlinked file whose content lives in an inode shard.
func healthyFixture(t *testing.T, uuid string, opts publish.Options) (pelicanobj.Store, string, *publish.Result) {
	t.Helper()
	inner, volDir := newInner(t)
	v := testvol.New(t, inner, testvol.Options{
		VolumeID:    testvol.ParseUUID(t, uuid),
		DEK:         opts.DEK,
		IdentityKey: opts.IdentityKey,
		KeyID:       opts.KeyID,
		KeyTable:    opts.KeyTable,
	})

	dir := v.Mkdir(rootIno, "dir")
	v.WriteFile(dir, "small.txt", []byte("inline body, well under the threshold"))
	v.Symlink(dir, "link", "small.txt")
	v.WriteFile(rootIno, "big.bin", pseudorandom(6<<20, 42))
	v.WriteFile(dir, "mid.bin", pseudorandom(2<<20, 43))
	hard := v.WriteFile(rootIno, "hard1", pseudorandom(3<<20, 44))
	v.Link(hard, dir, "hard2")

	opts.SMax = 1000 // force /dir into a nested catalog
	if opts.TargetPackSize == 0 {
		opts.TargetPackSize = 2 << 20
	}
	res := v.Publish(publish.Options{SMax: opts.SMax, TargetPackSize: opts.TargetPackSize})
	if res.Stats.Catalogs < 2 || res.Stats.Shards < 1 || len(res.Superblock.PackList) < 2 {
		t.Fatalf("fixture is not representative: %d catalogs, %d shards, %d packs",
			res.Stats.Catalogs, res.Stats.Shards, len(res.Superblock.PackList))
	}
	return inner, volDir, res
}

func check(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, o fsck.Options) *fsck.Report {
	t.Helper()
	o.Inner = inner
	o.SB = sb
	if o.CacheDir == "" {
		o.CacheDir = t.TempDir()
	}
	rep, err := fsck.Check(context.Background(), o)
	if err != nil {
		t.Fatalf("fsck.Check: %v", err)
	}
	return rep
}

// problemsOf returns the problems of one kind, for assertions that care
// about a class rather than a count.
func problemsOf(rep *fsck.Report, kind string) []fsck.Problem {
	var out []fsck.Problem
	for _, p := range rep.Problems {
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

func dumpProblems(t *testing.T, rep *fsck.Report) {
	t.Helper()
	for _, p := range rep.Problems {
		t.Logf("problem: %s %s: %s", p.Kind, p.Path, p.Detail)
	}
}

// packEntries lists one pack's trailer entries.
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
	for _, pe := range sb.PackList {
		for _, e := range packEntries(t, inner, pe) {
			if want(e) {
				return pe, e
			}
		}
	}
	t.Fatal("no pack holds a matching entry")
	return superblock.PackEntry{}, packstore.PackEntry{}
}

func isData(e packstore.PackEntry) bool { return e.Type == "" || e.Type == "data" }

func TestHealthyGeneration(t *testing.T) {
	inner, _, res := healthyFixture(t, "11111111-2222-3333-4444-555555555555", publish.Options{})
	rep := check(t, inner, res.Superblock, fsck.Options{})
	dumpProblems(t, rep)

	if !rep.OK() {
		t.Fatalf("healthy generation reported %d problems", len(rep.Problems))
	}
	st := res.Stats
	if rep.Dirs != st.Dirs || rep.Files != st.Files || rep.Symlinks != st.Symlinks {
		t.Fatalf("tree counts = %d dirs/%d files/%d symlinks, publish said %d/%d/%d",
			rep.Dirs, rep.Files, rep.Symlinks, st.Dirs, st.Files, st.Symlinks)
	}
	if rep.Catalogs != st.Catalogs || rep.Shards != st.Shards {
		t.Fatalf("objects = %d catalogs/%d shards, publish said %d/%d", rep.Catalogs, rep.Shards, st.Catalogs, st.Shards)
	}
	if rep.InlineFiles != st.InlineFiles {
		t.Fatalf("inline files = %d, publish said %d", rep.InlineFiles, st.InlineFiles)
	}
	if rep.Chunks != st.ChunksAdded {
		t.Fatalf("chunks = %d, publish uploaded %d", rep.Chunks, st.ChunksAdded)
	}
	if rep.Packs != len(res.Superblock.PackList) {
		t.Fatalf("verified %d packs of %d", rep.Packs, len(res.Superblock.PackList))
	}
	if rep.Bytes != int64(6<<20+2<<20+3<<20+len("inline body, well under the threshold")) {
		t.Fatalf("logical bytes = %d", rep.Bytes)
	}
	// Default mode is presence-only, by design.
	if rep.ChunksVerified != 0 {
		t.Fatalf("default mode verified %d chunks; it must not fetch any", rep.ChunksVerified)
	}
}

func TestDeepHealthy(t *testing.T) {
	inner, _, res := healthyFixture(t, "22222222-3333-4444-5555-666666666666", publish.Options{})
	rep := check(t, inner, res.Superblock, fsck.Options{Deep: true, Workers: 4})
	dumpProblems(t, rep)

	if !rep.OK() {
		t.Fatalf("deep check of a healthy generation reported %d problems", len(rep.Problems))
	}
	if rep.Chunks == 0 || rep.ChunksVerified != rep.Chunks {
		t.Fatalf("verified %d of %d chunks", rep.ChunksVerified, rep.Chunks)
	}
}

func TestMissingPack(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "33333333-4444-5555-6666-777777777777", publish.Options{})
	sb := res.Superblock

	// Delete a pack holding only data: the catalogs survive, so the sweep
	// must complete and report the whole tree alongside the damage.
	victim, _ := packHolding(t, inner, sb, isData)
	for _, pe := range sb.PackList {
		if pe.Name != victim.Name {
			continue
		}
		if err := os.Remove(filepath.Join(volDir, packstore.PackDirKey, pe.Name)); err != nil {
			t.Fatal(err)
		}
	}

	rep := check(t, inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	missing := problemsOf(rep, fsck.KindMissingPack)
	if len(missing) != 1 || !strings.Contains(missing[0].Path, victim.Name) {
		t.Fatalf("missing-pack problems = %+v", missing)
	}
	if len(problemsOf(rep, fsck.KindMissingChunk)) == 0 {
		t.Fatal("no chunk was reported missing after deleting a data pack")
	}
	// Everything else still reported.
	if rep.Packs != len(sb.PackList)-1 {
		t.Fatalf("verified %d packs, want %d", rep.Packs, len(sb.PackList)-1)
	}
	if rep.Files != res.Stats.Files || rep.Dirs != res.Stats.Dirs || rep.Catalogs != res.Stats.Catalogs {
		t.Fatalf("the sweep stopped early: %d files, %d dirs, %d catalogs", rep.Files, rep.Dirs, rep.Catalogs)
	}
}

// rewriteTrailer replaces a pack's trailer with a well-formed but
// different one (the created_ms stamp is bumped). The pack still parses,
// so what fails is the hash against the SIGNED pack list — the failure
// mode a silently rewritten location map produces.
func rewriteTrailer(t *testing.T, packPath string) {
	t.Helper()
	raw, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	n := len(raw)
	if n < 16 || string(raw[n-8:]) != "PELFSPK2" {
		t.Fatalf("%s is not a PELFSPK2 pack", packPath)
	}
	idxLen := int(binary.LittleEndian.Uint64(raw[n-16 : n-8]))
	off := n - 16 - idxLen
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	js, err := dec.DecodeAll(raw[off:n-16], nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	doc["created_ms"] = float64(1)
	js2, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	stored := enc.EncodeAll(js2, nil)
	enc.Close() //nolint:errcheck
	out := append(append([]byte(nil), raw[:off]...), stored...)
	footer := make([]byte, 16)
	binary.LittleEndian.PutUint64(footer[:8], uint64(len(stored)))
	copy(footer[8:], "PELFSPK2")
	if err := os.WriteFile(packPath, append(out, footer...), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptTrailer(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "44444444-5555-6666-7777-888888888888", publish.Options{})
	sb := res.Superblock
	victim, _ := packHolding(t, inner, sb, isData)
	rewriteTrailer(t, filepath.Join(volDir, packstore.PackDirKey, victim.Name))

	rep := check(t, inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindPackTrailer)
	if len(bad) != 1 || !strings.Contains(bad[0].Detail, "trailer hash mismatch") {
		t.Fatalf("pack-trailer problems = %+v", bad)
	}
	if len(problemsOf(rep, fsck.KindMissingPack)) != 0 {
		t.Fatal("a present-but-rewritten pack must not be reported missing")
	}
	// A rewritten trailer is also a size change, and the sweep keeps going.
	if rep.Files != res.Stats.Files {
		t.Fatalf("the sweep stopped early: %d files", rep.Files)
	}
}

func TestTruncatedPack(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "55555555-6666-7777-8888-999999999999", publish.Options{})
	sb := res.Superblock
	victim, _ := packHolding(t, inner, sb, isData)
	packPath := filepath.Join(volDir, packstore.PackDirKey, victim.Name)
	fi, err := os.Stat(packPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(packPath, fi.Size()-8); err != nil {
		t.Fatal(err)
	}

	rep := check(t, inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	if len(problemsOf(rep, fsck.KindPackTrailer)) != 1 {
		t.Fatalf("truncated pack: pack-trailer problems = %+v", problemsOf(rep, fsck.KindPackTrailer))
	}
	if len(problemsOf(rep, fsck.KindPackSize)) != 1 {
		t.Fatalf("truncated pack: pack-size problems = %+v", problemsOf(rep, fsck.KindPackSize))
	}
}

// flipDataByte corrupts one byte inside a pack's DATA region, leaving the
// trailer and every recorded length intact — the damage class default mode
// cannot see.
func flipDataByte(t *testing.T, packPath string, off int64) {
	t.Helper()
	f, err := os.OpenFile(packPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptChunkBytes(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "66666666-7777-8888-9999-aaaaaaaaaaaa", publish.Options{})
	sb := res.Superblock
	victim, entry := packHolding(t, inner, sb, isData)
	flipDataByte(t, filepath.Join(volDir, packstore.PackDirKey, victim.Name), entry.Off+entry.Length/2)

	// Default mode is presence-only and says so: the entry is still there,
	// still the recorded length, and nothing reads it.
	shallow := check(t, inner, sb, fsck.Options{})
	dumpProblems(t, shallow)
	if !shallow.OK() {
		t.Fatalf("default mode reported %d problems; it must not read chunk bytes", len(shallow.Problems))
	}

	deep := check(t, inner, sb, fsck.Options{Deep: true, Workers: 4})
	dumpProblems(t, deep)
	bad := problemsOf(deep, fsck.KindChunk)
	if len(bad) != 1 {
		t.Fatalf("deep mode found %d chunk problems, want 1", len(bad))
	}
	if !strings.Contains(bad[0].Detail, "hashes to") {
		t.Fatalf("deep problem should be an identity mismatch: %+v", bad[0])
	}
	if deep.ChunksVerified != deep.Chunks-1 {
		t.Fatalf("verified %d of %d chunks", deep.ChunksVerified, deep.Chunks)
	}
}

func encryptedFixture(t *testing.T, uuid string) (pelicanobj.Store, string, *publish.Result, []byte) {
	t.Helper()
	dek := pseudorandom(32, 1)
	inner, volDir, res := healthyFixture(t, uuid, publish.Options{
		DEK:         dek,
		IdentityKey: pseudorandom(32, 2),
		KeyID:       7,
		KeyTable: []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		},
	})
	return inner, volDir, res, dek
}

// On an encrypted volume the identity is keyed BLAKE3, which fsck cannot
// recompute; the GCM tag is the authentication. Deep mode must therefore
// still catch tampering, and a wrong DEK must fail loudly rather than
// quietly reporting a clean volume.
func TestEncryptedDeep(t *testing.T) {
	inner, volDir, res, dek := encryptedFixture(t, "77777777-8888-9999-aaaa-bbbbbbbbbbbb")
	sb := res.Superblock

	rep := check(t, inner, sb, fsck.Options{DEK: dek, Deep: true, Workers: 4})
	dumpProblems(t, rep)
	if !rep.OK() {
		t.Fatalf("healthy encrypted generation reported %d problems", len(rep.Problems))
	}
	if rep.Chunks == 0 || rep.ChunksVerified != rep.Chunks {
		t.Fatalf("verified %d of %d chunks", rep.ChunksVerified, rep.Chunks)
	}

	// A wrong DEK cannot even open the root catalog: loud, not silent.
	if _, err := fsck.Check(context.Background(), fsck.Options{
		Inner: inner, SB: sb, DEK: pseudorandom(32, 99), CacheDir: t.TempDir(),
	}); err == nil {
		t.Fatal("check with the wrong DEK succeeded")
	}
	// No DEK at all is refused up front.
	if _, err := fsck.Check(context.Background(), fsck.Options{
		Inner: inner, SB: sb, CacheDir: t.TempDir(),
	}); err == nil {
		t.Fatal("check of an encrypted volume without a DEK succeeded")
	}

	// Tampered ciphertext: the GCM open fails, which is the whole integrity
	// story on a keyed-identity volume.
	victim, entry := packHolding(t, inner, sb, isData)
	flipDataByte(t, filepath.Join(volDir, packstore.PackDirKey, victim.Name), entry.Off+entry.Length/2)
	if shallow := check(t, inner, sb, fsck.Options{DEK: dek}); !shallow.OK() {
		t.Fatalf("default mode reported %d problems on tampered ciphertext; it must not read chunk bytes", len(shallow.Problems))
	}
	deep := check(t, inner, sb, fsck.Options{DEK: dek, Deep: true, Workers: 4})
	dumpProblems(t, deep)
	bad := problemsOf(deep, fsck.KindChunk)
	if len(bad) != 1 || !strings.Contains(bad[0].Detail, "decrypt entry") {
		t.Fatalf("deep mode on tampered ciphertext = %+v", bad)
	}
}

// Every failure is reported, not just the first, and the list is ordered
// deterministically.
func TestMultipleProblemsSorted(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "88888888-9999-aaaa-bbbb-cccccccccccc", publish.Options{})
	sb := res.Superblock

	var damaged []string
	for _, pe := range sb.PackList {
		for _, e := range packEntries(t, inner, pe) {
			if !isData(e) {
				continue
			}
			damaged = append(damaged, pe.Name)
			break
		}
	}
	if len(damaged) < 2 {
		t.Fatalf("fixture has only %d data packs", len(damaged))
	}
	if err := os.Remove(filepath.Join(volDir, packstore.PackDirKey, damaged[0])); err != nil {
		t.Fatal(err)
	}
	rewriteTrailer(t, filepath.Join(volDir, packstore.PackDirKey, damaged[1]))

	rep := check(t, inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	if len(problemsOf(rep, fsck.KindMissingPack)) != 1 || len(problemsOf(rep, fsck.KindPackTrailer)) != 1 {
		t.Fatalf("both pack failures must be reported: %+v", rep.Problems)
	}
	if len(problemsOf(rep, fsck.KindMissingChunk)) < 2 {
		t.Fatalf("chunks from two lost packs must all be reported: %+v", rep.Problems)
	}
	for i := 1; i < len(rep.Problems); i++ {
		a, b := rep.Problems[i-1], rep.Problems[i]
		if a.Path > b.Path || (a.Path == b.Path && a.Kind > b.Kind) {
			t.Fatalf("problems out of order at %d: %+v then %+v", i, a, b)
		}
	}
	// A second run over the same damage produces the identical list.
	again := check(t, inner, sb, fsck.Options{})
	if len(again.Problems) != len(rep.Problems) {
		t.Fatalf("re-run found %d problems, first run %d", len(again.Problems), len(rep.Problems))
	}
	for i := range rep.Problems {
		if again.Problems[i] != rep.Problems[i] {
			t.Fatalf("re-run differs at %d: %+v vs %+v", i, again.Problems[i], rep.Problems[i])
		}
	}
}

// A root catalog that cannot be read is the one failure that aborts: with
// no tree to descend, everything else would be guesswork.
func TestUnreadableRootAborts(t *testing.T) {
	inner, volDir, res := healthyFixture(t, "99999999-aaaa-bbbb-cccc-dddddddddddd", publish.Options{})
	sb := res.Superblock
	rootHex := fmt.Sprintf("%x", sb.RootCatalog)
	victim, _ := packHolding(t, inner, sb, func(e packstore.PackEntry) bool { return e.Key == rootHex })
	if err := os.Remove(filepath.Join(volDir, packstore.PackDirKey, victim.Name)); err != nil {
		t.Fatal(err)
	}

	rep, err := fsck.Check(context.Background(), fsck.Options{
		Inner: inner, SB: sb, CacheDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("a missing root catalog must abort the check")
	}
	// The partial report still carries what was learned about the packs.
	if rep == nil || len(problemsOf(rep, fsck.KindMissingPack)) != 1 {
		t.Fatalf("partial report = %+v", rep)
	}
}
