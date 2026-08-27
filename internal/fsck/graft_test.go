package fsck_test

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// fsck on a volume that serves part of its namespace from somebody else's
// storage.
//
// The headline is one line long and is the reason this file exists: a
// healthy grafted volume used to report EVERY grafted file as
// missing-chunk and exit 1, because checkChunkRef had the same absence
// check genfs.ContentOf and genfs.Prefetch both had, and a grafted chunk
// is in no pack by design. Everything else here is the severity
// assignment that had to come with the fix — which of the things that can
// go wrong with a graft are this volume's damage and which are a third
// party's news.

// graftFix is a volume whose whole tree is grafted from a second prefix
// served by a SEPARATE http server, so that a test can take the third
// party offline, delete one of its objects, or edit one in place, without
// touching the volume's own storage.
type graftFix struct {
	inner  pelicanobj.Store
	src    pelicanobj.Store
	srcSrv *httptest.Server
	srcDir string
	volDir string
	sb     *superblock.Superblock
	ent    superblock.GraftEntry
	policy graft.BlockPolicy
	key    ed25519.PrivateKey
	root   string

	// heads and gets count what a check asked the SOURCE for, which is
	// the whole difference between the two check depths.
	heads, gets atomic.Int64
}

// files is the source tree: one file under the inline threshold (copied
// into the catalog, not grafted at all), and three above it with
// different block counts.
var graftFiles = map[string]int{
	"data/small.txt":      40,
	"data/one.bin":        70000,
	"data/multi.bin":      200000,
	"data/nested/big.bin": 500000,
}

func newGraftFix(t *testing.T) *graftFix {
	t.Helper()
	ctx := context.Background()
	f := &graftFix{root: t.TempDir(), policy: graft.BlockPolicy{Block: 4096, Max: 16384, PerObject: 2}}
	f.volDir = filepath.Join(f.root, "vol")
	f.srcDir = filepath.Join(f.root, "ext")

	volSrv := httptest.NewServer(fakeorigin.Handler(f.root))
	t.Cleanup(volSrv.Close)
	// Counting, so a test can assert that the cheap mode moved no data.
	inner := fakeorigin.Handler(f.root)
	f.srcSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			f.heads.Add(1)
		case http.MethodGet:
			f.gets.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srcSrv.Close)

	newStore := func(base, prefix string) pelicanobj.Store {
		s, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: base + "/" + prefix})
		if err != nil {
			t.Fatalf("pelicanobj.New: %v", err)
		}
		return s
	}
	f.inner = newStore(volSrv.URL, "vol")
	f.src = newStore(f.srcSrv.URL, "ext")

	for name, n := range graftFiles {
		p := filepath.Join(f.srcDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, pseudorandom(n, int64(len(name)+n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, key, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	var vid [16]byte
	if _, err := crand.Read(vid[:]); err != nil {
		t.Fatal(err)
	}
	init, err := publish.InitVolume(ctx, publish.Options{
		Inner: f.inner, SpoolDir: t.TempDir(), Branch: "main", SigningKey: key, VolumeID: vid,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	res, ent := f.spider(t, f.src, "/ext", f.srcSrv.URL+"/ext")
	gsrc, err := publish.NewGraftSource(publish.GraftSourceOptions{Mount: "/ext", Result: res})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publish.Publish(ctx, publish.Options{
		Source: gsrc, Inner: f.inner, SpoolDir: t.TempDir(), Branch: "main",
		SigningKey: key, Prev: init.Superblock, PrevRaw: init.Raw,
		Grafts: []superblock.GraftEntry{ent},
	})
	if err != nil {
		t.Fatalf("publish generation: %v", err)
	}
	f.sb, f.ent = pub.Superblock, ent
	// The counters exist to measure a CHECK, so whatever the spider spent
	// getting here does not belong in them.
	f.heads.Store(0)
	f.gets.Store(0)
	return f
}

// spider walks one source prefix and publishes its index into the volume.
func (f *graftFix) spider(t *testing.T, src pelicanobj.Store, mount, source string) (*graft.Result, superblock.GraftEntry) {
	t.Helper()
	ctx := context.Background()
	w, err := graft.NewWriter(t.TempDir(), f.policy.Block)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	res, err := graft.Spider(ctx, graft.SpiderOptions{
		Src: src, Index: w, Policy: f.policy, Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("Spider: %v", err)
	}
	ent, err := w.Publish(ctx, f.inner, graft.PublishOptions{
		Mount: mount, Source: source, Policy: f.policy,
		Bytes: res.Bytes, Files: len(res.Files) - res.Inlined,
	})
	if err != nil {
		t.Fatalf("publish index: %v", err)
	}
	return res, ent
}

// opener is the reader's veto, saying yes.
func (f *graftFix) opener() func(context.Context, string) (pelicanobj.Store, error) {
	return func(context.Context, string) (pelicanobj.Store, error) { return f.src, nil }
}

// check runs fsck over a (possibly doctored) superblock.
func (f *graftFix) check(t *testing.T, sb *superblock.Superblock, o fsck.Options) *fsck.Report {
	t.Helper()
	if o.GraftOpener == nil {
		o.GraftOpener = f.opener()
	}
	return check(t, f.inner, sb, o)
}

// indexPath is where a graft's index object sits on the volume's disk.
func (f *graftFix) indexPath(ent superblock.GraftEntry) string {
	return filepath.Join(f.volDir, filepath.FromSlash(graft.IndexKey(ent.Index)))
}

// clone copies the superblock so a test can doctor the graft entries
// without disturbing the others. fsck takes the superblock as an already
// verified integrity root, which is exactly what makes this legitimate:
// these are generations somebody could have signed.
func (f *graftFix) clone() *superblock.Superblock {
	sb := *f.sb
	sb.Grafts = append([]superblock.GraftEntry(nil), f.sb.Grafts...)
	return &sb
}

// kinds counts the findings by kind, which is how nearly every assertion
// below is phrased: what was reported, and at what severity.
func kinds(rep *fsck.Report) map[string]int {
	out := map[string]int{}
	for _, p := range rep.Problems {
		out[p.Kind]++
	}
	return out
}

func onlyKind(t *testing.T, rep *fsck.Report, kind string) []fsck.Problem {
	t.Helper()
	got := problemsOf(rep, kind)
	if len(got) == 0 {
		dumpProblems(t, rep)
		t.Fatalf("no %s finding; the report holds %v", kind, kinds(rep))
	}
	return got
}

// TestAGraftedVolumeChecksClean is the headline. Before this, every
// grafted file was reported `missing-chunk` and `pelfs fsck` exited 1 on
// a perfectly healthy volume.
func TestAGraftedVolumeChecksClean(t *testing.T) {
	f := newGraftFix(t)
	rep := f.check(t, f.sb, fsck.Options{})

	if !rep.Clean() {
		dumpProblems(t, rep)
		t.Fatalf("a healthy grafted volume reported %d findings: %v", len(rep.Problems), kinds(rep))
	}
	if rep.Damaged() {
		t.Fatal("a healthy grafted volume is damaged")
	}
	if rep.Grafts != 1 || rep.GraftBlocks == 0 || rep.GraftObjects == 0 {
		t.Fatalf("report says %d grafts, %d blocks, %d source objects",
			rep.Grafts, rep.GraftBlocks, rep.GraftObjects)
	}
	// The counts have to say that most of this namespace is external, or
	// the fixture is not testing what it claims to.
	if rep.GraftChunks == 0 || rep.GraftChunks != rep.Chunks {
		t.Fatalf("%d of %d chunks resolved through a graft; this fixture's tree is entirely "+
			"grafted, so they should be equal and nonzero", rep.GraftChunks, rep.Chunks)
	}
	// The one file under InlineKeep is copied into the catalog rather
	// than grafted, which is the behaviour that makes "grafted files" and
	// "files" different numbers.
	if rep.InlineFiles != 1 || rep.Files != len(graftFiles) {
		t.Fatalf("%d files, %d of them inline; want %d and 1", rep.Files, rep.InlineFiles, len(graftFiles))
	}
}

// TestTheCheapModeStatsAndReadsNothing pins the cost of the default,
// which is the claim `pelfs fsck` prints. A HEAD per source object, and
// not one byte of a tree that could be 10 TB.
func TestTheCheapModeStatsAndReadsNothing(t *testing.T) {
	f := newGraftFix(t)
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})

	if !rep.Clean() {
		dumpProblems(t, rep)
		t.Fatal("a healthy volume was not clean")
	}
	if got := int(f.gets.Load()); got != 0 {
		t.Errorf("the cheap mode issued %d GETs against the source; its whole claim is that "+
			"it moves no data", got)
	}
	if got, want := int(f.heads.Load()), rep.GraftObjects; got != want {
		t.Errorf("the cheap mode issued %d HEADs for %d source objects", got, want)
	}
	if rep.GraftObjectsChecked != rep.GraftObjects {
		t.Errorf("report says %d of %d source objects checked", rep.GraftObjectsChecked, rep.GraftObjects)
	}
	if rep.GraftBlocksVerified != 0 || rep.GraftBytesVerified != 0 {
		t.Errorf("the cheap mode claims to have verified %d blocks / %d bytes",
			rep.GraftBlocksVerified, rep.GraftBytesVerified)
	}
	if rep.GraftDepth != fsck.GraftHead {
		t.Errorf("report says depth %v", rep.GraftDepth)
	}
}

// TestGraftNoneTouchesNoThirdParty: with the source gone entirely, a
// check that was told not to contact it is still clean — because
// resolution comes from the INDEX, which is this volume's own object.
func TestGraftNoneTouchesNoThirdParty(t *testing.T) {
	f := newGraftFix(t)
	f.srcSrv.Close()

	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftNone})
	if !rep.Clean() {
		dumpProblems(t, rep)
		t.Fatal("--grafts=none contacted the source, or reported it")
	}
	if rep.GraftBlocks == 0 || rep.GraftChunks == 0 {
		t.Fatal("--grafts=none stopped resolving grafted chunkrefs; the index is not optional")
	}
	if n := f.heads.Load() + f.gets.Load(); n != 0 {
		t.Fatalf("--grafts=none made %d requests of the source", n)
	}
}

// TestAChunkInNeitherLayerIsStillMissing. The fix is "a graft is a
// location", not "absence is fine": with the graft entry gone from the
// generation, the same chunkrefs resolve nowhere and are damage again.
func TestAChunkInNeitherLayerIsStillMissing(t *testing.T) {
	f := newGraftFix(t)
	sb := f.clone()
	sb.Grafts = nil

	rep := f.check(t, sb, fsck.Options{})
	if !rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("chunkrefs that resolve in no pack and no graft were not reported as damage")
	}
	missing := onlyKind(t, rep, fsck.KindMissingChunk)
	// One per FILE, which is what a human needs: the same lost chunk in
	// ten files is ten broken files.
	if len(missing) < 3 {
		t.Fatalf("%d missing-chunk findings for %d grafted files", len(missing), len(graftFiles)-1)
	}
	for _, p := range missing {
		if p.Severity != fsck.SeverityError {
			t.Fatalf("missing-chunk is %v, want error", p.Severity)
		}
	}
}

// TestAMissingIndexObjectIsDamage. The index lives under THIS volume's
// prefix and is the only record of where a grafted file's bytes are; a
// generation that lost it is a generation no reader can serve.
func TestAMissingIndexObjectIsDamage(t *testing.T) {
	f := newGraftFix(t)
	if err := os.Remove(f.indexPath(f.ent)); err != nil {
		t.Fatal(err)
	}
	rep := f.check(t, f.sb, fsck.Options{})

	if !rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a missing graft index was not damage")
	}
	for _, p := range onlyKind(t, rep, fsck.KindGraftIndex) {
		if p.Severity != fsck.SeverityError {
			t.Fatalf("graft-index is %v, want error", p.Severity)
		}
	}
	// And the files under it are missing-chunk, because they are: with no
	// index there is no location for a single one of their blocks.
	if len(problemsOf(rep, fsck.KindMissingChunk)) == 0 {
		t.Fatal("no missing-chunk findings under a graft whose index is gone")
	}
	// ONE finding about the graft itself. Comparing the signed entry
	// against the nothing an unreadable index yielded would add "the
	// entry says 4 blocks, its index holds 0" and "says 2 objects, names
	// 0" — two more lines saying the first line's news in worse words.
	if n := len(problemsOf(rep, fsck.KindGraftEntry)); n != 0 {
		dumpProblems(t, rep)
		t.Fatalf("%d graft-entry findings downstream of an unreadable index", n)
	}
	if n := len(problemsOf(rep, fsck.KindGraftIndex)); n != 1 {
		t.Fatalf("%d graft-index findings for one lost index", n)
	}
}

// TestACorruptIndexObjectIsDamage: the object is there and is not the
// object the signature covers.
func TestACorruptIndexObjectIsDamage(t *testing.T) {
	f := newGraftFix(t)
	p := f.indexPath(f.ent)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-9] ^= 0x40 // in the records, past everything a mount parses at Load
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	rep := f.check(t, f.sb, fsck.Options{})

	if !rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a corrupt graft index was not damage")
	}
	got := onlyKind(t, rep, fsck.KindGraftIndex)
	if !strings.Contains(got[0].Detail, "hashes to") {
		t.Fatalf("the finding does not name the hash mismatch: %s", got[0].Detail)
	}
}

// TestAnEntryThatContradictsItsIndexIsDamage. The entry is signed and the
// index is hash-named; a disagreement between them means one of the two
// is not what this generation was published with.
func TestAnEntryThatContradictsItsIndexIsDamage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		doctor func(*superblock.GraftEntry)
		want   string
	}{
		{"block count", func(e *superblock.GraftEntry) { e.Blocks += 7 }, "blocks"},
		{"object count", func(e *superblock.GraftEntry) { e.Objects += 3 }, "source objects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraftFix(t)
			sb := f.clone()
			tc.doctor(&sb.Grafts[0])

			rep := f.check(t, sb, fsck.Options{})
			if !rep.Damaged() {
				dumpProblems(t, rep)
				t.Fatal("an entry contradicting its index was not damage")
			}
			got := onlyKind(t, rep, fsck.KindGraftEntry)
			if !strings.Contains(got[0].Detail, tc.want) {
				t.Fatalf("the finding does not name what disagreed: %s", got[0].Detail)
			}
			// The FILES are still fine: the index is intact, so every
			// chunkref still resolves. A wrong count is damage to the
			// generation's self-description, not to its content.
			if n := len(problemsOf(rep, fsck.KindMissingChunk)); n != 0 {
				t.Fatalf("%d missing-chunk findings from a wrong count", n)
			}
		})
	}
}

// TestAnEncryptedVolumeWithGraftsIsDamage. genfs refuses to mount such a
// generation at all: a grafted block carries no AEAD tag and its identity
// is keyed under a key no reader holds, so nothing can verify it. That is
// decidable without touching any source and is not fixable by a refresh.
func TestAnEncryptedVolumeWithGraftsIsDamage(t *testing.T) {
	f := newGraftFix(t)
	rep := f.check(t, f.sb, fsck.Options{DEK: make([]byte, 32)})

	if !rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a graft on an encrypted volume was not damage")
	}
	got := onlyKind(t, rep, fsck.KindGraftEntry)
	if !strings.Contains(got[0].Detail, "encrypted") {
		t.Fatalf("the finding does not say why: %s", got[0].Detail)
	}
}

// TestAChangedSourceIsAWarningNotDamage, in the two shapes the cheap mode
// can see: an object that grew and one that was truncated. This is the
// exit-code claim the whole severity axis exists for — a volume whose
// upstream republished a file is NOT broken.
func TestAChangedSourceIsAWarningNotDamage(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want string
	}{
		{"grew", 260000, "it was"},
		{"truncated", 40000, "reads of its last blocks fail now"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGraftFix(t)
			p := filepath.Join(f.srcDir, "data", "multi.bin")
			if err := os.WriteFile(p, pseudorandom(tc.size, 9), 0o644); err != nil {
				t.Fatal(err)
			}
			rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})

			if rep.Damaged() {
				dumpProblems(t, rep)
				t.Fatal("a source that moved on made the volume DAMAGED; that is the report " +
					"that gets a healthy volume restored from backup")
			}
			if rep.Clean() {
				t.Fatal("a source that moved on was not reported at all")
			}
			got := onlyKind(t, rep, fsck.KindGraftSourceChanged)
			if got[0].Severity != fsck.SeverityWarning {
				t.Fatalf("graft-source-changed is %v, want warning", got[0].Severity)
			}
			if !strings.Contains(got[0].Detail, tc.want) {
				t.Fatalf("the finding does not say what changed: %s", got[0].Detail)
			}
			if !strings.Contains(got[0].Detail, "--refresh") {
				t.Fatalf("the finding does not name the fix: %s", got[0].Detail)
			}
			// The exit contract, which is what an operator's cron reads.
			if rep.Warnings() == 0 || rep.Errors() != 0 {
				t.Fatalf("%d errors and %d warnings", rep.Errors(), rep.Warnings())
			}
		})
	}
}

// TestADeletedSourceObjectIsAWarning, and this is the assignment worth
// arguing about: the files behind it are unreadable and --refresh will
// not bring them back. It is still not this volume's damage — pelfs never
// held those bytes — and fsck cannot tell a deletion from an expired
// token or a partition, so calling an outage corruption is the one thing
// it must not do.
func TestADeletedSourceObjectIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	if err := os.Remove(filepath.Join(f.srcDir, "data", "multi.bin")); err != nil {
		t.Fatal(err)
	}
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})

	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a deleted source object made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftSourceMissing)
	if got[0].Severity != fsck.SeverityWarning {
		t.Fatalf("graft-source-missing is %v, want warning", got[0].Severity)
	}
	if !strings.Contains(got[0].Detail, "pelfs never held a copy") {
		t.Fatalf("the finding does not say what it means: %s", got[0].Detail)
	}
	// It must not ALSO be reported as a change: "gone" and "moved on" are
	// different sentences and an operator greps for one of them.
	if n := len(problemsOf(rep, fsck.KindGraftSourceChanged)); n != 0 {
		t.Fatalf("a deleted object also produced %d graft-source-changed findings", n)
	}
}

// TestAnUnreachableSourceIsUncheckedNotChanged. genfs already refuses to
// classify an unreachable source as changed data and has a test for it;
// fsck must make the same distinction, because "I could not ask" and "I
// asked and it was wrong" lead an operator to different places.
func TestAnUnreachableSourceIsUncheckedNotChanged(t *testing.T) {
	f := newGraftFix(t)
	f.srcSrv.Close()

	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("an unreachable source made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftUnchecked)
	if got[0].Severity != fsck.SeverityWarning {
		t.Fatalf("graft-unchecked is %v, want warning", got[0].Severity)
	}
	for _, kind := range []string{fsck.KindGraftSourceChanged, fsck.KindGraftSourceMissing} {
		if n := len(problemsOf(rep, kind)); n != 0 {
			t.Fatalf("an unreachable source produced %d %s findings — an outage is not an "+
				"accusation against the source's data", n, kind)
		}
	}
	// And nothing about the VOLUME was reported: its own objects were all
	// readable, which is the point of keeping the two populations apart.
	if n := len(problemsOf(rep, fsck.KindMissingChunk)); n != 0 {
		t.Fatalf("%d missing-chunk findings from a source outage", n)
	}
}

// TestARefusedSourceIsUnchecked: the reader's veto is fsck's veto too,
// and declining to look is reported as declining to look.
func TestARefusedSourceIsUnchecked(t *testing.T) {
	f := newGraftFix(t)
	rep := f.check(t, f.sb, fsck.Options{
		GraftDepth: fsck.GraftHead,
		GraftOpener: func(context.Context, string) (pelicanobj.Store, error) {
			return nil, errors.New("this mount does not fetch from that federation")
		},
	})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a refused source made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftUnchecked)
	if !strings.Contains(got[0].Detail, "does not fetch from that federation") {
		t.Fatalf("the finding does not carry the refusal: %s", got[0].Detail)
	}
}

// TestNoOpenerContactsNobody. The opener is the gate and the depth is the
// dial: a caller that supplies no opener never reaches a third party,
// whatever depth it asked for, and nothing is reported about a source
// nobody could have looked at.
func TestNoOpenerContactsNobody(t *testing.T) {
	f := newGraftFix(t)
	rep := check(t, f.inner, f.sb, fsck.Options{GraftDepth: fsck.GraftDeep})
	if !rep.Clean() {
		dumpProblems(t, rep)
		t.Fatal("a check with no graft opener reported something")
	}
	if n := f.heads.Load() + f.gets.Load(); n != 0 {
		t.Fatalf("a check with no graft opener made %d requests of the source", n)
	}
	if rep.GraftDepth != fsck.GraftNone {
		t.Fatalf("report says depth %v, want none: with no opener there is no source check", rep.GraftDepth)
	}
}

// TestTheTwoDepthsDifferOnASameLengthEdit is the whole argument for
// having two of them. One byte changed in place, length unchanged, mtime
// within the skew allowance: the cheap mode is silent, and says so in the
// report, while the deep mode fails the block. This is exactly the
// mutation docs/design-graft.md's spike uses.
func TestTheTwoDepthsDifferOnASameLengthEdit(t *testing.T) {
	f := newGraftFix(t)
	p := filepath.Join(f.srcDir, "data", "multi.bin")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	raw[150000] ^= 0xff
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	// The mtime test is the cheap mode's other signal and it is one-sided
	// against the GENERATION's timestamp; keeping the file's mtime where
	// it was isolates the size test, which is what this test is about.
	stamp := time.Unix(f.sb.CreatedUnixNano/1e9-3600, 0)
	if err := os.Chtimes(p, stamp, stamp); err != nil {
		t.Fatal(err)
	}

	cheap := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})
	if !cheap.Clean() {
		dumpProblems(t, cheap)
		t.Fatal("the cheap mode claimed to see a same-length edit; it cannot, and pretending " +
			"otherwise here would mean it is firing on something else")
	}

	deep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftDeep})
	if deep.Damaged() {
		dumpProblems(t, deep)
		t.Fatal("a changed source is still not this volume's damage in deep mode")
	}
	got := onlyKind(t, deep, fsck.KindGraftSourceChanged)
	if got[0].Severity != fsck.SeverityWarning {
		t.Fatalf("graft-source-changed is %v in deep mode, want warning", got[0].Severity)
	}
	if !strings.Contains(got[0].Detail, "hashes to") {
		t.Fatalf("the deep finding does not name the hash: %s", got[0].Detail)
	}
	// One block, not the whole file: verification is per block.
	if len(got) != 1 {
		t.Fatalf("%d blocks reported for a one-byte edit", len(got))
	}
	// And the deep mode's claim is the expensive one, so it has to have
	// actually moved the bytes.
	if deep.GraftBlocksVerified == 0 || deep.GraftBytesVerified == 0 {
		t.Fatalf("deep mode verified %d blocks / %d bytes",
			deep.GraftBlocksVerified, deep.GraftBytesVerified)
	}
	if f.gets.Load() == 0 {
		t.Fatal("deep mode read nothing from the source")
	}
}

// TestAnMtimeAfterTheGenerationIsAWarning: the cheap mode's only signal
// against a same-length edit, and it costs nothing because the HEAD was
// already made. It is one-sided — an object NEWER than the generation was
// modified after it was spidered — so it cannot fire on a source that has
// not moved.
func TestAnMtimeAfterTheGenerationIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	p := filepath.Join(f.srcDir, "data", "one.bin")
	stamp := time.Unix(f.sb.CreatedUnixNano/1e9+86400, 0)
	if err := os.Chtimes(p, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})

	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a republished source made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftSourceChanged)
	if !strings.Contains(got[0].Detail, "was modified at") {
		t.Fatalf("the finding does not name the mtime: %s", got[0].Detail)
	}
	if !strings.Contains(got[0].Detail, "--grafts=deep") {
		t.Fatalf("the finding does not say what the cheap mode could not settle: %s", got[0].Detail)
	}
}

// TestAnUnmovedSourceNeverWarns is the other half of the mtime test, and
// the one that keeps --strict usable: every object in the fixture is
// older than the generation, so nothing fires.
func TestAnUnmovedSourceNeverWarns(t *testing.T) {
	f := newGraftFix(t)
	// Push every source object's mtime right up to the generation's own
	// timestamp — inside the skew allowance, which is where a source
	// written moments before the spider legitimately sits.
	stamp := time.Unix(0, f.sb.CreatedUnixNano)
	for name := range graftFiles {
		p := filepath.Join(f.srcDir, filepath.FromSlash(name))
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})
	if !rep.Clean() {
		dumpProblems(t, rep)
		t.Fatal("a source whose objects are as old as the generation produced findings")
	}
}

// TestAGraftNothingReferencesIsAWarning. A second graft over a tree the
// namespace never names: the volume reads perfectly and is carrying a
// dependency on a third party for nothing, which is worth saying and is
// not damage.
func TestAGraftNothingReferencesIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	// A second source tree, spidered and published, but never spliced
	// into the namespace.
	otherDir := filepath.Join(f.root, "other")
	if err := os.MkdirAll(filepath.Join(otherDir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "d", "x.bin"), pseudorandom(300000, 77), 0o644); err != nil {
		t.Fatal(err)
	}
	otherSrv := httptest.NewServer(fakeorigin.Handler(f.root))
	t.Cleanup(otherSrv.Close)
	other, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: otherSrv.URL + "/other"})
	if err != nil {
		t.Fatal(err)
	}
	_, ent := f.spider(t, other, "/other", otherSrv.URL+"/other")

	sb := f.clone()
	sb.Grafts = append(sb.Grafts, ent)
	rep := f.check(t, sb, fsck.Options{
		GraftDepth: fsck.GraftHead,
		GraftOpener: func(_ context.Context, source string) (pelicanobj.Store, error) {
			if strings.HasSuffix(source, "/other") {
				return other, nil
			}
			return f.src, nil
		},
	})

	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("an unused graft made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftUnreferenced)
	if got[0].Severity != fsck.SeverityWarning {
		t.Fatalf("graft-unreferenced is %v, want warning", got[0].Severity)
	}
	if !strings.Contains(got[0].Detail, "--remove") {
		t.Fatalf("the finding does not name the fix: %s", got[0].Detail)
	}
	if len(got) != 1 {
		t.Fatalf("%d unreferenced findings for one unused graft", len(got))
	}
}

// TestAStaleGraftPathIsAWarning. Renaming a grafted directory moves every
// file without touching a single identity, so the recorded path goes
// stale while every read keeps working. Nothing routes by Path, so this
// cannot make a read wrong — it makes `--list` lie.
func TestAStaleGraftPathIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	sb := f.clone()
	sb.Grafts[0].Path = "/somewhere-else"

	rep := f.check(t, sb, fsck.Options{GraftDepth: fsck.GraftNone})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a stale graft path made the volume damaged")
	}
	got := onlyKind(t, rep, fsck.KindGraftMetadata)
	if !strings.Contains(got[0].Detail, "the reads are correct") {
		t.Fatalf("the finding does not say the reads are fine: %s", got[0].Detail)
	}
}

// TestTwoGraftsAtOnePathIsAWarning: `--list` cannot tell them apart, and
// nothing else cares, because a graft is consulted by identity.
func TestTwoGraftsAtOnePathIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	sb := f.clone()
	sb.Grafts = append(sb.Grafts, sb.Grafts[0])

	rep := f.check(t, sb, fsck.Options{GraftDepth: fsck.GraftNone})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("two grafts at one path made the volume damaged")
	}
	var found bool
	for _, p := range problemsOf(rep, fsck.KindGraftMetadata) {
		if strings.Contains(p.Detail, "two grafts are recorded at this path") {
			found = true
		}
	}
	if !found {
		dumpProblems(t, rep)
		t.Fatal("a duplicate graft path was not reported")
	}
}

// TestABlockPolicyThatCouldNotHaveCutThisIndexIsAWarning. Nothing
// resolves through the recorded rule — the index carries a length per
// block — so a bad one costs a refresh, not a read.
func TestABlockPolicyThatCouldNotHaveCutThisIndexIsAWarning(t *testing.T) {
	f := newGraftFix(t)
	sb := f.clone()
	sb.Grafts[0].Block = 5000 // not a power of two

	rep := f.check(t, sb, fsck.Options{GraftDepth: fsck.GraftNone})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("an impossible block policy made the volume damaged")
	}
	var found bool
	for _, p := range problemsOf(rep, fsck.KindGraftMetadata) {
		if strings.Contains(p.Detail, "a refresh cannot reproduce this cut") {
			found = true
		}
	}
	if !found {
		dumpProblems(t, rep)
		t.Fatal("an impossible block policy was not reported")
	}
}

// TestDeepModeSkipsTheBlocksOfAMissingObject. One finding per object
// beats ten thousand failed requests for a fact already reported.
func TestDeepModeSkipsTheBlocksOfAMissingObject(t *testing.T) {
	f := newGraftFix(t)
	if err := os.Remove(filepath.Join(f.srcDir, "data", "nested", "big.bin")); err != nil {
		t.Fatal(err)
	}
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftDeep})

	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("a missing source object made the volume damaged in deep mode")
	}
	if n := len(onlyKind(t, rep, fsck.KindGraftSourceMissing)); n != 1 {
		t.Fatalf("%d findings for one missing object", n)
	}
	if n := len(problemsOf(rep, fsck.KindGraftUnchecked)); n != 0 {
		dumpProblems(t, rep)
		t.Fatalf("deep mode made %d per-block complaints about an object already reported gone", n)
	}
	// The rest of the graft was still verified.
	if rep.GraftBlocksVerified == 0 {
		t.Fatal("deep mode verified nothing after one object went missing")
	}
}

// TestTheTwoDeepModesAreIndependent. `--grafts=deep` re-reads a third
// party's bytes and `--deep` re-reads this volume's own; a caller may ask
// for either without the other, because re-reading a 10 TB graft over
// somebody else's network is a different decision from re-reading the
// packs this volume wrote.
func TestTheTwoDeepModesAreIndependent(t *testing.T) {
	f := newGraftFix(t)
	rep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftDeep})
	if rep.Damaged() {
		dumpProblems(t, rep)
		t.Fatal("the fixture is not healthy")
	}
	if rep.GraftChunks != rep.Chunks {
		t.Fatalf("%d of %d chunks are external", rep.GraftChunks, rep.Chunks)
	}
	if rep.ChunksVerified != 0 {
		t.Fatalf("--grafts=deep alone fetched %d PACKED chunks; --deep is the flag for that",
			rep.ChunksVerified)
	}
}

// TestFsckExitStatusFollowsFromSeverity is the contract a cron reads. It
// is stated here rather than only in cmd/pelfs because the mapping is
// what the severity assignment is FOR.
func TestFsckExitStatusFollowsFromSeverity(t *testing.T) {
	f := newGraftFix(t)
	exit := func(rep *fsck.Report, strict bool) int {
		switch {
		case rep.Damaged():
			return 1
		case strict && rep.Warnings() > 0:
			return 1
		}
		return 0
	}
	healthy := f.check(t, f.sb, fsck.Options{})
	if got := exit(healthy, false); got != 0 {
		t.Fatalf("a healthy grafted volume exits %d", got)
	}
	if got := exit(healthy, true); got != 0 {
		t.Fatalf("a healthy grafted volume exits %d under --strict", got)
	}

	if err := os.WriteFile(filepath.Join(f.srcDir, "data", "multi.bin"), pseudorandom(999, 4), 0o644); err != nil {
		t.Fatal(err)
	}
	moved := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftHead})
	if moved.Warnings() == 0 || moved.Errors() != 0 {
		dumpProblems(t, moved)
		t.Fatalf("a moved source gave %d errors and %d warnings", moved.Errors(), moved.Warnings())
	}
	if got := exit(moved, false); got != 0 {
		t.Fatalf("a moved source exits %d without --strict; warnings alone must not fail a run", got)
	}
	if got := exit(moved, true); got != 1 {
		t.Fatalf("a moved source exits %d under --strict", got)
	}

	if err := os.Remove(f.indexPath(f.ent)); err != nil {
		t.Fatal(err)
	}
	broken := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftNone})
	if !broken.Damaged() {
		t.Fatal("a lost index is not damage")
	}
	if got := exit(broken, false); got != 1 {
		t.Fatalf("damage exits %d", got)
	}
}

// TestReportCountsAddUp, so the line `pelfs fsck` prints is not making
// claims the check did not earn.
func TestReportCountsAddUp(t *testing.T) {
	f := newGraftFix(t)
	deep := f.check(t, f.sb, fsck.Options{GraftDepth: fsck.GraftDeep})
	if deep.GraftBlocksVerified != deep.GraftChunks {
		t.Fatalf("deep verified %d of %d external chunks", deep.GraftBlocksVerified, deep.GraftChunks)
	}
	if deep.GraftBlocksVerified > deep.GraftBlocks {
		t.Fatalf("verified %d blocks out of an index holding %d",
			deep.GraftBlocksVerified, deep.GraftBlocks)
	}
	// Bytes verified must be the sum of the blocks actually read, which
	// for this fixture is every grafted byte of every grafted file.
	var want int64
	for _, n := range graftFiles {
		if n > 64<<10 { // InlineKeep: the small one is copied, not grafted
			want += int64(n)
		}
	}
	if deep.GraftBytesVerified != want {
		t.Fatalf("deep verified %d bytes, the grafted files hold %d", deep.GraftBytesVerified, want)
	}
	if fmt.Sprint(deep.GraftDepth) != "deep" {
		t.Fatalf("depth prints as %q", deep.GraftDepth)
	}
}
