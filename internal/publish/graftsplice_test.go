package publish_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/graft"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// Grafting into a POPULATED volume, in the ordinary lane.
//
// The mount-backed end to end is scripts/graft-spike-test.sh; everything
// below the mount is ordinary Go and belongs where it runs on every push.
// What these tests are mostly about is the COLLISION MATRIX — what happens
// when something is already at the graft path — because that is the one
// place in this feature where a bug costs somebody data.

// graftBed is a populated volume plus a foreign tree to graft into it.
type graftBed struct {
	t      *testing.T
	inner  pelicanobj.Store
	srcDir string
	src    pelicanobj.Store
	source string
	spool  string

	sb  *superblock.Superblock
	raw []byte
	key []byte
	// smax is the catalog split threshold, held so that every publish in
	// one test uses the same one — publish disarms catalog reuse when it
	// moves, and a test that changed it between generations would be
	// measuring the disarm rather than the splice.
	smax int64
	// files is the foreign tree, by path relative to its prefix.
	files map[string][]byte
	// baseFiles is what the volume held BEFORE any graft, by path.
	baseFiles map[string][]byte
}

// newGraftBed publishes a volume with real content in it — files at the
// root, a nested directory, an empty directory somebody prepared as a
// mount point, and a populated directory that must not be replaced by
// accident — and stands up a second prefix holding a foreign tree.
func newGraftBed(t *testing.T) *graftBed { return newGraftBedWith(t, 0, 0) }

// newGraftBedWith takes the catalog split threshold and a number of extra
// directories, for the tests about NESTED CATALOGS: at a small SMax a
// handful of directories is enough to make the volume a catalog tree
// rather than one catalog, which is the shape a graft has to splice into
// without rewriting all of it.
func newGraftBedWith(t *testing.T, smax int64, wideDirs int) *graftBed {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	newStore := func(prefix string) pelicanobj.Store {
		s, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: srv.URL + "/" + prefix})
		if err != nil {
			t.Fatalf("pelicanobj.New: %v", err)
		}
		return s
	}
	b := &graftBed{
		t: t, inner: newStore("vol"), src: newStore("ext"),
		srcDir: filepath.Join(root, "ext"), source: srv.URL + "/ext",
		spool: t.TempDir(), smax: smax,
		files: map[string][]byte{}, baseFiles: map[string][]byte{},
	}
	// The foreign tree. Every file is over graft.InlineKeep so it is
	// really grafted rather than copied into the catalog.
	for name, n := range map[string]int{
		"one.bin":        90_000,
		"deep/two.bin":   140_000,
		"deep/three.bin": 70_000,
	} {
		p := filepath.Join(b.srcDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		body := pseudorandom(n, int64(len(name)*7+n))
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		b.files[name] = body
	}

	v := testvol.New(t, b.inner, testvol.Options{})
	b.key = v.SigningKey()
	root0 := uint64(testvol.RootInode)
	b.baseFiles["keep.txt"] = []byte("a file the volume already had")
	v.WriteFile(root0, "keep.txt", b.baseFiles["keep.txt"])
	// Big enough to be chunked rather than inlined, so the reuse path is
	// the one under test rather than the inline path.
	b.baseFiles["big.bin"] = pseudorandom(40_000, 99)
	v.WriteFile(root0, "big.bin", b.baseFiles["big.bin"])
	docs := v.Mkdir(root0, "docs")
	b.baseFiles["docs/readme.txt"] = []byte("nested, and must survive a graft elsewhere")
	v.WriteFile(docs, "readme.txt", b.baseFiles["docs/readme.txt"])
	v.Mkdir(root0, "empty")
	busy := v.Mkdir(root0, "busy")
	b.baseFiles["busy/mine.txt"] = []byte("do not lose me")
	v.WriteFile(busy, "mine.txt", b.baseFiles["busy/mine.txt"])
	v.WriteFile(busy, "mine2.txt", []byte("nor me"))
	for d := 0; d < wideDirs; d++ {
		dir := v.Mkdir(root0, fmt.Sprintf("wide%02d", d))
		for f := 0; f < 12; f++ {
			name := fmt.Sprintf("wide%02d/f%02d.txt", d, f)
			b.baseFiles[name] = pseudorandom(700, int64(d*100+f))
			v.WriteFile(dir, fmt.Sprintf("f%02d.txt", f), b.baseFiles[name])
		}
	}
	res := v.Publish(publish.Options{SMax: smax})
	b.sb, b.raw = res.Superblock, res.Raw
	return b
}

// opener is the reader's veto, wired to accept every prefix on the test
// origin. It builds a store PER SOURCE rather than handing back one:
// grafts of two different prefixes are the interesting case, and a single
// store would resolve them both against the same prefix by accident.
func (b *graftBed) opener() func(context.Context, string) (pelicanobj.Store, error) {
	return func(ctx context.Context, source string) (pelicanobj.Store, error) {
		return pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: source})
	}
}

// open reads the volume's current head back.
func (b *graftBed) open() *genfs.FS {
	b.t.Helper()
	fs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: b.inner, SB: b.sb, CacheDir: b.t.TempDir(), GraftOpener: b.opener(),
	})
	if err != nil {
		b.t.Fatalf("genfs.Open: %v", err)
	}
	b.t.Cleanup(func() { fs.Close() }) //nolint:errcheck
	return fs
}

// spiderOpts are the knobs a test varies.
type spliceOpts struct {
	mount   string
	replace bool
	refresh bool
	// remove drops the graft at mount instead of adding one.
	remove bool
	// subtree limits the foreign prefix, so two grafts can come from two
	// different sources on the same origin.
	subtree string
}

// splice runs the real thing: spider the foreign tree, publish its index,
// build the splice source, and publish the generation. The error it
// returns is the one a caller of `pelfs graft` would see.
func (b *graftBed) splice(o spliceOpts) (*publish.Result, error) {
	b.t.Helper()
	ctx := context.Background()
	base := b.open()
	var gsrc *publish.GraftSource
	var entry superblock.GraftEntry
	source := b.source
	if o.subtree != "" {
		source = b.source + "/" + o.subtree
	}
	if !o.remove {
		policy := graft.BlockPolicy{Block: 32 << 10, Max: 64 << 10, PerObject: 2}
		w, err := graft.NewWriter(b.t.TempDir(), policy.Block)
		if err != nil {
			b.t.Fatal(err)
		}
		defer w.Close() //nolint:errcheck
		src := b.src
		if o.subtree != "" {
			s, err := pelicanobj.New(ctx, pelicanobj.Config{PrefixURL: source})
			if err != nil {
				b.t.Fatal(err)
			}
			src = s
		}
		res, err := graft.Spider(ctx, graft.SpiderOptions{Src: src, Index: w, Policy: policy, Concurrency: 4})
		if err != nil {
			b.t.Fatalf("Spider: %v", err)
		}
		entry, err = w.Publish(ctx, b.inner, graft.PublishOptions{
			Mount: o.mount, Source: source, Policy: policy,
			Bytes: res.Bytes, Files: len(res.Files) - res.Inlined,
		})
		if err != nil {
			b.t.Fatalf("publish index: %v", err)
		}
		gsrc, err = publish.NewGraftSource(publish.GraftSourceOptions{Mount: o.mount, Result: res})
		if err != nil {
			b.t.Fatal(err)
		}
	}
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Graft: gsrc, Source: source, Mount: o.mount,
		Replace: o.replace, Refresh: o.refresh, Remove: o.remove,
	})
	if err != nil {
		return nil, err
	}
	grafts := graftListWith(b.sb.Grafts, entry, o.mount, o.remove)
	res, err := publish.Publish(ctx, publish.Options{
		Source: splice, Inner: b.inner, SpoolDir: b.t.TempDir(), Branch: "main",
		SigningKey: b.key, Prev: b.sb, PrevRaw: b.raw, Grafts: grafts, SMax: b.smax,
	})
	if err != nil {
		return nil, err
	}
	b.sb, b.raw = res.Superblock, res.Raw
	return res, nil
}

// graftListWith is what cmd/pelfs/graft.go does: state the whole list, so
// a second graft never deletes the first.
func graftListWith(prev []superblock.GraftEntry, e superblock.GraftEntry, mount string, remove bool) []superblock.GraftEntry {
	out := make([]superblock.GraftEntry, 0, len(prev)+1)
	for _, g := range prev {
		if g.Path == mount {
			continue
		}
		out = append(out, g)
	}
	if !remove {
		out = append(out, e)
	}
	if out == nil {
		// A non-nil empty slice REMOVES the last graft; nil would carry
		// the parent's list forward.
		out = []superblock.GraftEntry{}
	}
	return out
}

// readAll reads a whole file out of a generation.
func readAll(t *testing.T, fs *genfs.FS, p string, size int) []byte {
	t.Helper()
	ino := lookup(t, fs, p)
	buf := make([]byte, size)
	n, err := fs.Read(context.Background(), ino, 0, buf)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return buf[:n]
}

func lookup(t *testing.T, fs *genfs.FS, p string) uint64 {
	t.Helper()
	ino := uint64(genfs.RootInode)
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		n, err := fs.Lookup(context.Background(), ino, part)
		if err != nil {
			t.Fatalf("lookup %s (in %s): %v", part, p, err)
		}
		ino = n.Inode
	}
	return ino
}

func names(t *testing.T, fs *genfs.FS, p string) []string {
	t.Helper()
	ino := uint64(genfs.RootInode)
	if strings.Trim(p, "/") != "" {
		ino = lookup(t, fs, p)
	}
	des, err := fs.ReaddirRetain(context.Background(), ino)
	if err != nil {
		t.Fatalf("readdir %s: %v", p, err)
	}
	out := make([]string, 0, len(des))
	for _, de := range des {
		out = append(out, de.Name)
	}
	return out
}

// TestGraftIntoPopulatedVolume is the whole point: everything that was
// there is still there, the grafted tree reads, and neither knows about
// the other.
func TestGraftIntoPopulatedVolume(t *testing.T) {
	b := newGraftBed(t)
	before := b.sb.Generation
	res, err := b.splice(spliceOpts{mount: "/ext"})
	if err != nil {
		t.Fatalf("graft into a populated volume: %v", err)
	}
	if res.Superblock.Generation != before+1 {
		t.Fatalf("published generation %d, want %d", res.Superblock.Generation, before+1)
	}
	fs := b.open()
	// The pre-existing content, byte for byte.
	for p, want := range b.baseFiles {
		if got := readAll(t, fs, p, len(want)); string(got) != string(want) {
			t.Fatalf("%s did not survive the graft: %q", p, got)
		}
	}
	// The grafted content, byte for byte, out of the foreign prefix.
	for p, want := range b.files {
		if got := readAll(t, fs, "/ext/"+p, len(want)); string(got) != string(want) {
			t.Fatalf("/ext/%s read %d bytes that do not match the source", p, len(got))
		}
	}
	// And the two live side by side at the root.
	got := strings.Join(names(t, fs, "/"), ",")
	if want := "big.bin,busy,docs,empty,ext,keep.txt"; got != want {
		t.Fatalf("the root holds %q, want %q", got, want)
	}
	st := fs.GraftStats()
	if st.Grafts != 1 || st.Resolved == 0 || st.Mismatch != 0 {
		t.Fatalf("graft stats say %+v", st)
	}
}

// TestGraftReusesTheCatalogsItDidNotTouch. Without this a graft into a
// populated volume rewrites and re-uploads the whole namespace, which is
// the difference between usable and not at any real size.
func TestGraftReusesTheCatalogsItDidNotTouch(t *testing.T) {
	b := newGraftBed(t)
	res, err := b.splice(spliceOpts{mount: "/deep/under/here"})
	if err != nil {
		t.Fatalf("graft: %v", err)
	}
	if res.Stats.ReusedFiles == 0 {
		t.Fatal("the splice re-derived every base file's content records; ContentReuser is not engaged")
	}
	if res.Stats.ReusedChunks == 0 {
		t.Fatal("no chunk records were carried forward from the base generation")
	}
	// The synthesized directories are reported, so a mistyped path is
	// visible rather than discovered later.
	fs := b.open()
	for _, p := range []string{"/deep", "/deep/under", "/deep/under/here"} {
		if lookup(t, fs, p) == 0 {
			t.Fatalf("%s was not created", p)
		}
	}
	if got := readAll(t, fs, "keep.txt", len(b.baseFiles["keep.txt"])); string(got) != string(b.baseFiles["keep.txt"]) {
		t.Fatal("a base file did not survive a graft three directories deep")
	}
}

// TestGraftKeepsAnExistingDirectorysIdentity: a spine directory the volume
// already had keeps its inode, so nothing that referenced it breaks.
func TestGraftKeepsAnExistingDirectorysIdentity(t *testing.T) {
	b := newGraftBed(t)
	fs0 := b.open()
	docsIno := lookup(t, fs0, "/docs")
	readmeIno := lookup(t, fs0, "/docs/readme.txt")
	if _, err := b.splice(spliceOpts{mount: "/docs/ext"}); err != nil {
		t.Fatalf("graft under an existing directory: %v", err)
	}
	fs := b.open()
	if got := lookup(t, fs, "/docs"); got != docsIno {
		t.Fatalf("/docs was renumbered %d -> %d by a graft inside it", docsIno, got)
	}
	if got := lookup(t, fs, "/docs/readme.txt"); got != readmeIno {
		t.Fatalf("/docs/readme.txt was renumbered %d -> %d", readmeIno, got)
	}
	if got := strings.Join(names(t, fs, "/docs"), ","); got != "ext,readme.txt" {
		t.Fatalf("/docs holds %q after the graft", got)
	}
	// AND ITS ATTRIBUTES. Publish records an inode's attributes from the
	// LISTING that named it -- only the root is Stat'ed -- so a spine
	// directory re-described by the splice from its inode and type alone
	// would be published with mode 0, making an existing directory
	// inaccessible because something was grafted underneath it. That was a
	// real bug in this file's first draft.
	ctx := context.Background()
	was, err := fs0.GetAttr(ctx, docsIno)
	if err != nil {
		t.Fatal(err)
	}
	now, err := fs.GetAttr(ctx, lookup(t, fs, "/docs"))
	if err != nil {
		t.Fatal(err)
	}
	if now.Mode != was.Mode || now.UID != was.UID || now.GID != was.GID || now.MtimeNS != was.MtimeNS {
		t.Fatalf("/docs was republished as mode %o uid %d gid %d mtime %d, was mode %o uid %d gid %d mtime %d",
			now.Mode, now.UID, now.GID, now.MtimeNS, was.Mode, was.UID, was.GID, was.MtimeNS)
	}
	// Nlink is recomputed from the namespace by publish, so it MUST have
	// moved: /docs gained a subdirectory.
	if now.Nlink != was.Nlink+1 {
		t.Fatalf("/docs has nlink %d after gaining a subdirectory, was %d", now.Nlink, was.Nlink)
	}
}

// ---- the collision matrix ----

// TestGraftRefusesToReplaceAPopulatedDirectory. Silently replacing one is
// the worst outcome available in this feature, so the refusal is the test
// that matters most in this file.
func TestGraftRefusesToReplaceAPopulatedDirectory(t *testing.T) {
	b := newGraftBed(t)
	gen := b.sb.Generation
	_, err := b.splice(spliceOpts{mount: "/busy"})
	if !errors.Is(err, publish.ErrGraftPathNotEmpty) {
		t.Fatalf("grafting over a populated directory gave %v", err)
	}
	for _, want := range []string{"2 entries", "mine.txt", "--replace"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q: %v", want, err)
		}
	}
	if b.sb.Generation != gen {
		t.Fatal("a refused graft published a generation anyway")
	}
	// And the contents are still there.
	fs := b.open()
	if got := strings.Join(names(t, fs, "/busy"), ","); got != "mine.txt,mine2.txt" {
		t.Fatalf("/busy holds %q", got)
	}
}

// TestGraftReplacesAPopulatedDirectoryWhenAsked. The escape hatch has to
// work, or the refusal above is a dead end.
func TestGraftReplacesAPopulatedDirectoryWhenAsked(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/busy", replace: true}); err != nil {
		t.Fatalf("--replace: %v", err)
	}
	fs := b.open()
	if got := strings.Join(names(t, fs, "/busy"), ","); got != "deep,one.bin" {
		t.Fatalf("/busy holds %q after --replace, want the grafted tree", got)
	}
	if got := readAll(t, fs, "/busy/one.bin", len(b.files["one.bin"])); string(got) != string(b.files["one.bin"]) {
		t.Fatal("the grafted file does not read after replacing a directory")
	}
	// Everything else is untouched.
	if got := readAll(t, fs, "keep.txt", len(b.baseFiles["keep.txt"])); string(got) != string(b.baseFiles["keep.txt"]) {
		t.Fatal("--replace of one directory disturbed the rest of the volume")
	}
}

// TestGraftIntoAnEmptyDirectoryIsAllowed: nothing is lost, so nothing is
// asked. This is the shape a user who prepared a mount point leaves.
func TestGraftIntoAnEmptyDirectoryIsAllowed(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/empty"}); err != nil {
		t.Fatalf("grafting into an empty directory was refused: %v", err)
	}
	fs := b.open()
	if got := readAll(t, fs, "/empty/one.bin", len(b.files["one.bin"])); string(got) != string(b.files["one.bin"]) {
		t.Fatal("the grafted tree does not read from an adopted empty directory")
	}
}

// TestGraftRefusesAFileAtThePath, and says what to do about it.
func TestGraftRefusesAFileAtThePath(t *testing.T) {
	b := newGraftBed(t)
	_, err := b.splice(spliceOpts{mount: "/keep.txt"})
	if !errors.Is(err, publish.ErrGraftPathOccupied) {
		t.Fatalf("grafting onto a file gave %v", err)
	}
	for _, want := range []string{"is a file", "--replace"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q: %v", want, err)
		}
	}
	// With --replace it goes through, and the file is gone.
	if _, err := b.splice(spliceOpts{mount: "/keep.txt", replace: true}); err != nil {
		t.Fatalf("--replace over a file: %v", err)
	}
	fs := b.open()
	n, err := fs.GetAttr(context.Background(), lookup(t, fs, "/keep.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if n.Type != catalog.TypeDir {
		t.Fatalf("/keep.txt is still type %d after --replace", n.Type)
	}
}

// TestGraftRefusesAPathThroughAFile: /keep.txt/under cannot exist, and the
// message says which component is the problem.
func TestGraftRefusesAPathThroughAFile(t *testing.T) {
	b := newGraftBed(t)
	_, err := b.splice(spliceOpts{mount: "/keep.txt/under"})
	if !errors.Is(err, publish.ErrGraftPathNotDir) {
		t.Fatalf("a path through a file gave %v", err)
	}
	if !strings.Contains(err.Error(), "/keep.txt is a file") {
		t.Fatalf("the refusal does not name the component: %v", err)
	}
	// --replace does NOT force this: replacing a file with a directory
	// tree the user did not describe is a different operation.
	if _, err := b.splice(spliceOpts{mount: "/keep.txt/under", replace: true}); !errors.Is(err, publish.ErrGraftPathNotDir) {
		t.Fatalf("--replace forced a path through a file: %v", err)
	}
}

// TestRegraftingTheSameSourceIsARefresh: idempotence. Running the same
// command twice must not quietly do something else.
func TestRegraftingTheSameSourceIsARefresh(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/ext"}); err != nil {
		t.Fatalf("first graft: %v", err)
	}
	gen := b.sb.Generation
	_, err := b.splice(spliceOpts{mount: "/ext"})
	if !errors.Is(err, publish.ErrGraftSameSource) {
		t.Fatalf("re-grafting the same source gave %v", err)
	}
	if !strings.Contains(err.Error(), "--refresh") {
		t.Fatalf("the refusal does not name --refresh: %v", err)
	}
	if b.sb.Generation != gen {
		t.Fatal("a refused re-graft published anyway")
	}
	// And --refresh goes through, keeping the tree readable.
	if _, err := b.splice(spliceOpts{mount: "/ext", refresh: true}); err != nil {
		t.Fatalf("--refresh: %v", err)
	}
	fs := b.open()
	for p, want := range b.files {
		if got := readAll(t, fs, "/ext/"+p, len(want)); string(got) != string(want) {
			t.Fatalf("/ext/%s does not read after a refresh", p)
		}
	}
	if got := readAll(t, fs, "keep.txt", len(b.baseFiles["keep.txt"])); string(got) != string(b.baseFiles["keep.txt"]) {
		t.Fatal("a refresh disturbed the base tree")
	}
}

// TestRefreshOfNothingIsRefused: --refresh on a path with no graft.
func TestRefreshOfNothingIsRefused(t *testing.T) {
	b := newGraftBed(t)
	_, err := b.splice(spliceOpts{mount: "/ext", refresh: true})
	if !errors.Is(err, publish.ErrGraftNotThere) {
		t.Fatalf("--refresh of a path with no graft gave %v", err)
	}
}

// TestAGraftFromAnotherSourceReplaces, and the caller can say so: the
// prior entry is reported rather than swallowed.
func TestAGraftFromAnotherSourceReplaces(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/ext"}); err != nil {
		t.Fatalf("first graft: %v", err)
	}
	ctx := context.Background()
	base := b.open()
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Graft: mustGraftSource(t, "/ext"),
		Source: b.source + "/deep", Mount: "/ext",
	})
	if err != nil {
		t.Fatalf("a graft from another source at the same path was refused: %v", err)
	}
	if splice.Placement() != publish.GraftPlaceReplacedGraft {
		t.Fatalf("placement is %v, want a replaced graft", splice.Placement())
	}
	prior := splice.Prior()
	if prior == nil || prior.Source != b.source {
		t.Fatalf("the prior graft was not reported: %+v", prior)
	}
}

// mustGraftSource builds an EMPTY-ish graft source for the tests that only
// care about placement, not about bytes.
func mustGraftSource(t *testing.T, mount string) *publish.GraftSource {
	t.Helper()
	res := &graft.Result{Files: []graft.File{{Path: "/x.bin", Size: 1, Block: 1 << 20, IDs: nil, Body: []byte("x")}}}
	g, err := publish.NewGraftSource(publish.GraftSourceOptions{Mount: mount, Result: res})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// ---- nesting ----

// TestAGraftInsideAGraftIsRefused, by name, because the outer graft's next
// refresh would silently drop it.
func TestAGraftInsideAGraftIsRefused(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/ext"}); err != nil {
		t.Fatalf("first graft: %v", err)
	}
	_, err := b.splice(spliceOpts{mount: "/ext/inner", subtree: "deep"})
	if !errors.Is(err, publish.ErrGraftNested) {
		t.Fatalf("a graft inside a graft gave %v", err)
	}
	for _, want := range []string{"/ext/inner is inside the graft at /ext", "--refresh", "--remove"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// TestAGraftThatWouldSwallowAGraftIsRefused: the other direction.
func TestAGraftThatWouldSwallowAGraftIsRefused(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/a/b/ext"}); err != nil {
		t.Fatalf("first graft: %v", err)
	}
	_, err := b.splice(spliceOpts{mount: "/a", subtree: "deep"})
	if !errors.Is(err, publish.ErrGraftSwallows) {
		t.Fatalf("a graft containing a graft gave %v", err)
	}
	if !strings.Contains(err.Error(), "--remove") {
		t.Fatalf("the refusal does not offer a way forward: %v", err)
	}
}

// TestTwoGraftsSideBySide is the case that must NOT be refused, and the
// one that proves the nesting checks are about nesting rather than about
// there being a graft at all.
func TestTwoGraftsSideBySide(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/one"}); err != nil {
		t.Fatalf("first graft: %v", err)
	}
	if _, err := b.splice(spliceOpts{mount: "/two", subtree: "deep"}); err != nil {
		t.Fatalf("second graft beside the first: %v", err)
	}
	if len(b.sb.Grafts) != 2 {
		t.Fatalf("the volume names %d grafts, want 2", len(b.sb.Grafts))
	}
	fs := b.open()
	if got := readAll(t, fs, "/one/one.bin", len(b.files["one.bin"])); string(got) != string(b.files["one.bin"]) {
		t.Fatal("the first graft stopped reading when the second was added")
	}
	if got := readAll(t, fs, "/two/two.bin", len(b.files["deep/two.bin"])); string(got) != string(b.files["deep/two.bin"]) {
		t.Fatal("the second graft does not read")
	}
	if got := readAll(t, fs, "keep.txt", len(b.baseFiles["keep.txt"])); string(got) != string(b.baseFiles["keep.txt"]) {
		t.Fatal("two grafts disturbed the base tree")
	}
}

// TestGraftAtTheVolumeRootIsRefused. A graft at "/" is not a splice.
func TestGraftAtTheVolumeRootIsRefused(t *testing.T) {
	b := newGraftBed(t)
	base := b.open()
	_, err := publish.GraftPreflight(context.Background(), publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Mount: "/", Source: b.source,
	})
	if !errors.Is(err, publish.ErrGraftRootPath) {
		t.Fatalf("a graft at the volume root gave %v", err)
	}
}

// ---- removal ----

// TestRemoveAGraft: the tree it served goes away, the volume does not, and
// the superblock stops naming the source.
func TestRemoveAGraft(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/ext"}); err != nil {
		t.Fatalf("graft: %v", err)
	}
	if _, err := b.splice(spliceOpts{mount: "/ext", remove: true}); err != nil {
		t.Fatalf("--remove: %v", err)
	}
	if len(b.sb.Grafts) != 0 {
		t.Fatalf("the superblock still names %d grafts", len(b.sb.Grafts))
	}
	fs := b.open()
	if got := strings.Join(names(t, fs, "/"), ","); got != "big.bin,busy,docs,empty,keep.txt" {
		t.Fatalf("the root holds %q after --remove", got)
	}
	for p, want := range b.baseFiles {
		if got := readAll(t, fs, p, len(want)); string(got) != string(want) {
			t.Fatalf("%s did not survive --remove", p)
		}
	}
}

// TestRemoveOfNothingIsRefused.
func TestRemoveOfNothingIsRefused(t *testing.T) {
	b := newGraftBed(t)
	_, err := b.splice(spliceOpts{mount: "/docs", remove: true})
	if !errors.Is(err, publish.ErrGraftNotThere) {
		t.Fatalf("--remove of a path with no graft gave %v", err)
	}
	if !strings.Contains(err.Error(), "--list") {
		t.Fatalf("the refusal does not say how to see what IS grafted: %v", err)
	}
}

// TestRemoveThenGraftAgain: the path is ordinary again afterwards, which
// is what makes --remove the answer the nesting refusals offer.
func TestRemoveThenGraftAgain(t *testing.T) {
	b := newGraftBed(t)
	if _, err := b.splice(spliceOpts{mount: "/ext"}); err != nil {
		t.Fatalf("graft: %v", err)
	}
	if _, err := b.splice(spliceOpts{mount: "/ext", remove: true}); err != nil {
		t.Fatalf("--remove: %v", err)
	}
	if _, err := b.splice(spliceOpts{mount: "/ext", subtree: "deep"}); err != nil {
		t.Fatalf("re-grafting a removed path: %v", err)
	}
	fs := b.open()
	if got := readAll(t, fs, "/ext/two.bin", len(b.files["deep/two.bin"])); string(got) != string(b.files["deep/two.bin"]) {
		t.Fatal("the re-grafted tree does not read")
	}
}

// ---- interruption safety ----

// TestAFailedGraftLeavesThePreviousGeneration. A killed `pelfs graft` must
// leave the volume on the generation it was on, not half spliced.
func TestAFailedGraftLeavesThePreviousGeneration(t *testing.T) {
	b := newGraftBed(t)
	was, wasGen := b.sb.RootCatalog, b.sb.Generation
	ctx := context.Background()
	base := b.open()
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Graft: mustGraftSource(t, "/ext"), Source: b.source, Mount: "/ext",
	})
	if err != nil {
		t.Fatal(err)
	}
	// A store that dies partway through the uploads, which is what a
	// SIGKILL, a full disk or an expired token looks like from in here.
	dying := &failAfterPuts{Store: b.inner, allow: 1}
	if _, err := publish.Publish(ctx, publish.Options{
		Source: splice, Inner: dying, SpoolDir: t.TempDir(), Branch: "main",
		SigningKey: b.key, Prev: b.sb, PrevRaw: b.raw,
		Grafts: []superblock.GraftEntry{{Path: "/ext", Source: b.source}},
	}); err == nil {
		t.Fatal("a publish against a dying store succeeded")
	}
	// The branch still holds the generation it held.
	head, err := headOf(ctx, b.inner)
	if err != nil {
		t.Fatal(err)
	}
	if head.Generation != wasGen || head.RootCatalog != was {
		t.Fatalf("the branch moved to generation %d after a failed graft (was %d)",
			head.Generation, wasGen)
	}
	// And it still reads, through a cold cache, with nothing of the
	// half-published generation in it.
	fs, err := genfs.Open(ctx, genfs.Options{
		Inner: b.inner, SB: head, CacheDir: t.TempDir(), GraftOpener: b.opener(),
	})
	if err != nil {
		t.Fatalf("the volume is unreadable after a failed graft: %v", err)
	}
	defer fs.Close() //nolint:errcheck
	for p, want := range b.baseFiles {
		if got := readAll(t, fs, p, len(want)); string(got) != string(want) {
			t.Fatalf("%s is wrong after a failed graft", p)
		}
	}
	if _, err := fs.Lookup(ctx, genfs.RootInode, "ext"); err == nil {
		t.Fatal("the failed graft left /ext in the namespace")
	}
}

// TestAGraftAgainstAMovedBranchIsRefused: the CAS guard, which is what
// makes two writers safe without either of them losing work silently.
func TestAGraftAgainstAMovedBranchIsRefused(t *testing.T) {
	b := newGraftBed(t)
	ctx := context.Background()
	stalePrev, staleRaw := b.sb, b.raw
	base := b.open()
	splice, err := publish.NewGraftSpliceSource(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: stalePrev, Graft: mustGraftSource(t, "/ext"), Source: b.source, Mount: "/ext",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Somebody else advances the branch while the spider is running.
	if _, err := b.splice(spliceOpts{mount: "/other"}); err != nil {
		t.Fatalf("the concurrent writer's graft: %v", err)
	}
	_, err = publish.Publish(ctx, publish.Options{
		Source: splice, Inner: b.inner, SpoolDir: t.TempDir(), Branch: "main",
		SigningKey: b.key, Prev: stalePrev, PrevRaw: staleRaw,
		Grafts: []superblock.GraftEntry{{Path: "/ext", Source: b.source}},
	})
	if err == nil {
		t.Fatal("a graft against a branch that moved was published anyway")
	}
	if !strings.Contains(err.Error(), "changed since") {
		t.Fatalf("the refusal does not say the branch moved: %v", err)
	}
	// The concurrent writer's generation is intact.
	fs := b.open()
	if got := readAll(t, fs, "/other/one.bin", len(b.files["one.bin"])); string(got) != string(b.files["one.bin"]) {
		t.Fatal("the loser's publish damaged the winner's generation")
	}
}

// failAfterPuts is a store that stops accepting writes after n of them:
// the shape a SIGKILL, a full disk or an expired token has from in here.
type failAfterPuts struct {
	pelicanobj.Store
	allow int
	seen  int
}

func (s *failAfterPuts) Put(ctx context.Context, key string, in io.Reader) error {
	s.seen++
	if s.seen > s.allow {
		return errors.New("the storage went away")
	}
	return s.Store.Put(ctx, key, in)
}

func headOf(ctx context.Context, inner pelicanobj.Store) (*superblock.Superblock, error) {
	raw, err := pelicanobj.ReadMutable(ctx, inner, "refs/main")
	if err != nil {
		return nil, err
	}
	return superblock.Decode(raw)
}

// TestGraftAcrossANestedCatalogBoundary. The interesting claim is not that
// it works but what it COSTS: a graft into a volume whose namespace is
// already a tree of catalogs must rewrite the catalogs from the graft to
// the root and NOT LOOK at the rest — the git property CatalogReuser
// exists for. A volume big enough to have nested catalogs is the only
// place that can be observed.
func TestGraftAcrossANestedCatalogBoundary(t *testing.T) {
	b := newGraftBedWith(t, 4096, 8)
	if len(b.sb.Catalogs) < 3 {
		t.Fatalf("the fixture has %d catalogs; it cannot test a nested boundary", len(b.sb.Catalogs))
	}
	res, err := b.splice(spliceOpts{mount: "/wide03/ext"})
	if err != nil {
		t.Fatalf("graft inside a nested catalog: %v", err)
	}
	if res.Stats.CatalogsReused == 0 {
		t.Fatal("the graft rebuilt every catalog in the volume; nothing was carried forward")
	}
	if res.Stats.SubtreesPruned == 0 {
		t.Fatal("the graft WALKED every subtree; the dirty scope is not pruning anything")
	}
	if res.Stats.CatalogsReused <= res.Stats.Catalogs {
		t.Logf("carried %d catalogs, wrote %d", res.Stats.CatalogsReused, res.Stats.Catalogs)
	}
	fs := b.open()
	// Every base file, including the ones inside the catalogs that were
	// never read.
	for p, want := range b.baseFiles {
		if got := readAll(t, fs, p, len(want)); string(got) != string(want) {
			t.Fatalf("%s is wrong after a graft into a nested catalog", p)
		}
	}
	for p, want := range b.files {
		if got := readAll(t, fs, "/wide03/ext/"+p, len(want)); string(got) != string(want) {
			t.Fatalf("/wide03/ext/%s does not read", p)
		}
	}
	if got := strings.Join(names(t, fs, "/wide03"), ","); !strings.Contains(got, "ext") {
		t.Fatalf("/wide03 holds %q", got)
	}
}

// TestPreflightRefusesBeforeAnythingIsRead. The preflight is the reason a
// mistyped path costs a second instead of an hours-long walk of somebody
// else's storage, so it has to make every refusal the publish would make.
func TestPreflightRefusesBeforeAnythingIsRead(t *testing.T) {
	b := newGraftBed(t)
	base := b.open()
	ctx := context.Background()
	for _, tc := range []struct {
		mount string
		want  error
	}{
		{"/busy", publish.ErrGraftPathNotEmpty},
		{"/keep.txt", publish.ErrGraftPathOccupied},
		{"/keep.txt/inside", publish.ErrGraftPathNotDir},
		{"/", publish.ErrGraftRootPath},
	} {
		_, err := publish.GraftPreflight(ctx, publish.GraftSpliceOptions{
			Base: base, Prev: b.sb, Source: b.source, Mount: tc.mount,
		})
		if !errors.Is(err, tc.want) {
			t.Fatalf("preflight of %s gave %v, want %v", tc.mount, err, tc.want)
		}
	}
	// And it reports the placements it does NOT refuse, with the
	// directories it would have to create.
	plan, err := publish.GraftPreflight(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Source: b.source, Mount: "/a/b/ext",
	})
	if err != nil {
		t.Fatalf("preflight of a fresh path: %v", err)
	}
	if plan.Placement != publish.GraftPlaceNew {
		t.Fatalf("placement is %v, want new", plan.Placement)
	}
	if got := strings.Join(plan.SyntheticDirs, ","); got != "/a,/a/b" {
		t.Fatalf("the plan would create %q, want /a,/a/b", got)
	}
	plan, err = publish.GraftPreflight(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Source: b.source, Mount: "/empty",
	})
	if err != nil || plan.Placement != publish.GraftPlaceEmptyDir {
		t.Fatalf("preflight of an empty directory: %v, %v", plan, err)
	}
	plan, err = publish.GraftPreflight(ctx, publish.GraftSpliceOptions{
		Base: base, Prev: b.sb, Source: b.source, Mount: "/busy", Replace: true,
	})
	if err != nil || plan.Placement != publish.GraftPlaceReplacedDir || plan.DisplacedEntries != 2 {
		t.Fatalf("preflight of --replace over a populated directory: %+v, %v", plan, err)
	}
}
