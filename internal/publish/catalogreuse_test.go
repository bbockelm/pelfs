package publish_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/retention"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// splitTreeSMax is small enough that the fixture below splits into a tree
// of catalogs rather than one flat catalog — which is the only shape in
// which "rewrite one catalog, not all of them" means anything.
const splitTreeSMax = 3000

// splitTree writes three top-level directories of subdirectories of small
// files. With splitTreeSMax it publishes as several nested catalogs.
func (v *reuseVol) splitTree() map[string][]byte {
	v.t.Helper()
	ctx := context.Background()
	body := make(map[string][]byte)
	for _, top := range []string{"a", "b", "c"} {
		td, err := v.ov.Mkdir(ctx, publishRootInode, top, 0755, 0, 0)
		if err != nil {
			v.t.Fatalf("mkdir %s: %v", top, err)
		}
		for s := 0; s < 3; s++ {
			sub, err := v.ov.Mkdir(ctx, td.Inode, fmt.Sprintf("s%d", s), 0755, 0, 0)
			if err != nil {
				v.t.Fatalf("mkdir: %v", err)
			}
			for f := 0; f < 6; f++ {
				p := fmt.Sprintf("%s/s%d/f%d", top, s, f)
				body[p] = []byte(fmt.Sprintf("contents of %s, inline and unremarkable", p))
				v.create(sub.Inode, fmt.Sprintf("f%d", f), body[p])
			}
		}
	}
	return body
}

// catalogPaths indexes a generation's recorded catalog tree by path.
func catalogPaths(sb *superblock.Superblock) map[string]superblock.CatalogEntry {
	out := make(map[string]superblock.CatalogEntry, len(sb.Catalogs))
	for _, ce := range sb.Catalogs {
		out[ce.Path] = ce
	}
	return out
}

func sortedPaths(m map[string]superblock.CatalogEntry) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// One new file must rewrite the catalogs on the path from its directory to
// the root, and nothing else — the property the format's tree objects are
// supposed to have and did not: every catalog in the volume was rebuilt and
// re-uploaded for one row.
func TestSealRewritesOnlyTheChangedPath(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x01})
	v.smax = splitTreeSMax
	body := v.splitTree()
	first := v.checkpoint()
	if first.Stats.Catalogs < 4 {
		t.Fatalf("fixture published %d catalogs; it must split for this test to mean anything",
			first.Stats.Catalogs)
	}
	before := catalogPaths(first.Superblock)

	// One file, deep in one subtree.
	sub := lookupPath(t, v.ov, "a/s0")
	body["a/s0/new.txt"] = []byte("one new file in a whole volume")
	v.create(sub.Inode, "new.txt", body["a/s0/new.txt"])

	second := v.checkpoint()
	after := catalogPaths(second.Superblock)

	if second.Stats.CatalogsReused == 0 {
		t.Fatalf("nothing was carried forward")
	}
	if len(before) != len(after) {
		t.Errorf("catalog tree changed shape: %v -> %v", sortedPaths(before), sortedPaths(after))
	}
	// Everything off the path from /a/s0 to the root keeps its identity.
	changed := map[string]bool{"/": true, "/a": true, "/a/s0": true}
	for p, was := range before {
		now, ok := after[p]
		if !ok {
			continue // shape mismatch already reported
		}
		switch {
		case changed[p] && now.Identity == was.Identity && v.spans(before, p):
			t.Errorf("catalog %s covers the change but kept its identity", p)
		case !changed[p] && now.Identity != was.Identity:
			t.Errorf("catalog %s is off the changed path but was rewritten", p)
		}
	}
	if second.Stats.Catalogs > len(changed) {
		t.Errorf("wrote %d catalogs for one new file; at most %d lie on the path to the root",
			second.Stats.Catalogs, len(changed))
	}
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}

// spans reports whether a path names a catalog in the recorded tree.
func (v *reuseVol) spans(cats map[string]superblock.CatalogEntry, p string) bool {
	_, ok := cats[p]
	return ok
}

// A carried catalog's bytes live in a pack an OLDER generation wrote, and
// retention deletes any pack no live superblock names. The new generation
// must therefore still list that pack — the same obligation carried-forward
// chunkrefs have, and the same test: sweep with a clock far past the grace
// window, so age protects nothing and only the pack LIST can save a pack,
// then read the whole generation back through a cold cache.
func TestCarriedCatalogsStayRetained(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x02})
	v.smax = splitTreeSMax
	body := v.splitTree()
	first := v.checkpoint()

	sub := lookupPath(t, v.ov, "c/s2")
	body["c/s2/late.txt"] = []byte("a late arrival")
	v.create(sub.Inode, "late.txt", body["c/s2/late.txt"])
	second := v.checkpoint()
	if second.Stats.CatalogsReused == 0 {
		t.Fatalf("nothing was carried forward; the test would prove nothing")
	}

	// The carried catalogs really do live in the first generation's packs:
	// nothing this seal uploaded contains them.
	newPacks := make(map[string]bool, len(second.NewPacks))
	for _, sp := range second.NewPacks {
		newPacks[sp.Name] = true
	}
	env := newReadEnv(t, v.inner, nil, nil)
	carried := 0
	for _, ce := range second.Superblock.Catalogs {
		loc, ok := env.index[hex.EncodeToString(ce.Identity[:])]
		if !ok {
			t.Fatalf("catalog %s is in no pack at all", ce.Path)
		}
		if !newPacks[loc.pack] {
			carried++
		}
	}
	if carried == 0 {
		t.Fatalf("every catalog came from this seal's own packs; nothing was carried")
	}

	listed := make(map[string]bool, len(packsOf(t, v.inner, second.Superblock)))
	for _, pe := range packsOf(t, v.inner, second.Superblock) {
		listed[pe.Name] = true
	}
	for _, pe := range packsOf(t, v.inner, first.Superblock) {
		if !listed[pe.Name] {
			t.Errorf("pack %s holds carried-forward catalogs but is not listed by the new generation", pe.Name)
		}
	}

	rstore, err := refs.New(v.inner, filepath.Join(v.state, "refs-gc"), v.pub)
	if err != nil {
		t.Fatalf("refs.New: %v", err)
	}
	rep, err := retention.GC(ctx, retention.Options{
		Inner: v.inner, Refs: rstore, Delete: true,
		Now: time.Now().Add(365 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("retention.GC: %v", err)
	}
	if rep.Deleted != 0 {
		t.Errorf("GC deleted %d pack(s) the head still references: %v", rep.Deleted, rep.CandidateNames)
	}

	// The generation must read back whole from a cache that holds nothing,
	// which is where a carried reference into a deleted pack would surface.
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}

// A carried catalog states the path it covers, so a subtree that MOVED
// wholesale may not be carried even though its contents are untouched:
// the recorded path would be a lie to anything reassembling the tree from
// packs alone.
func TestSealRebuildsMovedSubtreeCatalogs(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x03})
	v.smax = splitTreeSMax
	body := v.splitTree()
	v.checkpoint()

	for p, b := range body {
		if strings.HasPrefix(p, "b/") {
			body["moved"+strings.TrimPrefix(p, "b")] = b
			delete(body, p)
		}
	}
	if err := v.ov.Rename(ctx, publishRootInode, "b", publishRootInode, "moved"); err != nil {
		t.Fatalf("rename b -> moved: %v", err)
	}
	second := v.checkpoint()

	for _, ce := range second.Superblock.Catalogs {
		if strings.HasPrefix(ce.Path, "/b") {
			t.Errorf("catalog %s survives a rename of /b", ce.Path)
		}
	}
	for _, ce := range second.Superblock.Catalogs {
		if !strings.HasPrefix(ce.Path, "/moved") {
			continue
		}
		cat := env(t, v).openCatalog(ce.Identity[:])
		if got := cat.Meta().CoveredPath; got != ce.Path {
			t.Errorf("catalog at %s says it covers %q", ce.Path, got)
		}
		cat.Close() //nolint:errcheck
	}
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}

func env(t *testing.T, v *reuseVol) *readEnv { return newReadEnv(t, v.inner, nil, nil) }

// Every kind of mutation, applied at once to a tree of catalogs, must
// produce a generation that reads back exactly like the overlay it was
// sealed from — through a cache holding nothing. Reuse decides what NOT to
// rebuild; a wrong decision is a change silently missing from a signed
// generation, and this is the assertion that catches it.
func TestSealWithReuseMatchesTheOverlayView(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x04})
	v.smax = splitTreeSMax
	v.splitTree()
	v.checkpoint()

	must := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	// A new file, a rewrite, an attribute change, an xattr, a symlink, a
	// deletion, a new directory, and a hardlink — each in a different
	// subtree, so each exercises a different catalog.
	a0 := lookupPath(t, v.ov, "a/s0")
	v.create(a0.Inode, "created.txt", []byte("brand new"))

	b0 := lookupPath(t, v.ov, "b/s0/f0")
	v.rewrite(b0.Inode, []byte("rewritten body, longer than what it replaced"))

	mode := uint32(0600)
	_, err := v.ov.SetAttr(ctx, lookupPath(t, v.ov, "b/s1/f1").Inode, overlay.SetAttrIn{Mode: &mode})
	must(err, "chmod b/s1/f1")

	must(v.ov.SetXattr(ctx, lookupPath(t, v.ov, "c/s0/f0").Inode, "user.tag", []byte("x")), "setxattr")

	c1 := lookupPath(t, v.ov, "c/s1")
	_, err = v.ov.Symlink(ctx, c1.Inode, "link", "../s0/f0", 0, 0)
	must(err, "symlink")

	must(v.ov.Unlink(ctx, lookupPath(t, v.ov, "c/s2").Inode, "f5"), "unlink c/s2/f5")

	nd, err := v.ov.Mkdir(ctx, publishRootInode, "fresh", 0755, 0, 0)
	must(err, "mkdir /fresh")
	v.create(nd.Inode, "inside.txt", []byte("in a brand new directory"))

	_, err = v.ov.Link(ctx, lookupPath(t, v.ov, "a/s2/f0").Inode, nd.Inode, "hard")
	must(err, "link")

	want := snapshot(t, v.ov)
	res := v.checkpoint()
	if res.Stats.CatalogsReused == 0 {
		t.Fatalf("nothing was carried forward; the test would prove nothing")
	}
	compareViews(t, want, snapshot(t, openGenfs(t, v.inner, res.Superblock, nil)))
}

// Reuse is allowed only from the generation this publish builds on, for
// the same reason content reuse is: the carried bytes are locatable only
// through that generation's pack list, which is the one carried forward.
func TestCatalogReuseDeclinesFromAnotherGeneration(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x05})
	v.smax = splitTreeSMax
	body := v.splitTree()

	first := v.sealOnly(v.head)
	second := v.sealOnly(first)
	if second.Stats.CatalogsReused != 0 {
		t.Errorf("carried %d catalogs from generation %d, which the source does not serve",
			second.Stats.CatalogsReused, first.Superblock.Generation)
	}
	v.verifyBodies(second, body)
}

// A split threshold that moved invalidates every recorded boundary, so
// nothing may be carried: the catalogs on hand were cut in places this
// publish would not cut.
func TestCatalogReuseDeclinesOnChangedSplitThreshold(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x06})
	v.smax = splitTreeSMax
	body := v.splitTree()
	v.checkpoint()

	v.smax = splitTreeSMax * 4
	second := v.checkpoint()
	if second.Stats.CatalogsReused != 0 {
		t.Errorf("carried %d catalogs across an SMax change", second.Stats.CatalogsReused)
	}
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}

// The recorded catalog tree must describe every live catalog, including
// the ones under a carried root that this seal never looked at. A gap
// there is silent: the next generation simply rebuilds more than it needed
// to, forever.
func TestCatalogListCoversTheWholeTree(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x07})
	v.smax = splitTreeSMax
	v.splitTree()
	first := v.checkpoint()

	sub := lookupPath(t, v.ov, "a/s0")
	v.create(sub.Inode, "new.txt", []byte("one file"))
	second := v.checkpoint()

	before, after := catalogPaths(first.Superblock), catalogPaths(second.Superblock)
	if len(before) == 0 {
		t.Fatal("the first generation recorded no catalogs")
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("catalog %s vanished from the recorded tree", p)
		}
	}
	// And every recorded catalog is really there, carried ones included.
	e := newReadEnv(t, v.inner, nil, nil)
	for _, ce := range second.Superblock.Catalogs {
		cat := e.openCatalog(ce.Identity[:])
		if got := cat.Meta().CoveredPath; got != ce.Path {
			t.Errorf("catalog recorded at %s covers %q", ce.Path, got)
		}
		cat.Close() //nolint:errcheck
	}
}

// Carrying a catalog forward is only half the saving; the other half is
// never reading the subtree it covers. A seal that still walks 85k inodes
// to conclude it has nothing to do is still a seal that takes seconds.
func TestSealPrunesUnchangedSubtrees(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x08})
	v.smax = splitTreeSMax
	body := v.splitTree()
	first := v.checkpoint()
	allDirs := first.Stats.Dirs
	if allDirs < 10 {
		t.Fatalf("fixture has %d directories; too few to prove anything", allDirs)
	}

	sub := lookupPath(t, v.ov, "a/s0")
	body["a/s0/new.txt"] = []byte("one new file")
	v.create(sub.Inode, "new.txt", body["a/s0/new.txt"])
	second := v.checkpoint()

	if second.Stats.SubtreesPruned == 0 {
		t.Errorf("the walk descended the whole tree for one new file")
	}
	if second.Stats.Dirs >= allDirs {
		t.Errorf("walked %d directories of %d for one new file", second.Stats.Dirs, allDirs)
	}
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}

// A promoted (nlink > 1) inode's content records live in an inode shard,
// and shards are rebuilt whole from the walk. A subtree holding one may
// therefore never be skipped — the rebuilt shard would simply not contain
// it, and the file would read as empty from a generation that still names
// it. The recorded promoted count per catalog is what prevents that, and
// this is the test that it does.
func TestSealNeverPrunesPromotedInodes(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xca, 0x7a, 0x10, 0x09})
	v.smax = splitTreeSMax
	body := v.splitTree()

	// A hardlinked file, both names inside subtrees that are otherwise
	// untouched from here on.
	target := lookupPath(t, v.ov, "b/s0/f0")
	if _, err := v.ov.Link(ctx, target.Inode, lookupPath(t, v.ov, "b/s1").Inode, "hard"); err != nil {
		t.Fatalf("link: %v", err)
	}
	body["b/s1/hard"] = body["b/s0/f0"]
	first := v.checkpoint()
	if first.Stats.PromotedInodes == 0 {
		t.Fatal("the fixture promoted nothing; the test would prove nothing")
	}
	if first.Stats.Shards == 0 {
		t.Fatal("the fixture wrote no shard")
	}

	// Change something far away, so everything the hardlink lives in looks
	// skippable to a seal that is not counting promoted inodes.
	sub := lookupPath(t, v.ov, "a/s0")
	body["a/s0/elsewhere.txt"] = []byte("nowhere near the hardlink")
	v.create(sub.Inode, "elsewhere.txt", body["a/s0/elsewhere.txt"])
	second := v.checkpoint()

	if second.Stats.PromotedInodes != first.Stats.PromotedInodes {
		t.Errorf("the second seal saw %d promoted inodes, the first saw %d: the shard lost records",
			second.Stats.PromotedInodes, first.Stats.PromotedInodes)
	}
	// Both names still read, out of a cold cache, from the new generation.
	v.verifyBodies(second, body)
	compareViews(t, snapshot(t, v.ov), snapshot(t, openGenfs(t, v.inner, second.Superblock, nil)))
}
