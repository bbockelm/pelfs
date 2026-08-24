package fsck_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/fsck"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// The structural invariants cannot be broken by damaging pack objects —
// they live INSIDE catalogs, which publish never emits inconsistently. So
// these tests build the damaged generation directly: hand-written
// catalogs, one pack, an unsigned superblock (fsck's contract is that the
// caller already verified it).
type genBuilder struct {
	t     *testing.T
	inner pelicanobj.Store
	dir   string
	pw    *packstore.PackWriter
	seq   int
}

func newGen(t *testing.T) *genBuilder {
	t.Helper()
	inner, _ := newInner(t)
	g := &genBuilder{t: t, inner: inner, dir: t.TempDir()}
	t.Cleanup(func() {
		if g.pw != nil {
			g.pw.Abort()
		}
	})
	return g
}

func (g *genBuilder) writer() *packstore.PackWriter {
	if g.pw == nil {
		pw, err := packstore.NewPackWriter(g.dir)
		if err != nil {
			g.t.Fatal(err)
		}
		g.pw = pw
	}
	return g.pw
}

// addCatalog builds one catalog (or shard) and packs it, returning its
// plain-BLAKE3 identity.
func (g *genBuilder) addCatalog(coveredPath, typ string, build func(w *catalog.Writer)) [32]byte {
	g.t.Helper()
	g.seq++
	fp := filepath.Join(g.dir, fmt.Sprintf("cat-%d.db", g.seq))
	w, err := catalog.Create(fp, catalog.Meta{
		VolumeUUID: "00000000-0000-4000-8000-000000000000", CoveredPath: coveredPath,
		Generation: 0, IdentityAlgo: "blake3-256",
	})
	if err != nil {
		g.t.Fatal(err)
	}
	build(w)
	if err := w.Close(); err != nil {
		g.t.Fatal(err)
	}
	raw, err := os.ReadFile(fp)
	if err != nil {
		g.t.Fatal(err)
	}
	id := chunkid.NewHasher(nil).Sum(raw)
	stored, err := entrycodec.EncodeZstd(raw, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	if err := g.writer().Add(id.Hex(), typ, stored); err != nil {
		g.t.Fatal(err)
	}
	return [32]byte(id)
}

// addChunk packs one data chunk and returns the chunkref that names it.
func (g *genBuilder) addChunk(data []byte) catalog.ChunkRef {
	g.t.Helper()
	id := chunkid.NewHasher(nil).Sum(data)
	stored, alg, err := entrycodec.Encode(data, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	if err := g.writer().Add(id.Hex(), packstore.EntryData, stored); err != nil {
		g.t.Fatal(err)
	}
	idb := id
	return catalog.ChunkRef{Identity: idb[:], LLen: int64(len(data)), CLen: int64(len(stored)), Alg: int64(alg)}
}

// seal uploads the pack and returns the generation's superblock.
func (g *genBuilder) seal(root [32]byte, shards []superblock.ShardEntry) *superblock.Superblock {
	g.t.Helper()
	sp, err := g.writer().Seal(context.Background(), g.inner)
	if err != nil {
		g.t.Fatal(err)
	}
	g.pw = nil
	sb := &superblock.Superblock{
		FormatVersion: superblock.FormatV2,
		RootCatalog:   root,
		PackList:      []superblock.PackEntry{{Name: sp.Name, TrailerHash: sp.TrailerHash, Size: sp.Size}},
		Shards:        shards,
		NextInode:     1000,
	}
	// SIGNED, even though nothing here verifies it. fsck now reports a
	// generation with no signature (KindUnsigned), which is a true and
	// deliberate finding — and a fixture that skipped signing would carry
	// it into every structural test as an extra problem, so these tests
	// would be asserting on the fixture's shortcut rather than on damage.
	if err := sb.Sign(testSigningKey(g.t)); err != nil {
		g.t.Fatal(err)
	}
	return sb
}

// testSigningKey is a deterministic key for fixtures: what it signs is
// never verified here, only counted as "this generation has a signature".
func testSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

func dirNode(inode int64, nlink uint32) catalog.Node {
	return catalog.Node{Inode: inode, Type: catalog.TypeDir, Mode: 0755, Nlink: nlink}
}

func fileNode(inode int64, length int64, nlink uint32) catalog.Node {
	return catalog.Node{Inode: inode, Type: catalog.TypeFile, Mode: 0644, Nlink: nlink, Length: length}
}

func mustAdd(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// A dirent whose inode has no node row is a broken namespace, and the
// sweep must keep going past it.
func TestStructuralDanglingDirent(t *testing.T) {
	g := newGen(t)
	ref := g.addChunk(pseudorandom(4096, 5))
	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 2)))
		mustAdd(t, w.AddEdge(1, []byte("ghost"), 5, catalog.TypeFile))
		mustAdd(t, w.AddEdge(1, []byte("real.bin"), 6, catalog.TypeFile))
		mustAdd(t, w.AddNode(fileNode(6, ref.LLen, 1)))
		mustAdd(t, w.AddChunks(6, []catalog.ChunkRef{ref}))
	})
	sb := g.seal(root, nil)

	rep := check(t, g.inner, sb, fsck.Options{Deep: true})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindDanglingDirent)
	if len(bad) != 1 || bad[0].Path != "/ghost" {
		t.Fatalf("dangling-dirent problems = %+v", bad)
	}
	if len(rep.Problems) != 1 {
		t.Fatalf("the intact sibling must not be reported: %+v", rep.Problems)
	}
	if rep.Files != 1 || rep.ChunksVerified != 1 {
		t.Fatalf("the sweep stopped at the dangling dirent: %d files, %d chunks verified", rep.Files, rep.ChunksVerified)
	}
}

// A transition point needs BOTH halves: the dirent (so lookup and stat
// never fetch the child) and the nested locator (so descent can).
func TestStructuralTransitionHalves(t *testing.T) {
	g := newGen(t)
	child := g.addCatalog("/sub", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(2, 2)))
	})
	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 3)))
		// Well-formed transition point.
		mustAdd(t, w.AddNode(dirNode(2, 2)))
		mustAdd(t, w.AddEdge(1, []byte("sub"), 2, catalog.TypeDir))
		mustAdd(t, w.AddNested(1, []byte("sub"), child[:]))
		// Locator with no dirent: nothing can ever reach it.
		mustAdd(t, w.AddNested(1, []byte("orphan"), child[:]))
	})
	sb := g.seal(root, nil)

	rep := check(t, g.inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindTransition)
	if len(bad) != 1 || bad[0].Path != "/orphan" || !strings.Contains(bad[0].Detail, "no dirent half") {
		t.Fatalf("transition problems = %+v", bad)
	}
	if rep.Catalogs != 2 || rep.Dirs != 2 {
		t.Fatalf("the well-formed transition was not descended: %d catalogs, %d dirs", rep.Catalogs, rep.Dirs)
	}
}

// A dirent's type must agree with the node row it names.
func TestStructuralTypeMismatch(t *testing.T) {
	g := newGen(t)
	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 2)))
		mustAdd(t, w.AddNode(fileNode(4, 0, 1)))
		mustAdd(t, w.AddEdge(1, []byte("liar"), 4, catalog.TypeDir))
	})
	sb := g.seal(root, nil)

	rep := check(t, g.inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindTypeMismatch)
	if len(bad) != 1 || bad[0].Path != "/liar" {
		t.Fatalf("type-mismatch problems = %+v", bad)
	}
}

// Chunk lists that cannot describe the file they belong to: lengths that
// do not sum to the node length, a stored length disagreeing with the pack
// index, and an identity in no pack.
func TestStructuralChunkRefs(t *testing.T) {
	g := newGen(t)
	ref := g.addChunk(pseudorandom(8192, 6))
	short := ref
	short.LLen = ref.LLen / 2 // node says more than the extents cover
	wrongCLen := ref
	wrongCLen.CLen = ref.CLen + 7
	lost := ref
	lostID := chunkid.NewHasher(nil).Sum([]byte("never packed"))
	lost.Identity = lostID[:]

	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 2)))
		mustAdd(t, w.AddNode(fileNode(2, ref.LLen, 1)))
		mustAdd(t, w.AddEdge(1, []byte("short.bin"), 2, catalog.TypeFile))
		mustAdd(t, w.AddChunks(2, []catalog.ChunkRef{short}))
		mustAdd(t, w.AddNode(fileNode(3, ref.LLen, 1)))
		mustAdd(t, w.AddEdge(1, []byte("clen.bin"), 3, catalog.TypeFile))
		mustAdd(t, w.AddChunks(3, []catalog.ChunkRef{wrongCLen}))
		mustAdd(t, w.AddNode(fileNode(4, ref.LLen, 1)))
		mustAdd(t, w.AddEdge(1, []byte("lost.bin"), 4, catalog.TypeFile))
		mustAdd(t, w.AddChunks(4, []catalog.ChunkRef{lost}))
		// A file whose node row claims bytes it has no records for.
		mustAdd(t, w.AddNode(fileNode(5, 99, 1)))
		mustAdd(t, w.AddEdge(1, []byte("empty.bin"), 5, catalog.TypeFile))
	})
	sb := g.seal(root, nil)

	rep := check(t, g.inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	byPath := map[string]fsck.Problem{}
	for _, p := range rep.Problems {
		byPath[p.Path] = p
	}
	if p := byPath["/short.bin"]; p.Kind != fsck.KindChunkRefs || !strings.Contains(p.Detail, "sum to") {
		t.Fatalf("short.bin problem = %+v", p)
	}
	if p := byPath["/clen.bin"]; p.Kind != fsck.KindChunkRefs || !strings.Contains(p.Detail, "clen") {
		t.Fatalf("clen.bin problem = %+v", p)
	}
	if p := byPath["/lost.bin"]; p.Kind != fsck.KindMissingChunk {
		t.Fatalf("lost.bin problem = %+v", p)
	}
	if p := byPath["/empty.bin"]; p.Kind != fsck.KindContent {
		t.Fatalf("empty.bin problem = %+v", p)
	}
	if len(rep.Problems) != 4 {
		t.Fatalf("want one problem per damaged file, got %+v", rep.Problems)
	}
}

// Promoted (nlink > 1) files keep their content in an inode shard: the
// routing must exist and must hold the record.
func TestStructuralShardRouting(t *testing.T) {
	g := newGen(t)
	ref := g.addChunk(pseudorandom(4096, 7))
	// A shard that covers inode 3 but not inode 2, and holds no record for
	// the inode it does cover.
	shard := g.addCatalog("inodes:3-3", packstore.EntryShard, func(w *catalog.Writer) {})
	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 2)))
		mustAdd(t, w.AddNode(fileNode(2, ref.LLen, 2)))
		mustAdd(t, w.AddEdge(1, []byte("uncovered"), 2, catalog.TypeFile))
		mustAdd(t, w.AddNode(fileNode(3, ref.LLen, 2)))
		mustAdd(t, w.AddEdge(1, []byte("absent"), 3, catalog.TypeFile))
	})
	sb := g.seal(root, []superblock.ShardEntry{{FirstInode: 3, LastInode: 3, Identity: shard}})

	rep := check(t, g.inner, sb, fsck.Options{})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindShardRouting)
	if len(bad) != 2 {
		t.Fatalf("shard-routing problems = %+v", bad)
	}
	if bad[0].Path != "/absent" || !strings.Contains(bad[0].Detail, "no record in shard") {
		t.Fatalf("absent = %+v", bad[0])
	}
	if bad[1].Path != "/uncovered" || !strings.Contains(bad[1].Detail, "covered by no shard") {
		t.Fatalf("uncovered = %+v", bad[1])
	}
	if rep.Shards != 1 {
		t.Fatalf("the shard itself is intact and must count: %d", rep.Shards)
	}
}

// A catalog referenced by a transition point but present in no pack costs
// its subtree, not the sweep.
func TestStructuralMissingCatalog(t *testing.T) {
	g := newGen(t)
	// Build the child, hash it, but never pack it: addCatalog packs, so
	// compute the identity of an unpacked catalog by hand.
	ghost := [32]byte(chunkid.NewHasher(nil).Sum([]byte("no such catalog")))
	ref := g.addChunk(pseudorandom(4096, 8))
	root := g.addCatalog("/", packstore.EntryCatalog, func(w *catalog.Writer) {
		mustAdd(t, w.AddNode(dirNode(1, 3)))
		mustAdd(t, w.AddNode(dirNode(2, 2)))
		mustAdd(t, w.AddEdge(1, []byte("gone"), 2, catalog.TypeDir))
		mustAdd(t, w.AddNested(1, []byte("gone"), ghost[:]))
		mustAdd(t, w.AddNode(fileNode(3, ref.LLen, 1)))
		mustAdd(t, w.AddEdge(1, []byte("fine.bin"), 3, catalog.TypeFile))
		mustAdd(t, w.AddChunks(3, []catalog.ChunkRef{ref}))
	})
	sb := g.seal(root, nil)

	rep := check(t, g.inner, sb, fsck.Options{Deep: true})
	dumpProblems(t, rep)
	bad := problemsOf(rep, fsck.KindMissingCatalog)
	if len(bad) != 1 || bad[0].Path != "/gone" {
		t.Fatalf("missing-catalog problems = %+v", bad)
	}
	if rep.Files != 1 || rep.ChunksVerified != 1 {
		t.Fatalf("the surviving sibling was not checked: %+v", rep)
	}
}
