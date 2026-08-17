package publish_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/retention"
)

// countingStore counts pack range reads. Every byte of file content a seal
// does not already hold locally arrives through one of these, so "did this
// seal download the tree back out of the federation" is exactly this
// number.
//
// It deliberately does NOT implement pelicanobj.Unwrapper: a caller that
// unwrapped to the transport would route around the counter and the
// assertions here would silently measure nothing.
type countingStore struct {
	pelicanobj.Store
	packGets atomic.Int64
}

func (c *countingStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if strings.HasPrefix(key, packstore.PackDirKey+"/") {
		c.packGets.Add(1)
	}
	return c.Store.Get(ctx, key, off, limit)
}

// reuseVol drives a volume the way a writable mount drives one: seal a
// frozen snapshot, follow the sealed generation, hand the published inodes
// back as clean, keep writing. Reproducing the whole cycle is the point —
// it is the cycle that exposed the defect these tests pin. After a rebase
// the files a session just wrote are CLEAN, so the next checkpoint used to
// fetch every one of them back from the federation to rediscover chunk
// identities it had uploaded minutes earlier.
type reuseVol struct {
	t     *testing.T
	inner *countingStore
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	state string
	index string
	head  *publish.Result
	base  *genfs.FS
	ov    *overlay.FS
	snaps int
	// sealGets is how many pack range reads the last checkpoint's SEAL
	// issued: the number this whole change exists to drive to zero.
	sealGets int64
	// smax overrides the catalog split threshold, so a test can force a
	// small fixture into a TREE of catalogs instead of one flat catalog.
	// Zero takes the default.
	smax int64
	// maxRes is the residency bound every genfs this volume opens carries,
	// so a remount reproduces the mount it replaces.
	maxRes int
	// remounts numbers the overlay directories a remount has opened.
	remounts int
}

func newReuseVol(t *testing.T, volID [16]byte) *reuseVol {
	t.Helper()
	return newReuseVolResident(t, volID, 0)
}

// newReuseVolResident bounds the base generation's residency map, the way
// a path-based frontend (the NFS backend) does. A seal must survive it.
func newReuseVolResident(t *testing.T, volID [16]byte, maxResident int) *reuseVol {
	t.Helper()
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := &reuseVol{
		t:      t,
		inner:  &countingStore{Store: newInner(t)},
		pub:    pub,
		priv:   priv,
		state:  t.TempDir(),
		maxRes: maxResident,
	}
	v.index = filepath.Join(v.state, "dedup.db")
	v.head, err = publish.InitVolume(ctx, publish.Options{
		Inner: v.inner, SpoolDir: t.TempDir(), SigningKey: priv, VolumeID: volID,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	// One cache directory for the life of the volume, as a mount has: a
	// chunk uploaded by a seal is not in it (uploads never fill the read
	// cache), which is precisely why re-chunking cost federation reads.
	v.base, err = genfs.Open(ctx, genfs.Options{
		Inner: v.inner, SB: v.head.Superblock, CacheDir: filepath.Join(v.state, "gencache"),
		MaxResident: maxResident,
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = v.base.Close() })
	v.ov, err = overlay.Open(filepath.Join(v.state, "overlay"), v.base, overlay.Options{
		NextInode:      v.base.NextInode(),
		BaseRoot:       v.base.RootCatalog(),
		BaseGeneration: v.base.Generation(),
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = v.ov.Close() })
	return v
}

// sealOnly publishes the LIVE overlay onto prev without following it, for
// tests that need the source and the predecessor to disagree.
func (v *reuseVol) sealOnly(prev *publish.Result) *publish.Result {
	v.t.Helper()
	res, err := publish.Seal(context.Background(), publish.Options{
		Overlay: v.ov, Inner: v.inner, SpoolDir: v.t.TempDir(),
		SigningKey: v.priv, Prev: prev.Superblock, PrevRaw: prev.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index, SMax: v.smax,
	})
	if err != nil {
		v.t.Fatalf("seal: %v", err)
	}
	return res
}

// checkpoint mirrors cmd/pelfs's sealLocked: freeze, seal the frozen view,
// swap the base to what was sealed, rebase the published inodes to clean.
func (v *reuseVol) checkpoint() *publish.Result {
	v.t.Helper()
	ctx := context.Background()
	v.snaps++
	snap, err := v.ov.Snapshot(filepath.Join(v.state, fmt.Sprintf("snap-%d", v.snaps)))
	if err != nil {
		v.t.Fatalf("snapshot: %v", err)
	}
	defer snap.Close() //nolint:errcheck
	// Measured around the SEAL alone. Following the branch afterwards
	// re-indexes the new generation's pack trailers, which is a read the
	// mount owes the reader, not one the seal owes its input.
	before := v.inner.packGets.Load()
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap, Inner: v.inner, SpoolDir: v.t.TempDir(),
		SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index, SMax: v.smax,
	})
	if err != nil {
		v.t.Fatalf("seal: %v", err)
	}
	v.sealGets = v.inner.packGets.Load() - before
	v.head = res
	if _, err := v.base.Swap(ctx, res.Superblock); err != nil {
		v.t.Fatalf("swap to the sealed generation: %v", err)
	}
	if _, err := v.ov.Rebase(ctx, snap.Seq(), overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	}); err != nil {
		v.t.Fatalf("rebase: %v", err)
	}
	return res
}

// remount reopens the volume the way starting a new session does: a fresh
// genfs over the published head and a fresh overlay directory on top of
// it. Nothing carries over — in particular no in-memory record of which
// base inodes this process has already resolved — so every base inode the
// next seal touches must be reachable from the walk alone.
//
// That distinction is what the same-session tests cannot make: a rebase
// re-pins provenance for everything the session wrote, which hides a walk
// that establishes none of its own.
func (v *reuseVol) remount() {
	v.t.Helper()
	ctx := context.Background()
	if err := v.ov.Close(); err != nil {
		v.t.Fatalf("close overlay: %v", err)
	}
	if err := v.base.Close(); err != nil {
		v.t.Fatalf("close base: %v", err)
	}
	v.remounts++
	var err error
	v.base, err = genfs.Open(ctx, genfs.Options{
		Inner: v.inner, SB: v.head.Superblock, CacheDir: filepath.Join(v.state, "gencache"),
		MaxResident: v.maxRes,
	})
	if err != nil {
		v.t.Fatalf("genfs.Open on remount: %v", err)
	}
	v.ov, err = overlay.Open(filepath.Join(v.state, fmt.Sprintf("overlay-%d", v.remounts)), v.base, overlay.Options{
		NextInode:      v.base.NextInode(),
		BaseRoot:       v.base.RootCatalog(),
		BaseGeneration: v.base.Generation(),
	})
	if err != nil {
		v.t.Fatalf("overlay.Open on remount: %v", err)
	}
}

func (v *reuseVol) create(parent uint64, name string, data []byte) uint64 {
	v.t.Helper()
	ctx := context.Background()
	n, err := v.ov.Create(ctx, parent, name, 0644, 0, 0)
	if err != nil {
		v.t.Fatalf("create %s: %v", name, err)
	}
	if len(data) > 0 {
		if _, err := v.ov.Write(ctx, n.Inode, 0, data); err != nil {
			v.t.Fatalf("write %s: %v", name, err)
		}
	}
	return n.Inode
}

// rewrite replaces a file's whole body. Truncating to zero FIRST means the
// overlay copies nothing out of the base, so a test can attribute every
// pack read that follows to the seal rather than to the mutation.
func (v *reuseVol) rewrite(ino uint64, data []byte) {
	v.t.Helper()
	ctx := context.Background()
	zero := int64(0)
	if _, err := v.ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &zero}); err != nil {
		v.t.Fatalf("truncate inode %d: %v", ino, err)
	}
	if _, err := v.ov.Write(ctx, ino, 0, data); err != nil {
		v.t.Fatalf("rewrite inode %d: %v", ino, err)
	}
}

// reuseTree is the fixture both content tests write: two chunked files, a
// chunked file one directory down, and two inline ones.
func (v *reuseVol) reuseTree(seed int64) (map[string][]byte, map[string]uint64) {
	v.t.Helper()
	body := map[string][]byte{
		"a.bin":        pseudorandom(3<<20, seed),
		"b.bin":        pseudorandom(2<<20, seed+1),
		"small.txt":    []byte("inline, well under the threshold"),
		"d/c.bin":      pseudorandom(3<<19, seed+2),
		"d/note.txt":   []byte("also inline"),
		"d/empty.file": nil,
	}
	ino := make(map[string]uint64, len(body))
	dir, err := v.ov.Mkdir(context.Background(), publishRootInode, "d", 0755, 0, 0)
	if err != nil {
		v.t.Fatalf("mkdir d: %v", err)
	}
	ino["d"] = dir.Inode
	for _, name := range []string{"a.bin", "b.bin", "small.txt"} {
		ino[name] = v.create(publishRootInode, name, body[name])
	}
	for _, name := range []string{"c.bin", "note.txt", "empty.file"} {
		ino["d/"+name] = v.create(dir.Inode, name, body["d/"+name])
	}
	return body, ino
}

// verifyBodies reads the generation back through a COLD cache — a fresh
// genfs with its own CacheDir — so every byte must come from a pack the
// new superblock lists. A carried-forward chunkref whose pack fell out of
// the list is unreadable exactly here and nowhere earlier.
func (v *reuseVol) verifyBodies(res *publish.Result, body map[string][]byte) {
	v.t.Helper()
	sealed := openGenfs(v.t, v.inner, res.Superblock, nil)
	for path, want := range body {
		n := lookupPath(v.t, sealed, path)
		if n.Length != int64(len(want)) {
			v.t.Errorf("%s: length %d, want %d", path, n.Length, len(want))
			continue
		}
		if len(want) == 0 {
			continue
		}
		if got := readWhole(v.t, sealed, n.Inode, n.Length); string(got) != string(want) {
			v.t.Errorf("%s: content differs after the seal (%d bytes)", path, len(got))
		}
	}
}

// A checkpoint over a tree nothing has touched must read nothing back.
// Before content reuse this walk re-opened every file, which for clean
// files resolves through the base generation — one federation round trip
// per chunk, every interval, for content the seal itself had uploaded.
func TestSealReusesUnchangedContent(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xc0, 0xff, 0xee, 0x01})
	body, _ := v.reuseTree(7001)

	first := v.checkpoint()
	if first.Stats.ChunksAdded == 0 {
		t.Fatalf("the fixture published no chunks; the test would prove nothing")
	}
	if first.Stats.ReusedFiles != 0 {
		t.Errorf("first seal reused %d files, but the base generation is empty", first.Stats.ReusedFiles)
	}

	second := v.checkpoint()

	if v.sealGets != 0 {
		t.Errorf("re-sealing an unchanged tree issued %d pack range read(s), want 0", v.sealGets)
	}
	if second.Stats.ChunksAdded != 0 {
		t.Errorf("re-sealing an unchanged tree uploaded %d chunk(s)", second.Stats.ChunksAdded)
	}
	if second.Stats.ChunksDeduped != 0 {
		t.Errorf("re-sealing an unchanged tree ran %d chunk(s) through the chunker", second.Stats.ChunksDeduped)
	}
	// Nothing changed, so nothing is rebuilt: the whole catalog tree is
	// carried forward, which subsumes per-file content reuse — the files
	// are never consulted because the catalogs describing them are never
	// rewritten.
	if second.Stats.Catalogs != 0 {
		t.Errorf("re-sealing an unchanged tree wrote %d catalog(s), want 0", second.Stats.Catalogs)
	}
	if second.Stats.CatalogsReused != first.Stats.Catalogs {
		t.Errorf("carried %d catalogs forward, the base published %d",
			second.Stats.CatalogsReused, first.Stats.Catalogs)
	}
	if second.Superblock.RootCatalog != first.Superblock.RootCatalog {
		t.Errorf("root catalog changed though nothing in the tree did")
	}
	if second.Superblock.Generation != 2 {
		t.Fatalf("generation = %d, want 2", second.Superblock.Generation)
	}
	v.verifyBodies(second, body)
}

// A modified file is re-chunked; its siblings are not, including one whose
// ATTRIBUTES changed — the new mode must reach the catalog without the
// content going back through the chunker.
func TestSealRechunksOnlyModifiedFiles(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xc0, 0xff, 0xee, 0x02})
	body, ino := v.reuseTree(7002)
	v.checkpoint()

	body["a.bin"] = pseudorandom(3<<20, 9999)
	v.rewrite(ino["a.bin"], body["a.bin"])
	mode := uint32(0600)
	if _, err := v.ov.SetAttr(ctx, ino["b.bin"], overlay.SetAttrIn{Mode: &mode}); err != nil {
		t.Fatalf("chmod b.bin: %v", err)
	}

	second := v.checkpoint()

	if v.sealGets != 0 {
		t.Errorf("sealing one modified file issued %d pack range read(s), want 0", v.sealGets)
	}
	if want := chunkCount(t, body["a.bin"]); second.Stats.ChunksAdded != want {
		t.Errorf("added %d chunks, want %d (the rewritten file alone)", second.Stats.ChunksAdded, want)
	}
	if want := 4; second.Stats.ReusedFiles != want {
		t.Errorf("reused %d files, want %d (everything but the rewritten one)", second.Stats.ReusedFiles, want)
	}
	v.verifyBodies(second, body)

	sealed := openGenfs(t, v.inner, second.Superblock, nil)
	if n := lookupPath(t, sealed, "b.bin"); n.Mode != mode {
		t.Errorf("b.bin mode = %#o, want %#o: the attribute change was lost with the reused content", n.Mode, mode)
	}
}

// Carried-forward chunkrefs name bytes in packs the PREVIOUS generation
// listed, so the new generation must list them too — otherwise retention
// is free to delete them and the generation quietly becomes unreadable.
func TestCarriedChunksStayRetained(t *testing.T) {
	ctx := context.Background()
	v := newReuseVol(t, [16]byte{0xc0, 0xff, 0xee, 0x03})
	body, _ := v.reuseTree(7003)
	first := v.checkpoint()

	body["late.bin"] = pseudorandom(1<<20, 4242)
	v.create(publishRootInode, "late.bin", body["late.bin"])
	second := v.checkpoint()
	if second.Stats.ReusedChunks == 0 {
		t.Fatalf("nothing was carried forward; the test would prove nothing")
	}

	listed := make(map[string]bool, len(second.Superblock.PackList))
	for _, pe := range second.Superblock.PackList {
		listed[pe.Name] = true
	}
	for _, pe := range first.Superblock.PackList {
		if !listed[pe.Name] {
			t.Errorf("pack %s holds carried-forward chunks but is not listed by the new generation", pe.Name)
		}
	}

	// And retention agrees. Sweep with a clock far past the grace window,
	// so the age guard protects nothing and only the pack LIST keeps a
	// pack alive, then read the generation back from a cold cache.
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
	if rep.RetainedPacks != len(second.Superblock.PackList) {
		t.Errorf("GC retained %d packs, the head lists %d", rep.RetainedPacks, len(second.Superblock.PackList))
	}
	v.verifyBodies(second, body)
}

// Reuse is allowed only from the generation the publish is building on.
// Sealing twice from a live overlay whose base was never advanced is the
// case: the second seal's Prev is the first seal's output, which the
// overlay does not serve, so the records it holds may name packs that
// generation does not list.
func TestSealDeclinesReuseFromAnotherGeneration(t *testing.T) {
	v := newReuseVol(t, [16]byte{0xc0, 0xff, 0xee, 0x04})
	body, _ := v.reuseTree(7004)

	first := v.sealOnly(v.head)
	if first.Stats.ReusedFiles != 0 {
		t.Errorf("first seal reused %d files over an empty base", first.Stats.ReusedFiles)
	}
	second := v.sealOnly(first)
	if second.Stats.ReusedFiles != 0 {
		t.Errorf("reuse engaged against generation %d, which the source does not serve",
			first.Superblock.Generation)
	}
	v.verifyBodies(second, body)
}
