package publish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// viewFS is the read surface genfs and overlay share (overlay.Node and
// overlay.DirEntry are genfs aliases), so one walker compares the sealed
// generation against the overlay it was sealed from.
type viewFS interface {
	Lookup(ctx context.Context, parent uint64, name string) (genfs.Node, error)
	Readdir(ctx context.Context, ino uint64) ([]genfs.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	ListXattr(ctx context.Context, ino uint64) ([]string, error)
	GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error)
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
}

func openGenfs(t *testing.T, inner pelicanobj.Store, sb *superblock.Superblock, dek []byte) *genfs.FS {
	t.Helper()
	fs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: sb, DEK: dek, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

func openOverlay(t *testing.T, base *genfs.FS, sb *superblock.Superblock) *overlay.FS {
	t.Helper()
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      sb.NextInode,
		BaseRoot:       sb.RootCatalog,
		BaseGeneration: sb.Generation,
	})
	if err != nil {
		t.Fatalf("overlay.Open: %v", err)
	}
	t.Cleanup(func() { _ = ov.Close() })
	return ov
}

// lookupPath descends from the root one Lookup at a time — the kernel
// order both genfs residency and the overlay's base pinning require.
func lookupPath(t *testing.T, fs viewFS, p string) genfs.Node {
	t.Helper()
	ino := uint64(publishRootInode)
	var n genfs.Node
	for _, name := range splitPath(p) {
		var err error
		n, err = fs.Lookup(context.Background(), ino, name)
		if err != nil {
			t.Fatalf("lookup %s (at %q): %v", p, name, err)
		}
		ino = n.Inode
	}
	return n
}

func splitPath(p string) []string {
	var out []string
	for _, part := range bytes.Split([]byte(p), []byte("/")) {
		if len(part) > 0 {
			out = append(out, string(part))
		}
	}
	return out
}

// snapEntry is one node of a merged-view snapshot.
type snapEntry struct {
	inode   uint64
	typ     uint8
	mode    uint32
	length  int64
	nlink   uint32
	subdirs int
	content []byte
	xattrs  map[string]string
	target  string
}

// snapshot walks a view by Lookup descent and records everything the seal
// is supposed to preserve, keyed by path.
func snapshot(t *testing.T, fs viewFS) map[string]snapEntry {
	t.Helper()
	out := make(map[string]snapEntry)
	var walk func(ino uint64, prefix string)
	walk = func(ino uint64, prefix string) {
		des, err := fs.Readdir(context.Background(), ino)
		if err != nil {
			t.Fatalf("readdir %s: %v", prefix, err)
		}
		for _, de := range des {
			n, err := fs.Lookup(context.Background(), ino, de.Name)
			if err != nil {
				t.Fatalf("lookup %s/%s: %v", prefix, de.Name, err)
			}
			p := prefix + "/" + de.Name
			e := snapEntry{
				inode: n.Inode, typ: n.Type, mode: n.Mode,
				length: n.Length, nlink: n.Nlink,
				xattrs: snapXattrs(t, fs, n.Inode),
			}
			switch n.Type {
			case catalog.TypeFile:
				e.content = readWhole(t, fs, n.Inode, n.Length)
			case catalog.TypeSymlink:
				target, err := fs.Readlink(context.Background(), n.Inode)
				if err != nil {
					t.Fatalf("readlink %s: %v", p, err)
				}
				e.target = target
			}
			out[p] = e
			if n.Type == catalog.TypeDir {
				walk(n.Inode, p)
				for q := range out {
					if filepath.Dir(q) == p && out[q].typ == catalog.TypeDir {
						e.subdirs++
					}
				}
				out[p] = e
			}
		}
	}
	walk(publishRootInode, "")
	return out
}

func snapXattrs(t *testing.T, fs viewFS, ino uint64) map[string]string {
	t.Helper()
	names, err := fs.ListXattr(context.Background(), ino)
	if err != nil {
		t.Fatalf("listxattr %d: %v", ino, err)
	}
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		v, err := fs.GetXattr(context.Background(), ino, name)
		if err != nil {
			t.Fatalf("getxattr %s of %d: %v", name, ino, err)
		}
		out[name] = string(v)
	}
	return out
}

func readWhole(t *testing.T, fs viewFS, ino uint64, length int64) []byte {
	t.Helper()
	buf := make([]byte, length)
	for off := int64(0); off < length; {
		n, err := fs.Read(context.Background(), ino, off, buf[off:])
		if err != nil {
			t.Fatalf("read inode %d at %d: %v", ino, off, err)
		}
		if n == 0 {
			t.Fatalf("read inode %d: short at %d of %d", ino, off, length)
		}
		off += int64(n)
	}
	return buf
}

// compareViews asserts the sealed generation reproduces the overlay's
// merged view. Directory nlink is the one attribute the overlay does not
// maintain (internal/overlay, Mkdir: parent link counts are recomputed at
// seal), so it is checked against the namespace instead.
func compareViews(t *testing.T, want, got map[string]snapEntry) {
	t.Helper()
	for p := range got {
		if _, ok := want[p]; !ok {
			t.Errorf("sealed generation has extra path %s", p)
		}
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			t.Errorf("sealed generation is missing %s", p)
			continue
		}
		if g.inode != w.inode {
			t.Errorf("%s: inode %d, overlay had %d", p, g.inode, w.inode)
		}
		if g.typ != w.typ || g.mode != w.mode || g.length != w.length {
			t.Errorf("%s: type/mode/length %d/%o/%d, overlay had %d/%o/%d",
				p, g.typ, g.mode, g.length, w.typ, w.mode, w.length)
		}
		if !bytes.Equal(g.content, w.content) {
			t.Errorf("%s: content differs (%d vs %d bytes)", p, len(g.content), len(w.content))
		}
		if g.target != w.target {
			t.Errorf("%s: symlink target %q, overlay had %q", p, g.target, w.target)
		}
		if !equalXattrs(g.xattrs, w.xattrs) {
			t.Errorf("%s: xattrs %v, overlay had %v", p, g.xattrs, w.xattrs)
		}
		if g.typ == catalog.TypeDir {
			if want := uint32(2 + g.subdirs); g.nlink != want {
				t.Errorf("%s: directory nlink %d, want %d (2 + %d subdirs)", p, g.nlink, want, g.subdirs)
			}
		} else if g.nlink != w.nlink {
			t.Errorf("%s: nlink %d, overlay had %d", p, g.nlink, w.nlink)
		}
	}
}

// pathsOf keeps failure messages readable (snapshots carry file content).
func pathsOf(m map[string]snapEntry) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func equalXattrs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// chunkCount is how many chunks the publish chunker cuts content into —
// the exact number of pack appends new content must cost.
func chunkCount(t *testing.T, data []byte) int {
	t.Helper()
	ck := chunkid.NewChunker(bytes.NewReader(data), chunkid.Options{})
	n := 0
	for {
		_, err := ck.Next()
		if err == io.EOF {
			return n
		}
		if err != nil {
			t.Fatalf("chunker: %v", err)
		}
		n++
	}
}

// sealBase is a published generation with an overlay open over it.
type sealBase struct {
	inner pelicanobj.Store
	res   *publish.Result
	base  *genfs.FS
	ov    *overlay.FS
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	index string
	ino   map[string]uint64
	body  map[string][]byte
}

// newSealBase publishes a fixed tree from a cut, then opens genfs and an
// overlay over it. dek/idKey empty publishes plaintext.
func newSealBase(t *testing.T, uuid string, dek, idKey []byte) *sealBase {
	t.Helper()
	inner := newInner(t)
	v := newTestVolume(t, uuid)
	s := &sealBase{
		inner: inner, index: filepath.Join(t.TempDir(), "dedup.db"),
		ino: map[string]uint64{}, body: map[string][]byte{},
	}
	s.body["keep.txt"] = []byte("untouched across the seal")
	s.body["big.bin"] = pseudorandom(3<<20, 4242)
	s.body["mod.txt"] = []byte("the first version")
	s.body["gone.txt"] = []byte("deleted by the overlay")
	s.body["olddir/inner.txt"] = []byte("inside the renamed directory")
	s.body["tagged.txt"] = []byte("carries xattrs")
	s.body["hard1"] = []byte("hardlink target body")

	for _, name := range []string{"keep.txt", "big.bin", "mod.txt", "gone.txt", "tagged.txt", "hard1"} {
		s.ino[name] = v.create(publishRootInode, name)
	}
	s.ino["olddir"] = v.mkdir(publishRootInode, "olddir")
	s.ino["olddir/inner.txt"] = v.create(s.ino["olddir"], "inner.txt")
	for p, b := range s.body {
		v.write(s.ino[p], b)
	}
	v.setxattr(s.ino["tagged.txt"], "user.color", []byte("blue"))
	v.symlink(publishRootInode, "link", "keep.txt")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.pub, s.priv = pub, priv

	var keyTable []superblock.KeyEntry
	keyID := uint32(0)
	if len(dek) != 0 {
		keyID = 7
		keyTable = []superblock.KeyEntry{
			{ID: 7, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-dek")},
			{ID: 8, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: []byte("wrapped-idkey")},
		}
	}
	s.res, err = publish.Publish(context.Background(), publish.Options{
		CutPath:        v.cut(),
		Blob:           v.blob,
		CacheDir:       t.TempDir(),
		Inner:          inner,
		SpoolDir:       t.TempDir(),
		SigningKey:     priv,
		IdentityKey:    idKey,
		DEK:            dek,
		KeyID:          keyID,
		KeyTable:       keyTable,
		TargetPackSize: 1 << 20,
		DedupIndexPath: s.index,
	})
	if err != nil {
		t.Fatalf("base Publish: %v", err)
	}
	s.base = openGenfs(t, inner, s.res.Superblock, dek)
	s.ov = openOverlay(t, s.base, s.res.Superblock)
	return s
}

// sealOpts builds the Seal options for the generation after prev.
func (s *sealBase) sealOpts(t *testing.T, prev *publish.Result, dek, idKey []byte) publish.Options {
	t.Helper()
	o := publish.Options{
		Overlay:        s.ov,
		Inner:          s.inner,
		SpoolDir:       t.TempDir(),
		SigningKey:     s.priv,
		IdentityKey:    idKey,
		DEK:            dek,
		TargetPackSize: 1 << 20,
		DedupIndexPath: s.index,
		Prev:           prev.Superblock,
		PrevRaw:        prev.Raw,
	}
	if len(dek) != 0 {
		o.KeyID = 7
		o.KeyTable = prev.Superblock.KeyTable
	}
	return o
}

func TestSealOverlayIntoGeneration(t *testing.T) {
	ctx := context.Background()
	s := newSealBase(t, "5e41c0de-0001-4002-8003-a0b0c0d0e0f0", nil, nil)
	ov := s.ov

	// A mixed change set over the base: modify, create, delete, rename,
	// xattr, hardlink — plus one new CHUNKED file, so the dedup assertions
	// separate new content from carried-forward content.
	freshContent := pseudorandom(2<<20, 909)

	modIno := lookupPath(t, ov, "mod.txt").Inode
	modContent := []byte("the second version, rewritten in the overlay")
	if err := truncWrite(ctx, ov, modIno, modContent); err != nil {
		t.Fatalf("rewrite mod.txt: %v", err)
	}

	newNode, err := ov.Create(ctx, publishRootInode, "new.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create new.txt: %v", err)
	}
	newContent := []byte("created directly in the overlay")
	if _, err := ov.Write(ctx, newNode.Inode, 0, newContent); err != nil {
		t.Fatalf("write new.txt: %v", err)
	}
	freshNode, err := ov.Create(ctx, publishRootInode, "fresh.bin", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create fresh.bin: %v", err)
	}
	if _, err := ov.Write(ctx, freshNode.Inode, 0, freshContent); err != nil {
		t.Fatalf("write fresh.bin: %v", err)
	}
	subNode, err := ov.Mkdir(ctx, publishRootInode, "newsub", 0755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir newsub: %v", err)
	}
	leafNode, err := ov.Create(ctx, subNode.Inode, "leaf.txt", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create newsub/leaf.txt: %v", err)
	}
	if _, err := ov.Write(ctx, leafNode.Inode, 0, []byte("leaf in a new directory")); err != nil {
		t.Fatalf("write newsub/leaf.txt: %v", err)
	}
	if _, err := ov.Mkdir(ctx, subNode.Inode, "deep", 0755, 0, 0); err != nil {
		t.Fatalf("mkdir newsub/deep: %v", err)
	}
	if err := ov.Unlink(ctx, publishRootInode, "gone.txt"); err != nil {
		t.Fatalf("unlink gone.txt: %v", err)
	}
	if err := ov.Rename(ctx, publishRootInode, "olddir", publishRootInode, "newdir"); err != nil {
		t.Fatalf("rename olddir: %v", err)
	}
	// A subdirectory under a BASE directory: its link count is stale in
	// the overlay and must be recomputed by the seal.
	newdirIno := lookupPath(t, ov, "newdir").Inode
	if _, err := ov.Mkdir(ctx, newdirIno, "sub", 0755, 0, 0); err != nil {
		t.Fatalf("mkdir newdir/sub: %v", err)
	}
	taggedIno := lookupPath(t, ov, "tagged.txt").Inode
	if err := ov.SetXattr(ctx, taggedIno, "user.sealed", []byte("yes")); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	hardIno := lookupPath(t, ov, "hard1").Inode
	if _, err := ov.Link(ctx, hardIno, publishRootInode, "hard2"); err != nil {
		t.Fatalf("link hard2: %v", err)
	}

	// The overlay is snapshotted AFTER the seal: sealing does not change
	// it, and a snapshot first would Lookup the whole tree, pre-warming the
	// base residency the seal's own descent has to establish.
	res, err := publish.Seal(ctx, s.sealOpts(t, s.res, nil, nil))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sb := res.Superblock
	if sb.Generation != 1 {
		t.Fatalf("generation = %d, want 1", sb.Generation)
	}
	if err := sb.Verify(s.pub); err != nil {
		t.Fatalf("verify sealed superblock: %v", err)
	}
	if sb.VolumeID != s.res.Superblock.VolumeID {
		t.Fatalf("sealed volume id %x, base %x", sb.VolumeID, s.res.Superblock.VolumeID)
	}
	if err := superblock.VerifyChain(s.res.Raw, sb, s.pub); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !bytes.Equal(fetchRef(t, s.inner, "refs/main"), res.Raw) {
		t.Fatalf("refs/main was not advanced to the sealed generation")
	}

	// The sealed generation reproduces the overlay's view exactly.
	want := snapshot(t, ov)
	sealed := openGenfs(t, s.inner, sb, nil)
	got := snapshot(t, sealed)
	if len(got) != 15 {
		t.Fatalf("sealed tree has %d paths, want 15: %v", len(got), pathsOf(got))
	}
	compareViews(t, want, got)
	// The recomputed link counts the overlay never maintained.
	if got["/newdir"].nlink != 3 || got["/newsub"].nlink != 3 {
		t.Errorf("directory nlink not recomputed: newdir %d, newsub %d (want 3 each)",
			got["/newdir"].nlink, got["/newsub"].nlink)
	}

	// Inodes survive the seal: untouched entries, and the renamed
	// directory together with its (never re-looked-up) child.
	for _, tc := range []struct{ path, base string }{
		{"/keep.txt", "keep.txt"},
		{"/big.bin", "big.bin"},
		{"/tagged.txt", "tagged.txt"},
		{"/newdir", "olddir"},
		{"/newdir/inner.txt", "olddir/inner.txt"},
	} {
		if got[tc.path].inode != s.ino[tc.base] {
			t.Errorf("%s: inode %d, base generation had %d for %s",
				tc.path, got[tc.path].inode, s.ino[tc.base], tc.base)
		}
	}
	if _, ok := got["/olddir"]; ok {
		t.Errorf("renamed directory still published at its old name")
	}
	if _, ok := got["/gone.txt"]; ok {
		t.Errorf("deleted file survived the seal")
	}
	if _, err := sealed.Lookup(ctx, publishRootInode, "gone.txt"); !errors.Is(err, genfs.ErrNotExist) {
		t.Errorf("lookup of the deleted name = %v, want ErrNotExist", err)
	}

	// The hardlink pair shares one inode, promoted to a shard.
	if got["/hard1"].inode != got["/hard2"].inode || got["/hard1"].inode != s.ino["hard1"] {
		t.Errorf("hardlink inodes %d/%d, want both %d",
			got["/hard1"].inode, got["/hard2"].inode, s.ino["hard1"])
	}
	if got["/hard1"].nlink != 2 {
		t.Errorf("hardlink nlink = %d, want 2", got["/hard1"].nlink)
	}
	if res.Stats.PromotedInodes != 1 || len(sb.Shards) != 1 {
		t.Errorf("stats %d promoted / %d shards, want 1/1", res.Stats.PromotedInodes, len(sb.Shards))
	}
	if !bytes.Equal(got["/mod.txt"].content, modContent) {
		t.Errorf("mod.txt content = %q", got["/mod.txt"].content)
	}
	if !bytes.Equal(got["/keep.txt"].content, s.body["keep.txt"]) {
		t.Errorf("keep.txt content changed under the seal")
	}
	if got["/link"].target != "keep.txt" {
		t.Errorf("symlink target = %q", got["/link"].target)
	}

	// Unchanged base content is never re-uploaded: the whole base chunk
	// set arrives from the dedup index, and only the new file's chunks are
	// added.
	if res.Stats.DedupIndexChunks != s.res.Stats.ChunksAdded {
		t.Errorf("dedup index preloaded %d chunks, base published %d",
			res.Stats.DedupIndexChunks, s.res.Stats.ChunksAdded)
	}
	if res.Stats.ChunksDeduped != s.res.Stats.ChunksAdded {
		t.Errorf("deduped %d chunks, want the base's %d", res.Stats.ChunksDeduped, s.res.Stats.ChunksAdded)
	}
	if want := chunkCount(t, freshContent); res.Stats.ChunksAdded != want {
		t.Errorf("added %d chunks, want %d (the new file's content alone)", res.Stats.ChunksAdded, want)
	}

	// The allocator mark clears every inode the overlay handed out.
	maxIno := uint64(0)
	for _, e := range got {
		if e.inode > maxIno {
			maxIno = e.inode
		}
	}
	if sb.NextInode <= maxIno {
		t.Errorf("NextInode = %d, not past max inode %d", sb.NextInode, maxIno)
	}
	if sb.NextInode < s.res.Superblock.NextInode {
		t.Errorf("NextInode regressed from %d to %d", s.res.Superblock.NextInode, sb.NextInode)
	}
}

// truncWrite replaces a file's whole content (the overlay has no truncate
// helper shorter than SetAttr + Write).
func truncWrite(ctx context.Context, ov *overlay.FS, ino uint64, data []byte) error {
	size := int64(len(data))
	if _, err := ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &size}); err != nil {
		return err
	}
	_, err := ov.Write(ctx, ino, 0, data)
	return err
}

func TestSealTwiceWithoutChanges(t *testing.T) {
	ctx := context.Background()
	s := newSealBase(t, "5e41c0de-0002-4002-8003-a0b0c0d0e0f0", nil, nil)

	first, err := publish.Seal(ctx, s.sealOpts(t, s.res, nil, nil))
	if err != nil {
		t.Fatalf("first Seal: %v", err)
	}
	if first.Stats.ChunksAdded != 0 {
		t.Errorf("clean seal added %d chunks", first.Stats.ChunksAdded)
	}

	second, err := publish.Seal(ctx, s.sealOpts(t, first, nil, nil))
	if err != nil {
		t.Fatalf("second Seal: %v", err)
	}
	if second.Superblock.Generation != 2 {
		t.Fatalf("generation = %d, want 2", second.Superblock.Generation)
	}
	if second.Superblock.PrevHash != superblock.Hash(first.Raw) {
		t.Errorf("lineage does not chain to the first seal")
	}
	if err := superblock.VerifyChain(first.Raw, second.Superblock, s.pub); err != nil {
		t.Errorf("VerifyChain: %v", err)
	}
	if second.Stats.ChunksAdded != 0 {
		t.Errorf("re-seal of an unchanged tree added %d chunks", second.Stats.ChunksAdded)
	}
	if second.Superblock.NextInode != first.Superblock.NextInode {
		t.Errorf("NextInode moved (%d -> %d) with no allocations",
			first.Superblock.NextInode, second.Superblock.NextInode)
	}
	// Generation 1's packs carry forward into generation 2.
	names := map[string]bool{}
	for _, pe := range second.Superblock.PackList {
		names[pe.Name] = true
	}
	for _, pe := range first.Superblock.PackList {
		if !names[pe.Name] {
			t.Errorf("pack %s dropped from the second seal's list", pe.Name)
		}
	}
	compareViews(t, snapshot(t, s.ov), snapshot(t, openGenfs(t, s.inner, second.Superblock, nil)))
}

func TestSealEncrypted(t *testing.T) {
	ctx := context.Background()
	dek := pseudorandom(32, 11)
	idKey := pseudorandom(32, 12)
	s := newSealBase(t, "5e41c0de-0003-4002-8003-a0b0c0d0e0f0", dek, idKey)
	ov := s.ov

	secret := []byte("rewritten under the DEK")
	if err := truncWrite(ctx, ov, lookupPath(t, ov, "mod.txt").Inode, secret); err != nil {
		t.Fatalf("rewrite mod.txt: %v", err)
	}
	blob := pseudorandom(2<<20, 313)
	blobNode, err := ov.Create(ctx, publishRootInode, "blob.bin", 0644, 0, 0)
	if err != nil {
		t.Fatalf("create blob.bin: %v", err)
	}
	if _, err := ov.Write(ctx, blobNode.Inode, 0, blob); err != nil {
		t.Fatalf("write blob.bin: %v", err)
	}

	res, err := publish.Seal(ctx, s.sealOpts(t, s.res, dek, idKey))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sb := res.Superblock
	if err := sb.Verify(s.pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if sb.CatalogKeyID != 7 {
		t.Fatalf("CatalogKeyID = %d, want 7", sb.CatalogKeyID)
	}
	if len(sb.KeyTable) != 2 {
		t.Fatalf("key table = %+v", sb.KeyTable)
	}
	// Without the DEK the sealed catalogs do not even open.
	if _, err := genfs.Open(ctx, genfs.Options{
		Inner: s.inner, SB: sb, CacheDir: t.TempDir(),
	}); err == nil {
		t.Fatalf("sealed encrypted generation opened without the DEK")
	}
	sealed := openGenfs(t, s.inner, sb, dek)
	got := snapshot(t, sealed)
	compareViews(t, snapshot(t, ov), got)
	if !bytes.Equal(got["/blob.bin"].content, blob) {
		t.Errorf("blob.bin did not round-trip through the DEK")
	}
	if !bytes.Equal(got["/mod.txt"].content, secret) {
		t.Errorf("mod.txt = %q", got["/mod.txt"].content)
	}
	if got["/keep.txt"].inode != s.ino["keep.txt"] {
		t.Errorf("keep.txt inode %d, base had %d", got["/keep.txt"].inode, s.ino["keep.txt"])
	}
	// Nothing from the base was re-chunked into new packs.
	if res.Stats.ChunksDeduped != s.res.Stats.ChunksAdded {
		t.Errorf("deduped %d chunks, want the base's %d", res.Stats.ChunksDeduped, s.res.Stats.ChunksAdded)
	}
	if want := chunkCount(t, blob); res.Stats.ChunksAdded != want {
		t.Errorf("added %d chunks, want %d", res.Stats.ChunksAdded, want)
	}
}

func TestSealRequiresOverlayAndPrev(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish.Seal(ctx, publish.Options{Inner: newInner(t), SpoolDir: t.TempDir(), SigningKey: priv}); err == nil {
		t.Fatalf("Seal without an overlay succeeded")
	}
	s := newSealBase(t, "5e41c0de-0004-4002-8003-a0b0c0d0e0f0", nil, nil)
	_, err = publish.Seal(ctx, publish.Options{
		Overlay: s.ov, Inner: s.inner, SpoolDir: t.TempDir(), SigningKey: s.priv,
	})
	if err == nil {
		t.Fatalf("Seal without Prev succeeded")
	}
	_, err = publish.Publish(ctx, publish.Options{
		CutPath: "cut.db", Overlay: s.ov, Inner: s.inner, SpoolDir: t.TempDir(), SigningKey: s.priv,
	})
	if err == nil {
		t.Fatalf("Publish with both CutPath and Overlay succeeded")
	}
}

// A volume must be creatable without JuiceFS: InitVolume writes
// generation 0 with an empty root, and the catalog-native write path
// takes it from there.
func TestInitVolumeThenSeal(t *testing.T) {
	ctx := context.Background()
	inner := newInner(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	volID := [16]byte{0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
		0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}

	gen0, err := publish.InitVolume(ctx, publish.Options{
		Inner:      inner,
		SpoolDir:   t.TempDir(),
		SigningKey: priv,
		VolumeID:   volID,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	if gen0.Superblock.Generation != 0 || gen0.Superblock.VolumeID != volID {
		t.Fatalf("generation %d volume %x, want 0 and %x",
			gen0.Superblock.Generation, gen0.Superblock.VolumeID, volID)
	}

	// The empty volume opens and is genuinely empty.
	base := openGenfs(t, inner, gen0.Superblock, nil)
	entries, err := base.Readdir(ctx, genfs.RootInode)
	if err != nil {
		t.Fatalf("readdir of a fresh volume: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("fresh volume has %d entries, want 0: %+v", len(entries), entries)
	}

	// Write into it through the phase-3 path and seal: a complete volume
	// lifecycle with no JuiceFS anywhere.
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ov.Close() //nolint:errcheck
	if _, err := ov.Mkdir(ctx, 1, "d", 0755, 0, 0); err != nil {
		t.Fatal(err)
	}
	fn, err := ov.Create(ctx, 1, "hello.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, fn.Inode, 0, []byte("born catalog-native")); err != nil {
		t.Fatal(err)
	}
	gen1, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: inner, SpoolDir: t.TempDir(),
		SigningKey: priv, Prev: gen0.Superblock, PrevRaw: gen0.Raw,
	})
	if err != nil {
		t.Fatalf("Seal onto a fresh volume: %v", err)
	}

	sealed := openGenfs(t, inner, gen1.Superblock, nil)
	n, err := sealed.Lookup(ctx, genfs.RootInode, "hello.txt")
	if err != nil {
		t.Fatalf("lookup in the sealed volume: %v", err)
	}
	got := make([]byte, n.Length)
	if _, err := sealed.Read(ctx, n.Inode, 0, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "born catalog-native" {
		t.Fatalf("content = %q", got)
	}
	if _, err := sealed.Lookup(ctx, genfs.RootInode, "d"); err != nil {
		t.Fatalf("lookup of the created directory: %v", err)
	}
}
