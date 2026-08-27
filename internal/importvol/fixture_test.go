package importvol_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/importvol"
	"github.com/bbockelm/pelfs/internal/inodemap"
	"github.com/bbockelm/pelfs/internal/manifest"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// bed is two INDEPENDENT volumes on one origin — the shape an import
// needs and the shape two volumes that have never met actually have.
// Distinct prefixes, distinct volume ids, distinct signing keys, distinct
// state directories.
type bed struct {
	t      testing.TB
	root   string
	srcObj pelicanobj.Store
	dstObj pelicanobj.Store
	src    *testvol.Volume
	dst    *testvol.Volume
}

func newBed(t testing.TB) *bed {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	store := func(prefix string) pelicanobj.Store {
		s, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/" + prefix})
		if err != nil {
			t.Fatalf("pelicanobj.New(%s): %v", prefix, err)
		}
		return s
	}
	b := &bed{t: t, root: root, srcObj: store("theirs"), dstObj: store("ours")}
	b.src = testvol.New(t, b.srcObj, testvol.Options{
		VolumeID: testvol.ParseUUID(t, "11111111-1111-1111-1111-111111111111"),
	})
	b.dst = testvol.New(t, b.dstObj, testvol.Options{
		VolumeID: testvol.ParseUUID(t, "22222222-2222-2222-2222-222222222222"),
	})
	return b
}

// coldOpen reads a published generation the way a reader who has never
// seen this volume does: a fresh cache directory, so nothing is answered
// out of a cache the publish warmed.
func coldOpen(t testing.TB, inner pelicanobj.Store, sb *superblock.Superblock) *genfs.FS {
	t.Helper()
	fs, err := genfs.Open(context.Background(), genfs.Options{
		Inner: inner, SB: sb, CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("genfs.Open: %v", err)
	}
	t.Cleanup(func() { fs.Close() }) //nolint:errcheck
	return fs
}

// headOf reads a branch head back through a refs store with a fresh state
// directory — the TOFU path a second machine takes.
func headOf(t testing.TB, inner pelicanobj.Store, branch string) *refs.Fetched {
	t.Helper()
	rs, err := refs.New(inner, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("refs.New: %v", err)
	}
	f, err := rs.Fetch(context.Background(), branch)
	if err != nil {
		t.Fatalf("fetch %s: %v", branch, err)
	}
	return f
}

func packsOf(t testing.TB, inner pelicanobj.Store, sb *superblock.Superblock) []superblock.PackEntry {
	t.Helper()
	packs, err := manifest.Packs(context.Background(), inner, sb)
	if err != nil {
		t.Fatalf("manifest.Packs: %v", err)
	}
	return packs
}

// importOptions are the knobs a test varies; everything else is what the
// command does.
type importOptions struct {
	Path     string
	Replace  bool
	Branch   string
	StateDir string
	// DstStore overrides where packs are written, for the interruption
	// test's failing store.
	DstStore pelicanobj.Store
	// SkipPublish stops after the copy, for a test about what the copy
	// alone leaves behind.
	SkipPublish bool
}

type importResult struct {
	Scan  *importvol.Scan
	Copy  *importvol.CopyResult
	Map   *inodemap.Map
	Entry superblock.ImportEntry
	Pub   *publish.Result
}

// runImport is the command's body without the command: scan, draw, copy,
// splice, publish. A test that drove the CLI would be testing argument
// parsing; this drives the machinery.
func (b *bed) runImport(o importOptions) (*importResult, error) {
	b.t.Helper()
	ctx := context.Background()
	if o.Branch == "" {
		o.Branch = "main"
	}
	spool := o.StateDir
	if spool == "" {
		spool = b.t.TempDir()
	}
	dstObj := o.DstStore
	if dstObj == nil {
		dstObj = b.dstObj
	}

	srcSB := b.src.Superblock()
	srcFS := coldOpen(b.t, b.srcObj, srcSB)
	dstSB := b.dst.Superblock()

	if _, err := importvol.CheckCustody(srcSB, dstSB, nil); err != nil {
		return nil, err
	}
	scan, err := importvol.Walk(ctx, importvol.ScanOptions{
		FS: srcFS, SB: srcSB, SpoolDir: spool, SortBytes: 1 << 16,
	})
	if err != nil {
		return nil, err
	}
	defer scan.Wants.Close() //nolint:errcheck

	taken := dstSB.TakenLineages()
	m, err := inodemap.DrawFor(scan.Lineages, inodemap.TakenIn(taken))
	if err != nil {
		return nil, err
	}
	res := &importResult{Scan: scan, Map: m}

	base := coldOpen(b.t, b.dstObj, dstSB)
	if _, err := publish.ImportPreflight(ctx, publish.ImportSpliceOptions{
		Base: base, Prev: dstSB, Mount: o.Path, Replace: o.Replace,
	}); err != nil {
		return nil, err
	}

	ckpt, err := importvol.OpenCheckpoint(
		importvol.CheckpointPath(spool, o.Path, "theirs"),
		importvol.Header{
			SourceVolumeID: srcSB.VolumeID, SourceGeneration: srcSB.Generation,
			SourceHash: superblock.Hash(b.src.Raw()), Path: o.Path, TargetPackSize: 512 << 10,
		})
	if err != nil {
		return nil, err
	}
	defer ckpt.Close() //nolint:errcheck
	cp, err := importvol.Copy(ctx, importvol.CopyOptions{
		Src: b.srcObj, SrcPacks: packsOf(b.t, b.srcObj, srcSB), Dst: dstObj,
		SpoolDir: filepath.Join(spool, "spool"), Wants: scan.Wants,
		TargetPackSize: 512 << 10, Checkpoint: ckpt,
	})
	if err != nil {
		return nil, err
	}
	res.Copy = cp
	if o.SkipPublish {
		return res, nil
	}

	splice, err := publish.NewImportSpliceSource(ctx, publish.ImportSpliceOptions{
		Base: base, Prev: dstSB, Src: srcFS, Map: m, SourceMark: srcSB.NextInode,
		Mount: o.Path, Replace: o.Replace,
		Packs: cp.Packs, Entries: cp.Entries,
	})
	if err != nil {
		return nil, err
	}
	entry := superblock.ImportEntry{
		Path: splice.Mount(), Source: "theirs", SourceBranch: "main",
		SourceVolumeID: srcSB.VolumeID, SourceGeneration: srcSB.Generation,
		SourceHash: superblock.Hash(b.src.Raw()), SourcePub: srcSB.SigningPub,
		ImportedUnixNano: 1, Lineages: m.Pairs(),
		Files: scan.Files, Inodes: scan.Inodes, Bytes: scan.Bytes,
	}
	res.Entry = entry
	pub, err := publish.Publish(ctx, publish.Options{
		Source: splice, Inner: dstObj, SpoolDir: spool, Branch: o.Branch,
		SigningKey: b.dst.SigningKey(), Prev: dstSB, PrevRaw: b.dst.Raw(),
		Imports: append(append([]superblock.ImportEntry(nil), dstSB.Imports...), entry),
	})
	if err != nil {
		return nil, err
	}
	res.Pub = pub
	b.dst.Adopt(pub.Superblock, pub.Raw)
	if err := ckpt.Remove(); err != nil {
		return nil, err
	}
	return res, nil
}

// tree is a whole filesystem read back as comparable text: one line per
// path, carrying everything an import claims to preserve.
func tree(t testing.TB, fs *genfs.FS, root uint64, prefix string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ctx := context.Background()
	var walk func(ino uint64, pth string)
	walk = func(ino uint64, pth string) {
		des, err := fs.ReaddirRetain(ctx, ino)
		if err != nil {
			t.Fatalf("readdir %s: %v", pth, err)
		}
		for _, de := range des {
			child := pth + "/" + de.Name
			n := de.Node
			line := fmt.Sprintf("type=%d mode=%o uid=%d gid=%d nlink=%d len=%d rdev=%d mtime=%d",
				n.Type, n.Mode, n.UID, n.GID, n.Nlink, n.Length, n.Rdev, n.MtimeNS)
			switch n.Type {
			case 3: // symlink
				tgt, err := fs.Readlink(ctx, n.Inode)
				if err != nil {
					t.Fatalf("readlink %s: %v", child, err)
				}
				line += " -> " + tgt
			case 1: // file
				if n.Length > 0 {
					buf := make([]byte, n.Length)
					if _, err := fs.Read(ctx, n.Inode, 0, buf); err != nil {
						t.Fatalf("read %s: %v", child, err)
					}
					line += fmt.Sprintf(" body=%x", buf)
				}
			}
			names, err := fs.ListXattr(ctx, n.Inode)
			if err != nil {
				t.Fatalf("listxattr %s: %v", child, err)
			}
			for _, name := range names {
				v, err := fs.GetXattr(ctx, n.Inode, name)
				if err != nil {
					t.Fatalf("getxattr %s %s: %v", child, name, err)
				}
				line += fmt.Sprintf(" xattr[%s]=%x", name, v)
			}
			out[prefix+child] = line
			if n.Type == 2 { // directory
				walk(n.Inode, child)
			}
		}
	}
	walk(root, "")
	return out
}

// inodesByPath is the same walk reporting only inode numbers, which is
// what a renumbering test compares.
func inodesByPath(t testing.TB, fs *genfs.FS, root uint64) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	ctx := context.Background()
	var walk func(ino uint64, pth string)
	walk = func(ino uint64, pth string) {
		des, err := fs.ReaddirRetain(ctx, ino)
		if err != nil {
			t.Fatalf("readdir %s: %v", pth, err)
		}
		for _, de := range des {
			child := pth + "/" + de.Name
			out[child] = de.Node.Inode
			if de.Node.Type == 2 {
				walk(de.Node.Inode, child)
			}
		}
	}
	walk(root, "")
	return out
}

// lookupPath resolves a slash path through a genfs.
func lookupPath(t testing.TB, fs *genfs.FS, p string) genfs.Node {
	t.Helper()
	n, err := fs.LookupPath(context.Background(), p)
	if err != nil {
		t.Fatalf("lookup %s: %v", p, err)
	}
	return n
}

// newKey mints a signing key for a test that needs a second one.
func newKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
