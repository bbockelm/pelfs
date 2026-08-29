package importvol_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/importvol"
	"github.com/bbockelm/pelfs/internal/inodemap"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/refs"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// bigBody is comfortably past the inline threshold, so the file is
// chunked and its bytes are in a pack — which is the case an import has
// to carry and the inline case does not.
//
// IT HAS TO BE INCOMPRESSIBLE, which cost an afternoon to notice. A body
// with any pattern in it deflates to a few hundred STORED bytes, and a
// test that thinks it is cutting six two-megabyte packs is in fact
// cutting one — so the pack-boundary and interruption tests pass by
// never reaching the case they are about. A counter-based ChaCha8 stream
// is deterministic for a given seed and does not compress.
func bigBody(seed byte, n int) []byte {
	var key [32]byte
	key[0] = seed
	r := rand.NewChaCha8(key)
	b := make([]byte, n)
	if _, err := r.Read(b); err != nil {
		panic(err)
	}
	return b
}

// populate builds the source tree: every shape an import claims to
// preserve exactly.
func populate(t testing.TB, v *testvol.Volume) {
	t.Helper()
	dir := v.Mkdir(testvol.RootInode, "dir")
	sub := v.Mkdir(dir, "sub")
	big := v.WriteFile(sub, "big.bin", bigBody(0x5a, 3<<20))
	v.WriteFile(sub, "small.txt", []byte("inline body"))
	empty := v.Create(sub, "empty")
	_ = empty
	v.Symlink(dir, "link", "sub/big.bin")
	// A HARDLINK: two names, one inode, nlink 2 — the case that lives in
	// an inode shard and the one a renumbering can silently break.
	v.Link(big, dir, "big-again")
	v.SetXattr(big, "user.checksum", []byte("abc123"))
	v.SetXattr(dir, "user.owner", []byte("brian"))
	v.Chmod(dir, 0750)
	v.Chown(sub, 4242, 4343)
	v.Chmod(sub, 0705)
}

func TestAnImportedTreeIsTheSourceTreeExactly(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})

	res, err := b.runImport(importOptions{Path: "/imported"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	// Read BOTH sides cold: a fresh cache directory, so nothing is
	// answered out of a cache either publish warmed.
	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpen(t, b.dstObj, head.Superblock)

	want := tree(t, srcFS, genfs.RootInode, "")
	root := lookupPath(t, dstFS, "/imported")
	got := tree(t, dstFS, root.Inode, "")
	if len(want) == 0 {
		t.Fatal("the source tree is empty; the fixture built nothing")
	}
	for _, p := range slices.Sorted(maps.Keys(want)) {
		if got[p] != want[p] {
			t.Errorf("%s:\n  source      %s\n  imported    %s", p, want[p], got[p])
		}
	}
	for _, p := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[p]; !ok {
			t.Errorf("%s is in the imported tree and not in the source", p)
		}
	}
	t.Logf("EVIDENCE: %d paths compared exactly — type, mode, uid, gid, nlink, length, rdev, "+
		"mtime, symlink target, xattrs and file bodies — through a COLD read of each side",
		len(want))

	// The directory the tree landed at is the SOURCE ROOT, with its
	// attributes, which is the fidelity a graft cannot give.
	srcRoot, err := srcFS.GetAttr(context.Background(), genfs.RootInode)
	if err != nil {
		t.Fatal(err)
	}
	if root.Mode != srcRoot.Mode || root.UID != srcRoot.UID || root.GID != srcRoot.GID {
		t.Errorf("/imported is mode %o uid %d gid %d; the source root is mode %o uid %d gid %d",
			root.Mode, root.UID, root.GID, srcRoot.Mode, srcRoot.UID, srcRoot.GID)
	}
	_ = res
}

func TestEveryImportedInodeIsRenumberedIntoALineageThisVolumeDrew(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	before := b.dst.Superblock().TakenLineages()

	res, err := b.runImport(importOptions{Path: "/imported"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpen(t, b.dstObj, head.Superblock)
	srcInos := inodesByPath(t, srcFS, genfs.RootInode)
	root := lookupPath(t, dstFS, "/imported")
	dstInos := inodesByPath(t, dstFS, root.Inode)

	drawn := map[uint32]bool{}
	for _, l := range res.Map.Destinations() {
		if before[l] {
			t.Fatalf("lineage %d was already taken by this volume and was drawn anyway", l)
		}
		drawn[l] = true
	}
	seen := map[uint64]string{}
	for _, p := range slices.Sorted(maps.Keys(srcInos)) {
		src, dst := srcInos[p], dstInos[p]
		if dst == 0 {
			t.Fatalf("%s is not in the imported tree", p)
		}
		if !drawn[superblock.LineageOf(dst)] {
			t.Errorf("%s is inode %d, in lineage %d, which this import did not draw",
				p, dst, superblock.LineageOf(dst))
		}
		if other, dup := seen[dst]; dup && other != p {
			// Two paths sharing one inode is legal ONLY for a hardlink,
			// which the source must also share.
			if srcInos[other] != src {
				t.Errorf("%s and %s collapsed onto inode %d but are different inodes in the source",
					other, p, dst)
			}
		}
		seen[dst] = p
		if int64(dst) < 0 {
			t.Errorf("%s is inode %d, which round-trips through int64 as %d", p, dst, int64(dst))
		}
	}
	t.Logf("EVIDENCE: %d paths, %d distinct inodes, all inside the %d lineage(s) this import drew "+
		"(%v), none of which this volume held before", len(srcInos), len(seen),
		len(drawn), res.Map.Destinations())

	// And the source's own numbers are gone: the root is the clearest
	// case, since both volumes call theirs inode 1.
	if root.Inode == genfs.RootInode {
		t.Fatal("the imported root kept the source's inode 1")
	}
}

func TestAHardlinkStillSharesOneInodeAfterTheRemap(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	if _, err := b.runImport(importOptions{Path: "/imported"}); err != nil {
		t.Fatalf("import: %v", err)
	}
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpen(t, b.dstObj, head.Superblock)

	a := lookupPath(t, dstFS, "/imported/dir/sub/big.bin")
	c := lookupPath(t, dstFS, "/imported/dir/big-again")
	if a.Inode != c.Inode {
		t.Fatalf("the two links are inodes %d and %d; the hardlink did not survive the remap",
			a.Inode, c.Inode)
	}
	if a.Nlink != 2 {
		t.Errorf("nlink is %d, want 2", a.Nlink)
	}
	// The content records of a promoted inode live in an inode SHARD, and
	// the shards are rebuilt whole from the walk — so the real check is
	// that the bytes come back through both names.
	body := bigBody(0x5a, 3<<20)
	for _, p := range []string{"/imported/dir/sub/big.bin", "/imported/dir/big-again"} {
		n := lookupPath(t, dstFS, p)
		buf := make([]byte, n.Length)
		if _, err := dstFS.Read(context.Background(), n.Inode, 0, buf); err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if !bytes.Equal(buf, body) {
			t.Fatalf("%s reads back wrong", p)
		}
	}
	var shards int
	for _, sh := range head.Superblock.Shards {
		if sh.FirstInode <= a.Inode && a.Inode <= sh.LastInode {
			shards++
		}
	}
	if shards != 1 {
		t.Fatalf("inode %d is covered by %d shards, want exactly 1", a.Inode, shards)
	}
	t.Logf("EVIDENCE: both names resolve to inode %d with nlink 2, its content records are in "+
		"exactly one inode shard, and 3 MiB reads back identically through each name", a.Inode)
}

// TestTheVolumesOwnTreeIsUntouched is the splice half: everything the
// destination already served must survive an import bit for bit.
func TestTheVolumesOwnTreeIsUntouched(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})

	mine := b.dst.Mkdir(testvol.RootInode, "mine")
	b.dst.WriteFile(mine, "keep.bin", bigBody(0x11, 2<<20))
	b.dst.WriteFile(testvol.RootInode, "top.txt", []byte("top"))
	b.dst.Publish(publish.Options{})

	beforeFS := coldOpen(t, b.dstObj, b.dst.Superblock())
	before := tree(t, beforeFS, genfs.RootInode, "")
	beforeInos := inodesByPath(t, beforeFS, genfs.RootInode)

	if _, err := b.runImport(importOptions{Path: "/imported"}); err != nil {
		t.Fatalf("import: %v", err)
	}
	head := headOf(t, b.dstObj, "main")
	afterFS := coldOpen(t, b.dstObj, head.Superblock)
	after := tree(t, afterFS, genfs.RootInode, "")
	afterInos := inodesByPath(t, afterFS, genfs.RootInode)

	for _, p := range slices.Sorted(maps.Keys(before)) {
		if after[p] != before[p] {
			t.Errorf("%s changed:\n  before %s\n  after  %s", p, before[p], after[p])
		}
		if afterInos[p] != beforeInos[p] {
			t.Errorf("%s was inode %d and is now %d", p, beforeInos[p], afterInos[p])
		}
	}
	if _, ok := after["/imported"]; !ok {
		t.Fatal("the imported tree is not in the namespace")
	}
	t.Logf("EVIDENCE: %d pre-existing paths kept their attributes AND their inode numbers across "+
		"the import", len(before))
}

func TestTheSuperblockRecordsTheImportAndItsLineages(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	res, err := b.runImport(importOptions{Path: "/imported"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	head := headOf(t, b.dstObj, "main")
	if len(head.Superblock.Imports) != 1 {
		t.Fatalf("the head records %d imports, want 1", len(head.Superblock.Imports))
	}
	got := head.Superblock.Imports[0]
	if got.SourceVolumeID != b.src.Superblock().VolumeID {
		t.Errorf("recorded source volume %x, want %x", got.SourceVolumeID[:4],
			b.src.Superblock().VolumeID[:4])
	}
	if got.SourceGeneration != b.src.Superblock().Generation {
		t.Errorf("recorded generation %d, want %d", got.SourceGeneration,
			b.src.Superblock().Generation)
	}
	if got.SourceHash != superblock.Hash(b.src.Raw()) {
		t.Error("the recorded source hash is not the source head's wire hash")
	}
	if len(got.Lineages) != res.Map.Len() {
		t.Fatalf("recorded %d lineage rows, want %d", len(got.Lineages), res.Map.Len())
	}
	// And the claim is honoured: TakenLineages now names every drawn one,
	// which is what stops a later branch drawing it.
	taken := head.Superblock.TakenLineages()
	for _, l := range res.Map.Destinations() {
		if !taken[l] {
			t.Errorf("lineage %d was drawn by the import and is not in TakenLineages", l)
		}
	}
	t.Logf("EVIDENCE: the head names source volume %x generation %d, and claims lineages %v",
		got.SourceVolumeID[:4], got.SourceGeneration, res.Map.Destinations())
}

// TestALaterSealCarriesTheLineageClaimForward is the failure with the
// long fuse: an ordinary checkpoint that restated the import list as
// empty would release lineages the tree is still using.
func TestALaterSealCarriesTheLineageClaimForward(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	res, err := b.runImport(importOptions{Path: "/imported"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// An ordinary write and seal, stating nothing about imports.
	b.dst.Lookup(testvol.RootInode, "imported")
	b.dst.WriteFile(testvol.RootInode, "afterwards.txt", []byte("hello"))
	b.dst.Publish(publish.Options{})

	head := headOf(t, b.dstObj, "main")
	if len(head.Superblock.Imports) != 1 {
		t.Fatalf("after an ordinary seal the head records %d imports, want 1",
			len(head.Superblock.Imports))
	}
	taken := head.Superblock.TakenLineages()
	for _, l := range res.Map.Destinations() {
		if !taken[l] {
			t.Fatalf("lineage %d was released by an ordinary seal", l)
		}
	}
	t.Logf("EVIDENCE: a seal that stated nothing about imports still carries the claim on %v",
		res.Map.Destinations())
}

func TestTheAllocatorMarkIsAboveEveryImportedInode(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	if _, err := b.runImport(importOptions{Path: "/imported"}); err != nil {
		t.Fatalf("import: %v", err)
	}
	head := headOf(t, b.dstObj, "main")
	fs := coldOpen(t, b.dstObj, head.Superblock)
	root := lookupPath(t, fs, "/imported")
	inos := inodesByPath(t, fs, root.Inode)
	var highest uint64
	for _, ino := range inos {
		if ino > highest {
			highest = ino
		}
	}
	if root.Inode > highest {
		highest = root.Inode
	}
	// The mark is a single number over disjoint slices, so what it has to
	// clear is the highest number this generation used anywhere — and it
	// must also be at or above the source's own mark renumbered, so that
	// a number the source burned on a deleted file is never handed out
	// here.
	if head.Superblock.NextInode <= highest {
		t.Fatalf("the allocator mark is %d and the tree holds inode %d", head.Superblock.NextInode, highest)
	}
	t.Logf("EVIDENCE: the mark is %d, above the highest imported inode %d", head.Superblock.NextInode, highest)
}

// ---- the collision matrix ----

func TestTheCollisionMatrixAtTheDestinationPath(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, b *bed)
		path    string
		replace bool
		wantErr error
		want    publish.ImportPlacement
	}{
		{
			name: "nothing is there",
			path: "/imported",
			want: publish.ImportPlaceNew,
		},
		{
			name: "an empty directory is adopted without a flag",
			prepare: func(t *testing.T, b *bed) {
				b.dst.Mkdir(testvol.RootInode, "imported")
				b.dst.Publish(publish.Options{})
			},
			path: "/imported",
			want: publish.ImportPlaceEmptyDir,
		},
		{
			name: "a populated directory is refused",
			prepare: func(t *testing.T, b *bed) {
				d := b.dst.Mkdir(testvol.RootInode, "imported")
				b.dst.WriteFile(d, "theirs.txt", []byte("mine"))
				b.dst.Publish(publish.Options{})
			},
			path:    "/imported",
			wantErr: publish.ErrImportPathNotEmpty,
		},
		{
			name: "a populated directory is replaced when asked",
			prepare: func(t *testing.T, b *bed) {
				d := b.dst.Mkdir(testvol.RootInode, "imported")
				b.dst.WriteFile(d, "theirs.txt", []byte("mine"))
				b.dst.Publish(publish.Options{})
			},
			path:    "/imported",
			replace: true,
			want:    publish.ImportPlaceReplacedDir,
		},
		{
			name: "a file at the path is refused",
			prepare: func(t *testing.T, b *bed) {
				b.dst.WriteFile(testvol.RootInode, "imported", []byte("a file"))
				b.dst.Publish(publish.Options{})
			},
			path:    "/imported",
			wantErr: publish.ErrImportPathOccupied,
		},
		{
			name: "a file at the path is replaced when asked",
			prepare: func(t *testing.T, b *bed) {
				b.dst.WriteFile(testvol.RootInode, "imported", []byte("a file"))
				b.dst.Publish(publish.Options{})
			},
			path:    "/imported",
			replace: true,
			want:    publish.ImportPlaceReplacedFile,
		},
		{
			name: "a file on the way to the path is refused",
			prepare: func(t *testing.T, b *bed) {
				b.dst.WriteFile(testvol.RootInode, "a", []byte("a file"))
				b.dst.Publish(publish.Options{})
			},
			path:    "/a/b/imported",
			wantErr: publish.ErrImportPathNotDir,
		},
		{
			name:    "the volume root is refused",
			path:    "/",
			wantErr: publish.ErrImportRootPath,
		},
		{
			name: "directories on the way are created",
			path: "/deep/deeper/imported",
			want: publish.ImportPlaceNew,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBed(t)
			populate(t, b.src)
			b.src.Publish(publish.Options{})
			if tc.prepare != nil {
				tc.prepare(t, b)
			}
			res, err := b.runImport(importOptions{Path: tc.path, Replace: tc.replace})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got error %v, want %v", err, tc.wantErr)
				}
				t.Logf("refused: %v", err)
				// AND THE BRANCH DID NOT MOVE.
				head := headOf(t, b.dstObj, "main")
				if head.Superblock.Generation != b.dst.Superblock().Generation {
					t.Fatalf("a refused import moved the branch to generation %d",
						head.Superblock.Generation)
				}
				return
			}
			if err != nil {
				t.Fatalf("import: %v", err)
			}
			_ = res
			head := headOf(t, b.dstObj, "main")
			fs := coldOpen(t, b.dstObj, head.Superblock)
			n := lookupPath(t, fs, tc.path)
			if n.Type != 2 {
				t.Fatalf("%s is type %d, want a directory", tc.path, n.Type)
			}
			// Whatever was there is gone, and what is there is the source.
			srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
			want := tree(t, srcFS, genfs.RootInode, "")
			got := tree(t, fs, n.Inode, "")
			if len(got) != len(want) {
				t.Fatalf("%s holds %d paths, the source holds %d", tc.path, len(got), len(want))
			}
			for p, line := range want {
				if got[p] != line {
					t.Errorf("%s%s differs", tc.path, p)
				}
			}
		})
	}
}

func TestImportingIntoOrOverAGraftIsRefusedByName(t *testing.T) {
	// A graft entry is enough to exercise both refusals: they are decided
	// from the superblock's graft list, before anything is read.
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	prev := b.dst.Superblock()
	withGraft := *prev
	withGraft.Grafts = []superblock.GraftEntry{{Path: "/ext", Source: "https://example/x", Block: 1 << 20}}

	base := coldOpen(t, b.dstObj, prev)
	for _, tc := range []struct {
		path string
		want error
	}{
		{"/ext/inside", publish.ErrImportIntoGraft},
		{"/ext", publish.ErrImportIntoGraft},
		{"/", publish.ErrImportRootPath},
	} {
		_, err := publish.ImportPreflight(context.Background(), publish.ImportSpliceOptions{
			Base: base, Prev: &withGraft, Mount: tc.path,
		})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.path, err, tc.want)
		} else {
			t.Logf("%s refused: %v", tc.path, err)
		}
	}
	// A path that CONTAINS the graft.
	_, err := publish.ImportPreflight(context.Background(), publish.ImportSpliceOptions{
		Base: base, Prev: &withGraft, Mount: "/ext-parent",
	})
	if err != nil {
		t.Fatalf("/ext-parent does not contain /ext and was refused: %v", err)
	}
	deeper := withGraft
	deeper.Grafts = []superblock.GraftEntry{{Path: "/a/b", Source: "https://example/x"}}
	_, err = publish.ImportPreflight(context.Background(), publish.ImportSpliceOptions{
		Base: base, Prev: &deeper, Mount: "/a",
	})
	if !errors.Is(err, publish.ErrImportOverGraft) {
		t.Fatalf("importing over a graft: got %v, want %v", err, publish.ErrImportOverGraft)
	}
	t.Logf("refused: %v", err)
}

// ---- what the source may be ----

func TestAGraftedSourceIsRefused(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	sb := *b.src.Superblock()
	sb.Grafts = []superblock.GraftEntry{{Path: "/borrowed", Source: "https://example/x"}}
	fs := coldOpen(t, b.srcObj, b.src.Superblock())
	_, err := importvol.Walk(context.Background(), importvol.ScanOptions{
		FS: fs, SB: &sb, SpoolDir: t.TempDir(),
	})
	if !errors.Is(err, importvol.ErrSourceGrafted) {
		t.Fatalf("got %v, want %v", err, importvol.ErrSourceGrafted)
	}
	t.Logf("refused: %v", err)
}

func TestTheScanFindsEveryLineageInTheTreeIncludingOnesTheSuperblockNeverNames(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	fs := coldOpen(t, b.srcObj, b.src.Superblock())
	scan, err := importvol.Walk(context.Background(), importvol.ScanOptions{
		FS: fs, SB: b.src.Superblock(), SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer scan.Wants.Close() //nolint:errcheck
	if len(scan.Lineages) == 0 {
		t.Fatal("the scan found no lineages")
	}
	if scan.Files == 0 || scan.Dirs == 0 || scan.Symlinks == 0 || scan.Hardlinks == 0 {
		t.Fatalf("the scan counted files=%d dirs=%d symlinks=%d hardlinks=%d; the fixture has all four",
			scan.Files, scan.Dirs, scan.Symlinks, scan.Hardlinks)
	}
	if scan.Chunks == 0 {
		t.Fatal("the scan found no chunk identities for a tree with a 3 MiB file in it")
	}
	t.Logf("EVIDENCE: %d inodes (%d dirs, %d files, %d symlinks, %d hardlinked), %d bytes, "+
		"%d distinct chunk identities named %d times, lineages %v",
		scan.Inodes, scan.Dirs, scan.Files, scan.Symlinks, scan.Hardlinks, scan.Bytes,
		scan.Chunks, scan.ChunkRefs, scan.Lineages)
}

// TestTheSuperblockUndercountsTheLineagesInTheTree is the fact that makes
// `pelfs import` WALK the source's catalogs rather than read the source's
// superblock — measured on a real volume rather than argued.
//
// The fixture is the ordinary shape of a volume with history: branch it,
// publish, branch it again. That leaves three kinds of file in the head's
// tree — one from before any fork (lineage 0), one from the middle branch
// (lineage 1234), one from the head branch (lineage 5678) — and the
// middle branch's file is still there, because inheriting the base tree
// is what a fork IS.
//
// The invariant, exactly as asserted below: the lineages the TREE contains
// are a STRICT SUPERSET of the lineages the superblock reveals. Superset,
// because a superblock never names a lineage that is not in the tree;
// STRICT, because it can and does miss one that is. `Fork.Lineage` names
// what a generation allocates FROM, `Catalogs[].Inode` samples whichever
// directories happen to root a catalog, and `Shards` cover only promoted
// inodes. Nothing in the format records the set.
//
// This is why importvol.Scan.Lineages comes from a walk, and why
// inodemap.Remap refuses an inode whose lineage its map does not declare.
func TestTheSuperblockUndercountsTheLineagesInTheTree(t *testing.T) {
	const middleLineage, headLineage uint32 = 1234, 5678

	b := newBed(t)
	v := b.src

	// Before any fork: lineage 0, where every volume begins and where its
	// root inode 1 lives on every volume there has ever been.
	v.WriteFile(testvol.RootInode, "before-any-fork.txt", []byte("gen 0"))
	gen0 := v.Publish(publish.Options{})

	// Branch once, and allocate a file out of the middle branch's lineage.
	mid, midRaw := forkInto(t, v, gen0.Superblock, gen0.Raw, middleLineage, "middle", "main",
		func(v *testvol.Volume) {
			v.WriteFile(testvol.RootInode, "from-the-middle-branch.txt", []byte("middle"))
		})

	// Branch again, FROM the middle branch. The head inherits that file
	// and its inode, and starts allocating out of a third lineage. The
	// middle branch could be deleted at this point and nothing about the
	// head would change — which is precisely the trouble.
	head, _ := forkInto(t, v, mid, midRaw, headLineage, "head", "middle",
		func(v *testvol.Volume) {
			v.WriteFile(testvol.RootInode, "from-the-head-branch.txt", []byte("head"))
		})

	// What the tree ACTUALLY contains, from the walk an import runs.
	fs := coldOpen(t, b.srcObj, head)
	scan, err := importvol.Walk(context.Background(), importvol.ScanOptions{
		FS: fs, SB: head, SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("walk the source: %v", err)
	}
	defer scan.Wants.Close() //nolint:errcheck
	inTree := map[uint32]bool{}
	for _, l := range scan.Lineages {
		inTree[l] = true
	}

	// What the superblock ALONE reveals: everything a shortcut that
	// declined to walk could possibly read. TakenLineages is lineage 0,
	// the lineage this generation allocates from, and every import's
	// claim; the two fields it deliberately leaves out are added here as
	// well, so that the gap this test measures cannot be blamed on having
	// consulted too few of them.
	revealed := head.TakenLineages()
	for _, c := range head.Catalogs {
		revealed[superblock.LineageOf(c.Inode)] = true
	}
	for _, s := range head.Shards {
		revealed[superblock.LineageOf(s.FirstInode)] = true
		revealed[superblock.LineageOf(s.LastInode)] = true
	}

	revealedList := slices.Sorted(maps.Keys(revealed))
	// SUPERSET. A superblock that named a lineage the tree does not hold
	// would be a different bug: `pelfs branch` and `inodemap.Draw` read
	// these as taken, so a phantom entry costs a lineage forever, and the
	// two sets being merely incomparable is not something the walk-versus-
	// superblock argument below would still hold over.
	for _, l := range revealedList {
		if !inTree[l] {
			t.Errorf("the superblock names lineage %d, which the tree does not contain: "+
				"the two sets are incomparable rather than nested", l)
		}
	}

	// STRICT. This is the whole point of the test.
	var missing []uint32
	for _, l := range slices.Sorted(maps.Keys(inTree)) {
		if !revealed[l] {
			missing = append(missing, l)
		}
	}

	listing := &strings.Builder{}
	byPath := inodesByPath(t, fs, genfs.RootInode)
	fmt.Fprintf(listing, "\n  inode %-18d (lineage %d)  /", genfs.RootInode,
		superblock.LineageOf(genfs.RootInode))
	for _, p := range slices.Sorted(maps.Keys(byPath)) {
		fmt.Fprintf(listing, "\n  inode %-18d (lineage %d)  %s",
			byPath[p], superblock.LineageOf(byPath[p]), p)
	}

	if len(missing) == 0 {
		t.Fatalf("THE GAP THIS TEST PINS HAS CLOSED.\n"+
			"the tree actually contains lineages %v\n"+
			"the superblock alone reveals        %v\n%s\n\n"+
			"These sets are now EQUAL on a volume built to make them differ: branched into "+
			"lineage %d, published, branched again into lineage %d, with the middle branch's "+
			"file still in the head's tree.\n\n"+
			"IF THE FORMAT NOW RECORDS THE COMPLETE LINEAGE SET, this is good news and it is "+
			"worth acting on: `pelfs import` walks the source's catalogs (importvol.Walk) "+
			"ONLY because it cannot get this set from the source superblock, and it could "+
			"stop. Read the new field, delete the walk's lineage collection, and rewrite this "+
			"test as the equality it has become.\n\n"+
			"IF INSTEAD THIS FIXTURE DRIFTED — the middle branch's file is no longer in the "+
			"head's tree, or forkInto stopped producing a real fork — then the gap is still "+
			"out there and this test has merely stopped looking at it. Fix the fixture; do "+
			"not delete the test, and do NOT let it stand as licence to trust the superblock. "+
			"An import that trusted it while the gap exists would draw no destination lineage "+
			"for the undeclared one, and every inode in that lineage would go through the "+
			"renumbering untranslated — two unrelated files landing on one inode number, "+
			"which IS a hardlink, in a signed generation that mounts and reads and that "+
			"nothing downstream can tell from the truth. Silent aliasing is the one outcome "+
			"inodemap.Remap's ErrUndeclaredLineage refusal exists to prevent.",
			slices.Sorted(maps.Keys(inTree)), revealedList, listing, middleLineage, headLineage)
	}
	if !slices.Equal(missing, []uint32{middleLineage}) {
		t.Fatalf("the tree holds %v that the superblock does not name; this fixture is built to "+
			"hide exactly one lineage, %d, so anything else here means the fixture is no longer "+
			"the shape its comment describes", missing, middleLineage)
	}

	t.Logf("EVIDENCE: the superblock does NOT name lineage %d\n"+
		"the tree actually contains lineages %v\n"+
		"the superblock alone reveals        %v\n%s\n\n"+
		"So the map `pelfs import` renumbers with cannot be derived from the source's "+
		"superblock, and importvol.Walk's O(catalog bytes) walk is not an optimization "+
		"anyone forgot to make.",
		middleLineage, slices.Sorted(maps.Keys(inTree)), revealedList, listing)
}

func TestContentDedupSurvivesAnImport(t *testing.T) {
	b := newBed(t)
	body := bigBody(0x77, 3<<20)
	d := b.src.Mkdir(testvol.RootInode, "d")
	b.src.WriteFile(d, "one.bin", body)
	b.src.WriteFile(d, "two.bin", body)
	b.src.Publish(publish.Options{})

	res, err := b.runImport(importOptions{Path: "/imported"})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Scan.ChunkRefs <= res.Scan.Chunks {
		t.Fatalf("two identical 3 MiB files named %d chunk refs over %d distinct identities; "+
			"dedup did not survive", res.Scan.ChunkRefs, res.Scan.Chunks)
	}
	if uint64(res.Copy.Copied) != res.Scan.Chunks {
		t.Fatalf("copied %d entries for %d distinct identities", res.Copy.Copied, res.Scan.Chunks)
	}
	t.Logf("EVIDENCE: %d chunk references over %d distinct identities, and the copy carried "+
		"exactly %d entries — identity IS the content, so content dedup crosses volumes unchanged",
		res.Scan.ChunkRefs, res.Scan.Chunks, res.Copy.Copied)
}

// ---- interruption ----

// failingStore stops accepting writes after limit of them, which is what
// a token expiring, a full origin, or a process being killed looks like
// from inside an import. Everything else passes through, so the failure
// lands in the middle of the work rather than at its edge.
type failingStore struct {
	pelicanobj.Store
	mu     sync.Mutex
	writes int
	limit  int
}

func newFailingStore(inner pelicanobj.Store, limit int) *failingStore {
	return &failingStore{Store: inner, limit: limit}
}

func (f *failingStore) Put(ctx context.Context, key string, in io.Reader) error {
	f.mu.Lock()
	f.writes++
	n := f.writes
	f.mu.Unlock()
	if n > f.limit {
		// Wrapping context.Canceled models the case the brief is about —
		// a KILLED import — and, not incidentally, is the one failure
		// packstore's retry loop does not spend a minute of exponential
		// backoff on before giving up.
		return fmt.Errorf("the store stopped accepting writes after %d (simulated interruption): %w",
			f.limit, context.Canceled)
	}
	return f.Store.Put(ctx, key, in)
}

func TestAKilledImportLeavesTheBranchOnItsPreviousGeneration(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	mine := b.dst.Mkdir(testvol.RootInode, "mine")
	b.dst.WriteFile(mine, "keep.txt", []byte("still here"))
	b.dst.Publish(publish.Options{})

	before := b.dst.Superblock().Generation
	beforeRoot := b.dst.Superblock().RootCatalog

	dying := newFailingStore(b.dstObj, 1)
	_, err := b.runImport(importOptions{Path: "/imported", DstStore: dying})
	if err == nil {
		t.Fatal("the import succeeded against a store that stops accepting writes")
	}
	t.Logf("the import failed as it had to: %v", err)

	// THE PROPERTY: the branch is where it was, read COLD — a fresh refs
	// store with no pinned key and a fresh cache directory, so nothing
	// here is answered out of state this process warmed.
	head := headOf(t, b.dstObj, "main")
	if head.Superblock.Generation != before {
		t.Fatalf("the branch moved from generation %d to %d", before, head.Superblock.Generation)
	}
	if head.Superblock.RootCatalog != beforeRoot {
		t.Fatal("the branch's root catalog changed")
	}
	fs := coldOpen(t, b.dstObj, head.Superblock)
	n := lookupPath(t, fs, "/mine/keep.txt")
	buf := make([]byte, n.Length)
	if _, err := fs.Read(context.Background(), n.Inode, 0, buf); err != nil {
		t.Fatalf("read /mine/keep.txt: %v", err)
	}
	if string(buf) != "still here" {
		t.Fatalf("/mine/keep.txt reads %q", buf)
	}
	if _, err := fs.LookupPath(context.Background(), "/imported"); err == nil {
		t.Fatal("/imported is in the namespace after a failed import")
	}
	t.Logf("EVIDENCE: generation %d still, root catalog unchanged, the volume's own file reads "+
		"back through a cold mount, and nothing is at /imported", head.Superblock.Generation)
}

func TestAnInterruptedCopyResumesWithoutReReadingWhatItAlreadyCarried(t *testing.T) {
	b := newBed(t)
	// Several files, each past the pack cut below, so the copy writes
	// more than one pack and there is something for a resume to skip.
	d := b.src.Mkdir(testvol.RootInode, "d")
	for i := range 4 {
		b.src.WriteFile(d, fmt.Sprintf("f%d.bin", i), bigBody(byte(i), 1<<20))
	}
	b.src.Publish(publish.Options{})

	state := t.TempDir()
	// First attempt: the store gives out after a couple of packs.
	dying := newFailingStore(b.dstObj, 2)
	_, err := b.runImport(importOptions{Path: "/imported", StateDir: state, DstStore: dying, SkipPublish: true})
	if err == nil {
		t.Fatal("the copy survived a store that stops accepting writes")
	}
	t.Logf("first attempt failed as it had to: %v", err)

	// Second attempt: the same state directory, a working store.
	res, err := b.runImport(importOptions{Path: "/imported", StateDir: state})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.Copy.Resumed == 0 {
		t.Fatal("the resume carried nothing forward from the first attempt")
	}
	t.Logf("EVIDENCE: the resume recovered %d entries (%d bytes) from packs the first attempt had "+
		"already uploaded, and read %d of the source's packs instead of all of them",
		res.Copy.Resumed, res.Copy.ResumedBytes, res.Copy.SourcePacksRead)

	// And the result is correct, not merely fast.
	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpen(t, b.dstObj, head.Superblock)
	want := tree(t, srcFS, genfs.RootInode, "")
	root := lookupPath(t, dstFS, "/imported")
	got := tree(t, dstFS, root.Inode, "")
	for p, line := range want {
		if got[p] != line {
			t.Errorf("%s differs after a resumed copy", p)
		}
	}
}

func TestACheckpointForADifferentSourceGenerationIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	path := importvol.CheckpointPath(dir, "/imported", "theirs")
	hdr := importvol.Header{SourceGeneration: 7, Path: "/imported", TargetPackSize: 1 << 20}
	hdr.SourceHash = superblock.Hash([]byte("seven"))
	c, err := importvol.OpenCheckpoint(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if c.Discarded() != "" {
		t.Fatalf("a fresh checkpoint reported a discard: %s", c.Discarded())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	newer := hdr
	newer.SourceGeneration = 8
	newer.SourceHash = superblock.Hash([]byte("eight"))
	c2, err := importvol.OpenCheckpoint(path, newer)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close() //nolint:errcheck
	if c2.Discarded() == "" {
		t.Fatal("a checkpoint taken against a different source generation was resumed")
	}
	if !strings.Contains(c2.Discarded(), "generation") {
		t.Fatalf("the reason does not name what moved: %s", c2.Discarded())
	}
	t.Logf("discarded: %s", c2.Discarded())
}

// ---- encryption ----

func TestImportingAcrossAnEncryptionBoundaryIsRefusedWithTheReason(t *testing.T) {
	plain := &superblock.Superblock{}
	enc := &superblock.Superblock{
		CatalogKeyID: 1,
		KeyTable: []superblock.KeyEntry{
			{ID: 1, Kind: superblock.KeyKindDEK, Wrapped: []byte("x")},
			{ID: 2, Kind: superblock.KeyKindIdentity, Wrapped: []byte("y")},
		},
	}
	if _, err := importvol.CheckCustody(plain, plain, nil); err != nil {
		t.Fatalf("plaintext to plaintext was refused: %v", err)
	}
	for _, tc := range []struct {
		name     string
		src, dst *superblock.Superblock
	}{
		{"encrypted source into a plaintext volume", enc, plain},
		{"plaintext source into an encrypted volume", plain, enc},
		{"encrypted both ways with no key to compare them", enc, enc},
	} {
		_, err := importvol.CheckCustody(tc.src, tc.dst, nil)
		if !errors.Is(err, importvol.ErrForeignCustody) {
			t.Errorf("%s: got %v, want %v", tc.name, err, importvol.ErrForeignCustody)
			continue
		}
		t.Logf("%s refused: %v", tc.name, err)
	}
}

func TestAPlaintextImportTranslatesNoKeyIDs(t *testing.T) {
	c, err := importvol.CheckCustody(&superblock.Superblock{}, &superblock.Superblock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Translate(0); err != nil || got != 0 {
		t.Fatalf("Translate(0) = %d, %v", got, err)
	}
	if _, err := c.Translate(3); !errors.Is(err, importvol.ErrForeignCustody) {
		t.Fatalf("a chunkref naming key id 3 on a plaintext volume: got %v", err)
	}
}

// TestAnInodeInAnUndeclaredLineageIsRefusedAtTheSplice is the guard where
// it actually has to hold. The unit test in internal/inodemap proves the
// map refuses; this proves the refusal reaches the seal instead of being
// swallowed somewhere between them.
//
// The case it stands for is a source that GAINED a lineage between the
// scan and the copy — a merge landing on the source branch while the
// hours of copying ran. Passing such an inode through untranslated would
// alias it onto a number this volume may already have handed out, in a
// generation that signs and mounts.
func TestAnInodeInAnUndeclaredLineageIsRefusedAtTheSplice(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	base := coldOpen(t, b.dstObj, b.dst.Superblock())

	// A map that declares a lineage the tree does not contain, and does
	// not declare the one it does.
	blind, err := inodemap.New(map[uint32]uint32{424242: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = publish.NewImportSpliceSource(context.Background(), publish.ImportSpliceOptions{
		Base: base, Prev: b.dst.Superblock(), Src: srcFS, Map: blind, Mount: "/imported",
	})
	if !errors.Is(err, inodemap.ErrUndeclaredLineage) {
		t.Fatalf("got %v, want %v", err, inodemap.ErrUndeclaredLineage)
	}
	t.Logf("refused: %v", err)

	// And the branch is untouched, because nothing was published.
	head := headOf(t, b.dstObj, "main")
	if head.Superblock.Generation != b.dst.Superblock().Generation {
		t.Fatal("a refused splice moved the branch")
	}
}

// TestTheSourceSignatureIsCheckedBeforeAnythingIsRead pins that an import
// reads the source THROUGH the ref store, which verifies, rather than
// around it. The check is what "we imported what they published" rests
// on, and after the import their signature has nothing left to sign in
// our document.
func TestTheSourceSignatureIsCheckedBeforeAnythingIsRead(t *testing.T) {
	b := newBed(t)
	populate(t, b.src)
	b.src.Publish(publish.Options{})

	// A ref store pinned to the WRONG key: what a reader gets when
	// somebody else's volume is served under a source's name.
	rs, err := refs.New(b.srcObj, t.TempDir(), newKey(t).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Fetch(context.Background(), "main"); err == nil {
		t.Fatal("a source signed by another key was accepted")
	} else {
		t.Logf("refused: %v", err)
	}
	// The right key verifies, and is what the import proceeds from.
	right, err := refs.New(b.srcObj, t.TempDir(),
		ed25519.PublicKey(b.src.Superblock().SigningPub[:]))
	if err != nil {
		t.Fatal(err)
	}
	f, err := right.Fetch(context.Background(), "main")
	if err != nil {
		t.Fatalf("the source's own key did not verify it: %v", err)
	}
	if f.Superblock.Generation != b.src.Superblock().Generation {
		t.Fatalf("fetched generation %d, want %d", f.Superblock.Generation,
			b.src.Superblock().Generation)
	}
}

// TestAnImportIntoAnUnsignedVolumeStaysUnsigned is the interaction with
// the mode a volume is authenticated in, which `pelfs rotate` is the only
// command allowed to change.
//
// An import publishes a SUCCESSOR generation, so it must sign the way the
// head signs — and on an unsigned volume that means not signing, and in
// particular not MINTING a key. A mint here would sign the next
// generation of a volume every reader has pinned as unsigned, which stops
// verifying for all of them at once. The verb re-loads the key against
// the head it actually publishes on for exactly this reason; this pins
// that the machinery underneath it carries a nil key through.
func TestAnImportIntoAnUnsignedVolumeStaysUnsigned(t *testing.T) {
	b := newBedWith(t, testvol.Options{}, testvol.Options{Unsigned: true})
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	if !b.dst.Superblock().IsUnsigned() {
		t.Fatal("the fixture did not make an unsigned volume")
	}
	if _, err := b.runImport(importOptions{Path: "/imported"}); err != nil {
		t.Fatalf("import: %v", err)
	}
	// Read the head back the way a reader who consented to unsigned does.
	rs, err := refs.NewWithPolicy(b.dstObj, t.TempDir(), refs.Policy{AllowUnsigned: true})
	if err != nil {
		t.Fatal(err)
	}
	head, err := rs.Fetch(context.Background(), "main")
	if err != nil {
		t.Fatalf("fetch the unsigned head: %v", err)
	}
	if !head.Superblock.IsUnsigned() {
		t.Fatalf("the import signed generation %d of a volume that was unsigned, with key %x",
			head.Superblock.Generation, head.Superblock.SigningPub[:8])
	}
	fs := coldOpen(t, b.dstObj, head.Superblock)
	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	root := lookupPath(t, fs, "/imported")
	want := tree(t, srcFS, genfs.RootInode, "")
	got := tree(t, fs, root.Inode, "")
	for p, line := range want {
		if got[p] != line {
			t.Errorf("%s differs on an unsigned destination", p)
		}
	}
	t.Logf("EVIDENCE: generation %d is still unsigned (SigningPub and Signature both zero) and "+
		"serves all %d imported paths", head.Superblock.Generation, len(want))
}

// TestTheRenumberingIsABijectionOverARealVolume is the proof asked for
// over a REAL published volume rather than a table of numbers: build a
// tree of a few hundred inodes with hardlinks in it, import it, and
// compare the two namespaces path by path.
//
// Three properties, and each of them is a thing that would be silent if
// it were false:
//
//   - INJECTIVE. Two source inodes landing on one destination inode makes
//     two unrelated files into hardlinks of each other, in a generation
//     that mounts and reads. The check is a count: as many distinct
//     destination inodes as distinct source inodes.
//   - SURJECTIVE ONTO THE PATHS. Every path in the source is a path here,
//     and paths that shared an inode there share one here — which is
//     what makes the inode shards come out right.
//   - INSIDE THE SIGNED 64-BIT CEILING. The published catalogs are SQLITE
//     here, on purpose: the ceiling exists because SQLite's integers are
//     signed and an inode above 2^63 round-trips as a negative number and
//     fails to scan back. Reading the whole tree out of a SQLite catalog
//     through a COLD cache is the real form of that proof; the arithmetic
//     check beside it is the cheap one.
func TestTheRenumberingIsABijectionOverARealVolume(t *testing.T) {
	b := newBed(t)
	// A tree with enough shape to be worth measuring: nested directories,
	// files of both content shapes, symlinks, and hardlinks whose identity
	// as ONE inode is the thing a renumbering can quietly break.
	top := b.src.Mkdir(testvol.RootInode, "tree")
	var linkTargets []uint64
	for d := range 16 {
		dir := b.src.Mkdir(top, fmt.Sprintf("d%02d", d))
		sub := b.src.Mkdir(dir, "sub")
		for f := range 16 {
			name := fmt.Sprintf("f%02d.bin", f)
			var ino uint64
			if f%3 == 0 {
				ino = b.src.WriteFile(sub, name, bigBody(byte(d*16+f), 1<<16))
			} else {
				ino = b.src.WriteFile(sub, name, []byte(fmt.Sprintf("small %d/%d", d, f)))
			}
			if f == 0 {
				linkTargets = append(linkTargets, ino)
			}
		}
		b.src.Symlink(dir, "link", "sub/f00.bin")
	}
	// One hardlink per directory, all pointing back into the first one's
	// files, so the promoted set spans the tree rather than sitting in a
	// corner of it.
	for i, ino := range linkTargets {
		b.src.Link(ino, top, fmt.Sprintf("hard%02d.bin", i))
	}
	b.src.Publish(publish.Options{})

	res, err := b.runImport(importOptions{Path: "/imported", SQLiteCatalogs: true})
	if err != nil {
		t.Fatalf("import: %v", err)
	}

	srcFS := coldOpen(t, b.srcObj, b.src.Superblock())
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpen(t, b.dstObj, head.Superblock)
	srcInos := inodesByPath(t, srcFS, genfs.RootInode)
	root := lookupPath(t, dstFS, "/imported")
	dstInos := inodesByPath(t, dstFS, root.Inode)

	if len(srcInos) < 200 {
		t.Fatalf("the fixture built %d paths; this test is not worth running under 200", len(srcInos))
	}
	if len(dstInos) != len(srcInos) {
		t.Fatalf("the source has %d paths and the import has %d", len(srcInos), len(dstInos))
	}

	// The map, read off the two namespaces rather than asked of the code:
	// a renumbering is only correct if this is what a reader observes.
	observed := map[uint64]uint64{} // source inode -> destination inode
	inverse := map[uint64]uint64{}  // destination inode -> source inode
	var highest uint64
	for _, p := range slices.Sorted(maps.Keys(srcInos)) {
		src, dst := srcInos[p], dstInos[p]
		if dst == 0 {
			t.Fatalf("%s is not in the imported tree", p)
		}
		if prev, ok := observed[src]; ok && prev != dst {
			t.Fatalf("source inode %d is %d at one path and %d at another (%s) — not a function",
				src, prev, dst, p)
		}
		if prev, ok := inverse[dst]; ok && prev != src {
			t.Fatalf("NOT INJECTIVE: source inodes %d and %d both became %d (at %s)",
				prev, src, dst, p)
		}
		observed[src], inverse[dst] = dst, src
		if dst > highest {
			highest = dst
		}
		// The cheap half of the ceiling check. The expensive half is that
		// every one of these numbers was written to and read back from a
		// SQLite catalog to get here.
		if int64(dst) < 0 {
			t.Fatalf("%s is inode %d, which round-trips through int64 as %d", p, dst, int64(dst))
		}
		if !res.Map.Holds(dst) {
			t.Fatalf("%s is inode %d, which the map does not claim", p, dst)
		}
		if back, err := res.Map.Unmap(dst); err != nil || back != src {
			t.Fatalf("Unmap(%d) = %d, %v; want %d", dst, back, err, src)
		}
	}
	if len(observed) != len(inverse) {
		t.Fatalf("%d distinct source inodes mapped onto %d distinct destination inodes",
			len(observed), len(inverse))
	}
	// Hardlinks: paths that shared an inode in the source share one here.
	shared := 0
	for _, p := range slices.Sorted(maps.Keys(srcInos)) {
		for _, q := range slices.Sorted(maps.Keys(srcInos)) {
			if p < q && srcInos[p] == srcInos[q] {
				shared++
				if dstInos[p] != dstInos[q] {
					t.Fatalf("%s and %s are one inode in the source and %d/%d here",
						p, q, dstInos[p], dstInos[q])
				}
			}
		}
	}
	if shared == 0 {
		t.Fatal("the fixture produced no hardlinked pair, so this proves nothing about them")
	}
	t.Logf("EVIDENCE over a real published volume: %d paths, %d distinct source inodes onto "+
		"%d distinct destination inodes (a bijection), %d hardlinked path pairs still sharing "+
		"one inode, every number read back out of SQLite catalogs through a cold cache. The "+
		"highest inode produced is %d, which is %.4f%% of the signed 64-bit ceiling",
		len(srcInos), len(observed), len(inverse), shared, highest,
		100*float64(highest)/float64(math.MaxInt64))
}

// ---- encryption, the case that is ALLOWED ----

// encryptedPair builds two volumes encrypted under ONE data key and ONE
// identity key but with DIFFERENT key IDs, which is the shape "same
// custody" actually takes: a key id is an index into one volume's own
// table, so the same key is id 1 on one and id 5 on another.
func encryptedPair(t testing.TB) (kek *rsa.PrivateKey, dek, idKey []byte, srcTable, dstTable []superblock.KeyEntry) {
	t.Helper()
	kek, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dek, idKey = make([]byte, 32), make([]byte, 32)
	if _, err := crand.Read(dek); err != nil {
		t.Fatal(err)
	}
	if _, err := crand.Read(idKey); err != nil {
		t.Fatal(err)
	}
	wrap := func(k []byte) []byte {
		w, err := superblock.WrapKey(&kek.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	// RSA-OAEP is randomized, so each of these four wraps produces
	// different bytes for the same key — which is precisely why custody
	// cannot be decided by comparing wrapped bytes and needs the KEK.
	srcTable = []superblock.KeyEntry{
		{ID: 1, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(dek)},
		{ID: 2, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(idKey)},
	}
	dstTable = []superblock.KeyEntry{
		{ID: 5, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(dek)},
		{ID: 6, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(idKey)},
	}
	return kek, dek, idKey, srcTable, dstTable
}

// TestImportingWithinOneEncryptionDomainCopiesStoredAndTranslatesKeyIDs is
// the encrypted case an import is ALLOWED to do, end to end.
//
// The bytes are ciphertext and are carried across untouched — no data key
// is used to move them, which is the property that makes a stored copy
// safe at all. What DOES change is the key ID on every chunkref, because
// an id indexes one volume's own key table and the same key is a
// different number on each side. Getting that wrong would be silent:
// merge's sameRef deliberately ignores CLen, Alg and KeyID, so anything
// that compared refs across the boundary would call a plaintext ref and
// an encrypted ref equal.
func TestImportingWithinOneEncryptionDomainCopiesStoredAndTranslatesKeyIDs(t *testing.T) {
	kek, dek, idKey, srcTable, dstTable := encryptedPair(t)
	// The SAME data key and identity key on both sides, under DIFFERENT
	// key ids, which is what "same custody" looks like in practice.
	b := newBedWith(t,
		testvol.Options{DEK: dek, IdentityKey: idKey, KeyID: 1, KeyTable: srcTable},
		testvol.Options{DEK: dek, IdentityKey: idKey, KeyID: 5, KeyTable: dstTable})
	populate(t, b.src)
	b.src.Publish(publish.Options{})
	if !isEncryptedSB(b.src.Superblock()) || !isEncryptedSB(b.dst.Superblock()) {
		t.Fatal("the fixture did not produce two encrypted volumes")
	}

	custody, err := importvol.CheckCustody(b.src.Superblock(), b.dst.Superblock(), kek)
	if err != nil {
		t.Fatalf("two volumes under one key were refused: %v", err)
	}
	if !custody.Encrypted {
		t.Fatal("custody does not report the volumes as encrypted")
	}
	if got, err := custody.Translate(1); err != nil || got != 5 {
		t.Fatalf("Translate(1) = %d, %v; want the destination's id for the same DEK (5)", got, err)
	}
	if got, err := custody.Translate(2); err != nil || got != 6 {
		t.Fatalf("Translate(2) = %d, %v; want 6", got, err)
	}
	if _, err := custody.Translate(9); err == nil {
		t.Fatal("a chunkref naming a key id the source's table does not have was accepted")
	}

	res, err := b.runImport(importOptions{Path: "/imported", KEK: kek})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.Copy.Copied == 0 {
		t.Fatal("the copy carried nothing")
	}

	// The tree reads back through a COLD cache, with the data key, on
	// both sides — which is the whole claim: the ciphertext moved and
	// still decrypts.
	srcFS := coldOpenWithDEK(t, b.srcObj, b.src.Superblock(), dek)
	head := headOf(t, b.dstObj, "main")
	dstFS := coldOpenWithDEK(t, b.dstObj, head.Superblock, dek)
	want := tree(t, srcFS, genfs.RootInode, "")
	root := lookupPath(t, dstFS, "/imported")
	got := tree(t, dstFS, root.Inode, "")
	if len(want) == 0 {
		t.Fatal("the encrypted source tree is empty")
	}
	for _, p := range slices.Sorted(maps.Keys(want)) {
		if got[p] != want[p] {
			t.Errorf("%s:\n  source   %s\n  imported %s", p, want[p], got[p])
		}
	}

	// And every imported chunkref now names THIS volume's key id, not the
	// source's.
	big := lookupPath(t, dstFS, "/imported/dir/sub/big.bin")
	c, err := dstFS.ContentOf(context.Background(), big.Inode)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Refs) == 0 {
		t.Fatal("the imported 3 MiB file has no chunk records")
	}
	for i, ref := range c.Refs {
		if ref.KeyID != 5 {
			t.Errorf("imported chunk %d names key id %d, want this volume's 5", i, ref.KeyID)
		}
	}
	t.Logf("EVIDENCE: %d paths identical through a cold decrypting read of each side, %d entries "+
		"carried as ciphertext without a data key being used to move them, and every imported "+
		"chunkref rewritten from the source's key id 1 to this volume's 5",
		len(want), res.Copy.Copied)
}

// isEncryptedSB mirrors importvol's own test, from outside the package.
func isEncryptedSB(sb *superblock.Superblock) bool {
	for _, k := range sb.KeyTable {
		if k.Kind == superblock.KeyKindDEK {
			return true
		}
	}
	return false
}

// TestTwoVolumesUnderDIFFERENTDataKeysAreRefusedWithTheRepackItWouldTake
// is the encrypted case an import is NOT allowed to do, with real keys
// rather than a stand-in — the wrapped bytes differ every time a key is
// wrapped, so only actually unwrapping them can tell these two situations
// apart, and the refusal has to rest on that rather than on a comparison
// that would have been wrong either way.
func TestTwoVolumesUnderDIFFERENTDataKeysAreRefusedWithTheRepackItWouldTake(t *testing.T) {
	kek, dek, idKey, srcTable, _ := encryptedPair(t)
	// A second data key, wrapped under the SAME user KEK: the operator
	// holds both volumes, and they are still not one custody domain.
	otherDEK := make([]byte, 32)
	if _, err := crand.Read(otherDEK); err != nil {
		t.Fatal(err)
	}
	wrap := func(k []byte) []byte {
		w, err := superblock.WrapKey(&kek.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	src := &superblock.Superblock{CatalogKeyID: 1, KeyTable: srcTable}
	dst := &superblock.Superblock{CatalogKeyID: 5, KeyTable: []superblock.KeyEntry{
		{ID: 5, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(otherDEK)},
		{ID: 6, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(idKey)},
	}}
	_, err := importvol.CheckCustody(src, dst, kek)
	if !errors.Is(err, importvol.ErrForeignCustody) {
		t.Fatalf("got %v, want %v", err, importvol.ErrForeignCustody)
	}
	if !strings.Contains(err.Error(), "data-encryption keys") {
		t.Fatalf("the refusal does not name which key differs: %v", err)
	}
	t.Logf("refused: %v", err)

	// And the identity key alone is enough to refuse, even with one DEK:
	// identity is keyed BLAKE3 over the plaintext, so an identity means a
	// different thing under a different key and nothing here could
	// recompute it.
	otherID := make([]byte, 32)
	if _, err := crand.Read(otherID); err != nil {
		t.Fatal(err)
	}
	dst2 := &superblock.Superblock{CatalogKeyID: 5, KeyTable: []superblock.KeyEntry{
		{ID: 5, Kind: superblock.KeyKindDEK, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(dek)},
		{ID: 6, Kind: superblock.KeyKindIdentity, Alg: superblock.KeyAlgRSAOAEPSHA256, Wrapped: wrap(otherID)},
	}}
	_, err = importvol.CheckCustody(src, dst2, kek)
	if !errors.Is(err, importvol.ErrForeignCustody) {
		t.Fatalf("one DEK but two identity keys: got %v, want %v", err, importvol.ErrForeignCustody)
	}
	if !strings.Contains(err.Error(), "chunk-identity keys") {
		t.Fatalf("the refusal does not name the identity key: %v", err)
	}
	t.Logf("refused: %v", err)

	// A KEK that unwraps neither is its own refusal, and says so rather
	// than reporting a key mismatch it never established.
	stranger, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := importvol.CheckCustody(src, dst, stranger); !errors.Is(err, importvol.ErrForeignCustody) {
		t.Fatalf("a KEK that unwraps nothing: got %v", err)
	} else {
		t.Logf("refused: %v", err)
	}
}
