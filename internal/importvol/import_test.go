package importvol_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/importvol"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
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

var _ = newKey
