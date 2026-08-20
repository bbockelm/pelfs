package overlay_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
)

// readView is the read surface a seal walks. Both the live overlay and a
// snapshot of it must serve it, which is the point of the primitive.
type readView interface {
	RootInode() uint64
	NextInode() (uint64, error)
	Lookup(ctx context.Context, parent uint64, name string) (overlay.Node, error)
	GetAttr(ctx context.Context, ino uint64) (overlay.Node, error)
	Readdir(ctx context.Context, ino uint64) ([]overlay.DirEntry, error)
	Readlink(ctx context.Context, ino uint64) (string, error)
	GetXattr(ctx context.Context, ino uint64, name string) ([]byte, error)
	ListXattr(ctx context.Context, ino uint64) ([]string, error)
	AllXattrs(ctx context.Context, ino uint64) (map[string][]byte, error)
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
	OpenFile(ctx context.Context, ino uint64, length int64) (io.ReadCloser, error)
}

var (
	_ readView = (*overlay.FS)(nil)
	_ readView = (*overlay.Snapshot)(nil)
)

// snapDirs remembers each snapshot's scratch path so tests can inspect
// the staging links and the release on Close.
var snapDirs = map[*overlay.Snapshot]string{}

func takeSnapshot(t *testing.T, ov *overlay.FS) *overlay.Snapshot {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snap")
	snap, err := ov.Snapshot(context.Background(), dir)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapDirs[snap] = dir
	t.Cleanup(func() { _ = snap.Close() })
	return snap
}

// truncWrite replaces a file's whole content.
func truncWrite(ctx context.Context, ov *overlay.FS, ino uint64, data []byte) error {
	size := int64(len(data))
	if _, err := ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &size}); err != nil {
		return err
	}
	_, err := ov.Write(ctx, ino, 0, data)
	return err
}

// sealAndSwap publishes the overlay as the next generation and moves the
// served base onto it — steps 2 and 3 of Rebase's contract.
//
// The seal walks the LIVE overlay rather than the snapshot, which is
// sound here because every caller leaves the overlay untouched between
// the snapshot and the seal, so the two views are the same bytes. What
// Rebase depends on is the ORDER, and that is exercised exactly as a
// mount would run it.
func sealAndSwap(t *testing.T, fx *fixture, ov *overlay.FS) *publish.Result {
	t.Helper()
	ctx := context.Background()
	res, err := publish.Seal(ctx, publish.Options{
		Overlay:        ov,
		Inner:          fx.inner,
		SpoolDir:       t.TempDir(),
		SigningKey:     fx.key,
		Prev:           fx.head.Superblock,
		PrevRaw:        fx.head.Raw,
		TargetPackSize: 1 << 20,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := fx.base.Swap(ctx, res.Superblock); err != nil {
		t.Fatalf("Swap base onto the sealed generation: %v", err)
	}
	fx.head = res
	return res
}

func rebase(t *testing.T, ov *overlay.FS, seq uint64, res *publish.Result) *overlay.RebaseReport {
	t.Helper()
	rep, err := ov.Rebase(context.Background(), seq, overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	})
	if err != nil {
		t.Fatalf("Rebase: %v", err)
	}
	return rep
}

func mustDirty(t *testing.T, ov *overlay.FS, ino uint64, want bool, what string) {
	t.Helper()
	got, err := ov.IsDirty(ino)
	if err != nil {
		t.Fatalf("IsDirty(%d): %v", ino, err)
	}
	if got != want {
		t.Errorf("%s: IsDirty(%d) = %v, want %v", what, ino, got, want)
	}
}

func mustBody(t *testing.T, v readView, path string, want []byte) {
	t.Helper()
	n, err := lookupPathErr(v, path)
	if err != nil {
		t.Fatalf("lookup %s: %v", path, err)
	}
	if n.Length != int64(len(want)) {
		t.Fatalf("%s: length = %d, want %d", path, n.Length, len(want))
	}
	if got := readAllFS(t, v, n.Inode, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("%s: body = %q, want %q", path, trunc(got), trunc(want))
	}
}

func trunc(b []byte) string {
	if len(b) > 64 {
		return fmt.Sprintf("%q...(%d bytes)", b[:64], len(b))
	}
	return fmt.Sprintf("%q", b)
}

// TestSnapshotIsolation: every kind of mutation applied to the LIVE
// overlay after the snapshot, and the snapshot still answering with the
// instant it was taken at.
func TestSnapshotIsolation(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0001-4000-8000-000000000001")
	ov := openOverlay(t, fx, "")

	// Pre-snapshot state: a staged overlay file, a COW'd base file, and
	// clean base content that must still resolve through the snapshot.
	newN, err := ov.Create(ctx, rootIno, "new.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	staged := []byte("staged before the snapshot")
	if _, err := ov.Write(ctx, newN.Inode, 0, staged); err != nil {
		t.Fatal(err)
	}
	baseIno := lookupPath(t, ov, "base.txt").Inode
	cow := []byte("OVERWRITTEN")
	if _, err := ov.Write(ctx, baseIno, 0, cow); err != nil {
		t.Fatal(err)
	}
	wantBase := append(append([]byte{}, cow...), fx.body["base.txt"][len(cow):]...)
	bigIno := lookupPath(t, ov, "big.bin").Inode
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	leafIno := lookupPath(t, ov, "dir/inner/leaf.txt").Inode

	snap := takeSnapshot(t, ov)
	want := mergedView(t, snap)
	if len(want) == 0 {
		t.Fatal("snapshot view is empty")
	}

	// Now move everything underneath it.
	if _, err := ov.Write(ctx, newN.Inode, 0, []byte("AFTER!")); err != nil { // in-place overwrite
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, baseIno, 0, []byte("later")); err != nil { // in-place, COW'd file
		t.Fatal(err)
	}
	zero := int64(0)
	if _, err := ov.SetAttr(ctx, bigIno, overlay.SetAttrIn{Size: &zero}); err != nil { // truncate
		t.Fatal(err)
	}
	if _, err := ov.Create(ctx, rootIno, "after.txt", 0644, 0, 0); err != nil { // create
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "tagged.txt"); err != nil { // delete
		t.Fatal(err)
	}
	if err := ov.Rename(ctx, rootIno, "dir", rootIno, "pivot"); err != nil { // rename a subtree
		t.Fatal(err)
	}
	if err := ov.SetXattr(ctx, leafIno, "user.after", []byte("x")); err != nil {
		t.Fatal(err)
	}

	// The live view really moved (otherwise the assertions below are
	// vacuous), and the snapshot did not.
	if live := mergedView(t, ov); reflect.DeepEqual(live, want) {
		t.Fatal("the live view did not change; the isolation assertions would be vacuous")
	}
	if got := mergedView(t, snap); !reflect.DeepEqual(got, want) {
		for p, w := range want {
			if g := got[p]; g != w {
				t.Errorf("snapshot path %s: %s\n            want: %s", p, g, w)
			}
		}
		for p := range got {
			if _, ok := want[p]; !ok {
				t.Errorf("snapshot gained path %s", p)
			}
		}
		t.Fatal("snapshot view changed after live mutations")
	}

	// Byte-exact spot checks through the snapshot, one per mutation kind.
	mustBody(t, snap, "new.txt", staged)
	mustBody(t, snap, "base.txt", wantBase)
	mustBody(t, snap, "big.bin", fx.body["big.bin"])
	mustBody(t, snap, "dir/child.txt", fx.body["dir/child.txt"])
	if _, err := lookupPathErr(snap, "after.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("snapshot sees post-snapshot create: %v", err)
	}
	if _, err := lookupPathErr(snap, "pivot"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("snapshot sees post-snapshot rename target: %v", err)
	}
	if n, err := lookupPathErr(snap, "tagged.txt"); err != nil || n.Inode != tagIno {
		t.Errorf("snapshot lost the deleted file: %+v %v", n, err)
	}
	xs, err := snap.AllXattrs(ctx, tagIno)
	if err != nil {
		t.Fatal(err)
	}
	if string(xs["user.color"]) != "blue" || len(xs) != 2 {
		t.Errorf("snapshot xattrs = %v", xs)
	}
	if xs, err := snap.AllXattrs(ctx, leafIno); err != nil || len(xs) != 0 {
		t.Errorf("snapshot sees a post-snapshot xattr: %v %v", xs, err)
	}

	// OpenFile streams the frozen bytes too (the seal's content path).
	rc, err := snap.OpenFile(ctx, baseIno, int64(len(wantBase)))
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(rc)
	rc.Close() //nolint:errcheck
	if err != nil || !bytes.Equal(all, wantBase) {
		t.Errorf("snapshot OpenFile = %q (%v)", all, err)
	}

	if next, err := snap.NextInode(); err != nil || next == 0 {
		t.Errorf("snapshot NextInode = %d (%v)", next, err)
	}
	if snap.RootInode() != rootIno {
		t.Errorf("snapshot root = %d", snap.RootInode())
	}
}

// TestSnapshotAppendAndOverwrite proves the copy-on-write rule the lazy
// pin rests on: the freeze copies nothing, a write ABOVE the frozen
// length keeps sharing the live staging file and is invisible to the
// snapshot, and a write BELOW it hands the old file over before changing
// a byte. Both views stay right throughout.
func TestSnapshotAppendAndOverwrite(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0002-4000-8000-000000000002")
	dir := t.TempDir()
	ov := openOverlay(t, fx, dir)

	head := bytes.Repeat([]byte("A"), 4096)
	app, err := ov.Create(ctx, rootIno, "append.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, app.Inode, 0, head); err != nil {
		t.Fatal(err)
	}
	ow, err := ov.Create(ctx, rootIno, "overwrite.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, ow.Inode, 0, head); err != nil {
		t.Fatal(err)
	}

	snap := takeSnapshot(t, ov)
	// handedOver reports whether the snapshot has taken its own copy of an
	// inode yet. Everything below turns on this: a snapshot that copied
	// eagerly would answer true from the start, and its freeze would cost
	// one file operation per staged inode with the overlay locked.
	handedOver := func(ino uint64) bool {
		t.Helper()
		frozen, err := os.Stat(filepath.Join(snapDir(snap), "staging", strconv.FormatUint(ino, 10)))
		if os.IsNotExist(err) {
			return false
		}
		if err != nil {
			t.Fatalf("stat snapshot staging: %v", err)
		}
		live, err := os.Stat(filepath.Join(dir, "staging", strconv.FormatUint(ino, 10)))
		if err == nil && os.SameFile(live, frozen) {
			t.Fatal("the snapshot's copy IS the live staging file; the live side can still change it underneath")
		}
		return true
	}
	if handedOver(app.Inode) || handedOver(ow.Inode) {
		t.Fatal("the freeze copied staging files; its cost then scales with the dirty set, not with dirty metadata")
	}

	tail := bytes.Repeat([]byte("B"), 1000)
	if _, err := ov.Write(ctx, app.Inode, int64(len(head)), tail); err != nil {
		t.Fatal(err)
	}
	if handedOver(app.Inode) {
		t.Error("an append handed the staging file over; only writes below the frozen length need to")
	}
	// A second append, and an extending truncate: still no copy.
	if _, err := ov.Write(ctx, app.Inode, int64(len(head)+len(tail)), []byte("C")); err != nil {
		t.Fatal(err)
	}
	grow := int64(len(head) + len(tail) + 4096)
	if _, err := ov.SetAttr(ctx, app.Inode, overlay.SetAttrIn{Size: &grow}); err != nil {
		t.Fatal(err)
	}
	if handedOver(app.Inode) {
		t.Error("an extending truncate handed the staging file over")
	}
	mustBody(t, snap, "append.txt", head)

	// In-place overwrite: the old file must reach the snapshot before a
	// single byte of it changes.
	if _, err := ov.Write(ctx, ow.Inode, 100, bytes.Repeat([]byte("Z"), 8)); err != nil {
		t.Fatal(err)
	}
	if !handedOver(ow.Inode) {
		t.Fatal("an in-place overwrite changed the bytes the snapshot froze without handing them over")
	}
	mustBody(t, snap, "overwrite.txt", head)
	wantLive := append([]byte{}, head...)
	copy(wantLive[100:], bytes.Repeat([]byte("Z"), 8))
	mustBody(t, ov, "overwrite.txt", wantLive)

	// A shrinking truncate is the other below-the-length mutation.
	small := int64(16)
	if _, err := ov.SetAttr(ctx, app.Inode, overlay.SetAttrIn{Size: &small}); err != nil {
		t.Fatal(err)
	}
	if !handedOver(app.Inode) {
		t.Fatal("a shrinking truncate changed the bytes the snapshot froze without handing them over")
	}
	mustBody(t, snap, "append.txt", head)
	mustBody(t, ov, "append.txt", head[:small])
}

// A snapshot reads the LIVE staging file until the live side hands it
// over, so the paths that DELETE one are as load-bearing as the paths
// that rewrite it: unlink, rename-over, and the rebase drop each destroy
// the only copy of content a seal in flight is still walking.
func TestSnapshotSurvivesDeletionOfStagedContent(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0007-4000-8000-000000000007")
	ov := openOverlay(t, fx, "")

	body := bytes.Repeat([]byte("gone"), 2048)
	victim, err := ov.Create(ctx, rootIno, "unlinked.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, victim.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	replaced, err := ov.Create(ctx, rootIno, "replaced.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, replaced.Inode, 0, body); err != nil {
		t.Fatal(err)
	}
	survivor, err := ov.Create(ctx, rootIno, "survivor.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, survivor.Inode, 0, []byte("kept")); err != nil {
		t.Fatal(err)
	}

	snap := takeSnapshot(t, ov)

	if err := ov.Unlink(ctx, rootIno, "unlinked.txt"); err != nil {
		t.Fatal(err)
	}
	// Rename over a staged file purges the destination inode the same way.
	if err := ov.Rename(ctx, rootIno, "survivor.txt", rootIno, "replaced.txt"); err != nil {
		t.Fatal(err)
	}

	mustBody(t, snap, "unlinked.txt", body)
	mustBody(t, snap, "replaced.txt", body)
	// And the live view really did delete them.
	if _, err := lookupPathErr(ov, "unlinked.txt"); err == nil {
		t.Error("the unlinked name still resolves in the live view")
	}
	mustBody(t, ov, "replaced.txt", []byte("kept"))
}

// snapDir recovers a snapshot's scratch path (the test chose it).
func snapDir(s *overlay.Snapshot) string { return snapDirs[s] }

// TestRebaseGoesClean is the whole cycle against a REAL sealed
// generation: snapshot, seal, swap, rebase — then everything untouched
// since the snapshot resolves from the new base with no overlay state,
// and everything touched after keeps its newer content.
func TestRebaseGoesClean(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0003-4000-8000-000000000003")
	ov := openOverlay(t, fx, "")

	published := []byte("published body")
	baseIno := lookupPath(t, ov, "base.txt").Inode
	if err := truncWrite(ctx, ov, baseIno, published); err != nil {
		t.Fatal(err)
	}
	created, err := ov.Create(ctx, rootIno, "created.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, created.Inode, 0, []byte("created body")); err != nil {
		t.Fatal(err)
	}
	subdir, err := ov.Mkdir(ctx, rootIno, "subdir", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	if err := ov.SetXattr(ctx, tagIno, "user.published", []byte("yes")); err != nil {
		t.Fatal(err)
	}
	childIno := lookupPath(t, ov, "dir/child.txt").Inode
	dirIno := lookupPath(t, ov, "dir").Inode
	if err := ov.Rename(ctx, dirIno, "child.txt", subdir.Inode, "moved.txt"); err != nil {
		t.Fatal(err)
	}
	// A hardlink to a BASE inode: two names for one inode, and the
	// detach-time provenance the rebase has to rewrite.
	bigIno := lookupPath(t, ov, "big.bin").Inode
	if _, err := ov.Link(ctx, bigIno, subdir.Inode, "linked.bin"); err != nil {
		t.Fatal(err)
	}

	snap := takeSnapshot(t, ov)
	seq := snap.Seq()

	// One inode is modified AFTER the snapshot: it must survive the
	// rebase with its newer bytes and stay dirty.
	leafIno := lookupPath(t, ov, "dir/inner/leaf.txt").Inode
	afterSnapshot := []byte("written after the snapshot")
	if err := truncWrite(ctx, ov, leafIno, afterSnapshot); err != nil {
		t.Fatal(err)
	}

	before := mergedView(t, ov)
	res := sealAndSwap(t, fx, ov)
	if res.Superblock.Generation != fx.res.Superblock.Generation+1 {
		t.Fatalf("sealed generation %d", res.Superblock.Generation)
	}
	rep := rebase(t, ov, seq, res)
	if err := snap.Close(); err != nil {
		t.Fatalf("snapshot Close: %v", err)
	}

	if len(rep.Unresolved) != 0 {
		t.Errorf("unresolved inodes after rebase: %v", rep.Unresolved)
	}
	// The merged view is unchanged by the rebase: same bytes, from the
	// base now instead of the overlay. This is the property that makes
	// dropping the rows legal.
	if after := mergedView(t, ov); !reflect.DeepEqual(before, after) {
		for p, w := range before {
			if g := after[p]; g != w {
				t.Errorf("path %s after rebase: %s\n                    want: %s", p, g, w)
			}
		}
		t.Fatal("the merged view changed across the rebase")
	}

	cleaned := map[uint64]bool{}
	for _, ino := range rep.Clean {
		cleaned[ino] = true
	}
	for _, ino := range []uint64{baseIno, created.Inode, subdir.Inode, tagIno, childIno, bigIno} {
		if !cleaned[ino] {
			t.Errorf("inode %d was published but not reported clean (clean=%v)", ino, rep.Clean)
		}
		mustDirty(t, ov, ino, false, "after rebase")
	}
	mustDirty(t, ov, leafIno, true, "modified after the snapshot")
	if cleaned[leafIno] {
		t.Error("an inode modified after the snapshot was reported clean")
	}

	// Content still reads, byte-exact, through the merged view.
	mustBody(t, ov, "base.txt", published)
	mustBody(t, ov, "created.txt", []byte("created body"))
	mustBody(t, ov, "subdir/moved.txt", fx.body["dir/child.txt"])
	mustBody(t, ov, "dir/inner/leaf.txt", afterSnapshot)
	mustBody(t, ov, "big.bin", fx.body["big.bin"])
	mustBody(t, ov, "subdir/linked.bin", fx.body["big.bin"])
	if n := lookupPath(t, ov, "subdir/linked.bin"); n.Inode != bigIno || n.Nlink != 2 {
		t.Errorf("hardlink after rebase = ino %d nlink %d, want %d/2", n.Inode, n.Nlink, bigIno)
	}
	if v, err := ov.GetXattr(ctx, tagIno, "user.published"); err != nil || string(v) != "yes" {
		t.Errorf("xattr after rebase = %q (%v)", v, err)
	}

	// The overlay now holds only the post-snapshot work.
	st, err := ov.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.DirtyNodes != 1 || st.StagedFiles != 1 {
		t.Errorf("after rebase: %+v, want exactly the one post-snapshot inode", st)
	}
	if st.DirtyEdges != 0 {
		t.Errorf("after rebase: %d edges survive, want 0", st.DirtyEdges)
	}
}

// TestRebasePublishedDeletionStaysDeleted: a whiteout whose deletion was
// published is redundant — the name is gone from the new base — so
// dropping it must not resurrect anything. A file recreated after the
// snapshot must survive with its new content.
func TestRebasePublishedDeletionStaysDeleted(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0004-4000-8000-000000000004")
	ov := openOverlay(t, fx, "")

	if err := ov.Unlink(ctx, rootIno, "base.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "tagged.txt"); err != nil {
		t.Fatal(err)
	}
	innerIno := lookupPath(t, ov, "dir/inner").Inode
	if err := ov.Unlink(ctx, innerIno, "leaf.txt"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Rmdir(ctx, lookupPath(t, ov, "dir").Inode, "inner"); err != nil {
		t.Fatal(err)
	}

	snap := takeSnapshot(t, ov)
	seq := snap.Seq()

	// Recreated AFTER the snapshot: the sealed generation has no
	// base.txt, and the overlay's new file must outlive the rebase.
	recreated, err := ov.Create(ctx, rootIno, "base.txt", 0600, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fresh := []byte("a different file at the same name")
	if _, err := ov.Write(ctx, recreated.Inode, 0, fresh); err != nil {
		t.Fatal(err)
	}

	res := sealAndSwap(t, fx, ov)
	rep := rebase(t, ov, seq, res)
	_ = snap.Close()

	// Root stayed dirty (base.txt was recreated under it), so its
	// whiteouts are not dropped; tagged.txt must still be gone either way.
	if _, err := lookupPathErr(ov, "tagged.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("published deletion came back: %v", err)
	}
	if _, err := lookupPathErr(ov, "dir/inner"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("published rmdir came back: %v", err)
	}
	mustBody(t, ov, "base.txt", fresh)
	mustDirty(t, ov, recreated.Inode, true, "recreated after the snapshot")

	names := entryNames(mustReaddir(t, ov, rootIno))
	if !reflect.DeepEqual(names, []string{"base.txt", "big.bin", "dir"}) {
		t.Errorf("root after rebase = %v", names)
	}

	// A SECOND snapshot/seal/rebase, with nothing left dirty afterwards:
	// now the root itself is published and its whiteouts go too.
	snap2 := takeSnapshot(t, ov)
	seq2 := snap2.Seq()
	res2 := sealAndSwap(t, fx, ov)
	rep2 := rebase(t, ov, seq2, res2)
	_ = snap2.Close()
	if rep2.Dirty != 0 {
		t.Errorf("after the second rebase %d inodes are still dirty (first report: %+v)", rep2.Dirty, rep)
	}
	st, err := ov.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.DirtyNodes != 0 || st.DirtyEdges != 0 || st.StagedFiles != 0 {
		t.Errorf("overlay is not empty after publishing everything: %+v", st)
	}
	if _, err := lookupPathErr(ov, "tagged.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("deletion resurrected once its whiteout was dropped: %v", err)
	}
	mustBody(t, ov, "base.txt", fresh)
	if _, err := lookupPathErr(ov, "dir/inner/leaf.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("deleted leaf came back: %v", err)
	}
}

func mustReaddir(t *testing.T, v readView, ino uint64) []overlay.DirEntry {
	t.Helper()
	es, err := v.Readdir(context.Background(), ino)
	if err != nil {
		t.Fatalf("readdir %d: %v", ino, err)
	}
	return es
}

// TestRebaseCleanDirtyCleanCycle runs the TTL-relevant transition twice:
// a clean base file goes dirty, a checkpoint makes it clean again, and
// the next write makes it dirty again.
func TestRebaseCleanDirtyCleanCycle(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0005-4000-8000-000000000005")
	ov := openOverlay(t, fx, "")

	ino := lookupPath(t, ov, "dir/child.txt").Inode
	mustDirty(t, ov, ino, false, "clean base file")
	mustBody(t, ov, "dir/child.txt", fx.body["dir/child.txt"])

	for round := 1; round <= 2; round++ {
		body := []byte(fmt.Sprintf("round %d content", round))
		if err := truncWrite(ctx, ov, ino, body); err != nil {
			t.Fatalf("round %d write: %v", round, err)
		}
		mustDirty(t, ov, ino, true, fmt.Sprintf("round %d after write", round))
		mustBody(t, ov, "dir/child.txt", body)

		// Closed before the rebase, the order a checkpoint really runs:
		// the seal consumes the snapshot, the snapshot is released, and
		// only the sequence number is carried into Rebase.
		snap := takeSnapshot(t, ov)
		seq := snap.Seq()
		res := sealAndSwap(t, fx, ov)
		if err := snap.Close(); err != nil {
			t.Fatalf("round %d: snapshot Close: %v", round, err)
		}
		rep := rebase(t, ov, seq, res)

		if len(rep.Clean) == 0 {
			t.Fatalf("round %d: nothing went clean", round)
		}
		mustDirty(t, ov, ino, false, fmt.Sprintf("round %d after rebase", round))
		mustBody(t, ov, "dir/child.txt", body)
		if st, err := ov.Stats(); err != nil || st.DirtyNodes != 0 || st.StagedFiles != 0 {
			t.Fatalf("round %d: overlay state survived the rebase: %+v (%v)", round, st, err)
		}
		// Untouched neighbours came along for free.
		mustBody(t, ov, "big.bin", fx.body["big.bin"])
		mustBody(t, ov, "base.txt", fx.body["base.txt"])
	}
}

// TestRebaseDirtySetMatchesReopen extends the drift check across a
// rebase: the in-memory set the FUSE binding reads for TTLs must equal
// what a fresh Open derives from the rebased tables.
func TestRebaseDirtySetMatchesReopen(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0006-4000-8000-000000000006")
	dir := t.TempDir()
	ov := openOverlay(t, fx, dir)

	// Seed the in-memory set FIRST, so what follows tests incremental
	// maintenance and not a lazy re-derivation from the same tables.
	if _, err := ov.IsDirty(rootIno); err != nil {
		t.Fatal(err)
	}
	created, err := ov.Create(ctx, rootIno, "created.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, created.Inode, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	baseIno := lookupPath(t, ov, "base.txt").Inode
	if err := truncWrite(ctx, ov, baseIno, []byte("modified base")); err != nil {
		t.Fatal(err)
	}
	tagIno := lookupPath(t, ov, "tagged.txt").Inode
	if err := ov.SetXattr(ctx, tagIno, "user.k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	sub, err := ov.Mkdir(ctx, rootIno, "subdir", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	childIno := lookupPath(t, ov, "dir/child.txt").Inode
	if err := ov.Rename(ctx, lookupPath(t, ov, "dir").Inode, "child.txt", sub.Inode, "moved.txt"); err != nil {
		t.Fatal(err)
	}

	snap := takeSnapshot(t, ov)
	seq := snap.Seq()
	leafIno := lookupPath(t, ov, "dir/inner/leaf.txt").Inode
	if err := truncWrite(ctx, ov, leafIno, []byte("after")); err != nil {
		t.Fatal(err)
	}
	// Keeps subdir dirty across the rebase, so the moved inode survives
	// reachable ONLY through an overlay edge with no attribute row of its
	// own — the case whose base provenance the rebase must rewrite, or a
	// reopened overlay cannot resolve it in the sealed generation.
	if _, err := ov.Create(ctx, sub.Inode, "sibling.txt", 0644, 0, 0); err != nil {
		t.Fatal(err)
	}
	res := sealAndSwap(t, fx, ov)
	rebase(t, ov, seq, res)
	_ = snap.Close()

	// Mutations AFTER the rebase, on top of the set it re-derived.
	if err := truncWrite(ctx, ov, baseIno, []byte("dirty again")); err != nil {
		t.Fatal(err)
	}
	postCreate, err := ov.Create(ctx, rootIno, "post.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	bigIno := lookupPath(t, ov, "big.bin").Inode
	if err := ov.Rename(ctx, rootIno, "big.bin", rootIno, "renamed.bin"); err != nil {
		t.Fatal(err)
	}
	if err := ov.Unlink(ctx, rootIno, "tagged.txt"); err != nil {
		t.Fatal(err)
	}

	probe := []uint64{created.Inode, sub.Inode, baseIno, tagIno, childIno, leafIno, rootIno,
		postCreate.Inode, bigIno, lookupPath(t, ov, "dir").Inode}
	live := map[uint64]bool{}
	for _, ino := range probe {
		d, err := ov.IsDirty(ino)
		if err != nil {
			t.Fatal(err)
		}
		live[ino] = d
	}
	if !live[leafIno] {
		t.Error("the inode written after the snapshot must still be dirty")
	}
	if live[created.Inode] {
		t.Error("a published inode is still dirty; the rebase did nothing")
	}
	for _, ino := range []uint64{baseIno, postCreate.Inode, bigIno} {
		if !live[ino] {
			t.Errorf("inode %d was mutated after the rebase and must be dirty", ino)
		}
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh Open over the SEALED generation derives the set from the
	// rebased tables alone.
	ov2 := openOverlay(t, fx, dir)
	for _, ino := range probe {
		d, err := ov2.IsDirty(ino)
		if err != nil {
			t.Fatal(err)
		}
		if d != live[ino] {
			t.Errorf("inode %d: in-memory dirty=%v, table-derived dirty=%v", ino, live[ino], d)
		}
	}
	if err := ov2.Close(); err != nil {
		t.Fatal(err)
	}

	// The real remount: a FRESH generation handle with no residency at
	// all, so every base half must be reachable from persisted state
	// alone. This is what the rebase's rewritten provenance is for —
	// subdir/moved.txt resolves through an overlay edge, which never
	// descends the base, so nothing else would make it resident.
	fresh, err := overlay.Open(dir, openBase(t, fx.inner, fx.head.Superblock), fx.options())
	if err != nil {
		t.Fatalf("reopen over a fresh generation handle: %v", err)
	}
	defer fresh.Close() //nolint:errcheck
	mustBody(t, fresh, "subdir/moved.txt", fx.body["dir/child.txt"])
	if n, err := fresh.GetAttr(ctx, childIno); err != nil || n.Length != int64(len(fx.body["dir/child.txt"])) {
		t.Errorf("moved inode after reopen: %+v (%v)", n, err)
	}
	mustBody(t, fresh, "dir/inner/leaf.txt", []byte("after"))
	mustBody(t, fresh, "created.txt", []byte("data"))
	mustBody(t, fresh, "base.txt", []byte("dirty again"))
	mustBody(t, fresh, "renamed.bin", fx.body["big.bin"])
	mustBody(t, fresh, "subdir/sibling.txt", nil)
	if _, err := lookupPathErr(fresh, "tagged.txt"); !errors.Is(err, overlay.ErrNotExist) {
		t.Errorf("unlink after the rebase did not survive the reopen: %v", err)
	}
}

// TestRebaseRefusals: the guards that keep a rebase from running against
// a base that is not the one the snapshot was sealed into.
func TestRebaseRefusals(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0007-4000-8000-000000000007")
	ov := openOverlay(t, fx, "")
	if _, err := ov.Create(ctx, rootIno, "x.txt", 0644, 0, 0); err != nil {
		t.Fatal(err)
	}
	snap := takeSnapshot(t, ov)
	seq := snap.Seq()

	// The base has not been swapped yet: the sealed root is not what the
	// mount serves, so nothing may be dropped.
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: fx.inner, SpoolDir: t.TempDir(), SigningKey: fx.key,
		Prev: fx.head.Superblock, PrevRaw: fx.head.Raw, TargetPackSize: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Rebase(ctx, seq, overlay.Options{BaseRoot: res.Superblock.RootCatalog}); !errors.Is(err, overlay.ErrGeneration) {
		t.Fatalf("rebase before the base swap = %v, want ErrGeneration", err)
	}
	if _, err := ov.Rebase(ctx, seq, overlay.Options{}); err == nil {
		t.Fatal("rebase without a sealed root was accepted")
	}
	// Still fully dirty.
	if st, _ := ov.Stats(); st.DirtyNodes == 0 {
		t.Fatal("a refused rebase dropped state")
	}

	if _, err := fx.base.Swap(ctx, res.Superblock); err != nil {
		t.Fatal(err)
	}
	fx.head = res
	opts := overlay.Options{BaseRoot: res.Superblock.RootCatalog, BaseGeneration: res.Superblock.Generation}
	if _, err := ov.Rebase(ctx, seq+1000, opts); err == nil {
		t.Fatal("rebase at a sequence no snapshot was taken at was accepted")
	}
	if _, err := ov.Rebase(ctx, seq, opts); err != nil {
		t.Fatalf("rebase after the swap: %v", err)
	}
	// The same sequence cannot be rebased twice: its snapshot record is
	// spent, and its rows are gone.
	if _, err := ov.Rebase(ctx, seq, opts); err == nil {
		t.Fatal("a spent sequence was rebased again")
	}
	_ = snap.Close()
}

// TestSnapshotConcurrentWriters runs Snapshot against live mutation. The
// snapshot must be internally consistent: every file it lists reads back
// as one of the whole-file generations a writer wrote, never a mix, and
// every name it lists resolves.
func TestSnapshotConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-0008-4000-8000-000000000008")
	ov := openOverlay(t, fx, "")

	const files, rounds = 6, 40
	const size = 512
	inos := make([]uint64, files)
	for i := range inos {
		n, err := ov.Create(ctx, rootIno, fmt.Sprintf("w%d.txt", i), 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, bytes.Repeat([]byte{'0'}, size)); err != nil {
			t.Fatal(err)
		}
		inos[i] = n.Inode
	}
	// Also let a base file be COW'd concurrently.
	bigIno := lookupPath(t, ov, "big.bin").Inode

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := range inos {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				select {
				case <-stop:
					return
				default:
				}
				mark := byte('a' + (r % 26))
				if _, err := ov.Write(ctx, inos[i], 0, bytes.Repeat([]byte{mark}, size)); err != nil {
					t.Errorf("concurrent write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := 0; r < rounds; r++ {
			name := fmt.Sprintf("churn%d.txt", r)
			n, err := ov.Create(ctx, rootIno, name, 0644, 0, 0)
			if err != nil {
				t.Errorf("concurrent create: %v", err)
				return
			}
			if _, err := ov.Write(ctx, n.Inode, 0, []byte(name)); err != nil {
				t.Errorf("concurrent write: %v", err)
				return
			}
			if r%2 == 0 {
				if err := ov.Unlink(ctx, rootIno, name); err != nil {
					t.Errorf("concurrent unlink: %v", err)
					return
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for r := 0; r < rounds/4; r++ {
			if _, err := ov.Write(ctx, bigIno, int64(r*8), []byte("XXXXXXXX")); err != nil {
				t.Errorf("concurrent COW write: %v", err)
				return
			}
		}
	}()

	// Take snapshots WHILE all of that runs.
	var snaps []*overlay.Snapshot
	for i := 0; i < 4; i++ {
		snaps = append(snaps, takeSnapshot(t, ov))
	}
	close(stop)
	wg.Wait()

	for i, snap := range snaps {
		names := entryNames(mustReaddir(t, snap, rootIno))
		for _, name := range names {
			n, err := snap.Lookup(ctx, rootIno, name)
			if err != nil {
				t.Fatalf("snapshot %d: listed %q but cannot look it up: %v", i, name, err)
			}
			if n.Type != catalog.TypeFile {
				continue
			}
			body := readAllFS(t, snap, n.Inode, int(n.Length))
			if int64(len(body)) != n.Length {
				t.Fatalf("snapshot %d: %s read %d bytes for a %d-byte file", i, name, len(body), n.Length)
			}
			if !strings.HasPrefix(name, "w") {
				continue
			}
			// A writer file: every byte must come from ONE write.
			if len(body) != size {
				t.Fatalf("snapshot %d: %s length %d, want %d", i, name, len(body), size)
			}
			if !bytes.Equal(body, bytes.Repeat(body[:1], size)) {
				t.Fatalf("snapshot %d: %s is torn: %q", i, name, trunc(body))
			}
		}
		// The snapshots were taken in order, so their sequences are
		// monotonic — a cheap check that Seq tracks real mutations.
		if i > 0 && snaps[i-1].Seq() > snap.Seq() {
			t.Fatalf("snapshot sequences went backwards: %d then %d", snaps[i-1].Seq(), snap.Seq())
		}
	}
	// Every snapshot still reads after the writers stopped.
	for i, snap := range snaps {
		if _, err := snap.GetAttr(ctx, bigIno); err != nil {
			t.Errorf("snapshot %d: GetAttr after the writers: %v", i, err)
		}
		if err := snap.Close(); err != nil {
			t.Errorf("snapshot %d: Close: %v", i, err)
		}
	}
	// Scratch is released.
	for _, snap := range snaps {
		if d, ok := snapDirs[snap]; ok {
			if _, err := os.Stat(filepath.Join(d, "overlay.db")); !os.IsNotExist(err) {
				t.Errorf("snapshot scratch survived Close: %v", err)
			}
		}
	}
}

// TestSnapshotOfEmptyOverlay: the degenerate case a checkpoint of an
// untouched mount takes.
func TestSnapshotOfEmptyOverlay(t *testing.T) {
	fx := newFixture(t, "5a405a40-0009-4000-8000-000000000009")
	ov := openOverlay(t, fx, "")
	snap := takeSnapshot(t, ov)
	if snap.Seq() != 0 {
		t.Errorf("untouched overlay snapshot seq = %d", snap.Seq())
	}
	if got, want := mergedView(t, snap), mergedView(t, ov); !reflect.DeepEqual(got, want) {
		t.Error("snapshot of an untouched overlay differs from the live view")
	}
	rep, err := snap.Dirty()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Nodes)+len(rep.Edges)+len(rep.Content) != 0 {
		t.Errorf("untouched overlay snapshot reports dirt: %+v", rep)
	}
	if err := snap.Close(); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestSnapshotCostAtScale measures what freezing costs on the shape that
// made it visible: an untar's worth of small staged files. The snapshot
// runs with the overlay lock held, so its cost is stall time for the mount
// as well as latency for the seal, and the two halves scale with different
// things — the VACUUM with dirty metadata, the pin with staged file COUNT.
//
//	PELFS_BIGSNAP=1 PELFS_BIGSNAP_FILES=85000 go test ./internal/overlay -run SnapshotCostAtScale -v -timeout 30m
func TestSnapshotCostAtScale(t *testing.T) {
	if os.Getenv("PELFS_BIGSNAP") == "" {
		t.Skip("set PELFS_BIGSNAP=1 to run the snapshot-cost measurement")
	}
	files := 20000
	if v := os.Getenv("PELFS_BIGSNAP_FILES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		files = n
	}
	ctx := context.Background()
	fx := newFixture(t, "b0000000-0000-4000-8000-00000000c001")
	ov := openOverlay(t, fx, t.TempDir())

	body := []byte("a small source file, the shape an unpack writes\n")
	start := time.Now()
	perDir := 16
	var dir uint64
	for i := 0; i < files; i++ {
		if i%perDir == 0 {
			d, err := ov.Mkdir(ctx, 1, fmt.Sprintf("d%06d", i/perDir), 0755, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			dir = d.Inode
		}
		n, err := ov.Create(ctx, dir, fmt.Sprintf("f%04d.c", i%perDir), 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, body); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("staged %d files in %s", files, time.Since(start).Round(time.Millisecond))

	snapDir := filepath.Join(t.TempDir(), "snap")
	start = time.Now()
	snap, err := ov.Snapshot(context.Background(), snapDir)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wall := time.Since(start)
	c := snap.Cost()
	t.Logf("SNAPSHOT %s wall: vacuum %s, pin %s (%d staged), namespace %s, open %s",
		wall.Round(time.Millisecond), c.Vacuum.Round(time.Millisecond),
		c.Freeze.Round(time.Millisecond), c.Staged,
		c.Edges.Round(time.Millisecond), c.Open.Round(time.Millisecond))

	start = time.Now()
	if err := snap.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Logf("SNAPSHOT release %s", time.Since(start).Round(time.Millisecond))
}

// TestFailedCheckpointsDoNotAccumulateSnapshotEdges is the memory claim
// C4 rests on: a checkpoint that never reaches its rebase — the federation
// refusing the flip, a seal that errors, a swap that fails — must not
// leave its namespace behind. The mount retries every five minutes for as
// long as the outage lasts, so a per-attempt map is an out-of-memory kill
// during exactly the failure this design is supposed to survive.
func TestFailedCheckpointsDoNotAccumulateSnapshotEdges(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, "5a405a40-000c-4000-8000-00000000000c")
	ov := openOverlay(t, fx, "")

	// A namespace worth remembering: every write names another inode in
	// the edge map a snapshot records.
	for i := 0; i < 20; i++ {
		n, err := ov.Create(ctx, rootIno, fmt.Sprintf("f%02d.txt", i), 0600, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, []byte("body")); err != nil {
			t.Fatal(err)
		}
	}
	prev := 0
	for round := 1; round <= 8; round++ {
		// The session keeps writing between attempts, which is what makes
		// each snapshot a distinct SEQUENCE and therefore a distinct map.
		// Without a write in between, every snapshot lands on the same seq
		// and overwrites its predecessor — and the test would pass against
		// the very leak it exists to catch.
		w, err := ov.Create(ctx, rootIno, fmt.Sprintf("r%02d.txt", round), 0600, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, w.Inode, 0, []byte("more")); err != nil {
			t.Fatal(err)
		}
		// The shape of a failed checkpoint: freeze, then discover the seal
		// cannot publish, release the frozen view, and never rebase.
		snap := takeSnapshot(t, ov)
		if err := snap.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", round, err)
		}
		st, err := ov.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if st.ResidentSnapEdges == 0 {
			t.Fatalf("round %d: the snapshot recorded no namespace at all", round)
		}
		// One namespace, which grows only by the file this round added.
		// Accumulating would show as a multiple of it.
		if want := prev + 1; round > 1 && st.ResidentSnapEdges != want {
			t.Fatalf("round %d holds %d resident snapshot edges, want %d: "+
				"failed checkpoints are accumulating namespaces",
				round, st.ResidentSnapEdges, want)
		}
		prev = st.ResidentSnapEdges
	}
}
