package publish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
)

// readoptVol is a volume driven the way `pelfs mount-gen --rw` drives one,
// with the two properties the reuse fixture above deliberately lacks:
//
//   - the content store is the MEMTABLE, journalled into a state directory
//     that outlives the session, so a partial write to a published file
//     ADOPTS it by reference and records the adoption on disk; and
//   - a session can END and a later one can REOPEN the same state
//     directory — fresh genfs, fresh overlay handle, fresh content store —
//     which is the only situation in which recovery replays that record.
//
// Everything a mount does between those two points is here in the order
// mountgen does it (openContent before overlay.Open; snapshot, seal, swap,
// rebase for a checkpoint), because the defect this file pins lives in the
// seam between them rather than in any one of them.
type readoptVol struct {
	t          *testing.T
	inner      *countingStore
	priv       ed25519.PrivateKey
	state      string
	index      string
	head       *publish.Result
	base       *genfs.FS
	ov         *overlay.FS
	store      *memtable.Store
	closeStore func() error
	snaps      int
}

func newReadoptVol(t *testing.T, volID [16]byte) *readoptVol {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := &readoptVol{t: t, inner: &countingStore{Store: newInner(t)}, priv: priv, state: t.TempDir()}
	v.index = filepath.Join(v.state, "dedup.db")
	v.head, err = publish.InitVolume(context.Background(), publish.Options{
		Inner: v.inner, SpoolDir: t.TempDir(), SigningKey: priv, VolumeID: volID,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index,
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}
	return v
}

// session opens one writable session over the state directory, exactly as
// mount-gen does: the base generation, then the content store (which
// recovers whatever the last session left), then the overlay on top.
func (v *readoptVol) session() error {
	v.t.Helper()
	ctx := context.Background()
	base, err := genfs.Open(ctx, genfs.Options{
		Inner: v.inner, SB: v.head.Superblock, CacheDir: filepath.Join(v.state, "gencache"),
	})
	if err != nil {
		return fmt.Errorf("genfs.Open: %w", err)
	}
	store, rep, closeStore, err := overlay.OpenContentStore(filepath.Join(v.state, "content"), memtable.Options{
		TableSize: 1 << 20, Obj: v.inner, Base: base,
		Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
		Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		base.Close() //nolint:errcheck
		// The sentence a user sees, kept verbatim: this is the mount
		// refusing to start, one frame in from the CLI's own wrapper.
		return fmt.Errorf("open the write path's content store: %w", err)
	}
	if rep.Loss() {
		v.t.Errorf("recovery reported loss over a state directory nothing crashed:\n%s", rep)
	}
	ov, err := overlay.Open(filepath.Join(v.state, "overlay"), base, overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
		Memtable:       store,
	})
	if err != nil {
		closeStore() //nolint:errcheck
		base.Close() //nolint:errcheck
		return fmt.Errorf("open overlay: %w", err)
	}
	v.base, v.store, v.closeStore, v.ov = base, store, closeStore, ov
	return nil
}

func (v *readoptVol) mustSession() {
	v.t.Helper()
	if err := v.session(); err != nil {
		v.t.Fatal(err)
	}
}

// end closes the session without sealing. That is not an exotic path: a
// checkpoint publishes and rebases everything the session wrote, so the
// overlay is CLEAN at unmount and sealAtExit returns on "nothing changed;
// no new generation" — leaving the overlay and the content journal in
// place for the next mount, which is what makes them replayable.
func (v *readoptVol) end() {
	v.t.Helper()
	if err := v.ov.Close(); err != nil {
		v.t.Fatalf("close overlay: %v", err)
	}
	if err := v.closeStore(); err != nil {
		v.t.Fatalf("close content store: %v", err)
	}
	if err := v.base.Close(); err != nil {
		v.t.Fatalf("close base: %v", err)
	}
	v.ov, v.store, v.closeStore, v.base = nil, nil, nil, nil
}

// checkpoint is cmd/pelfs's sealLocked: freeze, seal the frozen view, swap
// the base to what was sealed, rebase the published inodes to clean.
func (v *readoptVol) checkpoint() *publish.Result {
	v.t.Helper()
	ctx := context.Background()
	v.snaps++
	snap, err := v.ov.Snapshot(ctx, filepath.Join(v.state, fmt.Sprintf("snap-%d", v.snaps)))
	if err != nil {
		v.t.Fatalf("snapshot: %v", err)
	}
	defer snap.Close() //nolint:errcheck
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap, Inner: v.inner, SpoolDir: v.t.TempDir(),
		SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index,
	})
	if err != nil {
		v.t.Fatalf("checkpoint seal: %v", err)
	}
	v.head = res
	if _, err := v.base.Swap(ctx, res.Superblock); err != nil {
		v.t.Fatalf("swap to the sealed generation: %v", err)
	}
	if err := v.base.LoadPackIndex(ctx); err != nil {
		v.t.Fatalf("load pack index: %v", err)
	}
	if _, err := v.ov.Rebase(ctx, snap.Seq(), overlay.Options{
		BaseRoot:       res.Superblock.RootCatalog,
		BaseGeneration: res.Superblock.Generation,
	}); err != nil {
		v.t.Fatalf("rebase: %v", err)
	}
	return res
}

// seal publishes the live overlay and follows it, which is what unmount
// does when the session did change something.
func (v *readoptVol) seal() *publish.Result {
	v.t.Helper()
	res, err := publish.Seal(context.Background(), publish.Options{
		Overlay: v.ov, Inner: v.inner, SpoolDir: v.t.TempDir(),
		SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index,
	})
	if err != nil {
		v.t.Fatalf("seal: %v", err)
	}
	v.head = res
	return res
}

// read reads a whole file back through the OVERLAY — the merged view a
// mount serves, which for an adopted file is the memtable resolving part
// of it against the base generation.
func (v *readoptVol) read(path string, length int64) []byte {
	v.t.Helper()
	n := lookupPath(v.t, v.ov, path)
	if n.Length != length {
		v.t.Errorf("%s: overlay says %d bytes, want %d", path, n.Length, length)
	}
	return readWhole(v.t, v.ov, n.Inode, length)
}

// THE FOUR OPERATIONS, and the second writable session that has to survive
// them. Found by the hostile exerciser (internal/hostile/testdata/corpus/
// second-session-refuses-after-adopt.plan) and reproduced here through the
// same interfaces the mount uses, with no container and no frontend:
//
//  1. write a file
//  2. a CHECKPOINT publishes it, so it is in a base generation
//  3. overwrite PART of it, which makes the memtable ADOPT the file from
//     that base by reference and journal an adopted handle
//  4. a SECOND checkpoint publishes that, and REBASES — which drops the
//     inode's overlay rows and Forgets its content, leaving the journal's
//     adopted handle referenced by nothing
//
// Then reopen the state directory for writing. Recovery used to re-adopt
// every journalled handle against whatever base the new mount has, before
// knowing whether any surviving content row still named it, and the answer
// for a handle in this state is `genfs: stale inode (no residency)`: a
// fresh mount has descended nothing, so the base cannot answer for an
// inode nobody has looked up. The mount refused to start, and the state
// directory was unopenable for writing from then on.
//
// The assertions past the reopen are the other half. A mount that starts
// and then serves the file WITHOUT the overwrite is not a fix, so the
// reopened session must read the full body back and seal a generation that
// still has it.
func TestASecondWritableSessionSurvivesAnAdoption(t *testing.T) {
	ctx := context.Background()
	v := newReadoptVol(t, [16]byte{0xad, 0x09, 0x7e, 0x01})
	v.mustSession()

	// 1. write a file, one directory down as the corpus entry has it.
	dir, err := v.ov.Mkdir(ctx, publishRootInode, "ad", 0755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir ad: %v", err)
	}
	want := pseudorandom(40000, 11)
	ino := v.create(dir.Inode, "a.log", want)

	// 2. a checkpoint publishes it.
	first := v.checkpoint()
	if first.Stats.ChunksAdded == 0 {
		t.Fatal("the first checkpoint published no chunks; the test would prove nothing")
	}

	// 3. a PARTIAL overwrite: the memtable adopts the file from the base.
	patch := pseudorandom(999, 21)
	if _, err := v.ov.Write(ctx, ino, 101, patch); err != nil {
		t.Fatalf("partial overwrite: %v", err)
	}
	copy(want[101:], patch)
	if st := v.store.Stats(); st.AdoptedFiles != 1 {
		t.Fatalf("the partial overwrite adopted %d file(s), want 1: the sequence this test "+
			"exists for did not happen (%+v)", st.AdoptedFiles, st)
	}
	if got := v.read("ad/a.log", int64(len(want))); !bytes.Equal(got, want) {
		t.Fatal("the overlay does not read back the partial overwrite before any checkpoint")
	}

	// 4. a SECOND checkpoint, which is load-bearing: it publishes the
	// adopted file and rebases it clean, so nothing in the recovered
	// content map will name the adopted handle the journal still holds.
	second := v.checkpoint()
	if second.Superblock.Generation != first.Superblock.Generation+1 {
		t.Fatalf("the second checkpoint published generation %d, the first %d",
			second.Superblock.Generation, first.Superblock.Generation)
	}
	v.end()

	// The reopen. This is the refusal.
	if err := v.session(); err != nil {
		t.Fatalf("a second writable session could not start over the state directory:\n%v", err)
	}

	// It opened. Now it has to be the same filesystem: the published
	// generation holds the overwrite, and so must the merged view.
	if got := v.read("ad/a.log", int64(len(want))); !bytes.Equal(got, want) {
		t.Error("the reopened session does not read the adopted file's full contents back")
	}

	// And it has to be able to publish. The second session writes the way
	// the exerciser's phase C2 does — unaligned at both ends, so the seal
	// re-chunks across the boundary of what the base published — and the
	// generation it seals must read back byte-exact from a cold cache.
	late := pseudorandom(3000, 31)
	if _, err := v.ov.Write(ctx, ino, 5001, late); err != nil {
		t.Fatalf("write in the reopened session: %v", err)
	}
	copy(want[5001:], late)
	res := v.seal()
	if res.Superblock.Generation != second.Superblock.Generation+1 {
		t.Errorf("the reopened session sealed generation %d, on top of %d",
			res.Superblock.Generation, second.Superblock.Generation)
	}
	sealed := openGenfs(t, v.inner, res.Superblock, nil)
	n := lookupPath(t, sealed, "ad/a.log")
	if n.Length != int64(len(want)) {
		t.Fatalf("the sealed file is %d bytes, want %d", n.Length, len(want))
	}
	if got := readWhole(t, sealed, n.Inode, n.Length); !bytes.Equal(got, want) {
		t.Error("the generation the reopened session sealed does not hold the file it served")
	}
}

// The same adoption, still DIRTY when the session ends: no second
// checkpoint, so the recovered content map genuinely names the adopted
// handle and recovery has to resolve it rather than discard it. This is
// what an interrupted job leaves behind (a crash, a SIGKILL, --no-seal),
// and it is the shape the existing crash test cannot see, because that one
// hands the reopened store the SAME live *genfs.FS and so inherits the
// residency the first session's lookups established.
//
// A real remount inherits none: the resolution must come from what was
// written down, not from what the previous process happened to be holding.
func TestAWritableSessionResumesAnAdoptionAfterACrash(t *testing.T) {
	ctx := context.Background()
	v := newReadoptVol(t, [16]byte{0xad, 0x09, 0x7e, 0x02})
	v.mustSession()

	dir, err := v.ov.Mkdir(ctx, publishRootInode, "ad", 0755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir ad: %v", err)
	}
	want := pseudorandom(40000, 12)
	ino := v.create(dir.Inode, "a.log", want)
	v.checkpoint()

	patch := pseudorandom(999, 22)
	if _, err := v.ov.Write(ctx, ino, 101, patch); err != nil {
		t.Fatalf("partial overwrite: %v", err)
	}
	copy(want[101:], patch)
	if st := v.store.Stats(); st.AdoptedFiles != 1 {
		t.Fatalf("the partial overwrite adopted %d file(s), want 1 (%+v)", st.AdoptedFiles, st)
	}
	// The interruption: nothing is sealed and nothing is rebased, so the
	// overwrite exists only in this state directory.
	v.end()

	if err := v.session(); err != nil {
		t.Fatalf("a writable session could not resume the interrupted one:\n%v", err)
	}
	if got := v.read("ad/a.log", int64(len(want))); !bytes.Equal(got, want) {
		t.Error("the resumed session does not read the adopted file's full contents back")
	}
	res := v.seal()
	sealed := openGenfs(t, v.inner, res.Superblock, nil)
	n := lookupPath(t, sealed, "ad/a.log")
	if n.Length != int64(len(want)) {
		t.Fatalf("the sealed file is %d bytes, want %d", n.Length, len(want))
	}
	if got := readWhole(t, sealed, n.Inode, n.Length); !bytes.Equal(got, want) {
		t.Error("the resumed session sealed a generation without the overwrite it inherited")
	}
}

// adopted is the first three of the four operations: a file, a checkpoint
// that publishes it, and a partial overwrite that adopts it from the
// generation just published. What each caller below does with the fourth is
// the shape it tests.
func adopted(t *testing.T, volID [16]byte) (*readoptVol, uint64, []byte) {
	t.Helper()
	ctx := context.Background()
	v := newReadoptVol(t, volID)
	v.mustSession()
	dir, err := v.ov.Mkdir(ctx, publishRootInode, "ad", 0755, 0, 0)
	if err != nil {
		t.Fatalf("mkdir ad: %v", err)
	}
	want := pseudorandom(40000, int64(volID[3]))
	ino := v.create(dir.Inode, "a.log", want)
	v.checkpoint()
	patch := pseudorandom(999, int64(volID[3])+1)
	if _, err := v.ov.Write(ctx, ino, 101, patch); err != nil {
		t.Fatalf("partial overwrite: %v", err)
	}
	copy(want[101:], patch)
	if st := v.store.Stats(); st.AdoptedFiles != 1 {
		t.Fatalf("the partial overwrite adopted %d file(s), want 1 (%+v)", st.AdoptedFiles, st)
	}
	return v, ino, want
}

// THE ADJACENT SHAPES. Each is the four-op sequence with one thing done
// differently between the adoption and the reopen, and each is here because
// it is a way the journal's record of the adoption and the state the mount
// comes back to could disagree. None of them may cost the file.
func TestTheShapesAroundAnAdoptionAllReopen(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		id   byte
		// between runs after the adoption and before the reopen; it returns
		// the path the file should be read back at and its expected body.
		between func(t *testing.T, v *readoptVol, ino uint64, want []byte) (string, []byte)
	}{{
		// A THIRD checkpoint, and a second adoption of the same file
		// underneath it: two adopted handles in one journal, taken from two
		// different generations, both left behind by a rebase.
		name: "three checkpoints and two adoptions",
		id:   0x11,
		between: func(t *testing.T, v *readoptVol, ino uint64, want []byte) (string, []byte) {
			v.checkpoint()
			second := pseudorandom(700, 41)
			if _, err := v.ov.Write(ctx, ino, 20001, second); err != nil {
				t.Fatalf("second overwrite: %v", err)
			}
			copy(want[20001:], second)
			if st := v.store.Stats(); st.AdoptedFiles != 2 {
				t.Fatalf("the second overwrite adopted %d file(s) in total, want 2", st.AdoptedFiles)
			}
			v.checkpoint()
			return "ad/a.log", want
		},
	}, {
		// A RENAME after the adoption. The inode keeps its number and its
		// adopted extents, and the rebase has to rewrite the base descent
		// chain to the merged path — the failure mode next door to this one.
		name: "renamed after the adoption",
		id:   0x22,
		between: func(t *testing.T, v *readoptVol, ino uint64, want []byte) (string, []byte) {
			dir := lookupPath(t, v.ov, "ad")
			if err := v.ov.Rename(ctx, dir.Inode, "a.log", publishRootInode, "moved.log"); err != nil {
				t.Fatalf("rename: %v", err)
			}
			v.checkpoint()
			return "moved.log", want
		},
	}, {
		// A TRUNCATE after the adoption, which cuts the adopted extent
		// rather than replacing it: the surviving prefix is still the base's
		// chunks, and the record of them has to survive with the right
		// length.
		name: "truncated after the adoption",
		id:   0x44,
		between: func(t *testing.T, v *readoptVol, ino uint64, want []byte) (string, []byte) {
			cut := int64(12345)
			if _, err := v.ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &cut}); err != nil {
				t.Fatalf("truncate: %v", err)
			}
			v.checkpoint()
			return "ad/a.log", want[:cut]
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			v, ino, want := adopted(t, [16]byte{0xad, 0x09, 0x7e, tc.id})
			path, want := tc.between(t, v, ino, want)
			v.end()

			if err := v.session(); err != nil {
				t.Fatalf("the reopen refused:\n%v", err)
			}
			if got := v.read(path, int64(len(want))); !bytes.Equal(got, want) {
				t.Errorf("%s does not read back after the reopen", path)
			}
			// And it can still publish what it serves.
			late := pseudorandom(300, 51)
			if _, err := v.ov.Write(ctx, ino, 51, late); err != nil {
				t.Fatalf("write in the reopened session: %v", err)
			}
			copy(want[51:], late)
			res := v.seal()
			sealed := openGenfs(t, v.inner, res.Superblock, nil)
			n := lookupPath(t, sealed, path)
			if n.Length != int64(len(want)) {
				t.Fatalf("the sealed %s is %d bytes, want %d", path, n.Length, len(want))
			}
			if got := readWhole(t, sealed, n.Inode, n.Length); !bytes.Equal(got, want) {
				t.Errorf("the generation the reopened session sealed does not hold %s as served", path)
			}
		})
	}
}

// A HARDLINKED file, adopted: two names published in the base generation,
// one inode, one adopted extent under both of them. A second link is added
// after the adoption as well, so the shape covers a file that was already
// hardlinked when it was taken over AND one that gains a name afterwards.
//
// The lookup before that second link is not decoration. Link takes a bare
// inode number — it is the one namespace operation that does not resolve a
// name — and the overlay needs the base descent step for the inode to
// persist its edge chain. A checkpoint DROPS that step for every inode it
// cleans (rebase.go, the prov sweep), so linking an inode a checkpoint
// cleaned without looking it up first fails with `overlay: no base
// provenance for inode N`. A mount reaches that state whenever the kernel
// still holds a cached dentry — which clean inodes get the longest TTLs of
// anything here — so it is a real reachable failure and it is FILED in
// docs/TODO.md (readopt-agent) rather than fixed here: it is the namespace's
// provenance rule, not the content store's recovery, and its fix belongs
// with a genfs accessor for the residency record it wants.
func TestAnAdoptedFileWithTwoNamesReopens(t *testing.T) {
	ctx := context.Background()
	v := newReadoptVol(t, [16]byte{0xad, 0x09, 0x7e, 0x33})
	v.mustSession()
	dir, err := v.ov.Mkdir(ctx, publishRootInode, "ad", 0755, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := pseudorandom(40000, 33)
	ino := v.create(dir.Inode, "a.log", want)
	if _, err := v.ov.Link(ctx, ino, publishRootInode, "hard.log"); err != nil {
		t.Fatalf("link before the checkpoint: %v", err)
	}
	v.checkpoint()

	patch := pseudorandom(999, 34)
	if _, err := v.ov.Write(ctx, ino, 101, patch); err != nil {
		t.Fatalf("partial overwrite: %v", err)
	}
	copy(want[101:], patch)
	if st := v.store.Stats(); st.AdoptedFiles != 1 {
		t.Fatalf("the partial overwrite adopted %d file(s), want 1", st.AdoptedFiles)
	}
	// The lookup a mount's link path would have done (see above).
	if n := lookupPath(t, v.ov, "ad/a.log"); n.Inode != ino {
		t.Fatalf("ad/a.log is inode %d, want %d", n.Inode, ino)
	}
	if _, err := v.ov.Link(ctx, ino, publishRootInode, "third.log"); err != nil {
		t.Fatalf("link after the adoption: %v", err)
	}
	v.checkpoint()
	v.end()

	if err := v.session(); err != nil {
		t.Fatalf("the reopen refused:\n%v", err)
	}
	for _, path := range []string{"ad/a.log", "hard.log", "third.log"} {
		if got := v.read(path, int64(len(want))); !bytes.Equal(got, want) {
			t.Errorf("%s does not read back after the reopen", path)
		}
	}
	late := pseudorandom(300, 35)
	if _, err := v.ov.Write(ctx, ino, 51, late); err != nil {
		t.Fatal(err)
	}
	copy(want[51:], late)
	res := v.seal()
	sealed := openGenfs(t, v.inner, res.Superblock, nil)
	for _, path := range []string{"ad/a.log", "hard.log", "third.log"} {
		n := lookupPath(t, sealed, path)
		if n.Inode != ino {
			t.Errorf("%s is inode %d in the sealed generation, want %d (the links came apart)", path, n.Inode, ino)
		}
		if got := readWhole(t, sealed, n.Inode, n.Length); !bytes.Equal(got, want) {
			t.Errorf("the sealed %s is not what the reopened session served", path)
		}
	}
}

// The fifth shape, and the one whose answer is a REFUSAL rather than a
// recovery: the branch moved on under the state directory. A repack is the
// case that matters — it rewrites packs and publishes a generation of its
// own — but any other writer does the same thing, and this is that with the
// fixture's own machinery.
//
// Two things are being pinned. The content store recovers FINE: an adopted
// handle's records come out of the journal, so a generation nobody asked it
// about is not its problem, and the identities they name are content
// addressed — a repack that moves a chunk to another pack does not
// invalidate them. What refuses is the OVERLAY, whose rows mean something
// only over the generation they were recorded against, with the message it
// has always had and an escape in it. That is the right layer for this to
// fail at, and the wrong one is the one this fix removed.
func TestAGenerationPublishedUnderneathIsRefusedByTheOverlayPin(t *testing.T) {
	ctx := context.Background()
	v, _, _ := adopted(t, [16]byte{0xad, 0x09, 0x7e, 0x55})
	v.checkpoint()
	v.end()

	// Somebody else publishes on this branch: a fresh genfs, a fresh
	// overlay of its own, one file, sealed onto the head.
	other, err := genfs.Open(ctx, genfs.Options{
		Inner: v.inner, SB: v.head.Superblock, CacheDir: filepath.Join(v.state, "gencache-other"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck
	ov, err := overlay.Open(filepath.Join(v.state, "overlay-other"), other, overlay.Options{
		NextInode:      other.NextInode(),
		BaseRoot:       other.RootCatalog(),
		BaseGeneration: other.Generation(),
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := ov.Create(ctx, publishRootInode, "elsewhere.txt", 0644, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ov.Write(ctx, n.Inode, 0, []byte("published by another writer")); err != nil {
		t.Fatal(err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		Overlay: ov, Inner: v.inner, SpoolDir: t.TempDir(),
		SigningKey: v.priv, Prev: v.head.Superblock, PrevRaw: v.head.Raw,
		TargetPackSize: 1 << 20, DedupIndexPath: v.index,
	})
	if err != nil {
		t.Fatalf("the other writer's seal: %v", err)
	}
	if err := ov.Close(); err != nil {
		t.Fatal(err)
	}
	v.head = res

	err = v.session()
	if err == nil {
		t.Fatal("a state directory pinned to an older generation was reopened for writing")
	}
	if !errors.Is(err, overlay.ErrGeneration) {
		t.Errorf("the reopen failed with %v; the honest refusal here is the overlay's "+
			"generation pin, which says what to do about it", err)
	}
	if strings.Contains(err.Error(), "re-adopt") || strings.Contains(err.Error(), "no residency") {
		t.Errorf("the content store refused a generation it was never asked about: %v", err)
	}
}

// create is reuseVol.create against this fixture's overlay.
func (v *readoptVol) create(parent uint64, name string, data []byte) uint64 {
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
