package publish_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/publish"
	"github.com/bbockelm/pelfs/internal/superblock"
	"github.com/bbockelm/pelfs/internal/testvol"
)

// The write path this file exercises had exactly one test before it: one
// overlay, one memtable, one write per file, one seal. Everything else
// that walks an overlay — the snapshot, the rebase, the whole checkpoint
// cycle, the content-store conformance suite — ran against the STAGING
// store, whose bytes are a file and cannot be sparse. So the shape below
// had never been sealed by anything: an inode whose extent map covers
// less than its length.
//
// It is not exotic. A write past the end of the file makes one, and so
// does a truncate that grows one; the read path answers zeros for the
// gap and every byte reads back correctly. Only the SEAL could tell the
// difference, and it published a catalog whose chunk lengths summed
// short of the node's length — a file no reader will open.

// rig is one volume, one base generation, one overlay, sealed by publish.
// content picks which store holds the bytes, because that is the whole
// question here and both must answer the same way.
type rig struct {
	t     *testing.T
	obj   *countingObjStore
	v     *testvol.Volume
	base  *genfs.FS
	store *memtable.Store
	ov    *overlay.FS
	head  *publish.Result
}

func newRig(t *testing.T, uuid string, useMemtable bool) *rig {
	t.Helper()
	obj := &countingObjStore{Store: newInner(t)}
	v := newTestVolume(t, obj, uuid)
	v.WriteFile(genfs.RootInode, "seed.txt", []byte("seed"))
	head := v.Publish(publish.Options{})
	base := openGenfs(t, obj, head.Superblock, nil)

	r := &rig{t: t, obj: obj, v: v, base: base, head: head}
	opts := overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
	}
	if useMemtable {
		store, err := memtable.New(memtable.Options{
			Dir: t.TempDir(), TableSize: 1 << 20, Obj: obj, Base: base,
			Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
			Hasher: chunkid.NewHasher(nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() }) //nolint:errcheck
		r.store = store
		opts.Memtable = store
	}
	ov, err := overlay.Open(t.TempDir(), base, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ov.Close() }) //nolint:errcheck
	r.ov = ov
	return r
}

// checkpoint runs the mount's own sequence: snapshot, seal the snapshot,
// release the frozen view, swap the base, rebase (cmd/pelfs/mountgen.go).
func (r *rig) checkpoint(n int) {
	r.t.Helper()
	ctx := context.Background()
	snap, err := r.ov.Snapshot(ctx, filepath.Join(r.t.TempDir(), fmt.Sprintf("snap%d", n)))
	if err != nil {
		r.t.Fatalf("snapshot: %v", err)
	}
	res, err := publish.Seal(ctx, publish.Options{
		OverlaySnapshot: snap, Inner: r.obj, SpoolDir: r.t.TempDir(),
		SigningKey: r.v.SigningKey(), Prev: r.head.Superblock, PrevRaw: r.head.Raw,
	})
	if err != nil {
		r.t.Fatalf("checkpoint seal: %v", err)
	}
	seq := snap.Seq()
	if err := snap.Close(); err != nil {
		r.t.Fatalf("release the snapshot: %v", err)
	}
	if _, err := r.base.Swap(ctx, res.Superblock); err != nil {
		r.t.Fatalf("swap: %v", err)
	}
	if _, err := r.ov.Rebase(ctx, seq, overlay.Options{
		BaseRoot: res.Superblock.RootCatalog, BaseGeneration: res.Superblock.Generation,
	}); err != nil {
		r.t.Fatalf("rebase: %v", err)
	}
	r.head = res
}

// seal seals the live overlay, which is what unmount does.
func (r *rig) seal() *superblock.Superblock {
	r.t.Helper()
	res, err := publish.Seal(context.Background(), publish.Options{
		Overlay: r.ov, Inner: r.obj, SpoolDir: r.t.TempDir(),
		SigningKey: r.v.SigningKey(), Prev: r.head.Superblock, PrevRaw: r.head.Raw,
	})
	if err != nil {
		r.t.Fatalf("seal: %v", err)
	}
	r.head = res
	return res.Superblock
}

// mustReadBack opens the sealed generation and checks the file whole.
func (r *rig) mustReadBack(sb *superblock.Superblock, name string, want []byte) {
	r.t.Helper()
	ctx := context.Background()
	sealed := openGenfs(r.t, r.obj, sb, nil)
	n, err := sealed.Lookup(ctx, genfs.RootInode, name)
	if err != nil {
		r.t.Fatalf("lookup %s: %v", name, err)
	}
	if n.Length != int64(len(want)) {
		r.t.Fatalf("%s: node length %d, want %d", name, n.Length, len(want))
	}
	got := make([]byte, n.Length)
	if _, err := sealed.Read(ctx, n.Inode, 0, got); err != nil {
		// This is the owner's error, and the only place it can be caught
		// without a human reading the file: "chunk lengths sum to X, node
		// length is Y".
		r.t.Fatalf("%s does not read back from the sealed generation: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		r.t.Fatalf("%s does not read back byte-exact", name)
	}
}

const wr = 16384 // one NFS write

// forEachStore runs a case against both content stores. The staging
// store is the reference: it has no way to be sparse, so whatever it
// seals is what the memtable must seal too.
func forEachStore(t *testing.T, body func(t *testing.T, r *rig)) {
	t.Helper()
	for i, useMemtable := range []bool{false, true} {
		name := "staging"
		if useMemtable {
			name = "memtable"
		}
		t.Run(name, func(t *testing.T) {
			body(t, newRig(t, fmt.Sprintf("5ea15ea1-000%d-4000-8000-000000000001", i+4), useMemtable))
		})
	}
}

func TestSealOfASparseFileReadsBack(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		make func(t *testing.T, r *rig, ino uint64) []byte
	}{
		{"a write past the end of the file", func(t *testing.T, r *rig, ino uint64) []byte {
			want := make([]byte, 3*wr)
			head, tail := bytesPattern(wr, 1), bytesPattern(wr, 2)
			mustW(t, r, ino, 0, head)
			mustW(t, r, ino, 2*wr, tail)
			copy(want, head)
			copy(want[2*wr:], tail)
			return want
		}},
		{"a truncate that grows the file", func(t *testing.T, r *rig, ino uint64) []byte {
			want := make([]byte, 3*wr)
			body := bytesPattern(2*wr, 3)
			mustW(t, r, ino, 0, body)
			size := int64(3 * wr)
			if _, err := r.ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &size}); err != nil {
				t.Fatal(err)
			}
			copy(want, body)
			return want
		}},
		{"a file that is nothing but a hole", func(t *testing.T, r *rig, ino uint64) []byte {
			size := int64(2 * wr)
			if _, err := r.ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &size}); err != nil {
				t.Fatal(err)
			}
			return make([]byte, size)
		}},
		{"a hole a checkpoint published before the seal did", func(t *testing.T, r *rig, ino uint64) []byte {
			want := make([]byte, 4*wr)
			head := bytesPattern(wr, 4)
			mustW(t, r, ino, 0, head)
			copy(want, head)
			size := int64(3 * wr)
			if _, err := r.ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &size}); err != nil {
				t.Fatal(err)
			}
			r.checkpoint(0)
			tail := bytesPattern(wr, 5)
			mustW(t, r, ino, 3*wr, tail)
			copy(want[3*wr:], tail)
			return want
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, r *rig) {
				n, err := r.ov.Create(ctx, genfs.RootInode, "sparse.bin", 0644, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				want := tc.make(t, r, n.Inode)
				r.mustReadBack(r.seal(), "sparse.bin", want)
			})
		})
	}
}

// The git-checkout shape, which is how this was found: a train of 16 KiB
// writes, a checkpoint landing at every point in it, and the chmod git
// gives an executable after it closes the file. Nothing exercised a
// checkpoint over a memtable-backed overlay before, so the whole cycle —
// snapshot, seal, swap, rebase, adopt-from-the-new-base, seal again — is
// under test here for the first time.
func TestCheckpointedWriteTrainWithAChmod(t *testing.T) {
	ctx := context.Background()
	for n := 1; n <= 4; n++ {
		for cut := 0; cut <= n; cut++ {
			t.Run(fmt.Sprintf("%dx16KiB_checkpoint_after_%d", n, cut), func(t *testing.T) {
				r := newRig(t, "5ea15ea1-0006-4000-8000-000000000001", true)
				node, err := r.ov.Create(ctx, genfs.RootInode, "prog", 0644, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
				var want []byte
				if cut == 0 {
					r.checkpoint(0)
				}
				for i := 0; i < n; i++ {
					blk := bytesPattern(wr, uint64(i+1))
					mustW(t, r, node.Inode, int64(i*wr), blk)
					want = append(want, blk...)
					if i+1 == cut {
						r.checkpoint(i + 1)
					}
				}
				// git chmods an executable after it closes it, which is what
				// both of the owner's casualties had in common.
				mode := uint32(0755)
				if _, err := r.ov.SetAttr(ctx, node.Inode, overlay.SetAttrIn{Mode: &mode}); err != nil {
					t.Fatal(err)
				}
				sb := r.seal()
				r.mustReadBack(sb, "prog", want)
				sealed := openGenfs(t, r.obj, sb, nil)
				nd, err := sealed.Lookup(ctx, genfs.RootInode, "prog")
				if err != nil {
					t.Fatal(err)
				}
				if nd.Mode&0111 == 0 {
					t.Fatalf("the chmod did not reach the generation: mode %o", nd.Mode)
				}
			})
		}
	}
}

func mustW(t *testing.T, r *rig, ino uint64, off int64, p []byte) {
	t.Helper()
	if _, err := r.ov.Write(context.Background(), ino, off, p); err != nil {
		t.Fatalf("write inode %d at %d: %v", ino, off, err)
	}
}
