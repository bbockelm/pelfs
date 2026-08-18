package overlay_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// The two content stores must be indistinguishable from above. Every case
// here is run against both, because the only safe way to swap where a
// mount's bytes live is to have one set of expectations that neither
// backend is allowed to interpret differently.
//
// What the memtable changes is underneath: bytes reach the federation
// during the session, and a file that came from the base is taken over by
// reference. Neither is visible to a caller, which is the point.
func forEachContentStore(t *testing.T, body func(t *testing.T, fx *fixture, ov *overlay.FS)) {
	t.Helper()
	t.Run("staging", func(t *testing.T) {
		fx := newFixture(t, "c0f0c0f0-0001-4000-8000-000000000001")
		body(t, fx, openOverlay(t, fx, ""))
	})
	t.Run("memtable", func(t *testing.T) {
		fx := newFixture(t, "c0f0c0f0-0002-4000-8000-000000000002")
		store, err := memtable.New(memtable.Options{
			Dir: t.TempDir(), TableSize: 1 << 20, Obj: fx.inner, Base: fx.base,
			Chunk:  chunkid.Options{MinSize: 1 << 10, AvgSize: 4 << 10, MaxSize: 16 << 10},
			Hasher: chunkid.NewHasher(nil),
		})
		if err != nil {
			t.Fatalf("memtable.New: %v", err)
		}
		t.Cleanup(func() { store.Close() }) //nolint:errcheck
		opts := fx.options()
		opts.Memtable = store
		ov, err := overlay.Open(t.TempDir(), fx.base, opts)
		if err != nil {
			t.Fatalf("overlay.Open: %v", err)
		}
		t.Cleanup(func() { ov.Close() }) //nolint:errcheck
		body(t, fx, ov)
	})
}

func TestContentStoreCreateAndRead(t *testing.T) {
	forEachContentStore(t, func(t *testing.T, _ *fixture, ov *overlay.FS) {
		ctx := context.Background()
		n, err := ov.Create(ctx, rootIno, "new.txt", 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		// A file with no writes reads as empty rather than as an error.
		if got := readAllFS(t, ov, n.Inode, 0); len(got) != 0 {
			t.Fatalf("a fresh file read %d bytes", len(got))
		}
		body := pseudorandom(50000, 7)
		if _, err := ov.Write(ctx, n.Inode, 0, body); err != nil {
			t.Fatal(err)
		}
		mustBody(t, ov, "new.txt", body)

		// Append, then overwrite in the middle: the two shapes that decide
		// whether a store's copy-on-write rule is right.
		tail := pseudorandom(4000, 8)
		if _, err := ov.Write(ctx, n.Inode, int64(len(body)), tail); err != nil {
			t.Fatal(err)
		}
		want := append(append([]byte(nil), body...), tail...)
		mustBody(t, ov, "new.txt", want)

		patch := pseudorandom(300, 9)
		if _, err := ov.Write(ctx, n.Inode, 5000, patch); err != nil {
			t.Fatal(err)
		}
		copy(want[5000:], patch)
		mustBody(t, ov, "new.txt", want)
	})
}

func TestContentStoreWritesIntoABaseFile(t *testing.T) {
	forEachContentStore(t, func(t *testing.T, fx *fixture, ov *overlay.FS) {
		ctx := context.Background()
		base := fx.body["big.bin"]
		ino := lookupPath(t, ov, "big.bin").Inode

		// Reading before writing must come from the base.
		mustBody(t, ov, "big.bin", base)

		// One byte in the middle: the case that costs a staging store the
		// whole file and a memtable one row.
		patch := []byte{0xAA}
		if _, err := ov.Write(ctx, ino, 1000, patch); err != nil {
			t.Fatal(err)
		}
		want := append([]byte(nil), base...)
		copy(want[1000:], patch)
		mustBody(t, ov, "big.bin", want)

		// And an append past the base's end.
		tail := pseudorandom(2000, 11)
		if _, err := ov.Write(ctx, ino, int64(len(want)), tail); err != nil {
			t.Fatal(err)
		}
		want = append(want, tail...)
		mustBody(t, ov, "big.bin", want)
	})
}

func TestContentStoreTruncates(t *testing.T) {
	forEachContentStore(t, func(t *testing.T, fx *fixture, ov *overlay.FS) {
		ctx := context.Background()
		base := fx.body["big.bin"]
		ino := lookupPath(t, ov, "big.bin").Inode

		// Shrink a base file: the surviving prefix must be exact.
		small := int64(9000)
		if _, err := ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &small}); err != nil {
			t.Fatal(err)
		}
		mustBody(t, ov, "big.bin", base[:small])

		// Grow it again: the new region is a hole and reads as zeros.
		big := small + 4096
		if _, err := ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &big}); err != nil {
			t.Fatal(err)
		}
		want := append(append([]byte(nil), base[:small]...), make([]byte, 4096)...)
		mustBody(t, ov, "big.bin", want)

		// Truncate to zero, then write again.
		zero := int64(0)
		if _, err := ov.SetAttr(ctx, ino, overlay.SetAttrIn{Size: &zero}); err != nil {
			t.Fatal(err)
		}
		if got := readAllFS(t, ov, ino, 0); len(got) != 0 {
			t.Fatalf("a truncated file read %d bytes", len(got))
		}
		fresh := pseudorandom(3000, 12)
		if _, err := ov.Write(ctx, ino, 0, fresh); err != nil {
			t.Fatal(err)
		}
		mustBody(t, ov, "big.bin", fresh)
	})
}

func TestContentStoreDropsRemovedFiles(t *testing.T) {
	forEachContentStore(t, func(t *testing.T, _ *fixture, ov *overlay.FS) {
		ctx := context.Background()
		n, err := ov.Create(ctx, rootIno, "doomed.txt", 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, n.Inode, 0, pseudorandom(20000, 13)); err != nil {
			t.Fatal(err)
		}
		staged, err := ov.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if staged.StagedBytes == 0 {
			t.Fatal("a written file staged no bytes")
		}
		if err := ov.Unlink(ctx, rootIno, "doomed.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := lookupPathErr(ov, "doomed.txt"); err == nil {
			t.Fatal("the unlinked name still resolves")
		}
		after, err := ov.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if after.StagedBytes >= staged.StagedBytes {
			t.Errorf("staged bytes did not fall after an unlink (%d then %d)",
				staged.StagedBytes, after.StagedBytes)
		}
	})
}

// Reading a range rather than the whole file, at offsets that are not
// chunk boundaries — the shape a mount actually issues.
func TestContentStoreServesPartialReads(t *testing.T) {
	forEachContentStore(t, func(t *testing.T, fx *fixture, ov *overlay.FS) {
		ctx := context.Background()
		ino := lookupPath(t, ov, "big.bin").Inode
		want := append([]byte(nil), fx.body["big.bin"]...)
		patch := pseudorandom(777, 14)
		if _, err := ov.Write(ctx, ino, 12345, patch); err != nil {
			t.Fatal(err)
		}
		copy(want[12345:], patch)
		for _, r := range []struct{ off, n int64 }{
			{0, 1}, {1, 4095}, {12000, 1500}, {12345, 777}, {30000, 5000},
			{int64(len(want)) - 10, 10},
		} {
			got := make([]byte, r.n)
			n, err := ov.Read(ctx, ino, r.off, got)
			if err != nil {
				t.Fatalf("read [%d,+%d): %v", r.off, r.n, err)
			}
			if int64(n) != r.n || !bytes.Equal(got[:n], want[r.off:r.off+r.n]) {
				t.Fatalf("read [%d,+%d) returned %d bytes and did not match", r.off, r.n, n)
			}
		}
	})
}
