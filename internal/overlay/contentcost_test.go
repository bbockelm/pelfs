package overlay_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/overlay"
)

// What the two content stores cost on the write path, measured rather
// than argued. The open question the design left was whether journalling
// every operation to SQLite is affordable — the staging store writes one
// onode row per write and nothing else, so this is the comparison that
// decides it.
//
// Two shapes, because they stress different things. MANY SMALL FILES is
// the tar extraction the whole write path exists for: one create, one
// write, one journal row apiece. ONE LARGE FILE is the streaming case,
// where the extent map grows without bound and a journal that recorded
// state rather than operations would go quadratic.
//
// Run with: go test ./internal/overlay/ -run TestContentStoreWriteCost -v
func TestContentStoreWriteCost(t *testing.T) {
	if testing.Short() {
		t.Skip("write-cost measurement")
	}
	for _, shape := range []struct {
		name  string
		files int
		size  int
		chunk int
	}{
		{"2000 files of 8 KiB", 2000, 8 << 10, 8 << 10},
		{"one 32 MiB file in 128 KiB writes", 1, 32 << 20, 128 << 10},
	} {
		t.Run(shape.name, func(t *testing.T) {
			staging, _ := measureWrites(t, false, shape.files, shape.size, shape.chunk)
			memtabled, _ := measureWrites(t, true, shape.files, shape.size, shape.chunk)
			// The two numbers do not measure the same work, and the
			// difference is the design. Staging counts no chunking,
			// hashing, packing or uploading at all: it defers every byte of
			// that to the seal, where the user is waiting. The memtable
			// number includes whatever of it ran during the writes. So a
			// ratio above 1 is work MOVED rather than work added — the
			// question this answers is only whether the journal makes a
			// write too expensive to do at all.
			t.Logf("%s: staging %v, memtable %v — %.2fx",
				shape.name, staging.Round(time.Millisecond), memtabled.Round(time.Millisecond),
				float64(memtabled)/float64(staging))
		})
	}
}

// measureWrites times the writes alone: the fixture, the store and the
// overlay are all built before the clock starts, and nothing is sealed,
// because what is being compared is what a WRITE costs.
func measureWrites(t *testing.T, useMemtable bool, files, size, chunk int) (time.Duration, int64) {
	t.Helper()
	ctx := context.Background()
	uuid := "c0570000-0001-4000-8000-000000000001"
	if useMemtable {
		uuid = "c0570001-0001-4000-8000-000000000001"
	}
	fx := newFixture(t, uuid)
	opts := fx.options()
	var store *memtable.Store
	if useMemtable {
		var closeStore func() error
		var err error
		store, _, closeStore, err = overlay.OpenContentStore(t.TempDir(), memtable.Options{
			// A ring big enough that this measurement is not really a
			// measurement of backpressure, and packs small enough that
			// flushes happen during it rather than after.
			TableSize: 8 << 20, Obj: fx.inner, Base: fx.base,
			Chunk:  chunkid.Options{MinSize: 64 << 10, AvgSize: 256 << 10, MaxSize: 1 << 20},
			Hasher: chunkid.NewHasher(nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closeStore() }) //nolint:errcheck
		opts.Memtable = store
	}
	ov, err := overlay.Open(t.TempDir(), fx.base, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ov.Close() }) //nolint:errcheck

	buf := pseudorandom(chunk, 99)
	start := time.Now()
	for f := 0; f < files; f++ {
		n, err := ov.Create(ctx, rootIno, "f"+strconv.Itoa(f), 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < size; off += chunk {
			w := min(chunk, size-off)
			if _, err := ov.Write(ctx, n.Inode, int64(off), buf[:w]); err != nil {
				t.Fatal(err)
			}
		}
	}
	elapsed := time.Since(start)
	if store != nil {
		return elapsed, store.Stats().UploadedBytes
	}
	return elapsed, 0
}
