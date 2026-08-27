package graft

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/superblock"

	"lukechampine.com/blake3"
)

// The sequential pass over an index, which is the one piece of new
// mechanism fsck needed from this package.
//
// The property under test is not "it returns the right blocks" — that is
// table-stakes and the first test covers it. It is that the pass HOLDS
// NOTHING: the resident set the spike's deleted graftIdentities helper
// built is 336 MB at 10.5 million blocks, and the reason that helper was
// deleted rather than kept is that a check does not need it. If this
// enumerator quietly accumulates, the deletion bought nothing.

// publishIndex writes an index of n blocks spread over objs source objects
// and publishes it to a memStore, returning the store and the superblock
// entry that names it.
func publishIndex(t *testing.T, n, objs int) (*memStore, superblock.GraftEntry, []Block) {
	t.Helper()
	m := newMemStore()
	w, err := NewWriter(t.TempDir(), DefaultBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck

	want := make([]Block, 0, n)
	batch := make([]Block, 0, 512)
	for i := range n {
		var id chunkid.Identity
		// Distinct and deliberately NOT in the order they are added, so
		// the pass is proved to be reading the table's order rather than
		// the writer's.
		binary.BigEndian.PutUint64(id[:8], uint64(i)*0x9e3779b97f4a7c15)
		binary.BigEndian.PutUint64(id[8:16], uint64(i))
		b := Block{ID: id, Loc: Loc{
			Key:    fmt.Sprintf("data/%04d/object-%06d.bin", i%objs, i%objs),
			Off:    int64(i/objs) * DefaultBlock,
			Length: DefaultBlock,
		}}
		want = append(want, b)
		batch = append(batch, b)
		if len(batch) == cap(batch) {
			if err := w.Add(batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	if err := w.Add(batch); err != nil {
		t.Fatal(err)
	}
	ent, err := w.Publish(context.Background(), m, PublishOptions{
		Mount: "/ext", Source: "mem://ext", Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, ent, want
}

func collect(t *testing.T, m *memStore, ent superblock.GraftEntry) ([]Block, EnumResult) {
	t.Helper()
	var got []Block
	res, err := OpenReader(m, ent).Enumerate(context.Background(), func(b Block) error {
		got = append(got, b)
		return nil
	})
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	return got, res
}

// TestEnumerateAgreesWithLookup, in both modes. The windowed reader and
// the sequential one read the same object through completely different
// code, and a graft where they disagreed would be a graft whose fsck and
// whose mount saw different files.
func TestEnumerateAgreesWithLookup(t *testing.T) {
	const n, objs = 4000, 40
	m, ent, want := publishIndex(t, n, objs)

	for _, mode := range []struct {
		name     string
		maxWhole int64
		streamed bool
	}{
		{"held whole", 1 << 30, false},
		{"read by window", 1 << 10, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			defer SetWholeFetchMaxForTest(mode.maxWhole)()
			got, res := collect(t, m, ent)
			if res.Streamed != mode.streamed {
				t.Fatalf("Streamed = %v, want %v", res.Streamed, mode.streamed)
			}
			if len(got) != n || res.Blocks != n {
				t.Fatalf("enumerated %d blocks (result says %d), want %d", len(got), res.Blocks, n)
			}
			if res.Objects != objs {
				t.Fatalf("enumerated %d source objects, want %d", res.Objects, objs)
			}
			// Identity order, which is the contract fsck's per-object
			// folding and the order check both rest on.
			for i := 1; i < len(got); i++ {
				if string(got[i].ID[:]) <= string(got[i-1].ID[:]) {
					t.Fatalf("block %d does not sort after block %d", i, i-1)
				}
			}
			// Every block, with the location a lookup would give.
			r := OpenReader(m, ent)
			byID := make(map[string]Block, len(got))
			for _, b := range got {
				byID[string(b.ID[:])] = b
			}
			for _, w := range want {
				b, ok := byID[string(w.ID[:])]
				if !ok {
					t.Fatalf("block %x was never enumerated", w.ID[:8])
				}
				if b.Loc != w.Loc {
					t.Fatalf("block %x enumerated at %+v, added at %+v", w.ID[:8], b.Loc, w.Loc)
				}
				l, ok, err := r.Lookup(context.Background(), w.ID[:])
				if err != nil || !ok {
					t.Fatalf("Lookup(%x): %v ok=%v", w.ID[:8], err, ok)
				}
				if l != b.Loc {
					t.Fatalf("block %x: Lookup says %+v, Enumerate says %+v", w.ID[:8], l, b.Loc)
				}
			}
		})
	}
}

// TestEnumerateHoldsNothingPerBlock is the memory claim, measured rather
// than asserted, and measured the only way that means anything: the LIVE
// heap, sampled with a forced collection from inside the pass, at two
// index sizes eight times apart.
//
// Cumulative allocation would not do. It counts collectible garbage — a
// hash's internal churn, a buffer refill — and grows gently with any
// amount of data streamed, so a budget on it would either be so loose as
// to permit real accumulation or so tight as to be flaky. What the design
// actually claims is that the RESIDENT set is a function of the source
// object count and not of the block count, and the honest way to see that
// is to hold the block count against it: at 8x the blocks, the live set
// must be the same live set.
//
// The number that matters for scale is the one that was NOT paid: the
// spike's deleted graftIdentities helper built 32 bytes per block, which
// at the 10.5 million blocks of a 10 TB graft is 336 MB.
func TestEnumerateHoldsNothingPerBlock(t *testing.T) {
	const objs = 60
	defer SetWholeFetchMaxForTest(1 << 10)() // force the streamed path

	live := func(n int) (delta int64, size int64) {
		m, ent, _ := publishIndex(t, n, objs)
		var base, s runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&base)
		peak, seen := uint64(0), 0
		res, err := OpenReader(m, ent).Enumerate(context.Background(), func(Block) error {
			seen++
			// A forced collection makes the reading the LIVE set rather
			// than the live set plus whatever the allocator has not swept
			// yet. Every 10,000 blocks, so the sampling itself is not the
			// thing being measured.
			if seen%10000 == 0 {
				runtime.GC()
				runtime.ReadMemStats(&s)
				peak = max(peak, s.HeapAlloc)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Enumerate: %v", err)
		}
		if res.Blocks != n || seen != n {
			t.Fatalf("enumerated %d blocks, want %d", seen, n)
		}
		if res.Bytes != ent.Size {
			t.Fatalf("read %d bytes of a %d-byte index; the whole object has to reach the hash",
				res.Bytes, ent.Size)
		}
		// The store holds the index object, so it must stay reachable for
		// the whole measurement or the baseline moves under it.
		runtime.KeepAlive(m)
		return int64(peak) - int64(base.HeapAlloc), ent.Size
	}

	smallDelta, smallSize := live(30000)
	bigDelta, bigSize := live(240000)
	t.Logf("live set while enumerating: %d bytes over a %d-byte index, %d bytes over a %d-byte one",
		smallDelta, smallSize, bigDelta, bigSize)

	// One read buffer, the string table, the samples, and room for a test
	// not to be flaky. Nowhere near the object, let alone the identity set.
	budget := int64(enumBufSize) * 6
	if bigDelta > budget {
		t.Errorf("enumerating 240,000 blocks held %d bytes live, budget %d — the pass is "+
			"supposed to hold a buffer and the string table and nothing per block "+
			"(the index object is %d bytes; a resident identity set would be %d)",
			bigDelta, budget, bigSize, 240000*keyLen)
	}
	// THE PROPERTY: eight times the blocks, the same live set. A term
	// proportional to the block count would show up here as a factor near
	// eight; the allowance is for the string table and ordinary noise.
	if bigDelta > smallDelta*2 && bigDelta-smallDelta > 512<<10 {
		t.Errorf("the live set grew from %d to %d bytes when the index grew from %d to %d: "+
			"something in this pass is proportional to the number of BLOCKS, which is the "+
			"336 MB at 10.5 million blocks that internal/graft deleted a helper to avoid",
			smallDelta, bigDelta, smallSize, bigSize)
	}
}

// TestEnumerateVerifiesTheWholeObjectHash. The windowed READER cannot do
// this — it never holds the object — and argues, correctly, that it does
// not need to. The sequential pass does hold it, one buffer at a time, so
// it gets the check for free and takes it: this is the only place a
// corrupt index for a large graft becomes one clear finding instead of
// scattered read failures.
func TestEnumerateVerifiesTheWholeObjectHash(t *testing.T) {
	m, ent, _ := publishIndex(t, 4000, 20)
	defer SetWholeFetchMaxForTest(1 << 10)()

	// A byte in the RECORDS, past everything Load looks at, so nothing
	// but a full pass can notice it.
	key := IndexKey(ent.Index)
	m.mu.Lock()
	obj := m.objs[key]
	obj.data[len(obj.data)-9] ^= 0x40
	m.mu.Unlock()

	_, err := OpenReader(m, ent).Enumerate(context.Background(), func(Block) error { return nil })
	if err == nil {
		t.Fatal("a corrupted index object enumerated without complaint")
	}
	if !strings.Contains(err.Error(), "hashes to") {
		t.Fatalf("error does not name the hash mismatch: %v", err)
	}
}

// TestEnumerateRefusesAnUnsortedIndex.
//
// packidx deliberately does not check sort order at open, because that is
// a pass over every entry and an out-of-order table answers "not found"
// rather than answering wrongly. For a PACK that degrades to the caller's
// fallback. For a graft there is no fallback — an identity in no pack and
// in no graft is missing-chunk — so an unsorted index is silently
// unreadable files, and a sequential pass is the only thing in a position
// to catch it.
func TestEnumerateRefusesAnUnsortedIndex(t *testing.T) {
	m, ent, _ := publishIndex(t, 2000, 10)
	key := IndexKey(ent.Index)
	m.mu.Lock()
	data := m.objs[key].data
	m.mu.Unlock()

	// Swap two adjacent records at the very end of the table, then
	// re-name the object by its new hash: the point is the ORDER check,
	// not the hash check, so the object must otherwise be impeccable.
	entry := keyLen + recordLen
	end := len(data)
	a, b := end-2*entry, end-entry
	swapped := append([]byte(nil), data...)
	copy(swapped[a:b], data[b:end])
	copy(swapped[b:end], data[a:b])
	sum := blake3.Sum256(swapped)
	ent.Index = sum
	m.put(IndexKey(sum), swapped, m.objs[key].mtime)

	for _, mode := range []struct {
		name     string
		maxWhole int64
	}{{"held whole", 1 << 30}, {"read by window", 1 << 10}} {
		t.Run(mode.name, func(t *testing.T) {
			defer SetWholeFetchMaxForTest(mode.maxWhole)()
			_, err := OpenReader(m, ent).Enumerate(context.Background(), func(Block) error { return nil })
			if err == nil {
				t.Fatal("an out-of-order index enumerated without complaint")
			}
			if !strings.Contains(err.Error(), "does not sort after") {
				t.Fatalf("error does not name the ordering: %v", err)
			}
		})
	}
}

// TestEnumerateStopsWhenTheCallbackDoes, so a caller that has seen enough
// does not pay for the rest of a 500 MB object.
func TestEnumerateStopsWhenTheCallbackDoes(t *testing.T) {
	m, ent, _ := publishIndex(t, 5000, 25)
	defer SetWholeFetchMaxForTest(1 << 10)()
	stop := fmt.Errorf("enough")
	n := 0
	_, err := OpenReader(m, ent).Enumerate(context.Background(), func(Block) error {
		n++
		if n == 3 {
			return stop
		}
		return nil
	})
	if err != stop { //nolint:errorlint // the sentinel must come back unwrapped
		t.Fatalf("Enumerate returned %v, want the callback's own error unchanged", err)
	}
	if n != 3 {
		t.Fatalf("the callback ran %d times after asking to stop at 3", n)
	}
}
