package reach

import (
	"bytes"
	"encoding/binary"
	mrand "math/rand"
	"sync"
	"testing"
)

// records builds n deterministic records whose first keyLen bytes are the
// key and whose tail carries the record's ordinal, so a test can tell
// which copy of a duplicated key it is looking at.
func records(n, keyLen, recLen int, seed int64, keySpace int) []byte {
	rng := mrand.New(mrand.NewSource(seed))
	out := make([]byte, 0, n*recLen)
	rec := make([]byte, recLen)
	for i := range n {
		for j := range rec {
			rec[j] = 0
		}
		binary.BigEndian.PutUint32(rec[:keyLen], uint32(rng.Intn(keySpace)))
		binary.LittleEndian.PutUint32(rec[keyLen:], uint32(i))
		out = append(out, rec...)
	}
	return out
}

// drain reads a merge out and checks it is in key order, returning every
// record it produced.
func drain(t *testing.T, m *merged, keyLen, recLen int) [][]byte {
	t.Helper()
	var got [][]byte
	var prev []byte
	for {
		rec, ok := m.Next()
		if !ok {
			break
		}
		if len(rec) != recLen {
			t.Fatalf("record %d is %d bytes, want %d", len(got), len(rec), recLen)
		}
		if prev != nil && bytes.Compare(prev[:keyLen], rec[:keyLen]) > 0 {
			t.Fatalf("record %d (key %x) follows key %x", len(got), rec[:keyLen], prev[:keyLen])
		}
		cp := make([]byte, recLen)
		copy(cp, rec)
		got = append(got, cp)
		prev = cp
	}
	if err := m.Err(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	return got
}

// The spilling path and the memory path must produce the same multiset in
// the same order: which one runs is an accident of how much a caller
// buffered, and the sweep's numbers must not depend on it.
func TestSpilledAndResidentSortsAgree(t *testing.T) {
	const (
		n      = 20_000
		keyLen = 8
		recLen = 24
	)
	in := records(n, keyLen, recLen, 7, n/4) // a quarter as many keys as records: duplicates guaranteed

	run := func(budget int) [][]byte {
		s := newSorter(t.TempDir(), "t", keyLen, recLen, budget)
		defer s.Close() //nolint:errcheck
		// Batches of a few records, as the sweep hands over a trailer at a
		// time rather than a record at a time.
		for off := 0; off < len(in); off += 7 * recLen {
			end := min(off+7*recLen, len(in))
			if err := s.Add(in[off:end]); err != nil {
				t.Fatal(err)
			}
		}
		if s.Count() != n {
			t.Fatalf("accepted %d records, want %d", s.Count(), n)
		}
		m, err := s.Sorted()
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close() //nolint:errcheck
		return drain(t, m, keyLen, recLen)
	}

	spilled := run(64 * recLen) // 64 records per run: hundreds of runs
	resident := run(1 << 20)    // everything fits
	if len(spilled) != n {
		t.Fatalf("the spilled sort produced %d records, want %d", len(spilled), n)
	}
	if len(resident) != n {
		t.Fatalf("the resident sort produced %d records, want %d", len(resident), n)
	}
	for i := range spilled {
		if !bytes.Equal(spilled[i][:keyLen], resident[i][:keyLen]) {
			t.Fatalf("record %d: spilled key %x, resident %x", i, spilled[i][:keyLen], resident[i][:keyLen])
		}
	}
	t.Logf("%d records, %d distinct keys, spilled and resident agree", n, distinctKeys(spilled, keyLen))
}

func distinctKeys(recs [][]byte, keyLen int) int {
	seen := 0
	var prev []byte
	for _, r := range recs {
		if prev == nil || !bytes.Equal(prev[:keyLen], r[:keyLen]) {
			seen++
			prev = r
		}
	}
	return seen
}

// Every record survives, including duplicates: the sweep counts a chunk
// placed in two packs twice, once for each pack it keeps alive.
func TestSortKeepsEveryDuplicate(t *testing.T) {
	const (
		n      = 5_000
		keyLen = 8
		recLen = 16
	)
	in := records(n, keyLen, recLen, 11, 10) // ten keys, five hundred copies each
	s := newSorter(t.TempDir(), "dup", keyLen, recLen, 32*recLen)
	defer s.Close() //nolint:errcheck
	if err := s.Add(in); err != nil {
		t.Fatal(err)
	}
	m, err := s.Sorted()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close() //nolint:errcheck
	got := drain(t, m, keyLen, recLen)
	if len(got) != n {
		t.Fatalf("%d records came back, want %d", len(got), n)
	}
	ordinals := map[uint32]bool{}
	for _, r := range got {
		ordinals[binary.LittleEndian.Uint32(r[keyLen:])] = true
	}
	if len(ordinals) != n {
		t.Fatalf("%d distinct records survived, want %d: the sort lost or duplicated some", len(ordinals), n)
	}
}

// Adds arrive from the trailer workers concurrently.
func TestConcurrentAddsAreSorted(t *testing.T) {
	const (
		keyLen  = 8
		recLen  = 16
		workers = 8
		perW    = 2_000
	)
	s := newSorter(t.TempDir(), "conc", keyLen, recLen, 48*recLen)
	defer s.Close() //nolint:errcheck
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			in := records(perW, keyLen, recLen, int64(w), perW)
			for off := 0; off < len(in); off += 13 * recLen {
				end := min(off+13*recLen, len(in))
				if err := s.Add(in[off:end]); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
	if s.Count() != workers*perW {
		t.Fatalf("accepted %d records, want %d", s.Count(), workers*perW)
	}
	m, err := s.Sorted()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close() //nolint:errcheck
	if got := drain(t, m, keyLen, recLen); len(got) != workers*perW {
		t.Fatalf("%d records came back, want %d", len(got), workers*perW)
	}
}

// A batch that is not whole records is a caller bug that would otherwise
// corrupt every record after it in the buffer.
func TestARaggedBatchIsRefused(t *testing.T) {
	s := newSorter(t.TempDir(), "ragged", 8, 16, 0)
	defer s.Close() //nolint:errcheck
	if err := s.Add(make([]byte, 17)); err == nil {
		t.Fatal("a 17-byte batch of 16-byte records was accepted")
	}
}

// Adding after the merge has begun would drop records into a buffer
// nobody reads again — silently under-counting liveness, which is the
// direction that deletes data.
func TestAddingAfterTheMergeIsRefused(t *testing.T) {
	s := newSorter(t.TempDir(), "late", 8, 16, 0)
	defer s.Close() //nolint:errcheck
	if err := s.Add(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	m, err := s.Sorted()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close() //nolint:errcheck
	if err := s.Add(make([]byte, 16)); err == nil {
		t.Fatal("a record was accepted after the merge began")
	}
}
