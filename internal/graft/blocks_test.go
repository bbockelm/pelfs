package graft

import (
	"fmt"
	"testing"
)

// TestTheLadderKeepsSmallFilesSmallAndBoundsLargeOnes is the whole
// argument for a per-object block size in one table: the floor is what a
// software area gets, the ceiling is what a multi-GB payload gets, and
// nothing in between pays for the other's index budget.
func TestTheLadderKeepsSmallFilesSmallAndBoundsLargeOnes(t *testing.T) {
	p := DefaultPolicy()
	for _, tc := range []struct {
		size int64
		want int64
	}{
		{1 << 10, 1 << 20},          // a 1 KB file: one short block, no amplification
		{1 << 20, 1 << 20},          // exactly one block
		{32 << 20, 1 << 20},         // 32 blocks: still at the floor
		{33 << 20, 2 << 20},         // one block over: the ladder steps
		{100 << 20, 4 << 20},        // the 100 MB average of the 10 TB case
		{10 << 30, DefaultBlockMax}, // a 10 GB payload: clamped at the ceiling
	} {
		if got := p.For(tc.size); got != tc.want {
			t.Errorf("a %d-byte object is cut at %d, want %d", tc.size, got, tc.want)
		}
	}
	// Every step is a power-of-two multiple of the floor, which is what
	// makes a refresh reproducible from the three recorded numbers.
	for size := int64(1); size < 64<<30; size = size*3/2 + 1 {
		b := p.For(size)
		if b%p.Block != 0 || b&(b-1) != 0 {
			t.Fatalf("a %d-byte object is cut at %d, which is not a power-of-two multiple of %d",
				size, b, p.Block)
		}
	}
}

// TestTheOwnersCase is the arithmetic he asked for, run rather than
// asserted from memory: 100,000 files totalling 10 TB.
func TestTheOwnersCase(t *testing.T) {
	const files = 100000
	const total = 10 << 40
	const avg = total / files

	report := func(name string, p BlockPolicy) (int64, int64) {
		blocks := p.Blocks(avg) * files
		idx := blocks * 48
		t.Logf("%-22s block %-9s -> %d blocks, %d MB of index",
			name, byteStr(p.For(avg)), blocks, idx>>20)
		return blocks, idx
	}
	_, flat1 := report("one global 1 MiB", BlockPolicy{Block: 1 << 20, Max: 1 << 20, PerObject: 1 << 30})
	_, flat8 := report("one global 8 MiB", BlockPolicy{Block: 8 << 20, Max: 8 << 20, PerObject: 1 << 30})
	_, ladder := report("the ladder (default)", DefaultPolicy())

	// The point of the ladder is that it sits between the two, without
	// charging a small-file read for a large file's index budget — and
	// the superblock is untouched by all of it: ONE entry per graft root,
	// however many files there are.
	if !(ladder < flat1 && ladder > flat8) {
		t.Fatalf("the ladder indexes to %d bytes, outside the %d..%d it should sit between",
			ladder, flat8, flat1)
	}
	// A small file under the ladder is still cut at the floor, so its
	// minimum verified read is unchanged by anything a 10 GB sibling did.
	if got := DefaultPolicy().For(200 << 10); got != DefaultBlock {
		t.Fatalf("a 200 KB file next to a 10 GB one is cut at %d, want the %d floor", got, DefaultBlock)
	}
}

func byteStr(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

// TestBadPoliciesAreRefusedBeforeATerabyteIsRead: a flag mistake must
// fail at once, not after hours of reading.
func TestBadPoliciesAreRefusedBeforeATerabyteIsRead(t *testing.T) {
	for _, p := range []BlockPolicy{
		{Block: 3 << 20, Max: 6 << 20, PerObject: 4}, // not a power of two
		{Block: 1 << 20, Max: 3 << 20, PerObject: 4}, // ceiling not a multiple
		{Block: 1 << 20, Max: 4 << 30, PerObject: 4}, // a "block" that is a download
	} {
		if err := p.Validate(); err == nil {
			t.Errorf("%+v was accepted", p)
		}
	}
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatalf("the default policy is invalid: %v", err)
	}
}
