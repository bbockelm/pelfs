package memtable

// batch is one pack run's worth of extents, taken from the ring's tail.
//
// It replaces the frozen table the store used to swap to. With a ring
// there is nothing to swap: the writer keeps appending at the head while
// a batch is cut from the oldest bytes, and the space a batch occupied is
// reclaimed the moment its locations are published. What a batch carries
// is therefore a decision — these records, this range — rather than
// storage of its own.
type batch struct {
	seq uint64

	// recs are the extents this run will pack, in ring order. Oldest
	// first, because promotion is by age and age is position.
	recs []Record

	// live is liveness AT CUT TIME. An extent whose count is zero died in
	// the ring and is never uploaded — the design's central claim — and
	// snapshotting it here means a write landing mid-flush cannot change
	// what this run decided to send.
	live map[Handle]int

	// inodes is the set this batch touches, so the flush consults only
	// the content rows it must.
	inodes map[uint64]struct{}

	// from and to bound the ring region this batch consumed. Reclaiming
	// happens after publication, never before: until the locations are
	// installed, the ring is still the only copy.
	from, to uint64
}

func (b *batch) empty() bool { return len(b.recs) == 0 }
