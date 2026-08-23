package memtable

import (
	"context"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// Placer is the part of a Base that answers "does the generation I am
// building on already store these bytes". *genfs.FS satisfies it.
//
// It is separate from Base, and consulted by type assertion, because it is
// an OPTIMIZATION and a Base that cannot answer must stay a usable Base:
// every measurement harness and most tests supply one, and a store with no
// placer behind it is exactly today's store.
//
// The contract is three-valued and only two values are on the wire. A hit
// means "stored, in a pack this generation lists, confirmed against that
// pack's own signed-for trailer". A miss means "not cheaply", NEVER
// "absent" — the caller's answer to a miss is to store the bytes again,
// which is always correct because identity is content.
type Placer interface {
	Placed(ctx context.Context, id chunkid.Identity) (genfs.Placement, bool)
	// Generation names the generation the answers are about. A caller that
	// recorded one has to be able to notice it moved: under a live mount
	// only a repack moves it, and a repack is the only thing that can stop
	// a stored chunk being stored.
	Generation() uint64
}

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
