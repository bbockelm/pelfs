package graft

import "fmt"

// Block size, which is the one trade a graft cannot cheat.
//
// A grafted read is verified by rehashing a WHOLE BLOCK, so the block
// size IS the minimum verified read. That makes it a single knob with two
// opposed costs and no third option:
//
//   - index size, which is (bytes / block) * 48. A 10 TB graft at 1 MiB
//     is 10.5M blocks and a 505 MB index; at 8 MiB it is 1.3M blocks and
//     a 63 MB index.
//   - read amplification, which is the block. A 4 KiB read of a file cut
//     at 8 MiB fetches and hashes 8 MiB.
//
// One global value has to be wrong for one of them, because a real tree
// is not one size: a CVMFS software area is hundreds of thousands of
// files of a few KB next to a handful of multi-GB payloads, and the
// number that keeps the index small on the payloads is the number that
// makes every small-file read absurd.
//
// So the block size is chosen PER OBJECT, and the format did not have to
// change to allow it: an index record already carries a per-block LENGTH,
// because the last block of every object is short. Cutting different
// objects at different sizes uses a field that was always there. What did
// have to be recorded is the RULE, in the superblock entry, because a
// refresh that cut differently would move every identity and be a new
// graft rather than a refresh.
//
// # The rule
//
// An object is cut into at most PerObject blocks, at a block size that is
// a power-of-two multiple of Block and never above Max:
//
//	block = Block
//	while size/block > PerObject and block < Max: block *= 2
//
// The invariant it buys is that the index cost of a graft is bounded by
// its OBJECT COUNT (PerObject records each) as well as by its byte count,
// so a tree of a few enormous files cannot produce an index that must be
// windowed at all, and a tree of many small files — where each file is
// one short block anyway — is untouched by the ladder.
//
// Worked, for the case this was written against: 100,000 files totalling
// 10 TB, so 100 MB on average.
//
//	one global 1 MiB: 10.5M blocks, 505 MB index, 1 MiB minimum read
//	one global 8 MiB:  1.3M blocks,  63 MB index, 8 MiB minimum read
//	the ladder:       ~2.6M blocks, ~127 MB index, and the minimum read
//	                  is 4 MiB on a 100 MB file, 1 MiB on a 1 MB file,
//	                  and the file itself on anything under 1 MiB
//
// The ladder is not the smallest index available. It is the smallest
// index available WITHOUT charging a small-file read for a large file's
// index budget, which is the trade a single number cannot express.

// DefaultBlock is the floor: the size a small or medium object is cut at,
// and the granularity every larger size is a multiple of.
//
// 1 MiB, and the reasoning is the opposite of the packed path's. A CDC
// chunk is sized to maximize dedup across edits; a graft block is sized
// to trade index size against read amplification, and nothing about it
// dedups.
const DefaultBlock int64 = 1 << 20

// DefaultBlockMax is the ceiling the ladder will climb to. 8 MiB is one
// ranged GET that any transport is happy with and a verified read a
// bulk reader does not notice; it is also where the amplification on a
// small random read stops being defensible at all.
const DefaultBlockMax int64 = 8 << 20

// DefaultBlocksPerObject is how many blocks one object may be cut into
// before the ladder doubles its block size.
//
// 32 is chosen from the arithmetic above rather than from taste: it is
// the smallest power of two that keeps a 100,000-object 10 TB graft's
// index inside the ~128 MB a windowed reader is comfortable with, while
// leaving anything under 32 MiB cut at the 1 MiB floor — which is every
// file in a software area.
const DefaultBlocksPerObject = 32

// BlockPolicy is the recorded rule. It is carried in the superblock entry
// so that `pelfs graft --refresh` cuts identically; a policy change is a
// new graft, and the identities say so by all being different.
type BlockPolicy struct {
	// Block is the floor and the granularity, Max the ceiling, PerObject
	// the block count that triggers a doubling.
	Block     int64
	Max       int64
	PerObject int
}

// DefaultPolicy is the rule a graft takes when nothing says otherwise.
func DefaultPolicy() BlockPolicy {
	return BlockPolicy{Block: DefaultBlock, Max: DefaultBlockMax, PerObject: DefaultBlocksPerObject}
}

// withDefaults fills the zero fields, so a caller may set only what it
// cares about and a generation written before a field existed still reads
// as the rule that was in force.
func (p BlockPolicy) withDefaults() BlockPolicy {
	if p.Block <= 0 {
		p.Block = DefaultBlock
	}
	if p.Max < p.Block {
		// A ceiling below the floor is the flag "one global size", which
		// is what --block-max=0 means and what a version of this code
		// without the ladder did.
		p.Max = p.Block
	}
	if p.PerObject <= 0 {
		p.PerObject = DefaultBlocksPerObject
	}
	return p
}

// Validate refuses a policy that cannot be honoured, so a bad flag fails
// before a terabyte is read rather than after.
func (p BlockPolicy) Validate() error {
	q := p.withDefaults()
	if q.Block&(q.Block-1) != 0 {
		return fmt.Errorf("graft: block size %d is not a power of two", q.Block)
	}
	// The ladder doubles, so a ceiling that is not a power-of-two
	// multiple of the floor is a ceiling the ladder can never reach — it
	// would silently stop one step below and cut at a size the recorded
	// rule does not name.
	if r := q.Max / q.Block; q.Max%q.Block != 0 || r&(r-1) != 0 {
		return fmt.Errorf("graft: block ceiling %d is not a power-of-two multiple of the %d-byte "+
			"block, so the doubling ladder could never reach it", q.Max, q.Block)
	}
	if q.Max > 1<<30 {
		return fmt.Errorf("graft: block ceiling %d is over 1 GiB; the ceiling is the minimum "+
			"verified read, and a read that large is a download", q.Max)
	}
	return nil
}

// For is the block size one object of the given size is cut at.
func (p BlockPolicy) For(size int64) int64 {
	q := p.withDefaults()
	b := q.Block
	for b < q.Max && size > b*int64(q.PerObject) {
		b *= 2
	}
	if b > q.Max {
		b = q.Max
	}
	return b
}

// Blocks is how many blocks an object of the given size is cut into.
func (p BlockPolicy) Blocks(size int64) int64 {
	if size <= 0 {
		return 0
	}
	b := p.For(size)
	return (size + b - 1) / b
}
