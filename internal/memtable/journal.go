package memtable

import (
	"sort"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// Journal is where a store records what a crash must not lose: which
// extents a file is made of, and where the bytes of an extent went.
//
// It records OPERATIONS, not state, and that is the whole of why it is
// affordable. A file written sequentially accumulates one extent per
// write, so rewriting its map on every write would cost the map's whole
// size each time — quadratic in the number of writes, which for a 1 GiB
// file arriving in 128 KiB pieces is tens of millions of row writes.
// Appending one row per write is proportional to the write, and recovery
// replays the rows through the same code the live path uses (see
// ReplayJournal), so the rebuilt map cannot drift from the original by
// construction.
//
// Located is the other half and has the design's stated cost: one row per
// surviving extent and one per chunk, per flush. A handle that never
// leaves the ring — the overwritten-before-flush case the design is built
// around — is never located at all, so dead data costs nothing here
// either.
//
// A nil Journal is legal and means the store's content does not survive a
// crash, which is what the prototype and every test that does not care
// about recovery use.
type Journal interface {
	// Append records one content-map operation. Called with the store's
	// lock held, in the order the operations happened.
	Append(e JournalEntry) error
	// Adopted records the records an adopted handle was taken with, before
	// the OpAdopt entry that names the handle. Also called with the store's
	// lock held. See AdoptedExtent for why this is written down at all.
	Adopted(h Handle, a AdoptedExtent) error
	// Located records where a flush put things: the extents that now have
	// chunk slices, the chunks those name, and the packs holding them.
	// Also called with the store's lock held, from the flusher rather
	// than the writer — so an implementation never sees two calls at
	// once, and needs no lock of its own.
	Located(l Location) error
}

// JournalOp is what one entry did.
type JournalOp uint8

const (
	// OpPlace put an extent's bytes at a file offset.
	OpPlace JournalOp = iota + 1
	// OpTruncate set a file's length, dropping anything past it.
	OpTruncate
	// OpForget dropped a file's content entirely.
	OpForget
	// OpAdopt took a file over from the base generation by reference.
	OpAdopt
)

// JournalEntry is one recorded operation. The fields each op uses:
//
//	OpPlace     Inode, Handle, Off, Length
//	OpTruncate  Inode, Length (the new size)
//	OpForget    Inode
//	OpAdopt     Inode, Handle, Length (the adopted prefix)
type JournalEntry struct {
	Op     JournalOp
	Inode  uint64
	Handle Handle
	Off    int64
	Length int64
}

// AdoptedExtent is the durable record of one adopted handle: the base
// generation's own content records for that file, as they were when the
// store took it over.
//
// Recovery used to re-derive this by asking the base for the inode again,
// on the stated grounds that the base is immutable and "still describes
// those files exactly as it did when they were taken over". The base is
// immutable; THE BASE A LATER MOUNT HAS IS NOT THE SAME ONE. A checkpoint
// publishes a new generation and the mount swaps onto it, so by the time
// anyone replays this journal the generation the handle was taken from is
// two removes back — and, worse, the question cannot even be asked: genfs
// answers for an inode only after a descent has made it resident
// (genfs.ErrStale), and a mount that has just started has descended
// nothing. That is what made a state directory holding an adopted handle
// unopenable for writing, which is the one failure a local overlay must
// not have (docs/TODO.md, readopt-agent).
//
// So the records are written down. They are IDENTITIES, not locations:
// what a chunkref names is content-addressed and immutable, valid in every
// generation that still holds the chunk, whereas the pack a chunk sits in
// is rewritten by a repack. Recording where the bytes were would have
// bought a row that a maintenance operation can invalidate; recording what
// they are cannot go stale.
type AdoptedExtent struct {
	// Inode is the base inode the records came from. It is checked on the
	// way back in: a record whose inode disagrees with the operation log's
	// is not this handle's record.
	Inode uint64
	// Length is the base's length for the file, which is what Adopt
	// clamped its prefix against.
	Length int64
	// Refs are the base's chunk records, in file order. Every one has an
	// identity: Adopt falls back to reading for inline bodies and holes, so
	// a handle that reaches here is one whose extents are all named.
	Refs []catalog.ChunkRef
}

// Location is one flush's half of the durable state: the binding from
// extents to chunks to packs. Nothing on the federation has ever heard of
// a handle, so this binding exists nowhere else and a crash that lost it
// would leave published bytes unreachable.
type Location struct {
	Handles map[Handle][]ChunkSlice
	Chunks  map[string]PackLoc
	Packs   []packstore.SealedPack
}

// journalLocked records one operation, if there is a journal. A failure
// is returned to the caller: an operation whose durability record did not
// land must not be reported as having happened.
func (s *Store) journalLocked(e JournalEntry) error {
	if s.journal == nil {
		return nil
	}
	return s.journal.Append(e)
}

// ReplayJournal rebuilds content maps from recorded operations, through
// the same insert/punch code the live path uses. Entries must be in the
// order they were appended.
//
// It is a plain function rather than a method because recovery has no
// store yet: the rows it produces are what a store is rebuilt FROM (see
// Recover).
func ReplayJournal(entries []JournalEntry) ([]ContentRow, map[Handle]uint64) {
	content := make(map[uint64]*content)
	adopted := make(map[Handle]uint64)
	dropped := make(map[Handle]int)
	for _, e := range entries {
		switch e.Op {
		case OpPlace:
			c := contentOf(content, e.Inode)
			c.insert(e.Off, int(e.Length), e.Handle, dropped)
		case OpAdopt:
			c := contentOf(content, e.Inode)
			c.punch(0, c.size, dropped)
			c.insert(0, int(e.Length), e.Handle, dropped)
			c.size = e.Length
			adopted[e.Handle] = e.Inode
		case OpTruncate:
			contentOf(content, e.Inode).truncate(e.Length, dropped)
		case OpForget:
			delete(content, e.Inode)
		}
		clear(dropped)
	}
	inodes := make([]uint64, 0, len(content))
	for ino := range content {
		inodes = append(inodes, ino)
	}
	sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })
	rows := make([]ContentRow, 0, len(inodes))
	for _, ino := range inodes {
		c := content[ino]
		rows = append(rows, ContentRow{Inode: ino, Size: c.size, Refs: append([]ExtentRef(nil), c.refs...)})
	}
	return rows, adopted
}

func contentOf(m map[uint64]*content, ino uint64) *content {
	c, ok := m[ino]
	if !ok {
		c = &content{}
		m[ino] = c
	}
	return c
}
