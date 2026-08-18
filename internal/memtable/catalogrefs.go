package memtable

import (
	"errors"
	"fmt"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
)

// ErrNotTiled reports content that cannot be written into a catalog row.
//
// This is where the design turns out to be wrong. It claims a content row
// can name an extent handle and that "neither binding — identity at
// flush, location within a pack — ever rewrites a catalog row", because a
// catalog.ChunkRef already carries an identity rather than a place. But a
// ChunkRef also says WHERE in the file the chunk goes, via LogicalOffset,
// and genfs reads it as "chunk bytes [0, LLen) are file bytes
// [LogicalOffset, LogicalOffset+LLen)". There is no field for an offset
// INTO the chunk.
//
// So the format can express a file only as whole chunks laid end to end.
// The moment a write lands inside an already-appended extent, the
// extent's surviving bytes are two disjoint ranges of the file while the
// chunk CDC produced still spans both plus the hole between them — and no
// ChunkRef can say "take the first 5000 bytes of this chunk". Today's
// path never hits this because it re-chunks the whole file from a staging
// file at seal, which is exactly the work the design is trying to stop
// doing.
var ErrNotTiled = errors.New("memtable: content does not tile onto whole chunks")

// ErrNotFlushed reports content still in a memtable. Identity binds at
// flush, so a seal must flush before it can write a catalog row.
var ErrNotFlushed = errors.New("memtable: content has not been flushed, so it has no identity yet")

// ChunkRefs renders one inode's content as the rows a seal would write
// into a catalog. It moves no bytes: everything it needs was decided at
// flush. That is the "a seal becomes metadata only" claim, made concrete
// enough to fail.
func (s *Store) ChunkRefs(ino uint64) ([]catalog.ChunkRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.content[ino]
	if !ok {
		return nil, nil
	}
	var out []catalog.ChunkRef
	// A chunk becomes a row only once the file has consumed the WHOLE of
	// it, in order and with no gap. That accounting has to span content
	// refs rather than live inside one: a write larger than the ring's
	// record cap is split into several extents, the CDC pass runs over an
	// inode's extents as one stream, and so a chunk routinely straddles
	// the boundary between two of them. Judging each ref on its own would
	// call that untileable when the file tiles perfectly.
	var open struct {
		live bool
		id   chunkid.Identity
		have int64 // bytes of the chunk the file has taken so far
		want int64 // the chunk's length
		at   int64 // file offset the chunk starts at
	}
	notTiled := func(cs ChunkSlice, chunkOff, take, at int64, total int64) error {
		return fmt.Errorf("%w: inode %d wants bytes [%d,%d) of chunk %s (length %d) at file offset %d",
			ErrNotTiled, ino, chunkOff, chunkOff+take, cs.ID, total, at)
	}
	for _, r := range c.refs {
		if _, ok := s.index[r.Handle]; ok {
			return nil, fmt.Errorf("%w: inode %d extent %d is still in the ring", ErrNotFlushed, ino, r.Handle)
		}
		slices, ok := s.handleLoc[r.Handle]
		if !ok {
			return nil, fmt.Errorf("memtable: inode %d names extent %d, which is nowhere", ino, r.Handle)
		}
		pos, at := 0, r.FileOff
		want, remaining := r.Skip, r.Length
		for _, cs := range slices {
			if remaining == 0 {
				break
			}
			if pos+cs.Length <= want {
				pos += cs.Length
				continue
			}
			loc, ok := s.chunkLoc[cs.ID.Hex()]
			if !ok {
				return nil, fmt.Errorf("memtable: chunk %s has no location", cs.ID)
			}
			delta := max(want-pos, 0)
			take := min(cs.Length-delta, remaining)
			chunkOff := int64(cs.ChunkOff + delta)
			switch {
			case !open.live:
				// A catalog row can name this chunk only if the file takes
				// it from its first byte.
				if chunkOff != 0 {
					return nil, notTiled(cs, chunkOff, int64(take), at, loc.Length)
				}
				open.live, open.id, open.have, open.want, open.at = true, cs.ID, 0, loc.Length, at
			case cs.ID != open.id || chunkOff != open.have || at != open.at+open.have:
				// The file jumped: either to a different chunk mid-way
				// through this one, or over a hole inside it. Neither has a
				// ChunkRef that can say so.
				return nil, notTiled(cs, chunkOff, int64(take), at, open.want)
			}
			open.have += int64(take)
			if open.have > open.want {
				return nil, notTiled(cs, chunkOff, int64(take), at, open.want)
			}
			if open.have == open.want {
				out = append(out, catalog.ChunkRef{
					Identity:      append([]byte(nil), open.id[:]...),
					LLen:          open.want,
					CLen:          open.want,
					LogicalOffset: open.at,
				})
				open.live = false
			}
			at += int64(take)
			want += take
			remaining -= take
			pos += cs.Length
		}
		if remaining != 0 {
			return nil, fmt.Errorf("memtable: inode %d extent %d resolves %d bytes short", ino, r.Handle, remaining)
		}
	}
	if open.live {
		// The file ended part-way through a chunk: the rest of it belongs
		// to bytes that were overwritten or truncated away.
		return nil, fmt.Errorf("%w: inode %d ends %d bytes into chunk %s (length %d) at file offset %d",
			ErrNotTiled, ino, open.have, open.id, open.want, open.at)
	}
	return out, nil
}
