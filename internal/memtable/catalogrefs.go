package memtable

import (
	"errors"
	"fmt"

	"github.com/bbockelm/pelfs/internal/catalog"
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
	for _, r := range c.refs {
		if t := s.tableForLocked(r.Handle); t != nil {
			return nil, fmt.Errorf("%w: inode %d extent %d is still in memtable %d", ErrNotFlushed, ino, r.Handle, t.seq)
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
			// A catalog row can name this chunk only if the file wants all
			// of it, starting at its first byte.
			if cs.ChunkOff+delta != 0 || int64(take) != loc.Length {
				return nil, fmt.Errorf("%w: inode %d wants bytes [%d,%d) of chunk %s (length %d) at file offset %d",
					ErrNotTiled, ino, cs.ChunkOff+delta, cs.ChunkOff+delta+take, cs.ID, loc.Length, at)
			}
			out = append(out, catalog.ChunkRef{
				Identity:      append([]byte(nil), cs.ID[:]...),
				LLen:          int64(take),
				CLen:          loc.Length,
				LogicalOffset: at,
			})
			at += int64(take)
			want += take
			remaining -= take
			pos += cs.Length
		}
		if remaining != 0 {
			return nil, fmt.Errorf("memtable: inode %d extent %d resolves %d bytes short", ino, r.Handle, remaining)
		}
	}
	return out, nil
}
