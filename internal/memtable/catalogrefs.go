package memtable

import (
	"errors"
	"fmt"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
)

// ErrNotTiled reports content that cannot be written into a catalog row as
// it stands.
//
// A catalog.ChunkRef carries an identity and a LogicalOffset, and genfs
// reads it as "chunk bytes [0, LLen) are file bytes [LogicalOffset,
// +LLen)". There is no field for an offset INTO the chunk. So the format
// can express a file only as whole chunks laid end to end, and the moment
// a write lands inside an already-published extent, the surviving bytes
// are two disjoint ranges of the file while the chunk CDC produced spans
// both plus the hole between them.
//
// That is a limit of what a catalog can SAY, not a defect to be worked
// around in the reader: keeping "whole chunks, end to end" is what keeps
// every chunk boundary a legal dedup boundary and a legal catalog split
// point. The answer is to re-chunk the affected span at seal (see
// Sealer), which is bounded by the rewrite rather than by the file.
// ChunkRefs itself stays strict, because the honest way to know whether a
// seal moved any bytes is to have something that refuses to.
var ErrNotTiled = errors.New("memtable: content does not tile onto whole chunks")

// ErrNotFlushed reports content still in the ring. Identity binds when a
// pack is written, so a seal must flush before it can write a catalog row.
var ErrNotFlushed = errors.New("memtable: content has not been flushed, so it has no identity yet")

// piece is one contiguous run of one chunk's bytes that a file wants, in
// file order: the resolution of a content row against the location map,
// before any question of what a ChunkRef can express.
type piece struct {
	id   chunkid.Identity
	off  int64 // offset into the chunk
	n    int64 // bytes taken
	at   int64 // file offset they land at
	llen int64 // the chunk's whole LOGICAL length
	clen int64 // ... and its stored length, which differ once a chunk is
	// compressed or encrypted. Both travel because a ChunkRef carries
	// both, and a chunk adopted from the base must be emitted with the
	// base's own numbers rather than re-derived ones.
}

// group is consecutive pieces of the SAME chunk, taken in order and with
// no gap — the unit a ChunkRef can name, if it covers the whole chunk.
type group struct {
	id   chunkid.Identity
	off  int64
	n    int64
	at   int64
	llen int64
	clen int64
}

func (g group) whole() bool { return g.off == 0 && g.n == g.llen }
func (g group) end() int64  { return g.at + g.n }

func (g group) ref() catalog.ChunkRef {
	return catalog.ChunkRef{
		Identity:      append([]byte(nil), g.id[:]...),
		LLen:          g.llen,
		CLen:          g.clen,
		LogicalOffset: g.at,
	}
}

// piecesLocked resolves one inode's live content into the chunk bytes it
// wants, in file order. It is the shared front half of both renderers:
// the strict one below and the re-chunking one in seal.go.
func (s *Store) piecesLocked(ino uint64) ([]piece, error) {
	return s.piecesOfLocked(s.content[ino], ino)
}

// piecesOfLocked is the same resolution against a named content map, so a
// frozen view renders through exactly the code a live one does.
func (s *Store) piecesOfLocked(c *content, ino uint64) ([]piece, error) {
	if c == nil {
		return nil, nil
	}
	var out []piece
	for _, r := range c.refs {
		if _, ok := s.index[r.Handle]; ok {
			return nil, fmt.Errorf("%w: inode %d extent %d is still in the ring", ErrNotFlushed, ino, r.Handle)
		}
		// An adopted extent resolves to the BASE generation's own records.
		// They tile by construction — that is how a generation publishes a
		// file — so an untouched range of an adopted file costs a seal
		// nothing at all, and only what a write disturbed is re-chunked.
		if be, ok := s.baseRefs[r.Handle]; ok {
			out = append(out, be.pieces(r.FileOff, int64(r.Skip), int64(r.Length))...)
			continue
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
			take := int64(min(cs.Length-delta, remaining))
			out = append(out, piece{
				id:   cs.ID,
				off:  int64(cs.ChunkOff + delta),
				n:    take,
				at:   at,
				llen: loc.Length,
				clen: loc.Length,
			})
			at += take
			want += int(take)
			remaining -= int(take)
			pos += cs.Length
		}
		if remaining != 0 {
			return nil, fmt.Errorf("memtable: inode %d extent %d resolves %d bytes short", ino, r.Handle, remaining)
		}
	}
	return out, nil
}

// groupPieces joins pieces that continue one another within one chunk.
//
// The join has to span content refs rather than live inside one: a write
// larger than the ring's record cap is split into several extents, the
// CDC pass runs over an inode's extents as one stream, and so a chunk
// routinely straddles the boundary between two of them. Judging each ref
// on its own would call that untileable when the file tiles perfectly.
func groupPieces(ps []piece) []group {
	var out []group
	for _, p := range ps {
		if n := len(out); n > 0 {
			g := &out[n-1]
			if g.id == p.id && g.off+g.n == p.off && g.end() == p.at {
				g.n += p.n
				continue
			}
		}
		out = append(out, group{id: p.id, off: p.off, n: p.n, at: p.at, llen: p.llen, clen: p.clen})
	}
	return out
}

// ChunkRefs renders one inode's content as the rows a seal would write
// into a catalog, and REFUSES anything the format cannot say. It moves no
// bytes: everything it needs was decided when the packs were written.
// That is the "a seal becomes metadata only" claim, kept in a form that
// can fail — Sealer is the same rendering with the repair attached.
func (s *Store) ChunkRefs(ino uint64) ([]catalog.ChunkRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps, err := s.piecesLocked(ino)
	if err != nil {
		return nil, err
	}
	var out []catalog.ChunkRef
	for _, g := range groupPieces(ps) {
		if !g.whole() {
			return nil, fmt.Errorf("%w: inode %d wants bytes [%d,%d) of chunk %s (length %d) at file offset %d",
				ErrNotTiled, ino, g.off, g.off+g.n, g.id, g.llen, g.at)
		}
		out = append(out, g.ref())
	}
	return out, nil
}
