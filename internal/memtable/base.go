package memtable

import (
	"context"
	"fmt"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// Base is the immutable generation this store's content sits over.
// *genfs.FS satisfies it.
type Base interface {
	// ContentOf returns an inode's published content records — identities
	// and offsets, no bytes.
	ContentOf(ctx context.Context, ino uint64) (genfs.Content, error)
	// Read fills dst from the base's version of ino.
	Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
}

// baseExtent is a file the store ADOPTED from the base generation: the
// records that generation already published for it, taken once and never
// copied.
//
// This is what makes writing to a file the session did not create cheap.
// The staging store it replaces materializes such a file by copying it —
// the whole file, on the first dirty byte, and for a file only the
// federation holds that copy is a download. Here the same operation is a
// list of identities and one content ref, and nothing moves at all.
//
// The records stay in the base's terms: they name chunks in PREV's packs,
// which the superblock being built carries forward verbatim, so a seal
// can emit them untouched. Only the part a later write actually disturbs
// costs anything, and it costs a re-chunk of that span (see Sealer).
type baseExtent struct {
	ino    uint64
	refs   []catalog.ChunkRef
	length int64
}

// ErrNoBase reports a store asked to adopt without a base to adopt from.
var ErrNoBase = fmt.Errorf("memtable: no base generation is attached")

// Adopt gives ino a writable body that starts as the base generation's
// version of it, truncated to length. It moves no bytes when the base
// describes the file as whole chunks, which is how a base generation
// describes every file it published.
//
// Two shapes fall back to reading. INLINE content is already in hand and
// is small by definition, so it simply goes into the ring. A HOLE — a
// chunkref with no identity — is a shape publish never emits but a
// foreign producer may, and rather than teach every downstream path about
// it the file is read and re-written. Both are counted, because a
// fallback that quietly became the common case would undo the point.
func (s *Store) Adopt(ctx context.Context, ino uint64, length int64) error {
	if s.base == nil {
		return ErrNoBase
	}
	c, err := s.base.ContentOf(ctx, ino)
	if err != nil {
		return fmt.Errorf("memtable: adopt inode %d: %w", ino, err)
	}
	if length > c.Length {
		length = c.Length
	}
	if length <= 0 {
		s.mu.Lock()
		s.contentFor(ino).size = 0
		s.mu.Unlock()
		return nil
	}
	if c.Inline != nil {
		if int64(len(c.Inline)) < length {
			return fmt.Errorf("memtable: adopt inode %d: inline body is %d bytes, want %d",
				ino, len(c.Inline), length)
		}
		if err := s.Write(ctx, ino, 0, c.Inline[:length]); err != nil {
			return err
		}
		s.mu.Lock()
		s.stats.AdoptedInline++
		s.mu.Unlock()
		return nil
	}
	for _, r := range c.Refs {
		if len(r.Identity) == 0 {
			return s.adoptByReading(ctx, ino, length)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.nextHandle
	s.nextHandle++
	s.baseRefs[h] = baseExtent{ino: ino, refs: c.Refs, length: c.Length}
	cnt := s.contentFor(ino)
	dropped := make(map[Handle]int)
	cnt.punch(0, cnt.size, dropped)
	s.applyLocked(dropped)
	cnt.insert(0, int(length), h, dropped)
	cnt.size = length
	s.applyLocked(dropped)
	s.stats.AdoptedFiles++
	s.stats.AdoptedBytes += length
	return nil
}

// adoptByReading is the fallback: pull the bytes through the base's read
// path and write them into the ring like any other content.
func (s *Store) adoptByReading(ctx context.Context, ino uint64, length int64) error {
	buf := make([]byte, min(int64(s.maxPayload()), length))
	for off := int64(0); off < length; {
		want := min(int64(len(buf)), length-off)
		n, err := s.base.Read(ctx, ino, off, buf[:want])
		if err != nil {
			return fmt.Errorf("memtable: adopt inode %d at %d: %w", ino, off, err)
		}
		if n == 0 {
			return fmt.Errorf("memtable: adopt inode %d: base ended at %d of %d", ino, off, length)
		}
		if err := s.Write(ctx, ino, off, buf[:n]); err != nil {
			return err
		}
		off += int64(n)
	}
	s.mu.Lock()
	s.stats.AdoptedByReading++
	s.mu.Unlock()
	return nil
}

// chunkIdentity re-forms a catalog row's identity bytes.
func chunkIdentity(b []byte) chunkid.Identity {
	var id chunkid.Identity
	copy(id[:], b)
	return id
}

// basePieces resolves part of an adopted extent into the base's own
// chunk records, in file order. skip is an offset into the extent, which
// for an adopted file is an offset into the base's version of it.
func (be baseExtent) pieces(at int64, skip, length int64) []piece {
	var out []piece
	want := skip
	end := skip + length
	for _, r := range be.refs {
		if r.LogicalOffset+r.LLen <= want {
			continue
		}
		if r.LogicalOffset >= end {
			break
		}
		lo := max(r.LogicalOffset, want)
		hi := min(r.LogicalOffset+r.LLen, end)
		out = append(out, piece{
			id:   chunkIdentity(r.Identity),
			off:  lo - r.LogicalOffset,
			n:    hi - lo,
			at:   at + (lo - want),
			llen: r.LLen,
			clen: r.CLen,
		})
	}
	return out
}
