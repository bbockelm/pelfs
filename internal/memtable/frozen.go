package memtable

import (
	"context"
	"fmt"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// Frozen is a store's content as of one instant: what a checkpoint seals
// while the mount keeps writing.
//
// It is a copy of the extent maps and nothing else — no pinned files, no
// hand-over protocol, no scratch directory. The staging store needs all
// of that because its bytes are mutable and the live side overwrites them
// in place; extents are append-only, so a frozen map is a frozen file.
//
// The one rule that makes it that cheap: FREEZING FLUSHES FIRST. After a
// flush every extent the maps name has a location, so nothing the frozen
// view refers to can still be in the ring — and the ring is the only
// thing that gets recycled. A checkpoint flushes before it can render a
// catalog row anyway (identity binds when a pack is written), so this
// costs the checkpoint nothing it was not already paying.
//
// Without that ordering the freeze would have to defend against the
// design's central optimization: an extent superseded before its flush is
// never uploaded at all, so a frozen map naming one would resolve to
// bytes that deliberately went nowhere.
type Frozen struct {
	s    *Store
	rows map[uint64]*content
	// held is the ADOPTED handles these rows name, with multiplicity. They
	// are the one thing a frozen view owns beyond memory: an adopted
	// extent's baseRefs entry is collected the moment nothing names it,
	// and the live map may overwrite or forget the file the instant Freeze
	// returns. Ring records need no equivalent — the flush above emptied
	// the ring of anything a content row names, which is the same rule
	// that makes this whole arrangement a map copy.
	held []Handle
}

// Freeze flushes and then captures the content maps. The instant is the
// moment the lock is taken after the flush; writes that land afterwards
// belong to the next generation and are invisible here.
func (s *Store) Freeze(ctx context.Context) (*Frozen, error) {
	if err := s.Flush(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &Frozen{s: s, rows: make(map[uint64]*content, len(s.content))}
	for ino, c := range s.content {
		for _, r := range c.refs {
			if _, stillInRing := s.index[r.Handle]; stillInRing {
				// The flush above should have emptied the ring of anything
				// a content row names. Saying so is better than freezing a
				// view that resolves to bytes nobody uploaded.
				return nil, fmt.Errorf("memtable: freeze: inode %d extent %d is still in the ring after a flush",
					ino, r.Handle)
			}
			if _, adopted := s.baseRefs[r.Handle]; adopted {
				f.held = append(f.held, r.Handle)
			}
		}
		f.rows[ino] = &content{size: c.size, refs: append([]ExtentRef(nil), c.refs...)}
	}
	// Counted only once the whole view exists: a freeze that returned an
	// error above would otherwise leave references nobody can release.
	d := make(map[Handle]int, len(f.held))
	for _, h := range f.held {
		d[h]++
	}
	s.applyLocked(d)
	return f, nil
}

// Release drops the frozen maps and the references they hold. The maps
// themselves are only memory — that is the whole point of the
// arrangement — but the adopted extents they name are collectable state,
// so a view that is never released pins those for the session.
func (f *Frozen) Release() {
	if f.rows == nil {
		return
	}
	f.rows = nil
	if len(f.held) == 0 {
		return
	}
	d := make(map[Handle]int, len(f.held))
	for _, h := range f.held {
		d[h]--
	}
	f.held = nil
	f.s.mu.Lock()
	f.s.applyLocked(d)
	f.s.mu.Unlock()
}

// Size reports a file's length as of the instant.
func (f *Frozen) Size(ino uint64) int64 {
	if c, ok := f.rows[ino]; ok {
		return c.size
	}
	return 0
}

// Read fills dst from the frozen version of ino.
func (f *Frozen) Read(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	return f.s.readFrom(ctx, f.rows[ino], ino, off, dst)
}

// Records renders one inode's frozen content as catalog rows, re-chunking
// whatever the format cannot say — the same rendering a live seal does,
// over the frozen map instead of the current one.
func (f *Frozen) Records(ctx context.Context, sl *Sealer, ino uint64) ([]catalog.ChunkRef, error) {
	return sl.inodeFrom(ctx, f, f.rows[ino], ino)
}
