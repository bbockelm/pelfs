package memtable

import (
	"context"
	"fmt"
	"io"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
)

// Sealer renders inodes as catalog rows, re-chunking whatever the format
// cannot say (see ErrNotTiled) instead of refusing it.
//
// The repair is bounded by the REWRITE, not by the file. A rewritten span
// replaces the chunks wholly inside it — those are never read — and
// leaves the chunks wholly outside it tiling as they were. What has to be
// read back is the chunk straddling each end of the span: at most two per
// contiguous dirty region, whatever its size. An append is the same shape
// with only a tail chunk, which is why appending to a published file
// costs one small read rather than a re-chunk of the whole thing.
//
// The bytes come from wherever they now live — the ring, a pack this
// session wrote, or a pack from an earlier generation — through the
// store's own read path, so there is one resolver and the seal cannot
// disagree with the mount about what a file contains.
//
// The cost this could move onto the seal is a fetch: a straddling chunk
// in a pack that is no longer local would make publishing depend on the
// network for content that never left this machine. The local pack cache
// is what answers that (packcache.go) — a pack this session wrote is
// retained rather than deleted after its upload, and a pack read pulls
// the whole thing in — so the fetch is left only for content this session
// neither wrote nor read. It stays correct in that case, just slower.
type Sealer struct {
	s  *Store
	pk *flushPacker
}

// NewSealer starts a seal. Every inode it renders may add chunks to the
// same run of packs, so Finish must be called once at the end.
func (s *Store) NewSealer() *Sealer {
	return &Sealer{s: s, pk: newFlushPacker(s.obj, s.dir, int64(s.tableSize), s.cache, s.dek, s.keyID)}
}

// Inode renders one inode's live content as catalog rows.
func (sl *Sealer) Inode(ctx context.Context, ino uint64) ([]catalog.ChunkRef, error) {
	sl.s.mu.Lock()
	c := sl.s.content[ino]
	sl.s.mu.Unlock()
	return sl.inodeFrom(ctx, nil, c, ino)
}

// inodeFrom renders a named content map. view is where re-chunking reads
// from — nil means the live store — so a frozen render never picks up a
// byte written after its instant.
func (sl *Sealer) inodeFrom(ctx context.Context, view *Frozen, c *content, ino uint64) ([]catalog.ChunkRef, error) {
	s := sl.s
	s.mu.Lock()
	ps, err := s.piecesOfLocked(c, ino)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// Split the file into what already tiles and what does not. Adjacent
	// broken groups merge into one span so a rewrite that crosses several
	// chunks is re-chunked once, in one CDC pass, rather than chunk by
	// chunk — which would cut new boundaries at the old chunks' edges and
	// carry the old chunking forward forever.
	type segment struct {
		g     group
		whole bool
		from  int64
		to    int64
	}
	var segs []segment
	for _, g := range groupPieces(ps) {
		if g.whole() {
			segs = append(segs, segment{g: g, whole: true})
			continue
		}
		if n := len(segs); n > 0 && !segs[n-1].whole && segs[n-1].to == g.at {
			segs[n-1].to = g.end()
			continue
		}
		segs = append(segs, segment{from: g.at, to: g.end()})
	}

	var out []catalog.ChunkRef
	for _, seg := range segs {
		if seg.whole {
			out = append(out, seg.g.ref())
			continue
		}
		refs, err := sl.rechunk(ctx, view, ino, seg.from, seg.to)
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
	}
	return out, nil
}

// rechunk reads [from,to) of ino through the store's read path, runs the
// CDC pass over it, and adds the resulting chunks to this seal's packs.
//
// The last chunk of a span is cut at `to` rather than by content. That is
// a boundary the rewrite created and it persists, exactly as the short
// final chunk of any file does; the alternative is re-chunking to the end
// of the file to let CDC re-converge, which is the O(file) cost this
// whole path exists to avoid.
func (sl *Sealer) rechunk(ctx context.Context, view *Frozen, ino uint64, from, to int64) ([]catalog.ChunkRef, error) {
	s := sl.s
	ch := chunkid.NewChunker(&spanReader{ctx: ctx, s: s, view: view, ino: ino, off: from, end: to}, s.chunkOpts)
	var out []catalog.ChunkRef
	at := from
	for at < to {
		c, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("memtable: re-chunk inode %d at %d: %w", ino, at, err)
		}
		id := s.hasher.Sum(c.Data)
		// A chunk this store has already placed needs no second copy: the
		// identity IS the content, so the existing one is these bytes. It
		// happens more than the name "re-chunk" suggests — rewriting a
		// region with what was already there, or re-cutting a boundary at
		// the same place twice — and paying for it would make a rewrite
		// cost bytes it did not change.
		s.mu.Lock()
		_, placed := s.chunkLoc[id.Hex()]
		s.mu.Unlock()
		if !placed {
			if err := sl.pk.add(ctx, id, c.Data); err != nil {
				return nil, err
			}
		}
		out = append(out, catalog.ChunkRef{
			Identity:      append([]byte(nil), id[:]...),
			LLen:          int64(len(c.Data)),
			CLen:          int64(len(c.Data)),
			LogicalOffset: at,
		})
		at += int64(len(c.Data))
	}
	if at != to {
		return nil, fmt.Errorf("memtable: re-chunk inode %d covered [%d,%d), wanted [%d,%d)", ino, from, at, from, to)
	}
	s.mu.Lock()
	s.stats.RechunkedSpans++
	s.stats.RechunkedBytes += to - from
	s.mu.Unlock()
	return out, nil
}

// Finish seals whatever pack this run opened and installs the locations
// of the chunks it wrote, so the content it re-chunked is readable by the
// same path everything else is.
func (sl *Sealer) Finish(ctx context.Context) error {
	if err := sl.pk.finish(ctx); err != nil {
		return err
	}
	s := sl.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range sl.pk.locs {
		s.chunkLoc[k] = v
	}
	s.packs = append(s.packs, sl.pk.sealed...)
	s.stats.UploadedBytes += sl.pk.bytes
	s.stats.UploadedChunks += sl.pk.count
	s.stats.Packs += int64(len(sl.pk.sealed))
	if s.journal != nil {
		// The re-chunk's own chunks and packs. A seal that published rows
		// naming them without recording where they are would leave the
		// next session unable to read what this one just wrote.
		return s.journal.Located(Location{Chunks: sl.pk.locs, Packs: sl.pk.sealed})
	}
	return nil
}

// Abort discards an unfinished run's spool.
func (sl *Sealer) Abort() { sl.pk.abort() }

// spanReader streams one range of one inode through the store's read
// path, which is what makes the re-chunk source-agnostic: ring, this
// session's packs, or an earlier generation's, resolved the same way a
// mount would resolve them.
type spanReader struct {
	ctx  context.Context
	s    *Store
	view *Frozen // nil reads the live store
	ino  uint64
	off  int64
	end  int64
}

func (r *spanReader) Read(p []byte) (int, error) {
	if r.off >= r.end {
		return 0, io.EOF
	}
	if int64(len(p)) > r.end-r.off {
		p = p[:r.end-r.off]
	}
	var (
		n   int
		err error
	)
	if r.view != nil {
		n, err = r.view.Read(r.ctx, r.ino, r.off, p)
	} else {
		n, err = r.s.Read(r.ctx, r.ino, r.off, p)
	}
	r.off += int64(n)
	if err != nil {
		return n, err
	}
	if n == 0 {
		// The content rows said these bytes exist. Reading nothing is a
		// torn invariant, not an end of file.
		return 0, io.ErrUnexpectedEOF
	}
	return n, nil
}
