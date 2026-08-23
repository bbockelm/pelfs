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
	// recheck is set when this seal has to confirm that chunks it took
	// from the BASE generation are still stored there — see stillStored.
	// It is decided once, at the start, because the answer is a property
	// of the session rather than of an inode.
	recheck bool
	// ourPacks are the packs this session wrote, which is how a chunk it
	// placed itself is told from one it borrowed. Built only when recheck
	// is set; nothing else needs it.
	ourPacks map[string]struct{}
}

// NewSealer starts a seal. Every inode it renders may add chunks to the
// same run of packs, so Finish must be called once at the end.
func (s *Store) NewSealer() *Sealer {
	sl := &Sealer{s: s, pk: s.newPacker()}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A base-derived chunkref is only as good as the base generation's
	// pack list, and exactly one thing moves that list: a repack, which
	// runs under a live writable mount (cmd/pelfs/autorepack.go) and
	// DROPS packs. An ordinary generation only ever appends to the list,
	// so a chunk that was stored when the flush borrowed it is still
	// stored now and there is nothing to check.
	if s.needsBaseRecheckLocked() {
		sl.recheck = true
		sl.ourPacks = make(map[string]struct{}, len(s.packs))
		for _, sp := range s.packs {
			sl.ourPacks[sp.Name] = struct{}{}
		}
	}
	return sl
}

// stillStored reports whether a chunk this seal is about to name as a
// WHOLE chunk is still stored where the store thinks it is.
//
// It is the one guard on the dangerous direction of cross-generation
// dedup. Reusing an existing entry writes a row whose bytes live in
// somebody else's pack, and that is sound because reachability is over
// identities: the sweep credits every pack holding a reached identity, so
// the new row keeps the old pack alive, and gc cannot touch a pack a live
// generation lists because its liveness is set arithmetic over the lists.
//
// A repack is the exception, and the only one. It computes what is
// reachable, carries that out of the packs it condemns, and drops the
// rest — so a chunk that was PRESENT in a listed pack but REFERENCED by
// no live generation (the ordinary residue of a rewrite) can stop being
// stored, in the middle of a session, between the flush that borrowed it
// and the seal that names it. Without this check that seal publishes a row
// resolving in no listed pack: a generation that mounts, passes its own
// signature, and fails to read one file.
//
// So a borrowed chunk the base no longer stores is not whole any more, and
// the seal's existing repair takes it from there — the span is re-chunked
// and re-uploaded out of the bytes themselves, which the condemned pack
// still holds for the length of the grace window. That is the same repair
// a rewrite gets, reached by a different route.
func (sl *Sealer) stillStored(ctx context.Context, id chunkid.Identity) bool {
	if !sl.recheck {
		return true
	}
	s := sl.s
	s.mu.Lock()
	loc, known := s.chunkLoc[id.Hex()]
	s.mu.Unlock()
	if !known {
		// An adopted extent, which resolves through the base's own records
		// and was checked against its pack list when it was adopted.
		return true
	}
	if _, ours := sl.ourPacks[loc.Pack]; ours {
		return true
	}
	if _, still := s.placer.Placed(ctx, id); still {
		return true
	}
	// Not stored there any more. The span goes down the re-chunk path, and
	// the packer has to be told to ignore the stale location on the way —
	// see flushPacker.avoid.
	if sl.pk.avoid == nil {
		sl.pk.avoid = make(map[string]struct{})
	}
	sl.pk.avoid[id.Hex()] = struct{}{}
	return false
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
//
// The render is TOTAL: what comes back always accounts for exactly
// [0, size). An extent map is sparse by construction — a write past the
// end of the file and a truncate that grows one both leave a range no
// extent covers, and the read path is entitled to answer zeros for it
// without an extent existing — so a renderer that walked only the
// extents would emit a list whose lengths sum SHORT of the node's, which
// no catalog can hold and every reader refuses ("chunk lengths sum to X,
// node length is Y"). A gap is therefore a span to be chunked like any
// other, and it costs what the staging store this replaces always paid
// for the same file: the zeros are read through the store's own read
// path, which is where "a hole reads as zeros" already lives.
func (sl *Sealer) inodeFrom(ctx context.Context, view *Frozen, c *content, ino uint64) ([]catalog.ChunkRef, error) {
	s := sl.s
	s.mu.Lock()
	ps, err := s.piecesOfLocked(c, ino)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var size int64
	if c != nil {
		size = c.size
	}

	// Split the file into what already tiles and what does not. Adjacent
	// broken spans merge into one so a rewrite that crosses several
	// chunks is re-chunked once, in one CDC pass, rather than chunk by
	// chunk — which would cut new boundaries at the old chunks' edges and
	// carry the old chunking forward forever. A gap merges with them by
	// the same rule and for the same reason.
	type segment struct {
		g     group
		whole bool
		from  int64
		to    int64
	}
	var segs []segment
	broken := func(from, to int64) {
		if to <= from {
			return
		}
		if n := len(segs); n > 0 && !segs[n-1].whole && segs[n-1].to == from {
			segs[n-1].to = to
			return
		}
		segs = append(segs, segment{from: from, to: to})
	}
	var covered int64
	for _, g := range groupPieces(ps) {
		broken(covered, g.at) // the gap this group starts after, if any
		if g.whole() && sl.stillStored(ctx, g.id) {
			segs = append(segs, segment{g: g, whole: true})
		} else {
			broken(g.at, g.end())
		}
		covered = g.end()
	}
	broken(covered, size) // and the one at the end, which a truncate leaves

	var out []catalog.ChunkRef
	var total int64
	for _, seg := range segs {
		if seg.whole {
			out = append(out, seg.g.ref())
			total += seg.g.llen
			continue
		}
		refs, err := sl.rechunk(ctx, view, ino, seg.from, seg.to)
		if err != nil {
			return nil, err
		}
		out = append(out, refs...)
		total += seg.to - seg.from
	}
	// The standing check on the loop above. A row whose lengths do not
	// account for the node's is a file the format cannot express and a
	// reader refuses to open, so it must not leave this function — least
	// of all into a generation that is about to be signed.
	if total != size {
		return nil, fmt.Errorf("memtable: inode %d rendered %d bytes of chunk refs for a %d-byte file",
			ino, total, size)
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
		// A chunk this store has already placed needs no second copy, and
		// add makes that check for every producer. It matters more here than
		// the name "re-chunk" suggests — rewriting a region with what was
		// already there, or re-cutting a boundary at the same place twice —
		// because paying for it would make a rewrite cost bytes it did not
		// change.
		//
		// The row is filled in from what add reports, never from the
		// plaintext in hand. CLen is the length of the ENTRY in the pack and
		// Alg says how to decode it, and both differ from the logical length
		// the moment zstd shrinks the bytes or a volume key seals them —
		// which is to say for a span of zeros, and for every span on an
		// encrypted volume. A row that claimed otherwise sent a reader to
		// read a chunk that is not the size the row says it is.
		clen, alg, keyID, err := sl.pk.add(ctx, id, c.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, catalog.ChunkRef{
			Identity:      append([]byte(nil), id[:]...),
			LLen:          int64(len(c.Data)),
			CLen:          clen,
			Alg:           int64(alg),
			KeyID:         keyID,
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
	// A seal is the one thing that must not run ahead of the uplink: the
	// generation it is about to sign names these packs.
	sl.pk.outstanding.Wait()
	if err := sl.s.uploads.drain(); err != nil {
		return err
	}
	s := sl.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range sl.pk.locs {
		s.chunkLoc[k] = v
	}
	// Chunks a re-chunk found the base generation already holding. Their
	// locations belong in the map for the same reason the written ones do:
	// a read of those file bytes has to resolve, and the seal has just
	// written rows that name them.
	for k, v := range sl.pk.baseLocs {
		s.chunkLoc[k] = v
	}
	s.packs = append(s.packs, sl.pk.sealed...)
	s.stats.UploadedBytes += sl.pk.bytes
	s.stats.UploadedChunks += sl.pk.count
	s.stats.DedupedChunks += sl.pk.skipped
	s.stats.BaseDedupedChunks += sl.pk.baseChunks
	s.stats.BaseDedupedBytes += sl.pk.baseBytes
	if sl.pk.baseChunks > 0 {
		s.noteBaseHitLocked(sl.pk.baseGen)
	}
	s.stats.Packs += int64(len(sl.pk.sealed))
	if s.journal != nil {
		// The re-chunk's own chunks and packs. A seal that published rows
		// naming them without recording where they are would leave the
		// next session unable to read what this one just wrote.
		chunks := sl.pk.locs
		if len(sl.pk.baseLocs) > 0 {
			chunks = make(map[string]PackLoc, len(sl.pk.locs)+len(sl.pk.baseLocs))
			for k, v := range sl.pk.locs {
				chunks[k] = v
			}
			for k, v := range sl.pk.baseLocs {
				chunks[k] = v
			}
		}
		return s.journal.Located(Location{Chunks: chunks, Packs: sl.pk.sealed})
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
