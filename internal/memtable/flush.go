package memtable

import (
	"bytes"
	"context"
	"io"
	"sort"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// inodePlan is one inode's surviving extents, in file order. File order,
// not write order: CDC cuts on content, so the stream it sees has to be
// the file as it now reads, or boundaries would depend on the accident of
// which write arrived first.
type inodePlan struct {
	ino  uint64
	exts []Record
}

type flushResult struct {
	handleLoc      map[Handle][]ChunkSlice
	chunkLoc       map[string]PackLoc
	packs          []packstore.SealedPack
	uploadedBytes  int64
	uploadedChunks int64
	rawChunks      int64
	deadExtents    int64
	deadBytes      int64
	abandoned      bool
}

func (s *Store) runFlush(ctx context.Context, t *table) {
	plan, res := s.snapshot(t)
	if s.hooks.FlushStarted != nil {
		s.hooks.FlushStarted(t.seq)
	}
	if err := s.chunkAndPack(ctx, t, plan, res); err != nil {
		s.failFlush(err)
		return
	}
	if s.hooks.BeforePublish != nil {
		if err := s.hooks.BeforePublish(t.seq); err != nil {
			s.failFlush(err)
			return
		}
	}
	s.publish(t, res)
}

// snapshot captures the frozen table's live set. The design calls this
// constant time; it is not — it is proportional to the content refs of
// the inodes this table touched. That is still proportional to the flush
// rather than to the tree, which is the property that matters, but the
// claim as written is wrong.
func (s *Store) snapshot(t *table) ([]inodePlan, *flushResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := &flushResult{
		handleLoc: make(map[Handle][]ChunkSlice),
		chunkLoc:  make(map[string]PackLoc),
	}
	inodes := make([]uint64, 0, len(t.inodes))
	for ino := range t.inodes {
		inodes = append(inodes, ino)
	}
	sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })

	live := 0
	var plan []inodePlan
	for _, ino := range inodes {
		c := s.content[ino]
		if c == nil {
			continue
		}
		hs := c.handlesInOrder(func(h Handle) bool { _, ok := t.index[h]; return ok })
		if len(hs) == 0 {
			continue
		}
		exts := make([]Record, 0, len(hs))
		for _, h := range hs {
			exts = append(exts, t.index[h])
		}
		live += len(exts)
		plan = append(plan, inodePlan{ino: ino, exts: exts})
	}
	res.deadExtents = int64(len(t.index) - live)
	for h, rec := range t.index {
		if _, ok := t.live[h]; !ok {
			res.deadBytes += int64(rec.Length)
		}
	}
	return plan, res
}

func (s *Store) chunkAndPack(ctx context.Context, t *table, plan []inodePlan, res *flushResult) error {
	pk := newFlushPacker(s.obj, s.dir, int64(s.tableSize))
	defer pk.abort()
	for _, ip := range plan {
		if err := s.chunkInode(ctx, t, ip.exts, pk, res); err != nil {
			return err
		}
	}
	if err := pk.finish(ctx); err != nil {
		return err
	}
	res.chunkLoc = pk.locs
	res.packs = pk.sealed
	res.uploadedBytes = pk.bytes
	res.uploadedChunks = pk.count
	return nil
}

// chunkInode runs the CDC pass over one inode's surviving extents and
// feeds the resulting chunks to the pack.
//
// The abandon check is the backpressure release valve: chunking exists
// for dedup and incremental re-upload, not for correctness, so a flush
// that is holding a writer hostage stops searching for boundaries and
// ships what is left verbatim. Note that abandoning does NOT skip
// hashing — a pack entry's key IS the chunk identity — so what it buys is
// the cut search and the chunker's copy, not the digest.
func (s *Store) chunkInode(ctx context.Context, t *table, exts []Record, pk *flushPacker, res *flushResult) error {
	starts := make([]int64, len(exts)+1)
	for i, r := range exts {
		starts[i+1] = starts[i] + int64(r.Length)
	}
	total := starts[len(exts)]
	if total == 0 {
		return nil
	}

	// emit records, for every extent the chunk covers, which slice of the
	// chunk holds that extent's bytes. Chunk boundaries come from content
	// and respect nothing about where one write ended and the next began.
	emit := func(streamOff int64, id chunkid.Identity, n int) {
		end := streamOff + int64(n)
		i := sort.Search(len(exts), func(i int) bool { return starts[i+1] > streamOff })
		for ; i < len(exts) && starts[i] < end; i++ {
			lo := max(starts[i], streamOff)
			hi := min(starts[i+1], end)
			res.handleLoc[exts[i].Handle] = append(res.handleLoc[exts[i].Handle], ChunkSlice{
				ID:       id,
				ChunkOff: int(lo - streamOff),
				Length:   int(hi - lo),
			})
		}
	}

	readers := make([]io.Reader, len(exts))
	for i, r := range exts {
		readers[i] = bytes.NewReader(t.buf.At(r.Off, r.Length))
	}
	ch := chunkid.NewChunker(io.MultiReader(readers...), s.chunkOpts)
	var pos int64
	for pos < total && !t.abandon.Load() {
		c, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		id := s.hasher.Sum(c.Data)
		if err := pk.add(ctx, id, c.Data); err != nil {
			return err
		}
		emit(pos, id, len(c.Data))
		pos += int64(len(c.Data))
	}
	if pos >= total {
		return nil
	}
	res.abandoned = true
	// Whatever the chunker had buffered past pos is discarded: the bytes
	// are still in the frozen buffer at a known offset, so the remainder
	// is re-read from the mapping rather than recovered from the chunker.
	for i, r := range exts {
		if starts[i+1] <= pos {
			continue
		}
		from := int(max(pos, starts[i]) - starts[i])
		data := t.buf.At(r.Off+from, r.Length-from)
		id := s.hasher.Sum(data)
		if err := pk.add(ctx, id, data); err != nil {
			return err
		}
		emit(max(pos, starts[i]), id, len(data))
		res.rawChunks++
	}
	return nil
}

// publish installs the flush's locations and releases the table. Both
// happen under one lock hold: a reader must never observe a moment where
// the memtable has been dropped and the location map does not yet answer.
func (s *Store) publish(t *table, res *flushResult) {
	s.mu.Lock()
	for h, sl := range res.handleLoc {
		s.handleLoc[h] = sl
	}
	for k, v := range res.chunkLoc {
		s.chunkLoc[k] = v
	}
	s.packs = append(s.packs, res.packs...)
	s.stats.UploadedBytes += res.uploadedBytes
	s.stats.UploadedChunks += res.uploadedChunks
	s.stats.Packs += int64(len(res.packs))
	s.stats.DeadExtents += res.deadExtents
	s.stats.DeadBytes += res.deadBytes
	s.stats.RawChunks += res.rawChunks
	if res.abandoned {
		s.stats.AbandonedFlushes++
	}
	s.flushing = nil
	s.cond.Broadcast()
	s.mu.Unlock()
	t.retire()
}

// failFlush leaves the table in place. Until its locations are published
// the memtable is the only copy, so a failed flush must not discard it —
// it is retried by the next Flush.
func (s *Store) failFlush(err error) {
	s.mu.Lock()
	s.flushErr = err
	s.cond.Broadcast()
	s.mu.Unlock()
}

// flushPacker accumulates chunks into packs, cutting at target, and
// records where each chunk landed. It is deliberately not
// publish.packer: that file is being rewritten elsewhere, and a flush
// needs the per-chunk offsets that packer does not surface.
type flushPacker struct {
	obj    pelicanobj.Store
	dir    string
	target int64

	w       *packstore.PackWriter
	pend    []pendingLoc
	pending map[string]struct{}
	locs    map[string]PackLoc

	sealed []packstore.SealedPack
	bytes  int64
	count  int64
}

type pendingLoc struct {
	key    string
	off    int64
	length int64
}

func newFlushPacker(obj pelicanobj.Store, dir string, target int64) *flushPacker {
	return &flushPacker{
		obj: obj, dir: dir, target: target,
		pending: make(map[string]struct{}),
		locs:    make(map[string]PackLoc),
	}
}

func (p *flushPacker) add(ctx context.Context, id chunkid.Identity, data []byte) error {
	key := id.Hex()
	if _, done := p.locs[key]; done {
		return nil
	}
	// The open pack's entries need their own lookup, not a scan of pend: an
	// abandoned CDC pass emits one chunk per extent, so a pack can hold
	// thousands of small entries rather than the sixteen a 4 MiB average
	// would give.
	if _, open := p.pending[key]; open {
		return nil
	}
	if p.w != nil && p.w.Size() > 0 && p.w.Size()+int64(len(data)) > p.target {
		if err := p.cut(ctx); err != nil {
			return err
		}
	}
	if p.w == nil {
		w, err := packstore.NewPackWriter(p.dir)
		if err != nil {
			return err
		}
		p.w = w
	}
	off := p.w.Size()
	if err := p.w.Add(key, packstore.EntryData, data); err != nil {
		return err
	}
	p.pend = append(p.pend, pendingLoc{key: key, off: off, length: int64(len(data))})
	p.pending[key] = struct{}{}
	p.bytes += int64(len(data))
	p.count++
	return nil
}

// cut seals the open pack and uploads it. The upload is synchronous: a
// flush is already off the writer's path, and ordering location-map
// updates against partially failed concurrent uploads is a complication
// this prototype does not need to answer yet.
func (p *flushPacker) cut(ctx context.Context) error {
	if p.w == nil {
		return nil
	}
	sp, upload, err := p.w.Finalize()
	if err != nil {
		return err
	}
	if err := upload(ctx, p.obj); err != nil {
		return err
	}
	p.w = nil
	p.sealed = append(p.sealed, sp)
	for _, pl := range p.pend {
		p.locs[pl.key] = PackLoc{Pack: sp.Name, Off: pl.off, Length: pl.length}
	}
	p.pend = nil
	clear(p.pending)
	return nil
}

func (p *flushPacker) finish(ctx context.Context) error { return p.cut(ctx) }

func (p *flushPacker) abort() {
	if p.w != nil {
		p.w.Abort()
		p.w = nil
	}
}
