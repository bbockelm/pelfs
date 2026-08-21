package memtable

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
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
	dedupedChunks  int64
	deadExtents    int64
	deadBytes      int64
	uploaded       *sync.WaitGroup
}

func (s *Store) runFlush(ctx context.Context, b *batch) {
	plan, res := s.snapshot(b)
	if s.hooks.FlushStarted != nil {
		s.hooks.FlushStarted(b.seq)
	}
	if err := s.chunkAndPack(ctx, b, plan, res); err != nil {
		s.failFlush(err)
		return
	}
	if s.hooks.BeforePublish != nil {
		if err := s.hooks.BeforePublish(b.seq); err != nil {
			s.failFlush(err)
			return
		}
	}
	s.publish(b, res)
	// The journal record waits for the uploads this batch queued. Reads
	// are already served — the location map answers, and the pack cache
	// holds the bytes — but a record naming a pack that never left is one
	// a LATER session would publish from, and that generation would be
	// signed and unreadable.
	res.uploaded.Wait()
	s.journalLocated(res)
}

// snapshot captures the frozen table's live set. The design calls this
// constant time; it is not — it is proportional to the content refs of
// the inodes this table touched. That is still proportional to the flush
// rather than to the tree, which is the property that matters, but the
// claim as written is wrong.
func (s *Store) snapshot(b *batch) ([]inodePlan, *flushResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res := &flushResult{
		handleLoc: make(map[Handle][]ChunkSlice),
		chunkLoc:  make(map[string]PackLoc),
	}
	byHandle := make(map[Handle]Record, len(b.recs))
	for _, r := range b.recs {
		byHandle[r.Handle] = r
	}
	inodes := make([]uint64, 0, len(b.inodes))
	for ino := range b.inodes {
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
		hs := c.handlesInOrder(func(h Handle) bool { _, ok := byHandle[h]; return ok })
		if len(hs) == 0 {
			continue
		}
		exts := make([]Record, 0, len(hs))
		for _, h := range hs {
			exts = append(exts, byHandle[h])
		}
		live += len(exts)
		plan = append(plan, inodePlan{ino: ino, exts: exts})
	}
	// Whatever the content rows no longer reference died in the ring and
	// is never uploaded, which is the design's central claim.
	res.deadExtents = int64(len(b.recs) - live)
	for _, rec := range b.recs {
		if _, ok := b.live[rec.Handle]; !ok {
			res.deadBytes += int64(rec.Length)
		}
	}
	return plan, res
}

func (s *Store) chunkAndPack(ctx context.Context, b *batch, plan []inodePlan, res *flushResult) error {
	pk := s.newPacker()
	defer pk.abort()
	for _, ip := range plan {
		if err := s.chunkInode(ctx, b, ip.exts, pk, res); err != nil {
			return err
		}
	}
	if err := pk.finish(ctx); err != nil {
		return err
	}
	res.chunkLoc = pk.locs
	res.packs = pk.sealed
	res.uploaded = &pk.outstanding
	res.uploadedBytes = pk.bytes
	res.uploadedChunks = pk.count
	res.dedupedChunks = pk.skipped
	return nil
}

// chunkInode runs the CDC pass over one inode's surviving extents and
// feeds the resulting chunks to the pack.
//
// There is no way to abandon the pass under pressure. That release valve
// was built and measured, and it LOST: a session ran 10.31s with it
// against 7.77s without, abandoning 38 of 39 flushes even at zero
// modelled latency. Abandoning cannot skip hashing, because a pack
// entry's key IS the chunk identity, so it trades a cheap gear-hash scan
// for extra pack entries and comes out behind.
func (s *Store) chunkInode(ctx context.Context, b *batch, exts []Record, pk *flushPacker, res *flushResult) error {
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
		readers[i] = bytes.NewReader(s.ringAt(uint64(r.Off), r.Length))
	}
	ch := chunkid.NewChunker(io.MultiReader(readers...), s.chunkOpts)
	var pos int64
	for pos < total {
		c, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		id := s.hasher.Sum(c.Data)
		if _, _, _, err := pk.add(ctx, id, c.Data); err != nil {
			return err
		}
		emit(pos, id, len(c.Data))
		pos += int64(len(c.Data))
	}
	return nil
}

// publish installs the flush's locations and releases the table. Both
// happen under one lock hold: a reader must never observe a moment where
// the memtable has been dropped and the location map does not yet answer.
func (s *Store) publish(b *batch, res *flushResult) {
	s.mu.Lock()
	for h, sl := range res.handleLoc {
		s.handleLoc[h] = sl
		// The handle's references move from the ring's live set to the
		// location map's, because that is where the state now is. Taking
		// the count across rather than starting one is what makes the two
		// halves continuous: a reference that existed before the flush is
		// the same reference after it.
		//
		// Zero means the extent was superseded while this run was
		// chunking it — the pack run cuts outside the lock — so the entry
		// is dead on arrival and no row will ever name it. Installing and
		// immediately dropping it (rather than skipping) keeps this the
		// only place that decides, and matches what applyLocked would have
		// done a moment later.
		if n := s.live[h]; n > 0 {
			s.locRefs[h] = n
		} else {
			delete(s.handleLoc, h)
		}
	}
	for k, v := range res.chunkLoc {
		s.chunkLoc[k] = v
	}
	s.packs = append(s.packs, res.packs...)
	s.stats.UploadedBytes += res.uploadedBytes
	s.stats.UploadedChunks += res.uploadedChunks
	s.stats.DedupedChunks += res.dedupedChunks
	s.stats.Packs += int64(len(res.packs))
	s.stats.DeadExtents += res.deadExtents
	s.stats.DeadBytes += res.deadBytes

	// Locations are installed BEFORE the ring space is released, and both
	// happen under one lock hold. A reader must never observe a moment
	// where the ring no longer holds an extent and the location map does
	// not yet answer for it.
	for _, r := range b.recs {
		delete(s.index, r.Handle)
		delete(s.live, r.Handle)
	}
	if n := len(b.recs); n > 0 && n <= len(s.order) {
		s.order = s.order[n:]
	}
	if b.to > s.reclaimTo {
		s.reclaimTo = b.to
	}
	s.releaseLocked()
	// The journal record is NOT written here. It belongs after the packs
	// have landed (runFlush), and writing it at this point was a leftover
	// from when uploads were synchronous with the pack run: it recorded a
	// location for a pack that may still have been in the queue, which is
	// the one thing the wait in runFlush exists to prevent.
	s.packing = false
	s.cond.Broadcast()
	s.mu.Unlock()
}

// journalLocated records a landed batch. It runs after the uploads, off
// the path a writer waits on.
func (s *Store) journalLocated(res *flushResult) {
	if s.journal == nil {
		return
	}
	if err := s.journal.Located(Location{
		Handles: res.handleLoc, Chunks: res.chunkLoc, Packs: res.packs,
	}); err != nil {
		// The bytes are on the federation and the map is in memory; only
		// the RECORD of the map failed. Reads keep working, and a crash
		// now would lose content that is already durable — so it is a
		// failed flush, retried, rather than a silent downgrade.
		s.mu.Lock()
		s.flushErr = err
		s.cond.Broadcast()
		s.mu.Unlock()
	}
}

// failFlush leaves the records in place. Until their locations are
// published the ring is the only copy, so a failed pack run must not
// reclaim anything — it is retried by the next Flush.
//
// It must still clear the in-flight flag. The run IS over, and a flag
// left set is a lock nobody holds: the next Flush would wait on a
// broadcast that can never come.
func (s *Store) failFlush(err error) {
	s.mu.Lock()
	s.flushErr = err
	s.packing = false
	s.cond.Broadcast()
	s.mu.Unlock()
}

// flushPacker accumulates chunks into packs, cutting at target, and
// records where each chunk landed. It is deliberately not
// publish.packer: that file is being rewritten elsewhere, and a flush
// needs the per-chunk offsets that packer does not surface.
type flushPacker struct {
	obj      pelicanobj.Store
	dir      string
	target   int64
	cache    *packCache
	uploads  *uploadQueue
	dek      []byte
	keyID    int64
	onUpload func(string, int64, time.Duration)

	w    *packstore.PackWriter
	pend []pendingLoc
	// pending is the open pack's entries, by key. It holds the entry
	// rather than a marker because a caller writing a catalog row needs
	// the STORED numbers of a chunk this run has already encoded, and
	// those exist here before the pack is cut.
	pending map[string]pendingLoc
	locs    map[string]PackLoc

	// placed asks the store where a chunk already is — the only dedup that
	// reaches back past this run. Nil for a packer with no store behind
	// it, which is what the measurement harness builds.
	placed func(key string) (PackLoc, bool)

	sealed  []packstore.SealedPack
	bytes   int64
	count   int64
	skipped int64
	// outstanding counts packs cut and not yet landed. A flush installs
	// its locations without waiting on any of them; only the journal
	// record waits, because that record is what a later session would
	// publish from.
	outstanding sync.WaitGroup
}

type pendingLoc struct {
	key     string
	off     int64
	stored  int64
	logical int64
	alg     uint8
}

func newFlushPacker(obj pelicanobj.Store, dir string, target int64, cache *packCache, dek []byte, keyID int64,
	onUpload func(string, int64, time.Duration), uploads *uploadQueue) *flushPacker {
	return &flushPacker{
		obj: obj, dir: dir, target: target, cache: cache, dek: dek, keyID: keyID,
		onUpload: onUpload, uploads: uploads,
		pending: make(map[string]pendingLoc),
		locs:    make(map[string]PackLoc),
	}
}

// newPacker builds a packer bound to this store, which is the only kind
// that can dedup against what earlier flushes already sent.
func (s *Store) newPacker() *flushPacker {
	p := newFlushPacker(s.obj, s.dir, s.packTarget, s.cache, s.dek, s.keyID, s.onUpload, s.uploads)
	p.placed = s.placedChunk
	return p
}

// placedChunk reports where the store already knows a chunk's bytes are.
// It takes the lock for the lookup and nothing else: a packer runs OFF
// the store's lock by design, and holding it across a compress, an
// encrypt and a pack write would put every writer behind every chunk.
//
// Racing here is harmless in both directions. A location installed just
// after the lookup means one chunk is stored twice, which is a wasted
// upload and not a wrong answer; a location installed just before means
// the chunk is skipped, and skipping is only ever correct — identity IS
// the content, so the entry already in the map is these bytes.
func (s *Store) placedChunk(key string) (PackLoc, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	loc, ok := s.chunkLoc[key]
	return loc, ok
}

// add stores one chunk. The bytes are ENCODED first — zstd unless that
// makes them bigger, then AES-256-GCM when the volume has a key — which
// is the same treatment publish gives a chunk, through the same codec.
// Doing it here rather than at the seal is the whole point: a session
// that packs as it writes must produce the same objects a seal would, or
// it is not the same format.
//
// It reports how the chunk was STORED — the encoded length, the codec and
// the key — because that is what a catalog row carries alongside the
// logical length, and only the entry that encoded the bytes knows it. A
// caller that filled those fields in from the plaintext instead would
// write a row claiming an entry's stored length is its decoded length,
// which is true only for bytes zstd could not shrink and never true on an
// encrypted volume.
func (p *flushPacker) add(ctx context.Context, id chunkid.Identity, data []byte) (stored int64, alg uint8, keyID int64, err error) {
	key := id.Hex()
	if loc, done := p.locs[key]; done {
		return loc.Stored, loc.Alg, loc.KeyID, nil
	}
	// The open pack's entries need their own lookup, not a scan of pend: an
	// a chunk per extent is possible for tiny files, so a pack can hold
	// thousands of small entries rather than the sixteen a 4 MiB average
	// would give.
	if pl, open := p.pending[key]; open {
		return pl.stored, pl.alg, p.keyID, nil
	}
	// Neither of those maps outlives the run, so without this a chunk the
	// store sent in an EARLIER flush is compressed, encrypted and uploaded
	// again — the same bytes appearing under a second inode, or a rewrite
	// that restored what was already there, both of which are ordinary. The
	// re-chunk path has always made this check (Sealer.rechunk); making it
	// here is what puts the flush path on the same footing.
	//
	// The chunk is deliberately NOT recorded in p.locs: this run did not
	// place it, and a caller that copies p.locs into the store's map must
	// not overwrite the location that already answers for it.
	if p.placed != nil {
		if loc, ok := p.placed(key); ok {
			p.skipped++
			return loc.Stored, loc.Alg, loc.KeyID, nil
		}
	}
	if p.w != nil && p.w.Size() > 0 && p.w.Size()+int64(len(data)) > p.target {
		if err := p.cut(ctx); err != nil {
			return 0, 0, 0, err
		}
	}
	if p.w == nil {
		w, err := packstore.NewPackWriter(p.dir)
		if err != nil {
			return 0, 0, 0, err
		}
		p.w = w
	}
	enc, alg, err := entrycodec.Encode(data, p.dek)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("memtable: encode chunk %s: %w", key, err)
	}
	off := p.w.Size()
	if err := p.w.Add(key, packstore.EntryData, enc); err != nil {
		return 0, 0, 0, err
	}
	pl := pendingLoc{
		key: key, off: off,
		stored: int64(len(enc)), logical: int64(len(data)), alg: alg,
	}
	p.pend = append(p.pend, pl)
	p.pending[key] = pl
	p.bytes += int64(len(enc))
	p.count++
	return pl.stored, pl.alg, p.keyID, nil
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
	// From here the pack EXISTS: its bytes are laid out, its trailer is
	// written, and the file is about to be retained locally. Everything
	// downstream — the location map, the ring region this came from — can
	// proceed on that. Only publishing a generation has to wait for the
	// upload, and that waits once, at the seal.
	// The spool IS the pack, so it is handed to the local cache rather
	// than deleted after the upload. Retaining BEFORE the upload is what
	// makes it a rename of a file already on disk instead of a second
	// copy of it; the upload streams from the open descriptor, which a
	// rename does not disturb.
	retained := false
	if p.cache != nil {
		if err := p.w.Retain(p.cache.path(sp.Name)); err != nil {
			return err
		}
		retained = true
	}
	if retained {
		p.cache.admit(sp.Name, sp.Size)
	}
	p.w = nil
	p.sealed = append(p.sealed, sp)
	for _, pl := range p.pend {
		p.locs[pl.key] = PackLoc{
			Pack: sp.Name, Off: pl.off,
			Stored: pl.stored, Logical: pl.logical, Alg: pl.alg, KeyID: p.keyID,
		}
	}
	p.pend = nil
	clear(p.pending)

	p.outstanding.Add(1)
	started := time.Now()
	err = p.uploads.add(uploadJob{
		ctx: ctx, pack: sp, send: upload,
		done: func(err error) {
			if err != nil && retained {
				// Nothing that survives references a pack that never
				// landed, so the local copy is garbage rather than cache.
				p.cache.drop(sp.Name)
			}
			p.outstanding.Done()
		},
		onSent: func(name string, size int64) {
			if p.onUpload != nil {
				p.onUpload(name, size, time.Since(started))
			}
		},
	})
	if err != nil {
		p.outstanding.Done()
	}
	return err
}

func (p *flushPacker) finish(ctx context.Context) error { return p.cut(ctx) }

func (p *flushPacker) abort() {
	if p.w != nil {
		p.w.Abort()
		p.w = nil
	}
}
