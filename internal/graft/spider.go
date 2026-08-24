package graft

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// The spider: the one expensive thing a graft ever does.
//
// Verifiable ranged reads need a digest per block, so grafting reads
// EVERY BYTE of the source once. That is the whole cost model — O(source)
// in bandwidth at graft time and O(0) in storage forever, against a
// copy's O(source) in both, forever — and at the sizes this feature is
// for it is hours of network the user pays for once. Everything in this
// file exists to make those hours as few as possible and to make them
// survivable if something interrupts them.
//
// # Parallelism
//
// Fixed blocks are independent, so the work is embarrassingly parallel in
// two dimensions at once and the same mechanism serves both. The unit is
// a SPAN: a contiguous run of blocks within one object, fetched by one
// ranged GET and hashed block by block. A tree of small objects produces
// one span each and parallelises across objects; a single 100 GB object
// produces hundreds of spans and parallelises within itself. There is no
// second code path for the large-file case.
//
// A span is bounded by SpanBytes rather than by a block count so that the
// request size stays constant as the ladder changes the block size
// (blocks.go). Too small and the walk is one round trip per few MB; too
// large and a failure re-reads too much and the tail of the walk runs on
// one worker.
//
// # What bounds the concurrency, and where the default came from
//
// Measured, not chosen. TestSpiderThroughputTable (PELFS_GRAFT_BENCH=1)
// walks a 456 MB tree of 204 objects against cmd/fakeorigin's handler at
// three simulated round-trip times, on a 12-core M2 Pro whose BLAKE3
// floor is 1.7 GB/s per core:
//
//	workers     RTT 0      RTT 5ms    RTT 20ms      (MB/s)
//	      1     1984         280          86
//	      2     2521         439         178
//	      4     3244         887         353
//	      8     3614        1434         594
//	     16     3753        1643        1009
//	     32     3873        2023        1433
//	     64     3656        1693        1695
//
// Two knees, and the default has to sit between them. With no latency the
// walk is CPU-bound and flattens at 8 — everything past it is contention,
// and 64 is already slower than 32. With latency it is round-trip-bound
// and keeps climbing to 32 and beyond, because a worker spends its time
// waiting.
//
// DefaultConcurrency is 16: within 4% of the zero-latency ceiling, 70% of
// the 20 ms ceiling, and nowhere near the point where more workers make a
// real origin someone else operates unhappy. A source further away wants
// more, and --concurrency is how you say so.
//
// It does NOT invent a third pool. pelfs already has a transfer pool
// (pelicanobj.TransferWorkers, the Pelican client's WorkerCount) and a
// concurrent-upload cap (publish.DefaultUploadConcurrency = 4); a
// TransferWorkers larger than 16 is an operator who has already said what
// their client should do, and it wins.
//
// # Consistency
//
// The listing taken at the start is the WALK'S MANIFEST, and the same
// listing is taken again at the end. An object whose size or mtime moved
// between them, appeared, or vanished, aborts the graft — because an
// index that describes two different versions of a tree is the one
// outcome worth refusing outright, and it is not detectable later: every
// block in it verifies, the file lengths are all consistent, and the tree
// simply never existed.
//
// Aborting is affordable precisely because of the checkpoint: the re-run
// re-hashes only the objects that moved.

// InlineKeep is the size below which a spider KEEPS a file's bytes rather
// than only its digests, so publish can store it inline in the catalog.
//
// A grafted file under the inline threshold is COPIED into the volume and
// stops being grafted at all. Publish requires it — a file at or under
// Options.InlineMax is stored in the catalog by rule, and ContentProvider
// has no shape for "inline this one but here are chunk records" — and it
// is also the better answer: the bytes are kilobytes, the catalog they
// land in is content-addressed and signature-covered, so an inlined file
// no longer depends on the source at all, and serving it costs no
// request.
//
// Set above publish.DefaultInlineMax (2048) so a caller that raises the
// threshold somewhat still finds bytes in hand.
const InlineKeep = 64 << 10

// DefaultConcurrency is how many ranged reads of the source are in
// flight when nothing says otherwise. See the table above: it is between
// the CPU-bound knee (8) and the latency-bound one (32).
const DefaultConcurrency = 16

// DefaultSpanBytes is the most one ranged read of the source covers.
//
// 32 MiB is a compromise measured rather than guessed (see the
// concurrency table in docs/design-graft.md): large enough that the
// per-request overhead is under a percent of a walk even at a 20 ms RTT,
// small enough that a failed span re-reads seconds rather than minutes
// and that the last object of a walk does not run alone for long.
const DefaultSpanBytes int64 = 32 << 20

// File is one spidered file: where it lands in the volume, how big it is,
// when it changed at the source, and the block identities that describe
// it.
//
// It holds IDENTITIES rather than catalog.ChunkRef rows, and the
// difference is 32 bytes a block against about 100. On a 10 TB graft that
// is 336 MB instead of a gigabyte, and the rows are built on demand by
// Refs when publish asks for exactly one file's worth.
type File struct {
	Path    string
	Size    int64
	MtimeNS int64
	// Block is the size THIS file was cut at, which the ladder may have
	// raised above the graft's base (blocks.go).
	Block int64
	IDs   []chunkid.Identity
	// Body is the whole file, kept only for files at or under InlineKeep.
	// Nil for everything else, which is the case the graft exists for.
	Body []byte
}

// Refs builds the chunkref rows for one file.
//
// A grafted block is stored as it arrives: plaintext, uncompressed.
// AlgNone with clen == llen is exactly what entrycodec.Decode passes
// through untouched, so the read path needs no branch for it.
func (f *File) Refs() []catalog.ChunkRef {
	if len(f.IDs) == 0 {
		return nil
	}
	out := make([]catalog.ChunkRef, 0, len(f.IDs))
	var off int64
	for i := range f.IDs {
		n := f.Block
		if rem := f.Size - off; rem < n {
			n = rem
		}
		out = append(out, catalog.ChunkRef{
			Identity:      append([]byte(nil), f.IDs[i][:]...),
			LLen:          n,
			CLen:          n,
			Alg:           0,
			KeyID:         0,
			LogicalOffset: off,
		})
		off += n
	}
	return out
}

// Result is one completed spider.
type Result struct {
	Files []File
	Bytes int64
	// Inlined counts files small enough to be copied into the catalog
	// instead of grafted (InlineKeep), and InlinedBytes what they weigh.
	Inlined      int
	InlinedBytes int64
	// Objects is how many source objects the walk covered, Blocks how
	// many blocks it cut them into (duplicates included).
	Objects int
	Blocks  int64
	// BytesHashed is what this run actually read from the source, and
	// BytesResumed what a checkpoint spared it. The pair is the honest
	// answer to "what did this cost me", and on a re-run of an unchanged
	// source the first is zero.
	BytesHashed, BytesResumed int64
	ObjectsResumed            int
	// Elapsed is how long the walk took.
	Elapsed time.Duration
}

// Progress is a snapshot of a walk in flight.
type Progress struct {
	Objects, ObjectsDone, ObjectsResumed  int
	BytesTotal, BytesHashed, BytesResumed int64
	Blocks                                int64
	Elapsed                               time.Duration
}

// Rate is bytes hashed per second so far, or zero before anything has
// been read.
func (p Progress) Rate() float64 {
	if p.Elapsed <= 0 || p.BytesHashed <= 0 {
		return 0
	}
	return float64(p.BytesHashed) / p.Elapsed.Seconds()
}

// ETA is how much longer the walk has, or zero when it cannot be said
// yet.
func (p Progress) ETA() time.Duration {
	r := p.Rate()
	left := p.BytesTotal - p.BytesResumed - p.BytesHashed
	if r <= 0 || left <= 0 {
		return 0
	}
	return time.Duration(float64(left) / r * float64(time.Second))
}

// SpiderOptions configures a spider.
type SpiderOptions struct {
	// Src reads the foreign prefix.
	Src pelicanobj.Store
	// Index accumulates the location table. Required: the spider does not
	// hold one, because at target size it would not fit.
	Index *Writer
	// Policy is the block-size rule (blocks.go).
	Policy BlockPolicy
	// Hasher computes identities. The zero value hashes unkeyed, which is
	// the only mode a graft may use — see genfs's refusal on encrypted
	// volumes and the design doc's encryption section.
	Hasher chunkid.Hasher
	// Checkpoint, when set, is consulted for work already done and
	// appended to as work completes.
	Checkpoint *Checkpoint
	// Concurrency is how many ranged reads are in flight; zero takes
	// pelicanobj.TransferWorkers.
	Concurrency int
	// SpanBytes bounds one ranged read; zero takes DefaultSpanBytes.
	SpanBytes int64
	// Progress, when set, is called on a timer with a snapshot.
	Progress      func(Progress)
	ProgressEvery time.Duration
}

// object is one source object's plan and its accumulating result.
type object struct {
	key     string
	path    string
	size    int64
	mtimeNS int64
	block   int64
	nblocks int
	ids     []chunkid.Identity
	body    []byte // only for objects at or under InlineKeep
	// todo is set for objects this run must read; a resumed one is
	// indexed in the pre-pass instead of when its last span lands.
	todo    bool
	pending atomic.Int64
}

type span struct {
	ob   *object
	from int // first block
	to   int // one past the last
}

// Spider walks the source prefix, streams every object once, and cuts it
// into blocks with an identity each.
func Spider(ctx context.Context, o SpiderOptions) (*Result, error) {
	if o.Src == nil {
		return nil, errors.New("graft: a source store is required")
	}
	if o.Index == nil {
		return nil, errors.New("graft: an index writer is required")
	}
	policy := o.Policy.withDefaults()
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	workers := o.Concurrency
	if workers <= 0 {
		workers = DefaultConcurrency
		if n := pelicanobj.TransferWorkers(); n > workers {
			workers = n
		}
	}
	if workers > 1024 {
		workers = 1024
	}
	spanBytes := o.SpanBytes
	if spanBytes <= 0 {
		spanBytes = DefaultSpanBytes
	}
	start := time.Now()

	listed, err := listSource(ctx, o.Src)
	if err != nil {
		return nil, err
	}
	if len(listed) == 0 {
		return nil, fmt.Errorf("graft: %s holds no objects", o.Src)
	}

	res := &Result{Objects: len(listed)}
	var total int64
	objs := make([]*object, 0, len(listed))
	var todo []*object
	for _, ob := range listed {
		total += ob.Size
		blk := policy.For(ob.Size)
		n := int((ob.Size + blk - 1) / blk)
		if ob.Size == 0 {
			n = 0
		}
		obj := &object{
			key: ob.Key, path: path.Clean("/" + ob.Key),
			size: ob.Size, mtimeNS: ob.Mtime.UnixNano(),
			block: blk, nblocks: n,
		}
		objs = append(objs, obj)
		// RESUME, gated on the two things a listing can prove: the size
		// and the mtime the log recorded are the ones the source reports
		// now. Anything else is re-read.
		if o.Checkpoint != nil {
			if done, ok := o.Checkpoint.Done(ob.Key); ok {
				if done.Size == obj.size && done.MtimeNS == obj.mtimeNS &&
					done.Block == obj.block && len(done.IDs) == n {
					obj.ids = done.IDs
					obj.body = done.Body
					res.BytesResumed += obj.size
					res.ObjectsResumed++
					continue
				}
				o.Checkpoint.Forget(ob.Key)
			}
		}
		obj.ids = make([]chunkid.Identity, n)
		if obj.size > 0 && obj.size <= InlineKeep {
			// Allocated up front for the same reason ids is: an object
			// small enough to inline can still be cut into more than one
			// span (a small --block with a small --span), and its spans
			// run on different workers. Appending would be both a data
			// race and an inline body assembled in completion order.
			obj.body = make([]byte, obj.size)
		}
		obj.todo = true
		todo = append(todo, obj)
	}

	// Resumed objects still have to enter the index: the index object is
	// rebuilt from scratch every run, because it is hash-named and a
	// partial one would name nothing.
	var resumedBlocks int64
	for _, obj := range objs {
		if obj.todo {
			continue
		}
		resumedBlocks += int64(len(obj.ids))
		if err := addObject(o.Index, obj); err != nil {
			return nil, err
		}
	}

	var hashed atomic.Int64
	var blocks atomic.Int64
	var doneObjs atomic.Int64
	doneObjs.Store(int64(res.ObjectsResumed))

	// Progress on a timer rather than per object: a walk of one enormous
	// file would otherwise go silent for its whole duration, which is
	// exactly the complaint this exists to answer.
	stopProgress := func() {}
	if o.Progress != nil {
		every := o.ProgressEvery
		if every <= 0 {
			every = 2 * time.Second
		}
		tick := time.NewTicker(every)
		pctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer tick.Stop()
			for {
				select {
				case <-pctx.Done():
					return
				case <-tick.C:
					o.Progress(Progress{
						Objects: len(objs), ObjectsDone: int(doneObjs.Load()),
						ObjectsResumed: res.ObjectsResumed,
						BytesTotal:     total, BytesHashed: hashed.Load(),
						BytesResumed: res.BytesResumed,
						Blocks:       blocks.Load(), Elapsed: time.Since(start),
					})
				}
			}
		}()
		stopProgress = func() { cancel(); wg.Wait() }
	}

	// The spans, in object order so that a walk reads a tree roughly
	// front to back and a person watching it can tell where it is.
	var spans []span
	for _, obj := range todo {
		obj.pending.Store(int64(0))
		per := int(spanBytes / obj.block)
		if per < 1 {
			per = 1
		}
		if obj.nblocks == 0 {
			// A zero-length object still needs its record, and there is
			// nothing to fetch for it.
			continue
		}
		for from := 0; from < obj.nblocks; from += per {
			to := from + per
			if to > obj.nblocks {
				to = obj.nblocks
			}
			spans = append(spans, span{ob: obj, from: from, to: to})
			obj.pending.Add(1)
		}
	}

	err = runSpans(ctx, spans, workers, func(ctx context.Context, s span) error {
		n, nb, err := hashSpan(ctx, o, s)
		if err != nil {
			return err
		}
		hashed.Add(n)
		blocks.Add(int64(nb))
		if s.ob.pending.Add(-1) == 0 {
			if err := addObject(o.Index, s.ob); err != nil {
				return err
			}
			if o.Checkpoint != nil {
				if err := o.Checkpoint.Record(&CheckObject{
					Key: s.ob.key, Size: s.ob.size, MtimeNS: s.ob.mtimeNS,
					Block: s.ob.block, IDs: s.ob.ids, Body: s.ob.body,
				}); err != nil {
					return fmt.Errorf("graft: checkpoint: %w", err)
				}
			}
			doneObjs.Add(1)
		}
		return nil
	})
	stopProgress()
	if err != nil {
		return nil, err
	}
	// Zero-length objects have no spans, so their records are made here.
	for _, obj := range todo {
		if obj.nblocks == 0 {
			if err := addObject(o.Index, obj); err != nil {
				return nil, err
			}
			if o.Checkpoint != nil {
				if err := o.Checkpoint.Record(&CheckObject{
					Key: obj.key, Size: obj.size, MtimeNS: obj.mtimeNS, Block: obj.block,
				}); err != nil {
					return nil, fmt.Errorf("graft: checkpoint: %w", err)
				}
			}
		}
	}

	// THE SECOND LISTING. Everything above is worthless if the tree moved
	// underneath it, and this is the only place that can be seen.
	if err := confirmUnchanged(ctx, o.Src, listed); err != nil {
		return nil, err
	}

	for _, obj := range objs {
		f := File{Path: obj.path, Size: obj.size, MtimeNS: obj.mtimeNS, Block: obj.block, IDs: obj.ids}
		res.Bytes += obj.size
		if obj.size > 0 && obj.size <= InlineKeep {
			// Small enough to inline, so the digests just computed for it
			// are dropped along with its index rows: an inlined file is
			// not grafted, and leaving its blocks in the index would name
			// locations nothing resolves through.
			f.Body = obj.body
			f.IDs = nil
			res.Inlined++
			res.InlinedBytes += obj.size
		}
		res.Files = append(res.Files, f)
	}
	sort.Slice(res.Files, func(i, j int) bool { return res.Files[i].Path < res.Files[j].Path })
	res.BytesHashed = hashed.Load()
	res.Blocks = blocks.Load() + resumedBlocks
	res.Elapsed = time.Since(start)
	return res, nil
}

// addObject hands one object's blocks to the index.
//
// An object at or under InlineKeep is DELIBERATELY not indexed: it is
// copied into the catalog instead of grafted, so index rows for it would
// name locations nothing resolves through.
func addObject(w *Writer, obj *object) error {
	if len(obj.ids) == 0 || (obj.size > 0 && obj.size <= InlineKeep) {
		return nil
	}
	bs := make([]Block, 0, len(obj.ids))
	var off int64
	for i := range obj.ids {
		n := obj.block
		if rem := obj.size - off; rem < n {
			n = rem
		}
		bs = append(bs, Block{ID: obj.ids[i], Loc: Loc{Key: obj.key, Off: off, Length: n}})
		off += n
	}
	return w.Add(bs)
}

// hashSpan fetches one contiguous run of blocks and digests each.
func hashSpan(ctx context.Context, o SpiderOptions, s span) (int64, int, error) {
	obj := s.ob
	off := int64(s.from) * obj.block
	end := int64(s.to) * obj.block
	if end > obj.size {
		end = obj.size
	}
	length := end - off
	rc, err := o.Src.Get(ctx, obj.key, off, length)
	if err != nil {
		return 0, 0, fmt.Errorf("graft: read %s [%d,+%d): %w", obj.key, off, length, err)
	}
	defer rc.Close() //nolint:errcheck
	buf := make([]byte, obj.block)
	var read int64
	nb := 0
	for i := s.from; i < s.to; i++ {
		want := obj.block
		if rem := obj.size - int64(i)*obj.block; rem < want {
			want = rem
		}
		n, rerr := io.ReadFull(rc, buf[:want])
		if int64(n) != want {
			// The listing's length and the bytes actually delivered must
			// agree, or the catalog would record a length no read can
			// satisfy. This is the first place a source mutating
			// mid-spider is caught, and it is caught rather than
			// published.
			return read, nb, fmt.Errorf("graft: %s block %d wanted %d bytes and got %d "+
				"(the source changed while it was being spidered): %v", obj.key, i, want, n, rerr)
		}
		obj.ids[i] = o.Hasher.Sum(buf[:want])
		if obj.body != nil {
			// Written at the block's own offset, so two spans of the same
			// small object touch disjoint ranges of a slice neither of
			// them grows. Same shape as obj.ids just above it.
			copy(obj.body[int64(i)*obj.block:], buf[:want])
		}
		read += want
		nb++
	}
	// Nothing may follow the last block of the span: an object that grew
	// under the walk would otherwise be indexed as its old length.
	var extra [1]byte
	if n, _ := rc.Read(extra[:]); n > 0 {
		return read, nb, fmt.Errorf("graft: %s delivered more than the %d bytes it listed "+
			"(the source changed while it was being spidered)", obj.key, obj.size)
	}
	return read, nb, nil
}

// listSource takes the walk's manifest.
func listSource(ctx context.Context, src pelicanobj.Store) ([]*pelicanobj.Object, error) {
	ch, err := src.ListAll(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("graft: list %s: %w", src, err)
	}
	var objs []*pelicanobj.Object
	for ob := range ch {
		if ob == nil {
			return nil, fmt.Errorf("graft: listing %s failed", src)
		}
		if ob.IsDir {
			continue
		}
		objs = append(objs, ob)
	}
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key })
	return objs, nil
}

// confirmUnchanged re-lists the source and refuses a graft whose tree
// moved while it was being walked.
//
// A graft whose index describes two different versions of a tree is the
// failure mode with no later defence: every block in it verifies, every
// file length is self-consistent, and the tree it describes simply never
// existed at any instant. It has to be caught here or not at all.
func confirmUnchanged(ctx context.Context, src pelicanobj.Store, before []*pelicanobj.Object) error {
	after, err := listSource(ctx, src)
	if err != nil {
		return fmt.Errorf("graft: confirming the source did not change: %w", err)
	}
	was := make(map[string]*pelicanobj.Object, len(before))
	for _, ob := range before {
		was[ob.Key] = ob
	}
	var moved []string
	note := func(s string) {
		if len(moved) < 8 {
			moved = append(moved, s)
		}
	}
	for _, ob := range after {
		old, ok := was[ob.Key]
		if !ok {
			note(ob.Key + " appeared")
			continue
		}
		if old.Size != ob.Size {
			note(fmt.Sprintf("%s was %d bytes and is now %d", ob.Key, old.Size, ob.Size))
		} else if !old.Mtime.Equal(ob.Mtime) {
			note(ob.Key + " was modified")
		}
		delete(was, ob.Key)
	}
	for k := range was {
		note(k + " vanished")
	}
	if len(moved) == 0 {
		return nil
	}
	sort.Strings(moved)
	return fmt.Errorf("graft: the source changed while it was being walked (%v). Publishing now "+
		"would sign an index describing a tree that never existed at any instant, so it is "+
		"refused. Re-run when the source is quiet: the checkpoint means only what moved is "+
		"read again", moved)
}

// runSpans executes spans with at most workers of them in flight, and
// stops the walk at the first failure.
//
// A failure is fatal to the RUN and not to the checkpoint: every object
// that completed before it is on disk, so the retry costs the remainder.
// That is the whole reason the unit of durability is the object rather
// than the walk.
func runSpans(ctx context.Context, spans []span, workers int, fn func(context.Context, span) error) error {
	if len(spans) == 0 {
		return nil
	}
	if workers > len(spans) {
		workers = len(spans)
	}
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	in := make(chan span)
	var (
		mu    sync.Mutex
		first error
		wg    sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		if first == nil {
			first = err
			cancel()
		}
		mu.Unlock()
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range in {
				if ctx.Err() != nil {
					return
				}
				if err := fn(ctx, s); err != nil {
					fail(err)
					return
				}
			}
		}()
	}
feed:
	for _, s := range spans {
		select {
		case in <- s:
		case <-ctx.Done():
			break feed
		}
	}
	close(in)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if first != nil {
		return first
	}
	return ctx.Err()
}
