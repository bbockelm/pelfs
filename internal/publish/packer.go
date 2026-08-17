package publish

import (
	"context"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// packer feeds typed entries into a sequence of PackWriters, cutting at the
// target size (the cut runs before an append that would exceed it, so a
// lone larger-than-target entry seals alone). It also dedups keys across
// the whole publish: content addressing means a duplicate Add is always the
// same bytes, so the first copy wins.
//
// TODO(cross-generation dedup): a local sidecar identity index would let a
// publish skip chunks already uploaded by previous generations. Until then
// re-uploads are harmless duplicates — content addressing makes them dead
// weight, never corruption.
type packer struct {
	inner pelicanobj.Store
	dir   string
	// target is the steady-state cut size; cur is what the pack being
	// built is cut at, which starts smaller and doubles toward target.
	target int64
	cur    int64

	w      *packstore.PackWriter
	sealed []packstore.SealedPack
	added  map[string]struct{}

	// Uploads run in the background so building the next pack overlaps
	// the current one's round trip. mu guards sealed and err against the
	// upload goroutines; sem bounds how many are in flight at once.
	mu  sync.Mutex
	wg  sync.WaitGroup
	sem chan struct{}
	err error

	// onFirstUpload, if set, is called once, from the goroutine that puts
	// the first pack's bytes on the wire. It is how a publish announces
	// that it has stopped preparing and started sending; the caller sees
	// one line per seal no matter how many packs follow.
	onFirstUpload func(time.Duration)

	// Occupancy accounting, all under mu. started is this publish's t0;
	// inflight counts running uploads, since opens the current busy
	// stretch, and busy accumulates the wall time with at least one
	// upload running. Two extra lock acquisitions per pack, no sampling.
	started  time.Time
	uploads  int
	inflight int
	since    time.Time
	busy     time.Duration
	firstAt  time.Duration
}

// UploadReport is the evidence that a seal overlapped packing with
// sending, rather than doing all of one and then all of the other. First
// is how long after the publish began the first pack's bytes started
// moving; Busy is the wall time with at least one upload in flight.
//
// A reader compares Busy against the seal they just waited out: a Busy
// close to that wall time means the link was the constraint, and a small
// one means the link sat idle while pelfs was doing something else.
type UploadReport struct {
	Packs int
	First time.Duration
	Busy  time.Duration
}

func newPacker(inner pelicanobj.Store, dir string, target, first int64, conc int) *packer {
	if first <= 0 || first > target {
		first = target
	}
	if conc <= 0 {
		conc = DefaultUploadConcurrency
	}
	return &packer{
		inner: inner, dir: dir, target: target, cur: first,
		added:   make(map[string]struct{}),
		sem:     make(chan struct{}, conc),
		started: time.Now(),
	}
}

// uploadBegan opens one upload's occupancy interval and fires the
// first-upload hook, outside the lock so a slow sink cannot stall the
// transfer it is reporting on.
func (p *packer) uploadBegan() {
	p.mu.Lock()
	p.uploads++
	if p.inflight == 0 {
		p.since = time.Now()
	}
	p.inflight++
	first := p.uploads == 1
	if first {
		p.firstAt = time.Since(p.started)
	}
	at := p.firstAt
	p.mu.Unlock()
	if first && p.onFirstUpload != nil {
		p.onFirstUpload(at)
	}
}

func (p *packer) uploadEnded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inflight--
	if p.inflight == 0 {
		p.busy += time.Since(p.since)
	}
}

// uploadReport summarizes what the uploads did. Safe to call at any time;
// an upload still running counts its time so far.
func (p *packer) uploadReport() UploadReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := UploadReport{Packs: p.uploads, First: p.firstAt, Busy: p.busy}
	if p.inflight > 0 {
		r.Busy += time.Since(p.since)
	}
	return r
}

// has reports whether key was already added during this publish.
func (p *packer) has(key string) bool {
	_, ok := p.added[key]
	return ok
}

// add appends one entry, cutting the current pack first when the entry
// would push it past the target. Duplicate keys are silently skipped.
func (p *packer) add(ctx context.Context, key, typ string, data []byte) error {
	if p.has(key) {
		return nil
	}
	if p.w != nil && p.w.Size() > 0 && p.w.Size()+int64(len(data)) > p.cur {
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
	if err := p.w.Add(key, typ, data); err != nil {
		return err
	}
	p.added[key] = struct{}{}
	return nil
}

// cut finalizes the open pack (if any) and starts its upload in the
// background. It returns as soon as the pack has an identity, which is
// all the walk needs to keep going; the bytes land before finish
// returns. On error the writer is kept for abort.
func (p *packer) cut(ctx context.Context) error {
	if p.w == nil {
		return nil
	}
	// An upload that already failed makes every later one wasted work,
	// and the publish is going to abort regardless.
	if err := p.failure(); err != nil {
		return err
	}
	w := p.w
	sp, upload, err := w.Finalize()
	if err != nil {
		return err
	}
	p.w = nil
	// Ramp toward the steady-state target. The early packs exist to get
	// bytes onto the wire while the walk is still running; once the pipe
	// is full there is nothing left to buy and per-object overhead —
	// another trailer, another entry in the pack list every mount reads —
	// argues for the larger size.
	if p.cur < p.target {
		p.cur = min(p.cur*2, p.target)
	}
	p.mu.Lock()
	p.sealed = append(p.sealed, sp)
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		select {
		case p.sem <- struct{}{}:
			defer func() { <-p.sem }()
		case <-ctx.Done():
			p.setFailure(ctx.Err())
			return
		}
		// Occupancy is measured from where the bytes actually start
		// moving, i.e. after the concurrency gate, not from the cut: a
		// pack queued behind three others is not on the wire.
		p.uploadBegan()
		defer p.uploadEnded()
		if err := upload(ctx, p.inner); err != nil {
			p.setFailure(err)
		}
	}()
	return nil
}

// setFailure records the first upload failure; later ones are noise from
// a publish that is already doomed.
func (p *packer) setFailure(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err == nil {
		p.err = err
	}
}

func (p *packer) failure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// sealedSoFar returns a copy of the packs sealed so far (the open pack, if
// any, is not included).
func (p *packer) sealedSoFar() []packstore.SealedPack {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]packstore.SealedPack(nil), p.sealed...)
}

// finish seals the open pack and returns every pack this publish uploaded.
// finish cuts the open pack and waits for every upload to land. The
// caller flips the ref only after this returns, so a published
// generation never names a pack that is still in flight.
func (p *packer) finish(ctx context.Context) ([]packstore.SealedPack, error) {
	if err := p.cut(ctx); err != nil {
		p.wg.Wait()
		return nil, err
	}
	p.wg.Wait()
	if err := p.failure(); err != nil {
		return nil, err
	}
	return p.sealedSoFar(), nil
}

// abort discards the open spool. Safe to call repeatedly and after finish.
func (p *packer) abort() {
	// Wait for in-flight uploads before discarding anything: they own
	// spool files and are reading them right now.
	p.wg.Wait()
	if p.w != nil {
		p.w.Abort()
		p.w = nil
	}
}
