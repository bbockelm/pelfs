package publish

import (
	"context"
	"sync"

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
	inner  pelicanobj.Store
	dir    string
	target int64

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
}

func newPacker(inner pelicanobj.Store, dir string, target int64, conc int) *packer {
	if conc <= 0 {
		conc = DefaultUploadConcurrency
	}
	return &packer{
		inner: inner, dir: dir, target: target,
		added: make(map[string]struct{}),
		sem:   make(chan struct{}, conc),
	}
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
