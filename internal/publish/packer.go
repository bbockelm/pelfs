package publish

import (
	"context"

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
}

func newPacker(inner pelicanobj.Store, dir string, target int64) *packer {
	return &packer{inner: inner, dir: dir, target: target, added: make(map[string]struct{})}
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

// cut seals the open pack (if any) and uploads it. On error the writer is
// kept for abort.
func (p *packer) cut(ctx context.Context) error {
	if p.w == nil {
		return nil
	}
	sp, err := p.w.Seal(ctx, p.inner)
	if err != nil {
		return err
	}
	p.w = nil
	p.sealed = append(p.sealed, sp)
	return nil
}

// sealedSoFar returns a copy of the packs sealed so far (the open pack, if
// any, is not included).
func (p *packer) sealedSoFar() []packstore.SealedPack {
	return append([]packstore.SealedPack(nil), p.sealed...)
}

// finish seals the open pack and returns every pack this publish uploaded.
func (p *packer) finish(ctx context.Context) ([]packstore.SealedPack, error) {
	if err := p.cut(ctx); err != nil {
		return nil, err
	}
	return p.sealedSoFar(), nil
}

// abort discards the open spool. Safe to call repeatedly and after finish.
func (p *packer) abort() {
	if p.w != nil {
		p.w.Abort()
		p.w = nil
	}
}
