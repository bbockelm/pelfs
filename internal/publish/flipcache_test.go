package publish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/overlay"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/publish"
)

// cachingStore is a federation with a cache in front of it: a read of a
// key it has seen before is answered from the copy it kept, and the copy
// is never invalidated. That is not a caricature — refs are the one
// MUTABLE object in the format, so any cache holding one is stale from
// the next flip onward, and Pelican caches hold objects for minutes.
//
// DirectVariant hands back the uncached transport, which is what every
// reader of a mutable object is supposed to ask for.
type cachingStore struct {
	pelicanobj.Store
	mu     sync.Mutex
	cached map[string][]byte // first version written, served forever
	direct int               // reads that went past the cache
}

var _ pelicanobj.DirectReader = (*cachingStore)(nil)

func newCachingStore(inner pelicanobj.Store) *cachingStore {
	return &cachingStore{Store: inner, cached: map[string][]byte{}}
}

// DirectVariant is the uncached transport, counting what asks for it.
func (c *cachingStore) DirectVariant() pelicanobj.Store { return directView{Store: c.Store, owner: c} }

type directView struct {
	pelicanobj.Store
	owner *cachingStore
}

func (d directView) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if strings.HasPrefix(key, publish.RefPrefix) {
		d.owner.mu.Lock()
		d.owner.direct++
		d.owner.mu.Unlock()
	}
	return d.Store.Get(ctx, key, off, limit)
}

// Put fills the cache with the FIRST version of a key and never refreshes
// it, which is the whole of what a cache does wrong to a mutable object.
func (c *cachingStore) Put(ctx context.Context, key string, in io.Reader) error {
	if !strings.HasPrefix(key, publish.RefPrefix) {
		return c.Store.Put(ctx, key, in)
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	if err := c.Store.Put(ctx, key, bytes.NewReader(raw)); err != nil {
		return err
	}
	c.mu.Lock()
	if _, seen := c.cached[key]; !seen {
		c.cached[key] = raw
	}
	c.mu.Unlock()
	return nil
}

func (c *cachingStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	if !strings.HasPrefix(key, publish.RefPrefix) || off != 0 || limit >= 0 {
		return c.Store.Get(ctx, key, off, limit)
	}
	c.mu.Lock()
	hit, ok := c.cached[key]
	c.mu.Unlock()
	if ok {
		return io.NopCloser(bytes.NewReader(hit)), nil
	}
	return c.Store.Get(ctx, key, off, limit)
}

// A session that checkpoints publishes generation after generation onto
// the same branch, and each flip compares the current ref against the
// generation it grew from. Read that ref through a cache and the compare
// runs against the flip BEFORE last — so the seal aborts, having already
// done and uploaded all of its work, blaming a concurrent writer that
// does not exist. The fix is that the compare reads past caches; this
// pins it, because nothing else in a test federation would notice.
func TestFlipReadsTheRefPastCaches(t *testing.T) {
	ctx := context.Background()
	inner := newCachingStore(newInner(t))
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	head, err := publish.InitVolume(ctx, publish.Options{
		Inner: inner, SpoolDir: t.TempDir(), SigningKey: priv,
		VolumeID: [16]byte{0xca, 0xc4, 0xed},
	})
	if err != nil {
		t.Fatalf("InitVolume: %v", err)
	}

	// Three seals in a row against the same branch, each growing from the
	// one before it — the checkpoint pattern. The first flip populates the
	// cache; the second is where a cached read would answer with
	// generation 0 and the CAS would refuse.
	base := openGenfs(t, inner, head.Superblock, nil)
	ov, err := overlay.Open(t.TempDir(), base, overlay.Options{
		NextInode:      base.NextInode(),
		BaseRoot:       base.RootCatalog(),
		BaseGeneration: base.Generation(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ov.Close() //nolint:errcheck

	for i, name := range []string{"one.txt", "two.txt", "three.txt"} {
		fn, err := ov.Create(ctx, genfs.RootInode, name, 0644, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ov.Write(ctx, fn.Inode, 0, []byte(name)); err != nil {
			t.Fatal(err)
		}
		res, err := publish.Seal(ctx, publish.Options{
			Overlay: ov, Inner: inner, SpoolDir: t.TempDir(),
			SigningKey: priv, Prev: head.Superblock, PrevRaw: head.Raw,
		})
		if err != nil {
			t.Fatalf("checkpoint %d: %v", i+1, err)
		}
		head = res
	}
	if head.Superblock.Generation != 3 {
		t.Fatalf("three checkpoints produced generation %d", head.Superblock.Generation)
	}
	// Both halves of the setup have to have been live, or the run proves
	// nothing: the cache must have held a stale copy to serve, and the
	// flip must have gone around it.
	if len(inner.cached) == 0 {
		t.Error("the cache never held a ref; a cached read could not have gone wrong")
	}
	if inner.direct == 0 {
		t.Error("no ref was read through the direct variant; the compare ran against whatever the cache had")
	}
}
