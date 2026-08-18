package refs

import (
	"crypto/ed25519"
	"testing"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// cachedStore is a store that has NOT been switched to direct reads. Its
// DirectVariant returns a distinct store that records the switch.
type cachedStore struct {
	pelicanobj.Store
	direct bool
}

func (s *cachedStore) DirectVariant() pelicanobj.Store {
	return &cachedStore{Store: s.Store, direct: true}
}

// TestNewForcesDirectReads pins the invariant that the mutable superblock
// is never read through a federation cache. Handing New a cache-served
// store is the easy mistake, and against a real federation it surfaces as
// an md5 mismatch on refs/main -- nothing that points at caching, which
// is why New enforces the switch rather than trusting its callers.
func TestNewForcesDirectReads(t *testing.T) {
	cached := &cachedStore{}
	s, err := New(cached, t.TempDir(), ed25519.PublicKey(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, ok := s.inner.(*cachedStore)
	if !ok {
		t.Fatalf("inner store type changed unexpectedly: %T", s.inner)
	}
	if !got.direct {
		t.Fatal("refs.New kept the cache-served store; mutable refs must be read with ?directread")
	}
	if got == cached {
		t.Fatal("refs.New used the original store rather than its direct variant")
	}
}
