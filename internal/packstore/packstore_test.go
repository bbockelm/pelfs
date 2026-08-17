package packstore

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/fakeorigin"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// newInner starts a fakeorigin-backed pelicanobj store rooted at /vol and
// returns it along with the on-disk directory backing that prefix, so tests
// can inspect exactly which objects landed on "the federation".
func newInner(t *testing.T) (pelicanobj.Store, string) {
	t.Helper()
	root := t.TempDir()
	srv := httptest.NewServer(fakeorigin.Handler(root))
	t.Cleanup(srv.Close)
	inner, err := pelicanobj.New(context.Background(), pelicanobj.Config{PrefixURL: srv.URL + "/vol"})
	if err != nil {
		t.Fatalf("pelicanobj.New: %v", err)
	}
	return inner, filepath.Join(root, "vol")
}

// blob generates deterministic per-key content of length n.
func blob(key string, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = key[i%len(key)] ^ byte(i%251)
	}
	return b
}

func readObj(t *testing.T, s pelicanobj.Store, key string, off, limit int64) []byte {
	t.Helper()
	rc, err := s.Get(context.Background(), key, off, limit)
	if err != nil {
		t.Fatalf("Get %s (off=%d limit=%d): %v", key, off, limit, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return data
}

// listKeys drains ListAll and returns the keys in emission order plus a
// key -> size map.
func listKeys(t *testing.T, s pelicanobj.Store, prefix string) ([]string, map[string]int64) {
	t.Helper()
	ch, err := s.ListAll(context.Background(), prefix, "", false)
	if err != nil {
		t.Fatalf("ListAll(%q): %v", prefix, err)
	}
	var keys []string
	sizes := make(map[string]int64)
	for o := range ch {
		if o == nil {
			t.Fatalf("ListAll(%q) emitted the failure sentinel", prefix)
		}
		keys = append(keys, o.Key())
		sizes[o.Key()] = o.Size()
	}
	return keys, sizes
}

// rangeLiar wraps a store and ignores Get ranges, always returning the
// whole object from offset zero — modeling a federation transport that
// mishandles Range requests (the observed "bad pack magic" failure).
type rangeLiar struct {
	pelicanobj.Store
}

func (r rangeLiar) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	return r.Store.Get(ctx, key, 0, -1)
}

// TestFetchTrailerSurvivesRangeLiar: when the tail range probe returns
// wrong bytes, the trailer fetch must fall back to a whole-object read,
// warn, and still produce the correct index rather than failing the mount.
func TestFetchTrailerSurvivesRangeLiar(t *testing.T) {
	ctx := context.Background()
	inner, _ := newInner(t)

	w, err := NewPackWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewPackWriter: %v", err)
	}
	defer w.Abort()
	want := make(map[string][]byte)
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("%04x", i+1)
		want[key] = blob(key, 128)
		if err := w.Add(key, EntryData, want[key]); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	sealed, err := w.Seal(ctx, inner)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	entries, err := FetchTrailerVerified(ctx, rangeLiar{Store: inner}, sealed.Name, sealed.Size, sealed.TrailerHash)
	if err != nil {
		t.Fatalf("trailer fetch over a range-lying transport failed: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("trailer lists %d entries, want %d", len(entries), len(want))
	}
	for _, e := range entries {
		data := readObj(t, inner, PackDirKey+"/"+sealed.Name, e.Off, e.Length)
		if string(data) != string(want[e.Key]) {
			t.Fatalf("entry %s read back wrong", e.Key)
		}
	}
}
