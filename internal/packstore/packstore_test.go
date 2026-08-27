package packstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
	ch, err := s.ListAll(context.Background(), prefix, "")
	if err != nil {
		t.Fatalf("ListAll(%q): %v", prefix, err)
	}
	var keys []string
	sizes := make(map[string]int64)
	for o := range ch {
		if o == nil {
			t.Fatalf("ListAll(%q) emitted the failure sentinel", prefix)
		}
		keys = append(keys, o.Key)
		sizes[o.Key] = o.Size
	}
	return keys, sizes
}

// rangeLiar wraps a store and ignores Get ranges, always returning the
// whole object from offset zero — modeling a federation transport that
// mishandles Range requests (the observed "bad pack magic" failure).
type rangeLiar struct {
	pelicanobj.Store
}

func (r rangeLiar) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
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

// The stored-trailer length in a pack footer is eight bytes a hostile or
// corrupt origin picks, and it reaches a slice bound. A 16-byte "pack"
// whose footer claimed 0x7fffffffffffffff bytes of trailer used to panic
// parseTail with slice bounds [-9223372036854775807:] — the sum
// idxLen+footerSize wrapped negative and passed the bound check. The
// crasher is checked in as
// testdata/fuzz/FuzzParseTail/7a3b9f86271a383e; this pins the whole
// class, both entry points, and the error text that internal/retention
// and internal/rescue classify a doomed pack by.
func TestATailLengthCannotEscapeTheObject(t *testing.T) {
	claims := map[string]uint64{
		"max int64":         1<<63 - 1,
		"max uint64":        ^uint64(0),
		"absurd positive":   1 << 60,
		"negative as int64": 1 << 63,
		"one past the end":  1,
		"zero":              0,
	}
	for name, idxLen := range claims {
		t.Run(name, func(t *testing.T) {
			// The whole object is the footer, so a trailer of ANY positive
			// length is outside it.
			pack := make([]byte, footerSize)
			binary.LittleEndian.PutUint64(pack[:8], idxLen)
			copy(pack[8:], magic)

			// nil store: a length this far out must be refused before any
			// range read is attempted, so nothing here can dial out.
			_, _, _, err := parseTail(context.Background(), nil, "p-0-test", int64(len(pack)), pack)
			if err == nil {
				t.Fatalf("parseTail accepted an index length of %d in a %d-byte pack", idxLen, len(pack))
			}
			if !strings.Contains(err.Error(), "bad index length") {
				t.Errorf("parseTail said %q, which retention and rescue will not recognize as a doomed pack", err)
			}
			if _, err := StoredTrailerFrom(bytes.NewReader(pack), int64(len(pack))); err == nil {
				t.Fatalf("StoredTrailerFrom accepted an index length of %d in a %d-byte pack", idxLen, len(pack))
			}
		})
	}
}

// A pack smaller than its own footer, and a size that disagrees with the
// bytes in hand, are the other two ways the footer arithmetic can be fed
// a number it cannot subtract from.
func TestAPackTooSmallForItsFooterIsRefused(t *testing.T) {
	pack := make([]byte, footerSize)
	binary.LittleEndian.PutUint64(pack[:8], 1)
	copy(pack[8:], magic)
	for _, size := range []int64{0, footerSize - 1, -1, -1 << 62} {
		if _, _, _, err := parseTail(context.Background(), nil, "p-0-test", size, pack); err == nil {
			t.Errorf("parseTail accepted a listed size of %d", size)
		}
		if _, err := StoredTrailerFrom(bytes.NewReader(pack), size); err == nil {
			t.Errorf("StoredTrailerFrom accepted a listed size of %d", size)
		}
	}
}
