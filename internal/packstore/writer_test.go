package packstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"lukechampine.com/blake3"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

func TestPackWriterSealAndReadBack(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()

	w, err := NewPackWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewPackWriter: %v", err)
	}
	defer w.Abort()

	entries := map[string]struct {
		typ  string
		data []byte
	}{
		"aa11": {EntryData, blob("aa11", 300000)},
		"bb22": {EntryCatalog, blob("bb22", 120000)},
		"cc33": {EntryShard, blob("cc33", 5000)},
		"dd44": {EntrySuperblock, blob("dd44", 900)},
	}
	for k, e := range entries {
		if err := w.Add(k, e.typ, e.data); err != nil {
			t.Fatalf("Add %s: %v", k, err)
		}
	}
	if err := w.Add("aa11", EntryData, []byte("dup")); err == nil {
		t.Fatal("duplicate Add was accepted")
	}
	if w.Count() != len(entries) {
		t.Fatalf("Count = %d, want %d", w.Count(), len(entries))
	}

	sealed, err := w.Seal(ctx, inner)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// The uploaded object must match the reported size, and its trailer
	// must hash to TrailerHash.
	keys, sizes := listKeys(t, inner, PackDirKey+"/")
	if len(keys) != 1 {
		t.Fatalf("expected 1 pack object, got %v", keys)
	}
	if sizes[keys[0]] != sealed.Size {
		t.Fatalf("object size %d != sealed.Size %d", sizes[keys[0]], sealed.Size)
	}
	raw := readObj(t, inner, keys[0], 0, -1)
	if string(raw[len(raw)-8:]) != magicZ {
		t.Fatalf("bad magic at pack tail: %q", raw[len(raw)-8:])
	}
	idxLen := binary.LittleEndian.Uint64(raw[len(raw)-16 : len(raw)-8])
	stored := raw[uint64(len(raw))-16-idxLen : uint64(len(raw))-16]
	// TrailerHash covers the stored (compressed) bytes: verifiable straight
	// off the tail read, before any decoding.
	if blake3.Sum256(stored) != sealed.TrailerHash {
		t.Fatalf("trailer hash mismatch")
	}
	trailerJSON, err := trailerDec.DecodeAll(stored, nil)
	if err != nil {
		t.Fatalf("decompress trailer: %v", err)
	}

	// A reader holding only the pack list must locate every entry from the
	// trailer and read it back, whole and by range, with types preserved.
	located, err := FetchTrailerVerified(ctx, inner, sealed.Name, sealed.Size, sealed.TrailerHash)
	if err != nil {
		t.Fatalf("FetchTrailerVerified: %v", err)
	}
	if len(located) != len(entries) {
		t.Fatalf("trailer lists %d entries, want %d", len(located), len(entries))
	}
	packKey := PackDirKey + "/" + sealed.Name
	for _, pe := range located {
		e, ok := entries[pe.Key]
		if !ok {
			t.Fatalf("trailer names an entry nobody wrote: %s", pe.Key)
		}
		if pe.Type != e.typ {
			t.Fatalf("entry %s: type %q, want %q", pe.Key, pe.Type, e.typ)
		}
		if got := readObj(t, inner, packKey, pe.Off, pe.Length); !bytes.Equal(got, e.data) {
			t.Fatalf("entry %s: read %d bytes, want %d", pe.Key, len(got), len(e.data))
		}
		tail := readObj(t, inner, packKey, pe.Off+pe.Length-100, 100)
		if !bytes.Equal(tail, e.data[len(e.data)-100:]) {
			t.Fatalf("entry %s: tail range mismatch", pe.Key)
		}
	}
	if !bytes.Contains(trailerJSON, []byte(`"t":"catalog"`)) ||
		!bytes.Contains(trailerJSON, []byte(`"t":"sb"`)) {
		t.Fatalf("trailer lost entry types: %s", trailerJSON)
	}

	// Sealing an empty writer is refused.
	if w2, err := NewPackWriter(t.TempDir()); err != nil {
		t.Fatal(err)
	} else {
		defer w2.Abort()
		if _, err := w2.Seal(ctx, inner); err == nil {
			t.Fatal("empty Seal was accepted")
		}
	}
}

// Packs sealed before the zstd trailer (footer magic PELFSPK1, plain JSON
// index) must stay readable forever.
func TestLegacyJSONTrailerStillReadable(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()

	payload := blob("legacy", 4096)
	tr := trailer{Version: 1, Created: 12345}
	tr.Entries = append(tr.Entries, PackEntry{Key: "chunks/0/0/7_0_4096", Off: 0, Length: int64(len(payload))})
	idx, err := json.Marshal(&tr)
	if err != nil {
		t.Fatal(err)
	}
	footer := make([]byte, footerSize)
	binary.LittleEndian.PutUint64(footer[:8], uint64(len(idx)))
	copy(footer[8:], magic)
	pack := append(append(append([]byte{}, payload...), idx...), footer...)
	if err := inner.Put(ctx, PackDirKey+"/p-000000000000-legacy", bytes.NewReader(pack)); err != nil {
		t.Fatalf("upload legacy pack: %v", err)
	}

	located, err := FetchTrailer(ctx, inner, "p-000000000000-legacy", int64(len(pack)))
	if err != nil {
		t.Fatalf("FetchTrailer over a plain-JSON trailer: %v", err)
	}
	if len(located) != 1 || located[0].Key != "chunks/0/0/7_0_4096" {
		t.Fatalf("legacy trailer decoded as %+v", located)
	}
	got := readObj(t, inner, PackDirKey+"/p-000000000000-legacy", located[0].Off, located[0].Length)
	if !bytes.Equal(got, payload) {
		t.Fatalf("legacy pack entry mismatch: %d bytes", len(got))
	}
}

// flakyStore fails the first N calls of Put/Get/ListDir with a transient
// error, then behaves.
type flakyStore struct {
	pelicanobj.Store
	failures int
}

func (f *flakyStore) trip() error {
	if f.failures > 0 {
		f.failures--
		return fmt.Errorf("transient: connection reset by peer")
	}
	return nil
}

func (f *flakyStore) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
	if err := f.trip(); err != nil {
		// Consume part of the body to prove retries rewind correctly.
		_, _ = io.CopyN(io.Discard, in, 10)
		return err
	}
	return f.Store.Put(ctx, key, in, getters...)
}

func (f *flakyStore) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	if err := f.trip(); err != nil {
		return nil, err
	}
	return f.Store.Get(ctx, key, off, limit, getters...)
}

func (f *flakyStore) ListDir(ctx context.Context, dir string) ([]pelicanobj.DirEntry, error) {
	if err := f.trip(); err != nil {
		return nil, err
	}
	return f.Store.ListDir(ctx, dir)
}

// Transient federation failures must be retried with rewind: a seal whose
// first Put died mid-stream still uploads the complete pack, and
// bootstrap survives flaky listings and trailer reads.
func TestRetryOnTransientFailures(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	flaky := &flakyStore{Store: inner, failures: 2}

	w, err := NewPackWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	payload := blob("retry", 100000)
	if err := w.Add("retry-key", EntryData, payload); err != nil {
		t.Fatal(err)
	}
	sealed, err := w.Seal(ctx, flaky)
	if err != nil {
		t.Fatalf("Seal through flaky store: %v", err)
	}
	_, sizes := listKeys(t, inner, PackDirKey+"/")
	if sizes[PackDirKey+"/"+sealed.Name] != sealed.Size {
		t.Fatalf("uploaded pack size %d, want %d (mid-stream retry corrupted the upload?)",
			sizes[PackDirKey+"/"+sealed.Name], sealed.Size)
	}

	// Reading the trailer back through a flaky transport must retry rather
	// than fail the mount.
	flaky.failures = 2
	located, err := FetchTrailerVerified(ctx, flaky, sealed.Name, sealed.Size, sealed.TrailerHash)
	if err != nil {
		t.Fatalf("FetchTrailerVerified through a flaky store: %v", err)
	}
	if len(located) != 1 || located[0].Key != "retry-key" {
		t.Fatalf("trailer decoded as %+v", located)
	}
	got := readObj(t, inner, PackDirKey+"/"+sealed.Name, located[0].Off, located[0].Length)
	if !bytes.Equal(got, payload) {
		t.Fatalf("read through the retried trailer mismatched (%d bytes)", len(got))
	}
}
