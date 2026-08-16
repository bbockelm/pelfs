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

	// A read-side Store bootstrapping from the same prefix must serve
	// every entry, whole and by range, with types preserved in the trailer.
	// (The phase-1 middleware only intercepts packable keys, so a store
	// reading v2 identity keys declares everything packable.)
	rs := newPack(t, inner, Config{Packable: func(string) bool { return true }})
	for k, e := range entries {
		got := readObj(t, rs, k, 0, -1)
		if !bytes.Equal(got, e.data) {
			t.Fatalf("entry %s: read %d bytes, want %d", k, len(got), len(e.data))
		}
		tail := readObj(t, rs, k, int64(len(e.data))-100, 100)
		if !bytes.Equal(tail, e.data[len(e.data)-100:]) {
			t.Fatalf("entry %s: tail range mismatch", k)
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

	s := newPack(t, inner, Config{})
	got := readObj(t, s, "chunks/0/0/7_0_4096", 0, -1)
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

	// Bootstrap through a flaky store: ListDir fails twice, trailer read
	// fails twice more; the store must still come up with the entry.
	flaky.failures = 4
	rs := newPack(t, flaky, Config{Packable: func(string) bool { return true }})
	got := readObj(t, rs, "retry-key", 0, -1)
	if !bytes.Equal(got, payload) {
		t.Fatalf("read through retried bootstrap mismatched (%d bytes)", len(got))
	}
}

// A pack whose entries all died before the seal must not be uploaded:
// there is nothing to store, and an empty pack costs a round trip, an
// object, and a pack-list entry to say so. Its tombstones must still
// survive, riding the next pack that has content.
func TestFullyDeadPackIsNotUploaded(t *testing.T) {
	inner, _ := newInner(t)
	ctx := context.Background()
	s := newPack(t, inner, Config{WriteEnabled: true, TargetSize: 1 << 30})

	key := "chunks/0/0/1_0_4096"
	if err := s.Put(ctx, key, bytes.NewReader(blob(key, 4096))); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	packs, _ := listKeys(t, inner, PackDirKey+"/")
	if len(packs) != 0 {
		t.Fatalf("uploaded %v for a pack with no live entries", packs)
	}

	// The tombstone must not be lost: a later pack carries it, so a fresh
	// reader does not resurrect the deleted key.
	live := "chunks/0/0/2_0_4096"
	if err := s.Put(ctx, live, bytes.NewReader(blob(live, 4096))); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	packs, _ = listKeys(t, inner, PackDirKey+"/")
	if len(packs) != 1 {
		t.Fatalf("expected exactly one pack after a live write, got %v", packs)
	}
	rs := newPack(t, inner, Config{})
	if _, err := rs.Get(ctx, key, 0, -1); err == nil {
		t.Fatal("the deleted key resurfaced after a bootstrap: its tombstone was lost")
	}
	if got := readObj(t, rs, live, 0, -1); len(got) != 4096 {
		t.Fatalf("live key read back %d bytes", len(got))
	}
}
