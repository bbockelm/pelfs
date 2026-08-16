package packstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"

	"lukechampine.com/blake3"
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
