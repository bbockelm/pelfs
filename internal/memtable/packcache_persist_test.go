package memtable

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// A pack is immutable and its name is unique, so a cached copy is valid
// for as long as the pack is. The cache used to empty itself at startup,
// which meant a recovered session — one that HAS the location map, from
// the journal — re-fetched from the federation packs that were sitting on
// its own disk. That is what made a second mount stall.
func TestThePackCacheSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	dir := t.TempDir()
	cacheDir := filepath.Join(t.TempDir(), "packs")

	open := func(j Journal) *Store {
		t.Helper()
		s, err := New(Options{
			Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
			Hasher: chunkid.NewHasher(nil), PackCacheDir: cacheDir, Journal: j,
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	j := newMemJournal()
	s := open(j)
	body := fill(150000, 111)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := j.durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A new session over the same volume, recovering the location map.
	s2, _, err := Recover(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil), PackCacheDir: cacheDir, Journal: j,
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	packs, bytes := s2.CacheAdopted()
	if packs == 0 {
		t.Fatal("the new session adopted no packs; the cache did not survive")
	}
	t.Logf("adopted %d packs (%d bytes) from the previous session", packs, bytes)

	// The read that follows must not touch the federation: the bytes are
	// on this machine and the map says where.
	before := obj.getCount()
	if got := readAll(t, s2, 1); !bytesEqual(got, body) {
		t.Fatal("recovered content does not read back byte-exact")
	}
	if got := obj.getCount(); got != before {
		t.Errorf("%d federation reads for content already on local disk", got-before)
	}
	if st := s2.Stats(); st.PackReadsRemote != 0 {
		t.Errorf("%d pack reads went to the federation", st.PackReadsRemote)
	}
}

func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }
