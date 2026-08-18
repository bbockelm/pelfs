package memtable

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// memJournal is a journal in memory: enough to prove that what is
// recorded is enough to rebuild from, without pulling SQLite into a
// package that has no other use for it.
type memJournal struct {
	// The store calls a journal under its own lock, so an implementation
	// never sees concurrent calls — but a TEST reading what was recorded
	// is a third goroutine, and that needs its own guard.
	mu       sync.Mutex
	entries  []JournalEntry
	handles  map[Handle][]ChunkSlice
	chunks   map[string]PackLoc
	packs    []packstore.SealedPack
	appended int
	located  int
}

func newMemJournal() *memJournal {
	return &memJournal{handles: map[Handle][]ChunkSlice{}, chunks: map[string]PackLoc{}}
}

func (j *memJournal) Append(e JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, e)
	j.appended++
	return nil
}

func (j *memJournal) Located(l Location) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.located++
	for h, sl := range l.Handles {
		j.handles[h] = append([]ChunkSlice(nil), sl...)
	}
	for k, v := range l.Chunks {
		j.chunks[k] = v
	}
	j.packs = append(j.packs, l.Packs...)
	return nil
}

// durable is what a crash would have left behind.
func (j *memJournal) durable() Durable {
	j.mu.Lock()
	defer j.mu.Unlock()
	rows, adopted := ReplayJournal(j.entries)
	return Durable{Rows: rows, Handles: j.handles, Chunks: j.chunks, Packs: j.packs, Adopted: adopted}
}

func newJournaledStore(t *testing.T, dir string, obj *countingStore, base Base, j Journal) *Store {
	t.Helper()
	s, err := New(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Base: base, Journal: j,
		Chunk: smallChunks, Hasher: chunkid.NewHasher(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The journal records operations rather than state, so the test that
// matters is that REPLAYING them rebuilds the same file — including the
// shapes that are not a simple append: a write landing inside an earlier
// one, a truncate, and a file created and then removed.
func TestJournalReplayRebuildsTheSession(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	j := newMemJournal()
	s := newJournaledStore(t, dir, obj, nil, j)

	want := fill(200000, 61)
	if err := s.Write(ctx, 1, 0, want); err != nil {
		t.Fatal(err)
	}
	patch := fill(300, 62)
	if err := s.Write(ctx, 1, 5000, patch); err != nil {
		t.Fatal(err)
	}
	copy(want[5000:], patch)

	// A second file, truncated back.
	other := fill(40000, 63)
	if err := s.Write(ctx, 2, 0, other); err != nil {
		t.Fatal(err)
	}
	if err := s.Truncate(2, 12000); err != nil {
		t.Fatal(err)
	}

	// A third, removed outright: nothing of it may come back.
	if err := s.Write(ctx, 3, 0, fill(5000, 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(3); err != nil {
		t.Fatal(err)
	}

	// Flush so half the content is in packs and half is still in the ring
	// — the split a crash actually finds.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tail := fill(9000, 65)
	if err := s.Write(ctx, 1, int64(len(want)), tail); err != nil {
		t.Fatal(err)
	}
	want = append(want, tail...)

	d := j.durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, rep, err := Recover(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks, Hasher: chunkid.NewHasher(nil),
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	if rep.Loss() {
		t.Fatalf("a clean reopen reported loss:\n%s", rep)
	}
	if got := readAll(t, s2, 1); !bytes.Equal(got, want) {
		t.Fatal("the patched-and-appended file does not read back after replay")
	}
	if got := readAll(t, s2, 2); !bytes.Equal(got, other[:12000]) {
		t.Fatal("the truncated file does not read back after replay")
	}
	if got := readAll(t, s2, 3); len(got) != 0 {
		t.Fatalf("a removed file came back with %d bytes", len(got))
	}
	j.mu.Lock()
	t.Logf("%d journal entries and %d location records rebuilt %d bytes",
		j.appended, j.located, len(want)+12000)
	j.mu.Unlock()
}

// An adopted file is recorded as a reference, and recovery asks the base
// for the records again rather than keeping a second copy that could
// disagree with it.
func TestJournalReplayReadoptsFromTheBase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	base := newFakeBase()
	body := fill(120000, 66)
	base.put(8, body)
	j := newMemJournal()
	s := newJournaledStore(t, dir, obj, base, j)

	if err := s.Adopt(ctx, 8, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	patch := fill(400, 67)
	if err := s.Write(ctx, 8, 30000, patch); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), body...)
	copy(want[30000:], patch)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	d := j.durable()
	if len(d.Adopted) != 1 {
		t.Fatalf("%d adopted handles recorded, want 1", len(d.Adopted))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, rep, err := Recover(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Base: base, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil),
	}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	if rep.Loss() {
		t.Fatalf("reopen reported loss:\n%s", rep)
	}
	if got := readAll(t, s2, 8); !bytes.Equal(got, want) {
		t.Fatal("an adopted-and-patched file does not read back after replay")
	}
	// And it still seals: the base's rows for the untouched ranges, a
	// re-chunk for the span the patch straddled.
	sl := s2.NewSealer()
	refs, err := sl.Inode(ctx, 8)
	if err != nil {
		t.Fatalf("seal after recovery: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
	var at int64
	for _, r := range refs {
		at += r.LLen
	}
	if at != int64(len(want)) {
		t.Fatalf("recovered rows cover %d bytes, want %d", at, len(want))
	}
}

// One row per write, not one per extent the file has accumulated. The
// difference is quadratic, and it is the reason the journal records
// operations rather than state.
func TestJournalCostsOneEntryPerOperation(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	j := newMemJournal()
	s := newJournaledStore(t, t.TempDir(), obj, nil, j)
	defer s.Close() //nolint:errcheck

	const writes = 200
	body := fill(4000, 68)
	for i := 0; i < writes; i++ {
		if err := s.Write(ctx, 1, int64(i*len(body)), body); err != nil {
			t.Fatal(err)
		}
	}
	j.mu.Lock()
	appended := j.appended
	j.mu.Unlock()
	if appended != writes {
		t.Errorf("%d journal entries for %d writes; the record must follow the operation, not the map", appended, writes)
	}
}
