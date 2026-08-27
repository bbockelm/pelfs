package memtable

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/catalog"
	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// memJournal is a journal in memory: enough to prove that what is
// recorded is enough to rebuild from, without pulling SQLite into a
// package that has no other use for it.
type memJournal struct {
	// Append and Adopted arrive under the store's lock, but Located does
	// not and can overlap with itself (see the Journal interface), and a
	// TEST reading what was recorded is a third goroutine again. All
	// three reasons want the same guard.
	mu       sync.Mutex
	entries  []JournalEntry
	handles  map[Handle][]ChunkSlice
	chunks   map[string]PackLoc
	packs    []packstore.SealedPack
	adopted  map[Handle]AdoptedExtent
	appended int
	located  int
	// forgetAdoptions drops the adoption records on the way back out, which
	// is what a journal written by a build that recorded none looks like.
	forgetAdoptions bool
}

func newMemJournal() *memJournal {
	return &memJournal{
		handles: map[Handle][]ChunkSlice{},
		chunks:  map[string]PackLoc{},
		adopted: map[Handle]AdoptedExtent{},
	}
}

func (j *memJournal) Adopted(h Handle, a AdoptedExtent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	a.Refs = append([]catalog.ChunkRef(nil), a.Refs...)
	j.adopted[h] = a
	return nil
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
	refs := j.adopted
	if j.forgetAdoptions {
		refs = nil
	}
	return Durable{Rows: rows, Handles: j.handles, Chunks: j.chunks, Packs: j.packs,
		Adopted: adopted, AdoptedRefs: refs}
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

// staleBase is a base generation that answers reads but refuses to be
// asked what an inode's content records are — which is what EVERY freshly
// opened generation does for an inode nobody has looked up yet
// (genfs.ErrStale, residency is established by descent). A recovery that
// needs this answer is a recovery that cannot happen on a remount.
type staleBase struct{ *fakeBase }

func (b staleBase) ContentOf(context.Context, uint64) (genfs.Content, error) {
	return genfs.Content{}, genfs.ErrStale
}

// An adopted file is recorded as a reference, and the RECORDS COME FROM THE
// JOURNAL. They used to be re-derived by asking the base again, which is
// the one question a mount that has just started cannot ask: this test's
// base refuses it, exactly as a real one does before any descent, and
// recovery must still rebuild the file.
func TestJournalReplayReadoptsFromWhatWasRecorded(t *testing.T) {
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
		Dir: dir, TableSize: 1 << 20, Obj: obj, Base: staleBase{base}, Chunk: smallChunks,
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

// The residue a checkpoint leaves. Publishing an adopted file and rebasing
// the inode clean FORGETS its content, so the journal keeps an adopted
// handle that no surviving content row names — and recovery used to resolve
// it against the base before discovering that, then delete it unused three
// lines later. On a remount that question has no answer, so the mount
// refused to start over a handle it did not need.
//
// Nothing here may ask the base anything: the base refuses, and recovery
// must not care.
func TestRecoveryDropsAnAdoptionNothingNames(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	base := newFakeBase()
	base.put(9, fill(80000, 81))
	j := newMemJournal()
	s := newJournaledStore(t, dir, obj, base, j)

	if err := s.Adopt(ctx, 9, 80000); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, 9, 101, fill(999, 82)); err != nil {
		t.Fatal(err)
	}
	// The checkpoint: the file is published, and the rebase that follows it
	// drops the overlay's rows and forgets the content.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(9); err != nil {
		t.Fatal(err)
	}
	d := j.durable()
	if len(d.Adopted) != 1 {
		t.Fatalf("%d adopted handles in the log, want 1: the shape under test did not happen", len(d.Adopted))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, rep, err := Recover(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Base: staleBase{base}, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil),
	}, d)
	if err != nil {
		t.Fatalf("recovery refused a state directory whose only adoption is dead: %v", err)
	}
	defer s2.Close() //nolint:errcheck
	if rep.Loss() {
		t.Errorf("dropping an adoption nothing names is not loss, and was reported as some:\n%s", rep)
	}
	if got := s2.Stats().DroppedAdoptions; got != 1 {
		t.Errorf("DroppedAdoptions = %d, want 1", got)
	}
	if got := s2.Size(9); got != 0 {
		t.Errorf("a forgotten inode came back with %d bytes", got)
	}
	// And the handle number is not handed out again: a reused handle would
	// resolve through whatever the last life of that number left behind.
	if err := s2.Write(ctx, 10, 0, fill(100, 83)); err != nil {
		t.Fatal(err)
	}
	for _, r := range s2.Durable().Rows {
		for _, ref := range r.Refs {
			if _, reused := d.Adopted[ref.Handle]; reused {
				t.Errorf("inode %d was given handle %d, which an adoption already used", r.Inode, ref.Handle)
			}
		}
	}
}

// The one case recovery still refuses, and the shape of the refusal.
//
// A journal written before adoptions were recorded (AdoptedExtent) holds
// handles whose records exist nowhere but in the generation they were taken
// from, which a started mount cannot ask. There is no honest way to serve
// that file: the bytes are published and immutable, so dropping the extent
// would put zeros over live data and the next seal would publish them. So
// recovery refuses — but ONCE, naming every unresolvable inode, because a
// refusal a user has to hit five times to enumerate is a worse refusal.
func TestRecoveryRefusesUnresolvableAdoptionsAllAtOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	base := newFakeBase()
	base.put(11, fill(60000, 84))
	base.put(12, fill(70000, 85))
	j := newMemJournal()
	s := newJournaledStore(t, dir, obj, base, j)

	for _, ino := range []uint64{11, 12} {
		if err := s.Adopt(ctx, ino, 60000); err != nil {
			t.Fatal(err)
		}
		if err := s.Write(ctx, ino, 101, fill(999, 86)); err != nil {
			t.Fatal(err)
		}
	}
	j.mu.Lock()
	j.forgetAdoptions = true
	j.mu.Unlock()
	d := j.durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err := Recover(Options{
		Dir: dir, TableSize: 1 << 20, Obj: obj, Base: staleBase{base}, Chunk: smallChunks,
		Hasher: chunkid.NewHasher(nil),
	}, d)
	var unresolved *UnresolvedAdoptionsError
	if !errors.As(err, &unresolved) {
		t.Fatalf("recovery returned %v, want an UnresolvedAdoptionsError", err)
	}
	if len(unresolved.Adoptions) != 2 {
		t.Fatalf("the refusal names %d adoption(s), want both", len(unresolved.Adoptions))
	}
	for _, a := range unresolved.Adoptions {
		if a.Inode != 11 && a.Inode != 12 {
			t.Errorf("the refusal names inode %d, which was never adopted", a.Inode)
		}
		if a.Bytes == 0 {
			t.Errorf("inode %d is named with no byte count; the user cannot size the loss", a.Inode)
		}
		if !errors.Is(a.Err, genfs.ErrStale) {
			t.Errorf("inode %d: the reason recorded is %v, not the base's own answer", a.Inode, a.Err)
		}
	}
	if !strings.Contains(unresolved.Error(), "inode 11") || !strings.Contains(unresolved.Error(), "inode 12") {
		t.Errorf("the sentence a user reads does not name both inodes:\n%s", unresolved)
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
