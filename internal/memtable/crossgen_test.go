package memtable

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/genfs"
)

// CROSS-GENERATION DEDUP, at the unit the decision is made in.
//
// The end-to-end claim (a byte-identical file in a later generation costs
// nothing) is asserted in internal/publish, against a real volume. What is
// here is the part that cannot be seen from there: how many times the base
// generation was ASKED, what happens when its answer cannot be reconciled
// with the bytes in hand, and what happens when its answer stops being
// true half way through a session.

// placerBase is a base generation that answers where a chunk is stored out
// of a table the test built, and counts the questions.
//
// The placements it hands out are real: they name packs an earlier Store
// in the same test actually uploaded to the same object store, so a chunk
// borrowed from it can be READ, which is the difference between testing
// the decision and testing a stub.
type placerBase struct {
	mu    sync.Mutex
	at    map[chunkid.Identity]genfs.Placement
	gen   uint64
	asked int
	// gone makes every answer a miss without changing the table, which is
	// what a repack looks like from here.
	gone bool
}

func (f *placerBase) ContentOf(context.Context, uint64) (genfs.Content, error) {
	return genfs.Content{}, ErrNoBase
}

func (f *placerBase) Read(context.Context, uint64, int64, []byte) (int, error) {
	return 0, ErrNoBase
}

func (f *placerBase) Placed(_ context.Context, id chunkid.Identity) (genfs.Placement, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked++
	if f.gone {
		return genfs.Placement{}, false
	}
	pl, ok := f.at[id]
	return pl, ok
}

func (f *placerBase) Generation() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gen
}

func (f *placerBase) questions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked
}

// storeOn builds a Store over one object store, so two of them in the
// same test share the packs one of them wrote.
func storeOn(t *testing.T, obj *countingStore, base Base, chunks chunkid.Options) *Store {
	t.Helper()
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 4 << 20, Obj: obj, Base: base, Chunk: chunks,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// publishedBy runs one session that writes body and returns where its
// chunks ended up, in the shape a base generation would report them —
// which is exactly what makes the next session's borrowing real.
func publishedBy(t *testing.T, obj *countingStore, body []byte, chunks chunkid.Options) map[chunkid.Identity]genfs.Placement {
	t.Helper()
	ctx := context.Background()
	s := storeOn(t, obj, nil, chunks)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	out := map[chunkid.Identity]genfs.Placement{}
	s.mu.Lock()
	for k, loc := range s.chunkLoc {
		id, err := chunkid.ParseIdentity(k)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = genfs.Placement{Pack: loc.Pack, Off: loc.Off, Length: loc.Stored}
	}
	s.mu.Unlock()
	if len(out) == 0 {
		t.Fatal("the first session placed no chunks")
	}
	return out
}

// The threshold is a cost control, so what it has to buy is not fewer
// dedups but fewer QUESTIONS: at the shipped 64 KiB nothing a test-sized
// chunker cuts is worth an index window, and the base is not asked at all.
func TestChunksBelowTheLookupThresholdAreNeverLookedUp(t *testing.T) {
	ctx := context.Background()
	body := fill(200000, 0x5170)

	t.Run("above the threshold, no question is asked", func(t *testing.T) {
		obj := newCountingStore()
		base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}
		before, _ := obj.stats()
		s := storeOn(t, obj, base, smallChunks)
		if err := s.Write(ctx, 1, 0, body); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		if base.questions() != 0 {
			t.Errorf("the base was asked %d times about chunks under the threshold", base.questions())
		}
		if st := s.Stats(); st.BaseDedupedChunks != 0 {
			t.Errorf("%d chunks deduped under the threshold", st.BaseDedupedChunks)
		}
		if after, _ := obj.stats(); after == before {
			t.Error("the second session uploaded nothing, so this is not measuring the threshold")
		}
	})

	t.Run("below the threshold, the same content is free", func(t *testing.T) {
		defer SetMinReuseBytes(1 << 10)()
		obj := newCountingStore()
		base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}
		_, beforeBytes := obj.stats()
		s := storeOn(t, obj, base, smallChunks)
		if err := s.Write(ctx, 1, 0, body); err != nil {
			t.Fatal(err)
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		st := s.Stats()
		if st.BaseDedupedBytes != int64(len(body)) {
			t.Errorf("recognised %d of %d bytes (%d chunks)", st.BaseDedupedBytes, len(body), st.BaseDedupedChunks)
		}
		if _, afterBytes := obj.stats(); afterBytes != beforeBytes {
			t.Errorf("%d bytes went out for content the base already held", afterBytes-beforeBytes)
		}
		// And it still reads back, which is the only thing that proves a
		// row naming somebody else's pack is a row that works.
		if got := readAll(t, s, 1); !bytes.Equal(got, body) {
			t.Fatal("borrowed content does not read back byte-exact")
		}
	})
}

// A pack trailer records an entry's LENGTH and not its codec, so the alg
// column of a borrowed row is derived from the plaintext and checked
// against that length. An entry whose length no encoding of these bytes
// explains is one this writer may not claim — it stores the bytes itself
// rather than write a row that sends a reader to decode something else.
func TestAnEntryWhoseLengthTheAlgCannotExplainIsStoredAgain(t *testing.T) {
	defer SetMinReuseBytes(1 << 10)()
	ctx := context.Background()
	body := fill(200000, 0x5171)
	obj := newCountingStore()
	at := publishedBy(t, obj, body, smallChunks)
	// Bend every stored length by one byte. The identities still match, so
	// a writer that trusted the index would happily reuse them.
	for id, pl := range at {
		pl.Length++
		at[id] = pl
	}
	base := &placerBase{at: at, gen: 5}
	_, beforeBytes := obj.stats()
	s := storeOn(t, obj, base, smallChunks)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if base.questions() == 0 {
		t.Fatal("the base was never asked, so nothing was refused")
	}
	if st := s.Stats(); st.BaseDedupedChunks != 0 {
		t.Errorf("%d chunks were claimed from an entry whose length does not match", st.BaseDedupedChunks)
	}
	_, afterBytes := obj.stats()
	if afterBytes-beforeBytes < int64(len(body)) {
		t.Errorf("only %d bytes were stored for %d bytes the writer could not claim",
			afterBytes-beforeBytes, len(body))
	}
}

// THE DANGEROUS DIRECTION.
//
// Borrowing a chunk writes a row whose bytes live in a pack somebody else
// wrote. That is sound because reachability is over identities — the sweep
// credits every pack holding a reached identity, so the new row keeps the
// old pack alive, and gc cannot delete a pack a live generation lists. A
// REPACK is the exception and the only one: it carries what is reachable
// out of the packs it condemns and drops the rest, so a chunk that was
// present but referenced by no live generation can stop being stored in
// the middle of a session.
//
// A seal that published such a row would produce a generation that mounts,
// passes its own signature, and cannot read one file. So the seal rechecks
// what it borrowed when the base has moved under it, and takes the bytes
// itself when the answer has changed.
func TestASealDoesNotPublishABorrowedChunkTheBaseNoLongerHolds(t *testing.T) {
	defer SetMinReuseBytes(1 << 10)()
	ctx := context.Background()
	body := fill(200000, 0x5172)
	obj := newCountingStore()
	base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}

	s := storeOn(t, obj, base, smallChunks)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.BaseDedupedChunks == 0 {
		t.Fatal("nothing was borrowed, so there is nothing to recheck")
	}
	borrowed := map[string]struct{}{}
	s.mu.Lock()
	ours := map[string]struct{}{}
	for _, sp := range s.packs {
		ours[sp.Name] = struct{}{}
	}
	for k, loc := range s.chunkLoc {
		if _, mine := ours[loc.Pack]; !mine {
			borrowed[k] = struct{}{}
		}
	}
	s.mu.Unlock()
	if len(borrowed) == 0 {
		t.Fatal("no location names a foreign pack")
	}

	// A repack: the base moves on, and the chunks this session borrowed
	// are not in the new generation's packs.
	base.mu.Lock()
	base.gen, base.gone = 6, true
	base.mu.Unlock()

	sl := s.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatalf("seal inode: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatalf("finish seal: %v", err)
	}

	// Every row the seal wrote must name a chunk this session stored
	// itself, because nothing else is reachable from the generation it is
	// about to sign.
	s.mu.Lock()
	ours = map[string]struct{}{}
	for _, sp := range s.packs {
		ours[sp.Name] = struct{}{}
	}
	var dangling []string
	var total int64
	for _, r := range refs {
		id := chunkid.Identity(r.Identity).Hex()
		loc, known := s.chunkLoc[id]
		if !known {
			dangling = append(dangling, id+" (no location)")
			continue
		}
		if _, mine := ours[loc.Pack]; !mine {
			dangling = append(dangling, id+" in "+loc.Pack)
		}
		total += r.LLen
	}
	s.mu.Unlock()
	if len(dangling) > 0 {
		t.Errorf("the seal published %d row(s) naming a pack no live generation holds: %v",
			len(dangling), dangling)
	}
	if total != int64(len(body)) {
		t.Errorf("the rows account for %d bytes of a %d-byte file", total, len(body))
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, body) {
		t.Fatal("the repaired file does not read back byte-exact")
	}
}

// And the recheck costs nothing when there is nothing to recheck: an
// ordinary generation only ever APPENDS to its pack list, so a chunk that
// was stored when the flush borrowed it is still stored at the seal, and
// the seal must not spend a lookup per chunk finding that out.
func TestASealDoesNotRecheckWhatTheBaseStillHolds(t *testing.T) {
	defer SetMinReuseBytes(1 << 10)()
	ctx := context.Background()
	body := fill(200000, 0x5173)
	obj := newCountingStore()
	base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}

	s := storeOn(t, obj, base, smallChunks)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	asked := base.questions()
	if asked == 0 {
		t.Fatal("the flush asked nothing")
	}
	sl := s.NewSealer()
	if _, err := sl.Inode(ctx, 1); err != nil {
		t.Fatalf("seal inode: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatalf("finish seal: %v", err)
	}
	if got := base.questions(); got != asked {
		t.Errorf("the seal asked the base %d further questions about chunks nothing had moved", got-asked)
	}
}

// Compressible content, which is the case that proves the derived alg is
// derived CORRECTLY rather than merely accepted. Incompressible bytes are
// stored verbatim, so a writer that simply asserted "no compression" would
// be right by accident; these bytes are stored zstd-compressed, and a row
// claiming otherwise sends a reader to hand ciphertext-length plaintext to
// nobody's decompressor. The read back is the assertion.
func TestABorrowedCompressibleChunkIsNamedWithTheAlgItWasStoredWith(t *testing.T) {
	defer SetMinReuseBytes(1 << 10)()
	ctx := context.Background()
	body := bytes.Repeat([]byte("the same sixteen"), 200000/16)
	obj := newCountingStore()
	base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}
	_, beforeBytes := obj.stats()

	s := storeOn(t, obj, base, smallChunks)
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()
	if st.BaseDedupedBytes != int64(len(body)) {
		t.Fatalf("recognised %d of %d compressible bytes (%+v)", st.BaseDedupedBytes, len(body), st)
	}
	if _, afterBytes := obj.stats(); afterBytes != beforeBytes {
		t.Errorf("%d bytes went out for compressible content the base already held", afterBytes-beforeBytes)
	}
	// Every borrowed row must say AlgZstd, because that is how the entry
	// it names actually is: nothing read that fact anywhere, it was
	// recomputed and checked against the trailer's length.
	s.mu.Lock()
	for k, loc := range s.chunkLoc {
		if loc.Alg == 0 {
			s.mu.Unlock()
			t.Fatalf("chunk %s borrowed with alg 0 from a zstd-stored entry", k)
		}
	}
	s.mu.Unlock()
	if got := readAll(t, s, 1); !bytes.Equal(got, body) {
		t.Fatal("borrowed compressible content does not read back byte-exact")
	}
}

// A crash loses the one thing the recheck reasons from. A journal records
// WHERE a chunk is, not which generation put it there, so a replayed
// session holding borrowed locations cannot say whether a repack has moved
// the base out from under them — and has to assume it has. The alternative
// is a seal after a crash publishing rows nothing checked.
func TestARecoveredSessionRechecksWhatItBorrowed(t *testing.T) {
	defer SetMinReuseBytes(1 << 10)()
	ctx := context.Background()
	dir := t.TempDir()
	body := fill(200000, 0x5174)
	obj := newCountingStore()
	base := &placerBase{at: publishedBy(t, obj, body, smallChunks), gen: 5}

	s, err := New(Options{Dir: dir, TableSize: 4 << 20, Obj: obj, Base: base, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, 1, 0, body); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.BaseDedupedChunks == 0 {
		t.Fatal("nothing was borrowed, so there is nothing to recover")
	}
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The same base, at the SAME generation: without the recovery guard
	// the replayed session has nothing that says it should look again.
	s2, _, err := Recover(Options{Dir: dir, TableSize: 4 << 20, Obj: obj, Base: base, Chunk: smallChunks}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	s2.mu.Lock()
	recheck := s2.needsBaseRecheckLocked()
	s2.mu.Unlock()
	if !recheck {
		t.Error("a recovered session holding borrowed locations does not recheck them")
	}

	// And the recheck does what it is for: with the base's answers gone,
	// the seal stores the bytes rather than naming somebody else's pack.
	base.mu.Lock()
	base.gone = true
	base.mu.Unlock()
	sl := s2.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatalf("seal inode: %v", err)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatalf("finish seal: %v", err)
	}
	s2.mu.Lock()
	ours := map[string]struct{}{}
	for _, sp := range s2.packs {
		ours[sp.Name] = struct{}{}
	}
	var dangling int
	for _, r := range refs {
		loc, known := s2.chunkLoc[chunkid.Identity(r.Identity).Hex()]
		if _, mine := ours[loc.Pack]; !known || !mine {
			dangling++
		}
	}
	s2.mu.Unlock()
	if dangling > 0 {
		t.Errorf("%d of %d rows still name a pack no live generation holds", dangling, len(refs))
	}
}

// WHERE CROSS-GENERATION DEDUP STOPS, measured rather than asserted.
//
// The chunker cuts on content, so the identities two generations produce
// for the same bytes agree — but only where each generation's chunker SAW
// those bytes as one stream. A flush chunks one batch of the ring at a
// time (chunkInode), so a session whose writes exceed the ring is cut at
// boundaries the ring chose: the first chunk of a batch begins where the
// batch begins and the last one ends where it ends, and neither of those
// is a content boundary.
//
// A session that fits in the ring therefore realises the chunker's full
// potential — which is the case that matters for publishing an image, one
// file per generation — and a session that does not realises less. The
// damage is two chunks per batch, the one that begins where the batch
// begins and the one that ends where it ends, so it scales as the chunk
// size over the BATCH size. This fixture is deliberately in the regime
// where that ratio is small (a 512 KiB batch against a 4 KiB average
// chunk), which is why the second number below is still high; the shipped
// defaults are in the opposite regime — promoteAt is DefaultPackTarget, 2
// MiB, against a 4 MiB average chunk — and there the measured figure is
// 17 of 87 chunks, 28% of bytes, over a four-file 274 MB session. That
// measurement is not here because reproducing it needs production chunker
// parameters and a quarter of a gigabyte; it is recorded, with how it was
// taken, in docs/known-issues.md KL-9.
//
// The numbers are logged rather than bounded, because bounding them would
// be pinning an accident of where the ring happened to flush; what IS
// bounded is the first case, which is a real invariant, and that the
// second has not collapsed to nothing.
//
// docs/known-issues.md KL-9.
func TestFlushBatchBoundariesLimitWhatCanBeDeduped(t *testing.T) {
	ctx := context.Background()
	body := fill(6<<20, 0x5175)

	// What a single content-defined pass over the same bytes would cut.
	ideal := map[string]struct{}{}
	ck := chunkid.NewChunker(bytes.NewReader(body), smallChunks)
	var h chunkid.Hasher
	for {
		c, err := ck.Next()
		if err != nil {
			break
		}
		ideal[h.Sum(c.Data).Hex()] = struct{}{}
	}

	run := func(ring int, promotion uint64, packTarget int64) (agree, total int, bytesAgree int64) {
		s, err := New(Options{
			Dir: t.TempDir(), TableSize: ring, PromotionDistance: promotion,
			PackTarget: packTarget, Obj: newCountingStore(), Chunk: smallChunks,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close() //nolint:errcheck
		for off := 0; off < len(body); off += 64 << 10 {
			end := min(off+64<<10, len(body))
			if err := s.Write(ctx, 1, int64(off), body[off:end]); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for k, loc := range s.chunkLoc {
			total++
			if _, ok := ideal[k]; ok {
				agree++
				bytesAgree += loc.Logical
			}
		}
		return
	}

	// A session that fits: every chunk is content-determined, so every
	// chunk is a chunk another generation can recognise.
	agree, total, bytesAgree := run(8<<20, 0, 0)
	t.Logf("session inside the ring:  %d/%d chunks content-determined, %d of %d bytes",
		agree, total, bytesAgree, len(body))
	if agree != total || bytesAgree != int64(len(body)) {
		t.Errorf("a session that fits in the ring cut %d of %d chunks on content: "+
			"the whole cross-generation claim rests on this being all of them", agree, total)
	}

	// A session that does not: the ring's flush points become chunk
	// boundaries, and those chunks are unrecognisable to any other
	// generation. This is the residual gap.
	agree, total, bytesAgree = run(1<<20, 512<<10, 0)
	t.Logf("batch >> chunk (128x):    %d/%d chunks content-determined, %d of %d bytes",
		agree, total, bytesAgree, len(body))
	if agree == 0 {
		t.Errorf("not one of %d chunks was content-determined; the chunker is no longer "+
			"re-converging after a flush boundary at all", total)
	}

}
