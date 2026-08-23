package memtable

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// The crash boundary these tests drive, and why it is driven this way
// rather than by killing something.
//
// A write is durable in the operation log the moment it happens: Write
// appends an OpPlace under the store's own lock, so the content row —
// which is to say the file's LENGTH — survives any crash after it. Where
// the bytes went is recorded separately and much later: runFlush publishes
// the batch (installing locations, and RECLAIMING the ring region the
// records sat in) and only then waits for the packs to land and writes the
// Located record. A crash in that window leaves a state directory whose
// operation log knows the file is N bytes long and whose location map has
// nothing for part of it, with the ring already advanced past the records.
//
// That state is exactly `Durable` minus one Located record, so it is
// constructed here through the two exported interfaces recovery itself
// uses — Store.Durable and Recover — with no signal, no sleep, and no
// dependence on where a kill happens to land. `crashAfter` is the whole
// simulation.
//
// What must not happen is the failure the crash gate calls silent loss: an
// extent map with a lost extent removed from it has a GAP, a gap reads as
// zeros (content.go), and a file whose length still comes from the
// operation log therefore comes back at exactly the size it should be,
// full of zeros nobody wrote, passing every length check and sealing into
// a signed generation. Absence is allowed here. Wrongness is not.

// crashAfter is the durable state a crash leaves when the Located record
// for the named handles never landed: their locations are absent, their
// ring records are already reclaimed, and the operation log still says the
// files are as long as they were written.
func crashAfter(d Durable, lost map[Handle]struct{}) Durable {
	out := Durable{
		Rows:        d.Rows,
		Handles:     make(map[Handle][]ChunkSlice, len(d.Handles)),
		Chunks:      d.Chunks,
		Packs:       d.Packs,
		Adopted:     d.Adopted,
		AdoptedRefs: d.AdoptedRefs,
	}
	for h, sl := range d.Handles {
		if _, gone := lost[h]; gone {
			continue
		}
		out.Handles[h] = sl
	}
	return out
}

func allHandles(d Durable) map[Handle]struct{} {
	out := make(map[Handle]struct{}, len(d.Handles))
	for h := range d.Handles {
		out[h] = struct{}{}
	}
	return out
}

// A file whose every extent was in the lost batch must come back EMPTY,
// not at its full length reading zeros.
func TestARecoveredFileIsCutBackRatherThanServedAsZeros(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	// Three writes, so the file is three extents the way a copy of it
	// through a mount would be.
	for i := 0; i < 3; i++ {
		if err := s.Write(ctx, 1, int64(i*4000), fill(4000, uint64(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := s.Durable()
	if len(d.Handles) == 0 {
		t.Fatal("the flush recorded no locations, so there is no record for a crash to lose")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks},
		crashAfter(d, allHandles(d)))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	if !rep.Loss() {
		t.Fatal("a lost location record reported no loss")
	}
	// The assertion the crash gate makes, in one line: the file may be
	// absent or short, and it may not be present at the wrong bytes.
	if got := s2.Size(1); got != 0 {
		body := readAll(t, s2, 1)
		zeros := bytes.Equal(body, make([]byte, len(body)))
		t.Fatalf("inode 1 came back at %d bytes after every extent under it was lost "+
			"(all zeros: %v) — a reader sees a whole file of bytes nobody wrote", got, zeros)
	}
	if got := readAll(t, s2, 1); len(got) != 0 {
		t.Fatalf("inode 1 read %d bytes after being cut to nothing", len(got))
	}
	if len(rep.Truncations) != 1 || rep.Truncations[0].Inode != 1 {
		t.Fatalf("the cut was not reported: %+v", rep.Truncations)
	}
	if rep.Truncations[0].Was != 12000 || rep.Truncations[0].Size != 0 {
		t.Fatalf("cut reported as %d bytes, was %d; wanted 0 of 12000",
			rep.Truncations[0].Size, rep.Truncations[0].Was)
	}
	if msg := rep.String(); !strings.Contains(msg, "CUT BACK") {
		t.Errorf("the report does not say the file was cut back:\n%s", msg)
	}
}

// The sharper shape, and the one the crash gate actually hits: the FIRST
// extent of a file is in the lost batch and the rest survived. The
// survivors are behind a hole, so they go too — serving them would put
// zeros in front of real content, which is the same lie at a smaller size.
func TestARecoveredFileDropsWhatSitsBehindALostExtent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	head := fill(4000, 21)
	if err := s.Write(ctx, 1, 0, head); err != nil {
		t.Fatal(err)
	}
	// One flush, so the head has a location of its own to lose.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	lost := allHandles(s.Durable())
	// And two more extents, in a batch whose record DID land.
	for i := 1; i < 3; i++ {
		if err := s.Write(ctx, 1, int64(i*4000), fill(4000, uint64(i+30))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(d.Handles) <= len(lost) {
		t.Fatal("the second flush recorded nothing, so nothing survives the crash to be dropped")
	}

	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks},
		crashAfter(d, lost))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	if got := s2.Size(1); got != 0 {
		t.Fatalf("inode 1 came back at %d bytes with its first extent gone; "+
			"the range [0,4000) can only be answered with zeros", got)
	}
	if len(rep.Truncations) != 1 {
		t.Fatalf("the cut was not reported: %+v", rep.Truncations)
	}
	if got := rep.Truncations[0].Discarded; got != 8000 {
		t.Fatalf("the report says %d bytes of surviving content went with the cut, wanted 8000", got)
	}
	if rep.DiscardedBytes != 8000 {
		t.Fatalf("DiscardedBytes is %d, wanted 8000", rep.DiscardedBytes)
	}
}

// The other direction: a loss at the END of a file leaves an honest
// PREFIX, and the prefix has to be byte-exact. A cut that took the whole
// file whenever anything was lost would pass the "no zeros" assertion by
// throwing away content that was never in danger.
func TestARecoveredFileKeepsThePrefixAheadOfTheLoss(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	head := fill(4000, 41)
	if err := s.Write(ctx, 1, 0, head); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	kept := allHandles(s.Durable())
	if err := s.Write(ctx, 1, 4000, fill(4000, 42)); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	lost := allHandles(d)
	for h := range kept {
		delete(lost, h)
	}
	if len(lost) == 0 {
		t.Fatal("the tail flush recorded nothing, so there is no tail to lose")
	}

	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks},
		crashAfter(d, lost))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	if got := s2.Size(1); got != 4000 {
		t.Fatalf("inode 1 came back at %d bytes; wanted the 4000-byte prefix that survived", got)
	}
	if got := readAll(t, s2, 1); !bytes.Equal(got, head) {
		t.Fatalf("the surviving prefix is not byte-exact (%d bytes)", len(got))
	}
	if len(rep.Truncations) != 1 || rep.Truncations[0].Size != 4000 {
		t.Fatalf("the cut was not reported at 4000: %+v", rep.Truncations)
	}
	if rep.DiscardedBytes != 0 {
		t.Fatalf("a loss at the end discarded %d surviving bytes; it should discard none", rep.DiscardedBytes)
	}
}

// A file the recovery cut must SEAL at its new length. This is what makes
// the difference permanent rather than cosmetic: inodeFrom renders every
// span a content row covers, and a gap is rendered by reading it — which
// is to say by writing the zeros into a pack, under a signature, where
// fsck will call them consistent forever.
func TestASealAfterARecoveryDoesNotPublishTheZerosItCutAway(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Write(ctx, 1, int64(i*4000), fill(4000, uint64(i+51))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, _, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks},
		crashAfter(d, allHandles(d)))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck

	sl := s2.NewSealer()
	refs, err := sl.Inode(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, r := range refs {
		total += r.LLen
	}
	if total != 0 {
		t.Fatalf("the seal rendered %d bytes of chunk refs for a file whose content was lost; "+
			"those bytes are zeros it invented", total)
	}
	if err := sl.Finish(ctx); err != nil {
		t.Fatal(err)
	}
}

// A genuine hole is not a loss and must not be cut. Nothing was ever
// written to the front of this file, so the zeros there are the zeros the
// caller asked for — the distinction the cut turns on is whether a REF was
// lost, not whether a range is uncovered.
func TestARecoveredSparseFileKeepsItsHoles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	obj := newCountingStore()
	s, err := New(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks})
	if err != nil {
		t.Fatal(err)
	}
	tail := fill(4000, 61)
	if err := s.Write(ctx, 1, 8000, tail); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	d := s.Durable()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, rep, err := Recover(Options{Dir: dir, TableSize: 1 << 20, Obj: obj, Chunk: smallChunks}, d)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close() //nolint:errcheck
	if rep.Loss() || len(rep.Truncations) != 0 {
		t.Fatalf("a sparse file with nothing lost was cut: %s", rep)
	}
	if got := s2.Size(1); got != 12000 {
		t.Fatalf("the sparse file came back at %d bytes, wanted 12000", got)
	}
	body := readAll(t, s2, 1)
	if !bytes.Equal(body[:8000], make([]byte, 8000)) {
		t.Fatal("the hole did not read as zeros")
	}
	if !bytes.Equal(body[8000:], tail) {
		t.Fatal("the written tail of the sparse file does not read back")
	}
}
