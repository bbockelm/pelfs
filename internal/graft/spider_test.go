package graft

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
)

// smallPolicy exercises the ladder at sizes a test can build: a 4 KiB
// floor, a 16 KiB ceiling, two blocks per object before it doubles.
func smallPolicy() BlockPolicy {
	return BlockPolicy{Block: 4096, Max: 16384, PerObject: 2}
}

// tree builds a source with a deliberate size spread: under the inline
// threshold, one block, several blocks, and one large enough that the
// ladder climbs to its ceiling.
func tree(t *testing.T, m *memStore) map[string][]byte {
	t.Helper()
	rnd := rand.New(rand.NewSource(7))
	sizes := map[string]int{
		"data/tiny.txt":        100,
		"data/oneblock.bin":    4096,
		"data/two.bin":         8192,
		"data/ragged.bin":      5000,
		"data/nested/big.bin":  100000,
		"data/nested/huge.bin": 300000,
	}
	want := map[string][]byte{}
	for k, n := range sizes {
		b := make([]byte, n)
		rnd.Read(b)
		m.put(k, b, time.Unix(1700000000, 0))
		want[k] = b
	}
	return want
}

func spiderInto(t *testing.T, m *memStore, o SpiderOptions) (*Result, []byte) {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(dir, o.Policy.withDefaults().Block)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	o.Src, o.Index = m, w
	res, err := Spider(context.Background(), o)
	if err != nil {
		t.Fatalf("Spider: %v", err)
	}
	var buf bytes.Buffer
	if _, err := w.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	return res, buf.Bytes()
}

// TestSpiderDigestsEveryByteExactlyOnceAndInParallel is the correctness
// check under concurrency: every block in the index hashes to the bytes
// the source holds at the location the index names, the per-object block
// sizes follow the recorded rule, and more than one request really was in
// flight.
func TestSpiderDigestsEveryByteExactlyOnceAndInParallel(t *testing.T) {
	m := newMemStore()
	src := tree(t, m)
	// A stand-in round trip, so that a serial walk and a parallel one are
	// distinguishable at all: with an instant store every read finishes
	// before the next begins and the watermark says nothing.
	m.delay = 2 * time.Millisecond
	res, raw := spiderInto(t, m, SpiderOptions{
		Policy: smallPolicy(), Concurrency: 8, SpanBytes: 16384,
	})
	if res.Objects != len(src) {
		t.Fatalf("walked %d objects, want %d", res.Objects, len(src))
	}
	if m.peak.Load() < 2 {
		t.Fatalf("peak concurrent reads was %d: the walk did not parallelise", m.peak.Load())
	}
	t.Logf("%d objects, %d blocks, peak %d concurrent source reads",
		res.Objects, res.Blocks, m.peak.Load())

	ix, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := chunkid.NewHasher(nil)
	// Every file's records must name bytes that are actually there.
	for _, f := range res.Files {
		key := strings.TrimPrefix(f.Path, "/")
		data := src[key]
		if int64(len(data)) != f.Size {
			t.Fatalf("%s: recorded %d bytes, source has %d", key, f.Size, len(data))
		}
		if f.Body != nil {
			if !bytes.Equal(f.Body, data) {
				t.Fatalf("%s: inlined body does not match the source", key)
			}
			// An inlined file is COPIED, so it must not be in the index.
			continue
		}
		if want := smallPolicy().For(f.Size); f.Block != want {
			t.Fatalf("%s (%d bytes) was cut at %d, the rule says %d", key, f.Size, f.Block, want)
		}
		var off int64
		for i, id := range f.IDs {
			n := f.Block
			if rem := f.Size - off; rem < n {
				n = rem
			}
			if got := h.Sum(data[off : off+n]); got != id {
				t.Fatalf("%s block %d hashes to %s, the walk recorded %s", key, i, got.Hex(), id.Hex())
			}
			loc, ok := ix.Lookup(id[:])
			if !ok {
				t.Fatalf("%s block %d is not in the index", key, i)
			}
			if loc.Key != key || loc.Off != off || loc.Length != n {
				t.Fatalf("%s block %d resolves to %+v, want %s[%d,+%d)", key, i, loc, key, off, n)
			}
			off += n
		}
		if off != f.Size {
			t.Fatalf("%s: records cover %d of %d bytes", key, off, f.Size)
		}
	}
	// The source was read exactly once end to end, not twice.
	if got := m.bytes.Load(); got != res.Bytes {
		t.Fatalf("the walk moved %d bytes for a %d-byte tree", got, res.Bytes)
	}
}

// TestARerunOfAnUnchangedSourceReadsNothing is the resume guarantee in
// its cheapest form, and it is also what makes `--refresh` affordable.
func TestARerunOfAnUnchangedSourceReadsNothing(t *testing.T) {
	m := newMemStore()
	tree(t, m)
	dir := t.TempDir()
	path := filepath.Join(dir, "ckpt.log")
	hdr := CheckpointHeader{Source: "mem://ext", Mount: "/ext", Block: 4096,
		BlockMax: 16384, PerObject: 2, Hasher: "blake3-256"}

	ckpt, discarded, err := OpenCheckpoint(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if discarded != "" {
		t.Fatalf("a fresh checkpoint reported %q", discarded)
	}
	first, rawFirst := spiderInto(t, m, SpiderOptions{Policy: smallPolicy(), Checkpoint: ckpt, Concurrency: 4})
	if err := ckpt.Close(); err != nil {
		t.Fatal(err)
	}
	if first.BytesHashed != first.Bytes {
		t.Fatalf("the first walk hashed %d of %d bytes", first.BytesHashed, first.Bytes)
	}

	m.bytes.Store(0)
	ckpt2, discarded, err := OpenCheckpoint(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if discarded != "" {
		t.Fatalf("resuming the same walk discarded the log: %s", discarded)
	}
	second, rawSecond := spiderInto(t, m, SpiderOptions{Policy: smallPolicy(), Checkpoint: ckpt2, Concurrency: 4})
	if err := ckpt2.Close(); err != nil {
		t.Fatal(err)
	}
	if second.BytesHashed != 0 {
		t.Fatalf("a re-run of an unchanged source read %d bytes; it must read none", second.BytesHashed)
	}
	if second.BytesResumed != first.Bytes {
		t.Fatalf("the re-run resumed %d of %d bytes", second.BytesResumed, first.Bytes)
	}
	if !bytes.Equal(rawFirst, rawSecond) {
		t.Fatal("the resumed walk produced a DIFFERENT index; a refresh would move every identity")
	}
	// The listing is the only thing it paid for.
	t.Logf("the re-run moved %d bytes of source data", m.bytes.Load())
}

// TestAResumeRehashesOnlyWhatMoved: the point of the checkpoint at TB
// scale is that a change to one file costs that file, not the tree.
func TestAResumeRehashesOnlyWhatMoved(t *testing.T) {
	m := newMemStore()
	tree(t, m)
	path := filepath.Join(t.TempDir(), "ckpt.log")
	hdr := CheckpointHeader{Source: "mem://ext", Mount: "/ext", Block: 4096,
		BlockMax: 16384, PerObject: 2, Hasher: "blake3-256"}
	ckpt, _, err := OpenCheckpoint(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	spiderInto(t, m, SpiderOptions{Policy: smallPolicy(), Checkpoint: ckpt})
	ckpt.Close() //nolint:errcheck

	// One file rewritten, same length, NEW mtime — which is what the
	// listing can see, and all it can see.
	changed := make([]byte, 300000)
	rand.New(rand.NewSource(99)).Read(changed)
	m.put("data/nested/huge.bin", changed, time.Unix(1700009999, 0))

	ckpt2, _, err := OpenCheckpoint(path, hdr)
	if err != nil {
		t.Fatal(err)
	}
	res, raw := spiderInto(t, m, SpiderOptions{Policy: smallPolicy(), Checkpoint: ckpt2})
	ckpt2.Close() //nolint:errcheck
	if res.BytesHashed != 300000 {
		t.Fatalf("re-read %d bytes; only the 300000-byte file moved", res.BytesHashed)
	}
	// And the new bytes are what the index now names.
	ix, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := chunkid.NewHasher(nil)
	blk := smallPolicy().For(300000)
	id := h.Sum(changed[:blk])
	loc, ok := ix.Lookup(id[:])
	if !ok || loc.Key != "data/nested/huge.bin" || loc.Off != 0 {
		t.Fatalf("the rewritten file's first block resolves to %+v (found=%v)", loc, ok)
	}
}

// TestASourceThatMovesMidWalkIsRefused. An index describing two versions
// of a tree is undetectable afterwards — every block in it verifies — so
// it has to be caught here or never.
func TestASourceThatMovesMidWalkIsRefused(t *testing.T) {
	m := newMemStore()
	tree(t, m)
	// Change the tree between the walk's two listings by mutating on the
	// LAST read, which is inside the walk and before the confirmation.
	m.onGet = func(key string) {
		if key == "data/nested/huge.bin" {
			m.put("data/oneblock.bin", make([]byte, 9000), time.Unix(1700005555, 0))
		}
	}
	dir := t.TempDir()
	w, err := NewWriter(dir, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	_, err = Spider(context.Background(), SpiderOptions{
		Src: m, Index: w, Policy: smallPolicy(), Concurrency: 1,
	})
	if err == nil {
		t.Fatal("a graft was published over a source that changed under the walk")
	}
	if !strings.Contains(err.Error(), "changed while it was being walked") &&
		!strings.Contains(err.Error(), "changed while it was being spidered") {
		t.Fatalf("the refusal does not say the source moved: %v", err)
	}
	t.Logf("refused: %v", err)
}

// TestAnObjectThatGrowsUnderTheReadIsRefused is the per-object half of
// the same rule: the listing's length and the bytes delivered must agree,
// or the catalog would record a length no read can satisfy.
func TestAnObjectThatGrowsUnderTheReadIsRefused(t *testing.T) {
	m := newMemStore()
	m.put("a.bin", make([]byte, 4096), time.Unix(1700000000, 0))
	m.shortBy = 100 // the store hands back less than it listed
	w, err := NewWriter(t.TempDir(), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close() //nolint:errcheck
	_, err = Spider(context.Background(), SpiderOptions{Src: m, Index: w, Policy: smallPolicy()})
	if err == nil || !strings.Contains(err.Error(), "changed while it was being spidered") {
		t.Fatalf("a short delivery was accepted or misreported: %v", err)
	}
}

// TestProgressReportsSomethingBeforeTheEnd: the owner's complaint about
// operations that go quiet is the reason the ticker exists, so a walk
// long enough to tick must actually tick.
func TestProgressReportsSomethingBeforeTheEnd(t *testing.T) {
	m := newMemStore()
	for i := 0; i < 40; i++ {
		b := make([]byte, 20000)
		b[0] = byte(i)
		m.put(fmt.Sprintf("obj%02d.bin", i), b, time.Unix(1700000000, 0))
	}
	m.delay = 3 * time.Millisecond
	seen := make(chan Progress, 16)
	spiderInto(t, m, SpiderOptions{
		Policy: smallPolicy(), Concurrency: 2, ProgressEvery: 5 * time.Millisecond,
		Progress: func(p Progress) {
			select {
			case seen <- p:
			default:
			}
		},
	})
	select {
	case p := <-seen:
		if p.BytesTotal <= 0 {
			t.Fatal("progress reported no total, so no percentage or ETA is possible")
		}
		t.Logf("progress: %d/%d bytes, %d/%d objects, %.0f B/s, eta %s",
			p.BytesHashed, p.BytesTotal, p.ObjectsDone, p.Objects, p.Rate(), p.ETA())
	default:
		t.Fatal("a walk that ran for many ticks reported no progress at all")
	}
}
