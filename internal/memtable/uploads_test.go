package memtable

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// The property the queue exists for: a session's writes are paced by
// local disk, not by the uplink. A pack is durable the moment its file
// exists, so the ring region it came from is reclaimable then — and the
// writer keeps going while the bytes are still going out.
//
// This is the regression that made a kernel untar unusable: with the
// upload inside the pack run, the mount stopped for the length of every
// upload.
func TestWritesDoNotWaitForTheUplink(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	// One second per pack, which is an eternity next to a memcpy: if a
	// write waits for even one upload, the loop below cannot finish in
	// anything like the time asserted.
	obj.latency = 200 * time.Millisecond
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 2 << 20, Obj: obj, Chunk: smallChunks,
		PackTarget: 64 << 10, PromotionDistance: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	body := fill(64<<10, 51)
	start := time.Now()
	for i := 0; i < 48; i++ {
		if err := s.Write(ctx, uint64(i+1), 0, body); err != nil {
			t.Fatal(err)
		}
	}
	writing := time.Since(start)

	// 3 MiB at a 64 KiB cut is dozens of packs; serialised at 200ms each
	// that is many seconds. The writes themselves must not have paid it.
	if writing > 2*time.Second {
		t.Errorf("writing 3 MiB took %v with a %v-per-pack uplink; the writer is waiting for uploads",
			writing, obj.latency)
	}
	t.Logf("wrote 3 MiB in %v against a %v-per-pack uplink (backlog %d bytes)",
		writing.Round(time.Millisecond), obj.latency, s.Stats().UploadBacklog)

	// And a flush still means "on the federation": it drains what the
	// writes left behind.
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if backlog := s.Stats().UploadBacklog; backlog != 0 {
		t.Errorf("a flush left %d bytes queued; a flush means durable", backlog)
	}
	if got := readAll(t, s, 1); !bytes.Equal(got, body) {
		t.Fatal("content does not read back after an asynchronous upload")
	}
}

// The queue is bounded, and the bound is what stops a session outrunning
// its uplink without limit. Packing waits when the backlog is full; the
// writer waits behind it, through a ring that stops being reclaimed.
func TestTheUploadQueueIsBounded(t *testing.T) {
	ctx := context.Background()
	obj := newCountingStore()
	obj.latency = 50 * time.Millisecond
	s, err := New(Options{
		Dir: t.TempDir(), TableSize: 4 << 20, Obj: obj, Chunk: smallChunks,
		PackTarget: 64 << 10, PromotionDistance: 1 << 20,
		UploadQueueBytes: 128 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	body := fill(64<<10, 52)
	for i := 0; i < 40; i++ {
		if err := s.Write(ctx, uint64(i+1), 0, body); err != nil {
			t.Fatal(err)
		}
		if backlog := s.Stats().UploadBacklog; backlog > 8*(128<<10) {
			t.Fatalf("backlog reached %d bytes against a %d-byte bound", backlog, 128<<10)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, s, 40); !bytes.Equal(got, body) {
		t.Fatal("content does not read back after a bounded queue drained")
	}
}
