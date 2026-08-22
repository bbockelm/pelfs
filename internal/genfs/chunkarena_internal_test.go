package genfs

import (
	"fmt"
	"sync"
	"testing"
)

// The arena's locking, tested from inside the package, because the thing
// being pinned has no expression at the filesystem level.
//
// TestArenaEvictionUnderConcurrentReaders (chunkarena_test.go) drives the
// same structure through FS.Read, and it is the right test for the question
// it asks — do readers get their own bytes while the cursor wraps over them.
// It is the wrong test for the question here. Every miss it takes pays for a
// pack read and a decode, which is microseconds of work between one fill and
// the next, and the window this is about is the handful of instructions
// between a fill publishing its slot and an eviction taking that slot back.
//
// Measured, on the defect this file was written for: the FS-level test does
// not reproduce it in three hundred runs on an unloaded machine, and does
// reproduce it in every block of a hundred once the CPU is saturated or
// GOMAXPROCS is oversubscribed past the core count. So it wants PREEMPTION,
// not repetition, which is why an idle laptop said the code was fine and a
// shared CI runner said it was not. This test reproduces it on the first
// run, unloaded, because it takes the decode out from between the
// collisions.

// A fill and the eviction that takes its space back are not allowed to be a
// data race, and the loser is not allowed to leave a corpse in the index.
//
// put fills a slot under the slot's lock, drops it, and then takes a SHARD
// lock to publish. The cursor can lap in between, and kill declares the slot
// dead under the slot's lock — which put no longer holds. So put's last look
// at dead, and forget's look at the entry it finds, are reads without that
// lock, and they are why dead is an atomic.Bool rather than a plain one.
//
// Being race-free is not the same as being ordered, so this checks the
// consequence too. A slot that dies between put's check and put's publish is
// an index entry naming a corpse: every read of that chunk misses on it, and
// put's own duplicate check then refuses to cache the chunk ever again, for
// the life of the mount. Nothing sweeps it — its killer's forget already ran
// and found the shard empty. The fill has to notice and clean up after
// itself, and that is what `dead == 0` below is asserting.
//
// Wrong BYTES are not on the table here and the check is present anyway: a
// reader re-tests dead under the slot's read lock, which kill holds
// exclusively, so a published corpse serves a miss and never somebody else's
// chunk. The comparison below would catch it if that ever stopped being true.
func TestArenaFillAndEvictionDoNotRaceOnOneSlot(t *testing.T) {
	// A mapping small enough that the cursor is always lapping: ninety-six
	// distinct chunks of forty-eight kilobytes competing for one megabyte,
	// so nearly every put evicts and the readers are inside slots while it
	// happens.
	a, err := newChunkArena(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close() //nolint:errcheck

	const chunks, chunkSize, workers, rounds = 96, 48 << 10, 24, 4000
	ids := make([]string, chunks)
	body := make([][]byte, chunks)
	for i := range ids {
		// Identity-shaped: hex, and its first bytes spread across the index
		// shards the way BLAKE3 output does.
		ids[i] = fmt.Sprintf("%016x%048x", i*2654435761, i)
		b := make([]byte, chunkSize)
		for j := range b {
			b[j] = byte(i)
		}
		body[i] = b
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			window := make([]byte, 8<<10)
			for n := 0; n < rounds; n++ {
				i := (w*7 + n*13) % chunks
				// A mix of offset-zero and continuation reads, so the
				// promotion bookkeeping is exercised alongside the eviction.
				off := int64((n % 4) * len(window))
				if a.read(ids[i], off, window) {
					for _, c := range window {
						if c != byte(i) {
							t.Errorf("worker %d: chunk %d served another chunk's bytes", w, i)
							return
						}
					}
					continue
				}
				a.put(ids[i], body[i])
			}
		}(w)
	}
	wg.Wait()

	dead := 0
	for i := range a.idx {
		a.idx[i].mu.RLock()
		for _, s := range a.idx[i].byID {
			if s.dead.Load() {
				dead++
			}
		}
		a.idx[i].mu.RUnlock()
	}
	if dead != 0 {
		t.Errorf("%d dead slots left published in the index: those chunks can never be cached again", dead)
	}
	if fills, evicted, _, _ := a.stats(); fills == 0 || evicted == 0 {
		t.Errorf("fills %d, evictions %d: the arena never came under the pressure this test is about", fills, evicted)
	}
}
