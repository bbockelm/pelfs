package mountfs

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juicedata/juicefs/pkg/meta"
)

// PrefetchReport summarizes a cache-warmup pass.
type PrefetchReport struct {
	Slices   int
	Failed   int
	FirstErr error
}

// Prefetch downloads every block referenced by the volume metadata into the
// local cache (the same mechanism as `juicefs warmup`). It returns how many
// slices were processed and how many failed; a strict caller refuses to
// proceed when Failed > 0.
func (mnt *Mounted) Prefetch(ctx context.Context, workers int) (*PrefetchReport, error) {
	if workers <= 0 {
		workers = 8
	}
	type sl struct {
		id   uint64
		size uint32
	}
	var slices []sl
	c := meta.WrapContext(ctx)
	if st := mnt.m.ScanSlices(c, &meta.ScanSlicesOption{}, func(_ meta.Ino, s meta.Slice) error {
		if s.Id > 0 && s.Size > 0 {
			slices = append(slices, sl{s.Id, s.Size})
		}
		return nil
	}); st != 0 {
		return nil, fmt.Errorf("scan slices: %s", st)
	}

	rep := &PrefetchReport{Slices: len(slices)}
	var failed atomic.Int64
	var firstErr atomic.Value
	work := make(chan sl, 64)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range work {
				if err := mnt.store.FillCache(s.id, s.size); err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, fmt.Errorf("slice %d: %w", s.id, err))
				}
			}
		}()
	}
	for _, s := range slices {
		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return rep, ctx.Err()
		case work <- s:
		}
	}
	close(work)
	wg.Wait()
	rep.Failed = int(failed.Load())
	if e, ok := firstErr.Load().(error); ok {
		rep.FirstErr = e
	}
	return rep, nil
}

// StagingBlocks reports how many writeback-staged blocks still await upload
// to the federation (0 when writeback is disabled).
func (mnt *Mounted) StagingBlocks() int64 {
	families, err := mnt.registry.Gather()
	if err != nil {
		return -1
	}
	var total float64
	for _, f := range families {
		if strings.HasSuffix(f.GetName(), "staging_blocks") {
			for _, m := range f.GetMetric() {
				if g := m.GetGauge(); g != nil {
					total += g.GetValue()
				}
			}
		}
	}
	return int64(total)
}

// drainStaging waits until every writeback-staged block has been uploaded.
// The background uploader retries failed uploads on its own; this simply
// waits (up to timeout; 0 means wait forever) for the count to reach zero.
func (mnt *Mounted) drainStaging(timeout time.Duration) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	logged := false
	for {
		n := mnt.StagingBlocks()
		if n <= 0 {
			return nil
		}
		if !logged {
			logger.Infof("waiting for %d staged block(s) to upload to the federation", n)
			logged = true
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			return fmt.Errorf("%d staged block(s) still not uploaded after %s", n, timeout)
		}
		time.Sleep(2 * time.Second)
	}
}
