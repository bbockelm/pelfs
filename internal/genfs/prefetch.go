package genfs

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/bbockelm/pelfs/internal/catalog"
)

// Prefetch warms the decoded-chunk cache for a whole generation.
//
// This is the batch disposition the v1 mount already offers: an HTCondor
// job that wants every byte local before it starts, so a mid-job
// federation failure cannot stall it — and, in strict mode, that refuses
// to run at all rather than discover a missing chunk halfway through.
//
// It walks catalogs rather than the pack list on purpose. The pack list
// includes catalogs, shards, and superblock backups, and after a repack
// it can still name packs holding chunks no live file references;
// walking the tree fetches exactly what the generation's files are made
// of, once per distinct chunk identity.

// PrefetchReport summarizes a warm-up pass.
type PrefetchReport struct {
	Files   int
	Chunks  int   // distinct chunk identities fetched
	Cached  int   // already present, no transfer
	Bytes   int64 // decoded bytes now resident
	Failed  int
	Sample  []string // first few failures, for a human
	Skipped int      // inline files and holes: nothing to fetch
}

// Prefetch fills the chunk cache using workers concurrent fetchers. It
// stops early and returns the error only when ctx is cancelled; per-chunk
// failures are counted so a caller can decide whether "mostly warm" is
// good enough (background mode) or not (strict mode).
func (fs *FS) Prefetch(ctx context.Context, workers int) (*PrefetchReport, error) {
	if workers <= 0 {
		workers = 8
	}
	rep := &PrefetchReport{}
	var mu sync.Mutex

	// Collect the distinct chunk set by walking the tree. Deduplicating
	// up front matters: content addressing means one identity can back
	// many files, and fetching it once is the point.
	type job struct {
		ref *catalog.ChunkRef
	}
	seen := make(map[string]struct{})
	var jobs []job

	var walk func(ino uint64) error
	walk = func(ino uint64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := fs.Readdir(ctx, ino)
		if err != nil {
			return err
		}
		for _, e := range entries {
			// Descent establishes residency; Readdir alone does not.
			n, err := fs.Lookup(ctx, ino, e.Name)
			if err != nil {
				return fmt.Errorf("prefetch: lookup %q: %w", e.Name, err)
			}
			switch {
			case n.Type == catalog.TypeDir:
				if err := walk(n.Inode); err != nil {
					return err
				}
			case n.Type == catalog.TypeFile:
				rep.Files++
				ext, err := fs.extentsOf(ctx, n.Inode)
				if err != nil {
					return fmt.Errorf("prefetch: extents of %q: %w", e.Name, err)
				}
				for i := range ext.refs {
					r := &ext.refs[i]
					if len(r.Identity) == 0 {
						rep.Skipped++ // hole or inline: nothing to fetch
						continue
					}
					key := string(r.Identity)
					if _, dup := seen[key]; dup {
						continue
					}
					seen[key] = struct{}{}
					jobs = append(jobs, job{ref: r})
				}
			}
		}
		return nil
	}
	if err := walk(RootInode); err != nil {
		return rep, err
	}

	work := make(chan job)
	var wg sync.WaitGroup
	var cancelled atomic.Bool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				if ctx.Err() != nil {
					cancelled.Store(true)
					return
				}
				idHex := hex.EncodeToString(j.ref.Identity)
				fp := filepath.Join(fs.chunkDir, idHex)
				if fi, err := os.Stat(fp); err == nil {
					mu.Lock()
					rep.Cached++
					rep.Bytes += fi.Size()
					mu.Unlock()
					continue
				}
				// A one-byte read at offset 0 forces the whole chunk
				// through the same fill path a real read uses, so the
				// cache ends up in exactly the state reads expect.
				var one [1]byte
				err := fs.readChunkAt(ctx, j.ref, 0, one[:])
				mu.Lock()
				if err != nil {
					rep.Failed++
					if len(rep.Sample) < 5 {
						rep.Sample = append(rep.Sample, fmt.Sprintf("%s: %v", idHex[:16], err))
					}
				} else {
					rep.Chunks++
					rep.Bytes += j.ref.LLen
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		select {
		case work <- j:
		case <-ctx.Done():
			cancelled.Store(true)
		}
		if cancelled.Load() {
			break
		}
	}
	close(work)
	wg.Wait()
	if cancelled.Load() {
		return rep, ctx.Err()
	}
	return rep, nil
}
