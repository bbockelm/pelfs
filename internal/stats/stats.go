// Package stats collects session statistics for pelfs and writes them to a
// local JSON summary file, so an external supervisor (e.g. HTCondor) can
// determine after the fact whether the filesystem encountered errors and
// whether the session ended with all data safely in the federation.
//
// Object-storage operations are counted by wrapping the JuiceFS
// object.ObjectStorage; note these counts include attempts that JuiceFS
// retried successfully, so a nonzero error count means "something went
// wrong at least transiently", while the *_ok booleans describe the final
// session outcome.
package stats

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/juicedata/juicefs/pkg/object"
)

// ErrorSample is one recorded failure.
type ErrorSample struct {
	Time  time.Time `json:"time"`
	Op    string    `json:"op"`
	Key   string    `json:"key,omitempty"`
	Error string    `json:"error"`
}

// OpCounters aggregates one operation type.
type OpCounters struct {
	Ops    int64 `json:"ops"`
	Errors int64 `json:"errors"`
	Bytes  int64 `json:"bytes,omitempty"`
}

// Summary is the JSON document written to the stats file.
type Summary struct {
	Version    int       `json:"pelfs_stats_version"`
	Prefix     string    `json:"prefix"`
	Session    string    `json:"session"`
	MountPoint string    `json:"mountpoint,omitempty"`
	Started    time.Time `json:"started"`
	Updated    time.Time `json:"updated"`
	Finished   time.Time `json:"finished,omitempty"`

	// Object-storage traffic (includes retried attempts; see package doc).
	Get    OpCounters `json:"get"`
	Put    OpCounters `json:"put"`
	Delete OpCounters `json:"delete"`
	Other  OpCounters `json:"other"` // head/list/stat

	ObjectErrorsTotal int64         `json:"object_errors_total"`
	ErrorSamples      []ErrorSample `json:"error_samples,omitempty"`

	// Component outcomes.
	SnapshotsUploaded int64 `json:"snapshots_uploaded"`
	SnapshotErrors    int64 `json:"snapshot_errors"`
	FinalSnapshotOK   *bool `json:"final_snapshot_ok,omitempty"`

	PrefetchMode          string `json:"prefetch_mode,omitempty"`
	PrefetchSlices        int64  `json:"prefetch_slices,omitempty"`
	PrefetchFailed        int64  `json:"prefetch_failed,omitempty"`
	PrefetchComplete      bool   `json:"prefetch_complete,omitempty"`
	StagingDrained        *bool  `json:"staging_drained,omitempty"` // writeback only
	StagingBlocksLeft     int64  `json:"staging_blocks_left,omitempty"`
	LeaseHeld             bool   `json:"lease_held,omitempty"`
	LeaseConflictObserved bool   `json:"lease_conflict_observed,omitempty"`

	// Catalog-native (phase 3) sessions: `pelfs mount-gen`. A v1 session
	// leaves every field below zero, so one document shape serves both.
	//
	// Generation is what the mount serves NOW — with --poll it is the
	// head the last live refresh swapped to, not the one it started on.
	Generation      uint64 `json:"generation,omitempty"`
	Branch          string `json:"branch,omitempty"`
	Tag             string `json:"tag,omitempty"`
	Backend         string `json:"backend,omitempty"`  // fuse or nfs
	Writable        bool   `json:"writable,omitempty"` // --rw: an overlay shadows the generation
	GenerationSwaps int64  `json:"generation_swaps,omitempty"`

	// Prefetch on a catalog-native mount warms whole chunks, not the
	// slices a JuiceFS mount counts.
	PrefetchChunks int64 `json:"prefetch_chunks,omitempty"`
	PrefetchBytes  int64 `json:"prefetch_bytes,omitempty"`

	// Overlay pressure: unsealed work, i.e. exactly what is lost if the
	// session dies without a seal.
	OverlayDirtyNodes  int64 `json:"overlay_dirty_nodes,omitempty"`
	OverlayDirtyEdges  int64 `json:"overlay_dirty_edges,omitempty"`
	OverlayStagedFiles int64 `json:"overlay_staged_files,omitempty"`
	OverlayStagedBytes int64 `json:"overlay_staged_bytes,omitempty"`

	// Seal outcomes. Seals counts every generation this session published
	// (control-socket checkpoints plus the one at unmount); the Sealed*
	// fields describe the last of them. SealOK is nil when the session
	// never needed to seal — read-only, --no-seal, or nothing changed.
	Seals            int64  `json:"seals,omitempty"`
	SealedGeneration uint64 `json:"sealed_generation,omitempty"`
	SealedChunks     int64  `json:"sealed_chunks,omitempty"`
	SealedCatalogs   int64  `json:"sealed_catalogs,omitempty"`
	SealedPacks      int64  `json:"sealed_packs,omitempty"`
	SealOK           *bool  `json:"seal_ok,omitempty"`

	// Overall verdict for supervisors: true only when unmount, flush/drain,
	// and the final snapshot all succeeded.
	CleanShutdown bool `json:"clean_shutdown"`
	ExitCode      int  `json:"exit_code"`
}

const maxErrorSamples = 20

// Collector accumulates counters; safe for concurrent use.
type Collector struct {
	mu   sync.Mutex
	sum  Summary
	path string
}

// New creates a collector writing (atomically, on Flush) to path.
func New(prefix, session, path string) *Collector {
	return &Collector{
		sum: Summary{
			Version: 1,
			Prefix:  prefix,
			Session: session,
			Started: time.Now(),
		},
		path: path,
	}
}

// Update applies fn under the collector lock.
func (c *Collector) Update(fn func(*Summary)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.sum)
}

func (c *Collector) recordError(op, key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sum.ObjectErrorsTotal++
	if len(c.sum.ErrorSamples) < maxErrorSamples {
		c.sum.ErrorSamples = append(c.sum.ErrorSamples, ErrorSample{
			Time: time.Now(), Op: op, Key: key, Error: err.Error(),
		})
	}
}

// Flush writes the current summary to the stats file (atomic rename).
func (c *Collector) Flush() error {
	c.mu.Lock()
	c.sum.Updated = time.Now()
	data, err := json.MarshalIndent(&c.sum, "", "  ")
	path := c.path
	c.mu.Unlock()
	if err != nil || path == "" {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RunPeriodic flushes every interval until ctx is done.
func (c *Collector) RunPeriodic(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = c.Flush()
		}
	}
}

// Finalize stamps the outcome fields and writes the file one last time.
func (c *Collector) Finalize(exitCode int, clean bool) error {
	c.Update(func(s *Summary) {
		s.Finished = time.Now()
		s.ExitCode = exitCode
		s.CleanShutdown = clean
	})
	return c.Flush()
}

// WrapStorage returns an object storage that counts every operation into c.
func WrapStorage(inner object.ObjectStorage, c *Collector) object.ObjectStorage {
	return &countingStore{ObjectStorage: inner, c: c}
}

type countingStore struct {
	object.ObjectStorage
	c *Collector
}

func (s *countingStore) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	rc, err := s.ObjectStorage.Get(ctx, key, off, limit, getters...)
	s.c.Update(func(sum *Summary) { sum.Get.Ops++ })
	if err != nil {
		s.c.Update(func(sum *Summary) { sum.Get.Errors++ })
		s.c.recordError("get", key, err)
		return nil, err
	}
	return &countingReader{ReadCloser: rc, c: s.c, key: key}, nil
}

func (s *countingStore) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
	cr := &countingInput{Reader: in}
	err := s.ObjectStorage.Put(ctx, key, cr, getters...)
	s.c.Update(func(sum *Summary) {
		sum.Put.Ops++
		sum.Put.Bytes += cr.n
	})
	if err != nil {
		s.c.Update(func(sum *Summary) { sum.Put.Errors++ })
		s.c.recordError("put", key, err)
	}
	return err
}

func (s *countingStore) Delete(ctx context.Context, key string, getters ...object.AttrGetter) error {
	err := s.ObjectStorage.Delete(ctx, key, getters...)
	s.c.Update(func(sum *Summary) { sum.Delete.Ops++ })
	if err != nil {
		s.c.Update(func(sum *Summary) { sum.Delete.Errors++ })
		s.c.recordError("delete", key, err)
	}
	return err
}

func (s *countingStore) Head(ctx context.Context, key string) (object.Object, error) {
	obj, err := s.ObjectStorage.Head(ctx, key)
	s.c.Update(func(sum *Summary) { sum.Other.Ops++ })
	if err != nil {
		// Not-found is a routine answer for Head, not a failure.
		if !isNotExist(err) {
			s.c.Update(func(sum *Summary) { sum.Other.Errors++ })
			s.c.recordError("head", key, err)
		}
	}
	return obj, err
}

type countingReader struct {
	io.ReadCloser
	c   *Collector
	key string
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.c.Update(func(sum *Summary) { sum.Get.Bytes += int64(n) })
	}
	if err != nil && err != io.EOF {
		r.c.Update(func(sum *Summary) { sum.Get.Errors++ })
		r.c.recordError("get-read", r.key, err)
	}
	return n, err
}

type countingInput struct {
	io.Reader
	n int64
}

func (r *countingInput) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	return n, err
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
