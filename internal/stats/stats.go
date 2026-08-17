// Package stats collects session statistics for pelfs and writes them to a
// local JSON summary file, so an external supervisor (e.g. HTCondor) can
// determine after the fact whether the filesystem encountered errors and
// whether the session ended with all data safely in the federation.
//
// Object-storage operations are counted by wrapping the transport; those
// counts include attempts a lower layer retried successfully, so a
// nonzero error count means "something went wrong at least transiently",
// while the *_ok booleans describe the final session outcome.
//
// Every counter is also split by PHASE — while the payload ran, versus
// after it exited (see Phase). An aggregate cannot distinguish a session
// that streamed its output to the federation as it worked from one that
// saved every byte for the unmount, and that distinction is what the
// person watching an `exit` hang wants. The phases sum to the aggregates,
// so a total that is entirely teardown reads as exactly that rather than
// having to be inferred.
package stats

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
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

// Phase says WHEN work happened relative to the payload the session
// exists to run. It is the difference between "pelfs uploaded while I was
// working" and "pelfs uploaded after I typed exit", which is the only
// thing an aggregate byte count cannot tell its reader — and the thing a
// user waiting out an unmount most wants to know.
type Phase int

const (
	// PhaseSession is everything up to the moment the payload exited,
	// mid-session checkpoints included: a checkpoint is precisely work
	// that did NOT have to wait for the end, so counting it here is what
	// makes the split answer the question.
	PhaseSession Phase = iota
	// PhaseTeardown is everything after that: the seal at unmount, the
	// ref flip, the lease release.
	PhaseTeardown
)

// PhaseCounters is one phase's share of the session totals. Every counted
// operation lands in exactly one phase, so the two phases always sum to
// the aggregates above them; see Collector.count.
type PhaseCounters struct {
	Get    OpCounters `json:"get"`
	Put    OpCounters `json:"put"`
	Delete OpCounters `json:"delete"`
	Other  OpCounters `json:"other"`
	// Seals published in this phase: checkpoints under session, the seal
	// at unmount under teardown.
	Seals int64 `json:"seals,omitempty"`
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

	// SessionPhase and TeardownPhase split every counter above by when the
	// work happened. They sum to the aggregates exactly; a reader who
	// wants to know whether anything was published before the payload
	// exited reads session_phase.put.bytes and nothing else.
	SessionPhase  PhaseCounters `json:"session_phase"`
	TeardownPhase PhaseCounters `json:"teardown_phase"`
	// TeardownBegan is when the payload exited, i.e. where the phase
	// boundary was drawn. Zero for a session that never got that far.
	TeardownBegan time.Time `json:"teardown_began,omitempty"`

	ObjectErrorsTotal int64         `json:"object_errors_total"`
	ErrorSamples      []ErrorSample `json:"error_samples,omitempty"`

	// Component outcomes.
	PrefetchMode          string `json:"prefetch_mode,omitempty"`
	PrefetchFailed        int64  `json:"prefetch_failed,omitempty"`
	PrefetchComplete      bool   `json:"prefetch_complete,omitempty"`
	LeaseHeld             bool   `json:"lease_held,omitempty"`
	LeaseConflictObserved bool   `json:"lease_conflict_observed,omitempty"`

	// What the mount is serving. Generation is what it serves NOW — with
	// --poll it is the head the last live refresh swapped to, not the one
	// it started on.
	Generation      uint64 `json:"generation,omitempty"`
	Branch          string `json:"branch,omitempty"`
	Tag             string `json:"tag,omitempty"`
	Backend         string `json:"backend,omitempty"`  // fuse or nfs
	Writable        bool   `json:"writable,omitempty"` // --rw: an overlay shadows the generation
	GenerationSwaps int64  `json:"generation_swaps,omitempty"`

	// Prefetch warms whole content-defined chunks.
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
	RebasedClean     int64  `json:"rebased_clean,omitempty"`
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

// Version is the schema of the JSON document. 2 added the per-phase
// breakdown; every version-1 field kept its name and meaning.
const Version = 2

// Collector accumulates counters; safe for concurrent use.
type Collector struct {
	mu    sync.Mutex
	sum   Summary
	phase Phase
	path  string
}

// New creates a collector writing (atomically, on Flush) to path.
func New(prefix, session, path string) *Collector {
	return &Collector{
		sum: Summary{
			Version: Version,
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

// UpdatePhase applies fn under the collector lock, handing it both the
// summary and the counters of the phase in effect right now. A caller
// that bumps an aggregate and its phase together cannot let the two
// drift, which is the whole guarantee the split rests on.
func (c *Collector) UpdatePhase(fn func(*Summary, *PhaseCounters)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.sum, c.counters(c.phase))
}

// SetPhase moves subsequent accounting into p. It is called once, at the
// instant the payload exits; work already counted stays where it was.
func (c *Collector) SetPhase(p Phase) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.phase == p {
		return
	}
	c.phase = p
	if p == PhaseTeardown {
		c.sum.TeardownBegan = time.Now()
	}
}

// counters returns the block work in p is attributed to. Callers hold mu.
func (c *Collector) counters(p Phase) *PhaseCounters {
	if p == PhaseTeardown {
		return &c.sum.TeardownPhase
	}
	return &c.sum.SessionPhase
}

// opKind selects which pair of counters an operation lands in.
type opKind int

const (
	opGet opKind = iota
	opPut
	opDelete
	opOther
)

// count records one operation against the aggregate AND the phase in
// effect, under a single lock: this sits on the read path of a serving
// mount and on the upload path of a seal, so it must not become two
// lock acquisitions or an allocation.
func (c *Collector) count(k opKind, ops, errs, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ph := c.counters(c.phase)
	var pair [2]*OpCounters
	switch k {
	case opPut:
		pair = [2]*OpCounters{&c.sum.Put, &ph.Put}
	case opDelete:
		pair = [2]*OpCounters{&c.sum.Delete, &ph.Delete}
	case opOther:
		pair = [2]*OpCounters{&c.sum.Other, &ph.Other}
	default:
		pair = [2]*OpCounters{&c.sum.Get, &ph.Get}
	}
	for _, t := range pair {
		t.Ops += ops
		t.Errors += errs
		t.Bytes += bytes
	}
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

// WrapStorage returns an object store that counts every operation into c.
func WrapStorage(inner pelicanobj.ObjectStore, c *Collector) pelicanobj.ObjectStore {
	return &countingStore{ObjectStore: inner, c: c}
}

type countingStore struct {
	pelicanobj.ObjectStore
	c *Collector
}

func (s *countingStore) Get(ctx context.Context, key string, off, limit int64) (io.ReadCloser, error) {
	rc, err := s.ObjectStore.Get(ctx, key, off, limit)
	if err != nil {
		s.c.count(opGet, 1, 1, 0)
		s.c.recordError("get", key, err)
		return nil, err
	}
	s.c.count(opGet, 1, 0, 0)
	return &countingReader{ReadCloser: rc, c: s.c, key: key}, nil
}

// Put attributes the whole transfer to the phase in effect when the
// request RETURNS, not when it started. An upload that straddles the
// boundary is therefore charged to teardown in full — the conservative
// direction, and one that can only misattribute the single upload that
// happened to be in flight when the payload exited.
func (s *countingStore) Put(ctx context.Context, key string, in io.Reader) error {
	cr := &countingInput{Reader: in}
	err := s.ObjectStore.Put(ctx, key, cr)
	if err != nil {
		s.c.count(opPut, 1, 1, cr.n)
		s.c.recordError("put", key, err)
		return err
	}
	s.c.count(opPut, 1, 0, cr.n)
	return nil
}

func (s *countingStore) Delete(ctx context.Context, key string) error {
	err := s.ObjectStore.Delete(ctx, key)
	if err != nil {
		s.c.count(opDelete, 1, 1, 0)
		s.c.recordError("delete", key, err)
		return err
	}
	s.c.count(opDelete, 1, 0, 0)
	return nil
}

func (s *countingStore) Head(ctx context.Context, key string) (*pelicanobj.Object, error) {
	obj, err := s.ObjectStore.Head(ctx, key)
	// Not-found is a routine answer for Head, not a failure.
	if err != nil && !isNotExist(err) {
		s.c.count(opOther, 1, 1, 0)
		s.c.recordError("head", key, err)
		return obj, err
	}
	s.c.count(opOther, 1, 0, 0)
	return obj, err
}

type countingReader struct {
	io.ReadCloser
	c   *Collector
	key string
}

// Read charges bytes to the phase they arrive in, so a stream opened
// before the payload exited and drained afterwards splits across the
// boundary rather than landing wholly on either side.
func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.c.count(opGet, 0, 0, int64(n))
	}
	if err != nil && err != io.EOF {
		r.c.count(opGet, 0, 1, 0)
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
