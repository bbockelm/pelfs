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
	// LeaseKey is WHICH lease object this session holds:
	// meta/lease-<branch>.json. Reported because the exclusion is
	// per-branch now — "a lease was held" no longer tells a reader whether
	// another writer elsewhere on the volume was possible, and the key
	// does. Empty on a session that took none (read-only, or --no-lease).
	LeaseKey string `json:"lease_key,omitempty"`
	// LeaseInterrupted records that this session's lease OBJECT went missing
	// while the session still held it — it never deleted it, so something
	// else did. It is reported separately from a conflict because the two
	// have different resolutions and only one of them is necessarily bad: an
	// operator clearing what looked like a stale lease and a writer that
	// took the branch, published and released are the same absence, told
	// apart by whether the branch head moved (lease.Fence). This field says
	// the absence happened at all, which is otherwise unrecoverable after
	// the fact.
	LeaseInterrupted bool `json:"lease_interrupted,omitempty"`
	// LeaseRevalidatedAt is when a SYNCHRONOUS lease check last confirmed
	// the lease at seal time, as opposed to the background renewal loop.
	// Non-zero means this session went long enough without renewing — a
	// suspended laptop, a stalled uplink — that a publish had to stop and
	// re-establish that it still held the branch. It is the observable trace
	// of a gap that leaves none otherwise.
	LeaseRevalidatedAt time.Time `json:"lease_revalidated_at,omitempty"`

	// What the mount is serving. Generation is what it serves NOW — with
	// --poll it is the head the last live refresh swapped to, not the one
	// it started on.
	Generation      uint64 `json:"generation,omitempty"`
	Branch          string `json:"branch,omitempty"`
	Tag             string `json:"tag,omitempty"`
	Backend         string `json:"backend,omitempty"`  // fuse or nfs
	Writable        bool   `json:"writable,omitempty"` // --rw: an overlay shadows the generation
	GenerationSwaps int64  `json:"generation_swaps,omitempty"`

	// Prefetch makes whole PACKS local — the unit of transfer, and the
	// unit everything a read needs comes out of. PrefetchPacks is the size
	// of the generation's referenced pack set, PrefetchBytes what that set
	// takes on disk, PrefetchFetchedBytes what this session actually moved
	// (zero when a previous session had already cached it all).
	//
	// It replaced `prefetch_chunks`, which counted decoded chunk files, in
	// the release after v0.1.0: a prefetch no longer decodes anything.
	PrefetchPacks        int64 `json:"prefetch_packs,omitempty"`
	PrefetchBytes        int64 `json:"prefetch_bytes,omitempty"`
	PrefetchFetchedBytes int64 `json:"prefetch_fetched_bytes,omitempty"`
	// PrefetchGraftedChunks and PrefetchGraftedBytes are what the pass
	// could NOT make local because it lives at a graft source rather than
	// in a pack. They are not failures — there is no pack to cache — but
	// they are the exact amount by which "prefetched" falls short of
	// "local", and prefetch_complete is false whenever they are non-zero.
	PrefetchGraftedChunks int64 `json:"prefetch_grafted_chunks,omitempty"`
	PrefetchGraftedBytes  int64 `json:"prefetch_grafted_bytes,omitempty"`

	// ResidentInodes is how many inodes the mount is holding resolved, and
	// ResidencyEvicted how many a residency cap has dropped. The second is
	// zero on every mount that never reached its cap; on a FUSE mount a
	// nonzero value is the explanation for an ESTALE, since there the
	// kernel still believes it holds what was dropped.
	ResidentInodes   int64 `json:"resident_inodes,omitempty"`
	ResidencyEvicted int64 `json:"residency_evicted,omitempty"`

	// Write is the write path's backpressure picture: how far the session
	// is running ahead of its uplink, and whether that has begun to cost
	// writers. Nil on a read-only mount.
	Write *WriteStats `json:"write,omitempty"`

	// Cache is the LOCAL disk this mount is using — the decoded-chunk
	// arena, spilled catalogs, pack trailers, whole packs — against the
	// budget they are held to. Without it "the disk filled up" was unanswerable
	// without attaching to the process, and a cache sitting at its limit
	// with a large eviction count (a working set that does not fit, which
	// costs bandwidth) was indistinguishable from one that simply grew.
	Cache *CacheStats `json:"cache,omitempty"`

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
	// SealedDedupedChunks is chunks the seal did NOT store because the
	// volume already held them. It exists because the seal path is the one
	// that dedups on `--no-memtable`, and until this field the statistics
	// file reported zero for it — the write section is not even written
	// when there is no memtable, so the path that saved 45% of a volume's
	// bytes had no counter anywhere.
	SealedDedupedChunks int64 `json:"sealed_deduped_chunks,omitempty"`
	SealedCatalogs      int64 `json:"sealed_catalogs,omitempty"`
	SealedPacks         int64 `json:"sealed_packs,omitempty"`
	SealOK              *bool `json:"seal_ok,omitempty"`

	// Maintenance is what the background repack and sweep have done in this
	// session. Nil on a mount that runs neither.
	Maintenance *MaintenanceStats `json:"maintenance,omitempty"`

	// Overall verdict for supervisors: true only when unmount, flush/drain,
	// and the final snapshot all succeeded.
	CleanShutdown bool `json:"clean_shutdown"`
	ExitCode      int  `json:"exit_code"`
}

// MaintenanceStats is the background maintenance a writable mount performs
// on its own: repacks, and the sweeps that collect what they condemned.
//
// It exists because those are the two operations with NO natural observer.
// A seal is watched by the person who typed `exit`; a repack and a sweep
// happen while nobody is looking, six hours apart, and the question they
// prompt is asked much later and by someone else: "is this volume being
// maintained, or has it been quietly growing since March?" A log line
// cannot answer that once it has rotated away, so the answer is a
// TIMESTAMP and a COUNTER — the shape a supervisor can alert on.
//
// The two byte figures are deliberately not one number. CondemnedBytes is
// what repacks made collectable; ReclaimedBytes is what sweeps actually
// deleted. A volume where the first grows and the second does not is a
// volume whose collection half has stopped, which is exactly the failure
// this file exists to make visible.
type MaintenanceStats struct {
	Repacks        int64     `json:"repacks,omitempty"`
	LastRepackAt   time.Time `json:"last_repack_at,omitempty"`
	CondemnedBytes int64     `json:"condemned_bytes,omitempty"`

	Collections      int64     `json:"collections,omitempty"`
	LastCollectAt    time.Time `json:"last_gc_at,omitempty"`
	ReclaimedObjects int64     `json:"reclaimed_objects,omitempty"`
	ReclaimedBytes   int64     `json:"reclaimed_bytes,omitempty"`
	// GraceSeconds is the window the last sweep applied — the volume's
	// recorded T_grace. Reported beside the counts because "nothing was
	// reclaimed" and "nothing was old enough yet" are different answers.
	GraceSeconds int64 `json:"grace_seconds,omitempty"`
	// A sweep FAILS CLOSED: an unverifiable ref deletes nothing at all. So
	// a failing sweep looks exactly like a clean one from the outside, and
	// only these two fields distinguish them.
	CollectionFailures  int64  `json:"collection_failures,omitempty"`
	LastCollectionError string `json:"last_collection_error,omitempty"`
}

// WriteStats is what the memtable knows about pressure, published so a
// supervisor — or a person watching a copy get slower — can tell a mount
// that is pacing against its uplink from a mount that has hung. Every
// field here was already counted and was reachable from nowhere: Stats
// had one caller, reading one field.
type WriteStats struct {
	// BlockedWrites counts writes that had to wait for the packer. Nonzero
	// means the session is producing faster than the uplink sends.
	BlockedWrites int64 `json:"blocked_writes"`
	// UploadBacklog is bytes cut into packs and not yet sent — the size of
	// what is behind, where BlockedWrites is only the fact that it is.
	UploadBacklog int64 `json:"upload_backlog"`
	// RingUsed and RingFree are the write buffer, the leading indicator
	// for the two above: a ring at 5% free is about to block.
	RingUsed int64 `json:"ring_used"`
	RingFree int64 `json:"ring_free"`
	// What has actually gone out, for the ratio against the session total.
	Packs          int64 `json:"packs"`
	UploadedBytes  int64 `json:"uploaded_bytes"`
	UploadedChunks int64 `json:"uploaded_chunks"`
	// DedupedChunks is content the store already had a location for, so it
	// was neither encoded nor sent — the part of the write that cost
	// nothing.
	DedupedChunks int64 `json:"deduped_chunks,omitempty"`
	// BaseDedupedChunks and BaseDedupedBytes are the part of DedupedChunks
	// the GENERATION being built on already held, rather than an earlier
	// flush of this session. They are what says a volume is deduplicating
	// across generations — the bytes a related image did not cost — and
	// they were invisible before: the counter above cannot distinguish
	// "this session wrote the same bytes twice" from "the volume already
	// had them", and only the second one is the interesting claim.
	BaseDedupedChunks int64 `json:"base_deduped_chunks,omitempty"`
	BaseDedupedBytes  int64 `json:"base_deduped_bytes,omitempty"`
}

// CacheStats is the local generation cache, per directory, against its
// budget. Directories are named rather than fielded because the cache is
// genfs's to define and this file should not have to be edited when it
// grows a fifth one.
type CacheStats struct {
	Bytes        int64            `json:"bytes"`
	Files        int              `json:"files"`
	Limit        int64            `json:"limit,omitempty"`
	Dirs         map[string]int64 `json:"dirs,omitempty"`
	EvictedFiles int64            `json:"evicted_files,omitempty"`
	EvictedBytes int64            `json:"evicted_bytes,omitempty"`
	Pinned       int              `json:"pinned,omitempty"`

	// ChunkHits and ChunkMisses are the decoded-chunk arena's account of
	// itself: a chunk read served out of the arena, against one that had
	// to be decompressed and decrypted out of a pack again. It is the one
	// number that says whether the arena is the right size for this
	// workload — a low hit rate on a mount that re-reads its tree means
	// the working set does not fit, and a high one on a mount that reads
	// straight through means the arena is buying nothing and its share of
	// the budget would do more good as pack cache.
	ChunkHits   int64 `json:"chunk_hits,omitempty"`
	ChunkMisses int64 `json:"chunk_misses,omitempty"`
}

const maxErrorSamples = 20

// Version is the schema of the JSON document. 2 added the per-phase
// breakdown; every version-1 field kept its name and meaning. 3 is the
// first version that REMOVES keys: prefetch_chunks and cache.dirs.chunks
// went with the per-chunk cache files they counted, replaced by
// prefetch_packs and cache.dirs.arena. A reader that keys off those names
// gets nothing rather than a zero, so it has to be able to tell -- which
// is the whole job of this number, and leaving it at 2 through a removal
// would have made it a lie.
const Version = 3

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
