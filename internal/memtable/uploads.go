package memtable

import (
	"context"
	"sync"

	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// DefaultUploadQueueBytes is how much cut-but-unsent pack data may
// accumulate before packing has to wait for the uplink.
//
// Generous on purpose. The queue exists so that WRITING is paced by local
// disk rather than by the network: a pack is durable the moment its file
// exists, and the ring region it came from can be reclaimed then, so a
// slow uplink should cost a session nothing until the backlog is large
// enough to be a disk problem. A gigabyte is minutes of a home uplink and
// seconds of a fast one, and either way it is bytes already written once.
const DefaultUploadQueueBytes = 1 << 30

// DefaultUploadWorkers is how many packs may be in flight. It covers
// round trips rather than saturating a pipe: on a bandwidth-bound uplink
// extra streams divide the same bandwidth, while on a long-fat path one
// stream is window-limited and cannot fill it alone. Same reasoning, and
// same number, as the publish pipeline.
const DefaultUploadWorkers = 4

// uploadQueue sends packs in the background.
//
// It is what separates "the pack exists" from "the pack has landed", and
// that separation is the whole point. Uploading inside the pack run meant
// the ring could not be reclaimed until bytes were on the wire, so a
// 2 MiB/s uplink stopped the mount for the length of every upload. Here a
// pack run cuts, retains the file locally, and returns; the uplink drains
// the backlog on its own time.
//
// What still waits: a SEAL. A generation that named a pack which never
// left would be signed and unreadable, so publishing drains the queue
// first. That is the right place for the wait — one at the end of a
// session, rather than one per pack throughout it.
type uploadQueue struct {
	obj     pelicanobj.Store
	max     int64
	workers int

	mu      sync.Mutex
	cond    *sync.Cond
	jobs    []uploadJob
	queued  int64 // bytes cut and not yet sent
	running int
	err     error
	closed  bool
	started bool
	wg      sync.WaitGroup
}

type uploadJob struct {
	ctx    context.Context
	pack   packstore.SealedPack
	send   func(context.Context, pelicanobj.Store) error
	done   func(error)
	onSent func(string, int64)
}

func newUploadQueue(obj pelicanobj.Store, max int64, workers int) *uploadQueue {
	q := &uploadQueue{obj: obj, max: max, workers: workers}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// add queues one pack, waiting only when the backlog is already at its
// bound. The wait is the backpressure: it stops a session outrunning its
// uplink by more than the queue allows, and it reaches the writer the
// long way round, through a ring that stops being reclaimed.
func (q *uploadQueue) add(j uploadJob) error {
	q.mu.Lock()
	for q.queued+j.pack.Size > q.max && q.queued > 0 && q.err == nil && !q.closed {
		q.cond.Wait()
	}
	if q.err != nil {
		err := q.err
		q.mu.Unlock()
		return err
	}
	q.queued += j.pack.Size
	q.jobs = append(q.jobs, j)
	q.startLocked()
	q.cond.Broadcast()
	q.mu.Unlock()
	return nil
}

// startLocked spins the workers up on first use, so a store that never
// packs never starts a goroutine.
func (q *uploadQueue) startLocked() {
	if q.started {
		return
	}
	q.started = true
	for i := 0; i < q.workers; i++ {
		q.wg.Go(q.work)
	}
}

func (q *uploadQueue) work() {
	for {
		q.mu.Lock()
		for len(q.jobs) == 0 && !q.closed {
			q.cond.Wait()
		}
		if len(q.jobs) == 0 {
			q.mu.Unlock()
			return
		}
		j := q.jobs[0]
		q.jobs = q.jobs[1:]
		q.running++
		q.mu.Unlock()

		err := j.send(j.ctx, q.obj)

		q.mu.Lock()
		q.running--
		q.queued -= j.pack.Size
		if err != nil && q.err == nil {
			q.err = err
		}
		q.mu.Unlock()
		if err == nil && j.onSent != nil {
			j.onSent(j.pack.Name, j.pack.Size)
		}
		j.done(err)
		q.mu.Lock()
		q.cond.Broadcast()
		q.mu.Unlock()
	}
}

// drain waits for everything queued to land, and reports the first
// failure. A seal calls it; nothing else needs to.
func (q *uploadQueue) drain() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for (len(q.jobs) > 0 || q.running > 0) && q.err == nil {
		q.cond.Wait()
	}
	return q.err
}

// Backlog reports bytes cut and not yet sent, for a session that wants to
// say how far behind its uplink is.
func (q *uploadQueue) backlog() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.queued
}

// close stops the workers once the backlog is gone. It does NOT abandon
// queued packs: their bytes are already accounted for in a location map,
// and a store that dropped them on the way out would leave a session's
// own content unreadable.
func (q *uploadQueue) close() error {
	err := q.drain()
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
	q.wg.Wait()
	return err
}
