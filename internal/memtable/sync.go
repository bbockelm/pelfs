package memtable

// What a store can make durable without publishing anything, and what
// that is worth.
//
// A write reaches two places before Write returns: the ring's mapping,
// which holds the BYTES, and the journal, which holds the operation that
// says which file they belong to. Both are cheap because neither is
// forced to the platter — the ring's pages are dirty in the page cache,
// and the journal's SQLite connection runs `synchronous=NORMAL`, which
// syncs its write-ahead log at a checkpoint rather than at a commit. That
// is exactly the right default: a mount is tied to a job, so the crash
// worth surviving is the PROCESS dying, and both of those survive it
// already — the page cache and the WAL belong to the kernel, not to this
// process.
//
// The crash they do not survive is the MACHINE's. A power loss, a hard
// reset, a hypervisor pulling the floor out: dirty pages that were never
// msync'd and WAL frames that were never fsync'd are gone, and the state
// directory comes back describing a session shorter than the one the
// application was told about.
//
// Sync closes that gap on demand, which is what an application's fsync(2)
// is asking for. It is deliberately NOT a flush: nothing is chunked,
// packed or uploaded, and no generation is published. See the contract in
// internal/rawfuse (Fsync) for what that means and, more importantly, for
// what it does not mean on scratch that gets wiped.

// journalSyncer is a Journal that can make what it has recorded durable.
//
// Optional, and checked by type assertion, for the same reason Placer is:
// a journal that cannot answer must stay a usable journal. The in-memory
// one every test uses has nothing to sync, and a store built with no
// journal at all is the prototype's normal shape.
type journalSyncer interface {
	// Sync returns once every operation this journal has accepted would
	// survive the machine losing power.
	Sync() error
}

// Sync makes durable everything this store holds and has not published:
// the ring's mapping first, then the journal's record of the operations
// that named it.
//
// THAT ORDER, and it is the same rule the two databases already live by.
// The journal says "inode 7's bytes at offset 0 are extent 12"; the ring
// is where extent 12 is. A journal made durable ahead of the ring could
// name an extent whose bytes never reached the disk, which is the one
// direction the reconciliation rule forbids (internal/overlay/journal.go).
// The other direction is harmless: ring bytes no journal entry names are
// unreachable, which is to say they are garbage, which is what a ring is
// full of by design.
//
// The store's lock is held across the msync. An fsync that did not stop
// writes to the thing it is syncing would be answering about a moving
// target, and the ring is one mapping shared by every writer — so this is
// the ordinary meaning of fsync applied to the ring rather than a
// coarseness to apologise for. It is also why the coalescing lives above
// this, in the overlay: the cheapest sync is the one that never gets here.
func (s *Store) Sync() error {
	s.mu.Lock()
	if s.ring != nil {
		if err := s.ring.Sync(); err != nil {
			s.mu.Unlock()
			return err
		}
		s.stats.RingSyncs++
	}
	j := s.journal
	s.mu.Unlock()
	js, ok := j.(journalSyncer)
	if !ok {
		return nil
	}
	if err := js.Sync(); err != nil {
		return err
	}
	s.mu.Lock()
	s.stats.JournalSyncs++
	s.mu.Unlock()
	return nil
}
