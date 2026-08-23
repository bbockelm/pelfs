package overlay

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// What `fsync(2)` means on a pelfs mount, and — the part that matters more
// — what it does not.
//
// **It means: recoverable by remounting THIS state directory.** When Sync
// returns, everything the session has written is on the local disk of the
// machine the mount is running on: the ring's mapping is msync'd, the
// operation log that says which file those bytes belong to is fsync'd, and
// the metadata database holding the names, modes and lengths is fsync'd.
// Kill the process, cut the power, reboot: `pelfs mount` over the same
// state directory brings the session back with those writes in it.
//
// **It does NOT mean the data is in the federation.** Nothing here chunks,
// packs, uploads or publishes. A generation reaches the federation at a
// checkpoint or a seal, and the levers for that are `--snapshot-interval`
// and `pelfs ctl publish` — not fsync.
//
// That distinction has a sharp edge and it is worth saying in the plainest
// words available. **An HTCondor job writing to ephemeral scratch gets
// nothing from this.** The state directory dies with the slot: the job is
// evicted, the scratch is wiped, and every byte fsync covered goes with
// it, whether or not fsync returned. An application that calls fsync,
// checks the result, and believes its data is safe is believing something
// true about the wrong machine. What makes a job's output survive eviction
// is a CHECKPOINT — `--snapshot-interval` so one happens on a cadence
// without being asked, or `pelfs ctl publish` at the points the job knows
// are worth keeping. Federation durability is a publish, and it always was.
//
// So why implement it at all, if the case we care most about is the one it
// does not help? Because the alternative was a LIE, and a cheap true
// statement beats a free false one. `Fsync` returned `fuse.OK`
// unconditionally: an application that fsync'd and checked the result was
// told its data was safe when nothing whatsoever had been made durable.
// Now the answer is true, it is bounded (see the coalescing below), and a
// laptop mount — the case where the state directory outlives the process —
// gets exactly the guarantee it asks for.
//
// The federation round trip was considered and rejected: it would make
// every fsync a publish, which for the sqlite-in-a-container workload that
// motivates fsync at all is minutes per call.

// contentSyncer is a content store that can make what it holds durable
// without publishing it. Optional and checked by type assertion, the way
// contentSnapshotter is: a store that cannot answer must stay a usable
// store.
type contentSyncer interface {
	Sync() error
}

// SyncStats is what the durability path cost. It exists because the
// coalescing is a PROMISE — a chatty application's fsync storm must be
// nearly free — and a promise about cost needs a number.
type SyncStats struct {
	// Passes is how many times Sync actually made something durable.
	Passes int64
	// Coalesced is how many calls returned without touching the disk
	// because nothing had changed since the last pass.
	Coalesced int64
	// Fsyncs counts the file syncs those passes performed on THIS
	// overlay's own metadata database and its log. The content side is
	// counted where it is owned, in memtable's Stats(): RingSyncs for the
	// mapping holding the bytes, JournalSyncs for the records naming them.
	// Three numbers rather than one because a Sync that did two of the
	// three would be durable in a shape nothing can recover from, and one
	// total would hide it.
	Fsyncs int64
}

// SyncStats reports what fsync has cost this overlay.
func (fs *FS) SyncStats() SyncStats {
	return SyncStats{
		Passes:    fs.syncPasses.Load(),
		Coalesced: fs.syncCoalesced.Load(),
		Fsyncs:    fs.fsyncs.Load(),
	}
}

// Sync makes this session's state durable on the local disk, in the order
// each layer can only name what the layer under it has already committed:
// the content's bytes, then the journal that says which file they belong
// to, then the metadata that gives that file a name.
//
// THAT ORDER IS THE WHOLE OF WHY IT IS ONE CALL rather than two. The two
// databases in a state directory live under a one-directional rule (see
// contentJournal): the journal may hold entries for inodes the metadata
// never committed, and the metadata may never name content the journal
// lacks. Syncing metadata without the content journal underneath it
// creates exactly the state that rule forbids — a durable name for bytes
// whose record is still in a page cache.
//
// NOTHING IS COALESCED AWAY THE FIRST TIME. `fs.seq` counts mutations for
// this process, so a resumed session starts it at zero with a state
// directory that may hold another session's unsynced work; treating that
// as "already synced" would answer for a machine crash this process never
// witnessed. The first call always does the work.
//
// The filesystem lock is held throughout. An fsync that let writes land
// while it ran would be answering about a moving target, and the databases
// underneath are single-connection and single-writer anyway — a finer lock
// would buy concurrency SQLite refuses to deliver. What keeps that
// affordable is the coalescing, not the lock: the expensive call happens
// once per change, and a fsync storm with nothing between the calls is a
// lock acquisition and a comparison.
func (fs *FS) Sync() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.synced && fs.syncedSeq == fs.seq {
		fs.syncCoalesced.Add(1)
		return nil
	}
	seq := fs.seq
	if cs, ok := fs.content.(contentSyncer); ok {
		if err := cs.Sync(); err != nil {
			return fmt.Errorf("overlay: sync content: %w", err)
		}
	}
	if err := fs.syncDBLocked(filepath.Join(fs.dir, overlayDBName)); err != nil {
		return err
	}
	fs.synced, fs.syncedSeq = true, seq
	fs.syncPasses.Add(1)
	return nil
}

// syncDBLocked forces a SQLite database and its write-ahead log to the
// platter.
//
// The connections run `synchronous=NORMAL`, which is the right default for
// the write path — a WAL commit is durable against this PROCESS dying the
// moment it returns, because the frames are in the kernel's page cache —
// and is exactly what leaves a machine crash able to lose them. This is
// the on-demand version of `synchronous=FULL` for the one caller that asks.
//
// THE DATABASE FILE IS SYNCED BEFORE THE LOG, and the order is not
// arbitrary. A checkpoint copies frames out of the WAL into the database
// and then resets the log; both land in the page cache first. Syncing the
// reset log before the pages it was emptied into would make "the frames
// are no longer in the WAL" durable while "the frames are in the database"
// was not, which loses them. The other order cannot: a durable database
// plus a stale log replays frames it already holds, and replaying a frame
// is idempotent.
func (fs *FS) syncDBLocked(db string) error {
	for _, p := range []string{db, db + "-wal"} {
		if err := syncPath(p); err != nil {
			return fmt.Errorf("overlay: sync %s: %w", filepath.Base(p), err)
		}
		fs.fsyncs.Add(1)
	}
	return nil
}

// syncPath fsyncs one file by path, treating absence as nothing to do.
//
// By path rather than through the open connection because there is no way
// to reach a `database/sql` driver's descriptor, and by a SECOND
// descriptor rather than the driver's because opening one takes no lock
// that SQLite's own locking mode would object to. Absence is ordinary: a
// `-wal` file exists only once a connection has written, and a database
// that has never been committed to has nothing in a log that is not there.
func syncPath(path string) error {
	// O_RDWR rather than O_RDONLY: fsync on a read-only descriptor is
	// permitted on Linux and is what Darwin's F_FULLFSYNC is least happy
	// with, and these are our own files in our own state directory.
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncCounters is the accounting Sync keeps. Separate atomics rather than a
// guarded struct because SyncStats is read from outside the lock — a
// statistic nobody can sample without stopping the mount is not a
// statistic.
type syncCounters struct {
	syncPasses    atomic.Int64
	syncCoalesced atomic.Int64
	fsyncs        atomic.Int64
}
