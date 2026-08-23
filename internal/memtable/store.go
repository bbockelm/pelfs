package memtable

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bbockelm/pelfs/internal/chunkid"
	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// DefaultTableSize is the ring's capacity, and it must be LARGER than the
// promotion distance or aging can never fire: Promotable is
// used - distance, and used cannot exceed the ring. Setting the two equal
// meant nothing was ever packed by age, so the only path that packed was
// the one where a writer had already blocked on a full ring — a mount
// that stops dead for the length of an upload, repeatedly. The gap
// between this and DefaultPromotionDistance is the writer's runway, and a
// check at construction now refuses a configuration without one.
const DefaultTableSize = DefaultRingSize

// DefaultPackTarget is the cut size for packs this store writes. It is
// the FORMAT's cut size (publish's target), not the ring's size: a reader
// fetches packs whole, and a pack is not reclaimable — nor readable —
// until the whole of it has landed. Cutting at the ring's size made every
// upload a 64 MiB monolith, which on a home uplink is half a minute
// during which the ring cannot drain and the mount cannot write.
const DefaultPackTarget = 2 << 20

// Options configures a Store.
type Options struct {
	// Dir is the state directory holding buffer files.
	Dir string
	// TableSize is the ring's capacity in bytes, headers included.
	TableSize int
	// PackTarget is the size packs are cut at. Zero takes
	// DefaultPackTarget.
	PackTarget int64
	// PackCacheDir is where the local copy of packs lives. Empty puts it
	// under Dir, which is right for a test and wrong for a mount: Dir is
	// session state, retired with the generation it described, and a pack
	// cache outlives both.
	PackCacheDir string
	// UploadQueueBytes bounds how much cut-but-unsent pack data may
	// accumulate before packing waits for the uplink. Zero takes
	// DefaultUploadQueueBytes; the bound wants to be generous, because
	// what it buys by being small is nothing a session benefits from.
	UploadQueueBytes int64
	// UploadWorkers is how many packs may be in flight at once. Zero takes
	// DefaultUploadWorkers.
	UploadWorkers int
	// PromotionDistance is how far behind the head an extent must fall
	// before the packer takes it. Zero packs whatever is there, which is
	// what a flush wants; DefaultPromotionDistance is what a session
	// wants, so churn has a chance to die before anything is sent.
	PromotionDistance uint64
	// Obj is the federation. Flushes upload packs to packs/<name>.
	Obj pelicanobj.Store
	// Journal records what a crash must not lose (journal.go). Nil means
	// this store's content does not survive one, which is what the
	// prototype and most tests want.
	Journal Journal
	// Base is the immutable generation this store's content sits over.
	// Without it a file the session did not create cannot be adopted, and
	// the caller must supply its bytes.
	Base Base
	// PackCacheBytes bounds the local copy of packs (see packCache). Zero
	// takes DefaultPackCacheBytes; PackCacheDisabled turns it off, which
	// makes every read of packed content a federation round trip.
	PackCacheBytes int64
	// Chunk configures the CDC pass. Zero fields take chunkid's defaults.
	Chunk chunkid.Options
	// Hasher binds chunk identity (keyed for encrypted volumes).
	Hasher chunkid.Hasher
	// DEK encrypts pack entries (AES-256-GCM); nil stores them in the
	// clear. KeyID names it in the superblock's key table, and travels in
	// every chunkref this store writes.
	DEK   []byte
	KeyID int64
	// OnUpload is called once per pack this store sends, from the packing
	// goroutine. A session that packs as it writes is otherwise silent for
	// minutes at a time, and silence during a slow upload is
	// indistinguishable from a stall — which is exactly how it was read.
	OnUpload func(pack string, bytes int64, elapsed time.Duration)
	// Hooks are test seams; all fields may be nil.
	Hooks Hooks
}

// Hooks let a test observe the inside of a flush, which is the only way
// to assert on states that exist for microseconds in production — a pack
// uploaded but its locations not yet published, for instance.
type Hooks struct {
	// FlushStarted runs on the flusher goroutine once the live set has
	// been snapshotted and before any chunking.
	FlushStarted func(seq uint64)
	// BeforePublish runs after every pack of a flush is durable and
	// before any location is installed. Returning an error aborts the
	// flush there, simulating a crash in that window.
	BeforePublish func(seq uint64) error
}

// Stats is what the prototype is for. Every field is a count the design
// makes a claim about.
type Stats struct {
	WrittenBytes int64 // bytes handed to Write
	Extents      int64 // extents appended
	Flushes      int64
	// DeadExtents and DeadBytes are extents that were wholly superseded
	// before their table flushed and therefore never left the machine.
	DeadExtents int64
	DeadBytes   int64
	// UploadedBytes counts pack entry bytes actually sent, trailers
	// excluded, so it compares directly against WrittenBytes.
	UploadedBytes  int64
	UploadedChunks int64
	// DedupedChunks counts chunks a flush or a seal produced whose bytes
	// the store already had a location for, so they were neither encoded
	// nor sent. Repeats inside one pack run were always free; this is the
	// CROSS-flush case, and it is the one that costs real bytes on a tree
	// where the same content arrives under several names.
	DedupedChunks int64
	// BaseDedupedChunks and BaseDedupedBytes are the part of DedupedChunks
	// that the GENERATION this session builds on already had — dedup that
	// reaches across generations rather than across flushes. They are
	// counted separately because they are the answer to a different
	// question: the cross-flush number says a session wrote the same bytes
	// twice, and this one says the volume already held them, which is what
	// makes a related image cost a fraction of its size.
	BaseDedupedChunks int64
	BaseDedupedBytes  int64
	Packs             int64
	// ReclaimErrors counts ring regions a completed pack could not
	// release. That costs space, never correctness, so it is a statistic
	// rather than a failure.
	ReclaimErrors int64
	// RechunkedSpans and RechunkedBytes count what a seal could not
	// express as whole chunks and had to chunk again (see Sealer). They
	// are the price of keeping "whole chunks, end to end" in the format,
	// and the claim they check is that it is proportional to the REWRITE
	// rather than to the file.
	RechunkedSpans int64
	RechunkedBytes int64
	// BlockedWrites counts writes that had to wait for a flush to finish
	// — the backpressure rule firing.
	BlockedWrites int64
	// LostHandles counts extents a recovery could not find. Nonzero means
	// data loss and the caller must say so out loud.
	LostHandles int64
	// AdoptedFiles and AdoptedBytes count files taken over from the base
	// generation by REFERENCE — the operation the staging store performs
	// by copying the whole file. AdoptedInline and AdoptedByReading count
	// the two shapes that still have to move bytes; if either ever
	// approaches AdoptedFiles, the saving has quietly stopped happening.
	AdoptedFiles     int64
	AdoptedBytes     int64
	AdoptedInline    int64
	AdoptedByReading int64
	// DroppedAdoptions counts adopted handles a RECOVERY found in the
	// journal that no surviving content row named — the residue a
	// checkpoint leaves when it publishes an adopted file and rebases the
	// inode clean. It is not loss, and it is counted because recovery used
	// to refuse to start over one.
	DroppedAdoptions int64
	// UploadBacklog is bytes cut into packs and not yet sent. It is the
	// measure of how far a session is running ahead of its uplink, and
	// the thing that eventually applies backpressure.
	UploadBacklog int64
	// PackReadsLocal and PackReadsRemote split reads of packed content by
	// where the bytes came from. The claim they check is the one that
	// decides whether staging can go away: content this session wrote
	// stays readable — and re-chunkable at seal — without the network.
	PackReadsLocal  int64
	PackReadsRemote int64
	// RingUsed and RingFree are the write buffer itself: how much a writer
	// may still append before it must wait for the packer. They are the
	// leading indicator BlockedWrites is the lagging one for — a ring
	// running at 5% free is a session about to pace against its uplink,
	// and until both were reportable neither was visible from outside the
	// process.
	RingUsed int64
	RingFree int64
	// RingSyncs counts msyncs of the ring's mapping — the durable half of
	// an application's fsync(2), which is a cost that exists only when
	// something asked for it. It is here so the COALESCING above it is
	// checkable: a chatty application that fsyncs after every write with
	// nothing between the calls has to leave this number alone (see
	// Store.Sync, and Sync in internal/overlay).
	RingSyncs int64
	// JournalSyncs counts the same thing one layer up: how many times the
	// journal was asked to make its records durable. Separate from
	// RingSyncs because they answer different halves of a file — where the
	// bytes are, and which file they belong to — and a Sync that did one
	// and not the other would be durable in a shape nothing can recover.
	JournalSyncs int64
}

// noteBaseHitLocked records that a chunk was borrowed from generation gen
// of the base. The OLDEST wins: a session that borrowed before a repack
// and again after it has to recheck the older ones, and one number that
// errs toward rechecking is worth more than a map that errs toward not.
func (s *Store) noteBaseHitLocked(gen uint64) {
	if gen == 0 {
		// A placer that cannot name its generation cannot be trusted to
		// say the base has not moved.
		s.baseRecheckAll = true
		return
	}
	if s.baseHitGen == 0 || gen < s.baseHitGen {
		s.baseHitGen = gen
	}
}

// needsBaseRecheckLocked reports whether a seal has to confirm the chunks
// it borrowed from the base generation are still stored there.
func (s *Store) needsBaseRecheckLocked() bool {
	if s.placer == nil {
		return false
	}
	if s.baseRecheckAll {
		return true
	}
	return s.baseHitGen != 0 && s.placer.Generation() != s.baseHitGen
}

// asPlacer takes the cross-generation dedup lookup off a Base that has
// one. A Base that does not is not a lesser Base: correctness never
// depends on the lookup, since a miss only ever costs a duplicate upload
// (see Placer).
//
// The nil check is on the interface's dynamic value as well as the
// interface, because a Store built with no base at all holds a nil Base
// and a type assertion on that succeeds for nobody — but a caller passing
// a typed nil would otherwise install a placer that panics on first use.
func asPlacer(b Base) Placer {
	if b == nil {
		return nil
	}
	p, ok := b.(Placer)
	if !ok || p == nil {
		return nil
	}
	return p
}

// Store is the write path: one active memtable, at most one flushing
// memtable, and a location map naming what has reached the federation.
type Store struct {
	dir        string
	tableSize  int
	packTarget int64
	// promoteAt is how many aged bytes must accumulate before the write
	// path starts a run. It is a pack's worth, so that a batch is worth an
	// object to the federation, capped at half the runway between the
	// promotion distance and the ring's size — a threshold larger than the
	// runway could never be reached by aging, and packing would fall back
	// to the blocked-writer path this whole mechanism exists to avoid.
	promoteAt int64
	obj       pelicanobj.Store
	chunkOpts chunkid.Options
	hasher    chunkid.Hasher
	hooks     Hooks

	// promotion is how far behind the head an extent must fall before it
	// is packed. Zero means pack everything, which is what a flush asks
	// for.
	promotion uint64

	mu   sync.Mutex
	cond *sync.Cond

	// ring is the whole write buffer. There is no active/frozen pair: a
	// writer appends at the head while the packer consumes the tail, and
	// the region a pack covered is reclaimed as soon as its locations are
	// published.
	ring  *Ring
	index map[Handle]Record // handle -> its record, position absolute
	live  map[Handle]int    // content references per handle
	order []Handle          // handles in ring order, oldest first

	journal Journal
	base    Base
	// placer is base again, when it can answer where a chunk the base
	// generation holds is stored — the cross-generation dedup lookup. Nil
	// for a base that cannot, which changes nothing except that a chunk
	// the volume already holds is stored a second time.
	placer Placer
	// baseHitGen is the OLDEST base generation any chunk in chunkLoc was
	// borrowed from, or zero if none was. It is the whole of what a seal
	// needs to know whether its borrowed rows are still good: the base
	// only moves under a repack, and a repack is the only thing that can
	// stop a stored chunk being stored (Sealer.stillStored).
	baseHitGen uint64
	// baseRecheckAll forces that check regardless. Recovery sets it: a
	// journal records WHERE a chunk is and not which generation put it
	// there, so a replayed session that holds borrowed locations cannot
	// say whether the base has moved under them and must assume it has.
	baseRecheckAll bool
	// truncated is what a recovery cut back, kept for the caller that has
	// to apply the same cut to the overlay's node lengths. Nil in every
	// store that was not recovered.
	truncated []Truncation
	dek       []byte
	keyID     int64
	onUpload  func(string, int64, time.Duration)
	// baseRefs holds, per ADOPTED handle, the base generation's own
	// content records for that file (base.go). An extent is either these,
	// or a ring record, or a location-map entry — the three places bytes
	// can be, resolved in one place each.
	baseRefs map[Handle]baseExtent

	// cache is the local copy of packs this session wrote or read. It is
	// what lets a seal re-chunk a rewrite without fetching back bytes it
	// uploaded minutes ago.
	cache *packCache
	// uploads carries finished packs to the federation in the background,
	// so a pack run ends when the pack EXISTS rather than when it lands
	// (uploads.go).
	uploads *uploadQueue

	packing bool // a pack run is in flight
	// reclaimTo is the furthest position a completed pack has asked the
	// tail to reach. It is remembered because a reader's pin can hold the
	// tail short of it, and nothing else would ever try again — a writer
	// waiting for exactly that space would wait forever.
	reclaimTo uint64
	// locating is the published batches whose Located record is not yet
	// durable, in the order they were cut. Their ring regions may not be
	// reclaimed: until that record lands the ring is the only place
	// recovery could find those extents, and the operation log has already
	// made the files' LENGTHS durable — so a reclaim here is exactly the
	// batch-sized loss KL-10 described.
	//
	// A slice rather than a counter because a batch's region can only be
	// released as part of the PREFIX at the tail — a ring reclaims to a
	// position, not a set — and uploads finish out of order with four
	// workers in flight. It is bounded by the number of flushes that can
	// be published and unjournalled at once, which is the runway divided
	// by the pack target: single digits at the shipped sizes, and never a
	// function of the tree.
	locating []locating
	// locateStuck records that a Located record FAILED. The tail may never
	// pass the region that record was going to describe, so no later batch
	// may be reclaimed either, and the store says so rather than quietly
	// reopening the window.
	locateStuck bool
	flushErr    error

	nextHandle Handle
	nextSeq    uint64

	// content stands in for the overlay's ocontent rows. Nothing here is
	// rewritten by a flush; that is the property the design rests on, and
	// keeping it in one place makes it checkable.
	content map[uint64]*content

	// The two halves of the location map. A handle resolves to slices of
	// chunks; a chunk resolves to a place in a pack. Both bind at flush,
	// and neither touches a content row.
	//
	// The two halves have different LIFETIMES, and the difference is not
	// arbitrary. handleLoc answers "where are this extent's bytes", which
	// only a content row can ask, so an entry no row names is unreachable
	// and goes (locRefs). chunkLoc answers "where is this chunk", which
	// the seal's multi-pack index and the cross-flush dedup check both ask
	// about chunks NO current row names — that is the entire point of
	// them — so it is kept for the life of the store and bounded by the
	// distinct chunks a session writes rather than by its write calls.
	handleLoc map[Handle][]ChunkSlice
	chunkLoc  map[string]PackLoc
	// locRefs counts content references to a PUBLISHED handle, so its
	// location entry can be dropped when the last one goes. Without it
	// handleLoc grew with WRITE CALLS for the life of a session — ~100-150
	// MB per million files — including for files a checkpoint had already
	// published and the overlay had already forgotten.
	locRefs map[Handle]int
	packs   []packstore.SealedPack

	stats  Stats
	closed bool
	wg     sync.WaitGroup
}

// ChunkSlice maps part of an extent to part of a chunk. An extent's
// slices are ordered and cover it exactly: CDC boundaries are chosen from
// content, so they do not respect extent boundaries in either direction.
type ChunkSlice struct {
	ID       chunkid.Identity
	ChunkOff int // where in the chunk the extent's bytes start
	Length   int
}

// PackLoc is where a chunk landed AND how it was stored: the second half
// of the location map, reachable from the superblock's pack list through
// pack trailers.
//
// Stored and Logical differ the moment a chunk is compressed, and the
// pair is what a catalog row carries too (CLen and LLen). Carrying both
// here rather than one length is what lets a chunk be compressed and
// encrypted on the way into a pack — and it is why a read fetches whole
// chunks: a range inside a compressed, sealed entry means nothing.
type PackLoc struct {
	Pack    string
	Off     int64
	Stored  int64 // bytes in the pack
	Logical int64 // bytes after decoding
	Alg     uint8 // entrycodec compression id
	KeyID   int64 // superblock key table id, 0 for plaintext
}

func bufferName(seq uint64) string { return fmt.Sprintf("mem-%06d.buf", seq) }

// New creates a store in dir. An existing state directory is NOT
// recovered here; use Recover, which reports what it could not find.
func New(opts Options) (*Store, error) {
	s, err := newStore(opts)
	if err != nil {
		return nil, err
	}
	if err := s.openActive(); err != nil {
		return nil, err
	}
	return s, nil
}

func newStore(opts Options) (*Store, error) {
	if opts.TableSize == 0 {
		opts.TableSize = DefaultTableSize
	}
	if opts.PackTarget == 0 {
		opts.PackTarget = DefaultPackTarget
	}
	if opts.UploadQueueBytes == 0 {
		opts.UploadQueueBytes = DefaultUploadQueueBytes
	}
	if opts.UploadWorkers == 0 {
		opts.UploadWorkers = DefaultUploadWorkers
	}
	// A promotion distance at or above the ring's size is not a tuning
	// choice, it is a store that never ages anything out: every pack run
	// would start from a writer that has already stopped. The record cap
	// bounds how much a single append can consume of what is left, so the
	// runway has to clear it.
	if runway := int64(opts.TableSize) - int64(opts.PromotionDistance); opts.PromotionDistance > 0 &&
		runway <= int64(MaxRecord(opts.TableSize)) {
		return nil, fmt.Errorf("memtable: a %d-byte ring with a %d-byte promotion distance leaves %d bytes "+
			"of runway, under the %d-byte record cap: packing would only ever start from a blocked writer",
			opts.TableSize, opts.PromotionDistance, runway, MaxRecord(opts.TableSize))
	}
	if opts.TableSize <= recordHeader {
		return nil, fmt.Errorf("memtable: table size %d leaves no room for a record", opts.TableSize)
	}
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, err
	}
	if opts.PackCacheBytes == 0 {
		opts.PackCacheBytes = DefaultPackCacheBytes
	}
	s := &Store{
		dir:        opts.Dir,
		tableSize:  opts.TableSize,
		promotion:  opts.PromotionDistance,
		packTarget: opts.PackTarget,
		index:      make(map[Handle]Record),
		live:       make(map[Handle]int),
		base:       opts.Base,
		placer:     asPlacer(opts.Base),
		journal:    opts.Journal,
		dek:        opts.DEK,
		keyID:      opts.KeyID,
		baseRefs:   make(map[Handle]baseExtent),
		obj:        opts.Obj,
		chunkOpts:  opts.Chunk,
		hasher:     opts.Hasher,
		hooks:      opts.Hooks,
		content:    make(map[uint64]*content),
		handleLoc:  make(map[Handle][]ChunkSlice),
		chunkLoc:   make(map[string]PackLoc),
		locRefs:    make(map[Handle]int),
	}
	s.promoteAt = s.packTarget
	if runway := int64(opts.TableSize) - int64(opts.PromotionDistance); runway > 0 && s.promoteAt > runway/2 {
		s.promoteAt = runway / 2
	}
	s.cond = sync.NewCond(&s.mu)
	s.uploads = newUploadQueue(opts.Obj, opts.UploadQueueBytes, opts.UploadWorkers)
	if opts.PackCacheBytes > 0 {
		cacheDir := opts.PackCacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(opts.Dir, "packs")
		}
		c, err := newPackCache(cacheDir, opts.PackCacheBytes)
		if err != nil {
			return nil, err
		}
		s.cache = c
	}
	return s, nil
}

func (s *Store) openActive() error {
	r, err := CreateRing(filepath.Join(s.dir, bufferName(s.nextSeq)), s.tableSize)
	if err != nil {
		return err
	}
	s.nextSeq++
	s.ring = r
	return nil
}

// maxPayload is the largest single record. A write longer than this is
// split, which the write path must do regardless because one write() can
// be arbitrarily large — and the ring refuses an oversized record with a
// distinct error precisely so a caller cannot mistake it for something
// waiting will fix.
func (s *Store) maxPayload() int { return MaxRecord(s.tableSize) }

// Write appends p at off in ino. It blocks only when the ring has no room
// and the packer has not yet freed any — the design's backpressure rule,
// and the only place a write waits on the network.
func (s *Store) Write(ctx context.Context, ino uint64, off int64, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("memtable: store is closed")
	}
	for len(p) > 0 {
		n := min(len(p), s.maxPayload())
		h := s.nextHandle
		rec := Record{Handle: h, Inode: ino, FileOff: off}
		pos, err := s.appendLocked(ctx, &rec, p[:n])
		if err != nil {
			return err
		}
		s.nextHandle++
		rec.Off = int(pos)
		rec.Length = n
		s.index[h] = rec
		s.order = append(s.order, h)
		s.live[h]++
		s.applyLocked(s.contentFor(ino).place(off, n, h))
		if err := s.journalLocked(JournalEntry{
			Op: OpPlace, Inode: ino, Handle: h, Off: off, Length: int64(n),
		}); err != nil {
			return err
		}
		s.stats.WrittenBytes += int64(n)
		s.stats.Extents++
		off += int64(n)
		p = p[n:]
	}
	// Promotion by AGE, checked on the write that made something old
	// rather than on a timer: an extent more than PromotionDistance behind
	// the head has survived long enough that rewriting it is unlikely, so
	// it is packed and sent. Doing it here is what keeps the uplink busy
	// during a session instead of leaving the whole cost to the seal, and
	// it is what the runway between the distance and the ring's size buys
	// — packing starts while the writer still has room.
	//
	// A run starts only once a PACK'S WORTH has aged, never the moment
	// anything has. Promotable is used-distance, so a run leaves the
	// residue at zero and the very next write makes it exactly that
	// write's size: triggering on "anything" cut ONE BATCH PER WRITE.
	// A kernel untar against a real federation turned into 5,105
	// concurrent flushes of 3-6 KiB each, every one a 7-second round
	// trip, and a seal that should have moved 1.7 GB moved 25 MB in two
	// minutes. Federation cost is per OBJECT before it is per byte, so a
	// batch has to be worth an object.
	if s.promotion > 0 && !s.packing && int64(s.ring.Promotable(s.promotion)) >= s.promoteAt {
		s.startPackLocked(ctx, s.promotion)
	}
	return nil
}

// appendLocked puts one record in the ring, waiting for the packer when
// there is no room. This is the backpressure rule and the only place a
// write waits: the ring refusing an append IS the signal, and it is
// gradual rather than a cliff because the tail advances continuously
// instead of in whole-table steps.
func (s *Store) appendLocked(ctx context.Context, rec *Record, payload []byte) (uint64, error) {
	waited := false
	for {
		pos, err := s.ring.Append(rec, payload)
		if err == nil {
			return pos, nil
		}
		if !errors.Is(err, ErrRingFull) {
			// ErrRecordTooLarge and friends are not waitable. Returning
			// here rather than looping is what stops a writer spinning
			// forever on something no packer can fix.
			return 0, err
		}
		if s.flushErr != nil {
			return 0, s.flushErr
		}
		if !s.packing {
			// Nothing is draining the ring, so start a run that takes
			// everything: waiting on a packer that was never launched is
			// the deadlock this branch exists to prevent.
			s.startPackLocked(ctx, 0)
		}
		if !waited {
			// Counted before the wait, not after: a caller watching for
			// backpressure needs to see it while it is happening.
			waited = true
			s.stats.BlockedWrites++
			// And SAID, once, because a counter nobody reads is not
			// visibility. A mount whose writes have started pacing against
			// the uplink looks exactly like a mount that has hung, and
			// this is the only place that knows the difference.
			reportBlockedWrite(s.uploads.backlog())
		}
		s.cond.Wait()
		if s.closed {
			return 0, errors.New("memtable: store is closed")
		}
	}
}

// Truncate resizes ino, dropping content past the new size.
func (s *Store) Truncate(ino uint64, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := make(map[Handle]int)
	s.contentFor(ino).truncate(size, dropped)
	s.applyLocked(dropped)
	return s.journalLocked(JournalEntry{Op: OpTruncate, Inode: ino, Length: size})
}

// Forget drops an inode's content map. Its extents lose their last
// reference, which is exactly what happens when a write supersedes one:
// an extent still in the ring dies there and is never uploaded, and one
// already in a pack becomes garbage for a repack to sweep.
//
// What it does to the location map is exactly one thing: it releases the
// last reference to a published HANDLE, whose slice list then goes,
// because nothing can ask for it any more — only a content row can name a
// handle. Everything the old rule was protecting is untouched. The chunk
// half of the map stays, so the seal's multi-pack index still covers every
// chunk this session placed and cross-flush dedup still recognizes bytes
// it has already sent; the packs stay; and a catalog row in an earlier
// generation still names the same chunks, because retention — not a file
// being deleted in a session that has not sealed yet — is what decides
// when those packs go.
func (s *Store) Forget(ino uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.content[ino]
	if !ok {
		return nil
	}
	dropped := make(map[Handle]int)
	c.punch(0, c.size, dropped)
	s.applyLocked(dropped)
	delete(s.content, ino)
	return s.journalLocked(JournalEntry{Op: OpForget, Inode: ino})
}

// Size reports ino's current length.
func (s *Store) Size(ino uint64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.content[ino]; ok {
		return c.size
	}
	return 0
}

func (s *Store) contentFor(ino uint64) *content {
	c, ok := s.content[ino]
	if !ok {
		c = &content{}
		s.content[ino] = c
	}
	return c
}

// place inserts an extent and returns the reference-count deltas.
func (c *content) place(off int64, length int, h Handle) map[Handle]int {
	d := make(map[Handle]int)
	c.insert(off, length, h, d)
	return d
}

// applyLocked pushes reference-count deltas onto the three kinds of handle
// that have local state to lose: ring records, extents adopted from the
// base, and PUBLISHED extents, whose location entry is state too — the
// bytes in the pack are a repack's problem, but the map entry naming them
// is this store's, and nothing can reach it once no content row names it.
//
// This is the ONLY place any of the three counts moves, which is what
// makes it reachable from every path that can drop a reference: a write
// that supersedes, a truncate, a Forget, an Adopt over an existing body,
// and a frozen view being released.
func (s *Store) applyLocked(d map[Handle]int) {
	for h, delta := range d {
		if _, ok := s.index[h]; ok {
			s.live[h] += delta
			if s.live[h] <= 0 {
				delete(s.live, h)
			}
			continue
		}
		if _, ok := s.handleLoc[h]; ok {
			s.locRefs[h] += delta
			if s.locRefs[h] <= 0 {
				// Nothing names the extent, here or in any frozen view, so
				// nothing can resolve through it: a handle is reachable
				// only from a content row. The slice list goes; the chunks
				// it named, their locations, and the packs holding them all
				// stay exactly where they were.
				delete(s.locRefs, h)
				delete(s.handleLoc, h)
			}
			continue
		}
		if be, ok := s.baseRefs[h]; ok {
			be.nrefs += delta
			if be.nrefs <= 0 {
				// Nothing names the handle any more, in the live map or in
				// any frozen view — those count their copies here too. What
				// goes is only this store's note that it borrowed the base's
				// records; the base still holds them, and a catalog row in
				// an earlier generation still names the same chunks.
				delete(s.baseRefs, h)
				continue
			}
			s.baseRefs[h] = be
		}
	}
}

// cutLocked takes the records at the tail that are old enough to pack.
// distance is how far behind the head an extent must fall; zero takes
// everything, which is what a flush asks for.
//
// It is a decision, not a copy: the records stay exactly where they are
// in the ring until their locations are published, because until then the
// ring is the only place they exist.
func (s *Store) cutLocked(distance uint64) *batch {
	_, to := s.ring.PromotableRange(distance)
	if distance == 0 {
		to = s.ring.Head()
	}
	b := &batch{
		seq:    s.nextSeq,
		live:   make(map[Handle]int),
		inodes: make(map[uint64]struct{}),
		from:   s.ring.Tail(),
		to:     to,
	}
	s.nextSeq++
	for _, h := range s.order {
		rec, ok := s.index[h]
		if !ok {
			continue
		}
		end := uint64(rec.Off) + uint64(ringRecHdr) + uint64(rec.Length)
		if end > to {
			break // ring order: everything after this is younger still
		}
		b.recs = append(b.recs, rec)
		b.inodes[rec.Inode] = struct{}{}
		if n := s.live[h]; n > 0 {
			b.live[h] = n
		}
	}
	if len(b.recs) > 0 {
		last := b.recs[len(b.recs)-1]
		b.to = uint64(last.Off) + uint64(ringRecHdr) + uint64(last.Length)
	}
	return b
}

// locating is one published batch waiting on its Located record.
type locating struct {
	seq uint64
	// to is the ring position the batch consumed up to — what reclaimTo
	// may advance to once this batch's record is durable.
	to   uint64
	done bool
}

// locatedLocked settles one published batch: its Located record either
// landed (err nil) or did not, and the ring's tail moves accordingly.
//
// Only a PREFIX is released, because that is the only thing a ring can
// release. Uploads finish out of order — four workers — so batch 7's
// record can land before batch 6's, and reclaiming to 7's end would free
// 6's region as well. So a batch is marked done and the tail advances over
// however many done batches now sit at the front.
func (s *Store) locatedLocked(seq uint64, err error) {
	for i := range s.locating {
		if s.locating[i].seq != seq {
			continue
		}
		if err != nil {
			// The record is not durable, so this region stays the only
			// place these extents exist and the tail must never pass it.
			// The entry leaves the queue anyway: a Flush waiting on it has
			// to see the error rather than wait for a record that is not
			// coming.
			s.locating = append(s.locating[:i], s.locating[i+1:]...)
			s.locateStuck = true
		} else {
			s.locating[i].done = true
		}
		break
	}
	n := 0
	for !s.locateStuck && n < len(s.locating) && s.locating[n].done {
		if s.locating[n].to > s.reclaimTo {
			s.reclaimTo = s.locating[n].to
		}
		n++
	}
	s.locating = s.locating[n:]
	s.releaseLocked()
	// Broadcast even when nothing was reclaimed. A Flush waits for this
	// queue to drain, and a blocked writer waits for space that a pin may
	// have held back — both have to be woken by the record landing, not
	// only by the tail moving.
	s.cond.Broadcast()
}

// releaseLocked retries a reclaim a pin held off, and wakes anyone
// waiting for the space. Reclaim clamps to the oldest pin rather than
// failing, so a pack that published while a read was in flight leaves the
// tail short of where its bytes actually died; this is the only thing
// that ever picks that up again.
func (s *Store) releaseLocked() {
	if s.ring == nil || s.reclaimTo <= s.ring.Tail() {
		return
	}
	if _, err := s.ring.Reclaim(s.reclaimTo); err != nil {
		s.stats.ReclaimErrors++
		return
	}
	s.cond.Broadcast()
}

// startPackLocked launches a pack run over whatever is old enough.
func (s *Store) startPackLocked(ctx context.Context, distance uint64) {
	if s.packing {
		return
	}
	b := s.cutLocked(distance)
	if b.empty() {
		return
	}
	s.packing = true
	s.stats.Flushes++
	s.wg.Go(func() { s.runFlush(ctx, b) })
}

// Flush packs everything in the ring and waits for it to land. This
// is what a checkpoint or a seal calls, and it is the only user-visible
// operation that blocks on the network by design.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed pack left its records in the ring and still authoritative.
	// Retrying is the recovery; discarding would lose them.
	s.flushErr = nil
	for {
		if err := s.waitPackLocked(); err != nil {
			return err
		}
		// And for the Located records of everything already published.
		// A flush means "on the federation, and recorded": the batch's
		// ring region is not reclaimed until its record is durable, so
		// without this wait the ring would still look occupied, the loop
		// below would cut an empty batch, and Flush would return having
		// drained neither the uplink nor the journal.
		if err := s.waitLocatedLocked(); err != nil {
			return err
		}
		if s.ring == nil || s.ring.Used() == 0 {
			// Packing is done; the uplink may not be. A flush is what a
			// checkpoint and a seal call, and both mean "on the
			// federation", not "in a local pack".
			s.mu.Unlock()
			err := s.uploads.drain()
			s.mu.Lock()
			return err
		}
		s.startPackLocked(ctx, 0)
		if !s.packing {
			// Nothing was eligible and nothing is running: the ring holds
			// only records no content row references any more.
			return nil
		}
	}
}

// waitPackLocked waits for any pack run in flight.
func (s *Store) waitPackLocked() error {
	for s.packing {
		if s.flushErr != nil {
			return s.flushErr
		}
		s.cond.Wait()
	}
	return s.flushErr
}

// waitLocatedLocked waits for every published batch's Located record.
func (s *Store) waitLocatedLocked() error {
	for len(s.locating) > 0 {
		if s.flushErr != nil {
			return s.flushErr
		}
		s.cond.Wait()
	}
	return s.flushErr
}

// CacheAdopted reports the packs already on local disk when this store
// opened — content it can read without the federation.
func (s *Store) CacheAdopted() (packs int, bytes int64) {
	if s.cache == nil {
		return 0, 0
	}
	return s.cache.adopted()
}

// EachPlacedChunk reports every chunk this store has placed and the pack
// holding it, so a seal can fold them into the generation's multi-pack
// index.
//
// Without this the index covers only what the SEAL packed — catalogs,
// shards, the superblock backup — and misses every content chunk, which
// on a writable mount is nearly all of it. A reader would then find the
// index answering for catalogs and falling back to per-pack trailers for
// data, which is most of the round trips the index exists to remove.
func (s *Store) EachPlacedChunk(fn func(identityHex, pack string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, loc := range s.chunkLoc {
		fn(id, loc.Pack)
	}
}

// Packs returns the packs this store has uploaded, for a superblock's
// pack list.
func (s *Store) Packs() []packstore.SealedPack {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]packstore.SealedPack(nil), s.packs...)
}

// Stats returns a snapshot of the counters.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	st := s.stats
	if s.ring != nil {
		st.RingUsed = int64(s.ring.Used())
		st.RingFree = int64(s.ring.Free())
	}
	s.mu.Unlock()
	st.UploadBacklog = s.uploads.backlog()
	return st
}

// Close waits for in-flight flushes and unmaps everything. It does NOT
// flush: a caller that wants its bytes in the federation calls Flush
// first, and one that is discarding a failed job should not pay for an
// upload on the way out.
//
// Callers must have quiesced their readers. Close unmaps regardless of
// pins, because the alternative is a lifecycle call that can block
// forever on a stuck read, and a mount that has finished serving has
// nobody left to protect.
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.ring != nil {
		err = s.ring.Close()
		s.ring = nil
	}
	// The queue is closed last and not abandoned: packs in it are already
	// named by a location map, so dropping them would leave a session's
	// own content unreadable.
	if cerr := s.uploads.close(); err == nil {
		err = cerr
	}
	return err
}

// source is where a range of bytes lives right now. It is produced under
// the store's lock and consumed outside it. A ring source holds a PIN on
// its position, because immutable bytes are still bytes the writer gets
// handed back the moment the tail passes them.
type source struct {
	ring   bool
	base   bool
	ino    uint64
	pos    uint64
	off    int
	length int
	slices []packSlice
}

// ringAt reads a record's payload out of the ring. The caller holds a pin
// on the position, so the region cannot be reclaimed underneath it.
func (s *Store) ringAt(pos uint64, length int) []byte {
	b, ok := s.ring.At(pos, length)
	if !ok {
		return make([]byte, length) // unreachable while pinned; never a wild read
	}
	return b
}

// packSlice is one chunk to fetch and the part of it that is wanted. It
// names the whole stored entry rather than a byte range inside it,
// because a compressed or encrypted entry has no addressable interior.
type packSlice struct {
	loc    PackLoc
	skip   int // where in the DECODED chunk the wanted bytes start
	length int
}

type readPart struct {
	dst int
	src source
}

// Read fills p from ino at off. Resolution happens under the lock and the
// bytes are read outside it.
func (s *Store) Read(ctx context.Context, ino uint64, off int64, p []byte) (int, error) {
	s.mu.Lock()
	c := s.content[ino]
	s.mu.Unlock()
	return s.readFrom(ctx, c, ino, off, p)
}

// readFrom is Read against a named content map, which is what lets a
// frozen view (frozen.go) share every resolution path with the live one:
// the maps differ, the places bytes can be do not.
func (s *Store) readFrom(ctx context.Context, c *content, ino uint64, off int64, p []byte) (int, error) {
	parts, n, err := s.plan(c, off, len(p))
	if err != nil {
		return 0, err
	}
	defer func() {
		s.mu.Lock()
		for _, part := range parts {
			if part.src.ring {
				s.ring.Unpin(part.src.pos)
			}
		}
		// Dropping the last pin on a region a pack already published is
		// what finally frees it, and a writer may be blocked on exactly
		// those bytes.
		s.releaseLocked()
		s.mu.Unlock()
	}()
	clear(p[:n]) // holes and gaps read as zeros
	for _, part := range parts {
		dst := p[part.dst : part.dst+part.src.len()]
		if part.src.base {
			if _, err := s.base.Read(ctx, part.src.ino, int64(part.src.off), dst); err != nil {
				return 0, err
			}
			continue
		}
		if part.src.ring {
			b, ok := s.ring.At(part.src.pos, part.src.off+part.src.length)
			if !ok {
				return 0, fmt.Errorf("memtable: pinned extent at %d vanished", part.src.pos)
			}
			copy(dst, b[part.src.off:part.src.off+part.src.length])
			continue
		}
		at := 0
		for _, sl := range part.src.slices {
			if err := s.readPack(ctx, sl, dst[at:at+sl.length]); err != nil {
				return 0, err
			}
			at += sl.length
		}
	}
	return n, nil
}

func (src source) len() int {
	if src.ring || src.base {
		return src.length
	}
	n := 0
	for _, sl := range src.slices {
		n += sl.length
	}
	return n
}

// readPack reads one slice of one pack, from the local copy when there is
// one. A miss fetches the pack WHOLE and keeps it, which is the format's
// own read policy and also what makes a later seal of the same file free:
// reading a file to edit it pulls in the chunks the edit will straddle.
func (s *Store) readPack(ctx context.Context, sl packSlice, dst []byte) error {
	stored := make([]byte, sl.loc.Stored)
	if s.cache != nil {
		f, ok := s.cache.open(sl.loc.Pack)
		if !ok {
			var err error
			if f, err = s.cache.fetch(ctx, s.obj, sl.loc.Pack); err != nil {
				return err
			}
			s.countPackRead(false)
		} else {
			s.countPackRead(true)
		}
		defer f.Close() //nolint:errcheck
		if _, err := f.ReadAt(stored, sl.loc.Off); err != nil {
			return err
		}
	} else {
		s.countPackRead(false)
		rc, err := s.obj.Get(ctx, packstore.PackDirKey+"/"+sl.loc.Pack, sl.loc.Off, sl.loc.Stored)
		if err != nil {
			return err
		}
		defer rc.Close() //nolint:errcheck
		if _, err := io.ReadFull(rc, stored); err != nil {
			return err
		}
	}
	plain, err := entrycodec.Decode(stored, sl.loc.Alg, s.dek)
	if err != nil {
		return fmt.Errorf("memtable: decode chunk in %s at %d: %w", sl.loc.Pack, sl.loc.Off, err)
	}
	if int64(len(plain)) != sl.loc.Logical {
		return fmt.Errorf("memtable: chunk in %s at %d decoded to %d bytes, want %d",
			sl.loc.Pack, sl.loc.Off, len(plain), sl.loc.Logical)
	}
	copy(dst, plain[sl.skip:sl.skip+len(dst)])
	return nil
}

func (s *Store) countPackRead(local bool) {
	s.mu.Lock()
	if local {
		s.stats.PackReadsLocal++
	} else {
		s.stats.PackReadsRemote++
	}
	s.mu.Unlock()
}

// plan resolves a read to sources under the lock. The ordering — active
// table, flushing table, location map — is what makes a flush completing
// mid-read invisible: whichever level answered, its bytes are already
// final.
func (s *Store) plan(c *content, off int64, n int) ([]readPart, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c == nil {
		return nil, 0, nil
	}
	if off >= c.size {
		return nil, 0, nil
	}
	if int64(n) > c.size-off {
		n = int(c.size - off)
	}
	var parts []readPart
	for _, r := range c.overlapping(off, int64(n)) {
		lo := max(r.FileOff, off)
		hi := min(r.end(), off+int64(n))
		if hi <= lo {
			continue
		}
		src, err := s.resolveLocked(r.Handle, r.Skip+int(lo-r.FileOff), int(hi-lo))
		if err != nil {
			for _, p := range parts {
				if p.src.ring {
					s.ring.Unpin(p.src.pos)
				}
			}
			return nil, 0, err
		}
		parts = append(parts, readPart{dst: int(lo - off), src: src})
	}
	return parts, n, nil
}

// resolveLocked turns a handle plus an intra-extent range into a source.
func (s *Store) resolveLocked(h Handle, skip, length int) (source, error) {
	if be, ok := s.baseRefs[h]; ok {
		// An adopted file's bytes are still the base generation's, and the
		// base is immutable — nothing to pin, and nothing this store has
		// to hold a copy of.
		return source{base: true, ino: be.ino, off: skip, length: length}, nil
	}
	if rec, ok := s.index[h]; ok {
		// Pinning here is what makes reading outside the lock safe: the
		// packer may reclaim while this read is in flight, and the ring
		// refuses to let the tail pass a pinned position.
		s.ring.Pin(uint64(rec.Off))
		return source{ring: true, pos: uint64(rec.Off), off: skip, length: length}, nil
	}
	slices, ok := s.handleLoc[h]
	if !ok {
		return source{}, fmt.Errorf("memtable: extent %d is gone: it was neither in a memtable nor published", h)
	}
	var out []packSlice
	pos := 0
	want := skip
	remaining := length
	for _, cs := range slices {
		if remaining == 0 {
			break
		}
		if pos+cs.Length <= want {
			pos += cs.Length
			continue
		}
		delta := max(want-pos, 0)
		take := min(cs.Length-delta, remaining)
		loc, ok := s.chunkLoc[cs.ID.Hex()]
		if !ok {
			return source{}, fmt.Errorf("memtable: chunk %s has no location", cs.ID)
		}
		out = append(out, packSlice{loc: loc, skip: cs.ChunkOff + delta, length: take})
		want += take
		remaining -= take
		pos += cs.Length
	}
	if remaining != 0 {
		return source{}, fmt.Errorf("memtable: extent %d resolves %d bytes short", h, remaining)
	}
	return source{slices: out}, nil
}
