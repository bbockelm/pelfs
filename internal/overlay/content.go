package overlay

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// contentStore is where an overlay keeps the BYTES of the files it has
// changed. Names, attributes and directory structure stay in SQLite; this
// is the other half — and it is the half the write path replaces
// (docs/design-writepath.md). Pulling it behind an interface is what lets
// the two live side by side: the staging implementation below is exactly
// what the overlay has always done, and a memtable-backed one can be held
// to the same tests before anything depends on it.
//
// Every method is called with the owning FS's lock held. That is not
// incidental — the staging implementation's snapshot pins are protected
// by it, and a backend that needed finer locking would have to say so.
type contentStore interface {
	// Create gives a brand-new inode an empty body. It runs INSIDE the
	// transaction that publishes the inode, before commit, so a crash
	// leaves at worst an orphan nothing points at.
	Create(ino uint64) error
	// Adopt gives ino a writable body that begins as the first length
	// bytes of the base generation's version of it. The caller has
	// already established base residency.
	//
	// baseFile offers the same file two ways on purpose. A store that
	// keeps bytes copies them; a store that keeps IDENTITIES takes the
	// records and moves nothing, which is the difference between "writing
	// one byte of a 1 GiB file costs 1 GiB" and "it costs one row".
	Adopt(ctx context.Context, ino uint64, length int64, base baseFile) error
	// ReadAt fills dst from ino at off.
	ReadAt(ctx context.Context, ino uint64, off int64, dst []byte) (int, error)
	// WriteAt stores data at off. Bytes below off are the only ones a
	// write disturbs, which is what lets an append cost nothing extra.
	WriteAt(ctx context.Context, ino uint64, off int64, data []byte) error
	// Truncate resizes ino, zero-filling an extension.
	Truncate(ctx context.Context, ino uint64, size int64) error
	// Drop stops keeping ino's body and hands back the part of that work
	// which need not happen under the lock — the unlink, for a store that
	// keeps files. A rebase drops thousands of inodes at once, and one
	// syscall apiece with the mount's lock held is a stall the mount pays
	// for. nil when there is nothing deferred.
	Drop(ino uint64) (deferred func())
	// Size reports ino's body length on disk, and false when there is
	// none. It answers the STAGED-bytes statistic, which drives the
	// pressure checkpoint, so it must not be an estimate.
	Size(ino uint64) (int64, bool)
}

// ContentRecords is the capability of a content store that has ALREADY
// chunked and uploaded what it holds, so a seal can publish it without
// reading or re-chunking a byte. A staging store cannot: its bytes are
// bytes and nothing has ever hashed them.
//
// It is what connects the write path to publish.ContentProvider, and the
// pack list is the load-bearing half: those chunks live in packs this
// session uploaded, which no previous superblock names, so the generation
// being built has to name them or it is signed and unreadable.
type ContentRecords interface {
	// Records returns ino's content as catalog rows, and false when this
	// store has nothing for it.
	Records(ctx context.Context, ino uint64) (genfs.Content, bool, error)
	// Packs are every pack holding bytes Records named. Called once, after
	// the last Records: a store may still be cutting packs while it
	// answers.
	Packs(ctx context.Context) ([]packstore.SealedPack, error)
	// EachEntry reports every identity this store placed and the pack
	// holding it. A generation's multi-pack index is built from what the
	// SEAL packed; content the source packed itself never passes through
	// that, so without this the index answers for catalogs and shards and
	// misses the data — which on a writable mount is nearly everything.
	EachEntry(fn func(identityHex, pack string))
}

// ContentRecords reports whether this overlay's content is already
// chunked and uploaded, and hands back the surface a seal reads it
// through.
func (fs *FS) ContentRecords() (ContentRecords, bool) {
	r, ok := fs.content.(ContentRecords)
	return r, ok
}

// baseFile is one file as the base generation holds it, offered both
// ways: as bytes to copy, and as the inode number a store that speaks to
// the base itself can ask about.
type baseFile struct {
	ino  uint64
	body io.Reader
}

// stagingContent is one file per dirty inode under a directory: the
// overlay's original content store, and the one the write path exists to
// remove. Its costs are the ones that motivate the replacement — a write
// to a clean file copies the whole file first (Adopt), and a snapshot
// taken while it is live has to be protected from every mutation below a
// frozen length.
type stagingContent struct {
	dir string
	// fallback is set on a SNAPSHOT's frozen view: the LIVE overlay's
	// staging directory, read when this one holds no copy. See ReadAt.
	fallback string
	// pins is one entry per live snapshot. They are guarded by the owning
	// FS's lock, like everything else here.
	pins []*snapPin
	// unsynced is the inodes whose bodies have been written and not yet
	// fsync'd, which is what an application's fsync has to cover (Sync).
	//
	// A SET rather than a sweep of the directory, because the alternative
	// is the pathology: a `--no-memtable` mount with fifty thousand dirty
	// files and an application that fsyncs after every write would pay
	// fifty thousand fsyncs per call for one file's worth of new bytes.
	// The set is bounded by the writes BETWEEN two fsyncs, so an
	// application that never calls it never grows it past the session's
	// dirty inodes — which the overlay already tracks one of (dirtySet) —
	// and an application that calls it constantly keeps it near empty.
	unsynced map[uint64]struct{}
	// created records that a body's NAME is new since the last sync, so
	// the directory entry needs a sync of its own. Without it the metadata
	// can name an inode whose staging file is not durably in its
	// directory, which reads back as content that is gone.
	created bool
}

func newStagingContent(dir string) *stagingContent {
	return &stagingContent{dir: dir, unsynced: map[uint64]struct{}{}}
}

// dirtyLocked notes that one inode's body has bytes no fsync has covered.
// Called with the owning FS's lock held, like every other method here.
func (c *stagingContent) dirtyLocked(ino uint64) {
	if c.unsynced == nil {
		c.unsynced = map[uint64]struct{}{}
	}
	c.unsynced[ino] = struct{}{}
}

// Sync fsyncs the bodies written since the last call, and the directory
// holding them when any of their names are new.
//
// It is O(writes since the last fsync) rather than O(dirty files), which
// is the whole reason the set above exists. Nothing here publishes: see
// sync.go for what that guarantee covers and where it stops.
func (c *stagingContent) Sync() error {
	for ino := range c.unsynced {
		if err := syncPath(c.path(ino)); err != nil {
			return fmt.Errorf("overlay: sync staged inode %d: %w", ino, err)
		}
	}
	if c.created {
		// A directory is synced by fsync'ing the directory itself, which
		// is what makes a name durable rather than just its bytes.
		d, err := os.Open(c.dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		if cerr := d.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("overlay: sync staging directory: %w", err)
		}
		c.created = false
	}
	clear(c.unsynced)
	return nil
}

// path is where one inode's body lives. Decimal, so nothing else in the
// directory can collide with it.
func (c *stagingContent) path(ino uint64) string {
	return filepath.Join(c.dir, strconv.FormatUint(ino, 10))
}

func (c *stagingContent) Create(ino uint64) error {
	f, err := os.OpenFile(c.path(ino), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	c.created = true
	c.dirtyLocked(ino)
	return f.Close()
}

// Adopt copies the base version in. The file is synced before the caller
// commits the row that publishes it, so a crash before commit leaves an
// invisible orphan rather than a row pointing at half a file.
func (c *stagingContent) Adopt(_ context.Context, ino uint64, length int64, base baseFile) error {
	fp := c.path(ino)
	f, err := os.OpenFile(fp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		f.Close()     //nolint:errcheck
		os.Remove(fp) //nolint:errcheck
		return err
	}
	if length > 0 {
		if n, err := io.CopyN(f, base.body, length); err != nil {
			return fail(fmt.Errorf("overlay: COW copy inode %d: %d of %d bytes: %w", ino, n, length, err))
		}
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(fp) //nolint:errcheck
		return err
	}
	// The BODY is already durable — Adopt syncs it above, because the row
	// that publishes it commits next — but its NAME is not.
	c.created = true
	return nil
}

func (c *stagingContent) ReadAt(_ context.Context, ino uint64, off int64, dst []byte) (int, error) {
	f, err := c.open(ino)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck
	// The body's size tracks the onode length (writes extend, truncate
	// sets), so a full read succeeds; a short one means a torn invariant.
	if _, err := io.ReadFull(io.NewSectionReader(f, off, int64(len(dst))), dst); err != nil {
		return 0, fmt.Errorf("overlay: staging read inode %d at %d: %w", ino, off, err)
	}
	return len(dst), nil
}

// open resolves one inode's body, with the frozen view's fallback.
//
// A snapshot's scratch holds a file only for inodes the live side has
// since overwritten, truncated, or removed — the freeze itself copies
// nothing — so an absent one means the live file still holds the frozen
// bytes below the frozen length, which is all such a view will read.
//
// The re-check is what makes that safe without holding the live
// overlay's lock. The live side always moves the old file into the
// scratch BEFORE its own name stops naming those bytes, so a reader that
// saw no copy, opened the live name, and still sees no copy cannot have
// been overtaken by a copy-out. If one did land in between, it is the
// truth and the live handle is not.
func (c *stagingContent) open(ino uint64) (*os.File, error) {
	if c.fallback == "" {
		return os.Open(c.path(ino))
	}
	frozen := c.path(ino)
	if f, err := os.Open(frozen); err == nil {
		return f, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	live, liveErr := os.Open(filepath.Join(c.fallback, strconv.FormatUint(ino, 10)))
	if f, err := os.Open(frozen); err == nil {
		if liveErr == nil {
			live.Close() //nolint:errcheck
		}
		return f, nil
	}
	return live, liveErr
}

func (c *stagingContent) WriteAt(_ context.Context, ino uint64, off int64, data []byte) error {
	// Bytes below off are the only ones this write disturbs, so a pure
	// append never copies for a live snapshot.
	if err := c.copyOut(ino, off); err != nil {
		return err
	}
	f, err := os.OpenFile(c.path(ino), os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, off); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	c.dirtyLocked(ino)
	return f.Close()
}

func (c *stagingContent) Truncate(_ context.Context, ino uint64, size int64) error {
	// A shrink destroys bytes below the new size; an extension only adds
	// above it, which no snapshot can see.
	if err := c.copyOut(ino, size); err != nil {
		return err
	}
	c.dirtyLocked(ino)
	return os.Truncate(c.path(ino), size)
}

// Drop offers a purged inode's body to any live snapshot and hands the
// unlink back to the caller. The hand-off must happen here, under the
// lock: the snapshot froze content the transaction that just committed
// has stopped referencing, and this file is the only copy of it. Best
// effort, like the removal it replaces — if the hand-off fails, the seal
// reading that inode fails loudly, which is what this ordering exists to
// make impossible to miss.
func (c *stagingContent) Drop(ino uint64) func() {
	_, _ = c.handOver(ino, 0)
	path := c.path(ino)
	return func() { os.Remove(path) } //nolint:errcheck
}

// ---- snapshots ----

// snapPin is one live snapshot's frozen staging state: where its scratch
// lives, and the length it froze each staged inode at. An inode leaves
// lens the moment the live side has handed its bytes over — there is
// nothing left to protect. Identity is the pointer: release removes
// exactly this one.
type snapPin struct {
	dir  string
	lens map[uint64]int64
}

// contentFreezer is the capability a content store needs when a seal
// freezes a view of it: somewhere to put the bytes the live side is about
// to stop keeping. A store whose content is already immutable — the write
// path's ring, where an instant is a position rather than a protocol —
// will not implement it, because there is nothing to protect.
type contentFreezer interface {
	freeze(dir string, lens map[uint64]int64) *snapPin
	release(p *snapPin)
}

var _ contentFreezer = (*stagingContent)(nil)

// contentSnapshotter is the other way to freeze: a store whose content is
// append-only hands back a read-only VIEW of itself rather than
// protecting mutable bytes. There is nothing for the live side to do
// differently afterwards, which is why it needs no pin, no scratch and no
// copy-out.
//
// The work splits in two because only one half can hold the lock.
// prepareSnapshot may be slow and touch the network (the memtable flushes
// its ring) and runs with the mount serving; freezeContent is the
// instant, and must be quick.
type contentSnapshotter interface {
	prepareSnapshot(ctx context.Context) error
	freezeContent(ctx context.Context) (frozenContentStore, error)
}

// frozenContentStore is a content store that also knows when it is done.
type frozenContentStore interface {
	contentStore
	releaseFrozen()
}

// contentCanFreeze reports whether a seal can walk a frozen view of this
// overlay's content at all.
func (fs *FS) contentCanFreeze() bool {
	if _, ok := fs.content.(contentFreezer); ok {
		return true
	}
	_, ok := fs.content.(contentSnapshotter)
	return ok
}

func (c *stagingContent) freeze(dir string, lens map[uint64]int64) *snapPin {
	p := &snapPin{dir: dir, lens: lens}
	c.pins = append(c.pins, p)
	return p
}

func (c *stagingContent) release(p *snapPin) {
	for i, held := range c.pins {
		if held == p {
			c.pins = append(c.pins[:i], c.pins[i+1:]...)
			return
		}
	}
}

// handOver gives ino's current body to every live snapshot that still
// depends on it, by MOVING it into that snapshot's scratch, and reports
// where it went ("" when nobody needed it). It is what makes the freeze
// lazy: a snapshot takes a file only where the live side is about to stop
// keeping those bytes, so the cost follows what the mount does during a
// seal rather than the size of the dirty set.
//
// below bounds it the way the copy-out rule does: a snapshot that froze
// ino at length L does not care about bytes at or above L, so a change
// entirely above L needs nothing. Pass 0 for "all of it" — the file is
// going away.
//
// An inode drops out of lens once handed over: the snapshot has the file
// itself, and nothing the live side does to the name afterwards can reach
// it. A missing live file drops out too — there is nothing to hand over,
// and a read of it should fail loudly rather than quietly serve somebody
// else's bytes.
//
// ORDER MATTERS, and it is the whole of the lock-free read rule: the file
// arrives in the scratch BEFORE the live name stops naming those bytes. A
// reader that finds no copy, opens the live file, and then still finds no
// copy cannot have been overtaken.
func (c *stagingContent) handOver(ino uint64, below int64) (string, error) {
	if len(c.pins) == 0 {
		return "", nil
	}
	live := c.path(ino)
	name := strconv.FormatUint(ino, 10)
	moved := ""
	for _, p := range c.pins {
		l, ok := p.lens[ino]
		if !ok || l <= below {
			continue
		}
		dst := filepath.Join(p.dir, name)
		var err error
		if moved == "" {
			// The first taker gets the file itself. One rename, and no
			// staging file ever answers to two names.
			err = os.Rename(live, dst)
		} else {
			// A second live snapshot is not a thing a seal produces today
			// (one seal at a time, and it releases its snapshot), but the
			// pin list is a list, so the case has an answer: copy from
			// wherever the file went.
			err = copyFileSync(moved, dst)
		}
		if err != nil && !os.IsNotExist(err) {
			return moved, fmt.Errorf("overlay: hand inode %d to a live snapshot: %w", ino, err)
		}
		if err == nil {
			moved = dst
		}
		delete(p.lens, ino)
	}
	return moved, nil
}

// copyOut gives ino a private body when a live snapshot froze bytes below
// `below`. The snapshot takes the current file and the live side copies
// itself a fresh one, because a write below the frozen length needs the
// bytes it is not overwriting.
func (c *stagingContent) copyOut(ino uint64, below int64) error {
	pinned := false
	for _, p := range c.pins {
		if l, ok := p.lens[ino]; ok && l > below {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil
	}
	moved, err := c.handOver(ino, below)
	if err != nil || moved == "" {
		return err
	}
	live := c.path(ino)
	// Through a temporary, then rename: a crash must not leave the live
	// name pointing at a half-written copy. The suffix cannot collide with
	// a staging path (those are decimal).
	tmp := live + ".cow"
	if err := copyFileSync(moved, tmp); err != nil {
		return fmt.Errorf("overlay: snapshot copy-out inode %d: %w", ino, err)
	}
	if err := os.Rename(tmp, live); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return nil
}

// copyFileSync writes a durable copy: the staging crash contract is that
// bytes are on disk before anything points at them.
func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		out.Close()    //nolint:errcheck
		os.Remove(dst) //nolint:errcheck
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	return out.Close()
}

func (c *stagingContent) Size(ino uint64) (int64, bool) {
	fi, err := os.Stat(c.path(ino))
	if err != nil {
		return 0, false
	}
	return fi.Size(), true
}
