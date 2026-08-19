package overlay

import (
	"context"
	"errors"
	"os"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/memtable"
	"github.com/bbockelm/pelfs/internal/packstore"
)

// memtableContent keeps the bytes of changed files in the write path's
// memtable (internal/memtable) instead of in one staging file per dirty
// inode: writes land in an mmap'd ring, age out into packs, and reach the
// federation DURING the session rather than at the seal that ends it.
//
// It is deliberately a thin adapter. Everything interesting — the ring,
// the aging rule, the pack cache, adoption of base files by reference,
// the re-chunk a partial rewrite needs — belongs to the memtable, which
// is where it can be measured without a mount. What belongs here is the
// contentStore contract, and the two places where it does not line up:
//
//   - Create has nothing to do. A staging store makes an empty file
//     because a file is where its bytes will go; a memtable has no such
//     placeholder, and an inode with no writes simply has no content.
//     The ocontent row remains the marker either way.
//
//   - contentFreezer is NOT implemented, and that is the point of the
//     whole exercise. Snapshot pins exist because staging files are
//     mutable; a ring is append-only, so the consistent instant a
//     checkpoint needs is a position rather than a protocol. A snapshot
//     over this store freezes nothing and hands nothing over.
type memtableContent struct {
	store *memtable.Store
	// seal is the render in progress. One per seal run: it accumulates
	// whatever re-chunking the run needs into a shared pack, and Packs
	// finishes it.
	seal *memtable.Sealer
}

var (
	_ contentStore       = (*memtableContent)(nil)
	_ ContentRecords     = (*memtableContent)(nil)
	_ contentSnapshotter = (*memtableContent)(nil)
	_ frozenContentStore = (*frozenMemtableContent)(nil)
	_ ContentRecords     = (*frozenMemtableContent)(nil)
)

// prepareSnapshot flushes with the mount still serving. It is the
// expensive half — chunking, hashing and uploading whatever is in the
// ring — and it happens outside the overlay's lock precisely because a
// checkpoint must not stop the mount for the length of an upload.
func (m *memtableContent) prepareSnapshot(ctx context.Context) error {
	return m.store.Flush(ctx)
}

// freezeContent is the instant. The flush inside it covers only what
// arrived since prepareSnapshot, so the lock hold is a small flush and a
// copy of the extent maps rather than a session's worth of upload.
func (m *memtableContent) freezeContent(ctx context.Context) (frozenContentStore, error) {
	f, err := m.store.Freeze(ctx)
	if err != nil {
		return nil, err
	}
	return &frozenMemtableContent{store: m.store, view: f}, nil
}

// frozenMemtableContent serves one instant of a memtable's content. It is
// read-only by construction: a seal walks it and nothing writes to it,
// and the write methods say so rather than silently accepting bytes that
// would belong to no generation.
type frozenMemtableContent struct {
	store *memtable.Store
	view  *memtable.Frozen
	seal  *memtable.Sealer
}

func (f *frozenMemtableContent) releaseFrozen() { f.view.Release() }

func (f *frozenMemtableContent) ReadAt(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	return f.view.Read(ctx, ino, off, dst)
}

func (f *frozenMemtableContent) Size(ino uint64) (int64, bool) { return f.view.Size(ino), true }

func (f *frozenMemtableContent) Create(uint64) error { return errFrozenContent }
func (f *frozenMemtableContent) Adopt(context.Context, uint64, int64, baseFile) error {
	return errFrozenContent
}
func (f *frozenMemtableContent) WriteAt(context.Context, uint64, int64, []byte) error {
	return errFrozenContent
}
func (f *frozenMemtableContent) Truncate(context.Context, uint64, int64) error {
	return errFrozenContent
}
func (f *frozenMemtableContent) Drop(uint64) func() { return nil }

var errFrozenContent = errors.New("overlay: a frozen content view is read-only")

// Records renders the instant. No flush here: freezing already did it,
// and doing it again would fold bytes written after the instant into the
// generation being published.
func (f *frozenMemtableContent) Records(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if f.seal == nil {
		f.seal = f.store.NewSealer()
	}
	size := f.view.Size(ino)
	if size == 0 {
		return genfs.Content{}, false, nil
	}
	refs, err := f.view.Records(ctx, f.seal, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return genfs.Content{Length: size, Refs: refs}, true, nil
}

func (f *frozenMemtableContent) EachEntry(fn func(identityHex, pack string)) {
	f.store.EachPlacedChunk(fn)
}

func (f *frozenMemtableContent) Packs(ctx context.Context) ([]packstore.SealedPack, error) {
	if f.seal != nil {
		if err := f.seal.Finish(ctx); err != nil {
			return nil, err
		}
		f.seal = nil
	}
	return f.store.Packs(), nil
}

func newMemtableContent(store *memtable.Store) *memtableContent {
	return &memtableContent{store: store}
}

// Create does nothing: an inode with no writes has no content, and the
// row that says otherwise is in SQLite.
func (m *memtableContent) Create(uint64) error { return nil }

// Adopt takes the base generation's records rather than its bytes. The
// base file's reader is ignored on purpose — the memtable talks to the
// base itself, which is what lets this cost a row instead of a file.
func (m *memtableContent) Adopt(ctx context.Context, ino uint64, length int64, _ baseFile) error {
	return m.store.Adopt(ctx, ino, length)
}

func (m *memtableContent) ReadAt(ctx context.Context, ino uint64, off int64, dst []byte) (int, error) {
	return m.store.Read(ctx, ino, off, dst)
}

func (m *memtableContent) WriteAt(ctx context.Context, ino uint64, off int64, data []byte) error {
	return m.store.Write(ctx, ino, off, data)
}

func (m *memtableContent) Truncate(_ context.Context, ino uint64, size int64) error {
	return m.store.Truncate(ino, size)
}

// Drop forgets an inode's content. There is no file to unlink, so nothing
// is deferred: the extents it referenced become unreferenced, die in the
// ring if they never left it, and are a repack's problem if they did.
func (m *memtableContent) Drop(ino uint64) func() {
	// The purge has already committed, so there is nothing left to refuse:
	// a journal failure here is reported and the record is reconciled at
	// the next recovery, which replays a content map for an inode no
	// namespace row names and drops it.
	_ = m.store.Forget(ino)
	return nil
}

func (m *memtableContent) Size(ino uint64) (int64, bool) {
	return m.store.Size(ino), true
}

// Records renders one inode as catalog rows. The first call FLUSHES:
// identity binds when a pack is written, so content still in the ring has
// no rows yet — and the flush happens once per seal because the sealer it
// creates lives for the whole run.
func (m *memtableContent) Records(ctx context.Context, ino uint64) (genfs.Content, bool, error) {
	if m.seal == nil {
		if err := m.store.Flush(ctx); err != nil {
			return genfs.Content{}, false, err
		}
		m.seal = m.store.NewSealer()
	}
	size := m.store.Size(ino)
	if size == 0 {
		// Nothing written and nothing adopted: the caller reads it the
		// ordinary way, which for an empty file costs nothing.
		return genfs.Content{}, false, nil
	}
	refs, err := m.seal.Inode(ctx, ino)
	if err != nil {
		return genfs.Content{}, false, err
	}
	return genfs.Content{Length: size, Refs: refs}, true, nil
}

// Packs finishes the run and reports every pack this store has uploaded.
// All of them, not just this run's: a chunk row rendered above may name a
// pack cut minutes ago, during the session, and the superblock has to
// list that one too.
func (m *memtableContent) EachEntry(fn func(identityHex, pack string)) {
	m.store.EachPlacedChunk(fn)
}

func (m *memtableContent) Packs(ctx context.Context) ([]packstore.SealedPack, error) {
	if m.seal != nil {
		if err := m.seal.Finish(ctx); err != nil {
			return nil, err
		}
		m.seal = nil
	}
	return m.store.Packs(), nil
}

// OpenContentStore builds a memtable content store for an overlay
// directory, journalled into that directory, and recovers whatever a
// previous session left behind.
//
// It exists so a caller does not have to know the assembly order — the
// journal must be opened before the store, because what it holds is what
// the store is rebuilt FROM, and the ring file lives beside it. The
// returned report is recovery's account of itself and must be shown to
// the user whenever it reports loss.
func OpenContentStore(dir string, opts memtable.Options) (*memtable.Store, *memtable.Report, func() error, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, nil, err
	}
	j, err := openContentJournal(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	d, err := j.Load()
	if err != nil {
		j.Close() //nolint:errcheck
		return nil, nil, nil, err
	}
	opts.Dir = dir
	opts.Journal = j
	store, rep, err := memtable.Recover(opts, d)
	if err != nil {
		j.Close() //nolint:errcheck
		return nil, nil, nil, err
	}
	closeBoth := func() error {
		err := store.Close()
		if cerr := j.Close(); err == nil {
			err = cerr
		}
		return err
	}
	return store, rep, closeBoth, nil
}
