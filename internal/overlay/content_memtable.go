package overlay

import (
	"context"

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
	_ contentStore   = (*memtableContent)(nil)
	_ ContentRecords = (*memtableContent)(nil)
)

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
	m.store.Truncate(ino, size)
	return nil
}

// Drop forgets an inode's content. There is no file to unlink, so nothing
// is deferred: the extents it referenced become unreferenced, die in the
// ring if they never left it, and are a repack's problem if they did.
func (m *memtableContent) Drop(ino uint64) func() {
	m.store.Forget(ino)
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
func (m *memtableContent) Packs(ctx context.Context) ([]packstore.SealedPack, error) {
	if m.seal != nil {
		if err := m.seal.Finish(ctx); err != nil {
			return nil, err
		}
		m.seal = nil
	}
	return m.store.Packs(), nil
}
