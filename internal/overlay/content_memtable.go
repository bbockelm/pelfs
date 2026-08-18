package overlay

import (
	"context"

	"github.com/bbockelm/pelfs/internal/memtable"
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
}

var _ contentStore = (*memtableContent)(nil)

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
