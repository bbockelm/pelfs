// Package packstore is the phase-1 piece of the v2 format
// (docs/design-packfs.md): an ObjectStorage middleware that packs many
// small block objects into large immutable pack objects, with no metadata
// format change.
//
// Writes to packable keys (chunks/...) are spooled into an open local pack
// file and uploaded as one federation object when the pack reaches its
// target size, when a metadata snapshot is about to be published, or at
// shutdown. Reads consult an in-memory index and become HTTP range requests
// into the pack — Pelican origins and caches serve ranges natively, so a
// pack is never fetched whole.
//
// Every pack is immutable and self-describing: a JSON index trailer maps
// keys to (offset, length) and lists tombstones for keys deleted since the
// previous pack. Packs sort by name in creation order, so replaying their
// trailers in name order reconstructs the live index (later tombstones
// shadow earlier entries) — the LSM discipline, with the pack as the
// segment. A fresh session bootstraps by listing packs/ and fetching only
// the trailers.
//
// Deferred-durability warning: Put returns success once the block is
// spooled locally, not when it is in the federation. This matches
// writeback semantics (the staging area has already accepted the same
// deferral) and is only safe because callers flush packs before every
// metadata snapshot and at shutdown. Write-side packing must therefore
// only be enabled together with writeback; the read side is always active
// so any session can read a packed volume.
package packstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

const (
	magic         = "PELFSPK1"
	footerSize    = 8 + 8 // index length + magic
	tailProbe     = 128 << 10
	defaultTarget = 64 << 20
	// PackDirKey is the key-space directory holding pack objects.
	PackDirKey = "packs"
)

// Config controls a Store.
type Config struct {
	// SpoolDir holds the open pack file (local state directory).
	SpoolDir string
	// TargetSize cuts a pack once it grows past this many bytes (default 64 MiB).
	TargetSize int64
	// WriteEnabled turns on write-side packing. Only enable together with
	// writeback (see the package comment); the read side is always active.
	WriteEnabled bool
	// Packable decides which keys are packed (default: chunks/...).
	Packable func(key string) bool

	// Repack policy (see repack.go): a sealed pack whose live fraction
	// falls below RepackLiveness is condemned once total garbage exceeds
	// RepackMinGarbage, unless younger than RepackAgeFloor. Zero values
	// select the defaults (0.5, 256MiB, 10m).
	RepackLiveness   float64
	RepackMinGarbage int64
	RepackAgeFloor   time.Duration
}

// entry locates one object inside a pack (or the open spool).
type entry struct {
	pack    string // "" while the entry is still in the spool
	off     int64
	length  int64
	created int64 // unix ms, inherited from the pack
}

// trailer is the JSON document at the end of every pack.
type trailer struct {
	Version int            `json:"v"`
	Created int64          `json:"created_ms"`
	Entries []trailerEntry `json:"entries"`
	Dead    []string       `json:"dead,omitempty"`
}

type trailerEntry struct {
	Key    string `json:"k"`
	Off    int64  `json:"o"`
	Length int64  `json:"l"`
}

// Store implements pelicanobj.Store over an inner store, packing packable
// keys. Non-packable keys pass through untouched.
type Store struct {
	pelicanobj.Store // inner: ListDir, StatKey, and all passthrough ops

	inner    pelicanobj.Store
	cfg      Config
	ctx      context.Context
	packable func(string) bool

	mu        sync.Mutex
	index     map[string]entry // committed: packed and uploaded
	pending   map[string]entry // in the open spool, not yet uploaded
	dead      []string         // tombstones awaiting the next pack upload
	spool     *os.File
	spoolSz   int64
	packBytes map[string]int64 // sealed pack -> stored entry bytes (garbage accounting)

	// repackMu admits one repacker at a time (TryLock: skip, don't queue).
	repackMu sync.Mutex

	// flushMu serializes Flush end-to-end: a caller returning from Flush
	// must know every block spooled before the call is durable, even when
	// another flush was already in flight (the pre-snapshot hook depends
	// on this).
	flushMu sync.Mutex
}

var _ pelicanobj.Store = (*Store)(nil)

// New builds the middleware and bootstraps the index from existing packs.
func New(ctx context.Context, inner pelicanobj.Store, cfg Config) (*Store, error) {
	if cfg.TargetSize <= 0 {
		cfg.TargetSize = defaultTarget
	}
	if cfg.Packable == nil {
		cfg.Packable = func(key string) bool { return strings.HasPrefix(key, "chunks/") }
	}
	s := &Store{
		Store:     inner,
		inner:     inner,
		cfg:       cfg,
		ctx:       ctx,
		packable:  cfg.Packable,
		index:     make(map[string]entry),
		pending:   make(map[string]entry),
		packBytes: make(map[string]int64),
	}
	if err := s.bootstrap(ctx); err != nil {
		return nil, err
	}
	if cfg.WriteEnabled {
		if err := os.MkdirAll(cfg.SpoolDir, 0700); err != nil {
			return nil, err
		}
		// Leftover spools mean a previous session crashed before its final
		// flush; their blocks were never referenced by a published snapshot
		// (flush precedes every snapshot), so they are only garbage.
		if old, _ := filepath.Glob(filepath.Join(cfg.SpoolDir, "open.pack*")); len(old) > 0 {
			for _, p := range old {
				if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
					fmt.Fprintf(os.Stderr, "pelfs: discarding %d bytes of unflushed pack spool from a previous session\n", fi.Size())
				}
				_ = os.Remove(p)
			}
		}
		f, err := s.newSpool()
		if err != nil {
			return nil, err
		}
		s.spool = f
	}
	return s, nil
}

func (s *Store) newSpool() (*os.File, error) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return os.OpenFile(filepath.Join(s.cfg.SpoolDir, "open.pack."+hex.EncodeToString(b[:])),
		os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
}

// bootstrap lists packs/ and replays trailers in name order (names embed
// creation time, so lexicographic order is creation order; tombstones in
// later packs shadow entries in earlier ones).
func (s *Store) bootstrap(ctx context.Context) error {
	entries, err := s.inner.ListDir(ctx, PackDirKey)
	if err != nil {
		if isNotExist(err) {
			return nil // brand-new volume
		}
		return fmt.Errorf("list packs: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, e := range entries {
		if e.IsDir || !strings.HasPrefix(e.Name, "p-") {
			continue
		}
		tr, idxLen, err := s.fetchTrailer(ctx, e.Name, e.Size)
		if err != nil {
			return fmt.Errorf("pack %s: %w", e.Name, err)
		}
		s.applyTrailer(e.Name, tr)
		s.packBytes[e.Name] = e.Size - idxLen - footerSize
	}
	return nil
}

func (s *Store) applyTrailer(packName string, tr *trailer) {
	for _, te := range tr.Entries {
		s.index[te.Key] = entry{pack: packName, off: te.Off, length: te.Length, created: tr.Created}
	}
	for _, k := range tr.Dead {
		delete(s.index, k)
	}
}

// fetchTrailer reads a pack's index with (usually) one range request,
// returning the parsed trailer and the index length (for entry-byte
// accounting). When the tail range read yields bytes that are not a valid
// trailer — observed in the wild when a transport in the federation path
// mishandles Range requests — it falls back to fetching the whole pack,
// which both self-heals the mount and tells us whether the object itself
// is intact.
func (s *Store) fetchTrailer(ctx context.Context, name string, size int64) (*trailer, int64, error) {
	if size < footerSize {
		return nil, 0, fmt.Errorf("pack too small (%d bytes)", size)
	}
	probe := int64(tailProbe)
	if probe > size {
		probe = size
	}
	tail, err := s.readRange(ctx, s.packKey(name), size-probe, probe)
	if err != nil {
		return nil, 0, err
	}
	tr, idxLen, terr := s.parseTail(ctx, name, size, tail)
	if terr == nil {
		return tr, idxLen, nil
	}
	// Tail probe failed: fetch the entire pack and retry against its true
	// end. Success here means the object is fine and the RANGE read lied
	// (wrong bytes or wrong length) — report that loudly, because every
	// chunk read depends on ranges working.
	whole, werr := s.readRange(ctx, s.packKey(name), 0, size)
	if werr == nil && int64(len(whole)) == size {
		if tr, idxLen, ferr := s.parseTail(ctx, name, size, whole); ferr == nil {
			fmt.Fprintf(os.Stderr,
				"pelfs: WARNING: pack %s: tail range read returned invalid bytes (%v) but the full object is intact — a transport in the path is mishandling Range requests; reads may be unreliable\n",
				name, terr)
			return tr, idxLen, nil
		}
	}
	preview := tail
	if len(preview) > 16 {
		preview = preview[len(preview)-16:]
	}
	return nil, 0, fmt.Errorf("%w (listed size %d, tail read %d bytes, last bytes %x; full-object retry: %v)",
		terr, size, len(tail), preview, werr)
}

// parseTail validates and parses a trailer from buf, which is the final
// portion of a pack of the given total size.
func (s *Store) parseTail(ctx context.Context, name string, size int64, buf []byte) (*trailer, int64, error) {
	if len(buf) < footerSize || string(buf[len(buf)-8:]) != magic {
		return nil, 0, fmt.Errorf("bad pack magic")
	}
	idxLen := int64(binary.LittleEndian.Uint64(buf[len(buf)-16 : len(buf)-8]))
	if idxLen <= 0 || idxLen+footerSize > size {
		return nil, 0, fmt.Errorf("bad index length %d", idxLen)
	}
	var raw []byte
	var err error
	if idxLen+footerSize <= int64(len(buf)) {
		raw = buf[int64(len(buf))-footerSize-idxLen : int64(len(buf))-footerSize]
	} else {
		raw, err = s.readRange(ctx, s.packKey(name), size-footerSize-idxLen, idxLen)
		if err != nil {
			return nil, 0, err
		}
	}
	var tr trailer
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, 0, fmt.Errorf("parse index: %w", err)
	}
	if tr.Version != 1 {
		return nil, 0, fmt.Errorf("unsupported pack version %d", tr.Version)
	}
	return &tr, idxLen, nil
}

func (s *Store) readRange(ctx context.Context, key string, off, length int64) ([]byte, error) {
	rc, err := s.inner.Get(ctx, key, off, length)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, length))
}

func (s *Store) packKey(name string) string { return PackDirKey + "/" + name }

func newPackName() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("p-%016x-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

// ---- ObjectStorage interception ----

func (s *Store) String() string {
	return "pack+" + s.inner.String()
}

func (s *Store) Put(ctx context.Context, key string, in io.Reader, getters ...object.AttrGetter) error {
	if !s.cfg.WriteEnabled || !s.packable(key) {
		return s.inner.Put(ctx, key, in, getters...)
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	// Cut before an append that would push the spool past the target, so
	// unsealed bytes stay bounded by TargetSize plus whatever concurrent
	// writers land between the check and the cut. (A single block larger
	// than the target still spools whole and seals immediately below.)
	s.mu.Lock()
	if s.spoolSz > 0 && s.spoolSz+int64(len(data)) > s.cfg.TargetSize {
		s.mu.Unlock()
		if err := s.Flush(ctx); err != nil {
			return err
		}
		s.mu.Lock()
	}
	if _, err := s.spool.WriteAt(data, s.spoolSz); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("pack spool: %w", err)
	}
	s.pending[key] = entry{off: s.spoolSz, length: int64(len(data)), created: time.Now().UnixMilli()}
	s.spoolSz += int64(len(data))
	needCut := s.spoolSz >= s.cfg.TargetSize
	s.mu.Unlock()
	if needCut {
		return s.Flush(ctx)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	if !s.packable(key) {
		return s.inner.Get(ctx, key, off, limit, getters...)
	}
	s.mu.Lock()
	if e, ok := s.pending[key]; ok {
		// Serve from the local spool: the block exists nowhere else yet.
		buf, err := s.readSpool(e, off, limit)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	e, ok := s.index[key]
	s.mu.Unlock()
	if !ok {
		// Not packed: a legacy per-key object, or absent.
		return s.inner.Get(ctx, key, off, limit, getters...)
	}
	if off < 0 || off > e.length {
		return nil, fmt.Errorf("pack get %q: offset %d beyond entry (%d bytes)", key, off, e.length)
	}
	n := e.length - off
	if limit > 0 && limit < n {
		n = limit
	}
	return s.inner.Get(ctx, s.packKey(e.pack), e.off+off, n, getters...)
}

// readSpool must be called with s.mu held.
func (s *Store) readSpool(e entry, off, limit int64) ([]byte, error) {
	if off < 0 || off > e.length {
		return nil, fmt.Errorf("spool read beyond entry")
	}
	n := e.length - off
	if limit > 0 && limit < n {
		n = limit
	}
	buf := make([]byte, n)
	if _, err := s.spool.ReadAt(buf, e.off+off); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *Store) Head(ctx context.Context, key string) (object.Object, error) {
	if !s.packable(key) {
		return s.inner.Head(ctx, key)
	}
	s.mu.Lock()
	e, ok := s.pending[key]
	if !ok {
		e, ok = s.index[key]
	}
	s.mu.Unlock()
	if !ok {
		return s.inner.Head(ctx, key)
	}
	return packedObj{key: key, size: e.length, mtime: time.UnixMilli(e.created)}, nil
}

func (s *Store) Delete(ctx context.Context, key string, getters ...object.AttrGetter) error {
	if !s.packable(key) {
		return s.inner.Delete(ctx, key, getters...)
	}
	s.mu.Lock()
	_, wasPending := s.pending[key]
	delete(s.pending, key)
	_, wasPacked := s.index[key]
	if wasPacked {
		delete(s.index, key)
		if s.cfg.WriteEnabled {
			// Durable via the next pack's tombstone list. Without write
			// packing there is no next pack; the entry resurrects on the
			// next bootstrap and gc will find it again — space, not
			// correctness.
			s.dead = append(s.dead, key)
		}
	}
	s.mu.Unlock()
	if wasPending || wasPacked {
		return nil
	}
	return s.inner.Delete(ctx, key, getters...)
}

// ListAll merges the inner store's objects (legacy per-key blocks) with the
// packed index, in sorted key order. Pack objects themselves live under
// packs/ and are excluded from chunk listings by prefix.
func (s *Store) ListAll(ctx context.Context, prefix, marker string, followLink bool) (<-chan object.Object, error) {
	innerCh, err := s.inner.ListAll(ctx, prefix, marker, followLink)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	keys := make([]string, 0, len(s.index)+len(s.pending))
	byKey := make(map[string]entry, len(s.index)+len(s.pending))
	add := func(k string, e entry) {
		if strings.HasPrefix(k, prefix) && k > marker {
			if _, dup := byKey[k]; !dup {
				keys = append(keys, k)
			}
			byKey[k] = e
		}
	}
	for k, e := range s.index {
		add(k, e)
	}
	for k, e := range s.pending {
		add(k, e)
	}
	s.mu.Unlock()
	sort.Strings(keys)

	out := make(chan object.Object, 64)
	go func() {
		defer close(out)
		// On any early exit, drain the inner channel so its producer
		// goroutine can finish.
		defer func() {
			go func() {
				for range innerCh {
				}
			}()
		}()
		i := 0
		emitPacked := func(upto string, all bool) bool {
			for i < len(keys) && (all || keys[i] < upto) {
				e := byKey[keys[i]]
				select {
				case out <- packedObj{key: keys[i], size: e.length, mtime: time.UnixMilli(e.created)}:
				case <-ctx.Done():
					return false
				}
				i++
			}
			return true
		}
		for obj := range innerCh {
			if obj == nil {
				out <- nil // propagate the inner listing-failure sentinel
				return
			}
			key := obj.Key()
			if strings.HasPrefix(key, PackDirKey+"/") {
				continue // the packs themselves are not chunk objects
			}
			if !emitPacked(key, false) {
				return
			}
			if i < len(keys) && keys[i] == key {
				// A packed entry shadows the legacy object of the same key:
				// emit the packed view (matching Get/Head) and drop the
				// legacy one.
				e := byKey[keys[i]]
				i++
				select {
				case out <- packedObj{key: key, size: e.length, mtime: time.UnixMilli(e.created)}:
				case <-ctx.Done():
					return
				}
				continue
			}
			select {
			case out <- obj:
			case <-ctx.Done():
				return
			}
		}
		emitPacked("", true)
	}()
	return out, nil
}

// Flush uploads the open spool as one immutable pack (with any pending
// tombstones) and commits its entries to the index. Callers invoke it
// before every metadata snapshot and at shutdown; Put invokes it when the
// spool reaches the target size. Safe to call when there is nothing to do.
func (s *Store) Flush(ctx context.Context) error {
	// Serialized end-to-end: when Flush returns, everything spooled before
	// the call is durable, even if another flush was in flight at entry.
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	s.mu.Lock()
	if s.spool == nil || (len(s.pending) == 0 && len(s.dead) == 0) {
		s.mu.Unlock()
		return nil
	}
	// Snapshot the spool state; new Puts during the upload go to fresh
	// state and the next Flush.
	pending := s.pending
	dead := s.dead
	spool := s.spool
	spoolSz := s.spoolSz
	name := newPackName()
	created := time.Now().UnixMilli()

	f, err := s.newSpool()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.spool = f
	s.spoolSz = 0
	s.pending = make(map[string]entry)
	s.dead = nil
	s.mu.Unlock()

	// Compact at cut time: the spool may contain bytes whose entries were
	// tombstoned while pending — a file overwritten (or a hot byte range
	// re-flushed) several times within the pack window leaves only its
	// newest version live, and JuiceFS chunk compaction (triggered at just
	// 5 slices) tombstones stale versions quickly. Upload only the live
	// extents, re-based to fresh offsets, so blocks that die young never
	// reach the federation at all.
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return pending[keys[i]].off < pending[keys[j]].off })

	tr := trailer{Version: 1, Created: created}
	newOff := make(map[string]int64, len(keys))
	var liveSz int64
	for _, k := range keys {
		e := pending[k]
		newOff[k] = liveSz
		tr.Entries = append(tr.Entries, trailerEntry{Key: k, Off: liveSz, Length: e.length})
		liveSz += e.length
	}
	sort.Slice(tr.Entries, func(i, j int) bool { return tr.Entries[i].Key < tr.Entries[j].Key })
	tr.Dead = dead
	if droppedBytes := spoolSz - liveSz; droppedBytes > 0 {
		logDroppedBytes(droppedBytes)
	}
	idx, err := json.Marshal(&tr)
	if err != nil {
		return err
	}
	footer := make([]byte, footerSize)
	binary.LittleEndian.PutUint64(footer[:8], uint64(len(idx)))
	copy(footer[8:], magic)

	upload, err := os.CreateTemp(s.cfg.SpoolDir, "upload.pack.*")
	if err != nil {
		return err
	}
	defer func() {
		_ = upload.Close()
		_ = os.Remove(upload.Name())
	}()
	for _, k := range keys {
		e := pending[k]
		if _, err := io.Copy(upload, io.NewSectionReader(spool, e.off, e.length)); err != nil {
			s.requeue(spool, pending, dead)
			return fmt.Errorf("compact pack: %w", err)
		}
	}
	if _, err := upload.Write(append(idx, footer...)); err != nil {
		s.requeue(spool, pending, dead)
		return fmt.Errorf("finalize pack: %w", err)
	}
	if _, err := upload.Seek(0, io.SeekStart); err != nil {
		s.requeue(spool, pending, dead)
		return err
	}
	if err := s.inner.Put(ctx, s.packKey(name), upload); err != nil {
		// Put the entries back (from the original spool) so a later Flush
		// retries them in a fresh pack.
		s.requeue(spool, pending, dead)
		return fmt.Errorf("upload pack: %w", err)
	}
	_ = spool.Close()
	_ = os.Remove(spool.Name())

	s.mu.Lock()
	for k, e := range pending {
		s.index[k] = entry{pack: name, off: newOff[k], length: e.length, created: created}
	}
	s.packBytes[name] = liveSz
	s.mu.Unlock()
	return nil
}

func logDroppedBytes(n int64) {
	fmt.Fprintf(os.Stderr, "pelfs: pack cut dropped %d bytes of blocks deleted while pending\n", n)
}

// requeue merges a failed upload's entries back into the current spool by
// copying their bytes forward, so a later Flush retries them in a new pack.
func (s *Store) requeue(old *os.File, pending map[string]entry, dead []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range pending {
		buf := make([]byte, e.length)
		if _, err := old.ReadAt(buf, e.off); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: pack requeue lost %s: %v\n", k, err)
			continue
		}
		if _, err := s.spool.WriteAt(buf, s.spoolSz); err != nil {
			fmt.Fprintf(os.Stderr, "pelfs: pack requeue lost %s: %v\n", k, err)
			continue
		}
		s.pending[k] = entry{off: s.spoolSz, length: e.length, created: e.created}
		s.spoolSz += e.length
	}
	s.dead = append(s.dead, dead...)
	_ = old.Close()
	_ = os.Remove(old.Name())
}

// PendingBlocks reports how many blocks are spooled but not yet uploaded
// (for statistics and shutdown verification).
func (s *Store) PendingBlocks() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

type packedObj struct {
	key   string
	size  int64
	mtime time.Time
}

func (o packedObj) Key() string          { return o.key }
func (o packedObj) Size() int64          { return o.size }
func (o packedObj) Mtime() time.Time     { return o.mtime }
func (o packedObj) IsDir() bool          { return false }
func (o packedObj) IsSymlink() bool      { return false }
func (o packedObj) StorageClass() string { return "" }
func (o packedObj) Status() string       { return "" }

func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}
