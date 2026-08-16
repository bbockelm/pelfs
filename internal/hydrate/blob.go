package hydrate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/juicedata/juicefs/pkg/object"

	"github.com/bbockelm/pelfs/internal/entrycodec"
	"github.com/bbockelm/pelfs/internal/packstore"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// blob serves JuiceFS block reads of hydrated slices from packs and passes
// everything else — new writes from a live session included — through to
// the inner session store.
type blob struct {
	object.ObjectStorage // inner: all passthrough operations

	inner     object.ObjectStorage
	packs     pelicanobj.Store
	db        *sql.DB
	dek       []byte
	cacheDir  string
	blockSize int64
}

// NewBlob wraps a session block store so reads of slice ids recorded in
// the sidecar are answered from pack range reads (decoded, optionally
// cached under cacheDir); unknown slice ids and non-block keys pass
// through to inner untouched, as do Put/Delete/List.
func NewBlob(inner object.ObjectStorage, packSource pelicanobj.Store, sidecarPath string, dek []byte, cacheDir string) (object.ObjectStorage, error) {
	if len(dek) != 0 && len(dek) != entrycodec.KeySize {
		return nil, fmt.Errorf("hydrate: DEK is %d bytes, want nil or %d", len(dek), entrycodec.KeySize)
	}
	db, blockSize, err := openSidecar(sidecarPath)
	if err != nil {
		return nil, fmt.Errorf("hydrate: %w", err)
	}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			db.Close() //nolint:errcheck
			return nil, err
		}
	}
	return &blob{
		ObjectStorage: inner,
		inner:         inner,
		packs:         packSource,
		db:            db,
		dek:           dek,
		cacheDir:      cacheDir,
		blockSize:     blockSize,
	}, nil
}

func (b *blob) String() string { return "hydrate+" + b.inner.String() }

// parseBlockKey extracts (slice id, block index, block size) from a JuiceFS
// block object key: chunks/<id/1e6>/<id/1e3>/<id>_<indx>_<bsize> (the
// no-hash-prefix naming; see internal/offline blockKey).
func parseBlockKey(key string) (id uint64, indx int64, bsize int64, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "chunks" {
		return 0, 0, 0, false
	}
	fields := strings.Split(parts[3], "_")
	if len(fields) != 3 {
		return 0, 0, 0, false
	}
	var err error
	if id, err = strconv.ParseUint(fields[0], 10, 64); err != nil || id == 0 {
		return 0, 0, 0, false
	}
	if indx, err = strconv.ParseInt(fields[1], 10, 64); err != nil || indx < 0 {
		return 0, 0, 0, false
	}
	if bsize, err = strconv.ParseInt(fields[2], 10, 64); err != nil || bsize < 0 {
		return 0, 0, 0, false
	}
	return id, indx, bsize, true
}

// lookup fetches one slice_map row; ok=false means the id is not hydrated
// (a live session's new slice).
func (b *blob) lookup(id uint64) (sliceRow, bool, error) {
	r := sliceRow{id: id}
	var identity, inline []byte
	var pack sql.NullString
	var off, length, clen, alg, keyid sql.NullInt64
	err := b.db.QueryRow(`SELECT kind, identity, pack, off, length, clen, alg, keyid, llen, inline
		FROM slice_map WHERE slice_id = ?`, id).
		Scan(&r.kind, &identity, &pack, &off, &length, &clen, &alg, &keyid, &r.llen, &inline)
	if errors.Is(err, sql.ErrNoRows) {
		return sliceRow{}, false, nil
	}
	if err != nil {
		return sliceRow{}, false, fmt.Errorf("hydrate: sidecar slice %d: %w", id, err)
	}
	r.identity, r.inline = identity, inline
	r.pack, r.off, r.length = pack.String, off.Int64, length.Int64
	r.clen, r.alg, r.keyid = clen.Int64, alg.Int64, keyid.Int64
	return r, true, nil
}

func (b *blob) Get(ctx context.Context, key string, off, limit int64, getters ...object.AttrGetter) (io.ReadCloser, error) {
	id, indx, bsize, ok := parseBlockKey(key)
	if !ok {
		return b.inner.Get(ctx, key, off, limit, getters...)
	}
	r, found, err := b.lookup(id)
	if err != nil {
		return nil, err
	}
	if !found {
		return b.inner.Get(ctx, key, off, limit, getters...)
	}
	data, err := b.sliceBytes(ctx, r)
	if err != nil {
		return nil, err
	}
	blockOff := indx * b.blockSize
	if blockOff+bsize > int64(len(data)) {
		return nil, fmt.Errorf("hydrate: block %s spans [%d,+%d) of a %d-byte slice", key, blockOff, bsize, len(data))
	}
	block := data[blockOff : blockOff+bsize]
	if off < 0 || off > bsize {
		return nil, fmt.Errorf("hydrate: get %s: offset %d beyond block (%d bytes)", key, off, bsize)
	}
	n := bsize - off
	if limit > 0 && limit < n {
		n = limit
	}
	return io.NopCloser(bytes.NewReader(block[off : off+n])), nil
}

// Head synthesizes hydrated block objects from the sidecar (the block's
// size is encoded in its key); everything else passes through.
func (b *blob) Head(ctx context.Context, key string) (object.Object, error) {
	id, _, bsize, ok := parseBlockKey(key)
	if !ok {
		return b.inner.Head(ctx, key)
	}
	if _, found, err := b.lookup(id); err != nil {
		return nil, err
	} else if !found {
		return b.inner.Head(ctx, key)
	}
	return hydratedObj{key: key, size: bsize}, nil
}

// sliceBytes returns one slice's decoded content: inline rows from the
// sidecar, pack rows via a range read + entrycodec decode, with a
// best-effort local cache keyed by identity hex.
func (b *blob) sliceBytes(ctx context.Context, r sliceRow) ([]byte, error) {
	if r.kind == sliceKindInline {
		return r.inline, nil
	}
	var cachePath string
	if b.cacheDir != "" {
		cachePath = filepath.Join(b.cacheDir, hex.EncodeToString(r.identity))
		if data, err := os.ReadFile(cachePath); err == nil && int64(len(data)) == r.llen {
			return data, nil
		}
	}
	var key []byte
	if r.keyid != 0 {
		if len(b.dek) == 0 {
			return nil, fmt.Errorf("hydrate: slice %d is encrypted under key id %d but the blob store has no DEK", r.id, r.keyid)
		}
		key = b.dek
	}
	stored, err := readRange(ctx, b.packs, packstore.PackDirKey+"/"+r.pack, r.off, r.length)
	if err != nil {
		return nil, fmt.Errorf("hydrate: slice %d: %w", r.id, err)
	}
	data, err := entrycodec.Decode(stored, uint8(r.alg), key)
	if err != nil {
		return nil, fmt.Errorf("hydrate: decode slice %d (chunk %x): %w", r.id, r.identity, err)
	}
	if int64(len(data)) != r.llen {
		return nil, fmt.Errorf("hydrate: slice %d decoded to %d bytes, want %d", r.id, len(data), r.llen)
	}
	if cachePath != "" {
		cacheStore(cachePath, b.cacheDir, data)
	}
	return data, nil
}

// cacheStore writes one decoded chunk to the cache, best-effort (temp file
// + rename so concurrent readers never see a partial file).
func cacheStore(path, dir string, data []byte) {
	f, err := os.CreateTemp(dir, ".chunk-*")
	if err != nil {
		return
	}
	if _, err := f.Write(data); err == nil && f.Close() == nil {
		_ = os.Rename(f.Name(), path)
		return
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
}

type hydratedObj struct {
	key  string
	size int64
}

func (o hydratedObj) Key() string          { return o.key }
func (o hydratedObj) Size() int64          { return o.size }
func (o hydratedObj) Mtime() time.Time     { return time.Time{} }
func (o hydratedObj) IsDir() bool          { return false }
func (o hydratedObj) IsSymlink() bool      { return false }
func (o hydratedObj) StorageClass() string { return "" }
func (o hydratedObj) Status() string       { return "" }
