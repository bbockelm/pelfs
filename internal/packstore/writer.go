package packstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
)

// Entry types recorded in pack trailers (docs/design-packfs.md, typed
// entries): the phase-1 middleware writes only data entries; the v2
// publish pipeline adds catalogs, inode shards, and superblock backups so
// rescue can inventory a namespace from packs alone.
const (
	EntryData       = "" // "data" is implied; phase-1 packs predate the field
	EntryCatalog    = "catalog"
	EntryShard      = "shard"
	EntrySuperblock = "sb"
)

// SealedPack identifies an uploaded pack for the superblock's pack list:
// the object name, the BLAKE3-256 of its trailer JSON (verifying the
// location map after a trailer range-read; entry DATA integrity is
// separately end-to-end via chunk identity), and the total object size.
type SealedPack struct {
	Name        string
	TrailerHash [32]byte
	Size        int64
}

// PackWriter accumulates typed entries into a local spool file whose byte
// layout is already the final pack (zero-copy publish) and seals it as one
// federation object. It is the v2 publish pipeline's pack builder; unlike
// Store it has no read side, no tombstones, and no background lifecycle —
// TRANSFORM writes, Seal uploads, done. Not safe for concurrent use.
type PackWriter struct {
	f    *os.File
	size int64
	tr   trailer
	keys map[string]struct{}
}

// NewPackWriter creates a spool in dir.
func NewPackWriter(dir string) (*PackWriter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "publish.pack.*")
	if err != nil {
		return nil, err
	}
	return &PackWriter{
		f:    f,
		tr:   trailer{Version: 1, Created: time.Now().UnixMilli()},
		keys: make(map[string]struct{}),
	}, nil
}

// Has reports whether key was already added — publish dedups identical
// chunk identities within a pack by skipping the second Add.
func (w *PackWriter) Has(key string) bool {
	_, ok := w.keys[key]
	return ok
}

// Add appends one entry. Keys are chunk identities in hex (or catalog /
// shard identities); duplicates are rejected so a location map can never
// be ambiguous about which bytes a key names.
func (w *PackWriter) Add(key, typ string, data []byte) error {
	if w.Has(key) {
		return fmt.Errorf("pack writer: duplicate entry %q", key)
	}
	if _, err := w.f.WriteAt(data, w.size); err != nil {
		return fmt.Errorf("pack writer: append %q: %w", key, err)
	}
	w.tr.Entries = append(w.tr.Entries, PackEntry{Key: key, Off: w.size, Length: int64(len(data)), Type: typ})
	w.keys[key] = struct{}{}
	w.size += int64(len(data))
	return nil
}

// Size reports the accumulated entry bytes (trailer excluded), for the
// caller's cut-at-target-size policy.
func (w *PackWriter) Size() int64 { return w.size }

// Count reports the number of entries added.
func (w *PackWriter) Count() int { return len(w.tr.Entries) }

// Seal finalizes the pack and uploads it to inner under packs/<name>.
// The spool is removed on success; on error the writer remains usable
// only for Abort. An empty writer refuses to seal.
func (w *PackWriter) Seal(ctx context.Context, inner pelicanobj.Store) (SealedPack, error) {
	if len(w.tr.Entries) == 0 {
		return SealedPack{}, fmt.Errorf("pack writer: refusing to seal an empty pack")
	}
	idx, footer, err := encodeTrailer(&w.tr)
	if err != nil {
		return SealedPack{}, err
	}
	if _, err := w.f.WriteAt(append(idx, footer...), w.size); err != nil {
		return SealedPack{}, fmt.Errorf("pack writer: finalize: %w", err)
	}
	name := newPackName()
	if err := retryOn(ctx, "upload pack "+name, defaultRetries, func() error {
		if _, err := w.f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		return inner.Put(ctx, PackDirKey+"/"+name, w.f)
	}); err != nil {
		return SealedPack{}, fmt.Errorf("pack writer: upload %s: %w", name, err)
	}
	sp := SealedPack{Name: name, TrailerHash: blake3.Sum256(idx), Size: w.size + int64(len(idx)) + footerSize}
	w.Abort()
	return sp, nil
}

// Abort discards the spool. Safe to call after Seal or repeatedly.
func (w *PackWriter) Abort() {
	if w.f != nil {
		_ = w.f.Close()
		_ = os.Remove(w.f.Name())
		w.f = nil
	}
}

// PackNameTime extracts the creation timestamp embedded in a pack name
// (p-<unixnano hex>-<rand>). GC's age guard rests on this: packs young by
// name are never deletion candidates, which is what makes the sweep safe
// against concurrent writers without coordination.
func PackNameTime(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "p-") || len(name) < 18 {
		return time.Time{}, false
	}
	ns, err := strconv.ParseUint(name[2:18], 16, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, int64(ns)), true
}
