// Package packstore is the pack container of the v2 format
// (docs/design-packfs.md): many small entries — data chunks, catalogs,
// inode shards, superblock backups — written into one large immutable
// federation object.
//
// A pack is self-describing: a zstd-compressed JSON trailer maps entry
// keys to (offset, length, type), and a fixed footer records the trailer's
// length and magic. A reader fetches the trailer with a single tail range
// request — Pelican origins and caches serve ranges natively — and that
// tells it which pack holds what. Whether it then reads entries as ranges
// or takes the object whole is the reader's policy, not the container's;
// genfs takes it whole, and the trailer is what tells it which one to
// take.
//
// Pack names embed their creation time, which is what makes the retention
// sweep's age guard work without any coordination between writers and GC.
package packstore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"lukechampine.com/blake3"

	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/ui"
)

const (
	magic         = "PELFSPK1" // trailer stored as plain JSON (legacy packs)
	magicZ        = "PELFSPK2" // trailer stored as zstd-compressed JSON
	magicT        = "PELFSPK3" // trailer stored as a sorted lookup table
	footerSize    = 8 + 8      // stored-trailer length + magic
	tailProbe     = 128 << 10
	defaultTarget = 64 << 20
	// PackDirKey is the key-space directory holding pack objects.
	PackDirKey = "packs"
)

// trailer is the JSON document at the end of every pack.
type trailer struct {
	Version int         `json:"v"`
	Created int64       `json:"created_ms"`
	Entries []PackEntry `json:"entries"`
	Dead    []string    `json:"dead,omitempty"`
}

// Trailer codec: written as zstd-compressed JSON under magic PELFSPK2
// (identity hashes make trailers big and repetitive; nobody reads them by
// hand), read as either flavor so PELFSPK1 packs stay valid forever. The
// footer length and the pack list's TrailerHash both refer to the stored
// (compressed) bytes.
var (
	trailerEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	trailerDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
)

// encodeTrailer returns the stored trailer bytes and the 16-byte footer.
//
// The table form (PELFSPK3) is written now. A trailer is consulted to
// answer ONE question — where is this identity — and the JSON forms make
// a reader decompress the whole document and parse every entry before it
// can answer, which a mount pays once per pack. The table is read in
// place (see internal/packidx and LookupStored).
//
// Every key in a pack is a 32-byte identity in hex, which is what makes
// the table possible; a key that is not falls back to JSON rather than
// being dropped, because a trailer that cannot describe an entry is worse
// than a slow one.
func encodeTrailer(tr *trailer) (stored, footer []byte, err error) {
	stored, err = encodeTable(tr)
	m := magicT
	if err != nil {
		raw, jerr := json.Marshal(tr)
		if jerr != nil {
			return nil, nil, jerr
		}
		stored, m = trailerEnc.EncodeAll(raw, nil), magicZ
	}
	footer = make([]byte, footerSize)
	binary.LittleEndian.PutUint64(footer[:8], uint64(len(stored)))
	copy(footer[8:], m)
	return stored, footer, nil
}

// knownTrailerMagic is the one place the set of trailer forms is written
// down. Packs are immutable, so every form ever written stays readable
// for as long as a generation names the pack carrying it — and a reader
// that learns a new form must learn it HERE as well as in the decoder.
// Adding PELFSPK3 to the decoder alone made every new pack unreadable,
// with the footer check rejecting it before the decoder was reached.
func knownTrailerMagic(m string) bool {
	return m == magic || m == magicZ || m == magicT
}

// decodeTrailer parses stored trailer bytes according to the footer magic.
func decodeTrailer(stored []byte, m string) (*trailer, error) {
	if m == magicT {
		return decodeTable(stored)
	}
	raw := stored
	if m == magicZ {
		var err error
		if raw, err = trailerDec.DecodeAll(stored, nil); err != nil {
			return nil, fmt.Errorf("decompress index: %w", err)
		}
	}
	var tr trailer
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	if tr.Version != 1 {
		return nil, fmt.Errorf("unsupported pack version %d", tr.Version)
	}
	// Trailers are untrusted federation bytes: an entry with a negative
	// or overflowing extent must never reach the range-read path.
	for _, e := range tr.Entries {
		if e.Off < 0 || e.Length < 0 || e.Off+e.Length < 0 {
			return nil, fmt.Errorf("parse index: entry %q has invalid extent [%d,+%d)", e.Key, e.Off, e.Length)
		}
	}
	return &tr, nil
}

// PackEntry is one entry record in a pack trailer.
type PackEntry struct {
	Key    string `json:"k"`
	Off    int64  `json:"o"`
	Length int64  `json:"l"`
	// Type distinguishes entry kinds for disaster-recovery scavenging
	// (docs/design-packfs.md): "" or "data" = data chunk, plus "catalog",
	// "shard", and "sb" (superblock backup). It is omitempty, so a pack
	// of nothing but chunks carries no types and the rescue tooling has
	// to read an absent field as a data chunk.
	Type string `json:"t,omitempty"`
}

// FetchTrailer reads and parses one pack trailer directly from a transport
// (no Store needed): the restore path resolves identities from a
// GENERATION pack list, not a directory listing, and rescue inventories
// packs the same way. A non-positive size is looked up with a stat.
func FetchTrailer(ctx context.Context, inner pelicanobj.Store, name string, size int64) ([]PackEntry, error) {
	if size <= 0 {
		ki, err := inner.StatKey(ctx, PackDirKey+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("stat pack %s: %w", name, err)
		}
		size = ki.Size
	}
	tr, _, err := fetchTrailer(ctx, inner, name, size)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", name, err)
	}
	return tr.Entries, nil
}

// FetchTrailerVerified is FetchTrailer plus location-map authentication:
// the STORED trailer bytes must hash (BLAKE3-256) to wantHash — the value
// the superblock pack list records — before any entry is trusted. Readers
// resolving a signed generation use this; entry DATA integrity is
// separately end-to-end via chunk identity.
func FetchTrailerVerified(ctx context.Context, inner pelicanobj.Store, name string, size int64, wantHash [32]byte) ([]PackEntry, error) {
	entries, _, err := FetchTrailerStoredVerified(ctx, inner, name, size, wantHash)
	return entries, err
}

// FetchTrailerStoredVerified is FetchTrailerVerified that also hands back
// the STORED trailer bytes the hash was checked against.
//
// It exists so a reader can keep them. Packs are immutable and the hash
// comes from the signed superblock, so a saved copy is not a cache that
// has to be invalidated — it is the same bytes, authenticated the same
// way, and re-reading it locally is exactly as sound as re-fetching it.
// That matters because a mount indexes EVERY pack in the generation
// before it serves anything, which is one federation round trip per pack
// per mount for bytes that can never have changed.
func FetchTrailerStoredVerified(ctx context.Context, inner pelicanobj.Store, name string, size int64, wantHash [32]byte) ([]PackEntry, []byte, error) {
	if size <= 0 {
		ki, err := inner.StatKey(ctx, PackDirKey+"/"+name)
		if err != nil {
			return nil, nil, fmt.Errorf("stat pack %s: %w", name, err)
		}
		size = ki.Size
	}
	tr, stored, _, err := fetchTrailerStored(ctx, inner, name, size)
	if err != nil {
		return nil, nil, fmt.Errorf("pack %s: %w", name, err)
	}
	if got := blake3.Sum256(stored); got != wantHash {
		return nil, nil, fmt.Errorf("pack %s: trailer hash mismatch (got %x, pack list says %x) — the location map does not match the signed generation", name, got, wantHash)
	}
	return tr.Entries, stored, nil
}

// ParseStoredTrailer parses stored trailer bytes on their own, without the
// footer that normally says how they are encoded. A saved copy has no
// footer, and needs none: the two encodings are distinguishable from the
// bytes themselves — a zstd frame opens with its own magic number, and the
// legacy form is a JSON object.
//
// The caller is responsible for having authenticated the bytes (the
// superblock's TrailerHash); this only decodes them.
func ParseStoredTrailer(stored []byte) ([]PackEntry, error) {
	m := magic
	switch {
	case isTable(stored):
		m = magicT
	case len(stored) >= 4 && binary.LittleEndian.Uint32(stored[:4]) == zstdFrameMagic:
		m = magicZ
	}
	tr, err := decodeTrailer(stored, m)
	if err != nil {
		return nil, err
	}
	return tr.Entries, nil
}

// StoredTrailerFrom reads the stored trailer bytes out of a pack the
// caller already holds whole — a local file rather than a range request.
//
// It returns the bytes rather than the entries because the caller must
// still hash them against the signed pack list: a pack sitting in a cache
// directory has had no less opportunity to go wrong than one arriving off
// the wire, and a location map that came from an unverified trailer would
// send reads to arbitrary offsets in an arbitrary object.
func StoredTrailerFrom(r io.ReaderAt, size int64) ([]byte, error) {
	if size < footerSize {
		return nil, fmt.Errorf("pack too small (%d bytes)", size)
	}
	var footer [footerSize]byte
	if _, err := r.ReadAt(footer[:], size-footerSize); err != nil {
		return nil, err
	}
	if m := string(footer[8:]); !knownTrailerMagic(m) {
		return nil, fmt.Errorf("bad pack magic")
	}
	idxLen := int64(binary.LittleEndian.Uint64(footer[:8]))
	if idxLen <= 0 || idxLen+footerSize > size {
		return nil, fmt.Errorf("bad index length %d", idxLen)
	}
	stored := make([]byte, idxLen)
	if _, err := r.ReadAt(stored, size-footerSize-idxLen); err != nil {
		return nil, err
	}
	return stored, nil
}

// zstdFrameMagic is the zstd frame header magic number (RFC 8878), which
// is how stored trailer bytes announce their own encoding.
const zstdFrameMagic = 0xFD2FB528

func fetchTrailer(ctx context.Context, inner pelicanobj.Store, name string, size int64) (*trailer, int64, error) {
	tr, _, idxLen, err := fetchTrailerStored(ctx, inner, name, size)
	return tr, idxLen, err
}

func fetchTrailerStored(ctx context.Context, inner pelicanobj.Store, name string, size int64) (*trailer, []byte, int64, error) {
	if size < footerSize {
		return nil, nil, 0, fmt.Errorf("pack too small (%d bytes)", size)
	}
	probe := int64(tailProbe)
	if probe > size {
		probe = size
	}
	tail, err := readRangeFrom(ctx, inner, PackDirKey+"/"+name, size-probe, probe)
	if err != nil {
		return nil, nil, 0, err
	}
	tr, stored, idxLen, terr := parseTail(ctx, inner, name, size, tail)
	if terr == nil {
		return tr, stored, idxLen, nil
	}
	// Tail probe failed: fetch the entire pack and retry against its true
	// end. Success here means the object is fine and the RANGE read lied
	// (wrong bytes or wrong length) — report that loudly, because every
	// chunk read depends on ranges working.
	whole, werr := readRangeFrom(ctx, inner, PackDirKey+"/"+name, 0, size)
	if werr == nil && int64(len(whole)) == size {
		if tr, stored, idxLen, ferr := parseTail(ctx, inner, name, size, whole); ferr == nil {
			ui.Warn("pack {pack}: tail range read returned invalid bytes ({error}) but the full "+
				"object is intact — a transport in the path is mishandling Range requests; "+
				"reads may be unreliable", "pack", name, "error", terr)
			return tr, stored, idxLen, nil
		}
	}
	preview := tail
	if len(preview) > 16 {
		preview = preview[len(preview)-16:]
	}
	return nil, nil, 0, fmt.Errorf("%w (listed size %d, tail read %d bytes, last bytes %x; full-object retry: %v)",
		terr, size, len(tail), preview, werr)
}

// parseTail validates and parses a trailer from buf, which is the final
// portion of a pack of the given total size. It also returns the stored
// (possibly compressed) trailer bytes, which the superblock pack list
// hashes.
func parseTail(ctx context.Context, inner pelicanobj.Store, name string, size int64, buf []byte) (*trailer, []byte, int64, error) {
	if len(buf) < footerSize {
		return nil, nil, 0, fmt.Errorf("bad pack magic")
	}
	m := string(buf[len(buf)-8:])
	if !knownTrailerMagic(m) {
		return nil, nil, 0, fmt.Errorf("bad pack magic")
	}
	idxLen := int64(binary.LittleEndian.Uint64(buf[len(buf)-16 : len(buf)-8]))
	if idxLen <= 0 || idxLen+footerSize > size {
		return nil, nil, 0, fmt.Errorf("bad index length %d", idxLen)
	}
	var stored []byte
	var err error
	if idxLen+footerSize <= int64(len(buf)) {
		stored = buf[int64(len(buf))-footerSize-idxLen : int64(len(buf))-footerSize]
	} else {
		stored, err = readRangeFrom(ctx, inner, PackDirKey+"/"+name, size-footerSize-idxLen, idxLen)
		if err != nil {
			return nil, nil, 0, err
		}
	}
	tr, err := decodeTrailer(stored, m)
	if err != nil {
		return nil, nil, 0, err
	}
	return tr, stored, idxLen, nil
}

func readRangeFrom(ctx context.Context, inner pelicanobj.Store, key string, off, length int64) ([]byte, error) {
	var buf []byte
	err := retryOn(ctx, fmt.Sprintf("read %s [%d,+%d)", key, off, length), defaultRetries, func() error {
		var err error
		buf, err = readRangeOnce(ctx, inner, key, off, length)
		return err
	})
	return buf, err
}

func readRangeOnce(ctx context.Context, inner pelicanobj.Store, key string, off, length int64) ([]byte, error) {
	rc, err := inner.Get(ctx, key, off, length)
	if err != nil {
		return nil, err
	}
	buf, rerr := io.ReadAll(io.LimitReader(rc, length))
	// Transports that stream through a transfer engine may report the
	// job's failure only at Close: an errored transfer otherwise looks
	// like a clean zero-byte read. Never swallow it.
	cerr := rc.Close()
	if rerr != nil {
		return nil, rerr
	}
	if cerr != nil {
		return nil, fmt.Errorf("read %s [%d,+%d): %w", key, off, length, cerr)
	}
	if int64(len(buf)) != length {
		return nil, fmt.Errorf("read %s [%d,+%d): short read (%d bytes)", key, off, length, len(buf))
	}
	return buf, nil
}

func newPackName() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("p-%016x-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

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
