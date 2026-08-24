package graft

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"

	"lukechampine.com/blake3"
)

// Consulting a graft index without fetching it.
//
// The spike fetched every index WHOLE at mount and hashed it. That is
// right at 459 bytes and impossible at the size this feature is for: a
// 10 TB graft cut at the 1 MiB floor indexes to 505 MB, and a 100 TB one
// to 5 GB. A mount cannot begin by moving that, and the design doc named
// this the single thing between the feature and its own scale target.
//
// So this is the same reader internal/mpi already wrote for the multi-
// pack index, against the same packidx sampling, and the same two things
// stay resident: the samples (count/Stride identities — 328 KB for a
// 10 TB graft) and the STRING TABLE of source object keys, which is
// bounded by the number of source OBJECTS and not by the number of
// blocks. 100,000 objects is about 6 MB however large the tree is.
//
// # Why there is no per-window digest, and why that is not a weakening
//
// The superblock signs a BLAKE3 over the whole index object. A reader
// that fetches 48 KB out of the middle cannot check it, and mpi's answer
// — that an index is never consulted about BYTES — applies here word for
// word, though it takes one more step to see.
//
// What a graft index produces is a LOCATION. The bytes fetched from that
// location are hashed and compared against the identity the SIGNED
// CATALOG names, unconditionally, with no configuration that disables it
// (genfs.readGraftChunk). A substituted, corrupted or truncated index can
// therefore send a reader to the wrong object, to the wrong offset, or to
// nothing at all — and every one of those ends in a read that FAILS. None
// of them ends in a byte being accepted. The identity check is what the
// integrity story rests on; the index hash is defence in depth over a
// hint.
//
// The hash is still checked whenever the index comes down whole, because
// at that size it is free and it turns a corrupt index into one clear
// error at mount instead of a confusing one per file.
//
// What the whole-object hash was ALSO doing is bounding this reader's
// appetite, and that is replaced the way mpi replaced it: every length
// off the wire is held against GraftEntry.Size, which the signature does
// cover, before a byte is allocated.

// wholeFetchMax is the largest index still read whole. Below it the
// object is one request either way, the whole-object hash applies, and
// every lookup afterwards is free. 4 MiB is about 87,000 blocks — an
// 87 GB graft at the 1 MiB floor, or a 700 GB one where the ladder has
// climbed to 8 MiB.
//
// It is a var only so that tests can exercise the windowed path against a
// fixture that builds in milliseconds. Nothing in the tree writes it.
var wholeFetchMax int64 = 4 << 20

const (
	// prefixProbe is how much of a large index the first request asks
	// for, blind. It has to cover the header, the whole string table and
	// the samples to finish in one round trip, and the string table is
	// the term that grows: 256 KiB covers a few thousand source objects,
	// and a tree of a hundred thousand pays one more request ONCE, at
	// first use, not per lookup.
	prefixProbe = 256 << 10
	// maxWindowBytes refuses an outsized lookup window, so that a header
	// claiming a preposterous stride cannot turn one lookup into a
	// whole-object read.
	maxWindowBytes = 8 << 20
)

// Reader is one graft index consulted over the network — whole when it is
// small, through the header and windows when it is not.
//
// It makes NO REQUESTS until something asks it a question, which matters
// because openGrafts runs before the mount serves anything: a volume with
// a graft nobody reads pays nothing for it.
type Reader struct {
	obj pelicanobj.Store
	ent superblock.GraftEntry

	mu     sync.Mutex
	loaded bool
	err    error

	keys []string
	// whole is set when the object came down entire and verified; hdr and
	// tbl describe the windowed mode instead.
	whole *Index
	hdr   *packidx.Header
	tbl   int64
}

// OpenReader names an index without touching it.
func OpenReader(obj pelicanobj.Store, ent superblock.GraftEntry) *Reader {
	return &Reader{obj: obj, ent: ent}
}

// Entry is the superblock entry this reads.
func (r *Reader) Entry() superblock.GraftEntry { return r.ent }

// Load resolves the resident part. openGrafts calls it at mount so that
// an unreadable index is one clear failure there rather than a failure
// per file later — which is the asymmetry with PackIndexes the design doc
// argues for: a graft is the only record of where its bytes live.
func (r *Reader) Load(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		return nil
	}
	if r.err != nil && ctx.Err() == nil {
		return r.err
	}
	if err := r.loadLocked(ctx); err != nil {
		r.err = err
		return err
	}
	r.loaded, r.err = true, nil
	return nil
}

func (r *Reader) loadLocked(ctx context.Context) error {
	if r.ent.Size <= 0 {
		return fmt.Errorf("graft %s: index ref carries no size, so nothing can bound the read",
			r.ent.Path)
	}
	if r.ent.Size <= wholeFetchMax {
		raw, err := r.get(ctx, 0, r.ent.Size)
		if err != nil {
			return err
		}
		if h := blake3.Sum256(raw); h != r.ent.Index {
			return fmt.Errorf("graft %s: index object %x hashes to %x", r.ent.Path, r.ent.Index, h)
		}
		ix, err := Open(raw)
		if err != nil {
			return fmt.Errorf("graft %s: %w", r.ent.Path, err)
		}
		r.whole, r.keys = ix, ix.keys
		return nil
	}
	return r.loadPrefix(ctx)
}

// loadPrefix fetches header, string table and samples, growing the
// request to exactly what the bytes already in hand say is needed.
//
// Three attempts is the structural bound, not a retry policy: the first
// learns the string table's length, the second the sample count, and a
// third can only be needed if the string table pushed the samples out of
// the second. Each step asks for a length the previous step COMPUTED.
func (r *Reader) loadPrefix(ctx context.Context) error {
	want := int64(prefixProbe)
	for attempt := 0; attempt < 3; attempt++ {
		if want > r.ent.Size {
			want = r.ent.Size
		}
		buf, err := r.get(ctx, 0, want)
		if err != nil {
			return err
		}
		need, err := r.prefixExtent(buf)
		if err != nil {
			return err
		}
		if int64(len(buf)) >= need {
			return r.adopt(buf[:need])
		}
		if want == r.ent.Size {
			return fmt.Errorf("%w: graft %s needs a %d-byte prefix of a %d-byte object",
				ErrFormat, r.ent.Path, need, r.ent.Size)
		}
		want = need
	}
	return fmt.Errorf("%w: graft %s did not settle on a prefix length", ErrFormat, r.ent.Path)
}

// prefixExtent is how many bytes of the object the resident part
// occupies, computed from as much of it as buf already holds. When buf is
// too short to say, it returns a length that will be enough to say —
// never a guess that could be short twice for the same reason.
func (r *Reader) prefixExtent(buf []byte) (int64, error) {
	name := "graft " + r.ent.Path
	if len(buf) < headerLen {
		return headerLen + packidx.HeaderSize, nil
	}
	if string(buf[0:8]) != magic {
		return 0, fmt.Errorf("%w: %s", ErrFormat, name)
	}
	if v := binary.LittleEndian.Uint32(buf[8:]); v != Version {
		return 0, fmt.Errorf("%w: %s is version %d, not %d", ErrFormat, name, v, Version)
	}
	strLen := int64(binary.LittleEndian.Uint64(buf[24:]))
	tbl := int64(headerLen) + strLen
	if strLen < 0 || tbl+packidx.HeaderSize > r.ent.Size {
		return 0, fmt.Errorf("%w: %s claims %d bytes of object keys in a %d-byte object",
			ErrFormat, name, strLen, r.ent.Size)
	}
	if int64(len(buf)) < tbl+packidx.HeaderSize {
		// The samples are not readable yet. GraftEntry.Blocks is the
		// generation's own count, so it sizes the next ask without being
		// trusted — the answer is recomputed from the bytes that arrive.
		samples := (int64(r.ent.Blocks) + Stride - 1) / Stride
		return tbl + packidx.HeaderSize + samples*keyLen, nil
	}
	extent, err := packidx.SampleExtent(buf[tbl:])
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if tbl+extent > r.ent.Size {
		return 0, fmt.Errorf("%w: %s claims %d bytes of samples in a %d-byte object",
			ErrFormat, name, extent, r.ent.Size)
	}
	return tbl + extent, nil
}

// adopt keeps the resident part of a prefix known to be complete.
func (r *Reader) adopt(prefix []byte) error {
	name := "graft " + r.ent.Path
	keys, tbl, _, err := parsePrefix(prefix, r.ent.Size, name)
	if err != nil {
		return err
	}
	hdr, err := packidx.ParseHeader(prefix[tbl:])
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if hdr.KeyLen != keyLen || hdr.RecordLen != recordLen {
		return fmt.Errorf("%w: %s holds %d/%d entries", ErrFormat, name, hdr.KeyLen, hdr.RecordLen)
	}
	entry := int64(hdr.KeyLen + hdr.RecordLen)
	if int64(hdr.Stride)*entry > maxWindowBytes {
		return fmt.Errorf("%w: %s strides %d records, a %d-byte window",
			ErrFormat, name, hdr.Stride, int64(hdr.Stride)*entry)
	}
	if tbl+hdr.SampleBytes()+int64(hdr.Count)*entry > r.ent.Size {
		return fmt.Errorf("%w: %s claims %d entries in a %d-byte object",
			ErrFormat, name, hdr.Count, r.ent.Size)
	}
	r.keys, r.hdr, r.tbl = keys, hdr, tbl
	return nil
}

// Lookup resolves one identity against this graft.
//
// The three answers are distinct and the caller must keep them so: found,
// NOT IN THIS GRAFT (ok false, err nil), and COULD NOT ASK (err). The
// third may never be turned into the second — a graft chunkref resolves
// in no pack by construction, so a reader that shrugged at an unreadable
// index would report "present in no listed pack", which means damage
// everywhere else in this system.
func (r *Reader) Lookup(ctx context.Context, id []byte) (Loc, bool, error) {
	if err := r.Load(ctx); err != nil {
		return Loc{}, false, err
	}
	if r.whole != nil {
		l, ok := r.whole.Lookup(id)
		return l, ok, nil
	}
	if len(id) < keyLen {
		return Loc{}, false, fmt.Errorf("graft %s: %d-byte identity", r.ent.Path, len(id))
	}
	key := id[:keyLen]
	off, length, ok := r.hdr.Window(key)
	if !ok {
		return Loc{}, false, nil
	}
	if length <= 0 || length > maxWindowBytes {
		return Loc{}, false, fmt.Errorf("graft %s: a lookup window of %d bytes", r.ent.Path, length)
	}
	window, err := r.get(ctx, r.tbl+off, length)
	if err != nil {
		return Loc{}, false, err
	}
	if int64(len(window)) < length {
		return Loc{}, false, fmt.Errorf("graft %s: index window at %d came back %d bytes short",
			r.ent.Path, r.tbl+off, length-int64(len(window)))
	}
	v, ok := r.hdr.LookupWindow(window, key)
	if !ok {
		return Loc{}, false, nil
	}
	l, ok := decodeRecord(r.keys, v)
	if !ok {
		return Loc{}, false, fmt.Errorf("%w: graft %s names an object index outside its string table",
			ErrFormat, r.ent.Path)
	}
	return l, true, nil
}

// Objects lists the source objects this graft locates blocks in, read out
// of the string table rather than out of the records — so it costs
// nothing at any index size, in either mode. fsck's cheap mode stats
// exactly these.
func (r *Reader) Objects(ctx context.Context) ([]string, error) {
	if err := r.Load(ctx); err != nil {
		return nil, err
	}
	return append([]string(nil), r.keys...), nil
}

// Blocks is how many blocks the index holds, taken from the signed entry
// so that it is answerable without a request.
func (r *Reader) Blocks() int { return int(r.ent.Blocks) }

// Windowed reports whether this index is being read by window rather than
// held whole, which is a fact a mount's log line should carry: it is the
// difference between one round trip at mount and one small round trip per
// distinct block read.
func (r *Reader) Windowed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loaded && r.whole == nil
}

// get reads one range and returns it whole. Ranges here are a header, a
// string table or one window, so buffering the answer is the shape every
// caller wants anyway.
func (r *Reader) get(ctx context.Context, off, length int64) ([]byte, error) {
	rc, err := r.obj.Get(ctx, IndexKey(r.ent.Index), off, length)
	if err != nil {
		return nil, fmt.Errorf("graft %s: read index at %d: %w", r.ent.Path, off, err)
	}
	defer rc.Close() //nolint:errcheck
	// LimitReader rather than ReadAll: a store that ignores the limit must
	// not be able to hand back the whole object.
	buf, err := io.ReadAll(io.LimitReader(rc, length))
	if err != nil {
		return nil, fmt.Errorf("graft %s: read index at %d: %w", r.ent.Path, off, err)
	}
	return buf, nil
}

// SetWholeFetchMaxForTest lowers the whole-fetch ceiling so that a test
// can exercise the windowed path against a fixture that builds in
// milliseconds, and returns the function that restores it. Nothing in the
// tree calls it outside a test.
func SetWholeFetchMaxForTest(n int64) func() {
	old := wholeFetchMax
	wholeFetchMax = n
	return func() { wholeFetchMax = old }
}
