package mpi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/bbockelm/pelfs/internal/packidx"
	"github.com/bbockelm/pelfs/internal/pelicanobj"
	"github.com/bbockelm/pelfs/internal/superblock"
)

// Consulting an index without fetching it.
//
// The package comment says an index at target size "still is not something
// to fetch" and that "the table carries samples so a reader takes the
// header once and one ~64 KB window per lookup". Fetch did the opposite:
// Get(0, -1), BLAKE3 over the whole thing, and the bytes held for the life
// of the mount. At a hundred million objects that is 1.6 GB moved and 1.6
// GB resident before the mount answers its first question, and 25 refs of
// it once tiering freezes at the 64 MiB ceiling. This is the reader the
// format was designed for.
//
// WHAT STAYS RESIDENT, and why it is not the same trap in smaller
// clothing. Two things: the samples, which are N/stride KEYS — 293 KB at a
// hundred million entries — and the strings blob, which is bounded by the
// number of DISTINCT PACK-NAME LISTS rather than by entries. Every entry
// in a pack names the same list, so 400,000 packs cost about 10 MB of blob
// however many objects they hold. Both are already the asymmetry MergeTo
// documents and relies on; this reader just holds the same two things at
// read time that the writer holds at write time.
//
// The blob could be ranged too — a record is an offset INTO it — at the
// cost of a second round trip per lookup, since the offset is only known
// once the window has come back. Holding tens of MB to halve the latency
// of every lookup for the life of a mount is the right side of that trade,
// and it is the side the format's own reasoning already picked.
//
// THE INTEGRITY STORY, which changes here and must be stated rather than
// assumed. The superblock signs ref.Hash, a BLAKE3 over the WHOLE object.
// A reader that fetches 64 KB out of the middle cannot check it: there is
// no per-window digest in the format, and adding one would be a format
// change that buys nothing, because THE INDEX IS NOT WHERE INTEGRITY
// LIVES. What an index produces is a pack NAME, and a name is followed
// through two authenticated gates before it can affect a read:
//
//   - the signed pack list, which is the only thing that authorizes
//     reading a pack object at all and which supplies its size and its
//     trailer hash;
//   - that pack's own TRAILER, whose hash the pack list signs, and which
//     is what actually maps the full 32-byte identity to an offset.
//
// So a substituted, corrupted, or truncated index can make a reader look
// in the wrong pack, or in no pack; it cannot make a reader accept the
// wrong bytes, because it is never consulted about bytes. That is the same
// property that lets genfs treat a verified index as a HINT and fall back
// on it (see genfs/packindex.go), and it is why the whole-object hash was
// always redundant on the read path even when it was affordable.
//
// What the hash was ALSO doing is bounding this reader's appetite, and
// that has to be replaced with something a prefix can check. Every length
// off the wire is held against ref.Size — which the signature does cover —
// before a byte is allocated: a blob longer than the object, a sample
// array longer than the object, a window past its end. A ref with no size
// is refused outright rather than trusted, since without it there is no
// bound at all.
//
// SMALL INDEXES STILL COME WHOLE. Under wholeFetchMax the old path is
// strictly better: one round trip, the full hash check, and no per-lookup
// request thereafter. Windowed reading is what a large index needs, not a
// virtue in itself — which is what the package comment meant by "fetching
// an index whole is an optimization for small ones, not the model".

// wholeFetchMax is the largest index still read whole. Below it the
// object is one request either way, the whole-object hash applies, and
// every lookup afterwards is free — so the windowed path would trade a
// stronger check and fewer requests for memory that was never the problem
// at this size. 4 MiB is about 260,000 entries.
//
// It is a var only so that tests can exercise the windowed path against a
// fixture that builds in milliseconds. Nothing in the tree writes it.
var wholeFetchMax int64 = 4 << 20

const (
	// prefixProbe is how much of a large index the first request asks for,
	// blind. It has to cover the header, the whole strings blob and the
	// samples to finish in one round trip, and the blob is the term that
	// grows: 256 KiB covers a volume of a few thousand packs, and anything
	// larger pays one more request ONCE, at first use, not per lookup.
	prefixProbe = 256 << 10

	// maxWindowBytes refuses an outsized lookup window. A stride of 4096
	// 16-byte entries is 64 KiB; the ceiling is far above that and exists
	// only so a header claiming a preposterous stride cannot turn one
	// lookup into a whole-object read.
	maxWindowBytes = 8 << 20
)

// ErrNoSize reports a ref with no size, which cannot be read windowed:
// every bound this reader applies is relative to it.
var ErrNoSize = errors.New("mpi: index ref carries no size")

// Reader is one index object consulted over the network — whole when it
// is small, through the header and windows when it is not.
//
// It makes NO REQUESTS until something asks it a question. That matters
// beyond tidiness: a mount that resolves its root catalog through the
// superblock's hint, which is the ordinary case, never consults the index
// at all, so the index costs such a mount nothing rather than costing it
// every byte of itself.
type Reader struct {
	obj pelicanobj.Store
	ref superblock.IndexRef

	mu     sync.Mutex
	loaded bool
	err    error

	// blob is the strings blob, resident once loaded, in both modes.
	blob []byte
	// hdr and tbl describe the table for the windowed mode; whole is set
	// instead when the object came down entire and verified.
	hdr   *packidx.Header
	tbl   int64
	whole *Index
}

// OpenReader names an index without touching it.
func OpenReader(obj pelicanobj.Store, ref superblock.IndexRef) *Reader {
	return &Reader{obj: obj, ref: ref}
}

// Name is the object this reads, for an error message that has to say
// which index went wrong.
func (r *Reader) Name() string { return r.ref.Name }

// load resolves the resident part once. A failure is remembered, because
// an index that will not load is an index this mount does without and
// re-asking on every lookup would turn a missing object into a request
// per read — EXCEPT for a cancelled context, which says nothing about the
// index and everything about the caller that gave up.
func (r *Reader) load(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		return nil
	}
	if r.err != nil && ctx.Err() == nil && !errors.Is(r.err, context.Canceled) &&
		!errors.Is(r.err, context.DeadlineExceeded) {
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
	if r.ref.Size <= 0 {
		return fmt.Errorf("%w: %s", ErrNoSize, r.ref.Name)
	}
	if r.ref.Size <= wholeFetchMax {
		ix, err := Fetch(ctx, r.obj, r.ref)
		if err != nil {
			return err
		}
		r.whole, r.blob = ix, ix.blob
		return nil
	}
	return r.loadPrefix(ctx)
}

// loadPrefix fetches header, strings blob and samples, growing the request
// to exactly what the bytes already in hand say is needed.
//
// Three attempts is the structural bound, not a retry policy: the first
// learns the blob length, the second the sample count, and a third can
// only be needed if the blob pushed the samples out of the second. Each
// step asks for a length the previous step COMPUTED, so there is no
// doubling and no possibility of a loop.
func (r *Reader) loadPrefix(ctx context.Context) error {
	want := int64(prefixProbe)
	for attempt := 0; attempt < 3; attempt++ {
		if want > r.ref.Size {
			want = r.ref.Size
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
		if want == r.ref.Size {
			// The object is shorter than its own header says it is.
			return fmt.Errorf("%w: %s needs a %d-byte prefix of a %d-byte object",
				ErrFormat, r.ref.Name, need, r.ref.Size)
		}
		want = need
	}
	return fmt.Errorf("%w: %s did not settle on a prefix length", ErrFormat, r.ref.Name)
}

// prefixExtent is how many bytes of the object the resident part occupies,
// computed from as much of it as buf already holds. When buf is too short
// to say, it returns a length that will be enough to say — never a guess
// that could be short twice for the same reason.
func (r *Reader) prefixExtent(buf []byte) (int64, error) {
	if len(buf) < headerLen {
		return int64(headerLen) + packidx.HeaderSize, nil
	}
	if string(buf[0:8]) != magic {
		return 0, fmt.Errorf("%w: %s", ErrFormat, r.ref.Name)
	}
	if v := binary.LittleEndian.Uint32(buf[8:]); v != 1 {
		return 0, fmt.Errorf("%w: %s is version %d", ErrFormat, r.ref.Name, v)
	}
	blobLen := int64(binary.LittleEndian.Uint32(buf[12:]))
	tbl := int64(headerLen) + blobLen
	// The signed size is the only bound available before anything is
	// allocated, so every length off the wire is held against it.
	if tbl+packidx.HeaderSize > r.ref.Size {
		return 0, fmt.Errorf("%w: %s claims %d bytes of pack names in a %d-byte object",
			ErrFormat, r.ref.Name, blobLen, r.ref.Size)
	}
	if int64(len(buf)) < tbl+packidx.HeaderSize {
		// The samples are not readable yet; ref.Entries is the generation's
		// own count, so it sizes the next ask without being trusted — the
		// answer is recomputed from the bytes that come back.
		samples := (int64(r.ref.Entries) + packidx.DefaultStride - 1) / packidx.DefaultStride
		return tbl + packidx.HeaderSize + samples*KeyLen, nil
	}
	extent, err := packidx.SampleExtent(buf[tbl:])
	if err != nil {
		return 0, fmt.Errorf("%s: %w", r.ref.Name, err)
	}
	if tbl+extent > r.ref.Size {
		return 0, fmt.Errorf("%w: %s claims %d bytes of samples in a %d-byte object",
			ErrFormat, r.ref.Name, extent, r.ref.Size)
	}
	return tbl + extent, nil
}

// adopt keeps the resident part of a prefix that is known to be complete.
func (r *Reader) adopt(prefix []byte) error {
	blobLen := int64(binary.LittleEndian.Uint32(prefix[12:]))
	tbl := int64(headerLen) + blobLen
	hdr, err := packidx.ParseHeader(prefix[tbl:])
	if err != nil {
		return fmt.Errorf("%s: %w", r.ref.Name, err)
	}
	if hdr.KeyLen != KeyLen || hdr.RecordLen != recordLen {
		return fmt.Errorf("%w: %s holds %d/%d entries", ErrFormat, r.ref.Name, hdr.KeyLen, hdr.RecordLen)
	}
	// The records must fit in the object. Without this a truncated or
	// hostile Count would have windows reading past the end, which the
	// store answers with a short read and the window search then
	// misinterprets as a smaller table.
	entry := int64(hdr.KeyLen + hdr.RecordLen)
	// A window is Stride records, so the stride IS the per-lookup transfer
	// and a table naming a preposterous one is a table whose every lookup
	// is a whole-object read. Refusing it here rather than per lookup is
	// the difference between an index this mount does without and one that
	// costs 64 MiB a question.
	if int64(hdr.Stride)*entry > maxWindowBytes {
		return fmt.Errorf("%w: %s strides %d records, a %d-byte window",
			ErrFormat, r.ref.Name, hdr.Stride, int64(hdr.Stride)*entry)
	}
	if tbl+hdr.SampleBytes()+int64(hdr.Count)*entry > r.ref.Size {
		return fmt.Errorf("%w: %s claims %d entries in a %d-byte object",
			ErrFormat, r.ref.Name, hdr.Count, r.ref.Size)
	}
	// The prefix aliases a buffer sized for the request, which may be much
	// larger than what is kept; copy so the slack is collected.
	r.blob = append([]byte(nil), prefix[headerLen:tbl]...)
	r.hdr, r.tbl = hdr, tbl
	return nil
}

// Lookup returns the packs that may hold id. A failure to read the index
// is a MISS, not an error: an index is derived, the trailers answer every
// question it would have, and the caller's fallback is the same one a
// generation listing no index takes.
func (r *Reader) Lookup(ctx context.Context, id [32]byte) ([]string, bool) {
	if err := r.load(ctx); err != nil {
		return nil, false
	}
	if r.whole != nil {
		return r.whole.Lookup(id)
	}
	key := id[:KeyLen]
	off, length, ok := r.hdr.Window(key)
	if !ok || length <= 0 || length > maxWindowBytes {
		return nil, false
	}
	window, err := r.get(ctx, r.tbl+off, length)
	if err != nil || int64(len(window)) < length {
		return nil, false
	}
	v, ok := r.hdr.LookupWindow(window, key)
	if !ok {
		return nil, false
	}
	return names(r.blob, binary.LittleEndian.Uint32(v))
}

// PackNames is every pack this index could name, read out of the strings
// blob rather than out of the entries — the blob IS the set of pack-name
// lists, so this costs no records and works identically in both modes.
//
// It is a superset in principle: nothing forbids an index carrying an
// interned list no entry points at, and neither writer produces one. A
// caller must therefore treat it as "packs this index may know about",
// never as "packs this index has accounted for".
func (r *Reader) PackNames(ctx context.Context) ([]string, bool) {
	if err := r.load(ctx); err != nil {
		return nil, false
	}
	var out []string
	seen := map[string]struct{}{}
	for off := 0; off+2 <= len(r.blob); {
		n := int(binary.LittleEndian.Uint16(r.blob[off:]))
		if off+2+n > len(r.blob) {
			break
		}
		for _, p := range splitNames(string(r.blob[off+2 : off+2+n])) {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		off += 2 + n
	}
	return out, true
}

// get reads one range and returns it whole. Ranges here are a header, a
// blob or one window — kilobytes to a few megabytes — so buffering the
// answer is the shape the caller wants anyway.
func (r *Reader) get(ctx context.Context, off, length int64) ([]byte, error) {
	rc, err := r.obj.Get(ctx, Dir+"/"+r.ref.Name, off, length)
	if err != nil {
		return nil, fmt.Errorf("mpi: read %s at %d: %w", r.ref.Name, off, err)
	}
	defer rc.Close() //nolint:errcheck
	// LimitReader rather than ReadAll: a store that ignores the limit must
	// not be able to hand back the whole object.
	buf, err := io.ReadAll(io.LimitReader(rc, length))
	if err != nil {
		return nil, fmt.Errorf("mpi: read %s at %d: %w", r.ref.Name, off, err)
	}
	return buf, nil
}

// Hints is the generation's indexes consulted as one, oldest first.
//
// It is the read-path counterpart of Set, and separate from it because the
// two answer to different constraints: Set holds indexes a caller already
// has in memory (a merge, a test, a consolidation policy), while this one
// owns the fetching and never promises to have any of it.
type Hints struct{ readers []*Reader }

// NewHints names the generation's indexes. It makes no requests.
func NewHints(obj pelicanobj.Store, refs []superblock.IndexRef) *Hints {
	if len(refs) == 0 {
		return nil
	}
	h := &Hints{readers: make([]*Reader, len(refs))}
	for i, ref := range refs {
		h.readers[i] = OpenReader(obj, ref)
	}
	return h
}

// Lookup asks the NEWEST index first and stops at the first hit, which is
// "the most recent pack holding this object". Order matters because the
// same identity is placed again by any generation that rewrites it, and an
// older tier's answer names a pack retention is more likely to have swept.
func (h *Hints) Lookup(ctx context.Context, id [32]byte) ([]string, bool) {
	if h == nil {
		return nil, false
	}
	for i := len(h.readers) - 1; i >= 0; i-- {
		if packs, ok := h.readers[i].Lookup(ctx, id); ok {
			return packs, true
		}
	}
	return nil, false
}

// Warm loads every index's resident part CONCURRENTLY.
//
// Serial loads would trade N round trips for a smaller N still paid one
// after another, which is most of the problem rather than a fix. It is
// what makes TIERS affordable: a lookup that may consult several indexes
// costs one round trip of latency, not one per tier.
//
// Nothing calls this before the first question — a mount that never
// consults its indexes must not pay for them — so it exists for the first
// lookup, which pays for all of them at once instead of for its own.
func (h *Hints) Warm(ctx context.Context) {
	if h == nil {
		return
	}
	workers := min(len(h.readers), max(4, runtime.GOMAXPROCS(0)))
	next := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range next {
				_ = h.readers[i].load(ctx)
			}
		})
	}
	for i := range h.readers {
		select {
		case next <- i:
		case <-ctx.Done():
			close(next)
			wg.Wait()
			return
		}
	}
	close(next)
	wg.Wait()
}
