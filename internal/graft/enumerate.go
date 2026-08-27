package graft

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/bbockelm/pelfs/internal/packidx"

	"lukechampine.com/blake3"
)

// Walking a graft index instead of searching it.
//
// The spike had a graftIdentities helper that built the whole identity
// set in memory and nothing called it; it was deleted rather than kept,
// because at the 10.5 million blocks of a 10 TB graft that set is 336 MB
// resident and the shape a sweep actually wants is a SEQUENTIAL PASS.
// This is that pass.
//
// # Who needs it
//
// internal/fsck, and only it. A mount asks an index one question at a
// time and gets one window per question (remote.go); a check asks it
// every question there is, and doing that through Lookup would be one
// ranged request per block — ten million requests where one stream will
// do. The two access patterns want opposite readers, which is why this
// is a second entry point rather than a loop over the first.
//
// # What it costs, and what it does not
//
// Memory is the STRING TABLE plus one read buffer, and neither term
// grows with the number of blocks: the string table is bounded by the
// number of source objects (6 MB at 100,000 objects with 60-character
// keys, whether the graft is 10 GB or 10 TB) and the buffer is 256 KiB.
// Records are decoded one at a time into a stack array and handed to the
// callback, which is free to keep nothing. Nothing here accumulates.
//
// The samples are read and thrown away rather than kept: a sequential
// pass never searches, so the one structure a windowed READER holds for
// the life of a mount is exactly the one a sweep does not need. They are
// still fed to the hash, because the hash covers the object.
//
// # It verifies the whole-object hash, which a mount cannot
//
// A large index is loaded by header-plus-window (remote.go), and that
// reader deliberately does NOT check the object against the hash the
// superblock signs — it never holds the whole object, and the argument
// for why it does not need to is written there: an index produces a
// LOCATION, and every byte that location produces is checked against the
// identity a signed catalog names.
//
// A sweep does hold the whole object, one buffer at a time, so it gets
// the check for free and takes it. That makes fsck strictly stronger
// than a mount on this one point: a corrupt index that a mount would
// only reveal as scattered read failures is one clear finding here.

// EnumResult is what one pass over an index object saw.
type EnumResult struct {
	// Blocks is how many records the index holds, and Objects how many
	// distinct source objects its string table names. Objects counts the
	// TABLE, not the records: an object all of whose blocks deduped into
	// an earlier one keeps its name here and owns no record.
	Blocks, Objects int
	// Bytes is how much of the index object was read. Zero when the
	// index was already held whole and the pass ran over memory.
	Bytes int64
	// Streamed says which of those two happened, which is the difference
	// between a pass that cost a request and one that cost nothing.
	Streamed bool
}

// enumBufSize is the read buffer for a streamed pass. It is the only
// term in this pass's memory that is a choice rather than a consequence,
// and 256 KiB is about 5,400 records — enough that the syscall and TLS
// framing per record vanish, small enough to be uninteresting beside the
// string table it sits next to.
const enumBufSize = 256 << 10

// Enumerate calls fn once per block the index holds, in index order
// (which is identity order), and reports what the pass saw.
//
// It streams: a 505 MB index for a 10 TB graft is read one buffer at a
// time and never materialized, so memory is bounded by the source-object
// count and not by the block count. An index small enough to have been
// fetched whole at Load is walked over the copy already in hand, at no
// further cost.
//
// The pass CHECKS AS IT GOES, and the checks are the ones only a
// sequential reader is in a position to make:
//
//   - the object hashes to what the superblock's entry names (streamed
//     mode only; the whole-fetch path already did it at Load),
//   - the records are strictly ascending, which nothing else verifies —
//     packidx deliberately does not check order at open, because that is
//     a pass over every entry, and an out-of-order table answers "not
//     found" rather than answering wrongly. For a PACK that degrades to
//     the caller's fallback; for a graft there is no fallback, so an
//     unsorted index is silently unreadable files, and this is the only
//     place it can be caught,
//   - every record names an object inside the string table.
//
// A structural failure stops the pass and is returned; so is an error
// from fn, unchanged, so a caller may use it to stop early.
func (r *Reader) Enumerate(ctx context.Context, fn func(Block) error) (EnumResult, error) {
	if err := r.Load(ctx); err != nil {
		return EnumResult{}, err
	}
	r.mu.Lock()
	whole, keys := r.whole, r.keys
	r.mu.Unlock()
	if whole != nil {
		return enumerateTable(whole.table, keys, "graft "+r.ent.Path, fn)
	}
	return r.enumerateStream(ctx, fn)
}

// enumerateTable walks a table already in memory.
func enumerateTable(t *packidx.Table, keys []string, name string, fn func(Block) error) (EnumResult, error) {
	res := EnumResult{Objects: len(keys)}
	var prev []byte
	for i := range t.Len() {
		k, v := t.At(i)
		if err := checkOrder(name, i, prev, k); err != nil {
			return res, err
		}
		prev = k
		b, err := blockOf(keys, name, i, k, v)
		if err != nil {
			return res, err
		}
		res.Blocks++
		if err := fn(b); err != nil {
			return res, err
		}
	}
	return res, nil
}

// enumerateStream reads the object from byte zero, in order, hashing
// everything it consumes.
//
// It makes ONE ranged request for the whole object rather than a request
// per window. That is the shape a sequential reader wants from every
// transport pelfs has: a range server streams it, and the alternative —
// stride-sized ranges — is ten thousand round trips for a 500 MB index
// and no less memory.
func (r *Reader) enumerateStream(ctx context.Context, fn func(Block) error) (EnumResult, error) {
	name := "graft " + r.ent.Path
	res := EnumResult{Streamed: true}
	rc, err := r.obj.Get(ctx, IndexKey(r.ent.Index), 0, r.ent.Size)
	if err != nil {
		return res, fmt.Errorf("%s: read index: %w", name, err)
	}
	defer rc.Close() //nolint:errcheck

	h := blake3.New(32, nil)
	// LimitReader before TeeReader, in that order: a store that ignores
	// the range must not be able to feed the hash bytes the signature
	// never covered, nor to run this pass off the end of a signed length.
	counted := &countingReader{r: io.LimitReader(rc, r.ent.Size)}
	br := bufio.NewReaderSize(io.TeeReader(counted, h), enumBufSize)

	head := make([]byte, headerLen)
	if _, err := io.ReadFull(br, head); err != nil {
		return res, fmt.Errorf("%s: read index header: %w", name, err)
	}
	if string(head[0:8]) != magic {
		return res, fmt.Errorf("%w: %s", ErrFormat, name)
	}
	if v := binary.LittleEndian.Uint32(head[8:]); v != Version {
		return res, fmt.Errorf("%w: %s is version %d, not %d", ErrFormat, name, v, Version)
	}
	nkeys := int(binary.LittleEndian.Uint32(head[12:]))
	strLen := int64(binary.LittleEndian.Uint64(head[24:]))
	if strLen < 0 || headerLen+strLen > r.ent.Size {
		return res, fmt.Errorf("%w: %s claims %d bytes of object keys in a %d-byte object",
			ErrFormat, name, strLen, r.ent.Size)
	}
	strs := make([]byte, strLen)
	if _, err := io.ReadFull(br, strs); err != nil {
		return res, fmt.Errorf("%s: read object keys: %w", name, err)
	}
	keys := splitKeys(strs)
	if len(keys) != nkeys {
		return res, fmt.Errorf("%w: %s says %d objects, the string table holds %d",
			ErrFormat, name, nkeys, len(keys))
	}
	res.Objects = len(keys)

	hdr, err := readSampleHeader(br, r.ent.Size-headerLen-strLen, name)
	if err != nil {
		return res, err
	}
	if hdr.KeyLen != keyLen || hdr.RecordLen != recordLen {
		return res, fmt.Errorf("%w: %s holds %d/%d entries", ErrFormat, name, hdr.KeyLen, hdr.RecordLen)
	}
	entry := int64(hdr.KeyLen + hdr.RecordLen)
	tbl := int64(headerLen) + strLen
	if tbl+hdr.SampleBytes()+int64(hdr.Count)*entry > r.ent.Size {
		return res, fmt.Errorf("%w: %s claims %d entries in a %d-byte object",
			ErrFormat, name, hdr.Count, r.ent.Size)
	}

	var rec [keyLen + recordLen]byte
	var prev [keyLen]byte
	for i := range hdr.Count {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return res, fmt.Errorf("%s: read index record %d of %d: %w", name, i, hdr.Count, err)
		}
		var p []byte
		if i > 0 {
			p = prev[:]
		}
		if err := checkOrder(name, i, p, rec[:keyLen]); err != nil {
			return res, err
		}
		copy(prev[:], rec[:keyLen])
		b, err := blockOf(keys, name, i, rec[:keyLen], rec[keyLen:])
		if err != nil {
			return res, err
		}
		res.Blocks++
		if err := fn(b); err != nil {
			res.Bytes = counted.n
			return res, err
		}
	}
	// The tail is drained rather than ignored: the hash below is over the
	// WHOLE object, so anything after the last record has to reach it.
	if _, err := io.Copy(io.Discard, br); err != nil {
		return res, fmt.Errorf("%s: read index: %w", name, err)
	}
	res.Bytes = counted.n
	if res.Bytes != r.ent.Size {
		return res, fmt.Errorf("%w: %s is %d bytes, the generation names %d",
			ErrFormat, name, res.Bytes, r.ent.Size)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if sum != r.ent.Index {
		return res, fmt.Errorf("%s: index object %x hashes to %x", name, r.ent.Index, sum)
	}
	return res, nil
}

// readSampleHeader reads packidx's fixed header and then exactly the
// samples it names, in two reads, and parses the pair.
//
// The samples are consumed and discarded — a sequential pass never
// searches, so the structure a windowed reader keeps for the life of a
// mount is the one this does not need. They still pass through the hash,
// because the hash covers the object.
func readSampleHeader(br *bufio.Reader, avail int64, name string) (*packidx.Header, error) {
	fixed := make([]byte, packidx.HeaderSize)
	if _, err := io.ReadFull(br, fixed); err != nil {
		return nil, fmt.Errorf("%s: read table header: %w", name, err)
	}
	extent, err := packidx.SampleExtent(fixed)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	// SampleExtent's answer is a uint32 off the wire; held against the
	// bytes the signature says are there before anything is allocated.
	if extent < packidx.HeaderSize || extent > avail {
		return nil, fmt.Errorf("%w: %s claims %d bytes of samples with %d bytes left in the object",
			ErrFormat, name, extent, avail)
	}
	buf := make([]byte, extent)
	copy(buf, fixed)
	if _, err := io.ReadFull(br, buf[packidx.HeaderSize:]); err != nil {
		return nil, fmt.Errorf("%s: read table samples: %w", name, err)
	}
	hdr, err := packidx.ParseHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return hdr, nil
}

// checkOrder refuses a record that does not come strictly after the one
// before it. See Enumerate for why this is worth a comparison per record.
func checkOrder(name string, i int, prev, key []byte) error {
	if prev == nil || bytes.Compare(key, prev) > 0 {
		return nil
	}
	return fmt.Errorf("%w: %s record %d (%s) does not sort after record %d (%s), so lookups "+
		"below it silently answer \"not found\" and the files they back are unreadable",
		ErrFormat, name, i, hex.EncodeToString(key[:8]), i-1, hex.EncodeToString(prev[:8]))
}

// blockOf decodes one entry into the Block a caller sees.
func blockOf(keys []string, name string, i int, key, val []byte) (Block, error) {
	var b Block
	copy(b.ID[:], key)
	l, ok := decodeRecord(keys, val)
	if !ok {
		return b, fmt.Errorf("%w: %s record %d names an object outside its %d-entry string table",
			ErrFormat, name, i, len(keys))
	}
	b.Loc = l
	return b, nil
}

// countingReader is how the pass reports what it moved without holding
// it. io.Copy's own count would miss the buffered read-ahead.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if errors.Is(err, io.EOF) {
		return n, io.EOF
	}
	return n, err
}
