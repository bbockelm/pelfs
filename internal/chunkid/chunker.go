package chunkid

import (
	"fmt"
	"io"
	"math/bits"
)

// Default chunking parameters (decided in docs/design-packfs.md and
// recorded per-volume in the superblock): scientific data dedups
// modestly, so per-chunk costs — a catalog row and a range-GET — argue
// for large chunks; 4 MiB average preserves continuity with the v1
// block size.
const (
	DefaultMinSize = 1 << 20  // 1 MiB
	DefaultAvgSize = 4 << 20  // 4 MiB
	DefaultMaxSize = 16 << 20 // 16 MiB
)

// normalization is the FastCDC normalization level: the pre-average
// mask carries this many extra bits and the post-average mask this many
// fewer, concentrating cut points around AvgSize. Level 2 is the
// paper's recommendation.
const normalization = 2

// Options configures a Chunker. Zero fields take the package defaults.
// Chunking parameters are part of a volume's identity domain: two
// volumes dedup against each other only if they chunk identically.
type Options struct {
	// MinSize is the smallest chunk the cut search will produce; bytes
	// before it are not even hashed. Must be > 0 and < AvgSize.
	MinSize int
	// AvgSize is the target mean chunk size. Must be a power of two
	// (the cut masks are derived from its log2).
	AvgSize int
	// MaxSize is the forced-cut bound. Must be > AvgSize.
	MaxSize int
}

// Chunk is one content-defined chunk of the input stream.
type Chunk struct {
	// Data is the chunk's bytes. It is a private copy, valid after
	// subsequent Next calls.
	Data []byte
	// Offset is the chunk's byte position in the input stream.
	Offset int64
}

// Chunker splits a stream into content-defined chunks. It is not safe
// for concurrent use.
type Chunker struct {
	r             io.Reader
	min, avg, max int
	maskS, maskL  uint64 // strict (pre-average) and loose (post-average) cut masks

	buf []byte // window of unconsumed input, capacity max
	n   int    // valid bytes in buf
	off int64  // stream offset of buf[0]
	err error  // sticky reader error; io.EOF once the stream is drained
}

// NewChunker returns a Chunker reading from r. Invalid Options are a
// programming error and panic: chunk parameters are format constants,
// and silently substituting different ones would fork the volume's
// identity domain.
func NewChunker(r io.Reader, opts Options) *Chunker {
	if opts.MinSize == 0 {
		opts.MinSize = DefaultMinSize
	}
	if opts.AvgSize == 0 {
		opts.AvgSize = DefaultAvgSize
	}
	if opts.MaxSize == 0 {
		opts.MaxSize = DefaultMaxSize
	}
	if opts.AvgSize&(opts.AvgSize-1) != 0 {
		panic(fmt.Sprintf("chunkid: AvgSize must be a power of two, got %d", opts.AvgSize))
	}
	if !(0 < opts.MinSize && opts.MinSize < opts.AvgSize && opts.AvgSize < opts.MaxSize) {
		panic(fmt.Sprintf("chunkid: need 0 < MinSize < AvgSize < MaxSize, got %d/%d/%d",
			opts.MinSize, opts.AvgSize, opts.MaxSize))
	}
	avgBits := bits.TrailingZeros(uint(opts.AvgSize))
	if avgBits <= normalization || avgBits+normalization > 64 {
		panic(fmt.Sprintf("chunkid: AvgSize %d out of range for normalization level %d", opts.AvgSize, normalization))
	}
	return &Chunker{
		r:   r,
		min: opts.MinSize,
		avg: opts.AvgSize,
		max: opts.MaxSize,
		// The gear hash shifts left each step, so only the high bits of
		// the fingerprint see the full ~64-byte window; the masks must
		// therefore select the top bits, not the bottom.
		maskS: topMask(avgBits + normalization),
		maskL: topMask(avgBits - normalization),
		buf:   make([]byte, opts.MaxSize),
	}
}

// topMask returns a mask of the k highest bits of a uint64.
func topMask(k int) uint64 {
	return ^uint64(0) << (64 - k)
}

// Next returns the next chunk, or io.EOF after the final chunk has been
// returned. An empty input yields io.EOF immediately; an input shorter
// than MinSize yields a single chunk. Any other reader error is
// returned as-is (no partial chunk is emitted for a failed read).
func (c *Chunker) Next() (Chunk, error) {
	// Keep the window full to MaxSize so the cut search always sees as
	// far ahead as a forced cut could reach.
	if c.err == nil && c.n < c.max {
		m, err := io.ReadFull(c.r, c.buf[c.n:c.max])
		c.n += m
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		c.err = err
	}
	if c.n == 0 {
		if c.err == nil {
			// ReadFull filled the whole window with n starting at max=0;
			// unreachable because max > 0, but keep the invariant honest.
			return Chunk{}, io.ErrNoProgress
		}
		return Chunk{}, c.err
	}
	if c.err != nil && c.err != io.EOF {
		return Chunk{}, c.err
	}

	cut := c.cut(c.buf[:c.n])
	data := make([]byte, cut)
	copy(data, c.buf[:cut])
	ch := Chunk{Data: data, Offset: c.off}
	c.off += int64(cut)
	copy(c.buf, c.buf[cut:c.n])
	c.n -= cut
	return ch, nil
}

// cut returns the length of the next chunk in src using FastCDC
// normalized chunking: no cut before min, a 2^(avgBits+2) expected
// spacing between min and avg, a 2^(avgBits-2) spacing between avg and
// max, and a forced cut at max (or end of input).
func (c *Chunker) cut(src []byte) int {
	n := len(src)
	if n <= c.min {
		return n
	}
	normal := c.avg
	if normal > n {
		normal = n
	}
	// Bytes before min are skipped entirely (never hashed): the window
	// is only ~64 bytes, so seeding the gear inside the skipped region
	// buys nothing, and skipping is what makes min "free".
	var h uint64
	i := c.min
	for ; i < normal; i++ {
		h = (h << 1) + gearTable[src[i]]
		if h&c.maskS == 0 {
			return i + 1
		}
	}
	for ; i < n; i++ {
		h = (h << 1) + gearTable[src[i]]
		if h&c.maskL == 0 {
			return i + 1
		}
	}
	return n
}
