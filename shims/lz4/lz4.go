// Package lz4 is a cgo-free stand-in for github.com/hungys/go-lz4 backed by
// github.com/pierrec/lz4/v4, substituted via a go.mod replace directive. Both
// implement the standard LZ4 block format.
//
// Only the API surface JuiceFS's pkg/compress uses is provided:
// CompressBound, CompressDefault and DecompressSafe.
package lz4

import (
	"fmt"

	"github.com/pierrec/lz4/v4"
)

// CompressBound returns the worst-case compressed size for a size-byte input
// (matches the C library's LZ4_compressBound formula).
func CompressBound(size int) int {
	return size + size/255 + 16
}

// CompressDefault compresses src into dst, returning the number of bytes
// written.
func CompressDefault(src, dst []byte) (int, error) {
	var c lz4.Compressor
	n, err := c.CompressBlock(src, dst)
	if err != nil {
		return 0, err
	}
	if n == 0 && len(src) > 0 {
		// pierrec/lz4 signals "not compressible" with n == 0; the C library
		// (and callers) expect a valid block regardless, so emit a
		// literal-only block.
		return literalBlock(src, dst)
	}
	return n, nil
}

// DecompressSafe decompresses src into dst, returning the number of bytes
// written.
func DecompressSafe(src, dst []byte) (int, error) {
	return lz4.UncompressBlock(src, dst)
}

// literalBlock writes src as a single LZ4 sequence of literals with no match,
// which is valid as the final sequence of a block.
func literalBlock(src, dst []byte) (int, error) {
	need := 1 + len(src)/255 + 1 + len(src)
	if len(dst) < need {
		return 0, fmt.Errorf("lz4: destination too small (%d < %d)", len(dst), need)
	}
	i := 0
	n := len(src)
	if n < 15 {
		dst[i] = byte(n) << 4
		i++
	} else {
		dst[i] = 0xF0
		i++
		for rest := n - 15; ; rest -= 255 {
			if rest >= 255 {
				dst[i] = 255
				i++
			} else {
				dst[i] = byte(rest)
				i++
				break
			}
		}
	}
	copy(dst[i:], src)
	return i + n, nil
}
