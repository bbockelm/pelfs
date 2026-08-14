// Package zstd is a cgo-free stand-in for github.com/DataDog/zstd backed by
// github.com/klauspost/compress/zstd, substituted via a go.mod replace
// directive. Both packages produce standard zstd frames, so data written by
// one is readable by the other.
//
// Only the API surface JuiceFS's pkg/compress uses is provided:
// CompressBound, Compress, CompressLevel and Decompress, preserving the
// use-dst-if-large-enough contract that JuiceFS relies on.
package zstd

import (
	"sync"

	"github.com/klauspost/compress/zstd"
)

// DefaultCompression mirrors DataDog/zstd's default level.
const DefaultCompression = 5

var (
	encoders sync.Map // zstd.EncoderLevel -> *zstd.Encoder
	decOnce  sync.Once
	decoder  *zstd.Decoder
)

func encoderFor(level int) *zstd.Encoder {
	el := zstd.EncoderLevelFromZstd(level)
	if e, ok := encoders.Load(el); ok {
		return e.(*zstd.Encoder)
	}
	e, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(el))
	if err != nil {
		panic(err) // options are static; cannot fail
	}
	actual, _ := encoders.LoadOrStore(el, e)
	return actual.(*zstd.Encoder)
}

func getDecoder() *zstd.Decoder {
	decOnce.Do(func() {
		var err error
		decoder, err = zstd.NewReader(nil)
		if err != nil {
			panic(err)
		}
	})
	return decoder
}

// CompressBound returns a size guaranteed to hold the compressed form of a
// srcSize-byte input.
func CompressBound(srcSize int) int {
	return srcSize + srcSize>>8 + 1024
}

// Compress compresses src into dst (if it has enough capacity) at the
// default level and returns the compressed slice.
func Compress(dst, src []byte) ([]byte, error) {
	return CompressLevel(dst, src, DefaultCompression)
}

// CompressLevel is like Compress with an explicit compression level. The
// result aliases dst when dst has sufficient capacity.
func CompressLevel(dst, src []byte, level int) ([]byte, error) {
	return encoderFor(level).EncodeAll(src, dst[:0]), nil
}

// Decompress decompresses src into dst (if it has enough capacity) and
// returns the decompressed slice.
func Decompress(dst, src []byte) ([]byte, error) {
	return getDecoder().DecodeAll(src, dst[:0])
}
