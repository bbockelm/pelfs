package hydrate

import (
	"encoding/binary"

	"github.com/juicedata/juicefs/pkg/meta"
)

// jfs_chunk.slices is a concatenation of fixed 24-byte records, big-endian
// (pkg/meta/slice.go marshalSlice/read): pos u32, id u64, size u32, off
// u32, len u32. pos is the byte position within the 64 MiB chunk, size the
// FULL backing slice length (it drives block-object naming), off/len the
// visible window into that slice.
const sliceRecBytes = 24

// appendSliceRec appends one slice record to blob.
func appendSliceRec(blob []byte, pos uint32, id uint64, size, off, length uint32) []byte {
	var rec [sliceRecBytes]byte
	binary.BigEndian.PutUint32(rec[0:4], pos)
	binary.BigEndian.PutUint64(rec[4:12], id)
	binary.BigEndian.PutUint32(rec[12:16], size)
	binary.BigEndian.PutUint32(rec[16:20], off)
	binary.BigEndian.PutUint32(rec[20:24], length)
	return append(blob, rec[:]...)
}

// appendSliceSpans emits the slice records covering logical file bytes
// [pos, pos+llen) served by slice id (whose full size is llen), splitting
// at 64 MiB chunk boundaries — a CDC chunk is placed by content, so it may
// straddle one. Holes never reach here; they consume pos upstream and emit
// nothing (the engine's buildSlice fills gaps with zero slices).
func appendSliceSpans(blobs map[uint32][]byte, pos int64, id uint64, llen int64) {
	const chunkSize = int64(meta.ChunkSize)
	var offInSlice int64
	for remaining := llen; remaining > 0; {
		indx := uint32(pos / chunkSize)
		cpos := pos % chunkSize
		n := chunkSize - cpos
		if n > remaining {
			n = remaining
		}
		blobs[indx] = appendSliceRec(blobs[indx], uint32(cpos), id, uint32(llen), uint32(offInSlice), uint32(n))
		pos += n
		offInSlice += n
		remaining -= n
	}
}
