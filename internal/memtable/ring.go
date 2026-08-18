package memtable

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"

	"golang.org/x/sys/unix"
)

// Ring is the write buffer: an mmap'd circular log of extent records.
//
// It replaces a stack of fixed tables because the accounting favours it.
// Two tables double mmap'd pages, which the OS can evict, while a flush
// duplicates the expensive thing — a table's contents exist as raw
// extents AND as the packed, compressed copies built from them, for the
// flush's whole duration. A ring bounds that duplication by pack size
// instead: a tail region becomes a pack, uploads, and is reclaimed.
//
// Positions are ABSOLUTE and monotonic. head and tail count bytes ever
// written and ever reclaimed, and an offset into the mapping is the
// position modulo the data size. That removes the full-versus-empty
// ambiguity a wrapped pair of indices has, and it makes an extent's age —
// how far behind the head it sits — a subtraction.
type Ring struct {
	f     *os.File
	whole []byte // the whole mapping, file header included
	data  []byte // the data region: whole[ringFileHdr:]
	size  uint64 // len(data), fixed for the file's life

	head uint64 // absolute position of the next append
	tail uint64 // absolute position of the oldest unreclaimed byte
	seq  uint64 // sequence stamped on the next record
}

const (
	ringMagic    = "PTMRING1"
	ringFileHdr  = 64 // reserved before the data region
	ringRecHdr   = 48
	ringPadMagic = uint32(0x50414421) // "PAD!"
	ringRecMagic = uint32(0x32544d50) // "PMT2"
)

// Ring record header:
//
//	 0  u32 magic (record or pad)
//	 4  u32 payload length
//	 8  u64 handle
//	16  u64 inode
//	24  u64 file offset
//	32  u64 sequence
//	40  u32 crc32c(header[0:40] || payload)
//	44  u32 reserved
//
// The sequence is what a ring needs and an append-only log does not.
// Recovery cannot simply scan to the first bad CRC, because bytes past
// the head are well-formed records from a previous lap; it accepts the
// longest run whose sequences ascend.

// ErrRingFull reports that a record cannot be appended until the tail
// advances. It is routine — it is the backpressure signal — not a fault.
var ErrRingFull = errors.New("memtable: ring full")

// ErrRecordTooLarge reports a record no amount of waiting can fit. It is
// a SEPARATE sentinel from ErrRingFull on purpose: a writer that blocks
// until space frees is correct for one and an infinite loop for the
// other, and an unstructured error would make the two indistinguishable.
// The caller's answer is to split the write, never to wait.
var ErrRecordTooLarge = errors.New("memtable: record too large for the ring")

// MaxRecord is the largest payload a ring of the given size accepts.
//
// It is a fraction of the ring rather than "whatever fits", which closes
// a subtler trap than the obvious one. A record is padded past the seam
// rather than straddling it, and the pad consumes ring space too — so a
// record approaching the ring's own size can fail to fit even when
// nothing is live, and a writer waiting for a packer that has nothing
// left to pack would wait forever. Capping a record at an eighth of the
// ring means a pad plus a record always fits in a drained ring, so
// waiting always terminates.
func MaxRecord(ringSize int) int { return ringSize/8 - ringRecHdr }

// CreateRing makes a ring file of exactly size bytes of data region and
// maps it. The file is preallocated: appends are stores into the mapping
// and never extend the file, because extending would mean remapping under
// readers holding slices into it.
func CreateRing(path string, size int) (*Ring, error) {
	if size <= ringRecHdr*2 {
		return nil, fmt.Errorf("memtable: ring size %d is too small", size)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	total := ringFileHdr + size
	if err := f.Truncate(int64(total)); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	r, err := mapRing(f, size)
	if err != nil {
		return nil, err
	}
	r.seq = 1
	if err := r.writeFileHeader(); err != nil {
		r.Close() //nolint:errcheck
		return nil, err
	}
	return r, nil
}

func mapRing(f *os.File, size int) (*Ring, error) {
	whole, err := unix.Mmap(int(f.Fd()), 0, ringFileHdr+size,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("memtable: mmap ring: %w", err)
	}
	return &Ring{f: f, whole: whole, data: whole[ringFileHdr:], size: uint64(size)}, nil
}

// writeFileHeader records the size and a HINT of where the live region
// begins. The hint is not authoritative — records carry the truth — but
// it gives recovery a boundary to start walking from, which a ring needs
// because record boundaries cannot be found by scanning arbitrary bytes.
func (r *Ring) writeFileHeader() error {
	h := r.hdr()
	copy(h[0:8], ringMagic)
	binary.LittleEndian.PutUint64(h[8:], r.size)
	binary.LittleEndian.PutUint64(h[16:], r.tail)
	binary.LittleEndian.PutUint64(h[24:], r.head)
	binary.LittleEndian.PutUint64(h[32:], r.seq)
	binary.LittleEndian.PutUint32(h[40:], crc32.Checksum(h[0:40], crcTable))
	return nil
}

func (r *Ring) hdr() []byte { return r.whole[:ringFileHdr] }

// Used reports bytes written and not yet reclaimed.
func (r *Ring) Used() uint64 { return r.head - r.tail }

// Free reports how much a writer may still append before it must wait.
func (r *Ring) Free() uint64 { return r.size - r.Used() }

// Head and Tail expose the absolute positions, which is what an aging
// policy compares against: an extent at position p is head-p bytes old.
func (r *Ring) Head() uint64 { return r.head }
func (r *Ring) Tail() uint64 { return r.tail }

// Append writes one extent and returns its absolute position. A record
// never straddles the seam: if it will not fit before the end of the
// mapping, the remainder is filled with a pad record and the write wraps.
func (r *Ring) Append(rec *Record, payload []byte) (uint64, error) {
	if len(payload) > MaxRecord(int(r.size)) {
		return 0, fmt.Errorf("%w: %d bytes against a %d-byte limit in a %d-byte ring",
			ErrRecordTooLarge, len(payload), MaxRecord(int(r.size)), r.size)
	}
	need := uint64(ringRecHdr + len(payload))
	off := r.head % r.size
	if off+need > r.size {
		// Pad to the seam. The pad consumes ring space, so it must fit
		// too, or the writer waits rather than silently overwriting.
		pad := r.size - off
		if pad+need > r.Free() {
			return 0, ErrRingFull
		}
		r.writePad(off, pad)
		r.head += pad
		off = 0
	}
	if need > r.Free() {
		return 0, ErrRingFull
	}
	pos := r.head
	h := r.data[off : off+ringRecHdr]
	binary.LittleEndian.PutUint32(h[0:], ringRecMagic)
	binary.LittleEndian.PutUint32(h[4:], uint32(len(payload)))
	binary.LittleEndian.PutUint64(h[8:], uint64(rec.Handle))
	binary.LittleEndian.PutUint64(h[16:], rec.Inode)
	binary.LittleEndian.PutUint64(h[24:], uint64(rec.FileOff))
	binary.LittleEndian.PutUint64(h[32:], r.seq)
	copy(r.data[off+ringRecHdr:off+need], payload)
	crc := crc32.Checksum(h[0:40], crcTable)
	crc = crc32.Update(crc, crcTable, payload)
	binary.LittleEndian.PutUint32(h[40:], crc)

	r.head += need
	r.seq++
	return pos, nil
}

func (r *Ring) writePad(off, n uint64) {
	h := r.data[off : off+ringRecHdr]
	binary.LittleEndian.PutUint32(h[0:], ringPadMagic)
	binary.LittleEndian.PutUint32(h[4:], uint32(n-ringRecHdr))
	binary.LittleEndian.PutUint64(h[32:], r.seq)
	crc := crc32.Checksum(h[0:40], crcTable)
	binary.LittleEndian.PutUint32(h[40:], crc)
	r.seq++
}

// At returns the payload bytes of a record at an absolute position.
// Records never straddle the seam, so this is always one contiguous
// slice into the mapping — no copy, and safe to read outside a lock
// because a written record's bytes never change.
func (r *Ring) At(pos uint64, length int) ([]byte, bool) {
	end := pos + uint64(ringRecHdr) + uint64(length)
	if pos < r.tail || end > r.head {
		return nil, false
	}
	off := pos % r.size
	return r.data[off+ringRecHdr : off+ringRecHdr+uint64(length)], true
}

// Reclaim advances the tail to an absolute position, freeing everything
// before it. The CALLER owns the watermark rule: the tail must never pass
// the oldest position a reader still holds, because the bytes behind it
// become writable immediately.
func (r *Ring) Reclaim(to uint64) error {
	if to < r.tail || to > r.head {
		return fmt.Errorf("memtable: reclaim to %d outside [%d,%d]", to, r.tail, r.head)
	}
	r.tail = to
	return r.writeFileHeader()
}

// Sync flushes the mapping. Durability is the caller's policy; the ring
// only offers the primitive.
func (r *Ring) Sync() error { return unix.Msync(r.whole, unix.MS_SYNC) }

func (r *Ring) Path() string { return r.f.Name() }

func (r *Ring) Close() error {
	err := unix.Munmap(r.whole)
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	r.whole, r.data = nil, nil
	return err
}

func (r *Ring) Remove() error { return os.Remove(r.f.Name()) }

// OpenRing reopens a ring and recovers the records still live in it.
//
// A ring cannot be recovered the way an append-only log is — scan until a
// bad CRC — because the bytes past the head are well-formed records from
// a previous lap. Recovery walks from the tail hint in the file header
// and accepts the longest run whose sequence numbers ascend, stopping at
// the first record that is malformed, fails its CRC, or steps backwards
// in sequence. Everything after that point is a torn write or a stale
// lap, and either way it is not ours.
//
// Loss here is expected: a mount is tied to a job, and a crashed job
// usually discards its state. What is not acceptable is silence, so the
// caller is handed exactly what survived and reports the rest.
func OpenRing(path string) (*Ring, []Record, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, nil, err
	}
	if fi.Size() <= ringFileHdr {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: ring file %s is %d bytes", path, fi.Size())
	}
	r, err := mapRing(f, int(fi.Size())-ringFileHdr)
	if err != nil {
		return nil, nil, err
	}
	h := r.hdr()
	if string(h[0:8]) != ringMagic {
		r.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: %s is not a ring buffer", path)
	}
	if got := crc32.Checksum(h[0:40], crcTable); got != binary.LittleEndian.Uint32(h[40:]) {
		r.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: ring header of %s is corrupt", path)
	}
	if size := binary.LittleEndian.Uint64(h[8:]); size != r.size {
		r.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: ring %s says %d bytes, file holds %d", path, size, r.size)
	}
	r.tail = binary.LittleEndian.Uint64(h[16:])
	r.head = r.tail
	r.seq = 1

	var live []Record
	pos := r.tail
	for {
		off := pos % r.size
		if off+ringRecHdr > r.size {
			break
		}
		rh := r.data[off : off+ringRecHdr]
		magic := binary.LittleEndian.Uint32(rh[0:])
		if magic != ringRecMagic && magic != ringPadMagic {
			break
		}
		n := uint64(binary.LittleEndian.Uint32(rh[4:]))
		seq := binary.LittleEndian.Uint64(rh[32:])
		if seq < r.seq {
			break // a previous lap: this is where our run ends
		}
		total := uint64(ringRecHdr) + n
		if magic == ringPadMagic {
			total = uint64(ringRecHdr) + n
		}
		if off+total > r.size || total > r.size {
			break
		}
		crc := crc32.Checksum(rh[0:40], crcTable)
		if magic == ringRecMagic {
			crc = crc32.Update(crc, crcTable, r.data[off+ringRecHdr:off+total])
		}
		if crc != binary.LittleEndian.Uint32(rh[40:]) {
			break
		}
		if magic == ringRecMagic {
			live = append(live, Record{
				Handle:  Handle(binary.LittleEndian.Uint64(rh[8:])),
				Inode:   binary.LittleEndian.Uint64(rh[16:]),
				FileOff: int64(binary.LittleEndian.Uint64(rh[24:])),
				Off:     int(pos),
				Length:  int(n),
			})
		}
		pos += total
		r.head = pos
		r.seq = seq + 1
	}
	return r, live, nil
}
