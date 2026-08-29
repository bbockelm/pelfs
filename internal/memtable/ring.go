package memtable

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"sync/atomic"

	"github.com/bbockelm/pelfs/internal/mmapfile"
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
	f *os.File
	// mm is the mapping; whole is its bytes. internal/mmapfile spells out
	// the three ways Windows mappings are stricter than mmap, and this
	// type depends on all three — see mapRing and Remove.
	mm    *mmapfile.Mapping
	whole []byte // the whole mapping, file header included
	data  []byte // the data region: whole[ringFileHdr:]
	size  uint64 // len(data), fixed for the file's life

	// head and tail are ATOMIC because At reads them without the store's
	// lock. That is the design — resolve a position under the lock, read
	// the bytes outside it, with a pin holding the tail back — but the
	// bounds check inside At is still a read of state a concurrent
	// Reclaim writes. The pin makes the BYTES safe; this makes the check
	// safe. Writers always hold the store's lock, so plain loads and
	// stores are enough and no compare-and-swap is needed.
	head atomic.Uint64 // absolute position of the next append
	tail atomic.Uint64 // absolute position of the oldest unreclaimed byte

	seq uint64 // sequence stamped on the next record

	// pins counts readers holding each position. Reclaim may not pass the
	// oldest of them: the bytes behind the tail become writable at once,
	// so releasing one out from under a reader is a torn read of live
	// data, not a stale answer. The map is small by construction — it
	// holds only positions with a reader in flight.
	pins map[uint64]int

	// What recovery found wrong with the file, for the report a user reads
	// after a crash. Torn means the run ended at something that WANTED to
	// be a record and was not; Truncated means the file was shorter than
	// its own header says and was re-extended, with Missing bytes of the
	// data region restored as zeros.
	Torn      bool
	Truncated bool
	Missing   int64
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

// The sizes the write path runs at. The ring is deliberately LARGER than
// the distance that triggers packing: packing chunks, hashes and
// compresses, so a ring sized exactly at its trigger would block a writer
// the instant packing began and on every cycle after. The difference is
// the writer's runway while the tail drains.
const (
	DefaultRingSize          = 72 << 20
	DefaultPromotionDistance = 64 << 20
)

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
// A sixteenth, not an eighth: the cap has to fit inside the RUNWAY —
// the slack between the promotion distance and the ring's size — or one
// record can carry a writer from "not yet packing" to "full" in a single
// append, blocking it the instant packing begins, which is the exact
// pathology the runway exists to prevent. At the shipped sizes that is a
// 4.5 MiB record against 8 MiB of runway, and a test holds the relation.
//
// It is a fraction of the ring rather than "whatever fits", which closes
// a subtler trap than the obvious one. A record is padded past the seam
// rather than straddling it, and the pad consumes ring space too — so a
// record approaching the ring's own size can fail to fit even when
// nothing is live, and a writer waiting for a packer that has nothing
// left to pack would wait forever. Capping a record at an eighth of the
// ring means a pad plus a record always fits in a drained ring, so
// waiting always terminates.
func MaxRecord(ringSize int) int { return ringSize/16 - ringRecHdr }

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
	// The file is at its FINAL size before this — CreateRing truncates to
	// it, OpenRing maps the size the file already has — and it is never
	// resized afterwards, which the comment above calls an avoidance of
	// remapping under readers and which on Windows is a hard requirement:
	// there is no remap, and a mapping cannot survive a resize. The size
	// is also always positive (ringFileHdr is nonzero), so the zero-length
	// file Windows refuses to map never arises.
	mm, err := mmapfile.Map(f, ringFileHdr+size, mmapfile.ReadWrite)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("memtable: ring: %w", err)
	}
	whole := mm.Bytes()
	return &Ring{f: f, mm: mm, whole: whole, data: whole[ringFileHdr:], size: uint64(size)}, nil
}

// writeFileHeader records the size and a HINT of where the live region
// begins. The hint is not authoritative — records carry the truth — but
// it gives recovery a boundary to start walking from, which a ring needs
// because record boundaries cannot be found by scanning arbitrary bytes.
func (r *Ring) writeFileHeader() error {
	h := r.hdr()
	copy(h[0:8], ringMagic)
	binary.LittleEndian.PutUint64(h[8:], r.size)
	binary.LittleEndian.PutUint64(h[16:], r.tail.Load())
	binary.LittleEndian.PutUint64(h[24:], r.head.Load())
	binary.LittleEndian.PutUint64(h[32:], r.seq)
	binary.LittleEndian.PutUint32(h[40:], crc32.Checksum(h[0:40], crcTable))
	return nil
}

func (r *Ring) hdr() []byte { return r.whole[:ringFileHdr] }

// Used reports bytes written and not yet reclaimed.
func (r *Ring) Used() uint64 { return r.head.Load() - r.tail.Load() }

// Free reports how much a writer may still append before it must wait.
func (r *Ring) Free() uint64 { return r.size - r.Used() }

// Head and Tail expose the absolute positions, which is what an aging
// policy compares against: an extent at position p is head-p bytes old.
func (r *Ring) Head() uint64 { return r.head.Load() }
func (r *Ring) Tail() uint64 { return r.tail.Load() }

// Append writes one extent and returns its absolute position. A record
// never straddles the seam: if it will not fit before the end of the
// mapping, the remainder is filled with a pad record and the write wraps.
func (r *Ring) Append(rec *Record, payload []byte) (uint64, error) {
	if len(payload) > MaxRecord(int(r.size)) {
		return 0, fmt.Errorf("%w: %d bytes against a %d-byte limit in a %d-byte ring",
			ErrRecordTooLarge, len(payload), MaxRecord(int(r.size)), r.size)
	}
	need := uint64(ringRecHdr + len(payload))
	head := r.head.Load()
	off := head % r.size
	if off+need > r.size {
		// Pad to the seam. The pad consumes ring space, so it must fit
		// too, or the writer waits rather than silently overwriting.
		pad := r.size - off
		if pad+need > r.Free() {
			return 0, ErrRingFull
		}
		r.writePad(off, pad)
		head += pad
		r.head.Store(head)
		off = 0
	}
	if need > r.Free() {
		return 0, ErrRingFull
	}
	pos := head
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

	r.head.Store(head + need)
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
	if pos < r.tail.Load() || end > r.head.Load() {
		return nil, false
	}
	off := pos % r.size
	return r.data[off+ringRecHdr : off+ringRecHdr+uint64(length)], true
}

// Pin holds a position against reclamation for as long as a reader is
// reading it. Unpin releases it. Every Pin must be matched.
func (r *Ring) Pin(pos uint64) {
	if r.pins == nil {
		r.pins = make(map[uint64]int)
	}
	r.pins[pos]++
}

func (r *Ring) Unpin(pos uint64) {
	if n := r.pins[pos]; n > 1 {
		r.pins[pos] = n - 1
	} else {
		delete(r.pins, pos)
	}
}

// oldestPin reports the lowest pinned position, or the head when nothing
// is pinned.
func (r *Ring) oldestPin() uint64 {
	oldest := r.head.Load()
	for pos := range r.pins {
		if pos < oldest {
			oldest = pos
		}
	}
	return oldest
}

// Reclaim advances the tail toward an absolute position and returns where
// it actually reached, which may be short of the request.
//
// The watermark is enforced HERE rather than left to the caller. Bytes
// behind the tail become writable immediately, so passing a position a
// reader still holds is a torn read of live data — and a rule that lives
// in one place cannot be forgotten by the next caller the way an
// interface contract can.
func (r *Ring) Reclaim(to uint64) (uint64, error) {
	if tail, head := r.tail.Load(), r.head.Load(); to < tail || to > head {
		return tail, fmt.Errorf("memtable: reclaim to %d outside [%d,%d]", to, tail, head)
	}
	if limit := r.oldestPin(); to > limit {
		to = limit
	}
	r.tail.Store(to)
	return to, r.writeFileHeader()
}

// Promotable reports how much of what the ring HOLDS sits behind the age
// line, given the promotion distance. Age is distance behind the head, so
// this is one subtraction — the property that let the design drop discrete
// levels in favour of a single coordinate.
//
// It returns 0 rather than a negative when the ring holds less than the
// distance, which is the common case for a short session: nothing is old
// enough, so nothing is packed, and the seal at exit handles the lot.
//
// IT IS NOT A PROMOTION TRIGGER, and reading it as one is a defect this
// package has already shipped once. head-tail is OCCUPANCY: it still
// counts the region of a batch that has been packed and published and is
// waiting only for its Located record before the tail may pass it. A
// trigger built on it therefore stays satisfied for as long as that record
// is in flight, and the run it keeps starting has nothing left to cut but
// the one extent that aged since the last one. What a trigger wants is the
// span between the oldest UNPACKED record and the age line, which is the
// store's promotableLocked and not something the ring can answer: the ring
// does not know which of its bytes a run has already claimed.
func (r *Ring) Promotable(distance uint64) uint64 {
	used := r.Used()
	if used <= distance {
		return 0
	}
	return used - distance
}

// Sync flushes the mapping. Durability is the caller's policy; the ring
// only offers the primitive.
func (r *Ring) Sync() error { return r.mm.Flush() }

func (r *Ring) Path() string { return r.f.Name() }

func (r *Ring) Close() error {
	err := r.mm.Close()
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	r.whole, r.data = nil, nil
	return err
}

// Remove closes the ring and deletes its file.
//
// It CLOSES FIRST, which it did not used to. On Unix removing a mapped,
// open file is ordinary and the mapping stays valid; on Windows both the
// open handle and the live mapping pin the file, so the remove failed and
// the ring file leaked. Closing first is correct on both.
func (r *Ring) Remove() error {
	path := r.f.Name()
	err := r.Close()
	if rerr := os.Remove(path); err == nil && !os.IsNotExist(rerr) {
		err = rerr
	}
	return err
}

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
	h := make([]byte, ringFileHdr)
	if _, err := io.ReadFull(io.NewSectionReader(f, 0, ringFileHdr), h); err != nil {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: read ring header of %s: %w", path, err)
	}
	if string(h[0:8]) != ringMagic {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: %s is not a ring buffer", path)
	}
	if got := crc32.Checksum(h[0:40], crcTable); got != binary.LittleEndian.Uint32(h[40:]) {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: ring header of %s is corrupt", path)
	}
	size := binary.LittleEndian.Uint64(h[8:])
	if size == 0 || size > 1<<40 {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: ring header of %s claims %d bytes", path, size)
	}
	// A ring is preallocated, so a file shorter than its own header says is
	// a truncation. It is REPAIRED rather than refused: positions are
	// modulo the declared size, so shrinking the mapping would silently
	// move every record, while re-extending restores the missing region as
	// zeros — which reads as unwritten space and simply ends the run. The
	// caller is told, because bytes did go missing.
	want := int64(ringFileHdr) + int64(size)
	fi, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, nil, err
	}
	truncated, missing := false, int64(0)
	if fi.Size() != want {
		if fi.Size() > want {
			f.Close() //nolint:errcheck
			return nil, nil, fmt.Errorf("memtable: ring %s says %d bytes, file holds %d", path, size, fi.Size()-ringFileHdr)
		}
		truncated, missing = true, want-fi.Size()
		if err := f.Truncate(want); err != nil {
			f.Close() //nolint:errcheck
			return nil, nil, fmt.Errorf("memtable: re-extend truncated ring %s: %w", path, err)
		}
	}
	r, err := mapRing(f, int(size))
	if err != nil {
		return nil, nil, err
	}
	r.Truncated, r.Missing = truncated, missing
	tail := binary.LittleEndian.Uint64(h[16:])
	r.tail.Store(tail)
	r.head.Store(tail)
	r.seq = 1

	// The two ways a run ends are worth telling apart. Unwritten space and
	// a previous lap are CLEAN: that is simply where the head was. A record
	// whose magic is intact but whose length or CRC is not is TORN — the
	// crash caught a write in progress — and that is the shape a user has
	// to be told about, because everything behind it is unreachable even if
	// it is still on the disk.
	var live []Record
	pos := r.tail.Load()
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
		if off+total > r.size || total > r.size {
			r.Torn = true
			break
		}
		crc := crc32.Checksum(rh[0:40], crcTable)
		if magic == ringRecMagic {
			crc = crc32.Update(crc, crcTable, r.data[off+ringRecHdr:off+total])
		}
		if crc != binary.LittleEndian.Uint32(rh[40:]) {
			r.Torn = true
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
		r.head.Store(pos)
		r.seq = seq + 1
	}
	return r, live, nil
}
