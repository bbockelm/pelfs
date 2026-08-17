// Package memtable is a PROTOTYPE of the write path described in
// docs/design-writepath.md: an LSM tree whose memory tables are mmap'd
// buffer files in the state directory and whose bottom level is the
// federation's packs. It exists beside the staging-file-per-inode path in
// internal/overlay, not in place of it, so the two can be compared.
//
// The unit of the write path is an EXTENT: the raw bytes of one write()
// call, appended verbatim to the active table with no hashing and no
// boundary decision. A stable Handle names it. Content — the stand-in
// here for the overlay's ocontent rows — is a list of (handle, slice)
// references, so nothing a content row holds has to be rewritten when the
// extent's bytes move from a memtable into a pack. Identity and location
// both bind at flush.
package memtable

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"

	"golang.org/x/sys/unix"
)

// recordMagic marks the start of a buffer record. A freshly created
// buffer file is a hole of zeros, so "magic mismatch" is also how a scan
// finds the end of the written region — there is no separately durable
// tail pointer to disagree with the records themselves.
const recordMagic uint32 = 0x314d5450 // "PTM1" little-endian

// recordHeader is the fixed prefix before each extent's payload.
//
//	 0  u32 magic
//	 4  u32 payload length
//	 8  u64 handle
//	16  u64 inode
//	24  u64 file offset
//	32  u32 reserved
//	36  u32 crc32c(header[0:36] || payload)
//
// The CRC covers the header as well as the payload because a torn tail
// can corrupt either, and a header whose length field survives corruption
// would otherwise steer the scan into garbage.
const recordHeader = 40

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrBufferFull is returned by Append when the record does not fit. It is
// a routine condition — it is what tells the store to rotate tables — not
// an error to propagate to a caller.
var ErrBufferFull = errors.New("memtable: buffer full")

// Handle names one extent for the lifetime of a session. Handles are
// allocated monotonically and never reused, which is what lets a content
// row hold one for as long as it likes: the handle outlives the memtable
// that first held its bytes.
type Handle uint64

// Record is one extent's metadata, as recovered from a buffer file or as
// held in a live table's index.
type Record struct {
	Handle  Handle
	Inode   uint64
	FileOff int64
	// Off is where the payload starts in the buffer file.
	Off int
	// Length is the payload length.
	Length int
}

// Buffer is an mmap'd append-only record log. Appends are not
// synchronized; a Buffer belongs to exactly one table, and a table is
// appended to only under the store's lock. Reads of already-appended
// bytes need no synchronization at all: a record's bytes never change
// once written, which is the whole reason resolution can hand out a
// source under a lock and read outside it.
type Buffer struct {
	f    *os.File
	data []byte
	end  int
	seq  uint64
	torn bool
}

// CreateBuffer makes a buffer file of exactly size bytes and maps it.
// The file is preallocated so that appends are stores into the mapping
// and never extend the file — extending a mapping mid-session would mean
// remapping under readers holding slices into it.
func CreateBuffer(path string, size int, seq uint64) (*Buffer, error) {
	if size < recordHeader {
		return nil, fmt.Errorf("memtable: buffer size %d too small", size)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(int64(size)); err != nil {
		f.Close() //nolint:errcheck
		return nil, err
	}
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, fmt.Errorf("memtable: mmap %s: %w", path, err)
	}
	return &Buffer{f: f, data: data, seq: seq}, nil
}

// OpenBuffer maps an existing buffer file and scans it, returning every
// record up to the first malformed one. A short second return is not an
// error: it is the recovery contract. The caller must report the loss.
func OpenBuffer(path string, seq uint64) (*Buffer, []Record, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, nil, err
	}
	size := int(fi.Size())
	if size < recordHeader {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: buffer %s is %d bytes, too small to hold a record", path, size)
	}
	data, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		f.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("memtable: mmap %s: %w", path, err)
	}
	b := &Buffer{f: f, data: data, seq: seq}
	recs := b.scan()
	return b, recs, nil
}

// scan walks records from the start, stopping at the first one that does
// not validate, and leaves end at the boundary. Everything after that
// point is a torn tail: with no fsync ordering guarantee, a record that
// fails to validate says nothing about whether later ones are intact, and
// accepting them would be exactly the silent partial recovery the design
// forbids.
func (b *Buffer) scan() []Record {
	var recs []Record
	off := 0
	for off+recordHeader <= len(b.data) {
		h := b.data[off : off+recordHeader]
		if binary.LittleEndian.Uint32(h[0:4]) != recordMagic {
			break
		}
		n := int(binary.LittleEndian.Uint32(h[4:8]))
		if n < 0 || off+recordHeader+n > len(b.data) {
			break
		}
		want := binary.LittleEndian.Uint32(h[36:40])
		crc := crc32.Checksum(h[0:36], crcTable)
		crc = crc32.Update(crc, crcTable, b.data[off+recordHeader:off+recordHeader+n])
		if crc != want {
			break
		}
		recs = append(recs, Record{
			Handle:  Handle(binary.LittleEndian.Uint64(h[8:16])),
			Inode:   binary.LittleEndian.Uint64(h[16:24]),
			FileOff: int64(binary.LittleEndian.Uint64(h[24:32])),
			Off:     off + recordHeader,
			Length:  n,
		})
		off += recordHeader + n
	}
	b.end = off
	// Distinguishing "the writer stopped here" from "a record was torn"
	// is possible because the file was preallocated as a hole: a clean end
	// is followed by zeros only. Nonzero bytes past the last valid record
	// mean something was written and did not survive intact.
	for _, c := range b.data[off:] {
		if c != 0 {
			b.torn = true
			break
		}
	}
	return recs
}

// Torn reports whether bytes were found past the last valid record. A
// buffer cut short by a truncated file is NOT torn by this test — the
// evidence went with the bytes — which is why the loud report has to come
// from reconciling content rows, not from the buffer alone.
func (b *Buffer) Torn() bool { return b.torn }

// Append writes one extent. On success rec.Off is filled in with the
// payload's position. The CRC is computed before the header is stored so
// that a header is never visible without the checksum that validates it.
func (b *Buffer) Append(rec *Record, payload []byte) error {
	need := recordHeader + len(payload)
	if b.end+need > len(b.data) {
		return ErrBufferFull
	}
	off := b.end
	var h [recordHeader]byte
	binary.LittleEndian.PutUint32(h[0:4], recordMagic)
	binary.LittleEndian.PutUint32(h[4:8], uint32(len(payload)))
	binary.LittleEndian.PutUint64(h[8:16], uint64(rec.Handle))
	binary.LittleEndian.PutUint64(h[16:24], rec.Inode)
	binary.LittleEndian.PutUint64(h[24:32], uint64(rec.FileOff))
	crc := crc32.Checksum(h[0:36], crcTable)
	crc = crc32.Update(crc, crcTable, payload)
	binary.LittleEndian.PutUint32(h[36:40], crc)

	copy(b.data[off+recordHeader:], payload)
	copy(b.data[off:], h[:])
	b.end = off + need
	rec.Off = off + recordHeader
	rec.Length = len(payload)
	return nil
}

// Room reports whether a payload of n bytes would fit.
func (b *Buffer) Room(n int) bool { return b.end+recordHeader+n <= len(b.data) }

// Used reports the bytes consumed so far, headers included.
func (b *Buffer) Used() int { return b.end }

// Cap reports the buffer's total size.
func (b *Buffer) Cap() int { return len(b.data) }

// At returns a view of length bytes at off. The result aliases the
// mapping: it is valid until Close, and it is immutable because the
// region has already been appended.
func (b *Buffer) At(off, length int) []byte {
	return b.data[off : off+length : off+length]
}

// Sync flushes the mapping. The design leaves open whether to call this
// at file-close boundaries; nothing in this package calls it on its own,
// so the cost stays measurable rather than assumed.
func (b *Buffer) Sync() error { return unix.Msync(b.data, unix.MS_SYNC) }

// Path returns the buffer file's path.
func (b *Buffer) Path() string { return b.f.Name() }

// Close unmaps and closes. Slices previously returned by At become
// invalid, so the store closes a buffer only once no source can name it.
func (b *Buffer) Close() error {
	if b.data == nil {
		return nil
	}
	err := unix.Munmap(b.data)
	b.data = nil
	if cerr := b.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Remove closes the buffer and deletes its file. This is how a flushed
// table's space is reclaimed.
func (b *Buffer) Remove() error {
	path := b.f.Name()
	err := b.Close()
	if rerr := os.Remove(path); err == nil && !os.IsNotExist(rerr) {
		err = rerr
	}
	return err
}
