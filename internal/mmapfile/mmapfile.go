// Package mmapfile is the one place in pelfs that maps a file into
// memory, and it exists because Windows does not have mmap.
//
// Two callers need it and they need it for opposite reasons.
// internal/extsort writes a sorted table once and then maps it READ-ONLY
// to binary-search it, so that what is resident is page cache the kernel
// can reclaim rather than heap it cannot. internal/genfs preallocates a
// fixed-size arena and maps it READ-WRITE as the decoded-chunk cache.
// Both are scratch: neither mapping is the durable copy of anything, and
// neither survives the process that made it.
//
// WHY ONE PACKAGE RATHER THAN A FILE IN EACH. The Unix half is two calls
// and would happily live in either package. The Windows half is not: a
// mapping there is a SECTION OBJECT plus a VIEW of it, with a rule about
// which of the two may be released when, and a mistake does not fail
// loudly — it leaves the backing file undeletable. Four call sites
// spelling that out would be four chances to get it wrong.
//
// WHAT WINDOWS DOES DIFFERENTLY, since both call sites depend on it:
//
//   - A zero-length file cannot be mapped at all. CreateFileMapping with
//     a maximum size of zero means "the file's current size", and a file
//     of size zero is rejected outright. mmap refuses a zero length too,
//     so both call sites already had to handle the empty case; this is
//     the same rule with a different error.
//
//   - A mapping PINS the backing file. While the view exists, the file
//     cannot be deleted, renamed, or resized. On Unix an
//     unlinked file with a live mapping is perfectly ordinary. So Close
//     must tear the mapping down BEFORE anything tries to remove the
//     file, and it does: it unmaps the view, then closes the section.
//
//   - A mapping cannot outlive a resize of its file. There is no
//     remap-in-place. Neither call site resizes: extsort maps a file it
//     has finished writing, genfs truncates to its final size before it
//     maps. Any future caller that wants to grow a mapped file has to
//     Close and Map again, on every platform.
//
// The file handle itself is a separate lifetime from the mapping on both
// platforms: once Map returns, the caller may close the *os.File and the
// mapping stays valid (Windows keeps the file alive through the section).
// extsort relies on that; genfs holds its file open anyway.
package mmapfile

import "os"

// Mapping is a mapped region of a file. Bytes aliases the mapping
// directly and is valid until Close.
//
// It is not safe to use a Mapping after Close, and Close is not safe to
// call concurrently with a reader — which is the same contract munmap
// has always had, since the address range goes away under the reader
// either way.
type Mapping struct {
	b []byte
	// f is the file the mapping was made from, held for Flush's sake:
	// matching msync(MS_SYNC)'s promise on Windows takes a flush of the
	// view AND a flush of the file's buffers, and the second needs the
	// handle. Holding it does not keep the file open — the caller still
	// owns that — so Flush is only meaningful while the caller has not
	// closed it.
	f *os.File
}

// Bytes is the mapped region. A nil Mapping maps nothing and reports
// nil, so a caller that maps conditionally does not need a nil check at
// every use.
func (m *Mapping) Bytes() []byte {
	if m == nil {
		return nil
	}
	return m.b
}

// Len is how many bytes are mapped.
func (m *Mapping) Len() int { return len(m.Bytes()) }

// Mode is what the mapping may be used for.
type Mode int

const (
	// ReadOnly maps for reading. A write through the region faults.
	ReadOnly Mode = iota
	// ReadWrite maps for reading and writing, with writes shared back to
	// the file (MAP_SHARED / FILE_MAP_WRITE) rather than private to this
	// process.
	ReadWrite
)

// THE CONTRACT MAP HOLDS ON EVERY PLATFORM, stated here because each
// platform's implementation is a different file:
//
// Map(f, length, mode) maps the first length bytes of f. length must be
// positive and must not exceed the file's current size — Unix would map
// past the end and fault on first touch, Windows refuses the view
// outright. Callers size the file first, by writing it or by truncating
// to the size they want, and pass what they wrote. Close unmaps, and
// releases the file: after it returns the backing file can be removed on
// any platform.
