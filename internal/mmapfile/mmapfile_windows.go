package mmapfile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Map maps the first length bytes of f. See the package comment for the
// contract it holds on every platform, and for the three ways Windows
// mappings differ from mmap that the callers depend on.
//
// TWO OBJECTS, ONE OF WHICH IS IMMEDIATELY DISPOSABLE. CreateFileMapping
// makes a SECTION over the file — a kernel object with a handle and its
// own reference on the file — and MapViewOfFile projects a window of that
// section into this process. The VIEW holds its own reference to the
// section, so the section HANDLE has no further job once the view exists
// and is closed here rather than carried around. That is why Mapping has
// no handle field and why Close is a single call: there is nothing left
// to leak.
//
// What the view does hold is the file. Until it is unmapped the backing
// file cannot be deleted, renamed, or resized — see Close.
//
// A maximum size of zero means "as large as the file is now", which is
// what every caller wants: they have already given the file its final
// size, and passing an explicit maximum would let a caller silently
// EXTEND the file by mapping it, which mmap does not do.
func Map(f *os.File, length int, mode Mode) (*Mapping, error) {
	if length <= 0 {
		// Not just a guard against a bad caller: a zero-length file cannot
		// be mapped on Windows at all, so a caller that reaches here with
		// an empty file needs the empty case handled above rather than an
		// obscure ERROR_FILE_INVALID from the kernel.
		return nil, fmt.Errorf("mmapfile: map %s: length %d is not positive", f.Name(), length)
	}
	prot, access := uint32(windows.PAGE_READONLY), uint32(windows.FILE_MAP_READ)
	if mode == ReadWrite {
		// FILE_MAP_WRITE implies read access on Windows, so a ReadWrite
		// mapping is readable as well — which is what MAP_SHARED with
		// PROT_READ|PROT_WRITE gives on Unix.
		prot, access = windows.PAGE_READWRITE, windows.FILE_MAP_WRITE
	}
	sec, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, prot, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("mmapfile: create section for %s: %w", f.Name(), err)
	}
	// Offset zero, so the allocation-granularity rule on view offsets
	// (64 KiB, unlike mmap's page granularity) never comes up.
	addr, err := windows.MapViewOfFile(sec, access, 0, 0, uintptr(length))
	closeErr := windows.CloseHandle(sec)
	if err != nil {
		return nil, fmt.Errorf("mmapfile: map view of %s: %w", f.Name(), err)
	}
	if closeErr != nil {
		// The view is live and usable, but a handle we cannot close is a
		// handle that pins the file forever, which is exactly the failure
		// this package exists to prevent. Refuse rather than hand back a
		// mapping whose file can never be removed.
		windows.UnmapViewOfFile(addr) //nolint:errcheck
		return nil, fmt.Errorf("mmapfile: close section for %s: %w", f.Name(), closeErr)
	}
	return &Mapping{b: sliceAt(addr, length), f: f}, nil
}

// sliceAt turns an address the kernel handed us into a byte slice.
//
// THE DOUBLE INDIRECTION IS NOT DECORATION. Writing
// `unsafe.Pointer(addr)` on a uintptr is precisely the pattern go vet's
// unsafeptr check exists to catch, and rightly: a uintptr that once held
// a Go pointer is not safe to convert back, because the collector may
// have moved what it pointed at. This address is not a Go pointer.
// MapViewOfFile returned it, it names a region the Go heap knows nothing
// about, and the region does not move. Reinterpreting the uintptr's own
// bits says that, and says it here — rather than switching the check off
// for the whole package, which would also stop it catching a real misuse.
func sliceAt(addr uintptr, length int) []byte {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(p), length)
}

// base is the address MapViewOfFile returned. Mapping never reslices b,
// so &b[0] is still it. (Pointer-to-uintptr is the safe direction; it is
// the reverse that sliceAt has to explain.)
func (m *Mapping) base() uintptr { return uintptr(unsafe.Pointer(&m.b[0])) }

// Flush writes the mapping's dirty pages out and waits for them.
//
// TWO CALLS, because FlushViewOfFile alone does not promise what
// msync(MS_SYNC) promises. It hands the dirty pages to the filesystem and
// returns; the write is queued, not landed. FlushFileBuffers is what waits
// for the device, and Microsoft's own documentation says to use them
// together for exactly this reason. Doing only the first would give a
// caller a Sync that returned before its data was durable, on the one
// platform where nobody would think to check.
func (m *Mapping) Flush() error {
	if m == nil || m.b == nil {
		return nil
	}
	if err := windows.FlushViewOfFile(m.base(), uintptr(len(m.b))); err != nil {
		return fmt.Errorf("mmapfile: flush view: %w", err)
	}
	if m.f == nil {
		return nil
	}
	if err := windows.FlushFileBuffers(windows.Handle(m.f.Fd())); err != nil {
		return fmt.Errorf("mmapfile: flush file buffers: %w", err)
	}
	return nil
}

// Close unmaps the view. It is idempotent.
//
// AND IT IS WHAT FREES THE FILE. While the view is mapped the backing
// file cannot be deleted, renamed, or resized, and a caller's os.Remove
// comes back ERROR_SHARING_VIOLATION. Every caller that removes its file
// therefore closes first — extsort.Table.Close and memtable's
// Buffer.Remove and Ring.Remove all say so at the call site.
func (m *Mapping) Close() error {
	if m == nil || m.b == nil {
		return nil
	}
	addr := m.base()
	m.b, m.f = nil, nil
	if err := windows.UnmapViewOfFile(addr); err != nil {
		return fmt.Errorf("mmapfile: unmap view: %w", err)
	}
	return nil
}
