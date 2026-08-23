//go:build !windows

package mmapfile

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Map mmaps the first length bytes of f. See the package comment for the
// contract it holds on every platform.
//
// MAP_SHARED, not MAP_PRIVATE, in both modes: the read-only caller wants
// the kernel's page cache for the file rather than a private copy of it,
// which is the whole reason it maps instead of reading.
func Map(f *os.File, length int, mode Mode) (*Mapping, error) {
	if length <= 0 {
		return nil, fmt.Errorf("mmapfile: map %s: length %d is not positive", f.Name(), length)
	}
	prot := unix.PROT_READ
	if mode == ReadWrite {
		prot |= unix.PROT_WRITE
	}
	b, err := unix.Mmap(int(f.Fd()), 0, length, prot, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmapfile: map %s: %w", f.Name(), err)
	}
	return &Mapping{b: b, f: f}, nil
}

// Flush writes the mapping's dirty pages out and waits for them.
func (m *Mapping) Flush() error {
	if m == nil || m.b == nil {
		return nil
	}
	if err := unix.Msync(m.b, unix.MS_SYNC); err != nil {
		return fmt.Errorf("mmapfile: msync: %w", err)
	}
	return nil
}

// Close unmaps the region. It is idempotent.
func (m *Mapping) Close() error {
	if m == nil || m.b == nil {
		return nil
	}
	b := m.b
	m.b, m.f = nil, nil
	if err := unix.Munmap(b); err != nil {
		return fmt.Errorf("mmapfile: unmap: %w", err)
	}
	return nil
}
