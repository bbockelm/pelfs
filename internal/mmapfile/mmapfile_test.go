package mmapfile_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/pelfs/internal/mmapfile"
)

// The three Windows rules this package exists for are stated in its doc
// comment and depended on by four call sites. These are the executable
// form of them, so that a Windows build is checked and not merely
// compiled. Every one of them passes trivially on Unix — that is the
// point: the assertions are about behaviour that must be the SAME on both,
// and Windows is where each could differ.

// A read-only mapping over a file that has been written and closed. It is
// extsort's shape exactly: write, flush, map, then let the *os.File go.
func TestAMappingOutlivesTheFileHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "table")
	want := bytes.Repeat([]byte("pelfs!!!"), 512)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mmapfile.Map(f, len(want), mmapfile.ReadOnly)
	if err != nil {
		f.Close() //nolint:errcheck
		t.Fatal(err)
	}
	// Closed while the mapping is live, which is what extsort does. On
	// Windows the section keeps the file alive; on Unix the kernel's own
	// reference does.
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := m.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("mapped %d bytes, wanted %d equal bytes", len(got), len(want))
	}
	if m.Len() != len(want) {
		t.Errorf("Len = %d, want %d", m.Len(), len(want))
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}

// THE ONE THAT MATTERS. Close has to free the file, because three callers
// remove the file immediately afterwards and on Windows a live mapping
// pins it. A remove that fails here is a leaked table, a leaked buffer, or
// a leaked ring file.
func TestTheBackingFileIsRemovableAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	const size = 8 << 10
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	m, err := mmapfile.Map(f, size, mmapfile.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	copy(m.Bytes(), "written through the mapping")
	if err := m.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("the backing file was still pinned after Close: %v", err)
	}
}

// Writes through a ReadWrite mapping reach the file, which is what makes
// the memtable's ring a durable log rather than a scratch buffer.
func TestWritesThroughAMappingReachTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	const size = 4 << 10
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	m, err := mmapfile.Map(f, size, mmapfile.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("this must be readable through read(2) as well")
	copy(m.Bytes(), want)
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:len(want)], want) {
		t.Fatalf("the file holds %q, not the bytes written through the mapping", got[:len(want)])
	}
}

// A zero length is refused rather than attempted, on every platform:
// mmap rejects it by rule and Windows has no section to make. Both
// callers that could reach it handle the empty case first, and this is
// what says the refusal is theirs to rely on.
func TestAnEmptyMappingIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if m, err := mmapfile.Map(f, 0, mmapfile.ReadOnly); err == nil {
		m.Close() //nolint:errcheck
		t.Fatal("a zero-length mapping was accepted")
	}
	if m, err := mmapfile.Map(f, -1, mmapfile.ReadOnly); err == nil {
		m.Close() //nolint:errcheck
		t.Fatal("a negative-length mapping was accepted")
	}
}

// The nil and double-Close paths, because Close runs on error paths and
// from deferred teardown where it may already have run.
func TestCloseIsIdempotentAndNilSafe(t *testing.T) {
	var nilMap *mmapfile.Mapping
	if nilMap.Bytes() != nil || nilMap.Len() != 0 {
		t.Error("a nil Mapping should map nothing")
	}
	if err := nilMap.Close(); err != nil {
		t.Errorf("closing a nil Mapping: %v", err)
	}
	if err := nilMap.Flush(); err != nil {
		t.Errorf("flushing a nil Mapping: %v", err)
	}

	path := filepath.Join(t.TempDir(), "twice")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if err := f.Truncate(4096); err != nil {
		t.Fatal(err)
	}
	m, err := mmapfile.Map(f, 4096, mmapfile.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if m.Bytes() != nil {
		t.Error("Bytes after Close should be nil")
	}
}
