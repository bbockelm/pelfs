package nfsmount

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"

	"github.com/bbockelm/pelfs/internal/ui"
)

// The failure this exists to prevent: a client reports "Input/output
// error" and the log says nothing, because go-nfs -- not us -- did the
// translation and threw the cause away.
func TestExplainReportsWhatGoNFSWouldDiscard(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()
	eioReportedAt.Store(0)
	eioSuppressed.Store(0)

	// ESTALE is the shape that matters most: the layers below return it
	// routinely, go-nfs has an NFS status for it and never uses it for a
	// filesystem error, so it lands on the client as EIO.
	err := &os.PathError{Op: "chmod", Path: "/deep/tree/file.c", Err: syscall.ESTALE}
	if got := explain("chmod", "/deep/tree/file.c", err); got != error(err) {
		t.Fatalf("explain changed the error: %v", got)
	}
	line := out.String()
	for _, want := range []string{"chmod", "/deep/tree/file.c", "EIO", "stale"} {
		if !strings.Contains(strings.ToLower(line), strings.ToLower(want)) {
			t.Errorf("report is missing %q: %q", want, line)
		}
	}
}

// Errors go-nfs turns into a faithful status must not be reported: a
// create that legitimately loses a race says EEXIST, and a log line for
// every one of them is noise that buries the real thing.
func TestExplainStaysQuietForTranslatableErrors(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()
	eioReportedAt.Store(0)
	eioSuppressed.Store(0)

	for _, err := range []error{
		nil,
		&os.PathError{Op: "open", Path: "/a", Err: os.ErrNotExist},
		&os.PathError{Op: "open", Path: "/a", Err: os.ErrExist},
		&os.PathError{Op: "open", Path: "/a", Err: syscall.EPERM},
		&os.PathError{Op: "write", Path: "/a", Err: syscall.ENOSPC},
	} {
		explain("open", "/a", err)
	}
	if out.Len() != 0 {
		t.Errorf("reported a translatable error: %q", out.String())
	}
	if n := eioSuppressed.Load(); n != 0 {
		t.Errorf("counted %d translatable errors as suppressed", n)
	}
}

// A workload that trips this trips it per operation, and the reply it
// delays is what the client is blocked on. Suppressed occurrences must
// cost nothing, and the count must survive into the next line that gets
// through, since that count is the only remaining signal that the failure
// was in bulk.
func TestReportIsRateLimitedAndFree(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()

	eioReportedAt.Store(time.Now().UnixNano())
	eioSuppressed.Store(0)
	err := errors.New("something no NFS status describes")

	if n := testing.AllocsPerRun(200, func() { explain("create", "/a/b/c", err) }); n != 0 {
		t.Errorf("suppressed report allocates %v times per call", n)
	}
	if out.Len() != 0 {
		t.Errorf("reported inside the rate-limit window: %q", out.String())
	}
	if eioSuppressed.Load() == 0 {
		t.Fatal("nothing was counted as suppressed")
	}

	eioReportedAt.Store(0)
	explain("create", "/a/b/c", err)
	line := out.String()
	if !strings.Contains(line, "told EIO") {
		t.Errorf("no report after the window: %q", line)
	}
	if !strings.Contains(line, "more like it") {
		t.Errorf("report dropped the suppressed count: %q", line)
	}
	if eioSuppressed.Load() != 0 {
		t.Errorf("suppressed count not cleared by the report")
	}
}

// staleFS fails one named operation, so the wrapper can be checked
// against the shape go-nfs actually drives: Create then Chmod, which is
// what SetFileAttributes.Apply does on every CREATE.
type staleFS struct {
	billy.Filesystem
	failChmod bool
}

func (f *staleFS) Chmod(name string, mode os.FileMode) error {
	if f.failChmod {
		return &os.PathError{Op: "chmod", Path: name, Err: syscall.ESTALE}
	}
	return nil
}
func (f *staleFS) Lchown(string, int, int) error              { return nil }
func (f *staleFS) Chown(string, int, int) error               { return nil }
func (f *staleFS) Chtimes(string, time.Time, time.Time) error { return nil }

// The wrapper has to keep every property go-nfs tests for, or it changes
// the server's behavior while explaining it: WriteCapability (absent, and
// every mutating RPC is refused with ROFS) and billy.Change (absent, and
// SETATTR is refused as unsupported).
func TestDiagnosePreservesTheInterfacesGoNFSAsserts(t *testing.T) {
	plain := diagnose(memfs.New())
	if _, ok := plain.(billy.Change); ok {
		t.Error("wrapper claims billy.Change for a filesystem that has none")
	}
	if !billy.CapabilityCheck(plain, billy.WriteCapability) {
		t.Error("wrapper dropped WriteCapability")
	}

	changeable := diagnose(&staleFS{Filesystem: memfs.New()})
	if _, ok := changeable.(billy.Change); !ok {
		t.Fatal("wrapper dropped billy.Change")
	}
}

// The end-to-end shape: a chmod failing behind a wrapped filesystem is
// reported with the operation and the path, exactly as it would be seen
// on the create path.
func TestDiagnoseReportsThroughTheWrapper(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()
	eioReportedAt.Store(0)
	eioSuppressed.Store(0)

	fs := diagnose(&staleFS{Filesystem: memfs.New(), failChmod: true})
	f, err := fs.Create("/a.c")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := fs.(billy.Change).Chmod("/a.c", 0o644); err == nil {
		t.Fatal("chmod did not fail")
	}
	if line := out.String(); !strings.Contains(line, "chmod") || !strings.Contains(line, "/a.c") {
		t.Errorf("wrapper did not report the failing chmod: %q", line)
	}
}
