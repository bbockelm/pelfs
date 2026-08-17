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
	nfs "github.com/willscott/go-nfs"

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
	if got := explain("chmod", "/deep/tree/file.c", toldEIO, err); got != error(err) {
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
		explain("open", "/a", toldEACCES, err)
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

	if n := testing.AllocsPerRun(200, func() { explain("create", "/a/b/c", toldEIO, err) }); n != 0 {
		t.Errorf("suppressed report allocates %v times per call", n)
	}
	if out.Len() != 0 {
		t.Errorf("reported inside the rate-limit window: %q", out.String())
	}
	if eioSuppressed.Load() == 0 {
		t.Fatal("nothing was counted as suppressed")
	}

	eioReportedAt.Store(0)
	explain("create", "/a/b/c", toldEIO, err)
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

// chmodFS fails Chmod with a chosen error, so the wrapper can be checked
// against the shape go-nfs actually drives: Create then Chmod, which is
// what SetFileAttributes.Apply does on every CREATE.
type chmodFS struct {
	billy.Filesystem
	fail error
}

func (f *chmodFS) Chmod(name string, mode os.FileMode) error {
	if f.fail != nil {
		return &os.PathError{Op: "chmod", Path: name, Err: f.fail}
	}
	return nil
}
func (f *chmodFS) Lchown(string, int, int) error              { return nil }
func (f *chmodFS) Chown(string, int, int) error               { return nil }
func (f *chmodFS) Chtimes(string, time.Time, time.Time) error { return nil }

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

	changeable := diagnose(&chmodFS{Filesystem: memfs.New()})
	if _, ok := changeable.(billy.Change); !ok {
		t.Fatal("wrapper dropped billy.Change")
	}
}

// SetFileAttributes.Apply returns an attribute setter's error raw, and
// onSetAttr hands that straight to the response formatter -- which, for a
// type it does not recognize, answers with an RPC-level system error
// instead of an NFS status. Every error out of billy.Change must
// therefore arrive as an *nfs.NFSStatusError carrying the status that
// describes it, while still testing as the error it wraps, because that
// is what Apply itself matches on.
func TestChangeErrorsCarryAnNFSStatus(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, false)()

	for _, tc := range []struct {
		name     string
		err      error
		want     nfs.NFSStatus
		reported bool
	}{
		{"stale", syscall.ESTALE, nfs.NFSStatusStale, false},
		{"missing", os.ErrNotExist, nfs.NFSStatusNoEnt, false},
		{"denied", syscall.EPERM, nfs.NFSStatusAccess, false},
		{"notempty", syscall.ENOTEMPTY, nfs.NFSStatusNotEmpty, false},
		{"unknown", errors.New("the layer below came apart"), nfs.NFSStatusIO, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			eioReportedAt.Store(0)
			eioSuppressed.Store(0)

			fs := diagnose(&chmodFS{Filesystem: memfs.New(), fail: tc.err})
			err := fs.(billy.Change).Chmod("/a.c", 0o644)
			var st *nfs.NFSStatusError
			if !errors.As(err, &st) {
				t.Fatalf("chmod error is not an *nfs.NFSStatusError: %#v", err)
			}
			if st.NFSStatus != tc.want {
				t.Errorf("status = %v, want %v", st.NFSStatus, tc.want)
			}
			// Apply matches on the wrapped error; the chain must survive.
			if !errors.Is(err, tc.err) {
				t.Errorf("wrapping hid the cause: %v", err)
			}
			if got := strings.Contains(out.String(), "chmod") && strings.Contains(out.String(), "/a.c"); got != tc.reported {
				t.Errorf("reported = %v, want %v: %q", got, tc.reported, out.String())
			}
		})
	}
}
