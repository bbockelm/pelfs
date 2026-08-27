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
	defer ui.SetOutput(&out, ui.Plain)()
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
	defer ui.SetOutput(&out, ui.Plain)()
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
	defer ui.SetOutput(&out, ui.Plain)()

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

// permFS gives an in-memory filesystem the ACCESS answer go-nfs asks for
// by type assertion. What it permits is fixed; the point here is which
// wrapper shapes carry the method through.
type permFS struct {
	billy.Filesystem
	granted nfs.Permission
}

func (f *permFS) Permitted(string) (nfs.Permission, error) { return f.granted, nil }

// changePermFS has both of the optional interfaces at once, which is the
// combination the real filesystem (internal/vfsbilly) presents.
type changePermFS struct {
	chmodFS
	granted nfs.Permission
}

func (f *changePermFS) Permitted(string) (nfs.Permission, error) { return f.granted, nil }

// commitFS gives an in-memory filesystem the COMMIT answer go-nfs asks
// for by type assertion, and records that it was asked.
type commitFS struct {
	billy.Filesystem
	commits []string
	fail    error
}

func (f *commitFS) Commit(path string) error {
	f.commits = append(f.commits, path)
	return f.fail
}

// allFS is every optional interface at once, which is the shape the real
// filesystem (internal/vfsbilly) presents and the one the wrapper is most
// likely to drop something from.
type allFS struct {
	chmodFS
	granted nfs.Permission
	commits []string
}

func (f *allFS) Permitted(string) (nfs.Permission, error) { return f.granted, nil }
func (f *allFS) Link(string, string) error                { return nil }
func (f *allFS) Commit(path string) error {
	f.commits = append(f.commits, path)
	return nil
}

// nfs.Committer is the fourth optional interface, and the one where
// OVER-claiming is the expensive mistake. go-nfs reads it as "this
// filesystem BUFFERS": it starts answering UNSTABLE to writes and defers
// their durability to a COMMIT. A wrapper that claimed it over a
// filesystem with nothing behind the method would leave the client waiting
// for a commit that does nothing -- fsync(2) returning success over data
// no layer ever made durable, which is KI-10 restored one level up.
func TestDiagnosePreservesTheCommitInterface(t *testing.T) {
	if _, ok := diagnose(memfs.New(), nil).(nfs.Committer); ok {
		t.Error("wrapper claims nfs.Committer for a filesystem that has none: go-nfs would answer " +
			"UNSTABLE to writes and commit them nowhere")
	}

	inner := &commitFS{Filesystem: memfs.New()}
	wrapped := diagnose(inner, nil)
	c, ok := wrapped.(nfs.Committer)
	if !ok {
		t.Fatal("wrapper dropped nfs.Committer, so COMMIT goes back to answering without asking")
	}
	if err := c.Commit("/a.c"); err != nil {
		t.Fatalf("Commit through the wrapper: %v", err)
	}
	if len(inner.commits) != 1 || inner.commits[0] != "/a.c" {
		t.Errorf("the wrapper recorded commits %v, want one for /a.c", inner.commits)
	}
	if _, ok := wrapped.(billy.Change); ok {
		t.Error("wrapper invented billy.Change for a filesystem that only commits")
	}
	if _, ok := wrapped.(nfs.PermissionChecker); ok {
		t.Error("wrapper invented nfs.PermissionChecker for a filesystem that only commits")
	}

	// A commit that fails must still fail through the wrapper: it is the
	// only reply an application's fsync(2) is waiting on.
	failing := diagnose(&commitFS{Filesystem: memfs.New(), fail: syscall.ENOSPC}, nil)
	if err := failing.(nfs.Committer).Commit("/a.c"); !errors.Is(err, syscall.ENOSPC) {
		t.Errorf("a failed commit came back as %v, want ENOSPC", err)
	}

	// And the full combination, which is the one the mount actually runs.
	all := &allFS{chmodFS: chmodFS{Filesystem: memfs.New()}, granted: nfs.PermissionRead}
	full := diagnose(all, nil)
	if _, ok := full.(billy.Change); !ok {
		t.Error("wrapper dropped billy.Change from the four-way shape")
	}
	if _, ok := full.(nfs.HardLinker); !ok {
		t.Error("wrapper dropped nfs.HardLinker from the four-way shape")
	}
	if _, ok := full.(nfs.PermissionChecker); !ok {
		t.Error("wrapper dropped nfs.PermissionChecker from the four-way shape")
	}
	if _, ok := full.(nfs.Committer); !ok {
		t.Error("wrapper dropped nfs.Committer from the four-way shape")
	}
	if err := full.(nfs.Committer).Commit("/b.c"); err != nil || len(all.commits) != 1 {
		t.Errorf("Commit through the four-way wrapper: err=%v commits=%v", err, all.commits)
	}
}

// The four-way shape is also the shape a --finder mount runs, so the hide
// filter has to survive it. It is the one thing the Committer work and the
// Finder work touch in common: both are answered by WHICH wrapper type
// diagnose returns, and a filter that was dropped from the widest
// combination would leave the volume publishing .DS_Store on exactly the
// mounts that can see the Finder.
func TestDiagnoseKeepsTheFilterInTheFourWayShape(t *testing.T) {
	all := &allFS{chmodFS: chmodFS{Filesystem: memfs.New()}, granted: nfs.PermissionRead}
	full := diagnose(all, finderDropping)
	for _, iface := range []struct {
		name string
		ok   bool
	}{
		{"billy.Change", func() bool { _, ok := full.(billy.Change); return ok }()},
		{"nfs.HardLinker", func() bool { _, ok := full.(nfs.HardLinker); return ok }()},
		{"nfs.PermissionChecker", func() bool { _, ok := full.(nfs.PermissionChecker); return ok }()},
		{"nfs.Committer", func() bool { _, ok := full.(nfs.Committer); return ok }()},
	} {
		if !iface.ok {
			t.Errorf("a filtered four-way wrapper dropped %s", iface.name)
		}
	}
	if _, err := full.Create("/dir/.DS_Store"); !errors.Is(err, syscall.EACCES) {
		t.Errorf("creating .DS_Store on a filtered four-way mount = %v, want EACCES", err)
	}
	if _, err := full.Stat("/dir/.DS_Store"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("stat of .DS_Store on a filtered four-way mount = %v, want ENOENT", err)
	}
	// And the allowed neighbours the filter must never take: refusing an
	// AppleDouble sidecar fails the Finder copy that writes it, and
	// refusing .Trashes turns Move to Trash into an error.
	for _, name := range []string{"/dir/._paper.pdf", "/.Trashes"} {
		f, err := full.Create(name)
		if err != nil {
			t.Errorf("Create(%s) on a filtered four-way mount = %v, want success", name, err)
			continue
		}
		_ = f.Close()
	}
	// A COMMIT still reaches the filesystem underneath: diagCommitter
	// carries no filter, deliberately, because no handle for a hidden name
	// can exist to commit.
	if err := full.(nfs.Committer).Commit("/dir/._paper.pdf"); err != nil {
		t.Errorf("Commit of an allowed name through a filtered wrapper: %v", err)
	}
}

// The wrapper has to keep every property go-nfs tests for, or it changes
// the server's behavior while explaining it: WriteCapability (absent, and
// every mutating RPC is refused with ROFS), billy.Change (absent, and
// SETATTR is refused as unsupported), and nfs.PermissionChecker (absent,
// and ACCESS echoes the client's mask).
//
// The permission checker is the one where a wrapper that over-claims does
// real damage rather than merely lying: go-nfs would call a method with no
// filesystem behind it, and every ACCESS would come back granting nothing
// -- a mount on which nothing can be opened at all.
func TestDiagnosePreservesTheInterfacesGoNFSAsserts(t *testing.T) {
	plain := diagnose(memfs.New(), nil)
	if _, ok := plain.(billy.Change); ok {
		t.Error("wrapper claims billy.Change for a filesystem that has none")
	}
	if _, ok := plain.(nfs.PermissionChecker); ok {
		t.Error("wrapper claims nfs.PermissionChecker for a filesystem that has none")
	}
	if !billy.CapabilityCheck(plain, billy.WriteCapability) {
		t.Error("wrapper dropped WriteCapability")
	}

	changeable := diagnose(&chmodFS{Filesystem: memfs.New()}, nil)
	if _, ok := changeable.(billy.Change); !ok {
		t.Fatal("wrapper dropped billy.Change")
	}
	if _, ok := changeable.(nfs.PermissionChecker); ok {
		t.Error("wrapper invented nfs.PermissionChecker for a changeable filesystem")
	}

	checker := diagnose(&permFS{Filesystem: memfs.New(), granted: nfs.PermissionRead}, nil)
	pc, ok := checker.(nfs.PermissionChecker)
	if !ok {
		t.Fatal("wrapper dropped nfs.PermissionChecker")
	}
	if got, err := pc.Permitted("/a.c"); err != nil || got != nfs.PermissionRead {
		t.Errorf("Permitted through the wrapper = %v, %v; want %v, nil",
			got, err, nfs.PermissionRead)
	}

	both := diagnose(&changePermFS{
		chmodFS: chmodFS{Filesystem: memfs.New()},
		granted: nfs.PermissionRead | nfs.PermissionWrite,
	}, nil)
	if _, ok := both.(billy.Change); !ok {
		t.Error("wrapper dropped billy.Change from a filesystem that also checks permissions")
	}
	if _, ok := both.(nfs.PermissionChecker); !ok {
		t.Error("wrapper dropped nfs.PermissionChecker from a filesystem that is also changeable")
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
	defer ui.SetOutput(&out, ui.Plain)()

	for _, tc := range []struct {
		name     string
		err      error
		want     nfs.NFSStatus
		reported bool
	}{
		{"stale", syscall.ESTALE, nfs.NFSStatusStale, false},
		{"missing", os.ErrNotExist, nfs.NFSStatusNoEnt, false},
		// EPERM and EACCES are different answers and must not collapse: a
		// chmod refused for want of ownership is NFS3ERR_PERM, which
		// reaches a client as "Operation not permitted" — what the FUSE
		// frontend and every local filesystem say for the same refusal.
		{"not the owner", syscall.EPERM, nfs.NFSStatusPerm, false},
		{"denied by the mode bits", syscall.EACCES, nfs.NFSStatusAccess, false},
		{"notempty", syscall.ENOTEMPTY, nfs.NFSStatusNotEmpty, false},
		{"unknown", errors.New("the layer below came apart"), nfs.NFSStatusIO, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			eioReportedAt.Store(0)
			eioSuppressed.Store(0)

			fs := diagnose(&chmodFS{Filesystem: memfs.New(), fail: tc.err}, nil)
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
