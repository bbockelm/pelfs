package pelicanobj

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/error_codes"
)

// mismatchStore fails ordinary reads the way an origin does when its
// advertised digest disagrees with the body it served, and serves the
// real bytes only on the unverified path.
type mismatchStore struct {
	Store
	getErr      error
	body        string
	unverifieds int
}

func (s *mismatchStore) Get(_ context.Context, _ string, _, _ int64) (io.ReadCloser, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return io.NopCloser(strings.NewReader(s.body)), nil
}

func (s *mismatchStore) GetUnverified(_ context.Context, _ string) (io.ReadCloser, error) {
	s.unverifieds++
	return io.NopCloser(strings.NewReader(s.body)), nil
}

func TestReadMutableFallsBackOnChecksumMismatch(t *testing.T) {
	s := &mismatchStore{
		getErr: error_codes.NewTransfer_ChecksumMismatchError(errors.New("md5 differs")),
		body:   "superblock-bytes",
	}
	raw, err := ReadMutable(context.Background(), s, "refs/main")
	if err != nil {
		t.Fatalf("ReadMutable: %v", err)
	}
	if string(raw) != "superblock-bytes" {
		t.Fatalf("body = %q, want the object's bytes", raw)
	}
	if s.unverifieds != 1 {
		t.Fatalf("unverified reads = %d, want exactly 1", s.unverifieds)
	}
}

// The fallback is for ONE condition. Any other failure must propagate:
// silently re-reading past an unrelated error would turn a real transport
// failure into an unverified read.
func TestReadMutableDoesNotFallBackOnOtherErrors(t *testing.T) {
	s := &mismatchStore{getErr: errors.New("connection reset"), body: "bytes"}
	if _, err := ReadMutable(context.Background(), s, "refs/main"); err == nil {
		t.Fatal("ReadMutable hid a non-checksum failure")
	}
	if s.unverifieds != 0 {
		t.Fatalf("unverified reads = %d, want 0 for an unrelated error", s.unverifieds)
	}
}

// A healthy origin must never reach the unverified path, so ordinary
// reads keep their checksum guarantee.
func TestReadMutableKeepsVerificationWhenHealthy(t *testing.T) {
	s := &mismatchStore{body: "bytes"}
	raw, err := ReadMutable(context.Background(), s, "refs/main")
	if err != nil {
		t.Fatalf("ReadMutable: %v", err)
	}
	if string(raw) != "bytes" {
		t.Fatalf("body = %q", raw)
	}
	if s.unverifieds != 0 {
		t.Fatalf("unverified reads = %d, want 0 on a healthy read", s.unverifieds)
	}
}

// A transport with no unverified path (the plain-HTTP dev transport) must
// surface the original error rather than pretending to recover.
func TestReadMutableWithoutFallbackReportsTheError(t *testing.T) {
	s := &plainStore{getErr: error_codes.NewTransfer_ChecksumMismatchError(errors.New("md5 differs"))}
	if _, err := ReadMutable(context.Background(), s, "refs/main"); err == nil {
		t.Fatal("expected the checksum error to propagate")
	}
}

type plainStore struct {
	Store
	getErr error
}

func (s *plainStore) Get(_ context.Context, _ string, _, _ int64) (io.ReadCloser, error) {
	return nil, s.getErr
}

// TestChecksumMismatchSurvivesTypeLoss pins the textual half of the
// detection. The typed check is preferred, but the error crosses a
// boundary that can rebuild it as a plain error, and when that happened
// the fallback silently never ran.
func TestChecksumMismatchSurvivesTypeLoss(t *testing.T) {
	typed := error_codes.NewTransfer_ChecksumMismatchError(errors.New("md5 differs"))
	flattened := errors.New(typed.Error())
	if !isChecksumMismatch(flattened) {
		t.Fatalf("a flattened checksum error was not recognized: %q", flattened)
	}
	if !isChecksumMismatch(typed) {
		t.Fatal("the typed checksum error was not recognized")
	}
	for _, other := range []error{
		errors.New("connection reset by peer"),
		errors.New("Transfer.ChecksumMissing Error: Error code 6007: no checksum"),
		nil,
	} {
		if isChecksumMismatch(other) {
			t.Errorf("unrelated error treated as a checksum mismatch: %v", other)
		}
	}
}

// The fallback must also fire when the store returns the error only once
// reading begins, rather than at open: the transfer is what verifies.
func TestReadMutableFallsBackOnDeferredMismatch(t *testing.T) {
	s := &deferredMismatchStore{body: "superblock-bytes"}
	raw, err := ReadMutable(context.Background(), s, "refs/main")
	if err != nil {
		t.Fatalf("ReadMutable: %v", err)
	}
	if string(raw) != "superblock-bytes" {
		t.Fatalf("body = %q", raw)
	}
	if s.unverifieds != 1 {
		t.Fatalf("unverified reads = %d, want 1", s.unverifieds)
	}
}

type deferredMismatchStore struct {
	Store
	body        string
	unverifieds int
}

func (s *deferredMismatchStore) Get(_ context.Context, _ string, _, _ int64) (io.ReadCloser, error) {
	return io.NopCloser(&failingReader{
		err: error_codes.NewTransfer_ChecksumMismatchError(errors.New("md5 differs")),
	}), nil
}

func (s *deferredMismatchStore) GetUnverified(_ context.Context, _ string) (io.ReadCloser, error) {
	s.unverifieds++
	return io.NopCloser(strings.NewReader(s.body)), nil
}

type failingReader struct{ err error }

func (r *failingReader) Read([]byte) (int, error) { return 0, r.err }

// decorator stands in for the stats counter and the pack layer: it
// embeds the Store interface, so it presents none of the transport's
// optional capabilities on its own.
type decorator struct {
	Store
	inner Store
}

func (d decorator) Unwrap() Store { return d.inner }

// TestReadMutableUnwrapsDecorators is the regression that matters most in
// this file. The fallback was correct and completely inert in production
// because the mount hands refs a statistics wrapper, not the transport,
// and a bare type assertion stopped at the wrapper -- no error, no
// warning, just nothing happening.
func TestReadMutableUnwrapsDecorators(t *testing.T) {
	fed := &mismatchStore{
		getErr: error_codes.NewTransfer_ChecksumMismatchError(errors.New("md5 differs")),
		body:   "superblock-bytes",
	}
	// Two layers deep, as on the real mount path.
	wrapped := decorator{Store: fed, inner: decorator{Store: fed, inner: fed}}

	raw, err := ReadMutable(context.Background(), wrapped, "refs/main")
	if err != nil {
		t.Fatalf("ReadMutable through decorators: %v", err)
	}
	if string(raw) != "superblock-bytes" {
		t.Fatalf("body = %q", raw)
	}
	if fed.unverifieds != 1 {
		t.Fatalf("unverified reads = %d, want 1 -- the probe did not reach the transport", fed.unverifieds)
	}
}

// The same hiding disabled the direct-read rule for mutable objects.
func TestAsDirectReaderUnwrapsDecorators(t *testing.T) {
	fed := &cachedTransport{}
	wrapped := decorator{Store: fed, inner: fed}
	if _, ok := AsDirectReader(wrapped); !ok {
		t.Fatal("AsDirectReader stopped at the decorator; mutable reads would keep going through caches")
	}
	// A decorator over a transport WITHOUT the capability must still
	// report absence rather than looping or panicking.
	plain := decorator{Store: &plainStore{}, inner: &plainStore{}}
	if _, ok := AsDirectReader(plain); ok {
		t.Fatal("AsDirectReader invented a capability that does not exist")
	}
}

type cachedTransport struct{ Store }

func (c *cachedTransport) DirectVariant() Store { return c }
