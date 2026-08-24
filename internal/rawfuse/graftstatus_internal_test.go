//go:build !windows

package rawfuse

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/bbockelm/pelfs/internal/genfs"
	"github.com/bbockelm/pelfs/internal/ui"
)

// A graft-integrity failure gets its own status and its own log line.
//
// The distinction is operational: EIO from a grafted read used to mean
// either "retry, the network blinked" or "never retry, the source
// republished the file", and a job cannot tell them apart from one errno.
func TestGraftIntegrityGetsItsOwnStatus(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()
	graftReportedAt.Store(0)
	graftSuppressed.Store(0)

	err := fmt.Errorf("read failed: %w", &genfs.GraftIntegrityError{
		Kind: genfs.GraftHashMismatch, Graft: "/ext", Source: "pelican://x/y",
		Key: "data/one.bin", Off: 0, Length: 4096,
		Want: "aa", Got: "bb", Msg: "the graft source has changed",
	})
	if got := errStatus(err); got != fuse.Status(syscall.EBADMSG) {
		t.Fatalf("a graft-integrity failure mapped to %v, want EBADMSG", got)
	}
	// It is NOT the unrecognized-error path: that line would say the
	// binding did not understand its own failure, which here it does.
	line := out.String()
	if strings.Contains(line, "unrecognized error") {
		t.Fatalf("a classified failure went through the EIO explainer: %q", line)
	}
	if !strings.Contains(line, "graft integrity failure") {
		t.Fatalf("nothing said a graft's integrity failed: %q", line)
	}
	if !strings.Contains(line, "the graft source has changed") {
		t.Fatalf("the log line dropped the message that names the source: %q", line)
	}
}

// An ordinary transport failure keeps EIO, which is the other half of the
// same claim.
func TestAnOrdinaryGraftFailureKeepsEIO(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()
	eioReportedAt.Store(0)
	eioSuppressed.Store(0)
	if got := errStatus(errors.New("graft /ext: read: connection refused")); got != fuse.EIO {
		t.Fatalf("an unreachable graft source mapped to %v, want EIO", got)
	}
}

// The graft explainer has its own suppression budget, so a mount drowning
// in unrelated EIOs cannot silence the one line that names a changed
// source.
func TestGraftIntegrityReportHasItsOwnBudget(t *testing.T) {
	var out bytes.Buffer
	defer ui.SetOutput(&out, ui.Plain)()
	graftReportedAt.Store(time.Now().UnixNano())
	graftSuppressed.Store(0)
	eioReportedAt.Store(0)
	eioSuppressed.Store(0)

	gi := fmt.Errorf("%w", &genfs.GraftIntegrityError{Graft: "/ext", Msg: "changed"})
	logGraftIntegrity(gi)
	if out.Len() != 0 {
		t.Fatalf("reported inside its own rate-limit window: %q", out.String())
	}
	if graftSuppressed.Load() == 0 {
		t.Fatal("nothing was counted as suppressed")
	}
	// The EIO explainer is untouched by it.
	if eioSuppressed.Load() != 0 {
		t.Fatal("a graft report spent the EIO budget")
	}
	graftReportedAt.Store(0)
	logGraftIntegrity(gi)
	if !strings.Contains(out.String(), "more like it") {
		t.Fatalf("the report dropped the suppressed count: %q", out.String())
	}
}
